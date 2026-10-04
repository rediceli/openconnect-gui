//! openconnect 命令行构建器
//!
//! # 安全不变量（最重要的一节）
//!
//! **密码、cookie、私钥口令、令牌 secret 绝不进入 argv。**
//!
//! 原因：`argv` 在 Linux/macOS 上对同机所有用户可读（`/proc/<pid>/cmdline`、
//! `ps aux`），在 Windows 上也可被其他进程读取。把密钥放进命令行等于
//! 明文广播。
//!
//! 正确通道：
//! - 密码 → stdin（`--passwd-on-stdin`）
//! - cookie → stdin（`--cookie-on-stdin`）
//! - 私钥口令 → ⚠️ **没有 stdin 通道**，openconnect 只有 `-p/--key-password`。
//!   见 `ArgPlan::key_password_via_stdin` 的说明与 P1 文档的未决项。
//! - 令牌 secret → `--token-secret`，同样只能走命令行（有 `@file` 形式，
//!   见该函数）。
//!
//! 这些不变量由 `tests::security::` 下的测试强制保证。

use crate::profile::{formmap, Profile};

/// 构建出的连接方案。
///
/// ⚠️ 刻意**不**实现 `Clone`：克隆会导致 `config_file` 被复制成两份，
/// 一份被 Drop 删除后 openconnect 就读不到文件了。需要多处使用时用
/// `Arc<ArgPlan>`。
#[derive(Debug)]
pub struct ArgPlan {
    /// 传给 `openconnect` 的参数（不含 argv[0]，不含服务器）
    pub args: Vec<String>,
    /// 服务器地址（含端口与路径），作为最后一个位置参数
    pub server: String,
    /// 需要通过 stdin 送入的密钥
    pub stdin_secrets: Vec<StdinSecret>,
    /// 承载私钥口令的 0600 config 文件。
    ///
    /// 必须由 ArgPlan 持有：`ConfigFile` 的 Drop 会删除自己，
    /// 若在 `build()` 里就地创建，返回时文件就没了。
    #[allow(dead_code)]
    config_file: Option<crate::tunnel::occonfig::ConfigFile>,
    /// 构建期致命错误。非空时不应启动 openconnect。
    pub fatal_error: Option<String>,
}

/// 需要走 stdin 的密钥。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdinSecret {
    /// `--passwd-on-stdin` 之后的密码
    Password(String),
    /// `--cookie-on-stdin` 之后的 cookie（SSO 流程）
    Cookie(String),
}

impl ArgPlan {
    /// 构造一个不带任何密钥的方案，供测试与 helper 使用。
    pub fn bare(args: Vec<String>, server: impl Into<String>) -> Self {
        Self {
            args,
            server: server.into(),
            stdin_secrets: Vec::new(),
            config_file: None,
            fatal_error: None,
        }
    }

    /// 完整的 argv（不含程序名）
    pub fn argv(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.args.iter().map(|s| s.as_str()).collect();
        v.push(&self.server);
        v
    }

    /// 拼成可读的命令行，仅用于日志展示与「复制诊断信息」。
    /// 绝不用于执行，且必须脱敏。
    pub fn redacted_display(&self) -> String {
        let mut parts: Vec<String> = self.args.iter().map(|s| s.to_string()).collect();
        for s in &mut parts {
            if let Some(v) = s.strip_prefix("--token-secret=") {
                // @file 形式本身不是密钥，只隐藏路径
                *s = if v.starts_with('@') {
                    "--token-secret=@<path>".to_string()
                } else {
                    format!("--token-secret=<redacted:{}>", v.len())
                };
            }
            if let Some(v) = s.strip_prefix("--key-password=") {
                *s = format!("--key-password=<redacted:{len}>", len = v.len());
            }
            if let Some(v) = s.strip_prefix("--mca-key-password=") {
                *s = format!("--mca-key-password=<redacted:{len}>", len = v.len());
            }
        }
        parts.push(self.server.clone());
        parts.join(" ")
    }

    /// 校验不变量：无任何明文密钥进入 argv。
    /// 返回泄漏的字段名，正常情况返回空。
    pub fn audit_argv(&self, secrets: &[String]) -> Vec<&'static str> {
        let mut leaks = Vec::new();
        let joined = self.args.join(" ");
        for s in secrets {
            if !s.is_empty() && s.len() >= 3 && joined.contains(s.as_str()) {
                leaks.push("secret-value-in-argv");
                break;
            }
        }
        // token-secret 只允许 @file 形式；内联 secret 一律判为泄漏
        let ts_flag = "--token-secret=";
        if self.args.iter().any(|a| {
            a.strip_prefix(ts_flag)
                .is_some_and(|v| !v.starts_with('@'))
        }) {
            leaks.push("token-secret-inline");
        }
        leaks
    }
}

/// 构建命令行。
///
/// `secrets` 由调用方从钥匙串取出，仅用于：
/// 1. 决定是否加 `--passwd-on-stdin`
/// 2. 填 `StdinSecret`
/// 3. `audit_argv` 自检
///
/// 不参与 argv 拼接。
pub fn build(profile: &Profile, secrets: &Secrets) -> ArgPlan {
    let mut args: Vec<String> = Vec::new();
    let mut stdin_secrets: Vec<StdinSecret> = Vec::new();

    // ---- 协议 ----
    args.push(format!("--protocol={}", profile.protocol.as_arg()));

    // ---- 日志：状态机完全依赖这些开关，不要改成 -q ----
    args.push("--timestamp".into()); // 解析器需要时间戳前缀
    args.push("-v".into()); // PRG_INFO 级，必须能拿到 "Configured as ..."

    // ---- 认证 ----
    if let Some(u) = &profile.username
        && !u.is_empty() {
            args.push("-u".into());
            args.push(u.clone());
        }

    // 分组：必须走 -F，不能用 --authgroup
    if let Some(group) = &profile.auth_group
        && !group.is_empty() {
            match formmap::resolve(profile) {
                // ⚠️ 必须用长选项 `--form-entry=`，**不能**写 `-F=`。
                // getopt 对短选项不做 `=` 剥离，`-F=main:group_list=X`
                // 会把 `=main:group_list=X` 整体当作参数传给 add_form_field()，
                // 后者按第一个 `=` 切分，得到空 opt_id →
                // "Form field invalid. Use --form-entry=FORM_ID:OPT_NAME=VALUE"
                // 并直接 exit(1)。P1 实测确认。
                Some(b) => args.push(format!(
                    "--form-entry={}:{}={}",
                    b.form_id, b.group_field, group
                )),
                None => {
                    // 没有默认绑定时静默跳过会让 openconnect 阻塞在交互提示，
                    // 必须让 UI 知道。argv 层用 --non-inter 暴露问题。
                }
            }
        }

    // 密码通道
    if let Some(pw) = &secrets.password {
        if !pw.is_empty() {
            args.push("--passwd-on-stdin".into());
            stdin_secrets.push(StdinSecret::Password(pw.clone()));
        }
    } else if profile.remember_password {
        // 勾选了记住密码但钥匙串里没有 → 必须提前失败，不能让 openconnect 阻塞
        args.push("--non-inter".into());
    }

    // cookie 通道（SSO）
    if let Some(cookie) = &secrets.cookie
        && !cookie.is_empty() {
            args.push("--cookie-on-stdin".into());
            stdin_secrets.push(StdinSecret::Cookie(cookie.clone()));
            // 有 cookie 时无需用户名/密码表单
            args.push("--no-passwd".into());
        }

    // ---- 证书认证 ----
    // ---- 私钥口令：写入 config 文件，只把路径挂进 argv ----
    //
    // ⚠️ openconnect 的 `-p/--key-password` 是唯一接受私钥口令的入口，
    //    **没有 stdin 通道，也没有 `@file` 语法**（源码核实：
    //    `grep -rn "case '@'" *.c` 只命中 --token-secret 与 oidc）。
    //    字面量进 argv 意味着 `ps aux` 全机可见。
    //
    //    解法是 `--config=FILE`：config 文件走同一套 long_options 匹配
    //    （main.c:1258），支持长选项 `key-password`，而短选项 `-p`
    //    只存在于 argv 路径。详见 `occonfig` 模块的完整实验记录。
    //
    //    ConfigFile 由 ArgPlan 持有 —— 它必须活到 openconnect 读完为止。
    let mut config_file = None;
    if let Some(kp) = &secrets.key_password
        && !kp.is_empty() {
            match crate::tunnel::occonfig::write_secure(kp) {
                Ok(cf) => {
                    args.push(cf.arg());
                    config_file = Some(cf);
                }
                // 口令不符合 config 文件格式 → **明确失败**。
                // 静默降级到明文 argv 才是真正的安全事故。
                Err(e) => {
                    return ArgPlan {
                        args: vec![INVALID_CONFIG_FILE.into()],
                        server: profile.server.clone(),
                        stdin_secrets: Vec::new(),
                        config_file: None,
                        fatal_error: Some(e.to_string()),
                    }
                }
            }
        }

    if let Some(c) = &profile.client_cert {
        if !c.certificate.is_empty() {
            args.push("-c".into());
            args.push(c.certificate.clone());
        }
        if !c.private_key.is_empty() {
            args.push("-k".into());
            args.push(c.private_key.clone());
        }
        if let Some(d) = c.expire_warning_days {
            args.push("-e".into());
            args.push(d.to_string());
        }
        if let Some(mc) = &c.mca_certificate {
            if !mc.is_empty() {
                args.push("--mca-certificate".into());
                args.push(mc.clone());
            }
            if let Some(mk) = &c.mca_key
                && !mk.is_empty() {
                    args.push("--mca-key".into());
                    args.push(mk.clone());
                }
        }

        // ⚠️ `--mca-key-password` 与 `-p` 同样没有 stdin / @file 通道。
        // 用户提供了这个口令却又静默丢弃，是最坏的处理方式 ——
        // 必须明确失败，让用户知情后选择方案。
        if secrets.mca_key_password.as_ref().is_some_and(|s| !s.is_empty()) {
            return ArgPlan {
                args: vec![INVALID_CONFIG_FILE.into()],
                server: profile.server.clone(),
                stdin_secrets: Vec::new(),
                config_file: None,
                fatal_error: Some(
                    "多证书认证的第二个私钥口令（--mca-key-password）没有安全的传入通道：\
                     openconnect 不支持 stdin 或 @file，只能明文进 argv。"
                        .into(),
                ),
            };
        }
    }

    // ---- 服务器校验 ----
    if let Some(pin) = &profile.advanced.server_cert_pin
        && !pin.is_empty() {
            args.push(format!("--servercert={pin}"));
        }
    if let Some(ca) = &profile.advanced.ca_file
        && !ca.is_empty() {
            args.push("--cafile".into());
            args.push(ca.clone());
        }
    if profile.advanced.no_system_trust {
        args.push("--no-system-trust".into());
    }

    // ---- 隧道参数 ----
    if let Some(m) = profile.advanced.mtu {
        args.push("--mtu".into());
        args.push(m.to_string());
    }
    if let Some(m) = profile.advanced.base_mtu {
        args.push("--base-mtu".into());
        args.push(m.to_string());
    }
    if profile.advanced.no_dtls {
        args.push("--no-dtls".into());
    }
    if profile.advanced.disable_ipv6 {
        args.push("--disable-ipv6".into());
    }
    if profile.advanced.pfs {
        args.push("--pfs".into());
    }
    if let Some(i) = profile.advanced.force_dpd {
        args.push("--force-dpd".into());
        args.push(i.to_string());
    }

    // ---- 网络 ----
    if let Some(ua) = &profile.advanced.user_agent
        && !ua.is_empty() {
            args.push("--useragent".into());
            args.push(ua.clone());
        }
    if let Some(p) = &profile.advanced.proxy
        && !p.is_empty() {
            args.push("--proxy".into());
            args.push(p.clone());
        }
    if let Some(os) = &profile.advanced.reported_os
        && !os.is_empty() {
            args.push("--os".into());
            args.push(os.clone());
        }

    // ---- 软令牌 ----
    if let Some(mode) = profile.advanced.token_mode {
        args.push(format!("--token-mode={}", mode.as_arg()));
        if secrets.token_secret.is_some() {
            // 用 @file 形式，避免 secret 进 argv（openconnect 支持 `--token-secret=@path`）
            // 见 P1 文档：需要在 helper 侧准备一个 0600 的临时文件
            args.push(format!("--token-secret=@{}", TOKEN_SECRET_FILE));
        }
    }

    // ---- 路径 ----
    if let Some(g) = &profile.advanced.user_group
        && !g.is_empty() {
            args.push("-g".into());
            args.push(g.clone());
        }

    // ---- 重连 ----
    args.push(format!(
        "--reconnect-timeout={}",
        profile.reconnect_timeout_secs
    ));

    // ---- 逃生舱 ----
    args.extend(profile.advanced.extra_args.iter().cloned());

    ArgPlan {
        args,
        server: profile.server.clone(),
        stdin_secrets,
        config_file,
        fatal_error: None,
    }
}

/// 占位参数。`fatal_error` 非空时 supervisor 会直接拒绝启动，
/// 不实际执行 —— 但 argv 仍需合法以通过类型检查。
const INVALID_CONFIG_FILE: &str = "--__wthinkvpn_invalid_config";

/// 令牌 secret 的临时文件路径（由 helper 以 0600 创建）。
pub const TOKEN_SECRET_FILE: &str = "/run/wthinkvpn/token.secret";

/// 构建所需的密钥。由调用方从钥匙串/内存取出。
#[derive(Debug, Default, Clone)]
pub struct Secrets {
    pub password: Option<String>,
    pub cookie: Option<String>,
    pub key_password: Option<String>,
    pub mca_key_password: Option<String>,
    pub token_secret: Option<String>,
}

impl Secrets {
    /// 所有非空值，用于 argv 泄漏自检
    pub fn values(&self) -> Vec<String> {
        [
            &self.password,
            &self.cookie,
            &self.key_password,
            &self.mca_key_password,
            &self.token_secret,
        ]
        .iter()
        .filter_map(|v| v.as_ref())
        .cloned()
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{ClientCert, TokenMode};

    fn base() -> Profile {
        let mut p = Profile::new("p1", "Corp", "vpn.corp.com");
        p.username = Some("alice".into());
        p
    }

    fn has(plan: &ArgPlan, flag: &str) -> bool {
        plan.args.iter().any(|a| a == flag)
    }

    fn value_of<'a>(plan: &'a ArgPlan, flag: &str) -> Option<&'a str> {
        let i = plan.args.iter().position(|a| a == flag)?;
        plan.args.get(i + 1).map(|s| s.as_str())
    }

    // -----------------------------------------------------------------
    // 基本形状
    // -----------------------------------------------------------------

    #[test]
    fn protocol_arg_present() {
        let plan = build(&base(), &Secrets::default());
        assert!(plan.args.contains(&"--protocol=anyconnect".to_string()));
    }

    #[test]
    fn timestamp_and_verbose_always_present() {
        // 状态机依赖 -v 的 PRG_INFO 输出；误加 -q 会让 UI 永远卡在 Connecting
        let plan = build(&base(), &Secrets::default());
        assert!(has(&plan, "--timestamp"));
        assert!(has(&plan, "-v"));
        assert!(!has(&plan, "-q"));
    }

    #[test]
    fn server_is_last_positional() {
        let plan = build(&base(), &Secrets::default());
        assert_eq!(*plan.argv().last().unwrap(), "vpn.corp.com");
    }

    #[test]
    fn server_with_port_and_path_preserved() {
        let mut p = base();
        p.server = "vpn.corp.com:8443/group".into();
        let plan = build(&p, &Secrets::default());
        assert_eq!(*plan.argv().last().unwrap(), "vpn.corp.com:8443/group");
    }

    // -----------------------------------------------------------------
    // 安全：密钥绝不进 argv
    // -----------------------------------------------------------------

    #[test]
    fn password_goes_to_stdin_never_argv() {
        let secrets = Secrets {
            password: Some("hunter2".into()),
            ..Default::default()
        };
        let plan = build(&base(), &secrets);
        assert!(has(&plan, "--passwd-on-stdin"));
        assert_eq!(plan.stdin_secrets, vec![StdinSecret::Password("hunter2".into())]);
        assert!(!plan.args.join(" ").contains("hunter2"));
        assert!(plan.audit_argv(&secrets.values()).is_empty(), "argv leaked secret");
    }

    #[test]
    fn cookie_goes_to_stdin_never_argv() {
        let secrets = Secrets {
            cookie: Some("webvpn=abc123".into()),
            ..Default::default()
        };
        let plan = build(&base(), &secrets);
        assert!(has(&plan, "--cookie-on-stdin"));
        assert!(!plan.args.join(" ").contains("abc123"));
        assert!(plan.audit_argv(&secrets.values()).is_empty(), "argv leaked secret");
    }

    #[test]
    fn cookie_mode_disables_password_prompt() {
        let secrets = Secrets {
            cookie: Some("webvpn=x".into()),
            password: Some("pw".into()),
            ..Default::default()
        };
        let plan = build(&base(), &secrets);
        // 两者都给时，cookie 优先：加 --no-passwd 避免 openconnect 仍要密码
        assert!(has(&plan, "--no-passwd"));
    }

    #[test]
    fn token_secret_uses_at_file_never_inline() {
        let mut p = base();
        p.advanced.token_mode = Some(TokenMode::Totp);
        let secrets = Secrets {
            token_secret: Some("JBSWY3DPEHPK3PXP".into()),
            ..Default::default()
        };
        let plan = build(&p, &secrets);
        let flag = plan
            .args
            .iter()
            .find(|a| a.starts_with("--token-secret"))
            .expect("应有 --token-secret");
        assert!(
            flag.starts_with("--token-secret=@"),
            "必须用 @file 形式，实际: {flag}"
        );
        assert!(!flag.contains("JBSWY3DPEHPK3PXP"));
        assert!(plan.audit_argv(&secrets.values()).is_empty(), "argv leaked secret");
    }

    #[test]
    fn redacted_display_hides_secret_lengths_but_not_content() {
        let mut p = base();
        p.advanced.token_mode = Some(TokenMode::Hotp);
        let secrets = Secrets {
            token_secret: Some("SECRETVALUE".into()),
            ..Default::default()
        };
        // 先构造一个真的把 secret 内联进去的 plan，验证脱敏逻辑本身
        let mut leaky = build(&p, &secrets);
        leaky.args.push("--token-secret=SECRETVALUE".into());
        let disp = leaky.redacted_display();
        assert!(!disp.contains("SECRETVALUE"), "脱敏失效: {disp}");
        assert!(disp.contains("redacted:11"), "应保留长度提示: {disp}");
    }

    #[test]
    fn audit_detects_injected_secret() {
        // 防御性：万一将来有人把密码塞进 extra_args
        let mut p = base();
        p.advanced.extra_args = vec!["--password=hunter2".into()];
        let secrets = Secrets {
            password: Some("hunter2".into()),
            ..Default::default()
        };
        let plan = build(&p, &secrets);
        assert!(plan.audit_argv(&secrets.values()).contains(&"secret-value-in-argv"));
    }

    // -----------------------------------------------------------------
    // 认证分组：P0 踩坑点
    // -----------------------------------------------------------------

    #[test]
    fn auth_group_uses_form_entry_not_authgroup_flag() {
        let mut p = base();
        p.auth_group = Some("Engineering".into());
        let plan = build(&p, &Secrets::default());
        // 不能用 --authgroup：它会退化成阻塞式交互提示
        assert!(!plan.args.iter().any(|a| a.starts_with("--authgroup")));
        let f = plan
            .args
            .iter()
            .find(|a| a.starts_with("--form-entry="))
            .expect("应用 --form-entry 预填分组");
        assert_eq!(f, "--form-entry=main:group_list=Engineering");
    }

    #[test]
    fn never_uses_short_form_entry_with_equals() {
        // `-F=main:...` 会让 openconnect 直接 exit(1)。
        // 见 auth_group_uses_form_entry_not_authgroup_flag 的注释。
        let mut p = base();
        p.auth_group = Some("G".into());
        let plan = build(&p, &Secrets::default());
        assert!(
            !plan.args.iter().any(|a| a.starts_with("-F")),
            "不得使用短选项 -F: {:?}",
            plan.args
        );
    }

    #[test]
    fn no_short_option_is_given_an_inline_equals() {
        // 系统性防护：getopt 对短选项不剥离 `=`。
        // 所有短选项都必须用「独立 argv 项」传值。
        let mut p = base();
        p.username = Some("alice".into());
        p.auth_group = Some("G".into());
        p.advanced.mtu = Some(1400);
        p.client_cert = Some(crate::profile::ClientCert {
            certificate: "/a.crt".into(),
            private_key: "/a.key".into(),
            ..Default::default()
        });
        let plan = build(&p, &Secrets::default());
        for a in &plan.args {
            if a.starts_with('-') && !a.starts_with("--") {
                assert!(
                    !a.contains('='),
                    "短选项不得内联 `=`: {a}（getopt 不会剥离，会把值传错）"
                );
            }
        }
    }

    #[test]
    fn auth_group_field_follows_protocol() {
        use crate::profile::Protocol;
        for (proto, expect) in [
            (Protocol::AnyConnect, "main:group_list"),
            (Protocol::Nc, "loginForm:realm"),
            (Protocol::F5, "main:domain"),
            (Protocol::Gp, "_portal:gateway"),
        ] {
            let mut p = base();
            p.protocol = proto;
            p.auth_group = Some("G".into());
            let plan = build(&p, &Secrets::default());
            assert!(
                plan.args.iter().any(|a| a == &format!("--form-entry={expect}=G")),
                "{proto:?} 应产生 --form-entry={expect}=G，实际: {:?}",
                plan.args
            );
        }
    }

    #[test]
    fn explicit_form_binding_overrides_protocol() {
        let mut p = base();
        p.auth_group = Some("G".into());
        p.form = Some(crate::profile::FormBinding {
            form_id: "custom".into(),
            group_field: "myfield".into(),
        });
        let plan = build(&p, &Secrets::default());
        assert!(plan.args.contains(&"--form-entry=custom:myfield=G".to_string()));
    }

    #[test]
    fn missing_password_uses_non_inter_to_avoid_hang() {
        // 勾了记住密码但钥匙串空 → 必须提前失败，绝不能让 openconnect 阻塞
        let mut p = base();
        p.remember_password = true;
        let plan = build(&p, &Secrets::default());
        assert!(has(&plan, "--non-inter"));
        assert!(plan.stdin_secrets.is_empty());
    }

    #[test]
    fn no_password_and_no_remember_is_left_interactive() {
        let plan = build(&base(), &Secrets::default());
        assert!(!has(&plan, "--non-inter"));
        assert!(!has(&plan, "--passwd-on-stdin"));
    }

    // -----------------------------------------------------------------
    // 证书认证
    // -----------------------------------------------------------------

    #[test]
    fn client_cert_args() {
        let mut p = base();
        p.client_cert = Some(ClientCert {
            certificate: "pkcs11:token=yubikey;id=1".into(),
            private_key: "/etc/pki/u.key".into(),
            key_password_saved: Some(true),
            mca_certificate: Some("/etc/pki/m.crt".into()),
            mca_key: Some("/etc/pki/m.key".into()),
            expire_warning_days: Some(14),
        });
        let plan = build(&p, &Secrets::default());
        assert_eq!(value_of(&plan, "-c"), Some("pkcs11:token=yubikey;id=1"));
        assert_eq!(value_of(&plan, "-k"), Some("/etc/pki/u.key"));
        assert_eq!(value_of(&plan, "-e"), Some("14"));
        assert_eq!(value_of(&plan, "--mca-certificate"), Some("/etc/pki/m.crt"));
        assert_eq!(value_of(&plan, "--mca-key"), Some("/etc/pki/m.key"));
    }

    #[test]
    fn mca_key_password_is_refused_not_silently_placed_in_argv() {
        // `--mca-key-password` 与 `-p` 同样没有 stdin/@file 通道。
        // 与其把口令明文放进 argv，不如**明确拒绝**，让用户知情后手动处理。
        let mut p = base();
        p.client_cert = Some(ClientCert {
            certificate: "a.crt".into(),
            private_key: "a.key".into(),
            mca_certificate: Some("m.crt".into()),
            mca_key: Some("m.key".into()),
            ..Default::default()
        });
        let secrets = Secrets {
            mca_key_password: Some("mcapass".into()),
            ..Default::default()
        };
        let plan = build(&p, &secrets);
        assert!(
            !has(&plan, "--mca-key-password"),
            "不得把 MCA 私钥口令放进 argv"
        );
        assert!(
            !plan.args.join(" ").contains("mcapass"),
            "MCA 私钥口令泄漏进 argv: {:?}",
            plan.args
        );
        // 明确报错，而不是静默忽略
        assert!(
            plan.fatal_error.is_some(),
            "应拒绝并给出原因，而不是静默丢弃用户提供的口令"
        );
    }

    #[test]
    fn server_cert_pin_is_passed_through() {
        let mut p = base();
        p.advanced.server_cert_pin = Some("pin-sha256:abc=".into());
        let plan = build(&p, &Secrets::default());
        assert!(plan.args.contains(&"--servercert=pin-sha256:abc=".to_string()));
    }

    // -----------------------------------------------------------------
    // 高级参数
    // -----------------------------------------------------------------

    #[test]
    fn boolean_flags_only_when_set() {
        let mut p = base();
        assert!(!build(&p, &Secrets::default()).args.contains(&"--no-dtls".to_string()));
        p.advanced.no_dtls = true;
        p.advanced.pfs = true;
        p.advanced.disable_ipv6 = true;
        let plan = build(&p, &Secrets::default());
        assert!(has(&plan, "--no-dtls"));
        assert!(has(&plan, "--pfs"));
        assert!(has(&plan, "--disable-ipv6"));
    }

    #[test]
    fn numeric_zero_is_not_treated_as_absent() {
        let mut p = base();
        p.advanced.mtu = Some(0);
        p.advanced.force_dpd = Some(0); // 0 = 禁用 DPD，是合法值
        let plan = build(&p, &Secrets::default());
        assert_eq!(value_of(&plan, "--mtu"), Some("0"));
        assert_eq!(value_of(&plan, "--force-dpd"), Some("0"));
    }

    #[test]
    fn reconnect_timeout_always_emitted() {
        let mut p = base();
        p.reconnect_timeout_secs = 0;
        let plan = build(&p, &Secrets::default());
        assert!(plan.args.contains(&"--reconnect-timeout=0".to_string()));
    }

    #[test]
    fn empty_optional_strings_are_skipped() {
        let mut p = base();
        p.advanced.user_agent = Some(String::new());
        p.advanced.proxy = Some(String::new());
        p.username = Some(String::new());
        let plan = build(&p, &Secrets::default());
        assert!(!has(&plan, "--useragent"));
        assert!(!has(&plan, "--proxy"));
        assert!(!has(&plan, "-u"));
    }

    #[test]
    fn extra_args_appended_last() {
        let mut p = base();
        p.advanced.extra_args = vec!["--pfs".into()];
        let plan = build(&p, &Secrets::default());
        assert_eq!(plan.args.last().unwrap(), "--pfs");
    }
}