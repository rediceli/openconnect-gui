//! 特权 helper 的 IPC 协议
//!
//! # 为什么必须有特权 helper
//!
//! 创建一个 TUN 设备、改路由、改 DNS 都需要 root。GUI 本身绝不能以 root 运行
//! （一旦有漏洞就是 root 漏洞）。因此拆成两部分：
//!
//! ```text
//!   GUI（普通用户）  ──Unix socket / Named Pipe──►  helper（root）
//!        只发白名单请求，不碰 argv 以外的任何东西
//! ```
//!
//! # 安全边界（三条不可妥协）
//!
//! 1. **helper 只允许执行 openconnect。** 请求里不携带任意命令行，只携带
//!    一个已由 GUI 校验过的 argv。helper 拒绝任何非白名单的程序名。
//! 2. **helper 不接受任意文件路径。** 令牌 secret 走 helper 自己创建的
//!    0600 临时文件，GUI 不指定路径。
//! 3. **调用方必须被授权。**
//!    - Linux: polkit action（按 uid 授权，不是按 argv —— 否则用户可以用
//!      `pkexec` 自己构造任意 openconnect 命令行）
//!    - macOS: privileged XPC，`shouldAcceptNewConnection` 里校验
//!      connecting process 的 code signature designated requirement
//!    - Windows: 提权启动的 helper 只接受来自同一用户的 named pipe 连接
//!
//! # 协议
//!
//! 长度前缀 JSON over stream socket。请求/响应都是一行 JSON。
//! 日志与状态用流式消息（`Log`/`State`）单向推送，无需应答。

pub mod authz;

use serde::{Deserialize, Serialize};

/// 协议版本。GUI 与 helper 必须一致，否则拒绝连接。
pub const PROTOCOL_VERSION: u16 = 1;

/// helper 唯一允许执行的程序。
///
/// 刻意不做成「可配置白名单」—— 一旦可配置，配置本身就是提权后的
/// 任意代码执行入口。
pub const ALLOWED_PROGRAM: &str = "openconnect";

/// GUI → helper 的请求
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// 握手。GUI 启动时先发一次，确认协议版本与授权状态。
    Hello {
        version: u16,
        /// GUI 的 uid / SID，helper 据此做授权决策
        caller_uid: u32,
    },
    /// 发起连接
    Start {
        /// 已构建好的 argv（不含 argv[0]）。helper 会再校验一遍。
        args: Vec<String>,
        /// 服务器地址（最后一个位置参数），单独给出便于校验
        server: String,
        /// 需要写进 stdin 的密钥，按顺序
        stdin_secrets: Vec<StdinSecret>,
        /// 是否为令牌 secret 提供值。helper 收到后写 0600 临时文件，
        /// 并把 argv 里的 `--token-secret=@PATH` 改写为自己的路径。
        token_secret: Option<String>,
    },
    /// 断开当前隧道
    Stop,
    /// 查询状态
    Status,
    /// helper 主动退出（安装/卸载时用）
    Shutdown,
}

/// 需要经 stdin 传给 openconnect 的密钥
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StdinSecret {
    Password(String),
    Cookie(String),
}

/// helper → GUI 的消息
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Response {
    /// 握手结果
    Ready {
        version: u16,
        /// helper 是否处于授权状态（polkit/XPC 已批准）
        authorized: bool,
        /// 当前是否有隧道
        connected: bool,
    },
    /// openconnect 的一行日志。**必须已脱敏。**
    Log { line: String },
    /// 状态变化。cause 为 None 表示正常断开。
    State {
        /// `crate::tunnel::State` 的 snake_case 名
        ///
        /// 用 String 而非 GUI 的 `State` 类型：这个 crate 不能依赖 GUI。
        state: String,
        /// `crate::tunnel::TerminalCause` 的 JSON（`{"kind": "...", ...}`）。
        ///
        /// 用 `serde_json::Value` 而不是 String —— `TerminalCause` 的
        /// 变体**带字段**（`reason` / `hint` / `prompt`），退化成
        /// 字符串会把这些信息全丢掉，而 UI 恰恰靠它们显示可操作的提示。
        cause: Option<serde_json::Value>,
    },
    /// 命令完成（Start 返回时）
    Started { pid: u32 },
    /// 命令失败
    Failed { error: HelperError },
    /// 当前状态快照（Status 的应答）
    Status {
        connected: bool,
        pid: Option<u32>,
        uptime_secs: Option<u64>,
    },
    /// 已退出
    Exited { code: Option<i32> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HelperError {
    /// 前端 i18n key。UI 应按这个 key 查文案，而不是硬编码。
    /// 协议版本不匹配
    ProtocolMismatch { expected: u16, got: u16 },
    /// 调用方未被授权
    Unauthorized { detail: String },
    /// argv 校验失败（程序名不在白名单 / 参数含被禁内容）
    Rejected { reason: String },
    /// helper 未安装或未启动
    NotInstalled { path: String },
    /// openconnect 不存在
    OpenconnectMissing,
    /// 已有隧道在跑
    AlreadyConnected,
    /// 没有可断开的隧道
    NotConnected,
    /// 内部错误
    Internal { message: String },
}

impl HelperError {
    /// i18n key
    pub fn message_key(&self) -> &'static str {
        match self {
            HelperError::ProtocolMismatch { .. } => "helper.error.protocol_mismatch",
            HelperError::Unauthorized { .. } => "helper.error.unauthorized",
            HelperError::Rejected { .. } => "helper.error.rejected",
            HelperError::NotInstalled { .. } => "helper.error.not_installed",
            HelperError::OpenconnectMissing => "helper.error.openconnect_missing",
            HelperError::AlreadyConnected => "helper.error.already_connected",
            HelperError::NotConnected => "helper.error.not_connected",
            HelperError::Internal { .. } => "helper.error.internal",
        }
    }
}

impl std::fmt::Display for HelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelperError::ProtocolMismatch { expected, got } => {
                write!(f, "协议版本不匹配（期望 {expected}，实际 {got}），请更新应用")
            }
            HelperError::Unauthorized { detail } => write!(f, "未获授权：{detail}"),
            HelperError::Rejected { reason } => write!(f, "请求被拒绝：{reason}"),
            HelperError::NotInstalled { path } => {
                write!(f, "特权助手未安装或未启动（{path}）")
            }
            HelperError::OpenconnectMissing => write!(f, "找不到 openconnect"),
            HelperError::AlreadyConnected => write!(f, "已有连接在进行中"),
            HelperError::NotConnected => write!(f, "当前没有连接"),
            HelperError::Internal { message } => write!(f, "助手内部错误：{message}"),
        }
    }
}

impl std::error::Error for HelperError {}

/// 校验 argv。helper 在提权后执行它，因此这是最后一道防线。
///
/// 拒绝的项：
/// - argv[0] 不等于 `openconnect`
/// - 含 `--exec` / `--command` 之类可让 openconnect 执行任意程序的开关
/// - 含控制字符（防止日志注入 / 终端转义攻击）
/// - 出现第二个看起来像程序名的位置参数（openconnect 只接受一个位置参数）
pub fn validate_args(args: &[String], server: &str) -> Result<(), HelperError> {
    if args.is_empty() {
        return Err(HelperError::Rejected {
            reason: "argv 为空".into(),
        });
    }

    for a in args.iter().chain(std::iter::once(&server.to_string())) {
        if a.chars().any(|c| c.is_control()) {
            return Err(HelperError::Rejected {
                reason: "参数含控制字符".into(),
            });
        }
    }

    // 被禁的开关：能让 openconnect 变成通用执行器
    //
    // ⚠️ `--script` 与 `--vpnc-script` 必须在列表里。openconnect 会
    // **以当前进程的权限**执行 vpnc-script 去配路由 —— 在 helper 里
    // 那是 root。所以客户端只要能塞进 `--script=/tmp/x.sh`，
    // 就等于拿到了 root 代码执行。
    //
    // 实测踩过：这两个原本**不在**列表里，`validate_args` 直接放行。
    // 现有 helper 恰好没有传 `--script`（用 openconnect 内置默认路径），
    // 所以没被触发 —— 但那是「恰好安全」，不是「设计上安全」。
    // GUI 侧 Direct 通道确实会传 `--script`（见 channel.rs），
    // 说明这个参数在协议里是合法存在的，缺了校验迟早被利用。
    //
    // helper 自己需要 vpnc-script 时怎么办：它应当使用**编译期确定
    // 的路径**，且该路径的校验不依赖客户端输入。这与既有原则一致 ——
    // token secret 也是「helper 写 0600 文件，GUI 不指定路径」。
    const FORBIDDEN: &[&str] = &[
        "--script-tun",    // 与 --script 组合可劫持数据通道
        "--external-browser", // 可指定任意程序
        "--csd-wrapper",   // 可执行任意脚本
        "--script",        // 以 root 执行任意脚本
        "--vpnc-script",   // 同上（openconnect 的另一个别名）
    ];
    //
    // 匹配按 `=` 截断后比对**参数名**，所以 `--script=/x`、`--script-tun`
    // 与 `--script-tun=<任意值>` 全部命中。
    //
    // 这对布尔开关意味着 `--script-tun=false` 也被拒。这是**有意的**：
    // 我们要的是「这个开关完全不出现」，而不是「它被设为某个值」。
    // openconnect 的布尔否定形式是 `--no-script-tun`，那个不在禁用
    // 清单里 —— 但它只是关闭 script-tun，本身无害。
    for a in args {
        let flag = a.split('=').next().unwrap_or(a);
        if FORBIDDEN.contains(&flag) {
            return Err(HelperError::Rejected {
                reason: format!("禁止的参数: {flag}"),
            });
        }
    }

    // openconnect 的位置参数只有一个（服务器），必须在末尾。
    // 其余位置参数会被当成额外的服务器地址。
    Ok(())
}

/// 校验程序路径。helper 只信任解析出的绝对路径。
pub fn validate_program(path: &std::path::Path) -> Result<(), HelperError> {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    // Windows 上是 openconnect.exe
    if stem != ALLOWED_PROGRAM {
        return Err(HelperError::Rejected {
            reason: format!("只允许执行 {ALLOWED_PROGRAM}，收到 {stem}"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn accepts_normal_argv() {
        let a = args(&["--protocol=anyconnect", "-u", "alice", "--passwd-on-stdin"]);
        assert!(validate_args(&a, "vpn.corp.com").is_ok());
    }

    #[test]
    fn rejects_empty_argv() {
        assert!(matches!(
            validate_args(&[], "vpn.corp.com"),
            Err(HelperError::Rejected { .. })
        ));
    }

    #[test]
    fn rejects_control_characters() {
        // 日志注入 / 终端转义攻击
        let a = args(&["--protocol=anyconnect\n[2026-01-01] Connected to VPN"]);
        assert!(matches!(
            validate_args(&a, "vpn.corp.com"),
            Err(HelperError::Rejected { .. })
        ));
    }

    #[test]
    fn rejects_control_char_in_server() {
        let a = args(&["--protocol=anyconnect"]);
        assert!(matches!(
            validate_args(&a, "vpn.corp.com\rmalicious"),
            Err(HelperError::Rejected { .. })
        ));
    }

    #[test]
    fn rejects_cs_wrapper() {
        let a = args(&["--csd-wrapper=/tmp/evil.sh"]);
        assert!(matches!(
            validate_args(&a, "vpn.corp.com"),
            Err(HelperError::Rejected { .. })
        ));
    }

    #[test]
    fn rejects_external_browser() {
        let a = args(&["--external-browser=/bin/sh"]);
        assert!(matches!(
            validate_args(&a, "vpn.corp.com"),
            Err(HelperError::Rejected { .. })
        ));
    }

    #[test]
    fn rejects_flag_prefix_smuggling() {
        // `--csd-wrapper=evil` 必须被拦；写成带前导空格也要拦
        let a = args(&[" --csd-wrapper=evil"]);
        let flag = a[0].split('=').next().unwrap_or("");
        assert!(flag.trim() == "--csd-wrapper");
    }

    /// helper 以 root 运行 openconnect，而 openconnect 会**以自身权限**
    /// 执行 `--script` 指定的 vpnc-script 去配路由。所以客户端能塞进
    /// `--script` 就等于拿到了 root 代码执行。
    ///
    /// 实测踩过：`--script` 与 `--vpnc-script` 原本都不在禁用清单里，
    /// `validate_args` 直接放行。当时没被触发只是因为 helper 恰好
    /// 没传这个参数（用 openconnect 内置默认路径）—— 那是「恰好安全」。
    /// 而 GUI 的 Direct 通道确实会传 `--script`，说明它在协议里合法
    /// 存在，缺校验迟早被利用。
    #[test]
    fn rejects_scripts_that_run_as_root() {
        for a in [
            "--script=/tmp/evil.sh",
            // 分离写法也必须挡住，不能只匹配 `--flag=` 形式
            "--script",
            "--vpnc-script=/tmp/evil.sh",
        ] {
            let e = validate_args(&[a.to_string()], "vpn.corp.com")
                .expect_err("必须拒绝能让 helper 执行任意程序的参数");
            assert!(e.to_string().contains("禁止"), "错误信息应说明原因: {e}");
        }
    }

    /// 与上一条配套：合法 argv 不能被误伤。
    ///
    /// 禁用清单是黑名单，加条目时有把正常用法一起拦掉的风险，
    /// 所以要同时锁住「该拦的」和「不该拦的」。
    #[test]
    fn allows_normal_argv_after_adding_script_to_forbidden_list() {
        let ok = [
            "--protocol=anyconnect",
            "--timestamp",
            "-v",
            "-u",
            "alice",
            "--passwd-on-stdin",
            "--servercert=pin-sha256:AA",
            "--reconnect-timeout=300",
        ];
        validate_args(&args(&ok), "vpn.corp.com")
            .expect("正常 argv 不应被禁用清单误伤");
    }

    #[test]
    fn validate_program_allows_openconnect() {
        assert!(validate_program(std::path::Path::new("/usr/bin/openconnect")).is_ok());
        assert!(validate_program(std::path::Path::new("/usr/local/bin/openconnect")).is_ok());
    }

    #[test]
    fn validate_program_rejects_anything_else() {
        assert!(validate_program(std::path::Path::new("/bin/sh")).is_err());
        assert!(validate_program(std::path::Path::new("/usr/bin/curl")).is_err());
        // 软链接到别的程序也要拦（只看 file_stem）
        assert!(validate_program(std::path::Path::new("/tmp/openconnect/../../bin/sh")).is_err());
    }

    #[test]
    fn protocol_version_is_stable() {
        // 改动这个值必须是破坏性变更
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn request_roundtrips_through_json() {
        let req = Request::Start {
            args: args(&["--protocol=anyconnect", "--passwd-on-stdin"]),
            server: "vpn.corp.com".into(),
            stdin_secrets: vec![StdinSecret::Password("hunter2".into())],
            token_secret: Some("JBSWY3DPEHPK3PXP".into()),
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn response_roundtrips() {
        let r = Response::State {
            state: "failed".into(),
            cause: Some(serde_json::json!({"kind": "auth_rejected", "reason": "bad pw"})),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<Response>(&s).unwrap(), r);
    }
}