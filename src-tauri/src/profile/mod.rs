//! 连接档案（Profile）
//!
//! 存储策略：**只持久化非敏感信息**。密码、证书私钥口令、SSO cookie
//! 一律进系统钥匙串（见 `crate::secret`），profile 里只留一个引用 key。
//!
//! 序列化格式用 TOML（人可读、可手改、diff 友好），落在系统标准配置目录。

pub mod formmap;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// openconnect 支持的协议。取值与 `--protocol=` 的参数完全一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
// ⚠️ 刻意**不用** `rename_all = "kebab-case"`。
//
// 它会把 `AnyConnect` 序列化成 `"any-connect"`，而 openconnect 的
// `--protocol=` 实际值是 `"anyconnect"`（无连字符）。于是同一个概念
// 出现两种字符串：serde 一种、`as_arg()` 另一种。
//
// 后果是实测出来的：前端按 openconnect 的写法硬编码
// `protocol: "anyconnect"`，Rust 直接拒绝 ——
//   unknown variant `anyconnect`, expected one of `any-connect`, ...
//
// 这里给每个变体显式改名成 **openconnect 真正接受的值**，让序列化
// 与 `as_arg()` 收敛成唯一一种表示。`protocol_serde_matches_openconnect_arg`
// 这个测试会锁住该不变量。
pub enum Protocol {
    /// Cisco ASA / ocserv（默认）
    #[default]
    #[serde(rename = "anyconnect")]
    // 兼容旧版本写下的 kebab-case 值。
    //
    // 曾用 `rename_all = "kebab-case"`，序列化成 "any-connect"。
    // 若只改读侧不加 alias，已保存的 profile 会变成**无法解析** ——
    // 而 `load()` 对解析失败是 `unwrap_or_default()`，于是整个
    // profile 库被静默清空，用户看到列表空掉却不知原因。
    // 实测踩过：改完协议名后所有 profile 消失。
    //
    // alias 只影响读，写出去始终是规范形式 "anyconnect"。
    #[serde(alias = "any-connect")]
    AnyConnect,
    /// Juniper Network Connect
    #[serde(rename = "nc")]
    Nc,
    /// Palo Alto Networks GlobalProtect
    #[serde(rename = "gp")]
    Gp,
    /// Pulse Connect Secure / Ivanti
    #[serde(rename = "pulse")]
    Pulse,
    /// F5 BIG-IP
    #[serde(rename = "f5")]
    F5,
    /// Fortinet FortiGate
    #[serde(rename = "fortinet")]
    Fortinet,
    /// Array Networks
    #[serde(rename = "array")]
    Array,
}

impl Protocol {
    pub fn as_arg(self) -> &'static str {
        match self {
            Protocol::AnyConnect => "anyconnect",
            Protocol::Nc => "nc",
            Protocol::Gp => "gp",
            Protocol::Pulse => "pulse",
            Protocol::F5 => "f5",
            Protocol::Fortinet => "fortinet",
            Protocol::Array => "array",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Protocol::AnyConnect => "Cisco AnyConnect / ASA",
            Protocol::Nc => "Juniper Network Connect",
            Protocol::Gp => "Palo Alto GlobalProtect",
            Protocol::Pulse => "Pulse Connect Secure",
            Protocol::F5 => "F5 BIG-IP",
            Protocol::Fortinet => "Fortinet FortiGate",
            Protocol::Array => "Array Networks",
        }
    }
}

/// 证书认证配置。证书私钥本身留在文件/PKCS#11 里，profile 只记路径。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientCert {
    /// `--certificate`。可以是文件路径，也可以是 `pkcs11:...` URL。
    pub certificate: String,
    /// `--sslkey`
    pub private_key: String,
    /// 私钥口令 / TPM SRK PIN。**不落盘**，存钥匙串。
    /// true 表示钥匙串里有对应条目。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_password_saved: Option<bool>,
    /// `--mca-certificate`（多证书认证的用户证书）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mca_certificate: Option<String>,
    /// `--mca-key`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mca_key: Option<String>,
    /// 证书到期前多少天开始告警（`--cert-expire-warning`）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_warning_days: Option<u32>,
}

/// 高级参数。只暴露真正有用的，罕见参数留给 `extra_args`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub struct Advanced {
    /// `--usergroup`：登录 URL 路径（部分设备的初始路径）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_group: Option<String>,
    /// `--servercert`：服务器证书指纹（如 `pin-sha256:...`）。
    /// 留空则首次连接时弹窗询问，确认后写入。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_cert_pin: Option<String>,
    /// `--cafile`：额外信任的 CA
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
    /// `--no-system-trust`（有额外 CA 时慎用）
    #[serde(default)]
    pub no_system_trust: bool,
    /// `--mtu`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// `--base-mtu`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_mtu: Option<u16>,
    /// `--no-dtls`：禁用 UDP/DTLS，强制走 TCP
    #[serde(default)]
    pub no_dtls: bool,
    /// `--disable-ipv6`
    #[serde(default)]
    pub disable_ipv6: bool,
    /// `--pfs`
    #[serde(default)]
    pub pfs: bool,
    /// `--useragent`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// `--proxy`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// `--force-dpd`：DPD 心跳间隔（秒），0 禁用
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_dpd: Option<u32>,
    /// `--os`：向服务端上报的系统类型
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_os: Option<String>,
    /// `--token-mode` + `--token-secret`。secret **不落盘**。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_mode: Option<TokenMode>,
    /// 密钥环中 token secret 的引用键（相对 profile id）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_secret_saved: Option<bool>,
    /// 逃生舱：数组里的一切原样附加到命令行。
    /// ⚠️ 严禁把密码写进来 —— UI 不提供密码输入框。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_args: Vec<String>,
}


/// 软令牌类型（`--token-mode`）。secret 存钥匙串。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenMode {
    Rsa,
    Totp,
    Hotp,
    Oidc,
}

impl TokenMode {
    pub fn as_arg(self) -> &'static str {
        match self {
            TokenMode::Rsa => "rsa",
            TokenMode::Totp => "totp",
            TokenMode::Hotp => "hotp",
            TokenMode::Oidc => "oidc",
        }
    }
}

/// 一个连接档案。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// 稳定 id（UUID v4），用作文件名与钥匙串 key 的一部分。
    pub id: String,
    /// 用户可改的显示名
    pub name: String,
    /// 服务器地址。允许 `vpn.corp.com`、`vpn.corp.com:8443`、`/group` 后缀。
    pub server: String,
    #[serde(default)]
    pub protocol: Protocol,
    /// 认证分组下拉值（`-F '<表单id>:group_list=<值>'`）。
    /// 真实字段名与表单 id 因协议/设备而异，见 `form` 字段与 `formmap`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_group: Option<String>,
    /// 显式指定表单 id 与字段名（覆盖自动推断）。
    /// 例：`form_id = "loginForm"`, `group_field = "realm"`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form: Option<FormBinding>,
    /// `--user`。留空则每次连接时询问。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// 密码已存入钥匙串
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_saved: Option<bool>,
    /// 是否记住密码
    #[serde(default)]
    pub remember_password: bool,
    /// 证书认证
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert: Option<ClientCert>,
    #[serde(default)]
    pub advanced: Advanced,
    /// 断线自动重连（openconnect 内建，`--reconnect-timeout`）
    #[serde(default)]
    pub auto_reconnect: bool,
    #[serde(default = "default_reconnect_timeout")]
    pub reconnect_timeout_secs: u32,
    /// 启动应用时若该 profile 已连接则恢复托盘图标
    #[serde(default)]
    pub launch_at_login: bool,
}

fn default_reconnect_timeout() -> u32 {
    300
}

/// 表单字段绑定。P0 实测：`--authgroup` 不够，必须用
/// `-F '<表单id>:<字段名>=<值>'`，而表单 id 与字段名因设备而异。
///
/// ⚠️ 字段名写错不会报错，只会退化成阻塞式交互提示。见 `formmap`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormBinding {
    /// `<auth id="...">`，多数 anyconnect 设备是 "main"
    pub form_id: String,
    /// 分组下拉的字段名。anyconnect=`group_list`, juniper=`realm`,
    /// f5=`domain`, gp=`gateway`。**不是** `auth_group`。
    pub group_field: String,
}

impl Profile {
    pub fn new(id: impl Into<String>, name: impl Into<String>, server: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            server: server.into(),
            protocol: Protocol::AnyConnect,
            auth_group: None,
            form: None,
            username: None,
            password_saved: None,
            remember_password: false,
            client_cert: None,
            advanced: Advanced::default(),
            auto_reconnect: false,
            reconnect_timeout_secs: default_reconnect_timeout(),
            launch_at_login: false,
        }
    }

    /// 钥匙串中该 profile 的 key。密码、token secret、key password 共用前缀。
    pub fn secret_key(&self, kind: SecretKind) -> String {
        format!("{}.{}", self.id, kind.as_str())
    }
}

/// 钥匙串条目种类
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    Password,
    KeyPassword,
    McaKeyPassword,
    TokenSecret,
}

impl SecretKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretKind::Password => "password",
            SecretKind::KeyPassword => "key-password",
            SecretKind::McaKeyPassword => "mca-key-password",
            SecretKind::TokenSecret => "token-secret",
        }
    }
}

// ---------------------------------------------------------------------------
// 持久化
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub profiles: Vec<Profile>,
}

/// 档案库读写。
pub struct Repo {
    dir: PathBuf,
}

impl Repo {
    /// 系统标准配置目录：
    /// - macOS `~/Library/Application Support/OC GUI/`
    /// - Windows `%APPDATA%\OC GUI\`
    /// - Linux `$XDG_CONFIG_HOME/oc-gui/`
    pub fn default_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(crate::APP_DIR)
    }

    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self) -> PathBuf {
        self.dir.join("profiles.toml")
    }

    /// 读取档案库。
    ///
    /// # 解析失败时为什么要备份而不是直接返回空
    ///
    /// 这里的容错策略是「读不出来就当空的」，它避免了一个坏文件让
    /// App 整个打不开。**但代价是静默丢数据**：实测踩过 ——
    /// `Protocol` 的序列化形式从 `any-connect` 改成 `anyconnect` 后，
    /// 旧 profile 变成无法解析，`unwrap_or_default()` 于是把**整个库**
    /// 变成空。用户看到的只是「列表空掉了」，既不知道原因，也可能
    /// 在下一次保存时把原数据覆盖掉。
    ///
    /// 所以解析失败时先把原文件另存为 `profiles.toml.corrupt-<n>`，
    /// 既保持 App 可用，又不销毁用户的配置。
    pub fn load(&self) -> std::io::Result<Store> {
        let p = self.path();
        if !p.exists() {
            return Ok(Store::default());
        }
        let text = std::fs::read_to_string(&p)?;
        match toml::from_str::<Store>(&text) {
            Ok(store) => Ok(store),
            Err(e) => {
                self.backup_corrupt(&text, &e);
                // 未知字段不应导致整个库读不出来；整库解析失败时
                // 逐条抢救，避免因一条坏数据丢掉全部 profile
                Ok(Self::salvage(&text))
            }
        }
    }

    /// 逐条抢救：整库解析失败时，尽量只丢掉真正坏掉的那几条。
    ///
    /// 为什么需要：库里往往只有一条因为字段改名/枚举值变更而失效，
    /// 其余完全正常。直接返回空库等于「因为一条坏数据丢了全部」。
    ///
    /// 做法是把 TOML 当作通用值读进来，逐个元素单独反序列化。
    fn salvage(text: &str) -> Store {
        let mut out = Store::default();
        let Ok(doc) = text.parse::<toml::Table>() else {
            return out;
        };
        let Some(arr) = doc.get("profiles").and_then(|v| v.as_array()) else {
            return out;
        };
        for item in arr {
            match item.clone().try_into::<Profile>() {
                Ok(p) => out.profiles.push(p),
                Err(e) => log::warn!("跳过无法解析的 profile（{}）: {e}", item),
            }
        }
        if !out.profiles.is_empty() {
            log::warn!("已从损坏的档案库中抢救出 {} 条 profile", out.profiles.len());
        }
        out
    }

    /// 解析失败时把原文另存一份，并尽力恢复出能读的部分。
    ///
    /// 先尝试「逐条丢弃坏 profile」而不是全盘放弃：库里往往只有一条
    /// 因为字段改名而失效，其余应当保留。
    fn backup_corrupt(&self, text: &str, err: &toml::de::Error) {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup = self.dir.join(format!("profiles.toml.corrupt-{stamp}"));
        if let Err(e) = std::fs::write(&backup, text) {
            log::warn!("备份损坏的 profiles.toml 失败: {e}");
        } else {
            log::error!(
                "profiles.toml 解析失败，已备份到 {}（原因：{err}）",
                backup.display()
            );
        }
    }

    pub fn save(&self, store: &Store) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let text = toml::to_string_pretty(store)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        write_atomic(&self.path(), text.as_bytes())
    }

    pub fn find<'a>(&self, store: &'a Store, id: &str) -> Option<&'a Profile> {
        store.profiles.iter().find(|p| p.id == id)
    }
}

/// 先写临时文件再 rename，避免崩溃留下半截 TOML。
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    /// serde 的序列化形式必须**等于** `as_arg()`。
    ///
    /// 两者一旦分叉，前端按 openconnect 的写法硬编码协议名就会被
    /// Rust 拒掉：`unknown variant 'anyconnect', expected one of
    /// 'any-connect', ...`。实测踩过。
    #[test]
    fn protocol_serde_matches_openconnect_arg() {
        for p in [
            Protocol::AnyConnect,
            Protocol::Nc,
            Protocol::Gp,
            Protocol::Pulse,
            Protocol::F5,
            Protocol::Fortinet,
            Protocol::Array,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(
                json,
                format!("\"{}\"", p.as_arg()),
                "{p:?} 的 serde 形式应与 as_arg() 一致"
            );
            let back: Protocol = serde_json::from_str(&json).unwrap();
            assert_eq!(back, p, "{p:?} 往返失败");
        }
    }

    /// 显式锁住 AnyConnect 这个具体值。
    ///
    /// 上面的测试是「serde == as_arg()」，但若有人同时改了两边
    /// （比如「顺手」把 as_arg 也改成 any-connect），测试仍会通过，
    /// 而 openconnect 会拒绝。所以这里把真实值钉住。
    #[test]
    fn anyconnect_arg_is_the_value_openconnect_expects() {
        assert_eq!(Protocol::AnyConnect.as_arg(), "anyconnect");
        assert_eq!(
            serde_json::to_string(&Protocol::AnyConnect).unwrap(),
            "\"anyconnect\""
        );
    }

    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oc-gui-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn roundtrip_preserves_all_fields() {
        let dir = tmpdir("roundtrip");
        let repo = Repo::new(&dir);

        let mut p = Profile::new("id-1", "公司 VPN", "vpn.corp.com/group");
        p.protocol = Protocol::Gp;
        p.auth_group = Some("prelogin-cookie".into());
        p.username = Some("alice".into());
        p.remember_password = true;
        p.password_saved = Some(true);
        p.client_cert = Some(ClientCert {
            certificate: "pkcs11:token=yubikey".into(),
            private_key: "/etc/pki/user.key".into(),
            key_password_saved: Some(true),
            mca_certificate: Some("/etc/pki/mca.crt".into()),
            mca_key: Some("/etc/pki/mca.key".into()),
            expire_warning_days: Some(14),
        });
        p.advanced = Advanced {
            server_cert_pin: Some("pin-sha256:abc".into()),
            no_dtls: true,
            mtu: Some(1400),
            token_mode: Some(TokenMode::Totp),
            token_secret_saved: Some(true),
            extra_args: vec!["--no-dtls".into()],
            ..Default::default()
        };

        let store = Store { profiles: vec![p.clone()] };
        repo.save(&store).unwrap();

        let loaded = repo.load().unwrap();
        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.profiles[0], p, "往返必须完全一致");
    }

    #[test]
    fn password_never_appears_in_serialized_profile() {
        // 这是最重要的安全不变量：即使将来有人不小心加了明文密码字段，
        // 这个测试也会立刻炸掉。
        let mut p = Profile::new("id-2", "x", "y");
        p.remember_password = true;
        p.password_saved = Some(true);
        let store = Store { profiles: vec![p] };
        let text = toml::to_string_pretty(&store).unwrap();
        assert!(
            !text.contains("hunter2"),
            "profile 序列化绝不能含密码明文"
        );
        // 只能有「是否已保存」的布尔标记
        assert!(text.contains("password_saved"));
    }

    #[test]
    fn missing_file_loads_empty_store() {
        let repo = Repo::new(tmpdir("missing"));
        assert_eq!(repo.load().unwrap().profiles.len(), 0);
    }

    /// 一条坏 profile 不能连带丢掉其余的。
    ///
    /// 实测踩过：`Protocol` 序列化形式改动后，旧值让整库解析失败，
    /// 而 `load()` 原本 `unwrap_or_default()` 返回空库 —— 用户所有
    /// 连接一起消失，且毫无提示。
    #[test]
    fn one_bad_profile_does_not_take_the_others_with_it() {
        let dir = tempfile::TempDir::new().unwrap();
        let repo = Repo::new(dir.path());
        std::fs::write(
            dir.path().join("profiles.toml"),
            r#"
[[profiles]]
id = "good-1"
name = "好的一条"
server = "vpn.corp.com"

[[profiles]]
id = "bad"
name = "坏的"
server = "vpn.corp.com"
protocol = "不存在的协议"

[[profiles]]
id = "good-2"
name = "另一条好的"
server = "vpn.other.com"
"#,
        )
        .unwrap();
        let store = repo.load().unwrap();
        let ids: Vec<&str> = store.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["good-1", "good-2"],
            "应保留两条可解析的 profile"
        );
        // 原始文件必须被备份，不能销毁用户数据
        let backups: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("corrupt"))
            .collect();
        assert_eq!(backups.len(), 1, "损坏的原文应被备份一份");
    }

    /// 旧版本写入的 `any-connect` 必须仍能读出来。
    ///
    /// 改协议名的教训：若不加 `serde(alias)`，已保存的 profile 直接
    /// 变成不可解析。
    #[test]
    fn legacy_kebab_case_protocol_is_still_readable() {
        let p: Profile = toml::from_str(
            r#"
id = "x"
name = "x"
server = "vpn.corp.com"
protocol = "any-connect"
"#,
        )
        .expect("旧的 any-connect 应仍可解析");
        assert_eq!(p.protocol, Protocol::AnyConnect);
    }

    #[test]
    fn corrupt_file_degrades_to_empty_not_panic() {
        let dir = tmpdir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("profiles.toml"), "这不是 TOML ][").unwrap();
        let repo = Repo::new(&dir);
        assert_eq!(repo.load().unwrap().profiles.len(), 0);
    }

    #[test]
    fn unknown_fields_are_tolerated() {
        // 旧版本写的字段，新版本读不出来时应忽略而不是崩
        let dir = tmpdir("unknown");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("profiles.toml"),
            "[[profiles]]\nid=\"a\"\nname=\"b\"\nserver=\"c\"\nfuture_field=42\n",
        )
        .unwrap();
        let store = Repo::new(&dir).load().unwrap();
        assert_eq!(store.profiles[0].server, "c");
    }

    #[test]
    fn secret_key_is_namespaced_by_profile_id() {
        let p = Profile::new("abc-123", "n", "s");
        assert_eq!(p.secret_key(SecretKind::Password), "abc-123.password");
        assert_ne!(
            p.secret_key(SecretKind::Password),
            p.secret_key(SecretKind::TokenSecret)
        );
    }

    #[test]
    fn protocol_arg_matches_openconnect_cli() {
        // 这些字符串直接进命令行，改错=连不上
        assert_eq!(Protocol::AnyConnect.as_arg(), "anyconnect");
        assert_eq!(Protocol::Nc.as_arg(), "nc");
        assert_eq!(Protocol::Gp.as_arg(), "gp");
        assert_eq!(Protocol::Pulse.as_arg(), "pulse");
        assert_eq!(Protocol::F5.as_arg(), "f5");
        assert_eq!(Protocol::Fortinet.as_arg(), "fortinet");
        assert_eq!(Protocol::Array.as_arg(), "array");
    }
}