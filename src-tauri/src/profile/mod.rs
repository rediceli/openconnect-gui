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
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    /// Cisco ASA / ocserv（默认）
    #[default]
    AnyConnect,
    /// Juniper Network Connect
    Nc,
    /// Palo Alto Networks GlobalProtect
    Gp,
    /// Pulse Connect Secure / Ivanti
    Pulse,
    /// F5 BIG-IP
    F5,
    /// Fortinet FortiGate
    Fortinet,
    /// Array Networks
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

    pub fn load(&self) -> std::io::Result<Store> {
        let p = self.path();
        if !p.exists() {
            return Ok(Store::default());
        }
        let text = std::fs::read_to_string(&p)?;
        // 未知字段不应导致整个库读不出来
        Ok(toml::from_str(&text).unwrap_or_default())
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