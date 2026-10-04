//! openconnect 配置文件生成（承载私钥口令）
//!
//! # 为什么需要这个文件
//!
//! openconnect 只有 `-p` / `--key-password` 一个入口接受私钥口令，
//! **没有 stdin 通道，也没有 `@file` 语法**。源码核实：
//!
//! ```sh
//! $ grep -rn "case '@'" *.c
//! main.c:1549    # --token-secret 的补全逻辑
//! main.c:3013    # 同上
//! oidc.c:36
//! stoken.c:47    # --token-secret 真正读文件
//! ```
//!
//! `-p` 走的是 `main.c:2109`：
//!
//! ```c
//! case 'p':
//!         vpninfo->certinfo[0].password = dup_config_arg();
//! ```
//!
//! 没有任何 `@` / 路径处理 —— 字面量进 argv，`ps aux` 全机可见。
//!
//! # 解法：`--config=FILE`
//!
//! openconnect 支持 `--config=FILE`，config 文件走同一套
//! `long_options` 匹配（`main.c:1258`），因此支持**长选项**
//! `key-password`，而短选项 `-p` 只存在于 argv 路径。
//!
//! P1 实测（加密 PKCS#8 私钥 + mock gateway）：
//!
//! | 命令行 | 结果 |
//! |---|---|
//! | `-p MyKeyPass` | `Using client certificate 'alice'`（但口令进 argv） |
//! | `--config=oc.conf` + 正确口令 | `Using client certificate 'alice'` ✅ |
//! | `--config=bad.conf` + 错误口令 | `Failed to decrypt PKCS#8 certificate file` ✅ |
//!
//! # 文件格式的硬约束（源码核实 + 实测）
//!
//! 解析逻辑在 `main.c:1256-1284`：取 `key-password` 后的第一个非
//! `[ \t=]` 字符，剩余部分**原样**作为值。
//!
//! | 约束 | 原因 | 实测 |
//! |---|---|---|
//! | 不能有换行 | 第二行会被当作未知选项 → `usage()` 退出 | ✅ |
//! | 不能有前导空格 | 前导空白被 `while (*line == ' ')` 跳过 | ✅ `Failed to decrypt` |
//! | 可以有内部空格 | 只跳前导 | ✅ `My Pass#word=1` 通过 |
//! | 可以有 `#` | 注释只在**行首**判定 | ✅ |
//! | 不能为空 | `has_arg == 1 && !*line` → 报错 | ✅ |

use std::io::Write;
use std::path::{Path, PathBuf};

/// 生成配置文件时的不变量检查结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// 含换行，会被 openconnect 当成未知选项
    ContainsNewline,
    /// 以空白开头，解析时会被跳过
    LeadingWhitespace,
    /// 空值，openconnect 会报 "requires an argument"
    Empty,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::ContainsNewline => write!(f, "私钥口令不能含换行符"),
            ConfigError::LeadingWhitespace => write!(f, "私钥口令不能以空格或 Tab 开头"),
            ConfigError::Empty => write!(f, "私钥口令为空"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// 检查口令能否安全写入 config 文件。
pub fn validate_passphrase(pass: &str) -> Result<(), ConfigError> {
    if pass.is_empty() {
        return Err(ConfigError::Empty);
    }
    if pass.contains(['\n', '\r']) {
        return Err(ConfigError::ContainsNewline);
    }
    if pass.starts_with([' ', '\t']) {
        return Err(ConfigError::LeadingWhitespace);
    }
    Ok(())
}

/// 渲染 config 文件内容。
///
/// 只写 `key-password`，其余选项继续走 argv —— 混合模式让可审计性更好：
/// argv 里除了这一个文件路径，全是显式可读的开关。
pub fn render(passphrase: &str) -> Result<String, ConfigError> {
    validate_passphrase(passphrase)?;
    // 末尾必须换行：openconnect 用 getline 逐行读，缺换行时最后一行可能被丢
    Ok(format!("key-password = {passphrase}\n"))
}

/// 在随机临时路径上写 config 文件，权限 0600。
///
/// 路径由本函数生成，调用方无法指定 —— 这与令牌 secret 的处理一致，
/// 避免「用户指定路径 → 符号链接攻击」。
#[cfg(unix)]
pub fn write_secure(passphrase: &str) -> std::io::Result<ConfigFile> {
    write_secure_in(&std::env::temp_dir(), passphrase)
}

/// 与 [`write_secure`] 相同，但写入指定目录。
///
/// 存在的理由是**可测性**：写死 `temp_dir()` 时，测试要断言
/// 「校验失败不产生文件」就只能去数共享临时目录里的文件，而并行的
/// 兄弟测试正往同一目录写正常文件 —— 断言因此会偶发失败。
/// 传入私有目录后断言只覆盖本测试的行为。
fn write_secure_in(dir: &std::path::Path, passphrase: &str) -> std::io::Result<ConfigFile> {
    use rand::RngExt;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let content = render(passphrase).map_err(std::io::Error::other)?;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    for _ in 0..16 {
        let name: String = (0..16)
            .map(|_| ALPHABET[rand::rng().random_range(0..ALPHABET.len())] as char)
            .collect();
        let path = dir.join(format!("oc-gui-oc-{name}.conf"));

        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut f) => {
                f.write_all(content.as_bytes())?;
                f.flush()?;
                drop(f);
                return Ok(ConfigFile { path });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("无法创建临时配置文件"))
}

/// Windows 上 `%TEMP%` 下的等价实现。
///
/// 注意：Windows 的 ACL 继承自目录，无法像 POSIX 那样用 mode 精确控制。
/// 因此必须额外检查目录 ACL，或改用 `--key-password` 走 argv。
/// 当前实现**保守**：调用方需自行确认 `%TEMP%` 不可被其他用户写入，
/// 否则应拒绝使用本路径。见 P1-DESIGN §6.1 的 Windows 备注。
#[cfg(windows)]
pub fn write_secure(passphrase: &str) -> std::io::Result<ConfigFile> {
    write_secure_in(&std::env::temp_dir(), passphrase)
}

/// 与 [`write_secure`] 相同，但写入指定目录（见 unix 版本的说明）。
#[cfg(windows)]
fn write_secure_in(dir: &std::path::Path, passphrase: &str) -> std::io::Result<ConfigFile> {
    use rand::RngExt;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for _ in 0..16 {
        let name: String = (0..16)
            .map(|_| ALPHABET[rand::rng().random_range(0..ALPHABET.len())] as char)
            .collect();
        let path = dir.join(format!("oc-gui-oc-{name}.conf"));
        let content = render(passphrase).map_err(std::io::Error::other)?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                f.write_all(content.as_bytes())?;
                return Ok(ConfigFile { path });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("无法创建临时配置文件"))
}

/// 一个已落盘的 config 文件。Drop 时自动删除。
///
/// `Debug` 只打印路径，不打印内容 —— 内容是私钥口令。
pub struct ConfigFile {
    path: PathBuf,
}

impl std::fmt::Debug for ConfigFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConfigFile({})", self.path.display())
    }
}

impl ConfigFile {
    /// 传给 openconnect 的参数值（配合 `--config=` 使用）
    pub fn arg(&self) -> String {
        format!("--config={}", self.path.display())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 手动删除。Drop 已经会做，正常不需要调用。
    pub fn remove(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        // openconnect 在启动时就已读完整个文件（getline 循环发生在
        // 参数解析阶段），因此 spawn 之后立刻删除是安全的。
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_key_password_line() {
        assert_eq!(
            render("MyKeyPass").unwrap(),
            "key-password = MyKeyPass\n"
        );
    }

    #[test]
    fn trailing_newline_is_mandatory() {
        // openconnect 用 getline 读；缺换行时最后一行可能丢失
        assert!(render("x").unwrap().ends_with('\n'));
    }

    #[test]
    fn rejects_newline() {
        assert_eq!(validate_passphrase("a\nb"), Err(ConfigError::ContainsNewline));
        assert_eq!(validate_passphrase("a\rb"), Err(ConfigError::ContainsNewline));
    }

    #[test]
    fn rejects_leading_whitespace() {
        // 实测：`key-password =  LeadSpace` 会丢前导空格，
        // 导致 `Failed to decrypt PKCS#8 certificate file`
        assert_eq!(validate_passphrase(" x"), Err(ConfigError::LeadingWhitespace));
        assert_eq!(validate_passphrase("\tx"), Err(ConfigError::LeadingWhitespace));
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(validate_passphrase(""), Err(ConfigError::Empty));
    }

    #[test]
    fn accepts_internal_spaces_and_hash() {
        // 实测：`My Pass#word=1` 可用 —— 空格只在行首被剥离，
        // `#` 只在行首才是注释
        assert!(validate_passphrase("My Pass#word=1").is_ok());
        assert!(validate_passphrase("a=b c").is_ok());
        assert!(validate_passphrase("密碼🔐").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn written_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let cf = write_secure("MyKeyPass").unwrap();
        let mode = std::fs::metadata(cf.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config 文件必须 0600，实际 {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn file_content_is_exact() {
        let cf = write_secure("MyKeyPass").unwrap();
        let s = std::fs::read_to_string(cf.path()).unwrap();
        assert_eq!(s, "key-password = MyKeyPass\n");
    }

    #[cfg(unix)]
    #[test]
    fn path_is_random_not_predictable() {
        let a = write_secure("x").unwrap();
        let b = write_secure("x").unwrap();
        assert_ne!(a.path(), b.path(), "每次应生成不同路径");
    }

    #[cfg(unix)]
    #[test]
    fn drop_deletes_the_file() {
        let path = {
            let cf = write_secure("x").unwrap();
            cf.path().to_path_buf()
        };
        assert!(!path.exists(), "Drop 应删除临时文件");
    }

    #[cfg(unix)]
    #[test]
    fn arg_form_is_openconnect_ready() {
        let cf = write_secure("x").unwrap();
        let a = cf.arg();
        assert!(a.starts_with("--config="), "实际: {a}");
        assert!(!a.contains('\n'));
    }

    /// 校验失败的输入必须**一个文件都不留下**。
    ///
    /// 密码会经 stdin 传给 openconnect，但私钥口令只能走 `--config`
    /// 文件（openconnect v9 不支持 `--key-password=@file`），所以这个
    /// 文件就是明文口令在磁盘上的唯一副本 —— 校验失败却留下文件，
    /// 等于把口令留在磁盘上。
    ///
    /// 用**私有临时目录**而不是数共享的 `temp_dir()`：并行的
    /// `passphrase_never_appears_in_arg` 会往同一目录写正常文件，
    /// 数全局数量必然偶发失败（实测 40 次里 2 次）。
    #[cfg(unix)]
    #[test]
    fn bad_passphrase_writes_nothing() {
        let dir = tempfile::TempDir::new().expect("TempDir");
        for bad in ["a\nb", "", " x"] {
            assert!(
                write_secure_in(dir.path(), bad).is_err(),
                "{bad:?} 应被拒绝"
            );
        }
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert!(left.is_empty(), "校验失败不应产生文件，实际: {left:?}");
    }

    #[test]
    fn passphrase_never_appears_in_arg() {
        let cf = write_secure("SuperSecret123").unwrap();
        assert!(!cf.arg().contains("SuperSecret123"));
    }
}