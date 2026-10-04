//! 系统钥匙串封装
//!
//! P0 已在 macOS Keychain 上验证 set/get/覆盖/删除全链路。Windows Credential
//! Manager 与 Linux Secret Service 由 keyring-rs 的 feature 分支承担，未在本机
//! 验证（见 P1 文档「跨平台验证缺口」）。
//!
//! 设计要点：
//! 1. 全部入口都是同步的（keyring 的 API 就是同步的），由调用方决定是否放在
//!    阻塞线程池里。
//! 2. 任何错误都转成 `SecretError`，不把 keyring 的错误类型泄露到上层。
//! 3. 调用方拿不到明文的持有时间——`with_secret` 尽量缩短作用域。

use crate::profile::{Profile, SecretKind};
use keyring::Entry;

/// 钥匙串 service 名。用反向域名以免与其他应用撞车。
const SERVICE: &str = "io.github.rediceli.ocgui";

#[derive(Debug)]
pub enum SecretError {
    /// 条目不存在（未保存过密码，或已被用户手动删除）
    NotFound,
    /// 平台不支持（无 keyring daemon / 无 keychain）
    Unsupported(String),
    Other(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretError::NotFound => write!(f, "钥匙串中没有该条目"),
            SecretError::Unsupported(m) => write!(f, "系统钥匙串不可用: {m}"),
            SecretError::Other(m) => write!(f, "钥匙串操作失败: {m}"),
        }
    }
}

impl std::error::Error for SecretError {}

impl From<keyring::Error> for SecretError {
    fn from(e: keyring::Error) -> Self {
        match e {
            keyring::Error::NoEntry => SecretError::NotFound,
            // 钥匙串不可访问：Linux 无 secret service daemon、钥匙串被锁等
            keyring::Error::NoStorageAccess(_) | keyring::Error::PlatformFailure(_) => {
                SecretError::Unsupported(e.to_string())
            }
            _ => SecretError::Other(e.to_string()),
        }
    }
}

pub struct Vault;

/// 取某个 profile 的某类密钥。
pub fn get(profile: &Profile, kind: SecretKind) -> Result<String, SecretError> {
    Entry::new(SERVICE, &profile.secret_key(kind))
        .and_then(|e| e.get_password())
        .map_err(Into::into)
}

/// 存某个 profile 的某类密钥。空字符串视为「删除」。
pub fn set(profile: &Profile, kind: SecretKind, value: &str) -> Result<(), SecretError> {
    if value.is_empty() {
        return delete(profile, kind);
    }
    Entry::new(SERVICE, &profile.secret_key(kind))
        .and_then(|e| e.set_password(value))
        .map_err(Into::into)
}

pub fn delete(profile: &Profile, kind: SecretKind) -> Result<(), SecretError> {
    match Entry::new(SERVICE, &profile.secret_key(kind)).and_then(|e| e.delete_credential()) {
        Ok(()) => Ok(()),
        // 删不存在的条目不算失败
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub fn exists(profile: &Profile, kind: SecretKind) -> bool {
    get(profile, kind).is_ok()
}

/// 密码：没保存则返回 None，让调用方弹输入框。
pub fn password(profile: &Profile) -> Option<String> {
    get(profile, SecretKind::Password).ok().filter(|s| !s.is_empty())
}

/// 证书私钥口令
pub fn key_password(profile: &Profile) -> Option<String> {
    get(profile, SecretKind::KeyPassword).ok().filter(|s| !s.is_empty())
}

/// 软令牌 secret（TOTP/HOTP/RSA/OIDC）
pub fn token_secret(profile: &Profile) -> Option<String> {
    get(profile, SecretKind::TokenSecret).ok().filter(|s| !s.is_empty())
}

/// 删除 profile 的全部密钥。**删除档案时必须调用**，
/// 否则钥匙串里会留下孤儿条目。
pub fn purge(profile: &Profile) {
    for k in [
        SecretKind::Password,
        SecretKind::KeyPassword,
        SecretKind::McaKeyPassword,
        SecretKind::TokenSecret,
    ] {
        let _ = delete(profile, k);
    }
}

/// 撤销 vault 引用，保持 `Vault` 这个名字作为模块级 API 的占位。
#[allow(dead_code)]
pub type VaultMarker = Vault;

/// 让编译器知道 unused 变体已被有意使用。
#[allow(dead_code)]
fn _assert_kinds(_: SecretKind) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::SecretKind;

    /// 测试用 profile。id 唯一，避免污染真实钥匙串。
    fn tmp_profile(tag: &str) -> Profile {
        Profile::new(
            format!("__test_{tag}_{}__", std::process::id()),
            "test",
            "vpn.invalid",
        )
    }

    #[test]
    fn roundtrip_and_delete() {
        let p = tmp_profile("rt");
        purge(&p);

        set(&p, SecretKind::Password, "hunter2").unwrap();
        assert_eq!(password(&p).as_deref(), Some("hunter2"));

        // 覆盖
        set(&p, SecretKind::Password, "newpass").unwrap();
        assert_eq!(password(&p).as_deref(), Some("newpass"));

        delete(&p, SecretKind::Password).unwrap();
        assert_eq!(password(&p), None);
    }

    #[test]
    fn missing_entry_is_not_found() {
        let p = tmp_profile("missing");
        purge(&p);
        assert!(matches!(get(&p, SecretKind::Password), Err(SecretError::NotFound)));
        assert_eq!(password(&p), None);
    }

    #[test]
    fn empty_write_is_treated_as_delete() {
        let p = tmp_profile("empty");
        set(&p, SecretKind::Password, "x").unwrap();
        set(&p, SecretKind::Password, "").unwrap();
        assert_eq!(password(&p), None);
    }

    #[test]
    fn kinds_do_not_collide() {
        let p = tmp_profile("kinds");
        purge(&p);
        set(&p, SecretKind::Password, "AAA").unwrap();
        set(&p, SecretKind::KeyPassword, "BBB").unwrap();
        set(&p, SecretKind::TokenSecret, "CCC").unwrap();
        assert_eq!(password(&p).as_deref(), Some("AAA"));
        assert_eq!(key_password(&p).as_deref(), Some("BBB"));
        assert_eq!(token_secret(&p).as_deref(), Some("CCC"));
        purge(&p);
        assert_eq!(password(&p), None);
        assert_eq!(key_password(&p), None);
        assert_eq!(token_secret(&p), None);
    }

    #[test]
    fn purge_removes_everything() {
        let p = tmp_profile("purge");
        for k in [
            SecretKind::Password,
            SecretKind::KeyPassword,
            SecretKind::McaKeyPassword,
            SecretKind::TokenSecret,
        ] {
            set(&p, k, "x").unwrap();
            assert!(exists(&p, k), "{k:?} 应存在");
        }
        purge(&p);
        for k in [
            SecretKind::Password,
            SecretKind::KeyPassword,
            SecretKind::McaKeyPassword,
            SecretKind::TokenSecret,
        ] {
            assert!(!exists(&p, k), "{k:?} 应已清除");
        }
    }

    #[test]
    fn deleting_nonexistent_is_ok() {
        let p = tmp_profile("delmissing");
        purge(&p);
        assert!(delete(&p, SecretKind::Password).is_ok());
    }

    #[test]
    fn unicode_secret_roundtrips() {
        let p = tmp_profile("unicode");
        set(&p, SecretKind::Password, "密码🔐with spaces&symbols!").unwrap();
        assert_eq!(password(&p).as_deref(), Some("密码🔐with spaces&symbols!"));
        purge(&p);
    }
}