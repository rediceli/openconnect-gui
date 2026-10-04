//! 表单字段绑定映射表
//!
//! # 为什么需要这张表
//!
//! P0 实测（mock gateway + openconnect v9.21）证明：
//! `-F` 的字段名写错时，openconnect **不报错**，而是退化成
//! 「交互式下拉提示」并阻塞等 stdin：
//!
//! ```text
//! GROUP: [|Engineering|Operations]:fgets (stdin): Resource temporarily unavailable
//! ```
//!
//! 在 GUI 客户端里这表现为「连接卡死，且没有任何可操作的错误信息」。
//! 因此字段名必须准确，且需要测试锁定。

use crate::profile::{FormBinding, Protocol};

/// 某协议下分组下拉的默认绑定。
///
/// 每条都对应 openconnect 源码里的字面量：
/// - anyconnect: `auth.c:173` — 仅当 select 的 `name` 为 **`group_list`**
///   才会被识别为「认证分组」并特殊处理（POST 时改写为 `<group-select>`）
/// - nc (juniper): `auth-html.c:168` — 字段名为 **`realm`**
/// - f5: `auth-html.c:169` — 字段名为 **`domain`**
/// - gp: `auth-globalprotect.c:456` — `opt->form.name = "gateway"`
///
/// ⚠️ `auth_group` **不是**任何协议的字段名。社区文档里常见的写法是错的。
pub fn default_binding(protocol: Protocol) -> Option<FormBinding> {
    match protocol {
        Protocol::AnyConnect => Some(FormBinding {
            form_id: "main".into(),
            group_field: "group_list".into(),
        }),
        Protocol::Nc => Some(FormBinding {
            // auth-juniper.c:64 — 可能是 frmLogin 或 loginForm，取决于设备
            form_id: "loginForm".into(),
            group_field: "realm".into(),
        }),
        Protocol::F5 => Some(FormBinding {
            form_id: "main".into(),
            group_field: "domain".into(),
        }),
        Protocol::Gp => Some(FormBinding {
            form_id: "_portal".into(), // auth-globalprotect.c:448
            group_field: "gateway".into(),
        }),
        // pulse / fortinet / array: 源码里没有 group_list 级别的特殊处理，
        // 分组通常走 usergroup 或设备特定字段。留给用户手动配置。
        Protocol::Pulse | Protocol::Fortinet | Protocol::Array => None,
    }
}

/// 解析 profile 的绑定：显式配置优先，否则按协议推断。
pub fn resolve(profile: &crate::profile::Profile) -> Option<FormBinding> {
    profile.form.clone().or_else(|| default_binding(profile.protocol))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;

    #[test]
    fn anyconnect_group_field_is_group_list_not_auth_group() {
        // 这是 P0 最重要的修正。写成 auth_group 会静默失效。
        let b = default_binding(Protocol::AnyConnect).unwrap();
        assert_eq!(b.group_field, "group_list");
        assert_ne!(b.group_field, "auth_group");
    }

    #[test]
    fn group_field_matches_openconnect_source() {
        // 逐条对应源码字面量，改错=静默失效
        assert_eq!(default_binding(Protocol::Nc).unwrap().group_field, "realm");
        assert_eq!(default_binding(Protocol::F5).unwrap().group_field, "domain");
        assert_eq!(default_binding(Protocol::Gp).unwrap().group_field, "gateway");
    }

    #[test]
    fn protocols_without_special_handling_return_none() {
        // 这些协议的分组不由 openconnect 特殊处理，需要用户手填
        for p in [Protocol::Pulse, Protocol::Fortinet, Protocol::Array] {
            assert!(
                default_binding(p).is_none(),
                "{} 不应有默认绑定",
                p.as_arg()
            );
        }
    }

    #[test]
    fn explicit_binding_overrides_protocol_default() {
        let mut p = Profile::new("id", "n", "s");
        p.protocol = Protocol::AnyConnect;
        p.form = Some(FormBinding {
            form_id: "custom".into(),
            group_field: "my_group".into(),
        });
        let r = resolve(&p).unwrap();
        assert_eq!(r.form_id, "custom");
        assert_eq!(r.group_field, "my_group");
    }

    #[test]
    fn falls_back_to_protocol_default() {
        let mut p = Profile::new("id", "n", "s");
        p.protocol = Protocol::Nc;
        assert_eq!(resolve(&p).unwrap().group_field, "realm");
    }
}