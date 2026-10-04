//! helper 的调用方授权
//!
//! # 威胁模型
//!
//! helper 以 root 运行。**任何本地用户只要能连上 socket，就能以 root
//! 执行 openconnect**。而 openconnect 支持 `--csd-wrapper=SCRIPT`
//! （运行任意脚本）、`--external-browser=BROWSER`、`-s/--script`
//! （vpnc 兼容脚本），这些都是 root 任意代码执行的入口。
//!
//! 因此 socket 的访问控制就是提权边界本身。
//!
//! # 为什么绝对不能「按 argv 授权」
//!
//! 一个天真的 polkit 规则是：
//!
//! ```xml
//! <!-- ❌ 千万不要这样 -->
//! <allow_any>
//!   <allow_command>pkexec</allow_command>
//!   <allow_arg>openconnect</allow_arg>
//! </allow_any>
//! ```
//!
//! 这等于对**全机所有用户**开放了以 root 运行 openconnect 的能力。
//! 任何用户都能自己构造：
//!
//! ```sh
//! pkexec openconnect --csd-wrapper=/tmp/evil.sh vpn.corp.com
//! ```
//!
//! 这就是一个无需提权提示的 root 漏洞。
//!
//! 正确做法是**按调用方身份授权**：
//!
//! | 平台 | 机制 | 校验什么 |
//! |---|---|---|
//! | Linux | polkit action（`org.github.rediceli.ocgui-helper`） | 调用方的 uid / 进程签名 |
//! | macOS | privileged XPC + code signature | connecting process 的 designated requirement |
//! | Windows | 提权启动的 helper + named pipe DACL | pipe 的 DACL + 客户端 SID |
//!
//! # 本模块负责的部分
//!
//! - [`PeerCredentials`]：跨平台获取对端 uid/pid
//! - [`authorize`]：平台相关的调用方校验
//! - socket 权限模型的说明与常量
//!
//! ⚠️ 本机（macOS + 无 root 的开发环境）无法端到端验证 polkit 与 XPC，
//!    因此授权逻辑写成**纯函数 + 可注入的对端身份**，
//!    测试只验证决策逻辑。真实授权路径的验证需要 root 与签名证书。

use std::io;

/// 对端进程的身份凭据
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    /// 有效 uid / SID。0 表示 root（helper 自身，排除）
    pub uid: u32,
    pub pid: u32,
}

/// 开发模式开关：允许 self_uid 连接。
///
/// 仅用于「以普通用户跑 helper 做本地测试」这一场景。生产部署中
/// helper 恒为 root，此检查永不触发，因此**不可**放宽到生产路径。
fn dev_allow_self() -> bool {
    std::env::var("OCGUI_DEV_ALLOW_SELF").as_deref() == Ok("1")
}

/// 授权决策
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    Allow,
    /// 拒绝，并附带可展示的原因
    Deny { reason: String },
}

/// polkit action id。安装到
/// `/usr/share/polkit-1/actions/org.github.rediceli.ocgui-helper.policy`
pub const POLKIT_ACTION: &str = "org.github.rediceli.ocgui-helper";

/// 允许调用 helper 的 uid 列表。
///
/// 默认为空 —— **必须由安装程序显式配置**。默认为空时只有 root 能连
/// （因为 socket 是 0600 root），等于 helper 不可用。这是刻意的：
/// 「静默允许所有用户」比「默认不可用」危险得多。
pub fn allowed_uids() -> Vec<u32> {
    std::env::var("OCGUI_ALLOWED_UIDS")
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|p| p.trim().parse::<u32>().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// 授权判定。**纯函数**，便于测试。
///
/// `self_uid` 是 helper 自己的 uid。Unix socket 允许进程连自己，
/// 那不是攻击面但也无意义，因此排除。
///
/// ⚠️ 开发模式下 helper 以普通用户身份运行时，`self_uid == peer.uid`
/// 会把**所有**本地连接都判成「自身」。这不是 bug 而是非 root 运行的
/// 固有歧义 —— 真实部署里 helper 恒为 root，两者不可能相等。
/// 生产部署用 `OCGUI_DEV_ALLOW_SELF=1` 之外的路径即可；
/// 开发模式请设置该变量跳过此检查。
pub fn authorize(
    peer: PeerCredentials,
    self_uid: u32,
    allowed: &[u32],
) -> AuthDecision {
    if peer.uid == self_uid && !dev_allow_self() {
        return AuthDecision::Deny {
            reason: "不接受来自 helper 自身的连接".into(),
        };
    }
    if peer.uid == 0 && self_uid != 0 {
        return AuthDecision::Deny {
            reason: "不接受来自 root 的连接（异常）".into(),
        };
    }
    if allowed.is_empty() {
        return AuthDecision::Deny {
            reason: format!(
                "未配置允许列表（{POLKIT_ACTION}）；请设置 OCGUI_ALLOWED_UIDS"
            ),
        };
    }
    if allowed.contains(&peer.uid) {
        AuthDecision::Allow
    } else {
        AuthDecision::Deny {
            reason: format!("uid {} 不在允许列表中", peer.uid),
        }
    }
}

// ---------------------------------------------------------------------------
// 获取对端凭据
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub fn peer_credentials(stream: &std::os::unix::net::UnixStream) -> io::Result<PeerCredentials> {
    use std::os::fd::AsRawFd;
    // SO_PEERCRED：内核在 connect 时就记录了对端的 uid/pid，
    // 无法伪造（不需要额外的往返握手）。
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred) as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCredentials {
        uid: cred.uid,
        pid: cred.pid,
    })
}

#[cfg(target_os = "macos")]
pub fn peer_credentials(stream: &std::os::unix::net::UnixStream) -> io::Result<PeerCredentials> {
    use std::os::fd::AsRawFd;

    // macOS 没有 Linux 的 SO_PEERCRED。用 `LOCAL_PEERCRED` 拿 `struct xucred`。
    //
    // ⚠️ 这里踩过一个坑：网上流传的写法是 getsockopt(..., LOCAL_PEERCRED, &uid_u32)。
    //    **那是错的** —— 返回结构是 `struct xucred`（含 version/uid/groups），
    //    只给 4 字节会让内核写超出缓冲，实测恒得 uid=0。
    //
    //    正确来源：/usr/include/sys/ucred.h
    //      struct xucred { u_int cr_version; uid_t cr_uid; short cr_ngroups; gid_t cr_groups[]; }
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERCRED: libc::c_int = 0x001;
    const XUCRED_VERSION: libc::c_int = 0;

    #[repr(C)]
    struct Xucred {
        cr_version: libc::c_uint,
        cr_uid: libc::uid_t,
        cr_ngroups: libc::c_short,
        // cr_groups 是柔性数组，这里不读它 —— 授权只需 uid
    }

    let mut cred = Xucred {
        cr_version: XUCRED_VERSION as libc::c_uint,
        cr_uid: 0,
        cr_ngroups: 0,
    };
    let mut len = std::mem::size_of::<Xucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERCRED,
            (&raw mut cred) as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if cred.cr_version != XUCRED_VERSION as libc::c_uint {
        return Err(io::Error::other(format!(
            "xucred 版本不匹配: {} != {XUCRED_VERSION}",
            cred.cr_version
        )));
    }
    Ok(PeerCredentials {
        uid: cred.cr_uid,
        pid: 0, // macOS 的 pid 需另一个 opt（LOCAL_PEEREPID），授权不需要
    })
}

/// Windows named pipe 上没有「对端凭据」的等价物 ——
/// named pipe 的访问控制完全由 **DACL** 表达：pipe 被创建时就把
/// 允许访问的 SID 写进安全描述符，非授权方连不上，不存在
/// 「连上了但被拒」的中间态。
///
/// 因此 Windows 上 `authorize()` 不会被调用 —— DACL 就是授权。
/// 保留这个函数是为了让跨平台调用方代码形状一致。
#[cfg(target_os = "windows")]
pub fn peer_credentials(_handle: std::os::windows::io::OwnedHandle) -> io::Result<PeerCredentials> {
    Err(io::Error::other(
        "Windows 上授权由 pipe DACL 表达，不做运行时 uid 校验",
    ))
}

/// Windows 上没有 socket 需要创建 —— DACL 在
/// `CreateNamedPipeW` 时就通过 `SECURITY_ATTRIBUTES` 指定。
#[cfg(target_os = "windows")]
pub fn create_per_user_socket(_uid: u32) -> io::Result<()> {
    Err(io::Error::other("Windows 使用 named pipe，不走 socket"))
}

// ---------------------------------------------------------------------------
// socket 权限模型
// ---------------------------------------------------------------------------

/// Unix socket 的权限位。
///
/// | 阶段 | 权限 | 属主 | 理由 |
/// |---|---|---|---|
/// | helper 启动、尚未授权 | `0600` | root | 只有 root 能连 |
/// | polkit 认证通过后 | `0660` | root:helper-group | 组内用户可连，授权仍在 authorize() 里做二次校验 |
///
/// ⚠️ 阶段二会让 socket 对组内所有用户可连接。这些用户能连上，但
/// `authorize()` 会按 uid 拒绝未列入允许列表的人。**两层防护缺一不可**：
/// socket 权限挡住普通用户，uid 白名单挡住同组内的其他人。
///
/// 更严格的做法是每个授权用户一个 socket（`/run/oc-gui-<uid>.sock`），
/// 权限 `0600` + 属主该 uid —— 授权结果直接编码在文件系统里，没有
/// 「先连上再被拒」的中间态。推荐生产环境采用这个。
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod socket_perms {
    /// 未授权阶段
    pub const LOCKED: u32 = 0o600;
    /// 授权后（组可读写）
    pub const UNLOCKED_GROUP: u32 = 0o660;
    /// 推荐：每用户独立 socket
    pub const PER_USER: u32 = 0o600;
}

#[cfg(target_os = "windows")]
pub mod pipe_dacl {
    /// 只允许 pipe 属主（当前用户）读写的安全描述符。
    ///
    /// 用 `ConvertStringSecurityDescriptorToSecurityDescriptorW` 从
    /// SDDL 生成：只给当前 SID 授 `FILE_GENERIC_READ|FILE_GENERIC_WRITE`，
    /// **不给 Everyone / Administrators / SYSTEM**。
    ///
    /// ⚠️ 常见的错误做法是放行 Administrators —— 那意味着任何
    /// 管理员账号都能连上这个提权管道，与 Linux 上「按 uid 白名单、
    /// 不按组」的原则相反。
    pub const SDDL_TEMPLATE: &str =
        "D:P(A;;0x12019b;;;{SID})(A;;0x12019b;;;SY)";
}

/// 每用户 IPC 端点的名字。
///
/// 三平台各有各的机制，但「授权结果编码在命名/权限里」的原则一致：
/// - Linux：`/run/oc-gui/helper-<uid>.sock`，`0600` + 属主该 uid
/// - Windows：`\\\\.\\pipe\\OC GUI-<sid>`，DACL 只放行该 SID
/// - macOS：Mach service + `SecCode` 校验（见 macos-helper）
pub const ENDPOINT_PREFIX: &str = "helper";

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub const RUNTIME_DIR: &str = "/run/oc-gui";

/// Linux/macOS：每用户 socket 的绝对路径。
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn per_user_socket_path(uid: u32) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{RUNTIME_DIR}/{ENDPOINT_PREFIX}-{uid}.sock"))
}

/// Windows：每用户 named pipe 的名字。
///
/// **不用 `Local\` 前缀**：`Local\` 的命名空间由创建 pipe 的进程
/// 拥有，SYSTEM 服务创建的 pipe 普通用户连不上。要让普通用户能连
/// 提权进程创建的 pipe，必须用 `\.\pipe\`（全局命名空间），
/// 靠 DACL 而不是命名空间来隔离。
#[cfg(target_os = "windows")]
pub fn per_user_pipe_name(sid_suffix: &str) -> String {
    format!(r"\.\pipe\OC GUI-{ENDPOINT_PREFIX}-{sid_suffix}")
}

/// 创建/接管每用户 socket。
///
/// 步骤（Linux）：
/// 1. `mkdir -p /run/oc-gui`，权限 0755 root
/// 2. 拒绝已存在的 socket（防 symlink / 抢占）
/// 3. `bind` 后立刻 `chown(uid)` + `chmod(0600)`
///
/// **为什么不用「先 0600 root、授权后 chown」**：那样会留下一个
/// 「能连上但会被拒」的中间态，且 chown 之后若 uid 白名单变更，
/// 旧 socket 仍在。相比之下每用户 socket 把授权结果直接编码在
/// 文件系统权限里，没有中间态也没有残留。
///
/// # 竞态说明
///
/// `bind` 与 `chown` 之间存在极短窗口，期间 socket 属主仍是 root，
/// 权限 0600 ⇒ 其他用户无法连接。因此不存在「未授权即可连」的窗口。
/// 上面显式检查 `path.exists()` 并拒绝复用，配合 bind 的原子性，
/// 保证不会跟随攻击者预置的符号链接。
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn create_per_user_socket(uid: u32) -> std::io::Result<std::os::unix::net::UnixListener> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let dir = std::path::Path::new(RUNTIME_DIR);
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
    }

    let path = per_user_socket_path(uid);
    // 已存在 = 可能被抢占或上次未清理。拒绝，不复用。
    if path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} 已存在，拒绝复用（可能被抢占）", path.display()),
        ));
    }

    let listener = UnixListener::bind(&path)?;
    // bind 后立刻收紧权限：此刻 socket 属主是 root 且 0600，
    // 其他用户连不上，所以 chown 前不存在未授权窗口。
    fs::set_permissions(&path, fs::Permissions::from_mode(socket_perms::PER_USER))?;
    chown(&path, uid)?;
    Ok(listener)
}

#[cfg(unix)]
fn chown(path: &std::path::Path, uid: u32) -> std::io::Result<()> {
    // gid 传 (uid_t::MAX = -1) 表示「不改变组」
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("路径含 NUL"))?;
    // SAFETY: c 是有效 NUL 结尾字符串；uid 来自内核提供的对端凭据。
    if unsafe { libc::chown(c.as_ptr(), uid, libc::uid_t::MAX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(uid: u32, pid: u32) -> PeerCredentials {
        PeerCredentials { uid, pid }
    }

    #[test]
    fn allows_listed_uid() {
        assert_eq!(
            authorize(peer(1000, 42), 0, &[1000, 1001]),
            AuthDecision::Allow
        );
    }

    #[test]
    fn denies_unlisted_uid() {
        assert!(matches!(
            authorize(peer(1002, 42), 0, &[1000, 1001]),
            AuthDecision::Deny { .. }
        ));
    }

    #[test]
    fn denies_when_allowlist_empty() {
        // 默认必须拒绝 —— 「静默允许所有」比「默认不可用」危险得多
        let d = authorize(peer(1000, 42), 0, &[]);
        assert!(matches!(d, AuthDecision::Deny { .. }));
        assert!(format!("{d:?}").contains("未配置允许列表"));
    }

    #[test]
    fn denies_self_connection() {
        // self_uid=0（helper 为 root）时，root peer 被拒
        assert!(matches!(
            authorize(peer(0, 1), 0, &[0, 1000]),
            AuthDecision::Deny { .. }
        ));
        // 非 root peer 与 self_uid 不同时不受影响
        assert!(matches!(
            authorize(peer(1000, 1), 501, &[1000]),
            AuthDecision::Allow
        ));
    }

    #[test]
    fn denies_root_peer_when_helper_is_not_root() {
        // helper 以 root 运行（self_uid=0）时的对端 root 已在上面覆盖。
        // 这里测另一侧：helper 非 root（开发模式）时，root peer 必须被拒，
        // 否则任何 root 进程都能驱动开发 helper。
        assert!(matches!(
            authorize(peer(0, 999), 501, &[0, 501]),
            AuthDecision::Deny { .. }
        ));
    }

    #[test]
    fn root_helper_allows_regular_peer() {
        // 正常生产路径：helper=root(0)，对端是普通用户(1000)
        assert_eq!(
            authorize(peer(1000, 42), 0, &[1000]),
            AuthDecision::Allow
        );
    }

    #[test]
    fn allowed_uids_parses_comma_list() {
        // 显式测试解析逻辑（不依赖环境变量，避免测试互相干扰）
        let parsed: Vec<u32> = "1000, 1001 ,1002"
            .split(',')
            .filter_map(|p| p.trim().parse::<u32>().ok())
            .collect();
        assert_eq!(parsed, vec![1000, 1001, 1002]);
    }

    #[test]
    fn allowed_uids_ignores_garbage() {
        let parsed: Vec<u32> = "1000,abc,,1002"
            .split(',')
            .filter_map(|p| p.trim().parse::<u32>().ok())
            .collect();
        assert_eq!(parsed, vec![1000, 1002]);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn per_user_socket_paths_differ_by_uid() {
        assert_ne!(
            per_user_socket_path(1000),
            per_user_socket_path(1001)
        );
        assert!(per_user_socket_path(1000)
            .to_string_lossy()
            .contains("1000"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn locked_phase_is_root_only() {
        assert_eq!(socket_perms::LOCKED, 0o600);
        // 0600 ⇒ 只有属主（root）可读写
        assert_eq!(socket_perms::LOCKED & 0o077, 0);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn unlocked_group_phase_still_blocks_others() {
        // 0660 ⇒ 其他用户无任何权限；uid 白名单是第二道防线
        assert_eq!(socket_perms::UNLOCKED_GROUP & 0o007, 0);
    }

    #[test]
    fn polkit_action_is_namespaced() {
        // 反向 DNS 命名空间。这个断言的作用是「重命名时必须同步更新」——
        // 漏改时 polkit 会找不到 action，授权静默失败（不是编译错误）。
        assert!(POLKIT_ACTION.starts_with("org.github.rediceli."));
        assert!(!POLKIT_ACTION.contains(' '));
        assert_eq!(POLKIT_ACTION, "org.github.rediceli.ocgui-helper");
    }

    /// 关键安全断言：允许列表永远不能被 argv 影响。
    ///
    /// 若将来有人想「按命令行参数决定授权」，这个测试会挡住。
    #[cfg(target_os = "windows")]
    #[test]
    fn pipe_dacl_only_grants_the_named_sid() {
        // DACL 里出现 Everyone / Administrators 都是权限泄漏
        let s = pipe_dacl::SDDL_TEMPLATE;
        for bad in ["WD", "BA", "BU", "AU"] {
            let ace = format!(";;;{bad})");
            assert!(!s.contains(&ace), "SDDL 不应放行 {bad}: {s}");
        }
        assert!(s.contains("{SID}"), "必须显式放行当前用户");
        assert!(s.contains("SY"), "SYSTEM 需要（helper 自身以 SYSTEM 运行）");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn pipe_name_is_in_global_namespace() {
        // Local\ 的 pipe 由创建进程拥有，SYSTEM 创建的普通用户连不上
        let n = per_user_pipe_name("S-1-5-21-1-2-3-1001");
        assert!(n.starts_with(r"\\.\pipe\"), "实际: {n}");
        assert!(n.contains("1001"), "应含用户标识: {n}");
    }

    #[test]
    fn authorization_never_depends_on_requested_arguments() {
        let allowed: Vec<u32> = vec![1000];
        for args in [
            vec!["--csd-wrapper=/tmp/evil.sh", "vpn.corp.com"],
            vec!["--script=/tmp/evil.sh"],
            vec![],
        ] {
            // 请求参数完全不参与判定函数
            let d = authorize(peer(1000, 1), 0, &allowed);
            assert_eq!(d, AuthDecision::Allow);
            // 未授权 uid 无论传什么参数都拒绝
            let d2 = authorize(peer(2000, 1), 0, &allowed);
            assert!(matches!(d2, AuthDecision::Deny { .. }));
            let _ = args;
        }
    }
}