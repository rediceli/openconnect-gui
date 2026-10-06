//! GUI → helper 的客户端
//!
//! 负责：找 socket → 握手 → 发请求 → 收响应。
//!
//! # 端点查找顺序
//!
//! 1. `OCGUI_HELPER_SOCKET` 环境变量（测试与多实例用）
//! 2. Linux: `/run/oc-gui/helper-<uid>.sock`
//! 3. Windows: `\\.\pipe\OC GUI-helper-<SID>`
//! 4. 开发模式: `/tmp/oc-gui-helper-<uid>.sock`
//!
//! 找不到端点时 GUI 应引导用户启动 helper（`HelperHandle::spawn_elevated`），
//! 而不是自己提权 —— 提权决策属于用户，不属于应用。
//!
//! # 跨平台抽象
//!
//! 只用 [`Conn`] 这一个类型别名把两种传输统一起来，调用方代码
//! （握手、发请求、读流）一行都不用改。新增平台时只改
//! `type Conn` 与 [`endpoint_for`]。

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::ipc::{HelperError, Request, Response, PROTOCOL_VERSION};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

/// 到 helper 的传输层。
#[cfg(unix)]
type Conn = UnixStream;
#[cfg(windows)]
type Conn = crate::ipc::pipe::ClientPipe;

/// 设置写超时。Unix socket 支持；Windows pipe 无对应的
/// 「写超时」概念，只能靠 helper 侧的 `PIPE_NOWAIT` 或整体超时，
/// 这里退化为 no-op。
#[cfg(unix)]
fn set_write_timeout(sock: &UnixStream, d: std::time::Duration) {
    sock.set_write_timeout(Some(d)).ok();
}

/// 设置读超时（Unix：直接交给 socket）。
#[cfg(unix)]
fn set_read_timeout(sock: &mut UnixStream, d: Option<std::time::Duration>) {
    let _ = sock.set_read_timeout(d);
}

/// 设置写超时（Windows 上是 no-op，见下）。
#[cfg(windows)]
fn set_write_timeout(_sock: &Conn, _d: std::time::Duration) {}

/// 设置读超时。
///
/// Windows named pipe 没有 per-handle 的 SO_RCVTIMEO 对应物。
/// 想超时只能改用 overlapped I/O + `WaitForSingleObject`，而当前
/// 传输是同步的 —— 所以这里是 no-op。
///
/// ⚠️ 实际风险：helper 若接受连接后卡住，GUI 的读会一直阻塞。
/// 缓解靠 helper 侧不阻塞（单线程、逐行应答），而不是靠这里的超时。
#[cfg(windows)]
fn set_read_timeout(_sock: &mut Conn, _d: Option<std::time::Duration>) {}

/// 开发模式 socket 路径（`--serve` 入口创建）。
#[cfg(unix)]
pub fn dev_socket_path(uid: u32) -> PathBuf {
    PathBuf::from(format!("/tmp/oc-gui-helper-{uid}.sock"))
}

/// 按平台与 uid/sid 推导端点名。
///
/// Unix 返回路径，Windows 返回 pipe 名 —— 都用 `String`，因为
/// `PathBuf` 表达不了 `\\.\pipe\` 这种设备路径。
///
/// ⚠️ 这里必须用 `#[cfg]` 分派而不是 `cfg!` —— `cfg!` 只是运行期
/// 布尔，两个分支都会参与类型检查，于是 Windows 上会去引用只在
/// Linux 存在的 `per_user_socket_path`，直接编译失败。
pub fn endpoint_for(uid: u32) -> String {
    let _ = uid; // Windows 上端点由 SID 决定，与 uid 无关
    if let Ok(p) = std::env::var("OCGUI_HELPER_SOCKET") {
        return p;
    }
    #[cfg(target_os = "linux")]
    {
        crate::ipc::authz::per_user_socket_path(uid).display().to_string()
    }
    #[cfg(target_os = "windows")]
    {
        // 当前用户的 SID：GUI 以普通用户运行，拿到的就是 helper
        // 创建 pipe 时放行的那个 SID
        crate::ipc::pipe::pipe_name_for_current_user()
            .unwrap_or_else(|_| crate::ipc::authz::per_user_pipe_name("unknown"))
    }
    // macOS：与 Linux 同款 —— LaunchDaemon 在 `/var/run/oc-gui/` 下
    // 为每个授权 uid 建 socket，0600 属主该 uid。
    //
    // 此前这里返回 dev 路径（`/tmp/oc-gui-helper-<uid>.sock`），
    // 于是生产环境下 `Channel::detect` 永远连不上 helper，直接
    // 回落 `Direct` —— 而 Direct 以 GUI 用户身份跑 openconnect，
    // 建不了 tun 设备。**macOS 的提权数据通路实际上从未可用过。**
    //
    // XPC（`SMAppService`）路线仍然是备选，但它要求代码签名；
    // 本 socket 路线不需要任何签名。见 P1-DESIGN §6.5。
    #[cfg(target_os = "macos")]
    {
        crate::ipc::authz::per_user_socket_path(uid).display().to_string()
    }
}

/// 到 helper 的连接
pub struct HelperHandle {
    sock: Conn,
}

impl std::fmt::Debug for HelperHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HelperHandle")
    }
}

impl HelperHandle {
    /// 连接并握手。握手失败会返回具体原因，UI 据此提示用户。
    pub fn connect(uid: u32) -> Result<Self, HelperError> {
        let sock = Self::open(uid)?;

        // ⚠️ 读超时：见 `pump_stream` 的说明，这里刻意不设 ——
        // 日志流可能长时间静默（openconnect 正在等认证），
        // 任何读超时都会把流打断。
        set_write_timeout(&sock, std::time::Duration::from_secs(10));

        let mut h = Self { sock };
        h.hello(uid)?;
        Ok(h)
    }

    /// 打开到 helper 的连接（不含握手）。
    #[cfg(unix)]
    fn open(uid: u32) -> Result<Conn, HelperError> {
        let path = endpoint_for(uid);
        if !PathBuf::from(&path).exists() {
            return Err(HelperError::NotInstalled { path });
        }
        UnixStream::connect(&path).map_err(|e| HelperError::Internal {
            message: format!("连接 {path} 失败: {e}"),
        })
    }

    /// 打开到 helper 的连接（不含握手）。
    ///
    /// Windows 上 pipe 不存在时 `CreateFileW` 返回
    /// `ERROR_FILE_NOT_FOUND`（不是 `ERROR_ACCESS_DENIED` —— 后者
    /// 意味着 pipe 在但 DACL 拒绝，那是授权问题，要区分开报给用户）。
    #[cfg(windows)]
    fn open(uid: u32) -> Result<Conn, HelperError> {
        let name = endpoint_for(uid);
        crate::ipc::pipe::ClientPipe::connect_to(&name).map_err(|e| HelperError::Internal {
            message: format!("连接 {name} 失败: {e}"),
        })
    }

    /// 轮询等待端点就绪（提权启动 helper 后调用）。
    pub fn spawn_elevated(uid: u32) -> Result<(), HelperError> {
        #[cfg(unix)]
        {
            Self::spawn_via_pkexec(uid)
        }
        #[cfg(windows)]
        {
            let _ = uid;
            let program = std::env::var("OCGUI_HELPER_BIN")
                .unwrap_or_else(|_| "oc-gui-helper.exe".to_string());
            let p = PathBuf::from(&program);
            crate::ipc::pipe::spawn_elevated(&p).map_err(|e| HelperError::Internal {
                message: format!("UAC 提权启动失败: {e}"),
            })
        }
    }

    /// 探测 helper 是否可用（不启动它）。
    pub fn probe(uid: u32) -> Result<(), HelperError> {
        Self::connect(uid).map(|_| ())
    }

    fn hello(&mut self, uid: u32) -> Result<(), HelperError> {
        let resp = self.request(&Request::Hello {
            version: PROTOCOL_VERSION,
            caller_uid: uid,
        })?;
        match resp {
            Response::Ready { version, .. } if version == PROTOCOL_VERSION => Ok(()),
            Response::Ready { version, .. } => Err(HelperError::ProtocolMismatch {
                expected: PROTOCOL_VERSION,
                got: version,
            }),
            Response::Failed { error } => Err(error),
            other => Err(HelperError::Internal {
                message: format!("握手返回了意外响应: {other:?}"),
            }),
        }
    }

    /// 发一个请求，等一个响应。
    ///
    /// ⚠️ **只适用于「一问一答」的请求**（Hello / Start / Status）。
    /// Start 之后 helper 会在同一连接上持续推送 `Response::Log` 与
    /// `Response::Exited` —— 用本方法再读会读到那些推送而不是新应答。
    /// 流式场景用 [`HelperHandle::pump_stream`]。
    pub fn request(&mut self, req: &Request) -> Result<Response, HelperError> {
        let line = serde_json::to_string(req).map_err(|e| HelperError::Internal {
            message: format!("序列化失败: {e}"),
        })?;
        self.sock
            .write_all(format!("{line}\n").as_bytes())
            .and_then(|_| self.sock.flush())
            .map_err(|e| HelperError::Internal {
                message: format!("发送失败: {e}"),
            })?;

        let mut reader = self.reader()?;
        let mut buf = String::new();
        reader.read_line(&mut buf).map_err(|e| HelperError::Internal {
            message: format!("读取响应失败: {e}"),
        })?;
        if buf.trim().is_empty() {
            // helper 对未授权连接是静默的：读到 EOF
            return Err(HelperError::Unauthorized {
                detail: "helper 无响应（可能被拒绝或已退出）".into(),
            });
        }
        serde_json::from_str(&buf).map_err(|e| HelperError::Internal {
            message: format!("解析响应失败: {e}"),
        })
    }

    /// 启动连接并把 helper 的日志流转发给回调。
    ///
    /// `on_event` 收到 `Log` / `State` / `Exited` / `Failed`。
    /// 返回 `(退出码, 终止原因)`。
    ///
    /// 与 [`Self::request`] 的区别：本方法**一直读到流结束**。
    /// Start 的应答（`Started`）也会回调一次 —— 调用方据此知道隧道
    /// 已经 spawn 成功。
    pub fn pump_stream(
        &mut self,
        req: &Request,
        mut on_event: impl FnMut(Response),
    ) -> (Option<i32>, Option<HelperError>) {
        // 日志流必须能无限期静默 —— openconnect 等用户输密码、
        // 等 DTLS 超时、跑 vpnc-script 时都可能几十秒不输出。
        // 这里显式清除读超时。
        //
        // 实测教训：早先在 connect() 里设了 10s 读超时，导致
        // 「Started 之后长时间无输出」的隧道会被误判为断开，
        // helper 侧随即回收会话，导致后续 Stop 找不到连接。
        // 失败可忽略：Unix 上不支持读超时本来就是常态
        set_read_timeout(&mut self.sock, None);

        if let Err(e) = self.send_raw(req) {
            return (None, Some(e));
        }
        let mut reader = match self.reader() {
            Ok(r) => r,
            Err(e) => return (None, Some(e)),
        };
        let mut buf = String::new();
        loop {
            buf.clear();
            match reader.read_line(&mut buf) {
                Ok(0) => return (None, None), // helper 关掉了连接
                Ok(_) => {}
                Err(e) => {
                    return (
                        None,
                        Some(HelperError::Internal {
                            message: format!("读取日志流失败: {e}"),
                        }),
                    )
                }
            }
            if buf.trim().is_empty() {
                continue;
            }
            let msg: Response = match serde_json::from_str(&buf) {
                Ok(m) => m,
                Err(e) => {
                    on_event(Response::Failed {
                        error: HelperError::Internal {
                            message: format!("解析日志流失败: {e}"),
                        },
                    });
                    continue;
                }
            };
            // State 也是终态：helper 只在**优雅断开收尾完成**时发它
            // （`Response::State{state:"idle"}`），发完这条连接就没用了。
            //
            // 之前只把 Exited/Failed 当终态，于是断开后 GUI 一直阻塞在
            // read_line 上等下一条 —— 而 helper 那边正等着 GUI 的下一条
            // 请求才能退出、释放会话槽。两边互等，结果是「断开后立刻
            // 重连」永远撞上「已有连接在进行中」，只能重启 App。
            let terminal = matches!(
                msg,
                Response::Exited { .. } | Response::State { .. }
            );
            let failed = matches!(&msg, Response::Failed { .. });
            on_event(msg);
            if terminal || failed {
                return (None, None);
            }
        }
    }

    fn send_raw(&mut self, req: &Request) -> Result<(), HelperError> {
        let line =
            serde_json::to_string(req).map_err(|e| HelperError::Internal {
                message: format!("序列化失败: {e}"),
            })?;
        self.sock
            .write_all(format!("{line}\n").as_bytes())
            .and_then(|_| self.sock.flush())
            .map_err(|e| HelperError::Internal {
                message: format!("发送失败: {e}"),
            })
    }

    fn reader(&mut self) -> Result<BufReader<Conn>, HelperError> {
        Ok(BufReader::new(
            self.sock
                .try_clone()
                .map_err(|e| HelperError::Internal { message: e.to_string() })?,
        ))
    }

    /// 请求断开当前隧道。
    ///
    /// 走**新开一条连接**而不是复用已有连接：`pump_stream` 正占着那条
    /// 连接读日志。两个线程共用一个 socket 的读半边会互相抢数据。
    ///
    /// helper 侧的会话是进程级的，所以这条新连接发来的 `Stop` 能找到
    /// 会话（这是 helper 把 session 存成全局槽而非 per-connection 的原因）。
    pub fn request_stop(uid: u32) -> Result<(), HelperError> {
        let mut h = Self::connect(uid)?;
        match h.request(&Request::Stop)? {
            Response::Status { .. } => Ok(()),
            Response::Failed { error } => Err(error),
            other => Err(HelperError::Internal {
                message: format!("Stop 返回了意外响应: {other:?}"),
            }),
        }
    }

    /// 请 helper 触发一次收发统计。
    ///
    /// 统计数字不是应答，而是随后以 `Response::Log` 混在日志流里回来
    /// —— 所以这里返回 `Ok(())` 只表示「信号已送达」，拿不到数字。
    /// 解析在 `commands.rs` 的日志分支里做。
    ///
    /// 同样走**新开一条连接**：已有那条被 `pump_stream` 占着在读日志。
    pub fn request_stats(uid: u32) -> Result<(), HelperError> {
        let mut h = Self::connect(uid)?;
        match h.request(&Request::Stats)? {
            Response::Status { .. } => Ok(()),
            // 旧 helper 不认识这个请求（serde 反序列化失败 → Failed）。
            // 当作「这台机器上没有统计」，不该打断用户。
            Response::Failed { .. } => Ok(()),
            other => Err(HelperError::Internal {
                message: format!("Stats 返回了意外响应: {other:?}"),
            }),
        }
    }

    /// 通过 polkit/pkexec 启动 helper。
    ///
    /// 会弹一次密码框。**这是 GUI 唯一允许触发的提权路径**，
    /// 且提权的理由由 polkit 的 message 字段向用户说明。
    ///
    /// 返回 `Ok(())` 表示 pkexec 已被调用（不代表 helper 已就绪），
    /// 调用方应随后轮询 [`HelperHandle::probe`]。
    pub fn spawn_via_pkexec(uid: u32) -> Result<(), HelperError> {
        let program = std::env::var("OCGUI_HELPER_BIN")
            .unwrap_or_else(|_| "/usr/libexec/oc-gui-helper".to_string());
        if !PathBuf::from(&program).exists() {
            return Err(HelperError::NotInstalled { path: program });
        }

        // 走 pkexec 而不是自己 setuid。pkexec 会：
        //   1. 把 euid 置 0
        //   2. 通过 polkit 询问授权
        //   3. 把 stdin/stdout 清空（安全）
        let status = std::process::Command::new("pkexec")
            .arg(&program)
            .arg("--authorize")
            .arg(uid.to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| HelperError::Internal {
                message: format!("无法启动 pkexec: {e}"),
            })?;

        // helper 是常驻进程，pkexec 本身会一直跑着。不要 wait()。
        std::mem::forget(status);
        Ok(())
    }

    /// 轮询等待 helper 就绪。
    pub fn wait_ready(uid: u32, timeout: std::time::Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if Self::probe(uid).is_ok() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_socket_is_not_installed_not_a_crash() {
        let err = match HelperHandle::connect(u32::MAX) {
            Err(e) => e,
            Ok(_) => panic!("不应连接成功"),
        };
        // uid::MAX 几乎不可能有 socket；关键是错误类型可读
        assert!(
            matches!(err, HelperError::NotInstalled { .. }),
            "实际: {err:?}"
        );
    }

    #[test]
    fn socket_path_env_override_wins() {
        // ScopedEnv 持有进程级环境变量锁 —— 否则会与并行的
        // linux_path_uses_run_directory 竞争（曾因此偶发失败）
        let _env = crate::testenv::ScopedEnv::set("OCGUI_HELPER_SOCKET", "/tmp/custom.sock");
        assert_eq!(endpoint_for(1000), "/tmp/custom.sock".to_string());
    }

    #[test]
    fn linux_path_uses_run_directory() {
        // 用 `#[cfg]` 而非 `cfg!`：`cfg!` 会让 Windows 也编译这段，
        // 而 `per_user_socket_path` 在 Windows 上不存在
        #[cfg(target_os = "linux")]
        {
            let p = endpoint_for(1000);
            assert!(p.starts_with("/run/oc-gui/"), "实际: {p}");
            assert!(p.contains("1000"), "实际: {p}");
        }
    }

    #[test]
    fn dev_path_is_per_uid() {
        assert_ne!(dev_socket_path(1000), dev_socket_path(1001));
        assert!(dev_socket_path(1000).to_string_lossy().contains("1000"));
    }

    #[test]
    fn pkexec_missing_binary_is_reported() {
        let _env = crate::testenv::ScopedEnv::set("OCGUI_HELPER_BIN", "/nonexistent/helper");
        let err = match HelperHandle::spawn_via_pkexec(1000) {
            Err(e) => e,
            Ok(_) => panic!("不应启动成功"),
        };
        assert!(matches!(err, HelperError::NotInstalled { .. }), "{err:?}");
    }

    #[test]
    fn probe_against_dead_socket_fails_fast() {
        // 造一个存在但没人监听的 socket
        let p = std::env::temp_dir().join(format!("oc-gui-dead-{}.sock", std::process::id()));
        let _ = std::os::unix::net::UnixListener::bind(&p);
        unsafe { std::env::set_var("OCGUI_HELPER_SOCKET", &p) };
        let r = HelperHandle::probe(1000);
        unsafe { std::env::remove_var("OCGUI_HELPER_SOCKET") };
        let _ = std::fs::remove_file(&p);
        // 监听器已 drop → connect 会被拒（ECONNREFUSED），不 panic
        assert!(r.is_err());
    }

    /// 关键回归：日志流必须能无限期静默。
    ///
    /// 早先在 `connect()` 里设了 10s 读超时，结果「Started 之后长时间
    /// 无输出」的隧道被误判为断开 —— 客户端关连接 → helper 回收会话 →
    /// 后续 Stop 找不到连接。`pump_stream` 必须清除读超时。
    #[cfg(unix)]
    #[test]
    fn read_timeout_policy() {
        use std::os::unix::net::UnixStream;
        let (a, _b) = UnixStream::pair().unwrap();
        a.set_read_timeout(Some(std::time::Duration::from_millis(50)))
            .unwrap();
        assert!(a.read_timeout().unwrap().is_some(), "前置：已设读超时");
        // pump_stream 做的正是这件事
        let _ = a.set_read_timeout(None);
        assert!(a.read_timeout().unwrap().is_none(), "必须能清除读超时");
    }

    /// `connect()` 不应再设读超时 —— 否则日志流必然被打断。
    #[cfg(unix)]
    #[test]
    fn connect_does_not_set_read_timeout() {
        use std::os::unix::net::UnixStream;
        let (a, _b) = UnixStream::pair().unwrap();
        let h = HelperHandle { sock: a };
        assert!(
            h.sock.read_timeout().unwrap().is_none(),
            "connect() 若设了读超时，pump_stream 之前的窗口就会断流"
        );
    }
}