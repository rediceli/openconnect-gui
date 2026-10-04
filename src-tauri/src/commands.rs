//! Tauri 命令层：profile CRUD + 连接控制
//!
//! 连接线程模型：
//! - `connect` 在 Tauri 的异步运行时里 spawn 一个 task
//! - openconnect 的 stdout/stderr 由 supervisor 的独立线程读取
//! - 状态变化通过 `app.emit()` 推给前端
//! - `disconnect` 通过 channel 通知 pump 线程退出
//!
//! 前端只需订阅事件，不做轮询。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};

use crate::channel::{self, Channel as Channel2};
use crate::profile::{self, Profile, Repo};
use crate::secret;
use crate::tunnel::{argv, Event, State as ConnState, TerminalCause};

/// 前端监听的事件名
pub mod events {
    pub const STATE: &str = "vpn://state";
    pub const LOG: &str = "vpn://log";
    pub const CAUSE: &str = "vpn://cause";
}

/// 应用级状态
pub struct AppState {
    pub repo: Repo,
    /// 当前运行的连接（若有）
    session: Mutex<Option<Box<SessionHandle>>>,
}

struct SessionHandle {
    /// openconnect 的 pid，由 connect 线程在 spawn 成功后写入。
    /// 保留给未来「断开超时强杀」用 —— 当前 SIGINT 由 cancel 轮询线程负责。
    #[allow(dead_code)]
    pid: Arc<Mutex<Option<u32>>>,
    /// 置位后 pump 线程会主动断开
    cancel: Arc<AtomicBool>,
}

use std::sync::Arc;

/// 供前端消费的连接状态快照
#[derive(Serialize, Clone)]
pub struct StatePayload {
    pub state: ConnState,
    pub profile_id: String,
    pub pid: Option<u32>,
}

#[derive(Serialize, Clone)]
pub struct CausePayload {
    pub profile_id: String,
    pub cause: TerminalCause,
    pub message_key: String,
    pub retryable: bool,
}

#[derive(Serialize, Clone)]
pub struct LogPayload {
    pub profile_id: String,
    pub line: String,
    pub level: String,
}

// ---------------------------------------------------------------------------
// Profile CRUD
// ---------------------------------------------------------------------------

/// 从 Tauri 托管状态里取 AppState。
fn st(app: &AppHandle) -> Result<tauri::State<'_, AppState>, String> {
    app.try_state::<AppState>()
        .ok_or_else(|| "应用状态未初始化".to_string())
}

#[tauri::command]
pub fn list_profiles(app: AppHandle) -> Result<Vec<Profile>, String> {
    Ok(st(&app)?.repo.load().map_err(to_err)?.profiles)
}

#[tauri::command]
pub fn save_profile(app: AppHandle, profile: Profile) -> Result<Profile, String> {
    let repo = &st(&app)?.repo;
    let mut store = repo.load().map_err(to_err)?;

    // 同步 password_saved 标志，避免 UI 与钥匙串不一致
    let mut p = profile;
    p.password_saved = if p.remember_password && secret::password(&p).is_some() {
        Some(true)
    } else {
        None
    };
    if let Some(c) = &p.client_cert {
        let _ = c;
    }

    match store.profiles.iter_mut().find(|x| x.id == p.id) {
        Some(slot) => *slot = p.clone(),
        None => store.profiles.push(p.clone()),
    }
    repo.save(&store).map_err(to_err)?;
    Ok(p)
}

/// 探测服务器证书，供首次信任（TOFU）弹窗使用。
///
/// 客户端在 `server_cert_pin` 为空时先调这个，把证书信息与指纹
/// 交给用户确认；确认后调 [`trust_server_cert`] 写入 pin，
/// 之后连接走 `--servercert=pin-sha256:...`，openconnect 不再
/// 向已被密钥占用的 stdin 索要交互确认。
#[tauri::command]
pub async fn probe_server_cert(
    server: String,
) -> Result<crate::tlsprobe::CertInfo, String> {
    // 探测要真连服务器，放到阻塞线程池，避免卡住 Tauri 的 IPC 线程
    tauri::async_runtime::spawn_blocking(move || crate::tlsprobe::probe(&server))
        .await
        .map_err(|e| format!("探测任务异常退出: {e}"))?
}

/// 用户确认后把证书 pin 写入 profile。
///
/// 只接受格式合法的 pin —— 免得 UI 传进来乱七八糟的东西被写进
/// `--servercert`，导致连接以难以理解的方式失败。
#[tauri::command]
pub fn trust_server_cert(
    app: AppHandle,
    profile_id: String,
    pin: String,
) -> Result<Profile, String> {
    let pin = pin.trim().to_string();
    if !pin.starts_with("pin-sha256:") || pin.len() < 20 {
        return Err(format!("非法证书 pin: {pin:?}"));
    }
    let repo = &st(&app)?.repo;
    let mut store = repo.load().map_err(to_err)?;
    let p = store
        .profiles
        .iter_mut()
        .find(|p| p.id == profile_id)
        .ok_or_else(|| format!("找不到 profile {profile_id}"))?;
    p.advanced.server_cert_pin = Some(pin);
    let snapshot = p.clone();
    repo.save(&store).map_err(to_err)?;
    Ok(snapshot)
}

/// 保存密码到系统钥匙串。
///
/// ⚠️ 密码只走这一步，绝不写进 profile 文件。
#[tauri::command]
pub fn store_password(profile: Profile, password: String) -> Result<bool, String> {
    if password.is_empty() {
        secret::delete(&profile, profile::SecretKind::Password).map_err(to_err)?;
        return Ok(false);
    }
    secret::set(&profile, profile::SecretKind::Password, &password).map_err(to_err)?;
    Ok(true)
}

/// 删除档案。**必须同时清理钥匙串**，否则会留下孤儿条目。
#[tauri::command]
pub fn delete_profile(app: AppHandle, id: String) -> Result<(), String> {
    let repo = &st(&app)?.repo;
    let mut store = repo.load().map_err(to_err)?;
    if let Some(idx) = store.profiles.iter().position(|p| p.id == id) {
        let p = store.profiles.remove(idx);
        secret::purge(&p);
    }
    repo.save(&store).map_err(to_err)
}

/// 钥匙串里到底有没有密码（UI 用来显示「已保存」标记）
#[tauri::command]
pub fn has_saved_password(profile: Profile) -> bool {
    secret::password(&profile).is_some()
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// 特权助手
// ---------------------------------------------------------------------------

/// 前端展示的助手状态
#[derive(Serialize, Clone)]
pub struct HelperStatus {
    /// 是否有可用的特权通道
    pub privileged: bool,
    /// 助手是否已就绪
    pub helper_ready: bool,
    /// 助手二进制是否已安装
    pub helper_installed: bool,
    /// 当前使用的通道
    pub channel: &'static str,
    /// 面向用户的说明
    pub message: String,
    pub message_key: &'static str,
    /// GUI 侧应执行的提权命令（供 UI 展示「复制这条命令」）
    pub elevate_command: Option<String>,
    /// 平台相关的原始状态串（如 macOS 的 not_found / requires_approval）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// macOS 未安装特权助手时给用户的指引。
///
/// 只给文字不给可粘贴命令：安装脚本在源码仓库里，不在 App bundle 内，
/// 拼不出一个在用户机器上真实存在的路径。
#[cfg(target_os = "macos")]
const MACOS_INSTALL_HINT: &str =
    "在 OC GUI 源码仓库中运行：sudo ./src-tauri/Scripts/install-macos-daemon.sh";

#[tauri::command]
pub fn helper_status() -> Result<HelperStatus, String> {
    // ---- macOS：两条通道，先看实际能用的那条 ----
    //
    // macOS 上有两条互不依赖的特权通道：
    //
    // 1. **LaunchDaemon + Unix socket**（免签名，当前的主路径）
    //    由 `Scripts/install-macos-daemon.sh` 安装。只要 socket 存在
    //    就能用，不需要 Developer ID。
    // 2. **XPC + SMAppService**（需要 Developer ID 签名）
    //    注册状态由 `macosctl` 查询。
    //
    // 判定顺序按「实际能不能连」来，而不是按哪条更现代 —— 否则装了
    // LaunchDaemon 的用户会看到 UI 报「未就绪」，因为他没买证书。
    #[cfg(target_os = "macos")]
    {
        let uid = channel::current_uid();
        let sock = crate::ipc::client::endpoint_for(uid);
        let socket_ready = std::path::Path::new(&sock).exists();

        if socket_ready {
            return Ok(HelperStatus {
                privileged: true,
                helper_ready: true,
                helper_installed: true,
                channel: "socket",
                message: "特权助手已就绪".into(),
                message_key: "helper.status.ready",
                elevate_command: None,
                detail: Some(sock),
            });
        }

        // 没有 socket —— 退到 XPC 路线（可能已签名）
        let state = channel::macos::daemon_state().unwrap_or_else(|_| "unknown".into());
        let registered = state == "registered";
        let (message, message_key) = match state.as_str() {
            "registered" => ("特权助手已就绪", "helper.status.ready"),
            // not_found = plist 未 embed 进 App bundle 或签名不匹配。
            // 与 not_registered 是不同的用户动作，提示也不同。
            "not_found" => (
                "特权助手未随应用安装，请重新安装 OC GUI",
                "helper.status.not_found",
            ),
            "requires_approval" => (
                "请在「系统设置 → 通用 → 登录项」批准 OC GUI",
                "helper.status.requires_approval",
            ),
            _ => (
                "需要管理员权限才能建立 VPN 连接",
                "helper.status.need_elevation",
            ),
        };
        Ok(HelperStatus {
            privileged: registered,
            helper_ready: registered,
            helper_installed: channel::macos::find_macosctl().is_some(),
            channel: "xpc",
            message: message.to_string(),
            message_key,
            // 未签名时给不出可执行的「一键提权」—— 安装要手动跑脚本。
            //
            // ⚠️ 这里**不能**用 `env!("CARGO_MANIFEST_DIR")` 拼路径：
            // 那是编译机的绝对路径（如 /Users/xxx/work/...），会被烧进
            // 二进制里，给用户显示一条他机器上根本不存在的命令。
            // 脚本本身也在源码仓库里、不在 App bundle 内，所以只能给
            // 文字指引。
            elevate_command: if registered {
                None
            } else {
                Some(MACOS_INSTALL_HINT.to_string())
            },
            detail: Some(format!("xpc={state} socket={sock}")),
        })
    }

    // ---- Linux：polkit + Unix socket ----
    #[cfg(not(target_os = "macos"))]
    {
        let uid = channel::current_uid();
        let ch = Channel2::detect(uid);
        let privileged = ch.is_privileged();

        let helper_ready = crate::ipc::client::HelperHandle::probe(uid).is_ok();
        let helper_bin = std::env::var("OCGUI_HELPER_BIN")
            .unwrap_or_else(|_| "/usr/libexec/oc-gui-helper".into());
        let helper_installed = std::path::Path::new(&helper_bin).exists();

        let (channel_name, message, message_key) = if privileged {
            ("helper", "特权助手已就绪", "helper.status.ready")
        } else if helper_installed {
            (
                "direct",
                "需要管理员权限才能建立 VPN 连接",
                "helper.status.need_elevation",
            )
        } else {
            (
                "direct",
                "未检测到特权助手，创建 VPN 连接需要管理员权限",
                "helper.status.not_installed",
            )
        };

        Ok(HelperStatus {
            privileged,
            helper_ready,
            helper_installed,
            channel: channel_name,
            message: message.to_string(),
            message_key,
            elevate_command: if privileged {
                None
            } else {
                Some(format!("pkexec {helper_bin} --authorize {uid}"))
            },
            detail: None,
        })
    }
}

/// 打开 macOS「系统设置」的登录项页面。
///
/// SMAppService 注册后不会自动批准，必须让用户手动开关。
/// 直接深链到登录项省掉用户自己找的麻烦。
///
/// 注：两个平台用 `#[cfg]` 分成独立函数而不是在一个函数里写
/// `#[cfg] { } else { }` —— 属性不能标注在 `else` 之前的块表达式上
/// （`error: expected expression, found keyword 'else'`）。
#[tauri::command]
#[cfg(target_os = "macos")]
pub fn open_system_settings() -> Result<(), String> {
    // login-items 是 Apple 认可的深链；失败时退回打开设置首页
    let url = "x-apple.systempreferences:com.apple.LoginItems-Settings.extension";
    let ok = std::process::Command::new("open")
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        let _ = std::process::Command::new("open")
            .arg("-a")
            .arg("System Settings")
            .status();
    }
    Ok(())
}

#[tauri::command]
#[cfg(not(target_os = "macos"))]
pub fn open_system_settings() -> Result<(), String> {
    // Linux 上没有「系统设置」这个概念，用 pkexec 兜底
    let uid = channel::current_uid();
    crate::ipc::client::HelperHandle::spawn_elevated(uid).map_err(|e| e.to_string())
}

/// 请求启动/注册特权助手。会弹系统密码框（Linux）或进入系统设置批准流（macOS）。
#[tauri::command]
pub fn helper_start_elevated() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        // SMAppService 注册不弹密码框 —— 返回状态让 UI 决定引导。
        channel::macos::register_daemon().map_err(|e| e.to_string())
    }

    #[cfg(not(target_os = "macos"))]
    {
        let uid = channel::current_uid();
        crate::ipc::client::HelperHandle::spawn_elevated(uid)
            .map_err(|e| e.to_string())?;
        Ok("registered".to_string())
    }
}

/// 等待助手就绪（前端轮询用，通常在 helper_start_elevated 之后）
#[tauri::command]
pub fn helper_wait_ready(timeout_ms: u64) -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        // macOS 没有「等 socket」这回事 —— 只看注册状态。
        let _ = timeout_ms;
        Ok(channel::macos::daemon_state()
            .map(|s| s == "registered")
            .unwrap_or(false))
    }

    #[cfg(not(target_os = "macos"))]
    {
        let uid = channel::current_uid();
        Ok(crate::ipc::client::HelperHandle::wait_ready(
            uid,
            std::time::Duration::from_millis(timeout_ms.clamp(500, 60_000)),
        ))
    }
}

// ---------------------------------------------------------------------------
// 连接控制
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn connect(
    app: AppHandle,
    profile: Profile,
    password: Option<String>,
    cookie: Option<String>,
) -> Result<(), String> {
    // ---- 单连接互斥 ----
    {
        let state = st(&app)?;
        let s = state.session.lock().map_err(to_err)?;
        if s.is_some() {
            return Err("已有连接在进行中".into());
        }
    }

    // ---- 取密钥 ----
    // 优先级：显式传入 > 钥匙串
    let pw = password.or_else(|| secret::password(&profile));
    let secrets = argv::Secrets {
        password: pw,
        cookie,
        key_password: secret::key_password(&profile),
        mca_key_password: secret::get(&profile, profile::SecretKind::McaKeyPassword).ok(),
        token_secret: secret::token_secret(&profile),
    };

    // 构建期致命错误（如私钥口令无法安全写入 config 文件）直接拒绝，
    // 不降级到明文 argv。
    let plan = argv::build(&profile, &secrets);
    if let Some(e) = &plan.fatal_error {
        return Err(e.clone());
    }

    let uid = channel::current_uid();
    let mut ch = channel::Channel::detect(uid);
    let profile_id = profile.id.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    let pid_slot: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));

    let h_cancel = cancel.clone();
    let h_app = app.clone();
    let h_profile_id = profile_id.clone();
    let h_pid = pid_slot.clone();
    tauri::async_runtime::spawn_blocking(move || {
        // ---- 启动 + 流式转发 ----
        // 两种通道都走 start_streaming：Direct 读子进程管道，
        // Helper 读 socket 上的 Response::Log 推送。
        let pid_slot_for_stream = h_pid.clone();
        let app_state = h_app.clone();
        let id_state = h_profile_id.clone();
        let app_log = h_app.clone();
        let id_log = h_profile_id.clone();

        let result = ch.start_streaming(
            &plan,
            pid_slot_for_stream,
            move |ev| match ev {
                channel::StreamEvent::Started { pid } => {
                    let _ = app_state.emit(
                        events::STATE,
                        StatePayload {
                            state: ConnState::Connecting,
                            profile_id: id_state.clone(),
                            pid: Some(pid),
                        },
                    );
                }
                channel::StreamEvent::Log { line, state } => {
                    if !line.is_empty() {
                        let level = crate::tunnel::parse_line(&line)
                            .map(|e: Event| format!("{:?}", e.level).to_lowercase())
                            .unwrap_or_else(|| "info".into());
                        let _ = app_log.emit(
                            events::LOG,
                            LogPayload {
                                profile_id: id_log.clone(),
                                line,
                                level,
                            },
                        );
                    }
                    if let Some(s) = state {
                        let _ = app_log.emit(
                            events::STATE,
                            StatePayload {
                                state: s,
                                profile_id: id_log.clone(),
                                pid: None,
                            },
                        );
                    }
                }
                channel::StreamEvent::Finished { state, cause } => {
                    let _ = app_state.emit(
                        events::STATE,
                        StatePayload {
                            state,
                            profile_id: id_state.clone(),
                            pid: None,
                        },
                    );
                    if let Some((key, retryable)) = cause {
                        // reason 留空：helper 通道下终止原因由
                        // message_key 承载（UI 显示 i18n 文案），
                        // 而非 openconnect 的原始日志行。
                        let _ = app_state.emit(
                            events::CAUSE,
                            CausePayload {
                                profile_id: id_state.clone(),
                                cause: TerminalCause::Unknown {
                                    reason: String::new(),
                                },
                                message_key: key,
                                retryable,
                            },
                        );
                    }
                }
                channel::StreamEvent::Exited { code } => {
                    let _ = app_state.emit(
                        events::STATE,
                        StatePayload {
                            state: ConnState::Idle,
                            profile_id: id_state.clone(),
                            pid: None,
                        },
                    );
                    let _ = code;
                }
                channel::StreamEvent::Failed { message, key } => {
                    let _ = app_state.emit(
                        events::CAUSE,
                        CausePayload {
                            profile_id: id_state.clone(),
                            cause: TerminalCause::Unknown { reason: message },
                            message_key: key,
                            retryable: true,
                        },
                    );
                }
            },
        );

        if let Err(e) = result {
            let key = e.message_key().to_string();
            let needs_helper = e.needs_privileged_helper();
            let msg = e.to_string();
            let _ = h_app.emit(
                events::CAUSE,
                CausePayload {
                    profile_id: h_profile_id.clone(),
                    cause: if needs_helper {
                        TerminalCause::PrivilegeRequired { hint: msg }
                    } else {
                        TerminalCause::Unknown { reason: msg }
                    },
                    message_key: key,
                    retryable: true,
                },
            );
        }

        let _ = h_cancel;
    });

    // 记录 session 句柄，供 disconnect 用
    {
        let state = st(&app)?;
        if let Ok(mut s) = state.session.lock() {
            *s = Some(Box::new(SessionHandle {
                pid: pid_slot,
                cancel,
            }));
        }
    }
    Ok(())
}

#[tauri::command]
pub fn disconnect(app: AppHandle) -> Result<(), String> {
    // 先看是不是 helper 通道 —— 是的话必须经 Request::Stop，
    // 否则 helper 侧的 SIGINT 只能靠自己的监督线程兜底（隐式依赖）。
    let privileged = Channel2::detect(channel::current_uid()).is_privileged();

    let state = st(&app)?;
    let taken = {
        let mut s = state.session.lock().map_err(to_err)?;
        s.take()
    };

    if let Some(h) = taken {
        h.cancel.store(true, Ordering::SeqCst);
    }

    if privileged {
        // 独立连接发 Stop。失败不阻断 disconnect —— cancel 标志与
        // helper 的监督线程仍会收敛。
        if let Err(e) = crate::ipc::client::HelperHandle::request_stop(
            channel::current_uid(),
        ) {
            log::warn!("helper Stop 失败（将由监督线程兜底）: {e}");
        }
    }
    Ok(())
}

fn to_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// 应用状态初始化
pub fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let repo = Repo::new(Repo::default_dir());
    app.manage(AppState {
        repo,
        session: Mutex::new(None),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_payload_is_serializable() {
        let p = StatePayload {
            state: ConnState::Connected,
            profile_id: "x".into(),
            pid: Some(1),
        };
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("\"connected\""), "state 应序列化为 snake_case: {j}");
    }

    #[test]
    fn cause_payload_carries_i18n_key_and_retryable() {
        let p = CausePayload {
            profile_id: "x".into(),
            cause: TerminalCause::AuthRejected {
                reason: "bad password".into(),
            },
            message_key: "error.auth_rejected".to_string(),
            retryable: true,
        };
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("error.auth_rejected"));
        assert!(j.contains("\"retryable\":true"));
    }

    #[test]
    fn event_names_are_namespaced() {
        // 前端按前缀过滤，避免与 Tauri 内置事件冲突
        for n in [events::STATE, events::LOG, events::CAUSE] {
            assert!(n.starts_with("vpn://"), "事件名必须带命名空间: {n}");
        }
    }
}