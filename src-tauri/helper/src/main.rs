//! 特权 helper（spike 版本）
//!
//! 职责边界（P1 设计）：
//! - 以 root 运行，但**只**执行 `openconnect`
//! - 收到的 argv 会被再次校验（GUI 侧的校验不可信 —— GUI 可能被攻破）
//! - 令牌 secret 由 helper 写 0600 临时文件，GUI 不指定路径
//!
//! 当前实现是 spike：Unix domain socket + JSON 行协议。

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use oc_proto::authz::{
    allowed_uids, authorize, create_per_user_socket, peer_credentials, per_user_socket_path,
    socket_perms, AuthDecision,
};
use oc_proto::{validate_args, validate_program, HelperError, Request, Response, PROTOCOL_VERSION};

fn usage() -> ! {
    eprintln!(
        "用法:\n\
         \x20 oc-gui-helper --authorize <uid>    polkit 授权后，为该用户创建 socket 并常驻\n\
         \x20 oc-gui-helper --serve <socket>      开发模式：在指定路径监听（不推荐）\n\
         \x20 oc-gui-helper --selftest           自检（不需要 root）\n\
         \n\
         GUI 侧应通过 pkexec 调用 --authorize <自己的 uid>：\n\
         \x20 pkexec /usr/libexec/oc-gui-helper --authorize $(id -u)\n\
         \n\
         polkit action: org.github.rediceli.ocgui-helper"
    );
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--selftest") => selftest(),
        Some("--serve") => {
            let path = args.get(2).unwrap_or_else(|| usage());
            serve(path)
        }
        Some("--authorize") => {
            let uid: u32 = match args.get(2).and_then(|s| s.parse().ok()) {
                Some(u) => u,
                None => {
                    eprintln!("--authorize 需要一个 uid 参数");
                    usage()
                }
            };
            authorize_and_serve(uid)
        }
        _ => usage(),
    }
}

/// 生产入口：polkit 已认证（process 以 root 运行），为指定 uid 建立
/// 每用户 socket 并常驻。
///
/// # 为什么 socket 路径由 uid 决定
///
/// `/run/oc-gui/helper-<uid>.sock`，权限 0600 属主该 uid。
/// 授权结果直接编码在文件系统权限里：
/// - 没通过 polkit ⇒ 根本没这个文件
/// - 通过了 polkit 的 uid ⇒ 只有它能打开
/// 不存在「先连上再被拒」的中间态，也不存在白名单变更后的残留。
///
/// # 为什么还要再查一遍 uid
///
/// 文件系统权限是第一道防线，`authorize()` 是第二道。两者独立：
/// 即使 `/run/oc-gui` 的目录权限被误配成 0777，
/// socket 本身仍是 0600 + 正确属主。
fn authorize_and_serve(target_uid: u32) {
    let self_uid = unsafe { libc::geteuid() };

    if self_uid != 0 {
        eprintln!("拒绝启动：必须以 root 运行（当前 euid={self_uid}）");
        eprintln!("提示：GUI 应通过 pkexec 调用本程序");
        std::process::exit(2);
    }
    if target_uid == 0 {
        eprintln!("拒绝为 root 创建 socket");
        std::process::exit(2);
    }

    let path = per_user_socket_path(target_uid);
    let listener = match create_per_user_socket(target_uid) {
        Ok(l) => {
            eprintln!("helper ready: {}", path.display());
            l
        }
        Err(e) => {
            eprintln!("创建 {} 失败: {e}", path.display());
            std::process::exit(1);
        }
    };

    serve_listener(listener, target_uid, &path);
}

/// 开发模式：直接在给定路径监听。
///
/// ⚠️ **生产环境不要用这个入口** —— 它不创建每用户 socket，
/// 也不做 polkit 授权。存在的唯一理由是本地无 root 环境下
/// 验证协议逻辑。`--authorize` 才是生产入口。
fn serve(socket_path: &str) {
    let self_uid = unsafe { libc::geteuid() };
    let allowed = allowed_uids();

    if allowed.is_empty() {
        if self_uid == 0 {
            eprintln!(
                "拒绝启动：未配置 OCGUI_ALLOWED_UIDS，helper 无可用调用方。\n\
                 例：OCGUI_ALLOWED_UIDS=1000"
            );
            std::process::exit(2);
        }
        eprintln!(
            "警告：OCGUI_ALLOWED_UIDS 为空，所有连接都会被 authorize() 拒绝。\n\
             （当前为非 root 开发模式，继续运行以便本地测试）"
        );
    }

    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {socket_path} 失败: {e}");
            std::process::exit(1);
        }
    };

    // 0600 root：只有 helper 自己能连
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(
        socket_path,
        std::fs::Permissions::from_mode(socket_perms::LOCKED),
    );

    eprintln!(
        "helper listening on {socket_path} (euid={self_uid}, allowed={allowed:?})\n\
         ⚠️ 开发模式入口，未经过 polkit 授权"
    );

    // 开发模式下 self_uid 可能等于 peer uid（如无 root 的本机测试），
    // 此时跳过 self 检查。生产路径不走这里。
    let _ = serve_listener_with(listener, self_uid, allowed, true);
}

/// 监听循环。`allow_self` 仅开发模式为 true。
fn serve_listener(
    listener: UnixListener,
    target_uid: u32,
    path: &std::path::Path,
) -> ! {
    let self_uid = unsafe { libc::geteuid() };
    // 每用户 socket 已由 create_per_user_socket 设好权限，
    // 但仍按 uid 白名单二次校验。
    let allowed = vec![target_uid];
    let _ = serve_listener_with(listener, self_uid, allowed, false);
    eprintln!("helper 退出: {}", path.display());
    std::process::exit(0);
}

fn serve_listener_with(
    listener: UnixListener,
    self_uid: u32,
    allowed: Vec<u32>,
    allow_self: bool,
) -> std::io::Result<()> {
    let slot: SessionSlot = Arc::new(Mutex::new(None));
    for stream in listener.incoming() {
        let s = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept: {e}");
                continue;
            }
        };

        // 授权在**接受连接后、读任何请求前**完成。
        // 顺序很重要：不能先读请求再决定授权，否则未授权的对端
        // 已经能让 helper 分配缓冲区了。
        let cred = match peer_credentials(&s) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("peer_credentials: {e}");
                continue;
            }
        };

        let decision = if allow_self && cred.uid == self_uid {
            AuthDecision::Allow
        } else {
            authorize(cred, self_uid, &allowed)
        };

        match decision {
            AuthDecision::Allow => {
                eprintln!("authorized uid={} pid={}", cred.uid, cred.pid);
                // ⚠️ 必须每连接一个线程。`handle` 会一直阻塞读该连接
                // （日志流场景下是整个隧道期间），在 accept 循环里
                // 同步调用会让**一条长连接饿死所有后续连接** ——
                // 表现为 GUI 的 `disconnect`（走第二条连接发 Stop）
                // 永远收不到应答。
                let slot = slot.clone();
                std::thread::spawn(move || handle(s, &slot));
            }
            AuthDecision::Deny { reason } => {
                eprintln!("denied uid={} pid={}: {reason}", cred.uid, cred.pid);
                // 不回复任何内容，直接关闭。静默拒绝让攻击者
                // 无法区分「helper 不在」与「被拒绝」。
            }
        }
    }
    Ok(())
}

/// 正在运行的 openconnect。
///
/// **整个 helper 进程只有一个**（不是每个连接一个）—— 这有两个原因：
/// 1. helper 是单隧道的，这与 AnyConnect 原生行为一致
/// 2. GUI 的 `disconnect` 走**第二条连接**发 `Request::Stop`。
///    若会话状态按连接保存，第二条连接就找不到它，`Stop` 会静默失效。
struct Session {
    pid: u32,
    /// 置位后监督线程给 openconnect 发断开信号
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// 进程级会话槽
type SessionSlot = Arc<Mutex<Option<Session>>>;

/// 写端被 log pump 线程共享，所以必须包 Mutex。
type Writer = std::sync::Arc<std::sync::Mutex<std::io::BufWriter<UnixStream>>>;

fn handle(stream: UnixStream, slot: &SessionSlot) {
    let out = match stream.try_clone() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("try_clone: {e}");
            return;
        }
    };
    let w: Writer = std::sync::Arc::new(std::sync::Mutex::new(
        std::io::BufWriter::new(out),
    ));
    let r = BufReader::new(stream);
    let slot = slot.clone();
    // 本连接是否拥有会话（拥有者断开时才负责收尾）
    let mut owns_session = false;

    for line in r.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                send(
                    &w,
                    Response::Failed {
                        error: HelperError::Internal {
                            message: format!("bad json: {e}"),
                        },
                    },
                );
                continue;
            }
        };

        match req {
            Request::Start {
                args,
                server,
                stdin_secrets,
                token_secret,
            } => {
                let mut g = slot.lock().unwrap_or_else(|e| e.into_inner());
                if g.is_some() {
                    send(
                        &w,
                        Response::Failed {
                            error: HelperError::AlreadyConnected,
                        },
                    );
                    continue;
                }
                match start_openconnect(&w, args, &server, stdin_secrets, token_secret) {
                    Ok(s) => {
                        *g = Some(s);
                        owns_session = true;
                    }
                    Err(resp) => send(&w, resp),
                }
            }
            Request::Stop => {
                let g = slot.lock().unwrap_or_else(|e| e.into_inner());
                match &*g {
                    Some(s) => {
                        s.stop.store(true, std::sync::atomic::Ordering::SeqCst);
                        send(
                            &w,
                            Response::Status {
                                connected: false,
                                pid: Some(s.pid),
                                uptime_secs: None,
                            },
                        );
                    }
                    None => send(
                        &w,
                        Response::Failed {
                            error: HelperError::NotConnected,
                        },
                    ),
                }
            }
            other => send(&w, dispatch_simple(other)),
        }
    }

    // 连接断了：若是会话所有者则主动断开隧道。
    //
    // 只有所有者这么做 —— 第二条连接（GUI 的 disconnect 用的那条）
    // 正常关闭时**不能**停掉别人的隧道。
    if owns_session {
        if let Some(s) = slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
            s.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// 发一条消息并 flush。
///
/// 不持锁写多行：每条都是独立的一行 JSON，客户端按行读。
fn send(w: &Writer, resp: Response) {
    if let Ok(mut out) = w.lock() {
        if let Ok(s) = serde_json::to_string(&resp) {
            let _ = writeln!(out, "{s}");
            let _ = out.flush();
        }
    }
}

/// 启动 openconnect 并把它的输出流式转发给 GUI。
///
/// 转发而非缓冲的原因：GUI 的状态机靠日志行驱动，且用户要看到
/// 「正在验证身份 / 正在建立隧道」这类实时反馈。缓冲到进程结束会让
/// 日志页在整个连接期间空白。
fn start_openconnect(
    w: &Writer,
    args: Vec<String>,
    server: &str,
    stdin_secrets: Vec<oc_proto::StdinSecret>,
    token_secret: Option<String>,
) -> Result<Session, Response> {
    // ---- 安全边界 1：程序白名单 ----
    let program = std::env::var("OCGUI_OPENCONNECT").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") {
            "/usr/local/bin/openconnect".into()
        } else {
            "/usr/bin/openconnect".into()
        }
    });
    let path = std::path::Path::new(&program);
    if let Err(e) = validate_program(path) {
        return Err(Response::Failed { error: e });
    }

    // ---- 安全边界 2：argv 复检 ----
    // GUI 可能已被攻破，helper 不信任它的校验。
    if let Err(e) = validate_args(&args, server) {
        return Err(Response::Failed { error: e });
    }

    // ---- 安全边界 3：令牌 secret 由 helper 自己管路径 ----
    let mut args = args;
    let tmp_secret: Option<PathBuf> = match token_secret {
        None => None,
        Some(sec) => match write_token_secret(&sec) {
            Ok(p) => {
                for a in args.iter_mut() {
                    if a.starts_with("--token-secret=@") {
                        *a = format!("--token-secret=@{}", p.display());
                    }
                }
                Some(p)
            }
            Err(e) => {
                return Err(Response::Failed {
                    error: HelperError::Internal {
                        message: format!("写入 token secret 失败: {e}"),
                    },
                })
            }
        },
    };

    let mut cmd = std::process::Command::new(path);
    cmd.args(&args).arg(server);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Err(Response::Failed {
                error: HelperError::Internal {
                    message: format!("spawn: {e}"),
                },
            })
        }
    };

    // ---- 密钥只走 stdin ----
    if let Some(mut si) = child.stdin.take() {
        for s in &stdin_secrets {
            let v = match s {
                oc_proto::StdinSecret::Password(p)
                | oc_proto::StdinSecret::Cookie(p) => p,
            };
            let _ = writeln!(si, "{}", v.trim_end_matches(['\r', '\n']));
        }
        let _ = si.flush();
        drop(si);
    }

    let pid = child.id();
    // 立刻删除临时文件：openconnect 在 exec 时已打开它。
    // 删早比删晚安全。
    if let Some(p) = tmp_secret {
        let _ = std::fs::remove_file(p);
    }

    send(w, Response::Started { pid });

    // ---- 日志转发 ----
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let w_out = w.clone();
    let w_err = w.clone();
    let s_poll = stop.clone();
    let s_ctl = stop.clone();

    if let Some(o) = child.stdout.take() {
        spawn_log_pump(o, w_out, s_poll.clone());
    } else {
        // 没有 stdout 也得有 pump，否则等待逻辑会提前结束
        spawn_log_pump(std::io::empty(), w_out, s_poll.clone());
    }
    if let Some(e) = child.stderr.take() {
        spawn_log_pump(e, w_err, s_poll.clone());
    } else {
        spawn_log_pump(std::io::empty(), w_err, s_poll.clone());
    }

    // 监督线程：等 stop 或进程退出，退出时发 Exited
    let w_ex = w.clone();
    std::thread::spawn(move || {
        loop {
            if s_ctl.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(_) => break,
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
        if s_ctl.load(std::sync::atomic::Ordering::SeqCst) {
            // 优雅断开：SIGINT 让 openconnect 跑 vpnc-script 的
            // disconnect 分支清理路由/DNS。用 SIGKILL 会留下脏配置。
            let _ = std::process::Command::new("kill")
                .arg("-INT")
                .arg(pid.to_string())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            // 给 vpnc-script 留时间
            for _ in 0..30 {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            // 还没退就强杀 —— 但要说明可能残留路由
            let _ = child.kill();
            let _ = child.wait();
            send(
                &w_ex,
                Response::State {
                    state: "idle".into(),
                    cause: None,
                },
            );
        } else {
            let code = child.wait().ok().map(|s| s.code()).unwrap_or(None);
            send(&w_ex, Response::Exited { code });
        }
    });

    Ok(Session { pid, stop })
}

/// 从一个流里逐行读，转成 `Response::Log` 发给 GUI。
///
/// `stop` 用于在 helper 决定收尾时让 pump 尽快退出；openconnect 被
/// 强杀后管道自然 EOF，两条路径都能收敛。
fn spawn_log_pump<R: std::io::Read + Send + 'static>(
    reader: R,
    w: Writer,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    std::thread::spawn(move || {
        use std::io::BufRead;
        let br = std::io::BufReader::new(reader);
        for line in br.lines() {
            if stop.load(std::sync::atomic::Ordering::SeqCst) {
                // 不丢弃剩余输出：断开瞬间的日志对排障有用
                if let Ok(l) = line {
                    send(&w, Response::Log { line: l });
                }
                break;
            }
            match line {
                Ok(l) => send(&w, Response::Log { line: l }),
                Err(_) => break,
            }
        }
    });
}

/// 不涉及进程控制的请求
fn dispatch_simple(req: Request) -> Response {
    match req {
        Request::Hello { version, .. } => {
            // 版本不匹配必须直接拒绝，而不是「尽力而为」——
            // 协议语义变更后旧 GUI 的请求可能被误解为提权指令。
            if version != PROTOCOL_VERSION {
                return Response::Failed {
                    error: HelperError::ProtocolMismatch {
                        expected: PROTOCOL_VERSION,
                        got: version,
                    },
                };
            }
            Response::Ready {
                version: PROTOCOL_VERSION,
                authorized: true,
                connected: false,
            }
        }
        Request::Status => Response::Status {
            connected: false,
            pid: None,
            uptime_secs: None,
        },
        Request::Shutdown => {
            eprintln!("收到 Shutdown");
            std::process::exit(0);
        }
        // Start 由 handle() 单独处理，Stop 也需要 session 上下文
        Request::Start { .. } | Request::Stop => Response::Failed {
            error: HelperError::Internal {
                message: "该请求应由会话循环处理".into(),
            },
        },
    }
}

/// 令牌 secret 写 0600 临时文件，路径由 helper 生成，GUI 无法指定。
///
/// 与 `tunnel::occonfig::write_secure` 同样的安全模型：
/// 随机名 + `create_new`（不跟随符号链接）+ 0600 + 调用方指定时限。
fn write_token_secret(secret: &str) -> std::io::Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = std::env::temp_dir();
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for _ in 0..16 {
        let name: String = (0..16)
            .map(|_| {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                let n: usize = ((nanos
                    ^ (std::process::id() as u64).rotate_left(17)
                    ^ secret.len() as u64)
                    % ALPHABET.len() as u64) as usize;
                ALPHABET[n] as char
            })
            .collect();
        let path = dir.join(format!("oc-gui-token-{name}"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut f) => {
                f.write_all(secret.as_bytes())?;
                let _ = f.flush();
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("无法创建临时文件"))
}

/// 不需要 root 的自检：验证协议校验逻辑在本进程内工作。
fn selftest() {
    let ok = ["--protocol=anyconnect".to_string(), "--passwd-on-stdin".to_string()];
    assert!(validate_args(&ok, "vpn.corp.com").is_ok());
    assert!(validate_program(std::path::Path::new("/usr/bin/openconnect")).is_ok());
    assert!(validate_args(&["--csd-wrapper=/bin/sh".to_string()], "x").is_err());
    assert!(validate_program(std::path::Path::new("/bin/sh")).is_err());

    let p = write_token_secret("JBSWY3DPEHPK3PXP").expect("写 token secret");
    let meta = std::fs::metadata(&p).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(meta.permissions().mode() & 0o777, 0o600, "必须是 0600");
    std::fs::remove_file(&p).ok();
    let _: Option<HelperError> = None;

    println!("selftest ok");
}
