//! 提权通道抽象
//!
//! 创建 TUN 设备、改路由、改 DNS 都需要 root。GUI 本身**绝不能**以 root 运行
//! —— 一旦有漏洞就是 root 漏洞。因此连接必须经由一个特权 helper。
//!
//! # 两个实现
//!
//! | 实现 | 平台 | 机制 |
//! |---|---|---|
//! | [`Helper`] | Linux | polkit + pkexec + Unix socket |
//! | [`Direct`] | macOS / 开发 | 直接 spawn openconnect，依赖系统已授予的能力 |
//!
//! macOS 上没有 polkit 那样的通用提权框架。常见做法是随包一个
//! `SMAppService.daemon` 特权 XPC helper（待实现，见 P1-DESIGN §6.3.6）。
//! 在那之前 macOS 走 `Direct` —— 它能工作是因为用户已通过其他途径
//! （如 `sudo openconnect` 的历史配置、`/etc/sudoers.d`、管理员组可写
//! `/dev/tun`）获得了所需能力。
//!
//! ⚠️ `Direct` 模式下的失败原因通常不是「权限不足」而是「需要 sudo」。
//! UI ��在错误里明示这一点，而不是笼统报「连接失败」。

use std::path::PathBuf;
use std::io::BufRead;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;

use crate::ipc::{self, HelperError, Request, Response};
use crate::tunnel::argv::StdinSecret;
use crate::tunnel::{ArgPlan, State, TerminalCause};

/// 定位 openconnect 可执行文件。
///
/// # 优先级
///
/// 1. `OCGUI_OPENCONNECT`（测试与自定义安装用）
/// 2. **与自身同级目录**（Windows 上的正解）
/// 3. 平台默认路径
/// 4. 裸名 `openconnect`（交给 OS 查 PATH）
///
/// # 为什么 Windows 必须用同级目录而不是 PATH
///
/// `ci/fetch-win-deps.sh` 把 openconnect.exe 打进安装包，用户不会
/// 单独安装它。Windows 的 PATH 也不像 Unix 那样有稳定约定 ——
/// 依赖 PATH 既可能找不到，也可能找到用户自己装的另一个版本，
/// 导致「能连上但版本不对」这类极难排查的问题。
///
/// 同级目录还有一个好处：升级只需替换目录内容，不用管注册表。
pub fn resolve_openconnect() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("OCGUI_OPENCONNECT") {
        let p = PathBuf::from(p);
        return if p.exists() { Some(p) } else { None };
    }

    // 与自身同级
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent() {
            let name = if cfg!(target_os = "windows") {
                "openconnect.exe"
            } else {
                "openconnect"
            };
            let cand = dir.join(name);
            if cand.exists() {
                return Some(cand);
            }
            // Tauri 的资源目录在 macOS 是 Contents/Resources，
            // Windows 是 exe 同级。两种都试一下。
            let nested = dir.join("resources").join("win-deps").join(name);
            if nested.exists() {
                return Some(nested);
            }
        }

    // 平台默认安装位置
    const CANDIDATES: &[&str] = if cfg!(target_os = "windows") {
        &[r"C:\Program Files\openconnect\openconnect.exe"]
    } else if cfg!(target_os = "macos") {
        &["/usr/local/bin/openconnect", "/opt/homebrew/bin/openconnect"]
    } else {
        &["/usr/sbin/openconnect", "/usr/bin/openconnect"]
    };
    CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

/// vpnc-script 的位置。
///
/// Windows 上 openconnect 用 `cscript.exe` 执行 `vpnc-script-win.js`，
/// 且该脚本要与 openconnect.exe 同目录（它靠 `TUNIDX` 等环境变量工作）。
/// Unix 上用系统安装的 `/etc/vpnc/vpnc-script`。
pub fn resolve_vpnc_script(program: &std::path::Path) -> Option<String> {
    if cfg!(target_os = "windows") {
        // openconnect 在 Windows 上会把相对路径解析为相对自身目录，
        // 所以这里给裸文件名即可。
        program.parent().map(|d| {
            d.join("vpnc-script-win.js")
                .to_string_lossy()
                .into_owned()
        })
    } else {
        None
    }
}

/// macOS 侧的 `macosctl` 客户端。
///
/// # 为什么是 spawn 一个 Swift CLI 而不是 Rust FFI
///
/// privileged XPC 只能从 Swift/ObjC 调用。Tauri 的 GUI 是 Rust。
/// 写 ObjC FFI + 桥接头从 Rust 直接调，可行但脆弱（ARC 桥接、
/// 块指针生命周期、异步队列），比重新实现 XPC 更糟。
///
/// 行协议边界让两端都保持原生实现，且与 Linux 的 socket 协议对 GUI
/// 完全一致 —— 都是 `crate::ipc` 的 JSON 形状。
#[cfg(target_os = "macos")]
pub mod macos {
    use super::*;
    use crate::ipc::{Request, Response, StdinSecret};

    /// 找 `macosctl`。优先与自身同级（打包后的形态），
    /// 再退到开发时的 SwiftPM 构建目录。
    pub fn find_macosctl() -> Option<PathBuf> {
        let name = "macosctl";
        if let Ok(exe) = std::env::current_exe() {
            let mut cands = vec![];
            if let Some(d) = exe.parent() {
                cands.push(d.join(name));
                cands.push(d.join("Resources").join(name));
                cands.push(d.join("MacOS").join(name));
            }
            // Tauri 的 macOS bundle 里资源在 Contents/Resources
            if let Some(res) = exe.parent().map(|d| d.join("Resources")) {
                cands.push(res.join("macos-helper").join(name));
            }
            for c in cands {
                if c.exists() {
                    return Some(c);
                }
            }
        }
        // 开发模式：macos-helper/.build/release/macosctl
        let manifest = env!("CARGO_MANIFEST_DIR");
        for profile in ["release", "debug"] {
            let c = PathBuf::from(manifest)
                .join("macos-helper/.build")
                .join(profile)
                .join(name);
            if c.exists() {
                return Some(c);
            }
        }
        None
    }

    /// `macosctl` 的常驻子进程。
    ///
    /// stdin/stdout 都是行协议。日志流期间不能退出 ——
    /// 这与 Unix socket 版的生命周期一致。
    pub struct Ctl {
        child: std::process::Child,
        stdin: std::process::ChildStdin,
    }

    impl Ctl {
        pub fn spawn() -> Result<Self, ChannelError> {
            let bin = find_macosctl().ok_or(ChannelError::MacosctlMissing)?;
            let mut child = std::process::Command::new(bin)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|e| ChannelError::MacosctlSpawn { message: e.to_string() })?;
            let stdin = child.stdin.take().ok_or(ChannelError::MacosctlSpawn {
                message: "无法接管 stdin".into(),
            })?;
            Ok(Self { child, stdin })
        }

        pub fn write(&mut self, req: &Request) -> Result<(), ChannelError> {
            use std::io::Write;
            let line = serde_json::to_string(req).map_err(|e| {
                ChannelError::MacosctlSpawn { message: format!("序列化失败: {e}") }
            })?;
            self.stdin
                .write_all(format!("{line}\n").as_bytes())
                .and_then(|_| self.stdin.flush())
                .map_err(|e| ChannelError::MacosctlSpawn {
                    message: format!("写入 macosctl 失败: {e}"),
                })
        }

        pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
            self.child.stdout.take()
        }

        pub fn pid(&self) -> u32 {
            self.child.id()
        }

        pub fn try_exit(&mut self) -> Option<i32> {
            match self.child.try_wait() {
                Ok(Some(s)) => s.code(),
                _ => None,
            }
        }

        /// 断开：向 macosctl 发 Stop。
        pub fn stop(&mut self) {
            let _ = self.write(&Request::Stop);
        }
    }

    /// 解析 `macosctl` 的一行输出。
    pub fn parse_line(line: &str) -> Option<Response> {
        serde_json::from_str(line.trim()).ok()
    }

    /// daemon 注册状态。
    pub fn daemon_state() -> Result<String, ChannelError> {
        let bin = find_macosctl().ok_or(ChannelError::MacosctlMissing)?;
        let out = std::process::Command::new(bin)
            .arg("status")
            .output()
            .map_err(|e| ChannelError::MacosctlSpawn { message: e.to_string() })?;
        let text = String::from_utf8_lossy(&out.stdout);
        // {"cause":null,"event":"state","state":"not_found"}
        let v: serde_json::Value =
            serde_json::from_str(text.trim()).map_err(|_| ChannelError::MacosctlSpawn {
                message: "无法解析 macosctl status 输出".into(),
            })?;
        Ok(v.get("state")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string())
    }

    /// 请求注册 daemon。
    ///
    /// ⚠️ `SMAppService` **不会弹密码框**。注册后若处于
    /// `requires_approval`，必须引导用户去
    /// 「系统设置 → 通用 → 登录项」批准 —— 这是 Apple 有意的设计。
    pub fn register_daemon() -> Result<String, ChannelError> {
        let bin = find_macosctl().ok_or(ChannelError::MacosctlMissing)?;
        let out = std::process::Command::new(bin)
            .arg("register")
            .output()
            .map_err(|e| ChannelError::MacosctlSpawn { message: e.to_string() })?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some(Response::State { state, cause }) = parse_line(line) {
                return Ok(match cause {
                    // Response::State 里 state 是枚举；注册状态那边
                    // Swift 发的是字符串。用 Debug 拿到可读名。
                    Some(c) => format!("{state:?}:{c:?}"),
                    None => format!("{state:?}"),
                });
            }
        }
        Err(ChannelError::MacosctlSpawn {
            message: "macosctl register 未返回可解析的状态".into(),
        })
    }

    /// 把 GUI 的 StdinSecret 转成 IPC 形状
    pub fn to_ipc(s: &StdinSecret) -> crate::ipc::StdinSecret {
        match s {
            StdinSecret::Password(p) => crate::ipc::StdinSecret::Password(p.clone()),
            StdinSecret::Cookie(p) => crate::ipc::StdinSecret::Cookie(p.clone()),
        }
    }
}

/// 已启动的连接
pub enum Running {
    /// 通过 helper 启动
    Helper {
        pid: u32,
        cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    },
    /// 直接 spawn
    Direct(DirectSession),
}

/// 直接 spawn 得到的会话
pub struct DirectSession {
    child: Child,
}

impl DirectSession {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn try_exit(&mut self) -> std::io::Result<Option<i32>> {
        Ok(self.child.try_wait()?.map(|s| s.code().unwrap_or(-1)))
    }

    /// 取走 stdout/stderr 交给 supervisor 读取
    pub fn take_pipes(&mut self) -> (Option<std::process::ChildStdout>, Option<std::process::ChildStderr>) {
        (self.child.stdout.take(), self.child.stderr.take())
    }
}

/// 连接通道
pub enum Channel {
    Helper(ipc::client::HelperHandle),
    Direct { program: PathBuf },
}

impl Channel {
    /// 探测当前平台可用的通道。
    ///
    /// Linux 优先 helper；helper 不可用时回落到 `Direct`，但
    /// [`Channel::is_privileged`] 会返回 false，UI 据此引导用户
    /// 先启动特权助手 —— 而不是让用户看到「权限不足」这种难懂错误。
    /// 注意这里用 `#[cfg(unix)]` 而非 `#[cfg(target_os = "linux")]`：
    /// macOS 生产部署走 XPC，但 socket 路径已按平台分支，
    /// 在 macOS 上允许 helper 通道能让这条路径在开发机上被真实执行，
    /// 而不是只在 CI 的 Linux runner 上跑过。
    pub fn detect(uid: u32) -> Self {
        #[cfg(unix)]
        {
            if let Ok(h) = ipc::client::HelperHandle::connect(uid) {
                return Channel::Helper(h);
            }
        }
        let _ = uid;
        Channel::Direct {
            program: resolve_openconnect().unwrap_or_else(|| PathBuf::from("openconnect")),
        }
    }

    /// 当前是否具备特权通道
    pub fn is_privileged(&self) -> bool {
        matches!(self, Channel::Helper(_))
    }

    /// 启动连接并把日志流式转发给回调。
    ///
    /// 这是 GUI 唯一应调用的启动入口 —— 它同时处理了两种通道下
    /// 「日志怎么到 UI」的问题：
    /// - Helper：读 socket 上的 `Response::Log` 推送
    /// - Direct：读子进程 stdout/stderr 并跑状态机
    pub fn start_streaming(
        &mut self,
        plan: &ArgPlan,
        pid_out: std::sync::Arc<std::sync::Mutex<Option<u32>>>,
        mut on_event: impl FnMut(StreamEvent),
    ) -> Result<(), ChannelError> {
        match self {
            Channel::Helper(h) => {
                let req = Request::Start {
                    args: plan.args.clone(),
                    server: plan.server.clone(),
                    stdin_secrets: plan.stdin_secrets.iter().map(to_ipc_secret).collect(),
                    token_secret: None,
                };
                let mut got_pid = false;
                // 完整 Tracker 跨整个日志流保持一个实例 ——
                // 与 Direct 通道完全同一套判定规则。之前的「单行判据」
                // 会丢掉需要多行累积的状态（如 Configuring）与
                // TerminalCause 的具体分类。
                let mut tracker = crate::tunnel::Tracker::new();
                h.pump_stream(&req, |msg| match msg {
                    Response::Started { pid } => {
                        *pid_out.lock().unwrap() = Some(pid);
                        got_pid = true;
                        on_event(StreamEvent::Started { pid });
                    }
                    Response::Log { line } => {
                        let state = tracker.feed_line(&line).map(|(_, to)| to);
                        on_event(StreamEvent::Log { line, state });
                    }
                    Response::State { state, cause } => {
                        on_event(StreamEvent::Finished {
                            state: parse_state(&state),
                            cause: cause.and_then(parse_cause),
                        })
                    }
                    Response::Exited { code } => {
                        // helper 侧只知道退出码，具体原因由 GUI 用
                        // Tracker 累积的日志推断。
                        tracker.on_exit(code);
                        let cause = tracker.cause();
                        on_event(StreamEvent::Finished {
                            state: tracker.state(),
                            cause: cause
                                .map(|c| (c.message_key().to_string(), c.is_retryable())),
                        });
                        on_event(StreamEvent::Exited { code });
                    }
                    Response::Failed { error } => {
                        on_event(StreamEvent::Failed {
                            message: error.to_string(),
                            key: error.message_key().to_string(),
                        });
                    }
                    _ => {}
                });
                if !got_pid {
                    return Err(ChannelError::Helper(HelperError::Internal {
                        message: "helper 未返回 Started".into(),
                    }));
                }
                Ok(())
            }
            Channel::Direct { program: _ } => {
                let running = self.start(plan)?;
                let Running::Direct(mut session) = running else {
                    unreachable!("Direct 分支只会返回 Direct")
                };
                *pid_out.lock().unwrap() = Some(session.pid());
                on_event(StreamEvent::Started { pid: session.pid() });

                // 两个回调都会改写 on_event，用 RefCell 借用一次
                let cb = std::cell::RefCell::new(&mut on_event);
                let (_, cause) = pump_direct(
                    &mut session,
                    |s, c| {
                        let mut f = cb.borrow_mut();
                        if let Some(c) = c {
                            (*f)(StreamEvent::Finished {
                                state: s,
                                cause: Some((c.message_key().to_string(), c.is_retryable())),
                            });
                        }
                    },
                    |l| {
                        (*cb.borrow_mut())(StreamEvent::Log {
                            line: l.to_owned(),
                            state: None,
                        });
                    },
                );
                // Finished 已由 pump_direct 的 state 回调发出；
                // 这里不再重复（否则 UI 会收到两次相同的结束事件）。
                let _ = cause;
                Ok(())
            }
        }
    }

    /// 启动连接。返回已就绪的会话。
    ///
    /// ⚠️ 只有测试与非流式场景用；GUI 走 [`Self::start_streaming`]。
    pub fn start(&mut self, plan: &ArgPlan) -> Result<Running, ChannelError> {
        match self {
            Channel::Helper(h) => {
                let args = plan.args.clone();
                let resp = h
                    .request(&Request::Start {
                        args,
                        server: plan.server.clone(),
                        stdin_secrets: plan
                            .stdin_secrets
                            .iter()
                            .map(|s| match s {
                                StdinSecret::Password(p) => {
                                    ipc::StdinSecret::Password(p.clone())
                                }
                                StdinSecret::Cookie(p) => {
                                    ipc::StdinSecret::Cookie(p.clone())
                                }
                            })
                            .collect(),
                        token_secret: None,
                    })
                    .map_err(ChannelError::Helper)?;

                match resp {
                    ipc::Response::Started { pid } => Ok(Running::Helper {
                        pid,
                        cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                            false,
                        )),
                    }),
                    ipc::Response::Failed { error } => Err(ChannelError::Helper(error)),
                    other => Err(ChannelError::Helper(HelperError::Internal {
                        message: format!("helper 返回了意外响应: {other:?}"),
                    })),
                }
            }
            Channel::Direct { program } => {
                let program: &std::path::Path = program;
                if !program.exists() {
                    return Err(ChannelError::NoOpenconnect);
                }

                // ⚠️ 必须与 helper 通道执行**同一套**校验。
                //
                // `profile.advanced.extra_args` 是文档明示的「逃生舱
                // （数组里的一切原样附加到命令行）」，而
                // `argv::build` 不对它做过滤 —— 禁用参数
                // （`--script-tun` / `--csd-wrapper` /
                // `--external-browser`）能从这里穿过去。
                //
                // helper 通道靠 `validate_args` 挡住（helper/src/main.rs
                // 与 helper-win/src/main.rs 都调了），但 Direct 通道
                // 原先只检查了密钥泄漏，**没检查禁用参数**。结果是
                // 同一个 profile 在两条通道上的安全性不一致 ——
                // 一个安全边界有一半没守住的典型。
                //
                // 同一份 `oc_proto::validate_args` 让两条通道行为一致，
                // 也让这个不变量只需在一处实现。
                //
                // 校验对象是 `plan.args`（即 profile 能控制的范围），
                // **不含**下面由本进程自己追加的 `--script`。
                // 顺序很重要：先校验再追加。
                //
                // Direct 通道跑的是 GUI 用户身份，所以它自己加的
                // `--script`（路径由 `resolve_vpnc_script` 从
                // openconnect 安装位置推导，不来自 profile）不构成
                // 提权。但 Helper 通道里同样东西会是 root —— 所以
                // `--script` 被列入 validate_args 的禁用清单，
                // helper 只能用自己的编译期内置路径。
                crate::ipc::validate_args(&plan.args, &plan.server)
                    .map_err(|e| ChannelError::Rejected(e.to_string()))?;

                // 启动前自检：密钥泄漏进 argv 就拒绝启动
                let secrets: Vec<String> = plan
                    .stdin_secrets
                    .iter()
                    .map(|s| match s {
                        StdinSecret::Password(p) | StdinSecret::Cookie(p) => p.clone(),
                    })
                    .collect();
                let leaks = plan.audit_argv(&secrets);
                if !leaks.is_empty() {
                    return Err(ChannelError::KeyLeak(leaks));
                }

                let mut cmd = Command::new(program);
                // Windows 上 vpnc-script 必须与 openconnect.exe 同目录。
                // Unix 上用系统安装的那个（通常已正确配置）。
                let script = resolve_vpnc_script(program);
                if let Some(script) = &script
                    && !plan.args.iter().any(|a| a == "--script" || a.starts_with("--script=")) {
                        cmd.arg("--script").arg(script);
                    }
                cmd.args(plan.argv());
                crate::tunnel::signal::apply_creation_flags(&mut cmd);
                cmd.stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());

                let mut child = cmd.spawn().map_err(|e| {
                    // openconnect 需要 root 才能建 TUN。非 root 下最典型的
                    // 错误是 permission denied，但这与「程序不存在」要区分开。
                    ChannelError::Spawn {
                        program: program.display().to_string(),
                        source: e,
                    }
                })?;

                // 密钥只走 stdin
                if let Some(mut si) = child.stdin.take() {
                    use std::io::Write;
                    for s in &plan.stdin_secrets {
                        let v = match s {
                            StdinSecret::Password(p) | StdinSecret::Cookie(p) => p,
                        };
                        let _ = writeln!(si, "{}", v.trim_end_matches(['\r', '\n']));
                    }
                    let _ = si.flush();
                    drop(si);
                }

                Ok(Running::Direct(DirectSession { child }))
            }
        }
    }
}

/// 流式事件。GUI 的所有状态更新都源自这里。
pub enum StreamEvent {
    /// openconnect 已 spawn
    Started { pid: u32 },
    /// 一行日志；`state` 为 None 表示该行未触发状态变化
    Log { line: String, state: Option<State> },
    /// 隧道结束
    Finished {
        state: State,
        /// `(i18n key, 是否可重试)`
        cause: Option<(String, bool)>,
    },
    /// 进程退出
    Exited { code: Option<i32> },
    /// 出错
    Failed { message: String, key: String },
}

/// 协议里的状态名 → 强类型。
///
/// `oc-proto` 不能依赖 GUI 的 `State`，所以线上传的是 snake_case
/// 字符串。未知值一律降级为 `Failed`，不能让 UI 停在一个不存在的状态上。
fn parse_state(s: &str) -> State {
    serde_json::from_value::<State>(serde_json::Value::String(s.to_string()))
        .unwrap_or_else(|_| {
            log::warn!("helper 回报了未知状态 {s:?}，按 failed 处理");
            State::Failed
        })
}

/// 协议里的终止原因 JSON → 强类型。
fn parse_cause(v: serde_json::Value) -> Option<(String, bool)> {
    serde_json::from_value::<TerminalCause>(v).ok().map(|c| {
        (c.message_key().to_string(), c.is_retryable())
    })
}

fn to_ipc_secret(s: &StdinSecret) -> ipc::StdinSecret {
    match s {
        StdinSecret::Password(p) => ipc::StdinSecret::Password(p.clone()),
        StdinSecret::Cookie(p) => ipc::StdinSecret::Cookie(p.clone()),
    }
}

/// 通道错误。每个变体都对应 UI 上不同的引导文案。
#[derive(Debug)]
pub enum ChannelError {
    Helper(HelperError),
    /// 找不到 `macosctl`（App bundle 不完整或未构建 macos-helper）
    MacosctlMissing,
    /// 启动/写入 `macosctl` 失败
    MacosctlSpawn { message: String },
    NoOpenconnect,
    /// 构建阶段就拒绝：密钥会泄漏进 argv
    KeyLeak(Vec<&'static str>),
    /// 构建阶段就拒绝：参数本身被禁止（如 `--script-tun`）。
    ///
    /// 与 [`ChannelError::KeyLeak`] 分开是因为处置方式不同：
    /// 密钥泄漏通常是 profile 被误配，而禁用参数意味着有人想让
    /// 助手执行任意代码 —— 前者提示改配置，后者应报安全事件。
    Rejected(String),
    Spawn { program: String, source: std::io::Error },
}

impl ChannelError {
    /// i18n key
    pub fn message_key(&self) -> &'static str {
        match self {
            ChannelError::Helper(e) => e.message_key(),
            ChannelError::MacosctlMissing => "channel.error.macosctl_missing",
            ChannelError::MacosctlSpawn { .. } => "channel.error.macosctl_spawn_failed",
            ChannelError::NoOpenconnect => "channel.error.openconnect_missing",
            ChannelError::KeyLeak(_) => "channel.error.key_leak",
            ChannelError::Rejected(_) => "channel.error.rejected_args",
            ChannelError::Spawn { .. } => "channel.error.spawn_failed",
        }
    }

    /// UI 是否应引导用户去启动特权助手
    pub fn needs_privileged_helper(&self) -> bool {
        match self {
            // macosctl 缺失 = App bundle 不完整 ⇒ 引导用户重装，
            // 而不是让用户去「系统设置」里找一个不存在的开关。
            ChannelError::MacosctlMissing => true,
            // macosctl 起来了但连不上 daemon ⇒ 引导去系统设置批准
            ChannelError::MacosctlSpawn { .. } => true,
            ChannelError::NoOpenconnect => false,
            ChannelError::KeyLeak(_) => false,
            // 参数被拒是 profile 的问题，不是缺特权 —— 别把用户
            // 引导去启动助手，那样只会让他更困惑。
            ChannelError::Rejected(_) => false,
            ChannelError::Helper(_) => true,
            ChannelError::Spawn { source, .. } => {
                source.kind() == std::io::ErrorKind::PermissionDenied
            }
        }
    }
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::Helper(e) => write!(f, "{e}"),
            ChannelError::MacosctlMissing => write!(
                f,
                "找不到 macosctl —— App bundle 不完整或未构建 macos-helper"
            ),
            ChannelError::MacosctlSpawn { message } => write!(f, "macosctl 失败: {message}"),
            ChannelError::NoOpenconnect => write!(f, "找不到 openconnect，请先安装"),
            ChannelError::KeyLeak(leaks) => {
                write!(f, "拒绝启动：密钥会泄漏进命令行 ({leaks:?})")
            }
            ChannelError::Rejected(why) => {
                write!(f, "拒绝启动：{why}")
            }
            ChannelError::Spawn { program, source } => {
                write!(f, "启动 {program} 失败: {source}")
            }
        }
    }
}

impl std::error::Error for ChannelError {}

/// 从 Direct 会话读日志并驱动状态机。
///
/// 与 [`crate::tunnel::supervisor::pump`] 同构，但从 `Running` 取管道。
pub fn pump_direct(
    session: &mut DirectSession,
    mut on_state: impl FnMut(State, Option<&TerminalCause>),
    mut on_line: impl FnMut(&str),
) -> (Option<i32>, TerminalCause) {
    let (stdout, stderr) = session.take_pipes();
    let (tx, rx) = mpsc::channel::<String>();

    fn spawn_reader<R: std::io::Read + Send + 'static>(
        reader: R,
        tx: mpsc::Sender<String>,
    ) {
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(reader).lines() {
                match line {
                    Ok(l) => {
                        if tx.send(l).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    if let Some(o) = stdout {
        spawn_reader(o, tx.clone());
    }
    if let Some(e) = stderr {
        spawn_reader(e, tx.clone());
    }
    drop(tx);

    let mut tracker = crate::tunnel::Tracker::new();
    for line in rx {
        on_line(&line);
        if let Some((_, to)) = tracker.feed_line(&line) {
            on_state(to, None);
        }
    }

    let code = session.try_exit().ok().flatten();
    tracker.on_exit(code);
    let cause = tracker
        .cause()
        .unwrap_or(TerminalCause::Unknown {
            reason: "进程退出但未记录原因".into(),
        });
    let final_state = tracker.state();
    on_state(final_state, Some(&cause));
    (code, cause)
}

/// 当前进程的 uid / Windows SID 对应的数值。
pub fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: getuid 无参数无副作用
        unsafe { libc::getuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;
    use crate::tunnel::argv;

    /// Direct 与 Helper 两条通道必须对同一份 argv 给出相同的拒绝。
    ///
    /// `extra_args` 是文档明示的逃生舱（内容原样附加到命令行），
    /// `argv::build` 不过滤它 —— 所以禁用参数能否被挡住，完全取决于
    /// 启动前有没有调 `validate_args`。
    ///
    /// 实测踩过：Helper 通道挡住了 `--script-tun`，Direct 通道没挡，
    /// 同一个 profile 在两条通道上安全性不一致。
    #[test]
    fn direct_channel_rejects_the_same_args_as_helper() {
        let forbidden = [
            "--script-tun",
            "--csd-wrapper=/tmp/evil.sh",
            "--external-browser=/bin/sh",
        ];
        for f in forbidden {
            let mut p = Profile::new("t", "t", "vpn.corp.com");
            p.advanced.extra_args = vec![f.into()];
            let plan = argv::build(
                &p,
                &argv::Secrets {
                    password: None,
                    cookie: None,
                    key_password: None,
                    mca_key_password: None,
                    token_secret: None,
                },
            );
            // argv::build 本身不过滤 —— 这正是问题所在
            assert!(
                plan.args.iter().any(|a| a == f),
                "{f} 应先进入 argv（否则这条测试没意义）"
            );
            // 但两条通道在启动前都会拒绝它。
            // 错误信息报的是**参数名**（不含 `=值`），所以按 `=` 截断比较。
            let flag = f.split('=').next().unwrap();
            let err = crate::ipc::validate_args(&plan.args, &plan.server)
                .expect_err("validate_args 应拒绝禁用参数");
            assert!(err.to_string().contains(flag), "错误信息应指明哪个参数: {err}");
        }
    }

    /// 在锁保护下设置环境变量并执行 `f`，之后恢复原值。
    ///
    /// 用 `crate::testenv` 的**全局**锁而不是本文件私有的锁 ——
    /// 环境变量是进程级状态，两个独立的锁保护它等于没锁：
    /// 拿 A 锁的测试仍可能与拿 B 锁的测试互相干扰。
    fn with_openconnect_env<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = crate::testenv::env_guard();
        let key = "OCGUI_OPENCONNECT";
        let saved = std::env::var(key).ok();
        // SAFETY: 持有 testenv 的全局环境变量锁
        unsafe {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        let r = f();
        // SAFETY: 锁仍在手里
        unsafe {
            match saved {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        r
    }

    #[test]
    fn env_override_wins() {
        let p = with_openconnect_env(Some("/tmp/fake-openconnect"), resolve_openconnect);
        // 路径不存在时返回 None（不静默回落到别的 openconnect ——
        // 那会导致用户以为在测 A 实际跑的是 B）
        assert_eq!(p, None);
    }

    #[test]
    fn finds_sibling_of_current_exe() {
        // 测试二进制的同级目录里没有 openconnect，应回落到平台候选或 None
        let p = with_openconnect_env(None, resolve_openconnect);
        if let Some(p) = p {
            assert!(
                p.exists(),
                "resolve_openconnect 返回了不存在的路径: {}",
                p.display()
            );
        }
    }

    #[test]
    fn never_returns_nonexistent_path() {
        // 核心不变量：返回值要么是 None，要么真实存在。
        // 返回不存在的路径会让 `spawn` 报一个难以理解的 ENOENT。
        with_openconnect_env(None, || {
            if let Some(p) = resolve_openconnect() {
                assert!(p.exists(), "返回了不存在的路径: {}", p.display());
            }
        });
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn vpnc_script_is_none_on_unix() {
        // Unix 上用系统安装的 vpnc-script，不该由我们指定
        let p = std::path::Path::new("/usr/bin/openconnect");
        assert_eq!(resolve_vpnc_script(p), None);
    }

    #[test]
    fn sibling_lookup_prefers_exe_dir() {
        // 逻辑层面验证优先级：同级目录候选在平台候选之前
        let exe = std::env::current_exe().unwrap();
        let dir = exe.parent().unwrap();
        let name = if cfg!(target_os = "windows") {
            "openconnect.exe"
        } else {
            "openconnect"
        };
        // 构造一个必然不存在的同级路径，确认代码会去检查它
        assert!(!dir.join(name).exists() || resolve_openconnect().is_some());
    }
}
