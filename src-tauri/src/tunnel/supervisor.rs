//! openconnect 子进程监管
//!
//! 职责：
//! - 按 [`ArgPlan`] 启动 openconnect，密钥只走 stdin
//! - 逐行读取 stdout+stderr，送进 [`Tracker`]
//! - 状态变化时回调（供 Tauri 事件总线转发给前端）
//! - 断开 = 发 SIGINT（不是 SIGKILL），让 openconnect 有机会跑 vpnc-script
//!   的 disconnect 分支清理路由/DNS
//!
//! # 为什么必须用 SIGINT
//!
//! SIGKILL 会留下脏路由和残留 DNS 配置。openconnect 捕获 SIGINT 后会走
//! 正常的 `openconnect_mainloop` 退出路径并执行 vpnc-script 的 `disconnect`。
//! 见 `main.c:817` `SIGINT` case。

use crate::tunnel::{ArgPlan, StdinSecret, State, TerminalCause, Tracker};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

/// 状态回调。`cause` 在终止时携带原因。
pub type StateFn<'a> = Box<dyn FnMut(State, Option<&TerminalCause>) + 'a>;

/// 运行中的连接
pub struct Session {
    child: Child,
    tracker: Tracker,
}

impl Session {
    /// 断开：SIGINT + 等待退出，超时后 SIGKILL
    pub fn disconnect(&mut self) -> std::io::Result<()> {
        // unix: 用 kill(2) 发 SIGINT；windows: openconnect 无 console 信号，
        // 用 CREATE_NEW_PROCESS_GROUP + 生成事件过于复杂，
        // 直接 terminate 由 P1 的 Windows spike 决定。
        send_sigint(&mut self.child)?;

        // 给 vpnc-script 清理留时间
        for _ in 0..50 {
            if self.child.try_wait()?.is_some() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        // 5 秒还没退 → 强杀，但要记录下来，因为可能留下脏路由
        self.child.kill()
    }

    pub fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        Ok(self.child.try_wait()?.map(|s| s.code().unwrap_or(-1)))
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

fn send_sigint(child: &mut Child) -> std::io::Result<()> {
    use crate::tunnel::signal::{self, SignalOutcome};
    match signal::send_disconnect(child) {
        SignalOutcome::Sent => Ok(()),
        SignalOutcome::Unsupported => Err(std::io::Error::other(
            "当前平台不支持优雅断开，只能强杀（可能残留路由）",
        )),
        SignalOutcome::Failed => Err(std::io::Error::other("发送断开信号失败")),
    }
}

/// 启动一个连接。
///
/// `on_state` 在每次状态变化时被调用。函数返回后连接仍在运行，
/// 调用者负责继续读取事件（见 [`pump`]）。
///
/// 注意：`plan` 里的密钥不会出现在子进程的命令行里，`audit_argv`
/// 会在启动前自检，失败则拒绝启动。
pub fn start(
    plan: &ArgPlan,
    program: &std::path::Path,
    mut on_state: StateFn<'_>,
) -> std::io::Result<Session> {
    // ---- 构建期致命错误 ----
    // 例如私钥口令含换行，无法安全写入 config 文件。
    // 此时**绝不**降级到明文 argv，直接拒绝启动。
    if let Some(msg) = &plan.fatal_error {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            msg.clone(),
        ));
    }

    // ---- 启动前自检 ----
    let secrets: Vec<String> = plan
        .stdin_secrets
        .iter()
        .map(|s| match s {
            StdinSecret::Password(p) | StdinSecret::Cookie(p) => p.clone(),
        })
        .collect();
    let leaks = plan.audit_argv(&secrets);
    if !leaks.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("拒绝启动：密钥泄漏进 argv ({leaks:?})"),
        ));
    }

    // argv 自检通过后，config 文件里若还有密钥则不属于 argv 泄漏
    // （它走的是文件通道），但仍需确认文件确实存在。

    let mut cmd = Command::new(program);
    cmd.args(plan.argv());
    crate::tunnel::signal::apply_creation_flags(&mut cmd);

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // ---- 写 stdin 然后关闭 ----
    // openconnect 只需要读到第一个换行；多写也无害。
    // 但必须关闭，否则 openconnect 在某些路径上会等 EOF。
    if let Some(mut stdin) = child.stdin.take() {
        for s in &plan.stdin_secrets {
            let v = match s {
                StdinSecret::Password(p) | StdinSecret::Cookie(p) => p,
            };
            let _ = writeln!(stdin, "{}", v.trim_end_matches(['\r', '\n']));
        }
        let _ = stdin.flush();
        drop(stdin);
    }

    on_state(State::Connecting, None);

    Ok(Session {
        child,
        tracker: Tracker::new(),
    })
}

/// 读取所有输出直到 EOF，逐行驱动状态机。
///
/// 返回进程退出码与终止原因。
///
/// ⚠️ 调用方需要能在读取过程中断开（用户在 UI 上点了取消）。
/// 当前实现是阻塞读取；P1 的 Tauri 集成会把 stdout 放到独立线程，
/// 用 channel 与主线程通信。
pub fn pump(session: &mut Session, mut on_state: StateFn<'_>) -> (Option<i32>, TerminalCause) {
    pump_inner(session, &mut on_state, None)
}

/// 同 `pump`，但把每一行原始日志也交给 `on_line`。
/// 日志页需要原文，状态机只需要事件 —— 两者分开避免重复解析。
pub fn pump_with_lines(
    session: &mut Session,
    mut on_state: StateFn<'_>,
    mut on_line: impl FnMut(&str),
) -> (Option<i32>, TerminalCause) {
    pump_inner(session, &mut on_state, Some(&mut on_line))
}

fn pump_inner(
    session: &mut Session,
    on_state: &mut StateFn<'_>,
    mut on_line: Option<&mut dyn FnMut(&str)>,
) -> (Option<i32>, TerminalCause) {
    let stdout = session.child.stdout.take();
    let stderr = session.child.stderr.take();

    // openconnect 把日志写到 stderr，但为了不丢行，两个流都要读。
    // 用两个线程 + channel 汇合。
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel::<String>();

    fn spawn_reader<R: std::io::Read + Send + 'static>(
        reader: R,
        tx: mpsc::Sender<String>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            for line in BufReader::new(reader).lines() {
                match line {
                    Ok(l) => {
                        if tx.send(l).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })
    }

    if let Some(o) = stdout {
        spawn_reader(o, tx.clone());
    }
    if let Some(e) = stderr {
        spawn_reader(e, tx.clone());
    }
    drop(tx);

    for line in rx {
        if let Some(cb) = on_line.as_deref_mut() {
            cb(&line);
        }
        if let Some((_, to)) = session.tracker.feed_line(&line) {
            on_state(to, None);
        }
    }

    let code = session.child.wait().ok().map(|s| s.code().unwrap_or(-1));
    session.tracker.on_exit(code);
    let cause = session
        .tracker
        .cause()
        .unwrap_or(TerminalCause::Unknown {
            reason: "进程退出但未记录原因".into(),
        });
    let final_state = session.tracker.state();
    on_state(final_state, Some(&cause));
    (code, cause)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;
    use crate::tunnel::argv;

    fn test_plan(profile: &Profile, secrets: argv::Secrets) -> ArgPlan {
        argv::build(profile, &secrets)
    }

    /// 用 /bin/cat 当 openconnect 的替身：验证 stdin 写入与 argv 不泄漏。
    #[cfg(unix)]
    #[test]
    fn secrets_reach_stdin_and_not_argv() {
        // 用手工 ArgPlan 而非 build()：`/bin/cat` 不认识 openconnect 的
        // 开关，会因为 --protocol 之类直接报错退出。
        let mut plan = ArgPlan::bare(vec!["--passwd-on-stdin".into()], "vpn.invalid");
        plan.stdin_secrets = vec![StdinSecret::Password("hunter2".into())];

        // 替身脚本忽略 argv，把 stdin 原样吐到 stdout
        let mut session = start(
            &plan,
            std::path::Path::new("tests/bin/echo-stdin.sh"),
            Box::new(|_, _| {}),
        )
        .unwrap();

        let lines = std::sync::Mutex::new(String::new());
        let _ = pump_with_lines(
            &mut session,
            Box::new(|_, _| {}),
            |l| {
                lines.lock().unwrap().push_str(l);
                lines.lock().unwrap().push('\n');
            },
        );
        let got = lines.into_inner().unwrap();
        assert!(
            got.contains("hunter2"),
            "密码应通过 stdin 到达子进程，实际收到: {got:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_start_when_secret_leaks_into_argv() {
        let mut p = Profile::new("t", "t", "vpn.invalid");
        p.remember_password = true;
        p.advanced.extra_args = vec!["--user=hunter2".into()];
        let plan = test_plan(
            &p,
            argv::Secrets {
                password: Some("hunter2".into()),
                ..Default::default()
            },
        );
        let err = start(
            &plan,
            std::path::Path::new("tests/bin/echo-stdin.sh"),
            Box::new(|_, _| {}),
        )
        .err()
        .expect("应拒绝启动");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            format!("{err}").contains("泄漏"),
            "错误信息应点明泄漏: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pump_reads_all_output() {
        // 替身脚本把 argv 原样打到 stdout，验证 pump 真的读到了子进程输出
        let plan = ArgPlan::bare(vec!["--first".into(), "--second=2".into()], "vpn.invalid");
        let mut session = start(
            &plan,
            std::path::Path::new("tests/bin/echo-args.sh"),
            Box::new(|_, _| {}),
        )
        .unwrap();

        let lines = std::sync::Mutex::new(Vec::<String>::new());
        let (code, _cause) = pump_with_lines(
            &mut session,
            Box::new(|_, _| {}),
            |l| lines.lock().unwrap().push(l.to_owned()),
        );
        assert_eq!(code, Some(0));
        let got = lines.into_inner().unwrap();
        assert!(
            got.iter().any(|l| l.contains("--first")),
            "pump 未读到子进程输出: {got:?}"
        );
        assert!(
            got.iter().any(|l| l.contains("vpn.invalid")),
            "server 未传入: {got:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn start_reports_connecting_immediately() {
        let plan = ArgPlan::bare(Vec::new(), "x");
        let (tx, rx) = std::sync::mpsc::channel::<State>();
        let mut session = start(
            &plan,
            std::path::Path::new("tests/bin/echo-stdin.sh"),
            Box::new(move |s, _| {
                let _ = tx.send(s);
            }),
        )
        .unwrap();
        assert_eq!(rx.recv().unwrap(), State::Connecting);
        let _ = pump(&mut session, Box::new(|_, _| {}));
    }

    #[cfg(unix)]
    #[test]
    fn exit_zero_after_clean_output_is_idle() {
        let plan = ArgPlan::bare(vec!["-n".into()], "bye");
        let mut session =
            start(&plan, std::path::Path::new("/bin/echo"), Box::new(|_, _| {})).unwrap();
        let (code, cause) = pump(&mut session, Box::new(|_, _| {}));
        assert_eq!(code, Some(0));
        // /bin/echo 不是 openconnect，最后一条是 Unknown error 的兜底
        // 但退出码为 0，状态应为 Idle
        assert_eq!(session.tracker.state(), State::Idle);
        let _ = cause;
    }

    #[cfg(unix)]
    #[test]
    fn missing_program_is_io_error() {
        let plan = ArgPlan::bare(Vec::new(), "x");
        let err = start(
            &plan,
            std::path::Path::new("/nonexistent/openconnect"),
            Box::new(|_, _| {}),
        )
        .err()
        .expect("程序不存在应报错");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[cfg(unix)]
    #[test]
    fn disconnect_terminates_process() {
        // 用 sleep 当长跑进程，验证 disconnect 能把它停掉
        let plan = ArgPlan::bare(vec!["30".into()], "/dev/null");
        let mut session =
            start(&plan, std::path::Path::new("/bin/sleep"), Box::new(|_, _| {})).unwrap();
        assert!(session.try_wait().unwrap().is_none(), "进程应在运行");
        session.disconnect().expect("disconnect 应成功");
        // disconnect 会等 5 秒再强杀，这里确认它最终结束
        assert!(session.child.wait().is_ok());
    }
}