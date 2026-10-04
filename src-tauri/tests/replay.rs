//! 集成回归测试：用真实 `openconnect -v --timestamp` 输出驱动解析器与状态机。
//!
//! fixture 由 P0 的 mock AnyConnect gateway 采集（见 docs/mock_gateway.py.txt）。
//! mock 不实现 DTLS/CSTP 数据通道，所以隧道无法真正 up —— 这正好把
//! 「认证阶段」与「隧道阶段」的边界固定下来。
//!
//! | fixture | 场景 |
//! |---|---|
//! | authok.log    | 密码正确 → CONNECT 被 mock 以 501 拒绝 |
//! | authfail.log  | 密码错误 |
//! | badgroup.log  | 分组值在服务器上不存在 |

use wthinkvpn_lib::tunnel::{parse_line, Event, Kind, State, TerminalCause, Tracker};

fn replay(path: &str) -> Vec<Event> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines().filter_map(parse_line).collect()
}

fn run(path: &str) -> (Tracker, Vec<State>) {
    let mut t = Tracker::new();
    let mut seen = vec![t.state()];
    for line in std::fs::read_to_string(path).unwrap().lines() {
        if let Some((_, to)) = t.feed_line(line) {
            seen.push(to);
        }
    }
    (t, seen)
}

// ---------------------------------------------------------------------------
// 认证成功（止于 CONNECT）
// ---------------------------------------------------------------------------

#[test]
fn authok_reaches_authenticating_then_fails_on_connect() {
    let (_t, seen) = run("tests/authok.log");
    // 真实轨迹（fixture 中 authok.log 有两次表单提示）：
    //
    //   Idle → Connecting → AwaitingUser → Authenticating
    //        → AwaitingUser → Authenticating → Failed
    //
    // 为什么表单提示出现两次：`-F main:group_list=` 只填了分组，密码走
    // stdin。openconnect 提交后网关回了一个新表单（P0 实测），于是再走一轮。
    //
    // 为什么 Configuring 不可达：mock 未实现 CONNECT 方法，openconnect
    // 直接收到 501，`cstp.c` 的 "Got CONNECT response" 分支不会走到。
    // 真实网关下 Configuring 会在这里出现。
    assert_eq!(
        seen,
        vec![
            State::Idle,
            State::Connecting,
            State::AwaitingUser,
            State::Authenticating,
            State::AwaitingUser,
            State::Authenticating,
            State::Failed,
        ],
        "轨迹与 fixture 不符"
    );
    assert!(!seen.contains(&State::Connected), "mock 无 DTLS，不可达");
}

#[test]
fn authok_never_reports_auth_failure() {
    for e in replay("tests/authok.log") {
        assert_ne!(e.kind, Kind::AuthFailed, "成功路径误判: {}", e.raw);
    }
}

#[test]
fn authok_cause_is_tunnel_setup_not_auth() {
    let (t, _) = run("tests/authok.log");
    let cause = t.cause().expect("应有终止原因");
    // 认证已通过，失败发生在隧道建立 → 必须分类为 TunnelSetupFailed，
    // 否则 UI 会错误地弹出「密码错误，请重新输入」
    assert!(
        matches!(cause, TerminalCause::TunnelSetupFailed { .. }),
        "分类错误: {cause:?}"
    );
}

// ---------------------------------------------------------------------------
// 认证失败
// ---------------------------------------------------------------------------

#[test]
fn authfail_classified_as_auth_rejected() {
    let (t, seen) = run("tests/authfail.log");
    assert_eq!(t.state(), State::Failed);
    assert!(!seen.contains(&State::Connected));
    assert!(!seen.contains(&State::Configuring), "认证失败不应建隧道: {seen:?}");

    let cause = t.cause().expect("应有终止原因");
    assert!(
        matches!(cause, TerminalCause::AuthRejected { .. }),
        "分类错误: {cause:?}"
    );
    assert!(cause.is_retryable(), "密码错应可重试");
}

// ---------------------------------------------------------------------------
// 分组值不存在
// ---------------------------------------------------------------------------

#[test]
fn bad_group_classified_as_auth_group_invalid() {
    let (t, _) = run("tests/badgroup.log");
    assert_eq!(t.state(), State::Failed);
    let cause = t.cause().expect("应有终止原因");
    assert!(
        matches!(cause, TerminalCause::AuthGroupInvalid { .. }),
        "分类错误: {cause:?}"
    );
    // 分组写错不是「密码错误」，不应让用户去改密码
    assert!(
        !cause.is_retryable(),
        "分组配置错误应引导改配置而非重试密码"
    );
}

// ---------------------------------------------------------------------------
// 终止原因分类：构造性测试
// ---------------------------------------------------------------------------

fn cause_of(lines: &[&str]) -> Option<TerminalCause> {
    let mut t = Tracker::new();
    for l in lines {
        t.feed_line(l);
    }
    t.cause()
}

#[test]
fn network_unreachable_classified() {
    let c = cause_of(&[
        "[2026-10-03 02:00:00] Attempting to connect to server vpn.corp:443",
        "[2026-10-03 02:00:01] Failed to connect to vpn.corp: Connection refused",
        "[2026-10-03 02:00:01] Failed to connect to host vpn.corp",
        "[2026-10-03 02:00:01] Failed to open HTTPS connection to vpn.corp",
    ])
    .unwrap();
    assert!(matches!(c, TerminalCause::NetworkUnreachable { .. }), "{c:?}");
    assert!(c.is_retryable());
}

#[test]
fn user_input_required_detected_when_form_not_prefilled() {
    // 这是 -F 字段名写错时的真实症状：GUI 里表现为「一直转圈」
    let mut t = Tracker::new();
    t.feed_line("[2026-10-03 02:00:00] Attempting to connect to server vpn.corp:443");
    t.feed_line("Please enter your username and password.");
    // 停在这里 = openconnect 正在等 stdin
    assert_eq!(t.state(), State::AwaitingUser);
    let c = t.cause().expect("应有原因");
    assert!(
        matches!(c, TerminalCause::UserInputRequired { .. }),
        "分类错误: {c:?}"
    );
}

#[test]
fn certificate_rejected_classified() {
    let c = cause_of(&[
        "[2026-10-03 02:00:00] Attempting to connect to server vpn.corp:443",
        "[2026-10-03 02:00:01] Certificate Validation Failure",
        "[2026-10-03 02:00:01] Failed to complete authentication",
    ])
    .unwrap();
    assert!(matches!(c, TerminalCause::AuthRejected { .. }), "{c:?}");
}

#[test]
fn cookie_expired_classified_as_session_terminated() {
    let c = cause_of(&[
        "[2026-10-03 02:00:00] Configured as 10.0.0.2/255.255.255.0, with SSL AES-256-GCM and UDP AES-256-GCM dtls",
        "[2026-10-03 03:00:00] Cookie was rejected by server; exiting.",
    ])
    .unwrap();
    assert!(
        matches!(c, TerminalCause::SessionTerminated { .. }),
        "{c:?}"
    );
}

#[test]
fn terminal_state_emitted_exactly_once() {
    // openconnect 失败时连打多条错误日志（具体原因 → "; exiting" →
    // "Unknown error; exiting."）。UI 不应收到 3 次 Failed。
    for f in ["tests/authok.log", "tests/authfail.log", "tests/badgroup.log"] {
        let mut t = Tracker::new();
        let mut failed_count = 0;
        for line in std::fs::read_to_string(f).unwrap().lines() {
            if let Some((_, to)) = t.feed_line(line)
                && to == State::Failed {
                    failed_count += 1;
                }
        }
        assert_eq!(failed_count, 1, "{f} 的 Failed 事件应恰好 1 次，实际 {failed_count}");
    }
}

#[test]
fn failure_reasons_accumulate_not_overwritten() {
    // 收尾永远是 "Unknown error; exiting."，若只存最后一条，
    // 真正的原因（CONNECT 失败 / 密码错）会被冲掉。
    let (t, _) = run("tests/authok.log");
    let c = t.cause().unwrap();
    match c {
        TerminalCause::TunnelSetupFailed { reason } => {
            assert!(reason.contains("CONNECT"), "应保留具体原因: {reason}");
        }
        other => panic!("分类错误: {other:?}"),
    }
}

#[test]
fn user_cancel_is_not_an_error() {
    let mut t = Tracker::new();
    t.feed_line("[2026-10-03 02:00:00] Configured as 10.0.0.2/255.255.255.0, with SSL AES-256-GCM and UDP AES-256-GCM dtls");
    assert_eq!(t.state(), State::Connected);
    t.feed_line("User cancelled (SIGINT/SIGTERM); exiting.");
    t.on_exit(Some(0));
    assert_eq!(t.state(), State::Idle);
    assert_eq!(t.cause(), Some(TerminalCause::UserCancelled));
}

// ---------------------------------------------------------------------------
// 状态机不变量
// ---------------------------------------------------------------------------

#[test]
fn connected_never_regresses_to_awaiting_user() {
    let mut t = Tracker::new();
    t.feed_line("[2026-10-03 02:00:00] Configured as 10.0.0.2/255.255.255.0, with SSL AES-256-GCM and UDP AES-256-GCM dtls");
    assert_eq!(t.state(), State::Connected);
    // 重连期间 openconnect 可能打印提示，不应把 UI 拉回「等待输入」
    t.feed_line("[2026-10-03 02:00:30] GROUP: [|Engineering|Operations]:");
    assert_eq!(t.state(), State::Connected);
}

#[test]
fn stats_line_promotes_configuring_to_connected() {
    let mut t = Tracker::new();
    t.feed_line("[2026-10-03 02:00:00] Got CONNECT response: HTTP/1.1 200 OK");
    assert_eq!(t.state(), State::Configuring);
    t.feed_line("[2026-10-03 02:00:01] RX: 10 packets (600 B); TX: 20 packets (1200 B)");
    assert_eq!(t.state(), State::Connected);
}

#[test]
fn crash_without_signal_is_failed() {
    let mut t = Tracker::new();
    t.feed_line("[2026-10-03 02:00:00] Attempting to connect to server vpn.corp:443");
    t.on_exit(Some(101));
    assert_eq!(t.state(), State::Failed);
}

// ---------------------------------------------------------------------------
// 安全性
// ---------------------------------------------------------------------------

#[test]
fn no_event_leaks_cookie_or_password() {
    for f in ["tests/authok.log", "tests/authfail.log", "tests/badgroup.log"] {
        for e in replay(f) {
            if let Some(d) = &e.detail {
                assert!(!d.contains("MOCKSESSIONCOOKIE"), "{f}: detail 泄漏 cookie");
            }
        }
    }
}

#[test]
fn timestamp_parsed_consistently() {
    for f in ["tests/authok.log", "tests/authfail.log", "tests/badgroup.log"] {
        for e in replay(f) {
            if let Some(ts) = &e.ts {
                assert_eq!(ts.len(), 19, "{f}: {ts}");
                assert_eq!(&ts[4..5], "-");
                assert_eq!(&ts[10..11], " ");
                assert_eq!(&ts[13..14], ":");
            }
        }
    }
}