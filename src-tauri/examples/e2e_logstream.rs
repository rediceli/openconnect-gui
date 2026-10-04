//! 端到端：GUI 客户端通过 helper 消费**流式日志**。
//!
//! 前置：
//!   python3 docs/mock_gateway.py &
//!   WTHINKVPN_ALLOWED_UIDS=$(id -u) WTHINKVPN_OPENCONNECT=/usr/local/bin/openconnect \
//!     ./helper/target/release/wthinkvpn-helper --serve /tmp/wthinkvpn-helper-$(id -u).sock &
//!
//! 用法：cargo run --example e2e_logstream -- <ca.crt>

use wthinkvpn_lib::channel::{self, Channel, StreamEvent};
use wthinkvpn_lib::ipc::client::HelperHandle;
use wthinkvpn_lib::profile::Profile;
use wthinkvpn_lib::tunnel::{argv, Secrets};

fn main() {
    let ca = std::env::args().nth(1).expect("usage: e2e_logstream <ca.crt>");
    let uid = channel::current_uid();

    match HelperHandle::probe(uid) {
        Ok(()) => println!("[ok] helper 可用"),
        Err(e) => {
            println!("[!!] helper 不可用: {e}");
            std::process::exit(1);
        }
    }

    let mut ch = Channel::detect(uid);
    println!("channel privileged = {}", ch.is_privileged());
    assert!(ch.is_privileged(), "应走 helper 通道");

    let mut p = Profile::new("e2e-stream", "stream", "127.0.0.1:8443/");
    p.username = Some("testuser".into());
    p.auth_group = Some("Engineering".into());

    let mut plan = argv::build(
        &p,
        &Secrets {
            password: Some("hunter2".into()),
            ..Default::default()
        },
    );
    // mock 是自签证书
    plan.args.push("--cafile".into());
    plan.args.push(ca);

    let pid = std::sync::Arc::new(std::sync::Mutex::new(None));
    let pid2 = pid.clone();
    let mut logs = 0usize;
    let mut states: Vec<String> = Vec::new();

    let r = ch.start_streaming(&plan, pid2, |ev| match ev {
        StreamEvent::Started { pid } => println!("[started] pid={pid}"),
        StreamEvent::Log { line, state } => {
            if !line.is_empty() {
                logs += 1;
                if logs <= 3 || line.contains("certificate") || line.contains("CONNECT") {
                    println!("  [log {}] {}", logs, &line[..line.len().min(70)]);
                }
            }
            if let Some(s) = state {
                let n = format!("{s:?}");
                if states.last() != Some(&n) {
                    println!("  [state] {n}");
                    states.push(n);
                }
            }
        }
        StreamEvent::Finished { state, cause } => {
            println!("[finished] state={state:?} cause={cause:?}");
        }
        StreamEvent::Exited { code } => println!("[exited] code={code:?}"),
        StreamEvent::Failed { message, key } => {
            println!("[failed] {message} ({key})")
        }
    });

    println!("\n结果: r={:?}", r.is_ok());
    println!("共收到 {logs} 条日志，状态轨迹 {states:?}");
    let finished = states.iter().filter(|s| *s == "Failed").count();
    assert_eq!(finished, 1, "Failed 应恰好出现一次，实际 {finished}");
    println!("pid slot = {:?}", pid.lock().unwrap());
    assert!(logs > 20, "应收到大量日志，实际 {logs}");
    assert!(r.is_ok(), "start_streaming 应成功");
    println!("\n[ok] helper 日志流式转发验证通过");
}
