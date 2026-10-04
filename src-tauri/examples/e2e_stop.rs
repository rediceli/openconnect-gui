//! 验证 disconnect 能真正停掉隧道：经**第二条连接**发 Request::Stop。
//!
//! 这测的是 helper 的会话必须是进程级（存进全局槽）而非 per-connection ——
//! 否则第二条连接的 Stop 找不到会话，会静默失效。
//!
//! 用长驻的 openconnect 替身（而非 mock gateway）—— mock 会在 CONNECT
//! 阶段立刻失败退出，隧道活不到能测 Stop 的时刻。
//!
//! 前置：
//!   mkdir -p /tmp/fakeoc && cat > /tmp/fakeoc/openconnect <<'SH'
//!   #!/bin/sh
//!   trap 'exit 0' INT
//!   cat > /dev/null
//!   while : ; do sleep 0.2; done
//!   SH
//!   chmod +x /tmp/fakeoc/openconnect
//!
//!   WTHINKVPN_ALLOWED_UIDS=$(id -u) WTHINKVPN_OPENCONNECT=/tmp/fakeoc/openconnect \
//!     ./helper/target/release/wthinkvpn-helper --serve /tmp/wthinkvpn-helper-$(id -u).sock &

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use wthinkvpn_lib::channel::{self, Channel, StreamEvent};
use wthinkvpn_lib::ipc::client::HelperHandle;
use wthinkvpn_lib::profile::Profile;
use wthinkvpn_lib::tunnel::{argv, Secrets};

fn main() {
    let ca = std::env::args().nth(1).unwrap_or_default();
    let uid = channel::current_uid();

    HelperHandle::probe(uid).expect("helper 不可用");
    let mut ch = Channel::detect(uid);
    assert!(ch.is_privileged(), "应走 helper 通道");

    let mut p = Profile::new("e2e-stop", "stop", "127.0.0.1:8443/");
    p.username = Some("testuser".into());
    p.auth_group = Some("Engineering".into());

    let mut plan = argv::build(
        &p,
        &Secrets {
            password: Some("hunter2".into()),
            ..Default::default()
        },
    );
    if !ca.is_empty() {
        plan.args.push("--cafile".into());
        plan.args.push(ca);
    }
    if !plan.args.iter().any(|a| a.starts_with("--reconnect-timeout")) {
        plan.args.push("--reconnect-timeout=3600".into());
    }

    let pid = Arc::new(std::sync::Mutex::new(None));
    let pid2 = pid.clone();
    let done = Arc::new(AtomicBool::new(false));
    let done2 = done.clone();
    let t = std::thread::spawn(move || {
        ch.start_streaming(&plan, pid2, |ev| match ev {
            StreamEvent::Started { pid } => println!("[started] pid={pid}"),
            StreamEvent::Exited { code } => {
                println!("[exited] code={code:?}");
                done2.store(true, Ordering::SeqCst);
            }
            StreamEvent::Finished { state, cause } => {
                println!("[finished] state={state:?} cause={:?}", cause.is_some());
                // Stop 路径下 helper 发的是 State{Idle}（而非 Exited）——
                // 因为那不是「进程自己退了」，是「我们让它退的」。
                if state == wthinkvpn_lib::tunnel::State::Idle {
                    done2.store(true, Ordering::SeqCst);
                }
            }
            StreamEvent::Failed { message, .. } => {
                println!("[failed] {message}");
                done2.store(true, Ordering::SeqCst);
            }
            StreamEvent::Log { .. } => {}
        })
    });

    // 等隧道起来
    let t0 = std::time::Instant::now();
    while pid.lock().unwrap().is_none() && t0.elapsed() < std::time::Duration::from_secs(15) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let oc_pid = pid.lock().unwrap().expect("隧道未启动");
    println!("[ok] openconnect pid = {oc_pid}");
    assert!(process_alive(oc_pid), "openconnect 应在运行");

    // ---- 第二条连接发 Stop ----
    println!("\n--- 从第二条连接发 Request::Stop ---");
    match HelperHandle::request_stop(uid) {
        Ok(()) => println!("[ok] Stop 已送达"),
        Err(e) => {
            println!("[!!] Stop 失败: {e}");
            std::process::exit(1);
        }
    }

    // 等断开完成
    let t1 = std::time::Instant::now();
    while !done.load(Ordering::SeqCst) && t1.elapsed() < std::time::Duration::from_secs(20) {
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    drop(t);

    let still = process_alive(oc_pid);
    println!("\nopenconnect 仍在运行: {still}");
    assert!(!still, "Stop 之后 openconnect 应已退出（已收到 SIGINT）");
    println!("[ok] 跨连接 Stop 验证通过");
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    // kill -0 只做存在性检查，不发信号
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
