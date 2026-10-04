//! 端到端：GUI 客户端 → helper（开发模式）→ 真实 openconnect。
//!
//! 前置：
//!   python3 docs/mock_gateway.py &
//!   WTHINKVPN_ALLOWED_UIDS=$(id -u) ./helper/target/release/wthinkvpn-helper \
//!       --serve /tmp/wthinkvpn-helper-$(id -u).sock &
//!
//! 用法：
//!   cargo run --example e2e_helper -- <ca.crt>

use wthinkvpn_lib::ipc::client::HelperHandle;
use wthinkvpn_lib::ipc::{Request, StdinSecret};

fn main() {
    let uid = unsafe { libc::getuid() };
    let ca = std::env::args().nth(1).expect("usage: e2e_helper <ca.crt>");

    // 1. 探测：socket 不存在时应给出可读错误，而不是崩
    match HelperHandle::probe(uid) {
        Ok(()) => println!("[ok] helper 可用"),
        Err(e) => {
            println!("[info] helper 不可用: {e}");
            println!("       UI 应引导用户执行：");
            println!("       pkexec /usr/libexec/wthinkvpn-helper --authorize {uid}");
            return;
        }
    }

    let mut h = HelperHandle::connect(uid).expect("连接 helper");

    // 2. 危险参数应被 helper 拒绝
    let r = h.request(&Request::Start {
        args: vec!["--csd-wrapper=/tmp/evil.sh".into()],
        server: "vpn.corp".into(),
        stdin_secrets: vec![],
        token_secret: None,
    });
    match r {
        Ok(wthinkvpn_lib::ipc::Response::Failed { error }) => {
            println!("[ok] helper 拒绝了危险参数: {error:?}");
        }
        other => panic!("helper 未拒绝危险参数: {other:?}"),
    }

    // 3. 正常启动
    let args = vec![
        "--protocol=anyconnect".to_string(),
        "--timestamp".into(),
        "-v".into(),
        "-u".into(),
        "testuser".into(),
        "--form-entry=main:group_list=Engineering".into(),
        "--passwd-on-stdin".into(),
        "--cafile".into(),
        ca.clone(),
    ];
    let r = h
        .request(&Request::Start {
            args,
            server: "127.0.0.1:8443/".into(),
            stdin_secrets: vec![StdinSecret::Password("hunter2".into())],
            token_secret: None,
        })
        .expect("Start 请求失败");
    println!("[ok] Start 响应: {r:?}");

    std::thread::sleep(std::time::Duration::from_secs(3));
    println!("\n（mock gateway 日志应显示 user='testuser' pass=*******）");
}
