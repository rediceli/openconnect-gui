//! 验证 channel 层：helper 不可用时明确要求提权，而不是含糊报错。
//!
//! 用法：cargo run --example e2e_channel

use oc_gui::channel::{self, Channel};
use oc_gui::profile::Profile;
use oc_gui::tunnel::{argv, Secrets};

fn main() {
    let uid = channel::current_uid();
    println!("uid = {uid}");

    let ch = Channel::detect(uid);
    println!(
        "channel privileged = {} (is_privileged={})",
        match &ch {
            Channel::Helper(_) => "helper",
            Channel::Direct { program } => {
                println!("  direct program = {}", program.display());
                "direct"
            }
        },
        ch.is_privileged()
    );

    // Direct 模式下程序不存在应给出明确错误。
    //
    // 必须先把 helper 端点摘掉：否则 `Channel::detect` 仍然会连上
    // helper（第一段刚启动了一个），于是 ch2 是 Helper 而非 Direct，
    // 断言的前提就不对了。
    //
    // 这类「测试依赖环境状态」的坑：`cargo run --example` 继承父进程
    // 的环境变量，测试自己设的 OCGUI_HELPER_SOCKET 会一直生效。
    unsafe {
        std::env::set_var("OCGUI_OPENCONNECT", "/nonexistent/openconnect");
        std::env::remove_var("OCGUI_HELPER_SOCKET");
    }
    let mut ch2 = Channel::detect(uid);
    assert!(
        !ch2.is_privileged(),
        "摘掉 helper 端点后应回落到 Direct"
    );

    let mut p = Profile::new("e2e-ch", "test", "vpn.invalid");
    p.username = Some("alice".into());
    let plan = argv::build(
        &p,
        &Secrets {
            password: Some("hunter2".into()),
            ..Default::default()
        },
    );

    match ch2.start(&plan) {
        Ok(_) => println!("[!!] 不该成功"),
        Err(e) => {
            println!("[ok] 启动失败，原因可读: {e}");
            println!("     message_key = {}", e.message_key());
            println!("     needs_privileged_helper = {}", e.needs_privileged_helper());
        }
    }
}
