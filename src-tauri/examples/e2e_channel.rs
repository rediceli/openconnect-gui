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
    // 必须让 `Channel::detect` **探测不到** helper。
    //
    // 原先只是 `remove_var("OCGUI_HELPER_SOCKET")`，但那只摘掉了环境
    // 变量覆盖 —— 一旦机器上真装了 daemon（/var/run/oc-gui/helper-<uid>.sock
    // 存在），默认路径照样能连上，ch2 仍是 Helper，断言前提就错了。
    //
    // 改成指向一个确定不存在的路径，才能真正模拟「helper 不可用」。
    unsafe {
        std::env::set_var("OCGUI_OPENCONNECT", "/nonexistent/openconnect");
        std::env::set_var("OCGUI_HELPER_SOCKET", "/nonexistent/helper.sock");
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
