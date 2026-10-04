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

    // Direct 模式下程序不存在应给出明确错误
    unsafe { std::env::set_var("OCGUI_OPENCONNECT", "/nonexistent/openconnect") };
    let mut ch2 = Channel::detect(uid);

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
