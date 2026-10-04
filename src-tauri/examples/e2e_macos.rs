//! macOS 特权通道的状态探测（不建立连接）。
//!
//! 验证：Rust → macosctl → SMAppService 的链路可用，
//! 且在未签名/未安装的情况下给出的是**可操作的**状态而不是崩溃。
//!
//! 用法：cargo run --example e2e_macos

use oc_gui::channel::{self, Channel};

fn main() {
    let uid = channel::current_uid();
    println!("uid = {uid}");

    #[cfg(target_os = "macos")]
    {
        match channel::macos::find_macosctl() {
            Some(p) => println!("[ok] macosctl: {}", p.display()),
            None => {
                println!("[!!] 找不到 macosctl");
                println!("     开发模式：swift build --package-path macos-helper");
                std::process::exit(1);
            }
        }

        match channel::macos::daemon_state() {
            Ok(s) => println!("[ok] daemon_state = {s}"),
            Err(e) => println!("[!!] daemon_state 失败: {e}"),
        }

        // 未签名时 register 会失败 —— 必须是可读错误
        match channel::macos::register_daemon() {
            Ok(s) => println!("[ok] register -> {s}"),
            Err(e) => println!("[info] register 失败（未签名时预期）: {e}"),
        }

        // Channel::detect 在 macOS 上仍走 socket helper（开发模式），
        // 生产部署会切换到 XPC。这里只验证不 panic。
        let ch = Channel::detect(uid);
        println!("[ok] Channel::detect 不 panic，privileged = {}", ch.is_privileged());

        println!("\n说明：macOS 的生产路径是 privileged XPC；");
        println!("socket helper 路径在 macOS 上仅用于开发/测试。");
    }

    #[cfg(not(target_os = "macos"))]
    {
        println!("此示例仅适用于 macOS");
    }
}
