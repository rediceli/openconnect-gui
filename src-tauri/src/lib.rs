//! OC GUI — 基于 openconnect 的跨平台桌面客户端
//!
//! 模块职责：
//! - [`profile`] 连接档案（只存非敏感信息，TOML）
//! - [`secret`] 系统钥匙串（密码、私钥口令、令牌 secret）
//! - [`tunnel`] argv 构建、日志事件解析、状态机、子进程监管

pub const APP_DIR: &str = "OC GUI";

pub mod channel;
pub mod commands;
pub mod ipc;
pub mod profile;
pub mod secret;
#[cfg(test)]
mod testenv;

pub mod tlsprobe;
pub mod tray;
pub mod tunnel;
use serde::Serialize;

#[derive(Serialize)]
pub struct BackendInfo {
    openconnect_path: Option<String>,
    openconnect_version: Option<String>,
    platform: &'static str,
}

/// P0 冒烟：后端是否可达 + openconnect 是否可用。
#[tauri::command]
fn backend_info() -> BackendInfo {
    let version = std::process::Command::new("openconnect")
        .arg("-V")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").to_string());
    BackendInfo {
        openconnect_path: version.as_ref().map(|_| "openconnect".to_string()),
        openconnect_version: version,
        platform: std::env::consts::OS,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::default().build())
        .invoke_handler(tauri::generate_handler![
            backend_info,
            commands::list_profiles,
            commands::save_profile,
            commands::delete_profile,
            commands::store_password,
            commands::has_saved_password,
            commands::connect,
            commands::disconnect,
            commands::helper_status,
            commands::helper_start_elevated,
            commands::helper_wait_ready,
            commands::open_system_settings,
            commands::probe_server_cert,
            commands::trust_server_cert,
            commands::tray_status,
            commands::show_main_window,
            commands::quit_app,
        ])
        .setup(|app| {
            commands::setup(app)?;
            // 托盘必须在 setup 里建：它依赖 AppHandle，而 window 事件
            // 回调也要用到托盘是否存在。
            if let Err(e) = tray::install(app.handle()) {
                // 装不上不致命 —— 关闭按钮会退化为直接退出，
                // 但窗口和连接功能不受影响。
                log::warn!("托盘安装失败，关闭按钮将直接退出: {e}");
            }
            Ok(())
        })
        .on_window_event(tray::on_window_event)
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            // Dock 点击 / 重新激活
            if let tauri::RunEvent::Reopen {
                has_visible_windows: false,
                ..
            } = event
            {
                tray::on_reopen(app);
            }
        });
}
