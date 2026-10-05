//! 状态栏图标（tray icon）与「关闭即最小化」的行为。
//!
//! # 为什么要托盘
//!
//! VPN 客户端的运行形态是「连上之后就不管了」。若点关闭按钮就退出，
//! 用户必须确认断开；而 VPN 断开需要时间（走 vpnc-script 拆路由），
//! 误关窗口等于丢掉连接。因此：**关闭按钮 = 隐藏到状态栏**，
//! 真正的退出必须显式从托盘菜单触发。
//!
//! # macOS 的两个细节
//!
//! 1. **模板图（Template Image）**：菜单栏图标必须是「纯黑 + alpha」的
//!    PNG，系统才会按菜单栏的深/浅色自动反色。用彩色图标会得到一个
//!    在浅色菜单栏上几乎看不清的图标。
//! 2. **Activation Policy**：窗口隐藏后 App 仍以 `Regular` 策略运行，
//!    Dock 里保留图标 —— 这是刻意的。用户从 Dock 点图标能直接唤回窗口，
//!    不必先去菜单栏。若改成 `Accessory`（纯菜单栏应用）则 Dock 无图标，
//!    唤回路径变长。
//!
//! # 托盘菜单上的状态
//!
//! 状态文字放在菜单里而不是只靠图标 —— 图标能表达的信息量太有限，
//! 而「当前到底连上没有」是用户最常问的问题。

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WindowEvent};

/// 托盘项的 id。用常量而非字面量，避免菜单与事件处理处写错字符串。
pub const TRAY_ID: &str = "oc-gui-tray";
pub const MENU_SHOW: &str = "show";
pub const MENU_STATUS: &str = "status";
pub const MENU_DISCONNECT: &str = "disconnect";
pub const MENU_QUIT: &str = "quit";

/// 状态栏图标文件名。按平台挑选：macOS 用单色模板图，其余用彩色版。
#[cfg(target_os = "macos")]
const ICON_FILE: &str = "trayTemplate.png";
#[cfg(not(target_os = "macos"))]
const ICON_FILE: &str = "tray.png";

/// 定位托盘图标。
///
/// # 踩过的坑：不能用相对路径
///
/// 最初写的是 `PathBuf::from("../icons/trayTemplate.png")` —— 依赖**当前
/// 工作目录**。但从 Finder/Dock 启动时 CWD 是 `/`，从终端启动时是用户
/// 当时的目录，两者都找不到图标，于是 `install()` 走降级分支跳过托盘，
/// 而「关闭即隐藏」依赖托盘存在 —— 结果**点关闭直接退出 App**，
/// 表现得像功能没实现。
///
/// 现在按优先级查找：
///   1. bundle 资源目录（打包后的正式路径，已在 tauri.conf.json 声明）
///   2. 编译期 `CARGO_MANIFEST_DIR/icons/`（`cargo tauri dev` 时用）
///   3. 若干候选相对路径（从仓库根手动跑二进制的情况）
///
/// 找不到时返回 `None`，由 `install()` 决定降级 —— 但**必须**打日志，
/// 否则就是上面那种「静默失效」。
fn tray_icon_path(app: &AppHandle) -> Option<std::path::PathBuf> {
    if let Ok(dir) = app.path().resource_dir() {
        let p = dir.join(ICON_FILE);
        if p.exists() {
            return Some(p);
        }
    }
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dev = manifest.join("icons").join(ICON_FILE);
    if dev.exists() {
        return Some(dev);
    }
    let cwd_icon = std::path::PathBuf::from(ICON_FILE);
    if cwd_icon.exists() {
        return Some(cwd_icon);
    }
    None
}

/// 托盘菜单的存放处。
///
/// 必须自己留着句柄：Tauri 的 `TrayIcon` **没有** `menu()` getter，
/// 而更新菜单项文字需要 `Menu` 对象。若不保存，连接状态变化时就无法
/// 更新菜单上的「状态：…」与「断开」可用性。
pub struct TrayMenu(pub std::sync::Mutex<Menu<tauri::Wry>>);

/// 安装托盘图标。
///
/// 幂等：重复调用不会产生第二个托盘。
///
/// 用具体的 `AppHandle`（即 `AppHandle<Wry>`）而非泛型：`commands` 层的
/// Tauri 命令也是具体类型，写成泛型反而要额外转换。
pub fn install(app: &AppHandle) -> tauri::Result<()> {
    if app.tray_by_id(TRAY_ID).is_some() {
        return Ok(());
    }

    let show = MenuItem::with_id(app, MENU_SHOW, "显示主窗口", true, None::<&str>)?;
    let status = MenuItem::with_id(app, MENU_STATUS, "状态：未连接", false, None::<&str>)?;
    // 断线时禁用，避免用户点一个必然失败的操作
    let disconnect = MenuItem::with_id(app, MENU_DISCONNECT, "断开连接", false, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, MENU_QUIT, "退出 OC GUI", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&show, &status, &disconnect, &sep, &quit])?;
    app.manage(TrayMenu(std::sync::Mutex::new(menu.clone())));

    let Some(icon_path) = tray_icon_path(app) else {
        // 没有图标就别装托盘 —— 装了用户也看不见，反而困惑。
        eprintln!("警告：找不到托盘图标，跳过安装（窗口关闭将直接退出）");
        return Ok(());
    };
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .tooltip("OC GUI")
        .icon(tauri::image::Image::from_path(&icon_path)?)
        .on_menu_event(handle_menu_event)
        .on_tray_icon_event(handle_tray_event);

    // macOS 专用：把图标标记为模板图，系统才会按菜单栏配色反色。
    #[cfg(target_os = "macos")]
    {
        builder = builder.icon_as_template(true);
    }

    builder.build(app)?;
    Ok(())
}

/// 托盘菜单点击。
fn handle_tray_event(tray: &tauri::tray::TrayIcon, event: TrayIconEvent) {
    // macOS 上左键点击托盘图标**不会**自动弹出菜单（那是右键的行为），
    // 所以这里手动唤回窗口 —— 否则用户点了没反应。
    #[cfg(target_os = "macos")]
    if let TrayIconEvent::Click {
        button: MouseButton::Left,
        button_state: MouseButtonState::Up,
        ..
    } = event
    {
        show_main_window(tray.app_handle());
    }

    #[cfg(not(target_os = "macos"))]
    {
        // 其余平台左键弹菜单是惯例，不做额外处理
        let _ = (tray, event);
    }
}

/// 菜单项被点击。
fn handle_menu_event(app: &AppHandle, event: tauri::menu::MenuEvent) {
    match event.id().as_ref() {
        MENU_SHOW => show_main_window(app),
        MENU_DISCONNECT => {
            // 断开是异步的（要走 vpnc-script），这里只发起请求。
            // 结果通过事件总线回到主窗口，托盘状态随之更新。
            if let Err(e) = crate::commands::disconnect(app.clone()) {
                log::warn!("托盘断开失败: {e}");
            }
        }
        MENU_QUIT => {
            // 显式退出：先把隧道断干净，否则会留下孤儿 openconnect
            // 进程与残留路由。
            let _ = crate::commands::disconnect(app.clone());
            app.exit(0);
        }
        _ => {}
    }
}

/// 显示并聚焦主窗口。
///
/// 隐藏过的窗口必须先 `show()` 再 `unminimize()`：`hide()` 之后窗口的
/// 最小化状态仍在，只调 `unminimize()` 会出现「调用了但看不见」。
pub fn show_main_window(app: &AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
}

/// 更新托盘菜单上的状态文字与「断开」项的可用性。
///
/// 由连接状态变化时调用。菜单项**用 id 取回再改**，不能保留旧句柄 ——
/// Tauri 的菜单项每次构建都会生成新句柄。
pub fn update_status(app: &AppHandle, label: &str, connected: bool) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    let Some(state) = app.try_state::<TrayMenu>() else {
        return;
    };
    let menu = state.0.lock().unwrap_or_else(|e| e.into_inner());

    // `Menu::get` 返回 `MenuItemKind`（可能是 Submenu/Predefined），
    // 必须先转成 `MenuItem` 才有 set_text / set_enabled。
    use tauri::menu::MenuItemKind;
    if let Some(MenuItemKind::MenuItem(i)) = menu.get(MENU_STATUS) {
        let _ = i.set_text(format!("状态：{label}"));
    }
    if let Some(MenuItemKind::MenuItem(i)) = menu.get(MENU_DISCONNECT) {
        let _ = i.set_enabled(connected);
    }
    // Tooltip 也带上状态：菜单栏图标旁边的提示文字。
    let _ = tray.set_tooltip(Some(format!("OC GUI — {label}")));
}

/// Dock 图标点击 / App 重新激活时唤回窗口。
///
/// # 为什么必须有这个
///
/// 窗口隐藏后，除了托盘之外，macOS 上还有一个用户会尝试的入口：
/// **点 Dock 里的 App 图标**。不接这个事件的话，那个点击毫无反应 ——
/// 图标明明在，用户点了却什么都没发生，比没有托盘更让人困惑。
///
/// `has_visible_windows == false` 正是「窗口被隐藏」的情形；
/// 已经可见时不要重复 show，否则会把用户从别的 App 抢焦点。
pub fn on_reopen(app: &AppHandle) {
    let hidden = app
        .get_webview_window("main")
        .map(|w| !w.is_visible().unwrap_or(true))
        .unwrap_or(true);
    if hidden {
        show_main_window(app);
    }
}

/// 「关闭按钮 = 隐藏到托盘」。
///
/// 这是整个 tray 功能的核心：否则用户一点关闭 App 就退出了，
/// 而断开需要时间。
///
/// # 为什么不能只依赖托盘存在
///
/// 没有托盘图标时（找不到图标文件）必须退化为正常退出，
/// 否则用户点关闭后 App 彻底消失且没有任何入口找回 —— 比直接退出更糟。
pub fn on_window_event(window: &tauri::Window, event: &WindowEvent) {
    let app = window.app_handle();
    // `prevent_close` 的句柄在 event 里，不是 window 的方法 ——
    // 写成 `window.close_requested_api()` 编译不过。
    let WindowEvent::CloseRequested { api, .. } = event else {
        return;
    };
    // 无托盘 → 允许正常关闭（否则 App 会变成唤不回的僵尸）
    if app.tray_by_id(TRAY_ID).is_none() {
        return;
    }
    // 阻止销毁，仅隐藏
    api.prevent_close();
    let _ = window.hide();
}

/// 托盘的自检信息。给「装上托盘了吗」一个可验证的答案。
///
/// # 为什么需要它
///
/// 这个功能出过一次**静默失效**：图标路径用了相对路径，从 Dock 启动
/// 时找不到，`install()` 走降级分支跳过托盘，而「关闭即隐藏」依赖托盘
/// 存在 —— 于是表现为「点关闭直接退出」，看起来像功能没实现。
///
/// 但当时没有任何报错可查（只有一个 eprintln，且换种启动方式才可见）。
/// 现在把它做成可查询的状态，排查时不必再靠猜。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrayStatus {
    /// 托盘是否已安装 —— 「关闭即隐藏」的前提
    pub installed: bool,
    /// 实际使用的图标路径（未安装时为空）
    pub icon_path: Option<String>,
    /// 图标是否为纯黑+alpha 的模板图（仅 macOS 有意义）
    pub is_template: bool,
    pub platform: &'static str,
}

pub fn status(app: &AppHandle) -> TrayStatus {
    let installed = app.tray_by_id(TRAY_ID).is_some();
    TrayStatus {
        installed,
        is_template: cfg!(target_os = "macos") && installed,
        icon_path: tray_icon_path(app).map(|p| p.display().to_string()),
        platform: std::env::consts::OS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 托盘图标必须存在，否则「关闭即隐藏」会把 App 变成无法唤回的僵尸。
    ///
    /// 这条不变量靠 `install()` 里的降级分支兜底，但降级意味着用户
    /// 点关闭就直接退出 —— 静默但行为不同，所以用测试钉住前提。
    #[test]
    fn tray_icon_file_exists() {
        // 无 AppHandle 时只能验证编译期路径（dev 模式那条分支）
        let dev = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("icons")
            .join(ICON_FILE);
        assert!(
            dev.exists(),
            "托盘图标缺失: {}",
            dev.display()
        );
    }

    /// macOS 必须用模板图，否则浅色菜单栏上会看不清。
    #[test]
    fn macos_uses_monochrome_template_icon() {
        if cfg!(target_os = "macos") {
            assert_eq!(ICON_FILE, "trayTemplate.png");
        } else {
            assert_eq!(ICON_FILE, "tray.png");
        }
    }

    /// 打包时必须把托盘图标带进 bundle，否则安装后托盘静默消失。
    #[test]
    fn tray_icons_are_declared_as_bundle_resources() {
        let conf = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tauri.conf.json");
        let text = std::fs::read_to_string(&conf).expect("读 tauri.conf.json");
        for f in [
            "icons/trayTemplate.png",
            "icons/trayTemplate@2x.png",
            "icons/tray.png",
            "icons/tray@2x.png",
        ] {
            assert!(text.contains(f), "tauri.conf.json 未声明资源 {f}");
        }
    }
}