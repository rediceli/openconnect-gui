//! 跨平台「请求 openconnect 断开」的信号发送
//!
//! # 为什么不能简单用 SIGKILL
//!
//! SIGKILL 会留下脏路由和残留 DNS。openconnect 捕获信号后才会走正常的
//! `openconnect_mainloop` 退出路径并执行 vpnc-script 的 `disconnect` 分支。
//!
//! # 三个平台的机制（均已源码核实）
//!
//! | 平台 | 机制 | openconnect 侧 | 结果 |
//! |---|---|---|---|
//! | Linux/macOS | `SIGINT` | `main.c:2349` `sigaction(SIGINT)` | mainloop 返回 `-EINTR` → 正常断开 |
//! | Windows | `CTRL_BREAK_EVENT` | `main.c:876` `console_ctrl_handler` | 发送 `OC_CMD_DETACH`（`'d'`） |
//!
//! ## Windows 的关键细节
//!
//! `console_ctrl_handler`（main.c:876）把控制事件映射为命令：
//!
//! ```c
//! case CTRL_C_EVENT:
//! case CTRL_CLOSE_EVENT:
//! case CTRL_LOGOFF_EVENT:
//! case CTRL_SHUTDOWN_EVENT:
//!         cmd = OC_CMD_CANCEL;   // 'x' —— 取消，丢弃会话
//!         break;
//! case CTRL_BREAK_EVENT:
//!         cmd = OC_CMD_DETACH;   // 'd' —— 断开隧道，保留会话
//!         break;
//! ```
//!
//! 用 `CTRL_BREAK_EVENT`（而不是 `CTRL_C_EVENT`）的原因：
//! - `CTRL_BREAK_EVENT` 可以用 `GenerateConsoleCtrlEvent` 发给
//!   **指定的进程组**；`CTRL_C_EVENT` 只能发给 0（当前所有进程组），
//!   会连 GUI 自己一起打断。
//! - 语义更合适：断开隧道而非注销会话。
//!
//! 前置条件：spawn 时必须带 `CREATE_NEW_PROCESS_GROUP`，否则子进程不
//! 独立成组，`GenerateConsoleCtrlEvent` 无法定位到它。
//!
//! ⚠️ Ctrl-Break 事件是投递到控制台的，openconnect 的 handler 在**独立
//! 线程**中执行（源码注释明确写了），因此投递后需要给它时间响应。
//! 超时后仍需有强杀兜底。

use std::process::Child;

/// 断开请求的结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalOutcome {
    /// 信号已发出
    Sent,
    /// 该平台不支持（调用方应直接走强杀）
    Unsupported,
    /// 发送失败
    Failed,
}

/// 平台 capability
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Posix,
    Windows,
}

/// 当前平台的断开能力
pub const fn platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        Platform::Posix
    }
}

/// spawn openconnect 时需要的进程创建标志。
///
/// 公开出来是为了让调用方能验证「标志与断开方式匹配」——
/// 不带 `CREATE_NEW_PROCESS_GROUP` 的话 Windows 断开必然失败。
#[cfg(windows)]
pub fn creation_flags() -> u32 {
    CREATE_NEW_PROCESS_GROUP
}

#[cfg(not(windows))]
pub fn creation_flags() -> u32 {
    0
}

#[cfg(windows)]
pub const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// 把平台需要的创建标志应用到 `Command`。
///
/// 抽出来是为了让 [`supervisor::start`] 不必写 `#[cfg]`。
pub fn apply_creation_flags(cmd: &mut std::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(creation_flags());
    }
    #[cfg(not(windows))]
    {
        let _ = cmd;
        let _ = creation_flags();
    }
}

#[cfg(unix)]
pub fn send_disconnect(child: &mut Child) -> SignalOutcome {
    // 用 /bin/kill 而不是 libc：容器/精简系统里未必有 libc 绑定，
    // 而 openconnect 一定在 PATH 里（我们就是这么 spawn 的）。
    // 子进程仍存活，不存在 pid 复用竞态。
    match std::process::Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(s) if s.success() => SignalOutcome::Sent,
        Ok(_) => SignalOutcome::Failed,
        Err(_) => SignalOutcome::Failed,
    }
}

#[cfg(windows)]
pub fn send_disconnect(child: &mut Child) -> SignalOutcome {
    use windows_sys::Win32::System::Console::{
        GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT,
    };

    let pid = child.id();
    // SAFETY: GenerateConsoleCtrlEvent 是纯 Win32 调用，无不变量要求。
    // dwProcessGroupId 必须是要发送的进程组 id —— 配合
    // CREATE_NEW_PROCESS_GROUP，进程 id 即进程组 id。
    let ok = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) };
    if ok != 0 {
        SignalOutcome::Sent
    } else {
        SignalOutcome::Failed
    }
}

#[cfg(not(any(unix, windows)))]
pub fn send_disconnect(_child: &mut Child) -> SignalOutcome {
    SignalOutcome::Unsupported
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(unused_variables)]
    fn flags_are_consistent_with_disconnect_mechanism() {
        match platform() {
            Platform::Windows => {
                // Windows 断开依赖独立进程组；缺了这个标志就发不出去。
                // 常量在 cfg(windows) 下才存在，这里用字面量交叉验证。
                const C: u32 = 0x0000_0200;
                assert_eq!(creation_flags() & C, C);
            }
            Platform::Posix => {
                // POSIX 不需要特殊标志（setsid 反而会切断控制台）
                assert_eq!(creation_flags(), 0);
            }
        }
    }

    #[test]
    fn platform_matches_cfg() {
        assert_eq!(platform() == Platform::Windows, cfg!(target_os = "windows"));
    }

    #[cfg(unix)]
    #[test]
    fn sigint_reaches_a_live_child() {
        // sleep 忽略 SIGINT，所以用一个会被 INT 打断的：
        // 默认动作是终止的 `sh -c 'trap ... INT'` 过于繁琐，
        // 这里验证「信号投递机制本身可用」—— 用一个立刻退出的进程。
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        assert!(child.try_wait().unwrap().is_none());
        let r = send_disconnect(&mut child);
        // sleep 默认不处理 SIGINT → 会被终止
        assert_eq!(r, SignalOutcome::Sent, "SIGINT 应成功发出");

        // 给它一点时间响应
        for _ in 0..50 {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(child.try_wait().unwrap().is_some(), "子进程应已退出");
    }

    #[cfg(unix)]
    #[test]
    fn sending_to_dead_child_does_not_panic() {
        // `/bin/echo` 比 `/bin/true` 更可移植（BSD/macOS 无 true）
        let mut child = std::process::Command::new("/bin/echo").spawn().unwrap();
        let _ = child.wait();
        // 可能成功（pid 还没被回收）也可能失败，但不能 panic
        let _ = send_disconnect(&mut child);
    }
}