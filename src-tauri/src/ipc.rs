//! GUI ↔ 特权 helper 的协议。
//!
//! 定义在 [`oc_proto`]（独立 crate，无 Tauri 依赖），
//! 这里只做 re-export，保持 `crate::ipc::*` 的引用路径不变。
//!
//! 独立成 crate 的原因：helper 与 GUI 需要共用同一份协议，但 helper
//! 不能依赖 Tauri（会把 `tauri-build` → `llvm-rc` 拖进依赖链，
//! 导致 Windows 交叉 `cargo check` 跑不起来）。
//!
//! 注意 `Response::State` 用字符串表达状态与原因，而不是 GUI 侧的
//! `tunnel::State` / `tunnel::TerminalCause` —— 这是保持解耦的代价，
//! 转换在 `crate::channel` 完成。

pub use oc_proto::*;

/// 保留原有模块路径（`crate::ipc::authz::*`）。
pub mod authz {
    pub use oc_proto::authz::*;
}

pub mod client;

/// Windows named pipe 传输层（仅 Windows 编译）。
#[cfg(windows)]
pub mod pipe;
