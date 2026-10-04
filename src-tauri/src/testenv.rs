//! 测试专用的进程全局环境变量锁。
//!
//! # 为什么需要
//!
//! `std::env::set_var` 改的是**进程级**状态，而 Rust 的测试 harness
//! 默认并行跑测试。于是两个测试一个在 `set_var`、一个在读，就会看到
//! 对方的值 —— 表现为偶发失败，且重跑就好了。
//!
//! 真实踩到过：`socket_path_env_override_wins` 设置
//! `WTHINKVPN_HELPER_SOCKET` 后 `remove_var`，与并行的
//! `linux_path_uses_run_directory` 竞争，后者读到 `/tmp/custom.sock`
//! 就断言失败。
//!
//! 正确做法是所有会动环境变量的测试都持有 [`ENV_LOCK`]。
//! 用 `Mutex` 而不是给单个测试加 `#[serial]`：不引第三方依赖，
//! 且新增测试时只要记得拿锁就自动正确。

use std::sync::{Mutex, MutexGuard, OnceLock};

static LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// 取得环境变量锁。**持有期间不要 `await`、不要 panic 逃逸。**
///
/// 同一线程重入会死锁 —— 所以别在持有它时调用会再拿锁的函数。
pub fn env_guard() -> MutexGuard<'static, ()> {
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        // 测试里 poison 说明前一个测试 panic 了；锁本身还是好用的，
        // 直接放行，好让后续测试能正常跑完并报告真正的失败。
        .unwrap_or_else(|e| e.into_inner())
}

/// 临时设置一个环境变量，返回守卫；守卫 drop 时恢复原值。
///
/// 比手写 `set_var` + `remove_var` 更难写错 —— 忘记恢复的分支
/// 不存在了。
pub struct ScopedEnv {
    key: String,
    prev: Option<String>,
    _guard: MutexGuard<'static, ()>,
}

impl ScopedEnv {
    pub fn set(key: &str, value: &str) -> Self {
        let guard = env_guard();
        let prev = std::env::var(key).ok();
        // SAFETY: 已持有 ENV_LOCK，同进程内没有其他线程会碰环境变量
        unsafe { std::env::set_var(key, value) };
        Self {
            key: key.to_string(),
            prev,
            _guard: guard,
        }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        // SAFETY: 同上，仍持有锁（_guard 还没 drop）
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }
}
