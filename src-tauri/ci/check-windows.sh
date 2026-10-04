#!/usr/bin/env bash
# 在 macOS/Linux 上对 Windows 代码做**类型检查**（不需要 Windows）。
#
# # 为什么需要这个脚本
#
# 主 crate 依赖 Tauri，而 `tauri-build` 的 Windows 分支要调
# `llvm-rc`（Xcode 里没有）。所以 `cargo check --target
# x86_64-pc-windows-msvc` 会在 build script 阶段就失败，
# 一个 Windows 类型的错误都报不出来。
#
# 绕过办法：把需要检查的模块**原样**抽到一个不含 Tauri 的临时
# crate 里检查。我们已经把协议拆成 `crates/oc-proto`（无 Tauri
# 依赖），`helper/` 与 `helper-win/` 也不再依赖主 crate，所以
# 这条路是通的。
#
# 覆盖范围：
#   - crates/oc-proto    协议 + authz（含 Windows DACL 分支）
#   - helper-win         Windows helper（pipe server + SDDL + 提权）
#   - src/ipc            GUI 侧客户端 + named pipe 传输层
#
# **注意**：这里只验证「能编译」，不验证「能运行」。Windows 上
# 真正的授权行为（DACL 是否真的挡住非授权方）必须有 Windows 实机。

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
TARGET=x86_64-pc-windows-msvc
export PATH="$HOME/.cargo/bin:$PATH"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mFAIL:\033[0m %s\n' "$*" >&2; exit 1; }

command -v cargo >/dev/null || die "未找到 cargo"

# ── 1. 目标工具链 ────────────────────────────────────────────────
if ! rustup target list --installed | grep -qx "$TARGET"; then
  log "安装 target $TARGET"
  rustup target add "$TARGET"
fi

# ── 2. oc-proto ────────────────────────────────────────────────
# 无需任何处理，直接就能检查。
log "cargo check --target $TARGET (crates/oc-proto)"
( cd crates/oc-proto && cargo check --target "$TARGET" ) || die "oc-proto 在 Windows 上编译失败"
( cd crates/oc-proto && cargo test ) >/dev/null || die "oc-proto 宿主测试失败"
log "oc-proto: Windows 编译 OK，宿主测试 OK"

# ── 3. helper-win ──────────────────────────────────────────────
log "cargo clippy --target $TARGET (helper-win)"
( cd helper-win && cargo clippy --target "$TARGET" ) || die "helper-win 在 Windows 上编译失败"
log "helper-win: Windows clippy OK"

# 非 Windows 上运行 helper-win 应该干净退出（防止误打包）。
# 注意：不能用 `cargo run | grep -q` —— pipefail 下 grep -q 提前退出
# 会给 cargo 发 SIGPIPE，整条管道因此返回失败。
out="$( cd helper-win && cargo run --quiet 2>&1 || true )"
case "$out" in
  *仅适用于*) log "helper-win: 非 Windows 上正确拒绝运行" ;;
  *) die "helper-win 在非 Windows 上没有正确拒绝运行：$out" ;;
esac

# ── 4. src/ipc（GUI 侧传输层）────────────────────────────────────
# 主 crate 查不了（tauri-winres 需要 llvm-rc），所以搭一个
# 只含 ipc 模块的临时 crate。
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/src"
cat > "$TMP/Cargo.toml" <<EOF
[package]
name = "oc-gui-ipcchk"
version = "0.0.0"
edition = "2024"

[dependencies]
oc-proto = { path = "$ROOT/crates/oc-proto" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
log = "0.4"

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.60", features = [
  "Win32_Foundation", "Win32_Security", "Win32_Security_Authorization",
  "Win32_Storage_FileSystem", "Win32_System_Pipes", "Win32_System_IO",
  "Win32_System_Threading", "Win32_System_Console",
  "Win32_UI_Shell", "Win32_UI_WindowsAndMessaging" ] }
EOF

# 复刻 src/ipc.rs 的模块树（去掉 client/pipe 子模块，用顶层挂载，
# 因为 #[path] 指向真实文件更简单）。
cat > "$TMP/src/lib.rs" <<'EOF'
pub mod ipc {
    pub use oc_proto::*;
    pub mod authz {
        pub use oc_proto::authz::*;
    }
}
#[path = "ipc_pipe.rs"]
pub mod pipe;
#[path = "ipc_client.rs"]
pub mod client;
EOF

# 把真实文件**原样**复制进来，只重写 `crate::ipc::pipe` 这一条路径
# （子模块在 shim 里是顶层 `crate::pipe`）。
sed 's|crate::ipc::pipe::|crate::pipe::|' "$ROOT/src/ipc/client.rs" > "$TMP/src/ipc_client.rs"
cp "$ROOT/src/ipc/pipe.rs" "$TMP/src/ipc_pipe.rs"

log "cargo check --target $TARGET (src/ipc 传输层)"
( cd "$TMP" && cargo check --target "$TARGET" ) || die "src/ipc 在 Windows 上编译失败"
log "src/ipc: Windows 编译 OK"

printf '\n\033[1;32m全部 Windows 交叉检查通过。\033[0m\n'
printf '提醒：这只证明「能编译」。DACL 的实际授权行为需要 Windows 实机验证。\n'