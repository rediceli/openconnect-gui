#!/usr/bin/env bash
# 在 CI 容器里运行完整的 Linux 特权边界测试。
#
# 用法：
#   docker build -f ci/Dockerfile -t oc-gui-ci .
#   docker run --rm --privileged oc-gui-ci
#
# `--privileged` 是必需的：测试需要 useradd、mount namespace 操作，
# 以及 polkitd 的 dbus/systemd 交互。

set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)

echo "### 环境"
cat /etc/os-release | head -2
echo "polkit: $(command -v pkaction || echo '未安装')"
echo "pkexec: $(command -v pkexec || echo '未安装')"
echo

echo "### 构建"
cd "$HERE/.."
cargo build --release --manifest-path helper/Cargo.toml
cargo test --lib --tests
echo

echo "### 特权边界回归"
exec "$HERE/privsep-test.sh"