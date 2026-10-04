#!/bin/sh
# 安装 OC GUI 特权 helper（Linux）
#
# 做四件事：
#   1. 复制 helper 到 /usr/libexec/
#   2. 安装 polkit .policy 到 /usr/share/polkit-1/actions/
#   3. 创建 /run/oc-gui 目录（systemd-tmpfiles 优先）
#   4. 校验：pkaction 能列出 action，helper --selftest 通过
#
# 用法：
#   sudo ./install.sh              # 安装
#   sudo ./install.sh --dry-run    # 只打印要做什么，不改系统
#   sudo ./install.sh --uninstall  # 移除
#
# 设计约束：
# - **不创建任何 setuid 二进制。** 提权完全交给 polkit + pkexec。
# - 不写入任何 uid 到文件。允许列表由 GUI 在调用时以自己的 uid 传入，
#   helper 只为「刚刚通过 polkit 认证的那个 uid」建 socket。
#   这消除了「配置文件里的 uid 过期」这类整类问题。

set -eu

PREFIX="${PREFIX:-/usr}"
LIBEXEC="$PREFIX/libexec/oc-gui-helper"
POLKIT_DIR="$PREFIX/share/polkit-1/actions"
POLKIT_FILE="$POLKIT_DIR/org.github.rediceli.ocgui-helper.policy"
RUNTIME_DIR="/run/oc-gui"
HELPER_ACTION="org.github.rediceli.ocgui-helper"

HERE=$(cd "$(dirname "$0")" && pwd)
SRC_HELPER="$HERE/target/release/oc-gui-helper"
[ -x "$SRC_HELPER" ] || SRC_HELPER="$HERE/../target/release/oc-gui-helper"
POLKIT_SRC="$HERE/polkit/org.github.rediceli.ocgui-helper.policy"

DRY=0
UNINSTALL=0
for a in "$@"; do
    case "$a" in
        --dry-run)   DRY=1 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help)   sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "未知参数: $a" >&2; exit 2 ;;
    esac
done

run() {
    if [ "$DRY" = 1 ]; then
        echo "  [dry-run] $*"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# 卸载
# ---------------------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
    echo "卸载 OC GUI helper"
    run rm -f "$LIBEXEC"
    run rm -f "$POLKIT_FILE"
    # 只删自己建的 socket，不 rm -rf 整个目录 —— 目录里可能有别的状态
    for s in "$RUNTIME_DIR"/helper-*.sock; do
        [ -e "$s" ] || continue
        echo "  注意：请先停止 helper 进程再删除 $s"
        run rm -f "$s"
    done
    run rmdir "$RUNTIME_DIR" 2>/dev/null || true
    exit 0
fi

# ---------------------------------------------------------------------------
# 前置检查
# ---------------------------------------------------------------------------
[ "$(id -u)" = 0 ] || { echo "必须以 root 运行（sudo ./install.sh）" >&2; exit 1; }

if [ ! -x "$SRC_HELPER" ]; then
    echo "找不到 helper 二进制: $SRC_HELPER" >&2
    echo "先构建：cargo build --release --manifest-path helper/Cargo.toml" >&2
    exit 1
fi
[ -f "$POLKIT_SRC" ] || { echo "找不到 policy 文件: $POLKIT_SRC" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 安装
# ---------------------------------------------------------------------------
echo "安装 OC GUI 特权 helper 到 $PREFIX"

install -d -m 0755 "$PREFIX/libexec"
install -d -m 0755 "$POLKIT_DIR"

# root:root, 0755 —— helper 本身不需要 setuid，提权靠 pkexec+polkit
run install -m 0755 -o root -g root "$SRC_HELPER" "$LIBEXEC"
run install -m 0644 -o root -g root "$POLKIT_SRC" "$POLKIT_FILE"
echo "  $LIBEXEC"
echo "  $POLKIT_FILE"

# /run 是 tmpfs，重启后消失。用 systemd-tmpfiles 声明，
# 没有 systemd 的系统退化为「helper 首次运行时自建」。
run install -d -m 0755 -o root -g root "$RUNTIME_DIR"
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    TMPFILES="$PREFIX/lib/tmpfiles.d/oc-gui.conf"
    run install -d -m 0755 "$PREFIX/lib/tmpfiles.d"
    printf '# 由 oc-gui install.sh 生成\nd %s 0755 root root -\n' "$RUNTIME_DIR" \
        > "$TMPFILES"
    run install -m 0644 -o root -g root "$TMPFILES" "$TMPFILES"
    run systemd-tmpfiles --create "$TMPFILES"
    echo "  $TMPFILES"
else
    echo "  （无 systemd-tmpfiles，$RUNTIME_DIR 将由 helper 首次运行时创建）"
fi

# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------
echo
echo "校验："

if [ "$DRY" = 1 ]; then
    echo "  [dry-run] 跳过全部校验"
    exit 0
fi

fail=0

# 1. helper 自检
if out=$("$LIBEXEC" --selftest 2>&1); then
    echo "  ok   helper --selftest: $out"
else
    echo "  FAIL helper --selftest: $out"
    fail=1
fi

# 2. polkit 能解析 action
if command -v pkaction >/dev/null 2>&1; then
    if pkaction --action-id "$HELPER_ACTION" >/dev/null 2>&1; then
        echo "  ok   polkit action 已注册: $HELPER_ACTION"
    else
        echo "  FAIL polkit 找不到 action $HELPER_ACTION"
        echo "       尝试: sudo systemctl reload polkit   或重启 polkit"
        fail=1
    fi
else
    echo "  warn pkaction 不存在（未装 polkit），跳过该校验"
fi

# 3. helper 里不含 setuid 位
mode=$(stat -c '%a' "$LIBEXEC" 2>/dev/null || stat -f '%Lp' "$LIBEXEC" 2>/dev/null || echo "?")
case "$mode" in
    4???|6???|7???)
        echo "  FAIL helper 意外带 setuid 位 (mode=$mode)"
        fail=1 ;;
    *)
        echo "  ok   helper 无 setuid 位 (mode=$mode)" ;;
esac

# 4. 非 root 无法直接启动 --authorize
if "$LIBEXEC" --authorize "$(id -u)" >/dev/null 2>&1; then
    echo "  FAIL 非 root 也能启动 --authorize，这不该发生"
    fail=1
else
    echo "  ok   非 root 启动 --authorize 被拒绝"
fi

echo
if [ "$fail" = 0 ]; then
    cat <<EOF
安装完成。

GUI 侧连接 helper 的方式：
    pkexec $LIBEXEC --authorize \$(id -u)

或用 GUI 内置的 "以管理员身份启动 helper" 按钮（内部就是上面这条命令）。

首次连接会弹出 polkit 密码框。helper 会为你的 uid 建立：
    $RUNTIME_DIR/helper-\$(id -u).sock   (0600, 属主你自己)

卸载：sudo ./install.sh --uninstall
EOF
else
    echo "校验未通过，请检查上面的 FAIL 项。" >&2
    exit 1
fi