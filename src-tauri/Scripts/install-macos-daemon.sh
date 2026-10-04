#!/usr/bin/env bash
# 安装 macOS 特权助手 —— **不需要任何代码签名**。
#
# # 为什么不用 SMAppService
#
# `SMAppService.register()` 要求 App 已签名（SDK 头文件原文：
# "Apps that use SMAppService APIs must be code signed"），而 Apple 的
# 公证规则又明确排除 ad-hoc 签名。也就是说不买 Developer ID
# （$99/年）就用不了那条路。
#
# 但 Apple 自己在 SMAppService.h 里承认了另一条路：
#
#   "Legacy LaunchDaemons installed in /Library/LaunchDaemons will
#    continue to be bootstrapped without explicit approval in System
#    Settings since writing to /Library is protected with filesystem
#    permissions."
#
# 翻译过来就是：**信任边界是 /Library 的文件权限，不是签名**。
# 能往 /Library/LaunchDaemons 写的人就是 root，launchd 不校验签名。
#
# # 授权模型（与 Linux 完全一致）
#
# 每个授权 uid 一个 socket，路径 `/var/run/oc-gui/helper-<uid>.sock`，
# 权限 0600、属主该 uid，再加 `getpeereid()` 运行时复检。
# 授权范围由**安装时的 uid 参数**决定；改 plist 需要 sudo，
# 非特权进程无法自行扩权。
#
# # 用法
#
#     sudo ./Scripts/install-macos-daemon.sh            # 授权当前用户
#     sudo ./Scripts/install-macos-daemon.sh 501 502    # 授权多个 uid
#     sudo ./Scripts/install-macos-daemon.sh --all      # 授权所有有登录 shell 的用户
#
# 卸载见 `uninstall-macos-daemon.sh`。

set -euo pipefail

LABEL="io.github.rediceli.ocgui.helper"
HELPER_DIR="/Library/PrivilegedHelperTools"
HELPER_BIN="$HELPER_DIR/oc-gui-helper"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
SOCKDIR="/var/run/oc-gui"

die() { printf '\033[1;31m错误:\033[0m %s\n' "$*" >&2; exit 1; }
log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

[[ "$(id -u)" -eq 0 ]] || die "需要 root：sudo $0 [uid...]"

HERE="$(cd "$(dirname "$0")" && pwd)"
# helper 源码在 ../helper/
SRC="$HERE/../helper"
[[ -f "$SRC/Cargo.toml" ]] || die "找不到 helper 源码: $SRC"

# ── 1. 确定要授权的 uid ─────────────────────────────────────────
case "${1:-}" in
  --all)
    # 所有有登录 shell 的用户 —— 适合跳板机。
    # 刻意排除 nologin/false 的服务账号（如 _apache），给它们开隧道
    # 没有意义却扩大了攻击面。
    #
    # ⚠️ 两个 macOS 特有的坑：
    #
    # 1. 不能用 `mapfile`/`readarray` —— macOS 自带 bash 3.2，
    #    它们是 bash 4 才有的。
    # 2. **不能用 /etc/passwd 枚举用户** —— macOS 用 Open Directory，
    #    /etc/passwd 只含系统账号，普通用户在 dscacheutil 里。
    #    实测：`awk -F: '$1=="lijian"' /etc/passwd` 什么都没有。
    #    正确做法是 `dscl . list /Users UniqueID`。
    #
    # 服务账号（uid < 500，且多为 _xxx / nologin）被排除：给它们开隧道
    # 没有意义，却扩大了攻击面。
    #
    # 结构刻意扁平：先用 awk 拿到「uid 用户名」，再逐个查 shell。
    # 早先把这段写成三层嵌套管道 + 内嵌 case，bash 3.2 下引号会被
    # 吃到打架（实测 `syntax error near unexpected token 'done'`）。
    UIDS=()
    for entry in $(dscl . list /Users UniqueID 2>/dev/null |
                   awk 'NF>=2 && $2+0>=500 {print $2"/"$1}'); do
      uid="${entry%%/*}"
      name="${entry#*/}"
      shell="$(dscl . -read "/Users/$name" UserShell 2>/dev/null |
                awk '/UserShell:/{print $2}')"
      case "$shell" in
        */nologin|*/false|"") ;;   # 不能登录，不授权
        *) UIDS+=("$uid") ;;
      esac
    done
    ;;
  "")
    # sudo 下 $SUDO_USER 才是真实用户；无 sudo 时用当前 uid
    if [[ -n "${SUDO_USER:-}" ]]; then
      UIDS=("$(id -u "$SUDO_USER")")
    else
      UIDS=("$(id -u)")
    fi
    ;;
  -h|--help)
    sed -n '2,30p' "$0"; exit 0 ;;
  *)
    UIDS=("$@") ;;
esac

# 校验：全部是数字、非 0
for u in "${UIDS[@]}"; do
  [[ "$u" =~ ^[0-9]+$ ]] || die "非法 uid: $u"
  [[ "$u" != "0" ]] || die "拒绝为 root 建立 socket"
done
[[ "${#UIDS[@]}" -gt 0 ]] || die "没有可授权的 uid"

log "将授权的 uid: ${UIDS[*]}"
for u in "${UIDS[@]}"; do
  log "  uid=$u  $(id -un "$u" 2>/dev/null || echo '(未知用户)')"
done

# ── 2. 构建 helper ────────────────────────────────────────────
log "构建 helper (release)"
( cd "$SRC" && cargo build --release ) || die "构建失败"

BIN="$SRC/target/release/oc-gui-helper"
[[ -x "$BIN" ]] || die "找不到构建产物: $BIN"

# ── 3. 停掉旧实例（若有）────────────────────────────────────────
if launchctl print "system/$LABEL" >/dev/null 2>&1; then
  log "停止已加载的 $LABEL"
  launchctl bootout "system/$LABEL" 2>/dev/null || true
fi

# ── 4. 安装二进制 ─────────────────────────────────────────────
log "安装到 $HELPER_BIN"
mkdir -p "$HELPER_DIR"
install -m 755 -o root -g wheel "$BIN" "$HELPER_BIN"

# ── 5. socket 目录 ────────────────────────────────────────────
# /var/run 是易失目录（symlink → /private/var/run），重启后为空，
# 所以每次开机都要重建。0755 root:root —— 普通用户需要能穿过它去
# connect 自己那个 0600 的 socket，但不能在里面创建/删除文件。
log "创建 $SOCKDIR"
mkdir -p "$SOCKDIR"
chown root:wheel "$SOCKDIR"
chmod 755 "$SOCKDIR"

# ── 6. 写 LaunchDaemon plist ──────────────────────────────────
# 注意用 `Program` + `ProgramArguments`，**不是** `Program` 指向 bundle：
# `Program` + bundle 形式只对 SMAppService 安装的 job 有效。
log "写入 $PLIST"

# 先停用并移除旧的，避免 launchd 读到过期配置
launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "$PLIST"

{
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>

    <key>ProgramArguments</key>
    <array>
        <string>$HELPER_BIN</string>
        <string>--daemon</string>
EOF
  for u in "${UIDS[@]}"; do printf '        <string>%s</string>\n' "$u"; done
  cat <<'EOF'
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <!-- helper 崩溃后避免疯狂重启：10s 内重启超过 3 次就放弃 -->
    <key>ThrottleInterval</key>
    <integer>10</integer>

    <key>StandardErrorPath</key>
    <string>/var/log/oc-gui-helper.log</string>

    <key>StandardOutPath</key>
    <string>/var/log/oc-gui-helper.log</string>

    <key>ProcessType</key>
    <string>Adaptive</string>

    <!-- 只需要网络与文件操作；不需要任何设备或隐私权限 -->
    <key>Sandboxing</key>
    <dict>
        <key>AllowNetworkClient</key>
        <true/>
        <key>AllowNetworkServer</key>
        <true/>
        <key>AllowFileRead*</key>
        <true/>
    </dict>

    <!-- 注意：不声明 MachServices，因此 launchd 不要求代码签名。
         这正是与 SMAppService 路线的关键区别。 -->
</dict>
</plist>
EOF
} > "$PLIST"

chown root:wheel "$PLIST"
chmod 644 "$PLIST"
plutil -lint "$PLIST" >/dev/null || die "生成的 plist 语法错误"

# ── 7. 加载 ───────────────────────────────────────────────────
log "launchctl bootstrap system/$LABEL"
launchctl bootstrap "system/$PLIST" || die "bootstrap 失败"

# ── 8. 验证 ───────────────────────────────────────────────────
sleep 1
if launchctl print "system/$LABEL" >/dev/null 2>&1; then
  log "✓ daemon 已加载 (pid=$(launchctl print "system/$LABEL" 2>/dev/null | awk '/pid =/{print $3; exit}') )"
else
  echo "--- /var/log/oc-gui-helper.log ---" >&2
  tail -20 /var/log/oc-gui-helper.log 2>/dev/null >&2 || true
  die "daemon 未运行，见上方日志"
fi

echo
log "socket 就绪情况："
ok=1
for u in "${UIDS[@]}"; do
  s="$SOCKDIR/helper-$u.sock"
  if [[ -S "$s" ]]; then
    printf '  \033[1;32m✓\033[0m %s\n' "$s"
  else
    printf '  \033[1;31m✗\033[0m %s (缺失)\n' "$s"
    ok=0
  fi
done

echo
if [[ "$ok" == "1" ]]; then
  printf '\033[1;32m安装完成。\033[0m 现在可以启动 OC GUI 连接 VPN 了。\n'
  printf '日志：tail -f /var/log/oc-gui-helper.log\n'
else
  die "部分 socket 缺失，见上方"
fi