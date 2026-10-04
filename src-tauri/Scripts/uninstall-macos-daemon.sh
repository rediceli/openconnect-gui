#!/usr/bin/env bash
# 卸载 macOS 特权助手（install-macos-daemon.sh 的逆操作）。
#
#     sudo ./Scripts/uninstall-macos-daemon.sh
#
# 会彻底移除：launchd job、二进制、plist、socket。
# **不会**删除任何 profile 或钥匙串条目 —— 那些属于用户数据，
# 删掉它们超出了「卸载特权组件」的范围。

set -euo pipefail

LABEL="io.github.rediceli.ocgui.helper"
HELPER_BIN="/Library/PrivilegedHelperTools/oc-gui-helper"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
SOCKDIR="/var/run/oc-gui"

die() { printf '\033[1;31m错误:\033[0m %s\n' "$*" >&2; exit 1; }
log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

[[ "$(id -u)" -eq 0 ]] || die "需要 root：sudo $0"

if launchctl print "system/$LABEL" >/dev/null 2>&1; then
  log "bootout system/$LABEL"
  launchctl bootout "system/$LABEL" 2>/dev/null || true
else
  log "未发现已加载的 $LABEL（跳过）"
fi

for f in "$PLIST" "$HELPER_BIN"; do
  if [[ -e "$f" ]]; then
    log "删除 $f"
    rm -f "$f"
  fi
done

if [[ -d "$SOCKDIR" ]]; then
  # 只删 socket 文件，目录本身可能是别的东西建的
  find "$SOCKDIR" -maxdepth 1 -name 'helper-*.sock' -delete 2>/dev/null || true
  log "清理 $SOCKDIR"
  rmdir "$SOCKDIR" 2>/dev/null && log "移除空目录" || log "保留非空目录 $SOCKDIR"
fi

# 尝试移除空的 PrivilegedHelperTools（仅当它是我们创建的空目录）
rmdir /Library/PrivilegedHelperTools 2>/dev/null && log "移除空目录 /Library/PrivilegedHelperTools" || true

echo
if launchctl print "system/$LABEL" >/dev/null 2>&1; then
  die "卸载后 daemon 仍在运行，请手动检查"
fi
printf '\033[1;32m卸载完成。\033[0m 用户 profile 与钥匙串条目未改动。\n'
printf '提示：日志文件 /var/log/oc-gui-helper.log 未删除，可按需手动清理。\n'