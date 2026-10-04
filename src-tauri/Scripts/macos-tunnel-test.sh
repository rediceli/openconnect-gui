#!/usr/bin/env bash
# macOS 上真实建立 AnyConnect 隧道并验证内网可达性。
#
# # 为什么必须 root
#
# openconnect 要创建 tun 设备（macOS 上是 /dev/tun），这是 root 专属
# 操作。App 正常流程走已签名的 privileged helper，但那条路需要
# Developer ID 证书（SMAppService），本机没有 —— 所以这个脚本是
# **手工验证通道**用的，不替代 App 的正常路径。
#
# # 用法
#
#     sudo ./Scripts/macos-tunnel-test.sh /path/to/account.txt
#
# account.txt 格式：
#
#     server: https://host:port
#     username: xxx
#     password: xxx
#     cert_pin: pin-sha256:...      # 可选，但自签证书必填
#
# # 安全
#
# 密码通过 stdin 传给 openconnect（`--passwd-on-stdin`），
# **不进 argv**，所以不会出现在 `ps` 输出里。脚本自身也用
# `--passwd-on-stdin`，与 App 的行为一致。

set -euo pipefail

ACCOUNT="${1:-}"
[[ -n "$ACCOUNT" ]] || { echo "用法: sudo $0 <account.txt>" >&2; exit 64; }
[[ -r "$ACCOUNT" ]] || { echo "读不到 $ACCOUNT" >&2; exit 66; }

[[ "$(id -u)" -eq 0 ]] || { echo "需要 root（创建 tun 设备）" >&2; exit 77; }

TMP="$(mktemp -d)"
LOG="$TMP/openconnect.log"
OC_PID=""

cleanup() {
  local rc=$?
  if [[ -n "$OC_PID" ]] && kill -0 "$OC_PID" 2>/dev/null; then
    echo "── 断开隧道 ──"
    # Ctrl-Break 等价物：先 TERM 让 openconnect 走正常清理（含 vpnc-script），
    # 再兜底 KILL
    kill -TERM "$OC_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$OC_PID" 2>/dev/null || break
      sleep 0.5
    done
    kill -KILL "$OC_PID" 2>/dev/null || true
    wait "$OC_PID" 2>/dev/null || true
  fi
  # 只删我们自己创建的 tun
  if [[ "${WE_CREATED_TUN:-0}" == "1" ]]; then
    echo "── 清理 /dev/tun ──"
    rm -f /dev/tun
  fi
  rm -rf "$TMP"
  exit $rc
}
trap cleanup EXIT INT TERM

# ── 解析 account.txt ───────────────────────────────────────────
field() { sed -n "s/^[[:space:]]*$1:[[:space:]]*//p" "$ACCOUNT" | head -1; }
SERVER="$(field server)"
USERNAME="$(field username)"
PASSWORD="$(field password)"
CERT_PIN="$(field cert_pin)"
[[ -n "$SERVER" && -n "$USERNAME" && -n "$PASSWORD" ]] || {
  echo "account.txt 缺少 server/username/password" >&2; exit 65; }

# ⚠️ 自签证书必须有 pin，否则 openconnect 会向 stdin 索要 yes/no，
# 而 stdin 已经被 --passwd-on-stdin 的密码占用了 —— 结果是永久挂起。
# 这也是 App 侧必须处理的情况（见 P1-DESIGN §6.1）。
if [[ -z "$CERT_PIN" ]]; then
  echo "提示: account.txt 未提供 cert_pin。" >&2
  echo "      若服务端证书自签，openconnect 会向 stdin 索要确认而挂起。" >&2
fi

echo "服务器   : $SERVER"
echo "用户名   : $USERNAME"
echo "密码     : （不显示，长度 ${#PASSWORD}）"

OC="$(command -v openconnect || true)"
[[ -n "$OC" ]] || { echo "未找到 openconnect" >&2; exit 69; }
echo "openconnect: $($OC --version 2>&1 | head -1)"

# ── /dev/tun ───────────────────────────────────────────────────
# macOS 内核自带 tun 支持，但没有 /dev/tun 设备节点，必须手工创建。
# char 设备 major=10 minor=200 是 macOS 的 tun（Linux 是 10/200 恰好
# 同值，但 FreeBSD 派生要小心 —— macOS 上实测 10/200 可用）。
WE_CREATED_TUN=0
if [[ ! -c /dev/tun ]]; then
  echo "── 创建 /dev/tun (c 10 200) ──"
  mknod /dev/tun c 10 200
  chmod 600 /dev/tun
  WE_CREATED_TUN=1
fi
ls -l /dev/tun

# ── 组装参数 ───────────────────────────────────────────────────
# 与 App 的 argv::build 保持一致：凭据只走 stdin。
# 额外加 --verbose 便于诊断（App 用 -v）。
ARGS=(
  --protocol=anyconnect
  --timestamp
  -v
  -u "$USERNAME"
  --passwd-on-stdin
  --reconnect-timeout=300
)
[[ -n "$CERT_PIN" ]] && ARGS+=("--servercert=$CERT_PIN")

echo
echo "── 启动 openconnect ──"
echo "openconnect ${ARGS[*]} $SERVER   （密码走 stdin）"

# 密码从管道喂给 stdin，绝不作为命令行参数。
# 管道喂完就 EOF：万一 openconnect 还要交互输入，会立刻拿到 EOF 报错，
# 而不是无限挂起（挂起很难诊断）。
printf '%s\n' "$PASSWORD" | "$OC" "${ARGS[@]}" "$SERVER" >"$LOG" 2>&1 &
OC_PID=$!

# ── 等待隧道建立 ───────────────────────────────────────────────
#
# ⚠️ 判定依据是**系统状态**，不是日志字符串。
#
# 踩过的坑：最初这里 grep `Established tunnel|ESTABLISHED`，但这个
# 字符串在 openconnect 9.21 的二进制里**根本不存在**（用 `grep -a`
# 验证过）。openconnect 建好 tun、跑完 vpnc-script 之后就静默进入
# 主循环，不再打任何日志 —— 于是等待条件永远不满足，**隧道明明通了
# 却被报成「60s 内未建立」**。
#
# 而且靠日志判断本身就是脆的：不同版本措辞不同，翻译catalog 也会变。
# 系统状态（接口拿到地址、路由装好）才是事实。
#
# 判定顺序：
#   1. 日志里解析出服务端分配的地址（X-CSTP-Address）
#   2. 该地址出现在某个 utun 接口上  → 隧道已建立
#   3. 兜底：split-include 路由进了路由表
TARGET_IP="${TARGET_IP:-172.10.13.95}"

echo "── 等待隧道建立（最多 90s）──"
established=0
local_ip=""
for i in $(seq 1 90); do
  if ! kill -0 "$OC_PID" 2>/dev/null; then
    echo
    echo "✗ openconnect 已退出，日志："
    cat "$LOG"
    exit 1
  fi

  # 1) 从日志解析服务端分配的地址
  local_ip="$(sed -n 's/.*X-CSTP-Address: *\([0-9.]*\).*/\1/p' "$LOG" | head -1)"
  : "${local_ip:=}"

  # 2) 该地址是否已配到某个 utun 上
  if [[ -n "$local_ip" ]] && ifconfig 2>/dev/null | grep -A3 "^utun" | grep -q "inet $local_ip"; then
    echo "  [${i}s] utun 已获得地址 $local_ip"
    established=1
    break
  fi

  # 3) 兜底：目标网段路由是否进了路由表
  if [[ "$i" -gt 5 ]] && netstat -rn -f inet 2>/dev/null | grep -qE "^${TARGET_IP%%.*}[\.]"; then
    echo "  [${i}s] 目标网段路由已出现（尚未确认地址，视为已建立）"
    established=1
    break
  fi
  sleep 1
done

echo
if [[ "$established" != "1" ]]; then
  echo "✗ 90s 内未建立隧道，日志："
  cat "$LOG"
  exit 1
fi

echo "✓ 隧道已建立（服务端分配地址 ${local_ip:-未知}）"

echo
echo "── openconnect 日志（末尾 25 行）──"
tail -25 "$LOG"

echo
echo "── 路由表中的 VPN 条目 ──"
netstat -rn -f inet | awk 'NR==1 || /172\.10\.|192\.168\.130\.|utun/'

echo
echo "── utun 接口地址 ──"
ifconfig 2>/dev/null | grep -A4 "^utun" | grep -E "^utun|inet " | head -10 || echo "(无)"

echo
echo "── ping $TARGET_IP ──"
if ping -c 4 -W 2000 "$TARGET_IP"; then
  echo
  echo "✓ $TARGET_IP 可达 —— 隧道验证通过"
  rc=0
else
  echo
  echo "✗ $TARGET_IP 不可达"
  echo "  排查方向："
  echo "    1. 上面的路由表里有没有 172.10.0.0/16 指向 utun？"
  echo "       vpnc-script 在 macOS 上可能装路由失败（它的 echo 输出"
  echo "       'add net ...' 不代表 route add 真成功）"
  echo "    2. 目标主机是否禁 ICMP —— 换个端口试："
  echo "         nc -vz -G 5 $TARGET_IP 22"
  echo "    3. 服务端侧 172.10.13.95 是否允许来自 VPN 网段的访问"
  exit 1
fi

# 顺带确认断开是否正常（TERM → vpnc-script 收尾 → 路由清干净）
echo
echo "── 断开并确认路由已清理 ──"
kill -TERM "$OC_PID" 2>/dev/null || true
for _ in $(seq 1 20); do
  kill -0 "$OC_PID" 2>/dev/null || break
  sleep 0.5
done
OC_PID=""   # 交给 cleanup 收尾 tun 设备
sleep 1
if netstat -rn -f inet | grep -qE "^172\.10\."; then
  echo "⚠ 断开后仍残留 172.10.x.x 路由："
  netstat -rn -f inet | grep -E "^172\.10\."
else
  echo "✓ 路由已清理干净"
fi

exit $rc
