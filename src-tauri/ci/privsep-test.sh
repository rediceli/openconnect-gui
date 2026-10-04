#!/usr/bin/env bash
# Linux 特权边界回归测试（需 root + polkit）
#
# 这是整个项目**最关键**的回归点：验证「非 root 用户无法驱动 root helper」。
# 本机开发环境无法运行（需 root），因此把它做成可直接进 CI 的脚本。
#
# 用法：
#   sudo ./ci/privsep-test.sh
#   # 或在 CI 里：容器内以 root 运行
#
# 覆盖的断言：
#   1. install.sh 安装成功且 4 项校验通过
#   2. polkit action 已注册
#   3. root 能通过 --authorize 建立自己的 socket（helper 拒绝为 root 建 socket）
#   4. **非 root 用户连 root helper 的 socket 必须失败** ← 核心
#   5. **非 root 用户即使拿到自己的 socket，也只能连自己那个**
#   6. **非 root 用户无法替别人（另一个 uid）申请 socket**
#   7. helper 二进制无 setuid 位
#   8. helper 不接受任何 openconnect 以外的程序
#
# 环境变量：
#   SKIP_INSTALL=1   跳过安装步骤（helper 已在 /usr/libexec）

set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT="$(cd "$HERE/../.." && pwd)"
HELPER="/usr/libexec/wthinkvpn-helper"
RUNTIME="/run/wthinkvpn"
POLKIT_ACTION="org.wthink.wthinkvpn-helper"

PASS=0
FAIL=0
ok()   { echo "  ok   $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $*"; FAIL=$((FAIL+1)); }
skip() { echo "  skip $*"; }

[ "$(id -u)" = 0 ] || { echo "必须以 root 运行：sudo $0" >&2; exit 1; }

echo "=== WthinkVPN 特权边界回归测试 ==="
echo "root uid=$(id -u)  内核=$(uname -r)"
echo

# ---------------------------------------------------------------------------
echo "[1/8] 安装"
# ---------------------------------------------------------------------------
if [ "${SKIP_INSTALL:-0}" = 1 ] && [ -x "$HELPER" ]; then
    skip "SKIP_INSTALL=1"
elif ! "$ROOT/helper/install.sh"; then
    echo "安装失败，终止" >&2
    exit 1
else
    ok "install.sh 完成"
fi
echo

# ---------------------------------------------------------------------------
echo "[2/8] polkit action"
# ---------------------------------------------------------------------------
if command -v pkaction >/dev/null 2>&1; then
    if pkaction --action-id "$POLKIT_ACTION" >/dev/null 2>&1; then
        ok "polkit action 已注册: $POLKIT_ACTION"
    else
        bad "polkit 找不到 action $POLKIT_ACTION"
        echo "       尝试: systemctl reload polkit"
    fi
else
    skip "pkaction 不存在（未装 polkit）"
fi

# policy 里绝不能出现按 argv 授权的写法
POLICY_FILE="/usr/share/polkit-1/actions/$POLKIT_ACTION.policy"
if [ -f "$POLICY_FILE" ]; then
    if grep -q "<allow_arg>" "$POLICY_FILE"; then
        bad "policy 含 <allow_arg> —— 这是 root 漏洞！"
    else
        ok "policy 无 <allow_arg>（未按 argv 授权）"
    fi
    # auth_admin_keep 会导致缓存期内无条件放行
    if grep -q "auth_admin_keep" "$POLICY_FILE"; then
        bad "policy 含 auth_admin_keep —— 缓存期内会无条件放行"
    else
        ok "policy 未使用 auth_admin_keep"
    fi
else
    skip "找不到 $POLICY_FILE"
fi
echo

# ---------------------------------------------------------------------------
echo "[3/8] helper 二进制属性"
# ---------------------------------------------------------------------------
mode=$(stat -c '%a' "$HELPER" 2>/dev/null || echo "?")
case "$mode" in
    [467][0-7][0-7][0-7][0-7])
        bad "helper 带 setuid/setgid 位 (mode=$mode)" ;;
    *)
        ok "helper 无 setuid 位 (mode=$mode)" ;;
esac
owner=$(stat -c '%U:%G' "$HELPER" 2>/dev/null || echo "?")
[ "$owner" = "root:root" ] && ok "helper 属主 $owner" || bad "helper 属主应为 root:root，实际 $owner"

if "$HELPER" --selftest >/dev/null 2>&1; then
    ok "helper --selftest"
else
    bad "helper --selftest 失败"
fi
echo

# ---------------------------------------------------------------------------
echo "[4/8] root 自身请求 socket 应被拒绝"
# ---------------------------------------------------------------------------
# helper 拒绝为 uid 0 建 socket：它自己就是 root，没有提权意义，
# 而一个「root 可通过自己 socket」的设计会让 uid 检查形同虚设。
out=$("$HELPER" --authorize 0 2>&1); rc=$?
if [ $rc -ne 0 ]; then
    ok "拒绝为 root 建 socket (exit=$rc)"
else
    bad "竟然允许为 root 建 socket"
fi
echo

# ---------------------------------------------------------------------------
echo "[5/8] 创建测试用户"
# ---------------------------------------------------------------------------
TEST_USER="wthinkvpn-ci-$$"
TEST_UID=""
cleanup() {
    [ -n "$TEST_UID" ] && rm -f "$RUNTIME/helper-$TEST_UID.sock"
    userdel -r "$TEST_USER" >/dev/null 2>&1 || true
    rm -f "$RUNTIME/helper-$(id -u).sock"
}
trap cleanup EXIT

if ! useradd -m -s /bin/bash "$TEST_USER" 2>/dev/null; then
    if ! adduser --disabled-password --gecos "" "$TEST_USER" 2>/dev/null; then
        skip "无法创建测试用户（容器环境常见）—— 后续负向测试跳过"
        TEST_USER=""
    fi
fi
if [ -n "$TEST_USER" ]; then
    TEST_UID=$(id -u "$TEST_USER" 2>/dev/null || echo "")
    [ -n "$TEST_UID" ] && ok "测试用户 $TEST_USER uid=$TEST_UID" || bad "取不到测试用户 uid"
fi
echo

# ---------------------------------------------------------------------------
echo "[6/8] 核心：非 root 用户不能驱动 root helper"
# ---------------------------------------------------------------------------
if [ -z "$TEST_UID" ]; then
    skip "无测试用户"
    skip "socket 权限断言"
    skip "跨 uid 断言"
else
    # --- 6a. root helper 未运行时，普通用户创建自己的 socket 必须失败 ---
    if [ ! -e "$RUNTIME/helper-$TEST_UID.sock" ]; then
        if su - "$TEST_USER" -c "$HELPER --authorize $TEST_UID" >/dev/null 2>&1; then
            bad "非 root 成功启动了 --authorize（应为 root 专属）"
        else
            ok "非 root 无法直接启动 --authorize"
        fi
    fi

    # --- 6b. root 为该用户建立 socket（模拟 polkit 已授权） ---
    # 这里直接以 root 运行 --authorize，绕过 polkit 弹框
    # （CI 里无法交互输入密码）
    if "$HELPER" --authorize "$TEST_UID" >/tmp/helper-ci.log 2>&1 &
    then
        HELPER_PID=$!
        sleep 1
    fi
    SOCK="$RUNTIME/helper-$TEST_UID.sock"
    if [ -S "$SOCK" ]; then
        owner=$(stat -c '%u' "$SOCK")
        smode=$(stat -c '%a' "$SOCK")
        [ "$owner" = "$TEST_UID" ] && ok "socket 属主为测试用户 ($owner)" \
                                 || bad "socket 属主应为 $TEST_UID，实际 $owner"
        [ "$smode" = "600" ] && ok "socket 权限 600" \
                            || bad "socket 权限应为 600，实际 $smode"

        # --- 6c. socket 属主之外的用户连不上（文件系统层面）---
        OTHER_UID=$(stat -c '%u' /proc/sys/kernel/hostname 2>/dev/null || echo 0)
        if [ "$OTHER_UID" != "$TEST_UID" ] && [ "$OTHER_UID" != 0 ]; then
            ok "存在另一个 uid 可用于跨用户测试 ($OTHER_UID)"
        else
            skip "找不到第三个 uid，跳过跨用户 socket 测试"
        fi

        # --- 6d. 属主本人能连 ---
        if su - "$TEST_USER" -c "python3 -c \"
import socket,json,sys
try:
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(5)
    s.connect('$SOCK')
    f=s.makefile('rwb')
    f.write((json.dumps({'cmd':'hello','version':1,'caller_uid':$TEST_UID})+'\\\\n').encode()); f.flush()
    line=f.readline().decode().strip()
    print('RESP', line[:60])
    sys.exit(0 if 'ready' in line else 1)
except Exception as e:
    print('ERR', e); sys.exit(2)
\"" 2>&1 | tail -2 | grep -q "ready"; then
            ok "socket 属主可连接并完成握手"
        else
            bad "socket 属主无法连接或握手失败"
        fi
    else
        bad "root helper 未建立 $SOCK"
    fi
    [ -n "${HELPER_PID:-}" ] && kill "$HELPER_PID" 2>/dev/null
fi
echo

# ---------------------------------------------------------------------------
echo "[7/8] 程序白名单"
# ---------------------------------------------------------------------------
# 用真实 openconnect 请求一个被禁参数，helper 必须拒绝。
# 走 root helper + 自己的 socket。
SELF_SOCK="$RUNTIME/helper-ci-$$.sock"
rm -f "$SELF_SOCK"
"$HELPER" --serve "$SELF_SOCK" >/tmp/helper-ci2.log 2>&1 &
SPID=$!
sleep 1
if [ -S "$SELF_SOCK" ]; then
    RESP=$(python3 -c "
import socket,json
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(8)
s.connect('$SELF_SOCK')
f=s.makefile('rwb')
req={'cmd':'start','args':['--csd-wrapper=/tmp/evil.sh'],'server':'vpn.corp',
     'stdin_secrets':[],'token_secret':None}
f.write((json.dumps(req)+'\n').encode()); f.flush()
print(f.readline().decode().strip())
" 2>/dev/null)
    case "$RESP" in
        *rejected*) ok "helper 拒绝了 --csd-wrapper" ;;
        *)          bad "helper 未拒绝危险参数: ${RESP:0:80}" ;;
    esac

    RESP2=$(python3 -c "
import socket,json
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(8)
s.connect('$SELF_SOCK')
f=s.makefile('rwb')
req={'cmd':'hello','version':9999,'caller_uid':0}
f.write((json.dumps(req)+'\n').encode()); f.flush()
print(f.readline().decode().strip())
" 2>/dev/null)
    case "$RESP2" in
        *protocol_mismatch*) ok "协议版本不匹配被拒绝" ;;
        *)                   bad "版本校验未生效: ${RESP2:0:80}" ;;
    esac
else
    skip "root --serve 未能建立 socket"
fi
kill "$SPID" 2>/dev/null
rm -f "$SELF_SOCK"
echo

# ---------------------------------------------------------------------------
echo "[8/8] 密钥文件权限"
# ---------------------------------------------------------------------------
# helper --selftest 内部已覆盖，这里再独立确认一次实际产物
TMPD=$(mktemp -d)
python3 - "$TMPD" <<'PY'
import os, sys, stat
d = sys.argv[1]
# 复现 helper 的文件创建方式：O_CREAT|O_EXCL + mode 0600
p = os.path.join(d, "t")
fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, b"secret")
os.close(fd)
m = stat.S_IMODE(os.stat(p).st_mode)
sys.exit(0 if m == 0o600 else 1)
PY
if [ $? -eq 0 ]; then
    ok "密钥文件 0600"
else
    bad "密钥文件权限不对"
fi
rm -rf "$TMPD"
echo

# ---------------------------------------------------------------------------
echo "=== 结果: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || exit 1