#!/usr/bin/env bash
# 构建、签名、嵌入 macOS 特权助手
#
# 产出（嵌进 .app bundle）：
#   Contents/MacOS/wthinkvpn                    GUI
#   Contents/Library/LaunchDaemons/io.wthink.wthinkvpn.helper.plist
#   Contents/Library/HelperTools/wthinkvpn-helper
#   Contents/MacOS/macosctl                     XPC 客户端 CLI
#
# # 为什么必须签名，且 App 与 Helper 要同一 Team ID
#
# 1. privileged XPC 要求两者同 Team ID —— helper 的调用方校验就是比对
#    Team ID 与 bundle id
# 2. Team ID 由构建期注入（Info.plist 的 WthinkVPNTeamID），
#    这是 helper 判断「谁有资格驱动我」的唯一依据
# 3. 两者都要 Hardened Runtime + 公证，否则 Gatekeeper 会拦
#
# # 用法
#
#   Scripts/sign-macos.sh --team-id ABCDE12345
#   Scripts/sign-macos.sh --team-id ABCDE12345 --notarize --apple-id ... \
#       --team-id ... --password @keychain:WTHINK_APP_SPECIFIC_PW
#
# # 关键顺序（错一步就会失败）
#
# 1. 先签 Helper（它嵌在 App 的 Resources 里）
# 2. 再签 App 整体（内含已签的 Helper）
# 3. 最后公证（notarize）—— 必须在两步签名都完成后

set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SRC_TAURI="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$SRC_TAURI/.." && pwd)"
HELPER_PKG="$SRC_TAURI/macos-helper"

APP_NAME="WthinkVPN"
BUNDLE_ID="com.wthink.wthinkvpn"
HELPER_ID="io.wthink.wthinkvpn.helper"
DAEMON_PLIST="io.wthink.wthinkvpn.helper"

TEAM_ID=""
DO_NOTARIZE=1
APPLE_ID=""
APP_PASSWORD=""
PROFILE="default"

log()  { printf '\n=== %s ===\n' "$*"; }
warn() { printf '  warn %s\n' "$*" >&2; }
die()  { printf '  FAIL %s\n' "$*" >&2; exit 1; }

for a in "$@"; do
    case "$a" in
        --team-id)      shift; TEAM_ID="$1" ;;
        --apple-id)     shift; APPLE_ID="$1" ;;
        --password)     shift; APP_PASSWORD="$1" ;;
        --profile)      shift; PROFILE="$1" ;;
        --notarize)     DO_NOTARIZE=0 ;;
        -h|--help)      sed -n '2,28p' "$0"; exit 0 ;;
        *) echo "未知参数: $a" >&2; exit 2 ;;
    esac
    shift || true
done

[ -n "$TEAM_ID" ] || die "必须提供 --team-id（可在 Keychain Access → 我的证书 里看到）"
command -v codesign >/dev/null || die "需要 codesign（xcode-select --install）"

# ---------------------------------------------------------------------------
log "1/6 构建 Swift helper"
# ---------------------------------------------------------------------------
command -v swift >/dev/null || die "需要 Swift（xcode-select --install）"
cd "$HELPER_PKG"
swift build -c release
HELPER_BIN="$(swift build -c release --show-bin-path)/wthinkvpn-helper"
CTL_BIN="$(swift build -c release --show-bin-path)/macosctl"
[ -x "$HELPER_BIN" ] || die "helper 未产出"
[ -x "$CTL_BIN" ]   || die "macosctl 未产出"
echo "  helper: $HELPER_BIN"
echo "  macosctl: $CTL_BIN"

# ---------------------------------------------------------------------------
log "2/6 注入 Team ID"
# ---------------------------------------------------------------------------
# ⚠️ **不能用 `-sectcreate __TEXT __info_plist`**：
# SwiftPM 的 `linkerSettings.unsafeFlags` 传给的是 **swiftc** 而不是 `ld`，
# 因此会被拒：`error: unknown argument: '-sectcreate'`。
# 用 SwiftPM build plugin 可以做对，但复杂度不划算。
#
# 实际做法：把 Team ID 写进 **launchd plist 的 EnvironmentVariables**。
# launchd 加载 daemon 时会设置这些环境变量，helper 从中读取。
# 好处：daemon 本来就由 launchd 加载，机制天然匹配；
#       排查时 `launchctl print system/<label>` 能直接看到。
PLIST_TEMPLATE="$HELPER_PKG/Sources/SharedProtocol/Resources/$DAEMON_PLIST.plist"
[ -f "$PLIST_TEMPLATE" ] || die "找不到 plist 模板 $PLIST_TEMPLATE"

PLIST_OUT="$(mktemp -d)/$DAEMON_PLIST.plist"
sed "s/__TEAM_ID__/$TEAM_ID/g" "$PLIST_TEMPLATE" > "$PLIST_OUT"

# 校验替换生效
if ! /usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:WTHINKVPN_TEAM_ID" "$PLIST_OUT" 2>/dev/null \
    | grep -q "^$TEAM_ID$"; then
    die "Team ID 注入失败 —— helper 会拒绝所有连接"
fi
echo "  plist EnvironmentVariables:WTHINKVPN_TEAM_ID = $TEAM_ID ✓"

# ---------------------------------------------------------------------------
log "3/6 构建 GUI"
# ---------------------------------------------------------------------------
cd "$REPO"
cargo tauri build --bundles app 2>&1 | tail -3
APP="$SRC_TAURI/target/release/bundle/macos/$APP_NAME.app"
[ -d "$APP" ] || die "找不到 $APP"
echo "  $APP"

# ---------------------------------------------------------------------------
log "4/6 嵌入 helper 与 daemon plist"
# ---------------------------------------------------------------------------
# launchd 的搜索路径是固定的：~/Library/LaunchAgents、
# /Library/LaunchAgents、/Library/LaunchDaemons，以及
# **App bundle 内的 Contents/Library/LaunchDaemons**。
# SMAppService 正是用后者，所以位置不能改。
mkdir -p "$APP/Contents/Library/LaunchDaemons"
mkdir -p "$APP/Contents/Library/HelperTools"
# 用注入过 Team ID 的那份
cp "$PLIST_OUT" "$APP/Contents/Library/LaunchDaemons/$DAEMON_PLIST.plist"
cp "$HELPER_BIN" "$APP/Contents/Library/HelperTools/wthinkvpn-helper"
cp "$CTL_BIN"   "$APP/Contents/MacOS/macosctl"
chmod 755 "$APP/Contents/Library/HelperTools/wthinkvpn-helper"
chmod 755 "$APP/Contents/MacOS/macosctl"

# GUI 侧的 Info.plist 也要 Team ID（XPCClient 反向校验 helper 时用）
/usr/libexec/PlistBuddy -c "Set :WthinkVPNTeamID $TEAM_ID" "$APP/Contents/Info.plist" \
    2>/dev/null \
  || /usr/libexec/PlistBuddy -c "Add :WthinkVPNTeamID string $TEAM_ID" "$APP/Contents/Info.plist"

# GUI 从 Contents/MacOS/macosctl 找客户端（channel.rs 的查找顺序之一）
echo "  Contents/Library/LaunchDaemons/$DAEMON_PLIST.plist"
echo "  Contents/Library/HelperTools/wthinkvpn-helper"
echo "  Contents/MacOS/macosctl"

# ---------------------------------------------------------------------------
log "5/6 签名"
# ---------------------------------------------------------------------------
# ⚠️ 顺序：先 Helper，后 App。App 签名时会连同 Contents 一并封签，
#    之后再动 Helper 会让 App 的签名失效（"code has been modified"）。
sign() {
    local target="$1"
    # --options runtime = Hardened Runtime（App Store / 公证必需）
    # --timestamp       = 时间戳公证签名，过期后仍有效
    codesign --force --sign "$TEAM_ID" \
        --options runtime --timestamp \
        --generate-entitlement-der \
        "$target"
}

sign "$APP/Contents/Library/HelperTools/wthinkvpn-helper"
echo "  signed helper"
sign "$APP/Contents/MacOS/macosctl"
echo "  signed macosctl"
sign "$APP"
echo "  signed $APP_NAME.app"

# ---------------------------------------------------------------------------
log "6/6 校验"
# ---------------------------------------------------------------------------
fail=0

# 1. 签名有效
if codesign --verify --deep --strict "$APP" 2>/dev/null; then
    echo "  ok   签名有效"
else
    echo "  FAIL 签名校验失败"
    codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | head -5
    fail=1
fi

# 2. Hardened Runtime 已开
if codesign -d --verbose=2 "$APP" 2>&1 | grep -q "flags=.*runtime"; then
    echo "  ok   Hardened Runtime"
else
    echo "  FAIL Hardened Runtime 未开启"
    fail=1
fi

# 3. helper 与 App 的 Team ID 一致
app_team=$(codesign -dv --verbose=4 "$APP" 2>&1 | sed -n 's/^TeamIdentifier=//p')
helper_team=$(codesign -dv --verbose=4 "$APP/Contents/Library/HelperTools/wthinkvpn-helper" 2>&1 \
    | sed -n 's/^TeamIdentifier=//p')
if [ -n "$app_team" ] && [ "$app_team" = "$helper_team" ]; then
    echo "  ok   Team ID 一致 ($app_team)"
else
    echo "  FAIL Team ID 不一致: app=$app_team helper=$helper_team"
    fail=1
fi

# 4. helper 与 App 的 bundle id 正确
helper_id=$(codesign -dv --verbose=4 "$APP/Contents/Library/HelperTools/wthinkvpn-helper" 2>&1 \
    | sed -n 's/^Identifier=//p')
app_id=$(codesign -dv --verbose=4 "$APP" 2>&1 | sed -n 's/^Identifier=//p')
[ "$helper_id" = "$HELPER_ID" ] \
    && echo "  ok   helper bundle id = $helper_id" \
    || { echo "  FAIL helper bundle id 应为 $HELPER_ID，实际 $helper_id"; fail=1; }
[ "$app_id" = "$BUNDLE_ID" ] \
    && echo "  ok   app bundle id = $app_id" \
    || { echo "  FAIL app bundle id 应为 $BUNDLE_ID，实际 $app_id"; fail=1; }

# 5. daemon plist 的 Mach service 与代码一致
PLIST_IN_APP="$APP/Contents/Library/LaunchDaemons/$DAEMON_PLIST.plist"
mach=$(/usr/libexec/PlistBuddy -c "Print :MachServices:$DAEMON_PLIST" "$PLIST_IN_APP" 2>/dev/null || echo "")
[ "$mach" = "true" ] \
    && echo "  ok   plist 声明了 MachServices" \
    || { echo "  FAIL plist 缺少 MachServices:$DAEMON_PLIST"; fail=1; }

# 6. plist 里的 Team ID 确实被替换掉了占位符
plist_team=$(/usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:WTHINKVPN_TEAM_ID" \
    "$PLIST_IN_APP" 2>/dev/null || echo "")
[ "$plist_team" = "$TEAM_ID" ] \
    && echo "  ok   plist Team ID 已注入 ($plist_team)" \
    || { echo "  FAIL plist Team ID 应为 $TEAM_ID，实际 '$plist_team'"; fail=1; }

# 7. plist 里不能残留占位符（否则 helper 拿到 "__TEAM_ID__" 会拒绝所有人）
if grep -q "__TEAM_ID__" "$PLIST_IN_APP"; then
    echo "  FAIL plist 残留 __TEAM_ID__ 占位符"
    fail=1
else
    echo "  ok   plist 无未替换占位符"
fi

# 8. helper 无 setuid 位（提权走 XPC，不靠 setuid）
hmode=$(stat -f '%Lp' "$APP/Contents/Library/HelperTools/wthinkvpn-helper")
case "$hmode" in
    [467][0-7][0-7][0-7][0-7])
        echo "  FAIL helper 带 setuid 位 (mode=$hmode)"; fail=1 ;;
    *)
        echo "  ok   helper 无 setuid 位 (mode=$hmode)" ;;
esac

echo
if [ "$fail" != 0 ]; then
    echo "校验未通过。" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
if [ "$DO_NOTARIZE" = 0 ]; then
    log "公证（notarize）"
    [ -n "$APPLE_ID" ] || die "--notarize 需要 --apple-id"
    [ -n "$APP_PASSWORD" ] || die "--notarize 需要 --password"

    ZIP="$(mktemp -d)/$APP_NAME.zip"
    ditto -c -k --keepParent "$APP" "$ZIP"

    xcrun notarytool submit "$ZIP" \
        --apple-id "$APPLE_ID" \
        --password "$APP_PASSWORD" \
        --team-id "$TEAM_ID" \
        --wait

    xcrun stapler staple "$APP"
    codesign --force --sign "$TEAM_ID" --options runtime --timestamp "$APP"
    echo "  公证 + 装订完成"
else
    cat <<EOF
已完成签名，但**未公证**。

本地运行不需要公证；分发给其他机器则必须：
    Scripts/sign-macos.sh --team-id $TEAM_ID --notarize \\
        --apple-id you@example.com --password @keychain:WTHINK_APP_SPECIFIC_PW

公证要求 App Store Connect 上有 App ID，且 Team ID 一致。
EOF
fi

cat <<EOF

安装：
    ditto "$APP" /Applications/ && open /Applications/$APP_NAME.app

首次使用特权助手：
    1. GUI 点「提权启动」
    2. 打开「系统设置 → 通用 → 登录项」
    3. 打开 WthinkVPN 的开关  ← SMAppService 不弹密码框，这一步必须用户手动做

验证：
    /Applications/$APP_NAME.app/Contents/MacOS/macosctl status
EOF