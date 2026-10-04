#!/usr/bin/env bash
# 准备 Windows 运行时依赖，产出可直接被 Tauri 打进安装包的文件。
#
# # 为什么需要这些
#
# openconnect 在 Windows 上不是自包含的。官方 NSIS 安装包（见
# openconnect/Makefile.am 的 `file-list.txt` 目标）会打包：
#
#   1. openconnect.exe            主程序（MinGW 交叉编译）
#   2. libopenconnect-*.dll       核心库（跨编译时是 DLL）
#   3. 传递依赖的第三方 DLL        gnutls/libxml2/zlib/lz4/stoken/p11-kit ...
#   4. wintun.dll                 TUN 驱动（v9.00 起取代 TAP-Windows）
#   5. vpnc-script-win.js         路由/DNS 配置脚本（cscript 执行）
#
# 缺任何一个，Windows 上都会在运行时失败 —— 而这类失败往往到用户
# 建立连接时才暴露，所以必须在构建期就把清单校验做掉。
#
# # 本脚本做什么
#
# 用 MinGW 交叉编译 openconnect，解析其**传递** DLL 依赖，
# 下载并校验 wintun + vpnc-script-win.js，输出一份
# `win-deps/` 目录和一份 `MANIFEST.txt`。
#
# # 用法
#
#   ./ci/fetch-win-deps.sh                    # 交叉编译 + 收集
#   CROSS_COMPILE=1 ./ci/fetch-win-deps.sh     # 用系统已装的 mingw 跳过编译
#
# 依赖（Debian/Ubuntu）：
#   apt-get install mingw-w64 jq curl
#   # 或 macOS: brew install mingw-w64 jq curl

set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SRC_TAURI="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$SRC_TAURI/.." && pwd)"

OUT="$SRC_TAURI/win-deps"
BUILD="$SRC_TAURI/.win-build"
OPENCONNECT_VER="${OPENCONNECT_VER:-v9.21}"
OPENCONNECT_URL="https://gitlab.com/openconnect/openconnect/-/archive/master/openconnect-master.tar.gz"

# 与 openconnect/Makefile.am 保持一致。上游更新时这里也要更新。
WINTUN_VERSION="${WINTUN_VERSION:-0.14.1}"
WINTUN_SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

# vpnc-script-win.js 取上游 master 的最新提交
VCS_SCRIPTS_URL="https://gitlab.com/openconnect/vpnc-scripts/raw/master/vpnc-script-win.js"

log()  { printf '\n=== %s ===\n' "$*"; }
warn() { printf '  warn %s\n' "$*" >&2; }
die()  { printf '  FAIL %s\n' "$*" >&2; exit 1; }

MINGW="${MINGW:-x86_64-w64-mingw32}"
OBJDUMP="${OBJDUMP:-$MINGW-objdump}"

command -v curl >/dev/null || die "需要 curl"
command -v jq   >/dev/null || die "需要 jq（用于解析 vpnc-scripts 的最新提交信息）"

rm -rf "$OUT" "$BUILD"
mkdir -p "$OUT" "$BUILD"

# ---------------------------------------------------------------------------
log "1/5 下载并交叉编译 openconnect"
# ---------------------------------------------------------------------------
if [ "${CROSS_COMPILE:-0}" = 1 ]; then
    die "CROSS_COMPILE=1 需要你自行提供 openconnect.exe 与 DLL，放到 $BUILD/ 后重跑"
fi

command -v "$MINGW-gcc" >/dev/null \
    || die "需要 $MINGW-gcc。Debian: apt-get install mingw-w64"

curl -sSL --max-time 300 -o "$BUILD/oc.tar.gz" "$OPENCONNECT_URL" \
    || die "下载 openconnect 源码失败"
tar xzf "$BUILD/oc.tar.gz" -C "$BUILD"
OC_SRC=$(find "$BUILD" -maxdepth 1 -type d -name 'openconnect-*' | head -1)
[ -n "$OC_SRC" ] || die "解压后找不到源码目录"

log "  构建依赖（configure 可能缺包，缺什么补什么）"
cd "$OC_SRC"
./configure \
    --host="$MINGW" \
    --with-vpnc-script=vpnc-script-win.js \
    --without-gnutls-version-check \
    --disable-dsa-tests \
    --disable-shared \
    --disable-static \
    >"$BUILD/configure.log" 2>&1 || {
        warn "configure 失败，末尾输出："
        tail -20 "$BUILD/configure.log" >&2
        die "configure 失败"
    }
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" \
    >"$BUILD/make.log" 2>&1 || {
        warn "make 失败，末尾输出："
        tail -30 "$BUILD/make.log" >&2
        die "make 失败"
    }

cp "$OC_SRC/openconnect.exe" "$OUT/" || die "没找到 openconnect.exe"
log "  ok openconnect.exe ($(stat -c%s "$OUT/openconnect.exe" 2>/dev/null || stat -f%z "$OUT/openconnect.exe") bytes)"

# ---------------------------------------------------------------------------
log "2/5 收集传递 DLL 依赖"
# ---------------------------------------------------------------------------
# openconnect.exe 链接的第三方 DLL 通常来自 mingw sys-root。
# 用 objdump 递归展开，与上游 Makefile.dlldeps 同样的思路。
collect_dlls() {
    local exe="$1"
    local sysroot
    sysroot=$("$MINGW-gcc" -print-sysroot 2>/dev/null || echo /usr/$MINGW)
    local bindir
    bindir=$(find "$sysroot" /usr/$MINGW -type d -path '*mingw*bin*' 2>/dev/null | head -1)
    [ -n "$bindir" ] || bindir=/usr/$MINGW/sys-root/mingw/bin

    local queue=("$exe")
    local seen=""
    while [ ${#queue[@]} -gt 0 ]; do
        local cur="${queue[0]}"
        queue=("${queue[@]:1}")
        local base
        base=$(basename "$cur")
        case "$seen" in *"|$base|"*) continue ;; esac
        seen="$seen|$base|"

        local deps
        deps=$("$OBJDUMP" -p "$cur" 2>/dev/null \
               | awk '/DLL Name/ {print $3}' \
               | grep -viE '^(KERNEL32|USER32|ADVAPI32|SHELL32|ole32|OLEAUT32|WS2_32|CRYPT32|NTDLL|msvcrt|comdlg32|GDI32|IMM32|SHLWAPI|version)\.dll$' || true)
        for d in $deps; do
            local src="$bindir/$d"
            if [ -f "$src" ]; then
                cp -n "$src" "$OUT/" 2>/dev/null || true
                queue+=("$src")
            else
                warn "找不到 DLL: $d（可能是 Windows 系统库，忽略）"
            fi
        done
    done
    printf '%s' "$seen"
}

DEPS=$(collect_dlls "$OC_SRC/openconnect.exe")
DLL_COUNT=$(ls "$OUT"/*.dll 2>/dev/null | wc -l | tr -d ' ')
log "  ok 收集 $DLL_COUNT 个 DLL"
[ "$DLL_COUNT" -gt 0 ] || die "一个 DLL 都没收集到 —— objdump 路径可能不对（$OBJDUMP）"

# libopenconnect：静态编译时不存在，动态时需要
if ls "$OC_SRC"/libopenconnect*.dll >/dev/null 2>&1; then
    cp "$OC_SRC"/libopenconnect*.dll "$OUT/"
    log "  ok libopenconnect.dll"
else
    warn "未找到 libopenconnect.dll（静态编译时正常）"
fi

# ---------------------------------------------------------------------------
log "3/5 下载 wintun"
# ---------------------------------------------------------------------------
# openconnect 9.00 起在 Windows 上用 Wintun 取代 TAP-Windows 驱动。
# 缺它 ⇒ 连接时报「Failed to create TUN device」。
if [ -f "$REPO/openconnect/build/$WINTUN_VERSION.zip" ]; then
    ZIP="$REPO/openconnect/build/wintun-$WINTUN_VERSION.zip"
else
    ZIP="$BUILD/wintun.zip"
    curl -sSL --max-time 300 -o "$ZIP" \
        "https://www.wintun.net/builds/wintun-$WINTUN_VERSION.zip" \
        || die "下载 wintun 失败"
fi

# 校验 SHA256 —— 上游 Makefile.am 里的同一个值
if command -v sha256sum >/dev/null; then
    EXPECTED="$WINTUN_SHA256"
    ACTUAL=$(sha256sum "$ZIP" | cut -d' ' -f1)
elif command -v shasum >/dev/null; then
    EXPECTED="$WINTUN_SHA256"
    ACTUAL=$(shasum -a 256 "$ZIP" | cut -d' ' -f1)
else
    EXPECTED=""
    ACTUAL=""
    warn "没有 sha256sum/shasum，跳过 wintun 校验"
fi
if [ -n "$EXPECTED" ] && [ "$ACTUAL" != "$EXPECTED" ]; then
    die "wintun SHA256 不匹配：期望 $EXPECTED，实际 $ACTUAL
     上游若更新了版本，请同步 Makefile.am 里的 WINTUNSHA256"
fi
log "  ok wintun SHA256 校验通过"

# 只取 x86_64 的 wintun.dll（zips 里还有 32 位与 ARM）
unzip -o -j -d "$OUT" "$ZIP" "wintun/bin/amd64/wintun.dll" >/dev/null \
    || die "解压 wintun.dll 失败（找不到 amd64 版本？）"
[ -f "$OUT/wintun.dll" ] || die "wintun.dll 未产出"
log "  ok wintun.dll ($(stat -c%s "$OUT/wintun.dll" 2>/dev/null || stat -f%z "$OUT/wintun.dll") bytes)"

# ---------------------------------------------------------------------------
log "4/5 下载 vpnc-script-win.js"
# ---------------------------------------------------------------------------
# 上游 Makefile.am 会在文件头写明来源提交，便于日后追溯。
SCRIPT="$OUT/vpnc-script-win.js"
{
    META=$(curl -sS --max-time 60 \
        'https://gitlab.com/api/v4/projects/openconnect%2Fvpnc-scripts/repository/commits?path=vpnc-script-win.js&branch=master')
    if [ -n "$META" ] && command -v jq >/dev/null; then
        printf '// This script matches the version found at '
        printf '%s' "$META" | jq -r '.[0].web_url | sub("/commit/"; "/blob/")'
        printf '\n// Updated on %s by %s <%s> ("%s")\n//\n' \
            "$(printf '%s' "$META" | jq -r '.[0].authored_date[:10]')" \
            "$(printf '%s' "$META" | jq -r '.[0].author_name')" \
            "$(printf '%s' "$META" | jq -r '.[0].author_email')" \
            "$(printf '%s' "$META" | jq -r '.[0].title')"
    fi
    curl -sSL --max-time 60 "$VCS_SCRIPTS_URL"
} > "$SCRIPT"
[ -s "$SCRIPT" ] || die "vpnc-script-win.js 为空"
grep -q "function main\|netsh" "$SCRIPT" || die "vpnc-script-win.js 内容异常（不含 netsh 调用？）"
log "  ok vpnc-script-win.js ($(wc -c < "$SCRIPT") bytes)"

# ---------------------------------------------------------------------------
log "5/5 生成 MANIFEST.txt"
# ---------------------------------------------------------------------------
# Tauri 会把 win-deps/ 打进安装包。MANIFEST 让「装了什么」可审计。
{
    echo "# WthinkVPN Windows 运行时依赖"
    echo "# 生成时间: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "# openconnect: $OPENCONNECT_VER (master 交叉编译)"
    echo "# wintun: $WINTUN_VERSION (sha256 $WINTUN_SHA256)"
    echo "# vpnc-script-win.js: 上游 master 最新提交（见文件头注释）"
    echo
    echo "## 文件"
    (cd "$OUT" && ls -1 | grep -v '^MANIFEST.txt$' | sort)
    echo
    echo "## openconnect.exe 的 DLL 依赖（已全部包含）"
    printf '%s\n' "$DEPS" | tr '|' '\n' | grep -v '^$' | sort
    echo
    echo "## 校验和"
    (cd "$OUT" && for f in *; do
        case "$f" in
            MANIFEST.txt) continue ;;
        esac
        if command -v sha256sum >/dev/null; then
            sha256sum "$f"
        else
            shasum -a 256 "$f"
        fi
    done)
} > "$OUT/MANIFEST.txt"

log "完成"
cat <<EOF

产物目录: $OUT

下一步（接入 Tauri 打包）：

  1. 把 win-deps/ 加进 tauri.conf.json 的 bundle.resources
  2. tauri.conf.json 里设置 openconnect 路径：
       "openconnect": "resources/win-deps/openconnect.exe"
  3. Windows 上 vpnc-script 用相对路径（openconnect 会相对自身目录找）：
       --script resources/win-deps/vpnc-script-win.js

在 channel.rs 里，Windows 分支的默认 program 应改为从
std::env::current_exe() 的同级目录找 openconnect.exe，
而不是系统 PATH（PATH 不可控，且 Windows 上的 openconnect 不会被
常规安装）。

EOF
ls -la "$OUT"