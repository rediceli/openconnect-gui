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
warn_root_owned_target() {
  local t="$1/target"
  [[ -d "$t" ]] || return 0
  if [[ ! -O "$t" ]]; then
    printf '\033[1;33m注意:\033[0m %s 属于 %s —— 之后普通用户跑 cargo build 会因权限失败。\n' \
      "$t" "$(stat -f '%Su' "$t")" >&2
    printf '      修复：sudo chown -R "$(id -un)":staff %s\n' "$t" >&2
  fi
}
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
#
# ⚠️ **sudo 会重置 PATH**，`~/.cargo/bin` 因此不在里面。实测踩过：
#    `sudo ./install-macos-daemon.sh` 直接报 `cargo: command not found`。
#
# 而且不能简单地用 `$HOME/.cargo/bin` —— sudo 下 `$HOME` 是 **root 的**
# 家目录，不是调用者的。所以要从 `$SUDO_USER` 反查它的家目录。
#
# 策略：**优先用已构建好的产物**，必要时才现场构建。
#
# ⚠️ 两个实测踩到的坑：
#
# 1. `sudo` 重置 PATH，`~/.cargo/bin` 不在里面 →
#    `cargo: command not found`。
#    且不能用 $HOME 兜底 —— sudo 下它是 **root 的** 家目录，
#    必须从 `$SUDO_USER` 反查。
#
# 2. 即便用绝对路径找到 cargo，以 root 运行时 rustup 又会去找
#    `$RUSTUP_HOME`（默认 `$HOME/.rustup` = `/var/root/.rustup`），
#    同样失败。所以构建时必须一并把 CARGO_HOME / RUSTUP_HOME
#    指回调用者的家目录。
#
# ⚠️ **更重要的：尽量不要以 root 构建。** 那会让
# `helper/target/` 变成 root 所有，之后普通用户再跑
# `cargo build` 会因权限失败。所以推荐流程是：
#
#     cargo build --release --manifest-path src-tauri/helper/Cargo.toml   # 普通用户
#     sudo src-tauri/Scripts/install-macos-daemon.sh                        # 再 sudo 安装
#
BIN="$SRC/target/release/oc-gui-helper"

invoking_home() {
  local h=""
  if [[ -n "${SUDO_USER:-}" ]]; then
    # macOS 没有 getent；两者都试只为兼容 Linux
    h="$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null |
         awk '/NFSHomeDirectory:/{print $2}')"
    [[ -z "$h" ]] && h="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)"
  fi
  printf '%s' "${h:-$HOME}"
}

find_cargo() {
  local c h
  if command -v cargo >/dev/null 2>&1; then command -v cargo; return 0; fi
  h="$(invoking_home)"
  for c in "$h/.cargo/bin/cargo" \
           /opt/homebrew/bin/cargo \
           /usr/local/bin/cargo \
           "$h"/.rustup/toolchains/*/bin/cargo; do
    [[ -x "$c" ]] && { printf '%s\n' "$c"; return 0; }
  done
  return 1
}

if [[ -x "$BIN" ]]; then
  log "使用已构建好的 helper：$BIN"
  log "  （如需重新构建，请以普通用户运行："
  log "   cargo build --release --manifest-path src-tauri/helper/Cargo.toml ）"
elif CARGO_BIN="$(find_cargo)"; then
  H="$(invoking_home)"
  log "未找到预构建产物，现场构建 — $CARGO_BIN"
  # rustup / cargo 都按 $HOME 找自己的目录，必须指回调用者
  export CARGO_HOME="${CARGO_HOME:-$H/.cargo}"
  export RUSTUP_HOME="${RUSTUP_HOME:-$H/.rustup}"
  ( cd "$SRC" && "$CARGO_BIN" build --release ) \
    || die "构建失败（注意：建议改为先以普通用户构建，再 sudo 安装）"
  warn_root_owned_target "$SRC"
else
  die "找不到已构建的 helper，也没有 cargo。
    请先以**普通用户**构建（不要用 sudo，否则 target/ 会变成 root 所有）：
      cargo build --release --manifest-path $SRC/Cargo.toml
    再重新运行本脚本。"
fi

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

PLIST_TMP="$PLIST.tmp"
# 写临时文件再 mv，保证 launchd 永远读不到半成品。
#
# 刻意用「分段 heredoc + 循环」而不是「占位符 + sed」：
# sed 的替换文本不能含换行（`unescaped newline inside substitute pattern`），
# 而多 uid 恰恰需要每行一个 `<string>`。改用循环直接输出。
#
# 插值安全性：这里只插入 $LABEL（脚本内常量）、$HELPER_BIN（本脚本
# 写死的绝对路径）与已校验为纯数字的 uid，不存在 XML 元字符注入面。
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

    <!--
      刻意保持在**最小已知良好集**。

      实测踩过两次：
      1. 曾加 `Sandboxing`，键名（AllowNetworkClient 等）是我编造的，
         launchd 在 exec 进程之前就把 job 杀掉，bootstrap 却返回成功，
         日志文件连创建都没有。
      2. 带 ProcessType / ThrottleInterval / StandardOutPath /
         StandardErrorPath 的版本，在 system 域下 bootstrap
         同样「返回成功但服务不存在」。

      授权安全靠的是 socket 权限 + getpeereid() 复检，
      日志路径、进程类型、节流间隔都不是必需的 —— 全部去掉。
      之后若仍失败，逐项加回来即可定位到具体是哪一项引起。

      也刻意不声明 MachServices，因此 launchd 不要求代码签名。
      这正是与 SMAppService 路线的关键区别。
    -->
</dict>
</plist>
EOF
} > "$PLIST_TMP"

plutil -lint "$PLIST_TMP" >/dev/null || die "生成的 plist 语法错误，内容如下：
$(cat "$PLIST_TMP")"

chown root:wheel "$PLIST_TMP"
chmod 644 "$PLIST_TMP"
mv -f "$PLIST_TMP" "$PLIST"

# ── 7. 加载 ───────────────────────────────────────────────────
log "launchctl bootstrap system/$LABEL"
#
# ⚠️ 必须捕获 stderr：launchctl 把「服务已存在」之类、以及真正的
# 失败原因都写到 stderr。只看返回值会以为成功了。
bootstrap_err="$(mktemp)"
if launchctl bootstrap "system/$PLIST" 2>"$bootstrap_err"; then
  if [[ -s "$bootstrap_err" ]]; then
    printf '\033[1;33m注意:\033[0m launchctl bootstrap 说了：\n' >&2
    sed 's/^/  /' "$bootstrap_err" >&2
  fi
  log "bootstrap 返回 0"
else
  rm -f "$bootstrap_err"
  launchctl print "system/$LABEL" 2>&1 | head -20 >&2 || true
  die "bootstrap 失败（launchctl 的错误信息应已打印在上方）"
fi
rm -f "$bootstrap_err"

# ── 8. 验证 ───────────────────────────────────────────────────
# 轮询而不是固定 sleep 1：launchd 启动 + 二进制 exec 有延迟，
# 睡 1 秒可能只是还没起来，会误报失败。
loaded=0
for _ in $(seq 1 20); do
  if launchctl print "system/$LABEL" >/dev/null 2>&1; then loaded=1; break; fi
  sleep 0.5
done

if [[ "$loaded" == "1" ]]; then
  pid="$(launchctl print "system/$LABEL" 2>/dev/null | awk '/pid =/{print $3; exit}')"
  log "✓ daemon 已加载 (pid=${pid:-?})"
else
  # 失败诊断要给出**可操作**的信息。
  # 实测踩过：bootstrap 返回成功但 job 被 launchd 在 exec 前杀掉，
  # 此时日志文件根本不存在，只说「见上方日志」等于什么都没说。
  {
    echo "--- launchctl print system/$LABEL ---"
    launchctl print "system/$LABEL" 2>&1 | head -20 || true
    echo
    echo "--- /var/log/oc-gui-helper.log ---"
    if [[ -f /var/log/oc-gui-helper.log ]]; then
      tail -20 /var/log/oc-gui-helper.log
    else
      echo "(文件不存在 —— 进程从未被执行。若 bootstrap 成功却如此，"
      echo "通常是 launchd 拒绝了 plist 中的某个配置项，例如无效的"
      echo " Sandboxing profile。)"
    fi
    echo
    echo "--- 手工前台运行以看真实错误 ---"
    echo "  sudo $HELPER_BIN --daemon ${UIDS[*]}"
  } >&2
  die "daemon 未运行"
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