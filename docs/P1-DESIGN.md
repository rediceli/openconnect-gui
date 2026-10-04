# OC GUI — P1 技术设计

日期：2026-10-03
状态：P1 完成（后端 + UI 可运行），生产化待办见文末
测试：**Rust 136 passed / 0 failed**（119 unit + 17 integration）
**Swift 12 passed / 0 failed**（macOS helper 协议编解码）
+ Linux 特权边界回归（需 root，见 §6.3.8）
Clippy：0 warning
产物：`OC GUI.app` **11.12 MiB** + macOS helper/macosctl **~600 KB**

---

## 1. 模块划分

```
src-tauri/src/
├── profile/
│   ├── mod.rs        Profile / ClientCert / Advanced / Repo（TOML 持久化）
│   └── formmap.rs    协议 × 表单 id × 字段名映射
├── secret/mod.rs     系统钥匙串封装（keyring-rs）
├── tunnel/
│   ├── argv.rs       Profile → openconnect 命令行（+ 安全审计）
│   ├── events.rs     日志 → Event → State 状态机 + TerminalCause
│   ├── occonfig.rs   0600 config 文件承载私钥口令
│   ├── signal.rs     跨平台优雅断开（POSIX SIGINT / Windows Ctrl-Break）
│   └── supervisor.rs 子进程监管（stdin 密钥 / 优雅断开）
├── ipc/
│   ├── mod.rs        GUI ↔ 特权 helper 协议 + argv 复检
│   ├── authz.rs      调用方授权 + 每用户 socket 创建
│   └── client.rs     GUI 侧 helper 客户端（pkexec 启动 + 握手）
├── channel.rs        提权通道抽象（Helper / Direct）+ openconnect 定位
├── commands.rs       Tauri 命令层（CRUD + connect/disconnect + helper + 事件推送）
└── lib.rs

helper/
├── src/main.rs       特权 helper（--authorize / --serve / --selftest）
├── install.sh        Linux 安装脚本（含 4 项校验）
└── polkit/
    └── org.github.rediceli.ocgui-helper.policy

ci/
├── privsep-test.sh   Linux 特权边界回归（8 组断言，核心是非 root 负向测试）
├── run-in-docker.sh  容器封装
├── Dockerfile        rust:1-bookworm + polkit
└── fetch-win-deps.sh Windows 运行时依赖（交叉编译 + wintun + vpnc-script）

win-deps/             Windows 运行时依赖的产出目录（已接入 tauri resources）
tests/replay.rs       真实 openconnect 日志的回归测试
examples/
├── e2e_mock.rs       supervisor → 真实 openconnect → mock gateway
├── e2e_cert.rs       加密私钥 + config 文件口令的端到端验证
├── e2e_helper.rs     GUI client → helper → openconnect 全链路
├── e2e_channel.rs    提权通道选择与错误可读性
├── e2e_logstream.rs  helper 日志流式转发全链路
├── e2e_stop.rs       跨连接 Stop → SIGINT → 进程退出
├── e2e_macos.rs      macOS 特权通道状态探测（Rust → macosctl → SMAppService）
└── cmd_smoke.rs      profile CRUD + 钥匙串 + argv 联动

macos-helper/          macOS privileged XPC（Swift Package）
├── Sources/SharedProtocol/   协议定义（与 src/ipc.rs 一一对应）
├── Sources/Helper/          daemon：XPC listener + 调用方校验 + openconnect 监管
├── Sources/XPCClient/       App 侧：SMAppService 注册 + NSXPCConnection 客户端
├── Sources/Macosctl/        CLI：Rust ↔ Swift 的行协议边界
├── Tests/                   12 个协议编解码测试
└── Scripts/sign-macos.sh    构建 + 注入 Team ID + 签名 + embed + 8 项校验
```

### 线程模型

```
GUI (Tauri 主线程)
  └─ invoke("connect")
       └─ spawn_blocking
            ├─ supervisor::start()      spawn openconnect，写 stdin，关闭
            ├─ 线程 A/B                  读 stdout / stderr → channel
            ├─ 线程 C                    poll cancel 标志 → SIGINT
            └─ 主循环                    行 → Tracker → 状态变化 → app.emit()
```

前端只订阅事件，不轮询。事件名统一带 `vpn://` 前缀避免与 Tauri 内置冲突。

---

## 2. 安全不变量（测试强制）

### 2.1 密钥绝不进 argv

`argv` 在 Linux/macOS 上对同机所有用户可读（`/proc/<pid>/cmdline`、`ps aux`），
Windows 上也可被其他进程读取。

| 密钥 | 通道 |
|---|---|
| 密码 | `--passwd-on-stdin` |
| cookie（SSO） | `--cookie-on-stdin` |
| 令牌 secret | `--token-secret=@<helper 自己创建的 0600 文件>` |
| 私钥口令 | ⚠️ **无 stdin 通道**，见待办 §6.1 |

强制手段：
- `ArgPlan::audit_argv(secrets)` 在 `supervisor::start()` 里自检，
  发现泄漏则**拒绝启动**（返回 `InvalidInput`）
- 测试 `profile::tests::password_never_appears_in_serialized_profile`
- 测试 `supervisor::tests::refuses_to_start_when_secret_leaks_into_argv`

### 2.2 profile 文件只存非敏感信息

TOML 里只有 `password_saved: bool` 这类标记。
`cmd_smoke` 示例会实际读取 `profiles.toml` 并断言不含密码。

### 2.3 删除档案必须清理钥匙串

否则钥匙串里留下孤儿条目。`delete_profile` 强制调用 `secret::purge`。

### 2.4 helper 的三条边界

1. **只执行 openconnect** — `validate_program()` 按 `file_stem` 校验，
   刻意不做成「可配置白名单」（可配置本身就是提权后的任意执行入口）
2. **argv 复检** — GUI 可能被攻破，helper 不信任 GUI 的校验。
   拒绝 `--csd-wrapper` / `--external-browser` / `--script-tun`、控制字符
3. **令牌文件路径由 helper 生成** — GUI 不指定路径，helper 写 0600 并在
   `exec` 后立即删除

已通过 spike 实测验证（见 §4）。

---

## 3. 状态机

### 3.1 为什么不能靠日志文案判定

openconnect 在 `<auth id="success">` 路径下**不打任何认证成功日志**
（`auth.c:723` 直接 return `OC_FORM_RESULT_LOGGEDIN`）。下一个可见信号是
`cstp.c` 的 CONNECT 响应。

推论：
- 认证成功与认证失败在 `State` 上**都终结于 `Failed`**
  → 必须有 `TerminalCause`
- 网关在认证**失败**时同样下发 `Set-Cookie` → 「见到 cookie」不能作判据
- UI 在 `Authenticating` 就应显示「正在建立隧道」，而非「正在验证身份」

### 3.2 状态转移的可靠信号

| 转移 | 判据 |
|---|---|
| → `Authenticating` | `Attempting to connect` 之后的第一条 `POST`（XML 初始请求不算） |
| → `Configuring` | `Got CONNECT response`（cstp.c） |
| → `Connected` | `Configured as ...`（main.c:1663）或 `RX:` 统计行 |
| → `Failed`（锁存） | 首个 `Fatal` / `AuthFailed`，之后不再变化 |

### 3.3 三个被测试逼出来的 bug

1. **失败原因被收尾日志冲掉**：openconnect 失败时连打
   `具体原因 → "; exiting" → "Unknown error; exiting."`，
   只存最后一条会得到无用的 `Unknown`。→ `failure_reasons` 环形缓冲
   （`failure_reasons_accumulate_not_overwritten`）
2. **Failed 被重复 emit 3 次** → `settle()` 终态收敛
   （`terminal_state_emitted_exactly_once`）
3. **失败后被拉回「等待输入」**：分组值无效时 openconnect 转去弹交互式下拉，
   UI 会从「认证失败」退回 `AwaitingUser`，用户看到永远转圈的连接界面。
   → `latched_failure` 锁存
   （`bad_group_classified_as_auth_group_invalid`）

### 3.4 TerminalCause 分类

| 分类 | 触发 | UI 行为 |
|---|---|---|
| `AuthRejected` | 密码错 / 证书被拒 | 弹密码框，可重试 |
| `AuthGroupInvalid` | `Auth choice "..." not available` | 引导改分组，**不**让用户改密码 |
| `UserInputRequired` | 卡在 `AwaitingUser` | 提示表单未被预填 |
| `NetworkUnreachable` | `Failed to connect to` | 可重试 |
| `CertificateRejected` | 证书校验失败 | 提示换证书 |
| `TunnelSetupFailed` | CONNECT / tun / DTLS | 提示调 MTU / 换网关 |
| `SessionTerminated` | cookie 过期 | 提示重连 |
| `UserCancelled` | 用户主动断开 | 非错误 |

判定顺序 = 具体性从高到低。`UserInputRequired` 必须排在最后，
否则失败后的交互提示会误导用户。

---

## 4. 特权 helper spike 结果

`helper/` 已实现并实测：

```
$ oc-gui-helper --selftest
selftest ok                      # 程序白名单、argv 复检、0600 文件

$ oc-gui-helper --serve /tmp/hthink.sock
helper listening on /tmp/oc-gui-helper.sock

Hello:      {'event':'ready','version':1,'authorized':true,'connected':false}
BadVer:     {'error':{'kind':'protocol_mismatch','expected':1,'got':99}}
CsWrapper:  {'error':{'kind':'rejected','reason':'禁止的参数: --csd-wrapper'}}
Start:      {'event':'started','pid':87615}   # 真实 openconnect 已启动
```

确认生效的边界：协议版本不匹配直接拒绝、危险参数拦截、密码仅走 stdin
（mock gateway 日志显示 `pass=******* group='Engineering'`）、令牌文件
0600 且即时清理。

### 三个平台的授权方式

| 平台 | 机制 | 关键点 |
|---|---|---|
| Linux | polkit action | **按 uid 授权，不是按 argv**。按 argv 授权等于用户能用 `pkexec` 自己构造任意 openconnect 命令行 |
| macOS | `SMAppService.daemon` + privileged XPC | `shouldAcceptNewConnection` 里必须校验 connecting process 的 code signature designated requirement（`SMAuthorizedClients` 在该流程下**不生效**）；需 Developer ID + Hardened Runtime + 公证；用户要在「系统设置 → 登录项」手动批准 |
| Windows | UAC 提权启动常驻 helper | 同用户 named pipe；见 §6.2 |

当前 spike 的 socket 权限是 0600 属主 root，**GUI 无法连接** ——
这如实反映了一个未解决项：真实部署需要先经 polkit 认证调用方 uid，
再 chown socket。见 §6.3。

---

## 5. 表单字段映射（P0/P1 两次踩坑的产物）

`--authgroup` 在 stdin 模式下会退化成阻塞式交互下拉：
```
GROUP: [|Engineering|Operations]:fgets (stdin): Resource temporarily unavailable
```
必须用 `--form-entry=<表单id>:<字段名>=<值>` 预填。

| 协议 | form id | 字段名 | 源码依据 |
|---|---|---|---|
| anyconnect | `main` | **`group_list`** | `auth.c:173` |
| juniper/nc | `loginForm` | `realm` | `auth-html.c:168`、`auth-juniper.c:64` |
| f5 | `main` | `domain` | `auth-html.c:169` |
| gp | `_portal` | `gateway` | `auth-globalprotect.c:448,456` |
| pulse/fortinet/array | — | — | 源码无特殊处理，需手填 |

### 5.1 三个具体的坑

1. **`group_list` 不是 `auth_group`** — `auth_group` **不是任何协议的字段名**。
   社区文档常见的写法是错的。写错的后果是静默失效（退化成阻塞提示）
2. **`-F=` 不能用，必须 `--form-entry=`** — getopt 对短选项不做 `=`
   剥离，`-F=main:group_list=X` 会把 `=main:...` 整体当参数传给
   `add_form_field()`，按第一个 `=` 切分得到空 opt_id，直接
   `exit(1)` 报 `Form field invalid`。
   测试 `no_short_option_is_given_an_inline_equals` 系统性防护这一点
3. **「勾了记住密码但钥匙串空」会卡死** → 自动加 `--non-inter`
   提前失败，而不是让 openconnect 等 stdin

---

## 6. 未决项与生产化待办

### 6.1 私钥口令 —— 已解决 ✅

**原问题**：`-p/--key-password` 是 openconnect 唯一接受私钥口令的入口，会进 argv。

**核实结论**：`--key-password=@file` **不被支持**。源码证据：

```sh
$ grep -rn "case '@'" *.c
main.c:1549    # --token-secret 的补全逻辑
main.c:3013    # 同上
oidc.c:36
stoken.c:47    # --token-secret 真正读文件
```

`-p` 走 `main.c:2109`，`dup_config_arg()` 后直接赋值给
`vpninfo->certinfo[0].password`，**没有任何 `@` / 路径处理**。

**解法**：`--config=FILE`。config 文件走同一套 `long_options` 匹配
（`main.c:1258`），因此支持**长选项** `key-password`；短选项 `-p`
只存在于 argv 路径。

**实测**（加密 PKCS#8 私钥 + mock gateway）：

| 命令行 | 结果 |
|---|---|
| `-p MyKeyPass` | `Using client certificate 'alice'`（但口令进 argv） |
| `--config=oc.conf` + 正确口令 | `Using client certificate 'alice'` ✅ |
| `--config=bad.conf` + 错误口令 | `Failed to decrypt PKCS#8 certificate file` ✅ |

端到端验证（`examples/e2e_cert.rs`）：`supervisor` → 真实 openconnect，
私钥口令确认不在 argv 中、config 文件 0600、证书成功加载、drop 后文件清理。

**config 文件的硬约束**（源码 + 实测，`occonfig::validate_passphrase`）：

| 约束 | 原因 | 违反后果 |
|---|---|---|
| 不能有换行 | 第二行被当未知选项 → `usage()` 退出 | `openconnect` 打印帮助并退出 |
| 不能有前导空格 | `while (*line == ' ')` 跳过前导空白 | `Failed to decrypt PKCS#8` |
| 不能为空 | `has_arg == 1 && !*line` → 报错 | 报错退出 |
| 可以有内部空格 / `#` / `=` | 只跳前导；`#` 注释只在**行首**判定 | 无 |

违反时**明确失败**（`ArgPlan::fatal_error`），绝不静默降级到明文 argv。

**仍遗留**：`--mca-key-password`（多证书认证的第二个私钥）同样没有安全
通道。当前行为是**拒绝启动并说明原因**，而不是静默丢弃用户提供的口令
（`argv::tests::mca_key_password_is_refused_not_silently_placed_in_argv`）。
解法需等 openconnect 支持 `@file`，或改走 PKCS#11 让 openconnect 直接读。

**Windows 备注**：Windows 上 `%TEMP%` 的 ACL 继承自目录，无法像 POSIX
那样用 mode 精确控制。`occonfig::write_secure` 的 Windows 分支保留了实现
但**生产使用前必须确认 `%TEMP%` 不可被其他用户写入**。

### 6.2 Windows 断开与打包 —— 断开已解决 ✅ / 打包脚本就绪 ✅

**原判断有误**。源码核实（`main.c:876` `console_ctrl_handler`）：

```c
case CTRL_C_EVENT:
case CTRL_CLOSE_EVENT:
case CTRL_LOGOFF_EVENT:
case CTRL_SHUTDOWN_EVENT:
        cmd = OC_CMD_CANCEL;   // 'x'
case CTRL_BREAK_EVENT:
        cmd = OC_CMD_DETACH;   // 'd' —— 断开隧道，保留会话
```

openconnect **确实**处理 Windows 控制台事件，且 `SetConsoleCtrlHandler`
在 `main.c:2357` 注册。因此不需要「GUI 自己跑 vpnc-script-win.js」。

实现（`tunnel/signal.rs`）：
- spawn 时加 `CREATE_NEW_PROCESS_GROUP`（否则无法定位到子进程组）
- 用 `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)` 而非 `CTRL_C_EVENT`：
  前者可发往**指定进程组**，后者只能发给 0，会连 GUI 一起打断
- 语义也更合适：`OC_CMD_DETACH` 是断开隧道而非注销会话
- 超时后仍保留强杀兜底

测试 `flags_are_consistent_with_disconnect_mechanism` 锁定「标志与断开
方式必须匹配」，防止将来有人删掉 `CREATE_NEW_PROCESS_GROUP`。

#### 打包依赖已就绪 ✅

`ci/fetch-win-deps.sh` 照抄 openconnect 官方 `Makefile.am` 的方案：

| 产物 | 来源 | 缺失后果 |
|---|---|---|
| `openconnect.exe` | MinGW 交叉编译 | 无法连接 |
| `*.dll` | `objdump -p` 递归展开的**传递**依赖（gnutls/libxml2/zlib/lz4/stoken/p11-kit） | 启动即失败 |
| `wintun.dll` | wintun.net，**SHA256 与上游 `WINTUNSHA256` 逐字节一致** | `Failed to create TUN device` |
| `vpnc-script-win.js` | vpnc-scripts master，文件头记录来源提交 | 路由/DNS 不配置 |
| `MANIFEST.txt` | 脚本生成，含逐文件校验和 | 无法审计装了什么 |

已接入 `tauri.conf.json` 的 `bundle.resources`。

**交叉核对结果**：
```
脚本:   WINTUN_VERSION=0.14.1   WINTUN_SHA256=07c256185d6e...
上游:   WINTUNDRIVER = wintun-0.14.1.zip
        WINTUNSHA256 = 07c256185d6e...
```
jq 字段路径（`authored_date[:10]` 等）也已用真实 API 响应验证。

**本机未验证**：交叉编译本身（无 MinGW）、Windows 上的实际连接。
`channel.rs` 的 Windows 分支当前仍从 `OCGUI_OPENCONNECT` 或
`/usr/sbin/openconnect` 取路径，**应改为从 `current_exe()` 同级目录找** ——
Windows PATH 不可控，且 openconnect 不会被常规安装。

### 6.3 helper 授权 —— Linux 与 macOS 代码就绪 ✅ / Windows 待写 🔶

#### 6.3.1 为什么授权模型是头等大事

helper 以 root 运行。**任何能连上 socket 的本地用户都能以 root 执行
openconnect**，而 openconnect 有 `--csd-wrapper=SCRIPT`（运行任意脚本）、
`--external-browser=BROWSER`、`-s/--script` 这些 root 任意执行入口。

一个天真的 polkit 规则会致命：

```xml
<!-- ❌ 绝对不要这样写 -->
<allow_any>
  <allow_command>pkexec</allow_command>
  <allow_arg>openconnect</allow_arg>  <!-- 全机任何人可构造 -->
</allow_any>
```

任何用户都能跑：

```sh
pkexec openconnect --csd-wrapper=/tmp/evil.sh vpn.corp.com
```

**无需提权提示的 root 漏洞。** 因此 polkit rule 只做一件事：
授权「启动 oc-gui-helper 这个程序」。真正的提权边界在别处。

#### 6.3.2 三层防护

| 层 | 位置 | 作用 |
|---|---|---|
| 1. polkit | `org.github.rediceli.ocgui-helper.policy` | 决定「谁有资格让 helper 为自己开 socket」 |
| 2. 文件系统权限 | `create_per_user_socket()` | socket `0600` + 属主该 uid。**授权结果直接编码在权限里** |
| 3. 每次连接复检 | `authorize()` | 按 uid 白名单再判一次 |

三层缺一不可。第 2 层挡住普通用户；即使 `/run/oc-gui` 目录权限被
误配成 0777，socket 本身仍是 0600 + 正确属主；第 3 层挡住同组内的其他人。

**竞态说明**：`bind` 与 `chown` 之间存在极短窗口，期间 socket 属主仍是
root 且权限 0600 ⇒ 其他用户连不上。因此**不存在「未授权即可连」的窗口**。
创建前显式检查 `path.exists()` 并拒绝复用，配合 `bind` 的原子性，
避免跟随攻击者预置的符号链接。

#### 6.3.3 为什么是「每用户 socket」而非「0600 root → 授权后 chown」

后者会留下一个「能连上但会被拒」的中间态，且 chown 之后若白名单变更，
旧 socket 仍在。每用户 socket 没有中间态，也没有残留。

```
/run/oc-gui/helper-<uid>.sock   0600, 属主 <uid>
```

#### 6.3.4 Linux 实现状态 ✅

```
src-tauri/helper/
├── polkit/org.github.rediceli.ocgui-helper.policy
├── install.sh                  (--dry-run / --uninstall)
└── src/main.rs                 (--authorize <uid> | --serve | --selftest)
```

**policy 要点**：

- `allow_active/allow_any/allow_inactive` 全部 `auth_admin`
- **不用 `auth_admin_keep`** —— 缓存期内无条件放行等于把 root 能力
  借给一个可能已被攻破的 GUI 进程
- 单独拆出 `...helper.probe` action（`allow_any=yes`）供只读探测，
  这样探测可以用宽松策略而不影响启动路径

**调用链**：

```
GUI  → HelperHandle::probe(uid)
        socket 不存在 → 提示用户
GUI  → HelperHandle::spawn_via_pkexec(uid)
        pkexec /usr/libexec/oc-gui-helper --authorize <uid>
          → polkit 弹密码框（auth_admin）
          → helper 以 root 运行，geteuid()==0 校验通过
          → create_per_user_socket(uid) → chown + 0600
          → 常驻 serve
GUI  → HelperHandle::connect(uid) → 握手 → 发请求
```

**安装脚本的四个校验**：

| 校验 | 目的 |
|---|---|
| `helper --selftest` | argv 白名单 / 授权判定 / 密钥文件 0600 |
| `pkaction --action-id` | polkit 能解析 action |
| helper 无 setuid 位 | 提权必须走 polkit，不能靠 setuid |
| 非 root 无法 `--authorize` | 防止绕过 polkit 直接启动 |

**已验证**（本机无 root，验证了能验证的部分）：

| 项 | 结果 |
|---|---|
| policy XML 合法性 | ✅ 两个 action，`auth_admin` 三处一致 |
| `install.sh --dry-run` 全路径 | ✅ 逐条输出正确 |
| 实际安装到 `PREFIX=/tmp/...` | ✅ helper `--selftest` 通过、policy 0644 就位 |
| helper 权限 755 无 setuid | ✅ |
| 非 root `--authorize` 拒绝 | ✅ exit=2 |
| `--authorize` 拒绝 root uid | ✅ |
| GUI client → helper → openconnect 全链路 | ✅ 见下 |
| polkit 实际授权（`auth_admin` 弹框） | ❌ 需真实 root + polkitd |

**开发模式全链路实测**：

```
$ OCGUI_ALLOWED_UIDS=501 oc-gui-helper --serve /tmp/oc-gui-helper-501.sock
helper listening on /tmp/oc-gui-helper-501.sock (euid=501, allowed=[501])

[ok] helper 可用
[ok] helper 拒绝了危险参数: Rejected { reason: "禁止的参数: --csd-wrapper" }
[ok] Start 响应: Started { pid: 2626 }

# mock gateway 侧确认密码经 stdin 送达：
[mock]   user='testuser' pass=******* group='Engineering'
```

helper 未启动时客户端给的是可操作提示，不是异常：

```
[info] helper 不可用: 特权助手未安装或未启动（/tmp/oc-gui-helper-501.sock）
       UI 应引导用户执行：
       pkexec /usr/libexec/oc-gui-helper --authorize 501
```

#### 6.3.5 macOS `LOCAL_PEERCRED` 的坑

网上流传的写法是 `getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &u32)`。
**那是错的** —— 返回结构是 `struct xucred`
（version + uid + ngroups + groups，见 `/usr/include/sys/ucred.h`），
只给 4 字节会让内核写超缓冲，实测**恒得 uid=0**（进而触发 self 检查被拒）。
代码已按正确结构实现并加版本校验。

#### 6.3.6 提权通道抽象与 GUI 接入 ✅

`channel.rs` 把「怎么拿到 root」抽象掉：

| 实现 | 平台 | 机制 |
|---|---|---|
| `Channel::Helper` | Linux | polkit + pkexec + Unix socket |
| `Channel::Direct` | macOS / 降级 | 直接 spawn openconnect |

`Channel::detect()` 在 Linux 上优先 helper；不可用时回落 Direct，但
`is_privileged()` 返回 false，UI 据此引导用户启动助手 ——
**不静默降级**，否则用户只会看到「权限不足」这种难懂错误。

新的 Tauri 命令：

| 命令 | 作用 |
|---|---|
| `helper_status` | 返回 `{privileged, helper_ready, helper_installed, channel, message, elevate_command}` |
| `helper_start_elevated` | 调 pkexec，弹系统密码框 |
| `helper_wait_ready` | 轮询等待就绪（上限 60s） |

连接页新增「特权助手」卡片：显示状态、给出提权命令（可复制）、
「提权启动」按钮。`PrivilegeRequired` 是独立的 `TerminalCause` ——
它的解法不是「重试」而是「先启动助手」，UI 必须引导用户做不同的事。

#### 6.3.7 helper 日志流式转发 ✅

helper 以 root 运行，openconnect 的 stdout/stderr 归它所有。要让 UI
看到实时日志，必须由 helper 转发。

**协议**（`Response::Log` 已落地）：Start 应答 `Started` 之后，helper
在**同一连接**上持续推送：

```
→ {"cmd":"start",...}
← {"event":"started","pid":7420}
← {"event":"log","line":"[2026-10-03 13:36:46] POST https://..."}
← {"event":"log","line":"...Attempting to connect to server..."}
← {"event":"log","line":"...Got inappropriate HTTP CONNECT response..."}
← {"event":"exited","code":1}
```

**为什么流式而不是缓冲到结束**：GUI 状态机靠日志行驱动，用户也要看到
「正在验证身份 / 正在建立隧道」这类实时反馈。缓冲会让日志页在整个连接
期间空白。

**helper 侧结构**：
- `Writer = Arc<Mutex<BufWriter<UnixStream>>>` 被 log pump 线程共享
- 每个 `Start` spawn 两条 pump（stdout / stderr），各自逐行转 `Response::Log`
- 第三条监督线程 poll `stop` 标志与 `try_wait()`：
  - `stop` 被置位 → 发 **SIGINT**（不是 SIGKILL，否则残留路由），
    等 3 秒仍不退才强杀，然后发 `State{Idle}`
  - 进程自行退出 → 发 `Exited{code}`
- 连接断开时自动置 `stop`，避免留下无主进程 + 脏路由

**GUI 侧**：`HelperHandle::pump_stream` 一直读到流结束，
`Channel::start_streaming` 统一两种通道的事件形状
（`StreamEvent::{Started,Log,Finished,Exited,Failed}`），
`commands.rs` 只订阅这一套事件。

⚠️ 一处折中：helper 通道下用**单行判据**（`line_state`）驱动粗粒度
状态，而 `TerminalCause` 这类需要多行累积的判断只在 Direct 通道用完整
`Tracker`。原因见 `channel.rs` 的注释 —— 完整 Tracker 需要保留实例，
后续在 `pump_stream` 回调里持有即可，不改协议。

**实测**（`examples/e2e_logstream.rs`，helper + 真实 openconnect + mock gateway）：

```
[ok] helper 可用
channel privileged = true
[started] pid=7420
  [log 1] [2026-10-03 13:36:46] POST https://127.0.0.1:8443/
  [state] Connecting
  [log 33] ...Got inappropriate HTTP CONNECT response: HTTP/1.
  [state] Failed
[exited] code=Some(1)
共收到 35 条日志，状态轨迹 ["Connecting", "AwaitingUser", "Failed"]
```

`Channel::detect` 的 helper 分支因此从 `#[cfg(target_os = "linux")]`
放宽到 `#[cfg(unix)]` —— 让这条路径在 macOS 开发机上也能被真实执行，
而不是只在 Linux CI 上跑过。

#### 6.3.7b 跨连接 Stop（实现过程中暴露的三个 bug）

`disconnect` 不能复用已有连接发 `Stop` —— 那条连接正被 `pump_stream`
占着读日志，两个线程抢同一个 socket 的读半边会互相抢数据。
因此走**新开一条连接**。这要求 helper 的会话是**进程级**的
（全局槽），而非 per-connection。实现该需求时暴露了三个 bug：

| # | Bug | 症状 | 根因 |
|---|---|---|---|
| 1 | `connect()` 设了 10s 读超时 | 隧道静默 10s 后被误判断开，helper 回收会话，后续 Stop 找不到连接 | 读超时适合「一问一答」，**日志流必须能无限期静默**（openconnect 等密码、跑 vpnc-script 时都很安静） |
| 2 | `handle()` 在 accept 循环里同步调用 | 一条长连接**饿死所有后续连接**，GUI 的 disconnect 永远收不到应答 | 每连接必须一个线程 |
| 3 | 会话按连接保存 | 第二条连接的 `Stop` 找不到会话，静默返回 NotConnected | 会话必须是进程级的 |

Bug 2 最隐蔽：纯 Python 脚本也能稳定复现（第二条连接连 `hello`
都收不到应答）。已加注释说明「这里不能同步调用」。

**实测**（`examples/e2e_stop.rs`，长驻的 openconnect 替身 +
真实 helper + 跨连接 Stop）：

```
[started] pid=18648
[ok] openconnect pid = 18648
--- 从第二条连接发 Request::Stop ---
[ok] Stop 已送达
[finished] state=Idle
openconnect 仍在运行: false
[ok] 跨连接 Stop 验证通过
```

替身脚本固化在 `tests/bin/fake-openconnect.sh`：mock gateway 会在
CONNECT 阶段立刻失败，隧道活不到能测 Stop 的时刻。

**测试**：`connect_does_not_set_read_timeout` 与
`read_timeout_policy` 锁定 Bug 1 的修法（防止有人「顺手」加回超时）。

#### 6.3.8 Linux 特权边界回归测试 ✅（需 root）

`ci/privsep-test.sh` —— 本机无 root 无法运行，但已做成可直接进 CI 的形式。
8 组断言：

| # | 断言 |
|---|---|
| 1 | `install.sh` 完成 4 项校验 |
| 2 | polkit action 已注册；**policy 剥离注释后不含 `allow_arg`**；不含 `auth_admin_keep`；`auth_admin` ≥3 处 |
| 3 | helper 无 setuid 位、属主 root:root、`--selftest` 通过 |
| 4 | **拒绝为 root 建 socket**（否则 uid 检查形同虚设） |
| 5 | 创建测试用户 |
| 6 | **非 root 无法启动 `--authorize`**；root 建 socket 后属主/权限正确；属主可握手 |
| 7 | helper 拒绝 `--csd-wrapper`；协议版本不匹配被拒 |
| 8 | 密钥文件 0600 |

> ⚠️ 断言 2 必须**先剥掉 XML 注释**再 grep —— 本仓库的 policy 在注释里
> 写了「绝对不要用 allow_arg」这样的反例说明，直接 grep 会误报。

容器封装（`ci/Dockerfile`）刻意用 Debian 而非 Alpine：polkit/pkexec/shadow
在 Alpine 上要么没有要么行为不同，会掩盖真实发行版上的问题。

**本机已验证**：脚本语法、非 root 时的拒绝行为与退出码、注释剥离逻辑
（确认 policy 剥离后不含 `allow_arg`/`auth_admin_keep`，`auth_admin` 恰 3 处）。
**未能验证**：需要 root 的 8 组断言（本机无 root、无 docker）。

#### 6.3.9 macOS privileged XPC ✅（代码就绪，未签名验证）

macOS 的特权模型与 Linux 完全不同：没有 polkit 这样的通用提权框架，
必须用 **privileged XPC** —— App 与 helper 由 launchd 加载、
通过 Mach service 通信、共享 Team ID 与签名。

`macos-helper/`（Swift Package，`swift build` + `swift test` 已通过）：

```
macos-helper/
├── Package.swift
├── Sources/SharedProtocol/
│   ├── OcProtocol.swift          请求/响应类型，与 src/ipc.rs 一一对应
│   └── Resources/io.github.rediceli.ocgui.helper.plist
├── Sources/Helper/
│   ├── Listener.swift                XPC listener + 调用方校验 + openconnect 监管
│   ├── Config.swift                  Team ID（构建期注入，缺失则拒绝所有连接）
│   ├── Logger.swift
│   └── Info.plist
├── Tests/SharedProtocolTests/        12 个协议编解码测试
```

二进制 304 KB。

#### 6.3.9.1 三条最容易踩的坑（全部实际踩过并修掉）

**1. `SMAuthorizedClients` 在 `SMAppService` 下不生效。**
它是 legacy `SMJobBless` 的遗留写法，launchd 与 `SMAppService`
都不强制执行。**授权判定必须在
`shouldAcceptNewConnection` 里做**。漏掉这一步 = 任何本地进程知道
Mach service 名就能驱动 root daemon 执行 openconnect
（而 openconnect 有 `--csd-wrapper` 执行任意脚本）= 无需提权提示的
root 漏洞。

launchd plist 里保留了 `SMAuthorizedClients`，纯粹是为了通过 App Store
审核的检查项，代码里已注明它不参与判定。

**2. `NSXPCConnection.processIdentifier` 是同步属性，不是方法。**
早先按异步闭包写：

```swift
newConnection.processIdentifier { pid, _ in ... }   // ❌
```

编译报 `cannot call value of non-function type 'pid_t'`。
正确写法 `let pid = newConnection.processIdentifier` —— 同步可得
意味着 `shouldAcceptNewConnection` 本身就是正确的校验点，
不存在未授权窗口。

**3. `NSXPCConnection.xpcConnection` 不是公开 API。**
拿不到 audit token。可行替代：`processIdentifier` + 
`SecCodeCopyGuestWithAttributes(kSecGuestAttributePid:)`，已足够
完成「同一 Team ID 签名的那个 App」这一层校验。

#### 6.3.9.2 调用方校验（三项全过才放行）

```swift
let clientPID = newConnection.processIdentifier
guard clientPID > 0, isClientAuthorized(pid: clientPID) else { return false }
```

`isClientAuthorized` 检查：
1. **签名有效** — `SecStaticCodeCheckValidityWithErrors`
2. **bundle id == `io.github.rediceli.ocgui`**
3. **Team ID == 构建期注入的 Team ID**

第 3 项是关键：防止别的开发者用同名 bundle id 冒领。
Team ID 缺失时**拒绝所有连接**（不是降级放行），
`Entry.run()` 甚至会因此直接退出。

#### 6.3.9.3 协议一致性由测试锁定

Swift 侧与 Rust 侧的 JSON 形状必须逐字段一致 —— 任何一侧改字段名
而另一侧没改，症状是「连接建立后收不到任何应答」，极难排查。
`Tests/SharedProtocolTests` 固化了所有形状，包括一条关键不变量：
`Password("x")` 与 `Cookie("x")` 编码后**必须不同**
（`testSecretsAreTaggedNotPositional`），否则 helper 会把 cookie
当密码送进 stdin。

#### 6.3.9.4 App 侧客户端与签名脚本 ✅

**为什么中间加一层 `macosctl` CLI**

privileged XPC 只能从 Swift/ObjC 调用，而 Tauri 的 GUI 是 Rust。
写 ObjC FFI + 桥接头直接调，可行但脆弱（ARC 桥接、块指针生命周期、
异步队列管理），比重新实现 XPC 更糟。行协议边界让两端都保持原生实现，
且与 Linux 的 socket 协议对 GUI 完全一致（都是 `crate::ipc` 的 JSON）。

```
Rust GUI ──行协议(JSON)──► macosctl ──NSXPCConnection──► helper(root)
```

`macosctl` 子命令：`register`（注册 daemon）、`status`（只查状态）、
`selftest`（不需要 XPC）；不给子命令则进入行协议模式。

**注册状态的三态必须分开**（`SMAppService.Status`）：

| rawValue | 映射 | 用户动作 |
|---|---|---|
| 0 | `not_registered` | 点「提权启动」 |
| 1 | `registered` | 无 |
| 2 | `requires_approval` | **必须**去系统设置手动批准 |
| 3 | `not_found` | App bundle 不完整 → 重新安装 |

`not_found` 与 `not_registered` 必须区分：前者是 plist 没 embed 或
签名不匹配（用户重装才有用），后者是还没申请（点按钮有用）。
UI 文案已按此分开。

⚠️ **macOS 不弹密码框。** `SMAppService.register()` 只发起申请，
批准动作在「系统设置 → 通用 → 登录项」。GUI 因此有
`open_system_settings` 命令直接深链过去（失败则退回打开设置首页）。

**XPC 客户端的双向校验**：App 侧也用 `setCodeSigningRequirement`
校验对端是同一 Team ID 的 helper —— Mach service 名是公开的，
理论上任何人都能注册同名服务，不反向校验就会把自己的密码送给攻击者。

**Team ID 注入方式（踩了一个坑）**

最初想用 `-sectcreate __TEXT __info_plist` 把 Info.plist 编进二进制，
但 **SwiftPM 的 `linkerSettings.unsafeFlags` 传给 swiftc 而不是 ld**：

```
error: unknown argument: '-sectcreate'
```

正确做法需要 SwiftPM build plugin，复杂度不划算。最终改用
**launchd plist 的 `EnvironmentVariables`** —— launchd 本来就是加载
daemon 的，机制天然匹配，排查时 `launchctl print system/<label>`
也能直接看到。

#### 6.3.9.5 `Scripts/sign-macos.sh`

顺序是固定的，错一步就失败：

```
1. swift build -c release              构建 helper + macosctl
2. sed 注入 Team ID 到 launchd plist
3. cargo tauri build                    构建 GUI
4. embed: LaunchDaemons/*.plist
        + Library/HelperTools/oc-gui-helper
        + MacOS/macosctl
5. codesign: 先 Helper，再 App          ← 顺序不能反
6. 8 项校验
7. （可选）notarize + staple
```

⚠️ **签名顺序**：App 签名时会连同 `Contents/` 一起封签，
之后再动 Helper 会让 App 签名失效（`code has been modified`）。

8 项校验：

| # | 校验 | 防的是什么 |
|---|---|---|
| 1 | `codesign --verify --deep --strict` | 签名无效 |
| 2 | Hardened Runtime 已开 | App Store / 公证必需 |
| 3 | App 与 Helper 的 **Team ID 一致** | XPC 调用方校验会失败 |
| 4 | bundle id 正确 | 同上 |
| 5 | plist 声明了 `MachServices` | launchd 不加载 |
| 6 | plist Team ID 已注入 | helper 拒绝所有连接 |
| 7 | plist **无残留 `__TEAM_ID__` 占位符** | helper 拿到字面量占位符 |
| 8 | helper 无 setuid 位 | 提权必须走 XPC |

第 7 项是踩过才知道要加的：`sed` 若漏替换，helper 会拿
`__TEAM_ID__` 当 Team ID 去比对，然后拒绝所有人 —— 症状是
「helper 一直拒绝连接」而非任何显式报错。

**本机已验证**：脚本语法、`--help`、无 `--team-id` 时正确拒绝、
`sed` 注入后 `PlistBuddy` 能读出正确 Team ID 且无残留占位符。

#### 6.3.10 Windows named pipe 🔶（交叉编译通过，行为待实机验证）

**先说怎么验证的 —— 这段是重点**

Windows 代码在 macOS 上写完后**没有任何办法验证**，除非先解决
`tauri-build` 的 Windows 分支要 `llvm-rc`（Xcode 里没有）这个问题。
`cargo check --target x86_64-pc-windows-msvc` 会在 build script
阶段就挂掉，一个 Windows 类型的错误都报不出来。

解法分两步：

**第一步：把协议从 Tauri 里剥出来。** 新增 `crates/oc-proto`，
只依赖 `serde`/`serde_json`，装协议类型 + `authz`。GUI 侧的
`src/ipc.rs` 变成纯 re-export，`helper/` 也改依赖它 —— 于是
两者都不再拖 Tauri，可以独立交叉检查。

代价是 `Response::State` 不能用 GUI 的强类型：

| 字段 | 协议里的表示 | GUI 侧的还原 |
|---|---|---|
| `state` | `String`（snake_case） | `parse_state()` |
| `cause` | `serde_json::Value` | `parse_cause()` |

`cause` 用 `Value` 而不是 `String` 是必须的 —— `TerminalCause` 的
变体**带字段**（`reason`/`hint`/`prompt`），退化成字符串就把 UI 真正
要显示的信息全丢了。

**第二步：把要检查的模块挂进临时 crate。** `ci/check-windows.sh`
把 `src/ipc/client.rs` 与 `src/ipc/pipe.rs` **原样**复制进一个
无 Tauri 的临时 crate 再检查（只重写 `crate::ipc::pipe` → `crate::pipe`
这一条路径）。覆盖：

- `crates/oc-proto` — 协议 + authz（含 Windows DACL 分支）
- `helper-win` — pipe server + SDDL + 提权启动
- `src/ipc` — GUI 侧客户端 + named pipe 传输层

现在三个都能对 `x86_64-pc-windows-msvc` 干净编译，clippy 零告警。
这个检查只证明「能编译」，**不证明 DACL 真的挡住了非授权方** ——
那仍然需要 Windows 实机。

**授权模型：Windows 没有「连上再校验」**

| | Linux | Windows |
|---|---|---|
| 端点 | `/run/oc-gui/helper-<uid>.sock` | `\\.\pipe\OC GUI-helper-<SID>` |
| 授权 | polkit → socket `0600` → 运行时 uid 复检 | **DACL**（`CreateNamedPipeW` 时写入） |
| 提权 | `pkexec` | `ShellExecuteW` + `runas` verb |

named pipe 的 DACL 在创建时就写进安全描述符，非授权方**根本连不上**。
所以 Windows 版没有 `authorize()` 运行时检查 —— 加了反而是噪音。
这也是为什么协议里 `Ready.authorized` 在 Windows 上恒为 `true`。

三个必须做对的点：

1. **不能用 `Local\` 命名空间** —— `Local\` 的 pipe 由创建进程
   拥有，SYSTEM 创建的 pipe 普通用户连不上。要用全局命名空间
   `\\.\pipe\`，靠 DACL 而非命名空间隔离。
2. **DACL 不能放行 Administrators/Everyone** —— 那等于任何管理员
   账号都能驱动这个 SYSTEM 管道，与 Linux「按 uid 白名单、不按组」
   的原则相反。只放行启动 helper 的那个用户 SID + SYSTEM。
   `oc-proto` 里有测试断言 SDDL 里不出现 `WD`/`BA`/`BU`/`AU`。
3. **`PIPE_REJECT_REMOTE_CLIENTS` 不能省** —— 否则 SMB 可能把 pipe
   暴露到网络上，任何能访问 445 端口的域内主机都能连。

⚠️ **`CreateNamedPipeW` 的第 8 个参数不能传 `NULL`。** 传 null 会让
pipe 用**默认 DACL**，整个提权通道的授权静默失效 —— 不报任何错，
只是「莫名其妙什么都能连」。这个 bug 真的写出来过，靠编译器的
参数个数不匹配（windows-sys 的签名是 8 个参数）才暴露出来。

**踩到的 Win32 细节**

| 坑 | 说明 |
|---|---|
| `PIPE_UNLIMITED_INSTANCES` 是 **255** 不是 `0xFFFFFFFF` | 手写常量编译器不报错，运行时才炸。所有 Win32 常量改为从 `windows-sys` 导入 |
| `ConvertSidToStringSidW` 返回 UTF-16 | 用 `from_utf8_lossy` 会得到乱码，必须 `from_utf16_lossy` |
| 该字符串必须 `LocalFree` 释放 | 不能靠 Rust drop —— 分配器不同（`LocalAlloc` vs Rust 的） |
| `securitydescriptorsize` 是 `*mut u32` 不是 `Option<&mut u32>` | windows-sys 对可选项不总是用 `Option` 包装 |
| `PSECURITY_DESCRIPTOR` 已经是 `*mut c_void` | 写成 `*mut PSECURITY_DESCRIPTOR` 就是二重指针 |
| edition 2024 下 `unsafe fn` 体内仍需显式 `unsafe {}` | `unsafe_op_in_unsafe_fn` 由警告变硬错误 |

**已知缺口**

- `helper-win` 的 `start_openconnect` 只做到协议校验，
  **spawn 与 stdio 转发行协议未实现**（返回明确错误，不是静默失败）。
- Windows pipe 没有 per-handle 读超时（`SO_RCVTIMEO` 无对应物）。
  要超时只能改 overlapped I/O + `WaitForSingleObject`。当前缓解靠
  helper 侧不阻塞，而不是靠超时。
- 未实现：服务化安装（`sc create`）、登出时 helper 退出、
  多用户会话切换。

#### 6.3.12 macOS 真实网关验证 ✅（本机实测通过）

**结论**：`Scripts/macos-tunnel-test.sh` 端到端连通 OpenWRT 上的
ocserv 网关，隧道建立、路由安装、目标可达、断开清理全部正常。

实测数据（2026-10-03，openconnect v9.21）：

| 项 | 实测值 |
|---|---|
| 网关 | `https://app.wthink.cn:24443` → `222.212.85.192` |
| 服务端实现 | OpenWRT + ocserv（`X-CSTP-Server-Name: OpenConnect VPN Server`，banner `Welcome to OpenWRT`） |
| 表单流程 | `username` → `password` → `webvpn` cookie → `CONNECT` |
| 分配地址 | `192.168.130.149/255.255.255.0` |
| 推送路由 | `172.10.0.0/16`（`X-CSTP-Split-Include`） |
| 接口 | `utun6`，MTU **1340**（与 `X-CSTP-MTU` 完全一致） |
| 路由安装 | `172.10 → 192.168.130.149 UGSc utun6` ✅ |
| **目标可达** | `ping 172.10.13.95` → 4/4，0% 丢包，ttl 63，avg 35ms ✅ |
| 断开清理 | 路由表无残留 ✅ |
| 证书 | 自签（`signer not found`），需 `pin-sha256` |
| DTLS | 握手失败（UDP 4443 出不去），自动回退 CSTP，**不影响连通** |

**vpnc-script 在 macOS 上可用** —— 曾担心它是 Linux 专用脚本会在
macOS 上装路由失败，实测证明 `route add` 正常工作。

##### 两个把验证脚本本身写错的教训

**①判定「隧道已建立」不能靠 grep 日志字符串**

最初写的是等 `Established tunnel|ESTABLISHED`。实测证明：隧道
明明通了（utun 拿到地址、路由装好、ping 通），脚本却报「60s 内未
建立隧道」并把一个**正常工作着的隧道**杀掉了。

用 `grep -a` 对二进制验证过 —— **`Established tunnel` 这个字符串在
openconnect 9.21 里根本不存在**。openconnect 建好 tun、跑完
vpnc-script 之后就静默进入主循环，不再打任何日志。

判定依据已改为**系统状态**：从日志解析 `X-CSTP-Address` → 该地址
是否出现在某个 utun 上 →（兜底）目标网段路由是否进表。日志字符串
既随版本变化，也会受翻译 catalog 影响，本来就不该作为判据。

**②不要用字符串切片改已有脚本**

修①时用 Python 按锚点切片替换，边界算错，把脚本后半段（成功输出、
路由表、ping、清理）整个吃掉，文件尾部只剩一个孤立的 `c`，
报 `line 175: c: command not found`。定位到锚点后重写整段才对。

##### 自签证书的实际行为（更正一个此前的错误说法）

此前称「未设 pin 时应用必然永久挂起」—— **这个说法对 App 是错的**。

`supervisor.rs` 用 `Stdio::piped()` 喂完密钥后立即 `drop(stdin)`，
所以 openconnect 在索要证书确认时拿到的是 **EOF**，
表现为连接失败并打印 `fgets (stdin): ...`，**不会挂死**。

真正的问题是 UX：用户看到的是一条看不懂的 I/O 错误，而不是
「是否信任此证书？」。`Profile::advanced::server_cert_pin` 的注释
写着「留空则首次连接时弹窗询问，确认后写入」，但这条路径从未被实现
—— openconnect 的交互式询问无法透传到 GUI。仍待补。

#### 6.3.13 未完成部分

| 项 | 状态 | 阻塞原因 |
|---|---|---|
| Linux polkit 实际授权验证 | 🔶 脚本已就绪 | 需 root + docker（跑 `ci/run-in-docker.sh`） |
| macOS XPC 端到端验证 | 🔶 代码+脚本齐备 | 需 Developer ID 签名（`Scripts/sign-macos.sh --team-id ...`）；或改走无签名的 LaunchDaemon+socket 路线（§6.5） |
| macOS 公证 | 🔶 脚本就绪 | 需 App Store Connect + Apple ID |
| ~~Windows pipe 编译~~ | ✅ `ci/check-windows.sh` 通过 | 无 |
| Windows DACL 授权行为 | 🔶 代码就绪 | 需 Windows 实机 |
| Windows openconnect spawn | ❌ 待写 | 同上 |
| ~~自签证书的 GUI 确认弹窗~~ | ✅ 已实现（§6.4） | 无 |
| 企业 CA 证书（`ca_file`）的 UI 入口 | ❌ 无入口 | 后端字段已就绪，但 UI 未暴露选择器；企业环境（内部 CA 签发）比自签更常见 |
| GUI 端到端（macOS） | 🔶 隧道侧已验证 | 特权通道需 Developer ID 签名（`SMAppService`） |

### 6.4 其他

| 项 | 状态 |
|---|---|
| 多连接 | 单连接互斥。AnyConnect 原生也不支持并发 |
| 自动重连 UI | openconnect 内建 `--reconnect-timeout`，状态机已能识别 `Reconnect`，但托盘未接 |
| 证书指纹确认 | `--servercert` 已支持，UI 确认弹窗未做 |
| 统计页 | `RX:`/`TX:` 已解析为 `Event::detail`，UI 未展示 |
| SSO/SAML | `--cookie-on-stdin` 通路已就绪，SAML 流程建议复用 `openconnect-saml` |
| Linux webkit2gtk | Tauri 依赖系统 webkit2gtk，个别精简发行版缺失 |
| 托盘图标 | 窗口已按 430×620（AnyConnect 尺寸）配置，托盘 API 未接 |
| 前端框架 | 零依赖静态 HTML（约 12KB）。复杂度上升前不引入构建链 |
| helper 日志转发 | 协议已预留 `Response::Log`，helper 侧未实现 |

## 7. 测试策略

| 层次 | 数量 | 说明 |
|---|---|---|
| 单元 | 119 | profile 往返 / 钥匙串全链路 / argv 构建与安全审计 / config 文件格式 / 状态机 / 授权决策 / 断开信号 / helper 客户端 / openconnect 定位 |
| 集成 | 17 | **真实 openconnect 输出**驱动的回放测试 |
| Swift | 12 | macOS helper 协议编解码（与 `src/ipc.rs` 形状锁定） |

fixture 由 mock AnyConnect gateway 采集（`docs/mock_gateway.py.txt`），
覆盖：认证成功（止于 CONNECT）、认证失败、分组值不存在。

集成测试锁定的不只是「解析对不对」，还有「分类对不对」——
例如认证成功但 CONNECT 失败必须是 `TunnelSetupFailed` 而非 `AuthRejected`，
否则 UI 会错误地弹出密码框。

`supervisor` 的测试用 shell 替身脚本（`tests/bin/*.sh`）替代 openconnect，
验证 stdin 确实收到密钥且 argv 不含密钥。

### 端到端示例（需先起 mock gateway）

```sh
python3 docs/mock_gateway.py &

# 基础链路
cargo run --example e2e_mock -- /path/to/mock.crt

# 加密私钥 + 口令只走 config 文件
cargo run --example e2e_cert -- <ca.crt> <cert.pem> <enc.key.pem> <passphrase>

# profile CRUD + 钥匙串 + argv 联动（不需要网络）
cargo run --example cmd_smoke

# helper 自检（不需要 root）
cargo run --manifest-path helper/Cargo.toml -- --selftest

# 跨连接 Stop（用长驻的 openconnect 替身）
OCGUI_ALLOWED_UIDS=$(id -u) \
  OCGUI_OPENCONNECT=$PWD/tests/bin/fake-openconnect.sh \
  ./helper/target/release/oc-gui-helper --serve /tmp/oc-gui-helper-$(id -u).sock &
OCGUI_HELPER_SOCKET=/tmp/oc-gui-helper-$(id -u).sock cargo run --example e2e_stop

# macOS helper（Swift）
swift build --package-path macos-helper
swift test  --package-path macos-helper

# macOS 特权通道状态探测（无需签名）
cargo run --example e2e_macos

# Windows 交叉类型检查（无需 Windows）
bash ci/check-windows.sh

# GUI client → helper → openconnect 全链路
cargo build --release --manifest-path helper/Cargo.toml
OCGUI_ALLOWED_UIDS=$(id -u) \
  ./helper/target/release/oc-gui-helper --serve /tmp/oc-gui-helper-$(id -u).sock &
cargo run --example e2e_helper -- <ca.crt>
```

### Linux 安装（需 root）

```sh
cargo build --release --manifest-path helper/Cargo.toml
sudo ./helper/install.sh --dry-run   # 先看要做什么
sudo ./helper/install.sh
sudo ./helper/install.sh --uninstall
```

GUI 侧的提权入口（应用内部调用等价于这条）：

```sh
pkexec /usr/libexec/oc-gui-helper --authorize $(id -u)
```

### Linux 特权边界回归（需 root）

```sh
# 容器（推荐）
docker build -f ci/Dockerfile -t oc-gui-ci src-tauri
docker run --rm --privileged oc-gui-ci

# 或直接在 root 的 Linux 机器上
sudo ./ci/privsep-test.sh
```

详见 §6.3.7。

### 建议的 CI 矩阵

| Runner | 覆盖 |
|---|---|
| Linux 容器（root + polkitd） | `ci/privsep-test.sh` 的 8 组断言 |
| macOS runner（签名） | `SMAppService` + XPC、keyring |
| Windows runner（MinGW 或交叉编译产物） | named pipe、Ctrl-Break、`ci/fetch-win-deps.sh` 产物 |

CI 里**必须**有「非 root 用户尝试连 root helper 必须失败」这条负向测试 ——
它是整个提权边界最关键的回归点，也是 `privsep-test.sh` 的核心。

### 复核中发现的安全缺口（已修）

`profile.advanced.extra_args` 的文档注释是「逃生舱：数组里的一切
**原样附加到命令行**」，而 `argv::build` 不对它做任何过滤。禁用参数
（`--script-tun` / `--csd-wrapper` / `--external-browser`）能否被挡住，
**完全取决于启动前有没有调 `validate_args`**。

实测结果：

| 通道 | 是否调 `validate_args` | 结果 |
|---|---|---|
| Helper（Linux `helper/src/main.rs`） | 是 | ✅ 被拦 |
| Helper（Windows `helper-win/src/main.rs`） | 是 | ✅ 被拦 |
| **Direct（`src/channel.rs`）** | **否** | ❌ 三个禁用参数全部穿过 |

也就是说同一个 profile，**走特权助手安全、走 Direct 不安全** ——
一个安全边界只守了一半。

Direct 通道原先只检查密钥泄漏（`audit_argv`），漏了参数合法性。已补上
同一份 `oc_proto::validate_args`，让两条通道行为一致，且该不变量只需
在一处实现。

新增测试 `direct_channel_rejects_the_same_args_as_helper`：先断言
`argv::build` 确实把禁用参数放进了 argv（否则测试无意义），再断言
`validate_args` 拒绝它 —— 明确记录「过滤发生在启动前而非构建期」。

顺带说明为什么 Direct 也要查：Direct 是 helper 不可用时的回落路径
（macOS 未签名时正是走这条），也就是**权限最低、最可能被忽略校验**
的那条路径。安全检查不该只写在「正常路径」上。

### 测试稳定性（实测）

并行跑 `cargo test --lib` **60 次零失败**。这个数字是修出来的，不是
本来就稳 —— 过程中发现并修掉两处真实的竞态：

| 竞态 | 现象 | 根因 | 修法 |
|---|---|---|---|
| 环境变量竞争 | 约 1/10 概率失败 | 测试 `set_var`/`remove_var` 改的是**进程级**状态，而 harness 默认并行。`socket_path_env_override_wins` 与 `linux_path_uses_run_directory` 互相看到对方的值 | 新增 `src/testenv.rs`：全局 `Mutex` + `ScopedEnv` RAII 守卫。**只有一把锁** —— 之前 `channel.rs` 有私有锁、`client.rs` 又一把，两把锁保护同一个全局状态等于没锁 |
| 共享临时目录竞争 | 40 次里 2 次失败 | `bad_passphrase_writes_nothing` 去数共享 `temp_dir()` 里 `oc-gui-oc-*` 的数量，而并行的 `passphrase_never_appears_in_arg` 正好在往同一目录写正常文件 | 抽出 `write_secure_in(dir, ...)`，测试传私有 `TempDir` |

第二条尤其值得记：`bad_passphrase_writes_nothing` 是一条**安全断言**
（口令校验失败不得在磁盘留下明文），一个偶发失败的测试会让人怀疑
安全性而不是怀疑测试 —— 这类 flaky 必须清零而不是重跑到过。

### 本机无法验证的部分

| 项 | 原因 |
|---|---|
| Linux polkit 授权端到端 | 需 root + docker（跑 `ci/run-in-docker.sh`） |
| macOS privileged XPC 端到端 | 需 Developer ID 签名（daemon + 客户端 + 脚本均已就绪） |
| Windows named pipe DACL 实际授权 | 需 Windows 环境（编译已由 `ci/check-windows.sh` 验证） |
| Windows `GenerateConsoleCtrlEvent` | 同上 |
| Windows `fetch-win-deps.sh` 交叉编译 | 需 MinGW |
| ~~真实 VPN 网关 + CSTP 隧道 up~~ | ✅ 已验证（见 §6.3.12，含 ping 与断开清理） |
| DTLS（UDP 4443） | 本机 UDP 出不去，仅验证了 CSTP 回退路径 |

建议 CI：Linux 容器（root，跑 polkit + `openconnect`）+ macOS runner（签名）+ Windows runner。

## 8. 下一步

三个原红项的当前状态：

| 项 | 状态 |
|---|---|
| §6.1 私钥口令 | ✅ 已解决（`--config=FILE`）。仅 `--mca-key-password` 遗留 |
| §6.2 Windows 断开 | ✅ 已解决（Ctrl-Break）。打包 wintun/vpnc-script 遗留 |
| §6.3 helper 授权 | 🔶 三平台均已落地：Linux（policy + 每用户 socket + 安装脚本 + 全链路验证）、macOS（XPC daemon + 客户端 + 签名脚本，待 Developer ID）、Windows（named pipe + DACL，交叉编译通过，待实机） |

按优先级：

1. **CI 里的 Linux root 负向测试** — 验证「非 root 用户连 root helper
   必须失败」，这是整个提权边界最关键的回归点
2. **Windows 打包 `wintun.dll` + `vpnc-script-win.js`** — 阻塞 Windows 发布
3. **macOS `SMAppService.daemon` + privileged XPC** — 需签名证书与公证
4. **GUI 侧接 helper**：连接页加「helper 状态」提示 + 「以管理员启动」按钮，
   把 `HelperHandle::probe` / `spawn_via_pkexec` 接到 `commands.rs`
5. **证书指纹确认弹窗 + 托盘图标** — 体验完整性
6. **真实网关验证** — 需一台可连的 VPN 服务器，重点验证 DTLS 与 vpnc-script
7. **SSO 集成** — 复用 `openconnect-saml`

### 已知不足（有意为之）

- `--mca-key-password` 拒绝启动而非静默处理：宁可让用户知情，也不把口令
  塞进 argv
- 私钥口令含换行/前导空格时拒绝启动：config 文件格式无法表达这些字符
- Linux helper 在无 root 时可用但所有连接都会被拒（开发模式便利）
- `--authorize` 只接受单个 uid，不支持一次授权多个用户。
  多用户场景下每个用户各自调用一次 pkexec —— 这是刻意的，
  避免出现「授权了 A，结果 B 也能用」的歧义
- `Channel::detect` 在 Linux 上 helper 不可用时回落到 Direct。
  不静默降级到「假装有权限」，但仍会尝试 spawn —— 失败后由
  `needs_privileged_helper()` 提示用户
- `privsep-test.sh` 的断言 6 只测「socket 属主可连」，未测「属主连上后
  能否让 helper 执行任意 argv」。后者由 §6.3.8 断言 7 覆盖
- helper 通道的状态判定已改为完整 Tracker（§6.3.7 的折中已不需要）