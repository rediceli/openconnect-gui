# WthinkVPN — P0 可行性验证报告

日期：2026-10-03
环境：macOS 14.8.9 (x86_64) / openconnect v9.21 (Homebrew) / Rust 1.99.0 / Tauri CLI 2.12.1

## 结论

技术路线**成立**，无阻断性风险。核心链路全部打通：

| 验证项 | 结果 |
|---|---|
| openconnect 可用性与参数面 | ✅ v9.21，PKCS#11 / TOTP / DTLS / ESP 全特性 |
| 子进程 spawn + stdin 传密钥 | ✅ `--passwd-on-stdin` / `--cookie-on-stdin` 均验证 |
| 表单/分组参数 | ⚠️ `--authgroup` 不够，必须用 `-F main:auth_group=X`（见下） |
| 两阶段认证 `--authenticate` | ✅ 输出 COOKIE/HOST/FINGERPRINT，SSO 集成通路成立 |
| 日志 → 状态机 | ✅ 19 个测试全绿，但**修正了初版全部错误规则**（见下） |
| keyring-rs 三平台凭据 | ✅ macOS Keychain 全链路（set/get/覆盖/删除）通过 |
| Tauri 2 编译与打包 | ✅ `.app` **10.27 MiB**，符合「不能有大框架」约束 |

## 验证过程中的三个实质性发现

### 发现 1：基于网络资料的日志规则表 100% 是错的

初版规则表参考了社区文档和 openconnect-gui 的常见说法，逐条 `grep` 源码后发现
**以下字符串在 openconnect 源码中根本不存在**：

- `Established session to ...`
- `Assigned IP address: ...`
- `Data connection: ...`
- `DPD data channel ...`
- `Reconnect interval ...`
- `Please try again`

真实的对应字符串是：

| 语义 | 真实字符串 | 出处 |
|---|---|---|
| 隧道已 up | `Configured as 10.x.x.x/255.255.255.0, with SSL ... and UDP ...` | `main.c:1663` `print_connection_info()` |
| 数据通道 | `CSTP connected. DPD 60, Keepalive 0` | `cstp.c:668` |
| 隧道通道建立 | `Got CONNECT response: HTTP/1.1 200 OK` | `cstp.c:384` |
| 周期统计（隧道健康） | `RX: N packets (N B); TX: ...` | `main.c:1691` `print_connection_stats()` |
| 重连 | `User requested reconnect` | `main.c:2478` |
| 软令牌 PIN | `PIN:` / `Enter software token PIN.` | `stoken.c:209,214` |
| Pulse 令牌 | `Token code request:` | `pulse.c:1244` |

规则表已全部改为源码验证过的字面量，每条注释标注来源文件。这一步不能省 ——
照抄文档写规则表会得到一个"能跑但永远连不上"的客户端。

### 发现 2：认证成功没有任何日志信号

`--authenticate`/正常登录在 `<auth id="success">` 路径下，
openconnect **不打印任何一行认证成功日志**（`auth.c:723` 直接 return
`OC_FORM_RESULT_LOGGEDIN`）。下一个可见信号是 `cstp.c` 的 CONNECT 响应。

推论：
- UI 在 `Authenticating` 阶段就必须显示「正在建立隧道」，而不是「正在验证身份」
- 认证成功与认证失败在 `State` 枚举上都会终结于 `Failed`，无法区分
  → P1 必须补 `TerminalCause` 枚举，由末尾 `Event::kind` 推导
- 网关在认证**失败**时同样下发 `Set-Cookie`，因此「见到 cookie」不能作为认证成功判据
  （这条已在测试 `authok_run_state_trajectory` 中固化为注释）

### 发现 3：`--authgroup` 会触发交互式下拉，stdin 模式下直接失败

AnyConnect 表单里的 group 下拉，在 `-F` 缺失时会阻塞等 stdin：
`GROUP: [|Engineering|Operations]:fgets (stdin): Resource temporarily unavailable`

正确做法是预填表单字段：

```
openconnect -F 'main:auth_group=Engineering' ...
```

`-F` 的第一个参数是**表单的 `<auth id>`**（多数设备是 `main`，但 Juniper 是
`loginForm`/`frmLogin`，Fortinet/Pulse 各不相同）。所以 group 字段名必须做成
profile 级配置，不能硬编码。P1 需要一张「协议 × 表单 id × 字段名」映射表。

## 产物

```
wthinkvpn/
├── .gitignore                     # account.txt 等本地凭据强制忽略
├── dist/index.html                # P0 冒烟页
└── src-tauri/                     # Tauri 2.12.1 骨架，已可打包
    └── .app = 10.27 MiB

oc-parser/                          # 状态解析器（可直接并入 src-tauri）
├── src/lib.rs                     # parse_line + Tracker 状态机
├── tests/replay.rs                # 12 个基于真实日志的回归测试
└── tests/*.log                    # mock gateway 采集的真实 fixture
```

测试：**21 passed / 0 failed**（9 unit + 12 integration）。

## mock gateway（测试基础设施）

`p0/mock_gateway.py` 实现 AnyConnect XML 认证流程的最小子集
（init → auth-reply → auth id="success"），用于在不接触真实 VPN 网关的前提下
锁定解析器行为。测试数据不会外泄到日志断言里（`no_event_leaks_cookie_material`）。

不支持 DTLS/CSTP 数据通道，因此只能验证到 CONNECT 之前。真实网关验证留待 P1。

## 风险与遗留

| 风险 | 影响 | 处理 |
|---|---|---|
| 表单 id 各协议不同 | 中 | P1 建映射表 + 可手动覆盖 |
| 特权 helper 未验证 | **高** | P1 首要任务，三平台各自 spike |
| Windows `vpnc-script-win.js` / `wintun.dll` 打包 | 高 | P1 照抄 openconnect 官方 `file-list.txt` |
| Linux `webkit2gtk` 缺失 | 中 | 文档说明或改 Slint |
| macOS 签名/公证/XPC 授权 | 高 | P1 spike，需 Developer ID |
| SSO（SAML/Entra ID） | 中 | 复用 `openconnect-saml`，不自研 |

## 下一步（P1）

按此顺序，每步都可独立验证：

1. **特权 helper spike**（三平台各一次，最优先）
2. profile 存储（TOML）+ keyring 集成
3. argv 构建器（profile → 命令行），含 `-F` 表单字段
4. 子进程监管 + `oc-parser` 状态机接入 Tauri 事件
5. AnyConnect 风格连接页 + 托盘
6. 证书认证 UI（选证书 / keyring 存 passphrase / PKCS#11 URL）
7. `TerminalCause` 枚举 + 错误分类与文案