# OC GUI

基于 [OpenConnect](https://www.infradead.org/openconnect/) 的轻量桌面 VPN 客户端，
兼容 Cisco AnyConnect 协议。

单文件前端（无构建链）+ Rust/Tauri 2 后端，macOS `.app` 约 13 MiB。

## 特性

- **三平台特权通道** —— 提权逻辑各自落地，而不是靠 sudo/pkexec 一套通吃
  - Linux：polkit + 每用户 socket（`0600`）+ 运行时 uid 复检
  - macOS：**免签名** —— LaunchDaemon + 每用户 socket（主路径）；
    另可选 XPC + `SMAppService`，需要 Developer ID 证书
  - Windows：named pipe + DACL（只放行当前用户 SID + SYSTEM）
- **凭据不进 argv** —— 密码与 cookie 一律走 `--passwd-on-stdin`；私钥口令经 `0600` 配置文件
- **服务器证书 TOFU** —— 首次连接展示证书指纹供确认，之后精确 pin 匹配
- **系统钥匙串** —— 密码存 Keychain / Credential Manager / Secret Service，profile 文件里只有标记
- **profile 管理** —— TOML 存储，支持证书、令牌模式、分组下拉等

## 快速开始

```bash
brew install openconnect          # 或对应平台的包
cargo tauri dev                   # 开发
cargo tauri build --bundles app   # 打包 macOS .app
```

连接需要管理员权限（创建 tun 设备）。**macOS 不需要代码签名**：

```bash
sudo ./src-tauri/Scripts/install-macos-daemon.sh   # 授权当前用户
sudo ./src-tauri/Scripts/uninstall-macos-daemon.sh # 卸载
```

Linux 用 polkit（`pkexec`，在 GUI 里点「提权启动」触发）。
两条路的授权模型一致：每个授权 uid 一个 socket，权限 `0600` +
属主该 uid，再加运行时 uid 复检。详见
[设计文档 §6.3.13](docs/P1-DESIGN.md)。

想只验证隧道而不安装助手：

```bash
sudo ./src-tauri/Scripts/macos-tunnel-test.sh <account.txt>
```

## 仓库结构

```
src-tauri/
├── src/                  GUI 主程序（Tauri 命令、channel、状态机）
├── src/ipc/              GUI 侧特权通道客户端
├── crates/oc-proto/      GUI ↔ helper 的协议 + 授权（无 Tauri 依赖）
├── helper/               Linux 特权助手
├── helper-win/           Windows 特权助手
├── macos-helper/         macOS XPC daemon + 客户端（Swift Package）
├── ci/                   交叉检查与 Linux 特权边界回归脚本
├── Scripts/              签名打包、隧道验证
└── dist/../dist/index.html  前端源码（单文件，直接由 Tauri 加载）
docs/P1-DESIGN.md         架构、安全模型、平台踩坑记录
```

`oc-proto` 单独拆出来是为了让 helper 不必依赖 Tauri —— 否则
`tauri-build` 的 Windows 分支需要 `llvm-rc`，开发机上无法对 Windows
代码做类型检查。`ci/check-windows.sh` 解决了这个问题。

## 开发

```bash
cargo test                # Rust 单元 + 集成
cargo clippy --all-targets
swift test --package-path src-tauri/macos-helper
bash src-tauri/ci/check-windows.sh    # Windows 交叉类型检查（无需 Windows）
```

## 安全性

提权边界只允许执行 `openconnect`，并拒绝 `--script-tun`、`--csd-wrapper`、
`--external-browser`。授权判定永远不依赖请求参数。这几条都有测试锁定，
详见 `docs/P1-DESIGN.md`。

## 许可证

[Apache License 2.0](LICENSE) —— 含明确的专利授权。

OC GUI **不链接也不打包** OpenConnect，而是将其作为独立进程启动。
OpenConnect 本身是 LGPL-2.1；由于是分离进程而非链接，本项目是
Apache-2.0 下的独立作品，并非 OpenConnect 的衍生作品。详见 [NOTICE](NOTICE)。

本项目与 Cisco 无隶属关系，不受其认可。AnyConnect 与 Cisco 是
Cisco Systems, Inc. 的商标。