# Windows 运行时依赖

此目录在 Linux/macOS 开发时为空。Windows 安装包需要的文件由以下脚本生成：

```sh
./ci/fetch-win-deps.sh
```

生成的内容（会一并打进安装包）：

| 文件 | 来源 | 缺失后果 |
|---|---|---|
| `openconnect.exe` | MinGW 交叉编译 openconnect master | 无法连接 |
| `*.dll` | openconnect.exe 的传递依赖（gnutls/libxml2/zlib/lz4/stoken/p11-kit） | 启动即失败 |
| `wintun.dll` | wintun.net，SHA256 与上游 `Makefile.am` 一致 | `Failed to create TUN device` |
| `vpnc-script-win.js` | vpnc-scripts master，文件头记录来源提交 | 路由/DNS 不配置 |
| `MANIFEST.txt` | 本脚本生成 | 无法审计装了什么 |

⚠️ 提交 `win-deps/` 时只应包含本文件。真实二进制走 release artifact 或
构建时生成，不入库。
