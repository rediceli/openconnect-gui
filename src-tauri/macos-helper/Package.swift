// swift-tools-version: 5.9
import PackageDescription

// OC GUI macOS 特权助手
//
// # 为什么是 Swift 而不是复用 Rust helper
//
// macOS 的特权模型与 Linux 完全不同：
// - Linux：polkit + pkexec，命令行驱动，root helper 是独立进程
// - macOS：**privileged XPC**，App 与 Helper 必须由 launchd 加载，
//   通过 Mach service 通信，且**必须共享 Team ID + 签名**
//
// XPC 的接口是 NSXPCConnection，不是 socket + JSON。把 Rust helper
// 硬套过来要自己实现 Mach service 与 SecCode 签名校验 —— 那是重新
// 发明 XPC，而且更难做对（Apple 审核也期望 native 实现）。
//
// 但**协议形状**（`src/ipc.rs` 的 JSON）保持一致，由
// `Tests/SharedProtocolTests` 锁定字段名。
//
// # 签名要求（缺一不可）
//
// 1. Developer ID Application（App 与 Helper 同一 Team ID）
// 2. Hardened Runtime
// 3. App 与 Helper 都要 notarize
// 4. 首次注册 daemon 后，用户需在「系统设置 → 登录项」手动批准
//
// # 构建
//
//   Scripts/sign-macos.sh            # 注入 Team ID、签名、embed
//   swift build -c release

let package = Package(
    name: "OcGuiHelper",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "oc-gui-helper", targets: ["Helper"]),
        // Rust GUI 与 Swift 之间的边界：行协议 CLI
        .executable(name: "macosctl", targets: ["Macosctl"]),
        .library(name: "SharedProtocol", targets: ["SharedProtocol"]),
        .library(name: "XPCClient", targets: ["XPCClient"]),
    ],
    targets: [
        .target(
            name: "SharedProtocol",
            resources: [.copy("Resources/io.github.rediceli.ocgui.helper.plist")]
        ),
        // App 侧 XPC 客户端
        .target(name: "XPCClient", dependencies: ["SharedProtocol"]),

        // CLI 包装：把行协议翻译成 XPC 调用
        .executableTarget(
            name: "Macosctl",
            dependencies: ["SharedProtocol", "XPCClient"]
        ),

        // ⚠️ 不要试图用 `-sectcreate __TEXT __info_plist` 把 Info.plist
        // 编进二进制：SwiftPM 的 `linkerSettings.unsafeFlags` 传给的是
        // **swiftc** 而不是 `ld`，会得到 `error: unknown argument:
        // '-sectcreate'`。
        //
        // Team ID 改由 launchd plist 的 `EnvironmentVariables` 注入
        // （见 Sources/SharedProtocol/Resources/*.plist 与
        // Scripts/sign-macos.sh）。launchd 本来就是加载 daemon 的，
        // 机制天然匹配，排查时 `launchctl print` 也能看到。
        .executableTarget(name: "Helper", dependencies: ["SharedProtocol"]),
        .testTarget(name: "SharedProtocolTests", dependencies: ["SharedProtocol"]),
    ]
)
