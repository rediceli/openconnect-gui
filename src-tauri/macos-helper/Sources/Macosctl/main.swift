import Foundation
import SharedProtocol
import XPCClient

/// Rust ↔ Swift 的行协议 CLI。
///
/// # 为什么是 CLI 而不是 Rust FFI
///
/// Tauri 的 GUI 是 Rust。XPC 只能从 Swift/ObjC 侧调用。写 ObjC FFI +
/// 桥接头来从 Rust 直接调，可行但脆弱（需要 ARC 桥接、块指针生命周期、
/// 异步队列管理），比重新实现 XPC 还糟。
///
/// 行协议边界的好处：
/// - 两端都保持原生实现
/// - 与 Linux 的 socket 协议对 GUI 完全一致（都是 `src/ipc.rs` 的 JSON）
/// - 可独立测试与调试
///
/// # 协议
///
/// stdin 每行一个 `WRequest` 的 JSON，stdout 每行一个 `WResponse`。
/// 与 Linux helper 的 Unix socket 协议同构。
///
/// ```sh
/// echo '{"cmd":"hello","version":1,"caller_uid":501}' | macosctl
/// ```
///
/// # 子命令
///
/// 除行协议外还有几个便于调试/自检的子命令：
/// - `register`  —— 注册 daemon，打印注册后的状态
/// - `status`   —— 只打印 daemon 注册状态
/// - `selftest` —— 不需要 XPC 的自检

// MARK: - 子命令

let args = CommandLine.arguments

func fail(_ message: String, code: Int32 = 2) -> Never {
    FileHandle.standardError.write(Data("macosctl: \(message)\n".utf8))
    exit(code)
}

if args.count > 1 {
    switch args[1] {
    case "register":
        // GUI 的「提权启动」按钮调这个。
        // 注册后若 requiresApproval，必须引导用户去系统设置批准 ——
        // SMAppService 不会自己弹密码框，这是 Apple 有意的设计。
        let state = HelperRegistration.shared.state
        if state == .notRegistered {
            do {
                let after = try HelperRegistration.shared.register()
                printResponse(.state(
                    state: describe(after),
                    cause: after == .requiresApproval
                        ? "请在「系统设置 → 通用 → 登录项」批准 OC GUI" : nil))
            } catch {
                fail(error.localizedDescription)
            }
        } else {
            printResponse(.state(state: describe(state), cause: nil))
        }
        exit(0)

    case "status":
        printResponse(.state(
            state: describe(HelperRegistration.shared.state),
            cause: nil))
        exit(0)

    case "selftest":
        selftest()
        exit(0)

    default:
        fail("未知子命令 \(args[1])；可用: register | status | selftest | <JSON 行协议>")
    }
}

// MARK: - 行协议模式

/// 把注册状态映射成 Rust 侧能识别的字符串。
///
/// `SMAppService.Status` 的 rawValue：
///   0 = notRegistered, 1 = enabled, 2 = requiresApproval, 3 = notFound
///
/// `notFound` 单独处理很重要：它表示 launchd 里没有这个 daemon ——
/// 与 `notRegistered`（App 从未注册过）是不同的用户动作。
func describe(_ s: HelperRegistration.State) -> String {
    switch s {
    case .notRegistered: return "not_registered"
    case .requiresApproval: return "requires_approval"
    case .registered: return "registered"
    case let .unknown(v):
        // rawValue 3 = notFound：plist 没被 embed 进 App bundle，
        // 或签名不匹配导致 launchd 拒载。这是最常见的配置错误，
        // 必须能被 Rust 侧区分出来并给出「重新安装/签名」提示。
        return v == "3" ? "not_found" : "unknown:\(v)"
    }
}

func printResponse(_ r: WResponse) {
    if let d = try? JSONEncoder().encode(r) {
        print(String(decoding: d, as: UTF8.self))
    }
}

// 连接一次，失败时明确告知 —— Rust 侧会据此引导用户
let client = XPCClient.shared

// 先握手：把「daemon 未注册」这类问题在协议层说清楚，
// 而不是让 Rust 去猜 NSError 的本地化文本。
do {
    let hello = try client.hello()
    guard case let .ready(version, _, _) = hello else {
        fail("helper 握手返回了非 ready")
    }
    guard version == OcProtocol.version else {
        printResponse(.failed(error: .protocolMismatch(
            expected: OcProtocol.version, got: version)))
        exit(1)
    }
} catch let e as XPCClientError {
    switch e {
    case .timeout:
        printResponse(.failed(error: .internalError(
            message: "helper 无响应（可能未注册或已崩溃）")))
    default:
        printResponse(.failed(error: .internalError(
            message: e.localizedDescription)))
    }
    exit(1)
} catch {
    printResponse(.failed(error: .internalError(message: "\(error)")))
    exit(1)
}

// 转发 stdin 的每一行
let stdinData = FileHandle.standardInput.readDataToEndOfFile()
let text = String(decoding: stdinData, as: UTF8.self)

for line in text.split(separator: "\n") {
    let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.isEmpty { continue }

    guard let data = trimmed.data(using: .utf8),
        let req = try? JSONDecoder().decode(WRequest.self, from: data)
    else {
        printResponse(.failed(error: .internalError(message: "无法解析: \(trimmed)")))
        continue
    }

    do {
        printResponse(try client.send(req))
    } catch let e as XPCClientError {
        printResponse(.failed(error: .internalError(message: e.localizedDescription)))
    } catch {
        printResponse(.failed(error: .internalError(message: "\(error)")))
    }
}

// MARK: - 自检

func selftest() {
    // 协议往返
    let req = WRequest.hello(version: OcProtocol.version, callerUID: 501)
    guard let d = try? JSONEncoder().encode(req),
        let back = try? JSONDecoder().decode(WRequest.self, from: d),
        case .hello(let v, let uid) = back, v == 1, uid == 501
    else {
        FileHandle.standardError.write(Data("selftest 协议往返失败\n".utf8))
        exit(1)
    }

    // 密钥必须带 kind 标签
    let pw = try! JSONEncoder().encode([WStdinSecret.password("x")])
    let ck = try! JSONEncoder().encode([WStdinSecret.cookie("x")])
    guard pw != ck else {
        FileHandle.standardError.write(Data("selftest: Password/Cookie 编码冲突\n".utf8))
        exit(1)
    }

    // Team ID 必须存在，否则 helper 会拒绝所有连接
    if Bundle.main.object(forInfoDictionaryKey: "OcGuiTeamID") == nil,
        ProcessInfo.processInfo.environment["OCGUI_TEAM_ID"] == nil {
        FileHandle.standardError.write(Data("""
        selftest 通过，但未检测到 Team ID。
        helper 会拒绝所有连接 —— 请用 Scripts/sign-macos.sh 构建。

        """.utf8))
        exit(1)
    }

    print("selftest ok")
}
