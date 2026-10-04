import Foundation
import ServiceManagement
import SharedProtocol

/// App 侧调用 privileged helper 的客户端。
///
/// # 为什么需要一个 CLI 中间层
///
/// Tauri 的 GUI 是 Rust。Swift 的 XPC 代码无法直接被 Rust 调用
/// （除非写 ObjC FFI + 桥接头，比重新实现 XPC 还脆弱）。
///
/// 因此边界定在**行协议**：Rust spawn `macosctl`，双方说
/// `src/ipc.rs` 那套 JSON。好处是两端都保持原生实现，
/// 且 Linux 的 socket 协议与 macOS 的 XPC 协议对 GUI 完全一致。
///
/// # 注册 daemon
///
/// ```swift
/// let status = try HelperRegistration.shared.register()
/// switch status {
/// case .registered: break
/// case .requiresApproval:
///     // 必须引导用户去「系统设置 → 通用 → 登录项」批准
///     // SMAppService **不会**自己弹密码框，这是 Apple 有意的设计
/// case .failed(let e): throw e
/// }
/// ```
public final class XPCClient {
    public static let shared = XPCClient()

    private var connection: NSXPCConnection?
    private let queue = DispatchQueue(label: "com.wthink.wthinkvpn.xpc")

    private init() {}

    // MARK: - 连接

    /// 建立（或复用）到 helper 的 privileged XPC 连接。
    @discardableResult
    public func connect() throws -> NSXPCConnection {
        if let c = connection { return c }

        let c = NSXPCConnection(machServiceName: WthinkProtocol.machService)
        c.remoteObjectInterface = NSXPCInterface(with: WthinkHelperClientProtocol.self)

        // helper 侧会做调用方校验；这里也应验证反向，
        // 以防有人用同名 Mach service 冒充 helper。
        // 签名：Swift 的 NSXPCConnection 只接受 designated requirement 字符串。
        // ⚠️ 没有 `asRequirementType:` 参数（那是 ObjC 的旧签名）——
        //    传了会得到 "extra argument 'asRequirementType' in call"。
        c.setCodeSigningRequirement(Self.helperRequirement())
        c.interruptionHandler = { [weak self] in
            self?.connection = nil
        }
        c.invalidationHandler = { [weak self] in
            self?.connection = nil
        }
        c.resume()
        connection = c
        return c
    }

    public func disconnect() {
        connection?.invalidate()
        connection = nil
    }

    /// 验证对端是「同一 Team ID 签名的 helper」。
    ///
    /// Mach service 名是公开的，理论上任何人都能注册同名服务。
    /// 因此 App 必须反向校验，否则会把自己的密码送给攻击者的 helper。
    private static func helperRequirement() -> String {
        let team = Bundle.main.object(forInfoDictionaryKey: "WthinkVPNTeamID") as? String ?? ""
        return """
        anchor apple generic \
        and certificate leaf[subject.OU] = "\(team)" \
        and identifier "\(HelperInfo.bundleID)"
        """
    }

    // MARK: - 请求

    /// 发一个请求并等一个应答。
    public func send(_ request: WRequest, timeout: TimeInterval = 15) throws -> WResponse {
        let c = try connect()
        let proxy = try c.remoteObjectProxyWithErrorHandler { err in
            NSLog("XPC 错误: \(err)")
        } as? WthinkHelperClientProtocol
        guard let p = proxy else {
            throw XPCClientError.notConnected
        }

        let payload = try JSONEncoder().encode(request)
        let sem = DispatchSemaphore(value: 0)
        var result: WResponse?
        var failure: Error?

        p.send(payload) { data in
            if let data { result = try? JSONDecoder().decode(WResponse.self, from: data) }
            sem.signal()
        }

        // XPC 的 reply 闭包不保证一定被调用（helper 崩溃/被杀时不调用），
        // 因此必须有超时 —— 否则 GUI 会永久卡在「连接中」。
        if sem.wait(timeout: .now() + timeout) == .timedOut {
            throw XPCClientError.timeout
        }
        if let failure { throw failure }
        guard let r = result else { throw XPCClientError.noReply }
        return r
    }

    /// 握手。版本不匹配会抛错。
    public func hello() throws -> WResponse {
        try send(.hello(version: WthinkProtocol.version, callerUID: UInt32(getuid())))
    }

    public func start(
        args: [String], server: String, secrets: [WStdinSecret]
    ) throws -> WResponse {
        try send(.start(args: args, server: server, stdinSecrets: secrets))
    }

    public func stop() throws -> WResponse {
        try send(.stop)
    }

    public func status() throws -> WResponse {
        try send(.status)
    }
}

public enum XPCClientError: Error, LocalizedError {
    case notConnected
    case timeout
    case noReply
    case notRegistered
    case needsApproval
    case registrationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .notConnected: return "无法连接特权助手"
        case .timeout: return "特权助手无响应（可能已崩溃）"
        case .noReply: return "特权助手返回了空应答"
        case .notRegistered: return "特权助手未注册，请先在设置中启用"
        case .needsApproval: return "请在「系统设置 → 通用 → 登录项」批准 WthinkVPN"
        case let .registrationFailed(m): return "注册特权助手失败：\(m)"
        }
    }
}

/// helper 侧导出的接口（App 侧看到的形状）。
@objc(WthinkHelperClientProtocol)
protocol WthinkHelperClientProtocol {
    func send(_ payload: Data, reply: @escaping (Data?) -> Void)
}

// MARK: - daemon 注册

/// `SMAppService.daemon` 的封装。
///
/// # 用户体验要点
///
/// `register()` **不会弹密码框**。macOS 13+ 的设计是：
/// App 请求注册 → 系统在「登录项」里放一个待批准项 →
/// 用户手动打开开关。若 App 自己弹密码框反而违反 Apple 的预期。
///
/// 因此 GUI 必须能表达这三种状态：未注册 / 待批准 / 已就绪。
public final class HelperRegistration {
    public static let shared = HelperRegistration()

    private let service = SMAppService.daemon(plistName: HelperInfo.daemonPlistName)

    public enum State: Equatable {
        case notRegistered
        case requiresApproval
        case registered
        case unknown(String)
    }

    public var state: State {
        switch service.status {
        case .notRegistered: return .notRegistered
        case .requiresApproval: return .requiresApproval
        case .enabled: return .registered
        default: return .unknown("\(service.status.rawValue)")
        }
    }

    /// 注册 daemon。返回注册后的状态。
    @discardableResult
    public func register() throws -> State {
        do {
            try service.register()
        } catch {
            throw XPCClientError.registrationFailed(error.localizedDescription)
        }
        return state
    }

    public func unregister() throws {
        try service.unregister()
    }
}

enum HelperInfo {
    static let daemonPlistName = "io.wthink.wthinkvpn.helper"
    static let bundleID = "com.wthink.wthinkvpn"
}