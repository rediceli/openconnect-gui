import Foundation

/// App ↔ privileged helper 的共享协议。
///
/// 与 Linux 版 `src/ipc.rs` 的 JSON 协议一一对应，便于两端行为一致。
/// 这里用 Codable + `JSONSerialization` 而不是 XPC 支持的 NSSecureCoding ——
/// 协议载荷结构简单，且我们已经在 Rust 侧固定了 JSON 形状。

public enum OcProtocol {
    /// 必须与 Rust 侧 `PROTOCOL_VERSION` 一致
    public static let version: UInt16 = 1

    /// Mach service 名。必须与 launchd plist 的 ServiceLabel 一致。
    public static let machService = "io.github.rediceli.ocgui.helper"

    /// 唯一允许执行的程序
    public static let allowedProgram = "openconnect"
}

// MARK: - 请求

public enum WRequest: Codable {
    case hello(version: UInt16, callerUID: UInt32)
    case start(args: [String], server: String, stdinSecrets: [WStdinSecret])
    case stop
    case status
    case shutdown

    private enum CodingKeys: String, CodingKey { case cmd, version, callerUID, args, server, stdinSecrets }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .hello(version, uid):
            try c.encode("hello", forKey: .cmd)
            try c.encode(version, forKey: .version)
            try c.encode(uid, forKey: .callerUID)
        case let .start(args, server, secrets):
            try c.encode("start", forKey: .cmd)
            try c.encode(args, forKey: .args)
            try c.encode(server, forKey: .server)
            try c.encode(secrets, forKey: .stdinSecrets)
        case .stop:
            try c.encode("stop", forKey: .cmd)
        case .status:
            try c.encode("status", forKey: .cmd)
        case .shutdown:
            try c.encode("shutdown", forKey: .cmd)
        }
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let cmd = try c.decode(String.self, forKey: .cmd)
        switch cmd {
        case "hello":
            self = .hello(
                version: try c.decode(UInt16.self, forKey: .version),
                callerUID: try c.decode(UInt32.self, forKey: .callerUID))
        case "start":
            self = .start(
                args: try c.decode([String].self, forKey: .args),
                server: try c.decode(String.self, forKey: .server),
                stdinSecrets: try c.decode([WStdinSecret].self, forKey: .stdinSecrets))
        case "stop": self = .stop
        case "status": self = .status
        case "shutdown": self = .shutdown
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .cmd, in: c,
                debugDescription: "未知命令: \(cmd)")
        }
    }
}

public enum WStdinSecret: Codable {
    case password(String)
    case cookie(String)

    private enum CodingKeys: String, CodingKey { case kind, value }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .password(v): try c.encode("password", forKey: .kind); try c.encode(v, forKey: .value)
        case let .cookie(v): try c.encode("cookie", forKey: .kind); try c.encode(v, forKey: .value)
        }
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(String.self, forKey: .kind)
        let value = try c.decode(String.self, forKey: .value)
        switch kind {
        case "password": self = .password(value)
        case "cookie": self = .cookie(value)
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .kind, in: c, debugDescription: "未知密钥种类: \(kind)")
        }
    }
}

// MARK: - 响应

public enum WResponse: Codable {
    case ready(version: UInt16, authorized: Bool, connected: Bool)
    case started(pid: UInt32)
    case log(line: String)
    case state(state: String, cause: String?)
    case exited(code: Int32?)
    case failed(error: WError)
    case status(connected: Bool, pid: UInt32?)

    private enum CodingKeys: String, CodingKey {
        case event, version, authorized, connected, pid, line, state, cause, code, error
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .ready(v, a, conn):
            try c.encode("ready", forKey: .event)
            try c.encode(v, forKey: .version)
            try c.encode(a, forKey: .authorized)
            try c.encode(conn, forKey: .connected)
        case let .started(pid):
            try c.encode("started", forKey: .event); try c.encode(pid, forKey: .pid)
        case let .log(line):
            try c.encode("log", forKey: .event); try c.encode(line, forKey: .line)
        case let .state(s, cause):
            try c.encode("state", forKey: .event)
            try c.encode(s, forKey: .state)
            try c.encode(cause, forKey: .cause)
        case let .exited(code):
            try c.encode("exited", forKey: .event); try c.encode(code, forKey: .code)
        case let .failed(error):
            try c.encode("failed", forKey: .event); try c.encode(error, forKey: .error)
        case let .status(conn, pid):
            try c.encode("status", forKey: .event)
            try c.encode(conn, forKey: .connected)
            try c.encode(pid, forKey: .pid)
        }
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let event = try c.decode(String.self, forKey: .event)
        switch event {
        case "ready":
            self = .ready(
                version: try c.decode(UInt16.self, forKey: .version),
                authorized: try c.decode(Bool.self, forKey: .authorized),
                connected: try c.decode(Bool.self, forKey: .connected))
        case "started":
            self = .started(pid: try c.decode(UInt32.self, forKey: .pid))
        case "log":
            self = .log(line: try c.decode(String.self, forKey: .line))
        case "state":
            self = .state(
                state: try c.decode(String.self, forKey: .state),
                cause: try c.decodeIfPresent(String.self, forKey: .cause))
        case "exited":
            self = .exited(code: try c.decodeIfPresent(Int32.self, forKey: .code))
        case "failed":
            self = .failed(error: try c.decode(WError.self, forKey: .error))
        case "status":
            self = .status(
                connected: try c.decode(Bool.self, forKey: .connected),
                pid: try c.decodeIfPresent(UInt32.self, forKey: .pid))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .event, in: c, debugDescription: "未知事件: \(event)")
        }
    }
}

public enum WError: Codable {
    case protocolMismatch(expected: UInt16, got: UInt16)
    case unauthorized(detail: String)
    case rejected(reason: String)
    case openconnectMissing
    case alreadyConnected
    case notConnected
    case internalError(message: String)

    private enum CodingKeys: String, CodingKey {
        case kind, expected, got, detail, reason, message
    }

    public var messageKey: String {
        switch self {
        case .protocolMismatch: return "helper.error.protocol_mismatch"
        case .unauthorized: return "helper.error.unauthorized"
        case .rejected: return "helper.error.rejected"
        case .openconnectMissing: return "helper.error.openconnect_missing"
        case .alreadyConnected: return "helper.error.already_connected"
        case .notConnected: return "helper.error.not_connected"
        case .internalError: return "helper.error.internal"
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .protocolMismatch(e, g):
            try c.encode("protocol_mismatch", forKey: .kind)
            try c.encode(e, forKey: .expected); try c.encode(g, forKey: .got)
        case let .unauthorized(d):
            try c.encode("unauthorized", forKey: .kind); try c.encode(d, forKey: .detail)
        case let .rejected(r):
            try c.encode("rejected", forKey: .kind); try c.encode(r, forKey: .reason)
        case .openconnectMissing:
            try c.encode("openconnect_missing", forKey: .kind)
        case .alreadyConnected:
            try c.encode("already_connected", forKey: .kind)
        case .notConnected:
            try c.encode("not_connected", forKey: .kind)
        case let .internalError(m):
            try c.encode("internal", forKey: .kind); try c.encode(m, forKey: .message)
        }
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(String.self, forKey: .kind)
        switch kind {
        case "protocol_mismatch":
            self = .protocolMismatch(
                expected: try c.decode(UInt16.self, forKey: .expected),
                got: try c.decode(UInt16.self, forKey: .got))
        case "unauthorized":
            self = .unauthorized(detail: try c.decode(String.self, forKey: .detail))
        case "rejected":
            self = .rejected(reason: try c.decode(String.self, forKey: .reason))
        case "openconnect_missing": self = .openconnectMissing
        case "already_connected": self = .alreadyConnected
        case "not_connected": self = .notConnected
        case "internal":
            self = .internalError(message: try c.decode(String.self, forKey: .message))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .kind, in: c, debugDescription: "未知错误: \(kind)")
        }
    }
}
