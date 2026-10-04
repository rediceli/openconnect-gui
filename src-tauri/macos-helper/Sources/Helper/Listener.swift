import Foundation
import Security
import SharedProtocol

/// daemon 入口。
///
/// 由 launchd 加载（`Contents/Library/LaunchDaemons/*.plist`，
/// `RunAtLoad=true`），以 root 运行。
///
/// 注册流程在 App 侧：
/// ```swift
/// try SMAppService.daemon(plistName: "io.github.rediceli.ocgui.helper").register()
/// ```
/// 注册后用户需在「系统设置 → 通用 → 登录项」手动批准 —— 这是
/// Apple 有意的设计，daemon 不会弹自己的密码框。
enum Entry {
    static func run() {
        guard getuid() == 0 else {
            FileHandle.standardError.write(Data("helper 必须以 root 运行\n".utf8))
            exit(2)
        }

        // Team ID 未注入 ⇒ 拒绝所有连接。这是配置错误，不可降级。
        guard let teamID = Config.teamID else {
            FileHandle.standardError.write(Data("""
            致命错误：OcGuiTeamID 未注入 Info.plist。
            helper 将拒绝所有连接。
            请用 Scripts/sign-macos.sh 构建（它会注入 Team ID）。

            """.utf8))
            exit(2)
        }

        let listener = NSXPCListener(machServiceName: Config.machService)
        let delegate = ConnectionListener()
        listener.delegate = delegate
        listener.resume()

        FileHandle.standardError.write(Data("""
        OC GUI helper 已就绪
          Mach service: \(Config.machService)
          Team ID: \(teamID)
          uid=\(getuid())

        """.utf8))

        dispatchMain()
    }
}

// MARK: - 会话状态

/// 整个 daemon 一个隧道（与 Linux helper、AnyConnect 原生行为一致）。
final class Session {
    let pid: pid_t
    let stop = DispatchSemaphore(value: 0)
    var process: Process?

    init(pid: pid_t, process: Process) {
        self.pid = pid
        self.process = process
    }
}

// MARK: - XPC 接口

/// App 侧调用的接口。协议与 `WRequest`/`WResponse` 一一对应。
@objc(OcHelperProtocol)
protocol OcHelperProtocol {
    func send(_ payload: Data, reply: @escaping (Data?) -> Void)
}

/// XPC 连接监听器。**必须在 `shouldAcceptNewConnection` 里校验签名。**
final class ConnectionListener: NSObject, NSXPCListenerDelegate {
    private let log = Logger.shared
    private var session: Session?

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        // ---- 安全边界 4：调用方授权 ----
        //
        // ⚠️ **这是整个 macOS 实现里最关键的几行。**
        // `SMAppService` / `SMJobBless` 流程下，plist 里的
        // `SMAuthorizedClients` **不被 launchd 或 SMAppService 强制执行** ——
        // 那是 legacy SMJobBless 的遗留写法。
        //
        // 漏掉这个校验的后果：任何本机进程只要知道 Mach service 名，
        // 就能连上这个 root daemon 并让它执行 openconnect。
        // 而 openconnect 有 `--csd-wrapper`（执行任意脚本）这类入口
        // ⇒ 无需提权提示的 root 漏洞。
        //
        // ⚠️ `NSXPCConnection.processIdentifier` 是**同步属性**（不是方法）
        // —— 早先误当作 `processIdentifier { pid, _ in }` 会编译失败：
        // "cannot call value of non-function type 'pid_t'"。
        // 同步可得意味着这里就是正确的校验点，不存在未授权窗口。
        //
        // 另外 `NSXPCConnection.xpcConnection` **不是**公开 API，
        // 拿不到 audit token；pid + SecCodeCopyGuestWithAttributes
        // 已足够完成「同一 Team ID 签名的那个 App」这一层校验。
        let clientPID = newConnection.processIdentifier
        guard clientPID > 0, Self.isClientAuthorized(pid: clientPID) else {
            log.error("拒绝未授权的连接方 (pid=\(clientPID))")
            return false
        }

        newConnection.exportedInterface = NSXPCInterface(with: OcHelperProtocol.self)
        newConnection.exportedObject = XPCBridge(listener: self)
        newConnection.resume()

        newConnection.invalidationHandler = { [weak self] in
            self?.log.info("连接断开 (pid=\(clientPID))")
        }
        return true
    }

    // MARK: 调用方校验

    /// App 的 bundle id
    static let expectedClientBundleID = "io.github.rediceli.ocgui"

    static func isClientAuthorized(pid: pid_t) -> Bool {
        guard let teamID = Config.teamID else {
            Logger.shared.error("TEAM_ID 未注入 —— 拒绝所有连接")
            return false
        }
        return isClientAuthorized(pid: pid, teamID: teamID)
    }

    /// 核心校验：pid 对应的进程必须
    /// 1. 签名有效（未被篡改）
    /// 2. Team ID 与 helper 一致
    /// 3. bundle id 等于本 App
    static func isClientAuthorized(pid: pid_t, teamID: String) -> Bool {
        // 签名：SecCodeCopyGuestWithAttributes(guest, attributes, flags, out)
        // ⚠️ 第 3 个参数是 **SecCSFlags** 不是 out 参数。
        var outCode: SecCode?
        let osStatus = SecCodeCopyGuestWithAttributes(
            nil,
            [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary,
            [],
            &outCode
        )
        guard osStatus == errSecSuccess, let code = outCode else { return false }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
            let staticCode
        else { return false }

        // 签名有效性：Gatekeeper / Hardened Runtime 校验
        var cfError: Unmanaged<CFError>?
        guard SecStaticCodeCheckValidityWithErrors(
            staticCode, [], nil, &cfError
        ) == errSecSuccess else {
            let msg = cfError?.takeRetainedValue().localizedDescription ?? "未知"
            Logger.shared.error("客户端签名无效: \(msg)")
            return false
        }

        guard let info = signingInfo(of: staticCode) else { return false }

        guard let bundleID = info["identifier"] as? String,
            bundleID == expectedClientBundleID
        else {
            Logger.shared.error(
                "bundle id 不匹配: \(String(describing: info["identifier"]))")
            return false
        }

        guard let team = teamIdentifier(of: info) else { return false }
        guard team == teamID else {
            Logger.shared.error("Team ID 不匹配：期望 \(teamID)，实际 \(team)")
            return false
        }
        return true
    }

    /// 签名信息。参数是 `(SecStaticCode, SecCSFlags, out)`。
    private static func signingInfo(of code: SecStaticCode) -> [String: Any]? {
        var out: CFDictionary?
        let status = SecCodeCopySigningInformation(code, [], &out)
        guard status == errSecSuccess, let dict = out as? [String: Any] else {
            Logger.shared.error("SecCodeCopySigningInformation 失败: \(status)")
            return nil
        }
        return dict
    }

    private static func teamIdentifier(of info: [String: Any]) -> String? {
        // SecCodeCopySigningInformation 把 team identifier 平铺在
        // "TeamIdentifier" / "TeamIdentifier0" 键上
        for key in ["TeamIdentifier", "TeamIdentifier0"] {
            if let v = info[key] as? String { return v }
        }
        if let arr = info["TeamIdentifier"] as? [String], let first = arr.first {
            return first
        }
        return nil
    }

    // MARK: 消息分发

    func dispatch(_ payload: Data, reply: @escaping (Data?) -> Void) {
        let decoder = JSONDecoder()
        let encoder = JSONEncoder()
        do {
            let req = try decoder.decode(WRequest.self, from: payload)
            switch req {
            case let .hello(version, _):
                // 版本不匹配必须直接拒绝，而不是「尽力而为」——
                // 协议语义变更后旧 App 的请求可能被误解为提权指令。
                guard version == OcProtocol.version else {
                    reply(try? encoder.encode(WResponse.failed(error: .protocolMismatch(
                        expected: OcProtocol.version, got: version))))
                    return
                }
                reply(try? encoder.encode(WResponse.ready(
                    version: OcProtocol.version,
                    authorized: true,
                    connected: session != nil)))

            case let .start(args, server, secrets):
                guard session == nil else {
                    reply(try? encoder.encode(WResponse.failed(error: .alreadyConnected)))
                    return
                }
                startOpenConnect(
                    args: args, server: server, secrets: secrets,
                    encoder: encoder, reply: reply)

            case .stop:
                if let s = session {
                    s.stop.signal()
                    reply(try? encoder.encode(WResponse.status(
                        connected: false, pid: UInt32(s.pid))))
                } else {
                    reply(try? encoder.encode(WResponse.failed(error: .notConnected)))
                }

            case .status:
                reply(try? encoder.encode(WResponse.status(
                    connected: session != nil,
                    pid: session.map { UInt32($0.pid) })))

            case .shutdown:
                reply(try? encoder.encode(WResponse.status(connected: false, pid: nil)))
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { exit(0) }
            }
        } catch {
            reply(try? encoder.encode(
                WResponse.failed(error: .internalError(message: "\(error)"))))
        }
    }

    // MARK: 启动 openconnect

    /// 启动 openconnect 并把输出通过 XPC 推给 App。
    private func startOpenConnect(
        args: [String],
        server: String,
        secrets: [WStdinSecret],
        encoder: JSONEncoder,
        reply: @escaping (Data?) -> Void
    ) {
        // ---- 安全边界 1：程序白名单 ----
        let program = ProcessInfo.processInfo.environment["OCGUI_OPENCONNECT"]
            ?? "/usr/local/bin/openconnect"
        let url = URL(fileURLWithPath: program)
        guard url.lastPathComponent.hasPrefix(OcProtocol.allowedProgram) else {
            reply(try? encoder.encode(WResponse.failed(error: .rejected(
                reason: "只允许执行 \(OcProtocol.allowedProgram)，"
                    + "收到 \(url.lastPathComponent)"))))
            return
        }

        // ---- 安全边界 2：argv 复检 ----
        // App 可能被攻破 —— helper 不信任它的校验
        let forbidden = ["--csd-wrapper", "--external-browser", "--script-tun"]
        for a in args {
            let flag = a.components(separatedBy: "=").first ?? a
            if forbidden.contains(flag) {
                reply(try? encoder.encode(WResponse.failed(
                    error: .rejected(reason: "禁止的参数: \(flag)"))))
                return
            }
        }
        for s in args + [server] {
            if s.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) {
                reply(try? encoder.encode(WResponse.failed(
                    error: .rejected(reason: "参数含控制字符"))))
                return
            }
        }

        guard FileManager.default.isExecutableFile(atPath: program) else {
            reply(try? encoder.encode(WResponse.failed(error: .openconnectMissing)))
            return
        }

        let p = Process()
        p.executableURL = url
        p.arguments = args + [server]

        let inPipe = Pipe()
        let outPipe = Pipe()
        let errPipe = Pipe()
        p.standardInput = inPipe
        p.standardOutput = outPipe
        p.standardError = errPipe

        do {
            try p.run()
        } catch {
            reply(try? encoder.encode(WResponse.failed(
                error: .internalError(message: "spawn: \(error)"))))
            return
        }

        // ---- 密钥只走 stdin ----（与 Linux 版一致：不进 argv）
        do {
            let inW = inPipe.fileHandleForWriting
            let text = secrets.map { secret -> String in
                let v: String
                switch secret {
                case let .password(x), let .cookie(x): v = x
                }
                return v.hasSuffix("\n") ? v : v + "\n"
            }.joined()
            inW.write(Data(text.utf8))
            try? inW.close()
        } catch {
            Logger.shared.error("写 stdin 失败: \(error)")
        }

        let s = Session(pid: p.processIdentifier, process: p)
        session = s
        reply(try? encoder.encode(WResponse.started(pid: UInt32(p.processIdentifier))))

        // ---- 日志转发 ----
        let push = ReplyBox.shared
        for pipe in [outPipe, errPipe] {
            pipe.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                guard !data.isEmpty else {
                    handle.readabilityHandler = nil
                    return
                }
                let text = String(decoding: data, as: UTF8.self)
                for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
                    guard let reply = push.reply,
                        let payload = try? JSONEncoder().encode(
                            WResponse.log(line: String(line)))
                    else { return }
                    reply(payload)
                }
            }
        }

        // ---- 监督线程 ----
        DispatchQueue.global().async { [weak self] in
            // 等 Stop 信号或进程自行退出
            while s.stop.wait(timeout: .now() + 0.15) == .timedOut {
                if !p.isRunning { break }
            }

            if s.stop.wait(timeout: .now()) == .success {
                // 优雅断开：SIGINT 让 openconnect 跑 vpnc-script 的
                // disconnect 分支清理路由/DNS。SIGKILL 会留下脏配置。
                kill(s.pid, SIGINT)
                for _ in 0..<30 where p.isRunning {
                    Thread.sleep(forTimeInterval: 0.1)
                }
                if p.isRunning { kill(s.pid, SIGKILL) }
                push.emit(.state(state: "idle", cause: nil))
            } else {
                p.waitUntilExit()
                push.emit(.exited(code: p.terminationStatus))
            }
            self?.session = nil
        }
    }
}

// MARK: - XPC 暴露对象

final class XPCBridge: NSObject, OcHelperProtocol {
    private let listener: ConnectionListener

    init(listener: ConnectionListener) { self.listener = listener }

    func send(_ payload: Data, reply: @escaping (Data?) -> Void) {
        // XPC 是单连接模型：请求应答与日志推送共用一个通道
        ReplyBox.shared.reply = reply
        listener.dispatch(payload, reply: reply)
    }
}

/// 保存当前 XPC 连接的 reply 闭包，供日志线程推送。
/// XPC 的 `send(_:reply:)` 每次都带一个 reply 闭包，但 NSXPCConnection
/// 的导出对象拿不到「当前连接」——只能由调用方把闭包存下来。
final class ReplyBox {
    static let shared = ReplyBox()
    private let lock = NSLock()
    private var _reply: ((Data?) -> Void)?

    var reply: ((Data?) -> Void)? {
        get { lock.lock(); defer { lock.unlock() }; return _reply }
        set { lock.lock(); _reply = newValue; lock.unlock() }
    }

    func emit(_ response: WResponse) {
        guard let r = reply, let d = try? JSONEncoder().encode(response) else { return }
        r(d)
    }
}