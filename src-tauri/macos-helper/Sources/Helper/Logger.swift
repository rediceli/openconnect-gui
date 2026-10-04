import Foundation
import os.log

/// 统一日志。root daemon 的 stderr 会进系统日志，用 os_log 更容易查。
final class Logger {
    static let shared = Logger()
    private let log = OSLog(
        subsystem: "io.github.rediceli.ocgui.helper", category: "helper")

    func info(_ msg: String) {
        os_log("%{public}@", log: log, type: .info, msg)
    }

    func error(_ msg: String) {
        // 拒绝授权的原因属于安全事件，用 .error 便于被 SIEM 采集
        os_log("%{public}@", log: log, type: .error, msg)
    }
}
