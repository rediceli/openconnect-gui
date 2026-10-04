import Foundation

/// 构建期/运行期注入的配置。
///
/// `teamID` 是 App 与 Helper 签名共用的 Team ID，调用方校验依赖它。
/// 缺失时 helper **拒绝所有连接**（而不是降级放行）。
///
/// # 两个来源，按优先级
///
/// 1. **环境变量 `WTHINKVPN_TEAM_ID`** —— 由 `Scripts/sign-macos.sh`
///    写进 launchd plist 的 `EnvironmentVariables`。这是实际生效的来源。
/// 2. Info.plist 的 `WthinkVPNTeamID` —— 仅作文档/调试用。
///
/// # 为什么不用 `-sectcreate __TEXT __info_plist`
///
/// SwiftPM 的 `linkerSettings.unsafeFlags` 传给的是 **swiftc** 而非
/// `ld`，因此 `-sectcreate` 会得到 `unknown argument`。
/// 正确做法需要 SwiftPM build plugin（Swift 5.6+ 的 `Plugin` API），
/// 复杂度不划算。
///
/// launchd plist 本来就支持环境变量，且 daemon 由 launchd 加载 ——
/// 用它更直接，也更容易在排查时 `launchctl print` 看到。
enum Config {
    static let teamID: String? = {
        if let v = ProcessInfo.processInfo.environment["WTHINKVPN_TEAM_ID"],
            !v.isEmpty
        {
            return v
        }
        if let v = Bundle.main.object(forInfoDictionaryKey: "WthinkVPNTeamID") as? String,
            !v.isEmpty
        {
            return v
        }
        return nil
    }()

    static let machService = "io.wthink.wthinkvpn.helper"
}
