import XCTest
@testable import SharedProtocol

/// 协议编解码测试。
///
/// 这些形状必须与 Rust 侧 `src/ipc.rs` 逐字段一致 —— 任何一侧改了
/// 字段名而另一侧没改，症状是「连接建立后收不到任何应答」，
/// 极难排查。故用测试固化。
final class OcProtocolTests: XCTestCase {
    func decode(_ json: String) throws -> WResponse {
        try JSONDecoder().decode(WResponse.self, from: Data(json.utf8))
    }

    func testReadyShape() throws {
        let r = try decode("""
        {"event":"ready","version":1,"authorized":true,"connected":false}
        """)
        guard case let .ready(version, authorized, connected) = r else {
            return XCTFail("形状不匹配: \(r)")
        }
        XCTAssertEqual(version, 1)
        XCTAssertTrue(authorized)
        XCTAssertFalse(connected)
    }

    func testStartedShape() throws {
        let r = try decode("{\"event\":\"started\",\"pid\":1234}")
        guard case let .started(pid) = r else { return XCTFail("形状不匹配: \(r)") }
        XCTAssertEqual(pid, 1234)
    }

    func testLogShape() throws {
        let r = try decode(#"{"event":"log","line":"hello world"}"#)
        guard case let .log(line) = r else { return XCTFail("形状不匹配: \(r)") }
        XCTAssertEqual(line, "hello world")
    }

    func testExitedWithAndWithoutCode() throws {
        guard case let .exited(code) = try decode("{\"event\":\"exited\",\"code\":1}") else {
            return XCTFail("形状不匹配")
        }
        XCTAssertEqual(code, 1)
        // 缺省 code 应解为 nil
        if case let .exited(code) = try decode("{\"event\":\"exited\"}") {
            XCTAssertNil(code)
        } else {
            XCTFail("exited 形状不匹配")
        }
    }

    func testFailedShapes() throws {
        for json in [
            #"{"event":"failed","error":{"kind":"not_connected"}}"#,
            #"{"event":"failed","error":{"kind":"already_connected"}}"#,
            #"{"event":"failed","error":{"kind":"openconnect_missing"}}"#,
        ] {
            guard case .failed = try decode(json) else {
                XCTFail("形状不匹配: \(json)")
                continue
            }
        }
        guard case let .failed(error: .rejected(reason)) =
            try decode(#"{"event":"failed","error":{"kind":"rejected","reason":"x"}}"#)
        else { return XCTFail("rejected 形状不匹配") }
        XCTAssertEqual(reason, "x")
    }

    func testProtocolMismatchCarriesBothVersions() throws {
        guard case let .failed(error: .protocolMismatch(expected, got)) = try decode(
            #"{"event":"failed","error":{"kind":"protocol_mismatch","expected":1,"got":99}}"#)
        else { return XCTFail("形状不匹配") }
        XCTAssertEqual(expected, 1)
        XCTAssertEqual(got, 99)
    }

    func testUnknownEventIsRejected() {
        XCTAssertThrowsError(try decode("{\"event\":\"nope\"}"))
    }

    // MARK: 请求

    func testHelloRoundTrip() throws {
        let req = WRequest.hello(version: 1, callerUID: 501)
        let data = try JSONEncoder().encode(req)
        let json = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(json.contains("\"cmd\":\"hello\""), json)
        XCTAssertTrue(json.contains("\"callerUID\":501"), json)
    }

    func testStartRoundTripPreservesSecrets() throws {
        let req = WRequest.start(
            args: ["--protocol=anyconnect", "--passwd-on-stdin"],
            server: "vpn.corp.com",
            stdinSecrets: [.password("hunter2"), .cookie("webvpn=abc")])
        let data = try JSONEncoder().encode(req)
        let back = try JSONDecoder().decode(WRequest.self, from: data)
        guard case let .start(args, server, secrets) = back else {
            return XCTFail("往返后类型变了")
        }
        XCTAssertEqual(args.count, 2)
        XCTAssertEqual(server, "vpn.corp.com")
        XCTAssertEqual(secrets.count, 2)
    }

    func testSecretsAreTaggedNotPositional() throws {
        // 密钥必须带 kind 标签 —— 否则 Password("x") 与 Cookie("x")
        // 编码后无法区分，helper 会把 cookie 当密码送进 stdin。
        let pw = try JSONEncoder().encode([WStdinSecret.password("x")])
        let ck = try JSONEncoder().encode([WStdinSecret.cookie("x")])
        XCTAssertNotEqual(String(decoding: pw, as: UTF8.self),
                          String(decoding: ck, as: UTF8.self))
    }

    func testSimpleCommandsEncodeOnlyCmd() throws {
        for (req, expected) in [
            (WRequest.stop, "stop"),
            (.status, "status"),
            (.shutdown, "shutdown"),
        ] {
            let json = String(decoding: try JSONEncoder().encode(req), as: UTF8.self)
            XCTAssertTrue(json.contains("\"cmd\":\"\(expected)\""), json)
        }
    }

    func testVersionMatchesRustSide() {
        // Rust 侧 src/ipc.rs: PROTOCOL_VERSION = 1
        XCTAssertEqual(OcProtocol.version, 1)
    }
}
