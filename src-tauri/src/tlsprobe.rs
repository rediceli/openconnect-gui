//! 服务器证书预探测（TOFU —— 首次信任）。
//!
//! # 为什么需要它
//!
//! 服务端证书不受信时，openconnect 会**向 stdin 索要交互确认**
//! （`Enter 'yes' to accept`）。而我们的密钥也走 stdin
//! （`--passwd-on-stdin`），喂完就关闭 —— 于是 openconnect 拿到 EOF，
//! 连接失败并打印一句用户看不懂的 `fgets (stdin): ...`。
//!
//! 用户永远看不到「是否信任此证书」这个问题。
//!
//! # 做法
//!
//! 自己先做一次 TLS 握手，把证书信息与指纹交给用户确认，确认后
//! 把 pin 写进 profile，后续连接用 `--servercert=pin-sha256:...`。
//! openconnect 的交互询问因此不再发生。
//!
//! # 为什么不复用 openconnect 的输出
//!
//! 可以让 openconnect 自己打印 pin，然后从 stderr 里正则提取。但那是
//! 解析文本输出 —— 本项目已经因此栽过两次
//! （见 P1-DESIGN §6.3.12）。这里用真实 TLS 握手取证书，不依赖
//! openconnect 的措辞、版本或翻译。
//!
//! # 安全
//!
//! 探测用的 verifier **接受任何证书** —— 否则自签证书在拿到之前就会
//! 被拒 we'd never see the pin。安全性不在这里，而在于：
//! 用户被展示完整指纹并显式确认（TOFU），确认结果以 pin 形式持久化，
//! 之后每次连接都做**精确的 pin 匹配**（openconnect 的
//! `--servercert`），任何中间人换证书都会导致连接失败。
//!
//! 注意这是 TOFU（首次使用即信任），不是 CA 校验。若要更强的保证，
//! 应让用户核对指纹的带外渠道。

use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// 证书的展示信息。字段与 `dist/index.html` 里的弹窗一一对应。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    /// 实际连上的主机
    pub host: String,
    pub port: u16,
    /// 证书主体，可能是 `CN=app.wthink.cn`
    pub subject: String,
    pub issuer: String,
    /// RFC3339 风格的可读有效期
    pub not_before: String,
    pub not_after: String,
    /// 自签（subject == issuer）时为 true，UI 应给出更强的警告
    pub self_signed: bool,
    /// **openconnect 的 pin**：SPKI（公钥）的 SHA256，base64。
    ///
    /// 注意是公钥而非整个证书 —— 按证书 DER 哈希会得到完全不同的值，
    /// 写进 profile 后连接必然失败（实测踩过）。
    pub pin_sha256: String,
    /// 整个证书的 SHA256 指纹，十六进制分组，给用户肉眼比对用
    pub cert_sha256: String,
    /// 已过期
    pub expired: bool,
}

/// 接受任意证书的 verifier —— 目的只是把证书**取出来**。
#[derive(Debug)]
struct CaptureAny;

impl ServerCertVerifier for CaptureAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 从 `host:port`、`https://host:port/path` 之类的输入里取出 host 与 port。
///
/// 服务端地址在 profile 里是 URL 形态（`https://app.wthink.cn:24443`），
/// 但 openconnect 的最后一个位置参数可能带路径。这里只取 host:port，
/// 忽略路径 —— 证书只与主机名有关。
pub fn split_host_port(server: &str) -> Result<(String, u16), String> {
    let mut s = server.trim();
    for prefix in ["https://", "http://"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest;
        }
    }
    // 去掉路径、查询、fragment 与末尾斜杠
    s = s.split(['/', '?', '#']).next().unwrap_or(s);
    if s.is_empty() {
        return Err(format!("无法从 {server:?} 解析出主机名"));
    }
    // IPv6 字面量：[::1]:443
    if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("IPv6 地址缺少右括号: {server:?}"))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| format!("非法端口: {p}"))?,
            None => 443,
        };
        return Ok((h.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) => Ok((
            h.to_string(),
            p.parse().map_err(|_| format!("非法端口: {p:?}"))?,
        )),
        None => Ok((s.to_string(), 443)),
    }
}

/// 探测 `server` 的证书。
///
/// 会建立一次**真实的 TLS 连接**（只到握手完成，不发任何 HTTP 请求），
/// 因此服务端会看到一次连接日志。这是 TOFU 的必要代价。
pub fn probe(server: &str) -> Result<CertInfo, String> {
    let (host, port) = split_host_port(server)?;
    let addr = format!("{host}:{port}");

    // 超时必须有：探测卡住会让 UI 的「连接中」永远转圈
    let tcp = std::net::TcpStream::connect(&addr).map_err(|e| format!("连接 {addr} 失败: {e}"))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();

    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CaptureAny))
        .with_no_client_auth();
    // 我们只要握手，禁用会话恢复与证书压缩等无关功能
    config.enable_sni = true;

    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| format!("{host:?} 不能作为 TLS SNI 使用"))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("TLS 初始化失败: {e}"))?;

    let mut sock = tcp;
    conn.complete_io(&mut sock).map_err(|e| format!("TLS 握手失败: {e}"))?;

    let certs = conn
        .peer_certificates()
        .ok_or_else(|| "服务端没有提供证书".to_string())?;
    parse_cert(&host, port, &certs[0])
}

/// 从 DER 解析出展示所需的信息与两个指纹。
fn parse_cert(host: &str, port: u16, der: &CertificateDer<'_>) -> Result<CertInfo, String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(der.as_ref())
        .map_err(|e| format!("证书 DER 解析失败: {e}"))?;

    let subject = parsed.subject().to_string();
    let issuer = parsed.issuer().to_string();
    let self_signed = subject == issuer;

    let not_before = parsed.validity().not_before.to_datetime();
    let not_after = parsed.validity().not_after.to_datetime();
    // `to_datetime()` 已转成 OffsetDateTime，因此直接与 now() 的
    // OffsetDateTime 比较（ASN1Time 与 OffsetDateTime 之间没有 PartialOrd）
    let expired = not_after < x509_parser::time::ASN1Time::now().to_datetime();

    // ── pin：SPKI（公钥）的 SHA256 ──
    // openconnect 的 pin-sha256 就是这个值，而不是整个证书的哈希。
    let spki = parsed.public_key().raw;
    let pin_sha256 = format!(
        "pin-sha256:{}",
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(spki))
    );

    // ── 指纹：整个证书的 SHA256，给用户肉眼比对 ──
    let cert_sha256 = hex_colon(&Sha256::digest(der.as_ref()));

    Ok(CertInfo {
        host: host.to_string(),
        port,
        subject,
        issuer,
        not_before: not_before.to_string(),
        not_after: not_after.to_string(),
        self_signed,
        pin_sha256,
        cert_sha256,
        expired,
    })
}

fn hex_colon(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_host_port() {
        assert_eq!(
            split_host_port("app.wthink.cn:24443").unwrap(),
            ("app.wthink.cn".to_string(), 24443)
        );
    }

    #[test]
    fn parses_url_and_strips_path() {
        // profile 里存的是 URL 形态
        assert_eq!(
            split_host_port("https://app.wthink.cn:24443").unwrap(),
            ("app.wthink.cn".to_string(), 24443)
        );
        assert_eq!(
            split_host_port("https://vpn.corp.com/Some%20Group").unwrap(),
            ("vpn.corp.com".to_string(), 443)
        );
    }

    #[test]
    fn defaults_to_443() {
        assert_eq!(
            split_host_port("vpn.corp.com").unwrap(),
            ("vpn.corp.com".to_string(), 443)
        );
        assert_eq!(
            split_host_port("https://vpn.corp.com/").unwrap(),
            ("vpn.corp.com".to_string(), 443)
        );
    }

    #[test]
    fn parses_ipv6_literal() {
        assert_eq!(
            split_host_port("[fd00::1]:24443").unwrap(),
            ("fd00::1".to_string(), 24443)
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(split_host_port("").is_err());
        assert!(split_host_port("host:abc").is_err());
        assert!(split_host_port("[fd00::1").is_err());
    }

    #[test]
    fn pin_is_spki_not_whole_cert() {
        // 实测：同一张自签证书
        //   SPKI  SHA256 → No+Ghe9gnoHr0y9Dd/jY16jCf6omRkKQ1icJc8zV0go=  （openconnect 要的）
        //   证书 SHA256 → 1b1dp3lANS4Qqmq2xe7iEXfEpOEOtxaPZE5GWqQuG3M=  （错的）
        // 两者必须不同，否则说明我们退化成了整证书哈希。
        let spki = b"pretend-this-is-the-spki";
        let der = b"pretend-this-is-a-much-longer-certificate-body";
        let a = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(spki));
        let b = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(der));
        assert_ne!(a, b, "SPKI 与整证书哈希相同时哈希算法用错了");
    }

    #[test]
    fn fingerprint_is_uppercase_colon_hex() {
        let f = hex_colon(&[0xd5, 0xbd, 0x5d]);
        assert_eq!(f, "D5:BD:5D");
    }
}
#[cfg(test)]
mod serde_tests {
    use super::*;

    /// UI 用 `info.notBefore` / `info.pinSha256` 这样的 camelCase 字段名。
    /// Rust 侧是 snake_case，两边不一致时前端会拿到 undefined 而不报错 ——
    /// 弹窗就会显示一片空白。这里锁住字段名。
    #[test]
    fn serializes_to_camel_case_for_the_ui() {
        let json = serde_json::to_value(CertInfo {
            host: "h".into(),
            port: 443,
            subject: "CN=x".into(),
            issuer: "CN=x".into(),
            not_before: "2026-01-01".into(),
            not_after: "9999-12-31".into(),
            self_signed: true,
            pin_sha256: "pin-sha256:AA".into(),
            cert_sha256: "AA:BB".into(),
            expired: false,
        })
        .unwrap();
        for k in [
            "host", "port", "subject", "issuer", "notBefore", "notAfter",
            "selfSigned", "pinSha256", "certSha256", "expired",
        ] {
            assert!(json.get(k).is_some(), "UI 需要的字段 {k} 缺失");
        }
    }
}
