//! 用真实网关验证证书探测：pin 必须与 openconnect 打印的一致。
fn main() {
    let server = std::env::args().nth(1).expect("用法: e2e_certprobe <server>");
    match oc_gui::tlsprobe::probe(&server) {
        Ok(i) => {
            println!("host        = {}", i.host);
            println!("port        = {}", i.port);
            println!("subject     = {}", i.subject);
            println!("issuer      = {}", i.issuer);
            println!("self_signed = {}", i.self_signed);
            println!("expired     = {}", i.expired);
            println!("not_before  = {}", i.not_before);
            println!("not_after   = {}", i.not_after);
            println!("pin_sha256  = {}", i.pin_sha256);
            println!("cert_sha256 = {}", i.cert_sha256);
        }
        Err(e) => {
            eprintln!("探测失败: {e}");
            std::process::exit(1);
        }
    }
}
