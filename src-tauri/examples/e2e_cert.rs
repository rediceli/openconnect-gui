//! 端到端：加密私钥 + 口令经 config 文件（不进 argv）→ 真实 openconnect。
//!
//! 用法：
//!   python3 docs/mock_gateway.py &
//!   cargo run --example e2e_cert -- <ca.crt> <cert.pem> <enc.key.pem> <passphrase>

use oc_gui::profile::{ClientCert, Profile};
use oc_gui::tunnel::{argv, supervisor};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (ca, cert, key, pass) = (
        a.get(1).cloned().expect("usage"),
        a.get(2).cloned().expect("usage"),
        a.get(3).cloned().expect("usage"),
        a.get(4).cloned().expect("usage"),
    );

    let mut p = Profile::new("e2e-cert", "cert", "127.0.0.1:8443/");
    p.username = Some("testuser".into());
    p.auth_group = Some("Engineering".into());
    p.client_cert = Some(ClientCert {
        certificate: cert,
        private_key: key,
        key_password_saved: Some(true),
        ..Default::default()
    });

    let secrets = argv::Secrets {
        password: Some("hunter2".into()),
        key_password: Some(pass.clone()),
        ..Default::default()
    };

    let mut plan = argv::build(&p, &secrets);
    if let Some(e) = &plan.fatal_error {
        eprintln!("构建失败: {e}");
        std::process::exit(1);
    }

    println!("argv: {}", plan.redacted_display());
    let joined = plan.args.join(" ");
    assert!(!joined.contains(&pass), "私钥口令泄漏进 argv!");
    println!("[ok] 私钥口令不在 argv 中");

    // 确认 config 文件确实是 0600
    let cf_path = {
        let cf_arg = plan
            .args
            .iter()
            .find(|a| a.starts_with("--config="))
            .expect("应有 --config=")
            .clone();
        cf_arg.trim_start_matches("--config=").to_string()
    };
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&cf_path).unwrap().permissions().mode() & 0o777;
    println!("[ok] config 文件权限 {mode:o} @ {cf_path}");
    assert_eq!(mode, 0o600);

    plan.args.push("--cafile".into());
    plan.args.push(ca);

    let mut session = supervisor::start(
        &plan,
        std::path::Path::new("/usr/local/bin/openconnect"),
        Box::new(|s, c| println!("[state] {s:?} cause={c:?}")),
    )
    .expect("启动失败");

    let (code, cause) = supervisor::pump_with_lines(
        &mut session,
        Box::new(|s, c| println!("[state] {s:?} cause={c:?}")),
        |l| {
            if l.contains("certificate")
                || l.contains("private key")
                || l.contains("decrypt")
                || l.contains("CONNECT")
            {
                println!("  | {l}");
            }
        },
    );
    println!("exit={code:?} cause={cause:?}");

    // config 文件必须活到 openconnect 读完为止，因此由 ArgPlan 持有。
    // drop plan 即应删除。
    drop(plan);
    assert!(
        std::fs::metadata(&cf_path).is_err(),
        "ArgPlan drop 后临时 config 文件应被删除"
    );
    println!("[ok] 临时 config 文件已随 ArgPlan drop 清理");
}
