//! 端到端冒烟：用 supervisor 驱动**真实** openconnect 对接 mock gateway。
//!
//! 用法：
//!   python3 docs/mock_gateway.py &          # 监听 127.0.0.1:8443
//!   cargo run --example e2e_mock

use oc_gui::profile::{FormBinding, Profile};
use oc_gui::tunnel::{argv, supervisor};

fn main() {
    let ca = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/mock.crt".to_string());

    let mut p = Profile::new("e2e", "mock", "127.0.0.1:8443/");
    p.username = Some("testuser".into());
    p.auth_group = Some("Engineering".into());
    p.form = Some(FormBinding {
        form_id: "main".into(),
        group_field: "group_list".into(),
    });

    let secrets = argv::Secrets {
        password: Some(std::env::var("MOCK_PASSWORD").unwrap_or_else(|_| "hunter2".into())),
        ..Default::default()
    };
    let plan = argv::build(&p, &secrets);

    println!("argv: {}", plan.redacted_display());
    println!("stdin secrets: {} item(s)", plan.stdin_secrets.len());

    // 把 --cafile 加上（mock 是自签证书）
    let mut plan = plan;
    plan.args.push("--cafile".into());
    plan.args.push(ca);

    let mut session = supervisor::start(
        &plan,
        std::path::Path::new("/usr/local/bin/openconnect"),
        Box::new(|s, c| println!("[state] {s:?} cause={c:?}")),
    )
    .expect("启动 openconnect 失败");

    println!("pid = {}", session.pid());
    let (_code, cause) = supervisor::pump_with_lines(
        &mut session,
        Box::new(|s, c| println!("[state] {s:?} cause={c:?}")),
        |l| println!("  | {l}"),
    );
    println!("final cause = {cause:?}");
}
