//! 用真实服务端校验 argv 生成。
//!
//! 与其他 e2e 示例不同，这个例子**不需要 root、不建立隧道**：
//! 它只跑 `tunnel::argv::build`，然后把生成的参数列表打印出来，
//! 供人工核对 openconnect 的 flag 是否适合目标服务端。
//!
//! 密码/cookie 不在这里 —— argv 里本来就不该有（走 `--passwd-on-stdin`）。
//! 这里验证的是「除了 stdin 之外，没有任何凭据进入 argv」。
//!
//! 用法：
//! ```text
//! cargo run --example e2e_argv -- <profile.toml>
//! ```

use wthinkvpn_lib::profile::Profile;
use wthinkvpn_lib::tunnel::argv;

fn main() {
    let path = std::env::args().nth(1).expect("用法: e2e_argv <profile.toml>");
    let text = std::fs::read_to_string(&path).expect("读取 profile 失败");
    let profile: Profile = toml::from_str(&text).expect("解析 profile 失败");

    let secrets = argv::Secrets {
        password: Some("dummy-password".into()),
        cookie: None,
        key_password: None,
        mca_key_password: None,
        token_secret: None,
    };
    let plan = argv::build(&profile, &secrets);

    // `plan.argv()` 才是真正交给 openconnect 的完整命令行
    //（`plan.args` 不含服务器 —— 它是最后一个位置参数）
    println!("== openconnect 命令行 ==");
    println!("  openconnect {}", plan.argv().join(" "));
    println!("== argv（不含服务器）==");
    for a in &plan.args {
        println!("  {a}");
    }
    println!("== 服务器（位置参数）==");
    println!("  {}", plan.server);
    println!("== stdin secrets ==");
    for (i, s) in plan.stdin_secrets.iter().enumerate() {
        println!("  [{i}] {s:?}");
    }

    // ── 安全断言：凭据绝不能出现在 argv 里 ──
    //
    // 断言值必须用**占位符**，绝不能写任何真实凭据：这段代码会入库，
    // 而 `account.txt` 虽然被 gitignore 了，代码不会。
    // （最初这里写了真实测试密码作为「反例」，差点随 commit 泄露。）
    let joined = plan.args.join(" ");
    for bad in ["dummy-password", "PLACEHOLDER-NOT-A-REAL-SECRET"] {
        assert!(
            !joined.contains(bad),
            "argv 里出现了凭据 {bad:?}: {joined}"
        );
    }
    assert!(
        plan.args.iter().any(|a| a == "--passwd-on-stdin"),
        "必须有 --passwd-on-stdin，否则密码会进 argv"
    );
    // 服务器必须作为位置参数存在，否则 openconnect 无从连接
    assert!(
        plan.argv().last() == Some(&plan.server.as_str()),
        "服务器必须是最后一个位置参数，实际: {:?}",
        plan.argv().last()
    );

    // ── 危险 flag 一律不应出现 ──
    for (flag, why) in [
        ("--script-tun", "能让 helper 执行任意脚本"),
        ("--csd-wrapper", "能执行任意程序"),
        ("--external-browser", "能拉起任意浏览器"),
    ] {
        assert!(
            !plan.args.iter().any(|a| a.starts_with(flag)),
            "不应出现 {flag}（{why}）"
        );
    }

    // ── openconnect 不支持的写法 ──
    assert!(
        !plan.args.iter().any(|a| a.starts_with("--key-password")),
        "v9 不支持 --key-password=@file，私钥口令必须走 --config"
    );
    assert!(
        !plan.args.iter().any(|a| a.starts_with("-F=")),
        "-F=... 形式不合法，应逐个 --form-entry"
    );

    println!("\n全部断言通过");
}