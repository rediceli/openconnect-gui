//! commands 层的无窗口冒烟：profile CRUD + 钥匙串 + argv 联动。
//!
//! 注意：不启动 Tauri（避免弹窗），直接复用 Repo/Vault/argv。

use wthinkvpn_lib::profile::{Profile, Repo, SecretKind};
use wthinkvpn_lib::{secret, tunnel::argv};

fn main() {
    let dir = std::env::temp_dir().join(format!("wthinkvpn-smoke-{}", std::process::id()));
    let repo = Repo::new(&dir);

    // 1. 空库
    assert_eq!(repo.load().unwrap().profiles.len(), 0);

    // 2. 保存档案
    let mut p = Profile::new("smoke-1", "公司 VPN", "127.0.0.1:8443/");
    p.username = Some("testuser".into());
    p.remember_password = true;
    let store = wthinkvpn_lib::profile::Store { profiles: vec![p.clone()] };
    repo.save(&store).unwrap();
    println!("[ok] save profile");

    // 3. 重新加载并校验
    let loaded = repo.load().unwrap();
    assert_eq!(loaded.profiles[0], p);
    println!("[ok] load profile round-trip");

    // 4. 密码存钥匙串
    secret::set(&p, SecretKind::Password, "hunter2").unwrap();
    assert_eq!(secret::password(&p).as_deref(), Some("hunter2"));
    println!("[ok] keyring round-trip");

    // 5. profile 文件里绝不能有密码
    let raw = std::fs::read_to_string(dir.join("profiles.toml")).unwrap();
    assert!(!raw.contains("hunter2"), "profiles.toml 泄漏了密码:\n{raw}");
    println!("[ok] no plaintext password on disk");

    // 6. 用钥匙串里的密码构建 argv
    let secrets = argv::Secrets {
        password: secret::password(&p),
        ..Default::default()
    };
    let plan = argv::build(&p, &secrets);
    assert!(plan.argv().contains(&"--passwd-on-stdin"));
    assert!(!plan.args.join(" ").contains("hunter2"));
    println!("[ok] argv uses stdin, no leak");

    // 7. 删除档案必须清理钥匙串
    let mut store = repo.load().unwrap();
    let victim = store.profiles.remove(0);
    repo.save(&store).unwrap();
    secret::purge(&victim);
    assert!(secret::password(&victim).is_none(), "钥匙串里留下了孤儿条目");
    println!("[ok] delete profile purges keyring");

    std::fs::remove_dir_all(&dir).ok();
    println!("\nsmoke ok");
}
