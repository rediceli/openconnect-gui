use std::path::PathBuf;

fn main() {
    // 无构建链的前端资源（dist/）由 tauri 在**编译期**嵌进二进制。
    //
    // tauri-build 只声明了 tauri.conf.json / capabilities / icons 的
    // rerun-if-changed，没有 dist/。于是改完 dist/app.js 再
    // `cargo tauri build`，crate 不重编、资源仍是旧的 —— 界面看起来
    // 「改了没生效」，排查非常费时间（本次就踩了）。
    //
    // 这里把 dist 下每个文件逐个登记：cargo 比较的是 mtime，逐文件登记
    // 才能感知「内容改了但目录 mtime 没变」。build script 重跑 ⇒ 依赖它
    // 的 crate 重编 ⇒ 资源重新嵌入。
    let dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("dist");
    if dist.is_dir() {
        for entry in std::fs::read_dir(&dist).expect("读取 dist/ 失败") {
            let path = entry.expect("读取 dist/ 条目失败").path();
            if path.is_file() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }

    tauri_build::build()
}
