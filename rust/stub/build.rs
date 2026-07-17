//! stub build script：注入版本信息（git hash + 构建时间）。
//!
//! 通过 cargo:rustc-env 设置环境变量，stub 源码用 env!() 在编译时读取。

use std::process::Command;

fn git_hash() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn main() {
    let git_hash = git_hash();
    let build_time = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let version = env!("CARGO_PKG_VERSION");

    println!("cargo:rustc-env=STUB_GIT_HASH={}", git_hash);
    println!("cargo:rustc-env=STUB_BUILD_TIME={}", build_time);
    println!("cargo:rustc-env=STUB_VERSION={}", version);

    // 监听源码变化
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/password_ui.rs");
}
