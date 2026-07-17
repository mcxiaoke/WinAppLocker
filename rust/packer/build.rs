//! packer build script：嵌入图标 + 注入版本信息 + 拷贝 stub 到 OUT_DIR。
//!
//! 1. 使用 winres 将 assets/app.ico 嵌入 exe 资源
//! 2. 通过 cargo:rustc-env 注入 git hash + 构建时间
//! 3. 将 stub_gui.exe / stub_console.exe 从 target/<profile>/ 复制到 OUT_DIR，
//!    供 packer 源码通过 include_bytes!(concat!(env!("OUT_DIR"), ...)) 嵌入。
//!    这样 packer 发布产物是单一 WinAppLocker.exe，不再需要外部 stub/ 目录。

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
    // === 版本信息 ===
    let git_hash = git_hash();
    let build_time = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let version = env!("CARGO_PKG_VERSION");

    println!("cargo:rustc-env=PACKER_GIT_HASH={}", git_hash);
    println!("cargo:rustc-env=PACKER_BUILD_TIME={}", build_time);
    println!("cargo:rustc-env=PACKER_VERSION={}", version);

    // === 图标 ===
    let mut res = winres::WindowsResource::new();
    res.set_icon("assets/app.ico");
    res.set("FileDescription", "WinAppLocker - EXE 密码保护工具");
    res.set("ProductName", "WinAppLocker");
    res.set("LegalCopyright", "Copyright (C) 2026");
    if let Err(e) = res.compile() {
        eprintln!("cargo:warning=winres compile error: {}", e);
    }

    // === 拷贝 stub 到 OUT_DIR（供 include_bytes! 嵌入）===
    // stub 必须先于 packer 构建（rebuild.ps1 已保证）。
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");

    for stub_name in ["stub_gui.exe", "stub_console.exe"] {
        let src = format!("../target/{}/{}", profile, stub_name);
        if !std::path::Path::new(&src).exists() {
            eprintln!(
                "cargo:warning=stub not found at {}, run `cargo build -p exelock-stub` first",
                src
            );
            continue;
        }
        let dst = format!("{}/{}", out_dir, stub_name);
        if let Err(e) = std::fs::copy(&src, &dst) {
            eprintln!("cargo:warning=copy {} -> {} failed: {}", src, dst, e);
        }
        println!("cargo:rerun-if-changed={}", src);
    }

    // 监听变化
    println!("cargo:rerun-if-changed=assets/app.ico");
    println!("cargo:rerun-if-changed=../stub/src/lib.rs");
}
