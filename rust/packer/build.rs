//! packer build script。
//!
//! 嵌入预编译的 stub EXE。stub 由 `cargo build -p exelock-stub --release` 生成，
//! 需要手动复制到 `packer/stubs/` 目录（由根目录的构建脚本或开发者手动执行）。
//!
//! 开发流程：
//! 1. `cargo build -p exelock-stub --release`
//! 2. 复制 `target/release/stub_gui.exe` → `packer/stubs/stub_gui.exe`
//! 3. 复制 `target/release/stub_console.exe` → `packer/stubs/stub_console.exe`
//! 4. `cargo build -p packer --release`

fn main() {
    // 声明依赖：stub 文件变化时重新编译 packer
    println!("cargo:rerun-if-changed=stubs/stub_gui.exe");
    println!("cargo:rerun-if-changed=stubs/stub_console.exe");
    // 也监听 stub 源码变化（提示开发者需要重建 stub）
    println!("cargo:rerun-if-changed=../stub/src/lib.rs");
    println!("cargo:rerun-if-changed=../stub/src/password_ui.rs");
    println!("cargo:rerun-if-changed=../stub/Cargo.toml");
}
