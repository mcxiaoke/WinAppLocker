//! packer build script。
//!
//! MVP 阶段：stub 尚未实现，用内置占位 stub（最小 PE）。
//! beta2 阶段：改为 `include_bytes!` 嵌入预编译的 stub_gui.exe / stub_console.exe。

fn main() {
    // 预留：beta2 阶段取消注释以下代码，嵌入真实 stub
    // println!("cargo:rerun-if-changed=stubs/stub_gui.exe");
    // println!("cargo:rerun-if-changed=stubs/stub_console.exe");
}
