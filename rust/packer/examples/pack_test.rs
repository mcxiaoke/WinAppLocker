//! 测试用打包工具：用 stub_test.exe（内置密码 test1234）打包。
//!
//! 用法：pack_test <input.exe> <output.exe>
//!
//! 打包后的 EXE 运行时不需要输入密码，直接用内置密码 "test1234" 解密。
//! 仅供自动化端到端测试使用。

use std::path::PathBuf;

use exelock_packer::pack::{pack, PackOptions};
use exelock_packer::stub_selector::StubPreference;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("用法: {} <input.exe> <output.exe>", args[0]);
        std::process::exit(1);
    }

    // 读取 stub_test.exe（由 `cargo build -p exelock-stub --release --bin stub_test` 生成）
    let stub_test_path = std::env::var("STUB_TEST_PATH")
        .unwrap_or_else(|_| "../target/release/stub_test.exe".to_string());
    let stub_bytes = std::fs::read(&stub_test_path)
        .unwrap_or_else(|e| {
            eprintln!("读取 stub_test.exe 失败 (path={}): {}", stub_test_path, e);
            std::process::exit(1);
        });
    eprintln!("使用 stub_test.exe: {} ({} bytes)", stub_test_path, stub_bytes.len());

    let opts = PackOptions {
        input_path: PathBuf::from(&args[1]),
        output_path: PathBuf::from(&args[2]),
        password: "test1234".to_string(),
        algorithm_id: 0x0001, // AES-256-GCM
        kdf_id: 0x0001,       // PBKDF2-SHA256
        kdf_iterations: 100_000, // 最低值，加快测试速度
        salt_len: 16,
        use_aad: true,
        erase_payload: true,
        stub_preference: StubPreference::Custom(stub_bytes),
        custom_extensions: Vec::new(),
    };

    match pack(&opts, None) {
        Ok(report) => {
            println!(
                "打包成功: {}KB -> {}KB (algo={:#06x}, kdf={:#06x}, iters={})",
                report.original_size / 1024,
                report.output_size / 1024,
                report.algorithm_id,
                report.kdf_id,
                report.kdf_iterations
            );
        }
        Err(e) => {
            eprintln!("打包失败: {}", e);
            std::process::exit(1);
        }
    }
}
