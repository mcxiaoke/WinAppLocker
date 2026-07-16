//! 命令行打包工具（用于自动化测试）。
//!
//! 用法：pack_cli <input.exe> <output.exe> <password>

use std::path::PathBuf;

use exelock_packer::pack::{pack, PackOptions};
use exelock_packer::stub_selector::StubPreference;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("用法: {} <input.exe> <output.exe> <password>", args[0]);
        std::process::exit(1);
    }

    let opts = PackOptions {
        input_path: PathBuf::from(&args[1]),
        output_path: PathBuf::from(&args[2]),
        password: args[3].clone(),
        algorithm_id: 0x0001, // AES-256-GCM
        kdf_id: 0x0001,       // PBKDF2-SHA256
        kdf_iterations: 100_000, // 最低值，加快测试速度
        salt_len: 16,
        use_aad: true,
        erase_payload: true,
        stub_preference: StubPreference::Auto,
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
