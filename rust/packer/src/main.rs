//! EXE加密工具 - Packer
//! 功能：读取目标EXE -> 使用密码加密 -> 嵌入到Stub中生成受保护的EXE

mod crypto;

use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::path::Path;

use crypto::{get_algorithm, EncryptedResult};

const MAGIC: &[u8; 8] = b"EXELOCK1";

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "help" || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        return Ok(());
    }

    match args[1].as_str() {
        "pack" => cmd_pack(&args[2..])?,
        "algorithms" => {
            println!("支持的加密算法:");
            println!("  aes256gcm  - AES-256-GCM (默认，推荐)");
            println!("  xor        - 自定义XOR混淆（仅演示）");
            println!("  sm4        - 国密SM4-GCM (需自行实现)");
            println!("  chacha20   - ChaCha20-Poly1305 (需自行实现)");
        }
        _ => {
            println!("未知命令: {}", args[1]);
            print_usage();
        }
    }

    Ok(())
}

fn print_usage() {
    println!("ExeLock - EXE密码加密工具 v0.1");
    println!();
    println!("用法:");
    println!("  exe-lock pack [选项]");
    println!();
    println!("选项:");
    println!("  -i, --input <路径>      要加密的EXE文件路径 (必填)");
    println!("  -o, --output <路径>     输出文件路径 (默认: <原文件名>_locked.exe)");
    println!("  -p, --password <密码>   加密密码 (必填)");
    println!("  -s, --stub <路径>       Stub加载器路径 (默认: stub.exe)");
    println!("  -a, --algorithm <算法>  加密算法 (默认: aes256gcm)");
    println!("      --overwrite         加密后覆盖原文件");
    println!();
    println!("其他命令:");
    println!("  exe-lock algorithms     列出支持的加密算法");
    println!();
    println!("示例:");
    println!("  exe-lock pack -i app.exe -p mypassword");
    println!("  exe-lock pack -i game.exe -p 123456 --overwrite");
    println!("  exe-lock pack -i test.exe -p pass -a xor");
}

fn cmd_pack(args: &[String]) -> Result<()> {
    let mut input = None;
    let mut output = None;
    let mut password = None;
    let mut stub_path = None;
    let mut algorithm = "aes256gcm";
    let mut overwrite = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" | "-i" => {
                input = Some(args[i + 1].clone());
                i += 2;
            }
            "--output" | "-o" => {
                output = Some(args[i + 1].clone());
                i += 2;
            }
            "--password" | "-p" => {
                password = Some(args[i + 1].clone());
                i += 2;
            }
            "--stub" | "-s" => {
                stub_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--algorithm" | "-a" => {
                algorithm = &args[i + 1];
                i += 2;
            }
            "--overwrite" => {
                overwrite = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    let input_path = input.context("请使用 --input 指定要加密的EXE路径")?;
    let password = password.context("请使用 --password 指定加密密码")?;
    let stub_path = stub_path.unwrap_or_else(|| "stub.exe".to_string());

    // 确定输出路径
    let output_path = if overwrite {
        // 覆盖原文件，先输出到临时文件最后替换
        let p = Path::new(&input_path);
        let tmp = p.with_extension("tmp");
        tmp.to_string_lossy().to_string()
    } else {
        output.unwrap_or_else(|| {
            let p = Path::new(&input_path);
            let stem = p.file_stem().unwrap().to_string_lossy();
            format!("{}_locked.exe", stem)
        })
    };

    pack_exe(&input_path, &output_path, &password, &stub_path, algorithm)?;

    // 如果是覆盖模式，替换原文件
    if overwrite {
        fs::rename(&output_path, &input_path)
            .with_context(|| format!("覆盖原文件失败: {}", input_path))?;
        println!("✅ 加密成功！已覆盖原文件: {}", input_path);
    } else {
        println!("✅ 加密成功！输出文件: {}", output_path);
    }

    Ok(())
}

/// 加密EXE并嵌入到Stub中
fn pack_exe(
    input_path: &str,
    output_path: &str,
    password: &str,
    stub_path: &str,
    algorithm_name: &str,
) -> Result<()> {
    // 1. 读取原始EXE
    println!("📖 读取原始EXE: {}", input_path);
    let original_exe = fs::read(input_path).context("读取输入EXE失败")?;
    println!("   原始大小: {} bytes", original_exe.len());

    // 2. 读取Stub
    println!("📖 读取Stub加载器: {}", stub_path);
    let mut stub_data = fs::read(stub_path)
        .context("读取Stub失败，请先编译stub项目 (cd stub && cargo build --release)")?;
    println!("   Stub大小: {} bytes", stub_data.len());

    // 3. 使用选择的算法加密
    println!("🔐 使用 {} 算法加密...", algorithm_name);
    let algo = get_algorithm(algorithm_name);
    let EncryptedResult {
        ciphertext: encrypted_data,
        salt,
        nonce,
    } = algo.encrypt(&original_exe, password)?;
    println!("   加密后大小: {} bytes", encrypted_data.len());

    // 4. 组装最终文件
    // 格式: Stub数据 + 加密数据 + Salt(16) + Nonce(12) + 加密长度(8, u64 LE) + Magic(8)
    let encrypted_len = encrypted_data.len() as u64;

    stub_data.extend_from_slice(&encrypted_data);
    stub_data.extend_from_slice(&salt);
    stub_data.extend_from_slice(&nonce);
    stub_data.extend_from_slice(&encrypted_len.to_le_bytes());
    stub_data.extend_from_slice(MAGIC);

    // 5. 写入输出文件
    fs::write(output_path, &stub_data).context("写入输出文件失败")?;
    println!("💾 最终文件大小: {} bytes", stub_data.len());

    Ok(())
}
