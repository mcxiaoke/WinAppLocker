//! 诊断工具：检查加密后的 EXE 文件结构
//!
//! 用法：diagnose <file.exe>

use std::env;
use std::path::PathBuf;

use exelock_payload::Payload;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <file.exe>", args[0]);
        std::process::exit(1);
    }

    let path = PathBuf::from(&args[1]);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read file: {}", e);
            std::process::exit(1);
        }
    };

    println!("File size: {} bytes", data.len());
    println!("First 2 bytes: {:02X} {:02X}", data[0], data[1]);

    match Payload::from_file_tail(&data) {
        Ok(payload) => {
            println!("=== Payload parsed successfully ===");
            println!("Header:");
            println!("  format_version: {}", payload.header.format_version);
            println!("  flags: 0x{:08X}", payload.header.flags);
            println!("  algorithm_id: 0x{:04X}", payload.header.algorithm_id);
            println!("  kdf_id: 0x{:04X}", payload.header.kdf_id);
            println!("  kdf_iterations: {}", payload.header.kdf_iterations);
            println!("  salt_len: {}", payload.header.salt_len);
            println!("  nonce_len: {}", payload.header.nonce_len);
            println!("  ciphertext_len: {}", payload.header.ciphertext_len);
            println!("  plaintext_len: {}", payload.header.plaintext_len);
            println!("  plaintext_crc32: 0x{:08X}", payload.header.plaintext_crc32);
            println!("  original_subsystem: {}", payload.header.original_subsystem);
            println!("  original_machine: 0x{:04X}", payload.header.original_machine);
            println!("  extension_offset: {}", payload.header.extension_offset);
            println!("  header_size: {}", payload.header.header_size);
            println!("Material:");
            println!("  salt ({} bytes): {:?}", payload.salt.len(), &payload.salt[..payload.salt.len().min(16)]);
            println!("  nonce ({} bytes): {:?}", payload.nonce.len(), &payload.nonce);
            println!("  ciphertext ({} bytes, first 16): {:02X?}", payload.ciphertext.len(), &payload.ciphertext[..payload.ciphertext.len().min(16)]);
            println!("Extensions:");
            for ext in payload.extensions.iter() {
                let value_str = if ext.value.len() <= 32 {
                    format!("{:02X?}", ext.value)
                } else {
                    format!("{:02X?}... ({} bytes total)", &ext.value[..32], ext.value.len())
                };
                println!("  tag=0x{:04X} len={} value={}", ext.tag, ext.value.len(), value_str);
            }
            if let Some(aad) = payload.aad() {
                println!("AAD ({} bytes): {:02X?}", aad.len(), aad);
            } else {
                println!("AAD: None");
            }
            println!();
            println!("Stub size: {} bytes", data.len() - payload.header.header_size as usize - payload.salt.len() - payload.nonce.len() - payload.ciphertext.len() - 24);
        }
        Err(e) => {
            eprintln!("Failed to parse payload: {}", e);
            std::process::exit(1);
        }
    }
}
