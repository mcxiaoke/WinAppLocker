//! Stub - 运行时加载器 (入门版 - 同目录释放)
//! ✅ 释放到原EXE所在目录，解决DLL/配置文件依赖问题
//! ✅ 传递命令行参数
//! ✅ 等待进程退出后自动清理临时文件
//! ✅ 正确设置工作目录

#![windows_subsystem = "windows"]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::exit;
use windows::core::PCSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    CreateProcessA, WaitForSingleObject, GetExitCodeProcess, PROCESS_INFORMATION, STARTUPINFOA,
    INFINITE, PROCESS_CREATION_FLAGS,
};
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxA, MB_ICONERROR, MB_ICONWARNING, MB_OK, MESSAGEBOX_STYLE,
};

const ITERATIONS: u32 = 100_000;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 16;
const MAGIC: &[u8; 8] = b"EXELOCK1";

fn main() {
    // 获取自身路径和所在目录
    let own_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => {
            msg_box("错误", "无法获取程序路径", MB_ICONERROR);
            return;
        }
    };
    let own_dir = own_path.parent().unwrap_or_else(|| Path::new("."));

    // 1. 从自身提取加密数据
    let encrypted = match extract_payload(&own_path) {
        Some(e) => e,
        None => {
            msg_box("错误", "无效的程序文件或数据损坏", MB_ICONERROR);
            return;
        }
    };

    // 2. 获取密码
    let password = match get_password_from_user() {
        Some(p) => p,
        None => return,
    };

    // 3. 派生密钥并解密
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &encrypted.salt, ITERATIONS, &mut key);

    let cipher = match Aes256Gcm::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => {
            msg_box("错误", "初始化失败", MB_ICONERROR);
            return;
        }
    };

    let nonce = Nonce::from_slice(&encrypted.nonce);
    let original_exe = match cipher.decrypt(nonce, encrypted.data.as_ref()) {
        Ok(d) => d,
        Err(_) => {
            msg_box("密码错误", "请输入正确的密码后重试", MB_ICONERROR);
            return;
        }
    };

    // 4. 释放到同目录并执行
    match execute_decrypted_exe(&original_exe, own_dir) {
        Ok(exit_code) => exit(exit_code as i32),
        Err(e) => {
            msg_box("启动失败", &format!("程序启动失败: {}\n\n将尝试释放到临时目录...", e), MB_ICONWARNING);
            // Fallback: 如果当前目录不可写，尝试临时目录
            match execute_from_temp_dir(&original_exe, own_dir) {
                Ok(exit_code) => exit(exit_code as i32),
                Err(e2) => {
                    msg_box("启动失败", &format!("无法启动程序: {}", e2), MB_ICONERROR);
                }
            }
        }
    }
}

struct EncryptedPayload {
    data: Vec<u8>,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

fn extract_payload(own_path: &Path) -> Option<EncryptedPayload> {
    let own_data = fs::read(own_path).ok()?;
    let len = own_data.len();

    if len < 8 + 8 + NONCE_LEN + SALT_LEN {
        return None;
    }

    if &own_data[len - 8..] != MAGIC {
        return None;
    }

    let encrypted_len = u64::from_le_bytes(own_data[len - 16..len - 8].try_into().ok()?) as usize;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&own_data[len - 16 - NONCE_LEN..len - 16]);
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&own_data[len - 16 - NONCE_LEN - SALT_LEN..len - 16 - NONCE_LEN]);

    let data_start = len - 16 - NONCE_LEN - SALT_LEN - encrypted_len;
    let data = own_data[data_start..len - 16 - NONCE_LEN - SALT_LEN].to_vec();

    Some(EncryptedPayload { data, salt, nonce })
}

fn get_password_from_user() -> Option<String> {
    unsafe { AllocConsole(); }

    println!("=================================");
    println!("       ExeLock 密码保护");
    println!("=================================");
    println!();
    print!("请输入启动密码: ");
    let _ = std::io::stdout().flush();

    let mut password = String::new();
    match std::io::stdin().read_line(&mut password) {
        Ok(_) => {
            unsafe { FreeConsole(); }
            let pwd = password.trim().to_string();
            if pwd.is_empty() { None } else { Some(pwd) }
        }
        Err(_) => {
            unsafe { FreeConsole(); }
            None
        }
    }
}

/// 在原EXE所在目录释放并执行（推荐方式，解决DLL依赖问题）
fn execute_decrypted_exe(exe_data: &[u8], working_dir: &Path) -> Result<u32, String> {
    // 生成同目录下的临时文件名
    let temp_path = generate_temp_path(working_dir);

    // 写入解密后的EXE
    fs::write(&temp_path, exe_data).map_err(|e| format!("写入文件失败: {}", e))?;

    // 获取命令行参数
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cmd_line = format!("\"{}\"", temp_path.to_string_lossy());
    for arg in &args {
        cmd_line.push(' ');
        if arg.contains(' ') {
            cmd_line.push_str(&format!("\"{}\"", arg));
        } else {
            cmd_line.push_str(arg);
        }
    }
    cmd_line.push('\0');

    // 启动进程
    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let working_dir_str = working_dir.to_string_lossy().to_string() + "\0";

    let success = unsafe {
        CreateProcessA(
            PCSTR::null(),
            PSTR(cmd_line.as_ptr() as *mut u8),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0),
            None,
            PCSTR(working_dir_str.as_ptr()),
            &si,
            &mut pi,
        )
    };

    if success.is_err() {
        let _ = fs::remove_file(&temp_path);
        return Err("创建进程失败".to_string());
    }

    // 关闭线程句柄，不需要
    unsafe { let _ = CloseHandle(pi.hThread); }

    // 等待进程结束
    unsafe { WaitForSingleObject(pi.hProcess, INFINITE); }

    // 获取退出码
    let mut exit_code = 0u32;
    unsafe {
        let _ = GetExitCodeProcess(pi.hProcess, &mut exit_code);
        let _ = CloseHandle(pi.hProcess);
    }

    // 尝试删除临时文件（如果删不掉也没关系，下次启动会清理）
    let _ = fs::remove_file(&temp_path);
    // 尝试清理之前遗留的临时文件
    cleanup_old_temp_files(working_dir);

    Ok(exit_code)
}

/// Fallback: 释放到临时目录执行（当原目录不可写时）
fn execute_from_temp_dir(exe_data: &[u8], working_dir: &Path) -> Result<u32, String> {
    let mut temp_path = std::env::temp_dir();
    let temp_name = format!("exelock_{}.exe", random_u64());
    temp_path.push(temp_name);

    fs::write(&temp_path, exe_data).map_err(|e| e.to_string())?;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cmd_line = format!("\"{}\"", temp_path.to_string_lossy());
    for arg in &args {
        cmd_line.push(' ');
        if arg.contains(' ') {
            cmd_line.push_str(&format!("\"{}\"", arg));
        } else {
            cmd_line.push_str(arg);
        }
    }
    cmd_line.push('\0');

    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let working_dir_str = working_dir.to_string_lossy().to_string() + "\0";

    let success = unsafe {
        CreateProcessA(
            PCSTR::null(),
            PSTR(cmd_line.as_ptr() as *mut u8),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0),
            None,
            PCSTR(working_dir_str.as_ptr()),
            &si,
            &mut pi,
        )
    };

    if success.is_err() {
        let _ = fs::remove_file(&temp_path);
        return Err("创建进程失败".to_string());
    }

    unsafe { let _ = CloseHandle(pi.hThread); }
    unsafe { WaitForSingleObject(pi.hProcess, INFINITE); }

    let mut exit_code = 0u32;
    unsafe {
        let _ = GetExitCodeProcess(pi.hProcess, &mut exit_code);
        let _ = CloseHandle(pi.hProcess);
    }

    let _ = fs::remove_file(&temp_path);
    Ok(exit_code)
}

/// 生成同目录下的临时文件名，避免和原文件冲突
fn generate_temp_path(dir: &Path) -> PathBuf {
    let random_id = random_u64();
    // 使用隐藏文件名，用户不容易看到
    let temp_name = format!("~el{:x}.tmp", random_id);
    dir.join(temp_name)
}

/// 清理之前运行遗留的临时文件
fn cleanup_old_temp_files(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                // 清理我们的临时文件
                if name.starts_with("~el") && name.ends_with(".tmp") {
                    // 尝试删除，删不掉就算了（可能被占用）
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}

fn random_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    // 简单的随机数，避免和其他实例冲突
    ((t >> 16) ^ t) as u64
}

fn msg_box(title: &str, text: &str, icon: MESSAGEBOX_STYLE) {
    let title = title.to_string() + "\0";
    let text = text.to_string() + "\0";
    unsafe {
        MessageBoxA(
            windows::Win32::Foundation::HWND(0),
            PCSTR(text.as_ptr()),
            PCSTR(title.as_ptr()),
            MB_OK | icon,
        );
    }
}

use windows::core::PSTR;

#[link(name = "kernel32")]
extern "system" {
    fn AllocConsole() -> i32;
    fn FreeConsole() -> i32;
}
