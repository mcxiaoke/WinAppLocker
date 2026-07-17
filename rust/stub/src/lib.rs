//! EXELock stub 入口逻辑。
//!
//! stub 是被加密后的 EXE 中的"前置代码"部分：
//! 1. 读取自身 EXE 文件字节
//! 2. 从尾部解析 payload（header + salt + nonce + ciphertext + footer）
//! 3. 弹出 Win32 密码对话框（最多重试若干次）
//! 4. 用密码 + salt + KDF 派生密钥
//! 5. AEAD 解密 ciphertext
//! 6. 校验明文长度与 CRC32
//! 7. （若启用）擦除内存中的 payload 字段
//! 8. 调用 `exelock_pe::run_pe()` 在当前进程内加载并执行原 EXE
//!
//! 详见 `docs/ARCHITECTURE.md §5.5`。

use std::path::PathBuf;
use std::io::Write;

use exelock_crypto::{algorithm_by_id, kdf_by_id, KdfParams};
use exelock_payload::header::{FLAG_ERASE_PAYLOAD, FLAG_USE_AAD};
use exelock_payload::Payload;
use exelock_pe::run_pe;

use crc32fast::Hasher as Crc32;

mod password_ui;

/// 版本信息（由 build.rs 注入）。
/// packer 通过在 stub 二进制中搜索 "EXELOCK_VER|" 标记来读取这些信息。
#[used]
static VERSION_BLOB: &str = concat!(
    "EXELOCK_VER|",
    env!("STUB_VERSION"),
    "|",
    env!("STUB_BUILD_TIME"),
    "|",
    env!("STUB_GIT_HASH"),
    "|EXELOCK_END"
);

/// 调试日志：设环境变量 EXELOCK_DEBUG=1 写入 %TEMP%\exelock_debug.log
fn dbg_log(msg: &str) {
    if std::env::var("EXELOCK_DEBUG").is_err() { return; }
    if let Some(path) = std::env::temp_dir().join("exelock_debug.log").to_str() {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{}", msg);
            let _ = f.flush();
        }
    }
}

/// 密码错误时的最大尝试次数（输错一次直接退出，避免暴力破解）。
const MAX_PASSWORD_RETRIES: usize = 1;

/// stub 返回的错误。
#[derive(Debug)]
pub enum StubError {
    /// 无法读取自身 EXE 文件
    ReadSelf(std::io::Error),
    /// payload 解析失败
    Payload(exelock_payload::PayloadError),
    /// 用户取消密码输入
    PasswordCancelled,
    /// 密码错误次数过多
    TooManyAttempts,
    /// 解密失败（密码错误或数据损坏）
    Decrypt(exelock_crypto::CryptoError),
    /// 明文校验失败（长度或 CRC32 不匹配）
    PlaintextVerify { field: &'static str },
    /// RunPE 加载失败
    Loader(exelock_pe::LoaderError),
    /// 未知算法 / KDF ID
    UnknownAlgoOrKdf,
}

impl std::fmt::Display for StubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StubError::ReadSelf(e) => write!(f, "读取自身 EXE 失败: {}", e),
            StubError::Payload(e) => write!(f, "payload 解析失败: {}", e),
            StubError::PasswordCancelled => write!(f, "用户取消密码输入"),
            StubError::TooManyAttempts => write!(f, "密码错误次数过多"),
            StubError::Decrypt(e) => write!(f, "解密失败: {}", e),
            StubError::PlaintextVerify { field } => {
                write!(f, "明文校验失败: {}", field)
            }
            StubError::Loader(e) => write!(f, "PE 加载失败: {}", e),
            StubError::UnknownAlgoOrKdf => write!(f, "未知的算法或 KDF ID"),
        }
    }
}

impl std::error::Error for StubError {}

/// stub GUI 入口（用 Win32 对话框输入密码）。返回进程退出码。
pub fn run() -> u32 {
    dbg_log("[stub] run() entered");
    match run_inner(Some(true), None) {
        Ok(code) => {
            dbg_log(&format!("[stub] run ok: code={}", code));
            code
        }
        Err(e) => {
            dbg_log(&format!("[stub] run err: {}", e));
            let msg = format!("EXELock 启动失败：\n\n{}", e);
            password_ui::show_error_box(&msg);
            1
        }
    }
}

/// stub Console 入口（用命令行输入密码）。返回进程退出码。
///
/// 适合原 EXE 是 Console 子系统的情况：
/// 在控制台中提示用户输入密码（不回显），而不是弹 GUI 对话框。
pub fn run_console() -> u32 {
    dbg_log("[stub] run_console() entered");
    match run_inner(Some(false), None) {
        Ok(code) => {
            dbg_log(&format!("[stub] run_console ok: code={}", code));
            code
        }
        Err(e) => {
            dbg_log(&format!("[stub] run_console err: {}", e));
            eprintln!("EXELock 启动失败：{}", e);
            1
        }
    }
}

/// stub 测试入口（内置密码，跳过密码 UI）。返回进程退出码。
pub fn run_hardcoded(password: &str) -> u32 {
    dbg_log(&format!("[stub] run_hardcoded() entered, pw_len={}", password.len()));
    match run_inner(None, Some(password)) {
        Ok(code) => {
            dbg_log(&format!("[stub] run_hardcoded ok: code={}", code));
            code
        }
        Err(e) => {
            dbg_log(&format!("[stub] run_hardcoded err: {}", e));
            eprintln!("EXELock 启动失败：{}", e);
            1
        }
    }
}

/// `use_gui`: Some(true)=GUI对话框, Some(false)=命令行输入, None=内置密码
fn run_inner(use_gui: Option<bool>, hardcoded_password: Option<&str>) -> Result<u32, StubError> {
    dbg_log("[stub] step 1: read self exe");
    // 1. 读取自身 EXE
    let self_path = current_exe_path()?;
    let exe_bytes = std::fs::read(&self_path).map_err(StubError::ReadSelf)?;
    dbg_log(&format!("[stub] step 1 ok: exe size = {} bytes", exe_bytes.len()));

    dbg_log("[stub] step 2: parse payload");
    // 2. 解析 payload
    let payload = Payload::from_file_tail(&exe_bytes).map_err(StubError::Payload)?;
    dbg_log(&format!("[stub] step 2 ok: algo=0x{:04x} kdf=0x{:04x} iters={} ct_len={}",
        payload.header.algorithm_id, payload.header.kdf_id,
        payload.header.kdf_iterations, payload.ciphertext.len()));

    dbg_log("[stub] step 3: resolve algo/kdf");
    // 3. 提取算法与 KDF
    let algo = algorithm_by_id(payload.header.algorithm_id)
        .ok_or(StubError::UnknownAlgoOrKdf)?;
    let kdf = kdf_by_id(payload.header.kdf_id).ok_or(StubError::UnknownAlgoOrKdf)?;
    dbg_log("[stub] step 3 ok");

    dbg_log("[stub] step 4: validate iters");
    // 4. 校验迭代次数（防止恶意文件触发 DoS）
    if let Err(e) = exelock_crypto::validate_iterations(payload.header.kdf_iterations) {
        return Err(StubError::Decrypt(e));
    }

    dbg_log("[stub] step 5: extract aad");
    // 5. 提取 AAD（若启用）
    let aad = if payload.header.flags & FLAG_USE_AAD != 0 {
        payload.aad()
    } else {
        None
    };
    dbg_log(&format!("[stub] step 5 ok: aad={}", if aad.is_some() { "some" } else { "none" }));

    dbg_log("[stub] step 6: get password");
    // 6. 密码输入循环
    let mut plaintext: Option<Vec<u8>> = None;
    let mut last_error: Option<String> = None;

    // 测试模式：内置密码，只尝试一次
    let max_attempts = if hardcoded_password.is_some() { 1 } else { MAX_PASSWORD_RETRIES };

    for attempt in 0..max_attempts {
        dbg_log(&format!("[stub] attempt {}", attempt));

        let password: String = if let Some(hp) = hardcoded_password {
            dbg_log("[stub] using hardcoded password");
            hp.to_string()
        } else {
            let prompt_msg = if attempt == 0 {
                None
            } else {
                Some("密码错误，请重新输入")
            };
            // 根据模式选择 GUI 对话框或命令行输入
            let result = match use_gui {
                Some(false) => {
                    dbg_log("[stub] calling prompt_password_console...");
                    password_ui::prompt_password_console(prompt_msg)
                }
                _ => {
                    dbg_log("[stub] calling prompt_password...");
                    password_ui::prompt_password(prompt_msg)
                }
            };
            match result {
                Ok(Some(p)) => p,
                Ok(None) => return Err(StubError::PasswordCancelled),
                Err(_) => return Err(StubError::PasswordCancelled),
            }
        };
        dbg_log("[stub] password obtained");

        // 派生密钥
        dbg_log("[stub] deriving key...");
        let key = match kdf.derive(
            password.as_bytes(),
            &payload.salt,
            KdfParams::Pbkdf2 {
                iterations: payload.header.kdf_iterations,
            },
        ) {
            Ok(k) => k,
            Err(e) => {
                last_error = Some(format!("KDF 失败: {}", e));
                continue;
            }
        };
        dbg_log("[stub] key derived");

        // 解密
        dbg_log("[stub] decrypting...");
        match algo.decrypt(&payload.ciphertext, &key, &payload.nonce, aad) {
            Ok(pt) => {
                plaintext = Some(pt);
                break;
            }
            Err(_e) => {
                last_error = Some("密码错误".to_string());
                continue;
            }
        }
    }

    let plaintext = plaintext.ok_or(StubError::TooManyAttempts)?;
    let _ = last_error; // 不再需要
    dbg_log(&format!("[stub] decrypt ok: plaintext len = {}", plaintext.len()));

    // 7. 校验明文长度与 CRC32
    dbg_log("[stub] step 7: verify crc32");
    if plaintext.len() as u64 != payload.header.plaintext_len {
        return Err(StubError::PlaintextVerify { field: "长度" });
    }
    let mut crc = Crc32::new();
    crc.update(&plaintext);
    let actual_crc = crc.finalize();
    if actual_crc != payload.header.plaintext_crc32 {
        return Err(StubError::PlaintextVerify { field: "CRC32" });
    }
    dbg_log("[stub] step 7 ok: crc verified");

    // 8. 擦除 payload 字段（若启用）
    #[cfg(feature = "erase-payload")]
    if payload.header.flags & FLAG_ERASE_PAYLOAD != 0 {
        // MVP 阶段为 no-op（详见 docs/ARCHITECTURE.md）。
    }

    // 9. 调用 RunPE 加载原 EXE
    dbg_log(&format!("[stub] step 9: calling run_pe, plaintext @ {:p}, len={}", plaintext.as_ptr(), plaintext.len()));
    // run_pe 成功时不返回（原 EXE 调用 ExitProcess 退出进程），
    // 失败时返回 LoaderError。
    let exit_code = run_pe(&plaintext).map_err(StubError::Loader)?;
    dbg_log(&format!("[stub] run_pe returned: {}", exit_code));

    Ok(exit_code)
}

/// 获取当前 EXE 的路径。
fn current_exe_path() -> Result<PathBuf, StubError> {
    std::env::current_exe()
        .map_err(|e| StubError::ReadSelf(std::io::Error::new(std::io::ErrorKind::Other, e)))
}
