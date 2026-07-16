//! Packer 加密核心逻辑（与 UI 解耦）。
//!
//! GUI 与未来可能的 CLI 都调用 [`pack`]。

use std::path::PathBuf;
use std::time::SystemTime;

use exelock_crypto::{algorithm_by_id, kdf_by_id, CryptoAlgorithm, Kdf, KdfParams};
use exelock_payload::writer::{crc32_of, default_aad};
use exelock_payload::PayloadBuilder;
use exelock_pe::{PeError, PeInfo, Subsystem};
use thiserror::Error;

use crate::stub_selector::{select_stub, StubPreference};

/// packer 加密选项。
#[derive(Debug, Clone)]
pub struct PackOptions {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub password: String,
    pub algorithm_id: u16,
    pub kdf_id: u16,
    pub kdf_iterations: u32,
    pub salt_len: u16,
    pub use_aad: bool,
    pub erase_payload: bool,
    pub stub_preference: StubPreference,
    /// 用户自定义 TLV 扩展（tag, value）。
    pub custom_extensions: Vec<(u16, Vec<u8>)>,
}

impl Default for PackOptions {
    fn default() -> Self {
        use exelock_crypto::{algorithm, kdf};
        Self {
            input_path: PathBuf::new(),
            output_path: PathBuf::new(),
            password: String::new(),
            algorithm_id: algorithm::id::AES_256_GCM,
            kdf_id: kdf::id::PBKDF2_SHA256,
            kdf_iterations: 600_000,
            salt_len: 16,
            use_aad: true,
            erase_payload: true,
            stub_preference: StubPreference::default(),
            custom_extensions: Vec::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum PackError {
    #[error("读取输入文件失败: {0}")]
    ReadInput(std::io::Error),
    #[error("写入输出文件失败: {0}")]
    WriteOutput(std::io::Error),
    #[error("PE 解析失败: {0}")]
    Pe(#[from] PeError),
    #[error(".NET 托管程序暂不支持")]
    DotNetNotSupported,
    #[error("加密失败: {0}")]
    Crypto(exelock_crypto::CryptoError),
    #[error("Payload 构建失败: {0}")]
    Payload(exelock_payload::PayloadError),
    #[error("密码不能为空")]
    EmptyPassword,
    #[error("密码长度过短（最少 {0} 字符）")]
    PasswordTooShort(usize),
}

const MIN_PASSWORD_LEN: usize = 4;

/// 加密进度回调。`fraction` ∈ [0.0, 1.0]。
pub type ProgressFn = Box<dyn FnMut(f32) + Send>;

/// 加密一个 EXE，生成 locked 输出文件。
///
/// 流程：
/// 1. 读取原 EXE
/// 2. PE 解析（提取子系统/机器类型，检测 .NET）
/// 3. 选择 stub 模板
/// 4. 生成 salt / nonce
/// 5. KDF 派生密钥
/// 6. AEAD 加密（可选 AAD）
/// 7. 用 PayloadBuilder 组装 payload
/// 8. stub + payload 写入输出文件
pub fn pack(opts: &PackOptions, mut progress: Option<ProgressFn>) -> Result<PackReport, PackError> {
    // 0. 校验
    if opts.password.is_empty() {
        return Err(PackError::EmptyPassword);
    }
    if opts.password.len() < MIN_PASSWORD_LEN {
        return Err(PackError::PasswordTooShort(MIN_PASSWORD_LEN));
    }

    let mut report_progress = |frac: f32| {
        if let Some(p) = progress.as_mut() {
            p(frac);
        }
    };

    // 1. 读取原 EXE
    let original_bytes =
        std::fs::read(&opts.input_path).map_err(PackError::ReadInput)?;
    report_progress(0.15);

    // 2. PE 解析
    let pe_info = PeInfo::parse(&original_bytes)?;
    if pe_info.is_dotnet {
        return Err(PackError::DotNetNotSupported);
    }
    report_progress(0.25);

    // 3. 选择 stub
    let (stub_template, _chosen_subsystem) =
        select_stub(pe_info.subsystem, opts.stub_preference);
    report_progress(0.30);

    // 4. 生成 salt / nonce
    let salt = exelock_crypto::random_bytes(opts.salt_len as usize);
    let algo = algorithm_by_id(opts.algorithm_id)
        .ok_or_else(|| PackError::Crypto(exelock_crypto::CryptoError::UnknownAlgorithm(opts.algorithm_id)))?;
    let nonce = exelock_crypto::random_bytes(algo.nonce_len());
    report_progress(0.35);

    // 5. KDF 派生密钥
    let kdf = kdf_by_id(opts.kdf_id)
        .ok_or_else(|| PackError::Crypto(exelock_crypto::CryptoError::UnknownKdf(opts.kdf_id)))?;
    let key = kdf
        .derive(
            opts.password.as_bytes(),
            &salt,
            KdfParams::Pbkdf2 {
                iterations: opts.kdf_iterations,
            },
        )
        .map_err(PackError::Crypto)?;
    report_progress(0.50);

    // 6. AEAD 加密
    let aad_bytes = if opts.use_aad {
        Some(default_aad(
            opts.algorithm_id,
            opts.kdf_id,
            opts.kdf_iterations,
            pe_info.subsystem.raw() as u32,
            pe_info.machine.raw(),
        ))
    } else {
        None
    };
    let ciphertext = algo
        .encrypt(&original_bytes, &key, &nonce, aad_bytes.as_deref())
        .map_err(PackError::Crypto)?;
    drop(key); // 立即 drop 触发 zeroize
    report_progress(0.75);

    // 7. 组装 payload
    let plaintext_crc = crc32_of(&original_bytes);
    let original_name = opts
        .input_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut builder = PayloadBuilder::new(opts.algorithm_id, opts.kdf_id, opts.kdf_iterations)
        .original_pe_info(
            pe_info.subsystem.raw() as u32,
            pe_info.machine.raw(),
            original_name.as_deref(),
        )
        .original_timestamp(timestamp)
        .plaintext_meta(original_bytes.len() as u64, plaintext_crc)
        .material(salt, nonce, ciphertext);

    if opts.use_aad {
        builder = builder.use_aad(None);
    }
    builder = builder.erase_payload(opts.erase_payload);

    // 用户自定义扩展
    for (tag, value) in &opts.custom_extensions {
        builder = builder.extension(*tag, value.clone());
    }

    let payload = builder.build();
    report_progress(0.90);

    // 8. 写入输出文件：stub + payload
    let mut out = Vec::with_capacity(stub_template.bytes.len() + payload.len());
    out.extend_from_slice(&stub_template.bytes);
    out.extend_from_slice(&payload);
    std::fs::write(&opts.output_path, &out).map_err(PackError::WriteOutput)?;
    report_progress(1.0);

    Ok(PackReport {
        original_size: original_bytes.len(),
        output_size: out.len(),
        stub_subsystem: stub_template.subsystem,
        original_subsystem: pe_info.subsystem,
        algorithm_id: opts.algorithm_id,
        kdf_id: opts.kdf_id,
        kdf_iterations: opts.kdf_iterations,
        used_aad: opts.use_aad,
        used_erase_payload: opts.erase_payload,
    })
}

/// 加密结果报告。
#[derive(Debug, Clone)]
pub struct PackReport {
    pub original_size: usize,
    pub output_size: usize,
    pub stub_subsystem: Subsystem,
    pub original_subsystem: Subsystem,
    pub algorithm_id: u16,
    pub kdf_id: u16,
    pub kdf_iterations: u32,
    pub used_aad: bool,
    pub used_erase_payload: bool,
}

// 保留 EXT_ORIGINAL_NAME 引用（文档性，未来可能用于诊断）
#[allow(dead_code)]
fn _ext_marker() -> u16 {
    exelock_payload::header::EXT_ORIGINAL_NAME
}
