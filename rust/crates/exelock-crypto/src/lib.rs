//! EXELock 共享加密库。
//!
//! 提供 `CryptoAlgorithm` / `Kdf` 两个 trait 与具体实现，
//! packer 与 stub 共用同一份实现，避免重复。
//!
//! 详见 `docs/FORMAT.md` 的算法注册表与 KDF 注册表。

pub mod algorithm;
pub mod kdf;

pub use algorithm::{algorithm_by_id, CryptoAlgorithm};
pub use kdf::{kdf_by_id, Kdf, KdfParams};

use thiserror::Error;
use zeroize::Zeroizing;

/// 密钥类型：drop 时自动安全清零。
pub type SecretKey = Zeroizing<Vec<u8>>;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("未知算法 ID: 0x{0:04x}")]
    UnknownAlgorithm(u16),
    #[error("未知 KDF ID: 0x{0:04x}")]
    UnknownKdf(u16),
    #[error("密钥长度错误: 期望 {expected}, 实际 {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Nonce 长度错误: 期望 {expected}, 实际 {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },
    #[error("加解密失败: {0}")]
    Aead(String),
    #[error("迭代次数超出允许范围: {0}")]
    InvalidIterations(u32),
}

/// 生成密码学安全的随机字节（用 `OsRng`）。
pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// 迭代次数的安全范围。
/// 上限防止恶意文件触发 DoS（stub 解析时拒绝超大值）。
pub const MIN_ITERATIONS: u32 = 100_000;
pub const MAX_ITERATIONS: u32 = 100_000_000;

/// 校验迭代次数是否在允许范围内。
pub fn validate_iterations(iters: u32) -> Result<(), CryptoError> {
    if iters < MIN_ITERATIONS || iters > MAX_ITERATIONS {
        return Err(CryptoError::InvalidIterations(iters));
    }
    Ok(())
}
