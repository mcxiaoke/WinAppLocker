//! 密钥派生函数（KDF）trait 与实现。
//!
//! MVP 仅实现 PBKDF2（SHA-256 / SHA-512），不引入 Argon2id。

use crate::{CryptoError, SecretKey};
use pbkdf2::pbkdf2_hmac;
use sha2::{Sha256, Sha512};

/// KDF 参数。MVP 只用 `iterations`，未来 scrypt 等可走 `EXT_KDF_EXTRA` 扩展区。
#[derive(Debug, Clone, Copy)]
pub enum KdfParams {
    /// PBKDF2 迭代次数。
    Pbkdf2 { iterations: u32 },
}

pub trait Kdf: Send + Sync {
    /// KDF 注册表 ID，见 `docs/FORMAT.md §7`。
    fn id(&self) -> u16;
    /// 人类可读名称。
    fn name(&self) -> &'static str;
    /// 派生出的密钥字节长度。
    fn key_len(&self) -> usize;
    /// 从密码 + salt 派生密钥。返回的 `SecretKey` 在 drop 时自动清零。
    fn derive(&self, password: &[u8], salt: &[u8], params: KdfParams) -> Result<SecretKey, CryptoError>;
}

/// KDF ID 常量。与 `docs/FORMAT.md §7` 一致。
pub mod id {
    pub const PBKDF2_SHA256: u16 = 0x0001;
    pub const PBKDF2_SHA512: u16 = 0x0002;
    pub const SCRYPT: u16 = 0x0003;
}

pub fn kdf_by_id(id: u16) -> Option<Box<dyn Kdf>> {
    match id {
        id::PBKDF2_SHA256 => Some(Box::new(Pbkdf2Sha256)),
        id::PBKDF2_SHA512 => Some(Box::new(Pbkdf2Sha512)),
        _ => None,
    }
}

/// 列出所有内置 KDF ID（GUI 用于填充下拉框）。
pub fn builtin_kdf_ids() -> &'static [u16] {
    &[id::PBKDF2_SHA256, id::PBKDF2_SHA512]
}

/// 默认密钥长度 32 字节（AES-256 / ChaCha20 都是 32）。
const DEFAULT_KEY_LEN: usize = 32;

// ===================== PBKDF2-SHA256 =====================

pub struct Pbkdf2Sha256;

impl Kdf for Pbkdf2Sha256 {
    fn id(&self) -> u16 {
        id::PBKDF2_SHA256
    }
    fn name(&self) -> &'static str {
        "PBKDF2-HMAC-SHA256"
    }
    fn key_len(&self) -> usize {
        DEFAULT_KEY_LEN
    }
    fn derive(&self, password: &[u8], salt: &[u8], params: KdfParams) -> Result<SecretKey, CryptoError> {
        let iters = match params {
            KdfParams::Pbkdf2 { iterations } => {
                crate::validate_iterations(iterations)?;
                iterations
            }
        };
        let mut key = vec![0u8; DEFAULT_KEY_LEN];
        pbkdf2_hmac::<Sha256>(password, salt, iters, &mut key);
        Ok(SecretKey::new(key))
    }
}

// ===================== PBKDF2-SHA512 =====================

pub struct Pbkdf2Sha512;

impl Kdf for Pbkdf2Sha512 {
    fn id(&self) -> u16 {
        id::PBKDF2_SHA512
    }
    fn name(&self) -> &'static str {
        "PBKDF2-HMAC-SHA512"
    }
    fn key_len(&self) -> usize {
        DEFAULT_KEY_LEN
    }
    fn derive(&self, password: &[u8], salt: &[u8], params: KdfParams) -> Result<SecretKey, CryptoError> {
        let iters = match params {
            KdfParams::Pbkdf2 { iterations } => {
                crate::validate_iterations(iterations)?;
                iterations
            }
        };
        let mut key = vec![0u8; DEFAULT_KEY_LEN];
        pbkdf2_hmac::<Sha512>(password, salt, iters, &mut key);
        Ok(SecretKey::new(key))
    }
}
