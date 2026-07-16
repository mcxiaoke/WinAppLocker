//! AEAD 对称加密算法 trait 与实现。

use crate::{CryptoError, SecretKey};
// aes-gcm / chacha20poly1305 都 re-export 了 `aead` crate，复用即可。
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;

/// AEAD 加密算法接口。
///
/// 所有实现必须：
/// - 自报 `id()`（写入 payload header 的 `algorithm_id`）
/// - 自报 `nonce_len()`（packer 据此生成正确长度 nonce）
/// - 支持 AAD（`Option<&[u8]>`，None 表示不启用）
pub trait CryptoAlgorithm: Send + Sync {
    /// 算法注册表 ID，见 `docs/FORMAT.md §6`。
    fn id(&self) -> u16;
    /// 人类可读名称（用于 GUI 显示）。
    fn name(&self) -> &'static str;
    /// Nonce/IV 字节长度。
    fn nonce_len(&self) -> usize;
    /// 认证 tag 字节长度（AEAD）。
    fn tag_len(&self) -> usize;
    /// 密钥字节长度。
    fn key_len(&self) -> usize;

    /// 加密。返回 `ciphertext || tag`。
    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError>;

    /// 解密。输入为 `ciphertext || tag`，返回明文。
    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError>;
}

/// 派生密钥的辅助：从 `SecretKey` 取出 `&[u8]`。
pub fn key_bytes(k: &SecretKey) -> &[u8] {
    k.as_slice()
}

// ===================== 算法注册表 =====================

/// 算法 ID 常量。与 `docs/FORMAT.md §6` 保持一致。
pub mod id {
    pub const AES_256_GCM: u16 = 0x0001;
    pub const CHACHA20_POLY1305: u16 = 0x0002;
    pub const AES_128_GCM: u16 = 0x0003;
    pub const SM4_GCM: u16 = 0x0004;
    pub const XCHACHA20_POLY1305: u16 = 0x0005;
}

/// 按 ID 查找算法实现。未知 ID 返回 `None`，由调用方决定拒绝。
pub fn algorithm_by_id(id: u16) -> Option<Box<dyn CryptoAlgorithm>> {
    match id {
        id::AES_256_GCM => Some(Box::new(Aes256GcmAlg)),
        id::CHACHA20_POLY1305 => Some(Box::new(ChaCha20Poly1305Alg)),
        _ => None,
    }
}

/// 列出所有内置算法 ID（GUI 用于填充下拉框）。
pub fn builtin_algorithm_ids() -> &'static [u16] {
    &[id::AES_256_GCM, id::CHACHA20_POLY1305]
}

// ===================== AES-256-GCM =====================

pub struct Aes256GcmAlg;

const AES_256_KEY_LEN: usize = 32;
const GCM_NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

impl CryptoAlgorithm for Aes256GcmAlg {
    fn id(&self) -> u16 {
        id::AES_256_GCM
    }
    fn name(&self) -> &'static str {
        "AES-256-GCM"
    }
    fn nonce_len(&self) -> usize {
        GCM_NONCE_LEN
    }
    fn tag_len(&self) -> usize {
        GCM_TAG_LEN
    }
    fn key_len(&self) -> usize {
        AES_256_KEY_LEN
    }

    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        if key.len() != AES_256_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: AES_256_KEY_LEN,
                actual: key.len(),
            });
        }
        if nonce.len() != GCM_NONCE_LEN {
            return Err(CryptoError::InvalidNonceLength {
                expected: GCM_NONCE_LEN,
                actual: nonce.len(),
            });
        }
        let cipher = Aes256Gcm::new_from_slice(key).expect("key length checked");
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        let payload = Payload { msg: plaintext, aad: aad.unwrap_or(&[]) };
        cipher
            .encrypt(nonce, payload)
            .map_err(|e| CryptoError::Aead(e.to_string()))
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        if key.len() != AES_256_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: AES_256_KEY_LEN,
                actual: key.len(),
            });
        }
        if nonce.len() != GCM_NONCE_LEN {
            return Err(CryptoError::InvalidNonceLength {
                expected: GCM_NONCE_LEN,
                actual: nonce.len(),
            });
        }
        let cipher = Aes256Gcm::new_from_slice(key).expect("key length checked");
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        let payload = Payload { msg: ciphertext, aad: aad.unwrap_or(&[]) };
        cipher
            .decrypt(nonce, payload)
            .map_err(|e| CryptoError::Aead(e.to_string()))
    }
}

// ===================== ChaCha20-Poly1305 =====================

pub struct ChaCha20Poly1305Alg;

const CHACHA_KEY_LEN: usize = 32;
const CHACHA_NONCE_LEN: usize = 12;
const POLY1305_TAG_LEN: usize = 16;

impl CryptoAlgorithm for ChaCha20Poly1305Alg {
    fn id(&self) -> u16 {
        id::CHACHA20_POLY1305
    }
    fn name(&self) -> &'static str {
        "ChaCha20-Poly1305"
    }
    fn nonce_len(&self) -> usize {
        CHACHA_NONCE_LEN
    }
    fn tag_len(&self) -> usize {
        POLY1305_TAG_LEN
    }
    fn key_len(&self) -> usize {
        CHACHA_KEY_LEN
    }

    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        if key.len() != CHACHA_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: CHACHA_KEY_LEN,
                actual: key.len(),
            });
        }
        if nonce.len() != CHACHA_NONCE_LEN {
            return Err(CryptoError::InvalidNonceLength {
                expected: CHACHA_NONCE_LEN,
                actual: nonce.len(),
            });
        }
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key length checked");
        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        let payload = Payload { msg: plaintext, aad: aad.unwrap_or(&[]) };
        cipher
            .encrypt(nonce, payload)
            .map_err(|e| CryptoError::Aead(e.to_string()))
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        if key.len() != CHACHA_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: CHACHA_KEY_LEN,
                actual: key.len(),
            });
        }
        if nonce.len() != CHACHA_NONCE_LEN {
            return Err(CryptoError::InvalidNonceLength {
                expected: CHACHA_NONCE_LEN,
                actual: nonce.len(),
            });
        }
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key length checked");
        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        let payload = Payload { msg: ciphertext, aad: aad.unwrap_or(&[]) };
        cipher
            .decrypt(nonce, payload)
            .map_err(|e| CryptoError::Aead(e.to_string()))
    }
}
