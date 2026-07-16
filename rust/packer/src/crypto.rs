//! 自定义加密算法插件接口
//!
//! 你可以在这里实现自己的加密算法，只需要实现 CryptoAlgorithm trait

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;

/// 加密算法trait - 自定义算法只需实现这个接口
pub trait CryptoAlgorithm {
    /// 算法名称
    fn name(&self) -> &'static str;

    /// 加密数据
    fn encrypt(&self, data: &[u8], password: &str) -> Result<EncryptedResult>;

    /// 解密数据
    fn decrypt(&self, data: &[u8], password: &str, salt: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;
}

pub struct EncryptedResult {
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
}

// ========== 内置算法实现 ==========

/// AES-256-GCM (默认推荐)
pub struct Aes256GcmAlgorithm;

impl CryptoAlgorithm for Aes256GcmAlgorithm {
    fn name(&self) -> &'static str {
        "AES-256-GCM"
    }

    fn encrypt(&self, data: &[u8], password: &str) -> Result<EncryptedResult> {
        const ITERATIONS: u32 = 100_000;
        const KEY_LEN: usize = 32;
        const NONCE_LEN: usize = 12;
        const SALT_LEN: usize = 16;

        // 生成随机盐
        let mut salt = vec![0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        // PBKDF2密钥派生
        let mut key = vec![0u8; KEY_LEN];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, ITERATIONS, &mut key);

        // 加密
        let cipher = Aes256Gcm::new_from_slice(&key)?;
        let mut nonce_bytes = vec![0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data).map_err(|_| anyhow::anyhow!("加密失败"))?;

        Ok(EncryptedResult {
            ciphertext,
            salt,
            nonce: nonce_bytes,
        })
    }

    fn decrypt(&self, data: &[u8], password: &str, salt: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        const ITERATIONS: u32 = 100_000;
        const KEY_LEN: usize = 32;

        let mut key = vec![0u8; KEY_LEN];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, ITERATIONS, &mut key);

        let cipher = Aes256Gcm::new_from_slice(&key)?;
        let nonce = Nonce::from_slice(nonce);
        let plaintext = cipher.decrypt(nonce, data).map_err(|_| anyhow::anyhow!("解密失败"))?;

        Ok(plaintext)
    }
}

/// 国密SM4-GCM (需要额外依赖)
/// 可以使用 sm4 和 gcm 库实现
pub struct Sm4GcmAlgorithm;

impl CryptoAlgorithm for Sm4GcmAlgorithm {
    fn name(&self) -> &'static str {
        "SM4-GCM"
    }

    fn encrypt(&self, _data: &[u8], _password: &str) -> Result<EncryptedResult> {
        todo!("需要添加 sm4 依赖后实现")
    }

    fn decrypt(&self, _data: &[u8], _password: &str, _salt: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> {
        todo!("需要添加 sm4 依赖后实现")
    }
}

/// 自定义XOR+混淆算法示例 (仅演示，安全性低)
pub struct CustomXorAlgorithm;

impl CryptoAlgorithm for CustomXorAlgorithm {
    fn name(&self) -> &'static str {
        "XOR-Custom"
    }

    fn encrypt(&self, data: &[u8], password: &str) -> Result<EncryptedResult> {
        let key = password.as_bytes();
        let mut result = vec![0u8; data.len()];
        for i in 0..data.len() {
            result[i] = data[i] ^ key[i % key.len()].wrapping_add(i as u8);
        }

        Ok(EncryptedResult {
            ciphertext: result,
            salt: vec![0; 16],
            nonce: vec![0; 12],
        })
    }

    fn decrypt(&self, data: &[u8], password: &str, _salt: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(data, password).map(|r| r.ciphertext)
    }
}

/// ChaCha20-Poly1305 算法
pub struct ChaCha20Poly1305Algorithm;

impl CryptoAlgorithm for ChaCha20Poly1305Algorithm {
    fn name(&self) -> &'static str {
        "ChaCha20-Poly1305"
    }

    fn encrypt(&self, _data: &[u8], _password: &str) -> Result<EncryptedResult> {
        todo!("需要添加 chacha20poly1305 依赖后实现")
    }

    fn decrypt(&self, _data: &[u8], _password: &str, _salt: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> {
        todo!("需要添加 chacha20poly1305 依赖后实现")
    }
}

// 算法注册表
pub fn get_algorithm(name: &str) -> Box<dyn CryptoAlgorithm> {
    match name {
        "aes" | "aes256gcm" => Box::new(Aes256GcmAlgorithm),
        "sm4" => Box::new(Sm4GcmAlgorithm),
        "xor" => Box::new(CustomXorAlgorithm),
        "chacha20" => Box::new(ChaCha20Poly1305Algorithm),
        _ => Box::new(Aes256GcmAlgorithm),
    }
}
