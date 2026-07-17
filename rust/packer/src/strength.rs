//! 加密强度预设。
//!
//! 详见 `docs/FORMAT.md §8` 与 `docs/ARCHITECTURE.md §7`。
//! 预设本身不写入 payload，只把实际生效的字段写入。

use exelock_crypto::{algorithm, kdf};

/// 加密强度预设。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    Fast,
    Balanced,
    Secure,
    Custom,
}

impl Strength {
    pub fn label(self) -> &'static str {
        match self {
            Strength::Fast => "fast（快速）",
            Strength::Balanced => "balanced（平衡）",
            Strength::Secure => "secure（高安全）",
            Strength::Custom => "自定义",
        }
    }

    pub fn all() -> &'static [Strength] {
        &[Strength::Fast, Strength::Balanced, Strength::Secure, Strength::Custom]
    }
}

/// 预设对应的具体参数。
#[derive(Debug, Clone, Copy)]
pub struct StrengthSpec {
    pub algorithm_id: u16,
    pub kdf_id: u16,
    pub kdf_iterations: u32,
    pub use_aad: bool,
    pub erase_payload: bool,
}

impl StrengthSpec {
    /// 返回指定预设的参数。Custom 返回 Balanced 的值作为起点（GUI 会在用户编辑后切换到 Custom）。
    pub fn for_strength(s: Strength) -> Self {
        match s {
            Strength::Fast => Self {
                algorithm_id: algorithm::id::AES_256_GCM,
                kdf_id: kdf::id::PBKDF2_SHA256,
                kdf_iterations: 100_000,
                use_aad: false,
                erase_payload: false,
            },
            Strength::Balanced | Strength::Custom => Self {
                algorithm_id: algorithm::id::AES_256_GCM,
                kdf_id: kdf::id::PBKDF2_SHA256,
                kdf_iterations: 600_000,
                use_aad: true,
                erase_payload: true,
            },
            Strength::Secure => Self {
                algorithm_id: algorithm::id::CHACHA20_POLY1305,
                kdf_id: kdf::id::PBKDF2_SHA512,
                kdf_iterations: 2_000_000,
                use_aad: true,
                erase_payload: true,
            },
        }
    }

    /// 默认参数（Balanced）。UI 不再暴露强度选择，统一使用此预设。
    pub fn balanced() -> Self {
        Self::for_strength(Strength::Balanced)
    }
}

/// 算法 ID → 人类可读名称（GUI 下拉框显示）。
pub fn algorithm_name(id: u16) -> &'static str {
    match id {
        algorithm::id::AES_256_GCM => "AES-256-GCM",
        algorithm::id::CHACHA20_POLY1305 => "ChaCha20-Poly1305",
        _ => "未知算法",
    }
}

/// KDF ID → 人类可读名称（GUI 下拉框显示）。
pub fn kdf_name(id: u16) -> &'static str {
    match id {
        kdf::id::PBKDF2_SHA256 => "PBKDF2-HMAC-SHA256",
        kdf::id::PBKDF2_SHA512 => "PBKDF2-HMAC-SHA512",
        _ => "未知 KDF",
    }
}

/// GUI 下拉框用的算法选项列表。
pub fn algorithm_options() -> &'static [(u16, &'static str)] {
    &[
        (algorithm::id::AES_256_GCM, "AES-256-GCM"),
        (algorithm::id::CHACHA20_POLY1305, "ChaCha20-Poly1305"),
    ]
}

/// GUI 下拉框用的 KDF 选项列表。
pub fn kdf_options() -> &'static [(u16, &'static str)] {
    &[
        (kdf::id::PBKDF2_SHA256, "PBKDF2-HMAC-SHA256"),
        (kdf::id::PBKDF2_SHA512, "PBKDF2-HMAC-SHA512"),
    ]
}
