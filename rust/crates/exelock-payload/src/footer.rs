//! Footer：24 字节，位于文件末尾，stub 反向定位 payload 的唯一入口。
//!
//! 布局：`[magic_a:8][payload_len:8][magic_b:8]`
//! 详见 `docs/FORMAT.md §5`。

use crate::PayloadError;

pub const FOOTER_LEN: usize = 24;
pub const FOOTER_MAGIC_A: &[u8; 8] = b"EXELOCK!";
pub const FOOTER_MAGIC_B: &[u8; 8] = b"EL2END!!";

/// 序列化 footer。
/// `payload_len` = header + salt + nonce + ciphertext + footer 的总字节数。
pub fn serialize(payload_len: u64) -> [u8; FOOTER_LEN] {
    let mut buf = [0u8; FOOTER_LEN];
    buf[0..8].copy_from_slice(FOOTER_MAGIC_A);
    buf[8..16].copy_from_slice(&payload_len.to_le_bytes());
    buf[16..24].copy_from_slice(FOOTER_MAGIC_B);
    buf
}

/// 从文件末尾 24 字节解析 footer。返回 payload 总长度。
pub fn parse(footer: &[u8; FOOTER_LEN]) -> Result<u64, PayloadError> {
    if &footer[0..8] != FOOTER_MAGIC_A || &footer[16..24] != FOOTER_MAGIC_B {
        return Err(PayloadError::BadFooterMagic);
    }
    let payload_len = u64::from_le_bytes(footer[8..16].try_into().unwrap());
    Ok(payload_len)
}
