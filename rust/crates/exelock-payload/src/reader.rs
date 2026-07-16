//! Stub 侧：从完整 EXE 字节流解析 payload。
//!
//! 解析流程：
//! 1. 读取文件末尾 24 字节 footer
//! 2. 校验 magic，取出 payload_len
//! 3. 从 `file_size - payload_len` 处读 header
//! 4. 校验 header magic / version / CRC32
//! 5. 切出 salt / nonce / ciphertext

use crate::footer::{parse as parse_footer, FOOTER_LEN};
use crate::header::{PayloadHeader, ExtensionMap, FLAG_USE_AAD, EXT_AAD};
use crate::{PayloadError, FIXED_HEADER_LEN};

/// 解析后的 payload。
pub struct Payload {
    pub header: PayloadHeader,
    pub extensions: ExtensionMap,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Payload {
    /// 从完整 EXE 字节流（stub + payload）解析。
    /// `data` = 整个文件内容。
    pub fn from_file_tail(data: &[u8]) -> Result<Self, PayloadError> {
        if data.len() < FOOTER_LEN {
            return Err(PayloadError::TooShort(data.len(), FOOTER_LEN));
        }

        // 1. 解析 footer
        let footer_start = data.len() - FOOTER_LEN;
        let mut footer = [0u8; FOOTER_LEN];
        footer.copy_from_slice(&data[footer_start..]);
        let payload_len = parse_footer(&footer)? as usize;
        if payload_len > data.len() || payload_len < FOOTER_LEN + FIXED_HEADER_LEN {
            return Err(PayloadError::PayloadLenMismatch {
                payload_len: payload_len as u64,
                file_size: data.len() as u64,
            });
        }

        // 2. 定位 payload 起始
        let payload_start = data.len() - payload_len;
        let payload_data = &data[payload_start..];

        // 3. 解析 header
        let (header, extensions, header_size) = PayloadHeader::parse(payload_data)?;

        // 4. 切出 salt / nonce / ciphertext
        let mut offset = header_size;
        let salt = slice_field(payload_data, &mut offset, header.salt_len as usize, "salt")?;
        let nonce = slice_field(payload_data, &mut offset, header.nonce_len as usize, "nonce")?;
        let ciphertext = slice_field(payload_data, &mut offset, header.ciphertext_len as usize, "ciphertext")?;

        // 5. ciphertext 之后应正好是 footer
        if offset + FOOTER_LEN != payload_data.len() {
            return Err(PayloadError::FieldOutOfBounds {
                field: "footer",
                value: offset as u64,
                offset: offset as u64,
                end: payload_data.len() as u64,
            });
        }

        Ok(Payload {
            header,
            extensions,
            salt,
            nonce,
            ciphertext,
        })
    }

    /// 若启用 AAD，返回 EXT_AAD 内容；否则返回 None。
    pub fn aad(&self) -> Option<&[u8]> {
        if self.header.flags & FLAG_USE_AAD != 0 {
            self.extensions.get(EXT_AAD)
        } else {
            None
        }
    }
}

fn slice_field(
    payload: &[u8],
    offset: &mut usize,
    len: usize,
    field: &'static str,
) -> Result<Vec<u8>, PayloadError> {
    let end = *offset + len;
    if end > payload.len() - FOOTER_LEN {
        return Err(PayloadError::FieldOutOfBounds {
            field,
            value: len as u64,
            offset: *offset as u64,
            end: (payload.len() - FOOTER_LEN) as u64,
        });
    }
    let v = payload[*offset..end].to_vec();
    *offset = end;
    Ok(v)
}
