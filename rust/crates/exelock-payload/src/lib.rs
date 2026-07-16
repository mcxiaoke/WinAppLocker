//! EXELock Payload 编解码库。
//!
//! 封装 `docs/FORMAT.md` 定义的二进制格式：
//! stub 原生内容 + `[header][salt][nonce][ciphertext][footer]`。
//!
//! - packer 用 [`writer::PayloadBuilder`] 组装 payload
//! - stub 用 [`reader::Payload::from_file_tail`] 解析自身末尾

pub mod header;
pub mod footer;
pub mod writer;
pub mod reader;

pub use header::{PayloadHeader, Extension, ExtensionMap, Flags, FLAG_NAMES};
pub use footer::{FOOTER_LEN, FOOTER_MAGIC_A, FOOTER_MAGIC_B};
pub use writer::PayloadBuilder;
pub use reader::Payload;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PayloadError {
    #[error("文件太短，无法包含 footer（{0} 字节 < {1}）")]
    TooShort(usize, usize),
    #[error("footer magic 不匹配")]
    BadFooterMagic,
    #[error("header magic 不匹配: 期望 {expected:?}, 实际 {actual:?}")]
    BadHeaderMagic { expected: &'static [u8], actual: [u8; 8] },
    #[error("format_version 不支持: {0}")]
    UnsupportedVersion(u16),
    #[error("header CRC32 校验失败: 期望 {expected}, 实际 {actual}")]
    HeaderCrcMismatch { expected: u32, actual: u32 },
    #[error("header_size 异常: {value}（应 >= {min}）")]
    BadHeaderSize { value: u16, min: u16 },
    #[error("payload_len 与文件大小不一致: payload_len={payload_len}, 文件={file_size}")]
    PayloadLenMismatch { payload_len: u64, file_size: u64 },
    #[error("字段长度越界: {field}={value}, offset={offset}, end={end}")]
    FieldOutOfBounds { field: &'static str, value: u64, offset: u64, end: u64 },
    #[error("扩展区 TLV 格式错误: {0}")]
    BadExtension(String),
    #[error("明文 CRC32 校验失败: 期望 {expected}, 实际 {actual}")]
    PlaintextCrcMismatch { expected: u32, actual: u32 },
    #[error("明文长度不匹配: 期望 {expected}, 实际 {actual}")]
    PlaintextLenMismatch { expected: u64, actual: u64 },
}

/// 当前格式版本。
pub const FORMAT_VERSION: u16 = 1;

/// 固定头字节数。
pub const FIXED_HEADER_LEN: usize = 64;
