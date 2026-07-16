//! Packer 侧：组装完整 payload。
//!
//! 用法：
//! ```ignore
//! let payload_bytes = PayloadBuilder::new(algo_id, kdf_id, iters)
//!     .original_pe_info(2, 0x8664, Some("app.exe"))
//!     .plaintext_meta(exe_len, exe_crc32)
//!     .use_aad(true)
//!     .erase_payload(true)
//!     .material(salt, nonce, ciphertext)
//!     .build();
//! // packer: stub_bytes + payload_bytes 写入输出文件
//! ```

use crate::header::{
    serialize_extensions, Extension, PayloadHeader, FLAG_ERASE_PAYLOAD, FLAG_HAS_EXTENSION,
    FLAG_ORIGINAL_IS_GUI, FLAG_PRESERVE_ORIGINAL_NAME, FLAG_USE_AAD, EXT_AAD, EXT_ORIGINAL_NAME,
    EXT_ORIGINAL_TIMESTAMP,
};
use crate::footer::{serialize as serialize_footer, FOOTER_LEN};
use crate::{FIXED_HEADER_LEN, FORMAT_VERSION};
use crc32fast::Hasher as Crc32;

/// AAD 默认构造：固定头前 22 字节中影响安全决策的部分。
/// `magic(8) || format_version(2) || algorithm_id(2) || kdf_id(2) || kdf_iterations(4) || original_subsystem(4) || original_machine(2)`
pub const DEFAULT_AAD_LEN: usize = 24;

pub struct PayloadBuilder {
    header: PayloadHeader,
    extensions: Vec<Extension>,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    /// 是否自动构造默认 AAD（写入 EXT_AAD）。
    auto_aad: bool,
}

impl PayloadBuilder {
    pub fn new(algorithm_id: u16, kdf_id: u16, kdf_iterations: u32) -> Self {
        Self {
            header: PayloadHeader::new(algorithm_id, kdf_id, kdf_iterations),
            extensions: Vec::new(),
            salt: Vec::new(),
            nonce: Vec::new(),
            ciphertext: Vec::new(),
            auto_aad: false,
        }
    }

    /// 设置原 EXE 的 PE 信息（packer 从 PE header 读取）。
    /// `subsystem`：2=GUI, 3=Console。
    /// `machine`：0x8664=x64。
    /// `original_name`：原文件名（UTF-8），写入 EXT_ORIGINAL_NAME。
    pub fn original_pe_info(mut self, subsystem: u32, machine: u16, original_name: Option<&str>) -> Self {
        self.header.original_subsystem = subsystem;
        self.header.original_machine = machine;
        if subsystem == 2 {
            self.header.flags |= FLAG_ORIGINAL_IS_GUI;
        } else {
            self.header.flags &= !FLAG_ORIGINAL_IS_GUI;
        }
        if let Some(name) = original_name {
            self.extensions.push(Extension {
                tag: EXT_ORIGINAL_NAME,
                value: name.as_bytes().to_vec(),
            });
            self.header.flags |= FLAG_PRESERVE_ORIGINAL_NAME;
        }
        self
    }

    /// 设置原 EXE 的修改时间（Unix 秒），写入 EXT_ORIGINAL_TIMESTAMP。
    pub fn original_timestamp(mut self, unix_seconds: u64) -> Self {
        self.extensions.push(Extension {
            tag: EXT_ORIGINAL_TIMESTAMP,
            value: unix_seconds.to_le_bytes().to_vec(),
        });
        self
    }

    /// 设置明文元数据（长度与 CRC32），用于解密后二次校验。
    pub fn plaintext_meta(mut self, plaintext_len: u64, plaintext_crc32: u32) -> Self {
        self.header.plaintext_len = plaintext_len;
        self.header.plaintext_crc32 = plaintext_crc32;
        self
    }

    /// 设置 salt / nonce / ciphertext（由 packer 加密后填入）。
    pub fn material(mut self, salt: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        self.header.salt_len = salt.len() as u16;
        self.header.nonce_len = nonce.len() as u16;
        self.header.ciphertext_len = ciphertext.len() as u64;
        self.salt = salt;
        self.nonce = nonce;
        self.ciphertext = ciphertext;
        self
    }

    /// 启用 AEAD AAD：置 FLAG_USE_AAD，并写入 EXT_AAD。
    /// `aad` 为 None 时自动构造默认 AAD（绑定 header 关键字段）。
    pub fn use_aad(mut self, aad: Option<Vec<u8>>) -> Self {
        let aad_bytes = aad.unwrap_or_else(|| self.build_default_aad());
        self.extensions.push(Extension {
            tag: EXT_AAD,
            value: aad_bytes,
        });
        self.header.flags |= FLAG_USE_AAD;
        self.auto_aad = true; // 标记：build 时如果 header 变了要重建 AAD
        self
    }

    /// 启用"解密后擦除 payload"。
    pub fn erase_payload(mut self, enable: bool) -> Self {
        if enable {
            self.header.flags |= FLAG_ERASE_PAYLOAD;
        } else {
            self.header.flags &= !FLAG_ERASE_PAYLOAD;
        }
        self
    }

    /// 添加自定义扩展条目（用户自定义 TLV）。
    pub fn extension(mut self, tag: u16, value: Vec<u8>) -> Self {
        self.extensions.push(Extension { tag, value });
        self
    }

    /// 构造默认 AAD：固定头前 24 字节（magic+version+algorithm_id+kdf_id+kdf_iterations+original_subsystem+original_machine）。
    fn build_default_aad(&self) -> Vec<u8> {
        default_aad(
            self.header.algorithm_id,
            self.header.kdf_id,
            self.header.kdf_iterations,
            self.header.original_subsystem,
            self.header.original_machine,
        )
    }

    /// 返回当前 header 的默认 AAD（packer 在加密前调用，确保加密用的 AAD 与最终写入 EXT_AAD 一致）。
    pub fn current_default_aad(&self) -> Vec<u8> {
        self.build_default_aad()
    }

    /// 组装完整 payload 字节流（header + salt + nonce + ciphertext + footer）。
    pub fn build(mut self) -> Vec<u8> {
        // 若启用了 AAD 且是自动构造，重建一次 AAD（因为 header 字段可能在 use_aad 后又被修改）
        if self.auto_aad {
            let new_aad = self.build_default_aad();
            if let Some(e) = self.extensions.iter_mut().find(|e| e.tag == EXT_AAD) {
                e.value = new_aad;
            }
        }

        // 更新 extension_offset 与 header_size
        let ext_bytes = serialize_extensions(&self.extensions);
        let header_size = FIXED_HEADER_LEN + ext_bytes.len();
        self.header.extension_offset = FIXED_HEADER_LEN as u32;
        self.header.header_size = header_size as u16;
        if !self.extensions.is_empty() {
            self.header.flags |= FLAG_HAS_EXTENSION;
        }

        // 序列化 header（含 CRC32）
        let header_bytes = self.header.serialize(&self.extensions);

        // payload = header + salt + nonce + ciphertext + footer
        let payload_len = (header_bytes.len()
            + self.salt.len()
            + self.nonce.len()
            + self.ciphertext.len()
            + FOOTER_LEN) as u64;
        let footer = serialize_footer(payload_len);

        let mut out = Vec::with_capacity(payload_len as usize);
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&footer);
        out
    }
}

/// 计算字节的 CRC32（packer 用于填 plaintext_crc32）。
pub fn crc32_of(data: &[u8]) -> u32 {
    let mut h = Crc32::new();
    h.update(data);
    h.finalize()
}

/// 构造默认 AAD（绑定 header 关键字段）。
/// packer 在加密前调用，确保加密用的 AAD 与最终写入 EXT_AAD 一致。
pub fn default_aad(
    algorithm_id: u16,
    kdf_id: u16,
    kdf_iterations: u32,
    original_subsystem: u32,
    original_machine: u16,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DEFAULT_AAD_LEN);
    aad.extend_from_slice(crate::header::HEADER_MAGIC);
    aad.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    aad.extend_from_slice(&algorithm_id.to_le_bytes());
    aad.extend_from_slice(&kdf_id.to_le_bytes());
    aad.extend_from_slice(&kdf_iterations.to_le_bytes());
    aad.extend_from_slice(&original_subsystem.to_le_bytes());
    aad.extend_from_slice(&original_machine.to_le_bytes());
    aad
}

// 保留 FORMAT_VERSION 引用以防未来格式迁移逻辑用到。
#[allow(dead_code)]
const _FORMAT_VERSION: u16 = FORMAT_VERSION;
