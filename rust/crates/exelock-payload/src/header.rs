//! Payload Header：固定头 64 字节 + TLV 扩展区。
//!
//! 详见 `docs/FORMAT.md §3`。

use crate::{PayloadError, FIXED_HEADER_LEN, FORMAT_VERSION};
use crc32fast::Hasher as Crc32;

/// 固定 8 字节 magic（头部与 footer 的 magic_a 共用）。
pub const HEADER_MAGIC: &[u8; 8] = b"EXELOCK!";

// ===================== Flags 位域 =====================

pub type Flags = u32;

pub const FLAG_HAS_EXTENSION: u32 = 1 << 0;
pub const FLAG_ORIGINAL_IS_GUI: u32 = 1 << 1;
pub const FLAG_USE_AAD: u32 = 1 << 2;
pub const FLAG_ANTI_DEBUG: u32 = 1 << 3;   // MVP 推迟，stub 遇到时忽略
pub const FLAG_ANTI_DUMP: u32 = 1 << 4;    // MVP 推迟，stub 遇到时忽略
pub const FLAG_ERASE_PAYLOAD: u32 = 1 << 5;
pub const FLAG_PRESERVE_ORIGINAL_NAME: u32 = 1 << 6;

/// flags 位名称（GUI 诊断用）。
pub const FLAG_NAMES: &[(u32, &str)] = &[
    (FLAG_HAS_EXTENSION, "HAS_EXTENSION"),
    (FLAG_ORIGINAL_IS_GUI, "ORIGINAL_IS_GUI"),
    (FLAG_USE_AAD, "USE_AAD"),
    (FLAG_ANTI_DEBUG, "ANTI_DEBUG"),
    (FLAG_ANTI_DUMP, "ANTI_DUMP"),
    (FLAG_ERASE_PAYLOAD, "ERASE_PAYLOAD"),
    (FLAG_PRESERVE_ORIGINAL_NAME, "PRESERVE_ORIGINAL_NAME"),
];

// ===================== 扩展区 TLV =====================

pub const EXT_END: u16 = 0x0000;
pub const EXT_ORIGINAL_NAME: u16 = 0x0001;
pub const EXT_ORIGINAL_TIMESTAMP: u16 = 0x0002;
pub const EXT_AAD: u16 = 0x0003;
pub const EXT_ORIGINAL_HASH: u16 = 0x0004;
pub const EXT_BUILD_INFO: u16 = 0x0005;
pub const EXT_PADDING: u16 = 0x0006;
pub const EXT_KDF_EXTRA: u16 = 0x0007;

/// 单个 TLV 扩展条目。
#[derive(Debug, Clone)]
pub struct Extension {
    pub tag: u16,
    pub value: Vec<u8>,
}

/// 扩展区按 tag 索引的只读视图。
#[derive(Debug, Default, Clone)]
pub struct ExtensionMap {
    entries: Vec<Extension>,
}

impl ExtensionMap {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, tag: u16, value: Vec<u8>) {
        self.entries.push(Extension { tag, value });
    }
    pub fn get(&self, tag: u16) -> Option<&[u8]> {
        self.entries.iter().find(|e| e.tag == tag).map(|e| e.value.as_slice())
    }
    pub fn iter(&self) -> impl Iterator<Item = &Extension> {
        self.entries.iter()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ===================== 固定头 =====================

/// 固定头字段。所有整数字段小端序。
#[derive(Debug, Clone)]
pub struct PayloadHeader {
    pub format_version: u16,
    pub flags: Flags,
    pub algorithm_id: u16,
    pub kdf_id: u16,
    pub kdf_iterations: u32,
    pub salt_len: u16,
    pub nonce_len: u16,
    pub ciphertext_len: u64,
    pub plaintext_len: u64,
    pub plaintext_crc32: u32,
    pub original_subsystem: u32,
    pub original_machine: u16,
    /// 扩展区起始相对 header 起的偏移；无扩展时等于 `header_size`。
    pub extension_offset: u32,
    /// 整个 header 字节数（固定头 + 扩展区 + EXT_END 终止符）。
    pub header_size: u16,
}

impl PayloadHeader {
    /// 新建一份默认 header，packer 在此基础上填字段。
    pub fn new(algorithm_id: u16, kdf_id: u16, kdf_iterations: u32) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            flags: 0,
            algorithm_id,
            kdf_id,
            kdf_iterations,
            salt_len: 16,
            nonce_len: 12, // 默认 AES/ChaCha 都是 12，packer 应按算法覆写
            ciphertext_len: 0,
            plaintext_len: 0,
            plaintext_crc32: 0,
            original_subsystem: 3, // 默认 Console，packer 按原 EXE 覆写
            original_machine: 0x8664,
            extension_offset: FIXED_HEADER_LEN as u32,
            header_size: FIXED_HEADER_LEN as u16,
        }
    }

    /// 序列化固定头 + 扩展区，返回字节数组（含 EXT_END 终止符）。
    /// `header_crc32` 字段位置先填 0，CRC 计算后再回填。
    pub fn serialize(&self, extensions: &[Extension]) -> Vec<u8> {
        // 1. 计算扩展区字节数（含 EXT_END 终止符 6 字节）
        let ext_bytes = serialize_extensions(extensions);
        let header_size = FIXED_HEADER_LEN + ext_bytes.len();

        // 2. 分配 buffer
        let mut buf = vec![0u8; header_size];

        // 3. 填充固定头字段（header_crc32 先填 0）
        buf[0..8].copy_from_slice(HEADER_MAGIC);
        buf[8..10].copy_from_slice(&self.format_version.to_le_bytes());
        buf[10..12].copy_from_slice(&(header_size as u16).to_le_bytes());
        // buf[12..16] = CRC32, 稍后填
        buf[16..20].copy_from_slice(&self.flags.to_le_bytes());
        buf[20..22].copy_from_slice(&self.algorithm_id.to_le_bytes());
        buf[22..24].copy_from_slice(&self.kdf_id.to_le_bytes());
        buf[24..28].copy_from_slice(&self.kdf_iterations.to_le_bytes());
        buf[28..30].copy_from_slice(&self.salt_len.to_le_bytes());
        buf[30..32].copy_from_slice(&self.nonce_len.to_le_bytes());
        buf[32..40].copy_from_slice(&self.ciphertext_len.to_le_bytes());
        buf[40..48].copy_from_slice(&self.plaintext_len.to_le_bytes());
        buf[48..52].copy_from_slice(&self.plaintext_crc32.to_le_bytes());
        buf[52..56].copy_from_slice(&self.original_subsystem.to_le_bytes());
        buf[56..58].copy_from_slice(&self.original_machine.to_le_bytes());
        // buf[58..60] reserved = 0
        buf[60..64].copy_from_slice(&self.extension_offset.to_le_bytes());

        // 4. 填扩展区
        buf[FIXED_HEADER_LEN..].copy_from_slice(&ext_bytes);

        // 5. 计算 CRC32（除 header_crc32 字段外的整个 header：固定头 12 字节 + 固定头 16..end + 扩展区）
        //    即：byte 0..12 || byte 16..header_size
        let crc = {
            let mut h = Crc32::new();
            h.update(&buf[0..12]);
            h.update(&buf[16..header_size]);
            h.finalize()
        };
        buf[12..16].copy_from_slice(&crc.to_le_bytes());

        buf
    }

    /// 从字节切片解析 header（含扩展区）。
    /// `data` 应从 header 起始位置开始。返回 (header, extensions, consumed_bytes)。
    pub fn parse(data: &[u8]) -> Result<(PayloadHeader, ExtensionMap, usize), PayloadError> {
        if data.len() < FIXED_HEADER_LEN {
            return Err(PayloadError::TooShort(data.len(), FIXED_HEADER_LEN));
        }

        // 校验 magic
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&data[0..8]);
        if &magic != HEADER_MAGIC {
            return Err(PayloadError::BadHeaderMagic {
                expected: HEADER_MAGIC,
                actual: magic,
            });
        }

        let format_version = u16::from_le_bytes([data[8], data[9]]);
        if format_version != FORMAT_VERSION {
            return Err(PayloadError::UnsupportedVersion(format_version));
        }

        let header_size = u16::from_le_bytes([data[10], data[11]]) as usize;
        if header_size < FIXED_HEADER_LEN || header_size > data.len() {
            return Err(PayloadError::BadHeaderSize {
                value: header_size as u16,
                min: FIXED_HEADER_LEN as u16,
            });
        }

        // 校验 CRC32
        let stored_crc = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let calc_crc = {
            let mut h = Crc32::new();
            h.update(&data[0..12]);
            h.update(&data[16..header_size]);
            h.finalize()
        };
        if stored_crc != calc_crc {
            return Err(PayloadError::HeaderCrcMismatch {
                expected: stored_crc,
                actual: calc_crc,
            });
        }

        let flags = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let algorithm_id = u16::from_le_bytes([data[20], data[21]]);
        let kdf_id = u16::from_le_bytes([data[22], data[23]]);
        let kdf_iterations = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        let salt_len = u16::from_le_bytes([data[28], data[29]]);
        let nonce_len = u16::from_le_bytes([data[30], data[31]]);
        let ciphertext_len = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let plaintext_len = u64::from_le_bytes(data[40..48].try_into().unwrap());
        let plaintext_crc32 = u32::from_le_bytes([data[48], data[49], data[50], data[51]]);
        let original_subsystem = u32::from_le_bytes([data[52], data[53], data[54], data[55]]);
        let original_machine = u16::from_le_bytes([data[56], data[57]]);
        // data[58..60] reserved
        let extension_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);

        // 解析扩展区
        let extensions = if header_size > FIXED_HEADER_LEN {
            let ext_start = extension_offset as usize;
            let ext_data = &data[ext_start..header_size];
            parse_extensions(ext_data)?
        } else {
            ExtensionMap::new()
        };

        let header = PayloadHeader {
            format_version,
            flags,
            algorithm_id,
            kdf_id,
            kdf_iterations,
            salt_len,
            nonce_len,
            ciphertext_len,
            plaintext_len,
            plaintext_crc32,
            original_subsystem,
            original_machine,
            extension_offset,
            header_size: header_size as u16,
        };

        Ok((header, extensions, header_size))
    }
}

// ===================== TLV 序列化/解析 =====================

/// 序列化扩展区（含 EXT_END 终止符）。
pub fn serialize_extensions(entries: &[Extension]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(entries.len() * 10 + 6);
    for e in entries {
        buf.extend_from_slice(&e.tag.to_le_bytes());
        buf.extend_from_slice(&(e.value.len() as u32).to_le_bytes());
        buf.extend_from_slice(&e.value);
    }
    // EXT_END 终止符
    buf.extend_from_slice(&EXT_END.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf
}

/// 解析扩展区（输入为从扩展区起始到 header 结束的字节，含 EXT_END）。
pub fn parse_extensions(data: &[u8]) -> Result<ExtensionMap, PayloadError> {
    let mut map = ExtensionMap::new();
    let mut pos = 0;
    loop {
        if pos + 6 > data.len() {
            return Err(PayloadError::BadExtension(format!(
                "TLV 头不足: pos={}, len={}",
                pos,
                data.len()
            )));
        }
        let tag = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let len = u32::from_le_bytes([
            data[pos + 2],
            data[pos + 3],
            data[pos + 4],
            data[pos + 5],
        ]) as usize;
        pos += 6;
        if tag == EXT_END {
            if len != 0 {
                return Err(PayloadError::BadExtension(format!(
                    "EXT_END 的 length 应为 0, 实际 {}",
                    len
                )));
            }
            break;
        }
        if pos + len > data.len() {
            return Err(PayloadError::BadExtension(format!(
                "TLV value 越界: tag=0x{:04x}, len={}, pos={}, data={}",
                tag,
                len,
                pos,
                data.len()
            )));
        }
        map.push(tag, data[pos..pos + len].to_vec());
        pos += len;
    }
    Ok(map)
}
