//! 版本信息。
//!
//! packer 自身版本由 build.rs 注入，stub 版本通过搜索二进制中的
//! `EXELOCK_VER|version|build_time|git_hash|EXELOCK_END` 标记读取。
//!
//! stub 现在通过 `include_bytes!` 嵌入 packer，所以版本信息也从
//! 编译时常量（嵌入的字节）中提取，不再访问文件系统。

use crate::stub_selector::{load_stub, StubKind};

/// packer 自身版本信息（编译时由 build.rs 注入）。
pub const PACKER_VERSION: &str = env!("PACKER_VERSION");
pub const PACKER_BUILD_TIME: &str = env!("PACKER_BUILD_TIME");
pub const PACKER_GIT_HASH: &str = env!("PACKER_GIT_HASH");

/// stub 版本信息（从 stub 二进制中提取）。
#[derive(Debug, Clone)]
pub struct StubVersionInfo {
    pub version: String,
    pub build_time: String,
    pub git_hash: String,
}

impl std::fmt::Display for StubVersionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{} ({}, git:{})", self.version, self.build_time, self.git_hash)
    }
}

/// 从 stub 二进制数据中搜索版本标记并提取版本信息。
///
/// 标记格式：`EXELOCK_VER|version|build_time|git_hash|EXELOCK_END`
pub fn parse_stub_version(stub_bytes: &[u8]) -> Option<StubVersionInfo> {
    let magic = b"EXELOCK_VER|";
    let end_marker = b"|EXELOCK_END";

    let start = find_subslice(stub_bytes, magic)?;
    let data_start = start + magic.len();
    let end = find_subslice(&stub_bytes[data_start..], end_marker)?;
    let data_end = data_start + end;

    let info_str = std::str::from_utf8(&stub_bytes[data_start..data_end]).ok()?;
    let parts: Vec<&str> = info_str.split('|').collect();
    if parts.len() >= 3 {
        Some(StubVersionInfo {
            version: parts[0].to_string(),
            build_time: parts[1].to_string(),
            git_hash: parts[2].to_string(),
        })
    } else {
        None
    }
}

/// 从嵌入的 stub 字节读取版本信息。
pub fn load_stub_version(kind: StubKind) -> Option<StubVersionInfo> {
    let bytes = load_stub(kind).ok()?;
    parse_stub_version(&bytes)
}

/// 在字节切片中搜索子切片，返回首次出现的索引。
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
