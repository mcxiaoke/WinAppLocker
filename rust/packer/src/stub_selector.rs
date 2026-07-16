//! 根据 Original Subsystem 选择 stub 模板。
//!
//! MVP 阶段：stub 尚未实现，用占位 stub（最小 PE）。
//!   占位 stub 不能真正运行原 EXE，但生成的 locked 文件格式完整，
//!   可被 `exelock_payload::Payload::from_file_tail` 正确解析（用于测试 packer 流程）。
//! beta2 阶段：改为 `include_bytes!` 嵌入预编译的 stub_gui.exe / stub_console.exe。

use exelock_pe::Subsystem;

/// stub 选择偏好。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubPreference {
    /// 自动：原 EXE 是 GUI 就用 GUI stub，否则 console stub。
    Auto,
    /// 强制用 GUI stub。
    Gui,
    /// 强制用 Console stub。
    Console,
}

impl Default for StubPreference {
    fn default() -> Self {
        StubPreference::Auto
    }
}

/// 选择 stub 模板字节。
///
/// 返回 `(stub_bytes, chosen_subsystem)`，其中 `chosen_subsystem` 是 stub 自身的子系统
/// （packer 可用于诊断或写入 payload 的 stub_subsystem 字段，目前未写入）。
pub fn select_stub(
    original_subsystem: Subsystem,
    preference: StubPreference,
) -> (StubTemplate, Subsystem) {
    let want_gui = match preference {
        StubPreference::Auto => original_subsystem.is_gui(),
        StubPreference::Gui => true,
        StubPreference::Console => false,
    };

    let template = if want_gui {
        StubTemplate::gui()
    } else {
        StubTemplate::console()
    };

    let chosen = if want_gui {
        Subsystem::Gui
    } else {
        Subsystem::Console
    };

    (template, chosen)
}

/// stub 模板：包装 stub 字节及其子系统。
#[derive(Debug, Clone)]
pub struct StubTemplate {
    pub bytes: Vec<u8>,
    pub subsystem: Subsystem,
}

impl StubTemplate {
    /// GUI 版 stub 模板。
    pub fn gui() -> Self {
        Self {
            bytes: placeholder_stub_gui(),
            subsystem: Subsystem::Gui,
        }
    }

    /// Console 版 stub 模板。
    pub fn console() -> Self {
        Self {
            bytes: placeholder_stub_console(),
            subsystem: Subsystem::Console,
        }
    }
}

// ===================== 占位 stub =====================
//
// MVP 阶段：真正的 stub 还没实现（beta2 阶段做）。
// 这里用最小有效 PE 作为占位，让 packer 能生成格式完整的 locked 文件，
// 供 payload reader 测试与 GUI 流程验证。
//
// 占位 PE 是一个最小 x64 PE：MZ + PE 头 + 一个节区，入口点立即 ret。
// 它能被 goblin 解析，能被 payload reader 正确读取尾部 payload，
// 但运行它不会执行原 EXE（因为没有 RunPE 逻辑）。
//
// beta2 阶段：删除这两个函数，改为：
//   pub const STUB_GUI: &[u8] = include_bytes!("../stubs/stub_gui.exe");
//   pub const STUB_CONSOLE: &[u8] = include_bytes!("../stubs/stub_console.exe");

fn placeholder_stub_gui() -> Vec<u8> {
    // 复用同一个最小 PE，子系统字段不同（beta2 阶段会被真实 stub 替换）
    minimal_x64_pe(2) // WINDOWS_GUI
}

fn placeholder_stub_console() -> Vec<u8> {
    minimal_x64_pe(3) // WINDOWS_CUI
}

/// 构造一个最小 x64 PE 文件字节。
/// 入口点指向节区起始的一个 `C3`（ret）指令。
///
/// 布局：
/// - 0x00  DOS Header（64 字节）
/// - 0x40  DOS Stub（可省略，这里直接跳过）
/// - 0x40  PE Signature + COFF Header
/// - 0x98  Optional Header（PE32+，x64）
/// - 0x148 Section Header（.text）
/// - 0x170 .text 节区（1 字节 ret + 填充）
fn minimal_x64_pe(subsystem: u16) -> Vec<u8> {
    // 这是手写 PE，略显繁琐但保证最小且可被 goblin 解析。
    // 对齐与字段值参考 PE 规范。
    let mut buf = vec![0u8; 0x400];

    // ---- DOS Header ----
    buf[0..2].copy_from_slice(b"MZ");
    let e_lfanew: u32 = 0x40;
    buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

    // ---- PE Signature ----
    let pe_off = e_lfanew as usize;
    buf[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");

    // ---- COFF Header（20 字节）----
    let coff = pe_off + 4;
    // Machine = 0x8664 (AMD64)
    buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    // NumberOfSections = 1
    buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    // TimeDateStamp = 0
    // PointerToSymbolTable = 0
    // NumberOfSymbols = 0
    // SizeOfOptionalHeader = 240 (PE32+)
    let opt_hdr_size: u16 = 240;
    buf[coff + 16..coff + 18].copy_from_slice(&opt_hdr_size.to_le_bytes());
    // Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE
    let chars: u16 = 0x0002 | 0x0020;
    buf[coff + 18..coff + 20].copy_from_slice(&chars.to_le_bytes());

    // ---- Optional Header（PE32+，240 字节）----
    let opt = coff + 20;
    // Magic = 0x20B (PE32+)
    buf[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
    // MajorLinkerVersion / MinorLinkerVersion
    buf[opt + 2] = 14;
    buf[opt + 3] = 0;
    // SizeOfCode = 0x200
    buf[opt + 4..opt + 8].copy_from_slice(&0x200u32.to_le_bytes());
    // SizeOfInitializedData = 0
    // SizeOfUninitializedData = 0
    // AddressOfEntryPoint = 0x1000（节区 RVA）
    buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    // BaseOfCode = 0x1000
    buf[opt + 20..opt + 24].copy_from_slice(&0x1000u32.to_le_bytes());

    // --- PE32+ Windows-specific fields（从 opt+24 开始）---
    let win = opt + 24;
    // ImageBase = 0x140000000
    buf[win..win + 8].copy_from_slice(&0x140000000u64.to_le_bytes());
    // SectionAlignment = 0x1000
    buf[win + 8..win + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    // FileAlignment = 0x200
    buf[win + 12..win + 16].copy_from_slice(&0x200u32.to_le_bytes());
    // MajorOperatingSystemVersion = 6, Minor = 0
    buf[win + 16] = 6;
    buf[win + 17] = 0;
    // MajorImageVersion / MinorImageVersion = 0
    // MajorSubsystemVersion = 6, Minor = 0
    buf[win + 22] = 6;
    buf[win + 23] = 0;
    // Win32VersionValue = 0
    // SizeOfImage = 0x3000（含 .text 节）
    buf[win + 28..win + 32].copy_from_slice(&0x3000u32.to_le_bytes());
    // SizeOfHeaders = 0x200
    buf[win + 32..win + 36].copy_from_slice(&0x200u32.to_le_bytes());
    // CheckSum = 0
    // Subsystem
    buf[win + 40..win + 42].copy_from_slice(&subsystem.to_le_bytes());
    // DllCharacteristics = IMAGE_DLLCHARACTERISTICS_NX_STACK | DYNAMIC_BASE
    let dll_chars: u16 = 0x0040 | 0x0100;
    buf[win + 42..win + 44].copy_from_slice(&dll_chars.to_le_bytes());
    // SizeOfStackReserve / Commit = 0x100000 / 0x1000
    buf[win + 44..win + 52].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[win + 52..win + 60].copy_from_slice(&0x1000u64.to_le_bytes());
    // SizeOfHeapReserve / Commit = 0x100000 / 0x1000
    buf[win + 60..win + 68].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[win + 68..win + 76].copy_from_slice(&0x1000u64.to_le_bytes());
    // LoaderFlags = 0
    // NumberOfRvaAndSizes = 16
    buf[win + 80..win + 84].copy_from_slice(&16u32.to_le_bytes());

    // Data Directories：16 个条目 × 8 字节 = 128 字节，全 0（无导入表等）
    // （已由 vec![0] 填充）

    // ---- Section Header（40 字节）----
    let sec = opt + opt_hdr_size as usize;
    // Name = ".text\0\0\0"
    buf[sec..sec + 8].copy_from_slice(b".text\0\0\0");
    // VirtualSize = 0x200
    buf[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes());
    // VirtualAddress = 0x1000
    buf[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    // SizeOfRawData = 0x200
    buf[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
    // PointerToRawData = 0x200
    buf[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
    // Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
    let sec_chars: u32 = 0x00000020 | 0x20000000 | 0x40000000;
    buf[sec + 36..sec + 40].copy_from_slice(&sec_chars.to_le_bytes());

    // ---- .text 节区内容（0x200 起）----
    // 入口点指令：C3 = ret
    buf[0x200] = 0xC3;

    // 截断到实际大小 0x400
    buf
}
