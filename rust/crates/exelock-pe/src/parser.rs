//! PE 解析：提取 packer 需要的元数据。
//!
//! 基于 `goblin`，不手写 PE 解析（减少 bug 面积，符合"复杂度优先简化"原则）。

use goblin::Object;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PeError {
    #[error("不是有效的 PE 文件: {0}")]
    NotPe(String),
    #[error("PE 解析失败: {0}")]
    Parse(String),
    #[error("不支持的架构: machine=0x{0:04x}（仅支持 x64 0x8664）")]
    UnsupportedMachine(u16),
    #[error(".NET 托管程序暂不支持（含 CLR header）")]
    DotNetNotSupported,
}

/// PE Subsystem 值。详见 `docs/FORMAT.md §4.1`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subsystem {
    /// `WINDOWS_GUI` = 2，无控制台。
    Gui,
    /// `WINDOWS_CUI` = 3，控制台程序。
    Console,
    /// 其他值按 GUI 处理。
    Unknown(u16),
}

impl Subsystem {
    pub fn from_raw(v: u16) -> Self {
        match v {
            2 => Subsystem::Gui,
            3 => Subsystem::Console,
            other => Subsystem::Unknown(other),
        }
    }
    /// 原始 u16 值（写入 payload header 的 `original_subsystem`）。
    pub fn raw(self) -> u16 {
        match self {
            Subsystem::Gui => 2,
            Subsystem::Console => 3,
            Subsystem::Unknown(v) => v,
        }
    }
    /// 是否为 GUI 类（用于 stub 选择）。
    pub fn is_gui(self) -> bool {
        matches!(self, Subsystem::Gui | Subsystem::Unknown(_))
    }
}

/// PE Machine 值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Machine {
    X64,
    Other(u16),
}

impl Machine {
    pub fn from_raw(v: u16) -> Self {
        match v {
            0x8664 => Machine::X64,
            other => Machine::Other(other),
        }
    }
    pub fn raw(self) -> u16 {
        match self {
            Machine::X64 => 0x8664,
            Machine::Other(v) => v,
        }
    }
}

/// PE 解析结果（packer 需要的元数据）。
#[derive(Debug, Clone)]
pub struct PeInfo {
    pub machine: Machine,
    pub subsystem: Subsystem,
    pub entry_point: u32,
    pub image_size: u64,
    pub is_dotnet: bool,
    /// 是否启用了动态基址（ASLR / DYNAMICBASE）。
    pub is_dynamic_base: bool,
}

impl PeInfo {
    /// 从字节解析 PE。
    pub fn parse(data: &[u8]) -> Result<Self, PeError> {
        let obj = Object::parse(data).map_err(|e| PeError::Parse(e.to_string()))?;
        let pe = match obj {
            Object::PE(pe) => pe,
            _ => return Err(PeError::NotPe("非 PE 格式".into())),
        };

        // 校验架构
        let machine_raw = pe.header.coff_header.machine;
        let machine = Machine::from_raw(machine_raw);
        if !matches!(machine, Machine::X64) {
            return Err(PeError::UnsupportedMachine(machine_raw));
        }

        let opt = pe
            .header
            .optional_header
            .ok_or_else(|| PeError::Parse("missing optional header".into()))?;

        // 子系统
        let subsystem_raw = opt.windows_fields.subsystem;
        let subsystem = Subsystem::from_raw(subsystem_raw);

        // 入口点在 standard_fields（goblin 0.8 中是 u64）
        let entry_point: u32 = opt.standard_fields.address_of_entry_point
            .try_into()
            .map_err(|_| PeError::Parse("entry_point 超出 u32 范围".into()))?;
        let image_size = opt.windows_fields.size_of_image as u64;

        // .NET 检测：COM Descriptor 目录项（索引 14）非空即含 CLR header
        // goblin 0.8 的 data_directories 是 Vec<Option<(usize, DataDirectory)>>
        const COM_DESCRIPTOR_INDEX: usize = 14;
        let is_dotnet = opt
            .data_directories
            .data_directories
            .get(COM_DESCRIPTOR_INDEX)
            .and_then(|opt_d| opt_d.as_ref())
            .map(|(_, d)| d.virtual_address != 0 && d.size != 0)
            .unwrap_or(false);

        // 动态基址（ASLR）：DllCharacteristics 的 IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
        let dll_chars = opt.windows_fields.dll_characteristics;
        let is_dynamic_base = dll_chars & 0x0040 != 0;

        Ok(PeInfo {
            machine,
            subsystem,
            entry_point,
            image_size,
            is_dotnet,
            is_dynamic_base,
        })
    }
}
