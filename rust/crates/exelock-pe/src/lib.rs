//! EXELock PE 解析库。
//!
//! MVP 只实现 parser（packer 与 stub 都用）：
//! - 读取 PE 头、提取 Subsystem / Machine
//! - 检测 .NET CLR header
//! - 校验 PE 有效性
//!
//! RunPE loader（stub 专用）将在 beta1 阶段加入，用 feature = "loader" 控制。

pub mod parser;

pub use parser::{PeInfo, PeError, Subsystem, Machine};

#[cfg(feature = "loader")]
pub mod loader;

#[cfg(feature = "loader")]
pub use loader::run_pe_in_place;
