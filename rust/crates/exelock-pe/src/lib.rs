//! EXELock PE 解析与加载库。
//!
//! - `parser` 模块（packer + stub 都用）：PE 解析、子系统提取、.NET 检测
//! - `loader` 模块（仅 stub 用，feature = "loader"）：RunPE 内存加载

pub mod parser;

pub use parser::{PeInfo, PeError, Subsystem, Machine};

#[cfg(feature = "loader")]
pub mod loader;

#[cfg(feature = "loader")]
pub use loader::{run_pe, LoaderError};
