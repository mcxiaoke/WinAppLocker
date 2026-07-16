//! 根据 Original Subsystem 选择 stub 模板。
//!
//! stub 通过 `include_bytes!` 嵌入预编译的 EXE（由 `cargo build -p exelock-stub --release` 生成）。
//! 两个变体：
//! - `stub_gui.exe`：windows 子系统，无控制台窗口（适合原 EXE 也是 GUI）
//! - `stub_console.exe`：console 子系统，保留控制台（适合原 EXE 是 CLI）

use exelock_pe::Subsystem;

/// 嵌入预编译的 stub EXE。
/// 这些文件由 `cargo build -p exelock-stub --release` 生成，
/// 在开发前需要手动复制到 `packer/stubs/` 目录。
/// build.rs 会设置 `cargo:rerun-if-changed` 以便 stub 更新时重新编译 packer。
static STUB_GUI_BYTES: &[u8] = include_bytes!("../stubs/stub_gui.exe");
static STUB_CONSOLE_BYTES: &[u8] = include_bytes!("../stubs/stub_console.exe");

/// stub 选择偏好。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StubPreference {
    /// 自动：原 EXE 是 GUI 就用 GUI stub，否则 console stub。
    Auto,
    /// 强制用 GUI stub。
    Gui,
    /// 强制用 Console stub。
    Console,
    /// 自定义 stub 字节（用于测试，如内置密码的 stub_test）。
    Custom(Vec<u8>),
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
    match preference {
        StubPreference::Custom(bytes) => (
            StubTemplate {
                bytes,
                // 自定义 stub 的子系统以原 EXE 为准（测试用，不深究）
                subsystem: if original_subsystem.is_gui() {
                    Subsystem::Gui
                } else {
                    Subsystem::Console
                },
            },
            original_subsystem,
        ),
        other => {
            let want_gui = match other {
                StubPreference::Auto => original_subsystem.is_gui(),
                StubPreference::Gui => true,
                StubPreference::Console => false,
                StubPreference::Custom(_) => unreachable!(),
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
    }
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
            bytes: STUB_GUI_BYTES.to_vec(),
            subsystem: Subsystem::Gui,
        }
    }

    /// Console 版 stub 模板。
    pub fn console() -> Self {
        Self {
            bytes: STUB_CONSOLE_BYTES.to_vec(),
            subsystem: Subsystem::Console,
        }
    }
}
