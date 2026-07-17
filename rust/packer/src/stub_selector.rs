//! 根据 Original Subsystem 选择并加载 stub。
//!
//! stub 通过 `include_bytes!` 在编译时嵌入 packer 二进制：
//! - `stub_gui.exe`：windows 子系统，无控制台窗口
//! - `stub_console.exe`：console 子系统，保留控制台
//!
//! build.rs 负责把 stub 从 target/<profile>/ 复制到 OUT_DIR，
//! 这样 packer 编译时就能直接把 stub 字节编进自己的 exe，
//! 发布产物是单一的 WinAppLocker.exe，不再需要外部 stub/ 目录。

use exelock_pe::Subsystem;

// 由 build.rs 在编译时把 stub 二进制拷贝到 OUT_DIR。
// include_bytes! 在编译期读取，stub 字节直接编进 packer exe。
const STUB_GUI_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/stub_gui.exe"));
const STUB_CONSOLE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/stub_console.exe"));

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

/// stub 模板：包装 stub 字节及其子系统。
#[derive(Debug, Clone)]
pub struct StubTemplate {
    pub bytes: Vec<u8>,
    pub subsystem: Subsystem,
}

/// stub 加载错误（嵌入模式下基本不会触发，保留是为了 API 兼容）。
#[derive(Debug, Clone)]
pub struct StubLoadError {
    pub kind: StubKind,
    pub error: String,
}

/// stub 种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubKind {
    Gui,
    Console,
}

impl StubKind {
    pub fn filename(self) -> &'static str {
        match self {
            StubKind::Gui => "stub_gui.exe",
            StubKind::Console => "stub_console.exe",
        }
    }

    pub fn subsystem(self) -> Subsystem {
        match self {
            StubKind::Gui => Subsystem::Gui,
            StubKind::Console => Subsystem::Console,
        }
    }
}

impl std::fmt::Display for StubLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "无法加载 stub '{}': {}", self.kind.filename(), self.error)
    }
}

/// 取嵌入的 stub 字节。
pub fn load_stub(kind: StubKind) -> Result<Vec<u8>, StubLoadError> {
    Ok(match kind {
        StubKind::Gui => STUB_GUI_BYTES.to_vec(),
        StubKind::Console => STUB_CONSOLE_BYTES.to_vec(),
    })
}

/// 嵌入模式下 stub 总是可用（除非编译时没拷到 OUT_DIR，那 include_bytes! 直接报错）。
pub fn check_stub_available(kind: StubKind) -> Result<(), StubLoadError> {
    let bytes = load_stub(kind)?;
    if bytes.len() < 64 {
        return Err(StubLoadError {
            kind,
            error: "stub 字节过小，可能已损坏".into(),
        });
    }
    Ok(())
}

/// 选择并加载 stub 模板。
///
/// 返回 `(stub_template, chosen_subsystem)` 或加载错误。
pub fn select_stub(
    original_subsystem: Subsystem,
    preference: StubPreference,
) -> Result<(StubTemplate, Subsystem), StubLoadError> {
    match preference {
        StubPreference::Custom(bytes) => {
            let subsystem = if original_subsystem.is_gui() {
                Subsystem::Gui
            } else {
                Subsystem::Console
            };
            Ok((
                StubTemplate {
                    bytes,
                    subsystem,
                },
                original_subsystem,
            ))
        }
        other => {
            let want_gui = match other {
                StubPreference::Auto => original_subsystem.is_gui(),
                StubPreference::Gui => true,
                StubPreference::Console => false,
                StubPreference::Custom(_) => unreachable!(),
            };

            let kind = if want_gui { StubKind::Gui } else { StubKind::Console };
            let bytes = load_stub(kind)?;
            let chosen = if want_gui { Subsystem::Gui } else { Subsystem::Console };

            Ok((
                StubTemplate {
                    bytes,
                    subsystem: chosen,
                },
                chosen,
            ))
        }
    }
}
