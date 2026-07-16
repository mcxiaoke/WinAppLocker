//! Win32 密码输入对话框。
//!
//! 使用 `DialogBoxIndirectParamW` + 内存中的对话框模板，
//! 不需要资源文件（.rc），避免 build.rs 链接 res 的复杂度。
//!
//! 对话框包含：
//! - 静态文本 "请输入密码："
//! - 密码编辑框（ES_PASSWORD | ES_AUTOHSCROLL，上限 256 字符）
//! - OK / Cancel 按钮
//!
//! 点击 OK 后，把编辑框内容（UTF-16）转成 String 返回；
//! 点击 Cancel 或关闭窗口返回 None。

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    DialogBoxIndirectParamW, EndDialog, GetDlgItem, GetDlgItemTextW,
    GetWindowLongPtrW, IDCANCEL, IDOK, MB_ICONERROR, MB_OK, MessageBoxW, SendMessageW,
    SetWindowLongPtrW, WM_CLOSE, WM_COMMAND, WM_GETTEXT, WM_GETTEXTLENGTH, WM_INITDIALOG,
    WINDOW_LONG_PTR_INDEX,
};

/// DWLP_USER 的正确值。
/// windows-rs 0.51 中只有 DWL_USER（=8，32 位专用），没有 DWLP_USER（=-21，64 位正确值）。
/// 使用 DWL_USER(8) 会覆写对话框的 DLGPROC 指针，导致后续消息分发时跳转到非法地址。
const DWLP_USER_VAL: i32 = -21;

// windows-rs 0.51 中 DS_*/BS_*/ES_*/SS_* 等是 i32 常量（不是 newtype），
// 而 WS_* 是 WINDOW_STYLE newtype（需要 .0 取 u32）。
// 为避免混乱，这里统一用原始 winuser.h 数值。

/// 对话框 / 控件 style 位（原始数值，详见 winuser.h）。
mod style {
    // DLGTEMPLATE style
    pub const DS_MODALFRAME: u32 = 0x0080;
    pub const DS_CENTER: u32 = 0x0800;
    pub const DS_SETFONT: u32 = 0x0040;
    // WINDOW_STYLE
    pub const WS_POPUP: u32 = 0x80000000;
    pub const WS_VISIBLE: u32 = 0x10000000;
    pub const WS_CAPTION: u32 = 0x00C00000;
    pub const WS_SYSMENU: u32 = 0x00080000;
    pub const WS_CHILD: u32 = 0x40000000;
    pub const WS_TABSTOP: u32 = 0x00010000;
    // STATIC
    pub const SS_LEFT: u32 = 0x00000000;
    // EDIT
    pub const ES_AUTOHSCROLL: u32 = 0x0080;
    pub const ES_PASSWORD: u32 = 0x0020;
    // BUTTON
    pub const BS_PUSHBUTTON: u32 = 0x00000000;
    pub const BS_DEFPUSHBUTTON: u32 = 0x00000001;
}

/// 控件原子值（DLGITEMTEMPLATE 中 class 字段为 0xFFFF + atom）。
mod atom {
    pub const BUTTON: u16 = 0x0080;
    pub const EDIT: u16 = 0x0081;
    pub const STATIC: u16 = 0x0082;
}

/// 对话框模板里每个控件的对齐前置填充（DWORD 对齐）。
fn align_dword(buf: &mut Vec<u8>) {
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// 写入以 0 结尾的 UTF-16 字符串（含终止符）。
fn push_wstr(buf: &mut Vec<u8>, s: &str) {
    for u in s.encode_utf16() {
        push_u16(buf, u);
    }
    push_u16(buf, 0);
}

/// 控件 ID 常量。
const IDC_EDIT: u16 = 100;
const IDC_STATIC: u16 = 0;
const IDOK_VAL: u16 = 1; // = IDOK as u16（windows-rs 的 IDOK 是 MESSAGEBOX_RESULT 结构）
const IDCANCEL_VAL: u16 = 2;

/// 组合 style 位。
fn combine(bits: &[u32]) -> u32 {
    bits.iter().fold(0u32, |acc, b| acc | b)
}

/// 构造对话框模板（DLGTEMPLATE + 4 个子项 DLGITEMTEMPLATE）。
fn build_dialog_template() -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);

    // ===== DLGTEMPLATE =====
    let dlg_style = combine(&[
        style::DS_MODALFRAME,
        style::DS_CENTER,
        style::DS_SETFONT,
        style::WS_POPUP,
        style::WS_VISIBLE,
        style::WS_CAPTION,
        style::WS_SYSMENU,
    ]);
    push_u32(&mut buf, dlg_style);
    push_u32(&mut buf, 0); // exstyle
    push_u16(&mut buf, 4); // cdit = 4 个控件
    push_u16(&mut buf, 0); // x
    push_u16(&mut buf, 0); // y
    push_u16(&mut buf, 240); // cx
    push_u16(&mut buf, 70); // cy
    push_u16(&mut buf, 0); // menu
    push_u16(&mut buf, 0); // class
    push_wstr(&mut buf, "EXELock 密码");
    push_u16(&mut buf, 9); // 字号
    push_wstr(&mut buf, "MS Shell Dlg");

    // ===== 子项 1：静态文本 =====
    align_dword(&mut buf);
    push_u32(
        &mut buf,
        combine(&[style::WS_CHILD, style::WS_VISIBLE, style::SS_LEFT]),
    );
    push_u32(&mut buf, 0);
    push_u16(&mut buf, 10); // x
    push_u16(&mut buf, 10); // y
    push_u16(&mut buf, 220); // cx
    push_u16(&mut buf, 12); // cy
    push_u16(&mut buf, IDC_STATIC);
    push_u16(&mut buf, 0xFFFF);
    push_u16(&mut buf, atom::STATIC);
    push_wstr(&mut buf, "请输入密码：");
    push_u16(&mut buf, 0); // cd

    // ===== 子项 2：编辑框 =====
    align_dword(&mut buf);
    push_u32(
        &mut buf,
        combine(&[
            style::WS_CHILD,
            style::WS_VISIBLE,
            style::ES_AUTOHSCROLL,
            style::ES_PASSWORD,
        ]),
    );
    push_u32(&mut buf, 0);
    push_u16(&mut buf, 10); // x
    push_u16(&mut buf, 25); // y
    push_u16(&mut buf, 220); // cx
    push_u16(&mut buf, 14); // cy
    push_u16(&mut buf, IDC_EDIT);
    push_u16(&mut buf, 0xFFFF);
    push_u16(&mut buf, atom::EDIT);
    push_wstr(&mut buf, "");
    push_u16(&mut buf, 0);

    // ===== 子项 3：OK 按钮（默认按钮）=====
    align_dword(&mut buf);
    push_u32(
        &mut buf,
        combine(&[
            style::WS_CHILD,
            style::WS_VISIBLE,
            style::BS_PUSHBUTTON,
            style::BS_DEFPUSHBUTTON,
            style::WS_TABSTOP,
        ]),
    );
    push_u32(&mut buf, 0);
    push_u16(&mut buf, 130); // x
    push_u16(&mut buf, 50); // y
    push_u16(&mut buf, 45); // cx
    push_u16(&mut buf, 14); // cy
    push_u16(&mut buf, IDOK_VAL);
    push_u16(&mut buf, 0xFFFF);
    push_u16(&mut buf, atom::BUTTON);
    push_wstr(&mut buf, "OK");
    push_u16(&mut buf, 0);

    // ===== 子项 4：Cancel 按钮 =====
    align_dword(&mut buf);
    push_u32(
        &mut buf,
        combine(&[
            style::WS_CHILD,
            style::WS_VISIBLE,
            style::BS_PUSHBUTTON,
            style::WS_TABSTOP,
        ]),
    );
    push_u32(&mut buf, 0);
    push_u16(&mut buf, 185); // x
    push_u16(&mut buf, 50); // y
    push_u16(&mut buf, 45); // cx
    push_u16(&mut buf, 14); // cy
    push_u16(&mut buf, IDCANCEL_VAL);
    push_u16(&mut buf, 0xFFFF);
    push_u16(&mut buf, atom::BUTTON);
    push_wstr(&mut buf, "Cancel");
    push_u16(&mut buf, 0);

    buf
}

/// 对话框过程状态：保存用户输入的密码。
struct DialogState {
    password: Option<String>,
}

/// 调试日志（写入文件）。
/// UI 相关日志已关闭（噪声太大），需要时把 0 改成 1。
fn ui_log(_msg: &str) {
    const UI_LOG_ENABLED: u32 = 0;
    if UI_LOG_ENABLED == 0 {
        return;
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(r"C:\Home\Projects\applocker\temp\stub_debug.log")
    {
        let _ = writeln!(f, "[ui] {}", _msg);
        let _ = f.flush();
    }
}

/// 对话框过程。
unsafe extern "system" fn dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    ui_log(&format!("dialog_proc: msg={} wparam={:x} lparam={:x}", msg, wparam.0, lparam.0));
    match msg {
        WM_INITDIALOG => {
            ui_log("WM_INITDIALOG");
            // 保存 state 指针到 DWLP_USER
            let state_ptr = lparam.0 as *mut DialogState;
            ui_log(&format!("state_ptr = {:p}", state_ptr));
            SetWindowLongPtrW(hwnd, WINDOW_LONG_PTR_INDEX(DWLP_USER_VAL), state_ptr as isize);
            ui_log("SetWindowLongPtrW done");
            1
        }
        WM_COMMAND => {
            let cmd = (wparam.0 >> 16) as u16; // HIWORD
            let id = (wparam.0 & 0xFFFF) as u16; // LOWORD
            ui_log(&format!("WM_COMMAND cmd={} id={}", cmd, id));
            // BN_CLICKED = 0
            if cmd != 0 {
                return 0;
            }
            match id {
                x if x == IDOK_VAL => {
                    ui_log("IDOK clicked");
                    let mut buf = [0u16; 256];

                    // 方法1: GetDlgItemTextW
                    let n = GetDlgItemTextW(hwnd, IDC_EDIT as i32, &mut buf);
                    ui_log(&format!("GetDlgItemTextW: n={}", n));

                    let password_str: Option<String> = if n > 0 {
                        Some(OsString::from_wide(&buf[..n as usize])
                            .to_string_lossy()
                            .into_owned())
                    } else {
                        // 方法2: GetDlgItem + SendMessageW(WM_GETTEXT)
                        ui_log("GetDlgItemTextW returned 0, trying WM_GETTEXT fallback");
                        let edit = GetDlgItem(hwnd, IDC_EDIT as i32);
                        if edit.0 == 0 {
                            ui_log("GetDlgItem returned null HWND");
                            None
                        } else {
                            ui_log(&format!("GetDlgItem ok: edit={:?}", edit));
                            let len = SendMessageW(
                                edit,
                                WM_GETTEXTLENGTH,
                                WPARAM(0),
                                LPARAM(0),
                            ).0;
                            ui_log(&format!("WM_GETTEXTLENGTH: {}", len));
                            if len > 0 && len < 256 {
                                let n2 = SendMessageW(
                                    edit,
                                    WM_GETTEXT,
                                    WPARAM(256),
                                    LPARAM(buf.as_mut_ptr() as isize),
                                ).0 as usize;
                                ui_log(&format!("WM_GETTEXT: n2={}", n2));
                                if n2 > 0 {
                                    Some(OsString::from_wide(&buf[..n2])
                                        .to_string_lossy()
                                        .into_owned())
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                    };

                    ui_log(&format!("password_str is_empty={}",
                        password_str.as_ref().map(|s| s.is_empty()).unwrap_or(true)));

                    if let Some(s) = password_str {
                        if !s.is_empty() {
                            let state_ptr = GetWindowLongPtrW(
                                hwnd,
                                WINDOW_LONG_PTR_INDEX(DWLP_USER_VAL),
                            ) as *mut DialogState;
                            if !state_ptr.is_null() {
                                (*state_ptr).password = Some(s);
                            }
                            let _ = EndDialog(hwnd, 1);
                        } else {
                            let _ = EndDialog(hwnd, 0);
                        }
                    } else {
                        let _ = EndDialog(hwnd, 0);
                    }
                    1
                }
                x if x == IDCANCEL_VAL => {
                    let _ = EndDialog(hwnd, 0);
                    1
                }
                _ => 0,
            }
        }
        WM_CLOSE => {
            let _ = EndDialog(hwnd, 0);
            1
        }
        _ => 0,
    }
}

/// 弹出密码输入对话框。
///
/// 返回 `Ok(Some(password))` 表示用户点击 OK 且输入非空；
/// 返回 `Ok(None)` 表示用户点击 Cancel；
/// 返回 `Err(...)` 表示对话框创建失败。
pub fn prompt_password(error_message: Option<&str>) -> Result<Option<String>, String> {
    ui_log("prompt_password: enter");
    // 如果有错误消息，先弹一个 MessageBox 提示用户
    if let Some(msg) = error_message {
        ui_log("prompt_password: showing error box");
        show_error_box(msg);
    }

    ui_log("prompt_password: building template");
    let template = build_dialog_template();
    ui_log(&format!("prompt_password: template size = {} bytes", template.len()));
    let mut state = DialogState { password: None };

    ui_log("prompt_password: GetModuleHandleW");
    let hinst = unsafe {
        windows::Win32::System::LibraryLoader::GetModuleHandleW(None)
            .map_err(|e| format!("GetModuleHandleW failed: {}", e))?
    };
    ui_log(&format!("prompt_password: hinst = {:?}", hinst));

    ui_log("prompt_password: calling DialogBoxIndirectParamW");
    let result = unsafe {
        DialogBoxIndirectParamW(
            hinst,
            template.as_ptr() as *const _,
            None,
            Some(dialog_proc),
            LPARAM(&mut state as *mut DialogState as isize),
        )
    };
    ui_log(&format!("prompt_password: DialogBoxIndirectParamW returned {}", result));

    // DialogBoxIndirectParamW 在失败时返回 -1
    if result == -1 {
        return Err("DialogBoxIndirectParamW 失败".to_string());
    }

    if result == 1 {
        Ok(state.password)
    } else {
        Ok(None)
    }
}

/// 简易错误提示框。
pub fn show_error_box(msg: &str) {
    let mut wide: Vec<u16> = msg.encode_utf16().collect();
    wide.push(0);
    let mut title: Vec<u16> = "EXELock".encode_utf16().collect();
    title.push(0);
    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR(wide.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}

// 防止未使用警告（IDOK / IDCANCEL 实际通过数值常量使用，这里保留导入引用）
#[allow(dead_code)]
fn _id_consts() -> (u16, u16) {
    (IDOK.0 as u16, IDCANCEL.0 as u16)
}

// ===================== Console 密码输入 =====================

/// 在控制台中提示用户输入密码（不回显）。
///
/// 返回 `Ok(Some(password))` 表示用户输入了非空密码并按回车；
/// 返回 `Ok(None)` 表示用户直接按回车（空密码）或 EOF；
/// 返回 `Err(...)` 表示控制台 API 失败。
pub fn prompt_password_console(error_message: Option<&str>) -> Result<Option<String>, String> {
    use std::io::Write;

    // 如果有错误消息，先打印到 stderr
    if let Some(msg) = error_message {
        eprintln!("{}", msg);
    }

    print!("请输入密码: ");
    std::io::stdout().flush().map_err(|e| format!("flush stdout 失败: {}", e))?;

    // 读取一行（不回显）
    let password = read_password_silent()?;

    if password.is_empty() {
        Ok(None)
    } else {
        Ok(Some(password))
    }
}

/// 读取一行密码，不回显到控制台。
///
/// 使用 Windows GetConsoleMode/SetConsoleMode 关闭回显，
/// 读取后恢复原设置。
fn read_password_silent() -> Result<String, String> {
    use std::io::BufRead;
    use windows::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT,
        STD_INPUT_HANDLE,
    };

    let stdin = std::io::stdin();
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) }
        .map_err(|e| format!("GetStdHandle 失败: {}", e))?;

    // 保存原模式
    let mut old_mode = CONSOLE_MODE(0);
    unsafe { GetConsoleMode(handle, &mut old_mode) }
        .map_err(|e| format!("GetConsoleMode 失败: {}", e))?;

    // 关闭回显
    let new_mode = CONSOLE_MODE(old_mode.0 & !ENABLE_ECHO_INPUT.0);
    unsafe { SetConsoleMode(handle, new_mode) }
        .map_err(|e| format!("SetConsoleMode 失败: {}", e))?;

    // 读取一行
    let mut line = String::new();
    let result = stdin.lock().read_line(&mut line);

    // 恢复原模式
    unsafe { let _ = SetConsoleMode(handle, old_mode); }

    // 回显换行（因为回显关闭时换行没打印）
    println!();

    result.map_err(|e| format!("read_line 失败: {}", e))?;

    // 去掉末尾换行符
    let password = line.trim_end_matches(['\r', '\n']).to_string();
    Ok(password)
}
