//! PE 加载器：将解密后的原 EXE 写入临时文件，创建子进程执行。
//!
//! 方案：临时文件（同目录）+ 立即删除
//! - 临时文件创建在原 EXE 所在目录（SxS 探测、DLL 搜索、相对路径都正确）
//! - 创建时即设置 `FILE_ATTRIBUTE_HIDDEN`，资源管理器默认不可见
//! - 随机文件名，创建子进程后立即 DeleteFile（pending delete，再次隐藏）
//! - 子进程工作目录 = 原目录，Windows 加载器处理所有 PE 加载细节
//! - 子进程退出后 OS 自动删除文件数据
//!
//! 设环境变量 EXELOCK_DEBUG=1 可启用调试日志（写入 %TEMP%\exelock_debug.log）。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;

use windows::Win32::Foundation::{CloseHandle, HMODULE, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_FLAGS_AND_ATTRIBUTES, CREATE_ALWAYS,
    FILE_ATTRIBUTE_HIDDEN,
};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::Threading::{
    CreateProcessW, WaitForSingleObject, GetExitCodeProcess,
    PROCESS_INFORMATION, STARTUPINFOW, CREATE_UNICODE_ENVIRONMENT,
};
use windows::core::PCWSTR;

use thiserror::Error;

fn log_enabled() -> bool {
    std::env::var("EXELOCK_DEBUG").is_ok()
}

fn log(msg: &str) {
    if !log_enabled() { return; }
    if let Some(path) = std::env::temp_dir().join("exelock_debug.log").to_str() {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "[loader] {}", msg);
            let _ = f.flush();
        }
    }
}

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("写入临时文件失败: {0}")]
    WriteFile(String),
    #[error("获取原EXE路径失败: {0}")]
    SelfPath(String),
    #[error("创建子进程失败: {0}")]
    CreateProcess(String),
    #[error("等待子进程失败: {0}")]
    Wait(String),
    #[error("获取子进程退出码失败")]
    ExitCode,
}

/// 临时文件名：基于 stub 进程 PID（确定性，便于排查残留）。
///
/// 不用随机时间戳，便于：
/// - 残留排查：看到 el_1234.exe 就知道是 PID 1234 的 stub 留下的
/// - 多实例共存：每个 stub 进程 PID 不同，文件名自然不冲突
fn temp_name() -> String {
    let pid = std::process::id();
    format!("el_{}.exe", pid)
}

fn to_wide(s: &Path) -> Vec<u16> {
    s.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

fn get_self_dir() -> Result<PathBuf, LoaderError> {
    let mut path = vec![0u16; 32768];
    let len = unsafe { GetModuleFileNameW(HMODULE(0), &mut path) };
    if len == 0 {
        return Err(LoaderError::SelfPath("GetModuleFileNameW returned 0".into()));
    }
    let path = String::from_utf16_lossy(&path[..len as usize]);
    let pb = PathBuf::from(path);
    Ok(pb.parent().ok_or(LoaderError::SelfPath("no parent dir".into()))?.to_path_buf())
}

pub fn run_pe(plaintext_pe: &[u8]) -> Result<u32, LoaderError> {
    log("run_pe: enter");

    let self_dir = get_self_dir()?;
    log(&format!("run_pe: self_dir={}", self_dir.display()));

    let temp_path = self_dir.join(temp_name());
    log(&format!("run_pe: temp_path={}", temp_path.display()));

    let temp_path_wide = to_wide(&temp_path);
    let self_dir_wide = to_wide(&self_dir);

    // 用 CreateFileW 创建文件时直接带上 HIDDEN 属性，
    // 避免 File::create 与后续 SetFileAttributes 之间的可见窗口。
    write_hidden_file(&temp_path_wide, plaintext_pe)?;
    log("run_pe: PE data written");

    let mut cmd_line = temp_path_wide.clone();

    let mut si = STARTUPINFOW::default();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi = PROCESS_INFORMATION::default();

    log("run_pe: calling CreateProcessW...");
    let create_result = unsafe {
        CreateProcessW(
            PCWSTR(temp_path_wide.as_ptr()),
            windows::core::PWSTR(cmd_line.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT,
            None,
            PCWSTR(self_dir_wide.as_ptr()),
            &si,
            &mut pi,
        )
    };

    if let Err(e) = create_result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(LoaderError::CreateProcess(e.to_string()));
    }

    log(&format!("run_pe: child created, pid={}", pi.dwProcessId));

    unsafe { CloseHandle(pi.hThread).ok(); }

    // 不在子进程运行期间 DeleteFile：子进程持有 EXE 镜像，DeleteFileW 会因
    // sharing violation 失败（Windows PE loader 默认不带 FILE_SHARE_DELETE）。
    // 改为等子进程退出后再删除：此时所有句柄已释放，删除必成功。

    log("run_pe: waiting for child...");
    let wait_result = unsafe { WaitForSingleObject(pi.hProcess, u32::MAX) };
    if wait_result != WAIT_OBJECT_0 {
        unsafe { CloseHandle(pi.hProcess).ok(); }
        // 等待失败也要尝试清理
        try_delete_with_retry(&temp_path);
        return Err(LoaderError::Wait(format!("Wait returned {}", wait_result.0)));
    }

    let mut exit_code: u32 = 0;
    unsafe {
        let ok = GetExitCodeProcess(pi.hProcess, &mut exit_code);
        CloseHandle(pi.hProcess).ok();
        if ok.is_err() {
            try_delete_with_retry(&temp_path);
            return Err(LoaderError::ExitCode);
        }
    }

    // 子进程已退出，句柄已关闭，删除临时文件（带重试，应对 OS 异步释放）
    try_delete_with_retry(&temp_path);

    log(&format!("run_pe: child exited with code {}", exit_code));
    Ok(exit_code)
}

/// 删除临时文件，带短重试（应对 OS 异步释放文件句柄 / 杀软扫描占用）。
fn try_delete_with_retry(path: &Path) {
    for attempt in 0..5 {
        match std::fs::remove_file(path) {
            Ok(_) => {
                log(&format!("run_pe: temp file deleted (attempt {})", attempt));
                return;
            }
            Err(e) => {
                log(&format!("run_pe: delete attempt {} failed: {}", attempt, e));
                if attempt < 4 {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
    }
    log("run_pe: WARNING failed to delete temp file after retries");
}

/// 创建临时文件并写入 PE 数据。
///
/// 使用 `CreateFileW` 直接指定 `FILE_ATTRIBUTE_HIDDEN`，
/// 文件从创建那一刻起就被标记为隐藏（资源管理器默认设置下不可见）。
fn write_hidden_file(
    path_wide: &[u16],
    data: &[u8],
) -> Result<(), LoaderError> {
    // GENERIC_WRITE = 0x40000000
    const GENERIC_WRITE: u32 = 0x4000_0000;
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            CREATE_ALWAYS,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_ATTRIBUTE_HIDDEN.0),
            None,
        )
    }
    .map_err(|e| LoaderError::WriteFile(format!("CreateFileW: {}", e)))?;

    // HANDLE 转 std::fs::File 写入数据；drop 时关闭句柄
    let mut file = unsafe { File::from_raw_handle(handle.0 as *mut _) };
    file.write_all(data)
        .and_then(|_| file.sync_all())
        .map_err(|e| LoaderError::WriteFile(e.to_string()))?;
    // 显式 drop 关闭句柄，让子进程能独占打开
    drop(file);
    Ok(())
}
