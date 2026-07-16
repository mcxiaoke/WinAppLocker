//! 图标资源复制：从原 EXE 提取图标资源写入到加密后的输出文件。
//!
//! 使用 Windows 资源 API（通过 FFI 直接调用，不依赖 windows-rs 的 feature 配置）：
//! - `LoadLibraryExW(LOAD_LIBRARY_AS_DATAFILE)` 加载原 EXE 作为数据文件
//! - `EnumResourceNamesW` 枚举 RT_ICON / RT_GROUP_ICON / RT_VERSION
//! - `BeginUpdateResourceW` / `UpdateResourceW` / `EndUpdateResourceW` 写入输出文件

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

// Windows API 常量
const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x00000002;
const RT_ICON: u32 = 3;
const RT_GROUP_ICON: u32 = 14;
const RT_VERSION: u32 = 16;
const LANG_NEUTRAL: u16 = 0;

// Windows API 类型
type HMODULE = isize;
type HANDLE = isize;
type BOOL = i32;
type HRSRC = isize;
type HGLOBAL = isize;

// Windows API 函数声明
extern "system" {
    fn LoadLibraryExW(lpFileName: *const u16, hFile: HANDLE, dwFlags: u32) -> HMODULE;
    fn FreeLibrary(hModule: HMODULE) -> BOOL;
    fn EnumResourceNamesW(
        hModule: HMODULE,
        lpType: u32,
        lpEnumFunc: unsafe extern "system" fn(HMODULE, u32, *const u16, isize) -> BOOL,
        lParam: isize,
    ) -> BOOL;
    fn FindResourceW(hModule: HMODULE, lpName: *const u16, lpType: u32) -> HRSRC;
    fn LoadResource(hModule: HMODULE, hResInfo: HRSRC) -> HGLOBAL;
    fn LockResource(hResData: HGLOBAL) -> *const u8;
    fn SizeofResource(hModule: HMODULE, hResInfo: HRSRC) -> u32;
    fn BeginUpdateResourceW(pFileName: *const u16, bDeleteExistingResources: BOOL) -> HANDLE;
    fn UpdateResourceW(
        hUpdate: HANDLE,
        lpType: u32,
        lpName: *const u16,
        wLanguage: u16,
        lpData: *const u8,
        cbData: u32,
    ) -> BOOL;
    fn EndUpdateResourceW(hUpdate: HANDLE, fDiscard: BOOL) -> BOOL;
}

/// 收集到的资源条目：(类型, 名称, 数据)
type ResourceEntry = (u32, Vec<u16>, Vec<u8>);

/// 从 `src_exe` 提取图标和版本资源，写入 `dst_exe`。
///
/// 如果提取或写入过程中出错，返回错误字符串（不影响主加密流程）。
pub fn copy_icon_and_version_resources(src_exe: &Path, dst_exe: &Path) -> Result<(), String> {
    let src_wide = path_to_wide(src_exe);

    // 1. 加载原 EXE 作为数据文件
    let hsrc = unsafe {
        LoadLibraryExW(src_wide.as_ptr(), 0, LOAD_LIBRARY_AS_DATAFILE)
    };
    if hsrc == 0 {
        return Err("LoadLibraryExW 失败".to_string());
    }

    // 2. 收集所有需要复制的资源
    let mut resources: Vec<ResourceEntry> = Vec::new();

    for rt in [RT_ICON, RT_GROUP_ICON, RT_VERSION] {
        let mut collector = Collector { resources: &mut resources, hsrc };
        unsafe {
            EnumResourceNamesW(
                hsrc,
                rt,
                enum_callback,
                &mut collector as *mut _ as isize,
            );
        }
    }

    // 3. 释放原 EXE
    unsafe { FreeLibrary(hsrc); }

    if resources.is_empty() {
        return Ok(());
    }

    // 4. 写入到目标 EXE
    let dst_wide = path_to_wide(dst_exe);
    let hupdate = unsafe { BeginUpdateResourceW(dst_wide.as_ptr(), 0) };
    if hupdate == 0 {
        return Err("BeginUpdateResourceW 失败".to_string());
    }

    for (rt, name, data) in &resources {
        // 资源名称需要以 0 结尾
        let mut name_buf = name.clone();
        name_buf.push(0);

        let result = unsafe {
            UpdateResourceW(
                hupdate,
                *rt,
                name_buf.as_ptr(),
                LANG_NEUTRAL,
                data.as_ptr(),
                data.len() as u32,
            )
        };
        if result == 0 {
            unsafe { EndUpdateResourceW(hupdate, 1); }
            return Err(format!("UpdateResourceW 失败 (rt={})", rt));
        }
    }

    let result = unsafe { EndUpdateResourceW(hupdate, 0) };
    if result == 0 {
        return Err("EndUpdateResourceW 失败".to_string());
    }

    Ok(())
}

/// 资源收集器。
struct Collector<'a> {
    resources: &'a mut Vec<ResourceEntry>,
    hsrc: HMODULE,
}

/// EnumResourceNamesW 回调。
unsafe extern "system" fn enum_callback(
    hmodule: HMODULE,
    _rt: u32,
    name: *const u16,
    lparam: isize,
) -> BOOL {
    let collector = &mut *(lparam as *mut Collector);

    // 读取资源名称（以 0 结尾的 UTF-16 字符串）
    let mut name_vec: Vec<u16> = Vec::new();
    let mut ptr = name;
    loop {
        let ch = *ptr;
        if ch == 0 {
            break;
        }
        name_vec.push(ch);
        ptr = ptr.add(1);
    }

    // 查找并加载资源
    // 资源名称：如果是数字（如 "#1"），需要用 MAKEINTRESOURCE 方式
    // 但 EnumResourceNamesW 回调中，name 直接就是可用的指针
    let mut name_buf = name_vec.clone();
    name_buf.push(0);

    // 使用回调中的 name 指针（而不是 name_buf），因为 FindResourceW 需要原始指针
    let hinfo = FindResourceW(hmodule, name, _rt);
    if hinfo == 0 {
        return 1; // 继续枚举
    }

    let hglobal = LoadResource(hmodule, hinfo);
    if hglobal == 0 {
        return 1;
    }

    let size = SizeofResource(hmodule, hinfo) as usize;
    let data_ptr = LockResource(hglobal);

    if size > 0 && !data_ptr.is_null() {
        let data = std::slice::from_raw_parts(data_ptr, size).to_vec();
        collector.resources.push((_rt, name_vec, data));
    }

    1 // TRUE - 继续枚举
}

/// 把路径转换为 UTF-16 字符串（以 0 结尾）。
fn path_to_wide(path: &Path) -> Vec<u16> {
    let os_str: &OsStr = path.as_ref();
    let mut wide: Vec<u16> = os_str.encode_wide().collect();
    wide.push(0);
    wide
}
