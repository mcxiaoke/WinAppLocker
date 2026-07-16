//! RunPE 内存加载器：在当前进程内手动加载 PE 并执行。
//!
//! 核心步骤（详见 `docs/ARCHITECTURE.md §5.2`）：
//! 1. 解析 PE，校验 MZ/PE 签名
//! 2. VirtualAlloc 分配内存（按 SizeOfImage）
//! 3. 复制 PE 头与各节区
//! 4. 处理基址重定位（若实际基址 != 期望基址）
//! 5a. 补丁 PEB（ImageBaseAddress / ImagePathName）— 修主模块查找
//! 5b. 激活 SxS 上下文（内嵌 manifest）— 必须在解析导入之前
//! 6. 处理导入表：LoadLibrary + GetProcAddress 填充 IAT（SxS 已生效）
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
const DIR_DELAY_IMPORT: usize = 13;

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

    // 注：SxS 激活上下文已由 packer 在打包时把原 EXE 的 RT_MANIFEST
    //     复制到 stub 资源中，OS loader 启动 stub 时自动建立。
    //     不再需要手动 activate_sxs_context。
    //
    // 但仍需补丁 PEB + 注入 LDR 条目：
    // - PEB.ImageBaseAddress：让 GetModuleHandleW(NULL) 返回映射镜像基址
    // - PEB.ProcessParameters->ImagePathName：GetModuleFileNameW(NULL) 返回正确路径
    // - LDR 链表注入：FindResource(hModule) 内部验证 hModule 在 Ldr 链表里，
    //   否则资源查找失败 → GUI 程序找不到对话框模板 → 静默退出
    let image_path_wide: Vec<u16> = std::env::current_exe()
        .ok()
        .map(|p| {
            let mut v: Vec<u16> = p.as_os_str().encode_wide().collect();
            v.push(0);
            v
        })
        .unwrap_or_default();
    let mut saved_peb = unsafe { patch_peb_for_image(base, &image_path_wide) };
    unsafe { ldr_register(&mut saved_peb, base, image_size as u32, entry_rva, &image_path_wide) };
    log(&format!(
        "run_pe: PEB patched + Ldr registered (ImageBase -> 0x{:x}, ldr_entry={})",
        base,
        !saved_peb.ldr_entry.is_null()
    ));

    // 6. 修复导入表（SxS 上下文已由 stub manifest 在进程启动时建立，
    //    comctl32 等会正确重定向到 v6）
    log("run_pe: resolving imports");
    resolve_imports(base, &pe)?;
    log("run_pe: imports resolved");
    // 6a. 延迟导入表：提前解析填充 IAT，避免运行时调用未初始化 thunk 崩溃
    resolve_delay_imports(base, &pe)?;

    // 7. 设置节区内存权限
    log("run_pe: setting section permissions");
    set_section_permissions_from_pe(base, image_size)?;
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

    // 11. 安全 Cookie：不预填，保留默认值 0x2B992DDFA232。
    //     程序 OEP 调用链里的 __security_init_cookie 会检测到默认值并自己
    //     生成随机 cookie + complement。若手动写随机值会破坏两者同步，
    //     导致后续 _initterm 全局构造里的栈检查失败 → SIGSEGV。

    // 12. 跳转到 OEP
    if entry_rva == 0 {
        log("run_pe: entry_rva=0, returning 0");
        return Ok(0);
    }
    let entry_point = base + entry_rva;
    log(&format!("run_pe: jumping to OEP at 0x{:x}", entry_point));

    // 诊断：dump cookie (0x45a3d0) 和 complement (0x45a3c8) 当前值
    let cookie_addr = base + 0x5a3d0;
    let complement_addr = base + 0x5a3c8;
    unsafe {
        let cookie_val = std::ptr::read(cookie_addr as *const u64);
        let comp_val = std::ptr::read(complement_addr as *const u64);
        log(&format!(
            "diag: cookie@0x{:x}=0x{:016x} complement@0x{:x}=0x{:016x}",
            cookie_addr, cookie_val, complement_addr, comp_val
        ));
    }

    // 注册 VEH 捕获 OEP 执行期间的首次异常，记录 RIP/异常码便于诊断
    unsafe {
        CRASH_BASE = base;
        let _ = AddVectoredExceptionHandler(1, crash_handler);
    }

    jump_to_oep(entry_point);

    // 理论上不会到达这里（原 EXE 会调用 ExitProcess）
    log("run_pe: returned from OEP (unexpected)");
    unsafe { restore_peb(saved_peb) };
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

// ===================== PEB 补丁（主镜像伪装） =====================

// x64 PEB 偏移：
//   PEB.ImageBaseAddress       @ +0x10
//   PEB.Ldr (PEB_LDR_DATA*)    @ +0x18
//   PEB.ProcessParameters      @ +0x20
//   RTL_USER_PROCESS_PARAMETERS.ImagePathName (UNICODE_STRING) @ +0x60
//     UNICODE_STRING { Length: u16, MaximumLength: u16, Buffer: *mut u16 }
//
// PEB_LDR_DATA 偏移：
//   InLoadOrderModuleList           @ +0x10  (LIST_ENTRY)
//   InMemoryOrderModuleList         @ +0x20  (LIST_ENTRY)
//   InInitializationOrderModuleList @ +0x30  (LIST_ENTRY)
//
// LDR_DATA_TABLE_ENTRY64 偏移（按 InLoadOrder 链表项布局）：
//   InLoadOrderLinks         @ +0x00  (LIST_ENTRY: Flink/Blink)
//   InMemoryOrderLinks       @ +0x10
//   InInitializationOrderLinks @ +0x20
//   DllBase                  @ +0x30
//   EntryPoint               @ +0x38
//   SizeOfImage              @ +0x40
//   FullDllName (UNICODE_STRING) @ +0x48
//   BaseDllName (UNICODE_STRING) @ +0x58
//   Flags                    @ +0x68
//   ...
// 注：InMemoryOrder 链表里存的是 &entry.InMemoryOrderLinks，即 entry+0x10
//     InInitializationOrder 链表里存的是 &entry.InInitializationOrderLinks，即 entry+0x20

#[repr(C)]
struct PebUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_initialization_order_links: ListEntry,
    dll_base: usize,
    entry_point: usize,
    size_of_image: u32,
    full_dll_name: PebUnicodeString,
    base_dll_name: PebUnicodeString,
    flags: u32,
    // 后续字段不使用，省略
}

/// PEB 补丁前的原始状态，用于事后恢复。
struct SavedPeb {
    image_base: usize,
    img_path_length: u16,
    img_path_max_length: u16,
    img_path_buffer: *mut u16,
    /// 我们插入的 LDR 条目（None 表示未插入）
    ldr_entry: *mut LdrDataTableEntry,
}

/// 读取 x64 PEB 指针（gs:[0x60]）。
unsafe fn peb_ptr() -> *mut u8 {
    let peb: *mut u8;
    std::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags, readonly),
    );
    peb
}

/// 在 PEB.Ldr 的三个链表头部插入一个 LDR_DATA_TABLE_ENTRY。
/// 这样 OS loader 在 InMemoryOrderModuleList 里能找到我们的镜像，
/// CreateActCtxW(ACTCTX_FLAG_HMODULE_VALID) 才会成功。
///
/// 返回新分配的 entry 指针（事后用于从链表摘除并释放）。
unsafe fn ldr_insert_module(
    base: usize,
    size_of_image: u32,
    entry_point: usize,
    full_path_wide: &[u16], // 含结尾 0
    base_name_wide: &[u16], // 含结尾 0
) -> *mut LdrDataTableEntry {
    let peb = peb_ptr();
    let ldr = std::ptr::read(peb.add(0x18) as *const *mut u8);
    if ldr.is_null() {
        return std::ptr::null_mut();
    }

    // 分配 entry（堆分配，生命周期到 unlink 为止）
    let entry = Box::into_raw(Box::new(std::mem::zeroed::<LdrDataTableEntry>()));

    (*entry).dll_base = base;
    (*entry).entry_point = entry_point;
    (*entry).size_of_image = size_of_image;

    // UNICODE_STRING：length 不含结尾 0，MaximumLength 含
    let set_str = |dst: *mut PebUnicodeString, src: &[u16]| {
        if src.is_empty() {
            return;
        }
        let byte_len = ((src.len() - 1) * 2) as u16;
        (*dst).length = byte_len;
        (*dst).maximum_length = (src.len() * 2) as u16;
        (*dst).buffer = src.as_ptr() as *mut u16;
    };
    set_str(&mut (*entry).full_dll_name, full_path_wide);
    set_str(&mut (*entry).base_dll_name, base_name_wide);

    // Flags：LDRP_IMAGE_DLL | LDRP_ENTRY_PROCESSED（避免 loader 再处理它）
    (*entry).flags = 0x00000004 | 0x00008000;

    // 插入三个链表的头部（Flink 指向原 first，Blink 指向 list head）
    // InLoadOrderModuleList @ PEB_LDR_DATA+0x10
    let load_list = ldr.add(0x10) as *mut ListEntry;
    insert_in_list(entry as *mut ListEntry, load_list, 0);

    // InMemoryOrderModuleList @ +0x20 —— 该链表项是 entry+0x10
    let mem_list = ldr.add(0x20) as *mut ListEntry;
    insert_in_list((entry as usize + 0x10) as *mut ListEntry, mem_list, 0);

    // InInitializationOrderModuleList @ +0x30 —— 该链表项是 entry+0x20
    let init_list = ldr.add(0x30) as *mut ListEntry;
    insert_in_list((entry as usize + 0x20) as *mut ListEntry, init_list, 0);

    entry
}

/// 把 `node` 插入到双向链表 `head` 的紧后面（即成为新的 first 元素）。
/// `offset` 仅用于日志，无实际作用。
unsafe fn insert_in_list(node: *mut ListEntry, head: *mut ListEntry, _offset: usize) {
    let first = (*head).flink;
    (*node).flink = first;
    (*node).blink = head;
    if !first.is_null() {
        (*first).blink = node;
    }
    (*head).flink = node;
}

/// 从三个链表中摘除 entry 并释放。
unsafe fn ldr_remove_module(entry: *mut LdrDataTableEntry) {
    if entry.is_null() {
        return;
    }
    remove_from_list(entry as *mut ListEntry);
    remove_from_list((entry as usize + 0x10) as *mut ListEntry);
    remove_from_list((entry as usize + 0x20) as *mut ListEntry);
    drop(Box::from_raw(entry));
}

/// 从双向链表摘除节点。
unsafe fn remove_from_list(node: *mut ListEntry) {
    let blink = (*node).blink;
    let flink = (*node).flink;
    if !blink.is_null() {
        (*blink).flink = flink;
    }
    if !flink.is_null() {
        (*flink).blink = blink;
    }
    (*node).flink = std::ptr::null_mut();
    (*node).blink = std::ptr::null_mut();
}

/// 补丁 PEB（ImageBaseAddress + ImagePathName），让 GetModuleHandleW(NULL) 等返回本镜像。
/// LDR 链表注入由 `ldr_register` 单独完成。
unsafe fn patch_peb_for_image(
    base: usize,
    image_path_wide: &[u16], // 含结尾 0
) -> SavedPeb {
    let peb = peb_ptr();

    // 1. ImageBaseAddress @ PEB+0x10
    let img_base_slot = peb.add(0x10) as *mut usize;
    let saved_image_base = std::ptr::read(img_base_slot);
    std::ptr::write(img_base_slot, base);

    // 2. ProcessParameters->ImagePathName @ PEB+0x20 -> +0x60
    let pp = std::ptr::read(peb.add(0x20) as *const *mut u8);
    let img_name = pp.add(0x60) as *mut PebUnicodeString;
    let saved = SavedPeb {
        image_base: saved_image_base,
        img_path_length: (*img_name).length,
        img_path_max_length: (*img_name).maximum_length,
        img_path_buffer: (*img_name).buffer,
        ldr_entry: std::ptr::null_mut(),
    };
    if !image_path_wide.is_empty() {
        let byte_len = ((image_path_wide.len() - 1) * 2) as u16;
        (*img_name).length = byte_len;
        (*img_name).maximum_length = (image_path_wide.len() * 2) as u16;
        (*img_name).buffer = image_path_wide.as_ptr() as *mut u16;
    }

    saved
}

/// 插入 LDR 条目（在 patch_peb_for_image 之后单独调用，因为需要 image_path_wide 存活）。
/// 把返回的 entry 写回 SavedPeb.ldr_entry 以便事后清理。
unsafe fn ldr_register(saved: &mut SavedPeb, base: usize, image_size: u32, entry_rva: usize, image_path_wide: &[u16]) {
    if image_path_wide.is_empty() {
        return;
    }
    // 从全路径提取 basename（最后一个 '\' 或 '/' 之后）
    let mut base_start = 0usize;
    for (i, &w) in image_path_wide.iter().enumerate() {
        if w == b'\\' as u16 || w == b'/' as u16 {
            base_start = i + 1;
        }
    }
    let base_name_wide = &image_path_wide[base_start..];

    let entry = ldr_insert_module(
        base,
        image_size,
        base + entry_rva,
        image_path_wide,
        base_name_wide,
    );
    saved.ldr_entry = entry;
}

/// 恢复 PEB 原始状态（仅当 OEP 返回时需要）。
unsafe fn restore_peb(mut saved: SavedPeb) {
    // 先摘除 LDR 条目
    ldr_remove_module(saved.ldr_entry);
    saved.ldr_entry = std::ptr::null_mut();

    let peb = peb_ptr();
    std::ptr::write(peb.add(0x10) as *mut usize, saved.image_base);
    let pp = std::ptr::read(peb.add(0x20) as *const *mut u8);
    let img_name = pp.add(0x60) as *mut PebUnicodeString;
    (*img_name).length = saved.img_path_length;
    (*img_name).maximum_length = saved.img_path_max_length;
    (*img_name).buffer = saved.img_path_buffer;
}

// ===================== SxS 激活上下文 =====================

// ACTCTXW 结构（x64 布局，repr(C) 自动处理 wLangId 后的对齐填充）。
#[repr(C)]
#[derive(Default)]
struct ActCtxW {
    cb_size: u32,
    dw_flags: u32,
    lp_source: *const u16,
    w_processor_architecture: u16,
    w_lang_id: u16,
    lp_assembly_directory: *const u16,
    lp_resource_name: *const u16,
    lp_application_name: *const u16,
    h_module: *mut std::ffi::c_void,
}

const ACTCTX_FLAG_RESOURCE_NAME_VALID: u32 = 0x0000_0008;
const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;

// RT_MANIFEST = 24, CREATEPROCESS_MANIFEST_RESOURCE_ID = 1
const RT_MANIFEST: u32 = 24;

#[link(name = "kernel32")]
extern "system" {
    fn CreateActCtxW(actctx: *mut ActCtxW) -> *mut std::ffi::c_void;
    fn ActivateActCtx(h: *mut std::ffi::c_void, cookie: *mut usize) -> i32;
    fn DeactivateActCtx(flags: u32, cookie: usize) -> i32;
    fn ReleaseActCtx(h: *mut std::ffi::c_void);
}

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
}

// PE 资源目录结构（仅取遍历 manifest 所需字段）
#[repr(C)]
#[derive(Default)]
struct ImageResourceDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    number_of_named_entries: u16,
    number_of_id_entries: u16,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct ImageResourceDirectoryEntry {
    name_or_id: u32,
    offset_to_data: u32,
}

/// 在镜像资源目录里查找 RT_MANIFEST 类型资源的 ID。
/// 返回找到的 manifest 资源 ID（通常为 1，但有些 EXE 用别的）。
/// 没找到返回 None。
unsafe fn find_manifest_resource_id(base: usize) -> Option<u32> {
    // 从 NT 头取资源目录 RVA
    let dos = base as *const u8;
    let e_lfanew = std::ptr::read(dos.add(0x3c) as *const i32) as usize;
    let nt = base + e_lfanew;
    // OptionalHeader 在 NT 头 + 0x18（4 字节签名 + 0x14 COFF 头）
    // DataDirectory 起始 = OptionalHeader + 0x70 (PE32+)
    let opt = nt + 0x18;
    let data_dir = opt + 0x70;
    // 资源目录 = DataDirectory[2]
    let res_rva = std::ptr::read((data_dir + 2 * 8) as *const u32) as usize;
    let res_size = std::ptr::read((data_dir + 2 * 8 + 4) as *const u32) as usize;
    if res_rva == 0 || res_size == 0 {
        return None;
    }
    let res_base = base + res_rva;

    // 顶层目录：遍历 entries，找 Name = RT_MANIFEST (24) 的
    let top_dir = res_base as *const ImageResourceDirectory;
    let top_count = (*top_dir).number_of_named_entries as u32 + (*top_dir).number_of_id_entries as u32;
    let top_entries = (top_dir as *const u8).add(std::mem::size_of::<ImageResourceDirectory>())
        as *const ImageResourceDirectoryEntry;

    for i in 0..top_count as usize {
        let entry = std::ptr::read(top_entries.add(i));
        let type_id = entry.name_or_id & 0x7FFF_FFFF; // 高位为 0 表示 ID
        if type_id != RT_MANIFEST {
            continue;
        }
        // entry.offset_to_data 高位为 1 表示指向下一层目录
        if entry.offset_to_data & 0x8000_0000 == 0 {
            continue; // 不正常，manifest 应该有子目录
        }
        let second_dir_offset = entry.offset_to_data & 0x7FFF_FFFF;
        let second_dir = (res_base + second_dir_offset as usize) as *const ImageResourceDirectory;
        let second_count = (*second_dir).number_of_named_entries as u32
            + (*second_dir).number_of_id_entries as u32;
        let second_entries = (second_dir as *const u8).add(std::mem::size_of::<ImageResourceDirectory>())
            as *const ImageResourceDirectoryEntry;

        // 第二层每个 entry 的 name_or_id 就是 manifest 资源 ID（通常为 1）
        if second_count > 0 {
            let manifest_id = std::ptr::read(second_entries).name_or_id & 0x7FFF_FFFF;
            return Some(manifest_id);
        }
    }
    None
}

/// 从镜像内嵌 manifest 创建并激活 SxS 上下文。
/// manifest 资源已在打包时复制到加密文件的资源段中，因此直接用
/// lpSource 指向加密文件路径 + RESOURCE_NAME_VALID 即可让 OS 加载。
///
/// 必须在 TLS 回调与 OEP 之前调用，以便 CRT 启动时 manifest 已生效；
/// 否则声明 comctl32 v6 依赖的 GUI 程序会拿到错误的控件版本。
///
/// 返回 (handle, cookie) 用于事后清理；无 manifest 资源或失败返回 None。
unsafe fn activate_sxs_context(
    base: usize,
    image_path_wide: &[u16],
) -> Option<(*mut std::ffi::c_void, usize)> {
    let manifest_id = match find_manifest_resource_id(base) {
        Some(id) => {
            log(&format!("activate_sxs: found manifest resource id={}", id));
            id
        }
        None => {
            log("activate_sxs: no RT_MANIFEST resource found");
            return None;
        }
    };

    // 提取所在目录（截到最后一个 '\' 或 '/'）
    let mut dir_end = image_path_wide.len();
    for (i, &w) in image_path_wide.iter().enumerate() {
        if w == b'\\' as u16 || w == b'/' as u16 {
            dir_end = i + 1;
        }
    }
    let mut dir_wide: Vec<u16> = image_path_wide[..dir_end].to_vec();
    dir_wide.push(0); // 结尾 0

    // lpSource 指向加密文件，OS 从文件资源段读取 RT_MANIFEST
    // manifest 资源已在打包时由 copy_icon_and_version_resources 复制到加密文件
    let mut ctx = ActCtxW {
        cb_size: std::mem::size_of::<ActCtxW>() as u32,
        dw_flags: ACTCTX_FLAG_RESOURCE_NAME_VALID,
        lp_source: image_path_wide.as_ptr(),
        lp_resource_name: manifest_id as usize as *const u16,
        lp_assembly_directory: dir_wide.as_ptr(),
        ..Default::default()
    };
    let h = CreateActCtxW(&mut ctx);
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        let err = GetLastError();
        log(&format!(
            "activate_sxs: CreateActCtxW failed, GetLastError={}",
            err
        ));
        return None;
    }

    let mut cookie = 0usize;
    if ActivateActCtx(h, &mut cookie) == 0 {
        let err = GetLastError();
        log(&format!(
            "activate_sxs: ActivateActCtx failed, GetLastError={}",
            err
        ));
        ReleaseActCtx(h);
        return None;
    }
    Some((h, cookie))
}

/// 反激活并释放 SxS 上下文（仅当 OEP 返回时需要）。
unsafe fn deactivate_sxs_context(h: *mut std::ffi::c_void, cookie: usize) {
    DeactivateActCtx(0, cookie);
    ReleaseActCtx(h);
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

        // 加载 DLL（SxS 上下文应已激活，LoadLibraryW 会正确处理重定向）
        let hmodule = load_dll(&dll_name)?;
        log(&format!("imports: '{}' loaded hmod=0x{:x}", dll_name, hmodule.0 as usize));

        // 遍历 thunk，解析每个函数
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        let mut thunk_offset = thunk_rva;
        let mut iat_offset = first_thunk;
        let mut func_count = 0u32;
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
            func_count += 1;

            thunk_offset += 8; // x64 thunk 是 8 字节
            iat_offset += 8;
        }
        log(&format!("imports: '{}' resolved {} funcs", dll_name, func_count));

        offset += 20; // 下一个 IMPORT_DESCRIPTOR
    }

    Ok(())
}

/// 解析延迟导入表（DataDirectory[13]）。
///
/// IMAGE_DELAYLOAD_DESCRIPTOR（32 字节）：
///   +0x00 Attributes (DWORD)
///   +0x04 DllNameRVA (DWORD)
///   +0x08 ModuleHandleRVA (DWORD)  —— 指向 HMODULE 存储槽
///   +0x0c ImportAddressTableRVA (DWORD)  —— IAT
///   +0x10 ImportNameTableRVA (DWORD)  —— INT
///   +0x14 BoundImportAddressTableRVA (DWORD)
///   +0x18 UnloadInformationTableRVA (DWORD)
///   +0x1c TimeDateStamp (DWORD)
///
/// 手动加载时把延迟导入当作普通导入提前解析，把函数地址写入 IAT，
/// 避免运行时跳到未初始化的延迟导入 thunk 导致调用 0 崩溃。
fn resolve_delay_imports(base: usize, pe: &PE) -> Result<(), LoaderError> {
    let (dir_rva, dir_size) = match get_data_directory(pe, DIR_DELAY_IMPORT) {
        Some((va, sz)) if va != 0 && sz != 0 => (va as usize, sz as usize),
        _ => return Ok(()), // 无延迟导入表
    };
    log("resolve_delay_imports: delay import directory present");

    let mut offset = dir_rva;
    let end = dir_rva + dir_size;
    while offset + 32 <= end {
        let attributes = read_u32(base, offset);
        let dll_name_rva = read_u32(base, offset + 4) as usize;
        let module_handle_rva = read_u32(base, offset + 8) as usize;
        let iat_rva = read_u32(base, offset + 0x0c) as usize;
        let int_rva = read_u32(base, offset + 0x10) as usize;

        // 结束标记：全 0 描述符
        if dll_name_rva == 0 && iat_rva == 0 && int_rva == 0 {
            break;
        }

        let dll_name_bytes = read_cstr(base, dll_name_rva);
        let dll_name = String::from_utf8_lossy(&dll_name_bytes).to_string();
        log(&format!("resolve_delay_imports: dll='{}' iat_rva=0x{:x}", dll_name, iat_rva));

        // 加载 DLL（失败不致命，跳过此描述符）
        let hmodule = match load_dll(&dll_name) {
            Ok(h) => h,
            Err(e) => {
                log(&format!("resolve_delay_imports: load '{}' failed: {}", dll_name, e));
                offset += 32;
                continue;
            }
        };

        // 把 HMODULE 写入 ModuleHandle 槽（供延迟导入 helper 使用）
        if module_handle_rva != 0 {
            write_u64_raw(base + module_handle_rva, hmodule.0 as u64);
        }

        // 遍历 INT，解析每个函数并写入 IAT
        // Attributes bit 1 (0x02) = RVABased，否则用 VA（手动映射时都是 RVA）
        let _ = attributes;
        let mut int_off = int_rva;
        let mut iat_off = iat_rva;
        let mut count = 0u32;
        loop {
            let thunk_value = read_u64(base, int_off);
            if thunk_value == 0 {
                break;
            }
            let func_addr = if thunk_value & (1u64 << 63) != 0 {
                // 序号导入
                let ordinal = (thunk_value & 0xFFFF) as u16;
                get_proc_address_by_ordinal(hmodule, ordinal, &dll_name)?
            } else {
                // 名称导入：thunk_value 是 RVA，指向 IMAGE_IMPORT_BY_NAME
                let hint_name_rva = thunk_value as usize;
                let func_name_bytes = read_cstr(base, hint_name_rva + 2);
                let func_name = String::from_utf8_lossy(&func_name_bytes).to_string();
                get_proc_address_by_name(hmodule, &func_name, &dll_name)?
            };
            write_u64_raw(base + iat_off, func_addr as u64);
            int_off += 8;
            iat_off += 8;
            count += 1;
        }
        log(&format!("resolve_delay_imports: '{}' resolved {} funcs", dll_name, count));

        offset += 32; // 下一个 DELAYLOAD_DESCRIPTOR
    }

    Ok(())
}

// ===================== 节区权限 =====================

fn set_section_permissions_from_pe(base: usize, image_size: usize) -> Result<(), LoaderError> {
    // 简化策略：整个镜像区域统一设为 RWX，避免分段 virtual_size 不覆盖
    // cookie/complement 等 BSS 扩展数据导致写权限缺失。
    // 隐蔽性损失可接受（运行期），稳定性优先。
    let mut old_protect = PAGE_PROTECTION_FLAGS::default();
    unsafe {
        VirtualProtect(
            base as *const _,
            image_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| LoaderError::VirtualProtect(e.to_string()))?;
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

// 用于 VEH 记录镜像基址，算崩溃 RVA
static mut CRASH_BASE: usize = 0;
static mut CRASH_CPP_COUNT: u32 = 0;

#[repr(C)]
struct ExceptionRecord {
    exception_code: u32,
    exception_flags: u32,
    exception_record: *mut ExceptionRecord,
    exception_address: usize,
    number_parameters: u32,
    _reserved: u32,
    exception_information: [usize; 15],
}

#[repr(C)]
struct ExceptionPointers {
    exception_record: *mut ExceptionRecord,
    context_record: *mut u8,
}

#[link(name = "kernel32")]
extern "system" {
    fn AddVectoredExceptionHandler(
        first: u32,
        handler: unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
    ) -> *mut std::ffi::c_void;
}

/// x64 CONTEXT 偏移（含开头 P1Home..P6Home 48 字节）：
/// Rsp@0x98, Rip@0xF8
const CTX_RSP_OFFSET: usize = 0x98;
const CTX_RIP_OFFSET: usize = 0xf8;

/// VEH：捕获 OEP 执行期间的异常，记录异常码/RIP/RVA/调用栈候选到日志。
/// 对 C++ 异常（0xe06d7363）记录前 8 次以定位抛出点；其它异常记录首次。
unsafe extern "system" fn crash_handler(ep: *mut ExceptionPointers) -> i32 {
    if ep.is_null() {
        return 0;
    }
    let rec = (*ep).exception_record;
    if rec.is_null() {
        return 0;
    }
    let code = (*rec).exception_code;
    let base = CRASH_BASE;

    // C++ 异常：记录前 8 次；其它异常：只记录首次
    let is_cpp_exc = code == 0xe06d7363;
    if is_cpp_exc {
        let n = CRASH_CPP_COUNT;
        if n >= 8 {
            return 0;
        }
        CRASH_CPP_COUNT = n + 1;
    } else {
        // 非C++异常：只记录一次
        if CRASH_BASE & 1 == 1 {
            return 0;
        }
        CRASH_BASE |= 1;
    }

    let addr = (*rec).exception_address;
    log(&format!(
        "crash[{}]: code=0x{:08x} addr=0x{:x} (RVA=0x{:x})",
        if is_cpp_exc { CRASH_CPP_COUNT - 1 } else { 0 },
        code,
        addr,
        if addr >= base && addr < base + 0x200000 { addr - base } else { 0 }
    ));
    // C++ 异常：ExceptionInformation[0]=throw code addr, [1]=obj ptr, [2]=throw info
    if is_cpp_exc && (*rec).number_parameters >= 3 {
        let throw_addr = (*rec).exception_information[0];
        let throw_info = (*rec).exception_information[2];
        log(&format!(
            "crash: cpp throw_addr=0x{:x} (RVA=0x{:x}) throw_info=0x{:x}",
            throw_addr,
            if throw_addr >= base && throw_addr < base + 0x200000 { throw_addr - base } else { 0 },
            throw_info
        ));
    }

    let ctx = (*ep).context_record;
    if !ctx.is_null() {
        let rip = *(ctx.add(CTX_RIP_OFFSET) as *const usize);
        let rsp = *(ctx.add(CTX_RSP_OFFSET) as *const usize);
        log(&format!(
            "crash: rip=0x{:x} (RVA=0x{:x}) rsp=0x{:x}",
            rip,
            if rip >= base && rip < base + 0x200000 { rip - base } else { 0 },
            rsp
        ));
        // 扫描栈找落在镜像范围的返回地址候选（最多扫 16KB，找 20 个）
        if rsp != 0 && base != 0 {
            let mut found = 0u32;
            let scan_end = rsp + 0x4000;
            let mut p = rsp;
            while p < scan_end && found < 20 {
                let v = *(p as *const usize);
                // 返回地址应在 .text 段范围内（base+0x1000 .. base+image_size）
                if v > base + 0x1000 && v < base + 0xaa000 {
                    log(&format!(
                        "crash: stack[0x{:x}] -> RVA=0x{:x}",
                        p - rsp,
                        v - base
                    ));
                    found += 1;
                }
                p += 8;
            }
            if found == 0 {
                log("crash: no in-image return addr on stack");
            }
        }
    }
    0 // EXCEPTION_CONTINUE_SEARCH
}

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
