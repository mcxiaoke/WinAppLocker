/*
 * winlock/reflective/loader.c - 反射式 stub 主体（MVP v1 明文模式）
 *
 * 设计原则（按 REFLECTIVE_DESIGN.md 阶段 1 MVP）：
 *   - 开发优先：用 Win32 API + CRT，允许 printf 调试
 *   - 不加密、不压缩、不反调试、不反 dump
 *   - 支持 x64 和 x86（用 _WIN64 宏区分）
 *   - reloc 5 类型全支持（ABS/DIR64/HIGHLOW/HIGH/LOW）
 *   - TLS 只调 ATTACH，不分配 TLS 数据块
 *   - IAT 用 LoadLibraryA + GetProcAddress（OS 自动处理 forwarder）
 *
 * 流程：
 *   1. 定位 .payload 节，解析 reflective_payload_t
 *   2. VirtualAlloc 分配 SizeOfImage 内存（优先 preferred ImageBase）
 *   3. 复制 PE headers + 各节
 *   4. 处理 IAT（LoadLibraryA + GetProcAddress）
 *   4.5 处理延迟导入表（DataDirectory[13]，预填延迟 IAT）
 *   5. 应用 relocations（5 类型）
 *   6. RtlAddFunctionTable 注册 .pdata（仅 x64，x86 SEH 走 FS:[0] 链无法手动注册）
 *   7. 初始化 SecurityCookie
 *   8. VirtualProtect 设置节权限
 *   9. 更新 PEB.ImageBaseAddress + PEB.Ldr 主 EXE 条目
 *  10. 调用原 PE 的 TLS callbacks（DLL_PROCESS_ATTACH）
 *  11. jump_to_oep(new_image + oep_rva)
 *
 * x86 vs x64 关键差异：
 *   - PE 头：IMAGE_NT_HEADERS32 vs 64，OptionalHeader 布局不同
 *   - IAT thunk：4 字节 vs 8 字节
 *   - 重定位：x86 主要用 HIGHLOW，x64 主要用 DIR64
 *   - 异常处理：x64 走 .pdata + RUNTIME_FUNCTION（可手动注册），
 *               x86 走 FS:[0] SEH 链（无法手动注册，依赖编译器生成的 SEH 表）
 *   - PEB 访问：fs:[0x30] vs gs:[0x60]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

#include "payload.h"

/* ---- 架构相关类型别名 ----
 * 让下面代码用统一的 IMAGE_NT_HEADERS_X / thunk_t 等符号，
 * 实际类型由 _WIN64 宏决定。
 * 这样 95% 的代码不需要 #ifdef 区分 */
#ifdef _WIN64
  typedef IMAGE_NT_HEADERS64            IMAGE_NT_HEADERS_X;
  typedef IMAGE_TLS_DIRECTORY64         IMAGE_TLS_DIRECTORY_X;
  typedef IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_X;
  typedef ULONGLONG                     cookie_va_t;   /* SecurityCookie VA 类型 */
  #define IMAGE_ORDINAL_FLAG_X    IMAGE_ORDINAL_FLAG64
  #define IMAGE_ORDINAL_X(v)      IMAGE_ORDINAL64(v)
  #define MY_MACHINE              IMAGE_FILE_MACHINE_AMD64
  typedef uint64_t thunk_t;   /* IAT/ILT 表项类型 */
#else
  typedef IMAGE_NT_HEADERS32            IMAGE_NT_HEADERS_X;
  typedef IMAGE_TLS_DIRECTORY32         IMAGE_TLS_DIRECTORY_X;
  typedef IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_X;
  typedef DWORD                         cookie_va_t;
  #define IMAGE_ORDINAL_FLAG_X    IMAGE_ORDINAL_FLAG32
  #define IMAGE_ORDINAL_X(v)      IMAGE_ORDINAL32(v)
  #define MY_MACHINE              IMAGE_FILE_MACHINE_I386
  typedef uint32_t thunk_t;
#endif

/* ---- 延迟导入表描述符（ImgDelayDescr）----
 * MinGW winnt.h 不一定提供，自己定义
 * 字段顺序与 Microsoft 文档一致（32 字节） */
typedef struct {
    DWORD Attributes;                  /* +0x00 bit1=DLAT_RVA 表示字段是 RVA 而非 VA */
    DWORD DllNameRVA;                  /* +0x04 DLL 名字 RVA/VA */
    DWORD ModuleHandleRVA;             /* +0x08 HMODULE 存放位置 RVA/VA（运行时填）*/
    DWORD ImportAddressTableRVA;       /* +0x0C IAT RVA/VA（运行时填函数指针）*/
    DWORD ImportNameTableRVA;          /* +0x10 INT RVA/VA（thunk 布局同 IAT）*/
    DWORD BoundImportAddressTableRVA;  /* +0x14 绑定 IAT（不用）*/
    DWORD UnloadInformationTableRVA;   /* +0x18 卸载信息（不用）*/
    DWORD TimeDateStamp;               /* +0x1C */
} IMAGE_DELAYLOAD_DESCRIPTOR_X;

#define DLAT_RVA 0x01  /* Microsoft PE 规范：bit 0 = 1 表示字段是 RVA（现代 PE 默认）*/

/* ---- 调试开关 ----
 * MVP 阶段开启 RDEBUG，日志写到 reflective_loader.log（与 EXE 同目录）
 * 同时通过 OutputDebugStringA 输出（可用 DebugView 观察）
 * 不再使用 AllocConsole + printf（避免 GUI 程序启动时弹 console 干扰）
 * 后期可关闭 RDEBUG */
#define RDEBUG 1

#if RDEBUG
static FILE* g_logf = NULL;
static void log_init(void) {
    /* 日志文件路径 = EXE 所在目录\reflective_loader.log */
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) { g_logf = NULL; return; }
    /* 替换 .exe 后缀为 _loader.log */
    char* p = strrchr(path, '.');
    if (p) strcpy(p, "_loader.log");
    else strcat(path, "_loader.log");
    g_logf = fopen(path, "w");
}
/* 只输出到文件（OutputDebugStringA 会触发 0x40010006 异常，干扰 VEH 调试） */
#define DBG(fmt, ...) do { \
    if (g_logf) { fprintf(g_logf, "[REFL] " fmt, ##__VA_ARGS__); fflush(g_logf); } \
} while (0)
#else
#define DBG(fmt, ...) do {} while (0)
static void log_init(void) {}
#endif

/* ---- PEB 访问 ----
 * x64: PEB 在 gs:[0x60]
 * x86: PEB 在 fs:[0x30]
 * PVOID 自动按架构变大小 */
typedef struct {
    UCHAR  a, b, c, d;       /* offset 0-3: InheritedAddressSpace 等  */
    PVOID  Mutant;           /* offset 8 (x64) / 4 (x86)，前面有 padding */
    PVOID  ImageBaseAddress; /* offset 16 (x64) / 8 (x86) */
    PVOID  Ldr;              /* offset 24 (x64) / 12 (x86) -> PEB_LDR_DATA */
} PEBX;

#ifdef _WIN64
#define WINLOCK_PEB() ((PEBX*)__readgsqword(0x60))
#else
#define WINLOCK_PEB() ((PEBX*)(uintptr_t)__readfsdword(0x30))
#endif

/* ---- PEB_LDR_DATA + LDR_DATA_TABLE_ENTRY（简化版，仅含需要的字段） ----
 * 用于修改主 EXE 在 PEB.Ldr 里的条目，让 OS 识别反射加载的 PE 为模块。
 * 这样 LoadString / LoadResource 等走 LdrFindResource_U 的 API 能工作。
 *
 * 布局参考：MS Internal `nt!_LDR_DATA_TABLE_ENTRY` 和 AlushPacker structs.h
 * 字段顺序/偏移必须与 OS 一致，因此用 BYTE 数组占位未用字段 */
typedef struct _MY_LIST_ENTRY {
    struct _MY_LIST_ENTRY* Flink;
    struct _MY_LIST_ENTRY* Blink;
} MY_LIST_ENTRY;

typedef struct _PEB_LDR_DATA_X {
    ULONG      Length;                              /* +0x00 */
    BOOLEAN    Initialized;                         /* +0x04 */
    PVOID      SsHandle;                            /* +0x08 */
    MY_LIST_ENTRY InLoadOrderModuleList;            /* +0x10 */
    MY_LIST_ENTRY InMemoryOrderModuleList;          /* +0x20 */
    MY_LIST_ENTRY InInitializationOrderModuleList;  /* +0x30 */
} PEB_LDR_DATA_X;

/* LDR_DATA_TABLE_ENTRY 仅前几个字段需要精确偏移，后面用 BYTE[] 占位
 * InLoadOrderLinks        +0x00 (16 字节)
 * InMemoryOrderLinks      +0x10 (16 字节)
 * InInitializationOrderLinks +0x20 (16 字节)
 * DllBase                 +0x30
 * EntryPoint              +0x38
 * SizeOfImage             +0x40 (ULONG)
 * FullDllName             +0x48 (UNICODE_STRING: USHORT Length, USHORT MaxLength, PVOID Buffer)
 * BaseDllName             +0x58
 */
typedef struct _LDR_DATA_TABLE_ENTRY_X {
    MY_LIST_ENTRY InLoadOrderLinks;          /* +0x00 */
    MY_LIST_ENTRY InMemoryOrderLinks;        /* +0x10 */
    MY_LIST_ENTRY InInitializationOrderLinks;/* +0x20 */
    PVOID         DllBase;                   /* +0x30 */
    PVOID         EntryPoint;                /* +0x38 */
    ULONG         SizeOfImage;               /* +0x40 */
    ULONG         _pad1;                     /* +0x44 对齐 */
    struct { USHORT Length; USHORT MaxLength; PVOID Buffer; } FullDllName; /* +0x48 */
    struct { USHORT Length; USHORT MaxLength; PVOID Buffer; } BaseDllName; /* +0x58 */
} LDR_DATA_TABLE_ENTRY_X;

/* ---- OEP return 后的兜底处理 ----
 * _mainCRTStartup 正常路径会调用 exit() 不返回；但如果原 PE 直接 return，
 * 会回到这里。这时调用 ExitProcess 终止，避免跳到栈上的垃圾地址。
 * noinline + used 防止编译器优化掉 */
static void __attribute__((noinline, used)) oep_returned(int exit_code) {
    if (g_logf) {
        fprintf(g_logf, "[REFL] OEP returned (unexpected, exit_code=%d), calling ExitProcess\n",
                exit_code);
        fflush(g_logf);
    }
    ExitProcess((UINT)exit_code);
    __builtin_unreachable();
}

/* ---- x64 栈对齐跳 OEP（借鉴 winlock stub.c:743-759 + peldr） ----
 * 用 push + jmp 模拟 call，压入返回地址（oep_returned）
 * 这样原 PE 内的 C++ 异常 dispatch 能正确 unwind 到本 stub 帧，
 * 不会因找不到 caller 而 terminate（修复 DontSleep/MFC42u 崩溃问题）
 *
 * x64 ABI: 函数入口 RSP % 16 == 8
 *   andq $-16, rsp  -> RSP % 16 == 0
 *   pushq ret       -> RSP -= 8, RSP % 16 == 8 ✓ */
static void jump_to_oep(void* oep, void* ret_addr) {
#ifdef _WIN64
    __asm__ volatile (
        "andq $-16, %%rsp\n\t"   /* 16 字节对齐 */
        "pushq %1\n\t"           /* 压入返回地址，RSP -= 8（RSP % 16 == 8） */
        "jmpq *%0\n\t"           /* jmp 到 OEP，相当于 call 但返回地址已压入 */
        : : "r"(oep), "r"(ret_addr) : "memory"
    );
#else
    __asm__ volatile (
        "andl $-16, %%esp\n\t"
        "pushl %1\n\t"
        "jmp *%0\n\t"
        : : "r"(oep), "r"(ret_addr) : "memory"
    );
#endif
    __builtin_unreachable();
}

/* ---- 节权限查表（借鉴 peldr ProtTab + AlushPacker 8 项） ----
 * 根据 IMAGE_SECTION_HEADER.Characteristics 的高 3 位
 * (W<<2)|(R<<1)|E 查表得到 PAGE_* 保护常量
 *   bit 31 (W) = IMAGE_SCN_MEM_WRITE   = 0x80000000
 *   bit 30 (R) = IMAGE_SCN_MEM_READ    = 0x40000000
 *   bit 29 (E) = IMAGE_SCN_MEM_EXECUTE = 0x20000000 */
static DWORD sec_char_to_prot(DWORD ch) {
    static const DWORD tab[8] = {
        PAGE_NOACCESS,            /* 0 --- */
        PAGE_EXECUTE,             /* 1 --E */
        PAGE_READONLY,            /* 2 -R- */
        PAGE_EXECUTE_READ,        /* 3 -RE */
        PAGE_READWRITE,           /* 4 W-- (Windows 上 write 隐含 read) */
        PAGE_EXECUTE_READWRITE,   /* 5 W-E */
        PAGE_READWRITE,           /* 6 WR- (writecopy -> readwrite) */
        PAGE_EXECUTE_READWRITE,   /* 7 WRE (writecopy+exec -> exec+readwrite) */
    };
    return tab[(ch >> 29) & 0x7];
}

/* ---- 定位 .payload 节 ----
 * 从 stub 自己的 image base 解析 PE 头，找名为 ".payload" 的节
 * 返回节的内存地址（已映射），NULL 表示未找到
 * out_size 输出节的 VirtualSize */
static uint8_t* find_payload_section(uint32_t* out_size) {
    HMODULE hSelf = GetModuleHandleW(NULL);
    if (!hSelf) return NULL;
    uint8_t* base = (uint8_t*)hSelf;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS_X* nt = (IMAGE_NT_HEADERS_X*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".payload", 8) == 0) {
            if (out_size) *out_size = sec[i].Misc.VirtualSize;
            return base + sec[i].VirtualAddress;
        }
    }
    return NULL;
}

/* ---- 处理 IAT ----
 * 遍历 Import Directory，对每个 DLL:
 *   LoadLibraryA(dll_name) 加载
 *   遍历 thunks，GetProcAddress 解析每个函数
 *   写入 IAT
 * GetProcAddress 自动处理 forwarder，MVP 不用自己实现递归 */
static int process_iat(uint8_t* img) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)img;
    IMAGE_NT_HEADERS_X* nt = (IMAGE_NT_HEADERS_X*)(img + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir->VirtualAddress == 0 || dir->Size == 0) {
        DBG("iat: no import directory, skip\n");
        return 1;
    }

    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(img + dir->VirtualAddress);
    int dll_count = 0, func_count = 0;
    for (; imp->Name != 0; imp++) {
        const char* dll_name = (const char*)(img + imp->Name);
        DBG("iat: loading %s\n", dll_name);
        HMODULE hMod = LoadLibraryA(dll_name);
        if (!hMod) {
            DBG("iat: LoadLibraryA(%s) failed, err=%lu\n", dll_name, GetLastError());
            return 0;
        }

        /* OriginalFirstThunk = ILT (Import Lookup Table)，FirstThunk = IAT
         * 有些 PE 的 OriginalFirstThunk 为 0（绑定导入），用 FirstThunk 兜底
         * x64 thunk 8 字节，x86 thunk 4 字节，用 thunk_t 统一 */
        thunk_t* ilt = (thunk_t*)(img + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        thunk_t* iat = (thunk_t*)(img + imp->FirstThunk);

        for (; *ilt != 0; ilt++, iat++) {
            const char* func_name = NULL;
            WORD ord = 0;
            if (*ilt & IMAGE_ORDINAL_FLAG_X) {
                ord = (WORD)IMAGE_ORDINAL_X(*ilt);
            } else {
                IMAGE_IMPORT_BY_NAME* iibn = (IMAGE_IMPORT_BY_NAME*)(img + (*ilt & 0x7FFFFFFF));
                func_name = (const char*)iibn->Name;
            }

            FARPROC fn;
            if (func_name) {
                fn = GetProcAddress(hMod, func_name);
                DBG("  %s!%s = %p\n", dll_name, func_name, (void*)fn);
            } else {
                fn = GetProcAddress(hMod, MAKEINTRESOURCEA(ord));
                DBG("  %s!#%u = %p\n", dll_name, ord, (void*)fn);
            }
            if (!fn) {
                /* MVP 宽松策略：失败的导入写 NULL，记录警告但不退出
                 * 原因：某些 PE 通过 SxS manifest 引用 v6 comctl32 等特殊版本，
                 *      stub 没解析 manifest，LoadLibraryA 加载的是默认版本，
                 *      部分 ordinal 可能不存在（如 comctl32 #381 仅 v6 有）
                 * 风险：原 PE 若实际调用此 import，运行时会 crash
                 *      但若只是声明未调用，能跳到 OEP 验证流程
                 * 后期可改进：用 ActivateActCtx + LoadLibraryExW 走 manifest */
                DBG("iat: WARN GetProcAddress failed for %s!%s (err=%lu), set NULL\n",
                    dll_name, func_name ? func_name : "#ord", GetLastError());
                *iat = 0;
                continue;
            }
            *iat = (thunk_t)fn;
            func_count++;
        }
        dll_count++;
    }
    DBG("iat: resolved %d dlls, %d functions\n", dll_count, func_count);
    return 1;
}

/* ---- 处理延迟导入表（IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT）----
 * 遍历 DataDirectory[13]，对每个 IMAGE_DELAYLOAD_DESCRIPTOR_X：
 *   1. LoadLibraryA(dll_name) 加载 DLL
 *   2. 把 HMODULE 写到 ModuleHandleRVA 指向的位置（供原 PE 的 __delayLoadHelper2 复用）
 *   3. 遍历 ImportNameTable，GetProcAddress 解析每个函数
 *   4. 写入 ImportAddressTable
 *
 * 策略：启动时主动加载所有延迟导入，跟普通 IAT 一样预填 IAT。
 * 优点：原 PE 跳到 OEP 时延迟 IAT 已就绪，首次调用直接走真实函数，
 *      不依赖原 PE 内部的 __delayLoadHelper2 stub 机制。
 * 缺点：失去延迟加载的启动加速效果（对 packer 不重要）。
 *
 * 字段格式：现代 PE（VS2008+）所有字段是 RVA（Attributes & DLAT_RVA），
 *          老格式是 VA，需要减去 preferred ImageBase 转成 RVA。
 *
 * 失败策略：DLL 加载失败或函数解析失败都写 NULL 并警告，不退出。
 * 原因：延迟导入本身就是可选的（程序不调用就不会触发），宽松处理能让
 *      更多 PE 跑到 OEP（即使个别延迟函数不存在）。 */
static int process_delay_imports(uint8_t* img) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)img;
    IMAGE_NT_HEADERS_X* nt = (IMAGE_NT_HEADERS_X*)(img + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (dir->VirtualAddress == 0 || dir->Size == 0) {
        DBG("delay: no delay import directory, skip\n");
        return 1;
    }

    /* preferred ImageBase，用于把老格式 VA 转 RVA */
    uint64_t img_base = (uint64_t)nt->OptionalHeader.ImageBase;

    IMAGE_DELAYLOAD_DESCRIPTOR_X* desc =
        (IMAGE_DELAYLOAD_DESCRIPTOR_X*)(img + dir->VirtualAddress);
    int dll_count = 0, func_count = 0;
    /* 终止条件：全 0 描述符（Attributes=0 && DllNameRVA=0）*/
    for (; desc->Attributes != 0 || desc->DllNameRVA != 0; desc++) {
        int is_rva = (desc->Attributes & DLAT_RVA) != 0;

        /* DllName 位置 */
        uint32_t name_rva = desc->DllNameRVA;
        if (!is_rva && name_rva) {
            /* VA 格式：减去 preferred ImageBase 得到 RVA */
            name_rva = (uint32_t)((uint64_t)desc->DllNameRVA - img_base);
        }
        if (name_rva == 0) continue;
        const char* dll_name = (const char*)(img + name_rva);

        /* IAT / INT / HMODULE 位置 */
        uint32_t iat_rva = desc->ImportAddressTableRVA;
        uint32_t int_rva = desc->ImportNameTableRVA;
        uint32_t hm_rva  = desc->ModuleHandleRVA;
        if (!is_rva) {
            if (iat_rva) iat_rva = (uint32_t)((uint64_t)iat_rva - img_base);
            if (int_rva) int_rva = (uint32_t)((uint64_t)int_rva - img_base);
            if (hm_rva)  hm_rva  = (uint32_t)((uint64_t)hm_rva  - img_base);
        }

        DBG("delay: loading %s (attrs=0x%lx, rva_fmt=%d)\n", dll_name, desc->Attributes, is_rva);
        HMODULE hMod = LoadLibraryA(dll_name);
        if (!hMod) {
            /* 延迟 DLL 加载失败：警告但不退出（程序可能根本不调用这些函数）*/
            DBG("delay: WARN LoadLibraryA(%s) failed, err=%lu, skip this dll\n",
                dll_name, GetLastError());
            continue;
        }

        /* 把 HMODULE 写到 ModuleHandleRVA 指向的位置
         * 原因：原 PE 的 __delayLoadHelper2 会读这个 HMODULE 复用已加载的 DLL */
        if (hm_rva) {
            HMODULE* hm_slot = (HMODULE*)(img + hm_rva);
            *hm_slot = hMod;
        }

        /* 遍历 INT，解析每个函数，写入 IAT
         * INT 和 IAT 都是 thunk_t 数组（x64=8字节，x86=4字节）
         * INT 项布局与普通 IAT 相同：
         *   - 高位 1（IMAGE_ORDINAL_FLAG_X）：按 ordinal 导入
         *   - 否则：低 31 位是 IMAGE_IMPORT_BY_NAME 的 RVA */
        if (int_rva && iat_rva) {
            thunk_t* intp = (thunk_t*)(img + int_rva);
            thunk_t* iatp = (thunk_t*)(img + iat_rva);
            for (; *intp != 0; intp++, iatp++) {
                const char* func_name = NULL;
                WORD ord = 0;
                if (*intp & IMAGE_ORDINAL_FLAG_X) {
                    ord = (WORD)IMAGE_ORDINAL_X(*intp);
                } else {
                    IMAGE_IMPORT_BY_NAME* iibn = (IMAGE_IMPORT_BY_NAME*)(img + (*intp & 0x7FFFFFFF));
                    func_name = (const char*)iibn->Name;
                }

                FARPROC fn;
                if (func_name) {
                    fn = GetProcAddress(hMod, func_name);
                } else {
                    fn = GetProcAddress(hMod, MAKEINTRESOURCEA(ord));
                }
                if (!fn) {
                    DBG("delay: WARN GetProcAddress failed for %s!%s (err=%lu), set NULL\n",
                        dll_name, func_name ? func_name : "#ord", GetLastError());
                    *iatp = 0;
                    continue;
                }
                *iatp = (thunk_t)fn;
                func_count++;
            }
        }
        dll_count++;
    }
    DBG("delay: resolved %d dlls, %d functions\n", dll_count, func_count);
    return 1;
}

/* ---- Fallback 重定位：扫描节找绝对地址引用 ----
 * 当 PE 没有 reloc 表但需要重定位时使用（如 AutoHotkey32.exe 无 reloc，
 * 但 OS 把 stack 放在 preferred base 0x400000 导致必须重定位）
 *
 * 算法：扫描所有节（除 .rsrc）的 1 字节步长 4 字节读取，
 * 如果 dword 在 [old_base, old_base + SizeOfImage) 范围内，
 * 认为是绝对地址引用，改成 new_base + (dword - old_base)。
 *
 * 关键保护：用 skip bitmap 标记所有不能改的区域：
 *   - IMPORT/IAT/DELAY_IMPORT 表本身（字段是 RVA，加 delta 会破坏）
 *   - IMPORT 表里所有 DLL 名字字符串和函数名字字符串
 *     （这些字符串在 .rdata 里，4 字节读可能恰好落在范围内被误改）
 *
 * 返回 1 成功，0 失败 */
static int fallback_relocations(uint8_t* img, uint64_t old_base, uint64_t new_base) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)img;
    IMAGE_NT_HEADERS_X* nt = (IMAGE_NT_HEADERS_X*)(img + dos->e_lfanew);
    uint32_t size_of_image = nt->OptionalHeader.SizeOfImage;
    int32_t delta32 = (int32_t)(new_base - old_base);

    uint64_t range_start = old_base;
    uint64_t range_end = old_base + size_of_image;

    /* 分配 skip bitmap：每字节标记一个 RVA 是否不能修改
     * SizeOfImage 通常 1MB 左右，分配代价小 */
    uint8_t* skip = (uint8_t*)calloc(size_of_image, 1);
    if (!skip) {
        DBG("reloc: fallback calloc(%u) failed\n", size_of_image);
        return 0;
    }

    /* 标记 IMPORT/IAT/DELAY_IMPORT 表本身所在区域 */
    uint32_t import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    uint32_t import_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    uint32_t iat_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
    uint32_t iat_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
    uint32_t delay_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
    uint32_t delay_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
    if (import_rva && import_rva + import_size <= size_of_image)
        memset(skip + import_rva, 1, import_size);
    if (iat_rva && iat_rva + iat_size <= size_of_image)
        memset(skip + iat_rva, 1, iat_size);
    if (delay_rva && delay_rva + delay_size <= size_of_image)
        memset(skip + delay_rva, 1, delay_size);

    /* 遍历 IMPORT 表，标记每个 DLL 名字和函数名字字符串的范围
     * 这些字符串在 .rdata 里，4 字节读可能恰好落在范围内被误改
     * 例如 "PSAPI.DLL\0" 中第 6-9 字节读成 0x004C4C44 落在 [0x400000, 0x4f5000) */
    int n_str = 0;
    if (import_rva && import_size) {
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(img + import_rva);
        for (; imp->Name != 0; imp++) {
            /* DLL 名字字符串 */
            uint32_t name_rva = imp->Name;
            if (name_rva && name_rva < size_of_image) {
                const char* p = (const char*)(img + name_rva);
                size_t slen = strnlen(p, size_of_image - name_rva);
                uint32_t end = name_rva + (uint32_t)slen + 1;
                if (end <= size_of_image) {
                    memset(skip + name_rva, 1, slen + 1);
                    n_str++;
                }
            }
            /* ILT 中的 IMAGE_IMPORT_BY_NAME 结构（hint + name） */
            uint32_t ilt_rva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
            if (ilt_rva && ilt_rva < size_of_image) {
                thunk_t* ilt = (thunk_t*)(img + ilt_rva);
                /* 防止 ILT 越界：限制最多扫 65536 项 */
                for (int k = 0; k < 65536 && *ilt != 0; ilt++, k++) {
                    if (*ilt & IMAGE_ORDINAL_FLAG_X) continue;
                    uint32_t iibn_rva = (uint32_t)(*ilt & 0x7FFFFFFF);
                    if (iibn_rva == 0 || iibn_rva >= size_of_image) continue;
                    /* IMAGE_IMPORT_BY_NAME: WORD hint + char name[] + '\0' */
                    const char* p = (const char*)(img + iibn_rva + 2);
                    size_t slen = strnlen(p, size_of_image - iibn_rva - 2);
                    uint32_t end = iibn_rva + 2 + (uint32_t)slen + 1;
                    if (end <= size_of_image) {
                        memset(skip + iibn_rva, 1, 2 + slen + 1);
                        n_str++;
                    }
                }
            }
        }
    }
    DBG("reloc: fallback protected %d IAT string regions\n", n_str);

    int count = 0;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        /* 跳过 .rsrc（资源节很少有绝对地址引用） */
        if (memcmp(sec[i].Name, ".rsrc", 5) == 0) continue;
        if (sec[i].SizeOfRawData < 4) continue;

        uint8_t* start = img + sec[i].VirtualAddress;
        SIZE_T size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (size > sec[i].SizeOfRawData) size = sec[i].SizeOfRawData;
        int sec_count = 0;
        /* 1 字节步长扫描（x86 absolute address 在指令中位置不固定，4 字节对齐会漏）
         * 跳过任何与 skip bitmap 相交的 4 字节范围 */
        for (SIZE_T off = 0; off + 4 <= size; off++) {
            uint32_t rva_here = sec[i].VirtualAddress + (uint32_t)off;
            /* 如果当前 4 字节范围内有任何 skip 标记，跳过这 4 字节
             * （保护 IAT 表和字符串内容） */
            if (rva_here + 4 <= size_of_image) {
                if (skip[rva_here] | skip[rva_here+1] | skip[rva_here+2] | skip[rva_here+3])
                    continue;
            }
            uint32_t val = *(uint32_t*)(start + off);
            if (val >= range_start && val < range_end) {
                *(uint32_t*)(start + off) = val + delta32;
                count++;
                sec_count++;
            }
        }
        DBG("reloc: fallback scanned %*.8s VA=0x%lx size=0x%zx, fixed %d refs\n",
            8, sec[i].Name, (unsigned long)sec[i].VirtualAddress, (size_t)size, sec_count);
    }
    free(skip);
    DBG("reloc: fallback total fixed %d absolute refs (delta=0x%x)\n",
        count, (unsigned)delta32);
    return 1;  /* 即使 count=0 也返回成功，让流程继续（可能 PE 真的不需要 reloc） */
}

/* ---- 应用 relocations（完整 5 类型：ABS/DIR64/HIGHLOW/HIGH/LOW） ----
 * old_base = preferred ImageBase（PE 头里的值）
 * new_base = 实际加载地址
 * 如果 old_base == new_base，无需重定位
 *
 * 类型说明：
 *   ABSOLUTE  (0)  - padding，跳过
 *   HIGHLOW   (3)  - 32 位绝对地址，加 (int32_t)delta（x86 用）
 *   HIGH      (1)  - 32 位地址的高 16 位，加 delta>>16（罕见，16 位 Windows 遗留）
 *   LOW       (2)  - 32 位地址的低 16 位，加 delta&0xFFFF（罕见，16 位 Windows 遗留）
 *   DIR64     (10) - 64 位绝对地址，加 delta（x64 用）
 *
 * HIGH/LOW 在现代 32 位 PE 中也极少见，主要用 HIGHLOW；
 * 但为完整性还是实现，避免边界情况崩溃 */
static int apply_relocations(uint8_t* img, uint64_t old_base, uint64_t new_base) {
    if (old_base == new_base) {
        DBG("reloc: no delta (base matched), skip\n");
        return 1;
    }
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)img;
    IMAGE_NT_HEADERS_X* nt = (IMAGE_NT_HEADERS_X*)(img + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir->VirtualAddress == 0 || dir->Size == 0) {
        /* Fallback: 无 reloc 表但 base 不匹配（如 AutoHotkey32.exe 无 reloc，OS 把 stack 放在 preferred base）
         * 扫描所有可执行节，找指向 [old_base, old_base+SizeOfImage) 范围的 4 字节绝对地址引用，
         * 修复为 new_base + RVA。
         * 风险：可能误改非地址数据（如常量 0x400000），但对大部分 x86 PE 能工作。
         * 仅作 fallback，正常 PE 走标准 reloc 路径 */
        DBG("reloc: no reloc table, trying fallback scan (old=0x%llx new=0x%llx)\n",
            (unsigned long long)old_base, (unsigned long long)new_base);
        return fallback_relocations(img, old_base, new_base);
    }

    int64_t delta = (int64_t)(new_base - old_base);
    int32_t delta32 = (int32_t)delta;
    uint16_t delta_high = (uint16_t)((delta >> 16) & 0xFFFF);
    uint16_t delta_low  = (uint16_t)(delta & 0xFFFF);
    DBG("reloc: applying delta=0x%llx (old=0x%llx new=0x%llx)\n",
        (long long)delta, (unsigned long long)old_base, (unsigned long long)new_base);

    IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(img + dir->VirtualAddress);
    uint8_t* reloc_end = (uint8_t*)reloc + dir->Size;
    int count_dir64 = 0, count_highlow = 0, count_high = 0, count_low = 0;

    while ((uint8_t*)reloc < reloc_end) {
        uint32_t block_size = reloc->SizeOfBlock;
        if (block_size == 0) break;
        uint32_t num_entries = (block_size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)((uint8_t*)reloc + sizeof(IMAGE_BASE_RELOCATION));

        for (uint32_t i = 0; i < num_entries; i++) {
            WORD entry = entries[i];
            int type = entry >> 12;
            int offset = entry & 0xFFF;
            uint8_t* patch = img + reloc->VirtualAddress + offset;

            switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    /* padding, skip */
                    break;
                case IMAGE_REL_BASED_DIR64:
                    *(uint64_t*)patch += (uint64_t)delta;
                    count_dir64++;
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *(uint32_t*)patch += (uint32_t)delta32;
                    count_highlow++;
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *(uint16_t*)patch += delta_high;
                    count_high++;
                    break;
                case IMAGE_REL_BASED_LOW:
                    *(uint16_t*)patch += delta_low;
                    count_low++;
                    break;
                default:
                    DBG("reloc: unsupported type %d at RVA 0x%lx, skip\n",
                        type, (unsigned long)(reloc->VirtualAddress + offset));
                    break;
            }
        }
        reloc = (IMAGE_BASE_RELOCATION*)((uint8_t*)reloc + block_size);
    }
    DBG("reloc: applied DIR64=%d HIGHLOW=%d HIGH=%d LOW=%d\n",
        count_dir64, count_highlow, count_high, count_low);
    return 1;
}

/* ---- 注册 .pdata（异常处理表）----
 * x64 的 SEH 走 .pdata + RUNTIME_FUNCTION 表
 * RtlAddFunctionTable 告诉 OS 这块内存的异常处理表
 * 不注册的话，原 PE 内的异常（如除零、栈溢出）无法被捕获
 *
 * x86 SEH 走 FS:[0] 链（每个函数 prolog 把 EXCEPTION_RECORD 注册到 TIB），
 * 这是编译器在函数 prolog/epilog 自动维护的，无法手动注册。
 * x86 反射式加载的 PE 无法让 OS 知道 .pdata 等价信息（x86 实际上没有 .pdata），
 * 所以本函数在 x86 下直接返回 1（成功），让流程继续。
 * 风险：x86 PE 内的异常（如除零）可能无法被 __try/__except 捕获。
 *      现代 MinGW/MSVC 编译的 x86 PE 在函数 prolog 自己注册 SEH，能工作。 */
static int register_exception_table(uint8_t* img) {
#ifndef _WIN64
    (void)img;
    DBG("pdata: x86 SEH uses FS:[0] chain, skip RtlAddFunctionTable\n");
    return 1;
#else
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)img;
    IMAGE_NT_HEADERS_X* nt = (IMAGE_NT_HEADERS_X*)(img + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (dir->VirtualAddress == 0 || dir->Size == 0) {
        DBG("pdata: no exception table, skip\n");
        return 1;
    }
    RUNTIME_FUNCTION* rf = (RUNTIME_FUNCTION*)(img + dir->VirtualAddress);
    DWORD count = dir->Size / sizeof(RUNTIME_FUNCTION);
    BOOLEAN ok = RtlAddFunctionTable(rf, count, (DWORD64)img);
    DBG("pdata: RtlAddFunctionTable(%p, %lu, %p) = %d\n",
        (void*)rf, count, (void*)img, (int)ok);
    return ok ? 1 : 0;
#endif
}

/* ---- 初始化 SecurityCookie ----
 * 仅当 cookie 为 MSVC 默认值或 0 时才覆盖
 * 熵源：KUSER_SHARED_DATA.InterruptTime (0x7FFE0008, 每 100ns 更新) XOR image_base
 *
 * cookie_va 处理两种情况：
 *   - apply_relocations 已修复：cookie_va 在 [img, img+SizeOfImage) 范围内
 *   - apply_relocations 未覆盖此字段：cookie_va = preferred_base + RVA
 */
static void init_security_cookie(uint8_t* img) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)img;
    IMAGE_NT_HEADERS_X* nt = (IMAGE_NT_HEADERS_X*)(img + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (dir->VirtualAddress == 0 ||
        dir->Size < offsetof(IMAGE_LOAD_CONFIG_X, SecurityCookie) + sizeof(cookie_va_t)) {
        DBG("cookie: no load config or no SecurityCookie field, skip\n");
        return;
    }
    IMAGE_LOAD_CONFIG_X* lc = (IMAGE_LOAD_CONFIG_X*)(img + dir->VirtualAddress);
    if (lc->SecurityCookie == 0) {
        DBG("cookie: SecurityCookie VA is 0, skip\n");
        return;
    }

    cookie_va_t cookie_va = lc->SecurityCookie;
    ULONG_PTR* cookie_ptr;
    /* 判断 reloc 是否已修复：cookie_va 在 image 范围内则已修复为绝对地址 */
    if ((uintptr_t)cookie_va >= (uintptr_t)img &&
        (uintptr_t)cookie_va < (uintptr_t)img + nt->OptionalHeader.SizeOfImage) {
        cookie_ptr = (ULONG_PTR*)(uintptr_t)cookie_va;
    } else {
        /* reloc 未修复，用 preferred_base 计算 RVA */
        cookie_ptr = (ULONG_PTR*)(img + ((uintptr_t)cookie_va - (uintptr_t)nt->OptionalHeader.ImageBase));
    }

    ULONG_PTR cur = *cookie_ptr;
#ifdef _WIN64
    const ULONG_PTR msvc_default = 0x00002B992DDFA232ULL;
    const ULONG_PTR mingw_default = 0x0000BB40E64EULL;
#else
    const ULONG_PTR msvc_default = 0x0000BB40ULL;
    const ULONG_PTR mingw_default = 0x0000BB40ULL;
#endif
    /* 如果 cookie 已经是非默认值（已初始化），跳过 */
    if (cur != 0 && cur != msvc_default && cur != mingw_default) {
        DBG("cookie: already initialized (0x%llx), skip\n", (unsigned long long)cur);
        return;
    }
    /* VS CRT 默认值：让原 PE 的 __security_init_cookie 自己处理
     * VS CRT 的 mainCRTStartup 会调用 __security_init_cookie，
     * 它会用 GetTickCount/QueryPerformanceCounter 生成安全的 cookie。
     * 如果我们提前覆盖，__security_init_cookie 检测到非默认值会跳过初始化，
     * 可能导致 cookie 熵不足或与 TLS 回调的 cookie 不一致 */
    if (cur == msvc_default) {
        DBG("cookie: VS CRT default value (0x%llx), let OEP __security_init_cookie handle\n",
            (unsigned long long)cur);
        return;
    }
    /* MinGW 默认值 (0xBB40E64E) 或 0：MinGW CRT 不调用 __security_init_cookie，
     * 必须由我们初始化。熵源：KUSER_SHARED_DATA.InterruptTime XOR image_base */
    volatile ULONGLONG* kuser_interrupt = (volatile ULONGLONG*)0x7FFE0008;
    *cookie_ptr = (ULONG_PTR)img ^ (ULONG_PTR)*kuser_interrupt;
    DBG("cookie: initialized to 0x%llx\n", (unsigned long long)*cookie_ptr);
}

/* ---- 设置节权限 ----
 * 遍历节表，按 Characteristics 设置 PAGE_* 保护
 * PE 头单独置 PAGE_READONLY */
static void set_section_permissions(uint8_t* img) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)img;
    IMAGE_NT_HEADERS_X* nt = (IMAGE_NT_HEADERS_X*)(img + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD prot = sec_char_to_prot(sec[i].Characteristics);
        DWORD old_prot = 0;
        SIZE_T size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (size == 0) continue;
        BOOL ok = VirtualProtect(img + sec[i].VirtualAddress, size, prot, &old_prot);
        DBG("perm: %-8.8s VA=0x%lx size=0x%zx prot=0x%lx -> %d\n",
            sec[i].Name, (unsigned long)sec[i].VirtualAddress, (size_t)size, prot, (int)ok);
    }
    /* PE 头单独置 PAGE_READONLY */
    DWORD old_prot = 0;
    VirtualProtect(img, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old_prot);
}

/* ---- 初始化原 PE 的 TLS 数据块 ----
 * 反射式加载的 PE 没有经过 OS 加载器的 TLS 初始化，
 * TEB->ThreadLocalStoragePointer (TLP) 仍指向 stub 的 TLS 数据。
 *
 * 问题：MinGW CRT 的动态 IAT 守卫逻辑读 TLP[0]+4 作为守卫值，
 *   如果 TLP[0] 是 stub 的数据，守卫比较会误判（0 <= eax 成立），
 *   跳过 GetProcAddress 路径，导致函数指针保持 NULL，call NULL 崩溃。
 *   （FastCopy/Bandizip 的 InitializeConditionVariable 等即此问题）
 *
 * 解决：分配原 PE 的 TLS 数据块，设置 TLP[0] 指向它。
 *   原 PE 编译时 __tls_index=0 被内联，所以代码硬编码读 TLP[0]。
 *   覆盖 TLP[0] 不影响 stub（跳到 OEP 后 stub 不再执行）。
 *
 * TLS 目录字段（IMAGE_TLS_DIRECTORY64）：
 *   StartAddressOfRawData - TLS 模板数据起始 VA（绝对地址）
 *   EndAddressOfRawData   - TLS 模板数据结束 VA
 *   AddressOfIndex        - 指向 DWORD，存放 TLS index（OS 加载器写入）
 *   AddressOfCallBacks    - TLS 回调函数指针数组
 *   SizeOfZeroFill        - 模板之后的零填充大小 */

/* ---- TLS callback 代理（参考 PELoader3 的 TlsCallbackProxy 方案）----
 * 问题：stub 有自己的 TLS 目录，OS 为 stub 分配 TLS index = 0
 *   目标 PE 的 __tls_index 也编译为 0，两者恰好匹配
 *   但新线程创建时，OS 只用 stub 的 TLS 模板（8 字节）初始化 TLP[0]
 *   目标 PE 访问 TLP[0]+0x1e0 等远偏移会读到越界数据（其他 slot 的数据）
 *   导致 Rust std::thread 的 "current thread handle already set" fastfail
 *
 * 解决：在 stub 中注册 TLS callback，当新线程创建时（DLL_THREAD_ATTACH）
 *   手动为目标 PE 分配正确大小的 TLS 数据块并设置 TLP[0]
 *   这样每个新线程都有正确的 TLS 数据 */
static IMAGE_TLS_DIRECTORY_X* g_target_tls = NULL;   /* 目标 PE 的 TLS 目录（重定位后） */
static volatile LONG g_entry_point_called = 0;        /* 目标 PE OEP 调用前为 0，之后为 1 */

/* 调用目标 PE 的所有 TLS callbacks（参考 PELoader3 ExecuteCallbacks）
 * AddressOfCallBacks 是 VA 数组（重定位后已是绝对地址），以 NULL 结尾
 * 与 run_tls_callbacks() 不同：后者仅在主线程 DLL_PROCESS_ATTACH 时调用一次，
 * 本函数供 TLS callback 代理在线程/进程事件时复用 */
static void run_target_tls_callbacks(DWORD reason, PVOID hModule, PVOID ctx) {
    if (!g_target_tls || g_target_tls->AddressOfCallBacks == 0) return;
    PIMAGE_TLS_CALLBACK* cbs = (PIMAGE_TLS_CALLBACK*)g_target_tls->AddressOfCallBacks;
    while (*cbs) {
        DBG("tls: proxy -> callback %p (reason=%lu)\n", (void*)*cbs, reason);
        (*cbs)(hModule, reason, ctx);
        cbs++;
    }
}

/* TLS callback 代理函数（参考 PELoader3 main.cpp 的 TlsCallbackProxy）
 * Windows 在以下事件时自动调用：
 *   DLL_PROCESS_ATTACH - 进程启动（此时 g_entry_point_called=0，跳过，由主流程处理）
 *   DLL_THREAD_ATTACH  - 新线程创建（分配 TLS 数据 + 调用目标 PE callbacks）
 *   DLL_THREAD_DETACH  - 线程退出（先调目标 PE callbacks，再释放 TLS 数据）
 *   DLL_PROCESS_DETACH - 进程退出（调用目标 PE callbacks，cleanup）
 *
 * 关键：必须在 ATTACH/DETACH 时都调用目标 PE 的 TLS callbacks，
 *   否则依赖 TLS callback 做线程级初始化的程序（如 Rust std::thread handle）会出问题 */
static void NTAPI tls_callback_proxy(PVOID hModule, DWORD reason, PVOID ctx) {
    /* 目标 PE 尚未加载完成，不处理 */
    if (!g_entry_point_called || !g_target_tls) return;

    if (reason == DLL_THREAD_ATTACH) {
        /* 新线程创建：为目标 PE 分配 TLS 数据块 */
        SIZE_T raw_size = (SIZE_T)(g_target_tls->EndAddressOfRawData -
                                   g_target_tls->StartAddressOfRawData);
        SIZE_T total = raw_size + (SIZE_T)g_target_tls->SizeOfZeroFill;
        if (total == 0) {
            /* 没有 TLS 数据要分配，但仍需调用 callbacks（PE 可能用 callback 做其他线程初始化） */
            run_target_tls_callbacks(reason, hModule, ctx);
            return;
        }

        uint8_t* block = (uint8_t*)VirtualAlloc(NULL, total, MEM_COMMIT, PAGE_READWRITE);
        if (!block) return;

        /* 复制模板数据（StartAddressOfRawData 是 VA，重定位后指向目标 PE 内存） */
        if (raw_size > 0 && g_target_tls->StartAddressOfRawData) {
            memcpy(block, (const void*)g_target_tls->StartAddressOfRawData, raw_size);
        }
        /* ZeroFill 部分已经是 0（VirtualAlloc 自动清零） */

        /* 设置 TLP[0] = 新的 TLS 数据块
         * x64: TEB->ThreadLocalStoragePointer 在 gs:[0x58]
         * x86: TEB->ThreadLocalStoragePointer 在 fs:[0x2C] */
#ifdef _WIN64
        PVOID* tlp = (PVOID*)__readgsqword(0x58);
#else
        PVOID* tlp = (PVOID*)(uintptr_t)__readfsdword(0x2C);
#endif
        if (tlp) {
            /* 释放 OS 为 stub 分配的旧 TLS 数据块（8 字节，小，不释放也无害） */
            if (tlp[0]) VirtualFree(tlp[0], 0, MEM_RELEASE);
            tlp[0] = block;
        }

        /* 数据块就绪后，调用目标 PE 的 TLS callbacks（DLL_THREAD_ATTACH）
         * 顺序很重要：必须先设置 TLP[0] 再调 callback，callback 内部可能读 TLS 数据 */
        run_target_tls_callbacks(reason, hModule, ctx);
    } else if (reason == DLL_THREAD_DETACH) {
        /* 线程退出：先调目标 PE callbacks（让 callback 在 TLS 数据释放前做 cleanup）
         * 然后再释放 TLS 数据块 */
        run_target_tls_callbacks(reason, hModule, ctx);

#ifdef _WIN64
        PVOID* tlp = (PVOID*)__readgsqword(0x58);
#else
        PVOID* tlp = (PVOID*)(uintptr_t)__readfsdword(0x2C);
#endif
        if (tlp && tlp[0]) {
            VirtualFree(tlp[0], 0, MEM_RELEASE);
            tlp[0] = NULL;
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        /* 进程退出：调用目标 PE 的 TLS callbacks（DLL_PROCESS_DETACH）
         * 不释放主线程 TLS 数据块（进程即将退出，OS 会回收） */
        run_target_tls_callbacks(reason, hModule, ctx);
    }
    /* DLL_PROCESS_ATTACH 不处理：由主流程 run_tls_callbacks() 在 OEP 前调用一次 */
}

/* 注册 TLS callback 到 stub 的 .CRT$XLB section
 * MinGW CRT 会合并 .CRT$XLA/XLB/XLZ 为一个数组
 * _tls_used.AddressOfCallBacks 指向 &__xl_a + 1（跳过首部 0）
 * 我们的 callback 在 .CRT$XLB 中，位于 __xl_a 和 __xl_z 之间 */
__attribute__((section(".CRT$XLB"), used))
static const PIMAGE_TLS_CALLBACK g_tls_cb_ptr = tls_callback_proxy;

static int init_tls_data(uint8_t* img, uint64_t preferred_base) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)img;
    IMAGE_NT_HEADERS_X* nt = (IMAGE_NT_HEADERS_X*)(img + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (dir->VirtualAddress == 0 || dir->Size == 0) {
        DBG("tls: no TLS directory, skip init\n");
        return 1;
    }

    IMAGE_TLS_DIRECTORY_X* tls = (IMAGE_TLS_DIRECTORY_X*)(img + dir->VirtualAddress);

    /* TLS 目录里的地址是 VA（绝对地址），转成 RVA 后用 img+RVA 访问
     *
     * 注意：apply_relocations 已经在前面执行，TLS 目录里的 VA 字段
     *      （StartAddressOfRawData/EndAddressOfRawData/AddressOfIndex/AddressOfCallBacks）
     *      可能已被重定位修复，值变成 img + RVA。
     *
     * 兼容两种情况：
     *   - 已重定位：StartAddressOfRawData = img + RVA，所以 raw_rva = StartAddressOfRawData - img
     *   - 未重定位：StartAddressOfRawData = preferred_base + RVA，所以 raw_rva = StartAddressOfRawData - preferred_base
     *
     * 判断方法：如果 StartAddressOfRawData 在 [img, img+SizeOfImage] 范围内，
     *          说明已被重定位，用 img 算；否则用 preferred_base 算。
     *
     * 实测 x86 FreeFileSync 的 TLS 字段会被 HIGHLOW 重定位修复（delta=0x2b0000），
     * 导致 raw_rva 计算错误（0x2f7fec 而非 0x47fec），memcpy 读到未映射内存 crash。 */
    uint64_t img_base = (uint64_t)(uintptr_t)img;
    uint64_t img_end = img_base + nt->OptionalHeader.SizeOfImage;
    uint64_t start_va, end_va, idx_va;
#ifdef _WIN64
    start_va = tls->StartAddressOfRawData;
    end_va   = tls->EndAddressOfRawData;
    idx_va   = tls->AddressOfIndex;
#else
    start_va = (uint64_t)tls->StartAddressOfRawData;
    end_va   = (uint64_t)tls->EndAddressOfRawData;
    idx_va   = (uint64_t)tls->AddressOfIndex;
#endif

    /* 判断 TLS VA 字段是否已被重定位修复 */
    int tls_relocated = (start_va >= img_base && start_va < img_end);
    uint64_t base_for_rva = tls_relocated ? img_base : preferred_base;

    uint32_t raw_rva = (uint32_t)(start_va - base_for_rva);
    SIZE_T raw_size = (SIZE_T)(end_va - start_va);
    SIZE_T total_size = raw_size + tls->SizeOfZeroFill;

    DBG("tls: start_va=0x%llx base_for_rva=0x%llx (relocated=%d) raw_rva=0x%x raw_size=%zu zero_fill=%lu total=%zu\n",
        (unsigned long long)start_va, (unsigned long long)base_for_rva, tls_relocated,
        raw_rva, raw_size, tls->SizeOfZeroFill, total_size);

    /* 分配 TLS 数据块（VirtualAlloc 自动清零，满足 SizeOfZeroFill） */
    uint8_t* tls_block = VirtualAlloc(NULL, total_size ? total_size : 1,
                                       MEM_COMMIT, PAGE_READWRITE);
    if (!tls_block) {
        DBG("tls: VirtualAlloc failed err=%lu\n", GetLastError());
        return 0;
    }

    /* 复制模板数据（RawData 是初始化好的静态 TLS 变量值） */
    if (raw_size > 0) {
        memcpy(tls_block, img + raw_rva, raw_size);
    }

    DBG("tls: block at %p, size %zu\n", tls_block, total_size);

    /* 设置 TLP[0] = TLS 数据块
     * x64: TEB->ThreadLocalStoragePointer 在 gs:[0x58]
     * x86: TEB->ThreadLocalStoragePointer 在 fs:[0x2C]
     * 原 PE 代码内联 __tls_index=0，读 TLP[0]，所以直接设置 TLP[0] */
#ifdef _WIN64
    PVOID* tlp = (PVOID*)__readgsqword(0x58);
#else
    PVOID* tlp = (PVOID*)(uintptr_t)__readfsdword(0x2C);
#endif
    if (tlp) {
        DBG("tls: TLP=%p, old TLP[0]=%p -> new %p\n", tlp, tlp[0], tls_block);
        tlp[0] = tls_block;
    } else {
        DBG("tls: TLP is NULL, cannot set\n");
    }

    /* 确保 AddressOfIndex = 0（和代码内联的 __tls_index 一致）
     * 某些 CRT 代码会读此值确认 TLS 已初始化
     * AddressOfIndex 同样可能被重定位，用 base_for_rva 算 RVA */
    if (idx_va) {
        uint32_t idx_rva = (uint32_t)(idx_va - base_for_rva);
        uint32_t* index_ptr = (uint32_t*)(img + idx_rva);
        DBG("tls: AddressOfIndex at %p (rva=0x%x), old=%u -> 0\n",
            index_ptr, idx_rva, *index_ptr);
        *index_ptr = 0;
    }

    /* 保存 TLS 目录指针供 TLS callback 代理使用
     * tls 指向目标 PE 内存中的 TLS 目录（重定位后）
     * callback 中直接用 tls->StartAddressOfRawData（VA）访问模板数据 */
    g_target_tls = tls;
    DBG("tls: saved g_target_tls=%p for TLS callback proxy\n", (void*)g_target_tls);

    return 1;
}

/* ---- 调用 TLS callbacks（仅 DLL_PROCESS_ATTACH）----
 * MVP 不分配 TLS 数据块（与 5 个参考项目一致）
 * 原 PE 若用 __declspec(thread) 静态 TLS，后续线程可能 crash
 * （MVP 接受此限制，后期阶段评估 AlushPacker TLS proxy 方案） */
static void run_tls_callbacks(uint8_t* img) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)img;
    IMAGE_NT_HEADERS_X* nt = (IMAGE_NT_HEADERS_X*)(img + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (dir->VirtualAddress == 0 || dir->Size == 0) {
        DBG("tls: no TLS directory, skip\n");
        return;
    }
    IMAGE_TLS_DIRECTORY_X* tls = (IMAGE_TLS_DIRECTORY_X*)(img + dir->VirtualAddress);
    if (tls->AddressOfCallBacks == 0) {
        DBG("tls: no callbacks, skip\n");
        return;
    }
    PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
    int count = 0;
    while (*callbacks) {
        DBG("tls: calling callback %p (DLL_PROCESS_ATTACH)\n", (void*)*callbacks);
        (*callbacks)((PVOID)img, DLL_PROCESS_ATTACH, NULL);
        callbacks++;
        count++;
    }
    DBG("tls: called %d callbacks\n", count);
}

/* ---- 更新 PEB.ImageBaseAddress ----
 * 让 GetModuleHandle(NULL) / GetModuleHandleW(NULL) 返回新 image
 * 注意：不更新 LDR_DATA_TABLE_ENTRY（反射式 image 不在 loader 表里）
 * 这意味着 EnumProcessModules / Module32First 看不到新 image
 * 但 GetModuleHandle(NULL) 等基础 API 能正常工作 */
static void update_peb_image_base(void* new_base) {
    PEBX* peb = WINLOCK_PEB();
    DBG("peb: ImageBaseAddress %p -> %p\n", peb->ImageBaseAddress, new_base);
    peb->ImageBaseAddress = new_base;
}

/* ---- 修改 PEB.Ldr 中主 EXE 的 LDR_DATA_TABLE_ENTRY ----
 *
 * 关键修复：让 OS 把反射加载的 new_img 当成"主 EXE 模块"
 *
 * 背景：FindResource 直接读 hModule 的 PE header，能工作；
 *      但 LoadString / LoadResource / LdrFindResource_U 需要在
 *      PEB.Ldr 里有对应模块条目，否则返回 ERROR_DIRECT_ACCESS_HANDLE (59)。
 *      MFC42u!AfxWinInit 内部调用 LoadString 加载 IDS_VALID_RES 等，
 *      失败时抛 C++ 异常 0xE06D7363，导致 DontSleep 崩溃。
 *
 * 方案（借鉴 AlushPacker LdrpPatchDataTableEntry）：
 *   遍历 PEB.Ldr.InMemoryOrderModuleList，第一个条目就是主 EXE
 *   （即 stub 自己）。覆写其 DllBase/EntryPoint/SizeOfImage/TimeDateStamp
 *   为 new_img 的值。stub 在 jump_to_oep 之后就不再需要被 OS 识别，
 *   所以覆写是安全的。
 *
 * 注意：BaseDllName / FullDllName 保持 stub 的名字不变
 *      （MFC 主要用 hInstance 找资源，不在意文件名） */
static void patch_peb_ldr_main_entry(void* new_img) {
    PEBX* peb = WINLOCK_PEB();
    PEB_LDR_DATA_X* ldr = (PEB_LDR_DATA_X*)peb->Ldr;
    if (!ldr) {
        DBG("peb: Ldr is NULL, skip patch\n");
        return;
    }

    /* InMemoryOrderModuleList 第一个 Flink 指向主 EXE 的 LDR_DATA_TABLE_ENTRY
     * 注意：Flink 指向的是 InMemoryOrderLinks 字段，需要 CONTAINING_RECORD 回退到结构头 */
    MY_LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    MY_LIST_ENTRY* first = head->Flink;
    if (first == head) {
        DBG("peb: InMemoryOrderModuleList is empty\n");
        return;
    }

    /* first 指向 LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks 字段
     * x64 偏移 0x10，x86 偏移 0x08。用 offsetof 自动适配架构。 */
    LDR_DATA_TABLE_ENTRY_X* entry = (LDR_DATA_TABLE_ENTRY_X*)
        ((uint8_t*)first - offsetof(LDR_DATA_TABLE_ENTRY_X, InMemoryOrderLinks));

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)new_img;
    IMAGE_NT_HEADERS_X* nt = (IMAGE_NT_HEADERS_X*)((uint8_t*)new_img + dos->e_lfanew);

    DBG("peb: patch LDR entry %p: DllBase %p -> %p, SizeOfImage 0x%lx -> 0x%lx\n",
        (void*)entry, (void*)entry->DllBase, new_img,
        entry->SizeOfImage, nt->OptionalHeader.SizeOfImage);
    DBG("peb:   EntryPoint %p -> %p\n",
        (void*)entry->EntryPoint,
        (void*)((uint8_t*)new_img + nt->OptionalHeader.AddressOfEntryPoint));

    entry->DllBase     = new_img;
    entry->EntryPoint  = (uint8_t*)new_img + nt->OptionalHeader.AddressOfEntryPoint;
    entry->SizeOfImage = nt->OptionalHeader.SizeOfImage;
    /* TimeDateStamp / HashLinks 等字段在 +0x80 之后，对 LdrFindResource_U
     * 不是必须的，跳过（AlushPacker 也只更新上述 4 个字段就够用） */
}

/* ---- 从内存 PE 提取 RT_MANIFEST 资源并创建 activation context ----
 *
 * 阶段 2 关键功能：解决 comctl32 v6 等 SxS manifest 依赖问题
 *
 * 背景：反射式加载的原 PE 可能依赖 comctl32 v6（通过 manifest 声明）。
 * 但 stub EXE 自身没有 manifest，进程启动时 OS 不会创建 activation context，
 * LoadLibraryA("comctl32.dll") 只能加载 v5（经典主题）。
 * 某些程序（如 DontSleep 用 MFC42u）在 comctl32 v5 下会 C++ 异常崩溃。
 *
 * 方案：stub 在跳 OEP 前，从原 PE 的 .rsrc 节提取 RT_MANIFEST 资源，
 *      写临时文件，CreateActCtx + ActivateActCtx 激活。
 *      后续 LoadLibrary 调用会自动走 manifest 声明的版本。
 *
 * 返回：0 成功（context 已激活），1 无 manifest，-1 失败 */
static int activate_manifest_from_image(uint8_t* img) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)img;
    IMAGE_NT_HEADERS_X* nt = (IMAGE_NT_HEADERS_X*)(img + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if (dir->VirtualAddress == 0 || dir->Size == 0) {
        DBG("actctx: no .rsrc directory, skip\n");
        return 1;
    }

    /* 遍历资源目录找 RT_MANIFEST (type=24) */
    uint8_t* rsrc_base = img + dir->VirtualAddress;
    IMAGE_RESOURCE_DIRECTORY* type_dir = (IMAGE_RESOURCE_DIRECTORY*)rsrc_base;

    /* 第一层：按 type 查找 RT_MANIFEST (24) */
    DWORD type_count = type_dir->NumberOfNamedEntries + type_dir->NumberOfIdEntries;
    IMAGE_RESOURCE_DIRECTORY_ENTRY* type_entries =
        (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(type_dir + 1);

    IMAGE_RESOURCE_DIRECTORY_ENTRY* manifest_type = NULL;
    for (DWORD i = 0; i < type_count; i++) {
        if (!type_entries[i].NameIsString && type_entries[i].Id == 24) {
            manifest_type = &type_entries[i];
            break;
        }
    }
    if (!manifest_type) {
        DBG("actctx: no RT_MANIFEST (type=24) resource, skip\n");
        return 1;
    }

    /* 第二层：按 name/id 查找（manifest 通常 id=1） */
    IMAGE_RESOURCE_DIRECTORY* name_dir =
        (IMAGE_RESOURCE_DIRECTORY*)(rsrc_base + manifest_type->OffsetToDirectory);
    DWORD name_count = name_dir->NumberOfNamedEntries + name_dir->NumberOfIdEntries;
    IMAGE_RESOURCE_DIRECTORY_ENTRY* name_entries =
        (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(name_dir + 1);
    if (name_count == 0) {
        DBG("actctx: RT_MANIFEST has no entries, skip\n");
        return 1;
    }

    /* 取第一个（manifest 通常只有一个，id=1） */
    IMAGE_RESOURCE_DIRECTORY_ENTRY* name_entry = &name_entries[0];

    /* 第三层：按 language 查找 */
    IMAGE_RESOURCE_DIRECTORY* lang_dir =
        (IMAGE_RESOURCE_DIRECTORY*)(rsrc_base + name_entry->OffsetToDirectory);
    DWORD lang_count = lang_dir->NumberOfNamedEntries + lang_dir->NumberOfIdEntries;
    IMAGE_RESOURCE_DIRECTORY_ENTRY* lang_entries =
        (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(lang_dir + 1);
    if (lang_count == 0) {
        DBG("actctx: RT_MANIFEST has no language entries, skip\n");
        return 1;
    }

    /* 取第一个 language */
    IMAGE_RESOURCE_DIRECTORY_ENTRY* lang_entry = &lang_entries[0];
    IMAGE_RESOURCE_DATA_ENTRY* data_entry =
        (IMAGE_RESOURCE_DATA_ENTRY*)(rsrc_base + lang_entry->OffsetToData);

    /* 数据在原 PE 的 RVA 空间里（data_entry->OffsetToData 是 RVA） */
    uint8_t* manifest_data = img + data_entry->OffsetToData;
    DWORD manifest_size = data_entry->Size;
    DBG("actctx: found RT_MANIFEST size=%lu at RVA=0x%lx\n",
        manifest_size, (unsigned long)data_entry->OffsetToData);

    if (manifest_size == 0 || manifest_size > 1024 * 1024) {
        DBG("actctx: invalid manifest size %lu, skip\n", manifest_size);
        return -1;
    }

    /* 写临时文件（CreateActCtx 的 lpSource 需要文件路径） */
    char tmp_path[MAX_PATH];
    DWORD n = GetTempPathA(MAX_PATH, tmp_path);
    if (n == 0 || n >= MAX_PATH) {
        DBG("actctx: GetTempPathA failed, skip\n");
        return -1;
    }
    strcat(tmp_path, "winlock_reflective_manifest.xml");

    HANDLE hf = CreateFileA(tmp_path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        DBG("actctx: CreateFile(%s) failed err=%lu\n", tmp_path, GetLastError());
        return -1;
    }
    DWORD written = 0;
    if (!WriteFile(hf, manifest_data, manifest_size, &written, NULL) || written != manifest_size) {
        DBG("actctx: WriteFile failed err=%lu\n", GetLastError());
        CloseHandle(hf);
        return -1;
    }
    CloseHandle(hf);
    DBG("actctx: wrote manifest to %s (%lu bytes)\n", tmp_path, manifest_size);

    /* 创建 activation context
     * lpSource 指向 manifest XML 文件（不是 PE 文件），
     * 所以不需要 ACTCTX_FLAG_RESOURCE_NAME_VALID
     * 不用 ACTCTX_FLAG_SET_PROCESS_DEFAULT（mingw CRT 可能已设置 default，
     * 重复设置会失败；改用 ActivateActCtx 推入当前线程栈） */
    ACTCTXA act = { 0 };
    act.cbSize = sizeof(act);
    act.dwFlags = 0;
    act.lpSource = tmp_path;
    act.lpResourceName = NULL;

    HANDLE hActCtx = CreateActCtxA(&act);
    /* CreateActCtx 失败可能返回 NULL 或 INVALID_HANDLE_VALUE，都要判断
     * 实测某些 manifest（如依赖 SxS 程序集）会返回 NULL 而非 -1 */
    if (hActCtx == NULL || hActCtx == INVALID_HANDLE_VALUE) {
        DBG("actctx: CreateActCtxA failed err=%lu (hActCtx=%p)\n",
            GetLastError(), hActCtx);
        DeleteFileA(tmp_path);
        return -1;
    }
    DBG("actctx: created context %p\n", hActCtx);

    /* 激活 */
    ULONG_PTR cookie = 0;
    if (!ActivateActCtx(hActCtx, &cookie)) {
        DBG("actctx: ActivateActCtx failed err=%lu\n", GetLastError());
        DeleteFileA(tmp_path);
        return -1;
    }
    DBG("actctx: activated (cookie=0x%lx)\n", (unsigned long)cookie);

    /* 注意：临时文件不能删除，activation context 可能需要它
     * 但实际上 CreateActCtx 成功后已经把 manifest 读入内存了，文件可以删
     * 不过保险起见先不删，进程退出时 %TEMP% 会被清理 */
    return 0;
}

/* ---- 反射式映射主流程 ---- */
static uint8_t* map_image(reflective_payload_t* hdr, uint8_t* payload_data) {
    (void)hdr;  /* MVP v1 不用 header 字段（v2 加密版会用到）*/
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)payload_data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        DBG("map: bad DOS magic 0x%04x\n", dos->e_magic);
        return NULL;
    }
    IMAGE_NT_HEADERS_X* nt = (IMAGE_NT_HEADERS_X*)(payload_data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        DBG("map: bad NT signature 0x%08lx\n", (unsigned long)nt->Signature);
        return NULL;
    }
    if (nt->FileHeader.Machine != MY_MACHINE) {
        DBG("map: machine mismatch (PE=0x%04x, stub=0x%04x), refuse to load\n",
            nt->FileHeader.Machine, (unsigned)MY_MACHINE);
        return NULL;
    }

    SIZE_T size_of_image = nt->OptionalHeader.SizeOfImage;
    uint64_t preferred_base = nt->OptionalHeader.ImageBase;
    DBG("map: SizeOfImage=0x%zx preferred_base=0x%llx OEP=0x%lx\n",
        (size_t)size_of_image, (unsigned long long)preferred_base,
        (unsigned long)nt->OptionalHeader.AddressOfEntryPoint);

    /* 1. 优先尝试 preferred_base，失败用任意地址
     *    如果加载在非 preferred 地址，需要应用 relocations */
    uint8_t* new_img = (uint8_t*)VirtualAlloc((void*)preferred_base, size_of_image,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!new_img) {
        DWORD err = GetLastError();
        DBG("map: VirtualAlloc(preferred=%p, size=0x%zx) failed (err=%lu), trying arbitrary\n",
            (void*)preferred_base, (size_t)size_of_image, err);
        /* 失败时打印 preferred_base 周围内存状态，便于诊断为何 err=487 */
        if (err == 487 /* ERROR_INVALID_ADDRESS */) {
            MEMORY_BASIC_INFORMATION mbi;
            uint8_t* q = (uint8_t*)preferred_base;
            for (int i = 0; i < 16 && q < (uint8_t*)preferred_base + size_of_image; i++) {
                if (VirtualQueryEx(GetCurrentProcess(), q, &mbi, sizeof(mbi)) == 0) break;
                const char* state = (mbi.State == 0x1000) ? "COMMIT" :
                                    (mbi.State == 0x2000) ? "RESERVE" :
                                    (mbi.State == 0x10000) ? "FREE" : "?";
                const char* type = (mbi.Type == 0x20000) ? "PRIVATE" :
                                   (mbi.Type == 0x40000) ? "MAPPED" :
                                   (mbi.Type == 0x1000000) ? "IMAGE" : "?";
                DBG("map:   0x%p-0x%p state=%s type=%s prot=0x%lx size=0x%zx allocBase=0x%p\n",
                    (void*)mbi.BaseAddress, (void*)((uint8_t*)mbi.BaseAddress + mbi.RegionSize),
                    state, type, (unsigned long)mbi.Protect, (size_t)mbi.RegionSize,
                    (void*)mbi.AllocationBase);
                q = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
            }
        }
        new_img = (uint8_t*)VirtualAlloc(NULL, size_of_image,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!new_img) {
        DBG("map: VirtualAlloc failed entirely, err=%lu\n", GetLastError());
        return NULL;
    }
    DBG("map: allocated at %p (delta=0x%llx)\n",
        (void*)new_img, (unsigned long long)((int64_t)new_img - (int64_t)preferred_base));

    /* 2. 复制 PE headers */
    SIZE_T hdr_size = nt->OptionalHeader.SizeOfHeaders;
    memcpy(new_img, payload_data, hdr_size);

    /* 3. 复制各节（按 PointerToRawData -> VirtualAddress 映射） */
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        uint8_t* dst = new_img + sec[i].VirtualAddress;
        uint8_t* src = payload_data + sec[i].PointerToRawData;
        SIZE_T size = sec[i].SizeOfRawData;
        memcpy(dst, src, size);
        DBG("map: copied section %-8.8s raw=0x%zx -> VA=0x%lx\n",
            sec[i].Name, (size_t)size, (unsigned long)sec[i].VirtualAddress);
    }

    /* 4. 应用 relocations（如果基址不匹配） */
    if (!apply_relocations(new_img, preferred_base, (uint64_t)new_img)) {
        DBG("map: apply_relocations failed\n");
        return NULL;
    }

    /* 4.5 提前更新 PEB.ImageBaseAddress + PEB.Ldr 主 EXE 条目（在 IAT 处理之前）
     *
     * 原因 1：IAT 处理调用 LoadLibraryA 加载依赖 DLL（如 MFC42u.dll），
     *        DLL 的 DllMain 可能调用 GetModuleHandle(NULL) 获取宿主 EXE 的 hInstance。
     *        如果此时 PEB.ImageBaseAddress 还是 stub 的基址，DLL 会获取到错误的 hInstance。
     *
     * 原因 2：原 PE 的 OEP（如 MFC42u!AfxWinInit）会调用 LoadString / LoadResource，
     *        这些走 LdrFindResource_U，需要 PEB.Ldr 里有对应模块条目，
     *        否则返回 ERROR_DIRECT_ACCESS_HANDLE (59)，MFC 抛 C++ 异常。
     *        修复：把 PEB.Ldr 第一个条目（主 EXE = stub）的 DllBase 改成 new_img。
     *
     * 风险：stub 自己的 CRT 全局变量已初始化（用的是 stub 基址），不受影响。
     *      stub 代码不依赖 GetModuleHandle(NULL)。stub 在 jump_to_oep 之后就不再
     *      需要 OS 识别，覆写主 EXE 条目是安全的。 */
    update_peb_image_base(new_img);
    patch_peb_ldr_main_entry(new_img);

    /* 4.55 设置 DLL 搜索路径 + 当前目录为 stub EXE 所在目录
     *
     * 背景：Chrome/Doubao 等程序依赖同目录下的 DLL（chrome_elf.dll/doubao_elf.dll）。
     * 但 stub EXE 可能在不同目录（如 temp/reflective_tests/），LoadLibraryA 默认
     * 用 stub 当前目录搜索，找不到原 PE 目录下的 DLL，报 ERROR_MOD_NOT_FOUND (126)。
     *
     * 方案：把当前目录和 DLL 搜索路径都设为 stub EXE 所在目录。
     * 前提：用户把加壳后 EXE 放在原程序目录（常见做法，否则外部 DLL 也找不到）。
     *
     * SetCurrentDirectoryW：影响 LoadLibrary 的"当前目录"搜索路径
     * SetDllDirectoryW：额外添加一个搜索路径（不影响后续 SetCurrentDirectory） */
    {
        wchar_t stub_path_w[MAX_PATH];
        DWORD n = GetModuleFileNameW(NULL, stub_path_w, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            /* 提取目录部分（去掉文件名） */
            for (DWORD i = n; i > 0; i--) {
                if (stub_path_w[i-1] == L'\\' || stub_path_w[i-1] == L'/') {
                    stub_path_w[i-1] = 0;
                    break;
                }
            }
            SetCurrentDirectoryW(stub_path_w);
            SetDllDirectoryW(stub_path_w);
            DBG("map: set current dir + dll dir to stub EXE directory: %ls\n", stub_path_w);
        }
    }

    /* 4.6 激活原 PE 的 manifest（解决 comctl32 v6 等 SxS 依赖）
     * 必须在 IAT 处理之前激活，LoadLibraryA("comctl32.dll") 才能走 SxS 找到 v6
     * 否则只能加载默认的 v5，TaskDialogIndirect 等 v6 函数解析失败为 NULL。
     * actctx 是线程局栈式激活，必须在主线程调用；激活后到 DeactivateActCtx 之前有效 */
    activate_manifest_from_image(new_img);

    /* 5. 处理 IAT */
    if (!process_iat(new_img)) {
        DBG("map: process_iat failed\n");
        return NULL;
    }

    /* 5.5 处理延迟导入表（DataDirectory[13]）
     *      CCleaner 等 app 有 12 个延迟导入 DLL，不处理会导致
     *      跳到 OEP 后调用延迟函数时 access violation。
     *      失败不致命：某些延迟函数可能在不同 Windows 版本不存在，
     *      但只要原 PE 不实际调用就不会崩 */
    if (!process_delay_imports(new_img)) {
        DBG("map: process_delay_imports failed (non-fatal, continue)\n");
    }

    /* 6. 注册 .pdata（失败不致命，SEH 可能不工作但能跑） */
    if (!register_exception_table(new_img)) {
        DBG("map: register_exception_table failed (non-fatal, continue)\n");
    }

    /* 7. 初始化 SecurityCookie */
    init_security_cookie(new_img);

    /* 8. 设置节权限 */
    set_section_permissions(new_img);

    /* 8.5 初始化原 PE 的 TLS 数据块
     * 必须在 TLS callbacks 和 jump_to_oep 之前完成，
     * 否则原 PE 的 MinGW CRT 守卫逻辑读 TLP[0] 会得到 stub 的数据，
     * 导致动态 IAT 解析被跳过（FastCopy/Bandizip 的 call NULL 问题） */
    init_tls_data(new_img, preferred_base);

    /* 9. 调用 TLS callbacks（actctx 已在 4.6 激活，TLS 数据已初始化） */
    run_tls_callbacks(new_img);

    return new_img;
}

/* ---- Vectored Exception Handler（调试用，捕获 OEP 后的崩溃） ----
 * 安装后，原 PE 代码崩溃时 VEH 会先触发，记录异常地址和代码。
 * 这样可以定位反射式加载后 OEP 代码在哪里崩溃。
 * 注意：VEH 里不能用 DBG 宏（可能触发递归异常），直接写文件 */
static LONG WINAPI refl_veh(PEXCEPTION_POINTERS ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    /* 过滤掉非严重异常 */
    if (code == 0x40010006) return EXCEPTION_CONTINUE_SEARCH;  /* OutputDebugString */
    if (code == 0x406D1388) return EXCEPTION_CONTINUE_SEARCH;  /* SetThreadName */

    /* C++ 异常只记录前 3 次（避免日志爆炸） */
    static int cpp_exc_count = 0;
    if (code == 0xE06D7363) {
        if (cpp_exc_count < 3) {
            cpp_exc_count++;
        } else {
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    /* 只记录真正的崩溃异常 + C++ 异常前几次 */
    if (code != 0xE06D7363 &&
        code != EXCEPTION_ACCESS_VIOLATION &&
        code != EXCEPTION_STACK_OVERFLOW &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_PRIV_INSTRUCTION &&
        code != EXCEPTION_IN_PAGE_ERROR &&
        code != EXCEPTION_ARRAY_BOUNDS_EXCEEDED &&
        code != EXCEPTION_DATATYPE_MISALIGNMENT &&
        code != EXCEPTION_FLT_DIVIDE_BY_ZERO &&
        code != EXCEPTION_INT_DIVIDE_BY_ZERO &&
        code != EXCEPTION_BREAKPOINT &&
        code != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    /* 直接写文件，不用 DBG 宏 */
    if (g_logf) {
        fprintf(g_logf, "[VEH] exception code=0x%08lx addr=%p\n",
                code, ep->ExceptionRecord->ExceptionAddress);
        if (code == EXCEPTION_ACCESS_VIOLATION) {
            const char* op = ep->ExceptionRecord->ExceptionInformation[0] == 0 ? "read" :
                             ep->ExceptionRecord->ExceptionInformation[0] == 1 ? "write" : "exec";
            fprintf(g_logf, "[VEH] ACCESS_VIOLATION %s address %p\n",
                    op, (void*)ep->ExceptionRecord->ExceptionInformation[1]);
        }
#ifdef _WIN64
        fprintf(g_logf, "[VEH] RIP=%p RSP=%p RAX=%p RCX=%p RDX=%p R8=%p R9=%p\n",
                (void*)ep->ContextRecord->Rip, (void*)ep->ContextRecord->Rsp,
                (void*)ep->ContextRecord->Rax, (void*)ep->ContextRecord->Rcx,
                (void*)ep->ContextRecord->Rdx, (void*)ep->ContextRecord->R8,
                (void*)ep->ContextRecord->R9);
#else
        fprintf(g_logf, "[VEH] EIP=%p ESP=%p EAX=%p ECX=%p EDX=%p EBX=%p ESI=%p EDI=%p EBP=%p\n",
                (void*)ep->ContextRecord->Eip, (void*)ep->ContextRecord->Esp,
                (void*)ep->ContextRecord->Eax, (void*)ep->ContextRecord->Ecx,
                (void*)ep->ContextRecord->Edx, (void*)ep->ContextRecord->Ebx,
                (void*)ep->ContextRecord->Esi, (void*)ep->ContextRecord->Edi,
                (void*)ep->ContextRecord->Ebp);
#endif
        fflush(g_logf);
#ifdef _WIN64
        /* 用 RtlVirtualUnwind 做正确的栈回溯（x64 专用）
         * 根据已注册的 .pdata 表逐帧 unwind，得到真正的调用链
         * 这样能精确定位抛异常的代码位置在 image 内的哪个函数
         * x86 没有 RtlVirtualUnwind，跳过栈回溯 */
        CONTEXT ctx = *ep->ContextRecord;
        fprintf(g_logf, "[VEH] call stack (RtlVirtualUnwind):\n");
        fflush(g_logf);
        /* 特殊处理 RIP=0：通常是 call NULL，caller 在 [RSP] */
        if (ctx.Rip == 0 && ctx.Rsp != 0) {
            uint64_t ret_addr = *(uint64_t*)ctx.Rsp;
            fprintf(g_logf, "  [0] ? rip=0x0 (NULL call, ret_addr=0x%llx at RSP=0x%llx)\n",
                    (unsigned long long)ret_addr, (unsigned long long)ctx.Rsp);
            fflush(g_logf);
            ctx.Rip = ret_addr;
            ctx.Rsp = ctx.Rsp + 8;
        }
        for (int depth = 0; depth < 32; depth++) {
            uint64_t rip = ctx.Rip;
            uint64_t rsp = ctx.Rsp;
            if (rip == 0) break;
            /* 标记地址所在模块 */
            const char* mod = "?";
            if (rip >= 0x400000 && rip < 0x500000) {
                mod = "IMG";  /* DontSleep image */
            } else if (rip >= 0x500000 && rip < 0x10000000) {
                mod = "?";
            }
            fprintf(g_logf, "  [%d] %s rip=0x%llx rsp=0x%llx",
                    depth, mod, (unsigned long long)rip, (unsigned long long)rsp);
            if (rip >= 0x400000 && rip < 0x500000) {
                fprintf(g_logf, " (RVA=0x%llx)", (unsigned long long)(rip - 0x400000));
            }
            fprintf(g_logf, "\n");
            fflush(g_logf);

            /* 用 RtlVirtualUnwind 计算下一帧 */
            DWORD64 img_base;
            PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(rip, &img_base, NULL);
            if (!rf) {
                /* 没有 .pdata 信息，假设是 leaf function（rsp+8 是返回地址） */
                fprintf(g_logf, "      (no RUNTIME_FUNCTION, leaf unwind)\n");
                fflush(g_logf);
                ctx.Rip = *(uint64_t*)rsp;
                ctx.Rsp = rsp + 8;
            } else {
                fprintf(g_logf, "      (rf: Begin=0x%x End=0x%x Unwind=0x%x img_base=0x%llx)\n",
                        (unsigned)rf->BeginAddress, (unsigned)rf->EndAddress,
                        (unsigned)rf->UnwindData, (unsigned long long)img_base);
                fflush(g_logf);
                PVOID handler_data;
                DWORD64 establisher_frame;
                RtlVirtualUnwind(0, img_base, rip, rf, &ctx, &handler_data,
                                 &establisher_frame, NULL);
            }
            /* 防止无限循环 */
            if (ctx.Rip == rip) break;
            if (ctx.Rsp <= rsp) break;
        }
        fflush(g_logf);
#else
        /* x86 简单栈扫描：从 esp 开始扫描 32 个 DWORD，找看起来像返回地址的值
         * 不精确但能给个线索（真正的栈回溯需要 FS:[0] SEH 链） */
        uint32_t* sp = (uint32_t*)ep->ContextRecord->Esp;
        fprintf(g_logf, "[VEH] stack dump (x86, raw scan):\n");
        for (int i = 0; i < 32; i++) {
            uint32_t v = sp[i];
            if (v >= 0x400000 && v < 0x500000) {
                fprintf(g_logf, "  [esp+0x%02x] 0x%08x (IMG RVA=0x%x)\n",
                        i*4, v, v - 0x400000);
            }
        }
        fflush(g_logf);
#endif
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ---- stub 入口 ----
 * MinGW-w64 + CRT 编译，mainCRTStartup 调用 main()
 * main() 完成反射式加载后 jump_to_oep 跳走，不返回
 * CRT 的 cleanup 不会执行（无害，因为 stub 自己的全局状态不再使用） */
int main(int argc, char* argv[]) {
    (void)argc; (void)argv;  /* stub 不处理命令行参数 */
#ifdef RDEBUG
    /* 只初始化日志文件，不再创建 console（避免 GUI 程序弹 console 干扰）
     * 如需实时观察，用 DebugView 查看 OutputDebugStringA 输出 */
    log_init();
#endif

    /* 安装 VEH 捕获 OEP 后的崩溃（调试用） */
    AddVectoredExceptionHandler(1 /*第一个调用*/, refl_veh);

    DBG("=== WinLock Reflective Loader MVP v1 ===\n");
    DBG("stub image base = %p\n", (void*)GetModuleHandleW(NULL));

    /* 1. 定位 .payload 节 */
    uint32_t payload_sec_size = 0;
    uint8_t* payload_sec = find_payload_section(&payload_sec_size);
    if (!payload_sec) {
        DBG("FATAL: .payload section not found in stub\n");
        return 1;
    }
    DBG("found .payload section at %p, size=0x%x\n",
        (void*)payload_sec, payload_sec_size);

    /* 2. 解析 payload 头 */
    if (payload_sec_size < sizeof(reflective_payload_t)) {
        DBG("FATAL: payload section too small (%u < %zu)\n",
            payload_sec_size, sizeof(reflective_payload_t));
        return 1;
    }
    reflective_payload_t* hdr = (reflective_payload_t*)payload_sec;
    if (hdr->magic != REFLECTIVE_PAYLOAD_MAGIC) {
        DBG("FATAL: bad payload magic 0x%llx (expected 0x%llx)\n",
            (unsigned long long)hdr->magic,
            (unsigned long long)REFLECTIVE_PAYLOAD_MAGIC);
        return 1;
    }
    if (hdr->version != REFLECTIVE_PAYLOAD_VERSION) {
        DBG("FATAL: unsupported payload version %u (expected %u)\n",
            hdr->version, REFLECTIVE_PAYLOAD_VERSION);
        return 1;
    }
    DBG("payload header: version=%u flags=0x%04x original_size=%llu stored_size=%llu\n",
        hdr->version, hdr->flags,
        (unsigned long long)hdr->original_size,
        (unsigned long long)hdr->stored_size);
    DBG("  oep_rva=0x%llx image_base=0x%llx\n",
        (unsigned long long)hdr->oep_rva,
        (unsigned long long)hdr->image_base);

    /* v1 MVP: 不加密，payload_data 紧跟在 header 后面 */
    if (hdr->flags & RFLAG_ENCRYPTED) {
        DBG("FATAL: encrypted payload not supported in MVP v1\n");
        return 1;
    }
    if (hdr->stored_size != hdr->original_size) {
        DBG("WARN: v1 expected stored_size == original_size, got %llu vs %llu\n",
            (unsigned long long)hdr->stored_size,
            (unsigned long long)hdr->original_size);
    }

    /* 校验 payload 数据完整在 .payload 节内 */
    size_t needed = sizeof(reflective_payload_t) + (size_t)hdr->stored_size;
    if (needed > payload_sec_size) {
        DBG("FATAL: payload data truncated (need %zu, have %u)\n",
            needed, payload_sec_size);
        return 1;
    }

    uint8_t* payload_data = payload_sec + sizeof(reflective_payload_t);

    /* 3. 反射式映射 */
    uint8_t* new_img = map_image(hdr, payload_data);
    if (!new_img) {
        DBG("FATAL: map_image failed\n");
        return 2;
    }
    DBG("=== image mapped at %p, jumping to OEP ===\n", (void*)new_img);

    /* 标记目标 PE 已初始化完成，TLS callback 代理开始工作
     * 此后新线程创建时（DLL_THREAD_ATTACH），callback 会为目标 PE 分配 TLS 数据 */
    InterlockedExchange(&g_entry_point_called, 1);
    DBG("tls: callback proxy enabled (g_entry_point_called=1)\n");

    /* 4. 跳 OEP */
    void* oep = new_img + hdr->oep_rva;
    DBG("jump_to_oep(%p) ret=%p\n", oep, (void*)oep_returned);
    jump_to_oep(oep, (void*)oep_returned);
    /* never returns */
    return 0;
}
