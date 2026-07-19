/*
 * winlock/reflective/loader.c - 反射式 stub 主体（MVP v1 明文模式）
 *
 * 设计原则（按 REFLECTIVE_DESIGN.md 阶段 1 MVP）：
 *   - 开发优先：用 Win32 API + CRT，允许 printf 调试
 *   - 不加密、不压缩、不反调试、不反 dump
 *   - 只支持 x64
 *   - reloc 只处理 DIR64（x64 PE 99% 够用）
 *   - TLS 只调 ATTACH，不分配 TLS 数据块
 *   - IAT 用 LoadLibraryA + GetProcAddress（OS 自动处理 forwarder）
 *
 * 流程：
 *   1. 定位 .payload 节，解析 reflective_payload_t
 *   2. VirtualAlloc 分配 SizeOfImage 内存（优先 preferred ImageBase）
 *   3. 复制 PE headers + 各节
 *   4. 处理 IAT（LoadLibraryA + GetProcAddress）
 *   5. 应用 relocations（仅 DIR64）
 *   6. RtlAddFunctionTable 注册 .pdata
 *   7. 初始化 SecurityCookie
 *   8. VirtualProtect 设置节权限
 *   9. 更新 PEB.ImageBaseAddress
 *  10. 调用原 PE 的 TLS callbacks（DLL_PROCESS_ATTACH）
 *  11. jump_to_oep(new_image + oep_rva)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

#include "payload.h"

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
/* 同时输出到文件 + OutputDebugStringA（便于 DebugView 实时观察） */
#define DBG(fmt, ...) do { \
    if (g_logf) { fprintf(g_logf, "[REFL] " fmt, ##__VA_ARGS__); fflush(g_logf); } \
    { char _buf[1024]; int _n = snprintf(_buf, sizeof(_buf), "[REFL] " fmt, ##__VA_ARGS__); \
      if (_n > 0) OutputDebugStringA(_buf); } \
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
} PEBX;

#ifdef _WIN64
#define WINLOCK_PEB() ((PEBX*)__readgsqword(0x60))
#else
#define WINLOCK_PEB() ((PEBX*)(uintptr_t)__readfsdword(0x30))
#endif

/* ---- x64 栈对齐跳 OEP（借鉴 winlock stub.c:743-759 + peldr） ----
 * 用 jmp 而非 call，不压返回地址
 * 16B 对齐 + 40B shadow space 符合 x64 ABI */
static void jump_to_oep(void* oep) {
#ifdef _WIN64
    __asm__ volatile (
        "andq $-16, %%rsp\n\t"   /* 16 字节对齐 */
        "subq $40,  %%rsp\n\t"   /* 32B shadow space + 8 对齐余量 */
        "jmpq *%0\n\t"           /* jmp 而非 call,不压返回地址 */
        : : "r"(oep) : "memory"
    );
#else
    __asm__ volatile (
        "andl $-16, %%esp\n\t"
        "jmp *%0\n\t"
        : : "r"(oep) : "memory"
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
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
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
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(img + dos->e_lfanew);
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
         * 有些 PE 的 OriginalFirstThunk 为 0（绑定导入），用 FirstThunk 兜底 */
        uint64_t* ilt = (uint64_t*)(img + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        uint64_t* iat = (uint64_t*)(img + imp->FirstThunk);

        for (; *ilt != 0; ilt++, iat++) {
            const char* func_name = NULL;
            WORD ord = 0;
            if (*ilt & IMAGE_ORDINAL_FLAG64) {
                ord = (WORD)IMAGE_ORDINAL64(*ilt);
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
            *iat = (uint64_t)fn;
            func_count++;
        }
        dll_count++;
    }
    DBG("iat: resolved %d dlls, %d functions\n", dll_count, func_count);
    return 1;
}

/* ---- 应用 relocations（MVP 只处理 DIR64） ----
 * old_base = preferred ImageBase（PE 头里的值）
 * new_base = 实际加载地址
 * 如果 old_base == new_base，无需重定位 */
static int apply_relocations(uint8_t* img, uint64_t old_base, uint64_t new_base) {
    if (old_base == new_base) {
        DBG("reloc: no delta (base matched), skip\n");
        return 1;
    }
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)img;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(img + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir->VirtualAddress == 0 || dir->Size == 0) {
        DBG("reloc: no reloc table, but base delta != 0, FAIL\n");
        return 0;
    }

    int64_t delta = (int64_t)(new_base - old_base);
    DBG("reloc: applying delta=0x%llx (old=0x%llx new=0x%llx)\n",
        (long long)delta, (unsigned long long)old_base, (unsigned long long)new_base);

    IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(img + dir->VirtualAddress);
    uint8_t* reloc_end = (uint8_t*)reloc + dir->Size;
    int count = 0;

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
                    *(uint64_t*)patch += delta;
                    count++;
                    break;
                default:
                    DBG("reloc: unsupported type %d at RVA 0x%lx, skip\n",
                        type, (unsigned long)(reloc->VirtualAddress + offset));
                    /* MVP 不处理 HIGHLOW/HIGH/LOW，后续可加 */
                    break;
            }
        }
        reloc = (IMAGE_BASE_RELOCATION*)((uint8_t*)reloc + block_size);
    }
    DBG("reloc: applied %d DIR64 fixups\n", count);
    return 1;
}

/* ---- 注册 .pdata（异常处理表）----
 * x64 的 SEH 走 .pdata + RUNTIME_FUNCTION 表
 * RtlAddFunctionTable 告诉 OS 这块内存的异常处理表
 * 不注册的话，原 PE 内的异常（如除零、栈溢出）无法被捕获 */
static int register_exception_table(uint8_t* img) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)img;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(img + dos->e_lfanew);
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
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(img + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (dir->VirtualAddress == 0 ||
        dir->Size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie) + sizeof(ULONGLONG)) {
        DBG("cookie: no load config or no SecurityCookie field, skip\n");
        return;
    }
    IMAGE_LOAD_CONFIG_DIRECTORY64* lc = (IMAGE_LOAD_CONFIG_DIRECTORY64*)(img + dir->VirtualAddress);
    if (lc->SecurityCookie == 0) {
        DBG("cookie: SecurityCookie VA is 0, skip\n");
        return;
    }

    ULONGLONG cookie_va = lc->SecurityCookie;
    ULONG_PTR* cookie_ptr;
    /* 判断 reloc 是否已修复：cookie_va 在 image 范围内则已修复为绝对地址 */
    if (cookie_va >= (ULONGLONG)img &&
        cookie_va < (ULONGLONG)img + nt->OptionalHeader.SizeOfImage) {
        cookie_ptr = (ULONG_PTR*)cookie_va;
    } else {
        /* reloc 未修复，用 preferred_base 计算 RVA */
        cookie_ptr = (ULONG_PTR*)(img + (cookie_va - nt->OptionalHeader.ImageBase));
    }

    ULONG_PTR cur = *cookie_ptr;
    const ULONG_PTR default_cookie = 0x00002B992DDFA232ULL;
    if (cur != default_cookie && cur != 0) {
        DBG("cookie: already initialized (0x%llx), skip\n", (unsigned long long)cur);
        return;
    }
    /* KUSER_SHARED_DATA.InterruptTime (0x7FFE0008, 每 100ns 更新) */
    volatile ULONGLONG* kuser_interrupt = (volatile ULONGLONG*)0x7FFE0008;
    *cookie_ptr = (ULONG_PTR)img ^ (ULONG_PTR)*kuser_interrupt;
    DBG("cookie: initialized to 0x%llx\n", (unsigned long long)*cookie_ptr);
}

/* ---- 设置节权限 ----
 * 遍历节表，按 Characteristics 设置 PAGE_* 保护
 * PE 头单独置 PAGE_READONLY */
static void set_section_permissions(uint8_t* img) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)img;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(img + dos->e_lfanew);
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

/* ---- 调用 TLS callbacks（仅 DLL_PROCESS_ATTACH）----
 * MVP 不分配 TLS 数据块（与 5 个参考项目一致）
 * 原 PE 若用 __declspec(thread) 静态 TLS，后续线程可能 crash
 * （MVP 接受此限制，后期阶段评估 AlushPacker TLS proxy 方案） */
static void run_tls_callbacks(uint8_t* img) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)img;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(img + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (dir->VirtualAddress == 0 || dir->Size == 0) {
        DBG("tls: no TLS directory, skip\n");
        return;
    }
    IMAGE_TLS_DIRECTORY64* tls = (IMAGE_TLS_DIRECTORY64*)(img + dir->VirtualAddress);
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

/* ---- 反射式映射主流程 ---- */
static uint8_t* map_image(reflective_payload_t* hdr, uint8_t* payload_data) {
    (void)hdr;  /* MVP v1 不用 header 字段（v2 加密版会用到）*/
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)payload_data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        DBG("map: bad DOS magic 0x%04x\n", dos->e_magic);
        return NULL;
    }
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(payload_data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        DBG("map: bad NT signature 0x%08lx\n", (unsigned long)nt->Signature);
        return NULL;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        DBG("map: not x64 PE (Machine=0x%04x), MVP only supports x64\n",
            nt->FileHeader.Machine);
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
        DBG("map: VirtualAlloc(preferred=%p) failed (err=%lu), trying arbitrary\n",
            (void*)preferred_base, GetLastError());
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

    /* 5. 处理 IAT */
    if (!process_iat(new_img)) {
        DBG("map: process_iat failed\n");
        return NULL;
    }

    /* 6. 注册 .pdata（失败不致命，SEH 可能不工作但能跑） */
    if (!register_exception_table(new_img)) {
        DBG("map: register_exception_table failed (non-fatal, continue)\n");
    }

    /* 7. 初始化 SecurityCookie */
    init_security_cookie(new_img);

    /* 8. 设置节权限 */
    set_section_permissions(new_img);

    /* 9. 更新 PEB.ImageBaseAddress */
    update_peb_image_base(new_img);

    /* 10. 调用 TLS callbacks */
    run_tls_callbacks(new_img);

    return new_img;
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

    /* 4. 跳 OEP */
    void* oep = new_img + hdr->oep_rva;
    DBG("jump_to_oep(%p)\n", oep);
    jump_to_oep(oep);
    /* never returns */
    return 0;
}
