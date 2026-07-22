/*
 * winlock/stub/stub.c - PIC stub
 *
 * 自包含，不依赖标准库与 PE 自带 IAT。
 * 流程：
 *   1. PEB 遍历找 kernel32.dll
 *   2. 解析 kernel32 导出表，拿 GetProcAddress / LoadLibraryA / VirtualProtect / ExitProcess
 *   3. LoadLibraryA("user32.dll") + GetProcAddress 解析 DialogBoxIndirectParamW 等
 *   4. 在栈上构建 DLGTEMPLATE（密码框 + OK/Cancel 按钮）
 *   5. DialogBoxIndirectParamW 弹框 -> DlgProc 校验密码
 *   6. 校验通过：VirtualProtect 改 RW -> XTEA 解密 .text -> 恢复原保护
 *   7. 跳原 OEP（PEB.ImageBaseAddress + oep_rva）
 *
 * PIC 保证：
 *   - 所有静态数据用 __attribute__((section(".lock.*"))) 放入 .lock 输出节
 *   - x64 small code model 默认 RIP-relative 访问全局，本身就是 PIC
 *   - 链接脚本 stub.ld 保证 stub_entry 在 .lock 节起始处
 *   - 不调用任何外部函数（无 IAT 依赖）
 */

#include <stdint.h>
#include "../common/winlock_compat.h"
#ifndef _MSC_VER
/* GCC-only: 为 windows.h 提供 __faststorefence 的替代实现
 * MinGW 的 -mno-sse2 编译模式下 sfence 是 SSE2 指令，需手动包装
 * MSVC 用 _mm_sfence()（intrin.h 已在 winlock_compat.h 中引入）
 *
 * 直接定义 __builtin_ia32_sfence 为内联汇编，避免中间 static 函数
 * 触发 MinGW intrin.h 的 'static but used in inline function' 警告 */
#define __builtin_ia32_sfence() __asm__ __volatile__("sfence" ::: "memory")
#endif
#include <windows.h>
#include "../common/config.h"

/* ---- stub 身份字段：编译期注入兜底（CMake/MinGW -D 未注入时给默认 0）---- */
#ifndef STUB_ARCH
#define STUB_ARCH 0
#endif
#ifndef STUB_TOOLCHAIN
#define STUB_TOOLCHAIN 0
#endif

/* ============================================================
 * MSVC /NODEFAULTLIB 下提供 memset/memcpy 本地实现
 *
 * MSVC /O1 优化会把"清零循环"识别为 memset 模式并转为 memset 调用，
 * 但 PIC stub 不链接 CRT，没有 memset 可解析。
 *
 * #pragma function(memset, memcpy) 强制编译器对这两个函数使用函数调用
 * （不用 intrinsic），让我们提供的本地实现被实际调用。
 *
 * 函数本身用 WINLOCK_SECTION_TEXT 放进 .lock$text 节，保持 PIC 自包含。
 *
 * GCC 不需要：-fno-builtin 已禁用 builtin 识别，循环保持为循环。
 * ============================================================ */
#ifdef _MSC_VER
#pragma function(memset, memcpy)
WINLOCK_SECTION_TEXT
void* memset(void* dst, int val, size_t n) {
    uint8_t* p = (uint8_t*)dst;
    while (n--) *p++ = (uint8_t)val;
    return dst;
}
WINLOCK_SECTION_TEXT
void* memcpy(void* dst, const void* src, size_t n) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    while (n--) *d++ = *s++;
    return dst;
}
#endif

/* ============================================================
 * 类型定义：PEB / LDR 类型由 common/peb_walk.h 提供
 * SHA-256 共享实现由 common/sha256.h 提供
 * ============================================================ */
#define WINLOCK_PIC 1
#include "../common/sha256.h"
#include "../common/peb_walk.h"

/* 函数指针类型 */
typedef HMODULE  (WINAPI *FnLoadLibraryA)(LPCSTR);
typedef FARPROC  (WINAPI *FnGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL     (WINAPI *FnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef VOID     (WINAPI *FnExitProcess)(UINT);
typedef INT_PTR  (WINAPI *FnDialogBoxIndirectParamW)(HINSTANCE, LPCDLGTEMPLATEW, HWND, DLGPROC, LPARAM);
typedef BOOL     (WINAPI *FnEndDialog)(HWND, INT_PTR);
typedef UINT     (WINAPI *FnGetDlgItemTextW)(HWND, int, LPWSTR, int);
typedef int      (WINAPI *FnMessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);

/* TLS callback 函数类型（stub_entry 在 TLS_PROXY 模式下手动调用原 PE 的 callbacks）*/
typedef void (WINAPI *TLS_CALLBACK)(PVOID, DWORD, PVOID);

/* TLS 回调原因（与 Win32 DLL_REASON_* 一致）*/
#define WINLOCK_DLL_PROCESS_ATTACH 1
#define WINLOCK_DLL_THREAD_ATTACH  2
#define WINLOCK_DLL_THREAD_DETACH  3
#define WINLOCK_DLL_PROCESS_DETACH 0

/* ============================================================
 * .lock.data 节：所有静态数据
 *   stub_data + 字符串常量 + 运行时函数指针表
 * ============================================================ */

/* builder 在 stub.bin 中搜索 STUB_DATA_MAGIC 来定位此结构并填充字段 */
WINLOCK_SECTION_DATA
volatile stub_data_t stub_data = {
    .magic         = STUB_DATA_MAGIC,
    .version       = STUB_DATA_VERSION,
    .flags         = 0,                    /* builder 设 1 表示用 hash */
    .max_retries   = STUB_DEFAULT_MAX_RETRIES,
    .reserved16    = 0,
    .oep_rva       = 0,
    .text_rva      = 0,
    .text_size      = 0,
    .text_raw_size = 0,
    .text_protect   = PAGE_EXECUTE_READ,
    .xtea_key      = { WINLOCK_XTEA_KEY0, WINLOCK_XTEA_KEY1,
                      WINLOCK_XTEA_KEY2, WINLOCK_XTEA_KEY3 },
    .salt          = { 0 },
    .pwd_hash      = { 0 },
    .password      = WINLOCK_DEFAULT_PASSWORD,
    .image_base    = 0,
    .reloc_rva     = 0,
    .reloc_size    = 0,
    .reserved32    = 0,
    .orig_tls_callbacks = 0,
    .security_cookie_rva = 0,    /* builder 填充（v4）*/
    .identity      = {
        .stub_arch      = STUB_ARCH,        /* CMake/MinGW -D 注入，未注入则为 0 */
        .stub_toolchain = STUB_TOOLCHAIN,   /* CMake/MinGW -D 注入，未注入则为 0 */
        .stub_bin_ver   = STUB_BIN_VER,     /* config.h 定义，POST_BUILD 可覆盖 */
        .stub_build_time = 0,               /* POST_BUILD patch */
        .stub_source_crc = 0,               /* POST_BUILD patch */
        .stub_size      = 0,                /* POST_BUILD patch */
        .stub_githash   = { 0 },            /* POST_BUILD patch */
    },
    .checksum      = 0,
};

/* 运行时解析的函数指针表 */
WINLOCK_SECTION_DATA
static volatile struct {
    FnLoadLibraryA             LoadLibraryA;
    FnGetProcAddress           GetProcAddress;
    FnVirtualProtect          VirtualProtect;
    FnExitProcess             ExitProcess;
    FnDialogBoxIndirectParamW DialogBoxIndirectParamW;
    FnEndDialog               EndDialog;
    FnGetDlgItemTextW         GetDlgItemTextW;
    FnMessageBoxW             MessageBoxW;
} fn = { 0 };

/* 字符串常量（必须显式放在 .lock.rdata 节，避免被 .rdata 丢弃）
 * 注意：const 与 non-const 不能混在同一个 section，所以单独用 .lock.rdata
 *
 * P1-1 后：API 名 / 模块名已 hash 化，明文字符串删除。
 * 仅保留 UI 文本（标题/按钮/提示）和 LoadLibraryA 参数 "user32.dll"。
 * "user32.dll" 仍为明文是因为 stub 没引入 LdrLoadDll（P2 候选）。
 * 测试密码 L"test123" 仍明文（仅测试模式用，生产模式不会激活）。*/
WINLOCK_SECTION_RDATA
static const wchar_t STR_TITLE[]    = L"WinLock - Password Required";
WINLOCK_SECTION_RDATA
static const wchar_t STR_OK[]       = L"OK";
WINLOCK_SECTION_RDATA
static const wchar_t STR_CANCEL[]   = L"Cancel";
WINLOCK_SECTION_RDATA
static const wchar_t STR_WRONG[]    = L"Wrong password";
WINLOCK_SECTION_RDATA
static const wchar_t STR_TEST_PWD[] = L"test123";  /* 测试模式硬编码密码 */
WINLOCK_SECTION_RDATA
static const wchar_t STR_MSGBOX[]   = L"WinLock Error";  /* 错误对话框标题（带 Error 前缀方便测试脚本识别）*/

WINLOCK_SECTION_RDATA
static const char STR_USER32_A[]                 = "user32.dll";

/* ============================================================
 * .lock.text 节：辅助函数
 * ============================================================ */

/* 窄字符串长度 */
WINLOCK_SECTION_TEXT
static size_t my_strlen(const char* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

/* 宽字符串长度 */
WINLOCK_SECTION_TEXT
static size_t my_wstrlen(const wchar_t* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

/* 宽字符串相等比较 */
WINLOCK_SECTION_TEXT
static int wstr_eq(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == *b;
}

/* 大小写不敏感的宽字符比较（用于模块名） */
WINLOCK_SECTION_TEXT
static int wstr_ieq_n(const wchar_t* a, const wchar_t* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        wchar_t ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return 0;
        if (!ca) return 0;
    }
    return 1;
}

/* ANSI 字符串相等（API 名区分大小写） */
WINLOCK_SECTION_TEXT
static int astr_eq(const char* a, const char* b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == *b;
}

/* PEB walk：按名字查找已加载模块基址 */
WINLOCK_SECTION_TEXT
static PVOID find_module(const wchar_t* name) {
    PEBX*   peb = WINLOCK_PEB();
    PEB_LDR_DATA_X* ldr = (PEB_LDR_DATA_X*)peb->Ldr;
    MY_LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    MY_LIST_ENTRY* curr = head->Flink;
    size_t name_len = my_wstrlen(name);
    while (curr != head) {
        LDR_DATA_TABLE_ENTRY_X* e = (LDR_DATA_TABLE_ENTRY_X*)curr;
        if (e->BaseDllName.Buffer) {
            size_t len = e->BaseDllName.Length / sizeof(wchar_t);
            if (len == name_len && wstr_ieq_n(e->BaseDllName.Buffer, name, name_len)) {
                return e->DllBase;
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

/* 解析 PE 导出表，按名查找函数地址 */
WINLOCK_SECTION_TEXT
static PVOID find_export(PVOID mod, const char* name) {
    if (!mod) return NULL;
    uint8_t* base = (uint8_t*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir->VirtualAddress == 0 || dir->Size == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY* exp =
        (IMAGE_EXPORT_DIRECTORY*)(base + dir->VirtualAddress);
    DWORD* names  = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords   = (WORD*)(base +  exp->AddressOfNameOrdinals);
    DWORD* funcs  = (DWORD*)(base + exp->AddressOfFunctions);

    DWORD exp_start = dir->VirtualAddress;
    DWORD exp_end   = dir->VirtualAddress + dir->Size;

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* n = (const char*)(base + names[i]);
        if (astr_eq(n, name)) {
            DWORD rva = funcs[ords[i]];
            /* forwarder 不处理（演示） */
            if (rva >= exp_start && rva < exp_end) return NULL;
            return base + rva;
        }
    }
    return NULL;
}

/* ============================================================
 * API 哈希化（P1-1）— 实现已抽取到 common/peb_walk.h
 * ============================================================ */
#define PEB_WALK_IMPLEMENT
#include "../common/peb_walk.h"

/* XTEA 解密实现已抽取到 common/xtea.h */
#include "../common/xtea.h"

/* ---- 对话框模板构造工具 ----
 *
 * 重要：必须用 put_dword/put_word 逐字段写入，不能用 DLGTEMPLATE / DLGITEMTEMPLATE
 * 结构体指针直接赋值。
 *
 * 原因：MinGW x86 -O2 会把连续 8 字节字段赋值（style+dwExtendedStyle / x+y+cx+cy）
 * 合并成一条 movq 指令，常量被放到 .rdata 常量池。stub.ld 的 /DISCARD/ 丢弃 .rdata，
 * 运行时 movq 从无效地址读到垃圾值 → DialogBoxIndirectParamW 返回 -1。
 *
 * 逐字段写入（每次 4 字节或 2 字节）让编译器生成立即数 mov，不引用常量池。
 * 详见 docs/CHANGES.md 中 bugfix 分支的 fix(build_dialog) 记录。
 */
WINLOCK_SECTION_TEXT
static uint8_t* put_word(uint8_t* p, uint16_t w) {
    *(uint16_t*)p = w;
    return p + 2;
}

WINLOCK_SECTION_TEXT
static uint8_t* put_dword(uint8_t* p, uint32_t dw) {
    *(uint32_t*)p = dw;
    return p + 4;
}

WINLOCK_SECTION_TEXT
static uint8_t* put_wstr(uint8_t* p, const wchar_t* s) {
    while (*s) {
        *(uint16_t*)p = (uint16_t)*s++;
        p += 2;
    }
    *(uint16_t*)p = 0;
    return p + 2;
}

WINLOCK_SECTION_TEXT
static uint8_t* align_dword(uint8_t* p, uint8_t* start) {
    uintptr_t off = (uintptr_t)(p - start);
    return start + ((off + 3) & ~(uintptr_t)3);
}

/* 在栈缓冲区上构建密码对话框 DLGTEMPLATE
 * 全部用 put_dword/put_word 逐字段写入，避免 GCC -O2 把常量合并到 .rdata 常量池。
 * sizeof(DLGTEMPLATE/DLGITEMTEMPLATE) 在不同编译器/对齐下可能为 18 或 20，
 * 逐字段写入也消除了对 sizeof 的依赖。 */
WINLOCK_SECTION_TEXT
WINLOCK_OPTIMIZE_OFF
static size_t build_dialog(uint8_t* buf) {
    uint8_t* start = buf;
    uint8_t* p = buf;

    /* DLGTEMPLATE (18 字节: DWORD style, DWORD ext, WORD cdit, 4xSHORT xy/cx/cy) */
    p = put_dword(p, WS_POPUP | WS_VISIBLE | WS_CAPTION | WS_SYSMENU
                     | DS_CENTER | DS_MODALFRAME);  /* style */
    p = put_dword(p, 0);                            /* dwExtendedStyle */
    p = put_word(p, 3);                             /* cdit */
    p = put_word(p, 0);                             /* x */
    p = put_word(p, 0);                             /* y */
    p = put_word(p, 200);                           /* cx */
    p = put_word(p, 60);                            /* cy */
    p = put_word(p, 0);                             /* no menu    */
    p = put_word(p, 0);                             /* default class */
    p = put_wstr(p, STR_TITLE);                     /* title      */

    /* EDIT (password input) — DLGITEMTEMPLATE 必须 DWORD 对齐 */
    p = align_dword(p, start);
    p = put_dword(p, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP
                     | ES_AUTOHSCROLL | ES_PASSWORD);  /* style */
    p = put_dword(p, 0);                            /* dwExtendedStyle */
    p = put_word(p, 10);                            /* x */
    p = put_word(p, 10);                            /* y */
    p = put_word(p, 180);                           /* cx */
    p = put_word(p, 14);                            /* cy */
    p = put_word(p, IDC_PWD_EDIT);                  /* id */
    p = put_word(p, 0xFFFF);                        /* class marker */
    p = put_word(p, 0x0081);                        /* Edit atom   */
    p = put_word(p, 0);                             /* no text      */
    p = put_word(p, 0);                             /* no cd        */

    /* OK button */
    p = align_dword(p, start);
    p = put_dword(p, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON); /* style */
    p = put_dword(p, 0);                            /* dwExtendedStyle */
    p = put_word(p, 60);                            /* x */
    p = put_word(p, 32);                            /* y */
    p = put_word(p, 50);                            /* cx */
    p = put_word(p, 14);                            /* cy */
    p = put_word(p, IDOK);                          /* id */
    p = put_word(p, 0xFFFF);                        /* class marker */
    p = put_word(p, 0x0080);                        /* Button atom  */
    p = put_wstr(p, STR_OK);
    p = put_word(p, 0);                             /* cd */

    /* Cancel button */
    p = align_dword(p, start);
    p = put_dword(p, WS_CHILD | WS_VISIBLE | WS_TABSTOP); /* style */
    p = put_dword(p, 0);                            /* dwExtendedStyle */
    p = put_word(p, 120);                           /* x */
    p = put_word(p, 32);                            /* y */
    p = put_word(p, 50);                            /* cx */
    p = put_word(p, 14);                            /* cy */
    p = put_word(p, IDCANCEL);                      /* id */
    p = put_word(p, 0xFFFF);                        /* class marker */
    p = put_word(p, 0x0080);                        /* Button atom  */
    p = put_wstr(p, STR_CANCEL);
    p = put_word(p, 0);                             /* cd */

    return (size_t)(p - start);
}

/* ============================================================
 * 对话框过程
 * 通过 .lock.data 全局 fn 访问 user32 函数
 * 通过 .lock.data 全局 stub_data 读取密码（v2: SHA-256 hash）
 * ============================================================ */
WINLOCK_SECTION_TEXT
static int verify_password(const wchar_t* input) {
    if (stub_data.flags & 0x1) {
        /* v2: hash 模式
         *   SHA-256(utf8(input) + salt) == pwd_hash
         */
        uint8_t utf8[256];
        size_t utf8_len = utf16le_to_utf8(input, utf8, sizeof(utf8) - 16);

        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, utf8, utf8_len);
        sha256_update(&ctx, (const uint8_t*)stub_data.salt, 16);
        uint8_t digest[32];
        sha256_final(&ctx, digest);

        return bytes_eq_const(digest, (const uint8_t*)stub_data.pwd_hash, 32);
    } else {
        /* v1 兼容：明文比较 */
        return wstr_eq(input, (const wchar_t*)stub_data.password);
    }
}

WINLOCK_SECTION_TEXT
static INT_PTR WINAPI dlg_proc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    (void)lParam;
    if (msg == WM_INITDIALOG) {
        return TRUE;
    }
    if (msg == WM_COMMAND) {
        WORD cmd = LOWORD(wParam);
        if (cmd == IDOK) {
            wchar_t buf[64];
            fn.GetDlgItemTextW(hDlg, IDC_PWD_EDIT, buf, 64);
            if (verify_password(buf)) {
                fn.EndDialog(hDlg, 1);  /* 成功 */
            } else {
                fn.MessageBoxW(hDlg, STR_WRONG, STR_MSGBOX,
                               MB_ICONERROR | MB_OK);
                /* 重试计数由 stub_entry 维护，EndDialog(2) 表示失败但可重试 */
                fn.EndDialog(hDlg, 2);
            }
            return TRUE;
        }
        if (cmd == IDCANCEL) {
            fn.EndDialog(hDlg, 0);
            return TRUE;
        }
    }
    return FALSE;
}

/* ============================================================
 * 重定位处理
 *   stub 解密 .text 后必须重新应用 relocations：
 *   - loader 加载时 .text 是密文，loader 应用 relocations 到密文上（无意义）
 *   - stub 解密恢复明文（ImageBase 基准），但实际加载在随机基址
 *   - 必须遍历 .reloc 表，把绝对地址引用从 ImageBase patch 到实际基址
 *
 *   参考：PE-Shield stub/relocation.c, AlushPacker loader.c:647
 * ============================================================ */

/* 重定位类型（IMAGE_REL_BASED_*） */
#define WINLOCK_RELOC_ABSOLUTE 0
#define WINLOCK_RELOC_HIGH     1
#define WINLOCK_RELOC_LOW      2
#define WINLOCK_RELOC_HIGHLOW  3
#define WINLOCK_RELOC_DIR64    10

/* 应用重定位表
 *   img_base: 实际加载基址（PEB.ImageBaseAddress）
 *
 *   关键：只 patch .text 范围内的条目！
 *   原因：loader 加载时 .text 是密文，loader 对密文应用了 relocations
 *         （修改 .text 里的绝对地址引用以匹配实际基址）。stub 解密 .text
 *         时用文件原字节覆盖，冲掉了 loader 的 reloc 修改 → .text 里绝对
 *         地址回到 preferred ImageBase 基准 → 必须重新应用 delta。
 *         但 .rdata/.data 等非加密节 loader 已经正确 reloc，stub 没碰它们，
 *         若再次应用 delta 会"双重重定位"→ 数据损坏。
 *
 *   返回：1 成功（或无需重定位），0 失败 */
WINLOCK_SECTION_TEXT
static int apply_relocations(uint8_t* img_base) {
    /* 如果 builder 没填 reloc 信息，或没启用 ASLR，跳过 */
    if (!(stub_data.flags & STUB_FLAG_ASLR)) return 1;
    if (stub_data.reloc_rva == 0 || stub_data.reloc_size == 0) {
        /* 启用了 ASLR 但无重定位表 → 无法修正绝对地址，失败 */
        return 0;
    }

    /* delta = 实际基址 - preferred ImageBase */
    int64_t delta = (int64_t)((uintptr_t)img_base - (uintptr_t)stub_data.image_base);
    if (delta == 0) return 1;  /* 加载在 preferred 基址，无需重定位 */

    /* .text 节的 RVA 范围（stub 只 patch 这个范围） */
    uint32_t text_rva = (uint32_t)stub_data.text_rva;
    uint32_t text_end = text_rva + (uint32_t)stub_data.text_size;

    uint8_t* reloc_start = img_base + stub_data.reloc_rva;
    uint8_t* reloc_end   = reloc_start + stub_data.reloc_size;
    IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)reloc_start;

    while ((uint8_t*)reloc < reloc_end && reloc->SizeOfBlock > 0) {
        DWORD block_size = reloc->SizeOfBlock;
        if (block_size < sizeof(IMAGE_BASE_RELOCATION)) break;

        DWORD block_rva = reloc->VirtualAddress;
        DWORD num_entries = (block_size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)(reloc + 1);

        for (DWORD i = 0; i < num_entries; i++) {
            WORD type = entries[i] >> 12;
            WORD offset = entries[i] & 0xFFF;
            DWORD patch_rva = block_rva + offset;

            /* 只 patch .text 范围内的条目。
             * 跨块边界的整块 RVA 检查：若整块都不在 .text 范围内，跳过；
             * 单条目检查更精确。 */
            if (patch_rva < text_rva || patch_rva >= text_end) {
                continue;  /* loader 已处理，跳过避免双重 reloc */
            }

            uint8_t* patch_addr = img_base + patch_rva;

            switch (type) {
                case WINLOCK_RELOC_ABSOLUTE:
                    break;  /* padding，跳过 */
                case WINLOCK_RELOC_HIGH: {
                    /* 高 16 位加 delta 高 16 位（x86 罕见） */
                    *(uint16_t*)patch_addr += (uint16_t)((uint32_t)delta >> 16);
                    break;
                }
                case WINLOCK_RELOC_LOW: {
                    /* 低 16 位加 delta 低 16 位 */
                    *(uint16_t*)patch_addr += (uint16_t)(delta & 0xFFFF);
                    break;
                }
                case WINLOCK_RELOC_HIGHLOW: {
                    /* 32 位加 delta（x86 主要类型） */
                    *(uint32_t*)patch_addr += (uint32_t)delta;
                    break;
                }
                case WINLOCK_RELOC_DIR64: {
                    /* 64 位加 delta（x64 主要类型） */
                    *(uint64_t*)patch_addr += (uint64_t)delta;
                    break;
                }
                default:
                    /* 未知类型，跳过（x64 PE 通常只有 ABSOLUTE/DIR64） */
                    break;
            }
        }

        reloc = (IMAGE_BASE_RELOCATION*)((uint8_t*)reloc + block_size);
    }

    return 1;
}

/* ============================================================
 * 初始化 SecurityCookie（P0-1，借鉴 AlushPacker + peldr）
 *
 *   - 仅当 stub_data.security_cookie_rva != 0 时执行
 *   - 仅当 cookie 当前值为 MSVC 默认值或 0 时才覆盖
 *     （CRT 启动后 __security_init_cookie 也是这个判断逻辑，
 *      如果 stub 先初始化为随机值，CRT 会跳过初始化，保持 stub 写入的值）
 *   - 熵源：KUSER_SHARED_DATA.InterruptTime (0x7FFE0008)
 *     每 100ns 更新一次，无 API 依赖，userland 不可预测
 *   - XOR PEB.ImageBaseAddress 让每个进程 cookie 不同
 *
 *   为什么需要这步：
 *   1. TLS_PROXY 模式下原 PE 的 TLS callbacks 在 mainCRTStartup 之前调用，
 *      如果 callbacks 用了 /GS，cookie 仍是默认值会误报 __report_gsfailure
 *   2. 某些程序 OEP 不是 CRT 启动代码，cookie 永远不会被初始化
 * ============================================================ */
WINLOCK_SECTION_TEXT
static void init_security_cookie(void) {
    if (stub_data.security_cookie_rva == 0) return;
    PEBX* peb = WINLOCK_PEB();
    uint8_t* img_base = (uint8_t*)peb->ImageBaseAddress;
    /* cookie 是 .data 中的 ULONG_PTR，stub 用 img_base + RVA 计算实际地址
     * （ASLR 模式下 OS loader 已经把 .data 重定位到 img_base，地址正确）*/
    ULONG_PTR* cookie_ptr = (ULONG_PTR*)(img_base + stub_data.security_cookie_rva);
    ULONG_PTR cur = *cookie_ptr;
    /* MSVC 编译时硬编码的默认 cookie 值（公开已知，无随机性）*/
#ifdef _WIN64
    const ULONG_PTR default_cookie = 0x00002B992DDFA232ULL;
#else
    const ULONG_PTR default_cookie = 0xBB40E64E;
#endif
    /* 仅当 cookie 仍是默认值或 0 时才覆盖（避免破坏已初始化的 cookie）*/
    if (cur != default_cookie && cur != 0) return;
    /* KUSER_SHARED_DATA.InterruptTime (0x7FFE0008, 8 字节，每 100ns 更新) */
    volatile ULONGLONG* kuser_interrupt = (volatile ULONGLONG*)0x7FFE0008;
    *cookie_ptr = (ULONG_PTR)img_base ^ (ULONG_PTR)*kuser_interrupt;
}

/* ============================================================
 * PEB 反调试（P1-2，借鉴 peldr loader.c:858-907 + TinyLoad）
 *
 *   零 API 依赖，纯内存读：
 *   1. PEB.BeingDebugged (offset 0x02)
 *      - 调试器 attach 时 OS 置 1；可被调试器 patch 绕过（OllyDbg/x64dbg 默认）
 *   2. NtGlobalFlag (PEB+0xBC x64 / +0x68 x86)
 *      - 调试器启动时 OS 设 FLG_HEAP_ENABLE_TAIL_CHECK(0x10) |
 *        FREE_CHECK(0x20) | VALIDATE_PARAMETERS(0x40) = 0x70
 *      - 可被 patch，但很多调试器默认不 patch
 *   3. KdDebuggerEnabled (KUSER_SHARED_DATA+0x2D4, 1 字节)
 *      - 系统级标志，userland 改不了（KUSER_SHARED_DATA 是只读共享页）
 *      - 反映是否有内核调试器连接
 *
 *   组合三项大幅提高反调试强度。检测到调试器返回 1。
 * ============================================================ */
WINLOCK_SECTION_TEXT
static int is_being_debugged(void) {
    PEBX* peb = WINLOCK_PEB();
    uint8_t* p = (uint8_t*)peb;

    /* 1. PEB.BeingDebugged (offset 0x02) */
    if (p[0x02]) return 1;

    /* 2. NtGlobalFlag — 调试器启动时设置 0x70 标志 */
#ifdef _WIN64
    uint32_t nt_global_flag = *(uint32_t*)(p + 0xBC);
#else
    uint32_t nt_global_flag = *(uint32_t*)(p + 0x68);
#endif
    if (nt_global_flag & 0x70) return 1;

    /* 3. KdDebuggerEnabled — KUSER_SHARED_DATA 里的系统标志，userland 改不了 */
    volatile uint8_t* kd_debugger_enabled = (volatile uint8_t*)0x7FFE02D4;
    if (*kd_debugger_enabled) return 1;

    return 0;
}

/* ============================================================
 * 清零运行时解析的函数指针表（P1-3，借鉴 peldr loader.c:1107-1126）
 *
 *   - 防止 dump 内存后分析者从 fn 表看出 stub 用了哪些 API
 *   - fn 是 volatile，编译器不会优化掉写入
 *   - 必须在跳 OEP 之前调用，那时 stub 不再需要这些指针
 * ============================================================ */
WINLOCK_SECTION_TEXT
static void clear_fn_pointers(void) {
    fn.LoadLibraryA             = NULL;
    fn.GetProcAddress           = NULL;
    fn.VirtualProtect          = NULL;
    fn.ExitProcess             = NULL;
    fn.DialogBoxIndirectParamW = NULL;
    fn.EndDialog               = NULL;
    fn.GetDlgItemTextW         = NULL;
    fn.MessageBoxW             = NULL;
}

/* ============================================================
 * 栈对齐跳 OEP（P0-2，借鉴 peldr loader.c:1144-1152）
 *
 * GCC 分支保持内联汇编不变（保证 stub 二进制字节级不变）；
 * MSVC 分支调用独立 .asm 文件实现的函数：
 *   x64: stub_asm_x64.asm（ml64.exe 编译）
 *   x86: stub_asm_x86.asm（ml.exe 编译）
 *   原因：MSVC x64 不支持内联汇编，必须独立 .asm + ml64.exe
 *
 *   - 用 jmp 而非 call：不压入返回地址，stub 不返回
 *   - x64: 强制 RSP ≡ 8 mod 16（MSVC ABI 假设 call 进入后栈对齐）
 *       andq $-16, %rsp  → RSP ≡ 0 mod 16
 *       subq $40, %rsp   → 32B shadow space + 8 对齐 = RSP ≡ 8 mod 16
 *       jmpq *reg        → 跳转（不压返回地址）
 *   - x86: 16 对齐（避免 SSE 指令对齐异常，CRT 启动代码可能要求）
 *       andl $-16, %esp
 *       jmp *reg
 *   - WINLOCK_UNREACHABLE 告诉编译器函数不返回，避免 fallthrough 警告
 * ============================================================ */
#ifdef _MSC_VER
/* MSVC: 独立 .asm 实现的函数声明
 * x64 ABI: 参数走 RCX，无需 name decoration
 * x86 __cdecl: MASM 符号名带前导下划线 _jump_to_oep_x86 */
#ifdef _WIN64
extern void jump_to_oep_x64(void* oep);
#else
extern void __cdecl jump_to_oep_x86(void* oep);
#endif
#endif

WINLOCK_SECTION_TEXT
static void jump_to_oep(void* oep) {
#ifndef _MSC_VER
    /* GCC: 内联汇编（保持 stub 二进制不变） */
#ifdef _WIN64
    __asm__ volatile (
        "andq $-16, %%rsp\n\t"   /* 16 字节对齐 */
        "subq $40,  %%rsp\n\t"   /* 32B shadow space + 8 对齐 */
        "jmpq *%0\n\t"           /* jmp 而非 call,不压返回地址 */
        : : "r"(oep) : "memory"
    );
#else
    __asm__ volatile (
        "andl $-16, %%esp\n\t"   /* 16 字节对齐 */
        "jmp *%0\n\t"
        : : "r"(oep) : "memory"
    );
#endif
#else
    /* MSVC: 调用独立 .asm 实现的 jump_to_oep_xXX */
#ifdef _WIN64
    jump_to_oep_x64(oep);
#else
    jump_to_oep_x86(oep);
#endif
#endif
    WINLOCK_UNREACHABLE();
}

/* ============================================================
 * 解密 .text 节 + 应用 relocations（stub_entry 与 stub_tls_callback 共用）
 *   返回：1 成功，0 失败
 * ============================================================ */
WINLOCK_SECTION_TEXT
static int decrypt_text_and_reloc(void) {
    PEBX*   peb       = WINLOCK_PEB();
    uint8_t* img_base = (uint8_t*)peb->ImageBaseAddress;
    uint8_t* text_va  = img_base + stub_data.text_rva;
    DWORD    old_prot = 0;

    /* 1. VirtualProtect 改 RW */
    if (!fn.VirtualProtect(text_va, (SIZE_T)stub_data.text_size,
                           PAGE_READWRITE, &old_prot))
        return 0;

    /* 2. XTEA 解密 .text（恢复明文，ImageBase 基准） */
    xtea_decrypt_buf(text_va, (size_t)stub_data.text_size,
                     (const uint32_t*)stub_data.xtea_key);

    /* 3. 重新应用 relocations（如果 ASLR 启用） */
    if (!apply_relocations(img_base)) {
        /* ASLR 启用但重定位失败，恢复保护后返回失败 */
        fn.VirtualProtect(text_va, (SIZE_T)stub_data.text_size,
                          stub_data.text_protect, &old_prot);
        return 0;
    }

    /* 4. 恢复原保护（让 CPU 能执行） */
    fn.VirtualProtect(text_va, (SIZE_T)stub_data.text_size,
                     stub_data.text_protect, &old_prot);

    return 1;
}

/* ============================================================
 * 弹密码框（stub_entry / stub_tls_callback 共用）
 *   返回：1 成功；0 失败（Cancel 或超限时内部已 ExitProcess，不会真正返回 0）
 * ============================================================ */
WINLOCK_SECTION_TEXT
static int prompt_password(void) {
    HMODULE u32 = fn.LoadLibraryA(STR_USER32_A);
    if (!u32) return 0;
    /* P1-1: user32 的 API 也用 hash 解析（直接遍历导出表，省一次 GetProcAddress） */
    fn.DialogBoxIndirectParamW = (FnDialogBoxIndirectParamW)
        find_export_by_hash(u32, HASH_DIALOGBOXINDIRECTPARAMW);
    fn.EndDialog          = (FnEndDialog)
        find_export_by_hash(u32, HASH_ENDDIALOG);
    fn.GetDlgItemTextW    = (FnGetDlgItemTextW)
        find_export_by_hash(u32, HASH_GETDLGITEMTEXTW);
    fn.MessageBoxW        = (FnMessageBoxW)
        find_export_by_hash(u32, HASH_MESSAGEBOXW);
    if (!fn.DialogBoxIndirectParamW || !fn.EndDialog
        || !fn.GetDlgItemTextW || !fn.MessageBoxW)
        return 0;

    uint8_t dlg_buf[1024];
    size_t  dlg_size = build_dialog(dlg_buf);
    (void)dlg_size;

    INT_PTR r = 0;
    uint16_t retries = 0;
    uint16_t max_retries = stub_data.max_retries;
    if (max_retries == 0) max_retries = STUB_DEFAULT_MAX_RETRIES;

    do {
        r = fn.DialogBoxIndirectParamW(
            NULL, (LPCDLGTEMPLATEW)dlg_buf, NULL, dlg_proc, 0);
        if (r == 1) return 1;        /* 成功 */
        if (r == 0) fn.ExitProcess(1); /* Cancel */
        retries++;
    } while (retries < max_retries);

    fn.ExitProcess(2);  /* 超过最大重试次数 */
    return 0;  /* never reach */
}

/* ============================================================
 * stub 入口
 *   链接脚本保证 stub_entry 在 .lock 节起始（offset 0）
 *   builder 设置 AddressOfEntryPoint = .lock_RVA + 0
 *
 *   两种工作模式：
 *   - 直接模式（默认）：stub_entry 完成密码校验 + 解密 + 跳 OEP
 *   - TLS 代理模式（flags & STUB_FLAG_TLS_PROXY）：
 *     stub_entry 跳过解密（已在 stub_tls_callback 完成），只跳 OEP
 * ============================================================ */
WINLOCK_SECTION_ENTRY WINLOCK_OPTIMIZE_OFF
void stub_entry(void) {

    /* 1. PEB walk 找 kernel32（windows 启动时已加载）
     *    P1-1: 用 hash 替代明文模块名，避免 strings 暴露 "kernel32.dll" */
    PVOID k32 = find_module_by_hash(HASH_MOD_KERNEL32_DLL);
    if (!k32) goto fail;

    /* 2. 解析 kernel32 关键函数（P1-1: hash 替代明文 API 名） */
    fn.GetProcAddress = (FnGetProcAddress)find_export_by_hash(k32, HASH_GETPROCADDRESS);
    fn.LoadLibraryA  = (FnLoadLibraryA)   find_export_by_hash(k32, HASH_LOADLIBRARYA);
    fn.VirtualProtect = (FnVirtualProtect) find_export_by_hash(k32, HASH_VIRTUALPROTECT);
    fn.ExitProcess   = (FnExitProcess)     find_export_by_hash(k32, HASH_EXITPROCESS);
    if (!fn.GetProcAddress || !fn.LoadLibraryA
        || !fn.VirtualProtect || !fn.ExitProcess)
        goto fail;

    /* 2a. PEB 反调试（P1-2）：检测到调试器立即退出，不让调试器有机会 dump IAT
     *     仅当 builder -d 设置 STUB_FLAG_ANTIDEBUG 时启用（默认关闭，方便开发）*/
    if ((stub_data.flags & STUB_FLAG_ANTIDEBUG) && is_being_debugged())
        fn.ExitProcess(0);

    /* 3. 密码校验（无论 TLS_PROXY 还是直接模式，都在 stub_entry 完成）
     *    原因：TLS callback 阶段持有 loader lock，调用 LoadLibraryA("user32.dll")
     *          会死锁（user32 加载触发其依赖 DLL 的 DllMain，DllMain 需要 loader lock）。
     *          所以 stub_tls_callback 改为空实现，密码校验推到 stub_entry。
     *    - 测试模式（flags & STUB_FLAG_TEST_MODE）：跳过弹框，
     *      直接用硬编码 L"test123" 走 verify_password，验证 v2 hash 路径
     *    - 正常模式：弹 DialogBox 让用户输入 */
    if (stub_data.flags & STUB_FLAG_TEST_MODE) {
        if (!verify_password(STR_TEST_PWD)) goto fail;
    } else {
        if (!prompt_password()) goto fail;
    }

    /* 4. 解密 .text 节 + 应用 relocations（如果 ASLR 启用） */
    if (!decrypt_text_and_reloc()) goto fail;

    /* 4a. 初始化 SecurityCookie（在跳 OEP / 调用原 TLS callbacks 之前）
     *     CRT 启动代码也会做这事，但 TLS_PROXY 模式下原 TLS callbacks 在 stub_entry
     *     阶段调用（晚于 DLL_PROCESS_ATTACH），需先初始化 cookie。*/
    init_security_cookie();

    /* 4b. TLS_PROXY 模式：调用原 PE 的 TLS callbacks
     *     stub_tls_callback 已改为空实现，原 callbacks 不再被 Windows loader 调用。
     *     stub_entry 在 .text 解密 + SecurityCookie 初始化之后手动调用它们，
     *     模拟 DLL_PROCESS_ATTACH 时的行为。
     *     stub_data.orig_tls_callbacks 是 callbacks 数组 VA（builder 填入），
     *     数组以 NULL 结尾。用 uintptr_t 中转避免 int-to-pointer-cast 警告。 */
    if (stub_data.flags & STUB_FLAG_TLS_PROXY) {
        PEBX* peb = WINLOCK_PEB();
        uint8_t* img_base = (uint8_t*)peb->ImageBaseAddress;
        if (stub_data.orig_tls_callbacks) {
            TLS_CALLBACK* callbacks = (TLS_CALLBACK*)(uintptr_t)stub_data.orig_tls_callbacks;
            while (*callbacks) {
                (*callbacks)(img_base, WINLOCK_DLL_PROCESS_ATTACH, NULL);
                callbacks++;
            }
        }
    }

    /* 5. 跳原 OEP */
    {
        PEBX* peb = WINLOCK_PEB();
        uint8_t* img_base = (uint8_t*)peb->ImageBaseAddress;
        void* oep = img_base + stub_data.oep_rva;
        clear_fn_pointers();   /* P1-3: 防 dump IAT */
        jump_to_oep(oep);
        /* never returns */
    }

fail:
    fn.ExitProcess(2);
    while (1) { /* never reach */ }
}

/* ============================================================
 * TLS callback 代理（空实现 — 所有工作推到 stub_entry）
 *
 *   背景：Windows loader 在调用 TLS callback 时持有 loader lock。
 *   若 stub_tls_callback 调用 LoadLibraryA（弹密码框需要 user32.dll），
 *   user32 加载会触发其依赖 DLL 的 DllMain，DllMain 需要获取 loader lock，
 *   但 loader lock 已被 TLS callback 持有 → 死锁。
 *
 *   详见 docs/TLS_LOADER_LOCK_DEADLOCK.md（hellomingw/helloucrt 卡死根因）。
 *   参考 AlushPacker TlsCallbackProxy（entryPointCalled 标志 + EP 中执行）。
 *
 *   流程：
 *   - builder 检测到原 PE 有 TLS callbacks 时启用 TLS_PROXY 模式：
 *     1. 在 .lock 节内创建新 TLS directory + callbacks 数组 [stub_tls_callback, NULL]
 *     2. DataDirectory[9] 指向新 TLS directory
 *     3. Windows loader 在 EP 之前调用 stub_tls_callback(DLL_PROCESS_ATTACH)
 *   - stub_tls_callback 直接返回（空实现），不做任何事
 *   - stub_entry (EP) 完成所有工作：
 *     1. PEB walk + 解析 kernel32 API（loader lock 已释放）
 *     2. 弹密码框（LoadLibraryA user32 不会死锁）
 *     3. 解密 .text + 应用 relocations
 *     4. 调用原 PE 的 TLS callbacks（通过 stub_data.orig_tls_callbacks）
 *     5. 跳 OEP
 *
 *   安全权衡：原 PE 的 TLS callbacks 在 EP 阶段而非 DLL_PROCESS_ATTACH 阶段调用。
 *   极少数 callbacks 依赖 loader lock（如 LoadLibrary），但 AlushPacker 同样这么
 *   做，实际兼容性良好。详见 docs/packer_code_review-20260720.md Bug #6。
 * ============================================================ */

/* stub_tls_callback 状态：保留用于未来扩展（当前未使用）*/
WINLOCK_SECTION_DATA
static volatile int g_tls_decrypted = 0;

/* ============================================================
 * stub_tls_callback + g_stub_tls_cb_marker 的定义（MinGW 路径）
 *
 * MSVC 路径：marker + function 由 stub_asm_${ARCH}.asm 提供，
 *           放进同一个 .lock$tlscb SEGMENT (READ EXECUTE)。
 *           原因：MSVC link.exe 不合并不同 flag 的 $ 子节
 *           (.lock$tlscbm 是 const data 0x40000040，
 *            .lock$tlscb 是 code 0x60000020)，
 *           导致 marker 和 function 分到不同输出节，
 *           builder.c 的 find_stub_tls_cb_offset 假设 function = magic + 16 失效。
 *
 * MinGW 路径：marker + function 用 C 定义，stub.ld 的 KEEP() + SUBALIGN(16)
 *           保证 marker 和 function 在 .lock 节内连续相邻。
 * ============================================================ */
#ifndef _MSC_VER
/* stub_tls_callback 的定位魔数：builder 在 stub.bin 中搜索此 8 字节，
 * 紧随其后的就是 stub_tls_callback 函数入口。
 *
 * 放在独立 section .lock.tlscbm 中（const 数据不能与函数同 section），
 * stub.ld 把 .lock.tlscbm 紧接在 .lock.text 之后、.lock.tlscb 之前。
 *
 * 用 16 字节数组（magic + zero pad）：因为 stub.ld 的 SUBALIGN(16) 强制
 * 每个子节 16 字节对齐，marker 后必然有填充。让 marker 自身占满 16 字节，
 * function 就紧跟在 marker+16 处（无额外填充），builder 计算 offset = M + 16。 */
WINLOCK_SECTION_TLSCBM
static const uint64_t g_stub_tls_cb_marker[2] = { STUB_TLS_CB_MAGIC, 0 };

/* TLS callback 必须有特定签名，且放在 .lock.tlscb 节（代码节）
 * Windows loader 通过 IMAGE_TLS_DIRECTORY.AddressOfCallBacks 调用 */
WINLOCK_SECTION_TLSCB
void WINAPI stub_tls_callback(PVOID hModule, DWORD reason, PVOID reserved) {
    /* 空实现：所有工作推到 stub_entry 完成。
     *
     * 原因：TLS callback 在 Windows loader lock 持有期间执行，
     *       调用 LoadLibraryA 会死锁（user32.dll 加载需要 loader lock）。
     *       所以 stub_tls_callback 直接返回，stub_entry (EP) 中完成：
     *         密码校验 + 解密 .text + 调用原 TLS callbacks + 跳 OEP。
     *
     * stub_entry 通过 stub_data.orig_tls_callbacks 调用原 PE 的 TLS callbacks
     * （builder 已保存原 callbacks 数组 VA，并把新数组设为 [stub_tls_callback, NULL]）。
     *
     * 参数全部保留以满足 TLS_CALLBACK 签名，但实际未使用。 */
    (void)hModule;
    (void)reason;
    (void)reserved;
    return;
}
#endif /* !_MSC_VER */
