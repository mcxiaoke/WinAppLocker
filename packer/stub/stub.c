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
/* Provide __faststorefence for windows.h under -mno-sse2 (sfence is SSE2) */
static __inline__ void __winlock_sfence(void) { __asm__ __volatile__("sfence" ::: "memory"); }
#define __builtin_ia32_sfence() __winlock_sfence()
#include <windows.h>
#include "../common/config.h"

/* ============================================================
 * 类型定义
 * ============================================================ */

typedef struct { USHORT Length; USHORT MaxLength; PWSTR Buffer; } USTR;

/* ============================================================
 * SHA-256 + UTF-16LE->UTF-8 + 常量时间比较（共享实现）
 *   - WINLOCK_PIC 让函数进入 .lock.text 节
 *   - 同一份代码被 tests/stub_sha256_test.c 复用（host 模式）
 * ============================================================ */
#define WINLOCK_PIC 1
#include "sha256.h"

typedef struct {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    USTR       FullDllName;
    USTR       BaseDllName;
} LDRENT;

typedef struct {
    ULONG      Length;
    UCHAR      Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} LDRCNT;

typedef struct {
    UCHAR  a, b, c, d;
    PVOID  Mutant;
    PVOID  ImageBaseAddress;
    LDRCNT *Ldr;
} PEBX;

/* PEB 访问：x64 用 gs:[0x60]，x86 用 fs:[0x30]。
 * PVOID 自动按架构变大小（8B/4B），PEBX/LDRENT/USTR 用 PVOID/LIST_ENTRY，
 * 默认对齐与 Windows 内核结构一致，x86/x64 都能正确解析。 */
#ifdef _WIN64
#define WINLOCK_PEB()  ((PEBX*)__readgsqword(0x60))
#else
#define WINLOCK_PEB()  ((PEBX*)(uintptr_t)__readfsdword(0x30))
#endif

/* 函数指针类型 */
typedef HMODULE  (WINAPI *FnLoadLibraryA)(LPCSTR);
typedef FARPROC  (WINAPI *FnGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL     (WINAPI *FnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef VOID     (WINAPI *FnExitProcess)(UINT);
typedef INT_PTR  (WINAPI *FnDialogBoxIndirectParamW)(HINSTANCE, LPCDLGTEMPLATEW, HWND, DLGPROC, LPARAM);
typedef BOOL     (WINAPI *FnEndDialog)(HWND, INT_PTR);
typedef UINT     (WINAPI *FnGetDlgItemTextW)(HWND, int, LPWSTR, int);
typedef int      (WINAPI *FnMessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);

/* ============================================================
 * .lock.data 节：所有静态数据
 *   stub_data + 字符串常量 + 运行时函数指针表
 * ============================================================ */

/* builder 在 stub.bin 中搜索 STUB_DATA_MAGIC 来定位此结构并填充字段 */
__attribute__((section(".lock.data"), used, aligned(16)))
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
    .checksum      = 0,
};

/* 运行时解析的函数指针表 */
__attribute__((section(".lock.data"), used, aligned(16)))
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
__attribute__((section(".lock.rdata"), used, aligned(2)))
static const wchar_t STR_TITLE[]    = L"WinLock - Password Required";
__attribute__((section(".lock.rdata"), used, aligned(2)))
static const wchar_t STR_OK[]       = L"OK";
__attribute__((section(".lock.rdata"), used, aligned(2)))
static const wchar_t STR_CANCEL[]   = L"Cancel";
__attribute__((section(".lock.rdata"), used, aligned(2)))
static const wchar_t STR_WRONG[]    = L"Wrong password";
__attribute__((section(".lock.rdata"), used, aligned(2)))
static const wchar_t STR_TEST_PWD[] = L"test123";  /* 测试模式硬编码密码 */
__attribute__((section(".lock.rdata"), used, aligned(2)))
static const wchar_t STR_MSGBOX[]   = L"WinLock";

__attribute__((section(".lock.rdata"), used, aligned(1)))
static const char STR_USER32_A[]                 = "user32.dll";

/* ============================================================
 * .lock.text 节：辅助函数
 * ============================================================ */

/* 窄字符串长度 */
__attribute__((section(".lock.text"), used, noinline))
static size_t my_strlen(const char* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

/* 宽字符串长度 */
__attribute__((section(".lock.text"), used, noinline))
static size_t my_wstrlen(const wchar_t* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

/* 宽字符串相等比较 */
__attribute__((section(".lock.text"), used, noinline))
static int wstr_eq(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == *b;
}

/* 大小写不敏感的宽字符比较（用于模块名） */
__attribute__((section(".lock.text"), used, noinline))
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
__attribute__((section(".lock.text"), used, noinline))
static int astr_eq(const char* a, const char* b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == *b;
}

/* PEB walk：按名字查找已加载模块基址 */
__attribute__((section(".lock.text"), used, noinline))
static PVOID find_module(const wchar_t* name) {
    PEBX*   peb = WINLOCK_PEB();
    LDRCNT* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* curr = head->Flink;
    size_t name_len = my_wstrlen(name);
    while (curr != head) {
        LDRENT* e = (LDRENT*)curr;
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
__attribute__((section(".lock.text"), used, noinline))
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
 * API 哈希化（P1-1，借鉴 peldr loader.c:99-114 + hash.py）
 *
 *   - DJB15: h = 1993; h = ((h<<4) - h) + c   即 h = h*15 + c
 *   - 大小写不敏感：ASCII_FOLD_MASK = ('A' <= c <= 'Z') ? 0x20 : 0
 *   - 模块名（wchar）取低 8 位当 ASCII 处理（系统 DLL 名都是 ASCII）
 *   - Hash 常量由 tools/gen_api_hash.py 离线生成，写入 config.h
 *   - 优点：.lock.rdata 中无明文 API 名/模块名，strings 抓取为乱码
 * ============================================================ */

/* DJB15 大小写不敏感 ASCII hash */
__attribute__((section(".lock.text"), used, noinline))
static uint32_t hash_ascii(const char* s) {
    uint32_t h = WINLOCK_HASH_SEED;
    uint8_t c;
    while ((c = (uint8_t)*s++)) {
        /* ASCII_FOLD_MASK: 'A' <= c <= 'Z' 时 mask=0x20（unsigned 比较 trick）*/
        if ((uint8_t)(c - 'A') <= (uint8_t)('Z' - 'A')) c |= 0x20;
        h = ((h << 4) - h) + c;
    }
    return h;
}

/* DJB15 大小写不敏感宽字符 hash（用于 PEB 模块名匹配）
 *   - 只取每个 wchar 的低 8 位（系统 DLL 名都是 ASCII）
 *   - len 是 wchar 数量（不是字节数） */
__attribute__((section(".lock.text"), used, noinline))
static uint32_t hash_wstr_lower(const wchar_t* s, size_t len) {
    uint32_t h = WINLOCK_HASH_SEED;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = (uint8_t)s[i];
        if ((uint8_t)(c - 'A') <= (uint8_t)('Z' - 'A')) c |= 0x20;
        h = ((h << 4) - h) + c;
    }
    return h;
}

/* PEB walk：按 hash 查找已加载模块基址 */
__attribute__((section(".lock.text"), used, noinline))
static PVOID find_module_by_hash(uint32_t want_hash) {
    PEBX*   peb = WINLOCK_PEB();
    LDRCNT* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* curr = head->Flink;
    while (curr != head) {
        LDRENT* e = (LDRENT*)curr;
        if (e->BaseDllName.Buffer) {
            size_t len = e->BaseDllName.Length / sizeof(wchar_t);
            if (hash_wstr_lower(e->BaseDllName.Buffer, len) == want_hash) {
                return e->DllBase;
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

/* 解析 PE 导出表，按 hash 查找函数地址（替代 find_export） */
__attribute__((section(".lock.text"), used, noinline))
static PVOID find_export_by_hash(PVOID mod, uint32_t want_hash) {
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
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords  = (WORD*)(base +  exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    DWORD exp_start = dir->VirtualAddress;
    DWORD exp_end   = dir->VirtualAddress + dir->Size;

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* n = (const char*)(base + names[i]);
        if (hash_ascii(n) == want_hash) {
            DWORD rva = funcs[ords[i]];
            if (rva >= exp_start && rva < exp_end) return NULL;  /* forwarder */
            return base + rva;
        }
    }
    return NULL;
}

/* XTEA 解密单个 8 字节块 */
__attribute__((section(".lock.text"), used, noinline))
static void xtea_decrypt_block(uint32_t* v, const uint32_t* key) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = XTEA_DELTA * XTEA_ROUNDS;  /* 0xC6EF3720 */
    for (int i = 0; i < XTEA_ROUNDS; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= XTEA_DELTA;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0; v[1] = v1;
}

/* XTEA 解密缓冲区（按 8 字节块，尾部按字节异或密钥流） */
__attribute__((section(".lock.text"), used, noinline))
static void xtea_decrypt_buf(uint8_t* data, size_t size, const uint32_t* key) {
    size_t n_blocks = size / 8;
    size_t i;
    for (i = 0; i < n_blocks; i++) {
        xtea_decrypt_block((uint32_t*)(data + i * 8), key);
    }
    /* 尾部不足 8 字节，简单异或密钥字节 */
    size_t tail_off = n_blocks * 8;
    uint8_t* k = (uint8_t*)key;
    for (i = 0; i < size - tail_off; i++) {
        data[tail_off + i] ^= k[i];
    }
}

/* ---- 对话框模板构造工具 ---- */
__attribute__((section(".lock.text"), used, noinline))
static uint8_t* put_word(uint8_t* p, uint16_t w) {
    *(uint16_t*)p = w;
    return p + 2;
}

__attribute__((section(".lock.text"), used, noinline))
static uint8_t* put_wstr(uint8_t* p, const wchar_t* s) {
    while (*s) {
        *(uint16_t*)p = (uint16_t)*s++;
        p += 2;
    }
    *(uint16_t*)p = 0;
    return p + 2;
}

__attribute__((section(".lock.text"), used, noinline))
static uint8_t* align_dword(uint8_t* p, uint8_t* start) {
    uintptr_t off = (uintptr_t)(p - start);
    return start + ((off + 3) & ~(uintptr_t)3);
}

/* 在栈缓冲区上构建密码对话框 DLGTEMPLATE */
__attribute__((section(".lock.text"), used, noinline))
static size_t build_dialog(uint8_t* buf) {
    uint8_t* start = buf;
    uint8_t* p = buf;

    DLGTEMPLATE* tmpl = (DLGTEMPLATE*)p;
    tmpl->style = WS_POPUP | WS_VISIBLE | WS_CAPTION | WS_SYSMENU
                | DS_CENTER | DS_MODALFRAME;
    tmpl->dwExtendedStyle = 0;
    tmpl->cdit = 3;
    tmpl->x = 0; tmpl->y = 0; tmpl->cx = 200; tmpl->cy = 60;
    p += sizeof(DLGTEMPLATE);
    p = put_word(p, 0);                       /* no menu    */
    p = put_word(p, 0);                       /* default class */
    p = put_wstr(p, STR_TITLE);               /* title      */

    /* EDIT (password input) */
    p = align_dword(p, start);
    {
        DLGITEMTEMPLATE* item = (DLGITEMTEMPLATE*)p;
        item->style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP
                    | ES_AUTOHSCROLL | ES_PASSWORD;
        item->dwExtendedStyle = 0;
        item->x = 10; item->y = 10; item->cx = 180; item->cy = 14;
        item->id = IDC_PWD_EDIT;
        p += sizeof(DLGITEMTEMPLATE);
        p = put_word(p, 0xFFFF);
        p = put_word(p, 0x0081);              /* Edit atom   */
        p = put_word(p, 0);                   /* no text      */
        p = put_word(p, 0);                   /* no cd        */
    }
    /* OK button */
    p = align_dword(p, start);
    {
        DLGITEMTEMPLATE* item = (DLGITEMTEMPLATE*)p;
        item->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON;
        item->dwExtendedStyle = 0;
        item->x = 60;  item->y = 32; item->cx = 50; item->cy = 14;
        item->id = IDOK;
        p += sizeof(DLGITEMTEMPLATE);
        p = put_word(p, 0xFFFF);
        p = put_word(p, 0x0080);              /* Button atom  */
        p = put_wstr(p, STR_OK);
        p = put_word(p, 0);
    }
    /* Cancel button */
    p = align_dword(p, start);
    {
        DLGITEMTEMPLATE* item = (DLGITEMTEMPLATE*)p;
        item->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP;
        item->dwExtendedStyle = 0;
        item->x = 120; item->y = 32; item->cx = 50; item->cy = 14;
        item->id = IDCANCEL;
        p += sizeof(DLGITEMTEMPLATE);
        p = put_word(p, 0xFFFF);
        p = put_word(p, 0x0080);
        p = put_wstr(p, STR_CANCEL);
        p = put_word(p, 0);
    }
    return (size_t)(p - start);
}

/* ============================================================
 * 对话框过程
 * 通过 .lock.data 全局 fn 访问 user32 函数
 * 通过 .lock.data 全局 stub_data 读取密码（v2: SHA-256 hash）
 * ============================================================ */
__attribute__((section(".lock.text"), used, noinline))
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

__attribute__((section(".lock.text"), used, noinline))
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
__attribute__((section(".lock.text"), used, noinline))
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
__attribute__((section(".lock.text"), used, noinline))
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
__attribute__((section(".lock.text"), used, noinline))
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
__attribute__((section(".lock.text"), used, noinline))
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
 *   - 用 jmp 而非 call：不压入返回地址，stub 不返回
 *   - x64: 强制 RSP ≡ 8 mod 16（MSVC ABI 假设 call 进入后栈对齐）
 *       andq $-16, %rsp  → RSP ≡ 0 mod 16
 *       subq $40, %rsp   → 32B shadow space + 8 对齐 = RSP ≡ 8 mod 16
 *       jmpq *reg        → 跳转（不压返回地址）
 *   - x86: 16 对齐（避免 SSE 指令对齐异常，CRT 启动代码可能要求）
 *       andl $-16, %esp
 *       jmp *reg
 *   - __builtin_unreachable 告诉 GCC 函数不返回，避免 fallthrough 警告
 * ============================================================ */
__attribute__((section(".lock.text"), used, noinline))
static void jump_to_oep(void* oep) {
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
    __builtin_unreachable();
}

/* ============================================================
 * 解密 .text 节 + 应用 relocations（stub_entry 与 stub_tls_callback 共用）
 *   返回：1 成功，0 失败
 * ============================================================ */
__attribute__((section(".lock.text"), used, noinline))
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
__attribute__((section(".lock.text"), used, noinline))
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
__attribute__((section(".lock.entry"), used, noinline, optimize("O0")))
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

    /* TLS 代理模式：解密 + 密码校验已在 stub_tls_callback 完成，直接跳 OEP */
    if (stub_data.flags & STUB_FLAG_TLS_PROXY) {
        PEBX* peb = WINLOCK_PEB();
        uint8_t* img_base = (uint8_t*)peb->ImageBaseAddress;
        void* oep = img_base + stub_data.oep_rva;
        clear_fn_pointers();   /* P1-3: 防 dump IAT */
        jump_to_oep(oep);
        /* never returns */
    }

    /* 3. 密码校验
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
     *     CRT 启动代码也会做这事，但 TLS_PROXY 模式下 TLS callbacks 先于 CRT，
     *     所以 stub 必须先做。非 TLS_PROXY 模式重做也无害（仅当默认值时覆盖）。*/
    init_security_cookie();

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
 * TLS callback 代理
 *   builder 检测到原 PE 有 TLS callbacks 时启用此模式：
 *   - builder 在 .lock 节内创建新 TLS directory + callbacks 数组
 *   - callbacks 数组 = [stub_tls_callback, NULL]
 *   - DataDirectory[9] 指向新 TLS directory
 *   - Windows loader 在 EP 之前调用 stub_tls_callback(DLL_PROCESS_ATTACH)
 *
 *   stub_tls_callback 流程：
 *   1. PEB walk 找 kernel32 + 解析函数
 *   2. 弹密码框（仅 DLL_PROCESS_ATTACH 时）
 *   3. 解密 .text + 应用 relocations
 *   4. 调用原 PE 的 TLS callbacks（保存在 stub_data.orig_tls_callbacks）
 *   5. 返回（loader 继续，最终跳 EP = stub_entry，stub_entry 检测 TLS_PROXY
 *      直接跳 OEP）
 *
 *   注意：TLS callback 必须很快返回？实际上 Windows 允许 TLS callback
 *   阻塞（弹 MessageBox 是 OK 的）。
 * ============================================================ */

/* TLS callback 函数类型 */
typedef void (WINAPI *TLS_CALLBACK)(PVOID, DWORD, PVOID);

/* TLS 回调原因 */
#define WINLOCK_DLL_PROCESS_ATTACH 1
#define WINLOCK_DLL_THREAD_ATTACH  2
#define WINLOCK_DLL_THREAD_DETACH  3
#define WINLOCK_DLL_PROCESS_DETACH 0

/* stub_tls_callback 状态：确保解密只做一次（DLL_PROCESS_ATTACH） */
__attribute__((section(".lock.data"), used, aligned(8)))
static volatile int g_tls_decrypted = 0;

/* stub_tls_callback 的定位魔数：builder 在 stub.bin 中搜索此 8 字节，
 * 紧随其后的就是 stub_tls_callback 函数入口。
 *
 * 放在独立 section .lock.tlscbm 中（const 数据不能与函数同 section），
 * stub.ld 把 .lock.tlscbm 紧接在 .lock.text 之后、.lock.tlscb 之前。
 *
 * 用 16 字节数组（magic + zero pad）：因为 stub.ld 的 SUBALIGN(16) 强制
 * 每个子节 16 字节对齐，marker 后必然有填充。让 marker 自身占满 16 字节，
 * function 就紧跟在 marker+16 处（无额外填充），builder 计算 offset = M + 16。 */
__attribute__((section(".lock.tlscbm"), used, aligned(16)))
static const uint64_t g_stub_tls_cb_marker[2] = { STUB_TLS_CB_MAGIC, 0 };

/* TLS callback 必须有特定签名，且放在 .lock.tlscb 节（代码节）
 * Windows loader 通过 IMAGE_TLS_DIRECTORY.AddressOfCallBacks 调用 */
__attribute__((section(".lock.tlscb"), used, noinline))
void WINAPI stub_tls_callback(PVOID hModule, DWORD reason, PVOID reserved) {
    (void)hModule;
    (void)reserved;

    /* 只在 DLL_PROCESS_ATTACH 时执行解密 + 密码校验 */
    if (reason != WINLOCK_DLL_PROCESS_ATTACH) return;

    /* 避免重复执行（理论上 TLS callbacks 只调一次，保险起见） */
    if (g_tls_decrypted) return;
    g_tls_decrypted = 1;

    /* 1. PEB walk 找 kernel32 */
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

    /* 2a. PEB 反调试（P1-2）：TLS callback 阶段也要检测，防调试器在 TLS 阶段 dump
     *     仅当 builder -d 设置 STUB_FLAG_ANTIDEBUG 时启用（默认关闭）*/
    if ((stub_data.flags & STUB_FLAG_ANTIDEBUG) && is_being_debugged())
        fn.ExitProcess(0);

    /* 3. 密码校验（测试模式 / 正常模式） */
    if (stub_data.flags & STUB_FLAG_TEST_MODE) {
        if (!verify_password(STR_TEST_PWD)) goto fail;
    } else {
        if (!prompt_password()) goto fail;
    }

    /* 4. 解密 .text + 应用 relocations */
    if (!decrypt_text_and_reloc()) goto fail;

    /* 4a. 初始化 SecurityCookie — 必须在调用原 TLS callbacks 之前完成
     *     （原 callbacks 可能用 /GS，cookie 仍是默认值会误报 gsfailure）*/
    init_security_cookie();

    /* 5. 调用原 PE 的 TLS callbacks
     *    stub_data.orig_tls_callbacks 是原 PE 的 callbacks 数组 VA
     *    （builder 填入，实际加载后该地址已正确）
     *    数组以 NULL 结尾。
     *    用 uintptr_t 中转避免 int-to-pointer-cast 警告（x86 上 uint64_t -> ptr）。 */
    if (stub_data.orig_tls_callbacks) {
        TLS_CALLBACK* callbacks = (TLS_CALLBACK*)(uintptr_t)stub_data.orig_tls_callbacks;
        while (*callbacks) {
            (*callbacks)(hModule, reason, reserved);
            callbacks++;
        }
    }
    return;

fail:
    fn.ExitProcess(2);
}
