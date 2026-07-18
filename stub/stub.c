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
#include "../config.h"

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
 * 注意：const 与 non-const 不能混在同一个 section，所以单独用 .lock.rdata */
__attribute__((section(".lock.rdata"), used, aligned(2)))
static const wchar_t STR_KERNEL32[] = L"kernel32.dll";
__attribute__((section(".lock.rdata"), used, aligned(2)))
static const wchar_t STR_USER32[]   = L"user32.dll";
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
static const char STR_FN_GETPROCADDRESS[]        = "GetProcAddress";
__attribute__((section(".lock.rdata"), used, aligned(1)))
static const char STR_FN_LOADLIBRARYA[]          = "LoadLibraryA";
__attribute__((section(".lock.rdata"), used, aligned(1)))
static const char STR_FN_VIRTUALPROTECT[]        = "VirtualProtect";
__attribute__((section(".lock.rdata"), used, aligned(1)))
static const char STR_FN_EXITPROCESS[]           = "ExitProcess";
__attribute__((section(".lock.rdata"), used, aligned(1)))
static const char STR_FN_DLGBOXINDIRECTPARAMW[]  = "DialogBoxIndirectParamW";
__attribute__((section(".lock.rdata"), used, aligned(1)))
static const char STR_FN_ENDDIALOG[]             = "EndDialog";
__attribute__((section(".lock.rdata"), used, aligned(1)))
static const char STR_FN_GETDLGITEMTEXTW[]        = "GetDlgItemTextW";
__attribute__((section(".lock.rdata"), used, aligned(1)))
static const char STR_FN_MESSAGEBOXW[]           = "MessageBoxW";
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
    PEBX*   peb = (PEBX*)__readgsqword(0x60);
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
 * stub 入口
 *   链接脚本保证 stub_entry 在 .lock 节起始（offset 0）
 *   builder 设置 AddressOfEntryPoint = .lock_RVA + 0
 * ============================================================ */
__attribute__((section(".lock.entry"), used, noinline, optimize("O0")))
void stub_entry(void) {
    /* 1. PEB walk 找 kernel32（windows 启动时已加载） */
    PVOID k32 = find_module(STR_KERNEL32);
    if (!k32) goto fail;

    /* 2. 解析 kernel32 关键函数 */
    fn.GetProcAddress = (FnGetProcAddress)find_export(k32, STR_FN_GETPROCADDRESS);
    fn.LoadLibraryA  = (FnLoadLibraryA)   find_export(k32, STR_FN_LOADLIBRARYA);
    fn.VirtualProtect = (FnVirtualProtect) find_export(k32, STR_FN_VIRTUALPROTECT);
    fn.ExitProcess   = (FnExitProcess)     find_export(k32, STR_FN_EXITPROCESS);
    if (!fn.GetProcAddress || !fn.LoadLibraryA
        || !fn.VirtualProtect || !fn.ExitProcess)
        goto fail;

    /* 3. 密码校验
     *    - 测试模式（flags & STUB_FLAG_TEST_MODE）：跳过弹框，
     *      直接用硬编码 L"test123" 走 verify_password，验证 v2 hash 路径
     *    - 正常模式：加载 user32，弹 DialogBox 让用户输入 */
    int pwd_ok = 0;
    if (stub_data.flags & STUB_FLAG_TEST_MODE) {
        /* 测试模式：不加载 user32，直接用硬编码密码 */
        pwd_ok = verify_password(STR_TEST_PWD);
    } else {
        /* 正常模式：加载 user32 并弹对话框 */
        HMODULE u32 = fn.LoadLibraryA(STR_USER32_A);
        if (!u32) goto fail;
        fn.DialogBoxIndirectParamW = (FnDialogBoxIndirectParamW)
            fn.GetProcAddress(u32, STR_FN_DLGBOXINDIRECTPARAMW);
        fn.EndDialog          = (FnEndDialog)
            fn.GetProcAddress(u32, STR_FN_ENDDIALOG);
        fn.GetDlgItemTextW    = (FnGetDlgItemTextW)
            fn.GetProcAddress(u32, STR_FN_GETDLGITEMTEXTW);
        fn.MessageBoxW        = (FnMessageBoxW)
            fn.GetProcAddress(u32, STR_FN_MESSAGEBOXW);
        if (!fn.DialogBoxIndirectParamW || !fn.EndDialog
            || !fn.GetDlgItemTextW || !fn.MessageBoxW)
            goto fail;

        /* 4. 在栈上构建对话框模板并显示，密码错误重试 */
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
            if (r == 1) break;          /* 成功 */
            if (r == 0) {                /* Cancel */
                fn.ExitProcess(1);
            }
            /* r == 2: 密码错误，dlg_proc 已弹错误框，重试 */
            retries++;
        } while (retries < max_retries);

        if (r != 1) {
            /* 超过最大重试次数 */
            fn.ExitProcess(2);
        }
        pwd_ok = 1;
    }
    (void)pwd_ok;

    /* 5. 解密 .text 节
     *    PEB.ImageBaseAddress 是真实加载基址（即使被 ASLR 重定位也正确） */
    PEBX*   peb       = (PEBX*)__readgsqword(0x60);
    uint8_t* img_base = (uint8_t*)peb->ImageBaseAddress;
    uint8_t* text_va  = img_base + stub_data.text_rva;
    DWORD    old_prot = 0;

    /* VirtualSize 可能 > RawSize，剩余部分加载时为 0，可直接解密 */
    if (!fn.VirtualProtect(text_va, (SIZE_T)stub_data.text_size,
                           PAGE_READWRITE, &old_prot))
        goto fail;

    xtea_decrypt_buf(text_va, (size_t)stub_data.text_size,
                     (const uint32_t*)stub_data.xtea_key);

    /* 恢复原保护（让 CPU 能执行） */
    fn.VirtualProtect(text_va, (SIZE_T)stub_data.text_size,
                     stub_data.text_protect, &old_prot);

    /* 6. 跳原 OEP */
    void* oep = img_base + stub_data.oep_rva;
    ((void(*)())oep)();
    /* never returns */

fail:
    fn.ExitProcess(2);
    while (1) { /* never reach */ }
}
