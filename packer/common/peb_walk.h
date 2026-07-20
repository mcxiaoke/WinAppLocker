/*
 * winlock/common/peb_walk.h - PEB 类型定义 + DJB15 hash API 解析
 *
 * 从 stub.c 和 loader.c 抽取的共享 PEB 遍历代码。
 *
 * 使用方式（两段式包含，保证 stub 函数在 .lock.text 节中的顺序不变）：
 *
 *   // 第一次包含：仅类型定义（放在文件顶部，供 find_module 等早期函数使用）
 *   #include "peb_walk.h"
 *
 *   // ... 其他函数 ...
 *
 *   // 第二次包含：函数实现（放在原始 hash 函数的位置）
 *   #define PEB_WALK_IMPLEMENT
 *   #include "peb_walk.h"
 *
 * loader.c / builder 等主机程序只需包含一次（不定义 PEB_WALK_IMPLEMENT），
 * 获取类型定义即可，hash 函数不会被定义（static inline 未使用时不会生成代码）。
 *
 * 所有函数用 static inline 避免 stub.c 和 loader.c 同时包含时符号冲突。
 * DJB15 hash 常量（HASH_MOD_KERNEL32_DLL 等）从 config.h 引用。
 */
#ifndef PEB_WALK_H
#define PEB_WALK_H

#include <stdint.h>
#include <windows.h>
#include "config.h"

/* ============================================================
 * PEB 类型定义
 *
 * 基于 loader.c 的更完整定义（PEB_LDR_DATA_X / LDR_DATA_TABLE_ENTRY_X），
 * stub.c 和 loader.c 共用。结构布局与 Windows 内核一致，x86/x64 都能正确解析。
 * ============================================================ */

/* 简化的 LIST_ENTRY（与 windows.h 的 LIST_ENTRY 布局一致） */
typedef struct _MY_LIST_ENTRY {
    struct _MY_LIST_ENTRY* Flink;
    struct _MY_LIST_ENTRY* Blink;
} MY_LIST_ENTRY;

/* PEB_LDR_DATA（简化版，仅含需要的字段） */
typedef struct _PEB_LDR_DATA_X {
    ULONG      Length;                              /* +0x00 */
    UCHAR      Initialized;                         /* +0x04 */
    PVOID      SsHandle;                            /* +0x08 */
    MY_LIST_ENTRY InLoadOrderModuleList;            /* +0x10 */
    MY_LIST_ENTRY InMemoryOrderModuleList;          /* +0x20 */
    MY_LIST_ENTRY InInitializationOrderModuleList;  /* +0x30 */
} PEB_LDR_DATA_X;

/* PEB（简化版，仅含前几个字段）
 *   offset 0x02: BeingDebugged
 *   offset 0x68(x86)/0xBC(x64): NtGlobalFlag
 *   Ldr 是 PVOID，调用方需 cast 为 PEB_LDR_DATA_X*（与 loader.c 一致） */
typedef struct {
    UCHAR  a, b, c, d;       /* offset 0-3: InheritedAddressSpace 等  */
    PVOID  Mutant;           /* offset 8 (x64) / 4 (x86) */
    PVOID  ImageBaseAddress; /* offset 16 (x64) / 8 (x86) */
    PVOID  Ldr;              /* offset 24 (x64) / 12 (x86) -> PEB_LDR_DATA */
} PEBX;

/* UNICODE_STRING 兼容类型（与 Windows UNICODE_STRING 布局一致） */
typedef struct { USHORT Length; USHORT MaxLength; PWSTR Buffer; } USTR;

/* LDR_DATA_TABLE_ENTRY（简化版，仅含需要的字段）
 *
 * 注意：偏移注释是 x64 下的（PVOID=8B, MY_LIST_ENTRY=16B）。
 * x86 上 PVOID/MY_LIST_ENTRY 都是 4B，编译器自动生成更小的偏移。
 *
 *   x64 布局：                         x86 布局（Windows 实际）：
 *   InLoadOrderLinks        +0x00      InLoadOrderLinks        +0x00
 *   InMemoryOrderLinks      +0x10      InMemoryOrderLinks      +0x08
 *   InInitializationOrderLinks +0x20  InInitializationOrderLinks +0x10
 *   DllBase                 +0x30      DllBase                 +0x18
 *   EntryPoint              +0x38      EntryPoint              +0x1c
 *   SizeOfImage             +0x40      SizeOfImage             +0x20
 *   _pad1                   +0x44      (无 padding，USTR.Buffer 是 4B 自然对齐)
 *   FullDllName             +0x48      FullDllName             +0x24
 *   BaseDllName             +0x58      BaseDllName             +0x2c
 *
 * 关键 bug 历史：
 *   原代码无条件 ULONG _pad1，导致 x86 上 BaseDllName 错位 4 字节。
 *   stub_x86 运行时 hash_wstr_lower 读 BaseDllName.Buffer 实际读到 +0x34，
 *   而 Windows 在 +0x30，读到错误指针值 -> AV 0xC0000005。
 *   x64 不受影响（_pad1 在 x64 上是必需的，对齐 FullDllName 到 8B 边界）。 */
typedef struct _LDR_DATA_TABLE_ENTRY_X {
    MY_LIST_ENTRY InLoadOrderLinks;          /* +0x00 */
    MY_LIST_ENTRY InMemoryOrderLinks;        /* +0x10 (x64) / +0x08 (x86) */
    MY_LIST_ENTRY InInitializationOrderLinks;/* +0x20 (x64) / +0x10 (x86) */
    PVOID         DllBase;                   /* +0x30 (x64) / +0x18 (x86) */
    PVOID         EntryPoint;                /* +0x38 (x64) / +0x1c (x86) */
    ULONG         SizeOfImage;               /* +0x40 (x64) / +0x20 (x86) */
#ifdef _WIN64
    ULONG         _pad1;                     /* +0x44 对齐 FullDllName 到 8B 边界（x64 only） */
#endif
    USTR          FullDllName;               /* +0x48 (x64) / +0x24 (x86) */
    USTR          BaseDllName;               /* +0x58 (x64) / +0x2c (x86) */
} LDR_DATA_TABLE_ENTRY_X;

/* PEB 访问：x64 用 gs:[0x60]，x86 用 fs:[0x30]。
 * PVOID 自动按架构变大小（8B/4B），PEBX/LDR_DATA_TABLE_ENTRY_X 用 PVOID/MY_LIST_ENTRY，
 * 默认对齐与 Windows 内核结构一致，x86/x64 都能正确解析。 */
#ifdef _WIN64
#define WINLOCK_PEB()  ((PEBX*)__readgsqword(0x60))
#else
#define WINLOCK_PEB()  ((PEBX*)(uintptr_t)__readfsdword(0x30))
#endif

#endif /* PEB_WALK_H */


/* ============================================================
 * 函数实现（仅当 PEB_WALK_IMPLEMENT 定义时包含）
 *
 *   DJB15 hash: h = 1993; h = ((h<<4) - h) + c  即 h = h*15 + c
 *   大小写不敏感：ASCII_FOLD_MASK = ('A' <= c <= 'Z') ? 0x20 : 0
 *   模块名（wchar）取低 8 位当 ASCII 处理（系统 DLL 名都是 ASCII）
 *   Hash 常量由 tools/gen_api_hash.py 离线生成，写入 config.h
 *
 *   此段在 include guard 之外，允许同一翻译单元多次包含 peb_walk.h：
 *   第一次（顶部）获取类型，第二次（原始位置）通过 PEB_WALK_IMPLEMENT 获取函数。
 * ============================================================ */
#ifdef PEB_WALK_IMPLEMENT

/* PIC stub 模式：函数进 .lock.text 节；host 模式：普通 static inline
 * 节名约定（见 winlock_compat.h）：
 *   - MSVC: .lock$text（用 #pragma code_seg，/MERGE 进 .lock）
 *   - GCC:  .lock.text（stub.ld KEEP 保留） */
#ifdef WINLOCK_PIC
  #ifdef _MSC_VER
    #define WINLOCK_PEBWALK_FN __pragma(code_seg(".lock$text")) __declspec(noinline)
  #else
    #define WINLOCK_PEBWALK_FN __attribute__((section(".lock.text"), used, noinline))
  #endif
#else
  #define WINLOCK_PEBWALK_FN
#endif

/* DJB15 大小写不敏感 ASCII hash */
WINLOCK_PEBWALK_FN
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
WINLOCK_PEBWALK_FN
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
WINLOCK_PEBWALK_FN
static PVOID find_module_by_hash(uint32_t want_hash) {
    PEBX*   peb = WINLOCK_PEB();
    PEB_LDR_DATA_X* ldr = (PEB_LDR_DATA_X*)peb->Ldr;
    MY_LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    MY_LIST_ENTRY* curr = head->Flink;
    while (curr != head) {
        LDR_DATA_TABLE_ENTRY_X* e = (LDR_DATA_TABLE_ENTRY_X*)curr;
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
WINLOCK_PEBWALK_FN
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

#undef WINLOCK_PEBWALK_FN
#undef PEB_WALK_IMPLEMENT
#endif /* PEB_WALK_IMPLEMENT */
