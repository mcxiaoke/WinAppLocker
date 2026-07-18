# WinLock 移植建议与实施计划

> 创建日期：2026-07-18
> 依据：[ANALYSIS_REPORT.md](file:///F:/Temp/pe/winlock/ANALYSIS_REPORT.md) 对 12 个 PE 加壳项目的深度分析
> 目标：把其他项目的优秀设计/代码移植到 winlock，按优先级分阶段实施

---

## 0. 移植原则

1. **保持 in-place 加壳架构**：不改变 winlock "加密 .text + 跳 OEP" 的核心模型，不引入反射式 loader 的复杂度
2. **保持 PIC 无 CRT 约束**：所有移植代码必须能在 `-nostdlib -ffreestanding -fno-pic` 下编译，纯 PEB walk + 内联汇编
3. **保持 stub 体积小**：当前 stub.bin 6.5KB，所有移植后总体积不超过 15KB
4. **不引入反 EDR 重型武器**：不抄 syscall / unhook ntdll / GPU VRAM / stack spoofing
5. **每阶段回归测试**：每个 P 级做完后用 hellogui / helloguix86 / hellomingw 三个样本验证

---

## 1. P0 — 立即修复（真实 bug，必修）

### P0-1. SecurityCookie 初始化

**问题**：几乎所有 MSVC 编译的程序启用 `/GS`（默认开），LoadConfig 里有 `SecurityCookie` 字段指向 .data/.bss 的一个 cookie 值。winlock 加密 .text 时没动 .data，但 cookie 的初始值是编译时硬编码的默认值（`0xBB40E64E` x86 / `0x00002B992DDFA232` x64），这是公开已知值。某些情况下会触发 `__report_gsfailure` 终止进程。MPC-BE 的 `WinError 998` 很可能就是这个。

**借鉴来源**：
- [AlushPacker loader.c:931-951](file:///F:/Temp/pe/AlushPacker-main/Packer/loader.c#L931-L951) — 判断逻辑（仅当 cookie 是默认值时才覆盖，避免破坏已初始化的 cookie）
- [peldr loader.c:464-482](file:///F:/Temp/pe/peldr-main/loader.c#L464-L482) — KUSER_SHARED_DATA 熵源（无 API 依赖）

**移植到 winlock**：

1. `config.h` 加字段：
```c
typedef struct {
    /* ... 原有字段 ... */
    uint64_t security_cookie_va;   /* LOAD_CONFIG.SecurityCookie 的 RVA，0 表示无 */
} stub_data_t;
```

2. `builder/builder.c` 在 `pack_main` 里读 `IMAGE_LOAD_CONFIG_DIRECTORY`：
```c
IMAGE_DATA_DIRECTORY* lc_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
if (lc_dir->VirtualAddress != 0 && lc_dir->Size >= 0x58) {
    IMAGE_LOAD_CONFIG_DIRECTORY* lc = (IMAGE_LOAD_CONFIG_DIRECTORY*)(img + RVA_to_offset(img, lc_dir->VirtualAddress));
    if (lc->SecurityCookie != 0) {
        stub_data.security_cookie_va = lc->SecurityCookie;  /* 注意：这是 VA 不是 RVA，已经是绝对地址 */
    }
}
```

3. `stub/stub.c` 在 `decrypt_text_and_reloc` 之后、跳 OEP 之前：
```c
__attribute__((section(".lock.text"), used, noinline))
static void init_security_cookie(PVOID img_base) {
    if (stub_data.security_cookie_va == 0) return;
    ULONG_PTR* cookie_ptr = (ULONG_PTR*)stub_data.security_cookie_va;
    ULONG_PTR default_x64 = 0x00002B992DDFA232ULL;
    ULONG_PTR default_x86 = 0xBB40E64E;
#ifdef _WIN64
    if (*cookie_ptr == default_x64 || *cookie_ptr == 0) {
#else
    if (*cookie_ptr == default_x86 || *cookie_ptr == 0) {
#endif
        /* 用 KUSER_INTERRUPT_TIME (0x7FFE0008) 作熵源，无 API 依赖 */
        volatile ULONGLONG* kuser_interrupt = (volatile ULONGLONG*)0x7FFE0008;
        *cookie_ptr = (ULONG_PTR)img_base ^ *kuser_interrupt;
    }
}
```

4. `stub_entry` 调用：
```c
/* 解密 .text 后 */
init_security_cookie(image_base);
/* 跳 OEP */
```

**工作量**：30 行 C 代码，1h
**测试**：加一个 `/GS` 编译的测试样本，验证加壳后能正常运行

---

### P0-2. 栈对齐跳 OEP

**问题**：[stub.c:685](file:///F:/Temp/pe/winlock/stub/stub.c#L685) `((void(*)())oep)()` 是个 call，编译器会保证调用点对齐，理论上 OK。但 MSVC 编译的 OEP 期望 RSP ≡ 8 mod 16（被 call 进入后状态），stub_entry 末尾的栈状态依赖编译器，某些情况下可能触发 SSE 指令对齐异常。

**借鉴来源**：[peldr loader.c:1144-1152](file:///F:/Temp/pe/peldr-main/loader.c#L1144-L1152)

**移植到 winlock**：

1. `stub/stub.c` 把跳 OEP 改成内联汇编（x64 only）：
```c
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
    /* x86 不需要 shadow space,直接 jmp */
    __asm__ volatile (
        "andl $-16, %%esp\n\t"
        "jmp *%0\n\t"
        : : "r"(oep) : "memory"
    );
#endif
    __builtin_unreachable();  /* 告诉编译器不返回 */
}
```

2. 替换 `stub_entry` 和 `stub_tls_callback` 末尾的 `((void(*)())oep)()` 调用为 `jump_to_oep((void*)oep)`

**工作量**：10 行内联汇编，0.3h
**测试**：hellogui / helloguix86 / hellomingw 三个样本回归

---

## 2. P1 — 短期增强（反静态分析，3-5h）

### P1-1. API 哈希化

**问题**：winlock 的 `.lock.rdata` 里有明文 API 名 `"GetProcAddress"` / `"LoadLibraryA"` / `"VirtualProtect"` / `"ExitProcess"` / `"DialogBoxIndirectParamW"` / `"EndDialog"` / `"GetDlgItemTextW"` / `"MessageBoxW"`，是静态分析的低挂果实，`strings` 一抓全是 API 名。模块名 `"kernel32.dll"` / `"user32.dll"` 也是明文。

**借鉴来源**：
- [peldr loader.c:99-114](file:///F:/Temp/pe/peldr-main/loader.c#L99-L114) + [hash.py:43-60](file:///F:/Temp/pe/peldr-main/hash.py) — DJB15 + 大小写折叠 + Python 离线生成
- [peldr loader.c:120-140](file:///F:/Temp/pe/peldr-main/loader.c#L120-L140) — 模块名 UINT64 一次比较
- [Maldev Utilities.c:12-45](file:///F:/Temp/pe/AlushPacker-main/RunPeFile/Utilities.c#L12-L45) — FNV-1a（备选）

**移植到 winlock**：

1. 选 **DJB15**（peldr 方案，最简单）：
```c
/* hash: 大小写不敏感 DJB15 */
__attribute__((section(".lock.text"), used, noinline))
static uint32_t hash_api(const char* s) {
    uint32_t h = 1993;  /* HASH_STR_SEED */
    while (*s) {
        char c = *s++;
        if (c >= 'A' && c <= 'Z') c += 32;  /* 大写转小写 */
        h = ((h << 4) - h) + (uint32_t)(uint8_t)c;  /* h * 15 + c */
    }
    return h;
}
```

2. `find_export` 改为按 hash 查找：
```c
__attribute__((section(".lock.text"), used, noinline))
static PVOID find_export_by_hash(PVOID mod, uint32_t want_hash) {
    /* ... PE 解析 ... */
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* n = (const char*)(base + names[i]);
        if (hash_api(n) == want_hash) {
            DWORD rva = funcs[ords[i]];
            if (rva >= exp_start && rva < exp_end) return NULL;
            return base + rva;
        }
    }
    return NULL;
}
```

3. 预计算 hash 常量（用 Python 离线算）：
```c
/* 自动生成,不要手算 */
#define HASH_GETPROCADDRESS          0x????????U  /* hash_api("GetProcAddress") */
#define HASH_LOADLIBRARYA            0x????????U
#define HASH_VIRTUALPROTECT          0x????????U
#define HASH_EXITPROCESS             0x????????U
#define HASH_DIALOGBOXINDIRECTPARAMW 0x????????U
#define HASH_ENDDIALOG               0x????????U
#define HASH_GETDLGITEMTEXTW         0x????????U
#define HASH_MESSAGEBOXW             0x????????U
```

4. `stub_entry` 解析 API 时用 hash：
```c
fn.GetProcAddress = (FnGetProcAddress)find_export_by_hash(k32, HASH_GETPROCADDRESS);
fn.LoadLibraryA   = (FnLoadLibraryA)find_export_by_hash(k32, HASH_LOADLIBRARYA);
/* ... */
```

5. 模块名匹配用 UINT64 一次比较（peldr 风格）：
```c
/* kernel32.dll 9 字节 + NULL = 10 字节,补齐到 16 字节做两次 UINT64 比较 */
/* 或简单点用 hash 匹配 */
__attribute__((section(".lock.text"), used, noinline))
static PVOID find_module_by_hash(uint32_t want_hash) {
    PEBX* peb = WINLOCK_PEB();
    LDRCNT* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* curr = head->Flink;
    while (curr != head) {
        LDRENT* e = (LDRENT*)curr;
        if (e->BaseDllName.Buffer) {
            /* 把 wchar 模块名转 ANSI 后 hash 比较 */
            /* 或直接对 wchar 做 hash（大小写不敏感） */
            if (hash_module_wstr(e->BaseDllName.Buffer) == want_hash) {
                return e->DllBase;
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}
```

6. 删除 `.lock.rdata` 里的 `STR_FN_*` 明文字符串和 `STR_KERNEL32` / `STR_USER32` 明文模块名（或保留但不用）

**工作量**：1.5h
**测试**：加壳后用 `strings stub_locked.exe | grep -i getprocaddress` 验证无明文

---

### P1-2. PEB 反调试

**问题**：winlock 当前 0 反调试，调试器 attach 后可以单步过密码框、dump .text 明文。

**借鉴来源**：
- [TinyLoad TinyLoad.cpp:261-273](file:///F:/Temp/pe/TinyLoad-main/TinyLoad.cpp#L261-L273) — PEB.BeingDebugged + NtGlobalFlag + IsDebuggerPresent + CheckRemoteDebuggerPresent
- [peldr loader.c:858-907](file:///F:/Temp/pe/peldr-main/loader.c#L858-L907) — KdDebuggerEnabled + PEB.BeingDebugged + ProcessParameters.DebugFlags（零 API 依赖）

**移植到 winlock**（选零依赖方案）：

```c
/* 反调试检查：检测到调试器返回 1 */
__attribute__((section(".lock.text"), used, noinline))
static int is_being_debugged(void) {
    PEBX* peb = WINLOCK_PEB();
    
    /* 1. PEB.BeingDebugged */
    if (peb->BeingDebugged) return 1;
    
    /* 2. NtGlobalFlag (PEB+0xBC x64 / +0x68 x86) */
    /*    FLG_HEAP_ENABLE_TAIL_CHECK | FREE_CHECK | VALIDATE_PARAMETERS = 0x70 */
#ifdef _WIN64
    uint32_t nt_global_flag = *(uint32_t*)((uint8_t*)peb + 0xBC);
#else
    uint32_t nt_global_flag = *(uint32_t*)((uint8_t*)peb + 0x68);
#endif
    if (nt_global_flag & 0x70) return 1;
    
    /* 3. KdDebuggerEnabled (KUSER_SHARED_DATA+0x2D4) */
    volatile uint8_t* kd_debugger_enabled = (volatile uint8_t*)0x7FFE02D4;
    if (*kd_debugger_enabled) return 1;
    
    return 0;
}
```

在 `stub_entry` 和 `stub_tls_callback` 开头调用：
```c
if (is_being_debugged()) {
    /* 静默退出,不给调试器任何提示 */
    fn.ExitProcess(0);
}
```

**注意**：PEB.BeingDebugged 可以被调试器 patch 绕过，但 `KdDebuggerEnabled` 在 KUSER_SHARED_DATA 里，userland 改不了。`NtGlobalFlag` 也是 PEB 之外难绕过的。

**工作量**：30 行 C，0.5h
**测试**：加壳后用 x64dbg attach，验证程序退出；不带调试器正常运行

---

### P1-3. 函数指针清零（防 dump IAT）

**问题**：winlock 的 `fn` 结构体在 `.lock.data` 节里，解密 .text 后跳 OEP 之前如果不清理，dump 出来的内存能看到完整的函数指针表，分析者一眼就能看出 stub 用了哪些 API。

**借鉴来源**：[peldr loader.c:1107-1126](file:///F:/Temp/pe/peldr-main/loader.c#L1107-L1126)

**移植到 winlock**：

在 `stub_entry` 跳 OEP 之前（`init_security_cookie` 之后）：
```c
/* 清零所有运行时解析的函数指针,防 dump IAT */
fn.LoadLibraryA = NULL;
fn.GetProcAddress = NULL;
fn.VirtualProtect = NULL;
fn.ExitProcess = NULL;
fn.DialogBoxIndirectParamW = NULL;
fn.EndDialog = NULL;
fn.GetDlgItemTextW = NULL;
fn.MessageBoxW = NULL;
```

**注意**：必须在跳 OEP 之前做，不能在弹密码框之前（那时还需要用 fn.DialogBoxIndirectParamW 等）。

**工作量**：8 行 C，0.2h
**测试**：加壳后运行，验证程序正常；用 Process Hacker dump 内存验证 fn 表为 NULL

---

## 3. P2 — 中期增强（可选，5-10h）

### P2-1. PBKDF2-HMAC-SHA256 KDF 升级

**问题**：当前 `SHA-256(pwd + salt)` 无迭代，GPU 暴力破解成本极低。

**方案**：复用 winlock 已有 SHA-256 实现（`stub/sha256.h`），实现 PBKDF2-HMAC-SHA256 100000 轮。

```c
/* PBKDF2-HMAC-SHA256 */
__attribute__((section(".lock.text"), used, noinline))
static void pbkdf2_hmac_sha256(
    const uint8_t* pwd, size_t pwd_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t* out, size_t out_len)
{
    /* HMAC(K, m) = H(K ^ opad || H(K ^ ipad || m)) */
    /* PBKDF2: U1 = HMAC(pwd, salt || INT(1)), U2 = HMAC(pwd, U1), ... */
    /* DK = U1 ^ U2 ^ ... ^ Uc */
    /* 实现略,约 80 行 */
}
```

**工作量**：2h
**影响**：stub.bin 增大约 2KB（SHA-256 已有，只加 PBKDF2 循环）

---

### P2-2. IAT Camouflage

**借鉴来源**：[AtomPePacker IatCamouflage.h:27-73](file:///F:/Temp/pe/AtomPePacker-NUL0x4C-main/PP64Stub/IatCamouflage.h#L27-L73)

**方案**：在 stub_entry 跳 OEP 之前，调用一堆"看起来合法"的 user32/menu/ole32 API（传 NULL 参数让它们立刻失败返回），让 dump 出来的 IAT 看起来像普通 GUI 程序。

```c
__attribute__((section(".lock.text"), used, noinline))
static void iat_camouflage(void) {
    /* 加载 user32.dll(已加载) 和 ole32.dll */
    HMODULE u32 = fn.LoadLibraryA("user32.dll");  /* 已加载,只 +1 refcount */
    HMODULE o32 = fn.LoadLibraryA("ole32.dll");
    
    /* 解析并调用一堆合法 API(NULL 参数,立刻失败返回) */
    /* 这些调用本身没意义,只是让 IAT 里出现这些 import */
    typedef void* (WINAPI *FnGetMenu)(HWND);
    /* ... */
}
```

**注意**：这会增加 stub.bin 体积（要解析更多 API），且要在跳 OEP 之前清零这些函数指针。

**工作量**：1.5h
**优先级**：低（对密码保护场景意义不大，主要是反静态分析）

---

### P2-3. stub-key 派生加密 stub_data

**借鉴来源**：[TinyLoad TinyLoad.cpp:1830-1833](file:///F:/Temp/pe/TinyLoad-main/TinyLoad.cpp#L1830-L1833)

**问题**：winlock 的 `stub_data` 结构在 `.lock.data` 节里，包含 `xtea_key` / `pwd_hash` / `salt` / `oep_rva` / `text_rva` 等敏感字段，可被 strings 抓或 PE 解析器直接读。

**方案**：builder 阶段从 stub.bin 的某个固定偏移（如 .lock.text 的前 256 字节）派生 64 位 key，XOR 加密 stub_data 后半部分敏感字段。stub 运行时用自身字节派生同样 key 解密。

```c
/* builder 阶段 */
uint64_t stub_key = 0x9E3779B97F4A7C15ULL;
for (size_t i = 0x100; i < 0x200 && i < stub_size; i++) {
    stub_key = (stub_key ^ stub[i]) * 0x9E3779B97F4A7C15ULL;
}
/* XOR 加密 stub_data.xtea_key / pwd_hash / salt / oep_rva / text_rva */
```

```c
/* stub 运行时 */
__attribute__((section(".lock.text"), used, noinline))
static uint64_t derive_stub_key(void) {
    /* 用 stub_entry 自己的地址反推 .lock.text 起始地址 */
    extern uint8_t lock_text_start[];  /* linker script 定义 */
    uint64_t key = 0x9E3779B97F4A7C15ULL;
    for (size_t i = 0; i < 0x100; i++) {
        key = (key ^ lock_text_start[0x100 + i]) * 0x9E3779B97F4A7C15ULL;
    }
    return key;
}

/* 解密 stub_data 敏感字段 */
static void decrypt_stub_data(void) {
    uint64_t key = derive_stub_key();
    uint8_t* p = (uint8_t*)&stub_data.xtea_key;
    for (size_t i = 0; i < sizeof(stub_data.xtea_key) + sizeof(stub_data.salt) + sizeof(stub_data.pwd_hash) + ...; i++) {
        p[i] ^= (uint8_t)(key >> ((i * 3) & 63));
    }
}
```

**工作量**：2h
**影响**：stub.bin 不增大（只加密现有字段）

---

### P2-4. Canary Corridor（.text 完整性校验）

**借鉴来源**：[TinyLoad TinyLoad.cpp:1062-1112](file:///F:/Temp/pe/TinyLoad-main/TinyLoad.cpp#L1062-L1112)

**方案**：builder 阶段在 .text 中随机选 N 个偏移（如 8 个），记录 `can_off[i]` 和 `can_exp[i] = actual[i] ^ prev_actual`（链式）。stub 解密 .text 后逐个校验，任何字节被 patch 立即失败。

```c
typedef struct {
    uint32_t can_off[8];
    uint8_t  can_exp[8];
} canary_t;
```

**工作量**：1.5h
**优先级**：低（防 patch，但对密码保护场景意义不大）

---

### P2-5. adasm 花指令

**借鉴来源**：[pe-packer adasm.cpp:7-25](file:///F:/Temp/pe/pe-packer-master/pe-packer/core/adasm.cpp#L7-L25)

**方案**：在 stub 的关键路径（如 `verify_password` / `decrypt_text_and_reloc` 入口）插入 `jz label; jnz label; db 0xE9` 4 字节花指令，干扰线性反汇编器。

```c
#define JUNK_4BYTES __asm__ volatile( \
    "jz 1f\n\t" \
    "jnz 1f\n\t" \
    ".byte 0xE9\n\t" \
    "1:\n\t" \
)
```

**工作量**：0.5h
**影响**：stub.bin 不增大（4 字节花指令）

---

### P2-6. .lock 节名 scramble

**借鉴来源**：[TinyLoad TinyLoad.cpp:1682-1695](file:///F:/Temp/pe/TinyLoad-main/TinyLoad.cpp#L1682-L1695)

**方案**：builder 阶段把 `.lock` 节名改成 `.text` / `.rdata` / `.idata` 等常见名（注意 features 不变，只改 Name 字段 8 字节）。

```c
/* builder.c */
const char* fake_names[] = {".text", ".rdata", ".idata", ".reloc"};
int idx = rand() % 4;
memcpy(sect.Name, fake_names[idx], 8);
```

**注意**：这会让 PE 出现两个同名节（`.text` 原 + `.text` 新），部分 PE 解析器会警告，但不影响运行。

**工作量**：0.3h

---

## 4. P3 — 不建议（场景不符或过度设计）

| 项 | 来源 | 不建议原因 |
|----|------|----------|
| AES-NI CTR 加密 | Maldev | 需 CPUID 检测 + 软件 fallback，与 `-mno-sse2` 冲突；当前 XTEA 够用 |
| VEH 页级加密 | TinyLoad | TLS_PROXY 模式下 VEH 未初始化；复杂度高 |
| 直接 syscall | TinyLoad | 反 EDR 专用，winlock 不是反 EDR 壳；in-place 只需 4 个 API |
| Argon2 KDF | pe-packer-rust | stub.bin 增大 30KB，不值 |
| ApiSetMap 解析 | Maldev | winlock 找 kernel32.dll 不需要（仍是真实模块） |
| GPU VRAM 隐藏 | Maldev | D3D11 依赖过重 |
| Stack Spoofing | Maldev | 反 EDR 重型武器 |
| TrapSyscalls | Maldev | 反 EDR 重型武器 |
| DWT 隐写 | Maldev | 反静态分析过度设计 |
| \KnownDlls\ unhook | AtomPePacker | in-place 加壳场景 ntdll hook 不是核心问题 |
| PE header erasure | peldr | in-place 加壳下 OS loader 还需要 header，慎用 |
| x86 SEH patch | AlushPacker | 硬编码偏移不可用，不同 Windows 版本会变 |
| RtlAddFunctionTable | AlushPacker 等 | in-place 不需要，OS loader 已注册 |
| 转发导出解析 | AlushPacker | 反射式才需要 |
| TLS index 分配 | AlushPacker | 反射式才需要 |
| LdrpPatchDataTableEntry | AlushPacker | 反射式才需要 |

---

## 5. 实施步骤与回归测试

### 阶段 1：P0 修复（约 1.5h）

1. ✅ 实现 P0-1 SecurityCookie 初始化
2. ✅ 实现 P0-2 栈对齐跳 OEP
3. ✅ `make all all-x86` 编译
4. ✅ 回归测试：
   - `samples/hellogui.exe` → 加壳 → 运行 → 输密码 → 弹框 ✓
   - `samples/helloguix86.exe` → 加壳 → 运行 → 输密码 → 弹框 ✓
   - `samples/hellomingw.exe`（TLS callbacks）→ 加壳 → 运行 → 输密码 → 弹框 ✓
5. ✅ 如有 `/GS` 编译的样本，额外测试（验证 cookie 初始化生效）

### 阶段 2：P1 增强（约 3h）

1. ✅ 实现 P1-1 API 哈希化（DJB15 + 模块名 hash）
2. ✅ 实现 P1-2 PEB 反调试
3. ✅ 实现 P1-3 函数指针清零
4. ✅ `make all all-x86` 编译
5. ✅ 回归测试：
   - hellogui / helloguix86 / hellomingw 三个样本正常加壳运行
   - `strings <locked.exe> | grep -i getprocaddress` → 无输出（验证 API hash 生效）
   - 用 x64dbg attach 到加壳后的 exe → 程序立即退出（验证反调试生效）
   - 正常运行（不带调试器）→ 程序正常运行
   - 用 Process Hacker dump 内存 → fn 表为 NULL（验证清零生效）

### 阶段 3：P2 增强（可选，约 8h）

按需选择实施 P2-1 ~ P2-6，每个做完后回归测试。

---

## 6. 风险与回滚

### 6.1 P0 风险

| 风险 | 影响 | 缓解 |
|------|------|------|
| SecurityCookie VA 解析错误 | 写错地址导致崩溃 | builder 校验 `lc_dir->Size >= 0x58` + cookie VA 在 ImageBase 范围内 |
| 栈对齐汇编语法错误 | stub.bin 编译失败 | `make all` 验证 |

### 6.2 P1 风险

| 风险 | 影响 | 缓解 |
|------|------|------|
| API hash 算法实现错误 | find_export_by_hash 失败 → stub_entry 无法解析 API → 程序崩溃 | 用 Python 离线算 hash 验证一致 |
| 模块名 hash 不匹配 | find_module 失败 | 保留原 find_module（wstr_ieq_n）作为 fallback |
| PEB 反调试误判 | 正常运行时被当成调试 → 程序退出 | 三个检查项都用 `&` 而非 `==`，避免误判 |
| 函数指针清零时机错误 | 跳 OEP 后 OEP 还需要这些 API → 崩溃 | 必须在 jump_to_oep 之前最后一刻清零 |

### 6.3 回滚

每个 P 级改动用 git commit 单独提交，方便回滚。如果某个 P 级导致回归测试失败，`git revert` 回滚到上一个稳定状态。

---

## 7. 预期效果

实施 P0 + P1 后，winlock 将具备：

| 能力 | 实施前 | 实施后 |
|------|--------|--------|
| /GS 程序兼容性 | ✗ 随机崩溃 | ✓ 正常运行 |
| 栈对齐 | ✗ 偶发 SSE 崩溃 | ✓ 标准 16 字节对齐 |
| API 名明文 | ✗ 8 个明文 API 名 | ✓ 全部 hash 化 |
| 模块名明文 | ✗ "kernel32.dll" 明文 | ✓ hash 匹配 |
| 反调试 | ✗ 无 | ✓ 3 项 PEB 检查 |
| 防 dump IAT | ✗ fn 表完整暴露 | ✓ 跳 OEP 前清零 |

**stub.bin 体积预估**：6.5KB → 约 8KB（增加 API hash 函数 + 反调试 + 清零，约 1.5KB）

---

**文档版本**：1.0
**最后更新**：2026-07-18
