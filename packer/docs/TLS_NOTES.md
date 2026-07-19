# 反射式 PE Loader 的 TLS 处理：原理、踩坑与最终方案

> 创建日期：2026-07-19
> 适用范围：`packer/reflective/loader.c` 的 TLS 实现
> 参考项目：`F:\Temp\pe\PELoader3`、`F:\Temp\pe\Fatpack-main`、`F:\Temp\pe\AlushPacker-main`、`F:\Temp\pe\PolyEngine-master`
> 参考文章：<https://maskray.me/blog/2021-02-14-all-about-thread-local-storage>（ELF 平台 TLS 详解，本文聚焦 Windows PE 平台）

---

## 0. 为什么反射式 Loader 必须专门处理 TLS

普通 PE 由 Windows OS loader（`ntdll!LdrpInitializeProcess` 等内部例程）加载时，OS 会自动完成静态 TLS 的全部初始化：

1. 给每个含 `IMAGE_DIRECTORY_ENTRY_TLS` 的模块分配一个 **TLS index**（slot 编号）
2. 为主线程分配 **TLS 数据块**，复制 `StartAddressOfRawData..EndAddressOfRawData` 模板，剩余部分用 `SizeOfZeroFill` 填零
3. 把数据块指针写入 `TEB->ThreadLocalStoragePointer[index]`（以下简称 `TLP[index]`）
4. 此后每个新线程创建时，OS 同样会按模板分配新数据块并设置 `TLP[index]`
5. 在 OEP 之前，按 `AddressOfCallBacks` 数组顺序调用各 TLS callback（reason=`DLL_PROCESS_ATTACH`）
6. 此后每个新线程创建/退出时，自动调用 callbacks（reason=`DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH`）

**反射式 loader 用 `VirtualAlloc` 自己映射 PE**，OS 完全不知道这块内存的存在，上述 6 件事一件都不会做。如果不手动补齐，依赖 TLS 的程序（Rust、Delphi、MinGW CRT、VS CRT `/GS`）会出现各种花式崩溃。

---

## 1. PE TLS 结构详解

### 1.1 IMAGE_TLS_DIRECTORY（32/64 位）

```c
typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG StartAddressOfRawData;   // TLS 模板起始 VA（绝对地址，需重定位）
    ULONGLONG EndAddressOfRawData;     // TLS 模板结束 VA
    ULONGLONG AddressOfIndex;          // 指向 ULONG，存放 TLS index（OS 加载器写入）
    ULONGLONG AddressOfCallBacks;      // TLS callback 函数指针数组 VA，NULL 结尾
    ULONG     SizeOfZeroFill;          // 模板之后的零填充字节数
    ULONG     Characteristics;         // 保留
} IMAGE_TLS_DIRECTORY64;
```

几个关键点容易踩坑：

| 字段 | 易错点 |
|---|---|
| `StartAddressOfRawData` / `EndAddressOfRawData` | 是 **VA（绝对地址）**，不是 RVA。反射式 loader 应用重定位后，这两个字段已指向目标 PE 内存中的真实模板地址，可直接 `memcpy` |
| `AddressOfIndex` | 也是 VA，指向一个 `ULONG` 变量。OS 加载器在这里写入分配的 TLS index。反射式 loader 若手动设为 0，要保证目标 PE 编译时 `__tls_index` 也内联为 0 |
| `AddressOfCallBacks` | VA，指向 callback 指针数组。每个指针也是 VA（应用重定位后即真实地址）。数组以 `NULL` 结尾 |
| `SizeOfZeroFill` | 模板之后还要补零多少字节。TLS 总大小 = `(EndAddressOfRawData - StartAddressOfRawData) + SizeOfZeroFill` |

### 1.2 TEB 与 ThreadLocalStoragePointer

每个线程的 TEB（Thread Environment Block）里有一个指针 `ThreadLocalStoragePointer`（简称 TLP），指向一个 `PVOID[]` 数组：

- **x64**: `TEB+0x58` 保存 TLP 指针，可用 `__readgsqword(0x58)` 读取
- **x86**: `TEB+0x2C` 保存 TLP 指针，可用 `__readfsdword(0x2C)` 读取

TLP 数组按 TLS index 索引：`TLP[index]` 就是当前线程对应模块的 TLS 数据块指针。

代码里访问 TLS 变量时（如 `__declspec(thread) int x;`），编译器生成的指令大致是：

```asm
; x64 假设 __tls_index = 0
mov rax, gs:[0x58]      ; rax = TLP
mov eax, [rax + offset] ; 读 TLP[0] + offset 处的 TLS 变量
```

### 1.3 TLS Callback 签名

```c
typedef VOID (NTAPI *PIMAGE_TLS_CALLBACK)(
    PVOID DllHandle,
    DWORD Reason,     // DLL_PROCESS_ATTACH / DLL_THREAD_ATTACH / DLL_THREAD_DETACH / DLL_PROCESS_DETACH
    PVOID Reserved
);
```

回调时机：

| Reason | 触发时机 | OS 是否自动调用 |
|---|---|---|
| `DLL_PROCESS_ATTACH` (1) | 进程主线程初始化期间，OEP 之前 | ✓ |
| `DLL_THREAD_ATTACH` (2) | 进程运行期间任何新线程创建时 | ✓ |
| `DLL_THREAD_DETACH` (3) | 任何线程退出时（含主线程） | ✓ |
| `DLL_PROCESS_DETACH` (0) | 进程退出时 | ✓ |

**关键**：TLS callback 在 OEP **之前**就被调用，且会伴随每个新线程触发。这是它和普通 ctor / DllMain 的本质区别。

---

## 2. 反射式 Loader 的 TLS 难题分解

### 2.1 难题 A：主线程 TLS 数据未初始化

**症状**：目标 PE 跳到 OEP 后立刻 NULL pointer call，或 `__security_init_cookie` 读到错误值。

**根因**：OS 加载器只为 stub 自己的 TLS 目录分配了数据块并写入 `TLP[0]`（stub 的 TLS index 也是 0）。目标 PE 内联的 `__tls_index=0`，访问 `TLP[0]+offset` 读到的是 stub 的 TLS 模板（通常只有 8 字节），而非目标 PE 的 TLS 模板（可能 700+ 字节）。

**修复**：在 `init_tls_data()` 中：

1. `VirtualAlloc` 分配目标 PE 的 TLS 数据块（大小 = `raw_size + SizeOfZeroFill`）
2. 从目标 PE 内存复制 `raw_size` 字节模板
3. 设置 `TLP[0] = block`（覆盖 stub 的小数据块）
4. 设置 `tls->AddressOfIndex` 指向的 DWORD 为 0（与代码内联的 `__tls_index=0` 匹配）

### 2.2 难题 B：新线程 TLS 数据越界（CC-Switch / Rust 崩溃）

**症状**：CC-Switch（Rust/Tauri 程序）反射式加载后，GUI 启动 OK，但创建工作线程时立即触发：

```
STATUS_STACK_BUFFER_OVERRUN (0xC0000409)
fatal runtime error: current thread handle already set during thread spawn, aborting
```

**诊断过程**（用 cdb 调试）：

1. 设置断点在 `RtlpCallThreadEntry`，让工作线程刚启动就断下
2. 检查 `gs:[0x58]` → TLP → `TLP[0]`，发现数据块只有 8 字节（stub 的模板大小）
3. 检查 `TLP[0] + 0x1e0`，发现读到 `0x8000000000000000`（非零！）
4. 这个值是其他 TLS slot 的数据，被误读为 Rust 线程句柄

**根因**：

- stub 有自己的 TLS 目录，OS 为 stub 分配 TLS index = 0
- 目标 PE 的 `__tls_index` 编译时也 = 0，两者恰好匹配（这是幸运，不是设计）
- 但**新线程创建时**，OS 只用 stub 的 TLS 模板（8 字节）初始化 `TLP[0]`
- 目标 PE 访问 `TLP[0]+0x1e0` 等远偏移会读到越界数据（其他 slot 的数据）
- Rust std::thread 误判 "current thread handle already set"，触发 `__fastfail(7)`

**关键认知**：难题 A 只解决了**主线程**的 TLS 数据，新线程的 TLS 数据由 OS 自动分配，**反射式 loader 无法影响 OS 的分配逻辑**。除非……

### 2.3 难题 C：TLS Callback 必须代理

PELoader3 的 README 给出了标准答案：**在 stub 里注册一个 TLS callback，让 OS 在每次线程事件时自动调用它，stub 在 callback 里手动为目标 PE 分配/释放 TLS 数据**。

这是因为 Windows OS loader 在调用 TLS callback 时，会按 `AddressOfCallBacks` 数组遍历，对每个 callback 都传入 reason。如果 stub 的 `.CRT$XLB` section 里有一个 callback 指针，OS 就会在每次 `DLL_THREAD_ATTACH` / `DLL_THREAD_DETACH` 时调用它。

**坑中坑**：第一版实现只分配 TLS 数据块，**没有调用目标 PE 自己的 TLS callbacks**。CC-Switch 的 GUI 虽然能起来，但 Rust 工作线程的 TLS callback 没被触发，存在隐蔽 bug。参考 PELoader3 `main.cpp` 的 `TlsCallbackProxy`：

```cpp
if (dwReason == DLL_THREAD_DETACH) {
    _tlsResolver->ExecuteCallbacks(_peImage, dwReason, pContext);  // 先调目标 PE callbacks
    _tlsResolver->ClearTlsData();                                  // 再释放数据
} else if (dwReason == DLL_THREAD_ATTACH) {
    _tlsResolver->InitializeTlsData(_peImage);                    // 先分配数据
    _tlsResolver->ExecuteCallbacks(_peImage, dwReason, pContext); // 再调 callbacks
}
```

顺序非常重要：

- `DLL_THREAD_ATTACH`：必须**先**设 `TLP[0]` 再调 callback，否则 callback 内部读 TLS 变量会读到旧数据
- `DLL_THREAD_DETACH`：必须**先**调 callback 让其做 cleanup，**再**释放数据块

---

## 3. 最终方案：TLS Callback 代理 + 数据块分配

### 3.1 整体架构

```
┌────────────────────────────────────────────────────────────┐
│  stub.exe (loader)                                          │
│  ├─ .CRT$XLB section 注册 g_tls_cb_ptr = tls_callback_proxy│
│  ├─ _tls_used.AddressOfCallBacks 指向 stub callback 数组   │
│  │                                                           │
│  ├─ main():                                                 │
│  │    1. 反射式加载目标 PE                                   │
│  │    2. init_tls_data(): 分配主线程 TLS 数据块             │
│  │    3. run_tls_callbacks(): 调目标 PE callbacks (ATTACH)  │
│  │    4. g_entry_point_called = 1  ← 启用 callback 代理     │
│  │    5. jump_to_oep()                                       │
│  │                                                           │
│  └─ tls_callback_proxy():  ← OS 自动调用                    │
│       DLL_THREAD_ATTACH:                                    │
│         VirtualAlloc + memcpy 模板 → TLP[0]                 │
│         调用目标 PE TLS callbacks                           │
│       DLL_THREAD_DETACH:                                    │
│         调用目标 PE TLS callbacks                           │
│         VirtualFree(TLP[0])                                 │
│       DLL_PROCESS_DETACH:                                   │
│         调用目标 PE TLS callbacks                           │
└────────────────────────────────────────────────────────────┘
```

### 3.2 关键代码片段

**注册 TLS callback 到 `.CRT$XLB`**（MinGW 写法）：

```c
__attribute__((section(".CRT$XLB"), used))
static const PIMAGE_TLS_CALLBACK g_tls_cb_ptr = tls_callback_proxy;
```

MinGW CRT 会把 `.CRT$XLA` / `.CRT$XLB` / `.CRT$XLZ` 合并成一个数组，`_tls_used.AddressOfCallBacks` 指向 `&__xl_a + 1`（跳过首部 NULL），我们的 callback 位于 `__xl_a` 和 `__xl_z` 之间。

**MSVC 等价写法**（参考 Fatpack / PELoader3）：

```c
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:tls_callback_func")
#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_func = (PIMAGE_TLS_CALLBACK)TlsCallbackProxy;
#pragma const_seg()
```

**主线程初始化**（`init_tls_data`）：

```c
static int init_tls_data(uint8_t* img, uint64_t preferred_base) {
    /* 1. 找 TLS 目录 */
    IMAGE_TLS_DIRECTORY_X* tls = (IMAGE_TLS_DIRECTORY_X*)(img + dir->VirtualAddress);

    /* 2. 计算 TLS 数据块大小并分配（VirtualAlloc 自动清零） */
    uint32_t raw_rva = (uint32_t)(tls->StartAddressOfRawData - preferred_base);
    SIZE_T raw_size = (SIZE_T)(tls->EndAddressOfRawData - tls->StartAddressOfRawData);
    SIZE_T total_size = raw_size + tls->SizeOfZeroFill;
    uint8_t* tls_block = VirtualAlloc(NULL, total_size, MEM_COMMIT, PAGE_READWRITE);

    /* 3. 复制模板（RawData 是初始化好的静态 TLS 变量值） */
    if (raw_size > 0) memcpy(tls_block, img + raw_rva, raw_size);

    /* 4. 设置 TLP[0] = 数据块（覆盖 stub 的小数据块） */
    PVOID* tlp = (PVOID*)__readgsqword(0x58);   /* x64 */
    if (tlp) tlp[0] = tls_block;

    /* 5. 确保 AddressOfIndex = 0（与代码内联的 __tls_index 一致） */
    if (tls->AddressOfIndex) {
        uint32_t* index_ptr = (uint32_t*)(img + (tls->AddressOfIndex - preferred_base));
        *index_ptr = 0;
    }

    /* 6. 保存 TLS 目录指针供 callback 代理使用 */
    g_target_tls = tls;
    return 1;
}
```

**TLS callback 代理**（核心）：

```c
static void NTAPI tls_callback_proxy(PVOID hModule, DWORD reason, PVOID ctx) {
    if (!g_entry_point_called || !g_target_tls) return;

    if (reason == DLL_THREAD_ATTACH) {
        /* 新线程：为目标 PE 分配 TLS 数据块 */
        SIZE_T raw_size = g_target_tls->EndAddressOfRawData - g_target_tls->StartAddressOfRawData;
        SIZE_T total = raw_size + g_target_tls->SizeOfZeroFill;
        uint8_t* block = VirtualAlloc(NULL, total, MEM_COMMIT, PAGE_READWRITE);
        if (block && raw_size > 0)
            memcpy(block, (void*)g_target_tls->StartAddressOfRawData, raw_size);

        PVOID* tlp = (PVOID*)__readgsqword(0x58);
        if (tlp) {
            if (tlp[0]) VirtualFree(tlp[0], 0, MEM_RELEASE);  /* 释放 stub 的小数据块 */
            tlp[0] = block;
        }

        /* 数据块就绪后，调目标 PE 的 TLS callbacks（顺序重要！） */
        run_target_tls_callbacks(reason, hModule, ctx);

    } else if (reason == DLL_THREAD_DETACH) {
        /* 线程退出：先调 callbacks 让其做 cleanup，再释放数据 */
        run_target_tls_callbacks(reason, hModule, ctx);
        PVOID* tlp = (PVOID*)__readgsqword(0x58);
        if (tlp && tlp[0]) {
            VirtualFree(tlp[0], 0, MEM_RELEASE);
            tlp[0] = NULL;
        }

    } else if (reason == DLL_PROCESS_DETACH) {
        /* 进程退出：只调 callbacks，不释放数据（OS 会回收） */
        run_target_tls_callbacks(reason, hModule, ctx);
    }
    /* DLL_PROCESS_ATTACH 由主流程 run_tls_callbacks() 在 OEP 前调用，这里不处理 */
}
```

### 3.3 `g_entry_point_called` 标志的作用

进程启动时 OS 会先调 stub 的 TLS callback（reason=`DLL_PROCESS_ATTACH`），此时目标 PE 还没加载完成，`g_target_tls` 是 NULL，必须跳过。通过 `g_entry_point_called` 标志区分：

- 进程启动早期（`DLL_PROCESS_ATTACH`）：`g_entry_point_called=0`，跳过
- `main()` 中目标 PE 初始化完成后：`InterlockedExchange(&g_entry_point_called, 1)`
- 此后任何线程事件：`g_entry_point_called=1`，正常处理

---

## 4. 踩坑历程时间线

| 阶段 | 症状 | 误诊 | 真因 | 修复 |
|---|---|---|---|---|
| **阶段 1** | FastCopy `call NULL` / Bandizip `read 0x18` | IAT 解析失败 | stub 的 TLS slot 0 数据被原 PE 读到，MinGW CRT 动态 IAT 守卫误判 | `init_tls_data()` 分配原 PE 的 TLS 数据块，设置 `TLP[0]` |
| **阶段 2** | CC-Switch 创建工作线程时 `__fastfail(7)` | SecurityCookie 检查失败 | OS 只用 stub 的小模板初始化新线程 `TLP[0]`，远偏移读到其他 slot 数据 | TLS callback 代理（`.CRT$XLB`），新线程时手动分配大块 |
| **阶段 2.5** | 扩展 stub TLS `SizeOfZeroFill` 仍失败 | 以为扩展模板大小即可 | OS 用 stub 的 `.tls` 节 VirtualSize 分配，光改 `SizeOfZeroFill` 不够 | 同时扩展 `.tls` 节 `VirtualSize` |
| **阶段 2.6** | 扩展 `.tls` VirtualSize 仍失败 | cdb 发现 `TLP[0]+0x1e0 = 0x8000000000000000` | 即使扩展了 stub 的 TLS 模板，目标 PE 的模板内容没被复制 | 改用 callback 代理模式，主动 `memcpy` 目标 PE 模板 |
| **阶段 3** | CC-Switch GUI 起来但 Rust 工作线程 callback 没触发 | 调研 PELoader3 发现实现不完整 | 只分配数据，没调目标 PE callbacks | `run_target_tls_callbacks()` 在 ATTACH/DETACH 时调用目标 PE callbacks |

---

## 5. 参考项目对比

| 项目 | TLS 数据分配 | TLS Callback 代理 | 备注 |
|---|---|---|---|
| **PELoader3** | ✓ `TlsResolver::InitializeTlsData` | ✓ `TlsCallbackProxy` 完整 4 reason | 最完整的参考实现 |
| **Fatpack** | ✓（与 PELoader3 同源） | ✓（与 PELoader3 同源） | 支持 Rust/Delphi，README 明确说"Full TLS support" |
| **AlushPacker** | ✗ | ✓ `.CRT$XLB` 4 reason 分发 | 反射式但只代理 callbacks，不分配数据 |
| **PolyEngine** | ✗ | ✓ `.CRT$XLB` 但仅反调试用 | TLS callback 用于反调试（PEB.BeingDebugged），非 TLS 代理 |
| **peldr** | ✗ | ✗ | 完全不处理 TLS（接受限制） |
| **PEPacker2 / AtomPePacker / MaldevAcademyLdr** | ✗ | 仅 ATTACH 主动调用 | 不代理新线程事件 |
| **当前实现** | ✓ `init_tls_data()` | ✓ `tls_callback_proxy` 3 reason | 综合 PELoader3 + AlushPacker 方案 |

### 5.1 PELoader3 的关键贡献

`F:\Temp\pe\PELoader3\README.md` 对静态 TLS 的原理做了清晰解释，核心要点：

1. **TLS index 复用**：反射式 loader 自身有 TLS 目录（因为注册了 callback），OS 会分配 index = 0。目标 PE 编译时 `__tls_index` 也常被内联为 0。两者**恰好匹配**，无需 `TlsAlloc`。作者明确说"曾经尝试 `TlsAlloc/TlsFree` 但不成功"。
2. **不要设置 `LDR_DATA_TABLE_ENTRY.TlsIndex`**：作者实验发现设置为真实 index 会引起异常行为，应保持 `TLS_OUT_OF_INDEXES`。
3. **`TlsCallbackProxy` 必须是第一个被调用的 callback**：这样代理能在目标 PE 的 callback 之前设置好 TLS 数据。

### 5.2 Fatpack 的工程化经验

Fatpack 是 PELoader3 的 packer 包装，README 提到：

- **支持 Rust 和 Delphi** 程序——这两类程序重度依赖 TLS callback 做线程级运行时初始化
- **No CRT usage**：stub 不链 CRT，避免 CRT 自身的 TLS callback 干扰代理逻辑
- **LZMA 压缩 + 完整 TLS 支持**：体积和兼容性兼顾

---

## 6. 调试技巧

### 6.1 用 cdb 检查 TLP 内容

```python
# Python 脚本通过 cdb 检查 TLP[0] 数据块大小和内容
import subprocess

cdb = r"C:\Home\Develop\WinDbg\x64\cdb.exe"
script = """
bp ntdll!RtlpCallThreadEntry
g
r @gs:0x58
; 输出 TLP 指针
.for (r $t0 = 0; $t0 < 0x200; $t0 = $t0 + 8) {
    .printf "TLP[0]+0x%x = %p\\n", $t0, poi(poi(@gs:0x58)+$t0)
}
q
"""
# 执行 cdb -z target.exe -c "$<script.txt"
```

**关键诊断点**：

- `TLP[0]` 指向的内存大小是否匹配目标 PE 的 `raw_size + SizeOfZeroFill`
- `TLP[0] + offset` 处的值是否为合理数据（不是其他 slot 的越界值）
- `__tls_index` 的值（应该 = 0）

### 6.2 区分 `__fastfail` 类型

| `__fastfail` 参数 | 含义 | 常见原因 |
|---|---|---|
| 7 (`FAST_FAIL_FATAL_APP_EXIT`) | Rust/CRT 主动调用 | Rust panic 转 abort、CRT 错误 |
| 11 (`FAST_FAIL_STACK_BUFFER_OVERRUN`) | SecurityCookie 校验失败 | `/GS` 检测到栈破坏 |

**注意**：`__fastfail` 不经过 VEH，无 VEH 日志，只能从 WER 或 cdb 看到。

### 6.3 启用 stub 日志

`loader.c` 的 `RDEBUG=1` 会把详细日志写到 `*_loader.log`（与 EXE 同目录）。关键字搜索：

- `tls: no TLS directory` — 目标 PE 无 TLS，跳过所有 TLS 处理
- `tls: raw_rva=0x... raw_size=N zero_fill=M total=K` — 模板信息
- `tls: TLP=... old TLP[0]=... -> new ...` — 主线程 TLP 覆盖
- `tls: saved g_target_tls=... for TLS callback proxy` — callback 代理已就绪
- `tls: proxy -> callback ... (reason=N)` — 每次代理调用目标 PE callback

reason 值：1=`DLL_PROCESS_ATTACH`，2=`DLL_THREAD_ATTACH`，3=`DLL_THREAD_DETACH`，0=`DLL_PROCESS_DETACH`

---

## 7. 边界情况与遗留问题

### 7.1 TLS Index 不匹配的情况

当前方案依赖 **stub 的 TLS index = 0** 且 **目标 PE 的 `__tls_index` 也 = 0**。这个假设在绝大多数情况下成立（因为 stub 通常没有 `__declspec(thread)` 变量，只有 callback，OS 分配 index 0；目标 PE 的 CRT 也通常用 index 0）。

**风险场景**：如果 stub 引入了其他 DLL（如 `kernel32.dll`）的静态 TLS 变量，OS 可能给 stub 分配非 0 index。此时需要：

1. 读取 stub 自己的 `IMAGE_TLS_DIRECTORY.AddressOfIndex` 指向的 DWORD 获取真实 index
2. 把目标 PE 的 `AddressOfIndex` 指向的 DWORD 改为 stub 的真实 index
3. 在 callback 代理中用真实 index 而非硬编码的 `TLP[0]`

PELoader3 的 `TlsResolver::TlsResolver()` 正是这样做的：

```cpp
PEImage peLoaderImage(GetModuleHandle(nullptr));
_tlsIndex = GetTlsIndex(&peLoaderImage);  // 从 loader 自己的 TLS 目录读真实 index
```

### 7.2 TLS Index >= 64 的情况

Windows 有两种 TLS slot 存储：

- `TEB->ThreadLocalStoragePointer`：前 64 个 slot
- `PEB->TlsExpansionSlots`：第 64 个之后的 slot（需要 `TlsExpansionSlots[index - 64]` 访问）

PELoader3 的 `SetTlsData` 处理了这种情况：

```cpp
if (tlsIndex < 64) {
    ((ULONG_PTR*)teb->ThreadLocalStoragePointer)[tlsIndex] = (ULONG_PTR)tlsData;
} else {
    if (!peb->TlsExpansionSlots) {
        peb->TlsExpansionSlots = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PVOID) * 1024);
    }
    peb->TlsExpansionSlots[tlsIndex - 64] = tlsData;
}
```

当前实现假设 index < 64，对 99% 的程序都成立。如需完整支持，参考 PELoader3 的写法。

### 7.3 动态 TLS（`TlsAlloc` / `__tls_get_addr`）

本文只讨论**静态 TLS**（`__declspec(thread)` 变量 + TLS callback）。动态 TLS（`TlsAlloc`/`TlsGetValue`/`TlsSetValue`）由 `kernel32!TlsAlloc` 分配 slot，与 PE 的 `IMAGE_TLS_DIRECTORY` 无关，反射式 loader 不需要特殊处理。

### 7.4 .NET 程序

CLR 内部假设主模块通过 OS loader 加载，反射式加载的 .NET 程序大概率崩溃。PELoader3 和 Fatpack 的 README 都明确说"No .NET support"。这是反射式 loader 的根本限制，与 TLS 无关。

### 7.5 x86 SEH

x86 程序的 SEH 走 `FS:[0]` 链，反射式 loader 无法手动注册 SEH 表。AlushPacker 的方案是 patch `ntdll!RtlIsValidHandler`（硬编码偏移，跨 Windows 版本不可靠）。当前实现对 x86 复杂 SEH 程序（如 AutoHotkey32）支持有限，但简单 x86 程序能跑。

---

## 8. 实测兼容性

截至 2026-07-19，反射式 loader 的 TLS 处理已通过以下程序测试：

| 程序 | 语言/框架 | TLS 复杂度 | 结果 |
|---|---|---|---|
| CC-Switch | Rust/Tauri | 高（Rust std::thread 重度依赖 TLS callback） | ✅ GUI 正常，工作线程 callback 触发 |
| FastCopy | MinGW C | 中（MinGW CRT 动态 IAT 守卫用 TLS slot 0） | ✅ 无回归 |
| Bandizip | MinGW C | 中（同上） | ✅ exit=10（正常退出码） |
| BCompare | VS C++ | 中（VS CRT `/GS` 用 TLS 存 SecurityCookie） | ✅ GUI 正常 |
| AutoHotkey64 | VS C++ | 低 | ✅ GUI 正常 |
| AutoHotkey32 (x86) | VS C++ | 低 | ❌ x86 SEH 问题（与 TLS 无关） |
| Notepad4 / DontSleep / 各种 hello* 样本 | — | 无/低 | ✅ 全部通过 |

---

## 9. 参考资料索引

### 9.1 参考项目源码

| 项目 | 关键文件 | 价值 |
|---|---|---|
| PELoader3 | `PELoader/TlsResolver.cpp` + `TlsCallbackProxy/TlsCallbackProxy.h` + `main.cpp` | 最完整的 TLS 代理实现，README 解释清晰 |
| Fatpack | `Shared/PELoader/` （与 PELoader3 同源）+ `Shared/CRT/crt_tls.h` | 工程化包装，支持 Rust/Delphi |
| AlushPacker | `Packer/tls.h` + `Packer/loader.c` | `.CRT$XLB` 4 reason 分发范例 |
| PolyEngine | `Stub/TlsCallback.c` | TLS callback 用于反调试（PEB.BeingDebugged + NtGlobalFlag + ProcessHeap.Flags + `__fastfail(7)`） |

### 9.2 关键文章

- **maskray - All about thread-local storage**：<https://maskray.me/blog/2021-02-14-all-about-thread-local-storage>（ELF 平台 TLS 详解，4 种 TLS 模型 Local/Initial/General/Local Dynamic）
- **kaimi - Developing PE file packer step by step, step 6: TLS**：<https://kaimi.io/en/2012/09/developing-pe-file-packer-step-by-step-step-6-tls/>
- **Microsoft PE Format - .TLS section**：<https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#tls>（官方规范，简略）

### 9.3 本项目相关文档

- [ANALYSIS_REPORT.md](file:///c:/Home/Projects/applocker/packer/docs/ANALYSIS_REPORT.md) — 12 个 PE 加壳项目对比（含 TLS 处理对比表）
- [REFLECTIVE_DESIGN.md](file:///c:/Home/Projects/applocker/packer/docs/REFLECTIVE_DESIGN.md) — 反射式 loader 设计方案
- [../reflective/loader.c](file:///c:/Home/Projects/applocker/packer/reflective/loader.c) — 实现代码（`init_tls_data` / `run_tls_callbacks` / `tls_callback_proxy` / `run_target_tls_callbacks`）

---

**文档版本**：1.0
**最后更新**：2026-07-19
**作者**：基于 applocker 项目反射式 loader 的 TLS 修复实践整理
