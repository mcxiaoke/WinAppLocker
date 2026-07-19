# 反射式 PE Loader 项目深度对比报告

> 创建日期：2026-07-19
> 分析对象：F:\Temp\pe 下 5 个反射式 PE loader 项目
> 视角：为 winlock 新增反射式 packer/stub 模式做技术储备
> 方法：1 个 subagent 深度阅读 5 个项目核心源码

---

## 一、逐项分析

### 1. peldr-main（最完整的反射式 loader）

**文件清单**
- `F:\Temp\pe\peldr-main\loader.c` — stub 主体（loader 入口 `Main`）
- `F:\Temp\pe\peldr-main\peldr.c` — builder，负责压缩/加密/拼装
- `F:\Temp\pe\peldr-main\loader.h` — stub 全部声明、宏、结构、API hash 常量
- `F:\Temp\pe\peldr-main\hash.py` — 离线 hash 生成器

**加壳方式**：stub + overlay。`peldr.c::build_exe` 拼接为 `STUB_EXE || keylen(1B) || key(N B) || raw_len(4B) || encrypted_payload || total_len(4B)`。stub 运行时通过 `NtQueryInformationProcess(ProcessImageFileName)` 拿到自己 EXE 路径，`NtOpenFile/NtReadFile` 反向读 overlay。这是"文件式 fileless"——不会落地原始 PE，但 stub 本体仍是 PE。

**stub 语言/约束**：纯 C（MinGW-w64 / w64devkit），`-nostdlib -ffreestanding -fvisibility=hidden -fomit-frame-pointer -Wl,--gc-sections -Wl,--no-seh -fno-exceptions`，`-e Main` 自定义入口，输出静态 PIE。`MEMCPY/ZEROS` 用 `__movsb/__stosb` 内建，`GET_PTR_PEB` 用 `__readgsqword(0x60)`，完全无 CRT、无 import。

**payload 格式**：无魔数、无版本。Overlay 末 4 字节是 `total_len`，向前回溯解析 `key_size/key/raw_len/payload`。`PE_EXE_SZ = max(DT_EXE_SZ, RW_EXE_SZ)` 取压缩前/后最大值，多分配空间避免解压越界。

**加密栈**（`peldr.c::encrypt` 与 `loader.c::UnPackData/DEC_BYTE`）：
- 压缩：自实现 RLE（`RLE_MIN_RUN=3`, `RLE_MAX_RUN=127`, `RLE_FLG_RUN=0x80`）
- 加密：自研流密码，状态字节 `stt`、`mask = keySz-1`（要求 keySz 是 2 的幂：16/32/64/128），每字节混合 `(k1<<1|k2>>7) ^ (j^j>>8)`，再 `rotl8(b,3) + (stt^k1) ^ m`，状态反馈 `stt = (b + k2) ^ (stt>>1)`
- 解密逻辑嵌入 stub，加密逻辑嵌入 builder，两端手写一致

**IAT 解析**（`loader.c::ProcessImageImports`）：用 `LdrLoadDll + LdrGetProcedureAddress`（不是 `LoadLibrary/GetProcAddress`）。支持按名/按序号。**不支持 forwarder**（如果遇到 forwarded export 直接 `return FALSE`）。把 `CHAR` 库名逐字节转 `WCHAR`（不调用 `MultiByteToWideChar`）。

**reloc 类型覆盖**（`loader.c::ApplyImageRelocations`）：**只处理 `IMAGE_REL_BASED_DIR64`**，其他全部跳过。对 x64 PE 来说 99% 够用，但混合模式或绝对 32 位 fixup 不会被修复。

**TLS callback 处理**（`loader.c::ExecuteImageTLS`）：仅以 `DLL_PROCESS_ATTACH` 调用一次，不处理 `DLL_THREAD_ATTACH/DETACH`，不分配 TLS 数据块（无 `CreateTlsData`、不写 TEB->ThreadLocalStoragePointer）。这意味着：原 PE 若用 `__declspec(thread)` 静态 TLS，后续线程会 crash。

**.pdata 注册**（`loader.c::InitImageExceptionTable`）：调用 `RtlAddFunctionTable(RuntimeFunction, count, imageBase)`。在节权限生效前完成，正确顺序。

**SecurityCookie 初始化**（`loader.c::InitImageSecurityCookie`）：从 `KUSER_SHARED_DATA::InterruptTime`(0x7FFE0008) 读 64 位值与 `img` 异或写回 `*lc->SecurityCookie`。不依赖任何 API，简洁。

**栈对齐跳 OEP**（`loader.c::Main` 末尾）：
```c
__asm__ volatile (
    "andq $-16, %%rsp\n\t"   // -16 = 0xFFFFFFFFFFFFFFF0，16字节对齐
    "subq $40,  %%rsp\n\t"   // 32B shadow space + 8B 对齐余量
    "jmpq *%0\n\t"           // 直接跳转，不通过 call
    : : "r"(AddrOfEntryPoint) : "memory");
```
对 EXE 是 `jmpq`，对 DLL 是 `((DllMain_t)AddrOfEntryPoint)(img, DLL_PROCESS_ATTACH, NULL)`。**这是5个项目中唯一显式做 16 字节栈对齐 + shadow space 的实现**，符合 x64 ABI。

**API hash 算法**（`loader.c::HashStr`）：DJB15 变种，种子 1993，`h = (h<<4) - h + c`，case-fold 通过 `ASCII_FOLD_MASK`。`hash.py` 离线预计算，输出 C 宏 `HASH_*`。`InitNtdllFunctions` 遍历 ntdll 导出表对每个名字算 hash 并对比预存表。

**反调试**（`loader.c::AntiDebugStage`，默认 `FALSE`）：
- `ADB_STAGE_PREAPI`：`KdDebuggerEnabled`(KUSER_SHARED_DATA+0x2D4) + `PEB->BeingDebugged` + `ProcessParameters->DebugFlags`
- `ADB_STAGE_NTAPI`：`NtQueryInformationProcess(ProcessDebugPort, ProcessDebugObjectHandle)`
- `ADB_STAGE_GUARD`：在 image 前留 1 页 `PAGE_NOACCESS` 作为 guard page，`MEM_TOP_DOWN` 分配
- 校验 `PROCESS_BASIC_INFORMATION.PebBaseAddress == __readgsqword(0x60)` 防 PEB spoofing

**反 dump**：
- 可选 `USING_ERASE_PE_HEADERS`：用 `__stosb` 清零 `SizeOfHeaders` 字节
- 跳 OEP 前把所有已解析函数指针 `= NULL`（`pNtClose = NULL` 等），scrub IAT-style 痕迹

**资源保留**：无。stub 是从零生成的 PIE，没有 .rsrc 节，原 PE 的资源/图标/manifest 在新 image 中按 RVA 映射，但**外壳 EXE 的资源是 stub 自己的（基本为空）**。

**stub 体积估算**：源码 ~1150 行 C，编译后 PIE 约 3-5 KB（无 CRT，gc-sections，所有函数 `static inline always_inline`）。README 提到典型压缩比 20-50%。

**与 OS loader 的协作方式**：完全旁路 OS loader。`GetNtdllAddr` 走 `PEB->Ldr->InMemoryOrderModuleList` 找 ntdll，自己解析导出表。但**会更新 `PEB->ImageBaseAddress`**（不更新 LDR_DATA_TABLE_ENTRY，因为 stub 不在 loader 表里），让后续 `GetModuleHandle(NULL)` 返回新 image。不调用 `RtlInsertInvertedFunctionTable`——这意味着 SEH 表仅通过 `RtlAddFunctionTable` 注册，对某些 Win10+ 版本可能不够。

**节权限**（`loader.c::SetImageSectionsPermission`）：8 项查表 `ProtTab[8]`，索引 = `(Characteristics & SECTION_PROT_MASK) >> 29`，简洁。PE 头单独置 `PAGE_READONLY`。不支持 `PAGE_NOCACHE`/`PAGE_WRITECOPY` 区分。

---

### 2. AlushPacker-main

**文件清单**
- `F:\Temp\pe\AlushPacker-main\Packer\loader.c` — stub（unpacker）
- `F:\Temp\pe\AlushPacker-main\Packer\decrypt.h` — TEA 解密
- `F:\Temp\pe\AlushPacker-main\Packer\tls.h` — TLS proxy 回调框架（**整段被 `/* */` 注释掉**）
- `F:\Temp\pe\AlushPacker-main\Builder\builder.c` — builder
- `F:\Temp\pe\AlushPacker-main\Builder\encrypt.h` — TEA 加密
- `F:\Temp\pe\AlushPacker-main\Packer\structs.h` — `packed_section` 结构 + PEB/TEB/LDR 完整定义
- `F:\Temp\pe\AlushPacker-main\Builder\stubs.h` — 预编译好的 x64/x86 stub 字节数组

**加壳方式**：在 precompiled stub EXE 末尾追加 `.packed` 节。builder 通过 `addSectionToInputFile` 增加节头并写入节内数据。stub 自己 `myGetModuleHandle(NULL) -> 找 .packed 节 -> 读 packed_section`。

**stub 语言/约束**：C (MSVC)，**带 CRT**（`#include <stdio.h>`、`malloc/system/printf/fopen` 全用），`#define DEBUG_STUB` 调试模式甚至硬编码 `fopen("C:\\Users\\tamar\\Downloads\\...")`。stub 体积大但开发友好。

**payload 格式**（`structs.h::_packed_section`）：
```c
typedef struct _packed_section {
    uint32_t unpacked_size;
    uint32_t packed_size;
    BOOL lockFlag;        // 4 bytes
    uint32_t lockHash;    // DJB2 of decrypted payload
    unsigned char payload[];
} packed_section;
```
**无魔数、无版本**，结构直接 memcpy 进节。

**加密栈**：
- 压缩：LZAV（`lzav_compress_default` / `lzav_decompress`，第三方高速通用压缩）
- 加密：TEA 32 轮（`encrypt.h`），128-bit 固定 key `{0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210}` 硬编码在源码里
- 可选密码锁：`-l password` 再加密一层，DJB2 hash 校验

**IAT 解析**（`loader.c::LdrpResolveProcedureAddress`）：完整实现：
- `LdrpNameToOrdinal` 用二分查找导出名字
- `LdrpParseForwarderDescription` 解析 forwarder 字符串（"NTDLL.NtCreateFile" 或 "NTDLL.#123"）
- 递归解析 forwarder（如果转发回自己则 fallback 到 `kernelbase.dll`）
- Hint 加速：先比对 `IMAGE_IMPORT_BY_NAME.Hint` 位置的名字，命中则跳过二分
- 同时处理 `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`（延迟导入表）

**reloc 类型覆盖**（`loader.c::LdrpRelocateImage`）：覆盖 `ABSOLUTE/DIR64/HIGHLOW/HIGH/LOW` 5 种。比 peldr 完整。

**TLS callback 处理**：**`tls.h` 整段被 `/* */` 注释掉**，最终只在 `executePE` 里手动调用 `DLL_PROCESS_ATTACH` 的 callbacks。原计划的 `TlsCallbackProxy` / `CreateTlsData` / `SetTlsData` / `ClearTlsData` 全部停用。所以静态 TLS 不可靠。

**.pdata 注册**：双路径：
- x64：`RtlAddFunctionTable`（通过 `myGetProcAddress(ntdll, "RtlAddFunctionTable")`）
- x86：硬编码 patch `ntdll + 0x699C3 + 0x3C22E + 1`，把 `RtlIsValidHandler` 的 `je` 改成 `jne`，绕过 SEH 校验（注释说 "I'm just too lazy to implement a proper solution"，**版本脆弱**）
- 还调用 `myRtlInsertInvertedFunctionTable`，**硬编码偏移 `ntdll + 0x108F0`**，极度版本依赖

**SecurityCookie 初始化**：`GetTickCount64() ^ GetCurrentProcessId()`，若 > `COOKIE_MAX (0x0000FFFFFFFFFFFF)` 则 `>>= 16`。仅在原值为 `DEFAULT_SECURITY_COOKIE (0x00002B992DDFA232)` 或 0 时覆盖。

**栈对齐跳 OEP**：**未做对齐**：
```c
LPVOID (*ep)() = (LPVOID)((DWORD_PTR)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
int result = ep();
```
直接函数指针调用。`ep()` 返回 `int` 但其实是 `void`——这是 UB，但 MSVC x64 默认 16 字节对齐 call site，多数情况能跑。

**API hash 算法**：DJB2（`5381` 种子，`hash*33 + byte`），仅用于 `lockHash` 校验，**API 解析直接用名字字符串** `myGetProcAddress(ntdll, "RtlInitUnicodeString")`——所以 stub IAT 里全是明文 API 名。

**反调试**：无。

**反 dump**：无。`system("pause")` 反而暴露行为。

**资源保留**：无。stub 是单独编译的 EXE，外壳资源是 stub 自己的。

**stub 体积估算**：带 CRT + 大量 printf + LZAV 静态链接 + Windows API 静态链接，估计 **30-60 KB**（DEBUG 模式更大）。

**与 OS loader 协作**：通过 `myGetModuleHandle` 走 PEB->Ldr。`LdrpPatchDataTableEntry` **修改 LDR_DATA_TABLE_ENTRY**（EntryPoint/SizeOfImage/DllBase/TimeDateStamp）和 `PEB->ImageBaseAddress`。这是5个项目里唯一会回写 Ldr 表的——会让 OS loader "以为"主 image 是新加载的，但也容易触发 LoaderLock 一致性问题。

**节权限**：8 种组合查表 + `PAGE_NOCACHE` 处理，最完整。但调用时机在 import 之后、TLS 之前，顺序正确。

---

### 3. AtomPePacker-NUL0x4C-main

**文件清单**
- `F:\Temp\pe\AtomPePacker-NUL0x4C-main\PePacker64\PePacker.c` — builder
- `F:\Temp\pe\AtomPePacker-NUL0x4C-main\PePacker64\NewSection.c` — 追加 .ATOM 节
- `F:\Temp\pe\AtomPePacker-NUL0x4C-main\PP64Stub\main.c` — stub 入口
- `F:\Temp\pe\AtomPePacker-NUL0x4C-main\PP64Stub\Unpack.c` — 解压+映射+解析+跳OEP核心
- `F:\Temp\pe\AtomPePacker-NUL0x4C-main\PP64Stub\Utils.c` — `GetModuleHandleH/LoadLibraryH/GetProcAddressH/RefreshNtdll`
- `F:\Temp\pe\AtomPePacker-NUL0x4C-main\PP64Stub\IatCamouflage.h` — IAT 伪装
- `F:\Temp\pe\AtomPePacker-NUL0x4C-main\PP64Stub\Syscalls.lib` — 预编译 syscall stub

**加壳方式**：在 stub 中追加 `.ATOM` 节，仅存 LZMA 压缩数据。builder (`NewSection.c::CreateNewSection`) 用 `CreateFileMapping/MapViewOfFile` 修改 stub 文件，新增节头 + 节数据。

**stub 语言/约束**：C (MSVC)，使用 `Syscalls.lib`（直接 syscall 而非 ntdll 调用），`#pragma comment(linker,"/ENTRY:main")` 自定义入口，`easylzma_s.lib` 静态链接 LZMA。

**payload 格式**：**裸 LZMA 压缩流**，无包装结构、无魔数、无版本。stub 通过节名 `.ATOM` 哈希查找。

**加密栈**：**无加密**，仅 LZMA 压缩。这是5个项目里唯一不加密的。

**IAT 解析**（`Unpack.c::_FixImportAddressTable`）：
- `LoadLibraryH` 用 `LdrLoadDll`
- `GetProcAddressH` 用 DJB2-style hash 在导出表里线性查找
- 处理 forwarder 递归（`_CopyDotStr` 分割点号，递归调用 `GetProcAddressH`）
- 按名/按序号双路径

**reloc 类型覆盖**（`Unpack.c::_ReallocationSupport`）：`ABSOLUTE/DIR64/HIGHLOW/HIGH/LOW` 5 种，未知类型 `return FALSE`。

**TLS callback 处理**：仅 `DLL_PROCESS_ATTACH` 调用，不分配 TLS 数据。

**.pdata 注册**：`RtlAddFunctionTable`（通过 `GetProcAddressH(GetModuleHandleH(KERNEL32DLL), RtlAddFunctionTable_StrHashed)`）。注意 `count - 1` 的写法可疑（通常 count = Size/sizeof(RuntimeFunction)）。

**SecurityCookie**：不处理。

**栈对齐跳 OEP**：`((VOID(*)())EP)();` 直接调用，**未做栈对齐**。

**API hash 算法**：自定义 `HASH` 宏（在 `Structs.h` 中），种子 `SEED`，用于模块名 + 函数名双 hash。比 DJB2 复杂。`InitializeDirectNtCalls` 用 hash 结构体初始化 syscall 表。

**反调试**：`RefreshNtdll`（`Utils.c`）—— 从 `\KnownDlls\ntdll.dll` 重新 `NtOpenSection/NtMapViewOfSection` 拿到干净 ntdll，把当前进程 ntdll `.text` 节覆盖回去，**解除用户态 hook**（EDR hook bypass）。非常实用。

**反 dump**：`_ZeroMemory(pAddress, _Pe1.pSecHdr[0].VirtualAddress)` 清零 PE 头到第一节开始处（约 4KB），在跳 OEP 之前。

**资源保留**：无。

**stub 体积估算**：含 Syscalls.lib + easylzma + IatCamouflage，估计 **50-100 KB**。

**与 OS loader 协作**：先 `NtUnmapViewOfSection(NULL, ImageBase)` 卸载原 image（注意：stub 自己也映射在某个地址，可能炸），再 `NtAllocateVirtualMemory(ImageBase, SizeOfImage)` 尝试原基址。失败则 fallback 到任意地址 + 重定位。

**节权限**（`Unpack.c` 跳 OEP 前）：8 种组合查表，但**顺序有问题**：在 TLS callback 之前才设置权限，可能让 TLS callback 跑在没有 X 权限的代码上。

**IAT 伪装**（`IatCamouflage.h::CamouflageImports`）：通过死代码引用 `MessageBoxW/UpdateWindow/GetMenu` 等大量 user32/menu API，让 stub 自己的 IAT 看起来像普通 GUI 程序，避免 "stub 只 import NtAllocateVirtualMemory 一个 API" 这种 IoC。

---

### 4. amber-master

**文件清单**
- `F:\Temp\pe\amber-master\loader\loader-x64\loader-x64.asm` — 完整 loader（含 wipe）
- `F:\Temp\pe\amber-master\loader\loader-x64\loader-x64-lite.asm` — lite 版（无 wipe）
- `F:\Temp\pe\amber-master\loader\loader-x64\stub.c` — **空文件**
- `F:\Temp\pe\amber-master\loader\loader-x64\inc\*.asm` — 9 个子模块（map_image/relocate_image/resolve_imports/protect_sections/run_tls_callbacks/load_module/get_proc_by_crc/get_module_by_crc/calc_crc/memcpy）
- `F:\Temp\pe\amber-master\stub\stub.c` — 外壳 EXE，复制末节并执行
- `F:\Temp\pe\amber-master\pkg\amber.go` — Go 端 PE 解析 + payload 拼装
- `F:\Temp\pe\amber-master\main.go` — CLI 入口
- `F:\Temp\pe\amber-master\config\options.go` — 参数定义

**加壳方式**：**纯 shellcode 模式**，与前面3个不同。
- `amber.go::AssembleLoader` 输出 `call + uint32 payload_size + payload + LOADER_64`
- 调用方通过 `stub.c`（外壳 EXE）或任意 shellcode runner 注入执行
- lite 版（`amber_loader-x64-lite.bin`）是预编译好的纯二进制

**stub 语言/约束**：**NASM x86/x64 纯汇编**，`[BITS 64]`，无 CRT、无 import、无节、无 PE 头——就是 position-independent shellcode。`build.sh` 用 `nasm -f bin` 输出裸 `.bin`。

**payload 格式**：
```
0xE8                  ; call start  (5 bytes)
uint32 payload_size   ; 跟在 call 后的 4 字节跳转偏移
payload (PE bytes)    ; 原始 PE 文件
loader shellcode      ; 反射式 loader
```
`call start` 让 `start` 地址入栈，loader pop 出来得到 payload 基址。**无魔数、无版本、无加密**。

**加密栈**：**无加密**。但 amber 自带 SGN 编码器（`github.com/EgeBalci/sgn`）对**整个 shellcode（含 payload + loader）**做 N 轮多态编码，可绕过签名检测。这是可选的，`-e N` 控制轮数。

**IAT 解析**（`inc/resolve_imports.asm` + `inc/get_proc_by_crc.asm`）：
- `load_module`：构建 UNICODE_STRING 调 `LdrLoadDll`
- `get_proc_by_crc`：在导出表里线性查找，比对 CRC32
- 处理 forwarder：解析 `.` 分割 DLL 名，递归 `load_module + get_proc_by_crc`
- 按序号：通过 `IMAGE_ORDINAL_FLAG` 判断，但实际看代码主要走 by-name 路径

**reloc 类型覆盖**（`inc/relocate_image.asm`）：从汇编看，**只处理 `IMAGE_REL_BASED_DIR64` (type 0xA)**：
```asm
and r8d, 0xfffffff0   ; 取高4位
cmp r8b, 0xa0         ; 0xA << 4 = 0xA0
je  loc_apply_fixup
```
其他类型直接跳过。

**TLS callback 处理**（`inc/run_tls_callbacks.asm`）：遍历 `AddressOfCallBacks` 调用，参数 `(rsi=image, 1=DLL_PROCESS_ATTACH, 0=NULL)`。不分配 TLS 数据。

**.pdata 注册**：**不处理**。注释里说 "May fail... ¯\_(ツ)_/¯"，所以 SEH 在 amber 加载的 PE 里可能不工作。

**SecurityCookie**：不处理。

**栈对齐跳 OEP**（`loader-x64.asm` 末尾）：
```asm
cld
mov rsp, rbp      ; 恢复 stub 入口保存的 rbp 栈帧
pop rbp
jmp rax           ; 直接跳 OEP
```
**未做 16 字节对齐**，依赖外壳调用 stub 时的栈状态。如果调用方栈未对齐，OEP 内的 SSE 指令可能 crash。

**API hash 算法**：**CRC32**（`inc/calc_crc.asm` 用 `crc32` 指令硬件加速），对模块名（UTF-16）和函数名（ASCII）都计算 CRC32。模块查找走 `PEB->Ldr->InMemoryOrderModuleList` 遍历。

**反调试**：无。

**反 dump**：完整版 `loader-x64.asm` 末尾有 `wipe` 段：`rep stosb` 清零原 PE + 调用代码（`call $+5; pop rcx; sub rcx, rsi; ... rep stosb`），把自身 shellcode 和原始 PE 字节全部擦除后才跳 OEP。lite 版没有 wipe。

**资源保留**：无。整个 stub 是裸 shellcode。

**stub 体积估算**：lite 版 `amber_loader-x64-lite.bin` 文件存在，约 **1.5-2 KB**；完整版含 wipe 约 **3-4 KB**。是5个项目里最小的。

**与 OS loader 协作**：完全旁路，不更新 PEB->ImageBaseAddress，不更新 LDR 表，不调用 `RtlAddFunctionTable`——这是 amber 的设计取舍：**最小化、shellcode-friendly、SEH/TLS 不可靠**。

**节权限**（`inc/protect_sections.asm`）：调用 `NtProtectVirtualMemory`（通过 `api_call` 间接调用，hash = `0x6EDE4D41`）。权限组合通过位运算判断 `0x40000000`(EXEC)/`0x20000000`(READ)/`0x10000000`(WRITE)/`0x80000000`(无权限)，组合出 PAGE_NOACCESS/READONLY/READWRITE/EXECUTE/EXEC_READ/EXEC_READWRITE。无 WRITECOPY/NOCACHE。

**SGN 编码器**：amber 的最大特色——`sgn` 对 shellcode 做语义保持的多态编码（xor + junk code + register substitution），可指定轮数和混淆限制。让最终 shellcode 字节每次都不同，绕静态签名。

---

### 5. pe-packer-rust

**文件清单**
- `F:\Temp\pe\pe-packer-rust\common\src\lib.rs` — 公共库（payload 结构/序列化/加解密）
- `F:\Temp\pe\pe-packer-rust\builder\src\main.rs` — builder
- `F:\Temp\pe\pe-packer-rust\stub\src\main.rs` — stub（unpacker）

**加壳方式**：在 stub EXE 末尾追加 `.packed` 节。builder (`builder/src/main.rs::embed_payload`) 解析 stub PE，计算对齐，新增节头，写入 payload，更新 `NumberOfSections` 和 `SizeOfImage`，清零 `CheckSum`。

**stub 语言/约束**：Rust（`std + winapi` crate），**带完整 std 和 CRT**，使用 `LoadLibraryA/GetProcAddress/VirtualAlloc/VirtualProtect/CreateThread/WaitForSingleObject` 全部走 Win32 API。无 PIC、无 hash、无反调试。

**payload 格式**（`common/src/lib.rs`）：
```
MAGIC = b"PEPK"           (4 bytes)
VERSION = 1 (u32 LE)      (4 bytes)
payload_len (u32 LE)      (4 bytes)
JSON-serialized PackedPayload:
{
  "original_size": u64,
  "compressed_data": [u8],  // AES-256-GCM ciphertext (含 GCM tag)
  "salt": [u8; 16],
  "nonce": [u8; 12],
  "password_hash": Option<[u8; 32]>  // Argon2 hash
}
```
**唯一带魔数 + 版本号 + 完整 KDF 的项目**。但用 JSON 序列化导致 payload 头部很大且有结构特征。

**加密栈**：
- 压缩：LZ4（`lz4_flex::compress_prepend_size`）
- KDF：Argon2（`argon2` crate 默认参数）
- 加密：AES-256-GCM（`aes-gcm` crate），12 字节随机 nonce，16 字节 GCM tag 附加在密文末尾
- 可选密码：用户密码经 Argon2 派生 key，密码 hash 单独存储用于预校验

**IAT 解析**（`stub/src/main.rs::resolve_imports`）：标准 `LoadLibraryA(dll_name) + GetProcAddress(h_module, name/ordinal)`，无 hash、无自定义实现。支持 x86/x64 双路径。

**reloc 类型覆盖**（`stub/src/main.rs::apply_relocations`）：仅 `ABSOLUTE/HIGHLOW/DIR64` 三种，其他忽略。

**TLS callback 处理**：**不处理**。

**.pdata 注册**：**不处理**。SEH 表不注册。

**SecurityCookie**：**不处理**。

**栈对齐跳 OEP**：**用 CreateThread 而非直接 jmp**：
```rust
let thread = CreateThread(
    ptr::null_mut(), 0,
    core::mem::transmute(entry_point),
    ptr::null_mut(), 0, ptr::null_mut(),
);
WaitForSingleObject(thread, INFINITE);
```
新线程入口由 OS 创建，**栈自动 16 字节对齐**。这是5个项目里最安全的方式（不依赖调用方栈状态），但代价是 OEP 在新线程里跑，原线程阻塞等待——若 OEP 期望主线程（如某些 GUI 消息循环），会有问题。

**API hash**：无。全部明文 `LoadLibraryA/GetProcAddress`。

**反调试**：无。

**反 dump**：无。

**资源保留**：无。

**stub 体积估算**：Rust std + aes-gcm + argon2 + lz4_flex + winapi + goblin + serde_json 静态链接，估计 **500 KB - 1 MB**。是5个项目里最大的。

**与 OS loader 协作**：完全依赖 OS loader。不更新 PEB，不更新 LDR 表。映射后的 image 对 OS 不可见——`GetModuleHandle(NULL)` 仍返回 stub。

**节权限**（`stub/src/main.rs::protect_sections`）：简化 5 种组合，无 WRITECOPY/NOCACHE。调用 `VirtualProtect`（不是 `NtProtectVirtualMemory`）。

---

## 二、横向对比表

| 维度 | peldr | AlushPacker | AtomPePacker | amber | pe-packer-rust |
|---|---|---|---|---|---|
| stub 语言 | C (MinGW) | C (MSVC+CRT) | C (MSVC+syscalls) | NASM x64 asm | Rust (std) |
| stub 体积 | 3-5 KB | 30-60 KB | 50-100 KB | 1.5-4 KB | 500KB-1MB |
| 加壳形态 | overlay | 新增 .packed 节 | 新增 .ATOM 节 | shellcode | 新增 .packed 节 |
| payload 魔数/版本 | 无 / 无 | 无 / 无 | 无 / 无 | 无 / 无 | PEPK / v1 |
| 加密 | 自研流密码 | TEA (硬编码key) | 无 | 无 (可选 SGN) | AES-256-GCM |
| 压缩 | RLE | LZAV | LZMA | 无 | LZ4 |
| KDF | 无 | 无 | 无 | 无 | Argon2 |
| IAT 解析 | LdrLoadDll+LdrGetProcAddr | LdrLoadDll+自实现解析 | LdrLoadDll+hash解析 | LdrLoadDll+CRC32 | LoadLibraryA+GetProcAddress |
| forwarder 处理 | 不支持 | 支持(递归) | 支持(递归) | 支持(递归) | 不支持 |
| 延迟导入 | 不支持 | 支持 | 不支持 | 不支持 | 不支持 |
| reloc 覆盖 | 仅 DIR64 | ABS/DIR64/HIGHLOW/HIGH/LOW | ABS/DIR64/HIGHLOW/HIGH/LOW | 仅 DIR64 | ABS/HIGHLOW/DIR64 |
| TLS callback | 仅 ATTACH | 仅 ATTACH (proxy 整段注释) | 仅 ATTACH | 仅 ATTACH | 不处理 |
| TLS 数据块分配 | 不分配 | 不分配 | 不分配 | 不分配 | 不分配 |
| .pdata 注册 | RtlAddFunctionTable | RtlAddFunctionTable + RtlInsertInvertedFunctionTable(硬编码偏移) | RtlAddFunctionTable | 不处理 | 不处理 |
| SecurityCookie | KUSER_SHARED_DATA XOR | GetTickCount64 ^ PID | 不处理 | 不处理 | 不处理 |
| 栈对齐跳 OEP | **16B 对齐 + 40B shadow + jmp** | 直接 call (UB) | 直接 call | jmp (依赖调用方栈) | CreateThread (OS 对齐) |
| API hash | DJB15 变种 seed=1993 | 不用 (DJB2 仅用于 lockHash) | 自定义 HASH 宏 | CRC32 (硬件指令) | 不用 |
| 反调试 | PEB/KdDebugger/NtQueryProc/GuardPage | 无 | 无 (但 RefreshNtdll 解 hook) | 无 | 无 |
| 反 dump | 可选 ERASE_PE_HEADERS + scrub 指针 | 无 | 清零 PE 头 4KB | wipe 整段 shellcode+PE | 无 |
| 资源/图标/manifest | 不保留 | 不保留 | 不保留 | 不保留 | 不保留 |
| PEB 更新 | ImageBaseAddress | ImageBaseAddress + LDR 表项 | 不更新 | 不更新 | 不更新 |
| 节权限表 | 8 项查表 | 8 项 + NOCACHE | 8 项查表 | 位运算推导 6 项 | 5 项简化 |
| x86 支持 | 否 | 是 | 否(仅 x64) | 是 | 是（解析层） |
| DLL 支持 | 是 (调 DllMain) | 否 | 否 | 是 (从 PE 特性判断) | 否 |
| 与 OS loader 协作 | 旁路 + PEB 更新 | 旁路 + PEB + LDR 表回写 | 旁路 (NtUnmap 原image) | 完全旁路 | 完全依赖 OS loader |

---

## 三、可借鉴度评分

| 项目 | 可借鉴度 | 主要价值 | 主要问题 |
|---|---|---|---|
| peldr | ★★★★★ | 栈对齐跳 OEP、SecurityCookie、RtlAddFunctionTable、API hash、整体架构清晰 | reloc 只支持 DIR64、TLS 仅 ATTACH |
| AlushPacker | ★★★ | forwarder 递归、节权限 NOCACHE、延迟导入 | 带 CRT 体积大、tls.h 注释掉、硬编码 ntdll 偏移极度脆弱 |
| AtomPePacker | ★★★ | RefreshNtdll 解 hook、IAT 伪装、Syscalls.lib | LZMA 库体积大、TLS 顺序错、无加密 |
| amber | ★★★★ | 纯 PIC shellcode、CRC32 硬件指令、wipe 反 dump、SGN 多态编码 | 无 .pdata/SecurityCookie/TLS 数据分配 |
| pe-packer-rust | ★★ | payload 魔数/版本/Argon2/AES-GCM 完整加密栈 | stub 体积爆炸、无 PIC、无 hash、依赖 OS loader |

---

## 四、关键源码位置索引（供后续深入查阅）

- peldr 栈对齐跳 OEP：`F:\Temp\pe\peldr-main\loader.c:1144-1152`
- peldr SecurityCookie：`F:\Temp\pe\peldr-main\loader.c:464-482`
- peldr API hash 表：`F:\Temp\pe\peldr-main\loader.h:262-277`
- peldr 反调试三阶段：`F:\Temp\pe\peldr-main\loader.c:858-908`
- peldr builder 加密：`F:\Temp\pe\peldr-main\peldr.c:197-235`
- AlushPacker forwarder 递归：`F:\Temp\pe\AlushPacker-main\Packer\loader.c:62-87, 241-300`
- AlushPacker TLS proxy（注释）：`F:\Temp\pe\AlushPacker-main\Packer\loader.c:395-557`
- AlushPacker SEH x86 patch（脆弱）：`F:\Temp\pe\AlushPacker-main\Packer\loader.c:560-578`
- AtomPePacker RefreshNtdll：`F:\Temp\pe\AtomPePacker-NUL0x4C-main\PP64Stub\Utils.c:90-163`
- AtomPePacker IAT 伪装：`F:\Temp\pe\AtomPePacker-NUL0x4C-main\PP64Stub\IatCamouflage.h`
- amber 完整 loader 流程：`F:\Temp\pe\amber-master\loader\loader-x64\loader-x64.asm`
- amber wipe 反 dump：`F:\Temp\pe\amber-master\loader\loader-x64\loader-x64.asm:47-56`
- amber CRC32 硬件：`F:\Temp\pe\amber-master\loader\loader-x64\inc\calc_crc.asm`
- amber SGN 编码集成：`F:\Temp\pe\amber-master\main.go:53-62`
- pe-packer-rust payload 格式：`F:\Temp\pe\pe-packer-rust\common\src\lib.rs:22-167`
- pe-packer-rust CreateThread 跳 OEP：`F:\Temp\pe\pe-packer-rust\stub\src\main.rs:88-105`
- pe-packer-rust 节追加：`F:\Temp\pe\pe-packer-rust\builder\src\main.rs:75-165`

---

## 五、总结

5 个项目代表反射式 PE loader 的 4 种典型范式：
1. **peldr = 工程化最完整的 PIC C 无 CRT 反射式 loader**（栈对齐、SecurityCookie、API hash、反调试、scrub 全部到位），最适合作为 winlock 反射式模式的主参考
2. **AlushPacker = 带 CRT 的 MSVC 友好实现**，forwarder 递归和节权限 NOCACHE 处理值得借鉴，但 TLS proxy 和 ntdll 偏移硬编码是反面教材
3. **AtomPePacker = 反 hook + IAT 伪装特色**，RefreshNtdll 从 KnownDlls 重映射 ntdll .text 的思路非常实用
4. **amber = 纯 PIC shellcode 极简主义**，CRC32 硬件 hash、wipe 反 dump、SGN 多态编码是独门绝技，但 SEH/TLS/SecurityCookie 全缺
5. **pe-packer-rust = 现代加密栈参考**，AES-GCM + Argon2 + 魔数版本号设计完整，但 stub 体积和 OS loader 依赖度不可接受

对 winlock 项目，**最值得借鉴的组合是 peldr 的整体架构 + AlushPacker 的 forwarder 递归 + AtomPePacker 的 RefreshNtdll + amber 的 wipe 反 dump + pe-packer-rust 的魔数版本号设计**。

---

**文档版本**：1.0
**最后更新**：2026-07-19
**分析依据**：1 个 subagent 深度阅读 5 个项目核心源码
