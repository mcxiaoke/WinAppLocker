# 变更记录

## 2026-07-20 23:30 修复 DontSleep 反射式加载崩溃 + 强制基址加载

### 问题
DontSleep 反射式加载后弹框 "Error! Loading language file string archive"，正常界面无法显示。
用 UPX/VMProtect 加壳同样问题，DIE 显示 `.data compressed`。

### 根因
1. DontSleep 的 `.data` 段被压缩（vsize=247KB, rsize=75KB），重定位表为空（ASLR 关闭），
   内层解压 stub 依赖原始 ImageBase 0x400000
2. 0x400000 处已有文件映射（MAPPED），VirtualAlloc 失败后 fallback 到任意地址导致偏移错误
3. manifest 激活（CreateActCtxA）在 PEB 刚修改后立即调用，触发 ntdll 内部 ACCESS_VIOLATION

### 修复
1. **map_image 新增 NtUnmapViewOfSection 逻辑**：VirtualAlloc(preferred) 失败时检查是否为 MAPPED 类型，
   如果是则卸载后重试，确保 payload 加载到原始 ImageBase
2. **manifest 激活延迟**：从 IAT 处理前移到 TLS callbacks 后，避免 PEB 修改后立即调用 CreateActCtxA

### 测试
- DontSleep 反射式加载成功，主界面正常显示 "Don't Sleep 9.96"
- manifest 正常激活（comctl32 v6）

## 2026-07-20 21:00 x86 MSVC 迁移完成：纯 C 位运算长除法替代 __aulldvrm

完成 x86 架构从 MinGW 迁移到 MSVC 的最后关键一步：用纯 C 位运算长除法替代 `__aulldvrm` MASM 实现，彻底消除 64 位除法的 CRT 依赖。

### 1. 问题背景

- x86 `/NODEFAULTLIB` PIC stub 中，MSVC 对 64 位 `/` 和 `%` 会生成 `__aulldiv` / `__aulldvrm` 调用
- 自实现 `__aulldvrm` MASM 汇编存在调用约定/参数数量不匹配问题（MSVC 实际调用时只 push 4 个参数，缺少 rem_ptr），导致 stub_reflective_x86 运行时 crash 在 `__aulldvrm+0x2b`

### 2. 解决方案

- **删除 `packer/reflective/aulldvrm.asm`**（移到 temp 备份）
- **新增 `pic_u64_divmod()` 函数**（packer/reflective/loader.c）：
  - 二进制长除法，循环 64 次
  - 所有位移都是常数（`<< 1`, `>> 63`），MSVC 编译为纯 `shl/rcl/shr` 指令
  - 64 位比较/减法是纯 `cmp/sbb/sub` 指令序列
  - **不引入任何外部符号引用，100% PIC 安全**
- **`u64_to_str()` 改用 `pic_u64_divmod()`** 替代 `v % base` 和 `v /= base`

### 3. 验证结果

完整 build（x64 + x86）+ 端到端测试 8 样本：
- **reflective 8/8 PASS**（x64 + x86 全部通过，包括之前 crash 的 helloguix86）
- **inplace 6/8 PASS**（hellomingw/helloucrt 的 x64 inplace 失败是已知 CRT/CFG 问题，stub.c 未改动，与本次迁移无关）

### 4. dist/ 最终产物（8 个文件）

```
builder_inplace.exe        stub_inplace_x64.bin     stub_reflective_x64.exe
builder_reflective.exe     stub_inplace_x64.exe     stub_reflective_x86.exe
                           stub_inplace_x86.bin
                           stub_inplace_x86.exe
```

---

## 2026-07-20 12:25 构建脚本统一：dotnet/build.ps1 改调 packer/build.ps1（MSVC x64）

把 .NET 项目的 WinLock 编译入口从 `mingw32-make` 切换为调用 `packer/build.ps1`（MSVC + CMake + Ninja），完成构建链统一化。

### 1. 主要改动

- **新增 `packer/build.ps1`**：MSVC + CMake + Ninja 构建脚本（x64 only）
  - 用 `-S $root -B $buildDir` 显式指定源码与 build 目录（修复污染源码目录的 bug）
  - 通过 `vcvars64.bat` 注入 MSVC 环境到 PowerShell session
  - 按需编译 target：`stub_x64` / `builder` / `loader_x64` / `builder_reflective`
  - 自动复制产物到源码目录（loader_x64.exe 由 CMake POST_BUILD 自动复制）
  - 支持 `-Debug` / `-Release` / `-Clean` / `-SkipReflective` / `-SkipInplace` 参数
- **修复 `dotnet/build.ps1`**：
  - 删除 `mingw32-make all all-x86 reflective-all` 调用 + PATH 设置 + Push-Location 逻辑
  - 改为 `& "$winlockDir\build.ps1" @winlockBuildArgs`（传递 -Release / -Clean）
  - 给所有 `dotnet build` 调用加 `-p:Platform=AnyCPU`：.NET 10 SDK 默认 Platform=x64 会把产物输出到 `bin\x64\Release\`，与 build.ps1 假设的 `bin\$(Configuration)\` 路径不一致
  - x86 stub/loader（MSVC 迁移未完成）继续由下方汇集逻辑以 warning 处理，不阻断构建

### 2. 验证结果

`dotnet/build.ps1 -Clean -Release` 端到端跑通：

```
stub_gui / stub_console / stub_test 编译（AnyCPU）  ✓
WinLock packer/build.ps1（MSVC x64）              ✓
  stub_x64.exe          9216 bytes
  stub_x64.bin         24592 bytes
  builder.exe         181760 bytes
  loader_x64.exe       29184 bytes
  builder_reflective.exe 170496 bytes
stub 汇集（15 个文件含 meta.json）                ✓
packer 编译 + Costura 嵌入依赖                    ✓
dist/ 准备就绪：
  WinAppLocker.exe     1172992 bytes
  WinAppLocker.exe.config 794 bytes
  stub/ 15 个 stub 文件                          ✓
```

### 3. 已知限制

- x86 stub/loader 仍需 MinGW Makefile.mingw 单独编（MSVC x86 迁移未完成，主要因 x86 ml.exe 不能处理 x64 寄存器 + loader_x86 缺 `__aulldvrm` 辅助）
- build.ps1 复制 winlock_stub_x86.bin / loader_x86.exe 时若缺失仅 warning，不阻断

---

## 变更记录 2026-07-20 MSVC 迁移阶段 4 步骤 C3b 完成：完全 PIC 化（剥离 CRT）

按 `packer/docs/MSVC_PORRINT_AND_PIC_SPEC.md` 阶段 4 步骤 C3b（spec 第 337-349 行）实施，把 `loader_x64.exe` 从 `/MT` 静态 CRT 模式改为 `/NODEFAULTLIB` 完全 PIC 化模式，剥离所有 CRT 依赖。

### 1. 核心收益

| 指标 | C3（/MT 静态 CRT） | C3b（完全 PIC） | 改善 |
|------|-------------------|----------------|------|
| loader_x64.exe 体积 | 127488 字节 | 29184 字节 | **-77%** |
| kernel32 导入函数数 | 80+ | 25 | **-69%** |
| CFG（Guard CF 表） | 启用（`.fptable` 节 + `guard_dispatch_icall_nop`） | 禁用（`/loadconfig` 输出空） | ✓ |
| CRT 启动依赖 | FlsAlloc/HeapAlloc/InitializeCriticalSectionEx/GetStartupInfoW/GetCommandLineW 等 | 无 | ✓ |
| DIE 识别特征 | "Microsoft Linker 14.51 + UCRT" | 仅 user32+kernel32 25 个 API | ✓ |

### 2. 实施内容

#### 2.1 编译选项（`packer/reflective/CMakeLists.txt`）

新增 MSVC PIC 化编译选项：
- `/GS-` 关闭 stack cookie（避免引用 `__security_cookie`）
- `/Gs1048576` 关闭栈探针（阈值 1MB，避免引用 `__chkstk`）
- `/GL-` 关闭 LTCG（避免引入额外 CRT 依赖）
- `/Zl` 不在 .obj 中引用默认库（配合 `/NODEFAULTLIB`）
- `/guard:cf-` 关闭 CFG 插桩（cl.exe 语法，避免生成 CFG 函数表）
- `/GUARD:NO` 链接阶段禁用 CFG（link.exe 语法，与 cl.exe 对应）

链接选项：
- `/NODEFAULTLIB` 不链接任何默认库（CRT/kernel32 等都不链）
- `/ENTRY:loader_main` 自定义入口（跳过 `mainCRTStartup`，不依赖 CRT 启动代码）
- 显式链接 `user32 + kernel32`（`/NODEFAULTLIB` 后需手动指定）

#### 2.2 loader.c 入口函数改造（`packer/reflective/loader.c:2044-2054`）

`WinMain` → `void WINAPI loader_main(void)`：
- MSVC：`void WINAPI loader_main(void)` + `LOADER_EXIT(n)` 宏（调用 `ExitProcess(n)`）
- GCC：保持 `int main(int argc, char* argv[])`（MinGW GUI 子系统接受 main）

```c
#ifdef _MSC_VER
#define LOADER_EXIT(n) ExitProcess((UINT)(n))
#else
#define LOADER_EXIT(n) return (n)
#endif
#ifdef _MSC_VER
void WINAPI loader_main(void) {
#else
int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
#endif
```

#### 2.3 自实现 memset/memcpy/memcmp（`packer/reflective/loader.c:69-100`）

`/NODEFAULTLIB` 下没有 CRT 提供的 memset/memcpy/memcmp，需要自实现。用 `#pragma function(memset, memcpy, memcmp)` 强制编译器使用函数调用（不用 intrinsic），让本地实现被实际调用。

与 stub.c 的实现一致（但不用 `WINLOCK_SECTION_TEXT`，loader 用普通 .text 节）。

### 3. CFG 禁用前后对比

#### C3（启用 CFG，`/MT`）

```
$ dumpbin /loadconfig loader_x64.exe
  Guard CF address of check-function pointer: 0x1400122C0
  Guard CF address of dispatch-function pointer: 0x1400122D0
  Guard Flags: 0x100 (CF instrumented)
  .fptable 节（CFG 函数表）
```

IAT 从 kernel32 导入 80+ 函数（HeapAlloc/FlsAlloc/InitializeCriticalSectionEx/QueryPerformanceCounter/GetStartupInfoW 等 CRT 启动依赖）。

#### C3b（禁用 CFG，`/NODEFAULTLIB`）

```
$ dumpbin /loadconfig loader_x64.exe
  (空输出 - 没有 Load Config Directory)
```

IAT 只剩 25 个真正用到的 kernel32 函数：
- `AddVectoredExceptionHandler` / `RtlAddFunctionTable` / `RtlLookupFunctionEntry` / `RtlVirtualUnwind`（VEH + SEH）
- `VirtualAlloc` / `VirtualProtect` / `VirtualFree` / `VirtualQueryEx`（反射式加载）
- `LoadLibraryA` / `GetProcAddress` / `GetModuleHandleW`（IAT 解析）
- `CreateFileA` / `WriteFile` / `FlushFileBuffers` / `CloseHandle` / `DeleteFileA`（日志）
- `ExitProcess` / `GetLastError` / `GetCurrentProcess`（控制流）
- `CreateActCtxA` / `ActivateActCtx` / `SetDllDirectoryW` / `SetCurrentDirectoryW` / `GetTempPathA` / `GetModuleFileNameA/W`（ActCtx + 路径）

节布局精简（无 `.fptable` 节）：
```
  .CRT   1000  (TLS callback)
  .data  1000
  .pdata 1000  (x64 SEH)
  .rdata 3000
  .rsrc  1000
  .text  4000
```

### 4. 测试结果

用 `temp/test_phase4c_compare.py` 双向对比测试（8 样本）：

| 样本 | MSVC C3b | MinGW 基线 | 一致 |
|------|---------|-----------|------|
| helloguix64 | PASS | PASS | yes |
| helloguix86 | PASS | PASS | yes |
| hellocli | PASS | PASS | yes |
| hellomfcx64 | PASS | PASS | yes |
| hellomingw | PASS | PASS | yes |
| helloucrt | PASS | PASS | yes |
| Notepad4 | PASS | PASS | yes |
| DontSleep | PASS | PASS | yes |

**8/8 全 PASS，与 MinGW 基线完全一致**。

### 5. 已知差异（不影响功能）

MSVC stub 的 `VirtualAlloc(preferred=0x140000000)` 失败（err=487），因为 stub 自身 ImageBase=0x140000000 占用了该地址。MinGW stub 启用 ASLR 运行时被重定位到其他地址，让出 0x140000000。

- 不影响功能：fallback_relocations 能处理（DontSleep 走此路径，8 字节扫描修复后 PASS）
- 不影响性能：大多数 PE 有 .reloc 表，走 apply_relocations 正常路径
- 后续优化：可改 /BASE 到不常用地址（如 0x10000000）让出 0x140000000

### 6. 涉及文件

- **修改** `packer/reflective/CMakeLists.txt`：加 PIC 化编译/链接选项（`/GS- /Gs1048576 /GL- /Zl /guard:cf- /NODEFAULTLIB /ENTRY:loader_main /GUARD:NO`）
- **修改** `packer/reflective/loader.c`：
  - 新增 memset/memcpy/memcmp 自实现（`#pragma function` + 本地实现）
  - 入口函数 `WinMain` → `void WINAPI loader_main(void)` + `LOADER_EXIT` 宏

### 7. 临时验证文件

- `temp/build_phase4c_msvc.py`：MSVC 编译脚本
- `temp/test_phase4c_compare.py`：MSVC vs MinGW 基线对比测试（8 样本）
- `temp/test_phase4c_regression.py`：精简回归测试（8 样本）
- `temp/analyze_loader_crt_deps.ps1`：dumpbin 分析 imports/loadconfig/symbols

### 下一步

阶段 4 步骤 C3b 完成，按 spec 进入：
- 阶段 5：方案 B 节名伪装 + 特征消除（`.lock` 节重命名、CheckSum 清零等）
- 阶段 6：stub 提取 .lock 节（与 builder 整合）
- 阶段 7：端到端验证

## 变更记录 2026-07-20 MSVC 迁移阶段 4 步骤 C 完成：TLS callback + MSVC 链接 + 8/8 全样本 PASS

按 `packer/docs/MSVC_PORRINT_AND_PIC_SPEC.md` 阶段 4 步骤 C（spec 第 315-380 行）实施，把 `packer/reflective/loader.c` + 汇编 stub 通过 CMake + MSVC 工具链编译，使 MSVC stub 替代 MinGW stub 作为加壳用的 loader。

### 1. C1：新增 jump_to_oep 独立 .asm 文件

MSVC x64 不支持内联汇编，必须把 `jump_to_oep` 抽到独立 MASM 文件实现。`__attribute__((section))` 在 MSVC 上也不支持 `$` 字符的节名，需要通过 `winlock_compat.h` 宏切换。

- **`packer/reflective/loader_asm_x64.asm`**（新建）：MASM 实现 `jump_to_oep_x64(oep, ret_addr)`，做 16 字节栈对齐 + push ret_addr + jmp oep
- **`packer/reflective/loader_asm_x86.asm`**（新建）：MASM x86 实现 `jump_to_oep_x86`，使用 `__cdecl` 调用约定

### 2. C2：loader.c 编译器抽象切换

`packer/reflective/loader.c` 中所有 GCC 内联汇编 / GCC section 属性都改为 `#ifdef _MSC_VER` 双模式：

- `jump_to_oep`：GCC 内联汇编 → MSVC extern 调用 .asm（`packer/reflective/loader.c:355-406`）
- TLS callback 节区属性：`__attribute__((section(".CRT$XLB"), used))` → `WINLOCK_SECTION_CRT_XLB` 宏（`packer/reflective/loader.c:1340-1350`）
- 入口函数：GCC `main` → MSVC `WinMain`（`/SUBSYSTEM:WINDOWS` 期望 `WinMain`，`packer/reflective/loader.c:2002-2017`）

`packer/common/winlock_compat.h` 提供 `WINLOCK_SECTION_CRT_XLB` 宏的跨编译器实现（MSVC `__pragma(section) + __declspec(allocate)`，GCC `__attribute__((section))`）。

### 3. C3：新建 reflective/CMakeLists.txt

`packer/reflective/CMakeLists.txt`（新建）+ `packer/CMakeLists.txt` 启用 `add_subdirectory(reflective)`：

- x64 target：`add_executable(loader_x64 WIN32 loader.c loader_asm_x64.asm)`
- 编译选项：`/O2 /Gy`（不定义 `WINLOCK_PIC`，loader 用普通 `.text` 节，不像 stub 那样做 `.lock` 节提取）
- 链接选项：`/SUBSYSTEM:WINDOWS /BASE:0x140000000 /DYNAMICBASE:NO /OPT:REF /OPT:ICF`
  - `/BASE:0x140000000` 与 MinGW 基线一致，避免撞上输入 PE 的 0x400000
  - （试过 `/BASE:0x10000` 导致系统在 0x400000 附近映射 shared section，VirtualAlloc 失败；后查证真正根因是 fallback_relocations 的 x64 8 字节扫描缺失，见下文 §6）
- 链接 user32（DialogBoxParamW / LoadStringW / MessageBoxW）
- x86 target：`if(WINLOCK_BUILD_X86 AND CMAKE_SIZEOF_VOID_P EQUAL 4)`，需用 `-A Win32` 单独配置，加 `/FIXED:NO` 保留 .reloc

### 4. C4：MSVC 编译验证

| 项目 | MSVC 新编译 | MinGW 基线 |
|------|------------|-----------|
| loader_x64.exe | 127488 字节 | 118098 字节 |
| ImageBase | 0x140000000 | 0x140000000 |
| 子系统 | WINDOWS | WINDOWS |
| builder_reflective.exe | 170496 字节 | — |

MSVC 版稍大（约 9KB），因为 `/MT` 静态链接 CRT（spec 中 C3b 才用 `/NODEFAULTLIB` 完全剥离 CRT）。

### 5. C5：MSVC vs MinGW 基线对比测试

用 `release/packer-mingw-git-7311644/` 作 MinGW 基线，运行 `temp/test_phase4c_compare.py` 双向对比：

| 样本 | MSVC | MinGW | 一致 |
|------|------|-------|------|
| helloguix64 | PASS | PASS | yes |
| helloguix86 | PASS | PASS | yes |
| hellocli | PASS | PASS | yes |
| hellomfcx64 | PASS | PASS | yes |
| hellomingw | PASS | PASS | yes |
| helloucrt | PASS | PASS | yes |
| Notepad4 | PASS | PASS | yes |
| **DontSleep** | **PASS** | PASS | yes |

**8/8 全部 PASS**，与 MinGW 基线完全一致。

### 6. 修复关键 bug：fallback_relocations 在 x64 上必须扫 8 字节（DIR64）

调试 DontSleep 时发现：原本 DontSleep 在 MSVC 下崩溃（exit=0xC0000005），VEH 日志显示崩溃在 `msvcrt!guard_dispatch_icall_nop`，`read address=0xffffffffffffffff`。

**根因**：`fallback_relocations` 原本无条件按 4 字节步长扫描绝对地址引用。在 x64 上这会破坏 8 字节对齐的指针：

- 例如 .CRT$XLB 节中的 CRT init 函数指针 `0x0000000140001234`（指向 DontSleep 内部函数）
- 4 字节扫描只改低 4 字节：`0x40001234` → `0x40001234 + delta = 0x20e01234`
- 高 4 字节 `0x00000001` 不变，最终指针变成 `0x00000001_20e01234`（错误地址，比目标 0x20e01234 多 1GB 偏移）
- DontSleep 启用 CFG，所有间接 call 走 `guard_dispatch_icall_nop`，调用坏指针时触发 AV，target 显示为 `0xffffffffffffffff`（越界读到栈垃圾）

**修复**（`packer/reflective/loader.c:973-1031`）：用 `#ifdef _WIN64` 区分扫描宽度，x64 上扫 8 字节、用 int64 delta；x86 保持 4 字节 + int32 delta：

```c
#ifdef _WIN64
    #define FALLBACK_SCAN_UNIT 8
    int64_t delta64 = (int64_t)(new_base - old_base);
#else
    #define FALLBACK_SCAN_UNIT 4
#endif
```

修复后 DontSleep fallback 改了 1469 个 8 字节引用（原 1918 个 4 字节引用），全部正确，PASS。

### 7. 清理：移除调试用 PEB.Ldr 模块遍历诊断代码

调试 DontSleep 时在 `loader.c` 中临时添加了 PEB.Ldr 模块遍历代码（找占用 0x400000 的 DLL）。问题修复后已移除（`packer/reflective/loader.c:1776` 处保留 VirtualQueryEx 区域查询作通用诊断，移除 PEB.Ldr 遍历）。

### 涉及文件

- **新建** `packer/reflective/loader_asm_x64.asm`：MASM x64 实现 jump_to_oep
- **新建** `packer/reflective/loader_asm_x86.asm`：MASM x86 实现 jump_to_oep
- **新建** `packer/reflective/CMakeLists.txt`：MSVC 编译配置
- **修改** `packer/CMakeLists.txt`：启用 `add_subdirectory(reflective)`
- **修改** `packer/reflective/loader.c`：
  - `jump_to_oep` 双模式（GCC 内联汇编 / MSVC extern + .asm）
  - TLS callback 用 `WINLOCK_SECTION_CRT_XLB` 宏
  - 入口函数 `main` → MSVC `WinMain`
  - `fallback_relocations` x64 改 8 字节扫描（DIR64 修复）
  - 移除 PEB.Ldr 调试诊断代码

### 临时验证文件（在 `temp/`，被 .gitignore 排除）

- `temp/build_phase4c_msvc.py`：MSVC 编译脚本（vcvars64.bat + cmake + ninja）
- `temp/test_phase4c_compare.py`：MSVC vs MinGW 基线双向对比测试（8 样本）
- `temp/test_phase4c_regression.py`：精简回归测试（8 样本）
- `temp/check_imagebase.ps1` / `temp/dump_sections.ps1` / `temp/dump_imports.ps1` / `temp/dump_dllchars.ps1`：dumpbin PE 分析脚本
- `temp/phase4c_compare/`：对比测试产物目录（msvc/ + mingw_baseline/）

### 下一步

阶段 4 步骤 C 完成，按 spec 进入阶段 5：
- 阶段 5：**C3b 完全 PIC 化**（用 `/NODEFAULTLIB /ENTRY:loader_main` 编译 loader，剥离 CRT 静态链接，loader_x64.exe 体积从 127KB 降到 15-20KB）
- 阶段 6：stub 提取 .lock 节（与 builder 整合）
- 阶段 7：端到端验证

## 变更记录 2026-07-20 MSVC 迁移阶段 4 步骤 B 完成：loader.c 内存改 Win32 API

按 `packer/docs/MSVC_PORRINT_AND_PIC_SPEC.md` 阶段 4 步骤 B（spec 第 306-313 行）实施，把 `packer/reflective/loader.c` 的动态内存分配从 CRT（calloc/free/strnlen）切换到 Win32 API（VirtualAlloc/VirtualFree），并为 step C 的 PIC 化（彻底剥离 CRT）继续铺路。

### 1. 双模式内存实现（`packer/reflective/loader.c:868-891`，`fallback_relocations`）

引入 `#ifdef WINLOCK_KEEP_CRT` 双模式开关（与 step A 一致）：

- **默认（Win32 API 模式，无 CRT 依赖）**：
  - `calloc(size_of_image, 1)` → `VirtualAlloc(NULL, size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE)`
  - 关键：`MEM_COMMIT` 提交的页是零页（OS 保证），与 `calloc(n, 1)` 行为等价，无需额外 `memset` 清零
  - 失败时调用 `GetLastError()` 记录错误码到日志（替代原 `calloc failed`）
  - `free(skip)` → `VirtualFree(skip, 0, MEM_RELEASE)`（释放整个 reserve 区域）

- **`-DWINLOCK_KEEP_CRT`（CRT 模式，回滚用）**：保留原 `calloc` / `free` 实现

### 2. strnlen → my_strnlen 自实现（`packer/reflective/loader.c:126-132`）

发现 step A 漏处理：`fallback_relocations` 中有 2 处 `strnlen` 调用（line 894、912），用于扫描 IMPORT 表中 DLL 名字 / 函数名字字符串长度。CRT 模式 `<string.h>` 提供，Win32 API 模式无此 API。

新增 `my_strnlen(const char* s, size_t maxlen)`：与 `strnlen` 语义完全一致（返回 s 长度，最多 maxlen 字节）。**无条件定义**，CRT 和 Win32 API 模式共用，保证行为一致。替换 line 894/912 两处 `strnlen` 调用。

### 3. memset/memcmp 保留

按 spec 要求保留，因为 MSVC 把它们当作 intrinsics（编译器内置），不会引入 CRT 符号依赖：
- `memset(skip + rva, 1, size)`（line 877-881）：标记 IMPORT/IAT/DELAY_IMPORT 区域为不可改
- `memcmp(sec[i].Name, ".rsrc", 5)`（line 928）：跳过 .rsrc 节
- `memcpy`（其他函数，如 TLS data 复制、节拷贝）：同理保留

GCC 也支持 `-fno-builtin` 不影响 intrinsics，所以默认模式下 `memset`/`memcmp`/`memcpy` 都是编译器内置实现，**没有 CRT 符号依赖**。

### 4. 影响范围

修改位置全部在 `packer/reflective/loader.c`：
- 新增 `my_strnlen`（line 126-132）
- `fallback_relocations` 的 skip bitmap 分配（line 868-891，calloc→VirtualAlloc 双模式）
- `fallback_relocations` 的 skip bitmap 释放（line 979-983，free→VirtualFree 双模式）
- IMPORT 表扫描的 2 处 `strnlen` → `my_strnlen`（line 901、919）

### 5. 验证结果（MinGW 编译）

测试脚本：`temp/test_phase4b.py`（test mode `-t`，跳过密码框直接走 `verify_password(L"test123")`）

| 样本 | 架构 | 结果 | 备注 |
|------|------|------|------|
| helloguix64 | x64 | PASS | GUI 启动后 3 秒仍存活 |
| helloguix86 | x86 | PASS | 日志显示 `VirtualAlloc(0x400000) failed err=487`（ERROR_INVALID_ADDRESS，预期 fallback），走任意地址 + fallback_relocations（**正好走 step B 修改的代码路径**） |
| hellocli | x64 | PASS | exit=0，stdout="Hello World!" |
| hellomfcx64 | x64 | PASS | MFC + /GS SecurityCookie 初始化正常 |
| hellomfcx86 | x86 | PASS | 同 helloguix86，VirtualAlloc fallback 路径正常 |
| hellomingw | x64 | PASS | TLS_PROXY 模式正常 |
| helloucrt | x64 | PASS | TLS_PROXY 模式正常 |
| Notepad4 | x64 | PASS | 真实应用（2.4MB），加载正常 |
| DontSleep | x64 | PASS | 真实应用（600KB），ImageBase=0x400000 但 x64 不冲突，正常加载 |

**9/9 全部 PASS**，与阶段 4 步骤 A 结束时基线一致。x86 样本 fallback_relocations 路径正好覆盖 step B 修改，验证 VirtualAlloc/VirtualFree 行为正确。

### 6. 编译产物对比

| 模式 | 文件 | 体积 | 说明 |
|------|------|------|------|
| Win32 API | loader_x64.exe | 79509 字节 | 默认模式（无 CRT 依赖） |
| Win32 API | loader_x86.exe | 144734 字节 | x86 比 x64 大，因 x86 调用约定差异 + winsock 等 |
| CRT 回归 | loader_x64_crt.exe | 113663 字节 | `-DWINLOCK_KEEP_CRT` 回滚路径仍可编译，体积比 Win32 模式大 34KB（CRT 静态链接） |

体积差异证明 Win32 API 模式确实剥离了 CRT 依赖，为 step C 的 PIC 化奠定了基础。

### 7. 残留 CRT 调用清单

经 grep 验证，loader.c 中 CRT 调用剩余分布：
- `calloc` / `free`：仅在 `#ifdef WINLOCK_KEEP_CRT` 分支内（line 877/880/980）—— 回滚路径，预期
- `fopen` / `fprintf` / `fflush` / `vsnprintf`：仅在 `#ifdef WINLOCK_KEEP_CRT` 分支内（step A 处理过）—— 回滚路径，预期
- `memset` / `memcmp` / `memcpy`：保留（MSVC intrinsics，非 CRT 依赖）

**Win32 API 模式下（默认编译），loader.c 已无任何 CRT 符号依赖**，为 step C 用 MSVC + `/NODEFAULTLIB` 编译铺平道路。

### 涉及文件

- `packer/reflective/loader.c`：`my_strnlen` 自实现 + `fallback_relocations` 的 calloc→VirtualAlloc / free→VirtualFree 双模式 + 2 处 strnlen→my_strnlen

### 临时验证文件（在 `temp/`，被 .gitignore 排除）

- `temp/test_phase4b.py`：阶段 4 步骤 B 编译 + 9 样本测试
- `temp/phase4b_test/`：测试产物目录（加壳 EXE + 日志）

### 下一步

阶段 4 步骤 C（spec 第 315-380 行）：TLS callback + MSVC 链接
- `__attribute__((section(".CRT$XLB"), used))` → 用 winlock_compat.h 宏（MSVC `#pragma section` + `__declspec(allocate)`）
- 新建 `packer/reflective/loader_asm_x64.asm` 和 `loader_asm_x86.asm`（jump_to_oep 独立汇编，与 stub 一致）
- 新建 `packer/reflective/CMakeLists.txt`（用 MSVC + `/NODEFAULTLIB /ENTRY:loader_main /SUBSYSTEM:WINDOWS` 编译 PIC 化 loader）
- 验证点：DIE 识别从 "Unknown" → "Microsoft Linker 14.51"，loader_x64.exe 体积 40-60KB → 15-20KB

## 变更记录 2026-07-20 MSVC 迁移阶段 4 步骤 A 完成：loader.c 日志改 Win32 API

按 `packer/docs/MSVC_PORRINT_AND_PIC_SPEC.md` 阶段 4 步骤 A（spec 第 295-304 行）实施，把 `packer/reflective/loader.c` 的日志实现从 CRT（fopen/fprintf/fflush/strrchr/strcpy/strcat）切换到 Win32 API（CreateFileA/WriteFile/FlushFileBuffers），为阶段 4 步骤 C 的 PIC 化（剥离 CRT）铺路。

### 1. 双模式日志实现（`packer/reflective/loader.c`）

引入 `#ifdef WINLOCK_KEEP_CRT` 双模式开关（spec 部分回滚 1 的接口）：

- **默认（Win32 API 模式，无 CRT 依赖）**：
  - `log_init()` 改用 `CreateFileA(path, GENERIC_WRITE, ..., CREATE_ALWAYS, ...)` 替代 `fopen`
  - `log_write()` 改用 `WriteFile` + `FlushFileBuffers` 替代 `fwrite` + `fflush`
  - `log_printf()` 用自实现的 `mini_vsnprintf` 格式化替代 `vsnprintf`（user32 的 `wvsprintfA` 不支持 `%zu`/`%llx`/`%p`/`%ls`）
  - 自实现 `my_strrchr` / `my_strcpy` / `my_strcat` 替代 CRT 字符串操作
  - 不调 `OutputDebugStringA`（避免触发 `0x40010006` 异常干扰 VEH 调试，保留原行为）

- **`-DWINLOCK_KEEP_CRT`（CRT 模式，回滚用）**：
  - 保留原 `fopen` / `fprintf` / `fflush` / `vsnprintf` / `strrchr` / `strcpy` / `strcat` 实现
  - 但 `log_init` 也用 `my_strrchr`/`my_strcpy`/`my_strcat`（统一行为，单点测试）

### 2. mini_vsnprintf 实现（约 100 行）

支持 loader.c 中用到的所有格式化字符串：
- 整数：`%d` `%i` `%u` `%x` `%X` `%ld` `%lu` `%lx` `%lld` `%llu` `%llx` `%zu`
- 指针：`%p`（输出 `0x` + 十六进制，与 CRT 一致）
- 字符串：`%s` `%ls`（宽字符串按低 8 位转 ASCII 输出，节名/路径用）
- 字符：`%c`
- 精度：`%.Ns`（如 `%-8.8s` 输出节名前 8 字符）
- flags 和宽度：跳过（不实现填充，仅兼容解析，避免 `%4x` 被误识别为 `%` + `4` + `x`）
- 不支持：浮点 `%f`/`%e`/`%g`（loader.c 不用）

### 3. 影响范围

修改位置（全部在 `packer/reflective/loader.c` 内）：
- 顶部 includes：用 `#ifdef WINLOCK_KEEP_CRT` 控制 `<stdio.h>`/`<stdlib.h>`/`<string.h>`，Win32 模式只引入 `<stdarg.h>`（va_list 是编译器内置）
- `log_init` / `log_write` / `log_printf` / `DBG` / `DBG_RAW`：双模式实现
- `oep_returned`：`fprintf` + `fflush` → `DBG_RAW`（自动调 `log_printf`）
- `refl_veh`（VEH 异常处理）：所有 `fprintf`/`fflush` 调用替换为 `DBG_RAW`（约 15 处）
- `activate_manifest_from_image`：`strcat` → `my_strcat`

### 4. 验证结果（MinGW 编译）

测试脚本：`temp/test_phase4a_extended.py`（test mode `-t`，跳过密码框直接走 `verify_password(L"test123")`）

| 样本 | 架构 | 结果 | 备注 |
|------|------|------|------|
| helloguix64 | x64 | PASS | GUI 启动后 3 秒仍存活 |
| helloguix86 | x86 | PASS | GUI 启动后 3 秒仍存活 |
| hellocli | x64 | PASS | exit=0，stdout="Hello World!" |
| hellomfcx64 | x64 | PASS | MFC + /GS SecurityCookie 初始化正常 |
| hellomfcx86 | x86 | PASS | MFC x86 启动正常 |
| Notepad4 | x64 | PASS | 真实应用（2.5MB），加载正常 |
| DontSleep | x64 | PASS | 真实应用（600KB），加载正常 |
| hellomingw | x64 | PASS | TLS_PROXY 模式正常（reflective 的 TLS proxy 一直工作） |
| helloucrt | x64 | PASS | TLS_PROXY 模式正常 |

**9/9 全部 PASS**，与阶段 3 结束时基线一致（reflective 模式从未受 inplace TLS_PROXY bug 影响）。

### 5. 日志格式差异（无功能影响）

- CRT 模式 `%p` 输出大写 `00007FF6...`（补 0 到 16 位），Win32 模式输出小写 `0x7ff6...`（不补 0）
- CRT 模式 `%04x` 输出 `000b`，Win32 模式输出 `b`（不补 0）
- 节名 `%-.8s` 两种模式都正确输出 `.text` / `.rdata` 等

差异不影响功能（日志可读性无差别），是预期的代价（mini_vsnprintf 不实现填充以保持代码简洁）。

### 6. CRT 模式回归验证

用 `gcc -DWINLOCK_KEEP_CRT` 编译生成 `loader_x64_crt.exe`，加壳 helloguix64 运行后日志输出正常，证明 CRT 模式（回滚路径）仍工作。

### 涉及文件

- `packer/reflective/loader.c`：双模式日志实现 + mini_vsnprintf + my_str* + VEH/oep_returned/actctx CRT 调用替换

### 临时验证文件（在 `temp/`，被 .gitignore 排除）

- `temp/test_phase4a_samples.py`：基础 5 样本测试（hellogui/hellomfc x64+x86 + hellocli）
- `temp/test_phase4a_extended.py`：扩展 9 样本测试（含 Notepad4/DontSleep/hellomingw/helloucrt）
- `temp/loader.c.bak`：loader.c 修改前备份

### 下一步

阶段 4 步骤 B（spec 第 306-313 行）：内存改 Win32 API
- `calloc(size_of_image, 1)` → `VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE)`（自动清零）
- `free(skip)` → `VirtualFree(skip, 0, MEM_RELEASE)`
- `memset`/`memcmp` 保留（MSVC intrinsics，非 CRT 依赖）

## 变更记录 2026-07-20 MSVC 迁移阶段 3 完成：x86 stub 构建 + 多样本验证 + 关键 bug 修复

承接上一条「阶段 3 批 3」记录，本条完成 x86 stub 构建配置、多样本端到端验证，并修复两个关键 bug。整个阶段 3 验证点（spec 第 264-275 行）全部通过：x64 3/5 PASS + x86 2/2 PASS（剩 2 个 TLS_PROXY 样本为已知基线 bug，非回归）。

### 1. x86 stub CMake 配置修复（`packer/stub/CMakeLists.txt`）

- **`/ENTRY:stub_entry` 替代 `/ENTRY:_stub_entry`**：link.exe 会自动按 `__cdecl` 装饰为 `_stub_entry`。原写法 `/ENTRY:_stub_entry` 会被再次装饰为 `__stub_entry`，导致 LNK2001 无法解析外部符号
- **添加 `/FIXED:NO` 保留 `.reloc` 节**：仅 `/DYNAMICBASE:NO` 会让 link.exe strip 掉 `.reloc`，导致 builder 加壳 x86 PE 时报 "winlock_stub_x86.exe has no .reloc section"。`/FIXED:NO` 配合 `/DYNAMICBASE:NO` 既关闭 ASLR 又保留 `.reloc`（x86 stub 用绝对地址引用静态数据，builder 必须读 `.reloc` 做预 patch）
- **POST_BUILD 复制 stub_x86.exe**：stub_x86.bin 在 `CMAKE_CURRENT_BINARY_DIR`，但 stub_x86.exe 在 `Release/` 子目录，builder 期望两者在同目录（`--stub-dir` 指向此目录）。新增 `copy_if_different` 命令复制 stub_x86.exe 到 stub_x86.bin 同目录

### 2. x86 jump_to_oep 节区修复（`packer/stub/stub_asm_x86.asm`）

- 与 x64 同样的问题：MASM 默认 `.code` 段会被 link.exe 放进 `.text` 节，`extract_lock_section.py` 不提取 `.text`，stub.bin 缺失此函数
- 用 `SEGMENT ALIAS('.lock$text')` 替代 `.code`，link.exe 按 `$` 分组合并到 `.lock` 节

### 3. builder `extract_stub_reloc_info` bug 修复（`packer/builder/builder.c`）

- **原 bug**：循环遍历所有节找 `.lock`，但没 break，`lock_rva` 被覆盖为最后一个 `.lock` 节的 VA（如 `.lock$tlscbm` VA=0x5000）。这导致 `patch_stub_relocations` 用错误范围 `[0x5000, 0x5000+stub_size)` 过滤 `.reloc` 条目，0 个条目被 patch，x86 stub 运行时所有绝对地址错位 -> AV 0xC0000005
- **修复**：取所有 `.lock` 节的最小 RVA 作为 `lock_rva`，最大 `(RVA+VSize)` 减最小 RVA 作为 `lock_size`，覆盖整个 `.lock` 区域。修复后 builder 报告 `Patched 84 stub relocations`（之前是 0）

### 4. peb_walk.h x86 结构布局 bug 修复（`packer/common/peb_walk.h`）

- **原 bug**：`LDR_DATA_TABLE_ENTRY_X._pad1` 是 x64 only 的对齐 padding（用于让 FullDllName 对齐到 8 字节边界），但代码无条件定义此字段。x86 上 PVOID 是 4 字节，USTR.Buffer 4 字节本身对齐，不需要 _pad1
- **后果**：x86 上 BaseDllName 错位 4 字节（编译器在 +0x30，Windows 实际在 +0x2c）。`find_module_by_hash` 调用 `hash_wstr_lower(e->BaseDllName.Buffer, ...)` 时，Buffer 读到错误的字段值（无效指针 0x22cc），导致 `mov bl, byte ptr [eax+edi*2]` 触发 AV 0xC0000005
- **修复**：用 `#ifdef _WIN64` 包裹 `_pad1`。x64 仍保留（必需），x86 不定义（自然对齐）
- **影响范围**：此 bug 只影响 x86 stub/loader，x64 不受影响（_pad1 仍存在，二进制不变）

### 5. 多样本端到端验证

测试脚本：`temp/test_phase3_samples.py`（test mode `-t`，跳过密码框直接走 `verify_password(L"test123")`）

| 样本 | 架构 | 结果 | 备注 |
|------|------|------|------|
| helloguix64 | x64 | PASS | GUI 启动后 3 秒仍存活 |
| hellomfcx64 | x64 | PASS | MFC + /GS SecurityCookie 初始化正常 |
| hellocli | x64 | PASS | exit=0，stdout="Hello World!" |
| hellomingw | x64 | FAIL | exit=0xC00000FD，TLS_PROXY 模式崩溃，MinGW 基线也崩溃（非回归） |
| helloucrt | x64 | FAIL | exit=0xC0000005，同上 TLS_PROXY 问题 |
| helloguix86 | x86 | PASS | GUI 启动后 3 秒仍存活（修复 _pad1 bug 后通过） |
| hellomfcx86 | x86 | PASS | MFC x86 启动正常 |

### 6. 已知 TLS_PROXY bug（非 MSVC 迁移引入）

- `hellomingw` / `helloucrt` 有 2 个 TLS callbacks，builder 启用 TLS_PROXY 模式（在 `.lock` 节内创建新 TLS directory + callbacks 数组 `[stub_tls_callback, NULL]`）
- 用 MinGW 版 stub_x64.bin（25008 字节）替换 MSVC 版加壳 `hellomingw`，运行同样崩溃（exit=0xC0000005），确认是基线 bug 而非 MSVC 迁移引入
- cdb 调试显示 crash 在 `rip=image_base`（MZ header `4d5a` = `pop r10` 当代码执行），推测 `stub_tls_callback` 调用原 callbacks 时地址错误（原 callbacks 数组 VA 指向 image base）
- 不阻塞 MSVC 迁移，留作后续单独修复

### 涉及文件

- `packer/stub/CMakeLists.txt`：x86 链接选项 + POST_BUILD 复制 stub_x86.exe
- `packer/stub/stub_asm_x86.asm`：`SEGMENT ALIAS('.lock$text')` 修复
- `packer/builder/builder.c`：`extract_stub_reloc_info` 取最小 RVA 而非最后一个
- `packer/common/peb_walk.h`：`_pad1` 用 `#ifdef _WIN64` 包裹

### 临时验证文件（在 `temp/`，被 .gitignore 排除）

- `temp/test_phase3_samples.py`：阶段 3 多样本验证脚本
- `temp/build_x86_stub.ps1`：x86 stub 构建脚本（用 vcvarsamd64_x86.bat 交叉编译）
- `temp/dump_stub_sections.py`：检查 stub_xXX.exe 节布局
- `temp/dump_stub_reloc.py`：dump stub_x86.exe 的 .reloc 表条目
- `temp/find_stub_magic.py`：搜索 stub.bin 中 STUB_*_MAGIC 位置
- `temp/disasm_stub_x86.py`：用 capstone 反汇编 stub_x86.bin
- `temp/debug_x86.ps1`：用 cdb 调试 x86 崩溃

## 变更记录 2026-07-20 MSVC 迁移阶段 3 批 3 完成：jump_to_oep_x64 修复 + SHA-256 用 Brad Conte 实现

承接上一条「阶段 3 进度」记录，本条完成批 3（MASM 实现 jump_to_oep_x64）并修复 SHA-256 bug，整个 stub 现在可在 MSVC 下端到端工作（加壳→密码校验→解密 .text→跳 OEP）。

### 1. SHA-256 实现替换（`packer/common/sha256.h`）
- 原 `packer/common/sha256.h` 的 K[] 常量数组有 1 位错误：`K[52] = 0x5b9cca5f`（应为 `0x5b9cca4f`），导致 stub 内 `verify_password` 永远失败，test mode 退出码 2
- 用 Brad Conte 的标准实现（`temp/crypto-algorithms-master/sha256.c`，已用 `C:\Home\Tools\coreutils\sha256sum.exe` 对比验证）整体替换 `sha256.h` 内部实现
- 保留三层 PIC 节区切换架构（MSVC `#pragma const_seg(".lock$rdata")` / GCC `__attribute__((section(".lock.rdata")))` / host 普通常量）和对外接口（`sha256_hash` / `bytes_eq_const` / `utf16le_to_utf8`）
- 主循环 `sha256_transform` 与 Brad Conte 实现完全一致；宏 `SHA256_ROTR/CH/MAJ/EP0/EP1/SIG0/SIG1` 沿用
- 验证：`temp/test_sha256_host.c` 在 host 模式下跑通 3 项测试（空串、"abc"、与 builder 写入的实际 pwd_hash 比对），全部匹配

### 2. jump_to_oep_x64 节区修复（`packer/stub/stub_asm_x64.asm`）
- 原 `.asm` 用默认 `.code` 段，MASM 把 `jump_to_oep_x64` 放进默认 `.text` 节，link.exe 不会自动合并到 `.lock`
- `extract_lock_section.py` 只提取 PE 中 `.lock*` 节，导致 `stub_x64.bin` 缺失此函数
- 运行时 stub 调用 `jump_to_oep_x64`（RVA 0x13000）落到 `.lock` 节内 padding 区域（全 0），执行 `add byte ptr [rax],al` 引发 AV，test mode 退出码 0xC0000005
- **修复**：用 MASM `SEGMENT ... ALIAS('.lock$text')` 语法把函数放进 `.lock$text` COFF 节，link.exe 按 `$` 分组合并规则把它合并到 `.lock` 节
- 重建 stub_x64.bin 新增第 4 个 `.lock` 子节（10 字节，VA=0x7000），机器码验证：`48 83 E4 F0 48 83 EC 28 FF E1` = `and rsp,-16; sub rsp,40; jmp rcx`

### 3. 端到端验证（test mode + 密码模式）
- **test mode（`-t`）**：加壳 `helloguix64.exe` 后运行，3 秒后仍存活，原 PE GUI 正常显示（不再 crash）
- **密码模式（`-p test123`）**：加壳后运行弹出 "WinLock - Password Required" 对话框，输入 `test123` 回车后密码校验通过，原 PE `.text` 被解密、jump_to_oep_x64 跳到 OEP，原窗口 "helloguiaslr" 正常显示
- dumpbin /disasm 确认 Section Summary 中只有 `.lock`（合并显示 3 个），不再有 `.text` 节
- `call 0x17000`（jump_to_oep_x64 新位置，在 .lock 节内）替代旧 `call 0x13000`（在 .text 节）

### 涉及文件
- `packer/common/sha256.h`：整体重写（保留接口和三层 PIC 节区架构）
- `packer/stub/stub_asm_x64.asm`：`SEGMENT ALIAS('.lock$text')` 替代默认 `.code` 段

### 临时验证文件（在 `temp/`，已被 .gitignore 排除）
- `temp/test_brad_sha256.c` / `temp/build_brad_sha256.ps1`：验证 Brad Conte 实现正确
- `temp/test_sha256_host.c`：验证新 sha256.h host 模式
- `temp/disasm_stub_full.ps1` / `temp/stub_disasm.txt`：dumpbin /disasm 反汇编 stub_x64.exe
- `temp/run_testmode.ps1`：运行 test mode 检查退出码
- `temp/debug_testmode.ps1`：cdb 调试 AV crash
- `temp/dump_jump_to_oep.py`：dump stub_x64.bin 确认 jump_to_oep_x64 机器码

## 变更记录 2026-07-20 MSVC 迁移阶段 0-2：MinGW 后备 + 共享代码抽取 + CMake/Builder 迁移

按照 `packer/docs/MSVC_PORRINT_AND_PIC_SPEC.md` 推进 MSVC 工具链迁移，阶段 0/1/2 全部完成。MinGW 版 Makefile 保留为后备，CMake 与之并存可随时回退。

### 阶段 0：准备工作（零风险）
- `packer/Makefile` → `packer/Makefile.mingw`（git rename 保留历史）
- 跑全样本加壳基线，记录到 `packer/tests/baseline_mingw.txt`
- 验证 `mingw32-make -f Makefile.mingw all all-x86 reflective-all` 仍可编译通过

### 阶段 1：共享代码抽取（低风险，MinGW 回归验证）
抽出 4 个共享头文件到 `packer/common/`，消除 4 处 XTEA 重复、2 处 SHA-256 路径、PEB walk 单点实现：
- **`common/winlock_compat.h`**（新建）：编译器抽象层，集中所有 GCC/MSVC 差异宏（`WINLOCK_SECTION_TEXT` / `WINLOCK_SECTION_DATA` / `WINLOCK_SECTION_RDATA` / `WINLOCK_SECTION_ENTRY` / `WINLOCK_SECTION_TLSCBM` / `WINLOCK_SECTION_TLSCB` / `WINLOCK_SECTION_CRT_XLB` / `WINLOCK_UNREACHABLE` / `WINLOCK_NOINLINE` / `WINLOCK_OPTIMIZE_OFF` / `WINLOCK_SFENCE`）。MSVC 分支用 `__pragma(code_seg/data_seg/const_seg)` + `__declspec(noinline/align)`；GCC 分支保持原 `__attribute__` 写法，确保 stub 二进制字节级不变
- **`common/peb_walk.h`**（新建）：从 `stub.c` / `loader.c` 抽取 PEB walk + DJB15 hash 解析（`find_module_by_hash` / `find_export_by_hash` / `WINLOCK_PEB()`），用 `static inline` 避免符号冲突
- **`common/xtea.h`**（新建）：从 4 处重复实现抽取 XTEA 加密/解密（`xtea_encrypt_block/buf` / `xtea_decrypt_block/buf`），用 `#ifdef WINLOCK_PIC` 区分 stub 与 host 用途
- **`common/pe_meta.h`**（新建）：节名/魔数常量集中管理（为阶段 5 节名伪装做准备）
- **`common/sha256.h`**（移动）：从 `packer/stub/sha256.h` 移过来，路径不再有 `../stub/` 跨模块引用
- 修改 `stub.c` / `loader.c` / `builder.c` / `builder_reflective.c` 删除本地实现，改 `#include "../common/*.h"`
- 修改 `tests/stub_sha256_test.c` 的 include 路径

### 阶段 2：CMake 骨架 + Builder 迁移（低风险）
验证 MSVC + CMake 工具链可用，迁移最简单的 builder（纯 C 无 GCC 扩展）：
- **`packer/CMakeLists.txt`**（新建顶层）：强制 MSVC（不用则 FATAL_ERROR），引入 `cmake/msvc_setup.cmake`，全局加 `/utf-8`（解决中文注释导致的 C4819 警告 + C2059 语法错误）+ `/Zc:preprocessor`（支持 `##__VA_ARGS__`）+ `_CRT_SECURE_NO_WARNINGS` + `/MT`（静态 CRT）
- **`packer/cmake/msvc_setup.cmake`**（新建）：封装 vcvars64.bat 路径 + 查找 w64devkit/msys2 mingw32 的 binutils（objcopy/nm），binutils 与编译器无关继续使用
- **`packer/builder/CMakeLists.txt`**（新建）：定义 `builder` 和 `builder_reflective` 两个 target，链 `advapi32`（CryptoAPI），编译选项 `/O2 /W3 /MT`
- **`.gitignore`**（更新）：添加 `build-x64/` / `build-x86/` / `build-msvc*/` / CMake 生成文件（`*.vcxproj` / `*.sln` / `CMakeFiles/` 等）
- **`packer/docs/MSVC_PORRINT_AND_PIC_SPEC.md`**（新建）：实际使用的迁移 + PIC 化规格说明（7 阶段计划 + 风险表 + 回滚触发条件）

### 编译验证
- CMake 配置成功：MSVC 19.51.36248，所有 binutils 找到
- `builder.exe`（181760 字节，比 MinGW 110826 大，因 MSVC /MT 静态 CRT）+ `builder_reflective.exe` 编译通过，仅 2 个无害的 C4319 零扩展警告
- 加壳 `helloguix64.exe` 成功：输出 114688 字节（原 107008 + stub 7536 ≈ 7KB 增量），`builder --help` 完美运行
- `builder_reflective` 测试通过：v1 明文 payload + 图标资源复制，输出 271360 字节

### 阶段 3 进度（已启动）
- stub.c 的 46 处 GCC 扩展中，批 1（15 处 section attribute）+ 批 2（optimize/unreachable/sfence）已通过 `winlock_compat.h` 宏抽象完成
- 仅剩批 3（jump_to_oep 的 `__asm__ volatile` 内联汇编，2 处）需要独立 `.asm` 文件

## 变更记录 2026-07-19 Reflective 加壳添加密码弹框 + XTEA 加密（v2 模式）

**目标**：Reflective 加壳方案之前是 MVP v1 半成品（明文 payload，无密码框），现在参考 WinLock Inplace（`packer/stub/stub.c`）补齐密码弹框 + 加密功能。

**实现方案**：复用 Inplace 的加密栈（XTEA + SHA-256(pwd+salt)），通过 payload.h 的 v2 版本号区分。

**改动文件**：

1. **`packer/reflective/payload.h`**：新增 `REFLECTIVE_PAYLOAD_VERSION_V2 = 2`，v2 = XTEA 加密 + SHA-256 密码校验。v1 字段（salt/pwd_hash/xtea_key）此前已预留。

2. **`packer/builder/builder_reflective.c`**：
   - 新增 `-p <pwd>` / `--password <pwd>` 参数：用密码加密 payload，启用 v2 模式
   - 新增 `-t` / `--test` 参数：测试模式，硬编码 `test123` 密码，跳过弹框（CI/自动化用）
   - 新增加密工具函数：`gen_random_bytes`（CryptGenRandom）、`sha256_hash`（CryptoAPI）、`wstr_to_utf8`、`xtea_encrypt_block`、`xtea_encrypt_buf`
   - 密码模式流程：生成随机 XTEA key[4] + salt[16] → SHA-256(utf8(pwd)+salt) → pwd_hash[32] → XTEA 加密 payload_data → 填入 hdr 字段 + 设置 `RFLAG_ENCRYPTED|RFLAG_HASH`
   - 无密码时仍写 v1 明文（向后兼容）
   - 链接 `advapi32`（CryptGenRandom + SHA-256）

3. **`packer/reflective/loader.c`**：
   - 复用 `packer/stub/sha256.h` 的纯 C SHA-256 + UTF-16LE→UTF-8 + 常量时间比较
   - 新增 `xtea_decrypt_block` / `xtea_decrypt_buf`（与 builder 互逆）
   - 新增 `build_dialog` / `dlg_proc` / `verify_password` / `prompt_password` / `decrypt_payload_if_needed`
     - 与 stub.c 不同：loader.c 用 CRT 编译，可以直接 `#include <user32.h>` 调用 `DialogBoxIndirectParamW`，不用 PEB walk + hash 解析
   - 修改 `main()`：接受 v1 和 v2，v2 时弹密码框 → SHA-256 校验 → VirtualProtect 改 .payload 为 RW → XTEA 解密 → map_image
   - 测试模式（`RFLAG_TEST_MODE`）：跳过弹框，用硬编码 `L"test123"` 校验
   - 链接 `user32`（DialogBoxIndirectParamW）

4. **`packer/Makefile`**：
   - `builder_reflective.exe` 增加 `-ladvapi32`
   - `loader_x64.exe` / `loader_x86.exe` 增加 `-luser32`
   - 更新依赖关系：reflective 模块依赖 `stub/sha256.h` 和 `common/config.h`

**密码框 UI**（参考 stub.c build_dialog）：
- 标题 "WinLock - Password Required"
- 一个 EDIT 控件（ES_PASSWORD 属性，输入显示为 *）
- OK / Cancel 按钮
- 错误密码弹 MessageBox "Wrong password"，可重试 3 次
- Cancel / 超过重试次数 → ExitProcess

**测试结果**（2026-07-19）：
- ✅ x64 + v2 密码模式：Notepad4.exe 加壳后弹密码框，输入正确密码 `testpwd123` → Notepad4 启动
- ✅ x64 + v2 错误密码重试：输入 `wrongpassword` → 弹"Wrong password" → 重输正确密码 → 启动
- ✅ x64 + v2 test 模式：跳过弹框，自动用 `test123` 校验 → Notepad4 启动
- ✅ x64 + v1 明文向后兼容：不加 `-p`/`-t` 仍走 v1，Notepad4 启动
- ✅ x86 + v2 test 模式：helloguix86.exe 加壳 + 运行 → 显示主窗口
- ✅ x86 + v2 密码模式加壳：成功生成

**关键经验**：
- `.payload` 节默认是 `IMAGE_SCN_MEM_READ` 只读，XTEA 解密前必须 `VirtualProtect` 改成 `PAGE_READWRITE`，否则触发 ACCESS_VIOLATION（实测日志可见）
- loader.c 用 CRT 编译可以省掉 stub.c 那套 PEB walk + DJB2 hash 的 API 解析，直接 `LoadLibraryA("user32.dll")` + `DialogBoxIndirectParamW` 即可
- builder 和 stub 共享 `packer/common/config.h` 的 `XTEA_DELTA`/`XTEA_ROUNDS`/`IDC_PWD_EDIT` 常量，避免魔法数字

## 变更记录 2026-07-19 新增 PE 加壳方案技术对比文档

新增 `packer/docs/PACKER_TECHNIQUES.md`（约 400 行），系统对比主流 PE 加壳方案的原理、优缺点、适用场景，并给出本项目的选型决策与演进路线。

**文档结构**：
1. 加壳方案分类（OS Loader 加载 / 手动加载 / 环境模拟 三大流派）
2. 已实现方案详解（Tempfile / Inplace / Reflective）
3. 未实现的成熟方案（Process Hollowing / RunPE / VFS / Shellcode / AppInit_DLLs / .NET 加壳 / 代码虚拟化）
4. 横向对比表（10 个方案 × 9 个维度）
5. 本项目选型决策（为什么选这三种、为什么不选其他）
6. 演进路线（短期 v1→v2 加密 / 中期资源保留反 dump / 长期 VFS）
7. 已知限制与兼容性矩阵
8. 参考资料索引

**关键结论**：
- 已实现的三种方案（Tempfile / Inplace / Reflective）覆盖了 native PE 保护的主要场景
- Process Hollowing / RunPE 被杀软重点监控，与"合法 EXE 保护"目标冲突，不推荐
- VFS 是解决 Chrome/Electron 类程序的长期方案，但工作量极大
- .NET 加壳技术栈不同，引导用户用 ConfuserEx 等专用工具
- 短期最值得做的是 Reflective 加密版（v1 明文 → v2 AES + 密码弹框）

## 变更记录 2026-07-19 dotnet packer 检测 Chromium 系浏览器并禁用加壳按钮

**问题**：Chrome / Edge / Doubao 等 Chromium 系浏览器不适合反射式加壳（依赖版本化子目录 DLL，浏览器有自己的 DLL 加载逻辑）。之前用户选这些程序加壳后会 crash，没有任何提示。

**检测方案**（`dotnet/packer/PeReader.cs`）：
- 新增 `IsChromiumLike` 字段
- 新增 `DetectChromiumLike(pe)` 方法：解析 PE 导入表，遍历每个导入的 DLL 名字，匹配 `*_elf.dll` 后缀（`chrome_elf.dll`/`doubao_elf.dll` 等 Chromium 系浏览器特征）
- 新增 `RvaToFileOffset` 辅助函数：PE RVA 转文件偏移（遍历节表）
- 新增 `ReadAsciiString` 辅助函数：读 null-terminated ASCII 字符串

**UI 提示 + 禁用按钮**（`dotnet/packer/MainForm.cs/GetStubCompatibilityWarning`）：
- WinLock + Chromium → `⚠ WinLock 不支持 Chromium 系浏览器（Chrome/Edge/Doubao），请改用临时文件模式` (blocking)
- Reflective + Chromium → `⚠ 反射式加载不支持 Chromium 系浏览器（Chrome/Edge/Doubao，依赖版本化子目录 DLL），请改用临时文件模式` (blocking)
- `UpdatePeInfoLabel`：Chromium 程序即使选 Tempfile 也用 OrangeRed 显示（提醒这是特殊程序）

**CLI 防御性检查**（`dotnet/packer/PackCore.cs`）：
- WinLock/Reflective + Chromium → 抛 `InvalidOperationException`（万一 UI 检测失效）

**CLI `--pe-info` 输出**（`dotnet/packer/Program.cs`）：
- 新增 `Chromium 系浏览器: True/False` 行

**测试结果**（`temp/test_chromium_detect.py` 11/11 ALL PASS）：

| 程序 | 期望 | 实际 | 结果 |
|---|---|---|---|
| Doubao | True | True | ✓ |
| Chrome | True | True | ✓ |
| FastCopy | False | False | ✓ |
| Bandizip | False | False | ✓ |
| BCompare | False | False | ✓ |
| CC-Switch | False | False | ✓ |
| FreeFileSync | False | False | ✓ |
| AutoHotkey64 | False | False | ✓ |
| hellowinforms (.NET) | False | False | ✓ |
| helloguix64 | False | False | ✓ |
| hellocli | False | False | ✓ |

**限制说明**：
- 此检测覆盖 Chrome / Edge / Doubao / Brave 等 Chromium 原生浏览器（导入 `*_elf.dll`）
- Electron 程序不在此列（Electron 主 EXE 不引用 `*_elf.dll`，但 Electron 程序的反射式加壳可行性需单独评估）
- 检测基于 PE 导入表，纯静态分析，不需要文件系统访问

## 变更记录 2026-07-19 reflective loader 修复 x86 TLS 重定位 + 设置 DLL 搜索路径

**修复 1：x86 TLS 重定位导致 FreeFileSync 崩溃**

**问题**：FreeFileSync (x86) 反射式加载后，`init_tls_data` 计算 `raw_rva` 错误，`memcpy` 读到未映射内存触发 ACCESS_VIOLATION。

**根因**：
- `init_tls_data` 用 `preferred_base` 计算 `raw_rva`：`raw_rva = tls->StartAddressOfRawData - preferred_base`
- 但 `apply_relocations` 已在 `init_tls_data` 之前执行，TLS 目录的 VA 字段（`StartAddressOfRawData`/`EndAddressOfRawData`/`AddressOfIndex`）已被 HIGHLOW 重定位修复
- x86 FreeFileSync 的 `StartAddressOfRawData` 从 `0x447fec`（preferred_base + RVA）变成 `0x6f7fec`（new_img + RVA，delta=0x2b0000）
- `raw_rva = 0x6f7fec - 0x400000 = 0x2f7fec`（错误，应该是 `0x47fec`）
- `img + raw_rva = 0x6b0000 + 0x2f7fec = 0x9a7fec` 远超 SizeOfImage（0xb0000），读到未映射内存 crash

**修复**（`packer/reflective/loader.c/init_tls_data`）：
- 判断 `StartAddressOfRawData` 是否在 `[img, img+SizeOfImage]` 范围内
  - 是：说明已被重定位，用 `img` 作为 base 算 RVA
  - 否：说明未重定位，用 `preferred_base` 作为 base 算 RVA
- `AddressOfIndex` 同样用 `base_for_rva` 算 RVA
- 新增 `tls_relocated` 标志和 `base_for_rva` 变量，日志显示判断结果

**测试**：FreeFileSync (x86) 之前 ACCESS_VIOLATION 崩溃，现在 `tls: start_va=0x727fec base_for_rva=0x6e0000 (relocated=1) raw_rva=0x47fec`，GUI 正常启动。

---

**修复 2：DLL 搜索路径导致 Chrome/Doubao 找不到同目录 DLL**

**问题**：Chrome 反射式加载后 `LoadLibraryA(chrome_elf.dll) failed err=126`，Doubao 类似。

**根因**：stub EXE 可能在不同目录（如 `temp/reflective_tests/`），`LoadLibraryA` 默认用 stub 当前目录搜索，找不到原 PE 目录下的 DLL（如 `chrome_elf.dll`）。

**修复**（`packer/reflective/loader.c/map_image` 步骤 4.55）：
- 在 IAT 处理之前，`GetModuleFileNameW(NULL)` 拿到 stub EXE 路径
- 提取目录部分，`SetCurrentDirectoryW` + `SetDllDirectoryW` 设置为 stub EXE 所在目录
- 前提：用户把加壳后 EXE 放在原程序目录（常见做法）

**效果**：Doubao 的 `doubao_elf.dll` 现在能成功加载（之前 err=126）。Chrome 的 `chrome_elf.dll` 在版本子目录（`145.0.7632.68\`），仍找不到（Chrome 自身有特殊 DLL 加载逻辑，反射式 loader 无法自动处理）。

---

**已知限制**：Chrome/Doubao 等浏览器程序不适合反射式加壳
- Chrome 的 `chrome_elf.dll` 在版本化子目录（如 `145.0.7632.68\`），Chrome 原版 EXE 有特殊逻辑加载子目录 DLL
- Doubao 的 actctx 失败（err=14001 SXS_ASSEMBLY_NOT_FOUND），manifest 引用的 SxS 程序集找不到，OEP 后崩溃
- 这类浏览器程序有自己的 DLL 加载和 SxS 逻辑，反射式 loader 无法完全模拟 OS loader 行为
- 建议这类程序使用临时文件模式（Tempfile），让 OS loader 完整加载

---

**回归测试**（`temp/retest_all.py`）：所有之前通过的程序无回归
- FreeFileSync: ✅ 修复（之前崩，现在 GUI up）
- FastCopy / BCompare / CC-Switch: ✅ 仍正常
- Bandizip: ✅ exit=10
- AutoHotkey32 (x86): ❌ 仍 x86 SEH 问题（与本次修复无关）

## 变更记录 2026-07-19 dotnet packer GUI：WinLock/Reflective 不兼容时红字提示 + 禁用按钮

**问题**：WinLock (InplaceBuilder) 不支持 .NET 程序和 Console 程序，Reflective 不支持 .NET 程序。之前只有用户点"执行加密"后才在 `PackCore.Pack` 里抛异常报错，体验差。`MainForm.WarnIfIncompatible` 虽然有检测但只对 WinLock 弹 MessageBox，没覆盖 Reflective，也没禁用按钮。

**修复方案**（`dotnet/packer/MainForm.cs`）：

1. **新增 `_lastPeInfo` / `_lastPePath` 缓存字段**：避免切换 stub 时重复读取大文件解析 PE

2. **新增 `GetStubCompatibilityWarning(StubKind, PeInfo)` 方法**：返回 `(warning, blocking)` 元组
   - `InplaceBuilder` + .NET → `⚠ WinLock 不支持 .NET 程序，请改用临时文件模式` (blocking)
   - `InplaceBuilder` + Console → `⚠ WinLock 仅支持 GUI 程序，请改用临时文件或反射式模式` (blocking)
   - `ReflectiveBuilder` + .NET → `⚠ 反射式加载不支持 .NET 程序（CLR 假设主模块由 OS loader 加载）` (blocking)
   - `Tempfile` → 无限制
   - 选中"自动"时不附加警告（让 PackCore 按子系统自己选合适的 stub）

3. **重写 `UpdatePeInfoLabel`**：
   - 解析 PE 后缓存到 `_lastPeInfo`，路径不变时复用缓存
   - 在 PE 信息行末尾追加当前选中 stub 的兼容性警告，整体显示为红字
   - 例：`x64 | GUI | ASLR✓ ... | .NET✓ | 8.5KB  |  ⚠ WinLock 不支持 .NET 程序，请改用临时文件模式`

4. **重写 `UpdatePackButton`**：除原有字段非空检查外，加 stub 兼容性检查，blocking=true 时禁用按钮

5. **替换 `WarnIfIncompatible` + 弹框逻辑**：去掉 MessageBox（红字提示已足够醒目，弹框反而打断流程）

6. **`cbStubPreference_SelectedIndexChanged`**：切换 stub 时同时刷新 PE 信息行（重算警告）和按钮状态

**测试结果**（`temp/test_compat_logic.py` 复用 packer `--pe-info` 验证逻辑）：

| 程序 | 类型 | WinLock | Reflective | Tempfile |
|---|---|---|---|---|
| hellowinforms.exe | .NET GUI | ❌ 不支持 .NET | ❌ 不支持 .NET | ✓ |
| hellocli.exe | Console | ❌ 仅支持 GUI | ✓ | ✓ |
| helloguix64.exe | native GUI | ✓ | ✓ | ✓ |
| helloguix86.exe | native GUI | ✓ | ✓ | ✓ |
| ShanaEncoder.exe | .NET GUI | ❌ 不支持 .NET | ❌ 不支持 .NET | ✓ |
| CC-Switch.exe | native GUI | ✓ | ✓ | ✓ |

dotnet packer 编译通过（0 警告 0 错误）。

## 变更记录 2026-07-19 reflective builder 复制原图标/版本资源到输出 EXE

**问题**：反射式加壳后的 EXE 在 Explorer 里显示的是 stub 的默认 MinGW 图标，不是原 PE 的图标。文件属性也没有原 PE 的版本信息。

**根因**：OS/Explorer 显示图标和版本信息时只看 stub 自己的 `.rsrc` 节。反射式 loader 运行时虽然能从 `.payload` 节读原 PE 资源，但 OS 加载 stub 时不知道 `.payload` 的存在。之前 `PackCore.cs/PackWithReflective` 注释错误地说"原 PE .rsrc 已完整保留在 .payload 中，不需要 IconCopier"——实际上 `.payload` 是运行时数据，不是 OS 资源。

**修复方案**（`packer/builder/builder_reflective.c`）：
1. 新增 `copy_resources(src_w, dst_w)` 函数，用 Windows `UpdateResource` API 复制资源
2. 流程：`LoadLibraryExW(src, LOAD_LIBRARY_AS_DATAFILE)` 加载原 PE → `BeginUpdateResourceW(dst, FALSE)` 打开输出 → `EnumResourceNamesW` 枚举 RT_GROUP_ICON/RT_ICON/RT_VERSION → 回调里 `FindResourceW` + `LoadResource` + `UpdateResourceW` 逐个复制 → `EndUpdateResourceW` 提交
3. 在 `main()` 写完输出文件后调用，新增 `--no-icon` 参数可跳过
4. 失败不致命（图标错不影响程序运行），只打印警告

**MinGW 编译坑**：`RT_GROUP_ICON` 等宏是 `MAKEINTRESOURCE` 返回 `LPWSTR`，传给 `EnumResourceNamesW` 的 `LPCWSTR` 参数需显式 cast，否则 GCC 报 `incompatible pointer type` error。

**测试结果**（`temp/extract_icons.py` 用 `System.Drawing.Icon.ExtractAssociatedIcon` 提取图标对比 PNG 大小）：

| 程序 | 原 PE 图标大小 | 加壳后图标大小 | stub 默认图标 | 结果 |
|---|---|---|---|---|
| FastCopy | 628B | 628B | 533B | ✓ 和原图标一致 |
| Bandizip | 533B | 533B | 533B | 原 PE 无图标，显示默认 |
| BCompare | 6520B | 6520B | 533B | ✓ 和原图标一致 |
| CC-Switch | 3910B | 3910B | 533B | ✓ 和原图标一致 |
| AutoHotkey64 | 974B | 974B | 533B | ✓ 和原图标一致 |

**回归测试**（`temp/retest_all.py`）：UpdateResource 修改 `.rsrc` 节不影响 `.payload` 节，所有程序运行正常：
- FastCopy / BCompare / CC-Switch: ✅ TIMEOUT (GUI up)
- Bandizip: ✅ exit=10
- AutoHotkey32 (x86): ❌ 仍 x86 SEH 问题（与图标无关）

**dotnet packer 同步**：`PackCore.cs/PackWithReflective` 更新注释，说明 builder 已处理图标复制，dotnet 层不再调 IconCopier（避免重复操作）。

## 变更记录 2026-07-19 新增 TLS 专业文档 packer/docs/TLS_NOTES.md

整理反射式 loader 的 TLS 处理经验，撰写专业文档供备忘和参考。

**新增文件**：`packer/docs/TLS_NOTES.md`

**内容大纲**：
1. 为什么反射式 loader 必须专门处理 TLS（OS loader 自动完成的 6 件事）
2. PE TLS 结构详解（`IMAGE_TLS_DIRECTORY` / TEB TLP / TLS Callback 签名）
3. 反射式 loader 的 3 大 TLS 难题分解
   - 难题 A：主线程 TLS 数据未初始化
   - 难题 B：新线程 TLS 数据越界（CC-Switch / Rust 崩溃）
   - 难题 C：TLS Callback 必须代理
4. 最终方案：TLS Callback 代理 + 数据块分配（含整体架构图和关键代码片段）
5. 踩坑历程时间线（5 个阶段，从 FastCopy 到 CC-Switch 的完整调试轨迹）
6. 参考项目对比表（PELoader3 / Fatpack / AlushPacker / PolyEngine 等）
7. 调试技巧（cdb 检查 TLP / `__fastfail` 类型区分 / stub 日志关键字）
8. 边界情况与遗留问题（TLS index 不匹配 / index >= 64 / 动态 TLS / .NET / x86 SEH）
9. 实测兼容性表（CC-Switch / FastCopy / Bandizip / BCompare / AutoHotkey 等）
10. 参考资料索引（PELoader3 / Fatpack / AlushPacker / PolyEngine 源码 + maskray/kaimi 文章）

**参考来源**：
- `F:\Temp\pe\PELoader3` 的 README + TlsResolver.cpp + main.cpp
- `F:\Temp\pe\Fatpack-main` 的 README + Shared/CRT/crt_tls.h + Shared/PELoader/TlsCallbackProxy
- `F:\Temp\pe\PolyEngine-master` 的 Stub/TlsCallback.c（反调试 TLS callback 范例）
- `F:\Temp\pe\AlushPacker-main` 的 Packer/tls.h（`.CRT$XLB` 4 reason 分发范例）
- maskray 博客 "All about thread-local storage"（ELF 平台 TLS 理论参考）
- 本项目 `packer/reflective/loader.c` 的完整修复历程

## 变更记录 2026-07-19 reflective loader TLS callback 代理补齐：调用目标 PE 的 TLS callbacks

**背景**：调研 `F:\Temp\pe` 中 Fatpack/PELoader3 的 TLS 实现（README + `TlsResolver.cpp` + `main.cpp`）后发现，上一版 TLS callback 代理只分配 TLS 数据块，**没有调用目标 PE 自己的 TLS callbacks**。PELoader3 的标准做法是：`DLL_THREAD_ATTACH` 时先 `InitializeTlsData` 再 `ExecuteCallbacks`；`DLL_THREAD_DETACH` 时先 `ExecuteCallbacks` 再 `ClearTlsData`；`DLL_PROCESS_DETACH` 也调 `ExecuteCallbacks`。

**问题**：依赖 TLS callback 做线程级初始化的程序（如 Rust std::thread handle、Delphi 线程局部运行时）会因 callback 不被触发而出现隐蔽 bug。当前 CC-Switch 虽然 GUI 能起来，但 Rust 工作线程的 TLS callback 没被调，存在潜在风险。

**改动**（`packer/reflective/loader.c`）：
1. 新增 `run_target_tls_callbacks(reason, hModule, ctx)` 辅助函数，遍历 `g_target_tls->AddressOfCallBacks` 数组调用各 callback
2. `tls_callback_proxy` 的 `DLL_THREAD_ATTACH` 分支：在 `TLP[0] = block` 之后调用目标 PE 的 callbacks（顺序很重要：先设 TLP 再调 callback）
3. `DLL_THREAD_DETACH` 分支：先调目标 PE 的 callbacks，再 `VirtualFree(TLP[0])`（让 callback 在数据释放前做 cleanup）
4. 新增 `DLL_PROCESS_DETACH` 分支：调用目标 PE 的 callbacks，不释放数据块（进程即将退出，OS 回收）
5. `DLL_PROCESS_ATTACH` 仍由主流程 `run_tls_callbacks()` 在 OEP 前调用一次，代理不处理

**测试结果**：
- CC-Switch: ✅ TIMEOUT (GUI up) — 日志显示大量 `tls: proxy -> callback 140f69360 (reason=2)` 即 DLL_THREAD_ATTACH 调用，证明目标 PE TLS callback 被正确触发
- Bandizip: ✅ exit=10 — 无回归
- BCompare: ✅ TIMEOUT (GUI up) — 无回归
- FastCopy: ✅ TIMEOUT (GUI up) — 无回归
- AutoHotkey32 (x86): ❌ 仍 ACCESS_VIOLATION（"no TLS directory"，与 TLS 代理无关，是 x86 SEH 问题）

## 变更记录 2026-07-19 reflective loader TLS callback 代理（修复 CC-Switch 崩溃）

**问题**：CC-Switch（Rust/Tauri 程序）反射式加载后，创建工作线程时触发 `STATUS_STACK_BUFFER_OVERRUN (0xC0000409)`，错误信息 "fatal runtime error: current thread handle already set during thread spawn"。

**根因**：
- stub 有自己的 TLS 目录，OS 为 stub 分配 TLS index = 0
- 目标 PE 的 `__tls_index` 编译时也 = 0，两者恰好匹配
- 但新线程创建时，OS 只用 stub 的 TLS 模板（8 字节）初始化 `TLP[0]`
- 目标 PE 访问 `TLP[0]+0x1e0` 等远偏移会读到越界数据（其他 TLS slot 的数据）
- 导致 Rust std::thread 的线程句柄检查误判，触发 `__fastfail(7)`

**修复方案**（参考 PELoader3 的 TlsCallbackProxy）：
1. 在 stub 中注册 TLS callback（`.CRT$XLB` section），由 Windows 在线程创建/销毁时自动调用
2. `DLL_THREAD_ATTACH` 时：手动为目标 PE 分配正确大小的 TLS 数据块（VirtualAlloc + 复制模板），设置 `TLP[0]`
3. `DLL_THREAD_DETACH` 时：释放 TLS 数据
4. `g_entry_point_called` 标志确保只在目标 PE 初始化完成后才处理 TLS 事件

**改动文件**：
- `packer/reflective/loader.c`：新增 `tls_callback_proxy()` 函数 + `g_target_tls`/`g_entry_point_called` 全局变量 + `.CRT$XLB` 注册
- `packer/builder/builder_reflective.c`：扩展 stub 的 `.tls` 节 VirtualSize（配合 TLS 数据块大小）

**测试结果**：
- CC-Switch: ✅ TIMEOUT (GUI up) — 之前崩溃，现在修复
- FastCopy: ✅ TIMEOUT (GUI up) — 无回归
- Bandizip: ✅ exit=10 — 无回归
- BCompare: ✅ TIMEOUT (GUI up) — 无回归
- AutoHotkey64: ✅ TIMEOUT (GUI up) — 无回归
- AutoHotkey32 (x86): ❌ 仍崩溃（x86 SEH 问题，与 TLS 无关）

## 变更记录 2026-07-19 dotnet packer 集成 reflective 加壳模式

把反射式 packer 集成到 dotnet packer GUI，新增第三种加壳方案 `ReflectiveBuilder`（与现有 `Tempfile` / `InplaceBuilder` 并列）。

1. **新增 `StubKind.ReflectiveBuilder` 枚举值**（`dotnet/packer/StubManifest.cs`）
   - `Kind` 属性加 switch 分支：`"reflective-builder"` → `ReflectiveBuilder`

2. **新增 `dotnet/packer/ReflectivePacker.cs`**
   - 调用 `builder_reflective.exe` 加壳
   - 命令行格式与 WinLockPacker 不同：位置参数 + `--stub`（不是 `-i/-o` + `--stub-dir`）
   - 按输入 PE 的 Machine 字段选 loader_x64.exe / loader_x86.exe

3. **新增 `dotnet/packer/stub/winlock_reflective_builder.exe.meta.json`**
   - `kind=reflective-builder`，`components` 引用 `loader_x64.exe` / `loader_x86.exe`

4. **修改 `dotnet/packer/PackCore.cs`**
   - 主分支加 `else if (selected.Kind == StubKind.ReflectiveBuilder)` 调用 `PackWithReflective`
   - 新增 `PackWithReflective` 方法：复制输入到临时文件 → 调用 builder → 复制输出
   - 不限制子系统（GUI/Console 都支持，stub 继承原 PE subsystem）
   - 不调用 IconCopier（原 PE .rsrc 已完整保留在 .payload 节）

5. **修改 `dotnet/packer/MainForm.cs`**
   - UI 标签加 "(内存加载，支持 Console/x86)" 区分 reflective 模式
   - 结果显示 modeTag 加 `[Reflective]`

6. **修改 `dotnet/build.ps1`**
   - WinLock 编译命令从 `all all-x86` 改为 `all all-x86 reflective-all`
   - 新增 reflective 产物拷贝：`builder_reflective.exe` → `winlock_reflective_builder.exe`，`loader_x64.exe` / `loader_x86.exe`
   - 新增第 5 个 meta.json 生成（reflective-builder）

7. **测试结果**（CLI `--pack --stub-name winlock-reflective`）
   - helloguix64.exe (x64 GUI) → 自动选 loader_x64.exe ✓
   - helloguix86.exe (x86 GUI) → 自动选 loader_x86.exe ✓
   - hellocli.exe (x64 Console) → 自动选 loader_x64.exe，Subsystem=3(CUI) ✓
   - 加壳后 EXE 运行：反射式加载成功，jump_to_oep，窗口弹出 ✓
   - `--list-stubs` 显示 5 个 stub（3 tempfile + 1 inplace + 1 reflective）全部 OK

8. **三种加壳方案对比**

| 方案 | Kind | 密码 | 支持 .NET | 支持 Console | 支持 x86 | 原文件完整性 |
|------|------|------|----------|-------------|---------|------------|
| Tempfile | `Tempfile` | ✓ AES+HMAC | ✓ | ✓ | ✓ | 完整（作为 payload 附加） |
| InplaceBuilder (WinLock) | `InplaceBuilder` | ✓ XTEA | ✗ | ✗ | ✓ | 修改 .text 节 |
| ReflectiveBuilder (新) | `ReflectiveBuilder` | ✗ MVP v1 明文 | 部分 | ✓ | ✓ | 完整（作为 .payload 节） |

9. **遗留**
   - reflective MVP v1 是明文模式，后续可加 AES 加密 + 密码弹框（payload.h 已预留字段）
   - .NET 程序支持不保证（CLR 内部假设主模块通过 OS loader 加载，反射式内存无 Section backing）
   - 复杂 .NET 程序可能需要补强 PEB.Ldr 的 BaseDllName/FullDllName 字段

## 变更记录 2026-07-19 反射式 Packer 阶段二续2：延迟导入表处理 + 大型 app 测试通过

实现 `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` 延迟导入表处理，CCleaner（45MB, 12 个延迟 DLL）从"OEP 后立即崩"修复到"OEP reached"。

1. **`packer/reflective/loader.c` 新增 `process_delay_imports` 函数**
   - 自定义 `IMAGE_DELAYLOAD_DESCRIPTOR_X` 结构（MinGW winnt.h 不提供），32 字节
   - `DLAT_RVA = 0x01`（Microsoft PE 规范：bit 0 = 1 表示字段是 RVA；之前误用 0x02 导致 CCleaner 崩溃）
   - 流程：遍历描述符表 → `LoadLibraryA(dll_name)` → HMODULE 写到 `ModuleHandleRVA`（供原 PE 的 `__delayLoadHelper2` 复用）→ 遍历 INT 用 `GetProcAddress` 解析函数 → 写入 IAT
   - 字段格式：现代 PE（VS2008+）用 RVA 格式（Attributes & 1），老格式用 VA，按 Attributes 判断
   - 失败策略：DLL 加载失败或函数解析失败写 NULL + 警告，不退出（延迟导入本身可选）
   - 在 `map_image` 主流程 `process_iat` 之后调用，失败不致命

2. **测试结果**
   - **CCleaner x64**（45.85MB, 12 延迟 DLL）：延迟导入 10/12 DLL 加载，107 函数解析，jump_to_oep 成功（之前 OEP 后立即 access violation）
     - CCleanerDU.dll / libwaapi.dll 加载失败（CCleaner 可选组件，目录里没有），CCleaner 内部调用这些 NULL 函数指针时 VEH 捕获异常，非 loader 问题
   - **VLC x64/x86**：窗口弹出 ✓
   - **回归测试 9/9 PASS**：Notepad4 / DontSleep / helloguix64 / helloguix86 / hellocli / hellomingw / helloucrt / ddccli / sha256sum（无延迟导入的 PE 不受影响）

3. **大型 app 测试脚本** `temp/test_testapps.py`
   - 在原目录就地加壳（保留外部 DLL 依赖路径）
   - 启动 → 等待 → 检查窗口 → 读日志 → kill
   - 测试 CCleaner x64 / VLC x64 / VLC x86

4. **遗留**
   - forwarder 递归解析（GetProcAddress 自动处理，暂不需要）
   - 资源保留（builder 端复制 .rsrc 节，PEB.Ldr 覆写后 OS 能找到资源，暂不阻塞）
   - x86 复杂 SEH 程序支持
   - dotnet packer 集成

## 变更记录 2026-07-19 反射式 Packer 阶段二续：x86 架构支持 + 9/9 样本通过

在 x64 反射式 loader 基础上新增 x86 (i386) 架构支持，builder 按输入 PE 的 Machine 字段自动选 stub，**batch test 9/9 全部 PASS**（含 x86 样本 helloguix86.exe）。

1. **`packer/reflective/loader.c` 双架构重构**
   - 新增架构相关类型别名：`IMAGE_NT_HEADERS_X` / `thunk_t` / `IMAGE_ORDINAL_FLAG_X` / `MY_MACHINE` 等，用 `#ifdef _WIN64` 切换，让 95% 代码无需 #ifdef
   - IAT 处理改用 `thunk_t`（x64=8字节 / x86=4字节）
   - 重定位 5 类型全支持（x86 主要 HIGHLOW，x64 主要 DIR64）
   - `init_security_cookie` x86 默认 cookie 0x0000BB40，x64 默认 0x00002B992DDFA232
   - `register_exception_table` x86 跳过（x86 SEH 走 FS:[0] 链无法手动注册，x64 走 .pdata + RtlAddFunctionTable）
   - VEH 函数 x86 分支输出 EIP/ESP 等 + 简单栈扫描；x64 分支输出 RIP/RSP 等 + RtlVirtualUnwind
   - `map_image` Machine 检查用 MY_MACHINE，stub 与输入 PE 架构不匹配时拒绝加载
   - PEB 访问：x64 `gs:[0x60]` / x86 `fs:[0x30]`，PEB 字段偏移用 offsetof 自动适配

2. **`packer/Makefile` 新增 x86 编译规则**
   - `RFL_EXE_X86 := $(RFL_DIR)/loader_x86.exe`
   - x86 stub 用 MSYS2 mingw32 gcc（`C:/Home/Develop/msys64/mingw32/bin/gcc.exe`）编译
   - 新增 `check-x86-toolchain` 目标检查工具链
   - 新增 `reflective-all` 目标一键编译 x64+x86 stub + builder
   - `reflective-clean` 清理 x86 产物

3. **`packer/builder/builder_reflective.c` 架构自动选择**
   - 按输入 PE 的 Machine 字段选默认 stub：x64→`loader_x64.exe`，x86→`loader_x86.exe`
   - `--stub` 显式覆盖默认选择
   - stub PE 头解析同时支持 IMAGE_NT_HEADERS32/64，按 Machine 字段决定用哪个类型
   - 检查 stub 架构与输入 PE 架构匹配（防止用 x64 stub 加壳 x86 PE）
   - 输出 PE 头更新按架构分支（x64 用 o_nt64，x86 用 o_nt32）

4. **`packer/tests/reflective_batch_test.ps1` 加入 x86 样本**
   - 新增 `helloguix86.exe` 测试项（WindowMatch="hellogui"）
   - 移除写死的 `--stub $Stub`，让 builder 按架构自动选
   - 修复 builder 默认 stub 相对路径问题：调用前 Push-Location 到 builder 目录

5. **端到端测试结果**（`make reflective-all` + batch test）
   - x86 样本 helloguix86.exe：加壳 → 反射加载 → IAT 解析 8 dlls/54 funcs → PEB.Ldr 覆写 → jump_to_oep → MessageBox 弹出 ✓
   - 9/9 全部 PASS：Notepad4 / DontSleep / helloguix64 / **helloguix86** / hellocli / hellomingw / helloucrt / ddccli / sha256sum

6. **参考项目调研**（`F:\Temp\pe`）
   - AlushPacker：x86 SEH 方案 patch `ntdll!RtlIsValidHandler`（硬编码偏移，跨版本不可靠）
   - peldr：只支持 x64，forwarder 不支持
   - amber：仅 shellcode wrapper，非反射式 loader
   - 当前实现：x86 SEH 暂跳过（简单 PE 如 helloguix86 无 SEH 依赖能正常跑），复杂 x86 SEH 程序支持留到阶段 3

7. **遗留**
   - x86 复杂 SEH 程序支持（需 VEH + RtlInsertInvertedFunctionTable 或 patch RtlIsValidHandler）
   - 延迟导入表（`IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`）
   - builder 端资源保留（`.rsrc` 节复制到 stub EXE）
   - dotnet packer 集成

## 变更记录 2026-07-19 反射式 Packer 阶段二：PEB.Ldr 覆写修复 DontSleep 崩溃 + 8/8 样本通过

阶段 2 核心障碍修复：反射式加载 DontSleep.exe 跳到 OEP 后被 MFC42u 内部抛出的 C++ 异常（0xE06D7363）终止。诊断并修复后 **8/8 x64 样本 round-trip 全部通过**。

1. **`packer/reflective/loader.c` 新增 PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY 结构**
   - 借鉴 `F:\Temp\pe\AlushPacker-main\Packer\structs.h`，按 Windows 内部 `_LDR_DATA_TABLE_ENTRY` 布局定义精简结构
   - 字段偏移与 OS 一致：DllBase +0x30 / EntryPoint +0x38 / SizeOfImage +0x40
   - PEBX 结构同步新增 `Ldr` 字段（offset 24/x64、12/x86）

2. **`packer/reflective/loader.c` 新增 `patch_peb_ldr_main_entry()` 函数**
   - 遍历 `PEB.Ldr.InMemoryOrderModuleList`，第一个条目就是主 EXE（stub 自己）
   - 覆写该条目 `DllBase/EntryPoint/SizeOfImage` 为反射式加载的 new_img 值
   - 借鉴 AlushPacker `LdrpPatchDataTableEntry` 思路，让 OS 把手动映射的 PE 当作"已加载模块"识别

3. **`packer/reflective/loader.c` 在 `map_image()` 中调用 `patch_peb_ldr_main_entry`**
   - 紧接 `update_peb_image_base` 之后，IAT 处理之前完成覆写
   - 保证 PEB.ImageBaseAddress 和 PEB.Ldr 主 EXE 条目一致

4. **DontSleep 崩溃根因分析与修复（核心进展）**
   - **症状**：DontSleep 反射式加载后 `_mainCRTStartup` 在 0x43014c 调用 `MFC42u!#1584`，该函数抛 C++ 异常 0xE06D7363 终止进程
   - **诊断**：在 stub 中加 FindResourceW / LoadStringW / GetModuleHandleW 测试代码，发现
     - `FindResourceW(0x400000, 1, RT_MANIFEST) = 0x48ac50` 成功（直接读 PE header）
     - `LoadStringW(0x400000, 1) = 0 chars, err=59` 失败（**ERROR_DIRECT_ACCESS_HANDLE**）
     - `GetModuleHandleW(L"DontSleep.exe") = NULL` - PEB.Ldr 里没有 0x400000 条目
   - **根因**：`LoadString` / `LoadResource` 走 `LdrFindResource_U`，需要 PEB.Ldr 里有对应模块条目。MFC42u!AfxWinInit 内部调用 `LoadString` 加载资源失败，抛 C++ 异常导致崩溃
   - **修复**：覆写 PEB.Ldr 主 EXE 条目，让 OS 认为 0x400000 是合法模块
   - **效果**：8/8 样本 PASS（Notepad4 / DontSleep / helloguix64 / hellocli / hellomingw / helloucrt / ddccli / sha256sum）

5. **清理调试代码**
   - 移除 main() 中用于诊断的 FindResource/LoadString/GetModuleHandle 测试代码块
   - 优化 patch_peb_ldr_main_entry 中不正确的 TimeDateStamp 日志行

6. **遗留**：阶段 2 剩余未完成项（不影响当前 8/8 通过）
   - 延迟导入表（`IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`）
   - builder 端资源保留（manifest / `.rsrc` 节复制到 stub EXE）
   - forwarder 递归解析（目前依赖 `GetProcAddress` 自动处理）
   - dotnet packer 集成

## 变更记录 2026-07-19 反射式 Packer/Stub 阶段一 MVP 实施完成

按照 `packer/docs/REFLECTIVE_DESIGN.md` 阶段 1 MVP 计划完成反射式 loader 的首个可运行版本，**已通过端到端验收**：反射式加载 Notepad4.exe / hellocli.exe 跳 OEP 成功。

1. **新增 `packer/reflective/payload.h`**：反射式 payload 容器格式定义
   - 魔数 `WLOCKR` + 版本 + flags 位域（HASH/TEST_MODE/COMPRESS/ENCRYPTED/ANTIDEBUG/ERASE_HDR/SCRUB_FN）
   - `reflective_payload_t` 结构 152 字节：含 image_base / oep_rva / salt / nonce / pwd_hash / xtea_key 等字段（v1 明文模式这些字段全 0）
   - builder 和 stub 共享此头定义

2. **新增 `packer/reflective/loader.c`**：反射式 stub 主体（MVP v1 明文模式）
   - 用 Win32 API + CRT（开发优先，不做 PIC 无 CRT）
   - 仅 x64，PEB 访问用 `__readgsqword(0x60)`
   - 完整流程：定位 .payload 节 → 解析 header → VirtualAlloc preferred base → 复制 PE 头+各节 → 应用 relocations（DIR64）→ 处理 IAT（LoadLibraryA + GetProcAddress，OS 自动处理 forwarder）→ 注册 .pdata（RtlAddFunctionTable）→ 初始化 SecurityCookie（KUSER_SHARED_DATA）→ 设置节权限 → 更新 PEB.ImageBaseAddress → 调用 TLS callbacks（DLL_PROCESS_ATTACH）→ jump_to_oep（16B 对齐 + 40B shadow space）
   - 调试日志：写 `*_loader.log` 文件 + OutputDebugStringA（不弹 console 避免 GUI 干扰）
   - IAT 解析宽松策略：GetProcAddress 失败时写 NULL 警告但继续（解决 comctl32 v6 ordinal 在 v5 缺失的问题）

3. **新增 `packer/builder/builder_reflective.c`**：反射式 packer builder（MVP v1 明文模式）
   - 读取任意架构 PE（x86/x64/ARM64/.NET 都能读，反射式不挑食）
   - 构造 payload：reflective_payload_t 头 + 完整原 PE 文件（v1 明文不加密）
   - 在 stub EXE 末尾追加 .payload 节（含节头空间检查、对齐计算）
   - 继承原 PE 的 Subsystem（GUI 保持 GUI，console 保持 console）
   - 清零 CheckSum

4. **修改 `packer/Makefile`**：新增 reflective 构建规则
   - `make reflective`：编译 loader_x64.exe + builder_reflective.exe
   - `make reflective-test`：用 builder_reflective 加壳 Notepad4.exe
   - `make reflective-clean`：清理 reflective 产物
   - 不影响现有 in-place stub/builder 构建规则

5. **新增 `packer/tests/run_reflective_test.ps1`**：反射式加载测试脚本
   - 启动加壳后 EXE，等待若干秒，检查进程是否存活 + Notepad4 窗口是否出现
   - 自动清理测试进程

6. **端到端验收通过**：
   - ✅ `temp/samples/Notepad4.exe`（x64 GUI, 2.4MB）：加壳后启动，"未命名 - Notepad4" 窗口出现，进程存活
     - 日志显示：12 DLL / 482 函数解析成功，4028 个 .pdata 注册，节权限设置完成，OEP 跳转成功
   - ✅ `temp/samples/hellocli.exe`（x64 console, 12KB）：加壳后运行输出 "Hello World!"
   - 反射式加载完整流程（VirtualAlloc preferred base 命中 → 节复制 → IAT → reloc → .pdata → SecurityCookie → 节权限 → PEB 更新 → 跳 OEP）全部跑通

## 变更记录 2026-07-19 反射式 Packer/Stub 设计文档

新增反射式 loader 模式技术储备文档（无代码改动）

1. **新增 `packer/docs/REFLECTIVE_ANALYSIS.md`**：5 个反射式 PE loader 项目深度对比报告
   - peldr / AlushPacker / AtomPePacker / amber / pe-packer-rust
   - 每个项目的 stub 语言、payload 格式、加密栈、IAT 解析、reloc 覆盖、TLS/.pdata/SecurityCookie 处理、栈对齐跳 OEP、API hash、反调试、反 dump、资源保留、stub 体积、与 OS loader 协作方式
   - 横向对比表 + 可借鉴度评分 + 关键源码位置索引

2. **新增 `packer/docs/REFLECTIVE_DESIGN.md`**：WinLock 反射式 Packer/Stub 设计方案
   - 核心原则：**开发优先**（stub 体积放宽到 2MB）、**加密和反调试后置**（MVP 用 XTEA+SHA-256，后期升级 ChaCha20+PBKDF2）
   - 文件结构：新增 `reflective/loader.c` + `builder_reflective.c` + `payload.h`，与现有 in-place 模式并存
   - payload 格式：紧凑二进制头 + 魔数("WLOCKR") + 版本 + flags 位域
   - 实施计划 5 阶段：MVP → 完整 PE 初始化 → MVP 加密版 → 后期增强 → 测试
   - 决策记录：工具链、payload 容器、MVP 加密、TLS 处理、跳 OEP、API hash、反调试后置等 7 项决策

## 变更记录 2026-07-19 11:20

auto_test.ps1 扩展支持 WinLock 模式 + 样本列表更新 + --test CLI 参数

1. **auto_test.ps1 新增 -WinLock 模式**：用 `--stub-name winlock --test` 调 packer
   做加壳测试。WinLock 是 in-place 加壳，加壳后 exe 直接运行原程序逻辑（无 stub
   子进程，无临时文件），密码硬编码为 "test123"（builder -t 测试模式）。
   - 预期通过：helloguix64.exe / helloguix86.exe（原生 GUI）
   - 预期 SKIP：4 个 Console 程序（WinLock 仅支持 GUI）、hellowinforms.exe
     （WinLock 不支持 .NET CLR）
   - packer 拒绝时标 SKIP 而非 FAIL，避免误报

2. **PackOptions 新增 WinLockTestMode 字段**：CLI `--test` 开关启用，传给
   WinLockPacker → builder -t。stub 跳过密码弹框，用硬编码 "test123" 解密。
   用于 CI/自动化测试。非 --test 模式下保持原弹框行为不变。

3. **auto_test.ps1 默认样本列表更新**：
   - 移除 hellogui.exe（已从 samples 删除）
   - 新增 helloguix64.exe / helloguix86.exe（分架构 GUI 样本）
   - 新增 hellowinforms.exe（.NET WinForms GUI，临时文件模式应通过，WinLock 应拒绝）

4. **Is-GuiExe 改用 packer --pe-info 读子系统判断**（而非文件名启发式）：
   - hellowinforms.exe 是 .NET WinForms GUI 但文件名不含 "gui"
   - 文件名启发式会误判为 CLI，导致走 CLI 分支 stdout 为空触发异常
   - 改为读 Subsystem=2 (WindowsGui) 判断，pe-info 失败时退回启发式

5. **修复 Is-GuiExe 参数传递 bug**：`Is-GuiExe $sample` 传文件名（hellowinforms.exe）
   导致 --pe-info 找不到文件，改为 `Is-GuiExe $src` 传完整路径。

6. **CLI stdout 防御性处理**：stdout 为空时显示 "OK (exit=0, no stdout)" 而非
   触发 null 异常（GUI 程序意外走到 CLI 分支时不输出到 stdout）。

7. **hellowinforms.exe.config 一起拷贝到 work 目录**：.NET 程序需要 config 文件
   才能正确启动（startup useLegacyV2RuntimeActivationPolicy 等）。

## 变更记录 2026-07-19 11:05

dotnet dist 目录移到项目根 + auto_test.ps1 进程清理修复

1. **dist 目录移到 applocker 根目录**：`build.ps1 -Release` 输出从 `dotnet/dist/`
   改为 `applocker/dist/`（与 `dotnet/`、`packer/` 平级）。`$distDir` 改用
   `$applockerRoot\dist`，便于两个子项目产物统一汇集。日志目录随之变为
   `applocker/dist/logs/`（AppLogger 自动跟随 exe 路径，无需改代码）。

2. **auto_test.ps1 packer 查找路径回退**：新增 `$root\..\dist\WinAppLocker.exe`
   回退路径，与 `$root\dist\`、`packer/bin/Release/`、`packer/bin/Debug/` 三级查找。

3. **auto_test.ps1 修复 hellogui 子进程残留 bug**：
   - **根因**：旧代码按 `el_*` 模式匹配临时子进程，但实际命名规则是
     `_{原名}_ori.exe`（见 `StubEntry.cs:122`），hellogui 测试启动的
     `_hellogui_test_locked_ori.exe` 永远匹配不到，测试后残留进程。
   - **修复**：按真实命名规则 `_*_ori` 匹配，并加显式 `[kill]` 日志。
   - **步骤3 临时文件清理**：`el_*.exe` 改为 `_*_ori.exe` 匹配。

4. **auto_test.ps1 已从 `dotnet/test.ps1` 改名到 `dotnet/tests/auto_test.ps1`**：
   用户已自行移动，路径变量用 `$root = Split-Path -Parent $PSScriptRoot` 推算。
   脚本顶部用法注释同步更新为 `.\tests\auto_test.ps1`。

## 变更记录 2026-07-19 10:40

packer 日志详细度调整 + WinLock stub 改名 + IconCopier 字符串名 bug 修复

1. **加密开始日志补充 PE 信息**：GUI `btnPack_Click` 和 CLI `RunCliPack` 在调用 `PackCore.Pack`
   之前先用 `PeReader.Parse` 读取所选 exe 的 PE 关键属性，拼接成 `PE=[x64/GUI ASLR=True DEP=True
   CFG=True HEVA=True TLS=True Signed=True Reloc=True .NET=False size=4735888]` 形式，
   追加到 "开始加密" 日志行尾。这样即便用户中途清空了 `lblPeInfo` 显示，日志里也保留该
   exe 的关键属性用于事后排查。

2. **日志级别区分（[INFO] / [WARN]）**：`PackCore` 的 `logger` 回调是单个 `Action<string>`，
   无法直接传级别枚举。改为按消息前缀约定区分：包含 `WARN:` / `ERROR:` / `[stderr]` 的消息
   走 `AppLogger.Warn`，其余走 `AppLogger.Info`。IconCopier 的所有错误信息前缀改为
   `[IconCopier] WARN:` 以匹配此约定。

3. **WinLock builder 加 `--debug` 参数**：新增 `g_debug` 全局标志和 `DBG(fmt, ...)` 可变参数宏。
   所有 `[*]` 详情日志（PE 解析、节列表、reloc patch、stub_data 填充等）从 `printf` 改为
   `DBG()`，只在 `-v` / `--debug` 时输出。`[+]` / `[-]` / `[!]` 关键日志保持 always-on。
   目的：避免 packer 把 builder 的 stdout 全部记入 AppLogger 时日志过载。

4. **WinLock stub 文件名加 `winlock_` 前缀**：分发目录统一改名：
   - `stub_x64.bin` → `winlock_stub_x64.bin`
   - `stub_x86.bin` → `winlock_stub_x86.bin`
   - `stub_x86.exe` → `winlock_stub_x86.exe`
   - `builder.exe` → `winlock_builder.exe`（已沿用）
   
   `build.ps1` 拷贝 WinLock 产物到 `dotnet/packer/stub/` 时按新名拷贝；
   `winlock_builder.exe.meta.json` 的 `components` 字段同步更新引用新名；
   `builder.c` 的 stub 搜索路径优先用新名，向后兼容旧名 `stub_x{64,86}.bin` /
   `stub_x86.exe`（开发者直接 `make` 产出的源文件名）。

5. **IconCopier 修复 `FindResourceW(RT_GROUP_ICON) failed: 1814`**：
   - **根因**：`EnumResourceNamesW` 回调返回的 `lpName` 字符串只在回调期间有效，回调返回后
     字符串可能失效（特别是字符串名如 `"IDR_MAINFRAME"`）。旧实现把 `lpName` 的 `IntPtr`
     直接保存，回调结束后 `FindResourceW` 用失效指针找不到资源（ERROR_RESOURCE_NAME_NOT_FOUND=1814）。
   - **修复**：新增 `ResourceName` struct，在回调中检测 `lpName` 类型（IS_INTRESOURCE：
     高位 WORD == 0 表示整数 ID），若是字符串则用 `Marshal.StringToHGlobalUni` 复制到
     long-lived 非托管内存。`finally` 块中调用 `mainGroupName.Free()` 释放。
   - **验证**：Doubao.exe（字符串名 `"IDR_MAINFRAME"` 主图标）打包后日志显示
     `主图标 group="IDR_MAINFRAME", 引用 8 个 RT_ICON，共 10 个资源将写入`，无 1814 错误。

6. **README 补充 Stub 自动选择标准章节**：新增 "Stub 自动选择标准" 章节，说明
   `StubRegistry.Select` 的三级优先级（用户指定 > 按子系统匹配 > 任意可用）、
   `IsAvailable` / `SupportsMachine` 约束、WinLock 不被自动选中的原因、以及
   WinLock 对输入 PE 的限制条件（.NET / Console / DLL / ARM 等不支持情况）。

## 变更记录 2026-07-19 09:58 

packer 新增操作日志与 PE 信息展示

1. **操作日志**：所有关键操作（GUI 启动、stub 加载、打包开始/成功/失败、CLI 调用、PE 信息查询）
   均写入按天滚动的日志文件 `packer_YYYYMMDD.log`。日志目录优先选 `WinAppLocker.exe`
   同级 `logs/` 子目录；若无写权限，自动回退到 `%LOCALAPPDATA%\WinAppLocker\logs\`。
   日志写入通过 `lock` 保护线程安全，所有 IO 异常被吞掉，日志失败不影响主流程。

2. **PE 信息展示**：选择 exe 后在"执行加密操作"按钮上方小字位置自动展示 PE 关键信息，
   包括架构 (x86/x64/arm/arm64)、子系统 (GUI/Console)、ASLR / DEP / CFG / HighEntropyVA、
   TLS 回调、Authenticode 签名、重定位表、.NET CLR 托管、文件大小。.NET 或带签名程序
   用警告色（OrangeRed）提示。同时新增 CLI 命令 `--pe-info <exe>` 用于命令行查看。
## 2026-07-20 10:28 项目记忆与资产定位机制
- AGENTS.md 新增「项目地图（速查）」章节，统一文件/工具位置索引（自动加载）
- 新增 tests/find_asset.py 资产定位器（dir/sample/test/tool 子命令），用查询代替记忆
- 初始化 .workbuddy/memory/ 记忆系统（每日日志 + 长期 MEMORY.md）

## 2026-07-20 10:32 跨工具记忆自动化（WorkBuddy/Trae/OpenCode 共用）
- 记忆从 .workbuddy/memory 迁到仓库级 memory/ 目录，三工具共享同一份
- 新增 scripts/memory_log.py：agent 任务结束后运行即自动写记忆，并同步 .workbuddy/memory
- AGENTS.md 新增「记忆协议」章节 + 修正地图记忆行指向 memory/
- 结论：跨工具自动化 = AGENTS.md(通用真相源) + 仓库脚本，而非某家私有 skill
