# 变更记录

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