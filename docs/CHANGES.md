# 变更记录

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