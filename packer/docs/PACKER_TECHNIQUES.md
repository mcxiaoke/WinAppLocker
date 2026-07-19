# PE 加壳方案技术对比

> 本文档系统对比主流 PE 加壳方案的原理、优缺点、适用场景，并给出本项目的选型决策与演进路线。
> 创建日期：2026-07-19

## 目录

- [1. 加壳方案分类](#1-加壳方案分类)
- [2. 已实现方案](#2-已实现方案)
  - [2.1 Tempfile（临时文件）](#21-tempfile临时文件)
  - [2.2 Inplace（原地加壳，WinLock）](#22-inplace原地加壳winlock)
  - [2.3 Reflective（反射式加载）](#23-reflective反射式加载)
- [3. 未实现的成熟方案](#3-未实现的成熟方案)
  - [3.1 Process Hollowing（进程镂空）](#31-process-hollowing进程镂空)
  - [3.2 RunPE / Process Replacement](#32-runpe--process-replacement)
  - [3.3 VFS（Virtual File System，虚拟文件系统）](#33-vfsvirtual-file-system虚拟文件系统)
  - [3.4 Shellcode 加载（PIC）](#34-shellcode-加载pic)
  - [3.5 AppInit_DLLs 注入](#35-appinit_dlls-注入)
  - [3.6 .NET 专用加壳](#36-net-专用加壳)
  - [3.7 代码虚拟化（Code Virtualization）](#37-代码虚拟化code-virtualization)
- [4. 横向对比表](#4-横向对比表)
- [5. 本项目的选型决策](#5-本项目的选型决策)
- [6. 演进路线](#6-演进路线)
- [7. 已知限制与兼容性矩阵](#7-已知限制与兼容性矩阵)
- [8. 参考资料](#8-参考资料)

---

## 1. 加壳方案分类

PE 加壳按 **"加载/执行方式"** 分类，主要有三大流派：

```
┌─────────────────────────────────────────────────────────────┐
│  加壳方案分类                                                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  A. OS Loader 加载（让 OS 完整加载 PE）                      │
│     ├─ Tempfile      解密到临时文件，CreateProcess 运行      │
│     ├─ Process Hollowing  启动合法进程后替换镜像             │
│     └─ RunPE         启动另一个进程后替换镜像                │
│                                                             │
│  B. 手动加载（stub 自己模拟 OS loader）                      │
│     ├─ Inplace        修改 .text 节为加密数据，原地跳 OEP    │
│     ├─ Reflective     内存映射加载原 PE，完整模拟 loader     │
│     └─ Shellcode      把 PE 转成 PIC，无需 PE 头             │
│                                                             │
│  C. 环境模拟（提供虚拟运行环境）                             │
│     ├─ VFS           虚拟文件系统，hook 文件访问             │
│     ├─ .NET 加壳     修改 IL 元数据                          │
│     └─ 代码虚拟化    自定义 VM 解释执行                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**核心权衡**：
- **兼容性** vs **隐蔽性**：OS Loader 加载兼容性最好，但需要落盘或操作其他进程；手动加载无落盘但兼容性差（需自己处理 TLS/PEB/.pdata 等）。
- **实现复杂度** vs **功能完整性**：越接近 OS loader 行为，需要手动处理的细节越多（TLS callbacks、PEB.Ldr、actctx、delay import、SecurityCookie、.pdata 注册等）。

---

## 2. 已实现方案

### 2.1 Tempfile（临时文件）

**原理**：
1. stub 启动后弹密码框
2. 密码正确 → AES 解密 payload → 写到临时文件（如 `%TEMP%\xxx.exe`）
3. `CreateProcessW` 启动临时文件
4. 等待子进程退出，删除临时文件

**代码位置**：`dotnet/packer/TempfilePacker.cs`

**优点**：
- ✅ **兼容性最好**：OS loader 完整加载，支持 .NET、Chrome、Chromium 系浏览器、所有 native 程序
- ✅ 实现简单，无需处理 TLS/PEB/重定位等
- ✅ 支持 AES-256-CBC + HMAC-SHA-256 加密，强度高
- ✅ 支持任意架构（x86/x64/ARM64）

**缺点**：
- ❌ 临时文件落盘，可能被复制/分析（即使删除也有时间窗口）
- ❌ 需要清理临时文件（异常退出可能残留）
- ❌ 杀软可能扫描临时文件

**适用场景**：.NET 程序、Chrome/Doubao 等 Chromium 浏览器、依赖大量外部 DLL 的程序

**实测兼容性**：所有程序都能跑

---

### 2.2 Inplace（原地加壳，WinLock）

**原理**：
1. builder 修改原 PE 的 `.text` 节为 XTEA 加密数据
2. 在 PE 末尾追加 stub 代码（新节）
3. 修改 OEP 指向 stub
4. 运行时 stub 弹密码框 → 解密 `.text` 节 → 跳回原 OEP

**代码位置**：`packer/builder/builder.c`、`packer/stub/stub.c`

**优点**：
- ✅ **无临时文件**：进程自包含
- ✅ 实现相对简单（只改 `.text` 节，不模拟 loader）
- ✅ 进程映像就是原程序（PEB.ImageBaseAddress 不变）

**缺点**：
- ❌ 仅支持 GUI 程序（Console 程序的 stub 弹窗会干扰）
- ❌ 不支持 .NET（CLR 检查元数据完整性）
- ❌ 加密强度受限（XTEA，且仅加密 `.text` 节）
- ❌ 不支持 ASLR 程序（`.text` 节地址需固定）

**适用场景**：原生 GUI 程序的轻量保护

**实测兼容性**：helloguix64/helloguix86 等 GUI 样本通过

---

### 2.3 Reflective（反射式加载）

**原理**：
1. builder 把原 PE 完整嵌入 stub 的 `.payload` 节
2. stub 解析 payload，VirtualAlloc 分配 SizeOfImage 内存
3. 复制 PE headers + 各节
4. 处理 IAT + 延迟导入表
5. 应用重定位（5 类型）
6. 注册 .pdata（RtlAddFunctionTable，仅 x64）
7. 初始化 SecurityCookie（区分 VS/MinGW CRT）
8. 设置节权限（按 Characteristics 查表）
9. 更新 PEB.ImageBaseAddress + PEB.Ldr 主 EXE 条目
10. 激活 manifest（actctx，解决 comctl32 v6 等 SxS 依赖）
11. 初始化 TLS 数据（主线程 TLP[0]）
12. 调用原 PE 的 TLS callbacks（DLL_PROCESS_ATTACH）
13. **注册 TLS callback 代理**（`.CRT$XLB`），新线程创建时手动分配 TLS 数据块
14. 设置 DLL 搜索路径（SetCurrentDirectory + SetDllDirectory）
15. jump_to_oep（16 字节对齐 + shadow space）

**代码位置**：`packer/reflective/loader.c`、`packer/builder/builder_reflective.c`

**优点**：
- ✅ **无临时文件**：原 PE 完整保留在 `.payload` 节
- ✅ 支持 Console 和 GUI 程序
- ✅ 支持 x86 和 x64
- ✅ 支持 TLS callbacks（完整代理实现）
- ✅ 支持 PEB.Ldr 覆写（让 OS 识别反射加载的 PE 为模块）
- ✅ 原文件完整性保留（作为 `.payload` 节，不修改）

**缺点**：
- ❌ 不支持 .NET（CLR 假设主模块由 OS loader 加载）
- ❌ 不支持 Chromium 系浏览器（依赖版本化子目录 DLL，浏览器有自己的加载逻辑）
- ❌ MVP v1 是明文模式（无加密，后续可加 AES + 密码弹框）
- ❌ x86 复杂 SEH 程序支持有限（FS:[0] 链无法手动注册）
- ❌ 实现复杂（需处理 TLS/PEB/.pdata/actctx/delay import/SecurityCookie 等）

**适用场景**：需要无临时文件且原程序是 native PE 的场景

**实测兼容性**：
- ✅ FastCopy / Bandizip / BCompare / CC-Switch / AutoHotkey64 / FreeFileSync
- ❌ Chrome / Doubao（Chromium 系，UI 已禁用）
- ❌ .NET 程序（UI 已禁用）
- ❌ AutoHotkey32（x86 SEH 问题）

---

## 3. 未实现的成熟方案

### 3.1 Process Hollowing（进程镂空）

**原理**：
1. `CreateProcess(suspended)` 启动一个合法系统进程（如 `svchost.exe`）
2. `ZwUnmapViewOfSection` 卸载原进程镜像
3. `VirtualAllocEx` 在目标进程分配内存
4. `WriteProcessMemory` 写入解密后的 PE（headers + sections）
5. 应用重定位 + 修复 IAT（跨进程写入）
6. `SetThreadContext` 修改 EIP/RIP 到 OEP
7. `ResumeThread` 恢复执行

**优点**：
- 进程映像看起来是合法系统程序（PEB 显示 `svchost.exe`）
- 无临时文件
- OS loader 已经初始化了进程环境（TLS、PEB.Ldr 都正常）

**缺点**：
- 需要写另一个进程内存（被 EDR/杀软重点监控）
- 跨进程操作复杂（重定位、IAT 都要跨进程写）
- 原进程的导入表/资源可能和实际不符（PEB 显示 svchost，实际跑别的代码）
- 被广泛用于恶意软件，杀软拦截率高

**代表项目**：`F:\Temp\pe\PEzor`、`F:\Temp\pe\AtomPePacker`

**对本项目适用性**：**不推荐**。我们目标是保护用户自己的程序，没必要伪装成系统进程，反而会被杀软误报。

---

### 3.2 RunPE / Process Replacement

**原理**：Process Hollowing 的变体，但目标进程是**自己启动的另一个合法 EXE**（不是系统进程），然后替换成被保护程序。

**优点/缺点**：和 Process Hollowing 类似，但伪装性较弱（启动的是任意 EXE，不是系统程序）

**对本项目适用性**：**不推荐**。与 Process Hollowing 同样的监控问题，且无明显优势。

> 备注：本项目早期 Rust 版本曾尝试过 RunPE 路线（见 `rust/stub/src/lib.rs` 的 `run_pe` 调用），但因 TLS/PEB/堆等进程资源冲突导致复杂程序崩溃而放弃，转向 Reflective 方案。Reflective 方案现已完整解决 TLS 问题（见 [TLS_NOTES.md](TLS_NOTES.md)）。

---

### 3.3 VFS（Virtual File System，虚拟文件系统）

**原理**：把被保护程序依赖的所有文件（EXE + DLL + 资源）打包成一个虚拟文件系统，运行时通过文件 hook（`NtCreateFile`/`NtOpenFile`）拦截访问，从内存返回数据。

**代表产品**：
- **BoxedApp SDK**（商业）
- **Enigma Protector** 的 Virtual Box 功能
- **VMProtect** 的 License System
- **Themida** 的 Virtualization

**优点**：
- ✅ 完美兼容性（程序以为自己在真实文件系统运行）
- ✅ 可以打包整个目录（包括 DLL、数据文件、配置）
- ✅ 无临时文件
- ✅ 解决 Chrome/Electron 这类依赖子目录 DLL 的程序

**缺点**：
- ❌ 实现极其复杂（需要 hook 内核 API 或文件系统过滤器）
- ❌ 性能损失（每次文件访问都走 hook）
- ❌ 体积大（打包所有依赖）
- ❌ 商业 SDK 昂贵

**对本项目适用性**：**未来可以考虑**。如果 Reflective 模式遇到 Chrome 这类依赖子目录 DLL 的程序，VFS 是解决方案——把整个 Chrome 目录打包，hook 文件访问从内存返回。但工作量极大，属于"长期目标"。

---

### 3.4 Shellcode 加载（PIC）

**原理**：把被保护程序转换为位置无关代码（shellcode），stub 加载后直接跳转执行，不需要 PE 头、不需要重定位。

**代表项目**：
- `F:\Temp\pe\amber`（shellcode wrapper）
- CactusTorch、Donut（.NET shellcode 生成）

**优点**：
- 极简，无需 PE loader
- 适合注入任意进程内存

**缺点**：
- ❌ 转换过程会破坏原 PE 结构（重写所有绝对地址引用）
- ❌ 不支持 TLS、SEH、.pdata 等依赖 PE 头的机制
- ❌ 兼容性差（复杂程序转换失败率高）

**对本项目适用性**：**不推荐**。牺牲兼容性换简化，与我们的目标（保护任意 EXE）冲突。

---

### 3.5 AppInit_DLLs 注入

**原理**：在注册表 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` 设置 DLL 路径，每个加载 user32.dll 的进程都会自动加载这个 DLL。

**优点**：
- 全局注入，覆盖几乎所有 GUI 程序

**缺点**：
- ❌ 需要管理员权限修改注册表
- ❌ 影响系统所有进程（被杀软重点监控）
- ❌ Windows 10+ 默认禁用 AppInit_DLLs
- ❌ 只能注入 DLL，不能直接保护 EXE

**对本项目适用性**：**不适用**。我们是 EXE 加壳，不是 DLL 注入。

---

### 3.6 .NET 专用加壳

我们三种方式都不支持 .NET。.NET 加壳是独立的技术栈：

**代表产品**：
- **ConfuserEx**（开源，最流行）
- **Dotfuscator**（微软官方，VS 集成）
- **Eazfuscator.NET**
- **.NET Reactor**

**原理**：
- 元数据混淆（重命名类/方法/字段）
- 控制流混淆
- 字符串加密
- 反调试
- JIT 钩子保护

**对本项目适用性**：**不适用**。我们是 native PE 加壳，.NET 加壳是另一套技术（修改 IL 元数据，不是 PE loader）。如果用户要保护 .NET 程序，建议引导到 ConfuserEx 这类专用工具。

---

### 3.7 代码虚拟化（Code Virtualization）

**原理**：把 x86/x64 指令翻译成自定义虚拟机字节码，运行时用自定义解释器执行。

**代表产品**：
- VMProtect
- Themida WinLicense
- Code Virtualizer

**优点**：
- 极难逆向（每个 VM 实例都不一样）
- 保护核心算法最有效

**缺点**：
- ❌ 性能损失大（10-100 倍慢）
- ❌ 只能虚拟化关键函数，不能整个程序
- ❌ 商业产品昂贵

**对本项目适用性**：**不适用**。我们做的是"EXE 密码保护"，不是"代码防逆向"。用户场景是"忘记密码打不开"，不是"防止别人破解算法"。

---

## 4. 横向对比表

| 方案 | 落盘 | 兼容性 | 实现复杂度 | 加密强度 | .NET | Chrome | x86 | Console | 反杀软 |
|---|---|---|---|---|---|---|---|---|---|
| **Tempfile** ✅ | 临时文件 | ★★★★★ | ★★ | AES-256 | ✓ | ✓ | ✓ | ✓ | ★★★★ |
| **Inplace** ✅ | 无 | ★★ | ★★ | XTEA | ✗ | ✗ | ✓ | ✗ | ★★★ |
| **Reflective** ✅ | 无 | ★★★★ | ★★★★★ | MVP v1 明文 | ✗ | ✗ | ✓ | ✓ | ★★★ |
| Process Hollowing | 无 | ★★★ | ★★★★ | 任意 | ✗ | 部分 | ✓ | ✓ | ★（被监控） |
| RunPE | 无 | ★★★ | ★★★ | 任意 | ✗ | 部分 | ✓ | ✓ | ★（被监控） |
| VFS | 无 | ★★★★★ | ★★★★★ | 任意 | ✓ | ✓ | ✓ | ✓ | ★★★★ |
| Shellcode | 无 | ★ | ★★★ | 任意 | ✗ | ✗ | ✓ | ✓ | ★★ |
| AppInit_DLLs | 无 | ★★ | ★★ | 任意 | ✗ | ✗ | ✓ | N/A | ★（被监控） |
| .NET 加壳 | 无 | ★★★★（仅 .NET） | ★★★★ | 任意 | ✓ | N/A | N/A | ✓ | ★★★★ |
| 代码虚拟化 | 无 | ★★（关键函数） | ★★★★★ | 任意 | 部分 | 部分 | ✓ | ✓ | ★★★★★ |

---

## 5. 本项目的选型决策

### 5.1 为什么选这三种

本项目目标是 **"EXE 密码保护"**（用户场景：忘记密码打不开），不是"防止逆向工程"。基于此目标：

1. **Tempfile** 作为兼容性兜底：所有程序都能跑，包括 .NET 和 Chrome
2. **Inplace** 作为无临时文件的轻量方案：满足"原进程自包含"的需求
3. **Reflective** 作为无临时文件的完整方案：支持 Console/x86/TLS 等复杂程序

### 5.2 为什么不选其他方案

- **Process Hollowing / RunPE**：被杀软重点监控，与"合法 EXE 保护"目标冲突
- **VFS**：工作量极大，作为长期目标
- **Shellcode**：牺牲兼容性换简化，与目标冲突
- **AppInit_DLLs**：不适用 EXE 加壳
- **.NET 加壳**：技术栈不同，引导用户用专用工具
- **代码虚拟化**：目标场景不匹配（密码保护 vs 防逆向）

### 5.3 三种方案的分工

```
┌─────────────────────────────────────────────────────────────┐
│  用户选择 EXE 后，UI 自动判断并提示兼容性                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  .NET 程序         → 仅 Tempfile（Inplace/Reflective 禁用） │
│  Chromium 系浏览器  → 仅 Tempfile（Inplace/Reflective 禁用） │
│  Console 程序      → Tempfile / Reflective（Inplace 禁用）  │
│  native GUI 程序   → 三种都可用                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

UI 检测逻辑见 `dotnet/packer/MainForm.cs/GetStubCompatibilityWarning`。

---

## 6. 演进路线

按价值排序：

### 短期（v1 → v2）

1. **Reflective 加密版**：当前 MVP v1 是明文，下一步加 AES-256-CBC + HMAC-SHA-256 + 密码弹框（payload.h 已预留字段）
2. **Reflective 反调试**：检测调试器附加，拒绝运行
3. **x86 SEH 支持**：通过 VEH + RtlInsertInvertedFunctionTable 或 patch RtlIsValidHandler 解决 AutoHotkey32 等 x86 SEH 程序

### 中期

4. **Reflective 资源保留**：builder 端复制原 PE 的 `.rsrc` 节到 stub（让 OS 资源 API 完整工作）
5. **Reflective 反 dump**：擦除 PE 头、加密 `.payload` 节、运行时解密

### 长期

6. **VFS（虚拟文件系统）**：解决 Chrome/Electron 这类依赖子目录 DLL 的程序
   - 把整个程序目录打包进 EXE
   - hook `NtCreateFile`/`NtOpenFile` 从内存返回数据
   - 工作量极大，作为长期目标
7. **.NET 引导**：检测到 .NET 程序时，提示用户用 ConfuserEx 等专用工具

### 不推荐

- **Process Hollowing / RunPE**：被杀软监控，与合法保护目标冲突
- **代码虚拟化**：目标场景不匹配

---

## 7. 已知限制与兼容性矩阵

### 7.1 三种方案的兼容性

| 程序类型 | Tempfile | Inplace | Reflective | 说明 |
|---|---|---|---|---|
| native GUI (x64) | ✅ | ✅ | ✅ | FastCopy / BCompare / CC-Switch |
| native GUI (x86) | ✅ | ✅ | ✅ | FreeFileSync / AutoHotkey32* |
| native Console (x64) | ✅ | ❌ | ✅ | hellocli |
| native Console (x86) | ✅ | ❌ | ✅ | - |
| .NET GUI | ✅ | ❌ | ❌ | hellowinforms |
| .NET Console | ✅ | ❌ | ❌ | - |
| Chromium 浏览器 | ✅ | ❌ | ❌ | Chrome / Edge / Doubao |
| Electron 程序 | ✅ | ❌ | ? | 未充分测试 |
| ARM64 PE | ✅ | ❌ | ❌ | 未实现 |

*AutoHotkey32 在 Reflective 模式下因 x86 SEH 问题仍崩溃，与 TLS 无关

### 7.2 Reflective 模式的已知限制

| 限制 | 根因 | 解决方案 |
|---|---|---|
| 不支持 .NET | CLR 假设主模块由 OS loader 加载 | 引导用 Tempfile 或 ConfuserEx |
| 不支持 Chromium | 浏览器依赖版本化子目录 DLL | 引导用 Tempfile 或未来 VFS |
| x86 SEH 程序崩溃 | FS:[0] SEH 链无法手动注册 | 计划用 VEH + RtlInsertInvertedFunctionTable |
| MVP v1 明文 | payload 未加密 | v2 加 AES + 密码弹框 |
| actctx 失败 | manifest 引用的 SxS 程序集找不到 | 部分程序仍能跑，致命时引导用 Tempfile |

### 7.3 TLS 处理

Reflective 模式已完整解决 TLS 问题，详见 [TLS_NOTES.md](TLS_NOTES.md)：

- ✅ 主线程 TLS 数据初始化（`init_tls_data`）
- ✅ TLS callback 代理（`.CRT$XLB` section 注册）
- ✅ 新线程 TLS 数据块分配（`DLL_THREAD_ATTACH` 时 VirtualAlloc）
- ✅ TLS 重定位字段处理（x86 HIGHLOW / x64 DIR64）
- ✅ 支持 Rust / Delphi / MinGW / MSVC CRT 的 TLS

---

## 8. 参考资料

### 8.1 本项目相关文档

- [ANALYSIS_REPORT.md](ANALYSIS_REPORT.md) — 12 个 PE 加壳项目对比分析
- [REFLECTIVE_ANALYSIS.md](REFLECTIVE_ANALYSIS.md) — 5 个反射式 PE loader 项目深度对比
- [REFLECTIVE_DESIGN.md](REFLECTIVE_DESIGN.md) — WinLock 反射式 Packer/Stub 设计方案
- [TLS_NOTES.md](TLS_NOTES.md) — 反射式 loader 的 TLS 处理经验

### 8.2 参考项目源码（`F:\Temp\pe`）

| 项目 | 加壳方式 | 参考价值 |
|---|---|---|
| PELoader3 | Reflective | TLS callback 代理（已用） |
| Fatpack | Reflective + 资源加壳 | Full TLS support（已调研） |
| AlushPacker | Reflective + x86 SEH | PEB.Ldr 覆写、x86 SEH 思路（已用） |
| peldr | Reflective | 节权限查表（已用） |
| amber | Shellcode | 不推荐（兼容性差） |
| PEzor | RunPE 注入 | 不推荐（被监控） |
| AtomPePacker | RunPE 重映射 | 不推荐（被监控） |
| WinXRunPE | Process Hollowing | 不推荐（被监控） |
| dotNetPELoader | Reflective (C#) | 不推荐（功能远不如我们） |

### 8.3 外部参考资料

- PE 文件格式规范：https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- TLS 实现：https://maskray.me/blog/2021-02-14-all-about-thread-local-storage
- Reflective DLL Injection：https://github.com/stephenfewer/ReflectiveDLLInjection
- Process Hollowing：https://github.com/dismantl/ImprovedReflectiveDLLInjection
