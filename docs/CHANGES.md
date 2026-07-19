# 变更记录

## 2026-07-18 WinLock (in-place PE 加壳器) 集成到 AppLocker .NET

### 改动概况

把 WinLock 项目（C + 内联汇编的 in-place PE 加壳器）集成到 AppLocker .NET 项目，
作为可选的 stub 加壳模式。packer 现在支持两种加壳方案：

1. **临时文件模式**（原有）：原 EXE 作为 payload 附加在 stub 后，运行时释放隐藏临时文件。
2. **WinLock in-place 模式**（新增）：原 EXE 被原地修改，stub 嵌入 `.lock` 节，
   运行时在内存中解密 `.text` 节，不释放任何文件，单文件独立运行。

发布格式从"单文件 exe + 嵌入资源 stub"改为"exe + stub/ 目录"，packer 启动时
扫描 stub/ 目录下的 `.meta.json` 文件动态建立可用 stub 列表。

### 新增文件

- `dotnet/packer/StubManifest.cs` — stub 元数据模型（StubKind / StubSubsystem 枚举 +
  .meta.json 反序列化），定义 `Tempfile` 和 `InplaceBuilder` 两种加壳方案
- `dotnet/packer/StubRegistry.cs` — stub 注册表，扫描 stub/ 目录所有 *.meta.json，
  按用户偏好 / 子系统 / 架构选择 stub
- `dotnet/packer/WinLockPacker.cs` — WinLock 加壳分支，调用 winlock_builder.exe
  作为外部进程对原 EXE 做 in-place 加壳
- `docs/CHANGES.md` — 本文件

### 修改文件

#### packer/ (WinLock 源码，根目录的子项目)

- `packer/builder/builder.c` — 新增 `--stub-dir <path>` 参数，让 packer 调用 builder 时
  能指定 stub.bin 所在目录（替代硬编码的相对路径 `stub/`）
  - 修改 `print_usage()` 帮助文本
  - 修改 stub_x64.bin / stub_x86.bin / stub_x86.exe 搜索逻辑：优先用 --stub-dir，
    失败再回退到 `stub/` 相对路径和 argv0 目录

#### dotnet/packer/ (packer 主项目)

- `dotnet/packer/PeReader.cs` — 把原 `StubKind` 枚举（Auto/Gui/Console/Test）重命名为
  `StubPreference`，避免与新 `StubManifest.StubKind`（Tempfile/InplaceBuilder）冲突
- `dotnet/packer/StubLoader.cs` — 新增 `FindStubDir()` 定位 stub/ 目录（packer exe 同目录
  优先，fallback 到 CWD），新增 `LoadFromStubDir()`。`SelectStub()` 先试 stub/ 目录，
  找不到再回退嵌入资源（兼容旧单文件发布）
- `dotnet/packer/PackCore.cs` —
  - `PackOptions` 新增 `PreferStubName` 字段（优先级高于 StubPreference）
  - `PackReport` 新增 `UsedStubName` / `UsedKind` 字段
  - `Pack()` 流程：扫描 stub/ → 加载 manifests → 选 stub → 分发到 PackWithWinLock 或 PackWithTempfile
  - `PackWithWinLock`：复制输入到临时文件，调用 WinLockPacker.Pack，复制输出，
    跳过 IconCopier（WinLock 已保留原 .rsrc，UpdateResourceW 会破坏 .lock 节）
  - `PackWithTempfile`：原逻辑，stub 字节优先从 stub.MainFilePath 读，回退到嵌入资源
  - `SelectByLegacyPreference`：旧 StubPreference(Auto/Gui/Console/Test) 映射到 manifest
  - WinLock 模式拒绝 .NET CLR PE 和 Console 子系统程序
- `dotnet/packer/MainForm.cs` —
  - 新增 `StubListItem` 内部类（包装 StubManifest + Label）
  - 新增 `_availableStubs` 字段、`LoadStubList()` 从 stub/ 目录动态填充 ComboBox
  - 新增 `UpdateStubVersionLabels()` 显示可用/缺失 stub 列表
  - 新增 `WarnIfIncompatible()` 在选 WinLock + Console/.NET 组合时弹警告
  - 新增 `cbStubPreference_SelectedIndexChanged` 事件处理
  - `btnPack_Click` 用 `PreferStubName` 传给 PackOptions，结果 label 显示 [WinLock] 标记
- `dotnet/packer/MainForm.Designer.cs` — 移除硬编码的 ComboBox Items，加宽下拉框，
  绑定 SelectedIndexChanged 事件
- `dotnet/packer/Program.cs` —
  - 修复 `StubKind` → `StubPreference` 引用（重命名后遗留）
  - 新增 `--stub-name <name>` 参数（指定 stub manifest 名称）
  - 新增 `--list-stubs` 顶级命令（列出 stub/ 目录所有 stub）
  - 更新帮助文本和用法错误消息
  - PackReport 输出加上 `UsedStubName (UsedKind)` 日志
- `dotnet/packer/WinAppLocker.Packer.csproj` —
  - 新增 `System.Text.Json` NuGet 包引用（.NET Framework 4.7.2 不内置，用于反序列化 .meta.json）
  - 新增 `<None Include="stub\**\*">` ItemGroup，把 stub/ 目录内容拷到输出目录
  - 保留原 `CopyStubs` Target 作为嵌入资源兜底（单文件发布模式）

#### dotnet/ (构建脚本)

- `dotnet/build.ps1` — 完全重写：
  - 新增 `-SkipWinLock` 参数
  - 新增 WinLock 编译步骤（调用 `mingw32-make all all-x86`，自动加入 w64devkit + msys2 到 PATH）
  - 新增 stub 汇集步骤：拷贝 dotnet stub exe + WinLock builder/bin/exe 到 `packer/stub/`
  - 新增 4 个 .meta.json 文件生成（stub_gui/console/test.exe.meta.json + winlock_builder.exe.meta.json）
  - 验证 packer 输出目录的 stub/ 子目录
  - Release 模式 dist/ 拷贝整个 stub/ 目录

#### dotnet/README.md — 完全重写：
  - 新增 WinLock 模式介绍、工作原理、与临时文件模式对比表
  - 新增 WinLock 限制说明（不支持 .NET/Console/DLL/带自校验程序等）
  - 新增发布格式说明（dist/ + stub/ 目录结构）
  - 新增 CLI 参数表（含 --stub-name / --list-stubs）
  - 新增项目结构说明
  - 新增 -SkipWinLock 构建参数说明

### 测试结果

#### tempfile 模式回归（test.ps1）

5 个样本全部通过：
- hellocli.exe (CLI, exit=0, "Hello World!")
- hellomingw.exe (CLI, exit=0, "Hello, MinGW!")
- helloucrt.exe (CLI, exit=0, "Hello, UCRT!")
- sha256sum.exe (CLI, exit=0, sha256 输出正确)
- hellogui.exe (GUI, 进程存活)

#### WinLock 模式端到端测试

3 个 GUI 样本全部通过（加壳 → 运行 → 弹密码框 → 输入密码 → 解密 → 原程序启动）：
- hellogui.exe (107KB → 114KB，窗口标题 "win32helloword")
- DontSleep.exe (523KB → 520KB，窗口标题 "Don't Sleep 9.96")
- Notepad4.exe (2.4MB → 2.4MB，窗口标题 "未命名 - Notepad4")

#### --list-stubs 命令

正确列出 4 个 stub：
- applocker-console (tempfile/console) [OK]
- applocker-gui (tempfile/gui) [OK]
- applocker-test (tempfile/test) [OK]
- winlock (inplace-builder/gui, arch=amd64+i386) [OK]

### 修复的问题

1. **StubKind 命名冲突**：原 PeReader.cs 的 `StubKind`（Auto/Gui/Console/Test，子系统偏好）
   与 INTEGRATION.md 新 spec 要求的 `StubKind`（Tempfile/InplaceBuilder，加壳方案）冲突。
   解决：原枚举重命名为 `StubPreference`，新枚举用 `StubKind`。

2. **System.Text.Json 缺失**：.NET Framework 4.7.2 不内置 System.Text.Json，编译报
   CS0234。解决：csproj 加 `System.Text.Json` NuGet 包引用，Costura.Fody 会把依赖 DLL
   嵌入 exe。

3. **WinLock 加壳后 PE 崩溃 (0xC0000005)**：PackCore 在 WinLock 加壳后又调用 IconCopier
   修改资源段，UpdateResourceW 重新布局 .rsrc 导致 .lock 节 RawOffset 改变 / 内容破坏。
   解决：WinLock 模式下不调用 IconCopier（原 PE 的 .rsrc 已被保留，图标自然在）。
