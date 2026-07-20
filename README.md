# WinAppLocker

给 Windows PE 文件（EXE）加密码保护的工具集。加密后的程序运行时会弹出密码框，输入正确密码才能启动原程序；不修改原 PE 的功能，仅做访问控制。

支持 x86 和 x64 原生 EXE，部分模式也支持 .NET EXE。不支持 DLL。

## 仓库结构

```
applocker/
├── dotnet/                 # 主项目（WinAppLocker GUI/CLI + stub 程序）
├── packer/                 # WinLock 模块（in-place PE 加壳器，C + 内联汇编）
├── rust/                   # 已废弃的早期实现，停止维护
├── dist/                   # Release 构建产物（build.ps1 -Release 输出到这里）
├── temp/samples/           # 测试用 EXE 样本
└── docs/                   # 项目级文档与变更记录
```

## 两种加壳方案

| 方案 | 来源 | 原 EXE 是否修改 | 运行时是否释放临时文件 | 适用范围 |
|------|------|----------------|----------------------|---------|
| **临时文件模式** | dotnet stub（GUI/Console/Test） | 不修改，作为 payload 附加在 stub 后 | 释放隐藏临时文件，退出后删除 | 任意 EXE（含 .NET、Console、ARM64） |
| **WinLock in-place 模式** | `packer/` 子项目 | 原地修改，新增 `.lock` 节，加密 `.text` 节 | 完全单文件，内存解密 | 仅原生 GUI EXE（x64/x86） |

默认走临时文件模式（兼容性最高）；WinLock 模式需用户显式选择，适合需要单文件分发、不留明文残高的场景。

## 开发环境

系统已安装的开发工具（参考 [AGENTS.md](AGENTS.md)）：

- **Visual Studio 2026** —— dotnet 项目的 IDE
- **.NET 10 SDK** —— 编译 dotnet stub 和 packer 主项目
- **w64devkit** (`C:\Home\Develop\w64devkit`) —— WinLock x64 GCC 工具链
- **msys2** (`C:\Home\Develop\msys64\`) —— GCC 工具链（可选）
- **pwsh**（PowerShell 7）—— 优先使用的 shell，构建/测试脚本基于它
- **venv**（Python VENV）—— 根目录venv，已安装 pywinauto/pyautogui/pefile 等常用包

测试样本exe都在 ** temp\samples **

## 构建流程

完整构建一次产出 `dist/` 目录，包含 packer 主程序和所有 stub 文件：

```powershell
# 在 dotnet/ 目录下执行
.\build.ps1 -Release
```

构建步骤（由 `build.ps1` 自动完成）：
1. 编译 3 个 dotnet stub（GUI / Console / Test）—— 临时文件模式的壳程序
2. 编译 WinLock（`packer/` 子项目，w64devkit + msys2 mingw32）—— in-place 加壳器和运行时 stub
3. 汇集所有 stub 到 `dotnet/packer/stub/`（dotnet stub + WinLock builder/bin + 4 个 `.meta.json` 清单）
4. 编译 dotnet packer 主项目（Costura 嵌入依赖 DLL，自动拷贝 stub/ 到输出目录）
5. 拷贝 Release 产物到 `dist/`（WinAppLocker.exe + exe.config + stub/ 子目录）

常用构建参数：
- `-Release` —— Release 构建，输出到 `dist/`
- `-Clean` —— 清理后重建
- `-SkipWinLock` —— 跳过 WinLock 编译（仅 dotnet 部分，调试时用）

## 测试流程

自动化测试脚本 `dotnet/tests/auto_test.ps1` 用内置密码的 stub 做端到端 round-trip 测试：

```powershell
# 在 dotnet/ 目录下执行
.\tests\auto_test.ps1                  # 临时文件模式（所有样本）
.\tests\auto_test.ps1 -WinLock         # WinLock 模式（仅 GUI 样本，Console/.NET 会 SKIP）
.\tests\auto_test.ps1 -Samples "a.exe,b.exe"  # 指定样本
.\tests\auto_test.ps1 -Info            # 同时用 --info 校验打包结果
```

测试样本在 `temp/samples/`，包含 CLI/GUI、x86/x64、.NET WinForms 等多种类型。

预期结果：
- **临时文件模式**：所有样本通过（7/7）
- **WinLock 模式**：仅原生 GUI 通过，Console 程序和 .NET 程序 SKIP（预期不支持）

## 使用流程

### 图形界面

运行 `dist/WinAppLocker.exe`，选择输入/输出 EXE 路径、输入密码、选择 stub 类型、点击"执行加密操作"。

### 命令行

```powershell
# 基本加密（默认按子系统自动选 tempfile stub）
WinAppLocker.exe --pack -i input.exe -o output.exe -p 你的密码

# 指定 WinLock 模式（in-place 加壳）
WinAppLocker.exe --pack -i input.exe -o output.exe -p 你的密码 --stub-name winlock

# 测试模式（CI 自动化用，stub 跳过弹框，密码硬编码 test123）
WinAppLocker.exe --pack -i input.exe -o output.exe -p test123 --stub-name winlock --test

# 查看已加密 EXE 的信息与完整性校验
WinAppLocker.exe --info output.exe

# 列出所有可用 stub
WinAppLocker.exe --list-stubs
```

详细 CLI 参数见 [dotnet/README.md](dotnet/README.md)。

## 分发

`dist/` 目录是完整分发单元，**必须整个目录一起分发**，不能只拷贝 `WinAppLocker.exe`：

```
dist/
├── WinAppLocker.exe              # packer 主程序（Costura 单文件，依赖 DLL 已嵌入）
├── WinAppLocker.exe.config       # 高 DPI 配置（WinForms 必需）
└── stub/                         # 所有 stub 文件（packer 运行时扫描此目录）
    ├── stub_gui.exe + .meta.json
    ├── stub_console.exe + .meta.json
    ├── stub_test.exe + .meta.json
    ├── winlock_builder.exe + .meta.json
    ├── winlock_stub_x64.bin
    ├── winlock_stub_x86.bin
    └── winlock_stub_x86.exe
```

## 子项目文档

- [dotnet/README.md](dotnet/README.md) —— WinAppLocker 主项目（GUI/CLI、stub 系统、临时文件模式）
- [packer/README.md](packer/README.md) —— WinLock 模块（in-place 加壳器，作为 dotnet 主项目的可选 stub 集成）
- [docs/CHANGES.md](docs/CHANGES.md) —— 项目级变更记录

## 版本管理

- dotnet 项目版本号统一在 `dotnet/Directory.Build.props` 的 `Major/Minor/Patch` 中维护
- 编译期自动注入 Git 提交哈希、构建时间、AssemblyVersion、FileVersion
- WinLock 模块版本独立（当前 2.0.0），由 `packer/common/config.h` 的 `STUB_DATA_VERSION` 控制 stub_data 结构版本
