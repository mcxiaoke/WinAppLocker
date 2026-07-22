# WinAppLocker

给 Windows PE 文件（EXE）加密码保护的工具集。加密后的程序运行时会弹出密码框，输入正确密码才能启动原程序；不修改原 PE 的功能，仅做访问控制。

支持 x86 和 x64 原生 EXE，部分模式也支持 .NET EXE。不支持 DLL。

## 代码结构

```
applocker/
├── dotnet/                 # WinAppLocker 主项目（GUI/CLI packer + 临时文件模式 stub）
│   ├── shared/             #   共享库（TLV payload、CRC32、字节搜索）
│   ├── stub/               #   GUI stub（WinForms 密码框）
│   ├── stub.console/       #   Console stub（控制台密码输入）
│   ├── stub.test/          #   测试 stub（硬编码密码，CI 用）
│   ├── packer/             #   packer 主程序（GUI/CLI，Costura 单文件）
│   ├── tests/              #   e2e 测试脚本
│   └── build.ps1           #   完整构建入口（含调用 packer/build.ps1）
├── packer/                 # WinLock 模块（in-place + reflective 加壳器，C/ASM）
│   ├── common/             #   共享头文件（config.h / pe_meta.h / winlock_compat.h 等）
│   ├── inplace/            #   in-place 模式：builder + stub（原地修改 PE，加 .lock 节）
│   ├── reflective/         #   reflective 模式：builder + loader stub（内存反射加载）
│   ├── cmake/              #   构建辅助脚本（patch_stub_identity.py / inspect_stub.py 等）
│   ├── tests/              #   e2e 测试脚本（auto_e2e_test.ps1）
│   ├── build.ps1           #   WinLock 独立构建入口
│   └── CMakeLists.txt      #   CMake 顶层（MSVC x64 + x86 + MinGW inplace stub）
├── rust/                   # 已废弃的早期实现，停止维护
├── dist/                   # Release 构建产物
├── temp/samples/           # 测试用 EXE 样本
└── docs/                   # 项目级文档与变更记录（CHANGES.md / DEVENV.md）
```

## 两种加壳方案

| 方案 | 来源 | 原 EXE 是否修改 | 运行时是否释放临时文件 | 适用范围 |
|------|------|----------------|----------------------|---------|
| **临时文件模式** | dotnet stub（GUI/Console/Test） | 不修改，作为 payload 附加在 stub 后 | 释放隐藏临时文件，退出后删除 | 任意 EXE（含 .NET、Console、ARM64） |
| **WinLock in-place 模式** | `packer/inplace/` | 原地修改，新增 `.lock` 节，加密 `.text` 节 | 完全单文件，内存解密 | 仅原生 GUI EXE（x64/x86） |
| **WinLock reflective 模式** | `packer/reflective/` | 不修改原 PE，整体作为 payload 内存反射加载 | 完全单文件，内存加载 | 原生 GUI EXE（x64/x86），不支持 .NET |

默认走临时文件模式（兼容性最高）；WinLock 模式需用户显式选择，适合需要单文件分发、不留明文残留的场景。

## 开发环境

参考 [AGENTS.md](AGENTS.md) 和 [docs/DEVENV.md](docs/DEVENV.md)，关键工具：

- **Visual Studio 2026** —— packer/ 用 MSVC 编译 builder + reflective stub
- **.NET 10 SDK** —— dotnet/ 主项目
- **MinGW (msys2)** —— packer/inplace stub（MinGW 构建产物覆盖 MSVC 版本）
- **pwsh**（PowerShell 7）—— 所有构建/测试脚本基于它，优先使用
- **Python 3** —— patch_stub_identity.py / inspect_stub.py 等构建辅助脚本
- **CMake + Ninja** —— packer/ 的构建系统
- **WinDbg / x64dbg** —— 调试加壳后的 PE（位于 `C:\Home\Develop\WinDbg` 和 `C:\Home\Develop\x64dbg`）
- **IDA Pro MCP** —— 逆向分析（mcp_ida-pro-mcp，分析第三方程序崩溃根因）

## 开发流程

### 完整构建（推荐）

```powershell
# 在 dotnet/ 目录下执行，自动编译 dotnet + WinLock，输出到 dist/
cd dotnet
.\build.ps1 -Release
```

构建步骤（由 `dotnet/build.ps1` 自动完成）：
1. 编译 3 个 dotnet stub（GUI / Console / Test）
2. 调用 `packer/build.ps1` 编译 WinLock（in-place + reflective builder + 所有 stub）
3. 汇集 WinLock 产物到 `dotnet/packer/stub/`（加 `winlock_` 前缀）
4. 编译 dotnet packer 主程序（Costura 嵌入依赖 DLL）
5. 拷贝 Release 产物到根目录 `dist/`

### 仅构建 WinLock 模块（packer/ 调试用）

```powershell
# 在 packer/ 目录下执行，只编译 WinLock 部分
cd packer
.\build.ps1               # 默认 Release，x64 + x86 + MinGW inplace stub
.\build.ps1 -Clean        # 清理后重建
.\build.ps1 -SkipX86      # 只构建 x64
.\build.ps1 -SkipMinGW    # 跳过 MinGW inplace stub（用 MSVC 版本）
```

`packer/build.ps1` 构建步骤：
1. MSVC vcvarsall 设置环境 → CMake configure + build（x64 + x86）
2. 编译 builder_inplace / builder_reflective + 4 个 stub（inplace/reflective × x64/x86）
3. MinGW 构建 inplace stub（x64 + x86），覆盖 MSVC 产物（TLS callback 保留更完整）
4. `patch_stub_identity.py` 注入 stub 身份字段（arch/toolchain/build_time/source_crc/githash）
5. 汇集产物到 `packer/dist/`，生成 `stub_manifest.json`

产物清单（`packer/dist/`）：
- `builder_inplace.exe` / `builder_reflective.exe` —— 加壳器
- `stub_inplace_x64.bin` / `stub_inplace_x86.bin` —— inplace stub 二进制
- `stub_reflective_x64.exe` / `stub_reflective_x86.exe` —— reflective stub exe

### 常用构建参数

| 参数 | 适用脚本 | 说明 |
|------|---------|------|
| `-Release` | dotnet/build.ps1 | Release 构建，输出到 `dist/` |
| `-Clean` | 两者 | 清理后重建 |
| `-SkipWinLock` | dotnet/build.ps1 | 跳过 WinLock 编译（仅 dotnet 部分，调试时用） |
| `-SkipX64` / `-SkipX86` | packer/build.ps1 | 跳过指定架构 |
| `-SkipMinGW` | packer/build.ps1 | 跳过 MinGW inplace stub（用 MSVC 版本） |
| `-Debug` | packer/build.ps1 | Debug 配置（注意：PIC stub 的 /GS- 与 /RTC1 冲突，仅 builder 可编） |

## 测试流程

> **重要：每次代码改动后必须运行 auto e2e test 确保不破坏现有功能。**

### WinLock 模块 e2e 测试（packer/ 改动后必跑）

```powershell
# 在 packer/ 目录下执行
cd packer
.\tests\auto_e2e_test.ps1                          # 默认：inplace + reflective，password 模式
.\tests\auto_e2e_test.ps1 -IncludeTestMode         # 同时测 -t test 模式（测试数翻倍）
.\tests\auto_e2e_test.ps1 -SkipReflective          # 只测 inplace
.\tests\auto_e2e_test.ps1 -SkipInplace             # 只测 reflective
.\tests\auto_e2e_test.ps1 -ExternalSamples ..\temp\bigapps  # 测外部大型应用
```

测试矩阵：每个样本 × {inplace, reflective} × {password 模式}（默认跳过 test 模式加速）。
内置样本（9 个）：hellocli / hellomingw / helloucrt / helloguix86 / helloguix64 /
hellomfcx86 / hellomfcx64 / Notepad4 / DontSleep。

测试流程（每个样本）：
1. 加壳（builder_inplace / builder_reflective）
2. 启动加壳后的 exe
3. 自动输入密码（`WM_SETTEXT` + `BM_CLICK`，通过 `EnumWindows` 找密码框）
4. 验证：CLI 程序检查 stdout；GUI 程序检查窗口是否出现
5. 杀进程，清理

日志：`packer/temp/auto_e2e_result/auto_e2e_test.log`（`Start-Transcript` 捕获所有输出）。

预期结果：18/18 PASS（inplace + reflective × 9 样本）。

### dotnet 主项目 e2e 测试

```powershell
# 在 dotnet/ 目录下执行
cd dotnet
.\tests\auto_test.ps1                  # 临时文件模式（所有样本）
.\tests\auto_test.ps1 -WinLock         # WinLock in-place 模式（仅 GUI 样本）
.\tests\auto_test.ps1 -Samples "a.exe,b.exe"  # 指定样本
.\tests\auto_test.ps1 -Info            # 同时用 --info 校验打包结果
```

预期结果：
- 临时文件模式：所有样本通过（含 .NET、Console）
- WinLock 模式：仅原生 GUI 通过，Console / .NET 程序 SKIP（预期不支持）

### 外部大型应用测试（bigapps）

```powershell
# 测 temp/bigapps 下的第三方应用（CC-Switch / DontSleep / Notepad++ / vlc / XnViewMP 等）
cd packer
.\tests\auto_e2e_test.ps1 -ExternalSamples ..\temp\bigapps
```

外部样本在原目录测试（保留 DLL/资源依赖），自动扫描子目录中的主 exe，过滤辅助 exe
（cache/crash/report/updater/uninstall/helper 等）和测试产物（`_locked`/`_refl`/`_inplace` 后缀）。

### stub 新鲜度校验

e2e 测试开始前自动校验 `dist/stub_*.bin` 的 `stub_source_crc` 是否与当前源码一致
（warn-only，不阻塞测试）。手动检查：

```powershell
python packer\cmake\check_stub_freshness.py --stub-dir packer\dist --winlock-root packer
```

## 调试技巧

### 加壳后程序崩溃排查

1. **看 loader 日志**：reflective 模式生成 `*_locked_loader.log`，记录 PE 加载每一步
2. **用 `-t` test 模式**：跳过密码框，硬编码密码 `test123`，便于复现
3. **用 WinDbg 附加**：
   ```powershell
   # 启动加壳 exe 后附加
   windbg -p <PID>
   # 或启动即附加（断在 entry）
   windbg -g c:\path\to\locked.exe
   ```
4. **用 IDA Pro MCP 逆向**：分析第三方程序崩溃根因（如 TLS/actctx/CRT 初始化问题）

### PE 诊断工具

```powershell
# dump PE 头信息（节表、DataDirectory、入口点）
python packer\tests\pe_info.py <file.exe>

# 检查 stub 二进制身份字段（arch/toolchain/build_time/source_crc/size/githash）
python packer\cmake\inspect_stub.py --summary packer\dist

# 检查 stub PE 的 TLS directory 状态
python temp\check_stub_tls.py <stub.exe>
```

### 常见崩溃代码

| 退出码 | 含义 | 常见原因 |
|--------|------|---------|
| 0xC0000005 | ACCESS_VIOLATION | NULL 指针 / 越界访问（IAT 条目为 NULL 等） |
| 0xC0000409 | STACK_BUFFER_OVERRUN / SECURITY_CHECK | `__fastfail(7)`，常见于 TLS/CRT 初始化失败 |
| 0xC0000142 | DLL_INIT_FAILED | DLL 依赖缺失或初始化失败 |
| 0xE06D7363 | C++ Exception | C++ 异常（通常是缺少 DLL 或资源） |

### 调试注意事项

- **内核调试必须关闭**：`bcdedit /set debug off`，否则 `KdDebuggerEnabled` 恒为 1，
  带 PEB 反调试（`-d`）的加壳样本会全部启动失败
- **UAC 提权弹窗**：部分程序（如 CCleaner）需要 UAC，e2e 测试可能因 UAC 弹窗超时
- **窗口标题匹配**：e2e 用通配符（`-like`）匹配外部样本名，避免正则量词错误
  （如 `notepad++` 的 `+` 号）

## 使用流程

### 图形界面

运行 `dist/WinAppLocker.exe`，选择输入/输出 EXE 路径、输入密码、选择 stub 类型、点击"执行加密操作"。

### 命令行

```powershell
# 基本加密（默认按子系统自动选 tempfile stub）
WinAppLocker.exe --pack -i input.exe -o output.exe -p 你的密码

# 指定 WinLock in-place 模式
WinAppLocker.exe --pack -i input.exe -o output.exe -p 你的密码 --stub-name winlock

# 测试模式（CI 自动化用，stub 跳过弹框，密码硬编码 test123）
WinAppLocker.exe --pack -i input.exe -o output.exe -p test123 --stub-name winlock --test

# 查看已加密 EXE 的信息与完整性校验
WinAppLocker.exe --info output.exe

# 列出所有可用 stub
WinAppLocker.exe --list-stubs
```

### WinLock builder 直接调用（开发用）

```powershell
cd packer\dist

# in-place 模式
.\builder_inplace.exe -i <input.exe> -o <output.exe> -p <password>
.\builder_inplace.exe -i <input.exe> -o <output.exe> -t    # test 模式

# reflective 模式（位置参数）
.\builder_reflective.exe <input.exe> <output.exe> -p <password>
.\builder_reflective.exe <input.exe> <output.exe> -t        # test 模式
```

> **重要：加壳后的 exe 必须在原目录运行**，不能移动到其它位置！绝大多数 Windows
> 程序依赖同目录的 DLL、配置文件、资源等。builder 默认输出到原 exe 同目录。

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
    ├── winlock_builder_inplace.exe + .meta.json
    ├── winlock_builder_reflective.exe + .meta.json
    ├── winlock_stub_inplace_x64.bin
    ├── winlock_stub_inplace_x86.bin
    ├── winlock_stub_reflective_x64.exe
    └── winlock_stub_reflective_x86.exe
```

## 子项目文档

- [dotnet/README.md](dotnet/README.md) —— WinAppLocker 主项目（GUI/CLI、stub 系统、临时文件模式）
- [packer/README.md](packer/README.md) —— WinLock 模块（in-place + reflective 加壳器技术细节）
- [docs/CHANGES.md](docs/CHANGES.md) —— 项目级变更记录（每次改动在顶部追加）
- [docs/DEVENV.md](docs/DEVENV.md) —— 开发工具全表（编译器/调试器路径）

## 版本管理

- dotnet 项目版本号统一在 `dotnet/Directory.Build.props` 的 `Major/Minor/Patch` 中维护
- 编译期自动注入 Git 提交哈希、构建时间、AssemblyVersion、FileVersion
- WinLock 模块版本独立（当前 2.0.0），由 `packer/common/config.h` 的 `STUB_DATA_VERSION` 控制 stub_data 结构版本
- 每个 stub 二进制注入身份字段（`stub_arch` / `stub_toolchain` / `stub_build_time` /
  `stub_githash` / `stub_source_crc` / `stub_bin_ver` / `stub_size`），便于反查产物对应的源码版本
