# WinAppLocker (.NET)

一个把 EXE 加密码保护的工具：用密码（PBKDF2 派生密钥）对原程序进行 AES-256-CBC + HMAC-SHA256
加密，打包进一个带密码输入框的"壳"程序（stub）。运行时输入正确密码，壳程序在内存解密并启动
原程序（以隐藏临时文件方式运行，退出后自动删除）。

**1.0.0** 新增 **WinLock 模式**（in-place 加壳）：原 EXE 被原地修改，stub 嵌入 `.lock` 节，
运行时在内存中解密 `.text` 节，**不释放任何临时文件**，单文件运行。详见下文"WinLock 模式"。

当前版本：**1.0.0**

---

## 功能特性

- **密码保护**：对 EXE 进行强加密，无正确密码无法运行。
- **算法**：
  - 临时文件模式：PBKDF2-HMAC-SHA256（默认 20 万次迭代）+ AES-256-CBC + HMAC-SHA256
  - WinLock 模式：SHA-256(password+salt) 校验 + XTEA 加密 `.text` 节
- **自动适配**：根据原 EXE 子系统（GUI / 控制台）自动选择对应 stub，也可手动指定。
- **图标继承**：打包后保留原程序的主图标和版本信息（仅临时文件模式）。
- **跨类型支持**：原生 EXE 与 .NET EXE 均支持（临时文件模式）；WinLock 模式仅原生 EXE。
- **两种加壳方案**：
  - **临时文件模式**（`applocker-gui` / `applocker-console` / `applocker-test`）：
    原 EXE 作为 payload 附加在 stub 后，运行时释放隐藏临时文件并启动，退出后删除。
  - **WinLock in-place 模式**（`winlock`）：
    原 EXE 被原地修改，新增 `.lock` 节嵌入 stub，`.text` 节被 XTEA 加密；
    运行时 stub 在内存中解密 `.text`，不释放任何文件，单文件独立运行。
- **自检命令**：`--info` 可解析已加密 EXE 的头部/尾部/扩展元数据并校验完整性。
- **stub 清单**：`--list-stubs` 列出 `stub/` 目录下所有可用 stub 及其属性。

---

## 使用方法

### 1. 构建

```powershell
# Debug 构建（产物在 packer/bin/Debug，含 stub/ 子目录）
.\build.ps1

# Release 构建，输出 dist/WinAppLocker.exe + dist/stub/
.\build.ps1 -Release

# 清理后重建
.\build.ps1 -Release -Clean

# 跳过 WinLock 编译（仅 dotnet 部分，调试用）
.\build.ps1 -SkipWinLock
```

构建顺序：
1. 编译三个 dotnet stub（GUI / 控制台 / 测试）→ `stub/bin/<Config>/stub_*.exe`
2. 编译 WinLock（`packer/` 子目录的 C + 内联汇编项目，用 w64devkit + msys2 mingw32）
   → `packer/builder/builder.exe` + `packer/stub/stub_x{64,86}.bin`
3. 汇集所有 stub 到 `packer/stub/`（dotnet stub exe + WinLock builder/bin + 4 个 `.meta.json`）
4. 编译 packer（Costura 嵌入依赖 DLL，csproj 自动把 `packer/stub/` 拷到输出目录）

> **依赖**：WinLock 编译需要 `w64devkit` 和 `msys2 mingw32` 工具链，默认路径
> `C:\Home\Develop\w64devkit` 和 `C:\Home\Develop\msys64`。若未安装，加 `-SkipWinLock` 跳过。

### 2. 发布格式

Release 构建产物在 `dist/` 目录：

```
dist/
├── WinAppLocker.exe              # packer 主程序（Costura 单文件，依赖 DLL 已嵌入）
├── WinAppLocker.exe.config       # 高 DPI 配置（WinForms 必需外部 config）
└── stub/                         # 所有 stub 文件（packer 运行时扫描此目录）
    ├── stub_gui.exe              # AppLocker GUI stub（临时文件模式）
    ├── stub_gui.exe.meta.json
    ├── stub_console.exe          # AppLocker Console stub（临时文件模式）
    ├── stub_console.exe.meta.json
    ├── stub_test.exe             # AppLocker Test stub（内置密码 test1234，测试用）
    ├── stub_test.exe.meta.json
    ├── winlock_builder.exe       # WinLock 加壳器（打包时用，x64 单文件）
    ├── winlock_builder.exe.meta.json
    ├── stub_x64.bin              # WinLock x64 运行时 stub（被 builder 嵌入目标 PE）
    ├── stub_x86.bin              # WinLock x86 运行时 stub
    └── stub_x86.exe              # x86 stub 完整 PE（builder 读 .reloc 用）
```

> **注意**：分发时必须把整个 `dist/` 目录一起分发，不能只拷 `WinAppLocker.exe`。
> packer 启动时会扫描 `stub/` 目录，找不到 stub 会无法工作。

### 3. 图形界面（GUI）

直接运行 `WinAppLocker.exe`，在窗口中：

1. 选择**输入 EXE**（原程序）和**输出 EXE** 路径。
2. 输入并确认**密码**（至少 4 个字符）。
3. **选择 Stub**：下拉框列出所有可用 stub（自动 / applocker-gui / applocker-console /
   applocker-test / winlock），默认"自动"按子系统选临时文件模式。
4. 设置迭代次数（默认 200000，仅临时文件模式生效）。
5. 点击"执行加密操作"。

> 若选 WinLock 但原 EXE 是 Console 或 .NET 程序，会弹出兼容性警告。

### 4. 命令行（CLI）

```powershell
# 加密：把 input.exe 加密为 output.exe（默认按子系统自动选 tempfile stub）
WinAppLocker.exe --pack -i input.exe -o output.exe -p 你的密码

# 指定 stub 偏好（旧的子系统偏好，仅 tempfile 模式）
WinAppLocker.exe --pack -i input.exe -o output.exe -p 你的密码 --stub Auto --iterations 300000

# 指定 stub manifest 名称（优先级高于 --stub，支持 WinLock）
WinAppLocker.exe --pack -i input.exe -o output.exe -p 你的密码 --stub-name winlock
WinAppLocker.exe --pack -i input.exe -o output.exe -p 你的密码 --stub-name applocker-gui

# 列出所有可用 stub
WinAppLocker.exe --list-stubs

# 查看已加密 EXE 的信息与完整性校验
WinAppLocker.exe --info output.exe

# 查看版本
WinAppLocker.exe --version
```

#### CLI 参数说明

| 参数 | 说明 |
|------|------|
| `--pack` | 加密模式 |
| `-i, --input <path>` | 输入 EXE 路径 |
| `-o, --output <path>` | 输出 EXE 路径 |
| `-p, --password <pass>` | 密码（至少 4 字符） |
| `--stub <Auto\|Gui\|Console\|Test>` | 旧 stub 偏好（按子系统选 tempfile 模式） |
| `--stub-name <name>` | 指定 stub manifest 名称（如 `winlock` / `applocker-gui`），优先级高于 `--stub` |
| `--iterations <N>` | PBKDF2 迭代次数（默认 200000，仅 tempfile 模式） |
| `--list-stubs` | 列出 `stub/` 目录所有可用 stub |
| `--info <packed.exe>` | 检查已加密 EXE 的信息 |
| `--version` | 显示版本 |

---

## WinLock 模式

### 工作原理

WinLock 是一种 **in-place PE 加壳器**（C + 内联汇编，PIC，无 CRT，PEB walk）：

1. **打包时**：builder.exe 读原 PE，找 `.text` 节，用 XTEA 加密前 N 字节；
   新增 `.lock` 节写入 stub.bin；修改 `AddressOfEntryPoint`（或 TLS callbacks）指向 stub；
   剥离 Authenticode 签名，清零 Bound Imports，保留 ASLR（stub 重应用 reloc）。
2. **运行时**：Windows loader 加载加壳后的 PE → 进入 stub_entry → 弹密码框
   （`DialogBoxIndirectParamW`）→ SHA-256(password+salt) 校验 → 解密 `.text` 节
   → 重应用 relocations → 跳回原 EP（或调用原 TLS callbacks）→ 原程序正常运行。

### 与临时文件模式对比

| 维度 | 临时文件模式 | WinLock 模式 |
|------|------------|-------------|
| **原 EXE 是否被修改** | 不修改，作为 payload 附加 | 原地修改，新增 `.lock` 节 |
| **运行时是否需要外部文件** | 需要：隐藏临时文件 | 不需要：完全单文件 |
| **磁盘明文残留风险** | 有：异常退出可能残留 | 无：解密在内存中 |
| **兼容性** | 极高（等同于原 EXE 直接运行） | 中（受 loader hook / 自校验限制） |
| **加密算法** | AES-256-CBC + HMAC-SHA256 + PBKDF2 | XTEA + SHA-256 |
| **架构支持** | 任意（stub AnyCPU） | 必须按架构选 stub_x64 / stub_x86 |
| **支持 .NET EXE** | 是 | 否 |
| **支持 Console 程序** | 是 | 否（仅 GUI） |

### WinLock 限制

WinLock 模式**不适用**于以下程序：
- ❌ .NET CLR 托管 PE
- ❌ Console 子系统程序（stub 用 `DialogBoxIndirectParamW` 弹 GUI 密码框）
- ❌ DLL（仅 EXE）
- ❌ Chrome：`chrome_elf.dll` 在 loader 阶段注册 UIA hook → loader lock 死锁
- ❌ QQ：`FirstLoad.dll` 调用 `WinVerifyTrust` 验证签名 → 加壳后签名失效
- ❌ 任何带自校验（hash / checksum / 签名）的程序

> packer 在用户选 WinLock 但原 EXE 是 Console 或 .NET 时会弹警告。

---

## 开发测试方法

- **构建**：`.\build.ps1 -Release` 生成 `dist/WinAppLocker.exe` + `dist/stub/`。
- **自动化测试**：`.\test.ps1` 使用内置密码的 `stub_test` 做端到端 round-trip 测试，
  默认对 `..\temp\samples` 下的 CLI/GUI 样本加解密并验证运行；可加 `-Info` 同时校验
  `--info` 输出，或 `-Samples "a.exe,b.exe"` 指定样本。
- **WinLock 手动测试**：
  ```powershell
  WinAppLocker.exe --pack -i ..\temp\samples\hellogui.exe -o test.exe -p test1234 --stub-name winlock
  ./test.exe   # 弹密码框，输入 test1234 后 hellogui 正常启动
  ```
- **手动验证**：`WinAppLocker.exe --info <加密文件>` 检查头部/尾部 CRC 与扩展元数据是否一致；
  `WinAppLocker.exe --list-stubs` 查看 stub 清单。
- **版本号**：统一在 `Directory.Build.props` 的 `Major/Minor/Patch` 中维护（当前 1.0.0），
  编译期自动注入 Git 提交、构建时间等元数据。

---

## 项目结构

```
dotnet/
├── build.ps1                       # 一键构建脚本（dotnet + WinLock + stub 汇集）
├── test.ps1                        # 自动化测试脚本
├── Directory.Build.props           # 统一版本号管理
├── README.md                       # 本文档
├── WinAppLocker.slnx               # 解决方案
├── shared/                         # 共享库（ByteSearch / Crc32 / PayloadFormat）
├── stub/                           # dotnet GUI stub 项目（生成 stub_gui.exe）
├── stub.console/                   # dotnet Console stub 项目（生成 stub_console.exe）
├── stub.test/                      # dotnet Test stub 项目（生成 stub_test.exe）
├── packer/                         # packer 主项目（生成 WinAppLocker.exe）
│   ├── WinAppLocker.Packer.csproj  # csproj（含 stub/ 目录拷贝规则）
│   ├── Program.cs                  # CLI 入口（--pack / --info / --list-stubs / --version）
│   ├── MainForm.cs                 # GUI 主界面（动态加载 stub 列表）
│   ├── PackCore.cs                 # 打包主流程（tempfile / WinLock 分支）
│   ├── StubLoader.cs               # stub 字节加载（stub/ 目录 + 嵌入资源兜底）
│   ├── StubManifest.cs             # stub 元数据模型（.meta.json 反序列化）
│   ├── StubRegistry.cs             # stub 注册表（扫描 stub/ + 按偏好选）
│   ├── WinLockPacker.cs            # WinLock 加壳分支（调用 winlock_builder.exe）
│   ├── PeReader.cs                 # PE 解析（子系统 / 机器类型 / .NET 检测）
│   ├── IconCopier.cs               # 图标复制（仅 tempfile 模式）
│   ├── CryptoUtil.cs               # KDF + AES-CBC+HMAC
│   ├── PayloadBuilder.cs           # payload 二进制组装
│   └── stub/                       # 构建时汇集的所有 stub（拷到输出目录）
│       ├── stub_gui.exe + .meta.json
│       ├── stub_console.exe + .meta.json
│       ├── stub_test.exe + .meta.json
│       ├── winlock_builder.exe + .meta.json
│       ├── stub_x64.bin
│       ├── stub_x86.bin
│       └── stub_x86.exe
└── tests/                          # 临时测试脚本
```

> WinLock 源码在项目根目录的 `packer/` 子目录（C + 内联汇编），由 `build.ps1` 自动编译。
