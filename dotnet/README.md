# WinAppLocker (.NET)

WinAppLocker 主项目，提供 GUI / CLI 两种界面，把 EXE 加密码保护后输出新的 EXE。

完整的项目介绍、构建/测试/使用流程见根目录 [../README.md](../README.md)，本文档仅描述 dotnet 子项目本身。

## 项目组成

| 项目 | 输出 | 角色 |
|------|------|------|
| `shared/` | WinAppLocker.Shared.dll | 共享库（ByteSearch / Crc32 / PayloadFormat） |
| `stub/` | stub_gui.exe | GUI 模式 stub（WinForms 密码框，临时文件模式） |
| `stub.console/` | stub_console.exe | Console 模式 stub（stdin 密码输入，临时文件模式） |
| `stub.test/` | stub_test.exe | 测试 stub（内置密码 test1234，跳过输入 UI） |
| `packer/` | WinAppLocker.exe | packer 主程序（GUI + CLI，含 stub 注册表与加壳流程） |

`packer/stub/` 是构建时汇集的所有 stub 文件目录（dotnet stub + WinLock builder/bin + `.meta.json` 清单），csproj 自动拷贝到输出目录。

## 加壳方案

dotnet 主项目支持两种加壳方案，统一通过 `PackOptions.PreferStubName` 或 `--stub` / `--stub-name` 参数选择：

### 临时文件模式（`applocker-*` stub）

- 原 EXE 作为加密 payload 附加在 stub 后
- 算法：PBKDF2-HMAC-SHA256（默认 20 万次迭代）+ AES-256-CBC + HMAC-SHA256
- 运行时 stub 在内存解密，释放隐藏临时文件并启动，原程序退出后删除
- 兼容性最高：支持任意架构、.NET / 原生 / Console 程序
- 图标继承：打包后保留原程序的主图标和版本信息

### WinLock in-place 模式（`winlock` stub）

- 原 EXE 被原地修改，新增 `.lock` 节嵌入 stub，加密 `.text` 节
- 算法：SHA-256(password+salt) 校验 + XTEA 加密
- 运行时 stub 在内存解密 `.text`，不释放任何文件，单文件独立运行
- 限制：仅原生 GUI EXE（x64/x86），不支持 .NET / Console / DLL
- 详细工作原理与限制见 [../packer/README.md](../packer/README.md)

## CLI 参数

```powershell
WinAppLocker.exe --pack -i <input> -o <output> -p <password> [options]
```

| 参数 | 说明 |
|------|------|
| `--pack` | 加密模式 |
| `-i, --input <path>` | 输入 EXE 路径 |
| `-o, --output <path>` | 输出 EXE 路径 |
| `-p, --password <pass>` | 密码（至少 4 字符） |
| `--stub <Auto\|Gui\|Console\|Test>` | 旧 stub 偏好（按子系统选 tempfile 模式） |
| `--stub-name <name>` | 指定 stub manifest 名称（`winlock` / `applocker-gui` / `applocker-console` / `applocker-test`），优先级高于 `--stub` |
| `--iterations <N>` | PBKDF2 迭代次数（默认 200000，仅 tempfile 模式） |
| `--test` | WinLock 测试模式：builder 用 `-t`，stub 跳过密码弹框，密码硬编码为 `test123` |
| `--pe-info <path>` | 显示 PE 信息（架构、子系统、.NET、ASLR/DEP/CFG 等） |
| `--info <packed.exe>` | 检查已加密 EXE 的信息与完整性校验 |
| `--list-stubs` | 列出 `stub/` 目录所有可用 stub |
| `--version` | 显示版本 |

## Stub 自动选择标准

当用户不显式指定 stub（即 `--stub Auto` 或 GUI 下拉框选"自动"）时，packer 按以下顺序在 `stub/` 目录中挑选：

1. **用户指定优先**：若 `--stub-name` 非空，且该 stub 满足 `IsAvailable`（主文件 + components 全部存在）和 `SupportsMachine`（架构匹配）→ 直接用
2. **按子系统自动匹配**：根据原 EXE 的 `OptionalHeader.Subsystem`：
   - `Windows Cui`（Console 程序）→ `applocker-console`
   - `Windows Gui`（GUI 程序）或其他 → `applocker-gui`
3. **退而求其次**：返回任意 `IsAvailable && SupportsMachine` 的 stub

**WinLock 不会被自动选中**，必须显式指定（`--stub-name winlock` 或 GUI 下拉框选 winlock）。

WinLock 输入 PE 限制：

| 输入 PE 特征 | WinLock 是否可用 | 原因 |
|------|------|------|
| .NET CLR 托管 | ❌ | XTEA 加密 `.text` 节会破坏 CLR metadata |
| Console 子系统 | ❌ | WinLock stub 用 `DialogBoxIndirectParamW` 弹 GUI 密码框 |
| DLL | ❌ | builder 只处理 EXE |
| ARM64 / ARM | ❌ | `winlock_stub_*.bin` 仅支持 amd64 / i386 |
| x64 / x86 原生 GUI EXE | ✅ | 正常加壳 |

## stub 元数据（`.meta.json`）

每个 stub 旁边放一个同名 `.meta.json` 描述其属性，packer 启动时扫描 `stub/` 目录加载所有 manifest：

```json
{
  "name": "winlock",
  "kind": "inplace-builder",
  "subsystem": "gui",
  "description": "WinLock in-place packer (XTEA + SHA-256)",
  "version": "2.0.0",
  "components": {
    "stub_x64": "winlock_stub_x64.bin",
    "stub_x86": "winlock_stub_x86.bin"
  },
  "supported_machines": ["amd64", "i386"]
}
```

- `kind`：`tempfile`（临时文件模式）或 `inplace-builder`（WinLock in-place 模式）
- `subsystem`：`gui` / `console` / `test`
- `components`：仅 inplace-builder 用，列出依赖的 stub 文件
- `supported_machines`：仅 inplace-builder 用，`amd64` / `i386`；tempfile stub 不填则视为 AnyCPU

## 项目结构

```
dotnet/
├── build.ps1                       # 一键构建脚本（dotnet + WinLock + stub 汇集）
├── tests/auto_test.ps1             # 自动化测试脚本（tempfile + WinLock 两种模式）
├── Directory.Build.props           # 统一版本号管理（Git hash + 构建时间自动注入）
├── WinAppLocker.slnx               # 解决方案
├── shared/                         # 共享库
├── stub/                           # GUI stub 项目
├── stub.console/                   # Console stub 项目
├── stub.test/                      # Test stub 项目
└── packer/                         # packer 主项目
    ├── WinAppLocker.Packer.csproj
    ├── Program.cs                  # CLI 入口
    ├── MainForm.cs                 # GUI 主界面
    ├── PackCore.cs                 # 打包主流程（tempfile / WinLock 分支）
    ├── StubLoader.cs               # stub 字节加载（stub/ 目录 + 嵌入资源兜底）
    ├── StubManifest.cs             # stub 元数据模型
    ├── StubRegistry.cs             # stub 注册表（按偏好选）
    ├── WinLockPacker.cs            # WinLock 加壳分支（调用 winlock_builder.exe）
    ├── PeReader.cs                 # PE 解析
    ├── IconCopier.cs               # 图标复制（仅 tempfile 模式）
    ├── CryptoUtil.cs               # KDF + AES-CBC+HMAC
    ├── PayloadBuilder.cs           # payload 二进制组装
    └── stub/                       # 构建时汇集的所有 stub（拷到输出目录）
```

## 版本号

版本号统一在 `Directory.Build.props` 的 `Major/Minor/Patch` 中维护（当前 1.0.0），编译期自动注入：
- AssemblyVersion = `Major.Minor.0.0`
- FileVersion = `Major.Minor.<天数>.<秒数>`
- InformationalVersion = `Major.Minor.Patch-<yyyyMMdd>-<git hash>`

`--version` 命令显示 InformationalVersion。
