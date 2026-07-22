# WinLock 模块

WinLock 是 applocker 项目的 **原生 PE 加壳模块**（C + 内联汇编），提供两种加壳方案：
- **in-place**：原地修改 PE，新增 `.lock` 节，加密 `.text` 节，运行时内存解密
- **reflective**：原 PE 作为 payload 附加在 stub 后，运行时内存反射加载

完整项目总览见根目录 [../README.md](../README.md)，本文档只讲 packer/ 的开发与测试。

## 代码结构（简述）

```
packer/
├── common/        # 共享头文件（config.h / pe_meta.h / winlock_compat.h / sha256.h / xtea.h / peb_walk.h）
├── inplace/       # in-place 加壳器：builder.c（加壳）+ stub.c/asm（运行时解密）
├── reflective/    # reflective 加壳器：builder_reflective.c（加壳）+ loader.c/asm（内存反射加载）
├── cmake/         # 构建辅助脚本（patch_stub_identity.py / inspect_stub.py / check_stub_freshness.py）
├── tests/         # e2e 测试脚本（auto_e2e_test.ps1）+ PE 诊断工具
├── docs/          # 技术分析与设计文档（实现细节在这里，不写在 README）
├── build.ps1      # 构建入口（MSVC x64 + x86 + MinGW inplace stub）
└── CMakeLists.txt # CMake 顶层
```

> 实现细节（stub_data 字段、TLS proxy 机制、节布局、PIC 约束等）见 [docs/](docs/)，
> 代码结构随时在变，README 不赘述。

## 开发流程

### 构建

```powershell
cd packer
.\build.ps1               # 默认 Release，x64 + x86 + MinGW inplace stub
.\build.ps1 -Clean        # 清理后重建
.\build.ps1 -SkipX86      # 只构建 x64
.\build.ps1 -SkipMinGW    # 跳过 MinGW inplace stub（用 MSVC 版本）
```

`build.ps1` 自动完成：
1. MSVC vcvarsall → CMake configure + build（x64 + x86）
2. 编译 builder_inplace / builder_reflective + 4 个 stub（inplace/reflective × x64/x86）
3. MinGW 构建 inplace stub，覆盖 MSVC 产物（TLS callback 保留更完整）
4. `patch_stub_identity.py` 注入 stub 身份字段
5. 汇集产物到 `packer/dist/`，生成 `stub_manifest.json`

产物清单（`packer/dist/`）：
- `builder_inplace.exe` / `builder_reflective.exe` —— 加壳器
- `stub_inplace_x64.bin` / `stub_inplace_x86.bin` —— inplace stub 二进制
- `stub_inplace_x64.exe` / `stub_inplace_x86.exe` —— inplace stub exe（builder 读 .reloc 用）
- `stub_reflective_x64.exe` / `stub_reflective_x86.exe` —— reflective stub exe

> **重要：每次代码改动后必须运行 auto e2e test 确保不破坏现有功能。**

### 完整构建（含 dotnet 主项目）

```powershell
# 在 dotnet/ 目录下执行，自动调用 packer/build.ps1
cd dotnet
.\build.ps1 -Release
```

详见根目录 [../README.md](../README.md)。

## 测试流程

### WinLock e2e 测试（packer/ 改动后必跑）

```powershell
cd packer
.\tests\auto_e2e_test.ps1                              # 默认：inplace + reflective，password 模式
.\tests\auto_e2e_test.ps1 -IncludeTestMode             # 同时测 -t test 模式
.\tests\auto_e2e_test.ps1 -SkipReflective              # 只测 inplace
.\tests\auto_e2e_test.ps1 -SkipInplace                 # 只测 reflective
.\tests\auto_e2e_test.ps1 -ExternalSamples ..\temp\bigapps  # 测外部大型应用
```

测试矩阵：每个样本 × {inplace, reflective} × {password 模式}（默认跳过 test 模式加速）。
内置样本 9 个：hellocli / hellomingw / helloucrt / helloguix86/x64 / hellomfcx86/x64 /
Notepad4 / DontSleep。

测试流程（每个样本）：
1. 加壳（builder_inplace / builder_reflective）
2. 启动加壳后的 exe
3. 自动输入密码（`WM_SETTEXT` + `BM_CLICK`）
4. 验证：CLI 程序检查 stdout；GUI 程序检查窗口是否出现
5. 杀进程，清理

日志：`packer/temp/auto_e2e_result/auto_e2e_test.log`。
预期结果：18/18 PASS。

### 外部大型应用测试（bigapps）

```powershell
.\tests\auto_e2e_test.ps1 -ExternalSamples ..\temp\bigapps
```

外部样本在原目录测试（保留 DLL/资源依赖），自动扫描子目录中的主 exe，
过滤辅助 exe（cache/crash/report/updater/uninstall/helper 等）和测试产物
（`_locked`/`_refl`/`_inplace` 后缀）。

### stub 新鲜度校验

e2e 测试开始前自动校验 `dist/stub_*.bin` 的 `stub_source_crc` 是否与当前源码一致
（warn-only）。手动检查：

```powershell
python cmake\check_stub_freshness.py --stub-dir dist --winlock-root .
```

## builder 直接调用（开发调试用）

```powershell
cd dist

# in-place 模式
.\builder_inplace.exe -i <input.exe> -o <output.exe> -p <password>
.\builder_inplace.exe -i <input.exe> -o <output.exe> -t    # test 模式（硬编码 test123，跳过弹框）
.\builder_inplace.exe -i <input.exe> -v                     # 详细日志

# reflective 模式（位置参数）
.\builder_reflective.exe <input.exe> <output.exe> -p <password>
.\builder_reflective.exe <input.exe> <output.exe> -t        # test 模式
```

> **加壳后的 exe 必须在原目录运行**，绝大多数程序依赖同目录的 DLL/资源。

## 调试技巧

### 崩溃排查

1. **看 loader 日志**：reflective 模式生成 `*_locked_loader.log`，记录 PE 加载每一步
2. **用 `-t` test 模式**：跳过密码框，便于复现
3. **用 WinDbg 附加**：`windbg -p <PID>` 或 `windbg -g <locked.exe>`
4. **用 IDA Pro MCP 逆向**：分析第三方程序崩溃根因

### PE 诊断工具

```powershell
python tests\pe_info.py <file.exe>                # dump PE 头信息
python cmake\inspect_stub.py --summary dist       # 检查 stub 身份字段
```

### 常见崩溃代码

| 退出码 | 含义 | 常见原因 |
|--------|------|---------|
| 0xC0000005 | ACCESS_VIOLATION | NULL 指针 / 越界访问 |
| 0xC0000409 | STACK_BUFFER_OVERRUN | `__fastfail(7)`，常见于 TLS/CRT 初始化失败 |
| 0xC0000142 | DLL_INIT_FAILED | DLL 依赖缺失或初始化失败 |
| 0xE06D7363 | C++ Exception | C++ 异常（通常是缺少 DLL 或资源） |

### 调试注意事项

- **内核调试必须关闭**：`bcdedit /set debug off`，否则带 PEB 反调试（`-d`）的样本全部失败
- **UAC 提权弹窗**：部分程序需要 UAC，e2e 可能因 UAC 超时
- **窗口标题匹配**：e2e 用通配符（`-like`）匹配外部样本名，避免 `notepad++` 的 `+` 号触发正则错误

## 相关文档

- [../README.md](../README.md) —— applocker 项目总览
- [../dotnet/README.md](../dotnet/README.md) —— WinAppLocker 主项目
- [docs/](docs/) —— 技术分析与设计文档（实现细节）
- [../docs/CHANGES.md](../docs/CHANGES.md) —— 项目级变更记录
