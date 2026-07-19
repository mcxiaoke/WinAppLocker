# WinLock 模块

WinLock 是 applocker 项目的 **in-place PE 加壳模块**，作为 dotnet 主项目（WinAppLocker）的可选 stub 集成。完整的项目结构与构建流程见根目录 [../README.md](../README.md)。

dotnet 主项目通过 `--stub-name winlock` 选项调用 WinLock 模块（详见 [../dotnet/README.md](../dotnet/README.md)）。

## 定位

WinLock 是**仅门禁壳**（非完整加壳器）：
- 只加密原 PE 的第一个可执行节（通常 `.text`），其它节（`.rdata` / `.data` / `.rsrc` 等）保持原样
- 目的是密码门禁，最大化与第三方程序的兼容性
- 不做反调试、反 dump、代码虚拟化等高级保护

## 与 dotnet 临时文件模式的区别

| 维度 | dotnet 临时文件模式 | WinLock in-place 模式 |
|------|---------------------|----------------------|
| 原 EXE 是否被修改 | 不修改，作为 payload 附加 | 原地修改，新增 `.lock` 节 |
| 运行时是否需要外部文件 | 需要：隐藏临时文件 | 不需要：完全单文件 |
| 磁盘明文残留风险 | 有：异常退出可能残留 | 无：解密在内存中 |
| 加密算法 | AES-256-CBC + HMAC-SHA256 + PBKDF2 | XTEA + SHA-256 |
| 架构支持 | 任意（stub AnyCPU） | 必须按架构选 `winlock_stub_x64` / `winlock_stub_x86` |
| 支持 .NET EXE | 是 | 否 |
| 支持 Console 程序 | 是 | 否（仅 GUI） |

## 输入 PE 限制

WinLock 模式**不支持**以下程序：

| 输入 PE 特征 | 原因 |
|------|------|
| .NET CLR 托管 PE | XTEA 加密 `.text` 节会破坏 CLR metadata |
| Console 子系统程序 | WinLock stub 用 `DialogBoxIndirectParamW` 弹 GUI 密码框 |
| DLL（`IMAGE_FILE_DLL`） | builder 只处理 EXE |
| ARM64 / ARM | `winlock_stub_*.bin` 仅支持 amd64 / i386 |
| Chrome | `chrome_elf.dll` 在 loader 阶段注册 UIA hook → loader lock 死锁 |
| QQ | `FirstLoad.dll` 调用 `WinVerifyTrust` 验证签名 → 加壳后签名失效 |
| 任何带自校验的程序 | 程序在 OEP 中算自身 hash / 校验 checksum → 加壳后不符 |

dotnet 主项目在用户选 WinLock 但原 EXE 是 Console 或 .NET 时会弹警告。

## 构建方式

WinLock 通常由 `dotnet/build.ps1` 自动编译，无需手动构建：

```powershell
# 在 dotnet/ 目录下执行（自动编译 WinLock + dotnet 部分）
.\build.ps1 -Release
```

产物被自动汇集到 `dotnet/packer/stub/`，并加 `winlock_` 前缀：
- `packer/builder/builder.exe` → `winlock_builder.exe`
- `packer/stub/stub_x64.bin` → `winlock_stub_x64.bin`
- `packer/stub/stub_x86.bin` → `winlock_stub_x86.bin`
- `packer/stub/stub_x86.exe` → `winlock_stub_x86.exe`

### 单独构建（开发/调试用）

依赖：
- [w64devkit](https://github.com/skeeto/w64devkit)（GCC 13+ / mingw-w64，x64 工具链）
- [msys2 mingw32](https://www.msys2.org/)（可选，仅编译 x86 stub 需要）

```powershell
cd packer
mingw32-make           # 生成 stub_x64.bin + builder.exe（x64 only）
mingw32-make all-x86   # 同时生成 stub_x86.bin（需要 msys2 mingw32）
mingw32-make -B        # 强制重建
```

Makefile 默认工具链路径（可覆盖）：
- `W64DEVKIT=C:/Home/Develop/w64devkit/bin`
- `MSYS_MINGW32=C:/Home/Develop/msys64/mingw32/bin`

> builder.exe 向后兼容旧名 `stub_x{64,86}.bin` / `stub_x86.exe`（开发者直接 `make` 产出的源文件名），但分发时统一加 `winlock_` 前缀避免混淆。

### builder.exe 直接调用（开发用）

builder.exe 通常由 dotnet 主项目通过 `WinLockPacker.cs` 调用，也可直接手动调用：

```powershell
# 默认输出到 <input_dir>/<input_base>_locked.exe
builder.exe -i <input.exe>                    # 用默认密码 hello123
builder.exe -i <input.exe> -p <password>      # 指定密码
builder.exe -i <input.exe> -t                 # 测试模式（硬编码 test123，跳过弹框）
builder.exe -i <input.exe> -d                 # 启用 PEB 反调试（默认关闭）
builder.exe -i <input.exe> -v                 # 详细日志（PE 解析、节列表、reloc patch 等）
builder.exe -i <input.exe> --stub-dir <dir>   # 覆盖 stub.bin 搜索目录
```

| 选项 | 说明 |
|------|------|
| `-i, --input <file>` | 输入 PE EXE（x86 或 x64），必填 |
| `-o, --output <file>` | 输出路径，默认 `<input_dir>/<base>_locked.exe` |
| `-p, --password <pwd>` | 密码，默认 `hello123` |
| `-t, --test` | 测试模式（固定密码 `test123`，不弹框，用于 CI 自动化） |
| `-d, --antidebug` | 启用 PEB 反调试（默认关闭，方便开发调试） |
| `-v, --debug` | 详细日志输出（默认只输出关键日志 `[+]`/`[-]`/`[!]`） |
| `--stub-dir <dir>` | 覆盖 stub.bin 搜索目录 |
| `-h, --help` | 显示帮助 |

> **重要：加壳后的 exe 必须在原目录运行**，不能移动到其它位置！绝大多数 Windows 程序依赖同目录的 DLL、配置文件、资源等。builder 默认输出到原 exe 同目录，确保加壳后的 exe 能找到这些依赖。

## 工作原理

### 打包时（builder.exe）

1. 读原 PE，验证：x86/x64 EXE，无 CLR
2. 找第一个可执行节（`.text`），记录 RVA / 大小
3. 检测 TLS callbacks（不拒绝，启用 TLS_PROXY 代理模式）
4. 随机生成 XTEA key（128-bit，CryptGenRandom）+ salt（16 字节）
5. 计算 `SHA-256(password_utf8 + salt)` 存 hash
6. XTEA 加密 `.text` 前 N 字节（N = `min(VirtualSize, RawSize) & ~7`）
7. 读 `stub.bin`，搜索 `STUB_DATA_MAGIC` 与 `STUB_TLS_CB_MAGIC` 定位 stub_data 和 stub_tls_callback
8. 填充 stub_data（v4 字段：image_base / reloc_rva / reloc_size / orig_tls_callbacks / security_cookie_rva）
9. 计算 `.lock` 节位置（保留 overlay），追加 TLS callbacks 数组（若 TLS_PROXY）
10. 剥离 Authenticode 签名，清零 Bound Imports
11. 新增 `.lock` 节，写入 stub.bin + callbacks 数组
12. 修改 `AddressOfEntryPoint` 指向 `.lock`
13. 更新 `SizeOfImage` / `NumberOfSections`
14. ASLR 处理：TLS_PROXY 模式禁用 ASLR；非 TLS_PROXY + ASLR 启用时保留，stub 重应用 reloc

### 运行时（stub）

1. **PEB walk** 找 `kernel32.dll` 基址（x64: `__readgsqword(0x60)`，x86: `__readfsdword(0x30)`）
2. **解析导出表** 获取 `GetProcAddress` / `LoadLibraryA` / `VirtualProtect` / `ExitProcess`
3. **密码校验**：
   - 测试模式（`-t`）：跳过弹框，直接用硬编码 `test123` 走 `verify_password`
   - 正常模式：`LoadLibraryA("user32.dll")` + 在栈上构建 `DLGTEMPLATE` + `DialogBoxIndirectParamW`
   - 失败可重试，超过 `max_retries` 次 `ExitProcess(2)`
4. **解密 `.text` 节**：`VirtualProtect` 改 RW → `xtea_decrypt_buf` → 恢复原保护
5. **（x64 + ASLR）重新应用 relocations**：`delta = actual_base - preferred_base`，patch `.text` 范围内的 reloc 条目
6. **（v4）初始化 SecurityCookie**：用 `KUSER_SHARED_DATA.InterruptTime` 作熵源生成随机 cookie
7. **跳原 OEP**：`PEB.ImageBaseAddress + oep_rva`

### TLS_PROXY 模式（原 PE 有 TLS callbacks 时）

builder 检测到原 PE 有 TLS callbacks，启用 `STUB_FLAG_TLS_PROXY`：
- 在 `.lock` 节末尾追加新 callbacks 数组 `[stub_tls_callback_VA, NULL]`
- 修改原 TLS directory 的 `AddressOfCallBacks` 指向新数组
- `stub_tls_callback` 在 `DLL_PROCESS_ATTACH` 时弹密码框 + 解密 `.text` + 调用原 TLS callbacks
- `stub_entry` 在 TLS_PROXY 模式下只跳 OEP（解密已由 TLS callback 完成）

### x86 stub 重定位预 patch

x86 stub 用绝对地址引用静态数据（非 PIC），builder 必须在写入 `.lock` 节前预 patch stub.bin 的所有绝对地址到目标加载位置：

1. `extract_stub_reloc_info()` 从 `stub_x86.exe` 读取 `.reloc` 节
2. `patch_stub_relocations()` 遍历 reloc 表，对每个 `.lock` 范围内的条目加 delta：
   `delta = (target_image_base + target_lock_rva) - (stub_image_base + stub_lock_rva)`
3. x86 PE 强制禁用 ASLR（`DYNAMIC_BASE` 清零），保证 stub 绝对地址始终有效

## 特性

- **双架构**：x64（PE32+）与 x86（PE32）PE 都支持
- **ASLR 兼容**：x64 stub 是 PIC（RIP-relative），保留原 PE 的 `DYNAMIC_BASE`；x86 stub 用绝对地址，builder 预 patch 重定位并禁用 ASLR
- **TLS callback 代理**：原 PE 有 TLS callbacks 时启用 `STUB_FLAG_TLS_PROXY`，在原 callbacks 执行前解密 `.text`
- **CFG 自动处理**：清除 `IMAGE_DLLCHARACTERISTICS_GUARD_CF`（原 PE 的 CFG 保护在 `.text` 加密后已无意义）
- **SHA-256 密码校验**：存 `SHA-256(password_utf8 + salt)` 而非明文，防 dump 破解
- **per-file 随机密钥**：XTEA key + salt 每个文件独立生成（CryptGenRandom）
- **剥离 Authenticode 签名**：加壳后签名失效，builder 自动剥离
- **保留 overlay**：原 PE 末尾的 overlay 数据原样保留到输出
- **PEB 反调试**（`-d`）：检查 `PEB.BeingDebugged` / `NtGlobalFlag & 0x70` / `KdDebuggerEnabled`，默认关闭

> ⚠️ **若系统启用了内核调试**（`bcdedit /set debug on`），`KdDebuggerEnabled` 恒为 1，加 `-d` 的加壳样本会全部启动失败。开发机请保持内核调试关闭。

## 加密细节

- 算法：XTEA（128-bit key，32 轮）
- 密钥：per-file 随机生成（CryptGenRandom）
- 范围：第一个可执行节的 RawData，实际加密字节数 = `min(VirtualSize, RawSize) & ~7`
  - **重要**：只加密内存中实际加载的部分，避免 stub 解密越界写坏下一节
- 尾部不足 8 字节部分用密钥流异或

### 密码校验

- 密码以 SHA-256 hash 形式存储：`SHA-256(utf8(password) + salt)`，salt 是 16 字节随机数
- stub 用自实现的 SHA-256（不依赖 Windows BCrypt），与 `tests/stub_sha256_test.c`（host 模式）共用 `stub/sha256.h`
- 校验用常量时间比较（`bytes_eq_const`）防 timing attack
- 默认最大重试 3 次，超过后 `ExitProcess(2)`

## 项目结构

```
packer/
├── Makefile               # 构建脚本（make / make all-x86）
├── README.md              # 本文档
├── common/
│   └── config.h           # 共享配置（builder + stub）：stub_data 结构、magic、flags
├── builder/
│   └── builder.c          # 加壳器：解析 PE、加密 .text、追加 .lock 节、预 patch stub reloc
├── stub/
│   ├── stub.c            # stub 主体（PEB walk / 弹框 / 解密 / 跳 OEP / TLS proxy / ASLR reloc）
│   ├── sha256.h          # 共享 SHA-256 实现（WINLOCK_PIC 宏切换 section）
│   └── stub.ld           # 链接脚本：保留 .lock + .reloc 节，丢弃其它
├── tests/
│   └── stub_sha256_test.c # SHA-256 单元测试（host 模式）
└── tools/                 # 调试与测试工具
    ├── e2e_test.py        # 综合端到端测试（pywinauto）
    ├── gui_test.py        # GUI 自动化测试
    ├── input_password.ps1 # 密码框自动化（PowerShell）
    ├── dump_stub_data.ps1 # stub_data dump
    ├── verify_pwd_hash.ps1
    ├── pe_info.py / pe_dump.py / pe_diag.py  # PE 诊断
    └── flip_aslr.py       # ASLR 标志翻转
```

### stub 节布局（stub.ld）

```
.lock 节（VMA = 0x11000，RVA = 0x1000）
  .lock.entry   stub_entry          ← builder 修改 EP 指向这里
  .lock.text    辅助函数
  .lock.tlscbm  stub_tls_callback 定位魔数（STUB_TLS_CB_MAGIC）
  .lock.tlscb   stub_tls_callback
  .lock.rdata   字符串常量
  .lock.data    stub_data + fn 表
  .lock.bss     BSS

.reloc 节                          ← builder 读取用于 x86 预 patch
  PE base relocation table
```

stub 的 PIC 约束（x64）：字符串字面量必须放进 `.lock.rdata`，否则 `lea rip+0x0` 会指向代码段随机字节：

```c
__attribute__((section(".lock.rdata"), used, aligned(2)))
static const wchar_t STR_TEST_PWD[] = L"test123";
```

x86 stub 用绝对地址（非 PIC），靠 builder 预 patch `.reloc` 条目到目标 ImageBase，因此 x86 加壳后强制禁用 ASLR。

`objcopy -O binary -j .lock stub_xXX.exe stub_xXX.bin` 导出 `.lock` 节为 raw bytes，builder 同时读 `stub_xXX.exe` 的 `.reloc` 节用于 x86 预 patch。

### stub_data 结构（v4）

`builder` 在 `stub.bin` 中搜索 `STUB_DATA_MAGIC`（`"WINLOCK!"`）定位 `stub_data`，填充以下字段后写入新 `.lock` 节（参见 `common/config.h`）：

| 字段 | 说明 |
|------|------|
| `magic` | `"WINLOCK!"` 魔数，builder 据此定位 stub_data |
| `version` | 4（结构版本号） |
| `flags` | bit0:hash / bit1:test / bit2:tls_proxy / bit3:aslr / bit4:antidebug |
| `max_retries` | 密码错误最大重试次数（默认 3） |
| `oep_rva` | 原 AddressOfEntryPoint |
| `text_rva` / `text_size` | 加密的节 RVA 与字节数 |
| `xtea_key[4]` | XTEA 密钥（per-file 随机） |
| `salt[16]` / `pwd_hash[32]` | SHA-256 salt + hash |
| `image_base` | 原 PE preferred ImageBase |
| `reloc_rva` / `reloc_size` | `.reloc` 节位置（0 = 无重定位表） |
| `orig_tls_callbacks` | 原 TLS callbacks 数组 VA（0 = 无） |
| `security_cookie_rva` | LOAD_CONFIG.SecurityCookie 的 RVA（v4 新增，0 = 无） |
| `checksum` | XOR 所有 64-bit 字段（防篡改） |

## 测试

### 通过 dotnet 主项目测试

```powershell
# 在 dotnet/ 目录下执行
.\tests\auto_test.ps1 -WinLock         # WinLock 模式端到端测试
.\tests\auto_test.ps1 -WinLock -Samples "helloguix64.exe,helloguix86.exe"
```

预期结果：原生 GUI 样本通过，Console / .NET 样本 SKIP（预期不支持）。

### WinLock 模块独立测试

测试依赖：`../venv`（已装 pywinauto, pyautogui）。

```powershell
cd packer
// 使用根目录的venv
..\venv\Scripts\python.exe tools\e2e_test.py
```

测试矩阵（8 项）：`stub_sha256_unit` / `hellocli_test_mode` / `hellogui_correct_pwd` / `hellogui_wrong_pwd` / `dontsleep_real` / `notepad4_real` / `bandizip_real` / `tls_rejected`。

### 单独运行 SHA-256 单元测试

```powershell
# 编译（host 模式，不带 WINLOCK_PIC）
gcc tests/stub_sha256_test.c -O2 -o tests/stub_sha256_test.exe

# 跑标准向量
tests/stub_sha256_test.exe

# 端到端验证 hash（builder 写入的 hash 是否匹配）
tests/stub_sha256_test.exe <password> <salt_hex_32> <expected_hash_hex_64>
```

### 调试工具

- `tools/dump_stub_data.ps1` —— 在加壳后的 PE 中查找并 dump `stub_data` 结构
- `tools/verify_pwd_hash.ps1` —— 验证 `pwd_hash = SHA-256(utf8(pwd) + salt)`
- `tools/check_dontsleep.py` —— 启动加壳程序、自动输入密码、列出所有窗口
- `tools/inspect_dlg.py` —— 用 `print_control_identifiers()` 枚举密码框控件树
- `tools/pe_info.py` —— dump PE 头信息（节表、DataDirectory、入口点等）
- `tools/pe_dump.py` —— dump PE 节原始字节
- `tools/flip_aslr.py` —— 翻转 PE 的 `DYNAMIC_BASE` 标志（调试用）

## 已验证样本

| 程序 | 架构 | 类型 | 特性 | 结果 |
|------|------|------|------|------|
| hellocli | x64 | 自编 CLI | 无 ASLR/CFG/TLS | test mode ✅ |
| hellogui | x64 | 自编 GUI | 无 ASLR/CFG/TLS | 正/错密码 ✅ |
| DontSleep 9.96 | x64 | 第三方 GUI | Authenticode 签名 + overlay | ✅ |
| Notepad4 | x64 | 第三方 GUI | ASLR + CFG=NO | ✅ |
| Bandizip x64 | x64 | 第三方 GUI | ASLR + CFG=YES + TLS dir | ✅（CFG 禁用后） |
| hellomingw / helloucrt / sha256sum | x64 | 自编 | TLS callbacks | ✅（TLS_PROXY 代理） |
| helloguix86 (VS2026) | x86 | 自编 GUI | 无 TLS | ✅ |
| hellox86 (mingw32) | x86 | 自编 GUI | TLS callbacks | ✅（TLS_PROXY + stub reloc 预 patch） |

## 相关文档

- [../README.md](../README.md) —— applocker 项目总览
- [../dotnet/README.md](../dotnet/README.md) —— WinAppLocker 主项目（dotnet 子项目）
- [docs/ANALYSIS_REPORT.md](docs/ANALYSIS_REPORT.md) —— WinLock 技术分析报告
