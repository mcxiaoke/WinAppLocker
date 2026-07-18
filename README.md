# WinLock

PE 文件密码门禁加壳器（x86 + x64 / Windows）。在原 PE 末尾追加一个 stub，
加密第一个可执行节（通常 `.text`），运行时 stub 弹密码框，校验通过后解密并跳原 OEP。

> 仅门禁壳，非完整加壳器：只加密 `.text` 一个节，其它节（`.rdata` / `.data` / `.rsrc` …）保持原样，
> 最大化与第三方程序的兼容性。

## 特性

- **双架构**：x64（PE32+）与 x86（PE32）PE 都支持
- **ASLR 兼容**：
  - x64 stub 是 PIC（RIP-relative），保留原 PE 的 `DYNAMIC_BASE`，stub 解密 `.text` 后重新应用 relocations
  - x86 stub 用绝对地址，builder 预 patch stub 重定位到目标 ImageBase，并禁用 ASLR
- **TLS callback 代理**：原 PE 有 TLS callbacks 时，builder 用 `stub_tls_callback` 代理原 callbacks，
  在原 callbacks 执行前解密 `.text`，避免 TLS 回调访问密文 `.text` 崩溃
- **CFG 自动处理**：清除 `IMAGE_DLLCHARACTERISTICS_GUARD_CF`（原 PE 的 CFG 保护在 `.text` 加密后已无意义）
- **SHA-256 密码校验**：存 `SHA-256(password_utf8 + salt)` 而非明文，防 dump 破解
- **per-file 随机密钥**：XTEA key + salt 每个文件独立生成（CryptGenRandom）
- **剥离 Authenticode 签名**：加壳后签名失效，builder 自动剥离
- **保留 overlay**：原 PE 末尾的 overlay 数据（如某些自定义数据）原样保留到输出

## 构建

依赖：
- [w64devkit](https://github.com/skeeto/w64devkit)（GCC 13+ / mingw-w64，x64 工具链）
- [msys2 mingw32](https://www.msys2.org/)（可选，仅编译 x86 stub 需要）

```powershell
# w64devkit/bin 加入 PATH（PowerShell）
$env:Path = "C:\Home\Develop\w64devkit\bin;" + $env:Path

cd winlock
mingw32-make           # 生成 stub_x64.bin + builder.exe（x64 only）
mingw32-make all-x86   # 同时生成 stub_x86.bin（需要 msys2 mingw32）
```

> Makefile 默认工具链路径：
> `W64DEVKIT=C:/Home/Develop/w64devkit/bin`
> `MSYS_MINGW32=C:/Home/Develop/msys64/mingw32/bin`
> 可通过 `make all-x86 MSYS_MINGW32=/path/to/mingw32/bin` 覆盖。

输出：
- `stub/stub_x64.bin` / `stub/stub_x86.bin` —— stub 二进制（约 5.5 KB）
- `stub/stub_x64.exe` / `stub/stub_x86.exe` —— 完整 PE（builder 读取它的 `.reloc` 节用于 x86 预 patch）
- `builder/builder.exe` —— 加壳器

### 安装 msys2 mingw32（x86 编译用）

```powershell
# 在 msys2 shell 中：
pacman -S mingw-w64-i686-gcc
```

若不安装 msys2 mingw32，仍可用 `make` 构建仅 x64 版本（`make all-x86` 会失败并给出提示）。

## 使用

### 标准参数

```powershell
# 默认输出到 <input_dir>/<input_base>_locked.exe
builder.exe -i <input.exe>                    # 用默认密码 hello123
builder.exe -i <input.exe> -p <password>      # 指定密码
builder.exe -i <input.exe> -o <output.exe>    # 指定输出路径
builder.exe -i <input.exe> -t                 # 测试模式（见下）
```

| 选项 | 说明 |
|------|------|
| `-i, --input <file>`    | 输入 PE EXE（x86 或 x64），必填 |
| `-o, --output <file>`    | 输出路径，默认 `<input_dir>/<base>_locked.exe` |
| `-p, --password <pwd>`  | 密码，默认 `hello123` |
| `-t, --test`            | 测试模式（固定密码 `test123`，不弹框） |
| `-h, --help`            | 显示帮助 |

builder 自动检测输入 PE 的架构（`IMAGE_FILE_MACHINE_AMD64` / `IMAGE_FILE_MACHINE_I386`），
选用对应的 stub.bin（`stub_x64.bin` / `stub_x86.bin`）。

### 测试模式 `-t`

stub 跳过弹框，直接用硬编码密码 `test123` 走完整 `verify_password` 流程
（含 SHA-256 hash 校验）。**用于 CI / 自动化测试**，无需 GUI 自动化即可验证
stub 解密 + 跳 OEP 的完整链路。

```powershell
builder.exe -i hellocli.exe -t
hellocli_locked.exe          # 直接输出 "Hello World!"，无密码框
```

### 默认输出到源目录

> ⚠️ **重要：加壳后的 exe 必须在原目录运行，不能移动到其它位置！**
>
> 绝大多数 Windows 程序依赖同目录的 DLL、配置文件、资源、插件等。builder 默认
> 输出到 `<input_dir>/<input_base>_locked.exe`（即原 exe 同目录），确保加壳后的
> exe 能找到这些依赖。**不要把加壳后的 exe 复制/移动到其它目录单独运行**，
> 否则会因找不到依赖而报错（如 "initialize failed"、找不到 DLL 等）。

```
输入：C:\Tools\Bandizip\Bandizip.x64.exe
输出：C:\Tools\Bandizip\Bandizip.x64_locked.exe   ← 同目录，原地运行
```

## 密码校验

- 密码以 **SHA-256 hash** 形式存储：`SHA-256(utf8(password) + salt)`，salt 是 16 字节随机数
- stub 用自实现的 SHA-256（不依赖 Windows BCrypt），与 `tests/stub_sha256_test.c`（host 模式）共用 `stub/sha256.h`
- 校验用常量时间比较（`bytes_eq_const`）防 timing attack
- 默认最大重试 3 次，超过后 `ExitProcess(2)`

## 加密

- 算法：XTEA（128-bit key，32 轮）
- 密钥：per-file 随机生成（CryptGenRandom）
- 范围：第一个可执行节的 RawData，实际加密字节数 = `min(VirtualSize, RawSize)` 向下对齐 8 字节
  - **重要**：只加密内存中实际加载的部分，避免 stub 解密越界写坏下一节
- 尾部不足 8 字节部分用密钥流异或

## stub 工作流程

1. **PEB walk** 找 `kernel32.dll` 基址
   - x64：`__readgsqword(0x60)` 取 PEB
   - x86：`__readfsdword(0x30)` 取 PEB
2. **解析导出表** 获取 `GetProcAddress` / `LoadLibraryA` / `VirtualProtect` / `ExitProcess`
3. **密码校验**
   - 测试模式（`-t`）：跳过弹框，直接用硬编码 `test123` 走 `verify_password`
   - 正常模式：`LoadLibraryA("user32.dll")` + 在栈上构建 `DLGTEMPLATE` + `DialogBoxIndirectParamW`
   - 失败可重试，超过 `max_retries` 次 `ExitProcess(2)`
4. **解密 `.text` 节**：`VirtualProtect` 改 RW → `xtea_decrypt_buf` → 恢复原保护
5. **（x64 + ASLR）重新应用 relocations**：`delta = actual_base - preferred_base`，patch `.text` 范围内的 reloc 条目
6. **跳原 OEP**：`PEB.ImageBaseAddress + oep_rva`

### TLS_PROXY 模式（原 PE 有 TLS callbacks 时）

builder 检测到原 PE 有 TLS callbacks，启用 `STUB_FLAG_TLS_PROXY`：
- 在 `.lock` 节末尾追加新 callbacks 数组 `[stub_tls_callback_VA, NULL]`
- 修改原 TLS directory 的 `AddressOfCallBacks` 指向新数组
- `stub_tls_callback` 在 `DLL_PROCESS_ATTACH` 时：
  1. 弹密码框 + 校验
  2. 解密 `.text`
  3. 调用原 TLS callbacks（保存在 `stub_data.orig_tls_callbacks`）
- `stub_entry` 在 TLS_PROXY 模式下只跳 OEP（解密已由 TLS callback 完成）

### x86 stub 重定位预 patch

x86 stub 用绝对地址引用静态数据（如字符串指针），不是 PIC。builder 必须在写入
`.lock` 节前预 patch stub.bin 的所有绝对地址到目标加载位置：

1. `extract_stub_reloc_info()` 从 `stub_x86.exe` 读取 `.reloc` 节
2. `patch_stub_relocations()` 遍历 reloc 表，对每个 `.lock` 范围内的条目加 delta：
   `delta = (target_image_base + target_lock_rva) - (stub_image_base + stub_lock_rva)`
3. x86 PE 强制禁用 ASLR（`DYNAMIC_BASE` 清零），保证 stub 绝对地址始终有效

## 限制

### Builder 拒绝加壳的情况

| 情况 | 原因 |
|------|------|
| DLL（`IMAGE_FILE_DLL`） | 仅支持 EXE |
| .NET CLR（`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`） | 不能加壳托管 PE |

### 加壳时自动处理

- **剥离 Authenticode 签名**（清 `DataDirectory[4]`，移除 overlay）
- **清零 Bound Imports**（`DataDirectory[11]`，避免 loader 走捷径跳过 IAT 解析）
- **CFG 标志清除**（`IMAGE_DLLCHARACTERISTICS_GUARD_CF`，原 CFG 在 `.text` 加密后已失效）
- **ASLR 处理**：
  - x64 + 无 TLS_PROXY：保留 `DYNAMIC_BASE`，stub 解密后重新应用 reloc
  - x64 + TLS_PROXY：禁用 ASLR（避免 `.lock` 内 VA 引用与 reloc 冲突）
  - x86：强制禁用 ASLR（stub 绝对地址已预 patch 到固定 ImageBase）

### 目标程序自身机制导致的失败（无法绕过）

以下情况不是 winlock 的 bug，而是目标程序的反加壳/反修改机制，无法在 PE 加壳器
层面解决（UPX 等其它加壳/压缩工具同样失败）：

| 程序 | 现象 | 根因 |
|------|------|------|
| **Chrome** (`chrome.exe`) | 密码框弹出后鼠标沙漏卡死、无响应 | `chrome_elf.dll` 在 loader 阶段注册 UI Automation hook，stub 的 `DialogBoxIndirectParamW` 消息循环触发 UIA hook → COM RPC 需要 loader 操作但 loader lock 已被 TLS callback 持有 → **loader lock 死锁**。改用 stub_entry (EP) 弹框避 loader lock 也不行：Chrome 在"原代码未跑起来就先干预"的场景下根进程会直接退出。 |
| **QQ** (`qq.exe`) | 输入密码点 OK 后弹窗 `initialize failed 0x00000002` | `FirstLoad.dll`（QQ.exe 导入的第一个 DLL）在初始化时调用 `WinVerifyTrust` 验证宿主 exe 的 Authenticode 签名。加壳必须剥签名（.text 改了 hash 就不对）→ 签名验证失败 → `TRUST_E_NOSIGNATURE`（0x02）。 |
| 一般带自校验的程序 | 启动后自报错或闪退 | 程序在 OEP 中算自身 hash / 校验 `OptionalHeader.CheckSum` / 验证签名 → 加壳后不符 → 报错 |

> 这些是程序自身的反加壳机制，**不是 winlock 的兼容性问题**。任何修改 PE 的工具
> （UPX、ASPack 等）都会触发同样的保护。

## 测试

测试依赖：`winlock/.venv`（已装 pywinauto）。

### 综合端到端测试

```powershell
cd winlock
.\.venv\Scripts\python.exe tools\e2e_test.py
```

测试矩阵（8 项）：

| # | 名称 | 说明 |
|---|------|------|
| 1 | `stub_sha256_unit`     | SHA-256 标准向量 + 端到端 hash |
| 2 | `hellocli_test_mode`  | CLI test mode（`-t`，无弹框） |
| 3 | `hellogui_correct_pwd` | GUI 正确密码路径 |
| 4 | `hellogui_wrong_pwd`   | GUI 错误密码 → 弹错误框 → 重试成功 |
| 5 | `dontsleep_real`      | DontSleep（第三方 GUI） |
| 6 | `notepad4_real`       | Notepad4（第三方 GUI） |
| 7 | `bandizip_real`       | Bandizip（第三方 GUI，带 ASLR + CFG + 大 `.text`） |
| 8 | `tls_rejected`        | 有 TLS callbacks 的样本被 builder 拒绝（v2 行为；v3 用 TLS_PROXY 代理） |

### GUI 自动化测试（单独）

```powershell
.\.venv\Scripts\python.exe tools\gui_test.py <locked.exe> <password> [options]

options:
  --main-title <TITLE>   主窗口标题子串匹配（如 "Bandizip"）
  --main-class <CLASS>   主窗口类名匹配（如 "Notepad4"）
  --wrong-pwd <PWD>      先输错误密码测重试路径
  --timeout <N>           超时秒数（默认 10）
```

### 密码框输入测试（PowerShell）

```powershell
# 启动加壳后的 exe，自动找到密码框、输入密码、点 OK
powershell -File tools\input_password.ps1 -Password <pwd> [-Timeout 10]
```

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

## 架构

```
winlock/
├── config.h              # 共享配置（builder + stub）：stub_data 结构、magic、flags
├── Makefile               # 构建脚本（make / make all-x86）
├── PLAN.md                # 完善计划与进度
├── README.md              # 本文档
├── builder/
│   └── builder.c          # 加壳器：解析 PE、加密 .text、追加 .lock 节、预 patch stub reloc
├── stub/
│   ├── stub.c            # stub 主体（PEB walk / 弹框 / 解密 / 跳 OEP / TLS proxy / ASLR reloc）
│   ├── sha256.h          # 共享 SHA-256 实现（WINLOCK_PIC 宏切换 section）
│   └── stub.ld           # 链接脚本：保留 .lock + .reloc 节，丢弃其它
├── tests/
│   └── stub_sha256_test.c # SHA-256 单元测试（host 模式）
└── tools/
    ├── e2e_test.py        # 综合端到端测试
    ├── gui_test.py        # GUI 自动化测试（pywinauto）
    ├── input_password.ps1 # 密码框自动化（PowerShell）
    ├── check_dontsleep.py # 窗口枚举调试
    ├── inspect_dlg.py     # 控件树调试
    ├── dump_stub_data.ps1 # stub_data dump
    ├── verify_pwd_hash.ps1
    ├── pe_info.py / pe_dump.py / pe_diag.py  # PE 诊断
    └── flip_aslr.py       # ASLR 标志翻转
```

### stub_data 结构（v3）

`builder` 在 `stub.bin` 中搜索 `STUB_DATA_MAGIC`（`"WINLOCK!"`）定位 `stub_data`，
填充以下字段后写入新 `.lock` 节（参见 `config.h`）：

```c
typedef struct {
    uint64_t magic;            /* "WINLOCK!" */
    uint16_t version;         /* 3 */
    uint16_t flags;           /* bit0:hash; bit1:test; bit2:tls_proxy; bit3:aslr */
    uint16_t max_retries;     /* 3 */
    uint16_t reserved16;
    uint64_t oep_rva;         /* 原 AddressOfEntryPoint */
    uint64_t text_rva;        /* 加密的节 RVA */
    uint64_t text_size;       /* 加密字节数 = min(VSize,RawSize) & ~7 */
    uint32_t text_raw_size;   /* 原 SizeOfRawData */
    uint32_t text_protect;    /* 节原保护属性 */
    uint32_t xtea_key[4];    /* XTEA 密钥（per-file 随机） */
    uint8_t  salt[16];       /* SHA-256 salt（per-file 随机） */
    uint8_t  pwd_hash[32];   /* SHA-256(utf8(pwd) + salt) */
    wchar_t  password[64];   /* 明文（v1 兼容，bit0=1 时忽略） */
    /* v3 新增 */
    uint64_t image_base;     /* 原 PE preferred ImageBase */
    uint64_t reloc_rva;      /* .reloc 节 RVA（0 = 无） */
    uint32_t reloc_size;     /* .reloc 节 Size */
    uint32_t reserved32;
    uint64_t orig_tls_callbacks; /* 原 TLS callbacks 数组 VA（0 = 无） */
    uint64_t checksum;       /* XOR 所有 64-bit 字段（防篡改） */
} stub_data_t;
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

stub 的 PIC 约束（x64）：
```c
/* 字符串字面量必须放进 .lock.rdata，否则 lea rip+0x0 会指向代码段随机字节 */
__attribute__((section(".lock.rdata"), used, aligned(2)))
static const wchar_t STR_TEST_PWD[] = L"test123";
```

x86 stub 用绝对地址（非 PIC），靠 builder 预 patch `.reloc` 条目到目标 ImageBase，
因此 x86 加壳后强制禁用 ASLR。

`objcopy -O binary -j .lock stub_xXX.exe stub_xXX.bin` 导出 `.lock` 节为 raw bytes，
builder 同时读 `stub_xXX.exe` 的 `.reloc` 节用于 x86 预 patch。

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

- [PLAN.md](PLAN.md) —— 完善计划、阶段划分、设计决策记录
- [DEVENV.md](DEVENV.md) —— 开发环境工具手册（编译器/调试器/PE 工具/命令行工具分类清单）
