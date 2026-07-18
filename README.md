# WinLock

PE 文件密码门禁加壳器（x64 / Windows）。在原 PE 末尾追加一个 PIC stub，
加密第一个可执行节（通常 `.text`），运行时 stub 弹密码框，校验通过后解密并跳原 OEP。

> 仅门禁壳，非完整加壳器：只加密 `.text` 一个节，其它节（`.rdata` / `.data` / `.rsrc` …）保持原样，
> 最大化与第三方程序的兼容性。

## 构建

依赖 [w64devkit](https://github.com/skeeto/w64devkit)（GCC 13+ / mingw-w64）。

```powershell
# 把 w64devkit/bin 加入 PATH（PowerShell）
$env:Path = "C:\Home\Develop\w64devkit\bin;" + $env:Path

cd winlock
make           # 生成 stub/stub.bin + builder/builder.exe
```

输出：
- `stub/stub.bin` —— PIC stub 二进制（约 5.5 KB）
- `builder/builder.exe` —— 加壳器

## 使用

### 标准参数

```powershell
# 默认输出到 <input_dir>/<input_base>_locked.exe
builder.exe -i <input.exe>                    # 用默认密码 hello123
builder.exe -i <input.exe> -p <password>      # 指定密码
builder.exe -i <input.exe> -o <output.exe>    # 指定输出路径
builder.exe -i <input.exe> -t                 # 测试模式（见下）

# 旧式位置参数（向后兼容）
builder.exe <input.exe> <output.exe> [password] [--test]
```

| 选项 | 说明 |
|------|------|
| `-i, --input <file>`    | 输入 PE EXE（必须是 x64） |
| `-o, --output <file>`    | 输出路径，默认 `<dir>/<base>_locked.exe` |
| `-p, --password <pwd>`  | 密码，默认 `hello123` |
| `-t, --test`            | 测试模式（固定密码 `test123`，不弹框） |
| `-h, --help`            | 显示帮助 |

### 测试模式 `-t`

stub 跳过弹框，直接用硬编码密码 `test123` 走完整 `verify_password` 流程
（含 SHA-256 hash 校验）。**用于 CI / 自动化测试**，无需 GUI 自动化即可验证
stub 解密 + 跳 OEP 的完整链路。

```powershell
builder.exe -i hellocli.exe -t
hellocli_locked.exe          # 直接输出 "Hello World!"，无密码框
```

### 默认输出到源目录

**带依赖的 exe（DLL、配置文件）必须在源目录测试**。默认输出路径为
`<input_dir>/<input_base>_locked.exe`，确保加壳后的 exe 能找到同目录的资源。

```
输入：C:\Tools\Bandizip\Bandizip.x64.exe
输出：C:\Tools\Bandizip\Bandizip.x64_locked.exe   ← 同目录
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
  - **重要**：只加密内存中实际加载的部分，避免 stub 解密越过节边界写坏下一节数据
- 尾部不足 8 字节部分用密钥流异或

## stub 工作流程

1. **PEB walk** 找 `kernel32.dll` 基址（不依赖 IAT）
2. **解析导出表** 获取 `GetProcAddress` / `LoadLibraryA` / `VirtualProtect` / `ExitProcess`
3. **密码校验**
   - 测试模式（`-t`）：跳过弹框，直接用硬编码 `test123` 走 `verify_password`
   - 正常模式：`LoadLibraryA("user32.dll")` + 在栈上构建 `DLGTEMPLATE` + `DialogBoxIndirectParamW`
   - 失败可重试，超过 `max_retries` 次 `ExitProcess(2)`
4. **解密 `.text` 节**：`VirtualProtect` 改 RW → `xtea_decrypt_buf` → 恢复原保护
5. **跳原 OEP**：`PEB.ImageBaseAddress + oep_rva`

## 限制

以下情况 builder 会拒绝加壳：

| 情况 | 原因 |
|------|------|
| 32 位 PE (`Machine != AMD64`) | 仅支持 x64 |
| DLL（`IMAGE_FILE_DLL`） | 仅支持 EXE |
| TLS callbacks 非空 | stub 解密会破坏 TLS 初始化顺序（v3 计划支持） |
| .NET CLR（`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`） | 不能加壳托管 PE |

加壳时会自动处理：
- **剥离 Authenticode 签名**（清 `DataDirectory[4]`，移除 overlay）
- **清零 Bound Imports**（`DataDirectory[11]`，避免 loader 走捷径跳过 IAT 解析）
- **禁用 ASLR**（清 `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`）
  - 原因：stub 解密用文件原字节覆盖内存，会冲掉 loader 应用过的 relocations
  - 后果：跳 OEP 时绝对地址引用错误 → `STATUS_STACK_BUFFER_OVERRUN (0xC0000409)`
  - stub 自身是 PIC，不受 ImageBase 影响

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
| 7 | `bandizip_real`       | Bandizip（第三方 GUI，带 ASLR + 大 `.text`） |
| 8 | `tls_rejected`        | 有 TLS callbacks 的样本被 builder 拒绝 |

### GUI 自动化测试（单独）

```powershell
.\.venv\Scripts\python.exe tools\gui_test.py <locked.exe> <password> [options]

options:
  --main-title <TITLE>   主窗口标题子串匹配（如 "Bandizip"）
  --main-class <CLASS>   主窗口类名匹配（如 "Notepad4"）
  --wrong-pwd <PWD>      先输错误密码测重试路径
  --timeout <N>           超时秒数（默认 10）
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

## 架构

```
winlock/
├── config.h              # 共享配置（builder + stub）
├── Makefile               # 构建脚本
├── builder/
│   └── builder.c          # 加壳器：解析 PE、加密 .text、追加 .lock 节
├── stub/
│   ├── stub.c            # PIC stub 主体（PEB walk / 弹框 / 解密 / 跳 OEP）
│   ├── sha256.h          # 共享 SHA-256 实现（WINLOCK_PIC 宏切换 section）
│   └── stub.ld           # 链接脚本：只保留 .lock 节，丢弃其它所有节
├── tests/
│   └── stub_sha256_test.c # SHA-256 单元测试（host 模式）
└── tools/
    ├── e2e_test.py        # 综合端到端测试
    ├── gui_test.py        # GUI 自动化测试（pywinauto）
    ├── check_dontsleep.py # 窗口枚举调试工具
    ├── inspect_dlg.py     # 控件树调试工具
    ├── dump_stub_data.ps1
    ├── verify_pwd_hash.ps1
    ├── input_password.ps1
    └── e2e_test.ps1       # 旧 PowerShell e2e（保留作参考）
```

### stub_data 结构（v2）

`builder` 在 `stub.bin` 中搜索 `STUB_DATA_MAGIC`（`"WINLOCK!"`）定位 `stub_data`，
填充以下字段后写入新 `.lock` 节：

```c
typedef struct {
    uint64_t magic;            /* "WINLOCK!" */
    uint16_t version;         /* 2 */
    uint16_t flags;           /* bit0: hash 校验; bit1: 测试模式 */
    uint16_t max_retries;     /* 3 */
    uint16_t reserved16;
    uint64_t oep_rva;         /* 原 AddressOfEntryPoint */
    uint64_t text_rva;        /* 加密的节 RVA */
    uint64_t text_size;       /* 加密字节数 = min(VirtualSize, RawSize) & ~7 */
    uint32_t text_raw_size;   /* 原 SizeOfRawData */
    uint32_t text_protect;    /* 节原保护属性 */
    uint32_t xtea_key[4];    /* XTEA 密钥（per-file 随机） */
    uint8_t  salt[16];       /* SHA-256 salt（per-file 随机） */
    uint8_t  pwd_hash[32];   /* SHA-256(utf8(pwd) + salt) */
    wchar_t  password[64];   /* 明文（v1 兼容，bit0=1 时忽略） */
    uint64_t checksum;       /* XOR 所有 64-bit 字段（防篡改） */
} stub_data_t;
```

### PIC stub 关键约束

stub 编译为 Position-Independent Code，所有静态数据必须显式放进 `.lock.*` 节，
否则会被 `stub.ld` 的 `/DISCARD/` 丢弃，运行时访问到错误地址。

```c
/* 字符串字面量必须放进 .lock.rdata，否则 lea rip+0x0 会指向代码段随机字节 */
__attribute__((section(".lock.rdata"), used, aligned(2)))
static const wchar_t STR_TEST_PWD[] = L"test123";
```

`stub.ld` 链接脚本只保留 `.lock` 输出节，丢弃 `.text` / `.rdata` / `.pdata` / `.xdata` / `.reloc` 等，
避免与目标 PE 的节冲突。`objcopy -O binary -j .lock` 导出为 raw bytes。

## 已验证样本

| 程序 | 类型 | 大小 | 说明 |
|------|------|------|------|
| hellocli | 自编 CLI | 12 KB | test mode 端到端 |
| hellogui | 自编 GUI | 16 KB | 正确/错误密码路径 |
| DontSleep 9.96 | 第三方 GUI | 270 KB | ASLR + 多节 |
| Notepad4 | 第三方 GUI | 2.5 MB | 主窗口用 class_name 匹配 |
| Bandizip x64 | 第三方 GUI | 3.4 MB | ASLR + 大 `.text`（2.4 MB）+ Authenticode 签名 |
| hellomingw / helloucrt / sha256sum | 自编 | - | 有 TLS callbacks，被 builder 正确拒绝 |
