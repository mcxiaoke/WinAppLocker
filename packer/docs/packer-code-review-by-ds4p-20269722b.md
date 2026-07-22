# Packer 代码审查报告

> 审查日期：2026-07-22  
> 审查范围：`packer/` 全部源码  
> 审查者：DeepSeek-v4-Pro (ds4p)

---

## 目录

1. [概述](#1-概述)
2. [架构评审](#2-架构评审)
3. [代码质量](#3-代码质量)
4. [逻辑与正确性](#4-逻辑与正确性)
5. [流程与构建系统](#5-流程与构建系统)
6. [扩展性](#6-扩展性)
7. [测试](#7-测试)
8. [安全性](#8-安全性)
9. [改进建议汇总](#9-改进建议汇总)

---

## 1. 概述

packer 是一个 PE 加壳器，包含两种工作模式：

- **inplace 模式**：在原 PE 中新增 `.text2` 节，加密原 `.text` 节，入口点改为 `stub_entry`
- **reflective 模式**：将原 PE 整体嵌入新 EXE 的 `.payload` 节，`loader` 运行时反射式映射

代码总量约 **5800 行**（C 约 4900 行，汇编约 300 行，Python 约 350 行，CMake/PS1 约 250 行）。

整体来看，代码质量在同类项目（PE packer/protector）中属于**中上水平**，有明显的迭代优化痕迹（从 v1 到 v5 的注释级演进），对边界情况有一定关注。以下逐方面分析。

---

## 2. 架构评审

### 2.1 优点

1. **双模式设计合理**。`inplace` 适合简单场景（轻量、无 CRT），`reflective` 适合复杂场景（需要延迟导入、SxS manifest、资源 API 支持），各有侧重，不互相耦合。

2. **共享代码正确抽取**。`common/` 中的 `peb_walk.h`、`sha256.h`、`xtea.h`、`pe_meta.h` 被两个模式共用，避免了"双份维护"。

3. **分层清晰**。`builder.c` → 加密/嵌入 → `stub.bin`，`stub.c` / `loader.c` → 解密/加载/跳 OEP，职责分明。

4. **汇编分层合理**。`stub_asm_x64.asm` / `stub_asm_x86.asm` 只包含绝对不可用 C 表达的部分（栈对齐跳转），其他逻辑全在 C 中。

5. **TLS 代理设计**是亮点。通过 `STUB_FLAG_TLS_PROXY` 标志 + `g_target_tls` 全局，优雅地解决了 TLS callback 在 loader lock 期间不能加载 DLL 的死锁问题。

### 2.2 问题

#### A1. **inplace 与 reflective 之间存在代码重复**

| 重复内容 | inplace (`stub.c`) | reflective (`loader.c`) |
|---------|-------------------|------------------------|
| PEB walk 找 kernel32 | `find_module_by_hash()` | 通过 CRT `GetModuleHandleA` |
| 密码弹框构建 | `build_dialog()` (手动逐字节构造) | `build_dialog()` (用结构体) |
| XTEA 解密 | `decrypt_text_and_reloc()` | `decrypt_payload_if_needed()` |
| 重定位处理 | `apply_relocations()` 仅 patch .text | `apply_relocations()` + `fallback_relocations()` |
| SecurityCookie 初始化 | `init_security_cookie()` | `init_security_cookie()` (不同实现) |
| Hash 校验 | `verify_password()` | `verify_password()` |
| UTF-8 转换 | `utf16le_to_utf8()` (在 sha256.h 中) | CRT `WideCharToMultiByte` |

**建议**：提取公共逻辑为 `common/loader_core.h`，用 `#ifdef` 条件编译区分 PIC/CRT 模式。可复用的包括：
- XTEA 解密 + VirtualProtect（参数化基址/大小即可）
- 密码验证流程（verify_password 可完全共用）
- SecurityCookie 初始化（逻辑一致，仅地址计算方式不同）
- reloc 应用（唯一的差异是"仅 patch .text" vs "patch 全部"）

**影响**：中等。当前两套代码已稳定且经测试验证，合并有回归风险。建议在下一个大版本（v6）重构。

#### A2. **builder.c 函数过长**

`builder.c` 的 `main()` 函数约 **870 行**（第 532-1400 行），包含了 PE 解析、架构判定、TLS 回调处理、加密、stub 嵌入、ASLR/CFG 处理、签名剥离、校验和重算等全部逻辑。

**建议**：拆分为子函数：
- `parse_pe()` → 返回 PE 解析结构
- `process_tls()` → 返回 TLS 信息
- `encrypt_text()` → 加密 .text 节
- `embed_stub()` → 嵌入 stub + 追加节
- `finalize_pe()` → ASLR/CFG 调整 + 签名剥离 + 校验和

**影响**：低（不影响功能，纯重构）

#### A3. **`reflective/loader.c` 约 2600 行，过于庞大**

这是整个项目最复杂的文件，包含：资源解析、manifest 处理、IAT/延迟导入、重定位（含 fallback）、异常表注册、SecurityCookie、TLS 回调代理、PEB patching、NLS 文件检测、VEH 异常处理等。

**建议**：拆分为 `loader_map.c`（PE 映射）+ `loader_iat.c`（IAT/延迟导入）+ `loader_reloc.c`（重定位）+ `loader_peb.c`（PEB/LDR patching）+ `loader_main.c`（入口/流程编排）。

**影响**：中等（需较多改动，当前流程已高度有序，拆分主要是可维护性收益）

---

## 3. 代码质量

### 3.1 优点

1. **注释详尽**。几乎每个非平凡函数都有中文注释说明背景、设计决策、边界情况。尤其难得的是记录了**为什么这样做**而不只是**做什么**。例如 `process_iat()` 中解释为何宽松处理 failed imports、`fallback_relocations()` 中解释 x64 必须扫 8 字节而非 4 字节的原因。

2. **错误处理有梯度**。区分 `FATAL`（必须退出）和 `WARN`（可继续），如 IAT 失败退出、延迟导入失败 continue。

3. **防御性编程**无处不在。例如：
   - `rva_to_raw()` 同时检查 `VirtualSize` 和 `SizeOfRawData`
   - `map_image()` 对 NLS 文件映射特殊处理
   - `extract_stub_reloc_info()` 对 MSVC 多 `.text2` 子节取并集

4. **调试支持**完善。VEH 异常处理器 + `RtlVirtualUnwind` 栈回溯 + DBG_RAW 文件日志，对反射式加载这样难以用调试器 single-step 的场景很实用。

### 3.2 问题

#### Q1. **魔法数字散落各处**

```c
// loader.c — 多处硬编码常量
for (int k = 0; k < 65536 && *ilt != 0; ilt++, k++)  // 65536 是什么？
if (rip >= 0x400000 && rip < 0x500000)                 // 硬编码地址范围
if (code == 0x40010006)                                 // OutputDebugString 异常码
if (code == 0x406D1388)                                 // SetThreadName 异常码
```

**建议**：
```c
#define MAX_IMPORT_THUNKS      65536
#define VE_NAME_DBG_PRINT        0x40010006   // DBG_PRINTEXCEPTION_C
#define VE_NAME_SET_THREAD_NAME  0x406D1388   // MS_VC_EXCEPTION
```

#### Q2. **`put_dword`/`put_word` 弹框构造模式脆弱**

`stub.c` 中 `build_dialog()` 用逐字段写入避免 GCC -O2 把常量合并到 `.rdata`。这是对编译器行为的巧妙 hack，但：
- 极度脆弱，依赖特定编译器和优化级别
- MSVC 下可能不需要此 hack（MSVC 对常量池处理不同）
- 一旦 linker 行为变化就会静默失败

**建议**：改为在 `stub.ld` 中 `KEEP(.text2.rdata)` 保留常量节，或在 CMake 中用 `-fno-merge-constants` 编译选项，消除 hack 依赖。

**影响**：低（当前稳定），但长期维护成本高。

#### Q3. **全局状态过多**

```c
// loader.c 全局变量（共 7 个）
static uint8_t* g_reserved_base = NULL;       // 早期预留内存
static size_t g_reserved_size = 0;
static int g_reserve_attempted = 0;
static int g_reserve_result = 0;
static DWORD g_reserve_err = 0;
static reflective_payload_t* g_pwd_hdr = NULL; // 密码相关
static IMAGE_TLS_DIRECTORY_X* g_target_tls = NULL; // TLS callback 代理
static volatile LONG g_entry_point_called = 0;
```

全局状态让代码难以测试和复用。理想情况下应封装为 `loader_context_t` 结构体，函数签名中显式传递。

**建议**：

```c
typedef struct {
    uint8_t* reserved_base;
    size_t   reserved_size;
    int      reserve_attempted;
    int      reserve_result;
    DWORD    reserve_err;
    IMAGE_TLS_DIRECTORY_X* target_tls;
    volatile LONG entry_point_called;
} loader_ctx_t;
```

**影响**：低（单线程 stub，全局变量实际不影响正确性），主要是可读性和可测试性的改善。

#### Q4. **宏 OH() 的写法依赖编译器对三元表达式的扩展**

```c
#define OH(field) (*(g_is_x64 ? &g_nt64->OptionalHeader.field : &g_nt32->OptionalHeader.field))
```

C 标准中三元表达式返回右值，不能作为左值（不能取址再解引用）。虽然 GCC/MSVC 都支持此扩展，但严格来说不是可移植 C。

**建议**：改为显式 if-else 的分派函数，或使用 C11 `_Generic`。

**影响**：极低（在两个目标编译器上都工作正常），主要是代码整洁性问题。

---

## 4. 逻辑与正确性

### 4.1 优点

1. **reloc 处理极其全面**。`apply_relocations()` 支持全部 5 种重定位类型（包括罕见的 HIGH/LOW），`fallback_relocations()` 有 skip bitmap 保护 IAT 和字符串区域，设计非常周到。

2. **TLS 处理细腻**。区分 `init_tls_data()`（主线程一次性）+ `tls_callback_proxy()`（每线程动态分配），解决了 Rust `std::thread` 等依赖 TLS 的程序。

3. **PEB.Ldr patch 延迟到 manifest 激活之后**。规避了 NLS 文件映射被覆盖导致 ntdll 崩溃的经典陷阱，是一个很好的防御性设计。

4. **NLS 文件检测**。通过 `K32GetMappedFileNameA` 检测 `preferred_base` 是否被系统 NLS 文件占据，避免 `NtUnmapViewOfSection` 后 ntdll cached pointer 崩溃。

### 4.2 问题

#### L1. **`fallback_relocations()` 存在误判风险**

扫描算法把 `[old_base, old_base + SizeOfImage)` 范围内的任何 4/8 字节值当作绝对地址，存在以下风险：

1. 常量数据恰好在此范围内（如 `0x401234` 是一个颜色值、表索引、枚举常量）
2. 指令中的立即数（如 `CMP EAX, 0x401000`）

skip bitmap 保护了 IAT 和导入字符串，但**不保护 `.text` 节中的指令立即数和 `.rdata` 中的非字符串常量**。

**缓解**：当前 fallback 仅在 PE 无 `.reloc` 表时触发，大部分现代 PE 有 `.reloc`，且注释中说明这是"能工作"而非"完美"的解决方案。但应在文档中明确声明风险。

**建议**：增加一个可选模式（通过 `-f` 标志），让 builder 拒绝无 `.reloc` 的 PE 而非使用 fallback。

#### L2. **`.nls` 后缀检测过于简单**

```c
if (e0 == '.' && e1 == 'n' && e2 == 'l' && e3 == 's') {
    is_nls = 1;
}
```

用文件后缀名判断系统 NLS 文件，存在被伪装的风险（虽在实际场景中可能性极低）。更准确的方式是检查映射文件的完整路径是否在 `SystemRoot\System32\` 下。

**影响**：低（恶意利用场景几乎不存在）。

#### L3. **`stub.c` 中 `apply_relocations()` 对 HIGH/LOW 类型的 delta 处理可能不精确**

```c
case WINLOCK_RELOC_HIGH: {
    *(uint16_t*)patch_addr += (uint16_t)((uint32_t)delta >> 16);
    break;
}
```

IMAGE_REL_BASED_HIGH 的语义是"地址的高 16 位加 delta 的高 16 位（含进位处理）"，直接取 `delta >> 16` 的低 16 位不正确。正确做法需要处理低 16 位的进位。

**影响**：极低（HIGH/LOW 类型在现代 PE 中几乎不存在，仅保留用于理论完整性）。

#### L4. **`verify_stub_identity()` 中对齐搜索可能遗漏**

```c
for (size_t i = 0; i + sizeof(stub_data_t) <= stub_bin_size; i += 8) {
    if (*(const uint64_t*)(stub_bin + i) != magic) continue;
```

以 8 字节步长搜索，如果 `stub_data_t` 在二进制中的实际偏移不是 8 字节对齐（理论上可能，实际由于链接器对齐规则不会发生），会遗漏。

**影响**：极低（链接器通常保证 16 字节对齐）。

#### L5. **`SHA-256` 在 builder 和 stub 中使用不同实现**

- builder (`builder.c`)：使用 Windows CryptoAPI (`CryptCreateHash` + `CALG_SHA_256`)
- stub (`sha256.h`)：自实现纯 C 版 SHA-256
- 密码转换：builder 用 `WideCharToMultiByte(CP_ACP)`，stub 用 `utf16le_to_utf8()`

这可能导致**编码不一致**：builder 用 ACP（MBSC），stub 用 UTF-8。如果密码含非 ASCII 字符，两者产生的 UTF-8 序列可能不同，导致 hash 不匹配。

**建议**：统一使用 UTF-8 编码，builder 改用 `WideCharToMultiByte(CP_UTF8, ...)`。

**影响**：中等（仅影响非 ASCII 密码，但当前默认密码和测试密码都是纯 ASCII，所以未暴露）。

---

## 5. 流程与构建系统

### 5.1 优点

1. **构建产物检查链完整**。`check_stub_freshness.py` → `patch_stub_identity.py` → `inspect_stub.py` → `build.ps1` 形成完整链路。

2. **双编译器支持**（MinGW + MSVC）让项目灵活。`#ifdef _MSC_VER` 覆盖良好。

3. **stub 身份校验**四重（magic + version + arch + size）防止用错 stub 版本。

### 5.2 问题

#### F1. **构建配置分散**

项目有：
- `CMakeLists.txt` + `CMakeLists.inc`（CMake 主构建）
- `build.ps1`（PowerShell 完整构建流程）
- `Makefile.mingw`（MinGW make 构建）

三者之间存在功能重叠。`build.ps1` 是最完整的主入口，但 CMakeLists 和 Makefile.mingw 也各有用途。不清楚哪个是"官方"构建方式。

**建议**：明确 build.ps1 为唯一入口，其他作为内部工具。在 README.md 中说明构建流程。

#### F2. **stub 编译产物管理混乱**

- `stub_inplace_x64.bin` / `stub_inplace_x86.bin`（Python 导出）
- `stub_inplace_x86.exe`（用于 x86 reloc 提取）
- `extract_lock_section.py` 从 .exe 导出 .bin
- `patch_stub_identity.py` 填充 stub 身份信息

这些步骤的依赖关系不直观。例如 `stub_inplace_x86.exe` 只在 x86 输入 PE 时才需要，但构建脚本可能总是生成它。

**建议**：用 CMake 的 `add_custom_command` + `add_custom_target` 显式建模依赖关系，避免不必要的重编译。

#### F3. **PowerShell 构建脚本不支持跨平台**

`build.ps1` 依赖 Windows MSBuild/VSWhere/MSVC 工具链。未来如需在 Linux 上交叉编译，需要完全重写。

**建议**：将平台无关逻辑（如 stub 源码编译）放在 CMake 中，`build.ps1` 只做 Windows 特定的 MSVC 调用。

---

## 6. 扩展性

### 6.1 优点

1. **加密算法可替换性**。`xtea.h` 是独立模块，替换为 AES/ChaCha20 只需改此文件和 builder 中对应的加密调用。

2. **密码验证可扩展**。`verify_password()` 目前只支持 SHA-256，但 `stub_data_t` 预留了 `flags` 字段，可增设 `STUB_FLAG_PBKDF2` 或 `STUB_FLAG_ARGON2` 标志。

3. **配置通过 `config.h` 集中管理**。`STUB_DATA_MAGIC`、`STUB_DATA_VERSION`、`WINLOCK_XTEA_KEY*` 等都统一在 `config.h` 中定义。

### 6.2 问题

#### E1. **XTEA 密钥硬编码为常量**

```c
#define WINLOCK_XTEA_KEY0 0x9E3779B9
#define WINLOCK_XTEA_KEY1 0x3C6EF372
#define WINLOCK_XTEA_KEY2 0xDA66D1FB
#define WINLOCK_XTEA_KEY3 0x786B5A4A
```

`stub_data.xtea_key` 虽然有字段，但 stub 编译时也用默认值初始化。实际 builder 会覆盖，但万一 builder 未覆盖则用默认密钥（已知常量），等同于未加密。

**建议**：`stub_data.xtea_key` 初始化为全 0，stub 检测到全 0 密钥时直接退出（说明 builder 未正确填充）。

#### E2. **密码算法不支持版本迁移**

当前只有一种密码方案：SHA-256(password + salt)。如需升级到 Argon2/PBKDF2，旧密码的 hash 将不兼容。

**建议**：在 `stub_data_t` 中增设 `uint16_t hash_algo` 字段（0=SHA-256, 1=PBKDF2-SHA-256, 2=Argon2id），stub 根据此字段选择验证算法。

#### E3. **不支持多密码/密码列表**

当前只支持单密码。某些场景可能需要"主密码 + 临时密码"或"密码列表"。

**建议**：`stub_data_t` 中预留 `uint8_t pwd_count` + `pwd_hash[4][32]`（4 个密码槽位，足够扩展），或改用固定大小的 hash 数组。

---

## 7. 测试

### 当前状态

1. **`auto_e2e_test.ps1`**：PowerShell 端到端测试框架，调用 builder 生成加壳 PE，运行并校验退出码
2. **`e2e_test.py`**：Python 端到端测试（功能与 PS1 版本并行）
3. 测试样本在 `temp/samples/` 中
4. CI/CD 未见配置（无 GitHub Actions / Azure Pipelines / Jenkinsfile）

### 问题

#### T1. **无单元测试**

所有测试都是端到端的（builder → 加壳 PE → 运行验证）。缺乏对关键函数的**单元测试**：
- `sha256_init/update/final` — 可用标准测试向量
- `xtea_encrypt_buf/decrypt_buf` — 可用已知明文/密文对
- `peb_walk.h` 中的模块查找 — 需要 Windows 环境但可做集成测试
- `apply_relocations()` — 可构造 mini PE 测试
- `utf16le_to_utf8()` — 可用标准编码测试向量

**建议**：创建 `tests/unit/` 目录，使用轻量框架（如 `µnit` 或 `minctest`）编写 C 单元测试，通过 CMake 的 `add_test()` 集成。

#### T2. **端到端测试不充分**

当前测试只验证"程序能否运行到退出"，未验证：
- 程序功能是否完整（如对特定程序验证所有 UI 元素可用）
- 加密是否生效（如对比加壳前后的 .text 节）
- 反调试绕过是否被正确检测
- TLS callbacks 是否被正确调用
- 资源是否可正常加载（FindResource/LoadString）

**建议**：按 PEP 分类建立测试套件：
- `samples/simple/hello_x64.exe` — 最小验证
- `samples/gui/notepad_like.exe` — 资源加载验证
- `samples/tls/tls_callback_test.exe` — TLS callback 验证
- `samples/delay/ccleaner_like.exe` — 延迟导入验证

#### T3. **缺少性能测试**

加壳后的启动延迟、内存占用、PE 大小变化等没有被量化。

**建议**：在 `e2e_test.py` 中增加性能指标的记录和对比。

---

## 8. 安全性

### 8.1 优点

1. **密码 hash 加盐**。SHA-256(password + 16-byte random salt) 让彩虹表攻击失效。
2. **per-file 随机密钥**。每次加壳生成新的 XTEA key，不同样本不可互解密。
3. **const-time 比较**。`bytes_eq_const()` 用于 hash 比较，防时序攻击。
4. **API hash 化**（inplace 模式）。用 DLL 导出名 hash 替代明文字符串，降低静态分析可读性。
5. **函数指针清零**。`clear_fn_pointers()` 在跳 OEP 前清除运行时 API 指针，防内存 dump 分析。
6. **PEB 反调试**。三重检测（BeingDebugged + NtGlobalFlag + KdDebuggerEnabled）。

### 8.2 问题

#### S1. **XTEA 安全性**

XTEA 是轻量级分组密码，提供基本混淆但不敌现代密码分析。对于"阻止普通用户运行程序"的需求足够，但不能抵抗专业逆向。

**建议**：考虑升级到 AES-256-CTR + HMAC-SHA-256（认证加密），或至少支持可选算法。

#### S2. **测试模式下的硬编码密码可被逆向提取**

`STR_TEST_PWD = L"test123"` 在 `.text2.rdata` 节中，未加密。虽然仅测试模式使用，但有被误用于生产环境的风险。

**建议**：测试模式在 builder 中增加确认提示："WARNING: Test mode will use hardcoded password 'test123'. Continue? [y/N]"

#### S3. **`.text2` 节属性为 ERC（无 W），但运行时动态改为 RWX**

虽然静态分析工具可能标记此为异常，但在某些 EDR/AV 环境中，运行时 RWX 内存分配（即使是合法的）可能触发告警。

**建议**：考虑用 `PAGE_EXECUTE_READ` → 写 fn 表时临时改 `PAGE_EXECUTE_READWRITE` → 恢复 `PAGE_EXECUTE_READ` 的策略（当前已有），同时建议在 `.text2` 节中隔离代码与数据（当前只在 MSVC 中部分实现）。

---

## 9. 改进建议汇总

### 优先级说明

- **P0**：必须修复，影响功能正确性或安全性
- **P1**：强烈建议，显著改善代码质量或可维护性
- **P2**：建议改进，在便利时实施
- **P3**：可选优化，锦上添花

| 编号 | 类别 | 优先级 | 标题 | 预计工时 |
|------|------|--------|------|----------|
| L5 | 逻辑 | **P0** | 修复 builder 与 stub 密码编码不一致（ACP vs UTF-8） | 0.5h |
| S2 | 安全 | **P0** | 测试模式增加确认提示 | 0.5h |
| Q2 | 质量 | **P1** | 消除 `put_dword`/`put_word` 弹框构造 hack | 2h |
| A2 | 架构 | **P1** | 拆分 `builder.c` 的 `main()` 为子函数 | 3h |
| A1 | 架构 | **P1** | 合并 inplace/reflective 的重复逻辑到 `common/loader_core.h` | 4h |
| E2 | 扩展 | **P1** | `stub_data_t` 中增加 `hash_algo` 字段 | 2h |
| T1 | 测试 | **P1** | 建立 `tests/unit/` 单元测试目录 | 8h |
| Q1 | 质量 | **P2** | 消除魔法数字，定义语义常量 | 2h |
| Q3 | 质量 | **P2** | 全局状态封装为 `loader_ctx_t` | 3h |
| E1 | 扩展 | **P2** | stub 检测到全 0 XTEA key 时退出 | 0.5h |
| A3 | 架构 | **P2** | 拆分 `loader.c` 为多个文件 | 8h |
| T2 | 测试 | **P2** | 扩充端到端测试样本库 | 4h |
| L1 | 逻辑 | **P2** | fallback_relocations 增加风险文档和可选严格模式 | 1h |
| F1 | 流程 | **P2** | 统一构建入口，清理 CMake/Makefile/PS1 冗余 | 3h |
| F2 | 流程 | **P2** | CMake 中显式建模 stub 构建产物依赖 | 2h |
| Q4 | 质量 | **P3** | 替换 `OH()` 宏为显式 if-else 函数 | 2h |
| L2 | 逻辑 | **P3** | .nls 检测改为检查完整路径 | 0.5h |
| L3 | 逻辑 | **P3** | HIGH/LOW reloc 类型修复进位处理 | 1h |
| S1 | 安全 | **P3** | 评估升级到 AES-256-CTR + HMAC | 8h |
| E3 | 扩展 | **P3** | 支持多密码槽位 | 2h |
| T3 | 测试 | **P3** | 增加性能基准测试 | 2h |

---

## 总结

该项目是一个**经过充分迭代、注重边界情况的 PE 加壳器**，代码质量在同类项目中表现良好。以下是核心亮点和需要关注的重点：

### 核心亮点

1. **异常处理体系完整**。VEH + `RtlVirtualUnwind` 栈回溯 + DBG_RAW 日志，在反射式加载这种难以调试的场景中极为实用。
2. **TLS 处理周到**。TLS callback 代理 + 线程级数据分配 + SizeOfZeroFill 扩展，解决了 Rust/MinGW CRT 等现代运行时的兼容性。
3. **PEB.Ldr patch 延迟到 manifest 激活后**，避免了 NLS 映射覆盖的经典崩溃。
4. **注释质量极高**，记录了大量设计决策和边界情况的原因。

### 关键风险

1. **密码编码不一致**（P0）：builder 用 ACP，stub 用 UTF-8，非 ASCII 密码会导致 hash 不匹配。
2. **`fallback_relocations()` 存在误判风险**（P2）：虽然只在无 `.reloc` 表时触发，但不应是无声默认行为。
3. **弹框构造 hack 脆弱**（P1）：依赖特定编译器行为，长期维护成本高。

### 改进路线建议

1. **第一阶段**（本周）：修复 P0 问题（密码编码不一致、测试模式提示）
2. **第二阶段**（本月）：P1 改进（消除 hack、拆分 builder、合并重复代码、单元测试框架）
3. **第三阶段**（下季度）：P2 改进（消除魔法数字、拆分 loader、扩充测试、统一构建）
4. **长期评估**：AES 替代 XTEA、多密码支持、跨平台构建
