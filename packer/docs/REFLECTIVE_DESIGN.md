# WinLock 反射式 Packer/Stub 设计方案

> 创建日期：2026-07-19
> 配套文档：[REFLECTIVE_ANALYSIS.md](REFLECTIVE_ANALYSIS.md) — 反射式 PE Loader 项目深度对比报告
> 目标：在现有 in-place 模式之外，新增一个反射式 loader 模式，两种模式并存

---

## 0. 重要前提（开发优先原则）

本方案遵循两条核心原则：

1. **开发优先，体积放宽**
   - stub 大小不再是约束。当前硬盘空间不值钱，**stub 编译后 2MB 以下完全可接受**。
   - 优先选择便于开发、便于调试的实现方式，而非极致压缩。
   - 允许 stub 用带 CRT 的 C 编译（如 MinGW-w64 默认 CRT 或 MSVC CRT），允许使用 `printf` 调试输出。
   - 允许 stub 体积大一些（如 50KB-500KB），换取开发效率和代码可读性。

2. **加密与反调试后置**
   - **第一版（MVP）不做 ChaCha20-Poly1305**，先用简单加密（XTEA 或 XOR + 随机 key），与现有 winlock in-place 模式的 XTEA 实现保持一致便于复用。
   - **第一版不做反调试**（PEB.BeingDebugged / NtGlobalFlag / NtQueryInformationProcess 等），避免开发调试时被自己的反调试挡住。
   - 加密栈升级（ChaCha20-Poly1305 + PBKDF2）和反调试增强作为**后期增强阶段**，待核心反射式 loader 跑通后再加。
   - 反调试始终做成**编译开关 / flags 位**，默认关闭，仅 release 模式可开启。

---

## 1. 现状回顾

**现有 in-place 模式**（`packer/builder/builder.c` + `packer/stub/stub.c`）：
- 原地修改 PE，新增 `.lock` 节装 PIC stub，加密 `.text` 节
- stub 在原 PE 上原地解密 `.text`，跳 OEP
- 优点：兼容性高、资源天然保留、stub 极小（6.5KB）
- 缺点：PE 结构暴露、`.text` 之外全明文、反 dump 弱、不支持 .NET/Console

**反射式模式目标**：原 PE 整体加密压缩成 payload 嵌入 stub EXE，运行时 stub 申请新内存反射映射 PE，跳 OEP。两个模式**并存**，由 dotnet packer 通过 `--stub-name winlock-reflective` 选择。

---

## 2. 设计原则（按优先级）

| 优先级 | 原则 | 说明 |
|--------|------|------|
| 1（最高） | **开发优先** | 便于写、便于读、便于调试，stub 体积 ≤2MB 即可 |
| 2 | **工具链一致** | 沿用 w64devkit + msys2 mingw32，与 winlock 现有 stub.c 同约束（PIC C 无 CRT）—— 但允许带 CRT 简化开发，后续如需可剥离 |
| 3 | **复用最大化** | SHA-256、DJB15 hash、PEB walk、`jump_to_oep`、`init_security_cookie`、`is_being_debugged`、PE 解析等已有代码直接复用 |
| 4 | **加密和反调试后置** | MVP 阶段用 XTEA 或 XOR + 随机 key，反调试默认关闭 |
| 5 | **payload 可演进** | 紧凑二进制头 + 魔数 + 版本 + flags 位域，与 `stub_data_t` 风格统一 |
| 6 | **资源保留** | builder 端把原 PE `.rsrc` 节复制到 stub EXE（保留图标/manifest/版本信息） |
| 7 | **完整 PE 初始化** | IAT（含 forwarder 递归）+ reloc 5 类型 + TLS ATTACH + .pdata 注册 + SecurityCookie + 8 种节权限 |

---

## 3. 借鉴对照表

| 设计点 | 借鉴来源 | 关键文件:行 |
|--------|----------|------------|
| 整体架构（PIC C，可带 CRT） | **peldr** | `loader.c:1-1152` |
| payload 魔数+版本+flags | **pe-packer-rust** | `common/src/lib.rs:22-167` |
| 16B 栈对齐跳 OEP | **peldr** | `loader.c:1144-1152` |
| SecurityCookie 初始化 | **peldr** + **AlushPacker** | `loader.c:464-482`（仅默认值时覆盖） |
| 完整 reloc 5 类型 | **AlushPacker** | `loader.c:647-700` |
| forwarder 递归解析 | **AlushPacker** | `loader.c:62-87, 241-300` |
| 延迟导入表 | **AlushPacker** | `loader.c:701-740` |
| API hash（DJB15） | **winlock 现有** | `stub.c:275-352` |
| PEB 反调试三阶段 | **peldr** + **winlock 现有** | `loader.c:858-908`（后期阶段） |
| PE header erasure | **peldr** + **AtomPePacker** | `loader.c:1078-1085`（后期阶段） |
| 函数指针 scrub | **peldr** | `loader.c:1107-1126` |
| `RtlAddFunctionTable` 注册 .pdata | **peldr** + **AlushPacker** | `loader.c:531-545` |
| 8 种节权限查表 | **AlushPacker** | `loader.c:770-810` |
| RefreshNtdll（反 hook） | **AtomPePacker** | `Utils.c:38-85`（可选后期编译开关） |
| IAT Camouflage | **AtomPePacker** | `IatCamouflage.h`（可选后期） |
| payload 加密栈（最终形态） | **pe-packer-rust** 思路 + ChaCha20 替换 AES-GCM | — |

---

## 4. 文件清单与目录结构

```
packer/
├── builder/
│   ├── builder.c                    # 现有 in-place builder（不动）
│   └── builder_reflective.c         # 新增：反射式 builder
├── stub/
│   ├── stub.c                       # 现有 in-place stub（不动）
│   ├── sha256.h                     # 现有（复用）
│   └── stub.ld                      # 现有（不动）
├── reflective/                      # 新增子目录
│   ├── loader.c                     # 反射式 stub 主体
│   ├── loader.ld                    # 链接脚本（如用 PIC 模式）
│   ├── payload.h                    # payload 容器格式（builder+stub 共享）
│   ├── chacha20.h                   # ChaCha20-Poly1305（后期阶段，header-only）
│   ├── lz4dec.h                     # LZ4 解压器（header-only，仅解压）
│   ├── pbkdf2.h                     # PBKDF2-HMAC-SHA256（后期阶段，基于 sha256.h）
│   └── apihash.py                   # API hash 生成器（沿用现有 gen_api_hash.py）
├── common/
│   ├── config.h                     # 现有（增加反射式相关常量）
│   └── pe_shared.h                  # 新增：PE 解析公用函数声明（让两个 builder 共用）
└── docs/
    ├── ANALYSIS_REPORT.md           # 现有
    ├── PORTING_PLAN.md              # 现有
    ├── REFLECTIVE_ANALYSIS.md       # 新增：对比报告
    └── REFLECTIVE_DESIGN.md         # 本文档
```

---

## 5. payload 容器格式

紧凑二进制头 + 密文，与现有 `stub_data_t` 风格统一：

```c
/* packer/reflective/payload.h */
#pragma pack(push, 8)
typedef struct {
    uint64_t magic;            /* "WLOCKR\0\0" = 0x00303052544E4F4C */
    uint16_t version;          /* 1 */
    uint16_t flags;            /* bit0: hash 校验; bit1: test; bit2: compress; bit3: antidebug */
    uint16_t kdf_iters;        /* KDF 迭代轮数（v2+ 用，v1 填 0） */
    uint16_t reserved16;
    uint64_t original_size;    /* 原 PE 未压缩大小 */
    uint64_t compressed_size;  /* 压缩后大小（== 密文长度） */
    uint64_t oep_rva;          /* 原 PE AddressOfEntryPoint RVA（备份） */
    uint64_t image_base;       /* 原 PE preferred ImageBase */
    uint8_t  salt[16];         /* KDF salt */
    uint8_t  nonce[12];        /* AEAD nonce（v2+ 用，v1 填 0） */
    uint8_t  pwd_hash[32];     /* KDF(password, salt, iters) 校验用 */
    uint8_t  auth_tag[16];     /* AEAD tag（v2+ 用，v1 填 0） */
    uint64_t checksum;         /* XOR 所有 8B 字段（防篡改） */
    /* 后跟 ciphertext[compressed_size] */
} reflective_payload_t;
#pragma pack(pop)

#define REFLECTIVE_PAYLOAD_MAGIC   0x00303052544E4F4CULL  /* "WLOCKR\0\0" */
#define REFLECTIVE_PAYLOAD_VERSION 1
#define REFLECTIVE_FLAG_HASH       0x0001
#define REFLECTIVE_FLAG_TEST       0x0002
#define REFLECTIVE_FLAG_COMPRESS   0x0004
#define REFLECTIVE_FLAG_ANTIDEBUG  0x0010  /* 后期阶段 */
#define REFLECTIVE_FLAG_ERASE_HDR  0x0020  /* 后期阶段：跳 OEP 前清零 PE headers */
```

**嵌入方式**：payload 追加在 stub EXE 末尾，作为新的 `.payload` 节。stub 通过 `find_section_by_hash(myself, HASH_PAYLOAD)` 定位（无需文件 IO，借鉴 AtomPePacker）。

**MVP 阶段加密**：v1 用 XTEA 32 轮（与 winlock in-place 同算法，**便于复用现有 stub.c 的 xtea_decrypt_buf**），密钥从 `KDF(password, salt)` 派生。KDF 在 MVP 阶段就是简单的 `SHA-256(password_utf8 + salt)`（与 in-place 同 KDF）。

**后期升级路径**：v2 用 ChaCha20-Poly1305 替换 XTEA，KDF 升级为 PBKDF2-HMAC-SHA256 100k 轮。payload.version 字段让 stub 能识别并兼容两种格式。

---

## 6. stub 架构（loader.c）

**MVP 阶段允许带 CRT** 简化开发（用 MinGW-w64 默认 CRT + `printf` 调试）。后期若要减小体积，可切换到 `-nostdlib -ffreestanding` PIC 模式。

整体流程（peldr 风格）：

```c
/* packer/reflective/loader.c - 反射式 stub 主体 */

/* 1. PEB walk 找 ntdll + kernel32（复用现有 find_module_by_hash） */
/* 2. 解析 ntdll 关键函数：NtAllocateVirtualMemory, NtProtectVirtualMemory,
 *    LdrLoadDll, LdrGetProcedureAddress, RtlAddFunctionTable,
 *    NtQueryInformationProcess, NtTerminateProcess */
/* 3. [后期] 反调试三阶段（flags & ANTIDEBUG）：
 *    PREAPI: PEB.BeingDebugged + NtGlobalFlag + KdDebuggerEnabled
 *    NTAPI:  NtQueryInformationProcess(ProcessDebugPort)
 *    GUARD:  在 image 前留 1 页 PAGE_NOACCESS guard page */
/* 4. 定位 .payload 节（hash 匹配节名），解析 reflective_payload_t 头 */
/* 5. 密码校验（默认 hash 模式）：
 *    - 测试模式：硬编码 L"test123" 走 KDF
 *    - 正常模式：弹 DialogBox（复用现有 build_dialog/dlg_proc）
 *    MVP: SHA-256(password_utf8 + salt) -> key，比对 pwd_hash
 *    后期: PBKDF2-HMAC-SHA256(password, salt, iters) -> key */
/* 6. 解密 payload（密文在 .payload 节，明文写入新分配内存）
 *    MVP: XTEA 解密（复用 xtea_decrypt_buf）
 *    后期: ChaCha20-Poly1305 解密 + tag 校验 */
/* 7. [后期] 可选 LZ4 解压 */
/* 8. 反射式映射：
 *    8a. NtAllocateVirtualMemory(preferred ImageBase, SizeOfImage)
 *        失败 fallback 任意地址（需重定位）
 *    8b. 复制 PE headers + 各节
 *    8c. 修复 IAT（含 forwarder 递归，借鉴 AlushPacker）
 *    8d. 应用 relocations（5 类型完整覆盖）
 *    8e. RtlAddFunctionTable 注册 .pdata
 *    8f. 初始化 SecurityCookie（仅当默认值时覆盖，复用现有 init_security_cookie）
 *    8g. 设置节权限（8 种组合查表）
 *    8h. 更新 PEB.ImageBaseAddress 指向新 image */
/* 9. [后期] 可选 ERASE_PE_HEADERS：清零新 image 的 SizeOfHeaders 字节 */
/* 10. 调用原 TLS callbacks（仅 DLL_PROCESS_ATTACH） */
/* 11. [后期] clear_fn_pointers() 清零解析的 API 指针（防 dump IAT） */
/* 12. jump_to_oep(image_base + oep_rva)  // 复用现有 jump_to_oep */
```

**关键模块来源**：
- `find_module_by_hash` / `find_export_by_hash` / `hash_ascii` / `hash_wstr_lower` → 直接复用现有 [stub.c:275-352](file:///c:/Home/Projects/applocker/packer/stub/stub.c#L275-L352)
- `jump_to_oep` → 直接复用 [stub.c:743-759](file:///c:/Home/Projects/applocker/packer/stub/stub.c#L743-L759)
- `init_security_cookie` → 复用 [stub.c:650-669](file:///c:/Home/Projects/applocker/packer/stub/stub.c#L650-L669)，但 `security_cookie_rva` 改为从新 image 的 LOAD_CONFIG 读
- `is_being_debugged` → 复用 [stub.c:688-708](file:///c:/Home/Projects/applocker/packer/stub/stub.c#L688-L708) + peldr 的 `NtQueryInformationProcess(ProcessDebugPort)` 扩展（后期阶段）
- `build_dialog` / `dlg_proc` / `prompt_password` → 改造现有 [stub.c:407-836](file:///c:/Home/Projects/applocker/packer/stub/stub.c#L407-L836)，密码校验改 KDF
- `xtea_decrypt_buf` → 直接复用 [stub.c:368-381](file:///c:/Home/Projects/applocker/packer/stub/stub.c#L368-L381)（MVP 阶段）
- ChaCha20-Poly1305 → 后期阶段新实现（header-only，约 2KB）
- PBKDF2-HMAC-SHA256 → 后期阶段，基于 [sha256.h](file:///c:/Home/Projects/applocker/packer/stub/sha256.h)，约 1KB
- LZ4 解压器 → 后期阶段，移植 lz4_flex 的 decompress，约 1KB
- 反射式 PE 映射主循环 → 新写，借鉴 peldr `loader.c:ProcessImage/MapImage/ApplyImageRelocations/ProcessImageImports/InitImageExceptionTable/SetImageSectionsPermission`

---

## 7. builder 架构（builder_reflective.c）

复用现有 [builder.c](file:///c:/Home/Projects/applocker/packer/builder/builder.c) 的：
- PE 解析（`OH()`/`OH_DATA_DIR()`/`rva_to_raw()` 等宏）
- 文件 IO（`read_file`/`write_file`）
- `gen_random_bytes` / `sha256_hash` / `wstr_to_utf8`
- 节追加逻辑
- `xtea_encrypt_buf`（MVP 阶段直接复用）

新增流程：

```c
/* packer/builder/builder_reflective.c - 反射式 builder */

int main(int argc, char* argv[]) {
    /* 1. 读输入 PE（任何架构：x86/x64/ARM64/.NET 都行，反射式不挑食）*/
    /* 2. [关键优势] 不检测 .NET CLR（反射式支持 .NET，这是相比 in-place 的重大优势） */
    /* 3. 读取原 PE 整体（in_size 字节）作为 plaintext */
    /* 4. [后期] 可选 LZ4 压缩 */
    /* 5. 生成 salt(16) + 随机 XTEA key（被 KDF 派生或直接随机）
     *    MVP: SHA-256(password_utf8 + salt) -> pwd_hash
     *         key = 随机 16 字节（CryptGenRandom），单独存入 payload
     *         key 用 password 加密一层（XTEA）保护
     *    后期: PBKDF2(password, salt, 100000) -> 32 字节 key
     *         SHA-256(key) -> pwd_hash 校验 */
    /* 6. XTEA 加密 plaintext -> ciphertext（复用现有 xtea_encrypt_buf） */
    /* 7. 构造 reflective_payload_t 头（magic/version/flags/sizes/...） */
    /* 8. 读预编译 stub EXE（winlock_reflective_x64.exe 或 _x86.exe）
     *    按输入 PE 架构选择，与 winlock_stub 选择方式一致 */
    /* 9. 在 stub EXE 末尾追加 .payload 节：
     *    - 新增节头（节名随机化或固定 .payload，避免 IOC）
     *    - 节内容 = reflective_payload_t + ciphertext
     *    - 更新 NumberOfSections/SizeOfImage
     *    - 清零 CheckSum */
    /* 10. 复制原 PE 的 .rsrc 节到 stub EXE（保留图标/manifest/版本信息）：
     *    用 LIEF 或手写 IMAGE_RESOURCE_DIRECTORY 三层遍历复制
     *    → 让加壳后 EXE 在 Explorer 显示原图标 */
    /* 11. 修改 stub EXE 的 AddressOfEntryPoint 指向 loader_entry
     *    （loader_entry 在 stub 编译时固定，builder 搜索 LOADER_ENTRY_MAGIC 定位）*/
    /* 12. 写输出 EXE */
}
```

---

## 8. dotnet packer 集成

新增 `dotnet/packer/stub/winlock_reflective_x64.exe.meta.json`：

```json
{
  "subsystem": "gui",
  "name": "winlock-reflective",
  "kind": "reflective-builder",
  "version": "1.0.0",
  "components": {
    "stub_x64": "winlock_reflective_x64.exe",
    "stub_x86": "winlock_reflective_x86.exe"
  },
  "supported_machines": ["amd64", "i386"],
  "description": "WinLock reflective packer (full PE encryption, memory mapping)"
}
```

**dotnet packer 改动**：
- `StubKind` 枚举新增 `ReflectiveBuilder`
- `StubRegistry.Select` 增加反射式优先级
- `PackCore.cs` 增加 `--stub-name winlock-reflective` 分支，调用 `winlock_reflective_builder.exe`（同现有 winlock builder 调用方式）
- `MainForm.cs` GUI 增加"反射式模式"选项

---

## 9. stub 体积预估（开发优先模式）

**MVP 阶段（带 CRT，便于开发）**：

| 模块 | 增量 |
|------|------|
| 基础反射式 loader（peldr 等价） | +4 KB |
| 完整 reloc 5 类型 | +200 B |
| forwarder 递归 + 延迟导入 | +600 B |
| XTEA 解密（复用现有） | +200 B |
| SHA-256（复用现有） | +1 KB |
| 8 种节权限查表 | +200 B |
| DialogBox 密码框（复用现有 build_dialog） | +1.5 KB |
| CRT 静态链接 + printf 调试 | +30-50 KB |
| **MVP stub 总体积** | **~40-60 KB** |

**后期完整阶段（PIC C 无 CRT）**：

| 模块 | 增量 |
|------|------|
| MVP 基础（剥离 CRT） | -30 KB（剥离 CRT） |
| ChaCha20-Poly1305 | +2 KB |
| PBKDF2-HMAC-SHA256 | +1 KB |
| LZ4 解压器 | +1 KB |
| 反调试三阶段 + scrub | +1 KB |
| PE header erasure | +200 B |
| **后期 stub 总体积** | **~15-20 KB**（PIC 无 CRT） |

**用户体积上限**：2MB。MVP 和后期阶段都远低于此上限，**有充足空间用于开发友好性**（如保留 CRT、保留 printf 调试、保留冗余函数）。

---

## 10. 加密强度演进对比

| 维度 | winlock in-place | winlock 反射式 MVP | winlock 反射式 后期 |
|------|------------------|------------------|---------------------|
| 加密算法 | XTEA 32 轮 | **XTEA 32 轮**（复用） | **ChaCha20-Poly1305**（AEAD 完整性） |
| KDF | SHA-256(pwd+salt) 1 轮 | **SHA-256(pwd+salt)**（复用） | **PBKDF2-HMAC-SHA256 100k 轮** |
| 加密范围 | 仅 `.text` 节 | **整个原 PE 文件** | **整个原 PE 文件** |
| 压缩 | 无 | 无 | **LZ4 可选**（flags.bit2） |
| 反 dump | 弱（.text 解密后明文在原位） | 中（payload 在 .payload 节加密） | **强**（新 image 可清零 headers、scrub 函数指针） |
| 反静态分析 | 中（PE 结构暴露） | **强**（PE 结构在密文里） | **强**（同左 + stub EXE 自身结构干净） |
| 反调试 | 可选（PEB 三件套） | **无**（开发优先） | **强**（三阶段 + scrub + ERASE_HEADERS） |

---

## 11. 反射式相比 in-place 的优势/劣势

**优势**：
1. **支持 .NET / Console / ARM64 EXE**（in-place 不支持，这是最大价值）
2. **整个原 PE 加密**，静态分析看不到 PE 结构
3. **可压缩**，LZ4 后体积可减小（后期）
4. **反 dump 强**（后期），新 image 可清零 headers、scrub 函数指针
5. **stub EXE 自身结构干净**，无 `.lock` 节特征
6. **资源保留**：builder 复制 `.rsrc` 节，Explorer 显示原图标

**劣势**：
1. **stub 体积大**（40-60KB MVP vs 6.5KB in-place，但用户已确认 2MB 内可接受）
2. **实现复杂度高**（反射式 PE 初始化 1500+ 行）
3. **兼容性风险**：手动 IAT/reloc/TLS/.pdata，任何 PE 特性不支持就崩
4. **`GetModuleHandle(NULL)` 返回 stub**，需 patch PEB.ImageBaseAddress
5. **被 EDR 监控概率高**（NtAllocateVirtualMemory + 跨节拷贝是反射式特征）

---

## 12. 实施计划（分阶段，开发优先排序）

> **重要**：阶段排序按"开发优先"原则，先跑通核心反射式 loader，再加加密强度，最后加反调试/反 dump。

### 阶段 1：MVP（最小可用反射式 loader）— 核心目标

**目标**：能反射式加载 notepad.exe 并跳 OEP，无加密、无密码框、无压缩。

- [ ] `reflective/loader.c` 实现 peldr 等价的反射式 loader
  - PEB walk 找 ntdll + kernel32（复用现有代码）
  - `NtAllocateVirtualMemory` 申请内存
  - 复制 PE headers + 各节
  - 修复 IAT（基础版，不含 forwarder 递归）
  - 应用 relocations（仅 DIR64，x64 PE 够用）
  - `RtlAddFunctionTable` 注册 .pdata
  - 初始化 SecurityCookie（复用现有）
  - 设置节权限（8 种查表）
  - 调用 TLS callbacks（仅 ATTACH）
  - `jump_to_oep`（复用现有）
- [ ] `reflective/payload.h` 定义 payload 容器格式
- [ ] `builder_reflective.c` 实现节追加 + payload 嵌入（明文不加密）
- [ ] **允许带 CRT**，用 printf 输出每一步状态便于调试
- [ ] **端到端测试**：反射式加载 notepad.exe 跳 OEP 成功

**验收**：能反射式加载 `temp/samples/Notepad4.exe` 跑起来。

---

### 阶段 2：完整 PE 初始化

**目标**：能跑通 `temp/samples/` 所有 GUI 样本（含 .NET、有 TLS callbacks、有 forwarder 的复杂 PE）。

- [ ] forwarder 递归解析（借鉴 AlushPacker `LdrpParseForwarderDescription`）
- [ ] 延迟导入表处理（`IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`）
- [ ] 完整 reloc 5 类型（ABS/DIR64/HIGHLOW/HIGH/LOW）
- [ ] 更新 PEB.ImageBaseAddress 指向新 image
- [ ] 资源保留：builder 端复制 `.rsrc` 节到 stub EXE
- [ ] dotnet packer 集成（meta.json + GUI 选项 + `--stub-name winlock-reflective`）

**验收**：`temp/samples/` 所有 GUI 样本 round-trip 通过。

---

### 阶段 3：加密 + 密码（MVP 加密版）

**目标**：原 PE 整体加密，弹密码框，输入正确密码才能解密反射式加载。

- [ ] payload 加密：**MVP 用 XTEA 32 轮**（复用现有 `xtea_encrypt_buf` / `xtea_decrypt_buf`）
- [ ] KDF：**MVP 用 SHA-256(password_utf8 + salt)**（复用现有，与 in-place 同 KDF）
- [ ] 密码校验：弹 DialogBox（复用现有 `build_dialog`/`dlg_proc`），SHA-256 比对
- [ ] payload.version=1，flags 标记 XTEA + SHA-256 模式
- [ ] 测试模式（flags & TEST）：硬编码 L"test123" 走 KDF，CI 自动化用

**验收**：加密 + 密码框 + 反射式加载完整流程跑通；CI 测试通过。

---

### 阶段 4：后期增强（按需进行，不阻塞主流程）

以下功能均为**可选编译开关**或**flags 位**，默认关闭，需要时再开：

- [ ] **压缩**：LZ4 解压器（flags & COMPRESS）
- [ ] **反调试**：PEB 三件套 + NtQueryInformationProcess + guard page（flags & ANTIDEBUG）
- [ ] **反 dump**：PE header erasure + 函数指针 scrub（flags & ERASE_HDR）
- [ ] **PIC 化**：剥离 CRT，切到 `-nostdlib -ffreestanding`（减小体积到 15-20KB）
- [ ] **反 hook**：RefreshNtdll 从 KnownDlls 重映射 ntdll .text（借鉴 AtomPePacker）
- [ ] **IAT 伪装**：CamouflageImports 让 stub IAT 看起来像普通 GUI 程序

---

### 阶段 5：测试与对比

- [ ] `temp/samples/` 所有样本 round-trip 测试
- [ ] 与 in-place 模式对比测试（同一组样本）
- [ ] .NET / Console / ARM64 样本专项测试（反射式独有优势验证）
- [ ] 性能测试：启动时间、内存占用对比

---

## 13. 关键风险与缓解

| 风险 | 缓解 |
|------|------|
| 反射式 PE 初始化兼容性 | 阶段 1 MVP 先跑通 notepad，逐步加样本；保留 in-place 模式作 fallback |
| 开发期踩坑多 | MVP 允许带 CRT + printf 调试，开发完成后再剥离 CRT |
| 加密实现错误 | MVP 复用现有 XTEA + SHA-256（已在 in-place 模式验证过），后期 ChaCha20 用 RFC 8439 测试向量验证 |
| TLS 静态变量不工作 | 阶段 2 仅做 ATTACH callback，文档明确不支持 `__declspec(thread)`；后期评估 AlushPacker TLS proxy |
| dotnet packer 集成复杂度 | 反射式 builder 作为独立 EXE（同 winlock_builder.exe 模式），dotnet packer 只做参数转发 |
| 反调试挡住自己调试 | 反调试始终是 flags 位 + 编译开关，默认关闭，仅 release 模式可开启 |

---

## 14. 核心设计决策记录

### 决策 1：stub 工具链 — MinGW-w64（可带 CRT）

**选择**：MinGW-w64，MVP 阶段允许带 CRT，后期可剥离。

**理由**：
- 与 winlock 现有 `stub.c` 同工具链（w64devkit + msys2 mingw32）
- MinGW-w64 支持 `-nostdlib -ffreestanding` PIC 模式，后期可平滑切换
- MSVC x64 不支持内联 asm（`jump_to_oep` 的 `andq/jmpq` 需要 ML64.exe 外部 .asm 文件）
- 开发优先：带 CRT 的 MinGW-w64 编译能直接用 printf 调试，比 MSVC 友好

### 决策 2：payload 容器 — 紧凑二进制头 + 魔数 + 版本

**选择**：紧凑二进制头（非 JSON），带 `MAGIC("WLOCKR\0\0") + VERSION(1) + FLAGS`。

**理由**：
- JSON 序列化在 stub 里实现重（pe-packer-rust 用 serde_json，stub 体积爆炸）
- 二进制头紧凑、stub 解析简单、可演进（version 字段）
- 与现有 `stub_data_t` 风格统一

### 决策 3：MVP 加密 — XTEA + SHA-256（复用现有）

**选择**：MVP 用 XTEA 32 轮 + SHA-256(pwd+salt)，与 in-place 同算法。

**理由**：
- **复用最大化**：现有 [stub.c](file:///c:/Home/Projects/applocker/packer/stub/stub.c) 的 `xtea_decrypt_buf` / `sha256_*` 直接拿来用
- **开发优先**：XTEA 30 行 C，简单可靠，已在 in-place 模式验证过
- **后期升级路径清晰**：payload.version=2 时切换到 ChaCha20-Poly1305 + PBKDF2，stub 通过 version 字段识别

### 决策 4：TLS 处理 — 仅 ATTACH callback（MVP）

**选择**：MVP 仅调用 DLL_PROCESS_ATTACH 的 TLS callbacks，不分配 TLS 数据块。

**理由**：
- 5 个参考项目全部这么做（peldr/AlushPacker/AtomPePacker/amber/pe-packer-rust）
- 完整 TLS proxy（AlushPacker 设计但未启用）复杂度高，MVP 不做
- 文档明确不支持 `__declspec(thread)` 静态 TLS（绝大多数 GUI 程序不用）

### 决策 5：跳 OEP — peldr 风格 16B 对齐 jmp

**选择**：直接复用 winlock 现有 `jump_to_oep`（已借鉴 peldr）。

**理由**：
- 已在 in-place 模式验证过
- 符合 x64 ABI（16B 栈对齐 + 40B shadow space）
- 用 jmp 而非 call，不压返回地址

### 决策 6：API hash — DJB15（复用现有）

**选择**：复用 winlock 现有 DJB15 hash 表（`HASH_GETPROCADDRESS` 等）。

**理由**：
- 已在 in-place 模式验证过
- `hash.py` 离线生成工具已存在
- 比 amber CRC32 硬件加速简单（无需 SSE4.2 依赖）

### 决策 7：反调试/反 dump — 后期可选

**选择**：MVP 不做反调试/反 dump，后期通过 flags 位 + 编译开关可选启用。

**理由**：
- **开发优先**：反调试会挡住自己的调试器，开发期极度不便
- peldr 的三阶段反调试 + scrub + ERASE_HEADERS 都是独立模块，后期加不影响核心流程
- 反调试始终默认关闭，仅 release 模式可开

---

## 15. 与现有 in-place 模式的协作关系

**两种模式并存**，由用户通过 `--stub-name` 选择：

| 模式 | `--stub-name` | 适用场景 | stub 体积 | 兼容性 |
|------|---------------|----------|-----------|--------|
| 临时文件模式（dotnet 默认） | `stub_gui` / `stub_console` | 任意 EXE，最兼容 | ~200KB | 最高 |
| in-place 加壳模式 | `winlock` | 仅原生 GUI EXE（x86/x64） | 6.5KB | 中 |
| **反射式 loader 模式**（新增） | `winlock-reflective` | 任意 EXE（含 .NET/Console/ARM64） | 40-60KB MVP | 中高 |

**共享代码**：
- `packer/common/config.h` — 共享常量、宏、stub_data_t 结构
- `packer/stub/sha256.h` — 共享 SHA-256 实现
- `packer/builder/builder.c` 中的 PE 解析、文件 IO、随机数生成等工具函数 → 抽取到 `packer/common/pe_shared.h` 让两个 builder 共用

**不互相干扰**：
- 现有 `builder.c` / `stub.c` 不修改（仅在必要时把公用函数抽到 `pe_shared.h`）
- 新增 `builder_reflective.c` / `reflective/loader.c` 完全独立
- dotnet packer 通过 meta.json 的 `kind` 字段区分三种模式

---

**文档版本**：1.0
**最后更新**：2026-07-19
**核心原则**：开发优先、加密反调试后置、stub 体积 ≤2MB、与 in-place 模式并存
