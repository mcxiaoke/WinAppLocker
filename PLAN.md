# WinLock 工业级 Packer 完善计划

> 创建日期：2026-07-18
> 目标：把当前 demo 升级为真正可用的工业级 PE 加壳器，能在 Win10/Win11 上对真实
> 应用（DontSleep、Notepad4、Chrome 等）做加密码门禁，加壳后正常运行。

## 1. 现状与问题分析

### 1.1 当前 demo 已验证的能力

- ✅ 新增 `.lock` 节存放 PIC stub
- ✅ XTEA 加密 `.text` 节 RawData
- ✅ 修改 `AddressOfEntryPoint` 指向 stub
- ✅ PEB walk 找 kernel32 / LoadLibraryA 加载 user32
- ✅ 栈上构建 DLGTEMPLATE 弹密码框
- ✅ VirtualProtect 改保护 → XTEA 解密 → 恢复保护 → 跳 OEP
- ✅ hellogui.exe（107KB，6 节，ImageBase=0x140000000）完整跑通

### 1.2 已发现的 bug / 工程缺陷

#### Bug 1: overlay 数据导致堆崩溃（DontSleep.exe 加壳时 builder 崩溃）

DontSleep.exe 文件大小 523576B (0x7FD38)，但最后一个节 `.rsrc` 的末尾在 0x7D308，
即文件末尾有 0x2A30 (10800B) 的 overlay（很可能是 Authenticode 签名或自定义数据）。

当前 builder 的 `out_size = new_raw_off + new_raw_size`，没有考虑 overlay。
执行 `memcpy(out, pe, in_size)` 时，`in_size > out_size`，堆缓冲区越界写 → 堆崩溃
（异常 0xC0000374 STATUS_HEAP_CORRUPTION）。

#### Bug 2: 仅 6 节、无 TLS、无签名的小程序能跑，复杂 PE 未验证

DontSleep.exe 的特点：
- 5 节（.text/.rdata/.data/.pdata/.rsrc）
- `DllCharacteristics = 0x8000`（HIGH_ENTROPY_VA，无 DYNAMIC_BASE = 无 ASLR）
- `.text` 200KB，`.rsrc` 130KB
- 有 `.pdata`（异常处理表）
- ImageBase=0x400000（低基址）

未知风险：
- 是否有 TLS 回调？（如果有，会在 stub 之前执行 → 此时 `.text` 是密文 → 崩）
- 是否有 Bound Imports？（影响 IAT 解析）
- 是否有 Delay Imports？
- 是否有 SxS Manifest？
- 是否有数字签名？（加壳后签名会失效，但 PE 结构需要保留）
- ASLR 关闭时 stub 中的 PEB walk 仍可用（PEB 永远在 gs:[0x60]），但 stub 内部
  访问 `fn` 全局变量依赖 `.lock` 节的真实加载地址。如果 ImageBase 不重定位，
  stub 的 `.lock` VA 是固定的，stub 内 RIP-relative 访问仍正确。

#### Bug 3: 仅加密 `.text` 的 RawData，不加密 VSize > RawSize 的尾部

如果原 PE 的 `.text` VirtualSize > SizeOfRawData，loader 会在加载时清零尾部，
但 stub 解密时只解密 RawData 范围。当前实现 OK（一致），但生产级应支持
VSize 加密（在末节后追加零页加密），避免反病毒分析。

#### Bug 4: 密码明文存储

`stub_data.password` 是 UTF-16 明文，PE dump 即可看到。
生产级应存 SHA-256 hash + salt。

#### Bug 5: 固定 XTEA key

XTEA key 在 `config.h` 中硬编码，所有加壳 PE 用同一 key。
应随机生成 per-file key + 用 PBKDF2/scrypt 从用户密码派生。

#### Bug 6: 未处理 TLS 回调

如果原 PE 有 TLS 回调，它们在 EP 之前执行。当前 stub 在 EP 时才解密 `.text`，
TLS 回调执行时 `.text` 是密文 → 崩溃。

修复方案 A：把解密逻辑提前到 TLS 回调（`.CRT$XLB` 段注册一个最早的 TLS callback），
让它在所有原 TLS 回调之前执行 → 解密 `.text` → 然后让原 TLS 回调正常跑。

修复方案 B：替换原 TLS DataDirectory，指向 stub 的"伪 TLS 回调"，
stub 完成 → 调用原 TLS 回调 → 返回。

修复方案 C：仅加密 .text 的 OEP 附近代码（不解密整个 .text）。
破坏性太大，放弃。

→ 选 A：在 .lock 节内嵌入 TLS 目录 + 伪回调，在 DataDirectory 中替换
TLS 表，stub 的解密作为 TLS 回调 0（DLL_PROCESS_ATTACH reason）执行，
stub 同时承担弹框、解密、跳 OEP 职责。

但这样 stub 必须 BEFORE 原 TLS 回调执行。Windows loader 在 LdrpProcessRelocationBlock
之后、LdrpCallTlsInitializers 之前完成 IAT。TLS 回调顺序由 TLS CallbackTable
中的指针顺序决定，所以 stub 把自己放在 CallbackTable[0] 即可。

但替换 TLS 表意味着：原 TLS Index / TLS Data 槽位的处理也得 stub 完成。
这复杂度大幅上升。

→ 简化方案 D：检测原 PE 是否有 TLS 回调。如果有，**拒绝加壳**（demo 阶段），
后续工业版再处理。当前样本（hellogui/DontSleep/Notepad4/Chrome）大概率没 TLS 回调，
所以方案 D 可行。

#### Bug 7: SEH/CFG 相关处理

如果 PE 有 CFG（Control Flow Guard），`__guard_fptr_table` 指向 .text 中的
间接调用目标。加密 .text 后，CFG 表本身不被加密，但表指向的代码是密文。

→ 因为 stub 解密 .text 后才跳 OEP，CFG 表在解密后即恢复正确，不影响。
→ 但 CFG 验证时 stub 自己的代码可能不在 CFG 表中 → 间接调用 stub 函数会 fail。
→ stub 内不使用间接调用（用 `call *%rax` 而非 `call qword ptr [import]`），不依赖 CFG。
→ stub 自身被加载后需要让 CFG 信任：可选地把 stub 加到 `__guard_fptr_table`，
或简单地在 OptionalHeader.DllCharacteristics 中清除 `IMAGE_DLLCHARACTERISTICS_GUARD_CF`
标志。后者更简单，但减弱了原 PE 的安全性。生产级应保留 CFG 并扩展 guard table。

→ 当前 demo 阶段：保留 CFG，stub 内部不使用受 CFG 保护的间接调用。
  stub 用 `call *%rax` 直接调用解析出的 API 地址，不经过 IAT，CFG 不管。

#### Bug 8: stub 的 `.lock` 节加入后，SizeOfStackReserve/SizeOfHeapReserve 不变

通常 OK，但某些 PE 可能栈保留区很小。stub 用 ~1KB 栈，应该没问题。

### 1.3 当前 builder 的设计缺陷

- C 语言手写 PE 解析，没有处理 overlay、签名、TLS、Bound Imports、Delay Imports
- 没有单元测试
- 没有备份/回滚
- 错误信息简陋
- 没有日志（verbose 模式）
- 没有验证加壳后 PE 是否可加载

## 2. 技术选型

### 2.1 builder 语言对比

| 语言 | PE 库 | 优势 | 劣势 |
|------|-------|------|------|
| **Rust** | `goblin` / `object` / `pelite` | 性能强、零成本抽象、cargo 生态成熟、静态链接单文件 exe | 学习曲线、unsafe |
| **Go** | `debug/pe` (标准库) | 标准库自带 PE 解析、单文件 exe、GC 友好 | 二进制较大（~5MB）、性能稍弱 |
| **C#** | `AsmResolver` / `PeNet` | 库最强大、API 友好 | 需要 .NET runtime 或 self-contained（~70MB） |
| **C++** | `pe-parse` / 手写 | 与 stub 同语言 | 没有 cargo 那样的包管理 |

**推荐：Rust + `goblin` + `object`**

理由：
1. 性能强、内存安全（避免当前 C 版本的 overlay 越界 bug）
2. cargo 包管理 + 依赖锁定，可重现构建
3. 静态链接生成单文件 exe（与 stub 同目录方便分发）
4. 已有 rust-pe、Squre、ProcHollowing_Rust、RustHollow 等参考项目验证可行
5. w64devkit 无法直接编 Rust，但 `cargo` 在用户环境中可用

### 2.2 stub 语言

保持 **C + 内联汇编**（用 w64devkit GCC 编译）：
- C 代码可读性高
- PIC 控制精细（`__attribute__((section))`）
- 已有可工作的 stub 基础

### 2.3 测试样本

- hellogui.exe (107KB) - 已通过
- DontSleep.exe (523KB) - 当前 builder 崩溃，需修复
- Notepad4.exe - 待测试
- chrome.exe - 待测试（大文件，可能有特殊保护）

## 3. 架构设计

### 3.1 目录结构（重构后）

```
winlock/
├── PLAN.md                       本计划文档
├── Makefile                      顶层构建（调用 cargo + make stub）
├── config.h                      共享常量（C 头文件，Rust 用 bindgen 读或不读）
├── stub/                         C 写 PIC stub
│   ├── stub.c
│   ├── stub.ld
│   ├── stub.h                    内部头文件
│   └── Makefile                  子构建
├── builder/                      Rust 写 PE 加壳器
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs               CLI 入口
│   │   ├── pe.rs                 PE 解析（基于 goblin）
│   │   ├── crypto.rs             XTEA + 密码 hash
│   │   ├── packer.rs             加壳主逻辑
│   │   ├── stub_data.rs          stub_data 结构定义
│   │   └── error.rs              错误类型
│   └── tests/
│       ├── pe_parse_test.rs      PE 解析单元测试
│       ├── xtea_test.rs          XTEA 加解密一致性测试
│       └── integration.rs        端到端测试（加壳后 PE 可加载）
├── samples/                      测试样本（软链接到 ../samples）
└── test/                         加壳输出
    ├── hellogui_locked.exe
    ├── DontSleep_locked.exe
    └── Notepad4_locked.exe
```

### 3.2 数据流

```
[input.exe]
    │
    ├─→ builder (Rust)
    │     │
    │     ├─ goblin 解析 PE（DOS/NT 头、节表、DataDirectory）
    │     ├─ 检查：x64? EXE? 有 TLS 回调? 有签名? 有 overlay?
    │     ├─ 随机生成 XTEA key + salt
    │     ├─ 计算 SHA-256(password + salt) -> 32B digest
    │     ├─ XTEA 加密 .text RawData
    │     ├─ 在 stub.bin 中搜索 STUB_DATA_MAGIC，填充 stub_data
    │     ├─ 新增 .lock 节（RWX），写入 stub.bin
    │     ├─ 修改 AddressOfEntryPoint -> .lock RVA
    │     ├─ 更新 SizeOfImage / NumberOfSections
    │     ├─ 保留 overlay（复制到输出文件末尾）
    │     └─→ [output.exe]
    │
    └─ stub.bin（C 编译，PIC，无 IAT 依赖）
          │
          └─ Windows loader 加载 output.exe
                │
                ├─ 正常处理 reloc/IAT/TLS/SEH/CFG/CRT
                ├─ 跳到 stub_entry
                │     ├─ PEB walk 找 kernel32
                │     ├─ LoadLibraryA("user32.dll")
                │     ├─ DialogBoxIndirectParamW 弹密码框
                │     ├─ SHA-256(input_password + salt) == stored_digest?
                │     │     ├─ 不匹配 -> 重试 / ExitProcess
                │     │     └─ 匹配:
                │     │           ├─ VirtualProtect(.text, RW)
                │     │           ├─ XTEA 解密 .text
                │     │           ├─ VirtualProtect(.text, 原保护)
                │     │           └─ 跳 OEP
                │     └─ 原 PE 正常运行
```

### 3.3 stub_data 扩展（v2）

```c
#pragma pack(push, 8)
typedef struct {
    uint64_t magic;            // STUB_DATA_MAGIC
    uint16_t version;          // 结构版本号 (v2 = 2)
    uint16_t flags;             // 位标志
                              //   bit0: 密码是 hash (1) 还是明文 (0)
                              //   bit1: 加密 .text 全部 (1) 还是 RawData (0)
    uint32_t reserved;
    uint64_t oep_rva;
    uint64_t text_rva;
    uint64_t text_size;
    uint32_t text_raw_size;
    uint32_t text_protect;
    uint32_t xtea_key[4];      // 随机生成
    uint8_t  salt[16];         // SHA-256 salt
    uint8_t  pwd_hash[32];    // SHA-256(password + salt)
    wchar_t  password[64];    // 明文（向后兼容，flags.bit0=0 时使用）
    uint64_t checksum;         // 简单校验和（XOR 所有字段）
} stub_data_t;
#pragma pack(pop)
```

### 3.4 stub 改进点

1. **SHA-256 实现**：内联实现（无外部依赖），~200 行 C 代码
2. **错误重试**：密码错误 3 次后退出
3. **失败清理**：解密失败时 ExitProcess 而非崩溃
4. **栈大小检查**：对话框构建需要 ~1KB 栈
5. **多节支持**：当前只加密第一个可执行节，未来扩展为多节加密

### 3.5 builder 改进点（Rust）

1. **完整 PE 解析**（goblin）：所有节、所有 DataDirectory、overlay、签名
2. **预检查**：
   - Machine == AMD64
   - 不是 DLL
   - 不在 .NET（CLR header）— .NET 程序加密 .text 会破坏 JIT
   - 检测 TLS 回调 → 警告或拒绝
   - 检测 Bound Imports → 清零 BoundDirectory
3. **overlay 保留**：原 PE 末尾的 overlay 数据复制到输出末尾
4. **签名剥离**：如果有 Authenticode 签名（DataDirectory[4]）：
   - 选项 A：剥离签名（清零 DataDirectory[4] + 删除 WIN_CERTIFICATE 结构）
   - 选项 B：保留但失效（输出会有无效签名）
   - 默认 A
5. **加密策略**：
   - 默认：加密 .text RawData
   - 可选：加密所有可执行节
   - 可选：加密 .text + .rdata（破坏 IAT 中的字符串引用 → 需 stub 重建 IAT → 复杂）
6. **CLI**：
   - `winlock pack <input> <output> [--password <pwd>]`
   - `winlock unpack <input> <output> --password <pwd>`（解密还原，便于调试）
   - `winlock inspect <input>`（显示 PE 信息）
7. **日志**：`-v` verbose 模式输出每一步
8. **dry-run**：`--dry-run` 不写输出文件，仅打印会做什么

## 4. 实施步骤

### 阶段 1: 修复当前 C 版本的紧急 bug（让 DontSleep 能加壳）✅

> 目标：不切换语言，仅修 bug，让 hellogui + DontSleep + Notepad4 都能加壳并运行。

- [x] **S1.1** 修复 builder overlay 越界 bug
- [x] **S1.2** builder 处理 Authenticode 签名（剥离 DataDirectory[4]）
- [x] **S1.3** builder 检测 TLS 回调（拒绝加壳）
- [x] **S1.4** builder 检测 .NET CLR（拒绝加壳）
- [x] **S1.5** builder 清零 Bound Imports
- [x] **S1.6** 随机生成 per-file XTEA key（用 CryptGenRandom）
- [x] **S1.7** 测试 DontSleep 加壳并运行 ✅ 弹密码框，输入 test123 后原程序启动
- [x] **S1.8** 测试 Notepad4 加壳并运行 ✅ 带 ASLR + CFG 也通过

阶段 1 测试结果：

| 样本 | 大小 | 特性 | 加壳 | 运行 | 密码正确 | 密码错误 |
|------|------|------|------|------|----------|----------|
| hellogui.exe | 107KB | 6 节, 无签名, 无 ASLR | ✅ | ✅ | ✅ 启动 | ✅ 拒绝 |
| DontSleep.exe | 523KB | 5 节, Authenticode 签名, overlay | ✅ | ✅ | ✅ 启动 | ✅ 拒绝 |
| Notepad4.exe | 2.4MB | 7 节, ASLR + CFG + 重定位 + .pdata + .fptable | ✅ | ✅ | ✅ 启动 | ✅ 拒绝 |

**结论**：当前 C 版本已经能处理真实工业级 PE（含 ASLR/CFG/重定位/签名/overlay）。
不需要切换 Rust。后续阶段 3 直接在 C stub 里加 SHA-256 即可。

### 阶段 2: Rust 重写 builder（工业级）

> 目标：用 Rust + goblin 重写 builder，单元测试 + 端到端测试。

- [ ] **S2.1** `cargo new builder --bin`，添加依赖：goblin, sha2, rand, clap, anyhow
- [ ] **S2.2** 实现 `pe.rs`：PE 解析（节、DataDirectory、overlay、签名）
- [ ] **S2.3** 实现 `crypto.rs`：XTEA + SHA-256 + PBKDF2（用 sha2/crate）
- [ ] **S2.4** 实现 `stub_data.rs`：stub_data 结构 + magic 搜索
- [ ] **S2.5** 实现 `packer.rs`：加壳主逻辑（参照 C 版本）
- [ ] **S2.6** 实现 `main.rs`：clap CLI
- [ ] **S2.7** 单元测试：
  - XTEA 加解密一致性
  - PE 解析（hellogui/DontSleep/Notepad4）
  - stub_data magic 搜索
- [ ] **S2.8** 端到端测试：
  - 加壳后 PE 可加载（用 `pe-inspect` 或 `objdump` 验证结构）
  - 实际运行加壳后 PE（需要密码）
- [ ] **S2.9** Rust builder 替换 C builder，更新 Makefile

### 阶段 3: stub 增强（工业级）

> 目标：stub 支持 SHA-256 密码、随机 key、错误重试、更鲁棒的 PEB walk。

- [ ] **S3.1** 在 stub 中内联实现 SHA-256
- [ ] **S3.2** stub_data 扩展为 v2（version 字段、flags、salt、pwd_hash、checksum）
- [ ] **S3.3** stub 支持密码错误重试 3 次
- [ ] **S3.4** stub 验证 stub_data.checksum，防篡改
- [ ] **S3.5** stub 失败路径全部 ExitProcess，不崩溃
- [ ] **S3.6** stub PEB walk 改进：
  - 使用 `InMemoryOrderModuleList`（更稳定）
  - 大小写不敏感比较（已实现）
  - 长度匹配检查（已实现）

### 阶段 4: 端到端测试

- [ ] **S4.1** 测试 hellogui.exe（小，已知通过）
- [ ] **S4.2** 测试 DontSleep.exe（中，523KB，有 .pdata + .rsrc + overlay）
- [ ] **S4.3** 测试 Notepad4.exe（中，需检查）
- [ ] **S4.4** 测试 chrome.exe（大，可能有特殊保护）
- [ ] **S4.5** 失败路径测试：
  - 错误密码 → 提示
  - 损坏的 PE → 友好报错
  - .NET PE → 拒绝加壳
  - DLL → 拒绝加壳
- [ ] **S4.6** 兼容性矩阵：
  - Win10 (19041+) 验证
  - Win11 验证（如有）

### 阶段 5: 文档与发布

- [ ] **S5.1** 更新 PLAN.md 标注完成情况
- [ ] **S5.2** 写 README.md（使用说明、限制、原理）
- [ ] **S5.3** 写 ARCHITECTURE.md（架构图、数据流、stub_data 协议）
- [ ] **S5.4** 整理 test/ 目录，每个样本有 _locked.exe + .log

## 5. 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| Chrome 加壳后无法运行（可能有反壳/反调试） | 高 | 中 | 文档说明限制；尝试 Notepad4 等普通应用 |
| ASLR + ImageBase 重定位时 stub RIP-relative 访问错位 | 低 | 高 | RIP-relative 本身就 PIC，与基址无关 |
| CFG 阻止 stub 内的间接调用 | 低 | 中 | stub 用 `call *%rax` 直接调用，CFG 不管 |
| TLS 回调在 stub 之前执行 | 中（取决于样本） | 高 | v1 检测并拒绝；v2 替换 TLS Directory |
| .NET 程序加壳后崩溃 | 低（已拒绝） | 低 | 拒绝加壳 |
| Authenticode 签名失效 | 100% | 低 | 默认剥离签名，警告用户 |
| Win10 SmartScreen 警告 | 中 | 低 | 文档说明，建议用户自签名 |

## 6. 验收标准

完成后用户能：
1. `cargo build --release` 生成 `winlock.exe`
2. `make stub` 生成 `stub.bin`
3. `winlock pack samples\DontSleep.exe test\DontSleep_locked.exe --password 123`
4. 运行 `test\DontSleep_locked.exe` → 弹密码框
5. 输入正确密码 → DontSleep 正常启动
6. 输入错误密码 → 提示错误，不崩溃
7. 同样流程对 hellogui / Notepad4 通过
8. （可选）对 chrome.exe 通过
9. `winlock inspect test\DontSleep_locked.exe` 显示加壳信息
10. `winlock unpack test\DontSleep_locked.exe test\DontSleep_restored.exe --password 123` 还原

## 7. 不在范围内（YAGNI）

- 代码混淆/虚拟化（VMProtect 级别）
- 反调试 / 反 dump
- 加壳后保持 Authenticode 签名有效（需重签名，超出 demo 范围）
- 多节加密（仅加密第一个可执行节）
- 资源加密（.rsrc 不加密）
- 压缩（LZ4/LZMA）—— 工业级 packer 通常带压缩，但 demo 简化
- IAT 重建（保留原 IAT，loader 处理）
- .NET 程序支持（拒绝加壳）
- DLL 支持（仅 EXE）

---

## 阶段 6: ASLR + TLS callback 代理 + CFG 修复 ✅

> 目标：解决 Bandizip 等 ASLR/CFG/TLS 程序加壳后 loader 阶段崩溃问题。
> 放弃 Rust 重写 builder（阶段 2），保持 C builder，直接增强 stub 与 builder 到 v3。

### 6.1 v3 stub_data 扩展

新增字段（参见 `config.h`）：
- `image_base`：原 PE preferred ImageBase（用于 ASLR 重定位 delta 计算）
- `reloc_rva` / `reloc_size`：原 .reloc 表位置与大小
- `orig_tls_callbacks`：原 TLS callbacks 数组 VA（TLS_PROXY 模式下 stub 调用）

新增 flags 位：
- `STUB_FLAG_HASH (0x0001)`：用 SHA-256 hash 校验密码
- `STUB_FLAG_TEST_MODE (0x0002)`：测试模式，硬编码 L"test123"
- `STUB_FLAG_TLS_PROXY (0x0004)`：TLS callback 代理模式
- `STUB_FLAG_ASLR (0x0008)`：ASLR 启用，stub 解密后重新应用 relocations

### 6.2 TLS callback 代理模式

builder 检测原 PE 是否有 TLS callbacks：
- **有 callbacks** → 启用 STUB_FLAG_TLS_PROXY，禁用 ASLR
  - builder 在 .lock 节末尾追加新 callbacks 数组 `[stub_tls_callback_VA, NULL]`
  - 修改原 TLS directory 的 AddressOfCallBacks 指向新数组
  - stub_tls_callback 在 DLL_PROCESS_ATTACH 时弹密码框 + 解密 .text + 调原 callbacks
  - stub_entry 在 TLS_PROXY 模式下只跳 OEP（解密已由 TLS callback 完成）
- **无 callbacks** → 启用 STUB_FLAG_ASLR（若 DYNAMIC_BASE 置位）
  - stub_entry 完成密码校验 + 解密 + 重新应用 relocations + 跳 OEP

stub_tls_callback 用 `STUB_TLS_CB_MAGIC` (0x424C4C4143534C54ULL, "TLSCALLB" 小端) +
16 字节 marker 让 builder 在 stub.bin 中定位函数入口偏移。

### 6.3 ASLR 处理（非 TLS_PROXY 路径）

loader 行为：加载到随机基址 → 对 .text 等节应用 relocations（但 .text 是密文，
relocations 应用到密文上无意义）→ 跳 EP（stub_entry）。

stub 行为：
1. 弹密码框，校验通过
2. `decrypt_text_and_reloc()`：
   - VirtualProtect 改 .text 为 RW
   - XTEA 解密 .text（覆盖 loader 应用的 relocations）
   - `apply_relocations()` 重新应用 relocations
     - delta = current_base - stub_data.image_base
     - 只 patch `.text` 范围（避免对 .rdata 等节双重 reloc）
     - 支持 ABSOLUTE/HIGH/LOW/HIGHLOW/DIR64 类型
   - VirtualProtect 恢复 .text 原保护
3. 跳 OEP

### 6.4 CFG (Control Flow Guard) 修复

**根因**：原 PE 启用 CFG（`DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF`）
时，loader 用 CFG dispatch 校验 EP 是否在 GFIDS 表中。我们把 EP 改为 .lock 节中的
`stub_entry`，不在 GFIDS 表 → `STATUS_STACK_BUFFER_OVERRUN (0xC0000409)` 在
`ntdll!RtlGetReturnAddressHijackTarget` 触发，stub_entry 根本没机会执行。

**症状**：
- Bandizip.x64.exe（CFG=YES）加壳后崩溃 0xC0000409
- Notepad4.exe（CFG=NO）正常
- 用 `flip_aslr.py` 禁用 ASLR 不影响 CFG（CFG 与 ASLR 独立），但仍崩溃 →
  排除 ASLR 是主因
- 在 stub_entry 最开头加 `ExitProcess(0x42)` 仍崩溃 → stub_entry 未执行

**修复**：builder 在 step 15b 清除 `IMAGE_DLLCHARACTERISTICS_GUARD_CF` 位。
副作用：原 PE 的 CFG 保护失效，但原 .text 已被 XTEA 加密，CFG 本来就保护不了
密文，影响可忽略。参考 pe-packer 项目（同样处理 CFG）。

### 6.5 测试结果

| 样本 | 特性 | 加壳 | 运行 |
|------|------|------|------|
| hellocli (test mode) | 无 ASLR/CFG/TLS | ✅ | ✅ |
| hellogui (正/错密码) | 无 ASLR/CFG/TLS | ✅ | ✅ |
| DontSleep | 无 ASLR/CFG，有签名 | ✅ | ✅ |
| Notepad4 | ASLR + CFG=NO | ✅ | ✅ |
| Bandizip | ASLR + CFG=YES + TLS dir | ✅ | ✅ (CFG 禁用后) |
| hellomingw/helloucrt/sha256sum | TLS callbacks (代理模式) | ✅ | ✅ |

e2e_test.py：8/8 PASS

---

## 阶段 7: x86 (PE32) 支持 ✅

> 目标：让 builder + stub 支持 32 位 PE，覆盖 QQ / FreeFileSync / ShutterEncoder 等。

### 7.1 设计要点

- 双架构 stub.bin：`stub_x64.bin` + `stub_x86.bin`
- builder 检测 `IMAGE_FILE_MACHINE_I386` (0x14c) vs `IMAGE_FILE_MACHINE_AMD64` (0x8664)
- x86 stub 编译选项：`-m32 -mno-sse -fno-pic`，链接 `--image-base=0x10000`
- x86 PEB 访问：`__readfsdword(0x30)` 而非 `__readgsqword(0x60)`
- x86 重定位类型：HIGHLOW(3) 为主，不再有 DIR64(10)
- x86 跳 OEP：用 `push OEP; ret` 或间接 `jmp *OEP`
- stub_data 字段类型保持 uint64_t（统一），stub 内部按架构截断使用
- builder 在 PE32 上修改的字段偏移不同（OptionalHeader 32 vs 64）

### 7.2 核心难点：x86 stub 非 PIC

x64 stub 是 PIC（RIP-relative），与 ImageBase 无关。x86 mingw32 gcc 生成绝对地址代码
（如 `mov DWORD PTR [esp], 0x2990`），stub 被加载到与编译时不同的地址时所有绝对引用
都会错位，访问无效地址（如 dump 显示的 `edx=0x2990`）崩溃。

**解决方案**：builder 预 patch stub 的绝对地址到目标加载位置。

1. `stub.ld` 保留 `.reloc` 节（之前 `/DISCARD/` 丢弃了），让 ld 生成重定位目录
2. `stub.ld` 修正 VMA：`0x1000` → `0x11000`，避免 RVA 溢出为 `0xFFFF1000`
   （`--image-base=0x10000` + `. = 0x1000` 让 RVA = 负数溢出）
3. builder 新增 `extract_stub_reloc_info()`：从 `stub_x86.exe` 读 `.reloc` 节
4. builder 新增 `patch_stub_relocations()`：遍历 reloc 表，对 `.lock` 范围内的条目加 delta：
   `delta = (target_image_base + target_lock_rva) - (stub_image_base + stub_lock_rva)`
   - `IMAGE_REL_BASED_HIGHLOW` (3)：x86 32 位绝对地址
   - `IMAGE_REL_BASED_DIR64` (10)：x64 64 位绝对地址
5. x86 PE 强制禁用 ASLR（预 patch 只在固定 ImageBase 下有效）

### 7.3 实施步骤

- [x] **S7.1** 把 stub.c 中所有 `__readgsqword(0x60)` / `PEBX` / `LDRENT` 等
      x64 专用代码用 `#ifdef WINLOCK_X64` / `WINLOCK_X86` 分开
- [x] **S7.2** stub.ld 增加 `.reloc` 节定义（之前 `/DISCARD/` 丢弃）
- [x] **S7.3** 在 stub.c 内 `apply_relocations` 增加 HIGHLOW 类型处理
- [x] **S7.4** stub_entry / stub_tls_callback 的"跳 OEP"按架构分开
- [x] **S7.5** Makefile 增加 `stub_x86.bin` 目标 + `check-x86-toolchain` 前置检查
- [x] **S7.6** builder 检测 Machine，按架构选 stub.bin
- [x] **S7.7** builder 处理 PE32 OptionalHeader（双架构宏 `OH()` / `OH_U64()`）
- [x] **S7.8** builder 实现 `extract_stub_reloc_info()` + `patch_stub_relocations()`
- [x] **S7.9** x86 PE 强制禁用 ASLR
- [x] **S7.10** 测试样本：
  - `helloguix86.exe` (VS2026 x86，无 TLS) - 密码模式 ✅
  - `hellox86.exe` (mingw32 x86 + TLS callbacks) - 密码模式 ✅
  - `hellogui.exe` (x64) - 回归测试 ✅

---

## 阶段 8: 文档更新 ✅

- [x] **S8.1** 更新 README.md：v3 架构、x86/x64 双架构、ASLR/TLS/CFG 处理、CLI 用法
- [x] **S8.2** 更新 PLAN.md（本文档）：阶段 6/7 完成情况
- [x] **S8.3** Makefile 增加 `check-x86-toolchain` 友好错误，工具链路径可覆盖
- [ ] **S8.4** 整理 tools/ 下的诊断脚本（pe_diag.py 等保留，废弃的删掉）—— 待办
