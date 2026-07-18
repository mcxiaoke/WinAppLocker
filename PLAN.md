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
- TLS 回调支持（v1 检测并拒绝，v2 再做）
- .NET 程序支持（拒绝加壳）
- 32 位 PE 支持（仅 x64）
- DLL 支持（仅 EXE）
