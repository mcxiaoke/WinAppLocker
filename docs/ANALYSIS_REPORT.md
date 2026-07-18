# PE 加壳项目深度对比分析报告

> 创建日期：2026-07-18
> 分析对象：F:\Temp\pe 下 12 个开源 PE 加壳项目
> 视角：winlock（in-place PE 加壳器，PIC C + 内联汇编，无 CRT，PEB walk 找 kernel32，加密 .text 节，跳 OEP）
> 方法：4 个 subagent 分批深读源码，每个项目覆盖 builder + stub/loader 核心代码

---

## 0. 重要前提

12 个项目里只有 **2 个是真正的 in-place 加壳**：
- **pe-packer-master**（C++ JIT emit PIC 汇编，加新节，改 EP）
- **Windows-PE-Packer-master**（C，加 `.shell` 节，但默认不应用 reloc — 是反例）

其余 10 个都是反射式 loader / RunPE / Shellcode 注入：
- PEPacker2、pe-packer-rust、TinyLoad、WinXRunPE、PeLoader、peldr、MaldevAcademyLdr、AlushPacker、PEzor、AtomPePacker

**反射式 loader 的"PE 初始化"逻辑（IAT 解析 / reloc 应用 / .pdata 注册 / TLS index 分配 / 节权限设置 / 转发导出）对 in-place 加壳完全不需要** — Windows loader 在 in-place 场景下已经全部做完。所以本报告只提取对 in-place 加壳真正有意义的设计和代码。

---

## 1. 12 项目全景对比矩阵

| 项目 | 加壳方式 | 是否 in-place | stub 语言 | 架构 | Crypto | KDF | API Hash | 反调试 | TLS 代理 | .pdata | Reloc | 资源保留 | 反 dump | 对 winlock 价值 |
|------|---------|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **PEPacker2** | 反射式（资源嵌入） | NO | C+CRT | x86 | AES-CBC+Gzip+Base32 | 无 | 无 | 无 | 部分 | RtlAddFunctionTable | 完整 switch | 无 | 无 | **NO** |
| **pe-packer-rust** | 反射式（新节嵌入） | NO | Rust | x64 | AES-256-GCM+LZ4 | **Argon2** | 无 | 无 | 无 | 无 | HIGHLOW/DIR64 | 无 | Zeroize | **部分**（KDF 思路） |
| **TinyLoad** | 反射式自嵌套 | NO | C++ | x64 | XXTEA+VM 字节码 | 无 | **sdec2 XOR** | **5 项** | 无 | 无 | DIR64 | cloneRes | **VEH/stub-key/canary/scramble** | **高**（反静态宝库） |
| **pe-packer-master** | **in-place** JIT | **YES** | C++ JIT emit | x86+x64 | XOR only | 无 | 无 | 无 | 无 | 无 | **-noaslr+XOR reloc** | 隐式 | **adasm 花指令/MBA** | **高**（架构 + 花指令） |
| **WinXRunPE** | Process Hollowing | NO | C# | x86+x64 | 无 | 无 | 无 | 无 | 无 | 无 | 不处理 | 无 | 无 | **NO** |
| **PeLoader** | 反射式 | NO | C+CRT | x86 | 无 | 无 | 无 | 无 | 无 | 无 | HIGHLOW only | 无 | 无 | **低**（概念） |
| **peldr** | 反射式 overlay | NO | C -nostdlib PIC | x64 | 自定义流密码 | 无 | **DJB15** | **PEB+Kd+guard page** | ATTACH only | 无 | DIR64 only | 无 | **header erasure/清零** | **高**（同风格 PIC） |
| **MaldevAcademyLdr** | 反射式+反 EDR | NO | C+CRT+D3D11 | x64 | **AES-NI CTR** | 无 | **FNV-1a** | 无（靠 syscall） | ATTACH only | RtlAddFunctionTable | 完整 | 手动遍历 | **VRAM/section fluct** | **中**（AES-NI + 资源遍历） |
| **AlushPacker** | 反射式 .packed | NO | C+CRT | x86+x64 | XTEA 32 轮 | strtoul（极弱） | 无 | 无 | `.CRT$XLB` 4 Reason | RtlAddFunctionTable | **完整 5 类型** | 无 | 无 | **中**（x86 reloc + cookie 逻辑） |
| **Windows-PE-Packer** | **in-place** .shell | YES | C+ASM | x86 | `+0xCC`（玩具） | 无 | 无 | 无 | 无 | 复制 dir | **反例：不应用 reloc** | overlay | 清零节名 | **中**（反例参考） |
| **PEzor** | RunPE 注入 | NO | C++ | x86+x64 | XOR+FQDN | 无 | 无 | **3 项 PEB** | 无 | 无 | 完整 | 无 | **Sleep fluct** | **低**（仅反调试思路） |
| **AtomPePacker** | RunPE 重映射 | NO | C+CRT | x64 | LZMA only | 无 | **Rotr32** | 仅 OS 版本 | 主动调用 | RtlAddFunctionTable | 完整 5 类型 | 无 | **IAT Camouflage/header 清零** | **高**（API hash + IAT 伪装） |

---

## 2. 按项目逐个深度分析

### 2.1 PEPacker2-master

**加壳方式**：反射式 loader（资源嵌入）
**架构**：x86 only
**stub 语言**：C + CRT

**流程**：
- Builder（`PEPacker/main.cpp`）把整个目标 PE 用 AES-CBC + Gzip + Base32 加密压缩，通过 `UpdateResource` 嵌入 stub 的 `PACKER` 资源段（分块 0x10000 字节）
- Stub（`PEStub/main.cpp`）从资源读密文 → 解密解压 → `VirtualAlloc(preferred ImageBase)` → 拷贝 PE 头+节 → 修 IAT → 应用 reloc → `RtlAddFunctionTable` 注册 .pdata → 设节权限 → 调 TLS callbacks → `CreateThread(EP)` 跳 OEP
- 加密 key 从外部 `LICENSE.txt` 读（hardcoded fallback 路径 `%TEMP%\LICENSE.txt`）

**可借鉴点**：
1. Reloc 完整 switch（HIGHLOW/DIR64/HIGH/LOW/ABSOLUTE）— `PEStub/main.cpp:428-478`。但 winlock 的 `apply_relocations`（`stub.c:480-555`）已更精细（只 patch .text 范围避免双重 reloc）
2. TLS callbacks 遍历调用 — `PEStub/main.cpp:582-592`。但 winlock 的 `stub_tls_callback`（`stub.c:741-788`）已更完整（代理模式 + orig_tls_callbacks 中转）
3. RtlAddFunctionTable 注册 .pdata — `PEStub/main.cpp:531-545`。反射式专属，in-place 不需要
4. 两次 VirtualAlloc 容错（preferred → fallback NULL）— 反射式专属

**关键代码引用**：
- [PEPacker2 main.cpp](file:///F:/Temp/pe/PEPacker2-master/PEPacker/main.cpp)
- [PEPacker2 PEStub main.cpp](file:///F:/Temp/pe/PEPacker2-master/PEStub/main.cpp)

**结论**：**不可移植**。所有逻辑都是反射式专属。安全 Cookie、栈对齐、API hash、反调试全都没实现。

---

### 2.2 pe-packer-rust

**加壳方式**：反射式 loader（新节嵌入）
**架构**：x64 only
**stub 语言**：Rust（winapi crate）

**流程**：
- Builder（`builder/src/main.rs`）用 `goblin` 解析 PE，把整个文件用 `PackedPayload::new` 处理：LZ4 压缩 + Argon2 派生 key + AES-256-GCM 加密 + Argon2 hash 校验密码，序列化成 `MAGIC(4) + VERSION(4) + len(4) + JSON`
- 在 stub PE 末尾追加新节 `.packed`（0xC0000040），写入序列化 payload，修改 NumberOfSections/SizeOfImage，清零 CheckSum
- Stub（`stub/src/main.rs`）用 `winapi` crate 找到 `.packed` 节 → `deserialize_payload` → `decrypt(password)` → `parse_pe_headers` → 反射式加载（VirtualAlloc + copy + reloc + IAT + section protect + `CreateThread(EP)`）
- Common（`common/src/lib.rs`）定义 `PackedPayload` 结构，用 `aes-gcm` / `argon2` / `lz4_flex` / `serde_json` / `zeroize` crates

**可借鉴点**：
1. **Argon2 密码派生 + 验证** — `common/src/lib.rs:127-141`（derive_key）+ `77-87`（hash 计算）+ `99-110`（验证）。用 `Argon2::default()` 派生 32 字节 key 和密码 hash，比 winlock 的 `SHA-256(pwd+salt)`（`builder.c:763-771`）抗 GPU/ASIC 暴力破解强很多。可移植性：部分 — 需要 C 实现 Argon2id（约 30KB），轻量替代可用 PBKDF2-HMAC-SHA256 多轮迭代，winlock 已有 SHA-256 实现（`stub/sha256.h`）
2. **AES-256-GCM 加密** — `common/src/lib.rs:73-75`（encrypt）+ `116-118`（decrypt）。AEAD 提供完整性校验，比 XTEA（无完整性）强。可移植性：部分 — 需 C 实现 AES-GCM 或 ChaCha20-Poly1305
3. **`Zeroize` / `ZeroizeOnDrop` 自动清零敏感数据** — `common/src/lib.rs:14, 52`。Rust drop 时自动 `zeroize` 内存中的 key/password。winlock 当前 `verify_password`（`stub.c:399-419`）用完 `digest` 没清零，`xtea_key` 也没清零。可移植性：YES — 用 `SecureZeroMemory` 或 volatile 写零
4. **序列化 magic + version 防 downgrade** — `common/src/lib.rs:143-167`。`MAGIC("PEPK") + VERSION(1)`，版本不匹配拒绝。winlock 的 stub_data 有 `version=3`（`config.h:82`）但 stub 没检查版本。可移植性：YES
5. **Section header 直接字节操作（无 LIEF 依赖）** — `builder/src/main.rs:130-162`。40 字节 section header 手写字段偏移。winlock 已用 `IMAGE_SECTION_HEADER` 结构体操作（`builder.c:1039-1049`），更清晰

**关键代码引用**：
- [pe-packer-rust lib.rs](file:///F:/Temp/pe/pe-packer-rust/common/src/lib.rs)
- [pe-packer-rust builder main.rs](file:///F:/Temp/pe/pe-packer-rust/builder/src/main.rs)

**结论**：**部分可移植**。加密栈（Argon2 + AES-GCM + LZ4）是 Rust crates，C 移植成本高。最直接可借鉴的是 Argon2 替代 SHA-256(pwd+salt)（显著提升抗暴力破解）和 Zeroize 模式（密码用后清零）。

---

### 2.3 TinyLoad-main

**加壳方式**：反射式 loader + 自嵌套（stub 既是 packer 又是被加壳产物）
**架构**：x64 only
**stub 语言**：C++ 单文件 2071 行

**流程**：
- `main()` 先 `tryRun()`（stub 模式），失败则当 packer（`pack()`）
- Packer 阶段（`TinyLoad.cpp:1697-2006`）：LZ77 压缩 + VM 字节码加密（XTEA-style stream cipher）+ 4 块 interleave + Fisher-Yates shuffle 序列化 Tail + XXTEA 加密 overlay + 把 128 位 XXTEA key 拆 4 个 DWORD XOR 到 stub 的 `.pxkey` guard block
- Stub 阶段（`TinyLoad.cpp:1478-1652`）：6 阶段状态机 `s_chk → s_ld → s_prs → s_vm → s_dc → s_ex`，每个阶段 `noiseDecrypt()` 干扰分析
- 反射式加载（`TinyLoad.cpp:1448-1463`）：`sp_hdr → sp_map → sp_reloc → sp_import → sp_veh → sp_go`，直接 `entry()` 跳 EP

**可借鉴点**（反静态分析/反 dump 宝库）：
1. **PEB 反调试三件套** — `TinyLoad.cpp:261-273`。x86 `__readfsdword(0x30)` / x64 `__readgsqword(0x60)` 取 PEB → 检查 `BeingDebugged`（PEB+2）/ `NtGlobalFlag & 0x70`（PEB+0xBC x64 / +0x68 x86）/ `IsDebuggerPresent` / `CheckRemoteDebuggerPresent`。可移植性：YES
2. **NtQueryInformationProcess(ProcessDebugPort=0x1F)** — `TinyLoad.cpp:1483`。比 kernel32 的 `IsDebuggerPresent` 更难被 hook 绕过。可移植性：YES（需要 PEB walk 找 ntdll）
3. **API 名 XOR 字符串加密（sdec2）** — `TinyLoad.cpp:36-72`。位置相关 XOR：`buf[i] = enc[i] ^ (key + i)`，每个字符串独立 key。winlock 当前 `STR_FN_GETPROCADDRESS` 等是明文（`stub.c:152-166`），strings 一抓全是 API 名。可移植性：YES，强烈推荐
4. **stub-key 派生加密敏感 metadata** — `TinyLoad.cpp:1830-1833, 1505-1508, 1865-1886`。用 stub 自身 `.text` 字节（0x1000-0x2000 范围）派生 64 位 key，XOR 加密 Tail 的 origSz/packSz/flags/dispKey/canaryOff/canaryExp/canaryCnt/vmCodeSz/sig/chunkOff/chunkSz/chunkOrder。任何对 stub 字节的 patch 都会让派生 key 变化 → metadata 解密失败。可移植性：YES，强烈推荐
5. **VEH 页级加密反 dump** — `TinyLoad.cpp:1274-1446`。反射式加载后把所有页 XOR 加密 + `PAGE_NOACCESS`，VEH 拦截缺页 → 解密单页 → watchdog 每 500ms 重新加密。可移植性：部分 — winlock in-place 加壳 .text 已被 XTEA 解密成明文，dump 工具可直接 dump。简化版：解密 .text → 执行 → 进入 OEP 后立即重新 XTEA 加密（自毁式），但要求 OEP 不回调 .text 之前的代码
6. **Canary corridor（解密后多点字节校验）** — `TinyLoad.cpp:1062-1112, 1788-1813`。builder 在 payload 中随机选 8 个偏移，记录 `canOff[i]` 和 `canExp[i] = actual[i] ^ prev_actual`（链式）。VM 解密完成后逐个校验。可移植性：YES — winlock 解密 .text 后校验 .text 中 N 个随机偏移
7. **Section 名 scramble** — `TinyLoad.cpp:1682-1695`。winlock 新增的 `.lock` 节（`builder.c:1041`）在 DIE/YARA 里是明显特征。可移植性：YES
8. **直接 syscall（SSN from disk ntdll）** — `TinyLoad.cpp:95-137`。从 `C:\Windows\System32\ntdll.dll` 映射文件，解析导出表读 SSN，运行时生成 12 字节 syscall stub。可移植性：部分 — winlock 当前用 VirtualProtect/LoadLibraryA 直接调，userland hook 能看到；换 syscall 能绕过，但 in-place 加壳只需 4 个 API，收益有限
9. **Tail 字段 Fisher-Yates shuffle** — `TinyLoad.cpp:330-368, 1986`。15 个字段用 LCG Fisher-Yates 打乱顺序序列化。可移植性：YES，中等价值
10. **Stub-key 加密 VM bytecode** — `TinyLoad.cpp:1883-1886, 1614-1616`。`vmCode[vi] ^= (BYTE)(stubKey >> ((vi*3)&63))`。可移植性：YES，和 #4 配套
11. **noiseDecrypt 干扰 + dead code** — `TinyLoad.cpp:79-84, 411-447`。每个状态机阶段调一次，用栈地址 hash 选 noise 字符串解密到栈 `volatile` 缓冲（立即丢弃）。可移植性：YES，低成本

**关键代码引用**：
- [TinyLoad.cpp](file:///F:/Temp/pe/TinyLoad-main/TinyLoad.cpp)

**结论**：**部分（最有价值）**。反射式 loader 主体对 in-place 不适用，但反静态分析/反调试/反 dump 技巧几乎全部可移植。

---

### 2.4 pe-packer-master（**真 in-place 加壳**）

**加壳方式**：**真 in-place**（C++ JIT emit PIC 汇编，加新节，改 EP）
**架构**：x86 + x64
**stub 语言**：C++ JIT emit 字节级 PIC 汇编

**流程**：
- PE 解析后追加 `.ptext` 节，把 JIT 生成的 stub 字节流写入新节，改 `AddressOfEntryPoint` 指向新节入口
- 原 `.text` 节原地保留（OEP 仍在里面），通过 stub 跳回去
- **跟 winlock 设计完全同构**

**可借鉴点**（高度可移植）：
1. **用 PEB 直接取自己的 ImageBase** — `stub_emitter.cpp:430-443`。`load_image_base` 用 `gs:[0x60]` (x64) / `fs:[0x30]` (x86) → PEB → `PEB.ImageBaseAddress` (+0x10 / +0x08)。字节级编码已写好
2. **`-noaslr` + XOR 加密 .reloc 的 in-place reloc 处理范式** — `core.cpp:294-297, pe_view.cpp:475-477`。builder 阶段清掉 `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`，然后把 `.reloc` 整个 XOR 加密掉（运行时不解密，因为没 ASLR 就不需要 reloc）。XOR decrypt loop 虽然被 emit 出来但放在 `call OEP` 之后是死代码。**winlock 当前选择保留 ASLR + 在 stub 里重新 patch .text 范围 reloc，更复杂但更安全**（ASLR 仍是开的状态，防固定地址攻击）
3. **反汇编技巧 jmp_label_skip（adasm）** — `adasm.cpp:7-25`。`jz label; jnz label; db 0xE9` — 两条互补条件跳转强制线性反汇编器走静态分支，`0xE9` (jmp rel32) 被当作垃圾字节忽略，但反汇编器会把它当真跳转读 4 字节立即数。经典 4 字节花指令
4. **XOR runtime decrypt loop 模板** — `core.cpp:131-169`。emit 出来的 PIC 解密循环结构可套到任何流密码/计数器模式
5. **OEP 跳转的 XOR 混淆变体** — `core.cpp:237-266`。`obf_call_oep` 模式不让 `call rel32` 直接出现 OEP，把 OEP 拆成 `(oep - idx) + idx`，idx 再做 XOR 混淆
6. **CFG (Guard CF) 表 patch** — `pe_view.cpp:638-738`。`add_guard_cf_target` 完整实现了 GFIDS 表的 stride 探测、排序插入。**in-place 加壳最容易踩的坑**：如果原 PE 有 `IMAGE_DLLCHARACTERISTICS_GUARD_CF`，新的 stub entry 必须加进 GFIDS 表，否则运行时被 CFG 拦截。**winlock 当前是直接清掉 GUARD_CF 标志（builder.c:...），简化但损失了 CFG 保护**
7. **MBA 混淆 + junk code 生成器** — `mba.cpp` + `core.cpp:418-526`。字节级 emit，语言无关

**关键代码引用**：
- [pe-packer stub_emitter.cpp](file:///F:/Temp/pe/pe-packer-master/pe-packer/emit/stub_emitter.cpp)
- [pe-packer core.cpp](file:///F:/Temp/pe/pe-packer-master/pe-packer/core/core.cpp)
- [pe-packer adasm.cpp](file:///F:/Temp/pe/pe-packer-master/pe-packer/core/adasm.cpp)
- [pe-packer pe_view.cpp](file:///F:/Temp/pe/pe-packer-master/pe-packer/pe_raw/pe_view.cpp)

**结论**：**YES（高度可移植）**。pe-packer 跟 winlock 同为 in-place 加壳，架构完全同构。adasm 花指令、CFG patch、-noaslr+XOR .reloc 范式都可抄。但 pe-packer 没做 SecurityCookie / 栈对齐 / API hash / 反调试。

---

### 2.5 WinXRunPE-x86_x64-master

**加壳方式**：Process Hollowing（反射式 + 进程替换）
**架构**：x86 + x64
**stub 语言**：C#（无 stub，builder 全做）

**流程**：`CreateProcessInternal(suspended)` → `NtUnmapViewOfSection(ImageBase)` → `VirtualAllocEx` 重申请 → `WriteProcessMemory` 头+节 → `GetThreadContext/SetThreadContext` 改 `Ebx+8`/`Rdx+16` (PEB.ImageBaseAddress) 和 `Eax`/`Rcx` (OEP) → `ResumeThread`

**可借鉴点**：
1. 通过 Thread Context 间接 patch PEB.ImageBaseAddress（`WinX86.cs:201, WinX64.cs:174`）— hollowing 核心，in-place 用不上
2. 字节级手写 ImageBase 拆解（`WinX86.cs:188-198`）— 不依赖 BitConverter
3. 神秘的 0x398 字节 patch（`WinX86.cs:64`）— Menalix 的 patch，固定偏移不可靠
4. CREATE_SUSPENDED | CREATE_NO_WINDOW 标志（`WinX86.cs:67-72`）

**结论**：**NO**。架构跟 in-place 完全相反。没有任何代码可以直接移植。

---

### 2.6 PeLoader-master

**加壳方式**：进程内反射式 loader（demo）
**架构**：x86 only
**stub 语言**：C + CRT + 内联汇编

**流程**：`VirtualAlloc(ImageBase)` → 拷贝 headers + sections → `BuildIAT`（用明文 `LoadLibraryA`+`GetProcAddress`） → `FixReloc`（x86 HIGHLOW only） → `__asm { jmp EntryOfImage }`

**可借鉴点**：
1. **PEB walk 找 kernel32 的内联汇编范例** — `test.cc:15-24`。x86 PEB walk 经典代码，winlock 已实现更完整版本（按 hash 匹配而非固定第三项）
2. **x86 reloc 表遍历最小实现** — `PELoader.cc:148-181`。只处理 `IMAGE_REL_BASED_HIGHLOW`，代码短到一眼看懂
3. **IAT 修复明文 API 写法** — `PELoader.cc:108-146`。winlock 不应照抄（应 PEB walk + API hash），但循环结构（`OriginalFirstThunk` / `FirstThunk` / `IMAGE_IMPORT_BY_NAME`）是对的
4. **`__asm { jmp EntryOfImage }` 跳 OEP** — `PELoader.cc:223-228`。最简洁的跳 OEP 写法，`jmp` 而非 `call`，不留返回地址。**winlock 应该用这种 jmp 模式**
5. **AllocateMemory 容错** — `PELoader.cc:55-76`。检查 `IMAGE_FILE_RELOCS_STRIPPED` 判断 PE 是否能 in-place 加壳

**关键代码引用**：
- [PeLoader PELoader.cc](file:///F:/Temp/pe/PeLoader-master/PELoader.cc)
- [PeLoader test.cc](file:///F:/Temp/pe/PeLoader-master/test.cc)

**结论**：**部分（概念可借鉴，代码需重写）**。主要是 PEB walk 范式和 reloc 遍历结构。但所有代码都是 32 位 C 带 CRT，不是 PIC，直接拷用不了。

---

### 2.7 peldr-main（**最像 winlock 的项目**）

**加壳方式**：反射式 loader（overlay）
**架构**：x64 only
**stub 语言**：C `-nostdlib -ffreestanding` PIC（与 winlock 同款约束）

**流程**：
- Builder（`peldr.c`）把整个原 PE 用 RLE 压缩 + 自定义流密码加密，附加在预编译的 loader stub 后面作为 overlay
- 运行时 stub 通过 `NtQueryInformationProcess(ProcessImageFileName)` + `NtReadFile` 把自己的 overlay 读回内存，解密解压后用 `NtAllocateVirtualMemory` 申请新内存反射映射，跳过去
- 原 PE 在磁盘上以加密形态存在，运行时被映射到新分配的内存

**可借鉴点**（核心 stub 技巧 YES）：
1. **栈对齐跳 OEP 的内联汇编** — `loader.c:1144-1152`。`andq $-16, %rsp; subq $40, %rsp; jmpq *%0`。直接可抄到 winlock
2. **SecurityCookie 初始化（用 KUSER_SHARED_DATA，无 API 依赖）** — `loader.c:464-482`。`*ckAdr = (ULONGLONG)img ^ *(volatile const ULONGLONG*)KUSER_INTERRUPT_TIME`。KUSER_INTERRUPT_TIME = 0x7FFE0008，每 1ms 更新一次。winlock 把 `img` 换成 `PEB.ImageBaseAddress` 即可
3. **API 哈希（DJB15 + 大小写折叠 + 32-bit 种子）** — `loader.c:99-114` + `hash.py:43-60`。`h = 1993; h = ((h << 4) - h) + c`，Python 离线生成 `#define HASH_NtTerminateProcess 0x596F6B0DU`
4. **NTDLL 模块名匹配（UINT64 一次比较 + bitmask 小写化）** — `loader.c:120-140`。`const UINT64 nm = *(PUINT64)rc->BaseDllName.Buffer; if ((nm | NTDLL_NAME_MASK) == NTDLL_NAME_HASH)`。一次 64-bit 读代替 `wcsicmp`，零字符串比较
5. **反调试栈顶 guard page + PEB 完整性校验** — `loader.c:893-907, 944-955`。`ADB_STAGE_PREAPI` 三重检查：`KdDebuggerEnabled` (KUSER_SHARED_DATA+0x2D4) + `PEB.BeingDebugged` + `PEB.ProcessParameters.DebugFlags`。全在解析 API 之前用 PEB+KUSER_SHARED_DATA 直接读，零依赖
6. **PE header erasure** — `loader.c:1078-1085`。跳 OEP 前 `ZEROS(img, ntHeaders->OptionalHeader.SizeOfHeaders)`，挡住 pe-sieve 这类工具
7. **函数指针自清零** — `loader.c:1107-1126`。解密后把所有运行时解析的函数指针置 NULL，dump 出来的内存看不到 IAT

**关键代码引用**：
- [peldr loader.c](file:///F:/Temp/pe/peldr-main/loader.c)
- [peldr loader.h](file:///F:/Temp/pe/peldr-main/loader.h)
- [peldr hash.py](file:///F:/Temp/pe/peldr-main/hash.py)

**结论**：**YES（最值得 winlock 抄）**。peldr 是唯一一个 `-nostdlib -ffreestanding` 编译的（和 winlock 同款约束），stub 完全无 CRT 依赖，纯 PEB walk + hash 解析 ntdll。栈对齐 jmp OEP、SecurityCookie、反调试、API 哈希、模块名 UINT64 匹配都是直接可抄的"纯 PIC C + 内联汇编"片段。

---

### 2.8 MaldevAcademyLdr.2-main

**加壳方式**：反射式 loader + 多重 EDR 规避
**架构**：x64 only
**stub 语言**：C + CRT + D3D11

**流程**：原 PE（mimikatz）用 DWT 隐写术分片藏进多个 PNG 图片，PNG 作为 RT_RCDATA 资源嵌入 loader。运行时从资源读 PNG、DWT 解码 + Reed-Solomon 纠错还原 PE 分片，拼接成完整 PE，然后用 `NtAllocateVirtualMemory` 在 ImageBase 反射映射

**可借鉴点**：
1. **AES-128-CTR 硬件加速（AES-NI intrinsics）** — `AES128CTR-NI.c:11-148`。10 轮 `_mm_aeskeygenassist_si128` + `_mm_shuffle_epi32` + `_mm_slli_si128` + `_mm_xor_si128`。比 XTEA 快一个数量级，无查找表（抗 cache 时序侧信道）。但 x86 in-place 加壳如果目标 CPU 不支持 AES-NI 需要 fallback，且 SSE2 与 winlock `-mno-sse2` 冲突
2. **FNV-1a 32-bit API 哈希 + 模块哈希** — `Utilities.c:12-45` + `Hashes.h`。`DWORD dwFnvHash = 0x811C9DC5; dwFnvHash ^= dwCharValue; dwFnvHash *= 0x01000193`。比 peldr DJB15 抗碰撞性更好，是行业标准。提供了 `HASH_STRING_A` / `HASH_STRING_W` / `HASH_STRING_A_CI` 四套宏
3. **ApiSetMap 解析（V2/V3/V4/V6 全版本）** — `ResolveAPIs.c:1018-1082`。Windows 10+ 上 ntdll.dll 很多 API 实际通过 `api-ms-win-*` 转发。但 winlock 找 kernel32.dll 不需要（kernel32 仍是真实模块）
4. **TrapSyscallsTampering（Trap Flag syscall 篡改）** — `TrapSyscallsTampering.c:16-80`。VEH 拦截 `EXCEPTION_SINGLE_STEP` 恢复真 SSN，让 EDR syscall hook 看到假调用。反 EDR 重型武器，winlock 不需要
5. **GPU VRAM 隐藏 + 睡眠时加密（section fluctuation）** — `UnpackAndHide.c:711-786, 967-1044`。每个 section 用 AES-CTR 加密 → 上传 D3D11 VRAM → 内存清零。VEH 拦截 AV 触发恢复。过度复杂，winlock 不需要 VRAM 部分，但"VEH + 按需解密"思路可借鉴简化版
6. **资源目录手动遍历** — `Utilities.c:248-308`。直接读 `IMAGE_RESOURCE_DIRECTORY` 三层结构，不走 API。对 winlock 保留图标/manifest 有价值

**关键代码引用**：
- [Maldev AES128CTR-NI.c](file:///F:/Temp/pe/AlushPacker-main/RunPeFile/AES128CTR-NI.c)
- [Maldev Utilities.c](file:///F:/Temp/pe/AlushPacker-main/RunPeFile/Utilities.c)
- [Maldev ResolveAPIs.c](file:///F:/Temp/pe/AlushPacker-main/RunPeFile/ResolveAPIs.c)

**结论**：**中**。AES-NI CTR 是 XTEA 升级时的首选（但需 CPUID 检测 + fallback），资源目录遍历是 winlock 保留图标/manifest 的模板。其他反 EDR 重型武器与 winlock 门禁壳目标不符。

---

### 2.9 AlushPacker-main

**加壳方式**：反射式 loader（.packed 节）
**架构**：x86 + x64
**stub 语言**：C + CRT

**流程**：Builder 在原 PE 末尾追加 `.packed` 节，装「LZAV 压缩 + XTEA 加密」的原 PE 完整副本 + precompiled_unpacker_x86/x64 字节数组。运行时 loader 通过 `myGetModuleHandle(NULL)` + 节名扫描定位 `.packed`，解密解压，用 `NtAllocateVirtualMemory` 申请新内存反射映射

**可借鉴点**：
1. **x86 + x64 双架构 reloc 完整 patch（含 HIGHLOW/HIGH/LOW）** — `loader.c:647-700`。完整 4 种 reloc 类型 switch。winlock 当前只 DIR64（x64），扩展 x86 时直接抄
2. **SecurityCookie 初始化（GetTickCount64 ^ GetCurrentProcessId，x86/x64 都支持）** — `loader.c:931-951`。**关键设计：只在 cookie 是默认值时才覆盖**（避免破坏已初始化的 cookie）。比 peldr 的无条件覆盖更稳健。默认 cookie：`0x00002B992DDFA232`（x64）/ `0xBB40E64E`（x86）
3. **x86 SEH 支持：PatchRtlIsValidHandler** — `loader.c:560-578`。patch ntdll 把 `je` 改成 `jne` 让所有 handler 都通过校验。但偏移 0x699C3 和 0x3C22E 是 hard-coded 的，不同 Windows 版本会变，**生产环境不可用**
4. **x64 .pdata 注册：RtlAddFunctionTable** — `loader.c:961-972`。反射式才需要，in-place 不需要
5. **TLS Callback 代理（.CRT$XLB 段）** — `tls.h:1-22` + `loader.c:531-557`。`#pragma comment (linker, "/INCLUDE:_tls_used")` + `TlsCallbackProxy` 实现 DLL_PROCESS_ATTACH/DETACH/THREAD_ATTACH/DETACH 完整分发。反射式才需要，in-place 用 builder 修改 AddressOfCallBacks 是更正确做法

**不值得借鉴**：XTEA 实现与 winlock builder.c 完全相同；API 解析用明文字符串；`myRtlInsertInvertedFunctionTable` 硬编码偏移 0x108F0；`LdrpPatchDataTableEntry` 修改 PEB.Ldr 链表（反射式才需要）；转发导出递归解析（反射式才需要）；TLS index 分配（反射式才需要）；KDF `strtoul` 把密码转 4×uint32（极弱）；硬编码 XTEA key `0x01234567...`（所有文件共用一个 key）

**关键代码引用**：
- [AlushPacker loader.c](file:///F:/Temp/pe/AlushPacker-main/Packer/loader.c)
- [AlushPacker tls.h](file:///F:/Temp/pe/AlushPacker-main/Packer/tls.h)

**结论**：**中**。完整 reloc 类型 switch（扩展 x86 时直接抄）+ SecurityCookie 判断逻辑（比 peldr 更稳健）。其他不值得。

---

### 2.10 Windows-PE-Packer-master（**真 in-place 加壳**，但部分是反例）

**加壳方式**：**真 in-place**（追加 `.shell` 节）
**架构**：x86 only
**stub 语言**：C + ASM

**流程**：不重映射 PE，在原 PE 上追加 `.shell` 节，把入口点改到 stub。原 PE 仍由 Windows loader 正常加载，stub 在原 PE 上原地解密 .text/.data/.rdata、重建 IAT、应用 reloc、跳 OEP。**与 winlock 一致**

**可借鉴点**：
1. **（反例）清零 LOAD_CONFIG 目录 → SecurityCookie 丢失** — `install_shell.c:200-202`。`ZeroMemory(&nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG], ...)`。**winlock 必须避免**：直接清零 LOAD_CONFIG 会让 /GS 程序返回时触发 stack cookie mismatch 崩溃
2. **TLS Directory 完整代理（复制到 stub 段）** — `install_shell.c:142-152`。把原 TLS directory 复制到 stub 段内，改 DataDirectory[9] 指向新位置。**winlock 现有方案更优**（改 AddressOfCallBacks 指向 stub_tls_callback，在原 callback 之前解密 .text）
3. **自写 IAT 序列化格式** — `import_table.c:269-337`。原 IAT 被全部清零，stub 自己用紧凑自定义格式重建 IAT。反静态分析的强项，dump 出来的 PE 完全没有 import table。winlock 可选增强
4. **跳 OEP 的 "push + ret" 内联汇编** — `entry_x86.asm:500-503`。`DB 68h, 0FFh, 0FFh, 0FFh, 0FFh; ret`。stub 运行时把 OEP VA 写到 0xFFFFFFFF 那四个字节。等价于 jmp OEP 但更隐蔽。winlock 用 `((void(*)())oep)()` 也 OK
5. **Reloc 处理 — 仅处理 HIGHLOW（反例）** — `entry_x86.asm:421-472`。假设"PE 实际加载在 ImageBase"所以默认不应用 reloc。**对 in-place 加壳这个假设是错的**：.text 被加密，loader 在加载时把 reloc 应用到了密文字节上，stub 解密 .text 后那些 reloc 修正被覆盖，**必须重新应用**。winlock 已正确处理（只 patch .text 范围）

**关键代码引用**：
- [Windows-PE-Packer install_shell.c](file:///F:/Temp/pe/Windows-PE-Packer-master/src/shell/install_shell.c)
- [Windows-PE-Packer entry_x86.asm](file:///F:/Temp/pe/Windows-PE-Packer-master/src/shell/entry_x86.asm)
- [Windows-PE-Packer import_table.c](file:///F:/Temp/pe/Windows-PE-Packer-master/src/import_table.c)

**结论**：**中（反例参考）**。是 in-place 加壳但设计有缺陷：清零 LOAD_CONFIG、默认不应用 reloc、字节 +0xCC 玩具加密。winlock 已避免这些坑。

---

### 2.11 PEzor-master

**加壳方式**：RunPE / Shellcode 注入器（不是 in-place）
**架构**：x86 + x64
**stub 语言**：C++

**流程**：把原 PE 用 donut 转成 shellcode，然后注入到新进程或自进程的 VirtualAlloc 内存里执行。原 PE 文件结构与最终输出文件毫无关系

**可借鉴点**：
1. **OutputDebugString 反调试（经典 SetLastError 技巧）** — `PEzor.cpp:20-29`。`SetLastError(1111); OutputDebugString(" "); if (GetLastError() != 1111) exit;`。调试器会"消费"OutputDebugString 而复位LastError。可移植性：部分 — winlock PIC stub 要拿 OutputDebugString/SetLastError/GetLastError 需多 resolve 3 个 kernel32 函数。建议只取 PEB.BeingDebugged + NtGlobalFlag
2. **内存 Sleep Fluctuation（反 dump）** — `fluctuate.cpp:71-188`。hook Sleep，在 sleep 期间把 shellcode 区域 XOR 加密 + 改 PAGE_NOACCESS，sleep 结束后再 XOR 解密 + 恢复。dump 出来的进程内存是密文。可移植性：部分 — winlock 可借鉴简化版（hook Sleep 重新加密 .text），但实现复杂
3. **反 hook（unhook ntdll）：从磁盘重新加载干净 ntdll** — `loader.c:42-278`。把磁盘上的 ntdll.dll 重新映射到内存，逐节比对当前内存中的 ntdll 与磁盘版本，把被 hook 的字节用磁盘版本覆盖。可移植性：部分 — winlock 无 CRT、PIC，要重新实现 CreateFileW/CreateFileMappingW/MapViewOfFile 太重。AtomPePacker 的 \KnownDlls\ 路径更轻量
4. **ApiSetMap 解析** — `ApiSetMap.c:55-`。解析 `api-ms-win-*` 虚拟 DLL 名到真实 DLL。winlock 不需要（直接找 kernel32.dll 真名）
5. **LDR 链遍历修复（RefreshPE）** — `loader.c:4-40`。反射式才需要

**加密算法**：仅 XOR，用 `GetComputerNameExA(ComputerNameDnsFullyQualified)` 作为 key。环境绑定 keying 思路可作 winlock 可选项

**关键代码引用**：
- [PEzor PEzor.cpp](file:///F:/Temp/pe/PEzor-master/PEzor.cpp)
- [PEzor fluctuate.cpp](file:///F:/Temp/pe/PEzor-master/fluctuate.cpp)

**结论**：**低**。场景与 in-place 完全不同。仅反调试思路（PEB.BeingDebugged + NtGlobalFlag）和 Sleep Fluctuation 思路可借鉴。

---

### 2.12 AtomPePacker-NUL0x4C-main

**加壳方式**：stub-exe + RunPE 重映射
**架构**：x64 only
**stub 语言**：C + CRT

**流程**：
- Builder 把原 PE 用 LZMA 压缩后塞进预编译 stub-exe 的 `.ATOM` 节
- stub-exe 运行时：PEB walk 找到自己（通过 .ATOM 节名 hash）→ LZMA 解压 → `NtUnmapViewOfSection(NULL, ImageBase)` → `NtAllocateVirtualMemory(ImageBase, SizeOfImage)` → 复制 headers + 各节 → 重建 IAT → 应用 reloc → `RtlAddFunctionTable` 注册 .pdata → unhook ntdll（从 \KnownDlls\ 重新映射）→ 设置节权限 → 调用 TLS callbacks → 跳 EP

**可借鉴点**：
1. **PEB walk + Ldr 链查找 module** — `Utils.c:175-205`。winlock 已实现等价功能且更直接（用 BaseDllName 短名做大小写不敏感比较）
2. **Rotr32 API hash + GetProcAddress by hash** — `General.c:190-209`。`Value = String[Index] + _HashStringRotr32SubA(Value, SEED)`。+ `Utils.c:237-282` `GetProcAddressH(HMODULE, DWORD Hash)`。winlock 当前 stub 里 `"GetProcAddress"` / `"LoadLibraryA"` / `"VirtualProtect"` / `"ExitProcess"` 都是明文字符串，dump 出来一眼就能看到。**强烈推荐借鉴**
3. **IAT Camouflage（伪装合法 import 降低 IOC）** — `IatCamouflage.h:27-73`。在 stub 里调用一堆"看起来合法"的 user32/menu/ole32 API（用 NULL 参数让它们立刻失败返回），让 dump 出来的 IAT 看起来像普通 GUI 程序
4. **.pdata (Exception Table) 完整注册** — `Unpack.c:294-308`。`RtlAddFunctionTable`。反射式才需要，in-place 不需要
5. **Unhook ntdll 通过 \KnownDlls\（轻量级反 hook）** — `Utils.c:38-85`。`NtOpenSection("\\KnownDlls\\ntdll.dll")` + `NtMapViewOfSection`。比 PEzor 的 CreateFileW+CreateFileMappingW 更轻量。字符串用 wchar 字面量字符数组构造，避免明文。可移植性：部分 — winlock stub 用 PIC C 理论上可移植，但对 in-place 加壳场景 ntdll hook 不是核心问题
6. **TLS callbacks 主动调用** — `Unpack.c:353-364`。`(*ppCallback)(pAddress, DLL_PROCESS_ATTACH, NULL)`。winlock 当前方案更优（builder 改 AddressOfCallBacks，loader 自动调 stub_tls_callback，stub_tls_callback 解密后再调原 callbacks）
7. **EP 前清零 PE headers 反 dump** — `Unpack.c:366-367`。`_ZeroMemory(pAddress, _Pe1.pSecHdr[0].VirtualAddress)`。dump 出来的进程 PE header 被清零，PE 解析器无法识别。可移植性：部分 — winlock 实现需要小心：必须保证 .lock 节在第一个原 PE 节之后，stub_entry 完成所有工作后才能清零

**关键代码引用**：
- [AtomPePacker Utils.c](file:///F:/Temp/pe/AtomPePacker-NUL0x4C-main/PP64Stub/Utils.c)
- [AtomPePacker General.c](file:///F:/Temp/pe/AtomPePacker-NUL0x4C-main/PP64Stub/General.c)
- [AtomPePacker IatCamouflage.h](file:///F:/Temp/pe/AtomPePacker-NUL0x4C-main/PP64Stub/IatCamouflage.h)
- [AtomPePacker Unpack.c](file:///F:/Temp/pe/AtomPePacker-NUL0x4C-main/PP64Stub/Unpack.c)

**结论**：**高**。API hash Rotr32 + IAT Camouflage 直接借鉴。其他反射式专属逻辑不需要。

---

## 3. 按关注点横向对比

### 3.1 SecurityCookie 初始化

| 项目 | 是否处理 | 方法 | 可借鉴性 |
|------|---------|------|---------|
| PEPacker2 | ✗ | — | NO |
| pe-packer-rust | ✗ | — | NO |
| TinyLoad | ✗ | — | NO |
| pe-packer-master | ✗ | — | NO |
| WinXRunPE | ✗ | — | NO |
| PeLoader | ✗ | — | NO |
| **peldr** | **YES** | `img ^ KUSER_INTERRUPT_TIME`（无条件覆盖） | **YES** |
| MaldevAcademyLdr | ✗ | — | NO |
| **AlushPacker** | **YES** | `GetTickCount64 ^ PID`（仅当为默认值时） | **YES**（判断逻辑更稳健） |
| Windows-PE-Packer | **反例** | 清零 LOAD_CONFIG | **反例参考** |
| PEzor | ✗ | — | NO |
| AtomPePacker | ✗ | — | NO |

**winlock 应该抄**：AlushPacker 的判断逻辑（仅当 cookie 是 `0xBB40E64E` x86 / `0x00002B992DDFA232` x64 默认值或 0 时才覆盖）+ peldr 的熵源（`PEB.ImageBaseAddress ^ KUSER_INTERRUPT_TIME`，无 API 依赖）

### 3.2 栈对齐跳 OEP

| 项目 | 写法 | 可借鉴性 |
|------|------|---------|
| PEPacker2 | `CreateThread(EP)` | NO |
| pe-packer-rust | `CreateThread(EP)` | NO |
| TinyLoad | 直接 `entry()` C 调用 | NO |
| pe-packer-master | `call rel32`（未显式对齐） | 部分 |
| WinXRunPE | patch Eax/Rcx | NO |
| PeLoader | `__asm { jmp }` | YES（推荐） |
| **peldr** | **`andq $-16; subq $40; jmpq *%0`** | **YES（直接抄）** |
| MaldevAcademyLdr | C 函数指针调用 | NO |
| AlushPacker | C 函数指针调用 | NO |
| Windows-PE-Packer | `push imm32; ret` | 部分 |
| PEzor | — | NO |
| AtomPePacker | C 函数指针调用 | NO |

**winlock 应该抄**：peldr 的内联汇编

### 3.3 加密算法

| 项目 | 算法 | 可借鉴性 |
|------|------|---------|
| PEPacker2 | AES-CBC + Gzip + Base32（CryptoPP） | NO |
| pe-packer-rust | AES-256-GCM + LZ4 | 部分（C 移植成本高） |
| TinyLoad | XXTEA + VM stream cipher | 部分 |
| pe-packer-master | XOR only | NO |
| WinXRunPE | 无 | NO |
| PeLoader | 无 | NO |
| peldr | 自定义流密码 | NO |
| **MaldevAcademyLdr** | **AES-128-CTR + AES-NI** | **YES（升级首选）** |
| AlushPacker | XTEA 32 轮（同 winlock） | NO（winlock 已有） |
| Windows-PE-Packer | `+0xCC`（玩具） | NO |
| PEzor | XOR + FQDN | NO |
| AtomPePacker | LZMA only | NO |

**winlock 现状**：XTEA 32 轮已够用。如升级首选 Maldev AES-NI CTR（需 CPUID 检测 + 软件 fallback）

### 3.4 KDF

| 项目 | KDF | 可借鉴性 |
|------|-----|---------|
| pe-packer-rust | **Argon2** | 部分（C 实现约 30KB） |
| AlushPacker | strtoul（极弱） | NO |
| PEzor | XOR + FQDN | 部分（环境绑定思路） |
| 其他 9 个 | 无 | NO |

**winlock 现状**：`SHA-256(pwd+salt)` 已经是 12 项目里最好的（除 pe-packer-rust 的 Argon2）。如需加强自行实现 PBKDF2-HMAC-SHA256（基于已有 SHA-256，100k 轮）

### 3.5 API 哈希解析

| 项目 | 是否实现 | 算法 | 可借鉴性 |
|------|---------|------|---------|
| TinyLoad | **YES** | sdec2 XOR（位置相关） | **YES** |
| **peldr** | **YES** | DJB15 + 大小写折叠 + Python 离线生成 | **YES**（推荐，简单） |
| **MaldevAcademyLdr** | **YES** | FNV-1a 32-bit + 预计算常量 | **YES**（标准） |
| **AtomPePacker** | **YES** | Rotr32 + GetProcAddressH | **YES** |
| 其他 8 个 | ✗ | 明文字符串 | NO |

**winlock 现状**：8 个明文 API 名（`STR_FN_GETPROCADDRESS` 等），是静态特征。应改成 hash

### 3.6 反调试

| 项目 | 反调试项 | 可借鉴性 |
|------|---------|---------|
| **TinyLoad** | PEB.BeingDebugged + NtGlobalFlag + IsDebuggerPresent + CheckRemoteDebuggerPresent + NtQueryInformationProcess(ProcessDebugPort) | **YES** |
| **peldr** | KdDebuggerEnabled (KUSER_SHARED_DATA+0x2D4) + PEB.BeingDebugged + ProcessParameters.DebugFlags + guard page + PEB 完整性 | **YES**（零依赖） |
| PEzor | OutputDebugString + PEB.BeingDebugged + NtGlobalFlag | 部分 |
| AtomPePacker | 仅 OS 版本检查 | NO |
| 其他 8 个 | 无 | NO |

**winlock 应该抄**：peldr 的零依赖 PEB+KUSER_SHARED_DATA 检查 + TinyLoad 的 NtQueryInformationProcess

### 3.7 TLS callback 完整代理

| 项目 | 方案 | 可借鉴性 |
|------|------|---------|
| PEPacker2 | 遍历调用 DLL_PROCESS_ATTACH | NO（winlock 已超越） |
| AlushPacker | `.CRT$XLB` 段 + 4 种 Reason 分发 | NO（反射式才需要） |
| Windows-PE-Packer | 复制 TLS dir 到 stub 段 | NO |
| AtomPePacker | 主动调用原 callbacks | NO |
| **winlock** | **builder 改 AddressOfCallBacks 指向 stub_tls_callback，stub 解密后再调原 callbacks** | **已是 in-place 最佳** |

### 3.8 .pdata 异常表

| 项目 | 处理 | 可借鉴性 |
|------|------|---------|
| PEPacker2 / Maldev / AlushPacker / AtomPePacker | `RtlAddFunctionTable` | NO（反射式才需要） |
| 其他 | 不处理 | NO |

**winlock**：in-place 加壳不需要处理，OS loader 已注册过原 .pdata

### 3.9 Reloc 处理

| 项目 | 类型覆盖 | 可借鉴性 |
|------|---------|---------|
| PEPacker2 | DIR64/HIGHLOW/HIGH/LOW/ABSOLUTE | NO（winlock 已有） |
| AlushPacker / Maldev / AtomPePacker | 完整 5 类型 | **YES**（扩展 x86 时抄） |
| peldr | DIR64 only | NO |
| **winlock** | DIR64 + x86 builder 预 patch | **已是 in-place 最佳** |
| Windows-PE-Packer | HIGHLOW only，默认不应用（反例） | 反例 |

### 3.10 资源/图标/manifest 保留

| 项目 | 方案 | 可借鉴性 |
|------|------|---------|
| pe-packer-master | 隐式保留（只加新节） | YES |
| Windows-PE-Packer | overlay 保留 | 部分 |
| MaldevAcademyLdr | 手动遍历 `IMAGE_RESOURCE_DIRECTORY` 三层结构 | **YES**（保留图标/manifest 模板） |
| 其他 | 不保留 | NO |

**winlock**：隐式保留（只加 .lock 节）。如需显式保留图标/manifest 抄 Maldev `Utilities.c:248-308`

### 3.11 反静态分析/反 dump

| 项目 | 技巧 | 可借鉴性 |
|------|------|---------|
| **TinyLoad** | VEH 页级加密 + stub-key 派生 + canary corridor + section 名 scramble + Tail shuffle + chunk interleave + dead code + noiseDecrypt | **高**（宝库） |
| **pe-packer-master** | adasm 花指令（jz+jnz+0xE9）+ MBA 混淆 + junk code 生成器 | **YES** |
| **peldr** | PE header erasure + 函数指针自清零 | **YES** |
| **MaldevAcademyLdr** | GPU VRAM 隐藏 + section fluctuation + stack spoofing + EDR VEH 覆盖 + DWT 隐写 | 部分（VEH 按需解密思路） |
| **AtomPePacker** | IAT Camouflage + EP 前清零 header | **YES** |
| pe-packer-rust | Zeroize | YES |
| PEzor | Sleep Fluctuation | 部分 |

---

## 4. 反射式 loader vs in-place 加壳（winlock）优缺点总结

### 4.1 反射式 loader（PEPacker2 / pe-packer-rust / TinyLoad / peldr / Maldev / AlushPacker / AtomPePacker 等 10 个项目）

**工作原理**：把整个原 PE 作为密文 payload 嵌入 stub（资源/新节/overlay），运行时 stub 申请新内存反射映射 PE，手动完成所有 PE 初始化（IAT/reloc/.pdata/TLS/节权限），跳 OEP。

**优点**：
1. **原 PE 完全加密**：整个文件都是密文，静态分析看不到任何 PE 结构
2. **可压缩**：LZMA/LZ4/LZAV 压缩后体积可显著减小
3. **stub 可独立编译**：不依赖原 PE 架构/子系统，可 AnyCPU
4. **反 dump 强**：解密后的明文 PE 在新分配的内存里，可随时重新加密/移到 VRAM（Maldev）/unhook（TinyLoad）
5. **PE 结构可重建**：可清零 IAT（Windows-PE-Packer）、伪造 IAT（AtomPePacker IAT Camouflage）、改节名（TinyLoad scramble）
6. **加密算法可任意选**：AES-GCM / Argon2 / XXTEA + VM 字节码都可（stub 不受体积限制，因为有 CRT）
7. **反调试/反 hook 手段丰富**：可直接 syscall（TinyLoad）、unhook ntdll（AtomPePacker）、stack spoofing（Maldev）

**缺点**：
1. **兼容性差**：手动完成所有 PE 初始化，任何一步出错都会崩溃；不支持的 PE 特性（如 SEH/CFG/.NET CLR）需要额外处理
2. **OS loader 看不到真实 PE**：`GetModuleHandle(NULL)` 返回 stub 而非原 PE，需要 patch PEB.Ldr 链表（AlushPacker `LdrpPatchDataTableEntry`），不同 Windows 版本偏移不同
3. **实现复杂度高**：IAT 解析、转发导出、TLS index 分配、.pdata 注册、节权限映射都要手动做，代码量 1500-2000 行
4. **资源保留难**：原 PE 的图标/manifest/版本信息要手动复制（Maldev `Utilities.c:248-308`），大部分项目不做
5. **被 EDR 重点监控**：`NtAllocateVirtualMemory` + `NtProtectVirtualMemory` + 跨节拷贝是典型反射式 loader 行为，EDR 容易识别
6. **stub 体积大**：需要 CRT 或大量手写函数，stub 至少 50KB+
7. **反调试反 EDR 工具链复杂**：直接 syscall / unhook ntdll / stack spoofing 等都是重型武器，维护成本高
8. **x86 + x64 双架构支持难**：reloc 类型、SEH、.pdata 都要分别处理

### 4.2 in-place 加壳（winlock + pe-packer-master + Windows-PE-Packer）

**工作原理**：原 PE 被原地修改，新增一个 `.lock` 节装 stub，改 EP 指向 stub，`.text` 节被加密。运行时 Windows loader 正常加载 PE（完成所有 PE 初始化），stub 在原 PE 上原地解密 .text，跳 OEP。

**优点**：
1. **兼容性极高**：OS loader 做完所有 PE 初始化（IAT/reloc/.pdata/TLS/节权限），stub 只需"解密 .text → 跳 OEP"，代码量 700 行
2. **资源天然保留**：原 PE 的 .rsrc 节不动，图标/manifest/版本信息都在
3. **PEB 正确**：`GetModuleHandle(NULL)` 返回真实 PE 基址，不需要 patch PEB.Ldr
4. **OS loader 兼容性好**：所有 PE 特性（SEH/CFG/.NET CLR/异常处理）都由 OS loader 正确处理
5. **stub 极小**：PIC C 无 CRT，stub.bin 仅 6.5KB
6. **反静态分析简单**：只需加密 .text，其他节不动，PE 结构完整
7. **x86 + x64 双架构**：reloc 只需处理 .text 范围，简单
8. **被 EDR 监控少**：无 VirtualAlloc/NtAllocateVirtualMemory 跨节拷贝行为，loader 看到的是正常 PE 加载

**缺点**：
1. **PE 结构暴露**：DOS+NT header、节表、IAT、.rdata、.rsrc 都是明文，静态分析能看到 PE 结构
2. **原 PE 体积不减小**：.text 加密后体积不变，不能压缩
3. **.text 之外的字节都明文**：.rdata/.data/.rsrc 不加密，字符串/常量/资源可读
4. **反 dump 弱**：解密后 .text 在原位明文，dump 工具（PROCDUMP/Process Hacker）可直接 dump
5. **反调试手段受限**：stub 是 PIC 无 CRT，不能直接调 Win32 API（需 PEB walk 解析），反调试选项少
6. **加密算法受 stub 体积限制**：XTEA 30 行够用，AES-GCM 200+ 行会让 stub.bin 膨胀
7. **stub_data 是明文**：xtea_key/pwd_hash/salt/oep_rva/text_rva 都在 .lock.data 节里，可被 strings 抓
8. **.lock 节是明显特征**：节名 `.lock` 在 DIE/YARA 里是 packer 特征
9. **CFG 处理只能简化**：winlock 当前直接清掉 GUARD_CF 标志，损失了 CFG 保护（pe-packer-master 的做法是 patch GFIDS 表把 stub entry 加进去，更完整但复杂）
10. **TLS callback 时序敏感**：stub_tls_callback 在 loader lock 持有期间运行，不能做复杂操作（如 Chrome 的 UIA hook 死锁问题）

### 4.3 适用场景对比

| 维度 | 反射式 loader | in-place 加壳（winlock） |
|------|-------------|------------------------|
| **目标** | 反 EDR / 反逆向 / 反 dump | 密码保护 / 简单门禁 |
| **兼容性要求** | 低（可接受部分 PE 不支持） | 高（要支持各种 GUI 程序） |
| **stub 体积** | 大（50KB+，有 CRT） | 小（6.5KB，PIC 无 CRT） |
| **实现复杂度** | 高（2000 行+） | 低（700 行） |
| **反静态分析** | 强（全文件加密） | 弱（只 .text 加密） |
| **反 dump** | 强（可重新加密/VRAM） | 弱（.text 明文在原位） |
| **反调试** | 强（syscall/unhook） | 弱（PEB walk 受限） |
| **资源保留** | 难（手动复制） | 易（天然保留） |
| **OS 兼容性** | 差（依赖 PEB 偏移） | 好（OS loader 兼容） |
| **EDR 检测** | 高（反射行为明显） | 低（看起来像正常 PE） |

### 4.4 结论：winlock 的定位是正确的

winlock 选择 in-place 加壳是正确的：
- **目标场景**是"密码保护/门禁"，不是"反 EDR/反逆向"
- **兼容性要求高**（要支持各种 GUI 程序），in-place 模式天然兼容
- **stub 极小**（6.5KB PIC 无 CRT），维护成本低
- **资源天然保留**，不需要手动复制图标/manifest

但 winlock 当前的弱点也很明显，应该借鉴反射式 loader 项目的经验来补强：
1. **SecurityCookie 未处理**（必修 bug，抄 peldr + AlushPacker）
2. **栈对齐未做**（必修 bug，抄 peldr）
3. **API 名明文**（应改 hash，抄 peldr DJB15 或 Maldev FNV-1a）
4. **无反调试**（应加 PEB 检查，抄 peldr + TinyLoad）
5. **stub_data 明文**（应加密，抄 TinyLoad stub-key 派生）
6. **.lock 节名特征**（应改名，抄 TinyLoad scramble）
7. **无 IAT 伪装**（应加 IAT Camouflage，抄 AtomPePacker）
8. **无 .text 完整性校验**（应加 canary corridor，抄 TinyLoad）

这些借鉴都在 stub 层面，不需要改变 in-place 加壳的整体架构。

---

## 5. 最值得借鉴的 5 个项目

1. **peldr**（最像 winlock 的项目：-nostdlib PIC C，栈对齐/Cookie/反调试/API hash 全套）
2. **TinyLoad**（反静态分析宝库：stub-key/canary/sdec2/scramble/dead code）
3. **AtomPePacker**（API hash Rotr32 + IAT Camouflage）
4. **pe-packer-master**（唯一同款 in-place + JIT emit，adasm 花指令 + CFG patch）
5. **AlushPacker**（x86 完整 reloc switch + cookie 判断逻辑）

---

**文档版本**：1.0
**最后更新**：2026-07-18
**分析依据**：4 个 subagent 分批深读源码 + 对比 winlock 当前实现
