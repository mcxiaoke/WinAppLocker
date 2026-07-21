# 构建系统改进计划审查报告

> 审查对象：`docs/BUILD_SYSTEM_IMPROVEMENT_PLAN.md`
> 核对代码：`packer/` 子目录（config.h、build.ps1、builder.c、stub.c、CMakeLists-*.txt、inplace/CMakeLists.inc、reflective/{payload.h,builder_reflective.c,CMakeLists.inc}、cmake/msvc_setup.cmake）
> 审查时间：2026-07-21 15:00

## 一、总体结论

计划目标正确、问题定位基本准确（x86/x64 工具链不一致、缺乏可追踪身份块、无 manifest、无端到端校验），整体方向值得推进。计划提出的"在 `stub_data_t` / `reflective_payload_t` 中嵌入 32 字节身份块，配合构建期注入与打包期校验"是合理且低侵入的设计。

**但存在 3 个必须在落地前修正的正确性缺陷（其中 1 个会导致 MSVC 下编译失败），以及若干与现有实现不符的描述和冗余/过度复杂的改动。** 最关键的一条优化建议是：**砍掉"改动 8"新增的 `.winlock` 节**——身份块已经随 `.lock` 节（inplace）或 payload（reflective）进入加壳产物，直接从产物里读 `stub_data_t` 即可反查，无需新增高风险 PE 节。

---

## 二、必须修正的正确性缺陷（Critical）

### 缺陷 1：`GITHASH_BYTES` 宏无法在 MSVC 下编译（改动 1 / 改动 3）

计划给出的宏：

```c
#define EXPAND_GITHASH(c0,c1,c2,c3,c4,c5,c6,c7) {(c0),(c1),(c2),(c3),(c4),(c5),(c6),(c7)}
#define GITHASH_BYTES(s) EXPAND_GITHASH s
// 使用：.stub_githash = GITHASH_BYTES(STUB_GITHASH)
// 其中 STUB_GITHASH 由 CMake 定义为字符串字面量 "abc12345"
```

`STUB_GITHASH` 是带引号的字符串 `"abc12345"`。展开过程：

```
GITHASH_BYTES("abc12345")  ->  EXPAND_GITHASH "abc12345"
```

`EXPAND_GITHASH` 是要求 8 个参数的函数式宏，但实际只收到**一个** 预处理 token（整个字符串字面量），属于参数个数不匹配，**预处理阶段直接报错**。即使去掉引号，`abc12345` 仍是一个标识符 token，同样报错。此宏**不可用**。

**建议（简单、稳健）**：不要在预处理器里拆字符串。在构建脚本里把 8 位 git 短 hash 算成逗号分隔的字节初始值宏，C 端直接展开：

```cmake
# CMake / PowerShell 里：
execute_process(COMMAND ${Python3_EXECUTABLE} -c
  "import subprocess,sys;h=subprocess.check_output(['git','rev-parse','--short=8','HEAD']).decode().strip();print(','.join(str(ord(c)) for c in h.ljust(8,'0')))"
  OUTPUT_VARIABLE GITHASH_LIST)   # 形如 "97,98,99,49,50,51,52,53"
target_compile_definitions(stub_inplace_x64 PRIVATE "STUB_GITHASH_BYTES=${GITHASH_LIST}")
```

```c
.stub_githash = { STUB_GITHASH_BYTES },   // 展开为 {97,98,99,...}
```

这样 MSVC / MinGW 两条路径完全一致，且彻底消除对 `.githash` 符号（改动 2）的依赖（见"建议 5"）。

---

### 缺陷 2：checksum 范围说明与实现不符，且存在隐性顺序依赖

计划写道："新增的 32 位字段不参与 checksum（避免改动 builder 的 checksum 逻辑）""保持 XOR 所有 64-bit 字段"。

但 `builder.c:998-1004` 的实际实现是：

```c
uint64_t* p = (uint64_t*)sd;
size_t sd_qwords = (sizeof(stub_data_t) - sizeof(uint64_t)) / sizeof(uint64_t);
for (qi = 0; qi < sd_qwords; qi++) cs ^= p[qi];
sd->checksum = cs;
```

它是把**整个 `stub_data_t`（除末位 checksum 自身外）按 8 字节逐段 XOR**，因此**新增的 32 字节 identity 块（占 4 个 qword）必然被纳入 checksum**。计划文字与实现相反。

这在当前构建顺序下"碰巧正确"：builder 在打包阶段**最后一个**计算 checksum（builder.c:998），而 `patch_stub_identity.py` 在 `build.ps1` 阶段已把 `stub_size` 写入 `stub.bin`，故 builder 计算的 checksum 已包含打好补丁的 `stub_size`，运行时（若实现校验）一致。

但存在两个隐患：

1. **顺序硬约束未写明**：计划把"patch 在 builder 之前"当成隐含前提。一旦有人后跑 patch 或只重新打包不重新 patch，checksum 就会失配（届时 stub 如果开始做运行时校验就会失败）。
2. **当前 stub 运行时并不校验 checksum**：`stub.c:119` 仅 `.checksum = 0`，没有任何运行时重算/比对代码；`payload.h:69` 也注明"v1 暂不校验"。因此"防篡改"目前是**空头承诺**，identity 是否与 checksum 相关其实无所谓，直到有人补上运行时校验为止。

**建议**：
- 修正计划文字，明确"identity 块**包含**在 checksum 中，且 `patch_stub_identity.py` 必须在 builder 打包之前执行"这一约束。
- 若希望身份块与 checksum 解耦，改 checksum 循环（跳过 identity 区间）也可行，但需同时改 builder 与 stub 两端。鉴于 stub 当前不校验，优先级不高。
- 若真要"防篡改"，应在 stub 端补一段运行时 checksum 重算（仅几十行），否则整个 checksum 字段没有意义。

---

### 缺陷 3：改动 12 缺少"builder 把 stub 身份拷入 payload"的步骤

计划给 `reflective_payload_t` 新增了 `stub_identity_t identity;` 字段，但**没有说明 builder 如何填充它**。当前 `builder_reflective.c` 只整体追加 payload，并不读取 stub PE 里的 `stub_data_t`。

若不补这一步，`reflective_payload_t.identity` 永远是 0，反查功能对 reflective 模式完全失效。

**建议**：在 `builder_reflective.c` 里新增——加载 stub PE（`read_file`）后用与 inplace 相同的 `STUB_DATA_MAGIC` 检索其 `stub_data_t`，取出 `identity` 拷进 `hdr->identity`。reflective stub 本身也必须通过"改动 3"的 CMake 注入拿到自己的 identity（计划已要求，需确保两端一致）。

---

## 三、与描述/现状不符或冗余的改动（Medium）

### 改动 7（reflective arch 校验）基本冗余

计划动机"防止用 x64 stub 加壳 x86 PE"，但 `builder_reflective.c:517` 已有 `s_machine != info.machine` 的硬性校验（`报错并退出`）。改动 7 与原逻辑重复，几乎不增加新价值。

**建议**：可省略；如为防御纵深保留，做成对既有校验的薄封装即可，不必独立成函数重复读取 PE Machine。

### 改动 8（新增 `.winlock` 节）复杂度最高且大部分冗余 —— 强烈建议砍掉

这是计划里**最重、风险最大**的一项：需要手工操作 PE 节表、`NumberOfSections`、`SizeOfImage` 并清零 `CheckSum`（见 `packer/docs/REFLECTIVE_ANALYSIS.md:283` 已有的加节经验）。但它提供的信息，**绝大部分已经被内嵌身份块覆盖**：

- inplace 模式：identity 块是 `stub_data_t` 的一部分，而 `stub_data_t` 位于 `.lock` 节、随加壳产物一起写出。直接读产物 `.lock` 节、搜 `STUB_DATA_MAGIC`、解析 `stub_data_t` 即可拿到 arch/toolchain/build_time/source_crc/githash/size。
- reflective 模式：`reflective_payload_t` 同样内嵌 identity（改动 12）。

也就是说，**反查加壳产物用哪个 stub** 不需要新节，读既有数据即可。

**建议**：删除改动 8。把 `inspect_stub.py` 升级为同时支持：
- 输入 `.bin`/`.exe` stub → 解析 `stub_data_t`；
- 输入加壳产物 exe → 定位 `.lock` 节（inplace）或 payload（reflective），解析其中 `stub_data_t` / `reflective_payload_t`，打印身份。

若确实想要 `packer_ver` / `pack_time` / `stub_crc32` 这类"构建侧"信息，再考虑一个**极小可选节**（或干脆只保留 `pack_time`+`packer_ver` 的 16 字节节），不必像计划那样搬一整个 `winlock_meta_t`。这是"不大幅增加复杂度"的关键取舍。

---

## 四、不大幅增加复杂度的优化建议（Low / Nice-to-have）

### 建议 4：identity 插入位置建议放 struct 末尾（checksum 之前）

计划把 identity 插在 `reserved16` 之后、`oep_rva` 之前，会整体平移所有后续 64 位字段的偏移。虽然 `STUB_DATA_VERSION` 守卫保证同版本整体重建（旧 stub 会被 `verify_stub_identity` 的版本校验拒掉，见 builder.c 既有 `cand->version != STUB_DATA_VERSION` 逻辑），但把高频字段（oep_rva/text_rva/image_base…）的偏移都挪动，风险高于必要。

**建议**：把 32 字节 identity 块追加在 `stub_data_t` 末尾、`checksum` 之前（对 `reflective_payload_t` 同理，计划其实已是这么放的）。checksum 循环按 qword 遍历，位置不影响正确性；高频字段偏移不变，回归面最小。

### 建议 5：统一 MSVC / MinGW 的 githash 注入方式

计划改动 2 让 MinGW 走 `.githash` 符号 + `nm`/`objdump` 抽取，改动 3 让 MSVC 走 `-D` 宏。两条路径在 patch 脚本里要分别处理。

**建议**：两条路径都用构建脚本算出的 `-DSTUB_GITHASH_BYTES=...` 字节宏（见缺陷 1 的做法）。MinGW 的 gcc 也接受该宏，可删除 `.githash` 符号逻辑，`patch_stub_identity.py` 只需统一补 `stub_size`，脚本复杂度显著下降。

### 建议 6：manifest 解析 bug（改动 9）

```powershell
$info = python ${root}\cmake\inspect_stub_bin.py $f.FullName
$manifest.stubs += $info
```

`$info` 是 Python 的 stdout 字符串，`ConvertTo-Json` 会把它当字符串嵌进去，而不是结构化对象。要求 `inspect_stub_bin.py` 输出 JSON，并：

```powershell
$info = python ... | ConvertFrom-Json
$manifest.stubs += $info
```

另外 manifest 还引用了 `stub_crc32`，需确认该脚本计算 `crc32(stub.bin)`（可用于与 `stub_source_crc` 区分：前者是二进制 CRC，后者是源码 CRC）。

### 建议 7：`string(TIMESTAMP "%s")` 的 `%s` 可移植性

计划改动 3 用 `string(TIMESTAMP STUB_BUILD_TIME "%s" UTC)`。`%s`（Unix epoch 秒）并非在所有 CMake/平台组合下都受支持，且与 MinGW 路径用 Python 算的方式不一致。

**建议**：CMake 路径也用 Python 算 epoch（`execute_process` 调 `${Python3_EXECUTABLE} -c "import time;print(int(time.time()))"`），保证两条路径字节级一致，并消除 `%s` 隐患。

### 建议 8：`STUB_DATA_VERSION` 在多处硬编码

`config.h` 与 `patch_stub_identity.py`、`inspect_stub_bin.py`、测试脚本都写了 `5`。下次升级版本要改 4 处，易漏。

**建议**：至少在一处统一注释；更稳妥是让 Python 脚本从 `config.h` 解析 `#define STUB_DATA_VERSION`，避免漂移。

### 建议 9：patch 只在 `-UseDist` 跑，dev 路径退化为仅版本校验

`build.ps1` 仅在 dist 路径调用 `patch_stub_identity.py`。dev 路径 `stub_size=0`，`verify_stub_identity` 的 `stub_size` 三重校验被跳过，只剩 version 校验。

**建议**：patch 成本极低，建议 dev 路径也始终执行（仅写 `stub_size`）；或至少在文档里写明 dev 产物不做 size 校验。

### 建议 10：端到端测试应比对 CRC 并校验产物 identity（改动 11）

当前测试脚本只**读取并打印** `stub_source_crc`，未与本地重算的 CRC 比对；且只检查 stub，不检查加壳产物。

**建议**：
- 用 Python 重算 `crc32(stub.c + stub_asm)` 与内嵌 `stub_source_crc` 比对，发现构建漂移；
- 加一步：解析加壳产物 `.lock` 节里的 `stub_data_t.identity`，确认与所用 stub 的 identity 一致（端到端反查验证，直接验证"建议 4"砍掉 `.winlock` 后的可行性）。

### 建议 11：测试脚本 magic 检索未 8 字节对齐

`data.find(magic)` 从任意偏移开始匹配。对小型 stub 文件无碍，但建议按 8 字节步长对齐搜索以减少误报风险。

### 建议 12：修正 `build.ps1` 头部与计划矛盾的注释

`build.ps1:21` 注释写"`stub_inplace_x86.bin` - inplace x86 stub (MSVC 构建)"，但代码实际让 MinGW 覆盖 x86 stub（archs 含 x86，拷贝到 `build\x86`，dist 收 `build\x86\stub_inplace_x86.bin`）。计划"问题 2"已正确指出 dist 的 x86 实为 MinGW（7856 字节），与脚本注释自相矛盾，应修正注释。

### 建议 13：`stub_source_crc` 跨工具链一致性（计划已正确要求，补充一点）

计划要求 MSVC/MinGW 用同一 Python 片段算 CRC（基于 `stub.c + stub_asm`），这点正确。补充：CRC 基于**源文件文本**，需确保两条路径读取的是同一份文本（建议统一为 LF 或显式归一化行尾），否则同一份源码可能因行尾不同产生不同 CRC，反而削弱可比性。

---

## 五、落地优先级建议

| 优先级 | 项 | 说明 |
|--------|----|------|
| P0 | 缺陷 1 | 修正 `GITHASH_BYTES` 宏，否则 MSVC 编译不过 |
| P0 | 缺陷 3 | 补 reflective builder 拷 identity 到 payload 的步骤 |
| P0 | 缺陷 2 | 修正 checksum 文字，明确 patch 先于 builder 的约束 |
| P1 | 建议 4（砍 `.winlock` 节） | 最高性价比简化，去除最高风险改动 |
| P1 | 建议 5/6 | 统一 githash 注入、修正 manifest 解析 |
| P2 | 建议 4/7/8/9/10/11/12/13 | 稳健性、可维护性、文档一致性 |

---

## 六、一句话总结

计划方向对、问题找得准，但存在一处会令 MSVC 编译失败的宏缺陷、与现有 checksum 实现不符的描述、以及一处会让 reflective 身份字段恒为 0 的步骤缺失；同时"改动 8"新增 `.winlock` 节风险高且冗余，**删掉它、改读已内嵌在产物里的 `stub_data_t` 身份块**，能在不增加复杂度的前提下达成全部反查目标。
