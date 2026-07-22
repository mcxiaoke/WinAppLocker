# Packer 代码审查报告（补充 / 勘误版）

> 审查日期：2026-07-22  
> 审查范围：`packer/` 全部源码（inplace / reflective / common / cmake / tests / docs）  
> 审查者：hy3  
> 关联文档：`packer/docs/packer-code-review-by-ds4p-20269722b.md`（下称「ds4p 报告」）

---

## 0. 与 ds4p 报告的关系说明

本文**不重复** ds4p 报告中已正确覆盖的内容（双模式架构、注释质量、弹框构造 hack、`OH()` 宏可移植性、魔法数字、`fallback_relocations` 误判、测试缺口、XTEA 安全性等），仅做**补充新发现**与**必要勘误**。

ds4p 报告中存在一处与代码不符的结论（见 §3 勘误），并已因此漏掉一个**会导致 reflective 目标编译失败的真实 bug**（见 §1 P0-N1）。其余分类建议可直接沿用 ds4p 报告。

---

## 1. 逻辑与正确性（新增 / 更正）

### P0-N1. `REFLECTIVE_PAYLOAD_VERSION_V2` 未定义 → reflective loader 编译失败（**新增，ds4p 漏报**）

```c
// packer/reflective/loader.c:585-597
if (hdr->magic != REFLECTIVE_PAYLOAD_MAGIC) return;
if (hdr->version != REFLECTIVE_PAYLOAD_VERSION) return;   // 已经是 v2 才通过
...
if (hdr->version == REFLECTIVE_PAYLOAD_VERSION_V2 && (hdr->flags & RFLAG_ENCRYPTED)) {
```

`payload.h` 中**只定义**了 `REFLECTIVE_PAYLOAD_VERSION`（值为 2），**从未定义** `REFLECTIVE_PAYLOAD_VERSION_V2`。全仓库检索（`grep -r REFLECTIVE_PAYLOAD_VERSION_V2`）仅在 `loader.c:597` 出现一次，无任何 `#define`。

**后果**：`build.ps1` 会构建 `stub_reflective_x64.exe` / `stub_reflective_x86.exe`，而该目标源 `loader.c` 因未定义标识符**无法编译**，整个 reflective 构建链路中断。这也是当前分支（packer-bugfix）很可能处于"构建已坏"状态的直接原因。

**为什么没被测试发现**：`auto_e2e_test.ps1` 依赖 `dist/` 下**预编译**产物，并用 `check_stub_freshness.py` 仅做 warn-only 校验，本身不触发编译。所以 reflective 目标的回归可以长期静默存在。

**修复建议**（最小改动，因为 585 行已用 `version != v2` 拦截，597 的版本判断恒为真）：

```c
/* 原：if (hdr->version == REFLECTIVE_PAYLOAD_VERSION_V2 && (hdr->flags & RFLAG_ENCRYPTED)) */
if (hdr->flags & RFLAG_ENCRYPTED) {
    preferred_base = hdr->image_base;
    size_of_image  = hdr->size_of_image;
    ...
}
```

若希望保留版本演进能力，也可在 `payload.h` 增加 `#define REFLECTIVE_PAYLOAD_VERSION_V2 REFLECTIVE_PAYLOAD_VERSION`，但本场景下前者更简洁。**同时必须在 CI 中对 reflective 目标执行 `cmake --build`**，否则同类回归会再次漏报。

---

### P2-N2. loader 中残留「调试 / 测试代码」用于生产构建（**新增**）

```c
// packer/reflective/loader.c:1801-1823
/* ---- 诊断：测试 patch 后 FindResource 能否找到 DontSleep 的 "AAAA_UNICODE.TMP" 资源 ---- */
...
HRSRC hr = FindResourceW((HMODULE)new_img, L"AAAA_UNICODE.TMP", L"PNG");
```

这是一段**针对特定样本（DontSleep）硬编码资源名**的探测代码，会在 loader 运行期真实调用 `FindResourceW` 并打出 DBG 日志。它不属于运行时逻辑，应：

- 直接删除；或
- 用 `RDEBUG`/`#ifdef REFLECTIVE_SELFTEST` 之类的宏整体包裹，确保 Release 产物不包含该路径。

否则每次启动都会白做一次无意义的资源查找，且暴露了调试样本信息。

---

### P2-N3. `g_tls_decrypted` 定义但从未使用（**新增，死代码**）

```c
// packer/inplace/stub.c:921
static volatile int g_tls_decrypted = 0;
```

全文件检索仅此一处。属于遗留死变量，删除即可（若原计划用于 TLS 解密状态同步，应补上读写或移除声明）。

---

### P2-N4. `sd->image_base` 依赖全局解析状态，存在耦合风险（**新增，稳健性**）

```c
// packer/inplace/builder.c:1028
sd->image_base = OH_IMG_BASE();
```

`OH_IMG_BASE()` 读取全局 `g_nt64/g_nt32` 的 `OptionalHeader.ImageBase`，而 `g_nt*` 会在 `parse_pe()` 中被多次重绑定（先后指向 stub 自身、输入 PE、最终输出 PE，见 `builder.c:622-627` 与 `builder.c:1172` 的 `g_nt64 = (IMAGE_NT_HEADERS64*)(out + ...)`）。

`sd->image_base` 是运行时重定位的基准（`delta = 实际基址 - sd->image_base`）。当前若 `set_stub_data()` 调用时全局恰指向输入 PE 则正确，但**可读性/稳健性差**：一旦 `parse_pe` 调用顺序调整，该字段可能在不知情下变成 stub 或输出 PE 的基址，导致 inplace 模式重定位错位、加载即崩。

**建议**：显式传入输入 PE 的 NT 头指针，例如 `sd->image_base = input_nt->OptionalHeader.ImageBase;`，或在调用处加注释明确"此刻 g_nt 指向输入 PE"。

---

### P2-N5. `reserve_preferred_base_region` 硬编码地址白名单，削弱 v2 显式字段（**新增**）

```c
// packer/reflective/loader.c:599-609
if (preferred_base != 0x400000 && preferred_base != 0x10000
    && preferred_base != 0x140000000 && preferred_base != 0x180000000) {
    return;   // 非"常见值"就放弃预留
}
```

v2 已经在 `reflective_payload_t.image_base` 里**显式**保存了原 PE 的 preferred ImageBase，本应无条件使用。这里的四值白名单是多余的启发式：任何不在此列表中的合法 ImageBase（例如 `0x00400000` 之外的自定义基址）会被静默放弃预留，退化为"任意地址映射"，从而失去 `delta==0`（无需重定位）的快速路径，并增大与已加载模块冲突的概率。

**建议**：删除该白名单判断，直接信任 `hdr->image_base`（已有 `size_of_image` 合理性校验兜底）。如需防御，应改为校验 `image_base` 是否落在合法用户态区间，而非枚举几个魔法值。

---

### §3 勘误：ds4p 报告 L5（密码 ACP vs UTF-8 不一致）属误报

ds4p 报告 L5 称「builder 用 ACP，stub 用 UTF-8，非 ASCII 密码会 hash 不匹配」。实际代码：

```c
// packer/inplace/builder.c:144-147  —— 密码 → UTF-8 用于 KDF
WideCharToMultiByte(CP_UTF8, 0, src, -1, ...);
```

builder 的**密码→UTF-8 这一步使用 `CP_UTF8`**，与 stub 端 `utf16le_to_utf8()` 的 UTF-8 语义一致，**核心 KDF 输入是 UTF-8，并不存在 ACP/UTF-8 混用导致的 hash 不匹配**。

ds4p 报告看到的是另一处 `CP_ACP`：

```c
// packer/inplace/builder.c:586 / 590  —— 仅用于把命令行 -p 参数从 ANSI 转 UTF-16
MultiByteToWideChar(CP_ACP, 0, "test123", -1, password, 63);
MultiByteToWideChar(CP_ACP, 0, pwd_arg, -1, password, 63);
```

即 `CP_ACP` 只出现在**从 `argv` 读取 `-p` 明文密码**的环节（`main(int, char**)` 拿到的是 ANSI 字符串）。对纯 ASCII 密码无影响；仅当用户在命令行输入**非 ASCII 密码**时，argv 的 ACP 解码可能与 stub 端用户从对话框输入的 UTF-16 不一致。

**结论**：L5 的"hash 不匹配"主论断不成立（P0 应下调/撤销）。但有一个真实的小改进点（见 P2-N8）。

---

## 2. 安全性（补充）

### P2-N8. 命令行密码的 `CP_ACP` 解码应改为 `CP_UTF8`（**更正 ds4p L5 后的真实建议**）

如上勘误，`builder.c:586/590` 的 `MultiByteToWideChar(CP_ACP, ...)` 只是为了把 `-p` 参数转成 UTF-16。为保证与 stub（UTF-16→UTF-8）在任意非 ASCII 密码下完全一致，应改为 `CP_UTF8`：

```c
MultiByteToWideChar(CP_UTF8, 0, pwd_arg, -1, password, 63);
```

同时建议在 `-p` 路径加警告：命令行密码会进入 shell 历史 / 进程参数，存在泄露风险（stub 中已有相关提示，builder 侧可补一句）。

---

## 3. 代码质量 / 架构（补充 ds4p A1 的具体落点）

### P1-N9. 对话框 / 密码 UI 在 stub.c 与 loader.c 中近乎逐字节重复（**补充 ds4p A1**）

ds4p A1 已指出 `build_dialog/verify_password/dlg_proc/prompt_password` 重复。补充可落地点：

- `packer/inplace/stub.c:329 build_dialog`、`stub.c:398 verify_password`、`stub.c:415 dlg_proc`、`stub.c:745 prompt_password`
- `packer/reflective/loader.c:659 build_dialog`、`loader.c:727 verify_password`、`loader.c:745 dlg_proc`、`loader.c:774 prompt_password`

两者对话框模板字节布局**完全相同**（都是手动 `put_word` 构造 `DLGTEMPLATE` + 控件）。可抽到 `common/ui_dialog.h`（仍用 `WINLOCK_NOINLINE/WINLOCK_USED` 防止被优化），由两端 `#include`。这样若一端修复弹框逻辑，另一端不会悄悄漂移。注意 stub 端为无 CRT 的 PIC 环境、loader 端为带 CRT 的 EXE，差异仅在于字符串转换（UTF-8 vs `WideCharToMultiByte`）和"测试密码"来源，可用 `#ifdef` 隔离。

### P2-N6. 更多魔法数字应常量化（**补充 ds4p Q1**）

除 ds4p Q1 列出的 `0x40010006 / 0x406D1388 / 0x400000-0x500000` 外，还有：

```c
// loader.c:595-596
if (size_of_image == 0 || size_of_image > 64 * 1024 * 1024) {
    size_of_image = 2 * 1024 * 1024;  /* 2MB 兜底 */
}
```

建议：

```c
#define MAX_PAYLOAD_SIZE_OF_IMAGE (64u * 1024 * 1024)
#define DEFAULT_SIZE_OF_IMAGE    ( 2u * 1024 * 1024)
#define VEH_IMG_RANGE_LO  0x400000
#define VEH_IMG_RANGE_HI  0x500000
#define VE_CODE_DBG_PRINT      0x40010006  /* DBG_PRINTEXCEPTION_C */
#define VE_CODE_SET_THREADNAME 0x406D1388  /* MS_VC_EXCEPTION */
```

### P2-N10. stub 节布局契约缺少单一事实来源（**新增，流程/稳健性**）

构建链依赖多处隐式约定：

- `stub.ld` 用 `KEEP` 固定 `.text2` 内符号顺序，builder 用 `STUB_DATA_MAGIC` / `STUB_TLS_CB_MAGIC` / `STUB_ENTRY_MAGIC` 按偏移搜索；
- `patch_stub_identity.py` 按**固定偏移**回填 `stub_arch/toolchain/bin_ver/build_time/source_crc/githash`；
- `extract_lock_section.py` 提取 `.lock` 节做"是否仍含明文 MZ"自检。

C 端（stub.ld / config.h 偏移假设）与 Python 端（patch/extract 偏移）必须**严格一致**，但代码里没有一份"节布局契约"文档，也没有编译期断言校验这些偏移。一旦某次改动调整了 `stub_identity_t` 大小或节排布，Python 与 C 会**静默错位**，自检形同虚设。

**建议**：在 `docs/` 增加 `STUB_LAYOUT.md`，用一张表列出每个 magic / 每个 identity 字段的节名、偏移、长度，并尽量在 `patch_stub_identity.py` 中从 `config.h`/`stub_identity_t` 自动推导偏移（而非手写常量）。

---

## 4. 测试（补充 ds4p T1/T2/T3）

### P1-N7. 缺少对 reflective 目标的编译门禁（**新增，源自 P0-N1**）

当前 e2e 测试用预编译 `dist/`，本身不编译，导致 P0-N1 这类编译级回归能长期存在。

**建议**：
1. CI 中对 **inplace 与 reflective 两个目标都执行 `cmake --build`**（任何失败即红）。
2. 增加一个最小 smoke 测试：`builder_reflective` 对 `hello` 样本加壳 → 运行 → 校验退出码，保证 reflective 链路端到端可用。
3. `check_stub_freshness.py` 的 warn-only 行为应至少在 CI 中转为 error（或单独一个"strict"开关）。

### P2-N11. 无加密/压缩路径的定向验证（**新增**）

`auto_e2e_test.ps1` 覆盖 inplace×reflective×密码/测试组合数，但（据现有样本与断言）主要验证"能跑到退出码"。建议补充：
- 用 `inspect_stub.py` 断言加壳后 `.text`/`.payload` 不再是明文 MZ（验证加密确实生效）；
- 显式构造无 `.reloc` 的 PE 触发 `fallback_relocations`，验证其不崩溃（ds4p L1 已指出其误判风险，应有回归用例兜底）；
- 显式构造带 TLS callback 的样本，验证回调在 OEP 前被调用。

---

## 5. 新增 / 更正发现汇总表

| 编号 | 类别 | 优先级 | 标题 | 预计工时 | 状态 |
|------|------|--------|------|----------|------|
| N1 | 逻辑 | **P0** | 修复 `REFLECTIVE_PAYLOAD_VERSION_V2` 未定义导致 reflective 编译失败 | 0.25h | 新增（ds4p 漏报） |
| N7 | 测试 | **P1** | CI 对 reflective 目标加编译门禁 + smoke 测试 | 2h | 新增 |
| N9 | 架构 | **P1** | 提取 `build_dialog/verify_password/dlg_proc/prompt_password` 到 `common/ui_dialog.h` | 3h | 补充 ds4p A1 |
| N2 | 质量 | **P2** | 删除 loader 中 DontSleep 硬编码调试代码（FindResource 探测） | 0.5h | 新增 |
| N3 | 质量 | **P2** | 删除未使用的 `g_tls_decrypted` | 0.1h | 新增 |
| N4 | 稳健性 | **P2** | `sd->image_base` 改为显式传入输入 PE 基址，避免依赖全局解析状态 | 1h | 新增 |
| N5 | 稳健性 | **P2** | 删除 `reserve_preferred_base_region` 的地址白名单，信任 `hdr->image_base` | 0.5h | 新增 |
| N6 | 质量 | **P2** | 常量化 size_of_image / VEH 区间 / 异常码等魔法数字 | 1h | 补充 ds4p Q1 |
| N8 | 安全 | **P2** | 命令行密码 `MultiByteToWideChar` 改用 `CP_UTF8` | 0.25h | 更正 ds4p L5 |
| N10 | 流程 | **P2** | 建立 stub 节布局契约文档 + Python 偏移自动推导 | 3h | 新增 |
| N11 | 测试 | **P2** | 增加加密生效 / 无 reloc / TLS 回调定向回归用例 | 3h | 新增 |
| — | 勘误 | — | ds4p L5（密码 ACP vs UTF-8 不一致）不成立，主论断撤销 | — | 更正 |

---

## 6. 优先级行动建议

1. **立刻（本分支）**：修 N1（一行改动），并跑一次 `build.ps1` 确认 reflective 目标可编译通过。
2. **本周**：加 N7 的 CI 编译门禁，避免 N1 类问题复发；清理 N2 / N3 死代码。
3. **本月**：实施 N9（去重 UI 代码）、N4 / N5（稳健性），并补 N11 定向测试。
4. **长期**：N6 / N8 / N10 随重构一并处理；加密算法升级（AES/ChaCha20，ds4p S1）纳入 v3 规划。

---

## 7. 总结

在 ds4p 报告良好覆盖的基础上，本次审查的核心增量价值是：

- **发现并定位一个真实编译阻断 bug（N1）**：`loader.c:597` 引用未定义的 `REFLECTIVE_PAYLOAD_VERSION_V2`，使 reflective 目标无法编译；ds4p 报告漏报，且因 e2e 测试不触发编译而长期隐藏。修复成本极低（约一行），但必须有编译门禁才能防止复发。
- **更正 ds4p 的一处误报（L5）**：密码 KDF 在 builder 端实际使用 `CP_UTF8`，与 stub 端一致，不存在 hash 不匹配；仅命令行 `-p` 参数的 ACP 解码存在极窄的非 ASCII 风险（N8）。
- **补充若干稳健性 / 死代码 / 调试残留问题（N2–N6, N10）**，以及把"去重 UI 代码""魔法数字常量化"落到具体文件与行号，便于直接执行。

整体评价与 ds4p 一致：项目架构清晰、注释详尽、对边界情况有真实投入；主要风险不在功能逻辑，而在**构建/测试的回归防护不足**与**跨文件隐式契约（节布局、全局解析状态）缺乏单一事实来源**。补齐编译门禁与布局契约文档，是当前性价比最高的两项改进。
