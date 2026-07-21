# packer 子目录代码审查报告

- 审查日期：2026-07-20
- 审查范围：`packer/`（inplace 加壳器、reflective 反射加载器、common 公共头、相关构建脚本与测试脚本）
- 对照基准：Microsoft PE/COFF 规范（`IMAGE_LOAD_CONFIG_DIRECTORY32/64`、`IMAGE_BASE_RELOCATION`、资源目录条目高位语义、`IMAGE_RESOURCE_DIRECTORY_ENTRY`）、C 运行库约定（MSVC SecurityCookie 默认值）

## 审查结论速览

| # | 严重度 | 位置 | 问题 |
|---|--------|------|------|
| 1 | **高** | `packer/inplace/builder.c` (约 975-981 行) | x86 下 `SecurityCookie` 偏移写错（读成 0x40，应为 0x3C） |
| 2 | **高** | `packer/reflective/loader.c` `activate_manifest_from_image` (1734、1748 行) | 资源子目录偏移未屏蔽高位 0x80000000，导致带 manifest 的 PE 解析越界 |
| 3 | 低 | `packer/inplace/builder.c` (AOC 检测处) | `rva_to_raw` 返回 0 的歧义；x86 缺失 AOC 仅告警未中止 |
| 4 | 低 | `packer/inplace/builder.c` `rva_to_raw` | 返回 0 既表示“未找到”也表示“raw 偏移 0”，存在歧义 |
| 5 | 低 | `packer/inplace/stub.c` `prompt_password` | `max_retries` 实际未生效（密码错误时对话框不返回，`retries` 永不自增） |
| 6 | 低 | `packer/tests/check_pe_header.py` (22 行) | x86 PE 的 `ImageBase` 读取偏移错误（读了 `BaseOfData`） |
| 7 | 设计/安全 | `packer/inplace/stub.c` TLS_PROXY 模式 | 解密在密码校验之前完成（解密先于鉴权） |

---

## 1. [高] x86 `SecurityCookie` 偏移错误（`builder.c`）

### 现象

```c
949:    /* ...
954:     *       PE32+ (64 位): 0x58 (ULONGLONG)
955:     *       PE32  (32 位): 0x40 (DWORD)        <-- 错误
... */
975:                } else {
976:                    /* IMAGE_LOAD_CONFIG_DIRECTORY32.SecurityCookie @ 0x40, 4 字节 */
977:                    if (lc_size >= 0x44) {
978:                        cookie_va = *(uint32_t*)(lc + 0x40);   <-- 读到了 SEHandlerTable
979:                        have_cookie = 1;
980:                    }
981:                }
```

### 规范对照

`IMAGE_LOAD_CONFIG_DIRECTORY32`（32 位，所有字段 ≤4 字节，无填充）各字段偏移：

```
0x00 Size
0x04 TimeDateStamp
0x08 MajorVersion
0x0A MinorVersion
0x0C GlobalFlagsClear
0x10 GlobalFlagsSet
0x14 CriticalSectionDefaultTimeout
0x18 DeCommitFreeBlockThreshold
0x1C DeCommitTotalFreeThreshold
0x20 LockPrefixTable
0x24 MaximumAllocationSize
0x28 VirtualMemoryThreshold
0x2C ProcessHeapFlags
0x30 ProcessAffinityMask
0x34 CSDVersion
0x36 DependentLoadFlags
0x38 EditList
0x3C SecurityCookie          <-- 正确偏移
0x40 SEHandlerTable          <-- 代码实际读到的位置
0x44 SEHandlerCount
```

也就是说 32 位 `SecurityCookie` 在 **0x3C**，而代码读的是 **0x40（SEHandlerTable，即 SafeSEH 表）**；阈值也写成 `lc_size >= 0x44`，实际只需 `lc_size >= 0x40`（64）即可包含 `SecurityCookie`。

> 注：64 位路径（`0x58`）是正确的——`IMAGE_LOAD_CONFIG_DIRECTORY64` 在 `DependentLoadFlags` 之后、8 字节的 `EditList` 之前有 4 字节填充，使 `SecurityCookie` 落在 0x58，符合规范。所以此 bug 仅影响 32 位。

### 影响

`builder` 把 `SEHandlerTable`（SafeSEH 表）的 VA 当成 `SecurityCookie` 写入 `stub_data.security_cookie_rva`。运行时 `stub.c::init_security_cookie` 会向该位置写入一个随机值，结果是：

- 破坏了目标 PE 的 SafeSEH 表指针（若目标启用了 SafeSEH，`SEHandlerTable != 0`）；
- 真正 `.data` 里的 `SecurityCookie` 从未被 stub 重新初始化。在 TLS_PROXY 模式下，目标 TLS callback 先于 CRT 运行且可能使用 `/GS`，此时 cookie 仍为默认值，会误报 `__report_gsfailure` 导致进程终止。

触发条件：目标为 **32 位** 且同时启用 **/GS（SecurityCookie）** 与 **SafeSEH（SEHandlerTable）** 的 PE。

### 修复建议

```c
} else {
    /* IMAGE_LOAD_CONFIG_DIRECTORY32.SecurityCookie @ 0x3C, 4 字节 */
    if (lc_size >= 0x40) {
        cookie_va = *(uint32_t*)(lc + 0x3C);
        have_cookie = 1;
    }
}
```
同时修正上方注释中的偏移说明。

---

## 2. [高] 资源子目录偏移未屏蔽高位（`loader.c`）

### 现象

`activate_manifest_from_image` 遍历资源目录定位 `RT_MANIFEST`(24) 时：

```c
1733:    IMAGE_RESOURCE_DIRECTORY* name_dir =
1734:        (IMAGE_RESOURCE_DIRECTORY*)(rsrc_base + manifest_type->OffsetToDirectory);  // 未 & 0x7FFFFFFF
...
1747:    IMAGE_RESOURCE_DIRECTORY* lang_dir =
1748:        (IMAGE_RESOURCE_DIRECTORY*)(rsrc_base + name_entry->OffsetToDirectory);     // 未 & 0x7FFFFFFF
...
1760:    IMAGE_RESOURCE_DATA_ENTRY* data_entry =
1761:        (IMAGE_RESOURCE_DATA_ENTRY*)(rsrc_base + lang_entry->OffsetToData);          // 叶子节点，高位为 0，正确
```

### 规范对照

`IMAGE_RESOURCE_DIRECTORY_ENTRY` 的 `OffsetToDirectory` 字段（中间层级）高位 `0x80000000` 置位表示“指向子目录偏移”，真正偏移是低 31 位。代码未做 `& 0x7FFFFFFF` 掩码，于是 `rsrc_base + 0x80000000 + 真实偏移` 会指向资源目录之外的野地址。

值得对照的是：同仓库 `packer/tests/analyze_samples.py`（339-348 行）对资源条目的处理是**正确**的（`is_subdir = (off_to_data & 0x80000000) != 0; sub_off = off_to_data & 0x7FFFFFFF;`）。说明 C 加载器与 Python 参考实现在此处不一致，C 侧有 bug。

### 影响

对任何**内嵌 manifest** 的 PE（GUI 程序、依赖 Common Controls v6 / 并排程序集的程序极为常见），`name_dir`/`lang_dir` 指向越界内存，`name_dir->NumberOfNamedEntries` 等读到垃圾值；若垃圾计数值很大，`name_entries[0]` / `lang_entries[0]` 会读取野指针，导致 `AV` 崩溃或 manifest 永远“找不到”（返回 1 被误判为“无 manifest”）。该函数在反射加载流程 `map_image` 末尾被调用，可能使加壳后的程序在加载阶段崩溃。

### 修复建议

```c
IMAGE_RESOURCE_DIRECTORY* name_dir =
    (IMAGE_RESOURCE_DIRECTORY*)(rsrc_base + (manifest_type->OffsetToDirectory & 0x7FFFFFFF));
...
IMAGE_RESOURCE_DIRECTORY* lang_dir =
    (IMAGE_RESOURCE_DIRECTORY*)(rsrc_base + (name_entry->OffsetToDirectory & 0x7FFFFFFF));
```
（叶子节点的 `OffsetToData` 高位为 0，可保持原样或同样掩码，均无副作用。）

---

## 3. [低] `rva_to_raw` 与 AOC 检测的健壮性

### 3.1 返回 0 的歧义

`rva_to_raw` 在“找不到所在节”时返回 `0`，而 `0` 同时也是合法的 raw 偏移（RVA 0 → 文件起始）。调用处用 `if (tls_raw != 0)` / `if (cb_raw != 0)` / `if (aoc_raw == 0)` 来判定“存在”。对于数据目录，`VirtualAddress == 0` 本身即表示“无此项”，所以普通情况下语义恰好成立；但当某个真实存在的目录 RVA 落入节外（畸形/异常 PE）时，`rva_to_raw` 返回 0 会被误判为“目录在 raw 0（DOS 头处）”，进而读取垃圾。属于健壮性边界问题，正常 PE 不触发。

### 3.2 x86 缺失 AOC 仅告警未中止

检测 Anti-Debug/OEP 的 AOC 时：

```c
DWORD aoc_raw = rva_to_raw(sec, n_sec, aoc_dir->VirtualAddress);
if (aoc_raw == 0)
    printf("[-] ... AntiDebug/OEP 结构未在节内找到（改用 fallback）...\n");
// 注意：此处没有 return 1，继续往下走
```

对 64 位这是可接受的（多数 64 位 PE 无 AOC，走 fallback）；但对 **32 位**，`lock_stub_antidebug_oep` 是 OEP/TLS 回调的主要来源，缺失会直接导致 `sd->oep_rva` 等为 0、产出损坏的加壳文件。建议对 x86 在确认无 AOC 时 `return 1` 报错，而不是继续。

---

## 4. [低] `prompt_password` 的 `max_retries` 未生效

`dlg_proc` 在密码错误时返回 `FALSE`（不调用 `EndDialog`），对话框保持打开；只有“正确密码”或“Cancel”才会让 `DialogBoxIndirectParamW` 返回。因此 `do { ...; retries++; } while (retries < max_retries);` 实际只执行一次——密码错误根本不会让 `DialogBoxIndirectParamW` 返回，`retries` 永远不会自增，最大重试次数形同虚设（用户可无限次输错，只有点 Cancel 才退出）。非崩溃性逻辑瑕疵，建议要么在密码错误时 `EndDialog(hDlg, 2)` 并以不同返回值触发重试计数，要么移除 `max_retries` 相关死代码。

---

## 5. [低] `check_pe_header.py` 的 x86 `ImageBase` 读偏移

```python
22:    img_base = struct.unpack_from('<Q' if is_x64 else '<I', data, oh_off + 24)[0]
```

- 64 位：`ImageBase` 在可选头偏移 24，8 字节——正确。
- 32 位：`ImageBase` 在可选头偏移 **28**（前面是 `BaseOfCode`@20、`BaseOfData`@24）；此处在偏移 24 用 4 字节读取，实际读到的是 `BaseOfData`，并非 `ImageBase`。

这是测试/校验脚本的显示错误（不影响加壳产物），但会在对比 x86 输入/输出时给出错误的 `img_base` 值。其余可选头字段（`SizeOfImage` 等）在 PE32/PE32+ 中偏移一致，读取正确。顺带一提，`dd_off = oh_off + 96` 的数据目录数组起始偏移对 PE32 和 PE32+ 都是 96，正确。

---

## 6. [设计/安全] TLS_PROXY 模式“先解密、后鉴权”

`stub.c` 当前设计为：TLS_PROXY 模式下密码弹框放在 `stub_entry`（CRT `main` 内，loader lock 释放后），而 `.text` 解密在 `stub_tls_callback`（进程加载阶段，先于密码校验）完成。这意味着**受保护代码在密码验证通过之前就已经在内存中还原**。

- 功能上不影响运行（验证失败会 `ExitProcess`），但违背了“密码正确才解密”的安全初衷：调试器可在 TLS callback 处断下并 dump 已解密的 `.text`。
- 若确实需要在 TLS_PROXY 模式下保护器密性，需把解密逻辑也挪到密码校验之后（代价是 TLS callback 中不能引用已加密的 `.text`，需要重构 stub 进入流程）。当前实现属于已知取舍，建议在文档中明确标注。

---

## 已核对为正确的关键点（增强结论可信度）

- **inplace `stub.c::apply_relocations` / `builder.c::patch_stub_relocations`**：均按 16 位 `WORD` 条目解析，`type = entry >> 12`、`offset = entry & 0xFFF`，符合 PE 基址重定位表规范；`DIR64` 用 `*(uint64_t*) += (uint64_t)delta`，`HIGHLOW` 用 32 位加法，均正确。
- **reflective `loader.c` 的 IAT / 延迟导入解析**：`IMAGE_ORDINAL_FLAG_X` 在 x86/x64 分别映射到 `IMAGE_ORDINAL_FLAG32/64`，`IMAGE_ORDINAL_X(v)` 用标准宏，`*ilt & 0x7FFFFFFF` 取名称 RVA 的低 31 位，对 x64 64 位 thunk 也成立，正确。
- **reflective `builder_reflective.c` 的 TLS 扩展与 `SizeOfImage`**：虽然扩展 `.tls` 的 `VirtualSize`/`SizeOfZeroFill` 发生在写基文件（步骤 7）之前，但 `.payload` 的位置是在 `EndUpdateResourceW` 回读文件（步骤 9）后，按**已扩展**后的节表重新计算 `last_va_end`（步骤 11），因此 `.payload` 不会与扩展后的 `.tls` 重叠——该流程正确（初看易误判为重叠 bug，实则为正确设计）。
- **XTEA 块加密一致性**：builder 与 loader 对“仅加密 8 字节整数倍、尾部 0–7 字节保持明文”的处理完全一致，可正确往返（唯一副作用是尾部未加密字节存在轻微信息泄露，安全层面可记为低）。
- **资源目录叶子节点**（`OffsetToData`，`loader.c` 1760 行）高位为 0，无需掩码，正确。

## 优先修复顺序建议

1. Bug #1（x86 SecurityCookie 偏移）—— 影响 32 位加壳产物的正确性与稳定性，改动极小。
2. Bug #2（loader 资源高位掩码）—— 影响所有带 manifest 的反射加载 PE，易导致加载期崩溃，改动极小。
3. 其余低优先级项可在后续迭代清理。

## 附：审查覆盖文件

- `packer/inplace/builder.c`、`packer/inplace/stub.c`
- `packer/reflective/builder_reflective.c`、`packer/reflective/loader.c`
- `packer/common/{config.h,xtea.h,peb_walk.h,sha256.h,winlock_compat.h,pe_meta.h}`
- `packer/cmake/extract_lock_section.py`、`packer/build.ps1`
- `packer/tests/check_pe_header.py`（及 `analyze_samples.py` 的 PE 解析作为对照）
- 汇编（`stub_asm_x64.asm` / `stub_asm_x86.asm`）为简单入口跳板，未发现问题。
