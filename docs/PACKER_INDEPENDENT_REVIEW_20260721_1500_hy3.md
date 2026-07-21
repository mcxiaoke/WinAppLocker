# packer 代码与构建系统独立改进建议（不依赖 BUILD_SYSTEM_IMPROVEMENT_PLAN）

> 审查时间：2026-07-21 15:00
> 审查范围：仅基于当前 `packer/` 代码与构建系统，不参考那份 improvement plan。
> 说明：部分结论与该 plan 重合属正常——那些确实是真实存在的问题。

---

## 一、最该先做的：构建可追踪性（最大短板）

当前 `dist/` 产物零元数据：无法知道某个 `stub_inplace_x86.bin` 是 MinGW 还是 MSVC、对应哪个 git commit、源码是否改动过。崩溃后只能靠猜。

**方案**：`build.ps1` 末尾生成 `dist/stub_manifest.json`，对每个 stub 记录
`{arch, toolchain, git_short_hash, build_time, size, sha256, source_crc}`；
同时在 `stub_data_t` 里加一个小的身份块（arch/toolchain/build_time/source_crc/githash），
让加壳后的 exe 自己就能反查用了哪个 stub。这样问题定位从"几小时"降到"几秒"。

---

## 二、消除 MinGW 静默回退（build.ps1:182-185, 218-224）

- `Build-InplaceMinGW` 里 gcc 不存在只 `continue` 跳过，dist 会**静默 fallback 到 MSVC stub** 而无任何警告（182-185 行）。
- 覆盖 MSVC 产物时只打一行日志，不记录 hash（218-224 行）。
- 还有自相矛盾：`build.ps1:21` 注释写 x86 是 "MSVC 构建"，但代码让 MinGW 覆盖了 x86 stub——实际 dist 的 x86 是 MinGW（~7856 字节）。

**方案**：必需工具链缺失应**fail loudly** 而非静默跳过；覆盖时必须打印 sha256 并说明来源；修正注释。
x86 到底用哪个工具链应**显式决策**，不要靠"谁后写谁赢"。

---

## 三、inplace builder 必须校验 stub 架构（builder.c:801-890, 830-877）

reflective builder 已在 `builder_reflective.c:517` 校验 `s_machine == info.machine`，但 inplace builder 只靠**文件名**信任 stub：
x86 路径读 `stub_inplace_x86.exe` 做 reloc，却**从不检查其 PE Machine 字段**（问题 1 也提到）。
如果用户传 `--stub-dir` 指错目录，会用错架构的 stub 静默产出损坏的 exe。

**方案**：inplace builder 读 stub exe 后，校验 `e_lfanew` 处 `Machine` 与 `g_is_x64` 一致，不一致直接报错退出，与 reflective 路径对齐。

---

## 四、重点怀疑：x86 MinGW stub 可能根本没有 `.reloc`（疑似 x86 崩溃根因）

`stub.c` 的 x86 版本是**非 PIC**（用绝对地址），依赖 `.reloc` 做预 patch
（`builder.c:1132` `patch_stub_relocations`，且 867 行若缺 `.reloc` 会报错退出）。
MSVC x86 stub 用 `/FIXED:NO`（CMakeLists.inc:78）保留 `.reloc`；
但 MinGW x86 stub 在 `build.ps1` 里是 `--image-base=0x10000`、**未开 DYNAMICBASE**，
固定基址下 ld 很可能**不生成 `.reloc` 节**。而 dist 的 x86 stub 实际是 MinGW（被静默覆盖，见第二节）。

**方案**：先确证 MinGW x86 stub 是否带 `.reloc`（读节表即可）。若没有，x86 inplace 路径在 clean build 下必然出问题——
这正是 `helloguix86/hellomfcx86` CRASH 的高概率根因。修复方向二选一：
① 让 MinGW x86 也生成 `.reloc`（链接期保证基址可重定位或改用 PIC 兼容路径）；
② 不要覆盖 MSVC x86 stub（x86 保留 MSVC，x64 用 MinGW）。

---

## 五、checksum 要么真校验，要么换成有意义的完整性值（builder.c:998-1004, stub.c:119）

当前 checksum 是"XOR 全部 8 字节字段"，且 stub 运行时不校验（`stub.c:119` 仅 `.checksum=0`），
等于**死字段**；XOR 也谈不上"防篡改"。

**方案**：二选一 ——
① 在 stub 端补一段运行时重算并比对（几十行），真正防篡改；
② 退一步，把 checksum 改成对整个 `.lock` 节字节算 CRC32/CRC64（覆盖身份块之外的代码与数据），
至少在打包/加载期能发现截断或损坏。当前状态的字段建议先明确标注"未启用"。

---

## 六、输出 PE 质量与抗检测（builder.c:1117, 1177）

- `.lock` 节当前属性是 `MEM_WRITE|MEM_EXECUTE`（1117 行），W+X 是明显的加壳特征。
- 输出 PE 的 `CheckSum` 被清零（1177 行），也是特征（docs 里已多次记录）。

**方案**：x86 reloc patch / x64 解密完成后，把 `.lock` 节属性降为 `READ|EXECUTE`（去掉 WRITE）；
打包完调用 `CheckSumMappedFile` 重算 `CheckSum`；节名从 `.lock` 改名为更中性的名字（如 `.text`）。
三者都低成本、显著降低可检测性。

---

## 七、构建脚本健壮性

- `build.ps1:54` 硬编码 `C:\Program Files\Microsoft Visual Studio\18\Community`——换机器/升级就断。改用 `vswhere.exe` 定位或读环境变量。
- Python 调用不一致：build.ps1 用 `python`，CMake 用 `Python3_EXECUTABLE`。统一成同一可执行文件，避免某系统 `python` 指向 py2。
- `build.ps1:105-110` 把 `CMakeLists-xXX.txt` 复制成 `CMakeLists.txt` 的临时文件 hack 可用，但 Ctrl-C 中断时可能残留，导致下次 `throw`。建议清理放进 `finally` 之外再加一层进程退出兜底。

---

## 八、测试增强（tests/auto_e2e_test.ps1）

当前只断言 exit code / 窗口是否出现，不验证"产物真的用了正确的 stub / 真的是原程序在跑"。

**方案**：
1. 加 **stale stub** 前置检查：重算 `crc32(stub.c+stub_asm)` 与内嵌 `source_crc` 比对，源码改了没重编就告警（开发期 warnOnly，CI 可 fail）。
2. 加 **产物反查**：解析加壳后 exe 里的 stub 身份，确认与 dist 一致。
3. 对 CUI 样本已比对 stdout，但 GUI 样本只查窗口——可加一个"标题不含 error"之外的功能性探针（如让样本输出特定标记）。

---

## 九、反射式 x86 TLS 扩展未完成（builder_reflective.c:662）

`builder_reflective.c:662` 有 `TODO: x86 TLS 扩展`。x86 输入 PE 若依赖 TLS（如带线程局部存储的 CRT/库），
反射式 x86 打包后新线程 TLS 会越界崩溃。要么实现 x86 分支，要么在检测到 x86 + 有 TLS 时**明确报错**而非静默忽略。

---

## 十、工具单一真相源

magic 搜索、`find_stub_tls_cb_offset`、`patch_stub_identity`、`inspect` 都依赖 `stub_data_t` 布局。
一旦 `config.h` 改字段，所有 Python 脚本的偏移要同步改，极易漂移。

**方案**：抽一个 `packer/cmake/winlock_meta.py`，从 `config.h` 解析 `stub_data_t` 字段偏移
（或用一个生成脚本输出常量），被所有工具共用，消除硬编码偏移。

---

## 我会怎么排优先级

1. **P0**：第二节（消除静默回退）、**第四节**（确认+修复 x86 MinGW `.reloc`——直接关系当前的 x86 崩溃）、第三节（stub 架构校验）。
   这三项不增加复杂度却能堵住真实的正确性/可诊断性缺口。
2. **P1**：第一节（可追踪性 manifest + 身份块）、第六节（W+X/CheckSum/节名）。
3. **P2**：第五节（checksum 实效）、第七节（脚本健壮性）、第八节（测试）、第九节（x86 TLS）、第十节（单一真相源）。
