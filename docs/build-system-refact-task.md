# 构建系统重构任务进度跟踪

**分支**: `packer-build-system-refact`
**方案文档**: [BUILD_SYSTEM_IMPROVEMENT_PLAN.md](file:///C:/Home/Projects/applocker/docs/BUILD_SYSTEM_IMPROVEMENT_PLAN.md)
**目标**: 按 5 步实施 12 个改动，每步完成 + 测试通过后 commit 一次

---

## 总体进度

- [x] 第 0 步（前置 P0）：改动 10（CMake hack 消除）+ 改动 11（malloc 检查）
- [x] 第 1 步（身份字段 + 注入）：改动 1 + 2 + 3 + 4
- [x] 第 2 步（builder 校验）：改动 5 + 6
- [ ] 第 3 步（inspect 工具 + manifest）：改动 7 + 8
- [ ] 第 4 步（测试校验）：改动 9
- [ ] 第 5 步（清理）：改动 12

---

## 详细进度记录

### ✅ 已完成 — 第 0 步：CMake hack 消除 + malloc 检查

**改动清单**：
- 改动 10：新建顶层 `packer/CMakeLists.txt`（按 `-DWINLOCK_ARCH` 用 `include()` 引入 `inplace/CMakeLists.inc` 和 `reflective/CMakeLists.inc`），删除 `CMakeLists-x64.txt` / `CMakeLists-x86.txt`，build.ps1 的 `Build-Arch` 改用 `-DWINLOCK_ARCH=$arch` 不再复制文件
- 改动 11：`builder.c` 和 `builder_reflective.c` 的 `read_file` 加 ftell<0 检查、512MB 上限、malloc 失败日志

**实施细节**：
- 放弃 `add_subdirectory(x64)` 方案（会产生 `build/x64/x64/` 嵌套目录导致 dist 收集失败），改用 `include()` 方式，产物直接落在 `-B build/x64` 指定目录
- builder.c 的 calloc（第 1081 行）原本就有 NULL 检查，无需修改
- builder_reflective.c 的 3 处 calloc/realloc（410/685/788 行）原本都有 NULL 检查，无需修改

**测试结果**：
- clean build 成功：8 个产物全部正确生成，dist/ 与重构前一致
- e2e 测试：32 pass / 4 fail（与重构前完全一致，未引入新回归）
  - 已知失败（与本步无关）：helloguix86/hellomfcx86 inplace_password CRASH、DontSleep reflective ERROR_WINDOW

**状态**：完成
**开始时间**：2026-07-21 22:30
**完成时间**：2026-07-21 22:45
**Commit hash**：`1d73483`

---

### ✅ 已完成 — 第 1 步：身份字段 + CMake/build.ps1/patch 脚本注入

**改动清单**：
- 改动 1：`packer/common/config.h` 加 `stub_identity_t` 结构（32 字节，7 字段），`stub_data_t` 末尾插入 `identity` 字段（checksum 之前），`STUB_DATA_VERSION` bump 4→5，加 `STUB_DATA_SIZEOF 320` 宏 + typedef 数组防漂移校验（替代 `_Static_assert`，MSVC C 模式不支持）
- 改动 1：`packer/inplace/stub.c` 顶部加 `#ifndef STUB_ARCH` / `STUB_TOOLCHAIN` 宏守卫，`stub_data` 初始化加 `.identity` 字段
- 改动 2：`packer/CMakeLists.txt` if/elseif 分支定义 `STUB_ARCH_VAL`（x64=2, x86=1）和 `STUB_TOOLCHAIN_VAL`（MSVC=1）
- 改动 2：`packer/inplace/CMakeLists.inc` 注入 `STUB_ARCH=${STUB_ARCH_VAL}` / `STUB_TOOLCHAIN=${STUB_TOOLCHAIN_VAL}` 编译期定义 + POST_BUILD `patch_stub_identity.py` 命令（在 extract_lock_section.py 之后）
- 改动 2：`packer/reflective/CMakeLists.inc` 不改动（reflective stub 是普通 PE，无 stub_data_t 结构）
- 改动 3：`packer/build.ps1` 头部加 Python 检测（`$pythonExe`），头部注释修正（MinGW 失败必须 fail，不再静默 fallback）
- 改动 3：`Build-InplaceMinGW` 加 `-DSTUB_ARCH` / `-DSTUB_TOOLCHAIN` 编译期注入，POST_BUILD 调用 `patch_stub_identity.py`，覆盖 MSVC 产物时打印 SHA256，gcc 不存在时 throw 而非 continue
- 改动 4：新建 `packer/cmake/patch_stub_identity.py`：8 字节对齐搜索 magic + version + arch 三重校验定位 stub_data_t，patch 5 个字段（bin_ver/build_time/source_crc/size/githash），幂等设计（patch 前清零 stub_size），行尾归一化 CRC 计算

**实施细节**：
- 最初用 `_Static_assert(sizeof(stub_data_t) == STUB_DATA_SIZEOF, ...)` 但 MSVC C 模式默认标准（C89/MS 扩展）不支持 C11 关键字，改用 `typedef char _static_assert_stub_data_sizeof[(cond) ? 1 : -1]` 数组技巧，所有编译器通用
- patch 脚本搜索条件用三重校验（magic + version + arch 范围），不校验 stub_size（脚本本身要写入 stub_size，避免先有鸡还是先有蛋）；builder.c 第 2 步会加第四重校验（stub_size）
- CRC 覆盖范围：stub.c / stub_asm_${ARCH}.asm / config.h / sha256.h / peb_walk.h / xtea.h / winlock_compat.h，行尾归一化为 LF
- githash 用 `git rev-parse --short=8 HEAD`，无 git 或不在仓库时全 0

**测试结果**：
- clean build 成功，身份字段全部正确注入：
  - MSVC x64 stub_inplace_x64.bin: 24592 bytes, arch=x64 toolchain=MSVC source_crc=0xe5035ac9 githash=1d73483f
  - MSVC x86 stub_inplace_x86.bin: 16400 bytes, arch=x86 toolchain=MSVC source_crc=0x4f28d90d githash=1d73483f
  - MinGW x64 stub_inplace_x64.bin: 8128 bytes（覆盖 MSVC 产物）, arch=x64 toolchain=MinGW source_crc=0xe5035ac9
  - MinGW x86 stub_inplace_x86.bin: 7888 bytes（覆盖 MSVC 产物）, arch=x86 toolchain=MinGW source_crc=0x4f28d90d
  - 覆盖时打印 SHA256 前缀便于排查
- e2e 测试：32 pass / 4 fail（与重构前完全一致，未引入新回归）
  - 已知失败（与本步无关）：helloguix86/hellomfcx86 inplace_password CRASH exit=2、DontSleep reflective CRASH exit=-1073741819

**状态**：完成
**开始时间**：2026-07-22 02:30
**完成时间**：2026-07-22 03:00
**Commit hash**：`1ecbf9a`

---

### ✅ 已完成 — 第 2 步：builder 四重校验 + reflective 薄封装日志

**改动清单**：
- 改动 5：`packer/inplace/builder.c` 新增 `verify_stub_identity` 函数（四重校验：magic + version + stub_size + arch 范围），替代原本只搜 `STUB_DATA_MAGIC` 的简单循环。函数返回 `const stub_data_t*`，调用处强制转 non-const 供后续修改字段
- 改动 6：`packer/reflective/builder_reflective.c` 在既有 `s_machine != info.machine` 检查处加 `fprintf(stderr, ...)` 详细日志（薄封装，不新增独立函数避免重复读取 PE Machine）。成功路径也加 `[*] reflective stub arch OK` 日志

**实施细节**：
- `verify_stub_identity` 第 3 重校验（stub_size）允许 0：patch_stub_identity.py 写入前 stub_size 为 0，patch 后才等于文件大小。这样 patch 前后的 stub.bin 都能被识别
- `verify_stub_identity` 第 4 重校验（arch 范围 1/2）防 magic+version 巧合匹配（patch 前 arch 已由 CMake -D 注入，不为 0）
- 找到 stub_data_t 后再校验 arch 是否匹配输入 PE 架构（`want_arch = pe_is_x64 ? STUB_ARCH_X64 : STUB_ARCH_X86`），防止 "x86 PE 用了 x64 stub" 这类严重错误
- 打印身份信息到 stderr（arch/toolchain/bin_ver/build_time/source_crc/githash/size），方便加壳时立即确认用了哪个 stub
- `builder_reflective.c` 不新增独立 verify 函数：reflective stub 是普通 PE，无 stub_data_t 结构，直接用 PE Machine 字段校验即可，加日志足够

**测试结果**：
- clean build 成功，8 个产物全部正确生成
- e2e 测试：32 pass / 4 fail（与重构前完全一致，未引入新回归）
  - 已知失败（与本步无关）：helloguix86/hellomfcx86 inplace_password CRASH exit=2、DontSleep reflective CRASH exit=-1073741819

**状态**：完成
**开始时间**：2026-07-22 05:30
**完成时间**：2026-07-22 06:00
**Commit hash**：`34b24f5`

---

## 历史记录

（每步完成后在此追加）
