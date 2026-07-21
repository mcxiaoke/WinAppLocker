# 构建系统重构任务进度跟踪

**分支**: `packer-build-system-refact`
**方案文档**: [BUILD_SYSTEM_IMPROVEMENT_PLAN.md](file:///C:/Home/Projects/applocker/docs/BUILD_SYSTEM_IMPROVEMENT_PLAN.md)
**目标**: 按 5 步实施 12 个改动，每步完成 + 测试通过后 commit 一次

---

## 总体进度

- [x] 第 0 步（前置 P0）：改动 10（CMake hack 消除）+ 改动 11（malloc 检查）
- [ ] 第 1 步（身份字段 + 注入）：改动 1 + 2 + 3 + 4
- [ ] 第 2 步（builder 校验）：改动 5 + 6
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
**Commit hash**：待 commit

---

## 历史记录

（每步完成后在此追加）
