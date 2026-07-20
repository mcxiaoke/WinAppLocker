# x86 MSVC 迁移 + 构建系统重构 + 命名规范化

**日期**: 2026-07-20
**状态**: approved

## 目标

1. 把 x86 stub/loader 也迁移到 MSVC（完成 MSVC 全工具链迁移）
2. 拆分 CMakeLists 为 x64/x86 独立两套，避免架构冲突
3. 规范化构建产物命名（`stub_inplace_*` / `stub_reflective_*` / `builder_inplace` / `builder_reflective`）
4. 所有构建临时文件和产物隔离到 `build/` 和 `dist/`，保持源码目录干净
5. 清理旧名 fallback 和 MinGW 兼容代码

## 背景

### 现状问题

- `packer/stub/CMakeLists.txt` 无条件编译 `stub_x64` target，导致 x86 配置下 32 位 ml.exe 试图汇编 64 位寄存器（`undefined symbol : rsp`）
- `packer/reflective/loader_x86` 用 `/NODEFAULTLIB` 后缺 `__aulldvrm`（x86 上 64 位除法 CRT 辅助）
- `packer/builder/` 目录混了 inplace 和 reflective 两个加壳器源文件
- 文件名硬编码散落各处（builder.c / builder_reflective.c / build.ps1 / ReflectivePacker.cs），新旧名双轨
- 构建产物直接写到源码目录（stub_x64.bin / builder.exe / loader_x64.exe 等）

### 用户决策

- dist/ 布局：平级在 dist/ 根目录
- builder 命名：`builder_inplace.exe` / `builder_reflective.exe`
- CMake 拆分：两个完全独立的 CMakeLists.txt
- 旧名支持：清理，只用新名
- 不要太多 fallback，MinGW fallback 代码也清理
- `stub_inplace_x64.exe` 也要分发
- `__aulldvrm` 用 MASM 实现

## 设计

### 1. 目录重组

```
packer/
├── common/                        # 公用头文件（保持）
│   ├── config.h
│   ├── peb_walk.h
│   ├── sha256.h
│   ├── winlock_compat.h
│   ├── xtea.h
│   └── pe_meta.h
│
├── inplace/                       # 新目录：inplace 模式
│   ├── builder.c                  # 从 packer/builder/builder.c 移过来
│   ├── stub.c                     # 从 packer/stub/stub.c 移过来
│   ├── stub_asm_x64.asm           # 从 packer/stub/ 移过来
│   ├── stub_asm_x86.asm
│   ├── aulldvrm.asm               # 新增：x86 64 位除法 MASM 实现
│   └── CMakeLists.inc             # 被 x64/x86 顶层 include 的公用逻辑
│
├── reflective/                    # 保持目录名，内容重组
│   ├── builder_reflective.c      # 从 packer/builder/builder_reflective.c 移过来
│   ├── loader.c                   # 保持
│   ├── loader_asm_x64.asm         # 保持
│   ├── loader_asm_x86.asm         # 保持
│   ├── payload.h                  # 保持
│   ├── aulldvrm.asm               # 新增：x86 64 位除法（与 inplace 共用思路）
│   └── CMakeLists.inc             # 公用逻辑
│
├── cmake/                         # 公用 cmake 脚本（保持）
│   ├── msvc_setup.cmake
│   └── extract_lock_section.py
│
├── CMakeLists-x64.txt             # x64 专用顶层
├── CMakeLists-x86.txt             # x86 专用顶层
├── build.ps1                      # 改造：调两次 cmake，产物汇集到 dist/
├── Makefile.mingw                 # 保留但不再用，标为废弃
├── dist/                          # 新增：最终产物（gitignore）
└── build/                         # 新增：所有临时文件（gitignore）
    ├── x64/
    └── x86/
```

### 2. 命名规范化映射

| 旧名 | 新名 | 说明 |
|-----|-----|------|
| `builder.exe` | `builder_inplace.exe` | inplace 加壳器 |
| `builder_reflective.exe` | `builder_reflective.exe` | 保持（已对） |
| `stub_x64.bin` | `stub_inplace_x64.bin` | inplace x64 stub bin |
| `stub_x64.exe` | `stub_inplace_x64.exe` | x64 stub exe（也分发） |
| `stub_x86.bin` | `stub_inplace_x86.bin` | inplace x86 stub bin |
| `stub_x86.exe` | `stub_inplace_x86.exe` | x86 stub exe（builder 读 .reloc 用） |
| `loader_x64.exe` | `stub_reflective_x64.exe` | reflective x64 stub |
| `loader_x86.exe` | `stub_reflective_x86.exe` | reflective x86 stub |

### 3. CMake 拆分

**`CMakeLists-x64.txt`**（x64 专用顶层，`cmake -C CMakeLists-x64.txt -B build/x64 -A x64`）：

编译 4 个 target（用 `include()` 复用 `inplace/CMakeLists.inc` 和 `reflective/CMakeLists.inc`）：

- `builder_inplace`（从 `inplace/builder.c`，链接 advapi32）
- `stub_inplace_x64`（从 `inplace/stub.c + stub_asm_x64.asm`，PIC，提取 .lock 节）
- `builder_reflective`（从 `reflective/builder_reflective.c`，链接 advapi32）
- `stub_reflective_x64`（从 `reflective/loader.c + loader_asm_x64.asm`，PIC）

**`CMakeLists-x86.txt`**（x86 专用顶层，`cmake -C CMakeLists-x86.txt -B build/x86 -A Win32`）：

编译 4 个 target：

- `builder_inplace`（同 x64，但 cl.exe 是 32 位）
- `stub_inplace_x86`（从 `inplace/stub.c + stub_asm_x86.asm`，PIC，提取 .lock + 复制 stub exe）
- `builder_reflective`（同 x64，但 32 位）
- `stub_reflective_x86`（从 `reflective/loader.c + loader_asm_x86.asm + aulldvrm.asm`，PIC）

两个 CMakeLists 完全独立，build.ps1 调用两次 cmake + cmake --build。

### 4. builder 搜索路径改造

`packer/inplace/builder.c` 默认搜索路径改为当前目录（`.`）：

- 改前候选：`./stub/winlock_stub_x64.bin` → `./winlock_stub_x64.bin` → `./stub/stub_x64.bin` → ...
- 改后候选：`./stub_inplace_x64.bin`（仅此一个，无 fallback）

`--stub-dir` 参数保留，可显式指定目录。

x86 额外读 `stub_inplace_x86.exe` 获取 .reloc（逻辑同之前，只改文件名）。

### 5. builder_reflective 默认路径改造

`packer/reflective/builder_reflective.c` 默认 stub 路径改为当前目录：

- 改前：`../reflective/loader_x64.exe`（相对 builder 所在目录）
- 改后：`./stub_reflective_x64.exe` / `./stub_reflective_x86.exe`

`--stub <path>` 参数保留不变。

### 6. 清理旧名 + MinGW fallback

- **builder.c**：删除 `winlock_stub_*` / `stub_x64.bin` / `stub_x86.bin` / `stub.bin` 所有旧名支持
- **builder_reflective.c**：清理旧默认路径字符串
- **loader.c**：删除 `#ifdef WINLOCK_KEEP_CRT` 宏及 MinGW fallback 分支（用户明确要求）
- **stub.c**：清理 MinGW 兼容代码（如果有）

### 7. `__aulldvrm` MASM 实现

**文件**：`packer/inplace/aulldvrm.asm` + `packer/reflective/aulldvrm.asm`（内容相同，可复用）

**功能**：x86 上 64 位无符号除法（`uint64_t / uint32_t`），返回商（edx:eax）和余数。

**实现参考**：MSVC CRT 的 `aulldvrm.asm`（Visual Studio 2026 的 src\vctools\crt\crtaws\crt0dat.c 附近有实现）。

**MASM 汇编框架**（32 位 calling convention）：

```asm
.686
.model flat
PUBLIC __aulldvrm
.code
__aulldvrm PROC
    ; 输入: [esp+4] 被除数低 32 位, [esp+8] 被除数高 32 位
    ;       [esp+12] 除数低 32 位, [esp+16] 除数高 32 位
    ; 输出: edx:eax = 商, [esp+20] 余数低, [esp+24] 余数高
    ;       （MSVC 约定：商在 edx:eax，余数通过栈返回）
    ...
__aulldvrm ENDP
END
```

**测试**：写一个测试程序 `tests/test_aulldvrm.c`，验证 `1234567890123ULL / 1000ULL == 1234567890ULL`。

### 8. build.ps1 改造

**流程**：

1. 设置 MSVC 环境（vcvars64.bat）
2. cmake -C CMakeLists-x64.txt -B build/x64 -A x64
3. cmake --build build/x64 -j
4. cmake -C CMakeLists-x86.txt -B build/x86 -A Win32
5. cmake --build build/x86 -j
6. 复制产物到 dist/

**dist/ 最终内容**（8 个文件）：

```
dist/
├── builder_inplace.exe              # x64 版（与 x86 同名，x64 优先；或分别加 _x64 后缀？待定）
├── stub_inplace_x64.bin
├── stub_inplace_x64.exe
├── stub_inplace_x86.bin
├── stub_inplace_x86.exe
├── builder_reflective.exe
├── stub_reflective_x64.exe
└── stub_reflective_x86.exe
```

**builder_inplace.exe 冲突问题**：x64 和 x86 都会编译 builder_inplace，但 builder_inplace 本身没有 PIC 需求，是否需要分 x64/x86？

**决策**：builder_inplace 只编 x64 版（builder 本身不需要匹配被加壳 PE 的架构），分发给 dotnet 一份就够。reflective 同理。

### 9. dotnet/build.ps1 改造

- 删除从 `packer/builder/`, `packer/stub/`, `packer/reflective/` 多目录拷贝的逻辑
- 改为：从 `packer/dist/` 整个目录复制到 `dotnet/packer/stub/`
- meta.json 命名改造：
  - `winlock_builder.exe.meta.json` → `builder_inplace.exe.meta.json`
    - components: `stub_inplace_x64.bin` / `stub_inplace_x86.bin`
  - `winlock_reflective_builder.exe.meta.json` → `builder_reflective.exe.meta.json`
    - components: `stub_reflective_x64.exe` / `stub_reflective_x86.exe`

### 10. ReflectivePacker.cs 改造

- `ReflectivePacker.cs:66-67` 硬编码的 `loader_x64.exe` / `loader_x86.exe` 改为 `stub_reflective_x64.exe` / `stub_reflective_x86.exe`

## 实施步骤

1. **目录重组**：移动文件，更新 include 路径
2. **CMake 拆分**：写 CMakeLists-x64.txt + CMakeLists-x86.txt + 子目录 CMakeLists.inc，删除旧 CMakeLists
3. **命名改造**：改 builder.c / builder_reflective.c / C# 代码里的文件名字符串
4. **x86 MSVC 迁移**：实现 `__aulldvrm` MASM，跑 x86 build
5. **清理 fallback**：删除 WINLOCK_KEEP_CRT 宏等 MinGW 兼容代码
6. **改 build.ps1**：实现新的构建流程
7. **改 dotnet/build.ps1**：从 dist/ 复制，更新 meta.json 命名
8. **端到端测试**：8/8 样本 PASS

## 验证

- `packer/build.ps1` 跑通，dist/ 下 8 个文件齐全
- `dotnet/build.ps1 -Clean -Release` 跑通，dist/ 下 WinAppLocker.exe + stub/ 齐全
- 8/8 样本全部 PASS（与之前 MinGW + MSVC C3b 基线一致）
- 测试样本：
  - helloguix64.exe (x64 GUI) - inplace + reflective
  - hellocli.exe (x64 Console) - inplace + reflective
  - helloguix86.exe (x86 GUI) - inplace + reflective
  - helloclix86.exe (x86 Console) - inplace + reflective
  - DontSleep.exe (CFG 启用) - reflective
  - 其他 temp/samples 下的样本

## 已知限制

- builder_inplace 只编 x64 版（用户未指定是否需要 x86 builder，默认 x64）
- MinGW Makefile.mingw 保留但标为废弃
