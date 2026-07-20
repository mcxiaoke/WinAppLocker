# WinLock packer MSVC 迁移 + PIC 化 + 特征消除 实施计划

## 总体策略

采用「**双工具链并存 + 渐进式迁移 + 每步可回滚**」策略，以方案 C（最小改动低风险）为基础，融合方案 A 的共享层前置与方案 B 的选择性性能优化：

- **保留 Makefile.mingw 后备**：原 Makefile 重命名为 Makefile.mingw，CMake 与之并存，迁移失败可快速回退
- **#ifdef _MSC_VER 双兼容**：代码改动用宏抽象同时支持 GCC/MSVC，不直接删除 GCC 分支
- **共享层前置**：先抽取 winlock_compat.h / peb_walk.h / xtea.h / pe_meta.h，降低后续高难度改动工作量
- **分批迁移**：stub.c 的 46 处 GCC 扩展分 3 批，loader.c 的 CRT 剥离分 3 步
- **选择性性能优化**：stub 用 /O1（体积优先）+ 关键函数 /O2；builder 用 /O2；暂不启用 LTCG/ARM64 预留/sccache
- **魔数定位**：不用 /ORDER（对自定义节无效），依赖 config.h 已定义的 STUB_DATA_MAGIC / STUB_ENTRY_MAGIC / STUB_TLS_CB_MAGIC

工具链分工（MSVC_PORTING_PLAN.md 第 2.2 节）：
- 编译器/链接器/汇编器：MSVC cl.exe / link.exe / ml64.exe / ml.exe（14.51.36231）
- binutils 后处理：w64devkit（x64）+ msys2 mingw32（x86）的 objcopy / nm / strip

测试样本：temp/samples/ 下 11 个 hello* 程序（hellocli/helloguix64/helloguix86/hellomfcx64/hellomfcx86/hellomingw/helloucrt/hellowinforms），默认密码 hello123。

---

## 阶段 0：准备工作（零风险）

**目标**：建立安全网，确保任何后续步骤失败都能回退。

### 0.1 基线测试
- 运行现有 MinGW 版全样本测试，记录基线到 `packer/tests/baseline_mingw.txt`
- 执行：`mingw32-make -f packer/Makefile all all-x86 reflective-all`
- 加壳验证：helloguix64 / helloguix86 / hellomfcx64 / hellomfcx86 / hellomingw / helloucrt / hellowinforms

### 0.2 备份 Makefile
- `packer/Makefile` → `packer/Makefile.mingw`（git mv 保留历史）
- 验证 `mingw32-make -f Makefile.mingw all all-x86 reflective-all` 仍能编译通过

**验证点**：MinGW 版全样本加壳 + 弹密码框 + 输入 hello123 后正常运行。
**回滚**：此阶段无风险。

---

## 阶段 1：共享代码抽取（低风险，用 MinGW 回归验证）

**目标**：消除 4 处 XTEA 重复、2 处 SHA-256 路径、PEB walk 单点实现，为后续高难度改动铺路。**此阶段不切换编译器**，仍用 MinGW 编译验证抽取正确。

### 1.1 新建 `packer/common/winlock_compat.h`（编译器抽象层）

集中所有 GCC/MSVC 差异宏，单点维护。核心宏定义（基于 MSVC_PORTING_PLAN.md 第 661-675 行，但扩展为三模式）：

```c
#ifdef _MSC_VER
  /* MSVC: 用 __pragma 包裹式宏（可在宏内使用 #pragma） */
  #define WINLOCK_SECTION_TEXT   __pragma(code_seg(".lock$text")) __declspec(noinline)
  #define WINLOCK_SECTION_DATA   __pragma(data_seg(".lock$data")) __declspec(align(16))
  #define WINLOCK_SECTION_RDATA  __pragma(const_seg(".lock$rdata"))
  #define WINLOCK_SECTION_ENTRY  __pragma(code_seg(".lock$entry")) __declspec(noinline)
  #define WINLOCK_SECTION_TLSCBM __pragma(const_seg(".lock$tlscbm")) __declspec(align(16))
  #define WINLOCK_SECTION_TLSCB  __pragma(code_seg(".lock$tlscb")) __declspec(noinline)
  #define WINLOCK_UNREACHABLE    __assume(0)
  #define WINLOCK_NOINLINE       __declspec(noinline)
  #define WINLOCK_OPTIMIZE_OFF   __pragma(optimize("", off))
  #define WINLOCK_OPTIMIZE_ON    __pragma(optimize("", on))
#else
  /* GCC: 保持原样 */
  #define WINLOCK_SECTION_TEXT   __attribute__((section(".lock.text"), used, noinline))
  #define WINLOCK_SECTION_DATA   __attribute__((section(".lock.data"), used, aligned(16)))
  #define WINLOCK_SECTION_RDATA  __attribute__((section(".lock.rdata"), used, aligned(2)))
  #define WINLOCK_SECTION_ENTRY  __attribute__((section(".lock.entry"), used, noinline))
  #define WINLOCK_SECTION_TLSCBM __attribute__((section(".lock.tlscbm"), used, aligned(16)))
  #define WINLOCK_SECTION_TLSCB  __attribute__((section(".lock.tlscb"), used, noinline))
  #define WINLOCK_UNREACHABLE    __builtin_unreachable()
  #define WINLOCK_NOINLINE       __attribute__((noinline))
  #define WINLOCK_OPTIMIZE_OFF   __attribute__((optimize("O0")))
  #define WINLOCK_OPTIMIZE_ON
#endif
```

### 1.2 新建 `packer/common/peb_walk.h`

从 `stub.c:42-67, 72-76, 275-352` 抽取（以 loader.c:120-173 的更全版本为基础）：
- PEBX / PEB_LDR_DATA_X / LDR_DATA_TABLE_ENTRY_X / MY_LIST_ENTRY 类型定义
- WINLOCK_PEB() 宏（x64: gs:[0x60]，x86: fs:[0x30]）
- hash_ascii() / hash_wstr_lower() DJB15 实现
- find_module_by_hash() / find_export_by_hash()（用 static inline 避免 stub.c 和 loader.c 符号冲突）

### 1.3 新建 `packer/common/xtea.h`

从 4 处重复实现抽取（builder.c:61-83 / builder_reflective.c:164-188 / stub.c:354-381 / loader.c:276-301）：
- xtea_encrypt_block/buf（builder 用）
- xtea_decrypt_block/buf（stub/loader 用）
- 用 WINLOCK_SECTION_TEXT 宏控制是否进 .lock.text 节（通过 #ifdef WINLOCK_PIC）

### 1.4 新建 `packer/common/pe_meta.h`

集中节名常量（为阶段 5 节名伪装做准备）：
- WINLOCK_SECTION_NAME（从 config.h:18 迁出，当前 ".lock\0\0\0"）
- REFLECTIVE_SECTION_NAME（新增，当前 ".payload\0\0"）
- 节属性常量（WINLOCK_LOCK_PERMS = 0xE0000020 等）
- config.h 改为 #include "pe_meta.h"

### 1.5 移动 `packer/stub/sha256.h` → `packer/common/sha256.h`

- 更新 stub.c:40 和 loader.c:45 的 #include 路径
- 更新 packer/tests/stub_sha256_test.c 和 test_sha256.c 的 #include 路径
- sha256.h 的 WINLOCK_FN 宏（第 18-22 行）扩展为三模式（GCC PIC / GCC host / MSVC）

### 1.6 修改 4 个 .c 文件的 #include

- stub.c / loader.c / builder.c / builder_reflective.c 删除本地 XTEA 实现，改 #include "../common/xtea.h"
- stub.c / loader.c 删除本地 PEB walk 实现，改 #include "../common/peb_walk.h"
- stub.c / loader.c 改 #include "../common/sha256.h"

**验证点**（用 MinGW 编译）：
- `mingw32-make -f Makefile.mingw all all-x86 reflective-all` 编译通过
- stub_x64.bin / stub_x86.bin 字节级对比基线无变化（cmp 命令）
- 加壳 helloguix64 + hellomfcx64，弹密码框 + 输入 hello123 + 正常启动
- 运行 stub_sha256_test.c 验证 SHA-256 无回归

**回滚触发**：若任一样本加壳后行为与基线不一致 → git revert，共享代码保留在原处。
**git commit**：`refactor(packer): extract shared XTEA/PEB walk/sha256 to common/`

---

## 阶段 2：CMake 骨架 + Builder 迁移（低风险）

**目标**：验证 MSVC + CMake 工具链可用，迁移最简单的 builder（纯 C 无 GCC 扩展）。

### 2.1 新建 `packer/CMakeLists.txt`（顶层）

```cmake
cmake_minimum_required(VERSION 3.20)
project(winlock_packer C ASM_MASM)

# 强制 MSVC
if(NOT MSVC)
    message(FATAL_ERROR "Requires MSVC. Run from x64 Native Tools Command Prompt or use vcvars64.bat")
endif()

option(WINLOCK_BUILD_X86 "Build x86 targets" ON)
option(WINLOCK_BUILD_TESTS "Build test programs" ON)

# binutils 查找（继续用 w64devkit/msys2，与编译器无关）
set(W64DEVKIT_BIN "C:/Home/Develop/w64devkit/bin")
set(MSYS_MINGW32_BIN "C:/Home/Develop/msys64/mingw32/bin")
find_program(OBJCOPY_X64 objcopy PATHS ${W64DEVKIT_BIN} REQUIRED)
find_program(NM_X64 nm PATHS ${W64DEVKIT_BIN} REQUIRED)
if(WINLOCK_BUILD_X86)
    find_program(OBJCOPY_X86 objcopy PATHS ${MSYS_MINGW32_BIN} REQUIRED)
    find_program(NM_X86 nm PATHS ${MSYS_MINGW32_BIN} REQUIRED)
endif()

include_directories(${CMAKE_SOURCE_DIR}/common)
add_subdirectory(stub)
add_subdirectory(reflective)
add_subdirectory(builder)
```

### 2.2 新建 `packer/cmake/msvc_setup.cmake`

封装 vcvars 路径 + binutils 路径查找逻辑。

### 2.3 新建 `packer/builder/CMakeLists.txt`

```cmake
add_executable(builder builder.c)
target_link_libraries(builder PRIVATE advapi32 imagehlp)
target_compile_options(builder PRIVATE /O2 /W3 /MT)

add_executable(builder_reflective builder_reflective.c)
target_link_libraries(builder_reflective PRIVATE advapi32)
target_compile_options(builder_reflective PRIVATE /O2 /W3 /MT)
```

### 2.4 验证 MSVC builder

- `cmake -B build-x64 -A x64` + `cmake --build build-x64 --config Release --target builder builder_reflective`
- builder.exe --help 正常输出
- 用 MSVC 版 builder 加壳 helloguix64.exe，弹密码框 + 输入 hello123 + 正常启动

**验证点**：MSVC 版 builder 功能与 MinGW 版完全一致。
**回滚触发**：若 MSVC builder 编译失败或加壳异常 → 删除 CMakeLists.txt，继续用 Makefile.mingw。
**git commit**：`feat(packer): add CMake skeleton + migrate builder to MSVC`

---

## 阶段 3：Inplace stub 迁移（高风险，46 处 GCC 扩展分 3 批）

**目标**：把 stub.c 从 MinGW 迁移到 MSVC，保持 PIC 自包含。保留 stub.ld 供 MinGW 后备。

### 批 1：section 属性宏替换（低风险，15 处）

修改 `packer/stub/stub.c`：
- 顶部 #include "../common/winlock_compat.h"
- 替换 15 处 `__attribute__((section(".lock.*")))` 为对应宏（WINLOCK_SECTION_TEXT/DATA/RDATA/ENTRY/TLSCBM/TLSCB）
- 涉及行号：94, 121, 140-153（8处字符串）, 161, 169, 177, 187, 368, 742, 765, 800, 848, 942, 954, 959

**验证**：MinGW 编译通过（宏的 GCC 分支），stub_x64.bin 字节级对比基线无变化。

### 批 2：optimize/unreachable/sfence（中风险，5 处）

- stub.c:848 `optimize("O0")` → WINLOCK_OPTIMIZE_OFF（配合 #pragma optimize("", off)）
- stub.c:758 `__builtin_unreachable()` → WINLOCK_UNREACHABLE
- stub.c:23-24 `__asm__ volatile("sfence")` + `__builtin_ia32_sfence` → `#include <intrin.h>` + `_mm_sfence()`

**验证**：MinGW 编译通过，加壳 helloguix64 弹框正常。

### 批 3：jump_to_oep 独立 .asm（高风险，3 处）

新建 `packer/stub/stub_asm_x64.asm`（MASM 语法，基于 MSVC_PORTING_PLAN.md 第 275-285 行）：
```asm
.code
; void jump_to_oep_x64(void* oep /*RCX*/);
jump_to_oep_x64 PROC
    and  rsp, -16        ; 16 字节对齐
    sub  rsp, 40         ; 32B shadow space + 8 对齐
    jmp  rcx             ; 跳到 OEP（不压返回地址）
jump_to_oep_x64 ENDP
END
```

新建 `packer/stub/stub_asm_x86.asm`：
```asm
.586
.model flat
.code
; void __cdecl jump_to_oep_x86(void* oep /*[esp+4]*/);
_jump_to_oep_x86 PROC
    mov  eax, [esp+4]    ; oep
    and  esp, -16        ; 16 字节对齐
    jmp  eax             ; 跳到 OEP
_jump_to_oep_x86 ENDP
END
```

修改 stub.c:743-759：
- 删除内联 asm，改为 `extern void jump_to_oep_x64(void* oep);` 声明 + 调用
- x86 同理

新建 `packer/stub/CMakeLists.txt`：
```cmake
# x64 stub
add_executable(stub_x64 WIN32 stub.c stub_asm_x64.asm)
target_compile_definitions(stub_x64 PRIVATE WINLOCK_STUB WINLOCK_PIC)
target_compile_options(stub_x64 PRIVATE
    /O1 /GS- /Gs1048576 /GL- /Zl /Gy
)
# 关键函数强制 /O2（XTEA 解密 32 轮循环）
# 在 stub.c 的 xtea_decrypt_block 前加 #pragma optimize("", on)

target_link_options(stub_x64 PRIVATE
    /NODEFAULTLIB /ENTRY:stub_entry /SUBSYSTEM:WINDOWS
    /BASE:0x10000 /DYNAMICBASE:NO
    /MERGE:.lock\$text=.lock /MERGE:.lock\$data=.lock /MERGE:.lock\$rdata=.lock
    /MERGE:.lock\$entry=.lock /MERGE:.lock\$tlscbm=.lock /MERGE:.lock\$tlscb=.lock
    /OPT:REF /OPT:ICF
)

# objcopy 提取 .lock 节为 stub_x64.bin（继续用 w64devkit binutils）
add_custom_command(TARGET stub_x64 POST_BUILD
    COMMAND ${OBJCOPY_X64} -O binary -j .lock $<TARGET_FILE:stub_x64> ${CMAKE_CURRENT_BINARY_DIR}/stub_x64.bin
    COMMAND ${NM_X64} $<TARGET_FILE:stub_x64> | findstr "stub_entry stub_data STR_"
    COMMENT "Extracting .lock section -> stub_x64.bin"
)
```

**验证点**（批 3 完成后，MSVC 编译）：
- `cmake --build build-x64 --config Release --target stub_x64` 生成 stub_x64.exe + stub_x64.bin
- nm 验证 stub_entry 符号存在
- stub_x64.bin 体积与 MinGW 版差异 < 30%（目标 < 8KB）
- 加壳 helloguix64.exe（x64），弹密码框，输入 hello123，程序正常启动
- 加壳 hellomfcx64.exe（MFC + /GS，验证 SecurityCookie 初始化）
- 加壳 hellocli.exe / hellomingw.exe / helloucrt.exe

**x86 验证**：
- `cmake -B build-x86 -A Win32` + `cmake --build build-x86 --config Release --target stub_x86`
- objcopy 用 msys2 mingw32（验证能处理 MSVC x86 PE）
- 加壳 helloguix86.exe / hellomfcx86.exe / hellowinforms.exe

**回滚触发**：
- stub_x64.bin 体积变化 > 50% → 部分回滚 2（Inplace 保留 MinGW）
- stub_entry 魔数搜索失败 → 检查 /MERGE，回退批 3
- hellogui/hellomfcx64 加壳后崩溃 → 回退批 3，保留批 1+2

**git commit**（3 个）：
- `refactor(stub): replace section attributes with macros (batch 1/3)`
- `refactor(stub): replace optimize/unreachable/sfence (batch 2/3)`
- `feat(stub): migrate jump_to_oep to standalone .asm for MSVC (batch 3/3)`

**关键 tag**：`inplace-msvc-done`

---

## 阶段 4：Reflective loader PIC 化（最高风险，CRT 剥离分 3 步）

**目标**：把 loader.c 从「带 CRT 的 host 程序」改为「PIC 自包含 stub」，对齐 REFLECTIVE_DESIGN.md 阶段 4 计划。体积 40-60KB → 15-20KB。

### 步骤 A：日志改 Win32 API（中风险）

修改 `packer/reflective/loader.c:94-114`：
- 删除 fopen/fprintf/fflush/strrchr/strcpy/strcat
- log_init() 改用 CreateFileA（或直接用 OutputDebugStringA + DebugView）
- DBG 宏改用 WriteFile + OutputDebugStringA
- 字符串操作改自实现（my_strrchr/my_strcpy/my_strcat，复用 stub.c 的 my_strlen 模式）
- 用 #ifdef WINLOCK_KEEP_CRT 保留 CRT 模式（对应部分回滚 1）

**验证**（MinGW 编译）：运行 reflective_batch_test.ps1，检查 reflective_loader.log 内容与基线一致。

### 步骤 B：内存改 Win32 API（中风险）

修改 `packer/reflective/loader.c:728`：
- calloc(size_of_image, 1) → VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE)（自动清零）
- free(skip) → VirtualFree(skip, 0, MEM_RELEASE)
- memset/memcmp 保留（MSVC intrinsics，非 CRT 依赖）

**验证**（MinGW 编译）：加壳 Notepad4.exe，验证 relocations 应用正常。

### 步骤 C：TLS callback + MSVC 链接（高风险）

修改 `packer/reflective/loader.c:1156`：
- `__attribute__((section(".CRT$XLB"), used))` → 用 winlock_compat.h 宏
  - MSVC: `#pragma section(".CRT$XLB", read)` + `__declspec(allocate(".CRT$XLB"))`
  - GCC: 保持原样

新建 `packer/reflective/loader_asm_x64.asm` 和 `loader_asm_x86.asm`：
- 与 stub 的 .asm 结构一致，但 loader 的 jump_to_oep 多一个 ret_addr 参数
- x64: RCX=oep, RDX=ret_addr，push rdx 后 jmp rcx
- x86: [esp+4]=oep, [esp+8]=ret_addr

修改 loader.c:179-214：
- oep_returned 的 __attribute__((noinline, used)) → WINLOCK_NOINLINE
- __builtin_unreachable → WINLOCK_UNREACHABLE
- jump_to_oep 内联 asm → extern 调用 .asm

应用共享层：
- #include "../common/peb_walk.h" 替换 loader.c:120-173 的 PEBX/LDRCNT/LDRENT 定义
- #include "../common/xtea.h" 替换 loader.c:274-296 的 XTEA 实现
- LoadLibraryA("user32.dll") 改用 find_module_by_hash(HASH_MOD_USER32_DLL)

新建 `packer/reflective/CMakeLists.txt`：
```cmake
# x64 loader（PIC 自包含，剥离 CRT）
add_executable(loader_x64 WIN32 loader.c loader_asm_x64.asm)
target_compile_definitions(loader_x64 PRIVATE _WIN64 WINLOCK_PIC)
target_compile_options(loader_x64 PRIVATE
    /O2 /GS- /Gs1048576 /GL- /Zl /Gy
)
target_link_options(loader_x64 PRIVATE
    /NODEFAULTLIB /ENTRY:loader_main /SUBSYSTEM:WINDOWS
    /BASE:0x10000 /DYNAMICBASE:NO /STACK:0x10000
    /OPT:REF /OPT:ICF
)
target_link_libraries(loader_x64 PRIVATE user32)
```

**验证点**（步骤 C 完成后，MSVC 编译）：
- DIE 识别从 "Unknown" → "Microsoft Linker 14.51"
- loader_x64.exe 体积从 40-60KB → 15-20KB
- 加壳 Notepad4.exe，弹密码框，输入正确密码，正常启动
- 加壳 temp/samples/ 下 11 个 hello* 程序全部验证：
  - hellocli.exe（VS CLI）
  - helloguix64.exe / helloguix86.exe（VS GUI）
  - hellomfcx64.exe / hellomfcx86.exe（MFC，TLS 重度依赖）
  - hellomingw.exe / helloucrt.exe（MinGW/UCRT）
  - hellowinforms.exe（.NET WinForms）

**x86 验证**：
- CMake -A Win32，加壳 helloguix86.exe + hellomfcx86.exe
- 验证 loader_x86.exe 体积 < 25KB

**回滚触发**：
- 步骤 A 后日志行为异常 → git revert，保留 CRT 日志
- 步骤 C 后 Notepad4 加壳失败 → 部分回滚 1（WINLOCK_REFLECTIVE_PIC=OFF，保留 CRT 用 MSVC 编译）
- PEB walk 共享导致编译失败 → 部分回滚 3（只迁移 Inplace，Reflective 保留 MinGW）
- MSVC x86 无法生成可用 loader_x86.exe → x86 保留 MinGW，x64 先迁移

**git commit**（4 个）：
- `feat(reflective): add standalone .asm for jump_to_oep`
- `refactor(reflective): replace CRT logging with Win32 API (step A)`
- `refactor(reflective): replace calloc with VirtualAlloc (step B)`
- `feat(reflective): PIC化 TLS callback + MSVC link (step C)`

**关键 tag**：`reflective-msvc-pic-done`

---

## 阶段 5：方案 B 节名伪装 + 特征消除（低风险）

**目标**：消除剩余 packer 特征（节名、W+X 属性、CheckSum 清零）。

### 5.1 节名伪装

修改 `packer/common/pe_meta.h`：
- WINLOCK_SECTION_NAME: ".lock\0\0\0" → ".text2\0\0\0"
- REFLECTIVE_SECTION_NAME: ".payload\0\0" → ".rdata2\0\0"

修改点（单点改 pe_meta.h 即可，所有引用自动更新）：
- stub/CMakeLists.txt 的 /MERGE 目标节名
- loader.c:250 的 find_payload_section 匹配新节名
- builder.c / builder_reflective.c 写入节表

### 5.2 Inplace .lock 节属性改造

- .lock 节属性：0xE0000020（ERWC）→ 0x60000020（ERC，去掉 W）
- stub_data 中需运行时写的字段（g_tls_decrypted）单独放 .lockw 节（0xC0000040，RWI 无 E）
- 修改 builder.c 写入节表的节属性
- stub.c 的 stub_data 用 WINLOCK_SECTION_DATA_RW 宏（新增到 winlock_compat.h）

### 5.3 CheckSum 重算

修改 builder.c 和 builder_reflective.c：
- 写完输出 PE 后调用 CheckSumMappedFile（imagehlp.lib）
- 写入 OptionalHeader.CheckSum

### 5.4 Reflective 假 IAT 注入（可选）

在 loader.c 加 dummy API 引用：
```c
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
__declspec(noinline) static void dummy_iat_padding(void) {
    volatile PVOID p1 = (PVOID)ShellExecuteW;
    volatile PVOID p2 = (PVOID)CoInitialize;
    (void)p1; (void)p2;
}
```

**验证点**：
- DIE 扫描：Inplace 仍报 MS Linker；Reflective 从 "Unknown" → "Microsoft Linker 14.51"
- pe_dump.py 验证：.lock/.text2 节无 W 属性，CheckSum 非零
- 全样本回归：11 个 hello* + Notepad4

**回滚触发**：若节名改动导致 builder 搜索魔数失败 → revert 5.1-5.4，保留 .lock 节名。
**git commit**：`feat(packer): scheme B - section rename + attribute fixup + checksum + fake IAT`

---

## 阶段 6：build.ps1 更新 + 全样本回归（中风险）

**目标**：更新 build.ps1 调用 CMake，确保 .NET 主程序不受影响。

### 6.1 修改 `dotnet/build.ps1:109`

把 `& $make.Name all all-x86 reflective-all` 改为：
```powershell
$cmakeBuildDir = "$winlockDir\build-msvc"
if (-not (Test-Path "$cmakeBuildDir\CMakeCache.txt")) {
    cmake -B $cmakeBuildDir -S $winlockDir -A x64
    cmake -B "$cmakeBuildDir-x86" -S $winlockDir -A Win32
}
cmake --build $cmakeBuildDir --config Release
cmake --build "$cmakeBuildDir-x86" --config Release
```

### 6.2 保留 -SkipWinLock 开关 + 加 -UseCMake 回退

- -SkipWinLock 语义不变
- 加 -UseCMake:$false 可回退到 Makefile.mingw

### 6.3 更新产物路径

- CMake 输出在 build-msvc/ 和 build-msvc-x86/
- build.ps1:124-140 的 Copy-Item 源路径更新
- 产物文件名保持不变（stub_x64.bin / loader_x64.exe 等），避免改 meta.json

### 6.4 验证端到端

- dotnet/build.ps1 完整运行：.NET 主程序 + WinLock 全部编译成功
- dotnet\packer\bin\Release\net10.0-windows\ 下生成完整 dist
- 用 .NET 主程序 GUI 加壳 helloguix64.exe，弹密码框 + 启动正常
- meta.json 不需改（stub.bin 格式不变）

**回滚触发**：
- .NET 主程序编译失败 → build.ps1 加 -UseCMake:$false 回退到 make
- .NET GUI 加壳行为异常 → 检查 stub.bin 路径汇集逻辑

**git commit**：`feat(build): update build.ps1 to use CMake for WinLock`
**关键 tag**：`msvc-migration-complete`

---

## 阶段 7：文档更新

### 7.1 更新 `docs/CHANGES.md`
追加迁移完成记录：日期时间、工具链版本、新增 common/ 头文件、删除的文件、DIE 识别结果变化。

### 7.2 更新 `packer/docs/PACKER_DETECTION.md`
重新跑 DIE 检测，记录迁移后的识别结果（预期从 "Unknown" → "Microsoft Linker 14.51"）。

### 7.3 更新 `packer/README.md`
构建说明从 mingw32-make 改为 cmake。

### 7.4 标记 `packer/docs/MSVC_PORTING_PLAN.md` 为已完成
文档顶部加 "Status: Completed (date)"。

### 7.5 更新 `packer/docs/REFLECTIVE_DESIGN.md`
第 408 行的 "PIC 化（后期）" 标记为已完成。

---

## 依赖关系

```
阶段 0（准备）
   │
   ▼
阶段 1（共享代码抽取）──── 用 MinGW 验证
   │
   ▼
阶段 2（CMake 骨架 + builder）──── 验证 MSVC 工具链
   │
   ▼
阶段 3（Inplace stub，分3批）──── 先做，经验复用
   │
   ▼
阶段 4（Reflective PIC 化，分3步）──── 后做，复用 .asm 模式
   │
   ▼
阶段 5（方案 B 特征消除）──── 可选，失败不影响功能
   │
   ▼
阶段 6（build.ps1 更新）──── 失败可回退 make
   │
   ▼
阶段 7（文档更新）
```

**并行机会**：
- 阶段 1 和阶段 2 可部分并行（共享头抽取不影响 CMake 骨架）
- 阶段 3 批 1/2 和阶段 4 步骤 A 可并行（不同文件）
- 阶段 5 和阶段 6 可部分并行

---

## 风险与缓解

### 高风险项

| 风险 | 影响 | 缓解措施 | 回滚方案 |
|------|------|---------|---------|
| loader.c 剥离 CRT 后行为变化 | Reflective 加壳全部失败 | 分 3 步（A日志/B内存/C TLS），每步用 MinGW 验证后再切 MSVC | 部分回滚 1：WINLOCK_REFLECTIVE_PIC=OFF，保留 CRT 用 MSVC 编译 |
| stub.c 46 处 GCC 扩展迁移遗漏 | stub.bin 字节级变化，魔数定位失败 | 分 3 批，批 1 用 MinGW 验证字节不变；批 3 用 MSVC 编译后 nm 验证符号 | 部分回滚 2：Inplace 保留 MinGW |
| MSVC x86 + msys2 objcopy 不兼容 | x86 stub/loader 无法生成 | 阶段 3 批 3 后单独验证 x86 | x86 保留 MinGW，x64 先迁移 |
| .CRT$XLB TLS callback 注册差异 | TLS proxy 模式失效 | 阶段 4 步骤 C 单独验证 hellomfcx64（有 TLS callback） | 保留 MinGW 版 TLS 注册语法（#ifdef 双模式） |

### 中风险项

| 风险 | 缓解措施 |
|------|---------|
| 共享代码抽取后 4 处 XTEA 行为不一致 | 阶段 1 后用 stub_sha256_test.c 模式写 xtea_test.c 验证互逆 |
| #ifdef _MSC_VER 宏抽象增加复杂度 | 宏定义集中在 common/winlock_compat.h，单点维护 |
| build.ps1 修改影响 .NET 主程序 | 加 -UseCMake 开关，默认 true 但可快速关 |
| /MERGE 节属性 OR 合并导致 W+X | 阶段 5 用独立 .lockw 节放 stub_data 可写字段 |

### 回滚触发条件汇总

| 回滚类型 | 触发条件 | 操作 |
|---------|---------|------|
| 完全回滚 | 阶段 2 CMake 骨架都无法搭建 | git reset --hard mingw-baseline，保留 Makefile.mingw |
| 部分回滚 1 | 阶段 4 步骤 C 后 >2 个样本加壳失败 | CMake 设 WINLOCK_REFLECTIVE_PIC=OFF |
| 部分回滚 2 | 阶段 3 批 3 后 stub.bin 体积变化 >50% | Inplace 保留 MinGW，仅 Reflective 用 MSVC |
| 部分回滚 3 | 阶段 4 PEB walk 共享导致编译失败 | 只迁移 Inplace，Reflective 保留 MinGW |
| x86 保留 MinGW | CMake -A Win32 无法生成可用 x86 | x86 用 Makefile.mingw，x64 用 CMake |

---

## 关键文件清单

1. **packer/common/winlock_compat.h**（新建）- 编译器抽象层，46 处 section attribute 单点维护
2. **packer/common/peb_walk.h**（新建）- PEB walk + DJB15 hash，stub.c 和 loader.c 共享
3. **packer/common/xtea.h**（新建）- XTEA 加密/解密，消除 4 处重复
4. **packer/common/pe_meta.h**（新建）- 节名/魔数常量集中管理
5. **packer/stub/stub.c**（修改）- 46 处 GCC 扩展迁移核心
6. **packer/stub/stub_asm_x64.asm** + **stub_asm_x86.asm**（新建）- jump_to_oep 独立汇编
7. **packer/reflective/loader.c**（修改）- CRT 剥离 + PIC 化核心
8. **packer/reflective/loader_asm_x64.asm** + **loader_asm_x86.asm**（新建）- jump_to_oep
9. **packer/CMakeLists.txt** + 各子目录 CMakeLists.txt（新建）- CMake 构建系统
10. **dotnet/build.ps1**（修改）- CMake 集成

---

## 拒绝的替代方案

### 拒绝方案 A 的「不保留 MinGW 后备」
- **理由**：MSVC 迁移有多个高风险点（PIC 自包含、CRT 剥离、x86 工具链），无后备会导致迁移失败时无法快速回退
- **采纳**：保留 Makefile.mingw + #ifdef _MSC_VER 双兼容，迁移完成并验证后再考虑清理

### 拒绝方案 B 的「LTCG 全程序优化」
- **理由**：/GL + /LTCG 可能引入意外 CRT 依赖（__chkstk 等），增加调试复杂度
- **采纳**：stub/loader 用 /GL- 禁用；builder 可选启用但非必须

### 拒绝方案 B 的「fallback_relocations 4 字节对齐优化」
- **理由**：1 字节步长 → 4 字节步长虽提升 4× 性能，但可能漏判 x86 绝对地址（如 AutoHotkey32），需额外验证
- **采纳**：本轮保持 1 字节步长，迁移稳定后再做性能优化

### 拒绝方案 B 的「ARM64 架构预留」
- **理由**：当前无 ARM64 需求，架构抽象层增加 CMake 复杂度
- **采纳**：本轮只做 x64/x86，ARM64 留待未来需求

### 拒绝方案 B 的「sccache 缓存」
- **理由**：需额外安装配置，本轮迁移聚焦正确性
- **采纳**：用 CMake 默认增量构建，CI 优化留待后续

### 拒绝方案 A 的「jump_to_oep 共享 .asm」
- **理由**：stub 版本（1 参数，不压返回地址）和 loader 版本（2 参数，压返回地址模拟 call）语义不同，强行共享需两个函数名，增加复杂度
- **采纳**：stub 和 loader 各自独立 .asm（共 4 个文件），逻辑清晰

---

## 测试策略

每个阶段完成后用 temp/samples/ 的 hello* 样本验证：

| 阶段 | 测试样本 | 验证点 |
|------|---------|--------|
| 0 | 全部 11 个 | 建立基线 |
| 1 | helloguix64 + hellomfcx64 + stub_sha256_test | MinGW 编译无回归 |
| 2 | helloguix64 | MSVC builder 功能一致 |
| 3 | helloguix64 + hellomfcx64 + hellocli + hellomingw + helloucrt（x64）；helloguix86 + hellomfcx86 + hellowinforms（x86） | MSVC stub 加壳 + 弹框 + 启动 |
| 4 | 全部 11 个 + Notepad4 | MSVC loader PIC 化 + DIE 识别 + 体积 |
| 5 | 全部 11 个 + Notepad4 | 节名伪装 + CheckSum + 无 W+X |
| 6 | helloguix64（.NET GUI 加壳） | build.ps1 端到端 |

自动化测试脚本：复用 packer/tests/ 下现有 e2e_test.ps1 / reflective_batch_test.ps1 / test_x64_regression.ps1 / test_x86_full.ps1。

---

## 实施节奏

总工作量 4-5 天，按以下节奏推进：

| 阶段 | 工作量 | 风险 | 预期产出 |
|------|--------|------|---------|
| 0 准备 | 0.5 天 | 低 | Makefile.mingw + 基线 |
| 1 共享抽取 | 0.5 天 | 低 | common/*.h + MinGW 回归通过 |
| 2 CMake + builder | 0.5 天 | 低 | MSVC builder 可用 |
| 3 Inplace stub | 1 天 | 高 | MSVC stub_x64/x86.bin |
| 4 Reflective PIC | 1.5 天 | 最高 | MSVC loader_x64/x86.exe（15-20KB） |
| 5 方案 B | 0.5 天 | 低 | 节名伪装 + CheckSum |
| 6 build.ps1 | 0.5 天 | 中 | .NET 集成 |
| 7 文档 | 0.5 天 | 低 | CHANGES.md + PACKER_DETECTION.md |

每个阶段完成后更新 docs/CHANGES.md，记录日期时间和关键变化。