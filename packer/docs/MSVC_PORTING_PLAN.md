# WinLock 工具链迁移 MSVC + 隐蔽性增强方案（方案 A+B）

> 创建日期：2026-07-19
> 依据：[PACKER_DETECTION.md](file:///c:/Home/Projects/applocker/packer/docs/PACKER_DETECTION.md) 的可检测性分析
> 参考：[REFLECTIVE_DESIGN.md](file:///c:/Home/Projects/applocker/packer/docs/REFLECTIVE_DESIGN.md) 阶段 4「PIC 化」计划
> 目标：把 Inplace/Reflective 全部从 MinGW GCC 迁移到 MSVC，并用 CMake 统一构建，同时消除暴露的 PE 特征
> 工作量预估：4-5 天（详见第八节时间表，含 Reflective PIC 化）

---

## 一、动机与目标

### 1.1 当前暴露特征回顾

| 加壳方案 | 致命特征 | DIE 识别结果 |
|---------|---------|-------------|
| **Inplace** | `.lock` 节名 + W+X 属性 + EP 在最后一个节 | ❌ 完全隐形（仍报原版 MS Linker） |
| **Reflective** | MinGW 链接器（2.46）+ `/4 /19` COFF 长节名 + 无 Rich Header + `.payload` 节名 + IAT 极少 | ⚠ "Unknown: Unknown" |

### 1.2 方案 A + B 的目标

**方案 A：迁移到 MSVC 工具链**
- ✅ DIE 识别 Reflective 加壳从 "Unknown" → "Microsoft Linker 14.44 / MSVC 19.x / VS 2026"
- ✅ 消除 MinGW 的所有特征（LinkerVersion、COFF 长节名、无 Rich Header、节数 18→5）
- ✅ Inplace 的 stub 也用 MSVC 编译，统一工具链

**方案 A+：Reflective loader PIC 化（顺带完成 REFLECTIVE_DESIGN.md 阶段 4 计划）**
- ✅ Reflective loader 剥离 CRT，从「带 CRT 的 host 程序」改为「PIC 自包含 stub」
- ✅ 与 Inplace stub 共享同一套编译策略（`/NODEFAULTLIB` + 自定义 entry + 魔数定位）
- ✅ 体积从 40-60 KB → 15-20 KB（符合 REFLECTIVE_DESIGN.md 第 305 行预估）
- ✅ IAT 只有真正需要的几个 API（更可控，假 IAT 注入更干净）
- ✅ 一次迁移到位，避免后期再改一次

**方案 B：节名伪装 + 假 IAT 注入**
- ✅ Inplace：`.lock` 节改名为 `.text2`（看起来像 MSVC 的额外代码节）
- ✅ Reflective：`.payload` 节改名为 `.rdata2`
- ✅ Inplace：`.lock` 节去掉 W 属性（stub 不需要运行时写自己）
- ✅ Reflective：在 stub IAT 里注入原 PE 的几个常用 DLL/函数，让 IAT 看起来正常
- ✅ 重算 CheckSum（避免被清零特征识别）

**最终效果**：DIE 仍无法识别加壳，但手动 PE 分析的特征从「明显 packer」降到「略有可疑」。

---

## 1.3 历史背景：Reflective PIC 化的渊源

[REFLECTIVE_DESIGN.md](file:///c:/Home/Projects/applocker/packer/docs/REFLECTIVE_DESIGN.md) 第 14 条「核心设计决策」记录了当初的两阶段策略：

| 阶段 | 工具链 | 模式 | 体积 |
|------|--------|------|------|
| MVP（当前已实现） | MinGW-w64 + CRT | 普通 host 程序，printf 调试 | 40-60 KB |
| **后期完整阶段（本方案 A+ 要做的）** | MSVC `-nostdlib -ffreestanding` | **PIC 自包含**（剥离 CRT） | 15-20 KB |

REFLECTIVE_DESIGN.md 第 408 行明确写着「**PIC 化**：剥离 CRT，切到 `-nostdlib -ffreestanding`（减小体积到 15-20KB）」是阶段 4 的计划。

当初决策用 MinGW 而非 MSVC 的理由（REFLECTIVE_DESIGN.md 决策 1，第 438-446 行）：
1. 与 winlock 现有 `stub.c` 同工具链
2. MinGW-w64 支持 `-nostdlib -ffreestanding` PIC 模式，后期可平滑切换
3. **MSVC x64 不支持内联 asm**（`jump_to_oep` 的 `andq/jmpq` 需要 ML64.exe 外部 .asm 文件）
4. 开发优先：带 CRT 的 MinGW-w64 编译能直接用 printf 调试，比 MSVC 友好

**现在切换 MSVC 的理由**（覆盖当初决策）：
1. 第 1 条仍成立：但「同工具链」的目标从 MinGW 改为 MSVC（Inplace 也一起切）
2. 第 2 条不再相关：MSVC 也能做 PIC 自包含（用 `/NODEFAULTLIB` + 魔数定位 + `.asm` 文件）
3. 第 3 条已解决：本方案已规划独立 `.asm` 文件 + `ml64.exe`，MSVC x64 无内联 asm 限制可克服
4. 第 4 条不再关键：MVP 阶段已完成，调试需求降低；MSVC 的 `OutputDebugStringA` + DebugView 可替代 printf

**结论**：当初选择 MinGW 的 4 个理由中，3 个已不成立或可克服，迁移到 MSVC 的收益（消除 MinGW PE 特征）大于代价（写 .asm 文件）。

---

## 二、目录结构重组

当前结构过于扁平（builder/stub/reflective 各一个目录），且代码复用靠相对路径 `../stub/sha256.h`。改为 CMake 项目结构：

```
packer/
├── CMakeLists.txt                 # 顶层 CMake
├── cmake/
│   ├── msvc_setup.cmake           # MSVC 工具链查找 + vcvars 设置
│   └── ExtractStub.cmake          # objcopy 替代：用 ml/link 生成 stub.bin
├── common/                        # 共享代码（已有）
│   ├── config.h
│   ├── xtea.h                     # 新增：从 builder.c 和 loader.c 抽出 XTEA 实现
│   ├── sha256.h                   # 从 stub/ 移过来，统一位置
│   └── pe_meta.h                  # 新增：PE 节名/魔数/flag 常量
├── stub/                          # Inplace stub（PIC 自包含）
│   ├── CMakeLists.txt
│   ├── stub.c
│   ├── stub_asm_x64.asm           # 新增：x64 jump_to_oep 实现
│   ├── stub_asm_x86.asm           # 新增：x86 jump_to_oep 实现
│   └── stub.ld                    # 替换为 link.exe /ORDER + /MERGE 实现
├── reflective/                    # Reflective loader
│   ├── CMakeLists.txt
│   ├── loader.c
│   ├── payload.h
│   ├── loader_asm_x64.asm         # 新增：x64 jump_to_oep 实现
│   ├── loader_asm_x86.asm         # 新增：x86 jump_to_oep 实现
│   └── stub.manifest
├── builder/                       # 加壳器
│   ├── CMakeLists.txt
│   ├── builder.c                  # Inplace builder
│   └── builder_reflective.c       # Reflective builder
├── tools/                         # 辅助工具
│   ├── gen_api_hash.py            # DJB15 hash 生成
│   └── extract_stub_bin.py        # 从 .obj/.exe 提取 .lock 节为 stub.bin
├── tests/                         # 已有
└── docs/                          # 已有
```

### 2.1 重组理由

| 改动 | 收益 |
|------|------|
| `common/xtea.h` | XTEA 加密/解密代码当前在 builder.c / loader.c / stub.c 三处重复，抽出后单点维护 |
| `common/sha256.h` | 从 `stub/` 移到 `common/`，路径不再有 `../stub/` 这种跨模块相对引用 |
| `common/pe_meta.h` | 节名/魔数集中管理（方案 B 改节名时只改一处） |
| 独立 `.asm` 文件 | MSVC x64 不支持内联汇编，必须独立 .asm + ml64.exe |
| CMakeLists.txt 每个 target 一个 | 可独立编译 x64 / x86，方便 CI 矩阵测试 |
| **复用 msys2/w64devkit 的 binutils** | **关键**：MSVC 工具链仅指编译器（cl/link/ml64），binutils（objcopy/nm/strip）是独立 PE 文件处理工具，与编译器无关，可继续使用。详见 2.2 节 |

### 2.2 工具链分工：MSVC 编译 + binutils 后处理

**重要澄清**：迁移到 MSVC 工具链**不等于**抛弃 msys2/w64devkit。两者分工如下：

| 工具类别 | 来源 | 用途 | 是否迁移 |
|---------|------|------|---------|
| **C 编译器** | MSVC `cl.exe` | 编译 .c → .obj | ✅ 迁移到 MSVC |
| **链接器** | MSVC `link.exe` | 链接 .obj → .exe | ✅ 迁移到 MSVC |
| **汇编器** | MSVC `ml64.exe` / `ml.exe` | 编译 .asm → .obj | ✅ 迁移到 MSVC |
| **库管理** | MSVC `lib.exe` | 创建 .lib | ✅ 迁移到 MSVC |
| **objcopy** | w64devkit / msys2 | 提取节区为 .bin | ❌ **继续用 binutils** |
| **nm** | w64devkit / msys2 | 查符号表 | ❌ **继续用 binutils** |
| **strip** | w64devkit / msys2 | 去调试符号 | ❌ **继续用 binutils** |
| **PE 分析** | Python pefile | 验证 PE 结构 | ❌ 继续用 |

**理由**：binutils 是通用的 PE/ELF 文件处理工具，与编译器无关。`objcopy -O binary -j .lock stub_x64.exe stub_x64.bin` 对 MSVC 生成的 .exe 同样有效，因为 PE 文件格式是统一的。

**好处**：
1. 不用重写 `objcopy -O binary -j .lock` 的 Python 替代脚本（原本担心 MSVC 没有 objcopy）
2. 现有 Makefile 里的 `objcopy` / `nm` 调用可以直接搬到 CMake
3. `strip` 可以用来去除 MSVC 生成的调试符号（虽然 MSVC 也有 `/DEBUG:NONE`，但 strip 更灵活）
4. CMake 配置简化：MSVC 编译 + binutils 后处理的混合工具链

**CMake 中的实现**：
```cmake
# MSVC 编译器（CMAKE_C_COMPILER 自动检测）
enable_language(C ASM_MASM)

# binutils 工具查找（继续用 w64devkit 或 msys2 的）
find_program(OBJCOPY objcopy PATHS C:/Home/Develop/w64devkit/bin REQUIRED)
find_program(NM nm PATHS C:/Home/Develop/w64devkit/bin REQUIRED)
find_program(STRIP strip PATHS C:/Home/Develop/w64devkit/bin REQUIRED)

# 提取 .lock 节为 stub.bin（沿用原 Makefile 写法）
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/stub_x64.bin
    COMMAND ${OBJCOPY} -O binary -j .lock
            ${CMAKE_CURRENT_BINARY_DIR}/stub_x64.exe
            ${CMAKE_CURRENT_BINARY_DIR}/stub_x64.bin
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/stub_x64.exe
    COMMENT "Extracting .lock section -> stub_x64.bin"
)
```

---

## 三、方案 A：迁移到 MSVC 工具链

### 3.1 工具链确认

系统已安装：
- **MSVC 14.44.35207**：`C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\`
  - `cl.exe` / `link.exe` / `ml64.exe` / `lib.exe` / `dumpbin.exe` / `editbin.exe`
- **Windows SDK**：通过 VS Installer 安装（10.x）
- **w64devkit binutils**：`C:\Home\Develop\w64devkit\bin\`（`objcopy` / `nm` / `strip` / `ld` 等）
- **msys2 mingw32 binutils**：`C:\Home\Develop\msys64\mingw32\bin\`（x86 版本）
- 无 clang-cl，只能用纯 MSVC 编译器，但 binutils 继续用 w64devkit/msys2 的（详见 2.2 节）

### 3.2 GCC 扩展到 MSVC 的语法映射

| GCC 语法 | 用途 | MSVC 替代 | 难度 |
|---------|------|----------|------|
| `__attribute__((section(".lock.text"), used, noinline))` | 函数放入特定节 | `#pragma code_seg(".lock$text")` + `__declspec(noinline)` | 中 |
| `__attribute__((section(".lock.data"), used, aligned(16)))` | 数据放入特定节 | `#pragma data_seg(".lock$data")` + `__declspec(align(16))` | 中 |
| `__attribute__((section(".lock.rdata"), used, aligned(2)))` | 只读数据 | `#pragma const_seg(".lock$rdata")` + `__declspec(align(2))` | 中 |
| `__asm__ volatile ("sfence" ::: "memory")` | 内存屏障 | `_mm_sfence()`（`<intrin.h>`） | 简单 |
| `__asm__ volatile ("andq $-16, %rsp..." :::)` | x64 内联汇编跳 OEP | **必须独立 .asm 文件** | 🔴 难 |
| `__asm__ volatile ("andl $-16, %esp..." :::)` | x86 内联汇编 | `__asm { and esp, -16; jmp eax }` | 中 |
| `__builtin_unreachable()` | 标记不可达 | `__assume(0)` 或 `__fastfail(7)` | 简单 |
| `__readgsqword(0x60)` / `__readfsdword(0x30)` | PEB/TEB 访问 | **MSVC 同名 intrinsics**，无需改 | 0 |
| `__attribute__((optimize("O0")))` | 关闭优化 | `#pragma optimize("", off)` | 简单 |
| `__attribute__((section(".CRT$XLB"), used))` | TLS callback 注册 | `#pragma section(".CRT$XLB", read)` + `__declspec(allocate(".CRT$XLB"))` | 中 |

### 3.3 关键技术细节

#### 3.3.1 Inplace stub 的节布局改造（最大难点）

**MinGW 版**用 `__attribute__((section(".lock.text")))` 等把所有 stub 代码/数据塞进一个 `.lock` 输出节，再用 `objcopy -O binary -j .lock` 导出为 `stub.bin`。

**MSVC 版**思路：
1. 用 `#pragma code_seg(".lock$text")` / `#pragma data_seg(".lock$data")` / `#pragma const_seg(".lock$rdata")` 把代码/数据分到子节
2. link.exe 用 `/MERGE:.lock$text=.lock /MERGE:.lock$data=.lock /MERGE:.lock$rdata=.lock` 合并成单一 `.lock` 节
3. 用 `/ORDER:@stub_order.txt` 控制 .lock 节内函数顺序（保证 stub_entry 在最前面）
4. **objcopy 继续用**（来自 w64devkit/msys2 binutils，详见 2.2 节）：`objcopy -O binary -j .lock stub_x64.exe stub_x64.bin` 对 MSVC 生成的 .exe 同样有效，无需写 Python 替代脚本

#### 3.3.2 stub_entry 节内偏移保证

MinGW 用 `stub.ld` 的 `KEEP(*(.lock.entry))` 保证 stub_entry 在 .lock 节起始。MSVC 方案：

**方案 1**：用 `/ORDER:@order.txt` 文件指定符号顺序
```
stub_entry
find_module_by_hash
find_export_by_hash
...
```
但 `/ORDER` 只对 .text 节有效，对自定义节无效。

**方案 2**（推荐）：改用魔数定位
- 在 stub_entry 函数前放一个 8 字节魔数（类似 `STUB_ENTRY_MAGIC`，已在 `config.h` 定义）
- builder 在 stub.bin 中搜索魔数定位 stub_entry 偏移
- 这样不依赖节内布局，MSVC 怎么排都行

**当前 builder.c 已经在用魔数定位**（`STUB_DATA_MAGIC` / `STUB_ENTRY_MAGIC` / `STUB_TLS_CB_MAGIC`），所以方案 2 完全兼容现有逻辑。

#### 3.3.3 PIC 自包含的挑战

Inplace stub 是 PIC（position-independent code）自包含设计：
- 不能调用任何外部函数（包括 CRT）
- 所有 API 通过 PEB walk + hash 解析
- 所有静态数据用 RIP-relative 访问（x64）或绝对地址 + reloc（x86）

**MSVC 编译 PIC 自包含代码的难点**：
1. MSVC 默认链接 CRT，需要 `/NODEFAULTLIB` + 自定义 entry
2. MSVC 默认会生成调用 CRT 的代码（如 __chkstk），需要 `/Gs1048576` 关掉栈探针
3. MSVC 会生成 `__security_cookie` 引用，需要 `/GS-` 关掉
4. MSVC x64 默认非 PIC，但 x64 的小代码模型（small code model）本身就是 RIP-relative，相当于 PIC

**结论**：MSVC 编译 PIC stub 是可行的，需要这些 flag：
```cmake
set(STUB_CFLAGS_MSVC
    /O2                    # 优化
    /GS-                   # 关闭 stack cookie
    /Gs1048576             # 关闭栈探针
    /GL-                   # 关闭 LTCG（避免引入额外 CRT 依赖）
    /Zl                    # 不引用默认库
    /NODEFAULTLIB          # 链接时
    /ENTRY:stub_entry      # 自定义入口
    /SUBSYSTEM:WINDOWS
    /BASE:0x10000          # 与 stub.ld 一致
    /DYNAMICBASE:NO        # 关闭 ASLR（PIC stub 自处理）
    /MERGE:.lock$text=.lock /MERGE:.lock$data=.lock /MERGE:.lock$rdata=.lock
)
```

#### 3.3.4 jump_to_oep 改造

**GCC 版**（x64）：
```c
static void jump_to_oep(void* oep, void* ret_addr) {
    __asm__ volatile (
        "andq $-16, %%rsp\n\t"
        "pushq %1\n\t"
        "jmpq *%0\n\t"
        : : "r"(oep), "r"(ret_addr) : "memory"
    );
    __builtin_unreachable();
}
```

**MSVC 版**（独立 .asm 文件）：

`stub_asm_x64.asm`：
```asm
.code
; void jump_to_oep_x64(void* oep /*RCX*/, void* ret_addr /*RDX*/);
; x64 calling convention: RCX=arg1, RDX=arg2
jump_to_oep_x64 PROC
    and  rsp, -16        ; 16 字节对齐
    push rdx             ; 压入返回地址（模拟 call）
    jmp  rcx             ; 跳到 OEP
jump_to_oep_x64 ENDP
END
```

`stub_asm_x86.asm`（用 MASM x86 语法）：
```asm
.586
.model flat
.code
; void __cdecl jump_to_oep_x86(void* oep /*[esp+4]*/, void* ret_addr /*[esp+8]*/);
_jump_to_oep_x86 PROC
    mov  eax, [esp+4]    ; oep
    mov  edx, [esp+8]    ; ret_addr
    and  esp, -16        ; 16 字节对齐
    push edx             ; 压入返回地址
    jmp  eax             ; 跳到 OEP
_jump_to_oep_x86 ENDP
END
```

C 代码改为：
```c
extern void jump_to_oep_x64(void* oep, void* ret_addr);
static void jump_to_oep(void* oep, void* ret_addr) {
    jump_to_oep_x64(oep, ret_addr);
}
```

### 3.4 Reflective loader 的迁移（PIC 化，与 Inplace 同等难度）

**重要**：本方案 A+ 把 Reflective loader 从「带 CRT 的 host 程序」改为「PIC 自包含 stub」，对齐 REFLECTIVE_DESIGN.md 阶段 4 计划。

Reflective loader 的 PIC 化比 Inplace stub 复杂度略低（不需要 objcopy 提取 .bin，因为是完整 EXE），但仍需处理：

1. **剥离 CRT**：`printf` 改用 `OutputDebugStringA` 或直接写日志文件（用 `CreateFileA` + `WriteFile`，不用 `fopen`/`fprintf`）
2. **节区布局**：用 `#pragma code_seg/.data_seg/const_seg` 把 loader 代码/数据分到子节，再用 `/MERGE` 合并到 `.rdata2`（原 `.payload` 节名）旁边的 `.text2` 节
3. **TLS callback 注册**：用 `#pragma section(".CRT$XLB", read)` + `__declspec(allocate(".CRT$XLB"))`
4. **jump_to_oep**：同 Inplace，独立 .asm 文件
5. **PEB walk + hash 解析 API**：复用 Inplace stub.c 的 `find_module_by_hash` / `find_export_by_hash`（已在 stub.c 实现）
6. **密码弹框**：保留现有 `DialogBoxIndirectParamW` 实现，但 API 解析改用 hash 而非 `LoadLibraryA`（避免 IAT 暴露 user32.dll）

```c
/* MinGW 版 */
__attribute__((section(".CRT$XLB"), used))
static const PIMAGE_TLS_CALLBACK g_tls_cb_ptr = tls_callback_proxy;

/* MSVC 版 */
#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB"))
static const PIMAGE_TLS_CALLBACK g_tls_cb_ptr = tls_callback_proxy;
```

#### 3.4.1 Reflective PIC 化的具体改动

**剥离 CRT 的难点**：当前 `loader.c` 大量使用 CRT 函数：
- `printf` / `fprintf` / `fflush`（日志）→ 改用 `OutputDebugStringA` + 直接 `WriteFile` 写日志文件
- `fopen` / `fclose` → 改用 `CreateFileA` / `CloseHandle`
- `memcpy` / `memset` → MSVC 内联（`<intrin.h>` 提供，不算 CRT 依赖）
- `malloc` / `free` → 改用 `VirtualAlloc` / `VirtualFree`（loader 已经在用）

**PEB walk 复用**：从 `stub.c` 抽取 `find_module_by_hash` / `find_export_by_hash` / `WINLOCK_PEB()` 宏到 `common/peb_walk.h`，Reflective 和 Inplace 共享。

**IAT 精简**：剥离 CRT 后，loader 的 IAT 只有：
- KERNEL32.dll: `VirtualAlloc` / `VirtualProtect` / `VirtualFree` / `LoadLibraryA` / `GetProcAddress` / `ExitProcess` / `CreateFileA` / `WriteFile` / `CloseHandle` / `GetModuleFileNameA` / `SetCurrentDirectoryW` / `SetDllDirectoryW` 等（约 15-20 个）
- USER32.dll: `DialogBoxIndirectParamW` / `EndDialog` / `GetDlgItemTextW` / `MessageBoxW`（4 个，密码弹框）

剥 CRT 后 IAT 仍比带 CRT 时少（msvcrt.dll 的 38 个函数会消失），需要假 IAT 注入补回来（见方案 B 第 4.5 节）。

### 3.5 Builder 的迁移（最简单）

`builder.c` 和 `builder_reflective.c` 都是纯 C，无 GCC 扩展：
- 直接 `cl.exe /O2 builder.c /link advapi32.lib`
- 唯一改动：`getopt` 风格的参数解析需自实现（MinGW 有 `getopt.h`，MSVC 没有）
  - 当前代码是手写 argv 解析，不依赖 getopt，无问题

---

## 四、方案 B：节名伪装 + 假 IAT 注入

### 4.1 节名伪装对照表

| 原节名 | 新节名 | 理由 |
|--------|--------|------|
| `.lock` (Inplace) | `.text2` | MSVC 程序常有 .text2（如 LTCG 分区），看起来正常 |
| `.payload` (Reflective) | `.rdata2` | rdata2 是合理的只读数据节名 |
| `WINLOCK_SECTION_NAME` 常量 | `.text2\0\0\0` | 8 字节内（PE 节名限制） |

**改动点**：
- `common/config.h`：改 `WINLOCK_SECTION_NAME` 宏
- `common/pe_meta.h`（新）：定义 `REFLECTIVE_PAYLOAD_SECTION_NAME`
- `reflective/loader.c`：`find_payload_section` 改匹配新节名
- `builder/builder.c`：写入节表时用新节名
- `builder/builder_reflective.c`：同上

### 4.2 Inplace `.lock` 节属性改造

当前 `.lock` 节属性 `0xE0000020`（ERWC）—— **W+X 是 packer 最典型的特征**。

**stub 真的需要 W 属性吗？**
- stub 代码本身不需要运行时写自己
- 解密 .text 节时用 VirtualProtect 临时改 .text 为 RW，与 .lock 节无关
- 唯一可能需要 W 的场景：stub_data 字段（密码错误次数等）运行时写入

**方案**：
- 把 stub_data 中需要运行时写的字段（如 `g_tls_decrypted`）单独放 `.lock$data_w` 子节
- `.lock` 主节只保留 `0x60000020`（ERC，Execute+Read+Code）
- `.lock$data_w` 用 `0xC0000040`（RWI），合并到 .lock 时 link.exe 会按最严格权限合并…

**问题**：link.exe `/MERGE` 会按 OR 合并节属性，`.lock$data_w` 的 W 会让整个 .lock 变成 W+X。

**最终方案**：
- **不合并** stub_data 到 .lock 节，单独放一个 `.lockw` 节
- `.lock` 节：`0x60000020`（ERC，无 W）
- `.lockw` 节：`0xC0000040`（RWI，无 E）
- 这样就没有 W+X 节了
- builder 仍只把 `.lock` 节内容写入 stub.bin（`stub_data` 通过魔数定位，不依赖节位置）

### 4.3 EP 节位置优化

当前 Inplace EP 在最后一个节（`.lock`），是 packer 的典型特征。

**改进**：builder 在添加 `.lock` 节时，把它**插入到节表中间**而不是末尾。

实现：
- 在原 PE 的 `.text` 之后、`.rdata` 之前插入 `.lock` 节
- 需要重写所有节的 `PointerToRawData` 和 `VirtualAddress`
- 复杂度高，**作为方案 B 的可选项**（如果不做，只靠节名改名已能消除大部分可疑性）

### 4.4 CheckSum 重算

当前 builder 不重算 CheckSum，输出 PE 的 CheckSum = 0，是低风险但明显的特征。

**改动**：builder 在写完输出 PE 后，调用 Windows API `CheckSumMappedFile` 重算：
```c
#include <imagehlp.h>
#pragma comment(lib, "imagehlp.lib")

DWORD new_checksum;
CheckSumMappedFile(output_pe_data, output_pe_size, NULL, &new_checksum);
/* 写入 OptionalHeader.CheckSum */
```

### 4.5 假 IAT 注入（Reflective 专用）

当前 Reflective stub 的 IAT 只有 3 个 DLL / 79 个函数，是 packer 强信号。

**方案**：builder 在生成 stub 时，从原 PE 的 IAT 里挑几个常用 DLL/函数注入到 stub 的 IAT。

**实现思路**：
1. builder 解析原 PE 的 IAT，统计每个 DLL 的函数列表
2. 挑出「看起来无害」的 DLL/函数组合（如 KERNEL32 的 GetCurrentProcess / GetTickCount，USER32 的 GetForegroundWindow，SHELL32 的 ShellExecuteW）
3. 用 `LoadLibrary` + `GetProcAddress` 在 stub 启动时填充这些 IAT 项（不影响运行时行为）
4. 或者更彻底：在 stub 源码里 `#pragma comment(lib, "shell32.lib")` + 显式调用 ShellExecuteW(NULL, L"open", NULL, NULL, NULL, 0) 等空操作

**折中方案**（推荐）：
- 在 stub 源码里显式引用几个常用 DLL 的常用函数（dummy 调用）
- 不影响 stub 功能，但 IAT 里会出现 SHELL32/OLE32/COMCTL32 等正常 DLL

```c
/* loader.c 里加 dummy 引用 */
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
__declspec(noinline) static void dummy_iat_padding(void) {
    /* 永远不会真正调用，但链接器会把这些 API 放进 IAT */
    volatile PVOID p1 = (PVOID)ShellExecuteW;
    volatile PVOID p2 = (PVOID)CoInitialize;
    volatile PVOID p3 = (PVOID)InitCommonControls;
    (void)p1; (void)p2; (void)p3;
}
```

### 4.6 Inplace 假 IAT（不需要）

Inplace 加壳保留原 PE 的完整 IAT（12 DLL / 484 函数），不需要假 IAT 注入。

---

## 五、CMake 构建系统设计

### 5.1 顶层 CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.20)
project(winlock_packer C ASM_MASM)

# 强制 MSVC（方案 A 核心）
if(NOT MSVC)
    message(FATAL_ERROR "This project requires MSVC. Run from 'x64 Native Tools Command Prompt for VS 2026' or use vcvars64.bat")
endif()

# 选项
option(WINLOCK_BUILD_X86 "Build x86 stub/loader" OFF)
option(WINLOCK_BUILD_TESTS "Build test programs" ON)

# MSVC 通用设置
set(CMAKE_C_FLAGS "/W3 /O2 /MT /Zl")
set(CMAKE_C_FLAGS_RELEASE "/O2 /MT")

# binutils 工具查找（继续用 w64devkit/msys2 的，详见 2.2 节）
# 这些工具与编译器无关，可处理 MSVC 生成的 PE 文件
set(W64DEVKIT_BIN "C:/Home/Develop/w64devkit/bin")
set(MSYS_MINGW32_BIN "C:/Home/Develop/msys64/mingw32/bin")
find_program(OBJCOPY x64 objcopy PATHS ${W64DEVKIT_BIN} REQUIRED)
find_program(NM_X64 nm PATHS ${W64DEVKIT_BIN} REQUIRED)
find_program(STRIP_X64 strip PATHS ${W64DEVKIT_BIN} REQUIRED)
if(WINLOCK_BUILD_X86)
    find_program(OBJCOPY_X86 objcopy PATHS ${MSYS_MINGW32_BIN} REQUIRED)
    find_program(NM_X86 nm PATHS ${MSYS_MINGW32_BIN} REQUIRED)
endif()

# 包含目录
include_directories(${CMAKE_SOURCE_DIR}/common)

# 子目录
add_subdirectory(stub)        # Inplace PIC stub
add_subdirectory(reflective)  # Reflective loader
add_subdirectory(builder)     # 加壳器

if(WINLOCK_BUILD_TESTS)
    add_subdirectory(tests)
endif()
```

### 5.2 stub/CMakeLists.txt（PIC 自包含 stub）

```cmake
# x64 stub
set(STUB_CFLAGS_X64
    /O2 /GS- /Gs1048576 /GL- /Zl
    /DWINLOCK_STUB /DWINLOCK_PIC
)

# 编译 stub.c 为 .obj（不链接）
add_library(stub_x64_obj OBJECT stub.c stub_asm_x64.asm)
target_compile_options(stub_x64_obj PRIVATE ${STUB_CFLAGS_X64})
set_target_properties(stub_x64_obj PROPERTIES
    CMAKE_C_FLAGS "${STUB_CFLAGS_X64}"
)

# 自定义命令：link stub_x64.exe（用 MSVC link.exe + /NODEFAULTLIB + 自定义 entry）
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/stub_x64.exe
    COMMAND link.exe
        /NODEFAULTLIB
        /SUBSYSTEM:WINDOWS
        /ENTRY:stub_entry
        /BASE:0x10000
        /DYNAMICBASE:NO
        /MERGE:.lock$text=.lock
        /MERGE:.lock$data=.lock
        /MERGE:.lock$rdata=.lock
        /ORDER:@${CMAKE_CURRENT_SOURCE_DIR}/stub_order.txt
        $<TARGET_OBJECTS:stub_x64_obj>
        /OUT:${CMAKE_CURRENT_BINARY_DIR}/stub_x64.exe
    DEPENDS stub_x64_obj
)

# 自定义命令：从 stub_x64.exe 提取 .lock 节为 stub_x64.bin
# 继续用 binutils objcopy（详见 2.2 节），与原 Makefile 写法一致
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/stub_x64.bin
    COMMAND ${OBJCOPY_X64} -O binary -j .lock
            ${CMAKE_CURRENT_BINARY_DIR}/stub_x64.exe
            ${CMAKE_CURRENT_BINARY_DIR}/stub_x64.bin
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/stub_x64.exe
    COMMENT "Extracting .lock section -> stub_x64.bin"
    VERBATIM
)

# 打印 stub 符号布局（调试用，与原 Makefile 行为一致）
add_custom_command(
    TARGET stub_x64_obj POST_BUILD
    COMMAND ${NM_X64} $<TARGET_FILE:stub_x64_obj>
            | findstr "stub_entry stub_data STR_"
    COMMENT "stub_x64 symbol layout"
    VERBATIM
)

add_custom_target(stub_x64 ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/stub_x64.bin
)

# x86 stub（可选，用 Hostx86\x86 的 cl.exe + msys2 objcopy）
if(WINLOCK_BUILD_X86)
    # 同上，但用 x86 工具链：
    # - cl.exe: C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx86\x86\
    # - ml.exe (x86 MASM)
    # - objcopy: ${OBJCOPY_X86}（msys2 mingw32）
    # ...
endif()
```

### 5.3 reflective/CMakeLists.txt

```cmake
# x64 loader（用 CRT，console subsystem 便于调试）
add_executable(loader_x64
    loader.c
    loader_asm_x64.asm
)
target_compile_definitions(loader_x64 PRIVATE _WIN64)
target_link_libraries(loader_x64 PRIVATE user32)
set_target_properties(loader_x64 PROPERTIES
    LINK_FLAGS "/BASE:0x10000 /DYNAMICBASE:NO /STACK:0x10000"
)

# x86 loader
if(WINLOCK_BUILD_X86)
    add_executable(loader_x86
        loader.c
        loader_asm_x86.asm
    )
    # 用 x86 工具链编译（CMake 多架构配置）
endif()
```

### 5.4 builder/CMakeLists.txt

```cmake
# Inplace builder
add_executable(builder builder.c)
target_link_libraries(builder PRIVATE advapi32 imagehlp)

# Reflective builder
add_executable(builder_reflective builder_reflective.c)
target_link_libraries(builder_reflective PRIVATE advapi32)
```

### 5.5 多架构支持

CMake 用 `WIN64` 和 `WIN32` 配置区分 x64/x86：

```bash
# x64
cmake -B build-x64 -A x64
cmake --build build-x64 --config Release

# x86
cmake -B build-x86 -A Win32
cmake --build build-x86 --config Release
```

或用 VS 生成器：
```bash
cmake -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release -- /p:Platform=x64
cmake --build build --config Release -- /p:Platform=Win32
```

---

## 六、代码改动清单

### 6.1 共享代码抽取（新增）

**`common/xtea.h`**（新增）：
- 从 `builder.c`、`builder_reflective.c`、`loader.c` 抽出 XTEA 加密/解密函数
- 用 `#ifdef WINLOCK_PIC` 区分 stub 用途和 host 用途

**`common/sha256.h`**（从 `stub/sha256.h` 移过来）：
- 路径更新：`stub.c` 和 `loader.c` 的 `#include` 改路径

**`common/pe_meta.h`**（新增）：
```c
#define WINLOCK_SECTION_NAME  ".text2\0\0"       /* 原 ".lock" */
#define REFLECTIVE_SECTION_NAME ".rdata2\0"        /* 原 ".payload" */
```

### 6.2 stub.c 改动

| 改动类型 | 数量 | 说明 |
|---------|------|------|
| `__attribute__((section(...)))` → `#pragma code_seg/data_seg/const_seg` | 46 处 | 用宏统一：`WINLOCK_SECTION_TEXT` / `WINLOCK_SECTION_DATA` / `WINLOCK_SECTION_RDATA` |
| `__asm__ volatile (...)` → 独立 .asm | 2 处 | jump_to_oep x64/x86 |
| `__builtin_unreachable()` → `__assume(0)` | 2 处 | |
| `__attribute__((optimize("O0")))` → `#pragma optimize("", off)` | 1 处 | stub_entry |
| `__asm__ __volatile__("sfence" ::: "memory")` → `_mm_sfence()` | 1 处 | |

**宏定义（在 stub.c 顶部）**：
```c
#ifdef _MSC_VER
  #define WINLOCK_SECTION_TEXT   __pragma(code_seg(".lock$text")) __declspec(noinline)
  #define WINLOCK_SECTION_DATA   __pragma(data_seg(".lock$data")) __declspec(align(16))
  #define WINLOCK_SECTION_RDATA  __pragma(const_seg(".lock$rdata"))
  #define WINLOCK_SECTION_ENTRY  __pragma(code_seg(".lock$entry")) __declspec(noinline)
  #define WINLOCK_UNREACHABLE    __assume(0)
#else
  #define WINLOCK_SECTION_TEXT   __attribute__((section(".lock.text"), used, noinline))
  #define WINLOCK_SECTION_DATA   __attribute__((section(".lock.data"), used, aligned(16)))
  #define WINLOCK_SECTION_RDATA  __attribute__((section(".lock.rdata"), used, aligned(2)))
  #define WINLOCK_SECTION_ENTRY  __attribute__((section(".lock.entry"), used, noinline))
  #define WINLOCK_UNREACHABLE    __builtin_unreachable()
#endif
```

### 6.3 loader.c 改动（PIC 化）

| 改动类型 | 数量 | 说明 |
|---------|------|------|
| `__attribute__((noinline, used))` → `__declspec(noinline)` | 1 处 | oep_returned |
| `__asm__ volatile (...)` → 独立 .asm | 2 处 | jump_to_oep |
| `__builtin_unreachable()` → `__assume(0)` | 2 处 | |
| `__attribute__((section(".CRT$XLB"), used))` → `#pragma section` + `__declspec(allocate)` | 1 处 | TLS callback 注册 |
| **剥离 CRT**（PIC 化核心） | 全文 | `printf`/`fopen`/`malloc` 改用 Win32 API |
| **PEB walk 复用** | 新增 | 从 stub.c 抽取 `find_module_by_hash` / `find_export_by_hash` |
| **API 解析改 hash** | 全文 | `LoadLibraryA("user32.dll")` 改用 hash 避免明文 IAT |
| **节区属性宏** | 多处 | 用 `WINLOCK_SECTION_TEXT` 等宏统一（与 stub.c 同套） |

**loader.c PIC 化后预计 GCC 扩展数**：从当前 6 处 → 与 stub.c 同等（约 40+ 处，因为剥离 CRT 后所有函数都要进 `.rdata2` 子节）

### 6.4 builder.c / builder_reflective.c 改动

| 改动类型 | 说明 |
|---------|------|
| 节名常量 | `.lock` → `.text2`，`.payload` → `.rdata2` |
| CheckSum | 写完输出 PE 后调用 `CheckSumMappedFile` 重算 |
| Inplace `.lock` 属性 | `0xE0000020` (ERWC) → `0x60000020` (ERC) |

### 6.5 新增文件

| 文件 | 内容 |
|------|------|
| `stub/stub_asm_x64.asm` | x64 jump_to_oep |
| `stub/stub_asm_x86.asm` | x86 jump_to_oep |
| `reflective/loader_asm_x64.asm` | x64 jump_to_oep |
| `reflective/loader_asm_x86.asm` | x86 jump_to_oep |
| `common/xtea.h` | XTEA 实现（builder + loader 共享） |
| `common/sha256.h` | 从 `stub/sha256.h` 移过来 |
| `common/pe_meta.h` | 节名/魔数常量 |
| `common/peb_walk.h` | PEB walk + DJB15 hash 解析（stub.c + loader.c 共享） |
| `cmake/msvc_setup.cmake` | MSVC 工具链设置 |

**不需要的文件**（原方案误以为要写）：
- ~~`tools/extract_stub_bin.py`~~ —— 继续用 binutils `objcopy -O binary -j .lock`，详见 2.2 节

---

## 七、实施步骤

### 步骤 1：搭建 CMake 骨架（半天）

- [ ] 创建 `packer/CMakeLists.txt` 顶层
- [ ] 配置 MSVC 工具链查找
- [ ] 验证 `cmake -B build -G "Visual Studio 18 2026"` 能生成 .sln
- [ ] 把 builder.c 先迁移过来（最简单，无 GCC 扩展）

### 步骤 2：抽取共享代码（半天）

- [ ] 创建 `common/xtea.h`，从三处抽出 XTEA 实现
- [ ] 把 `stub/sha256.h` 移到 `common/sha256.h`
- [ ] 创建 `common/pe_meta.h`，定义节名常量
- [ ] 更新所有 `#include` 路径
- [ ] 用 MinGW 编译验证抽取正确（回归测试）

### 步骤 3：迁移 Reflective loader（PIC 化，1 天）

**注意**：此步骤包含剥离 CRT + PEB walk 改造，与步骤 4 Inplace 同等难度。

- [ ] 写 `loader_asm_x64.asm` 和 `loader_asm_x86.asm`
- [ ] 创建 `common/peb_walk.h`，从 `stub.c` 抽取 `find_module_by_hash` / `find_export_by_hash` / `WINLOCK_PEB()`
- [ ] 改 `loader.c`：
  - [ ] 剥离 CRT：`printf`/`fprintf` → `OutputDebugStringA` + `WriteFile`；`fopen`/`fclose` → `CreateFileA`/`CloseHandle`；`malloc`/`free` → `VirtualAlloc`/`VirtualFree`
  - [ ] API 解析改用 hash（避免 IAT 明文 `LoadLibraryA("user32.dll")`）
  - [ ] 用 `WINLOCK_SECTION_TEXT` 等宏替换 GCC 扩展（与 stub.c 同套）
  - [ ] `__attribute__((section(".CRT$XLB"), used))` → `#pragma section` + `__declspec(allocate)`
  - [ ] `jump_to_oep` 改用独立 .asm
- [ ] CMake 编译 `loader_x64.exe`（用 `/NODEFAULTLIB` + 自定义 entry）
- [ ] 端到端测试：加壳 Notepad4.exe，弹密码框，输入正确密码，启动

### 步骤 4：迁移 Inplace stub（1 天）

- [ ] 写 `stub_asm_x64.asm` 和 `stub_asm_x86.asm`
- [ ] 改 `stub.c` 的 46 处 GCC 扩展（用宏统一）
- [ ] CMake 编译 `stub_x64.exe`（MSVC cl.exe + link.exe）
- [ ] 用 binutils `objcopy -O binary -j .lock` 提取 `stub_x64.bin`（详见 2.2 节）
- [ ] 端到端测试：加壳 Notepad4.exe，弹密码框，启动

### 步骤 5：方案 B 节名伪装（半天）

- [ ] 改 `common/pe_meta.h` 的节名常量
- [ ] 改 `reflective/loader.c` 的 `find_payload_section` 匹配新节名
- [ ] 改 builder 写入节表的节名
- [ ] 测试所有方案能正常工作

### 步骤 6：方案 B 其他特征消除（半天）

- [ ] Inplace `.lock` 节属性 ERWC → ERC（去掉 W）
- [ ] 把 stub_data 中需要 W 的字段单独放 `.lockw` 节
- [ ] builder 调用 `CheckSumMappedFile` 重算 CheckSum
- [ ] Reflective 假 IAT 注入（dummy API 引用）

### 步骤 7：回归测试（半天）

- [ ] 全样本回归测试：Notepad4 / FastCopy / Bandizip / BCompare / CC-Switch / AutoHotkey
- [ ] x64 + x86 都测
- [ ] DIE 扫描验证：Inplace 仍报 MS Linker，Reflective 从 "Unknown" → "Microsoft Linker 14.44"
- [ ] 更新 `docs/CHANGES.md` 和 `docs/PACKER_DETECTION.md`

---

## 八、复杂度与时间估算

| 阶段 | 工作量 | 风险 |
|------|--------|------|
| 步骤 1：CMake 骨架 | 半天 | 低（标准 CMake 配置） |
| 步骤 2：共享代码抽取 | 半天 | 低（有 MinGW 版回归验证） |
| 步骤 3：Reflective 迁移 + PIC 化 | **1 天** | **高**（剥离 CRT + PEB walk + 节区布局） |
| 步骤 4：Inplace stub 迁移 | 1 天 | **高**（PIC 自包含 + 节布局 + 46 处 GCC 扩展） |
| 步骤 5：节名伪装 | 半天 | 低 |
| 步骤 6：其他特征消除 | 半天 | 中（CheckSum / 假 IAT） |
| 步骤 7：回归测试 | 半天 | 中（可能发现兼容性问题） |
| **合计** | **4-5 天** | |

**最大风险点**：
1. **Reflective 剥离 CRT**：`loader.c` 当前大量使用 `printf`/`fopen`/`malloc`，全部要改 Win32 API，改动量大
2. **Inplace stub 的 PIC 自包含**：MSVC 编译 PIC 代码比 GCC 麻烦，可能需要多轮调试
3. **节内布局**：`/ORDER` 对自定义节无效，必须用魔数定位（已支持）
4. **x86 工具链**：CMake + MSVC 的 x86 配置（`-A Win32`）需要单独验证
5. **PEB walk 共享**：`stub.c` 和 `loader.c` 抽取 `peb_walk.h` 时要保证两者编译都能通过

**已化解的风险**（原方案误判）：
- ~~objcopy 不可用~~ —— binutils 与编译器无关，MSVC 生成的 PE 也能用 objcopy 处理（详见 2.2 节），原 Makefile 的 `objcopy -O binary -j .lock` 直接搬到 CMake 即可

**步骤 3 和 4 的执行顺序**：
- 推荐**先做步骤 4（Inplace）**，因为 Inplace stub 已经是 PIC 自包含，迁移经验可复用到步骤 3
- 或者**先做步骤 3（Reflective）**，因为 Reflective 可以先不剥 CRT（保留 host 模式），验证 MSVC + CMake + .asm 文件流程跑通后再剥 CRT
- 文档默认按步骤 3 → 4 顺序，但实际执行可根据情况调整

---

## 九、回滚方案

如果 MSVC 迁移遇到不可解决的技术问题，可以分阶段回滚：

- **完全回滚**：保留 MinGW 版本，只做方案 B 的节名伪装和假 IAT（消除 2 个特征）
- **部分回滚 1**：Reflective 保留 CRT（不做 PIC 化），仅用 MSVC 编译——消除 MinGW 特征但体积仍大
- **部分回滚 2**：Reflective 用 MSVC（简单），Inplace 保留 MinGW（PIC 难度高）
- **部分回滚 3**：只迁移 Inplace 到 MSVC，Reflective 保留 MinGW（如果 Reflective PIC 化太难）

CMake 设计天然支持多工具链，可以保留 MinGW 作为后备：
```cmake
option(WINLOCK_USE_MSVC "Use MSVC toolchain" ON)
option(WINLOCK_REFLECTIVE_PIC "Build reflective loader as PIC (no CRT)" ON)
if(NOT WINLOCK_USE_MSVC)
    # MinGW fallback
    set(CMAKE_C_COMPILER gcc)
    # ...
endif()
if(WINLOCK_USE_MSVC AND NOT WINLOCK_REFLECTIVE_PIC)
    # Reflective 保留 CRT 模式（部分回滚 1）
    target_compile_definitions(loader_x64 PRIVATE WINLOCK_KEEP_CRT)
endif()
```

---

## 十、预期收益对比

### 10.1 改进前（当前状态）

| 特征 | Inplace | Reflective |
|------|---------|-----------|
| DIE 识别 | ❌ 完全隐形 | ⚠ "Unknown" |
| 链接器版本 | MS 14.51 ✓ | MinGW 2.46 ❌ |
| Rich Header | ✓ | ❌ |
| COFF 长节名 | 无 | `/4 /19 /31` ❌ |
| 节名可疑 | `.lock` ❌ | `.payload` ❌ |
| W+X 节 | `.lock` ERWC ❌ | 无 |
| IAT 极少 | 保留原 IAT ✓ | 3 DLL / 79 func ❌ |
| IAT 有 msvcrt.dll | 无 | ✓ ❌（MinGW CRT 暴露） |
| stub 体积 | 6.5 KB | 40-60 KB ❌（带 CRT） |
| CheckSum 清零 | ❌ | ❌ |

### 10.2 改进后（方案 A+A+ + B）

| 特征 | Inplace | Reflective |
|------|---------|-----------|
| DIE 识别 | ❌ 仍完全隐形 | ❌ **从 "Unknown" → "Microsoft Linker 14.44"** |
| 链接器版本 | MS 14.51 ✓ | MS 14.44 ✓（新） |
| Rich Header | ✓ | ✓（新） |
| COFF 长节名 | 无 | 无（新） |
| 节名可疑 | `.text2` ✓（看起来正常） | `.rdata2` ✓（新） |
| W+X 节 | 无（新，去掉 W） | 无 |
| IAT 极少 | 保留原 IAT ✓ | 6+ DLL / 100+ func ✓（新，假 IAT） |
| IAT 有 msvcrt.dll | 无 | 无（新，PIC 化剥 CRT 后消失） |
| stub 体积 | 6.5 KB | **15-20 KB**（新，PIC 化后） |
| CheckSum 清零 | ✓（新，重算） | ✓（新，重算） |

**Inplace 暴露特征**：5 → 1（只剩 EP 位置在最后一个节，可选改进）
**Reflective 暴露特征**：10 → 3（只剩 TLS directory 存在、节数稍多、资源不全）

### 10.3 方案 A+（Reflective PIC 化）的额外收益

除了消除 MinGW PE 特征外，PIC 化还带来：

1. **stub 体积从 40-60 KB → 15-20 KB**：完成 REFLECTIVE_DESIGN.md 阶段 4 体积目标
2. **IAT 不再有 msvcrt.dll**：MinGW CRT 的 38 个 msvcrt 函数全部消失，IAT 更干净
3. **API 调用走 hash 解析**：`LoadLibraryA("user32.dll")` 改用 PEB walk + DJB15 hash，IAT 里看不到明文字符串
4. **与 Inplace stub 共享代码**：`peb_walk.h` / `xtea.h` / `sha256.h` 三处共享，减少重复
5. **为后续反调试/反 dump 铺路**：PIC 自包含后，加 PEB 反调试 / PE header erasure / 函数指针 scrub 都更简单（这些功能依赖无 CRT 环境）

---

## 十一、附录：参考资料

### 11.1 MSVC + CMake 资源
- [CMake Visual Studio 18 2026 generator](https://cmake.org/cmake/help/latest/generator/Visual+Studio+18+2026.html)
- [MSVC `/MERGE` option](https://learn.microsoft.com/en-us/cpp/build/reference/merge-combine-sections)
- [MSVC `/ORDER` option](https://learn.microsoft.com/en-us/cpp/build/reference/order-put-functions-in-order)
- [MSVC `#pragma code_seg`](https://learn.microsoft.com/en-us/cpp/preprocessor/code-seg)
- [MASM x64 syntax](https://learn.microsoft.com/en-us/cpp/assembler/masm/microsoft-macro-assembler-reference)

### 11.2 PIC stub 编译参考
- [How to compile position-independent code with MSVC](https://stackoverflow.com/questions/34519821/)
- [Creating shellcode with MSVC](https://modexp.wordpress.com/2019/06/24/shellcode-msvc/)
- [PE-bear 分析 MSVC 节布局](https://github.com/hasherezade/pe-bear)

### 11.3 本项目相关文档
- [PACKER_DETECTION.md](file:///c:/Home/Projects/applocker/packer/docs/PACKER_DETECTION.md) - 当前可检测性分析（本方案的依据）
- [REFLECTIVE_DESIGN.md](file:///c:/Home/Projects/applocker/packer/docs/REFLECTIVE_DESIGN.md) - Reflective 设计（阶段 4 PIC 化是本方案 A+ 的来源）
- [PORTING_PLAN.md](file:///c:/Home/Projects/applocker/packer/docs/PORTING_PLAN.md) - 历史移植计划
- [TLS_NOTES.md](file:///c:/Home/Projects/applocker/packer/docs/TLS_NOTES.md) - TLS 处理经验
