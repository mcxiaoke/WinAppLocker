# packer 构建系统改进方案

**日期**: 2026-07-21
**状态**: 已调查，待实施（经 4 份审查报告综合评估后修订）
**触发原因**: clean build 后 x86 inplace_password 崩溃回归，且无法确认 dist/ 里 stub 的真实版本/来源，排查困难

**修订说明**: 本版整合了 4 份独立审查报告的结论，修复了 3 个会导致编译失败或字段死代码的严重缺陷，采纳了 16 项低成本高收益的优化建议，砍掉了高复杂度低收益的改动 8（.winlock 节）。

## 一、现状问题（6 条）

### 问题 1：builder 对 stub 几乎无校验

[packer/inplace/builder.c](file:///C:/Home/Projects/applocker/packer/inplace/builder.c) 801-890 行读 stub 时：
- 只按 `STUB_DATA_MAGIC`（"WINLOCK!"）在二进制里搜 magic 定位 stub_data
- x86 额外读 `stub_inplace_x86.exe` 时只校验 DOS/NT signature
- **不校验 stub 二进制的 Machine 字段**（x86 builder 可能加载到 x64 stub 反之亦然）
- 不校验 stub 大小、hash、构建时间、toolchain
- builder 不把"用了哪个 stub"记录到输出 PE，崩溃后无法反查

### 问题 2：MinGW 静默覆盖 MSVC

[packer/build.ps1](file:///C:/Home/Projects/applocker/packer/build.ps1) 218-224 行 `Build-InplaceMinGW` 无条件用 MinGW 产物覆盖 `build/x86/` 和 `build/x64/` 里的 MSVC 产物。dist/ 最终是 MinGW 版本（x86: 7856 bytes，MSVC 是 16400 bytes，差 2 倍多）。

**风险**：
- 覆盖静默，只一行日志，不记录 hash/大小
- **MinGW 编译失败时只 `continue` 跳过不 fail**（182-185 行），dist/ 会静默 fallback 到 MSVC stub 而无警告

### 问题 3：stub 完全没有身份标识

[packer/inplace/stub.c](file:///C:/Home/Projects/applocker/packer/inplace/stub.c) 的 `stub_data_t`（[packer/common/config.h](file:///C:/Home/Projects/applocker/packer/common/config.h) 117-145 行）只有：
- `magic` = "WINLOCK!"（定位用，所有 stub 都一样）
- `version` = 4（**stub_data 结构版本**，不是 stub 二进制版本）
- `checksum`（防篡改，不是身份）

**缺失**：`arch`、`toolchain`、`build_time`、`bin_version`、`githash`、`source_crc` 等任何能唯一标识 stub 构建版本的字段。

### 问题 4：MinGW x86 和 MSVC x86 stub 行为差异巨大

大小差 2 倍（7856 vs 16400），根因：
- MSVC `/OPT:REF` 移除 TLS callback 代码（`.lock$tlscb` 节），MinGW 用 `__attribute__((used))` + `KEEP()` 保留
- MSVC link.exe 不合并不同特性 `.lock$X` 子节，`extract_lock_section.py` 提取并集带 padding
- MinGW `stub.ld` 精确合并所有 `.lock$X` 为单个 `.lock`

**后果**：用 MSVC stub 和 MinGW stub 加壳同一个 x86 PE 行为可能不同。当前 dist/ 默认用 MinGW，但如果 MinGW 构建失败，会静默 fallback 到 MSVC stub 而无警告。

### 问题 5：CMake 文件复制 hack（审查新发现，P0 级）

[packer/build.ps1](file:///C:/Home/Projects/applocker/packer/build.ps1) 106-110 行临时把 `CMakeLists-x64.txt` 复制为 `CMakeLists.txt`，构建后清理。**这是最大脆弱点**：
- 脚本中途崩溃时 `try/finally` 虽能恢复，但残留文件会导致后续手动 `cmake .` 读到旧配置
- x64/x86 两次复制+清理增加崩溃窗口
- `git status` 每次都有 `CMakeLists.txt` 的未跟踪变动

### 问题 6：malloc 无 NULL 检查 + 文件读取无大小上限（审查新发现，P0 级）

[packer/inplace/builder.c](file:///C:/Home/Projects/applocker/packer/inplace/builder.c) 和 [packer/reflective/builder_reflective.c](file:///C:/Home/Projects/applocker/packer/reflective/builder_reflective.c) 中：
- `read_file` 用 `fseek/ftell` 读整个文件，无大小上限，传入 2GB 垃圾文件直接 OOM
- 多处 `malloc` 后直接使用，未检查 NULL

---

## 二、magic 搜索方案分析

### 当前做法

builder 和 patch 脚本都用 `STUB_DATA_MAGIC`（"WINLOCK!"，0x214B434F4C4E4957）在 stub.bin 里线性搜索，找到的第一个 magic 位置就认为是 `stub_data_t` 的起始。

### 三个潜在问题

**1. magic 重复风险**：stub 代码里引用 magic 常量时，x64 可能产生连续 8 字节（`mov rax, imm64` 的 imm64）。当前 stub 代码不直接比较 magic（只有 builder 比较），所以暂无重复。但未来若 stub 自校验 magic 会引入重复。

**2. 低效**：stub.bin 很小（几 KB），线性扫描 8 字节对齐的 magic 只需几百次比较，不是性能问题。

**3. 错误风险（最严重）**：如果 stub_data 结构布局变了（version bump 加字段），magic 还能搜到，但后面字段偏移全是错的。magic 本身不验证 version，builder 可能读到垃圾数据。

### 改进方案：magic + version + stub_size + arch 范围 四重校验

保持 magic 搜索（不改为固定偏移，因为 MSVC link.exe 不支持 linker script 强制固定偏移），但找到 magic 后立即做四重校验：

```c
/* builder.c 里搜 magic 的循环改为：找到后校验 version + stub_size + arch 范围，不匹配继续搜 */
for (size_t i = 0; i + sizeof(stub_data_t) <= stub_size; i += 8) {
    if (*(uint64_t*)(stub_bin + i) != STUB_DATA_MAGIC) continue;
    const stub_data_t* cand = (const stub_data_t*)(stub_bin + i);
    /* 1. version 必须匹配（防结构版本不一致导致字段偏移错位）*/
    if (cand->version != STUB_DATA_VERSION) continue;
    /* 2. stub_size 必须匹配文件大小（防 stub.bin 截断或 magic 在代码段重复）*/
    /*    patch 前为 0，patch 后为实际大小，0 时跳过此校验 */
    if (cand->identity.stub_size != 0
        && cand->identity.stub_size != (uint32_t)stub_size) continue;
    /* 3. stub_arch 必须是合法值（防 magic 重复 + version 巧合的误报）*/
    if (cand->identity.stub_arch != STUB_ARCH_X86
        && cand->identity.stub_arch != STUB_ARCH_X64) continue;
    /* 四重校验通过，这就是正确的 stub_data */
    p = stub_bin + i;
    break;
}
```

**作用**：
- magic 重复时（代码段引用 magic 常量），version/stub_size/arch 不匹配，自动跳过误报
- stub_data 结构版本不匹配时，version 不匹配，跳过
- stub.bin 被截断或损坏时，stub_size 不匹配，跳过
- magic + version 巧合匹配时，arch 范围校验兜底（误报概率降到接近 0）

**注意**：patch 前的 stub（stub_size==0）会跳过 stub_size 校验，退化为三重校验（magic+version+arch）。dev 路径也运行 patch 后（见改动 8），所有产物 stub_size 都非 0，四重校验完整生效。

### 结论

magic 搜索可接受，但必须加 version + stub_size + arch 范围四重校验。不需要改为固定偏移或导出符号方案。

---

## 三、具体改动清单

### 改动 1：`stub_data_t` 末尾新增身份块（checksum 之前）

**改哪个文件**：[packer/common/config.h](file:///C:/Home/Projects/applocker/packer/common/config.h) 117-145 行

**为什么放末尾**：审查建议（A2）—— 避免平移所有后续 64 位字段（oep_rva/text_rva/image_base...）偏移，回归面最小。checksum 循环按 qword 遍历，位置不影响正确性。

**增加什么字段**：抽出一个公共结构 `stub_identity_t`，追加在 `stub_data_t` 的 `checksum` 字段之前（不是中间），所有字段统一 `stub_` 前缀：

```c
/* packer/common/config.h 顶部 STUB_DATA_MAGIC 附近加常量 */
#define STUB_ARCH_X86        1u
#define STUB_ARCH_X64        2u
#define STUB_TOOLCHAIN_MSVC  1u
#define STUB_TOOLCHAIN_MINGW 2u
/* stub 二进制版本，手动 bump：每次 stub 行为有变化时 +1 */
#ifndef STUB_BIN_VER
#define STUB_BIN_VER 0x0100u
#endif
/* stub_data_t 的 sizeof，手动维护（供 Python 脚本读取，避免硬编码漂移）*/
/* 当前 version=5，sizeof=320；每次结构变化时同步更新此宏和 STUB_DATA_VERSION */
#define STUB_DATA_SIZEOF 320

/* stub 身份块（32 字节，8 字节对齐）*/
/* 所有字段统一 stub_ 前缀；patch_stub_identity.py 在 POST_BUILD 阶段写入 */
#pragma pack(push, 8)
typedef struct {
    uint32_t stub_arch;        /* 1=x86, 2=x64（编译期注入）*/
    uint32_t stub_toolchain;   /* 1=MSVC, 2=MinGW（编译期注入）*/
    uint32_t stub_bin_ver;     /* stub 二进制版本（POST_BUILD patch）*/
    uint32_t stub_build_time;  /* Unix 时间戳（POST_BUILD patch）*/
    uint32_t stub_source_crc;  /* 源码 CRC32（POST_BUILD patch）*/
    uint32_t stub_size;        /* stub.bin 文件大小（POST_BUILD patch）*/
    uint8_t  stub_githash[8];  /* git commit short hash ASCII（POST_BUILD patch，无 git 全 0）*/
} stub_identity_t;
#pragma pack(pop)

/* stub_data_t 保持原有 pack(8) 包裹（与 stub_identity_t 的 pack 独立）*/
/* 注意：stub_identity_t 内部已 pop，但嵌入 stub_data_t 时按外层 pack(8) 布局 */
#pragma pack(push, 8)
typedef struct {
    uint64_t magic;
    uint16_t version;          /* bump 4→5（加身份字段后）*/
    uint16_t flags;
    uint16_t max_retries;
    uint16_t reserved16;
    /* ---- 原有字段保持不变 ---- */
    uint64_t oep_rva;
    uint64_t text_rva;
    /* ... 其他原有字段 ... */
    /* ---- 新增身份块（32 字节，放末尾、checksum 之前）---- */
    stub_identity_t identity;
    uint64_t checksum;         /* XOR 所有 8 字节块（含 identity，见下方说明）*/
} stub_data_t;
#pragma pack(pop)
```

**checksum 说明（修正审查 M5）**：
- [builder.c:998-1004](file:///C:/Home/Projects/applocker/packer/inplace/builder.c) 的 checksum 算法是 `for qi in 0..sizeof(stub_data_t)/8-1: cs ^= p[qi]`，即整个结构体（除末尾 checksum）按 8 字节块 XOR
- **identity 字段会自动并入 8 字节 XOR 链**，无需改动 builder 的 checksum 逻辑
- **关键约束**：`patch_stub_identity.py` 必须在 builder 打包之前执行，否则 builder 算的 checksum 会与 stub 运行时不一致（虽然 stub 当前不校验 checksum，但为未来补运行时校验留余地）

**sizeof 手动维护**（审查 A5 加强）：当前 `stub_data_t` sizeof = 288（version=4），加 identity(32) 后 = 320（version=5）。在 config.h 加 `#define STUB_DATA_SIZEOF 320` 宏，供 Python 脚本读取，避免脚本硬编码漂移。每次 stub_data_t 结构变化时，同步更新 `STUB_DATA_VERSION` 和 `STUB_DATA_SIZEOF` 两个宏。Python 脚本（patch_stub_identity.py / inspect_stub.py / check_stub_freshness.py）都从 config.h 解析这两个宏，不再维护独立的 size 字典。

**防漂移校验**：在 config.h 末尾加 `_Static_assert`，编译期捕获 STUB_DATA_SIZEOF 与实际 sizeof 不一致：
```c
_Static_assert(sizeof(stub_data_t) == STUB_DATA_SIZEOF,
               "STUB_DATA_SIZEOF 与实际 sizeof(stub_data_t) 不一致，请同步更新");
```

**stub.c 初始化**：identity 字段编译期只填 `stub_arch` 和 `stub_toolchain`（由 CMake/MinGW `-D` 注入），其余字段初始化为 0，由 POST_BUILD 脚本 patch：

```c
/* stub.c 顶部：config.h 已定义 STUB_ARCH/STUB_TOOLCHAIN（由 CMake -D 注入）*/
/* 若 CMake 未注入（如手动编译），给默认值避免编译错误 */
#ifndef STUB_ARCH
#define STUB_ARCH 0
#endif
#ifndef STUB_TOOLCHAIN
#define STUB_TOOLCHAIN 0
#endif

volatile stub_data_t stub_data = {
    .magic = STUB_DATA_MAGIC,
    .version = STUB_DATA_VERSION,   /* = 5 */
    .flags = 0,
    .max_retries = STUB_DEFAULT_MAX_RETRIES,
    .reserved16 = 0,
    /* ... 原有字段 ... */
    .identity = {
        .stub_arch = STUB_ARCH,
        .stub_toolchain = STUB_TOOLCHAIN,
        /* 其余字段编译期为 0，POST_BUILD patch */
    },
    .checksum = 0,   /* builder 打包时计算 */
};
```

**作用**：每个 stub 二进制携带唯一身份信息，builder 加壳时能立刻判断对错，崩溃后能反查。

**注意**：
- `STUB_DATA_VERSION` 从 4 改到 5，builder 和 stub 必须同步重编
- `STUB_BIN_VER` 用 `#ifndef` 守卫（审查 M2），避免 CMake 注入时宏重定义冲突
- reflective_payload_t **不再内嵌 stub_identity_t**（审查 M3：语义错位，且 builder_reflective 不读它）

### 改动 2：CMake 注入 STUB_ARCH/STUB_TOOLCHAIN（MSVC 路径，仅这两个字段）

**改哪个文件**：[packer/CMakeLists-x64.txt](file:///C:/Home/Projects/applocker/packer/CMakeLists-x64.txt)、[packer/CMakeLists-x86.txt](file:///C:/Home/Projects/applocker/packer/CMakeLists-x86.txt)、[packer/inplace/CMakeLists.inc](file:///C:/Home/Projects/applocker/packer/inplace/CMakeLists.inc)、[packer/reflective/CMakeLists.inc](file:///C:/Home/Projects/applocker/packer/reflective/CMakeLists.inc)

**为什么只注入两个字段**（审查 B 简化方案）：
- `stub_arch` 和 `stub_toolchain` 是真正的编译期常量，适合 `-D` 注入
- `stub_bin_ver`、`stub_build_time`、`stub_source_crc`、`stub_size`、`stub_githash` 都是构建期计算的，天然适合 POST_BUILD 脚本处理
- 这样消除 MinGW/MSVC 两套注入路径的分歧，githash 字符串展开问题（审查 M1）自动消失

**CMakeLists-x64.txt / CMakeLists-x86.txt 加**：

```cmake
# ---- 架构常量（编译期注入）----
if(ARCH STREQUAL "x64")
    set(STUB_ARCH_VAL 2)
else()
    set(STUB_ARCH_VAL 1)
endif()
set(STUB_TOOLCHAIN_VAL 1)   # MSVC=1
```

**inplace/CMakeLists.inc 加**（只加编译期注入，POST_BUILD 命令见改动 8）：

```cmake
target_compile_definitions(stub_inplace_${ARCH} PRIVATE
    WINLOCK_STUB
    WINLOCK_PIC
    STUB_ARCH=${STUB_ARCH_VAL}
    STUB_TOOLCHAIN=${STUB_TOOLCHAIN_VAL}
)
```

POST_BUILD 的 `extract_lock_section.py` + `patch_stub_identity.py` 命令统一在改动 8 描述（含执行顺序约束），此处不重复。

**reflective/CMakeLists.inc 不需要改动**：reflective stub 是普通 PE 文件，入口是 `loader_main`，没有 `stub_data_t` 结构。`STUB_ARCH`/`STUB_TOOLCHAIN` 宏在 reflective stub 里无处引用，注入它们没有意义。reflective 模式的身份校验只靠 builder_reflective 检查 PE Machine 字段（见改动 6）。如果以后需要 reflective stub 的完整身份信息，应单独设计 `reflective_stub_meta_t` 写入 stub 自身 PE 的保留区域，而不是复用 `stub_identity_t`。

### 改动 3：build.ps1 MinGW 注入 + Python 检测 + 注释修正

**改哪个文件**：[packer/build.ps1](file:///C:/Home/Projects/applocker/packer/build.ps1)

**改动点 1：开头检测 Python 路径**（审查 A12）

```powershell
# build.ps1 try 块开头加
$pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonExe) { $pythonExe = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
if (-not $pythonExe) { throw "Python 不在 PATH，无法计算 stub_source_crc 和运行 patch 脚本" }
Write-Host "    Python: $pythonExe" -ForegroundColor DarkGray
```

后续所有 `python -c` 改为 `& $pythonExe -c`，`python script.py` 改为 `& $pythonExe script.py`。

**改动点 2：MinGW 编译参数只注入 STUB_ARCH/STUB_TOOLCHAIN**

```powershell
function Build-InplaceMinGW {
    # ... 原有代码 ...

    foreach ($arch in $archs) {
        # ... 原有代码 ...

        $stubArch = if ($archName -eq "x64") { 2 } else { 1 }
        $stubToolchain = 2   # MinGW

        # 只注入编译期常量（与 CMake 路径一致）
        $identityCflags = @(
            "-DSTUB_ARCH=$stubArch",
            "-DSTUB_TOOLCHAIN=$stubToolchain"
        )
        $cflags = $commonCflags + $arch.ExtraCflags + $identityCflags

        # ... 原有编译 + 链接 + objcopy ...

        # POST_BUILD patch 其余身份字段（与 MSVC 路径一致）
        & $pythonExe ${root}\cmake\patch_stub_identity.py $binFile $archName MinGW $root
        if ($LASTEXITCODE -ne 0) { throw "MinGW $archName patch_stub_identity 失败" }
    }
}
```

**改动点 3：MinGW 失败必须 fail**（审查问题 2）

```powershell
if (-not (Test-Path $gcc)) {
    throw "MinGW $archName gcc 不存在: $gcc（必须安装 MinGW 才能构建 inplace stub）"
}
```

不再 `continue` 静默跳过。

**改动点 4：覆盖时打印 hash**（审查问题 2）

```powershell
$binHash = (Get-FileHash $binFile -Algorithm SHA256).Hash
Copy-Item $binFile (Join-Path $msvcDir "stub_inplace_$($archName).bin") -Force
Write-Host "    覆盖: stub_inplace_$($archName).bin $binSize bytes SHA256=$($binHash.Substring(0,16))..." -ForegroundColor Cyan
```

**改动点 5：修正头部注释矛盾**（审查 A9）

build.ps1 第 21 行注释从：
```
stub_inplace_x86.bin          - inplace x86 stub（MSVC 构建）
```
改为：
```
stub_inplace_x86.bin          - inplace x86 stub（MinGW 构建，若可用；否则 fallback MSVC）
```

### 改动 4：新增 `patch_stub_identity.py`（POST_BUILD 注入其余字段）

**新建文件**：`packer/cmake/patch_stub_identity.py`

**职责**：编译后的 stub.bin 里 identity 字段只有 `stub_arch` 和 `stub_toolchain`（编译期注入），其余 5 个字段（stub_bin_ver/stub_build_time/stub_source_crc/stub_size/stub_githash）都是 0。这个脚本计算并 patch 这 5 个字段。

**关键设计**（整合审查 A5/A6/A8/A10/A11）：
- **幂等**：patch 前先清零 stub_size，再写入，支持重复运行（审查 A11）
- **偏移从 config.h 解析**：避免硬编码漂移（审查 A5/A11）
- **8 字节对齐搜索 magic**：与 builder 一致（审查 A8）
- **行尾归一化**：CRC 计算前统一 LF（审查 A10）
- **CRC 覆盖所有 #include 的头文件**：stub.c + stub_asm_${ARCH}.asm + config.h + sha256.h + peb_walk.h + xtea.h + winlock_compat.h（审查 M4）

**怎么实现**：

```python
#!/usr/bin/env python3
"""patch_stub_identity.py - POST_BUILD 注入 stub 身份字段

用法：python patch_stub_identity.py <stub.bin> <arch> <toolchain> <winlock_root>
  arch:        x86 或 x64
  toolchain:   MSVC 或 MinGW
  winlock_root: packer/ 目录绝对路径（用于找源码和 config.h）

字段注入策略（审查 B 简化方案）：
  - stub_arch       编译期已注入（CMake/MinGW -D），脚本只校验
  - stub_toolchain  编译期已注入，脚本只校验
  - stub_bin_ver    脚本写入（从 config.h 读 STUB_BIN_VER）
  - stub_build_time 脚本写入（当前 Unix 时间戳）
  - stub_source_crc 脚本写入（CRC32 of 所有 #include 的源文件）
  - stub_size       脚本写入（stub.bin 文件大小）
  - stub_githash    脚本写入（git rev-parse，无 git 全 0）
"""
import sys, os, struct, subprocess, binascii, re

STUB_DATA_MAGIC = 0x214B434F4C4E4957  # "WINLOCK!"

# stub_identity_t 字段顺序（与 config.h 一致，6×uint32 + 8 bytes = 32 字节）
IDENTITY_FMT = "<IIIIII8s"
assert struct.calcsize(IDENTITY_FMT) == 32, "stub_identity_t 必须是 32 字节"

# stub 源文件列表（CRC 覆盖范围，审查 M4）
def stub_source_files(winlock_root, arch):
    return [
        os.path.join(winlock_root, "inplace", "stub.c"),
        os.path.join(winlock_root, "inplace", f"stub_asm_{arch}.asm"),
        os.path.join(winlock_root, "common", "config.h"),
        os.path.join(winlock_root, "common", "sha256.h"),
        os.path.join(winlock_root, "common", "peb_walk.h"),
        os.path.join(winlock_root, "common", "xtea.h"),
        os.path.join(winlock_root, "common", "winlock_compat.h"),
    ]

# 从 config.h 解析 STUB_DATA_VERSION、STUB_BIN_VER、STUB_DATA_SIZEOF（审查 A5）
def parse_config_h(winlock_root):
    config_path = os.path.join(winlock_root, "common", "config.h")
    with open(config_path, "r", encoding="utf-8") as f:
        content = f.read()
    ver_match = re.search(r"#define\s+STUB_DATA_VERSION\s+(\d+)", content)
    binver_match = re.search(r"#define\s+STUB_BIN_VER\s+(0x[0-9a-fA-F]+|\d+)", content)
    sizeof_match = re.search(r"#define\s+STUB_DATA_SIZEOF\s+(\d+)", content)
    if not ver_match or not binver_match or not sizeof_match:
        raise RuntimeError("无法从 config.h 解析 STUB_DATA_VERSION/STUB_BIN_VER/STUB_DATA_SIZEOF")
    return (int(ver_match.group(1)),
            int(binver_match.group(1), 0),
            int(sizeof_match.group(1)))

# 计算 stub_source_crc（行尾归一化为 LF，审查 A10）
def compute_source_crc(winlock_root, arch):
    crc = 0
    for path in stub_source_files(winlock_root, arch):
        if not os.path.exists(path):
            raise RuntimeError(f"源文件不存在: {path}")
        with open(path, "rb") as f:
            data = f.read()
        # 行尾归一化：CRLF -> LF
        data = data.replace(b"\r\n", b"\n")
        crc = binascii.crc32(data, crc)
    return crc & 0xffffffff

# 计算 stub_identity_t 在 stub_data_t 中的偏移
# identity 放在 checksum 之前，checksum 是最后 8 字节
# 所以 identity_offset = stub_data_size - 8(checksum) - 32(identity) = stub_data_size - 40
# stub_data_size 从 config.h 的 STUB_DATA_SIZEOF 宏读取（见 parse_config_h）
IDENTITY_SIZE = 32   # sizeof(stub_identity_t)
CHECKSUM_SIZE = 8    # sizeof(uint64_t checksum)

def find_stub_data(data, stub_data_version, stub_data_size):
    """8 字节对齐搜索 magic + version + arch 范围校验（审查 A8）"""
    magic_bytes = struct.pack("<Q", STUB_DATA_MAGIC)
    identity_off_in_struct = stub_data_size - CHECKSUM_SIZE - IDENTITY_SIZE

    i = 0
    while i + stub_data_size <= len(data):
        if data[i:i+8] == magic_bytes:
            # 校验 version
            candidate_ver = struct.unpack_from("<H", data, i + 8)[0]
            if candidate_ver != stub_data_version:
                i += 8
                continue
            # 校验 stub_arch 范围（1 或 2）
            identity_off = i + identity_off_in_struct
            arch_val = struct.unpack_from("<I", data, identity_off)[0]
            if arch_val not in (1, 2):
                i += 8
                continue
            return i, stub_data_size
        i += 8
    raise RuntimeError(f"magic+version+arch 校验未通过")

def main():
    if len(sys.argv) != 5:
        print("用法: python patch_stub_identity.py <stub.bin> <arch> <toolchain> <winlock_root>",
              file=sys.stderr)
        sys.exit(1)
    stub_bin_path = sys.argv[1]
    arch = sys.argv[2]       # x86 / x64
    toolchain = sys.argv[3]  # MSVC / MinGW
    winlock_root = sys.argv[4]

    arch_val = {"x86": 1, "x64": 2}[arch]
    toolchain_val = {"MSVC": 1, "MinGW": 2}[toolchain]

    stub_data_version, stub_bin_ver, stub_data_size = parse_config_h(winlock_root)
    source_crc = compute_source_crc(winlock_root, arch)
    # 直接用 time 模块，避免嵌套 python 调用
    import time
    build_time = int(time.time())

    # githash：无 git 则全 0
    try:
        githash_str = subprocess.check_output(
            ["git", "rev-parse", "--short=8", "HEAD"],
            cwd=winlock_root, stderr=subprocess.DEVNULL
        ).decode().strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        githash_str = ""
    githash_bytes = githash_str.encode("ascii")[:8].ljust(8, b"\0")

    # 读 stub.bin
    with open(stub_bin_path, "rb") as f:
        data = bytearray(f.read())
    stub_size = len(data)

    # 定位 stub_data_t
    offset, _ = find_stub_data(data, stub_data_version, stub_data_size)
    identity_off = offset + stub_data_size - CHECKSUM_SIZE - IDENTITY_SIZE

    # 幂等：patch 前先清零 stub_size 字段（审查 A11）
    # stub_size 在 identity 结构里的偏移 = 5×4 = 20（arch/toolchain/bin_ver/build_time/source_crc 各 4 字节之后）
    # 清零是为了重新运行时 find_stub_data 跳过 stub_size 校验（否则 stub_size 还是旧值会不匹配新文件大小）
    STUB_SIZE_OFF_IN_IDENTITY = 20  # 5 × sizeof(uint32_t)
    struct.pack_into("<I", data, identity_off + STUB_SIZE_OFF_IN_IDENTITY, 0)

    # 校验编译期注入的 stub_arch/stub_toolchain 是否匹配
    existing = struct.unpack_from(IDENTITY_FMT, data, identity_off)
    if existing[0] != arch_val:
        raise RuntimeError(f"stub_arch 不匹配: 文件里={existing[0]} 期望={arch_val}")
    if existing[1] != toolchain_val:
        raise RuntimeError(f"stub_toolchain 不匹配: 文件里={existing[1]} 期望={toolchain_val}")

    # 写入 5 个字段（stub_arch/stub_toolchain 保持不变）
    new_identity = (
        arch_val,           # stub_arch（不变）
        toolchain_val,      # stub_toolchain（不变）
        stub_bin_ver,       # stub_bin_ver
        build_time,         # stub_build_time
        source_crc,         # stub_source_crc
        stub_size,          # stub_size
        githash_bytes,      # stub_githash
    )
    struct.pack_into(IDENTITY_FMT, data, identity_off, *new_identity)

    with open(stub_bin_path, "wb") as f:
        f.write(data)

    githash_display = githash_str if githash_str else "(none)"
    print(f"[OK] patched {stub_bin_path}: arch={arch} toolchain={toolchain} "
          f"bin_ver=0x{stub_bin_ver:04x} build_time={build_time} "
          f"source_crc=0x{source_crc:08x} stub_size={stub_size} githash={githash_display}")

if __name__ == "__main__":
    main()
```

### 改动 5：builder 加壳时严格校验 stub

**改哪个文件**：[packer/inplace/builder.c](file:///C:/Home/Projects/applocker/packer/inplace/builder.c) 801-890 行

**改什么**：**替换**原 801-890 行的"只搜 magic"逻辑为四重校验（magic+version+stub_size+arch）。不是新增校验，是替换原 magic 搜索循环。替换后原本的 `find_stub_data`（或类似函数）变成下方 `verify_stub_identity`，builder 调用它一次完成"定位 + 校验"。

**什么时候校验**：builder 加壳时读完 stub.bin，调用 `verify_stub_identity` 一次性完成定位 + 校验。

**怎么校验**（含 magic + version + stub_size + arch 范围四重校验，见第二节）：

```c
/* builder.c 里 read_stub_binary 之后加 */
static int verify_stub_identity(const uint8_t* stub_bin, size_t stub_bin_size,
                                 int pe_is_x64, const char* stub_path) {
    /* 1. 四重校验定位 stub_data_t（见第二节 magic 搜索方案）*/
    const uint64_t magic = STUB_DATA_MAGIC;
    const uint8_t* p = NULL;
    for (size_t i = 0; i + sizeof(stub_data_t) <= stub_bin_size; i += 8) {
        if (*(const uint64_t*)(stub_bin + i) != magic) continue;
        const stub_data_t* cand = (const stub_data_t*)(stub_bin + i);
        if (cand->version != STUB_DATA_VERSION) continue;
        if (cand->identity.stub_size != 0
            && cand->identity.stub_size != (uint32_t)stub_bin_size) continue;
        if (cand->identity.stub_arch != STUB_ARCH_X86
            && cand->identity.stub_arch != STUB_ARCH_X64) continue;
        p = stub_bin + i;
        break;
    }
    if (!p) {
        fprintf(stderr, "[stub] ERROR: stub_data not found (magic+version+size+arch mismatch) in %s\n", stub_path);
        return -1;
    }

    /* 2. arch 必须匹配输入 PE */
    const stub_identity_t* id = &((const stub_data_t*)p)->identity;
    uint32_t want_arch = pe_is_x64 ? STUB_ARCH_X64 : STUB_ARCH_X86;
    if (id->stub_arch != want_arch) {
        fprintf(stderr, "[stub] ERROR: arch mismatch! stub=%s pe=%s\n",
                id->stub_arch == STUB_ARCH_X64 ? "x64" : "x86",
                pe_is_x64 ? "x64" : "x86");
        return -1;
    }

    /* 3. stub_size 必须匹配文件大小（patch 失败检测）*/
    if (id->stub_size != 0 && id->stub_size != (uint32_t)stub_bin_size) {
        fprintf(stderr, "[stub] WARN: stub_size mismatch (field=%u, file=%zu)\n",
                id->stub_size, stub_bin_size);
        /* 不 fail，只警告 */
    }

    /* 4. 打印身份信息到 stderr（调试用）*/
    char githash[9] = {0};
    memcpy(githash, id->stub_githash, 8);
    fprintf(stderr, "[stub] %s arch=%s toolchain=%s bin_ver=0x%04x "
            "build_time=%u source_crc=0x%08x githash=%s size=%zu\n",
            stub_path,
            id->stub_arch == STUB_ARCH_X64 ? "x64" : "x86",
            id->stub_toolchain == STUB_TOOLCHAIN_MSVC ? "MSVC" : "MinGW",
            id->stub_bin_ver, id->stub_build_time, id->stub_source_crc,
            githash, stub_bin_size);
    return 0;
}
```

**调用时机**：`builder.c` 读完 stub.bin 后立刻调用，arch 不匹配直接 `goto fail`。

**作用**：彻底防止"x86 PE 用了 x64 stub"这类错误，加壳时 stderr 打印身份信息方便排查。

### 改动 6：builder_reflective arch 校验（薄封装既有逻辑）

**改哪个文件**：[packer/reflective/builder_reflective.c](file:///C:/Home/Projects/applocker/packer/reflective/builder_reflective.c)

**审查 A 第三章指出**：builder_reflective.c:517 已有 `s_machine != info.machine` 的硬性校验，改动 6 与原逻辑重复。**改为薄封装**，不独立成函数重复读取 PE Machine：

```c
/* builder_reflective.c 已有 Machine 校验代码附近加注释和日志 */
/* 既有代码：if (s_machine != info.machine) { 报错退出 } */
/* 改为：*/
if (s_machine != info.machine) {
    fprintf(stderr, "[stub] ERROR: reflective stub arch mismatch! "
            "stub_machine=0x%04x pe_machine=0x%04x\n", s_machine, info.machine);
    goto fail;
}
fprintf(stderr, "[stub] reflective stub arch OK (machine=0x%04x)\n", s_machine);
```

**不新增独立函数**，避免重复读取 PE Machine 字段。

### 改动 7：合并 inspect_stub_bin.py 和 inspect_stub.py 为 inspect_stub.py

**新建文件**：`packer/cmake/inspect_stub.py`

**职责**（审查 A1 + A4 + A13）：
- 读 stub.bin → 按 magic 搜索 stub_data_t，打印 identity
- 读加壳产物 exe → 定位 .lock 节（inplace）或 payload（reflective），解析 stub_data_t，打印 identity
- 支持 `--format=json` 输出结构化数据（审查 A4，manifest 生成用）

**为什么合并**：两个工具都是"读 stub_data_t 身份字段并打印"，差别只在输入类型。合并后少维护一个工具。

**怎么实现**：

```python
#!/usr/bin/env python3
"""inspect_stub.py - 读 stub.bin 或加壳产物 exe 的 stub 身份信息

用法：
  python inspect_stub.py <stub.bin>                    # 读 stub.bin
  python inspect_stub.py <packed.exe>                  # 读加壳产物（自动找 .lock 节）
  python inspect_stub.py <input> --format=json         # 输出 JSON（manifest 生成用）
  python inspect_stub.py --summary <dir> [<winlock_root>]  # 批量打印目录下所有 stub
"""
import sys, os, struct, argparse, json

# 复用 patch_stub_identity.py 的常量和函数（两个脚本同目录）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from patch_stub_identity import (
    STUB_DATA_MAGIC, IDENTITY_FMT, IDENTITY_SIZE, CHECKSUM_SIZE,
    parse_config_h, find_stub_data
)

def read_identity(data, offset, stub_data_size):
    identity_off = offset + stub_data_size - CHECKSUM_SIZE - IDENTITY_SIZE
    fields = struct.unpack_from(IDENTITY_FMT, data, identity_off)
    return {
        "stub_arch": fields[0],
        "stub_toolchain": fields[1],
        "stub_bin_ver": fields[2],
        "stub_build_time": fields[3],
        "stub_source_crc": fields[4],
        "stub_size": fields[5],
        "stub_githash": fields[6].rstrip(b"\0").decode("ascii", "replace"),
    }

def format_identity(id_dict):
    arch = "x64" if id_dict["stub_arch"] == 2 else "x86"
    toolchain = "MSVC" if id_dict["stub_toolchain"] == 1 else "MinGW"
    return (f"arch={arch} toolchain={toolchain} bin_ver=0x{id_dict['stub_bin_ver']:04x} "
            f"build_time={id_dict['stub_build_time']} "
            f"source_crc=0x{id_dict['stub_source_crc']:08x} "
            f"stub_size={id_dict['stub_size']} githash={id_dict['stub_githash']}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--summary", metavar="DIR")
    parser.add_argument("--winlock-root", help="packer/ 目录路径（用于找 config.h），不传则从脚本位置自动推断")
    args = parser.parse_args()

    # winlock_root 未传时从脚本位置自动推断（cmake/ 上溯到 packer/）
    winlock_root = args.winlock_root
    if not winlock_root:
        winlock_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # parse_config_h 返回 (version, bin_ver, sizeof)，这里只用 version 和 sizeof
    stub_data_version, _, stub_data_size = parse_config_h(winlock_root)

    if args.summary:
        # 批量模式
        results = []
        for f in sorted(os.listdir(args.summary)):
            if f.startswith("stub_") and f.endswith(".bin"):
                path = os.path.join(args.summary, f)
                with open(path, "rb") as fh:
                    data = fh.read()
                off, sz = find_stub_data(data, stub_data_version, stub_data_size)
                if off >= 0:
                    id_dict = read_identity(data, off, sz)
                    id_dict["file"] = f
                    results.append(id_dict)
        if args.format == "json":
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                print(f"{r['file']}: {format_identity(r)}")
        return

    if not args.input:
        parser.error("需要 input 或 --summary")

    with open(args.input, "rb") as f:
        data = f.read()

    # 判断输入类型：stub.bin 还是 packed.exe
    if data[:2] == b"MZ":
        # PE 文件：解析节表找 .lock 节
        # TODO: 实施时补 PE 解析逻辑（读 IMAGE_SECTION_HEADER，找 .lock 节）
        print("[ERR] packed.exe 模式暂未实现，请用 stub.bin", file=sys.stderr)
        sys.exit(1)
    else:
        # stub.bin
        off, sz = find_stub_data(data, stub_data_version, stub_data_size)
        if off < 0:
            print("[ERR] stub_data not found", file=sys.stderr)
            sys.exit(1)
        id_dict = read_identity(data, off, sz)

    if args.format == "json":
        print(json.dumps(id_dict, indent=2))
    else:
        print(f"{args.input}: {format_identity(id_dict)}")

if __name__ == "__main__":
    main()
```

### 改动 8：build.ps1 严格化 + manifest 生成

**改哪个文件**：[packer/build.ps1](file:///C:/Home/Projects/applocker/packer/build.ps1)

**改动点 1：MinGW 失败 fail + 打印 hash**（见改动 3）

**改动点 2：dist 收集后生成 stub_manifest.json**（审查 A4）

```powershell
# build.ps1 末尾，dist 收集后
$manifest = @{
    build_time = (Get-Date -Format "o")
    githash = (git rev-parse --short=8 HEAD 2>$null)
    stubs = @()
}
foreach ($f in Get-ChildItem $distDir -Filter "stub_*.bin") {
    # 用 inspect_stub.py --format=json 读身份字段（--winlock-root 指向 packer/ 目录）
    $info = & $pythonExe ${root}\cmake\inspect_stub.py $f.FullName --format=json --winlock-root $root | ConvertFrom-Json
    # 注意：PowerShell 单元素 += 会退化成标量，强制包成数组
    $manifest.stubs = @($manifest.stubs + $info)
}
$manifest | ConvertTo-Json -Depth 5 | Out-File (Join-Path $distDir "stub_manifest.json")
```

**改动点 3：build.ps1 末尾打印汇总表**

```powershell
Write-Host ""
Write-Host "==== stub 身份信息汇总 ====" -ForegroundColor Green
& $pythonExe ${root}\cmake\inspect_stub.py --summary $distDir --winlock-root $root
```

**改动点 4：dev 路径也运行 patch**（审查 A6）

CMake `add_custom_command(POST_BUILD)` 绑定到 target，dev 和 dist 路径都会执行。但**必须注意执行顺序**：`patch_stub_identity.py` 需要读 stub.bin，而 stub.bin 由 `extract_lock_section.py` 从 stub.exe 提取生成。所以 CMakeLists.inc 里 `add_custom_command` 的顺序必须是：

```cmake
# 1. 先 extract .lock 节 -> stub.bin
add_custom_command(TARGET stub_inplace_${ARCH} POST_BUILD
    COMMAND ${Python3_EXECUTABLE} ${WINLOCK_ROOT}/cmake/extract_lock_section.py
            $<TARGET_FILE:stub_inplace_${ARCH}>
            ${CMAKE_CURRENT_BINARY_DIR}/stub_inplace_${ARCH}.bin
    COMMENT "Extracting .lock section"
    VERBATIM
)
# 2. 再 patch stub.bin 的身份字段（必须依赖上一步生成 stub.bin）
add_custom_command(TARGET stub_inplace_${ARCH} POST_BUILD
    COMMAND ${Python3_EXECUTABLE}
            ${WINLOCK_ROOT}/cmake/patch_stub_identity.py
            ${CMAKE_CURRENT_BINARY_DIR}/stub_inplace_${ARCH}.bin
            ${ARCH} MSVC ${WINLOCK_ROOT}
    COMMENT "Patching stub identity"
    VERBATIM
)
```

CMake POST_BUILD 命令按声明顺序执行，所以 patch 一定在 extract 之后。dev 路径（`cmake --build`）和 dist 路径都会执行这两个 POST_BUILD，所以 dev 产物也带完整 identity。

### 改动 9：测试脚本 source_crc 警告 + 端到端 identity 校验

**改哪个文件**：[packer/tests/auto_e2e_test.ps1](file:///C:/Home/Projects/applocker/packer/tests/auto_e2e_test.ps1)

**改动点 1：e2e 测试开始前校验 stub_source_crc**（审查 A10）

为避免 PowerShell + Python 混合引号转义问题，新建独立 Python 脚本 `packer/cmake/check_stub_freshness.py`，测试脚本调用它：

```powershell
# auto_e2e_test.ps1 主流程开头加
function Check-StubFreshness {
    param([string]$StubDir, [string]$WinlockRoot)
    # 调用独立 Python 脚本（避免内联 Python 的引号转义问题）
    # 返回 0 = 全部匹配，1 = 有不匹配（警告模式不 fail）
    & $pythonExe ${WinlockRoot}\cmake\check_stub_freshness.py --stub-dir $StubDir --winlock-root $WinlockRoot
    # check_stub_freshness.py 内部打印警告，不抛异常（warn-only 模式）
}

# 主流程开头调用
Check-StubFreshness -StubDir $distDir -WinlockRoot $winlockRoot
```

**新建 `packer/cmake/check_stub_freshness.py`**：

```python
#!/usr/bin/env python3
"""check_stub_freshness.py - 校验 dist/ 里的 stub 是否与当前源码一致

用法：python check_stub_freshness.py --stub-dir <dir> --winlock-root <dir>
  --stub-dir:    dist/ 目录路径（含 stub_inplace_x64.bin 等）
  --winlock-root: packer/ 目录路径

逻辑：
  1. 用 inspect_stub.py 读 stub.bin 的 stub_source_crc 字段
  2. 重算当前源码的 CRC32（与 patch_stub_identity.py 同逻辑）
  3. 对比，不一致则警告（warn-only，不 fail）
"""
import sys, os, argparse, binascii, struct

# 复用 patch_stub_identity.py 的常量和函数
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from patch_stub_identity import (
    STUB_DATA_MAGIC, IDENTITY_FMT, IDENTITY_SIZE, CHECKSUM_SIZE,
    parse_config_h, find_stub_data, compute_source_crc, stub_source_files
)

def read_stub_source_crc(stub_bin_path, stub_data_version, stub_data_size):
    with open(stub_bin_path, "rb") as f:
        data = f.read()
    off, _ = find_stub_data(data, stub_data_version, stub_data_size)
    if off < 0:
        return None
    identity_off = off + stub_data_size - CHECKSUM_SIZE - IDENTITY_SIZE
    fields = struct.unpack_from(IDENTITY_FMT, data, identity_off)
    return fields[4]  # stub_source_crc

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stub-dir", required=True)
    parser.add_argument("--winlock-root", required=True)
    args = parser.parse_args()

    # parse_config_h 返回 (version, bin_ver, sizeof)，这里只用 version 和 sizeof
    stub_data_version, _, stub_data_size = parse_config_h(args.winlock_root)

    stub_files = [
        ("stub_inplace_x64.bin", "x64"),
        ("stub_inplace_x86.bin", "x86"),
    ]

    all_ok = True
    for bin_name, arch in stub_files:
        bin_path = os.path.join(args.stub_dir, bin_name)
        if not os.path.exists(bin_path):
            continue

        stub_crc = read_stub_source_crc(bin_path, stub_data_version, stub_data_size)
        if stub_crc is None:
            print(f"[stub] WARN: {bin_name} 无法读取 stub_source_crc", file=sys.stderr)
            all_ok = False
            continue

        src_crc = compute_source_crc(args.winlock_root, arch)
        if src_crc is None:
            print(f"[stub] WARN: {bin_name} 源文件缺失，无法重算 CRC", file=sys.stderr)
            all_ok = False
            continue

        if src_crc != stub_crc:
            print(f"[stub] WARN: source CRC mismatch! {bin_name} "
                  f"stub=0x{stub_crc:08x} src=0x{src_crc:08x} — stub is stale, rebuild recommended",
                  file=sys.stderr)
            all_ok = False
        else:
            print(f"[stub] OK: {bin_name} source_crc=0x{stub_crc:08x} matches")

    sys.exit(0)  # warn-only 模式：即使有不匹配也返回 0，只打印警告

if __name__ == "__main__":
    main()
```

**改动点 2：端到端校验加壳产物 identity**（审查 A7）

测试脚本在 Pack-Sample 后，用 inspect_stub.py 读加壳产物 .lock 节里的 stub_data_t，确认 identity 与所用 stub 一致：

```powershell
function Verify-PackedIdentity {
    param([string]$PackedExe, [string]$StubBin)
    # inspect_stub.py packed.exe 模式暂未实现（见改动 7 TODO）
    # 实施时补 PE 节表解析，读 .lock 节里的 stub_data_t
    # 与 inspect_stub.py stub.bin 模式输出对比
}
```

**注意**：改动 7 的 inspect_stub.py packed.exe 模式需要补 PE 节表解析逻辑，实施时完成。如果时间紧张，端到端校验可延后，只做 source_crc 校验。

### 改动 10：消除 CMake 文件复制 hack（审查 A14，P0 级）

**改哪个文件**：[packer/build.ps1](file:///C:/Home/Projects/applocker/packer/build.ps1) 106-129 行 + CMakeLists 文件结构

**当前问题**：build.ps1 临时复制 `CMakeLists-x64.txt` 为 `CMakeLists.txt`，崩溃时残留文件导致后续 cmake 静默错误配置。

**改进方案**：用 `cmake -S` 指定源目录，把 `CMakeLists-xXX.txt` 移到子目录：

```
packer/
├── CMakeLists.txt          # 顶层：按 -DWINLOCK_ARCH 转发到子目录
├── x64/
│   └── CMakeLists.txt      # 原 CMakeLists-x64.txt 内容
└── x86/
    └── CMakeLists.txt      # 原 CMakeLists-x86.txt 内容
```

**顶层 CMakeLists.txt**：

```cmake
cmake_minimum_required(VERSION 3.20)
project(winlock_packer)

# WINLOCK_ROOT 顶层定义一次，子目录通过变量继承访问
set(WINLOCK_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

if(NOT DEFINED WINLOCK_ARCH)
    set(WINLOCK_ARCH "x64" CACHE STRING "Target arch: x64 or x86")
endif()
if(WINLOCK_ARCH STREQUAL "x64")
    add_subdirectory(x64)
elseif(WINLOCK_ARCH STREQUAL "x86")
    add_subdirectory(x86)
else()
    message(FATAL_ERROR "Unknown WINLOCK_ARCH: ${WINLOCK_ARCH}")
endif()
```

**子目录变量作用域**：`add_subdirectory(x64)` 创建新作用域，x64/CMakeLists.txt 里的 `set(ARCH x64)` 在子作用域内有效。`include(inplace/CMakeLists.inc)` 在子作用域内执行，能看到 `ARCH` 和继承的 `WINLOCK_ROOT`。无需 PARENT_SCOPE。

**build.ps1 改为**：

```powershell
# 不再复制 CMakeLists.txt
$cmakeArgs = @("-S", $root, "-B", $buildDir, "-G", "Ninja",
               "-DCMAKE_BUILD_TYPE=$config",
               "-DWINLOCK_ARCH=$arch")
& cmake @cmakeArgs
```

**作用**：消除最大脆弱点，`git status` 不再有 `CMakeLists.txt` 残留。

### 改动 11：malloc NULL 检查 + 文件读取大小上限（审查 A15，P0 级）

**改哪个文件**：[packer/inplace/builder.c](file:///C:/Home/Projects/applocker/packer/inplace/builder.c) 和 [packer/reflective/builder_reflective.c](file:///C:/Home/Projects/applocker/packer/reflective/builder_reflective.c)

**改动点 1：read_file 加大小上限**

```c
static uint8_t* read_file(const char* path, size_t* out_size) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0) { fclose(f); return NULL; }
    /* 审查 A15：512MB 上限，防 OOM */
    if (size > 512L * 1024 * 1024) {
        fprintf(stderr, "[-] File too large: %s (%ld bytes)\n", path, size);
        fclose(f);
        return NULL;
    }
    uint8_t* data = (uint8_t*)malloc((size_t)size);
    if (!data) { fclose(f); return NULL; }   /* 审查 A15：NULL 检查 */
    if (fread(data, 1, (size_t)size, f) != (size_t)size) {
        free(data); fclose(f); return NULL;
    }
    fclose(f);
    if (out_size) *out_size = (size_t)size;
    return data;
}
```

**改动点 2：所有 malloc 加 NULL 检查**

搜索 `malloc(`，每个调用后加：
```c
if (!ptr) { fprintf(stderr, "OOM at %s:%d\n", __FILE__, __LINE__); exit(1); }
```

或封装 xmalloc 宏（见独立审查 4.2）。

### 改动 12：Makefile.mingw 加 DEPRECATED 注释（审查 A16）

**改哪个文件**：[packer/Makefile.mingw](file:///C:/Home/Projects/applocker/packer/Makefile.mingw)

**改动**：文件顶加注释：

```makefile
# DEPRECATED: 此 Makefile 已过时，不再维护
# 请使用 build.ps1 构建（支持 MSVC + MinGW + 自动产物汇集）
# 保留此文件仅供历史参考
```

不花时间同步更新内容。

---

## 四、实施顺序

每个步骤实施后都要 clean build + e2e test 验证不破坏现有功能：

**第 0 步（前置 P0）**：改动 10（CMake hack 消除）+ 改动 11（malloc 检查）。先消除构建系统脆弱点，避免后续改动踩坑。

**第 1 步（身份字段 + 注入）**：改动 1（config.h 加字段）+ 改动 2（CMake 注入 STUB_ARCH/STUB_TOOLCHAIN）+ 改动 3（build.ps1 MinGW 注入 + Python 检测）+ 改动 4（patch_stub_identity.py）。这一步完成后，所有 stub 二进制都带完整 identity。

**第 2 步（builder 校验）**：改动 5（builder.c 四重校验）+ 改动 6（builder_reflective.c 薄封装）。这一步完成后，加壳时能立刻发现 arch 不匹配等错误。

**第 3 步（inspect 工具 + manifest）**：改动 7（inspect_stub.py）+ 改动 8（build.ps1 严格化 + manifest）。这一步完成后，构建流程完全可追溯。

**第 4 步（测试校验）**：改动 9（测试脚本 source_crc + 端到端 identity）。这一步完成后，测试能自动发现 stale stub。

**第 5 步（清理）**：改动 12（Makefile.mingw DEPRECATED）。

---

## 五、关于当前 x86 inplace_password 崩溃的推测

clean build 后 x86 又崩了（helloguix86 / hellomfcx86 CRASH exit=2），最可能的原因：

1. **MinGW x86 stub 本身有 bug**（之前 topics.md 提到"重新编译 x86 stub 解决"，但 clean build 后又是同样的 MinGW 产物，问题回归）
2. **MinGW x86 stub 的 TLS callback 行为与 MSVC 不同**，导致 x86 PE 的 CRT 初始化失败
3. **build.ps1 静默 fallback**：如果 MinGW x86 构建失败，dist/ 会用 MSVC x86 stub（16400 bytes），行为又不同

有了上述改动后，能立刻确认当前 dist/ 里 `stub_inplace_x86.bin` 是 MinGW 还是 MSVC、arch 对不对、用了哪个 git commit、source_crc 是否与当前源码一致，从而快速定位是 stub 本身问题还是 builder 用错 stub。

---

## 六、审查采纳记录

本版整合了 4 份独立审查报告的结论：

| 类别 | 数量 | 关键项 |
|------|------|--------|
| **必须改（已采纳）** | 5 | githash 宏（M1）、宏重定义（M2）、reflective identity 语义（M3）、source_crc 范围（M4）、checksum 描述（M5） |
| **应该采纳（已采纳）** | 16 | 砍 .winlock 节（A1）、identity 放末尾（A2）、统一注入（A3）、manifest bug（A4）、config.h 解析（A5）、dev 路径 patch（A6）、端到端校验（A7）、magic 四重校验（A8）、注释矛盾（A9）、行尾归一化（A10）、幂等+偏移注释（A11）、python 检测（A12）、inspect 合并（A13）、CMake hack（A14）、malloc 检查（A15）、Makefile.mingw（A16） |
| **可忽略（未采纳）** | 16 | 安全相关、性能优化、代码可读性等非本 plan 重点项 |

**核心结论**：
1. M1+M2+M3 是实施前必须解决的，否则编译失败或字段死代码
2. A1（砍 .winlock 节）是最大简化，去除最高风险改动，反查能力不损失
3. A14（CMake 文件复制 hack）是 plan 遗漏的 P0 问题，已补充加入
4. B 的简化方案（-D 只注入 arch/toolchain，其余 POST_BUILD patch）是最干净的注入策略，一次性解决 M1/M2/A3 三个问题

---

## 七、实现者自我审查修复记录

本版在整合 4 份审查报告后，又从实现者角度通读一遍，发现并修复了 13 个遗留问题：

**严重问题（会导致编译失败或运行时错误）**：
1. `STUB_DATA_SIZE_BY_VERSION` 字典描述过时（脚本已改为从 config.h 解析），删除该描述
2. `stub_data_t` 定义片段缺 `#pragma pack(push, 8)` 包裹，实现者可能遗漏导致字段对齐错位
3. 改动 5 没明确"替换原 magic 搜索逻辑"，可能造成 builder 重复搜索 stub_data_t
4. 改动 2 和改动 8 都描述 POST_BUILD patch 命令，重复且可能不一致，统一到改动 8
5. `parse_config_h` 返回 3 元组，但 inspect_stub.py / check_stub_freshness.py 按解包 2 元组，会抛 `ValueError`
6. inspect_stub.py 的 `--winlock-root` 是可选参数，但 import 的 `parse_config_h` 不支持自动推断，补充推断逻辑

**中等问题（影响正确性或可维护性）**：
7. 缺少 `_Static_assert(sizeof(stub_data_t) == STUB_DATA_SIZEOF)`，STUB_DATA_SIZEOF 宏可能与实际 sizeof 漂移
8. PowerShell `$manifest.stubs += $info` 单元素退化成标量陷阱，改为 `@(... + $info)`
9. `patch_stub_identity.py` 的 `identity_off + 20` 硬编码偏移注释不清晰，改为命名常量 + 详细注释
10. inspect_stub.py / check_stub_freshness.py 与 patch_stub_identity.py 代码重复，改为 import 复用

**小问题（影响可读性）**：
11. `sys.exit(0 if all_ok else 0)` 冗余写法，改为 `sys.exit(0)` + 注释
12. CMake 顶层 `WINLOCK_ROOT` 变量未定义，子目录无法继承，补充定义 + 作用域说明
13. `patch_stub_identity.py` 缺参数个数校验，`sys.argv[4]` 可能 IndexError，加 `len(sys.argv) != 5` 校验
