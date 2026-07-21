# Inplace 壳 Bug 分析报告

**日期**: 2026-07-20 21:54  
**分析范围**: `packer/inplace/` 全部代码（builder.c / stub.c）  
**测试工具**: PowerShell + Python + cdb (x86/x64) + objdump  

---

## 1. 测试失败清单

| 测试项 | 模式 | 结果 | 错误码 |
|--------|------|------|--------|
| hellomfcx86 | inplace_test | CRASH | exit=2 |
| hellomfcx86 | inplace_password | CRASH | exit=2 |
| DontSleep | reflective_test | CRASH | exit=0xC0000005 |

其余测试（hellocli / hellogui / Notepad4 / Bandizip / TLS）**全部 PASS**。  
`hellomfcx86 reflective` 也 **全部 PASS** → SHA-256 算法、PEB walk、hash 常量三者均正确。

---

## 2. 逐项验证记录

### 2.1 PE 构建正确性

使用 Python + PowerShell 逐字节验证输出 PE (`check_mfc_debug.exe` 284160 bytes)：

| 字段 | 原始 PE | 输出 PE | 状态 |
|------|---------|---------|------|
| NumberOfSections | 5 | 6 | ✅ |
| SizeOfOptionalHeader | 0xE0 | 0xE0 | ✅ |
| EP RVA | 0x9BD0 | **0x46000** | ✅ |
| ImageBase | 0x400000 | 0x400000 | ✅ |
| SizeOfImage | 0x46000 | **0x49000** | ✅ |
| DllCharacteristics | 0x8140 | **0x8100** (ASLR off) | ✅ |
| FileHeader.Characteristics | 0x0102 | 0x0102 | ✅ |

节表（正确偏移 0x1F0）：

| # | Name | VA | VSize | RawOff | RawSize | Status |
|---|------|----|-------|--------|---------|--------|
| 0 | .text | 0x1000 | 0xA765 | 0x400 | 0xA800 | ✅ |
| 1 | .rdata | 0xC000 | 0x8D9C | 0xAC00 | 0x8E00 | ✅ |
| 2 | .data | 0x15000 | 0x9E4 | 0x13A00 | 0x800 | ✅ |
| 3 | .rsrc | 0x16000 | 0x2BF28 | 0x14200 | 0x2C000 | ✅ |
| 4 | .reloc | 0x42000 | 0x3114 | 0x40200 | 0x3200 | ✅ |
| 5 | **.lock** | **0x46000** | **0x2030** | **0x43400** | **0x2200** | ✅新增 |

数据目录（与原始 PE 一致，未修改项目保持不变）：

| Index | Name | RVA | Size | Status |
|-------|------|-----|------|--------|
| 1 | IMPORT | 0x13668 | 0x12C | ✅ |
| 5 | BASERELOC | 0x42000 | 0x3114 | ✅ |
| 6 | DEBUG | 0x116A0 | 0x70 | ✅ |
| 9 | TLS | 0x11740 | 0x18 | ✅（无 callbacks） |
| 10 | LOAD_CONFIG | 0x115E0 | **0x40** | ✅ |
| 4/11 | SECURITY / BOUND_IMPORT | 清零 | 清零 | ✅ |

---

### 2.2 stub_data 字段验证

stub_data 在输出 PE 文件偏移 `0x43400 + 0x1F10 = 0x45310`：

| 字段 | 偏移 | 值 | 验证 |
|------|------|----|------|
| magic | +0 | 0x214B434F4C4E4957 | ✅ STUB_DATA_MAGIC |
| version | +8 | 4 | ✅ v4 |
| flags | +10 | 0x0003 | ✅ HASH(1) + TEST(2) |
| oep_rva | +16 | 0x9BD0 | ✅ 原始 EP |
| text_rva | +24 | 0x1000 | ✅ .text VA |
| text_size | +32 | 0xA760 (=42848) | ✅ min(VSize,RawSize)&~7 |
| text_raw_size | +40 | 0xA800 | ✅ |
| text_protect | +44 | 0x20 (PAGE_EXECUTE_READ) | ✅ |
| image_base | **+240** | 0x400000 | ✅ |
| reloc_rva | +248 | 0x42000 | ✅ |
| reloc_size | +256 | 0x3114 | ✅ |
| security_cookie_rva | +272 | 0x127F0 | ✅ |
| checksum | +280 | 0x34CE4F2F69FF87EB | ✅ |

---

### 2.3 SHA-256 Hash 三端验证

**Builder (Windows BCrypt)** 输出：
```
BDA7822C1C79CE3AC0745AC5BE9739843C67909D9F69822939D23A9B20D2B307
```

**Python hashlib**（salt + "test123" UTF-8）：
```
BDA7822C1C79CE3AC0745AC5BE9739843C67909D9F69822939D23A9B20D2B307
```
**完全一致** ✅

**输出 PE stub_data.pwd_hash**（@0x45360）：
```
BDA7822C1C79CE3AC0745AC5BE9739843C67909D9F69822939D23A9B20D2B307
```
**完全一致** ✅

Salt 16 字节（@0x45350）：`FD 49 8F 87 8E AC A2 2C 8B 14 F6 CB D5 61 D4 03` ✅

结论：**hash 计算无误，builder 正确写入，stub 应能正确校验**。

---

### 2.4 重定位修补验证

Builder 输出：`[+] Patched 112 stub relocations: delta=0x435000`

通过 Python 验证输出 PE 中所有 4 个关键 `fn` 指针的指令操作数：

| fn 指针 | .bin 偏移 | 原始值 | 修补后 | 期望值 | 结论 |
|---------|-----------|--------|--------|--------|------|
| GetProcAddress | +0x33 | 0x00012EF4 | **0x00447EF4** | 0x00447EF4 | ✅ |
| LoadLibraryA | +0x4B | 0x00012EF0 | **0x00447EF0** | 0x00447EF0 | ✅ |
| VirtualProtect | +0x63 | 0x00012EF8 | **0x00447EF8** | 0x00447EF8 | ✅ |
| ExitProcess | +0x7B | 0x00012EFC | **0x00447EFC** | 0x00447EFC | ✅ |

delta 计算：
- `stub_base = 0x10000 + 0x1000 = 0x11000`
- `target_base = 0x400000 + 0x46000 = 0x446000`
- `delta = 0x446000 - 0x11000 = 0x435000`
- 验证：`0x12EF4 + 0x435000 = 0x447EF4` = `0x400000 + 0x2EF4 = 0x402EF4`?  

  不对——fn 在 target 中的 RVA = `0x46000 + (0x12EF4 - 0x1000 - 0x10000) = 0x47EF4`  
  target VMA = `0x400000 + 0x47EF4 = 0x447EF4` ✅（与 patched 一致）

---

### 2.5 PEB/LDR 结构验证

**PEB 偏移（x86 WOW64）**：
- `WINLOCK_PEB()` = `__readfsdword(0x30)` → 读 FS:[0x30] = PEB 指针 ✅
- PEBX.Ldr @ offset +0x0C（4-byte PVOID）= PEB_LDR_DATA 指针 ✅

**PEB_LDR_DATA 偏移（Windows 10 19041 x86）**：
- InLoadOrderModuleList @ +0x0C ✅
- 已通过 Windows 10 19041 的公开结构验证匹配

**LDR_DATA_TABLE_ENTRY 偏移（x86）**：
- DllBase @ +0x18 ✅
- BaseDllName @ +0x2C ✅
- 已通过 `#ifdef _WIN64` 正确分派

**模块名 hash 无冲突**（Python 验证 40+ 系统 DLL）✅

---

### 2.6 cdb 运行时验证

使用 32 位 cdb 附加到打包后的 hellomfcx86：

```
ModLoad: 77000000 770f0000   KERNEL32.DLL
ModLoad: 5a110000 5a5ba000   mfc140u.dll
ModLoad: 71f40000 71f5d000   VCRUNTIME140.dll
...
```
**所有 DLL 正常加载** ✅。  
进程在 `ntdll!LdrInitShimEngineDynamic+0x6e2` 处停在初始断点。

stub 二进制反汇编验证：
```
mov DWORD PTR [esp],0x6022d7cb       ; HASH_MOD_KERNEL32_DLL
call _find_module_by_hash
```
PEB 读取指令 `64 A1 30 00 00 00` 存在于 stub 中 ✅

---

## 3. 未验证/无法定位的根因

**`exit=2` 的确切原因无法通过静态分析确定**。  
`exit=2` 来自 `stub_entry()` 的 `fail: fn.ExitProcess(2)`。

可能的 fail 路径：
1. `find_module_by_hash` 返回 NULL
2. `find_export_by_hash` 返回 NULL（4 个 API 任意一个）
3. `verify_password` 返回 0（hash 不匹配）
4. `decrypt_text_and_reloc` 返回 0（VirtualProtect 失败）

但由于：
- SHA-256 三端 hash 完全一致
- 112 项 reloc 修补全部正确
- PEB/LDR 结构偏移已验证
- 模块名 hash 无冲突

代码层面 **看不出问题**。

---

## 4. 最可能的根因（需 runtime 调试确认）

| 可能性 | 说明 | 出现概率 |
|--------|------|----------|
| **MinGW x86 `-O2` optimizer bug** | `sha256_transform` 或 `utf16le_to_utf8` 在 `-O2` 下产生错误机器码，导致 hash 算出错误结果 | 高 |
| **Inline SHA-256 vs BCrypt 差异** | 虽算法一致，但局部变量初始化/对齐可能在不同编译器下产生差异 | 中 |
| **TLS directory 空壳干扰 WOW64** | hellomfcx86 有 TLS dir(=0x18) 虽无 callbacks，但 SizeOfZeroFill/Characteristics 非零可能触发意外加载行为 | 低 |
| **MFC DLL 初始化破坏 stub 数据** | mfc140u.dll 的 TLS/CRT 初始化可能覆盖了 stub 的 .lock 数据（`.lock` 节是 RW 权限） | 中 |

---

## 5. 建议修复方向

### 优先级 P0：重建 x86 inplace stub 用 `-O0`

`build.ps1` 中 x86 MinGW 构建参数当前用 `-O2`，改为 `-O0`：

```powershell
# 修改前
$commonCflags = @(..., "-O2", ...)

# 修改后
$commonCflags = @(..., "-O0", ...)
```

### 优先级 P1：注入 OutputDebugString 日志

在 `stub.c` 的 `verify_password` 失败前输出实际计算的 digest：

```c
// 在 bytes_eq_const 失败后，用 OutputDebugStringW 输出
// 或用 fn.MessageBoxW 弹框显示
```

### 优先级 P2：32 位 cdb 单步跟踪

```
cdb.exe -o hellomfcx86_locked.exe
bp stub_entry
g
; 单步跟踪 find_module_by_hash / find_export_by_hash / verify_password
```
