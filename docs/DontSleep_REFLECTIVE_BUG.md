# DontSleep Reflective 加载问题分析

## 症状

输入密码后 DontSleep 弹出错误对话框 "Error! Loading language file string archive"
原始问题是 CRASH exit=0xC0000005，修复 PEB patch 时序后变为错误弹窗。

## 日志关键发现

```
[REFL] payload: test mode password OK, decrypting...
[REFL] map: VirtualAlloc(preferred=0x400000, size=0xaa000) failed (err=487)
[REFL] map:   0x400000-0x404000 state=COMMIT type=MAPPED
[REFL] map:   0x404000-0x408000 state=RESERVE type=MAPPED
[REFL] map:   0x470000-0x48e000 state=COMMIT type=PRIVATE  ← 阻断了连续 0xaa000 空间
[REFL] map: NtUnmapViewOfSection(0x400000) = 0             ← 只释放了 8KB MAPPED 区域
[REFL] map: retry VirtualAlloc(preferred) still failed      ← 仍有 PRIVATE 占用
[REFL] map: allocated at 0x20e0000 (delta=0x1ce0000)       ← 只能加载到其他地址
[REFL] reloc: no reloc table, trying fallback scan          ← ⚠️ DontSleep 无 .reloc 节
[REFL] reloc: fallback fixed 1469 absolute refs             ← fallback 产生了错误修补
```

## 根因分析

### 1. DontSleep PE 特性

- **无 basereloc 表**（DataDirectory[5] 不存在）
- **ASLR 关闭**：ImageBase=0x400000 必须准确加载
- 但进程启动时 0x400000-0x408000 已被 MAPPED（stub 自己的映射）
- NtUnmapViewOfSection 只释放了 MAPPED 区域（8KB），0x470000 的 PRIVATE 分配仍存在
- 导致 0x400000-0x470000 只有 448KB 连续空间，但需要 680KB (SizeOfImage=0xaa000)

### 2. Fallback relocations 问题

`fallback_relocations`（fallback 扫描）试图扫描所有节的数据来修复绝对地址引用。
但由于 DontSleep 没有 reloc 表，fallback 扫描在 ntdll 中产生**大量误修补**：
- 读 `sec[i].VirtualAddress` 得到 0x8（可能因头部拷贝不完整）
- 扫描范围 `size=0x20e01f8` 覆盖了整个 ntdll 地址空间
- 误修改了函数指针表、IAT、字符串常量等不应修改的数据

### 3. MFC42u.dll 加载崩溃

被 fallback 损坏的 image 传入 `process_iat`：
- LoadLibraryA("MFC42u.dll") 加载正常
- MFC42u!DllMain 读取被 corruption 的数据 → ACCESS_VIOLATION
- VEH 捕获但 DLL 初始化失败
- DontSleep 启动后依赖 MFC 失败 → 显示错误弹窗

## 修复方案

两种方案：

### 方案 A：确保加载到 preferred base（推荐）

修复 NtUnmapViewOfSection 逻辑，确保卸载完整的 0x400000-0x4ca000 范围：
- 用 `VirtualQuery` 遍历从 0x400000 到 SizeOfImage 的所有内存区域
- 对 MAPPED 区域用 NtUnmapViewOfSection
- 对 PRIVATE RESERVE 用 VirtualFree(MEM_RELEASE)
- 对 PRIVATE COMMIT（CRT 分配）用 NtUnmapViewOfSection 或推迟 OEP 到加载完成后再释放

### 方案 B：修复 fallback_relocations

修复 `fallback_relocations` 的节表扫描，确保：
- Section header 指针正确（IMAGE_FIRST_SECTION 偏移在 PE32+ 中需加 SizeOfOptionalHeader）
- 扫描范围限制在 `new_img + sec[i].VirtualAddress` 到 `new_img + sec[i].VirtualAddress + min(VSize, SizeOfRawData)`
- 当前值 `VA=0x8 size=0x20e01f8` 明显错误（读取了 ntdll 地址作为节大小）

### 方案 C：快速修复（当前）

修改 builder_reflective.c：在找到 preferred base 被占用时，
先用 NtUnmapViewOfSection 卸载所有 MAPPED 节后用 VirtualFree MEM_RELEASE
释放 PRIVATE RESERVE 区域。

## 当前状态

- PEB patch 时序修复已完成（`patch_peb_ldr_main_entry` 移到 process_iat 之后）
- DontSleep 已从 0xC0000005 崩溃变为错误弹窗（progress）
- 需要完成 preferred base 加载修复才能正确运行
