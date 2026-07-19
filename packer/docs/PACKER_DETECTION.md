# WinLock Inplace / Reflective 加壳可检测性分析

> 日期：2026-07-19
> 测试样本：`Notepad4.exe`（x64, MSVC 19.51 / VS 2026, 2.34 MB）
> 工具：Detect It Easy (diec 3.x)、pefile (Python)、自定义分析脚本

## 一、结论速览

| 加壳方案 | DIE 识别 | PEiD 风险 | 手动 PE 分析暴露程度 | 杀软启发式风险 |
|----------|----------|-----------|---------------------|---------------|
| **Inplace** | ❌ 完全检测不到（仍识别为原版 MS Linker / MSVC / VS 2026） | ❌ 无签名匹配 | ⚠ 中等（4 个特征） | 低（保留原 IAT/资源） |
| **Reflective v1 明文** | ⚠ 识别为 "Unknown: Unknown" | ❌ 无签名匹配 | 🔴 高（9 个特征） | 中（MinGW stub + 巨大 .payload 节） |
| **Reflective v2 加密** | ⚠ 识别为 "Unknown: Unknown" | ❌ 无签名匹配 | 🔴 高（9 个特征） | 中（同上 + 密码弹框 API） |

**关键发现**：
- **Inplace 加壳对 DIE 完全隐形**——DIE 默认和 `-a` 深度扫描都识别不出加壳，仍报原版的 MS Linker 14.51 / MSVC 19.51 / VS 2026 信息
- **Reflective 加壳被 DIE 标记为 "Unknown"**——因为整个外壳是 MinGW 编译的 stub，原 PE 隐藏在 `.payload` 节里，DIE 看不到原版 linker 信息
- **没有触发任何 packer/crypter 签名**——DIE 内置的 UPX / Themida / VMP / Enigma / MPRESS 等签名库都不匹配我们的产物
- **手动 PE 分析能看出明显异常**——但这些异常需要专业的逆向工程师或杀软启发式扫描才能识别

---

## 二、DIE (Detect It Easy) 检测结果

### 2.1 默认扫描

```
原版 Notepad4.exe:
    Linker: Microsoft Linker(14.51.36248)
    Compiler: Microsoft Visual C/C++(19.51.36248)[LTCG/C++]
    Tool: Microsoft Visual Studio(2026, 18.4)
    Debug data: Records[codeview, vc_feature, pogo]

Inplace 加壳 (Notepad4_inplace_pwd.exe):
    Linker: Microsoft Linker(14.51.36248)        ← 完全相同！
    Compiler: Microsoft Visual C/C++(19.51.36248)[LTCG/C++]
    Tool: Microsoft Visual Studio(2026, 18.4)
    Debug data: Records[codeview, vc_feature, pogo]

Reflective v1 (Notepad4_refl_v1.exe):
    Unknown: Unknown                              ← MinGW stub 不被识别

Reflective v2-pwd (Notepad4_refl_pwd.exe):
    Unknown: Unknown                              ← 同上

Reflective v2-test (Notepad4_refl_test.exe):
    Unknown: Unknown
```

### 2.2 深度扫描（`-a`）

深度扫描结果与默认扫描一致，**没有触发任何 packer / crypter / protector 签名**。

### 2.3 分析

- **Inplace 之所以隐形**：Inplace 加壳只修改了 `AddressOfEntryPoint` 和新增 `.lock` 节，原 PE 的 DOS header / Rich header / 所有节区 / 导入表 / 资源全部保留。DIE 的 linker/compiler 检测主要看 Rich header 和节区布局，这些都没变。
- **Reflective 之所以被标 Unknown**：Reflective 是把整个原 PE 嵌入到 MinGW 编译的 stub 的 `.payload` 节里。DIE 看到的是 stub 自己的 PE 结构（MinGW 链接器、`/4 /19 /31` 等 COFF 长节名、无 Rich header），匹配不到任何已知签名。

---

## 三、Inplace 加壳暴露的特征

### 3.1 PE 头对比

| 字段 | 原版 | Inplace 加壳 | 异常说明 |
|------|------|-------------|---------|
| FileSize | 2,449,408 | 2,457,088 | +7,680 字节（stub 体积） |
| NumberOfSections | 7 | **8** | 多了 1 个节（`.lock`） |
| AddressOfEntryPoint | 0x141730（在 .text） | **0x272000**（在 .lock） | **EP 改到最后一个节** |
| SizeOfImage | 0x272000 | 0x274000 | +0x2000（.lock 节大小） |
| CheckSum | 0x25e4f2 | **0x0** | **被清零**（builder 没重算） |
| LinkerVersion | 14.51 | 14.51 | 保持原版 |
| TimeDateStamp | 0x6a37910d | 0x6a37910d | 保持原版 |

### 3.2 节区对比

原版 7 个节全部保留原样，新增第 8 个 `.lock` 节：

```
.lock   VA=0x272000  VSize=0x1d30  RawSize=0x1e00  Char=0xE0000020  ERWC
                                                              ↑↑↑↑
                                                              Exec+Read+Write+Code
```

**异常特征**：
1. **节名 `.lock`**——非标准节名（标准 MS 链接器不会产生此节名），packer detector 一看就识别
2. **节属性 `0xE0000020`（ERWC）**——同时具有 `IMAGE_SCN_MEM_EXECUTE` + `IMAGE_SCN_MEM_WRITE`，**W+X 节是 packer 最典型的特征**，杀软启发式会高度警觉
3. **EP 在 `.lock` 节**——Entry Point 不在标准 `.text` 节，是 packer 的另一个典型特征
4. **EP 在最后一个节**——packer 通常把 stub 放在文件末尾

### 3.3 保留正常的部分

- ✅ 所有原版节区（.text / .rdata / .data / .pdata / .fptable / .rsrc / .reloc）完整保留
- ✅ 导入表完整保留（12 DLLs / 484 functions）
- ✅ 资源完整保留（ICON / VERSION / MANIFEST / MENU / DIALOG / STRING 全在）
- ✅ 没有 TLS directory
- ✅ Rich Header 完整保留（MS 链接器特征）

### 3.4 暴露特征总结

| # | 特征 | 检测难度 | 杀软关注度 |
|---|------|---------|-----------|
| 1 | `.lock` 节名 | 简单（节名匹配） | 低 |
| 2 | `.lock` 节 W+X 属性 | 简单（属性查表） | **高** |
| 3 | EP 在 `.lock` 节 | 简单（EP 节查表） | 中 |
| 4 | EP 在最后一个节 | 简单（位置检查） | 中 |
| 5 | CheckSum 被清零 | 简单（字段检查） | 低 |

---

## 四、Reflective 加壳暴露的特征

### 4.1 PE 头对比

| 字段 | 原版 | Reflective 加壳 | 异常说明 |
|------|------|---------------|---------|
| FileSize | 2,449,408 | 2,545,664 | +96,256（stub 体积） |
| NumberOfSections | 7 | **18** | **多了 11 个节**（MinGW 标准节 + .payload） |
| AddressOfEntryPoint | 0x141730 | **0x1440** | 改到 stub 的 .text 节 |
| SizeOfImage | 0x272000 | 0x27b000 | +0x9000 |
| CheckSum | 0x25e4f2 | **0x0** | 被清零 |
| LinkerVersion | 14.51 | **2.46** | **MinGW/GCC 链接器** |
| TimeDateStamp | 0x6a37910d | **0x00000000** | **被清零** |
| Rich Header | 有 | **无** | **MS 链接器特征缺失** |

### 4.2 节区列表（18 个节）

```
.text      0x00001000 VSize=0xb6f0    RawSize=0xb800   ERC   ← stub 代码
.data      0x0000d000 VSize=0x120     RawSize=0x200    RWI
.rdata     0x0000e000 VSize=0x28d0    RawSize=0x2a00   RI
.pdata     0x00011000 VSize=0x4ec     RawSize=0x600    RI
.xdata     0x00012000 VSize=0x4ac     RawSize=0x600    RI
.bss       0x00013000 VSize=0xbb0     RawSize=0        RWU   ← VSize>>RawSize
.idata     0x00014000 VSize=0xba0     RawSize=0xc00    RI
.tls       0x00015000 VSize=0x10      RawSize=0x200    RWI   ← stub 自己的 TLS
.rsrc      0x00016000 VSize=0x4fe4    RawSize=0x5000   RI    ← 只有 ICON/VERSION
.reloc     0x0001b000 VSize=0x84      RawSize=0x200    RI
/4         0x0001c000 ...                                       ← MinGW COFF 长节名 ⚠
/19        0x0001d000 ...
/31        0x0001f000 ...
/45        0x00020000 ...
/57        0x00021000 ...
/70        0x00022000 ...
/81        0x00023000 ...
.payload   0x00024000 VSize=0x256098 RawSize=0x256200  RI    ← 原 PE 数据 ⚠
```

**异常特征**：
1. **节名 `/4 /19 /31 /45 /57 /70 /81`**——MinGW COFF 长节名格式（GCC 编译产物特征，packer detector 一眼识别）
2. **节名 `.payload`**——非标准节名，明显的 packer 特征
3. **`.payload` 节巨大**——0x256098（2.4 MB），比所有其他节加起来还大 30 倍
4. **LinkerVersion = 2.46**——MinGW/GCC 链接器版本，与原版 MS Linker 14.51 完全不同
5. **TimeDateStamp = 0**——MinGW 默认不填或被清零
6. **没有 Rich Header**——MS 链接器特征缺失
7. **`.bss` 节 VSize >> RawSize**——`.bss` 是 0xc0000080（RWU），VSize=0xbb0 但 RawSize=0，正常节但被 detector 标记
8. **EP 在 .text 节的第一个节区**——但 `.text` 是 stub 的代码不是原 PE 的代码
9. **18 个节**——节区数量异常多（原版只有 7 个）

### 4.3 导入表对比

| 项目 | 原版 | Reflective 加壳 |
|------|------|----------------|
| DLL 数 | 12 | **3** |
| 函数数 | 484 | **79** |
| DLL 列表 | COMCTL32/SHLWAPI/IMM32/UxTheme/KERNEL32/USER32/GDI32/COMDLG32/ADVAPI32/SHELL32/ole32/OLEAUT32 | **KERNEL32/msvcrt/USER32** |

**stub 的导入表非常精简**：

```
KERNEL32.dll  (37 funcs)  ActivateActCtx, AddVectoredExceptionHandler, ...
msvcrt.dll    (38 funcs)  __C_specific_handler, ___lc_codepage_func, ...  ← MinGW CRT
USER32.dll    (4  funcs)  DialogBoxIndirectParamW, EndDialog,
                          GetDlgItemTextW, MessageBoxW                    ← 密码弹框 API
```

**异常特征**：
- **导入表只有 3 个 DLL / 79 个函数**——packer 的典型特征（原 PE 的 IAT 被隐藏在 .payload 里）
- **`USER32.dll` 只导入 4 个函数**：`DialogBoxIndirectParamW` + `EndDialog` + `GetDlgItemTextW` + `MessageBoxW`——**密码弹框 API 组合，packer detector 的强信号**

### 4.4 TLS Directory

- 原版：无 TLS
- Reflective：**有 TLS directory**（stub 自己用 TLS callback proxy 处理原 PE 的 TLS）

这本身不算 packer 特征（很多正常程序也有 TLS），但与原版对比是异常变化。

### 4.5 资源对比

| 资源类型 | 原版 | Reflective 加壳 |
|---------|------|----------------|
| CURSOR | 1 | ❌ 缺失 |
| BITMAP | 6 | ❌ 缺失 |
| ICON | 6 | ✅ 保留（builder copy_resources 复制） |
| MENU | 2 | ❌ 缺失 |
| DIALOG | 32 | ❌ 缺失 |
| STRING | 22 | ❌ 缺失 |
| ACCELERATOR | 2 | ❌ 缺失 |
| GROUP_CURSOR | 1 | ❌ 缺失 |
| GROUP_ICON | 3 | ✅ 保留 |
| VERSION | 1 | ✅ 保留 |
| MANIFEST | 1 | ❌ 缺失（运行时从 .payload 提取） |

**异常特征**：原 PE 的 MANIFEST / DIALOG / MENU / STRING 等资源全部丢失，只剩 ICON/VERSION。运行时虽然 stub 会从 .payload 重新提取 manifest，但静态分析看资源表会很明显。

### 4.6 暴露特征总结

| # | 特征 | 检测难度 | 杀软关注度 |
|---|------|---------|-----------|
| 1 | LinkerVersion = 2.46（MinGW） | 简单（字段检查） | 中 |
| 2 | TimeDateStamp = 0 | 简单 | 低 |
| 3 | 没有 Rich Header | 简单 | 中 |
| 4 | 节名 `/4 /19 /31 ...`（COFF 长节名） | 简单（节名匹配） | 中 |
| 5 | 节名 `.payload` | 简单 | **高** |
| 6 | `.payload` 节巨大（2.4 MB） | 简单（节大小比例） | 中 |
| 7 | 18 个节（原版 7 个） | 简单（节计数） | 低 |
| 8 | 导入表只有 3 DLL / 79 函数 | 简单（IAT 大小） | **高** |
| 9 | USER32 只导入 4 个密码弹框 API | 简单（API 组合匹配） | **高** |
| 10 | 资源只剩 ICON/VERSION | 简单（资源枚举） | 中 |

---

## 五、改进建议

### 5.1 Inplace 改进方向（隐蔽性已很高）

Inplace 加壳的隐蔽性已经很好（DIE 完全检测不到），但仍有几个特征可以优化：

| 改进项 | 优先级 | 复杂度 | 说明 |
|-------|-------|-------|------|
| `.lock` 节改名 | 中 | 低 | 改成 `.text2` 或 `.rdata2` 等看起来正常的名字 |
| `.lock` 节去掉 W 属性 | 高 | 中 | stub 不需要运行时写自己（除非解密 .text），改成 ER 即可 |
| 重算 CheckSum | 低 | 低 | 调用 `CheckSumMappedFile` 重算 |
| EP 不放在最后一个节 | 中 | 高 | 把 stub 代码塞到 `.text` 节末尾，不新增节 |

### 5.2 Reflective 改进方向（暴露较多）

Reflective 加壳暴露的特征较多，最致命的几个：

| 改进项 | 优先级 | 复杂度 | 说明 |
|-------|-------|-------|------|
| 用 MSVC 编译 stub 而不是 MinGW | **高** | 中 | 消除 LinkerVersion=2.46、`/4 /19` 节名、无 Rich Header 三个特征 |
| `.payload` 节改名 | **高** | 低 | 改成 `.text2` / `.data2` 等 |
| 假 IAT 注入 | 中 | 高 | 在 stub 导入表里伪造原 PE 的几个常用 DLL/函数 |
| 资源全量复制 | 中 | 中 | 不只复制 ICON/VERSION，把 MANIFEST/DIALOG/MENU 也复制到 stub |
| 把 stub 节合并减少 | 低 | 高 | MinGW 链接器 18 个节太显眼，用 MSVC 能降到 5-6 个 |

### 5.3 杀软启发式风险

**Inplace 风险**：低
- DIE / PEiD 都检测不到
- W+X 节是唯一明显信号，但很多合法程序（JIT 编译器、.NET runtime）也有 W+X 节
- 保留原 IAT 和资源，行为特征与原版一致

**Reflective 风险**：中
- "Unknown" 链接器 + MinGW 节名会被启发式标记为"可疑"
- `.payload` 节名 + 巨大体积 + IAT 极少是经典 packer 组合
- 密码弹框 API（DialogBoxIndirectParamW + GetDlgItemTextW + MessageBoxW）会被某些杀警觉
- 但因为没有匹配任何已知 packer 签名，杀软不会直接报"UPX"或"Themida"

---

## 六、对比主流 packer 的可检测性

| Packer | DIE 识别 | 特征 |
|--------|---------|------|
| UPX | ✅ "UPX 3.96" | 节名 `.UPX0`/`.UPX1`，EP 在 .UPX1 |
| Themida | ✅ "Themida 2.x" | 节名 `.themida`，虚拟机特征 |
| VMProtect | ✅ "VMProtect 3.x" | 节名 `.vmp0`/`.vmp1` |
| Enigma | ✅ "Enigma Protector" | 节名 `.enigma1`/`.enigma2` |
| MPRESS | ✅ "MPRESS 1.x" | 节名 `.MPRESS1`/`.MPRESS2` |
| **WinLock Inplace** | ❌ 不识别 | 节名 `.lock`（自定义，未入库） |
| **WinLock Reflective** | ⚠ "Unknown" | MinGW stub + `.payload`（未入库） |

**优势**：没有出现在 DIE/PEiD 的签名库里，自动扫描工具不会直接打标签。
**劣势**：手动分析能看出明显的 packer 特征（W+X 节、节名、IAT 极少等）。

---

## 七、复现方法

### 7.1 生成测试样本

```bash
cd packer
# 原版（对照组）
cp ../temp/samples/Notepad4.exe ../temp/

# Inplace 加壳（带密码）
./builder/builder.exe -i ../temp/samples/Notepad4.exe \
    -o ../temp/Notepad4_inplace_pwd.exe -p testpwd123

# Reflective v1 明文（无密码）
./builder/builder_reflective.exe ../temp/samples/Notepad4.exe \
    ../temp/Notepad4_refl_v1.exe \
    --stub ./reflective/loader_x64.exe

# Reflective v2 加密（带密码）
./builder/builder_reflective.exe ../temp/samples/Notepad4.exe \
    ../temp/Notepad4_refl_pwd.exe -p testpwd123 \
    --stub ./reflective/loader_x64.exe

# Reflective v2 测试模式
./builder/builder_reflective.exe ../temp/samples/Notepad4.exe \
    ../temp/Notepad4_refl_test.exe -t \
    --stub ./reflective/loader_x64.exe
```

### 7.2 运行分析工具

```bash
# DIE 默认扫描
C:/Home/Develop/DetectItEasy/diec.exe <sample.exe>

# DIE 深度扫描
C:/Home/Develop/DetectItEasy/diec.exe -a <sample.exe>

# DIE JSON 输出（便于脚本解析）
C:/Home/Develop/DetectItEasy/diec.exe -j <sample.exe>

# Python pefile 详细分析
C:/Home/Develop/Python/python.exe ../temp/analyze_pe.py
```

### 7.3 分析脚本

`temp/analyze_pe.py` —— 自动检查节区/EP/IAT/资源/Rich Header 等异常特征，输出对比报告。

---

## 八、附录：完整数据表

### 8.1 节区对比（原版 vs Inplace）

```
原版 (7 节):
.text      VA=0x1000   VSize=0x15ece9 RawSize=0x15ee00 Char=0x60000020 ERC
.rdata     VA=0x160000 VSize=0xbae22  RawSize=0xbb000  Char=0x40000040 RI
.data      VA=0x21b000 VSize=0x2a554  RawSize=0x11e00  Char=0xc0000040 RWI
.pdata     VA=0x246000 VSize=0xbcd0   RawSize=0xbe00   Char=0x40000040 RI
.fptable   VA=0x252000 VSize=0x100    RawSize=0x200    Char=0xc0000040 RWI
.rsrc      VA=0x253000 VSize=0x1ac50  RawSize=0x1ae00  Char=0x40000040 RI
.reloc     VA=0x26e000 VSize=0x3004   RawSize=0x3200   Char=0x42000040 RI

Inplace (8 节):
[原 7 节完全相同]
.lock      VA=0x272000 VSize=0x1d30   RawSize=0x1e00   Char=0xe0000020 ERWC  ⚠ W+X
```

### 8.2 节区对比（原版 vs Reflective）

```
Reflective (18 节，stub 是 MinGW 编译):
.text      VA=0x1000   VSize=0xb6f0   RawSize=0xb800   Char=0x60000020 ERC
.data      VA=0xd000   VSize=0x120    RawSize=0x200    Char=0xc0000040 RWI
.rdata     VA=0xe000   VSize=0x28d0   RawSize=0x2a00   Char=0x40000040 RI
.pdata     VA=0x11000  VSize=0x4ec    RawSize=0x600    Char=0x40000040 RI
.xdata     VA=0x12000  VSize=0x4ac    RawSize=0x600    Char=0x40000040 RI
.bss       VA=0x13000  VSize=0xbb0    RawSize=0        Char=0xc0000080 RWU
.idata     VA=0x14000  VSize=0xba0    RawSize=0xc00    Char=0x40000040 RI
.tls       VA=0x15000  VSize=0x10     RawSize=0x200    Char=0xc0000040 RWI
.rsrc      VA=0x16000  VSize=0x4fe4   RawSize=0x5000   Char=0x40000040 RI
.reloc     VA=0x1b000  VSize=0x84     RawSize=0x200    Char=0x42000040 RI
/4         VA=0x1c000  ...                                     ⚠ COFF 长节名
/19        VA=0x1d000  ...
/31        VA=0x1f000  ...
/45        VA=0x20000  ...
/57        VA=0x21000  ...
/70        VA=0x22000  ...
/81        VA=0x23000  ...
.payload   VA=0x24000  VSize=0x256098 RawSize=0x256200  Char=0x40000040 RI  ⚠
```

### 8.3 导入表对比

```
原版 (12 DLLs / 484 funcs):
  COMCTL32.dll  (14 funcs)  InitCommonControlsEx, ...
  SHLWAPI.dll   (37 funcs)  PathCombineW, ...
  IMM32.dll     (9  funcs)  ImmEscapeW, ...
  UxTheme.dll   (2  funcs)  IsAppThemed, ...
  KERNEL32.dll  (149 funcs) GlobalLock, ...
  USER32.dll    (173 funcs) GetForegroundWindow, ...
  GDI32.dll     (48 funcs)  Ellipse, ...
  COMDLG32.dll  (6  funcs)  ChooseFontW, ...
  ADVAPI32.dll  (11 funcs)  RegQueryValueExW, ...
  SHELL32.dll   (20 funcs)  SHGetDesktopFolder, ...
  ole32.dll     (11 funcs)  OleUninitialize, ...
  OLEAUT32.dll  (4  funcs)  VariantClear, ...

Inplace (12 DLLs / 484 funcs):
  [与原版完全相同，IAT 保留]

Reflective (3 DLLs / 79 funcs):
  KERNEL32.dll  (37 funcs)  ActivateActCtx, AddVectoredExceptionHandler, ...
  msvcrt.dll    (38 funcs)  __C_specific_handler, ___lc_codepage_func, ...
  USER32.dll    (4  funcs)  DialogBoxIndirectParamW, EndDialog,
                            GetDlgItemTextW, MessageBoxW  ← 密码弹框 API
```
