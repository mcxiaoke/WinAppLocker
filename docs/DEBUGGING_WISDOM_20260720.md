# Packer Inplace Bug 调试复盘记录

> 日期: 2026-07-20
> 问题: hellomfcx86 inplace_test/inplace_password crash exit=2
> 根因: MinGW x86 -O2 优化导致 SHA-256 计算错误

---

## 一、问题背景

### 症状

端到端测试 3 个 fail，用户要求排查 inplace packer 代码：

```
hellomfcx86 inplace_test     CRASH exit=2        ← 本文分析的
hellomfcx86 inplace_password CRASH exit=2        ← 同一根因
DontSleep    reflective_test CRASH exit=0xC0000005 ← 不同问题，未涉及
```

关键线索：**hellomfcx86 reflective 全部 PASS**，说明 SHA-256 算法 / PEB walk / 导出表解析代码本身正确。
唯一区别是 **inplace 使用 MinGW 编译的 stub**，reflective 使用 MSVC 编译的 stub。

---

## 二、调试步骤（按时间顺序）

### 第一步：代码全面审查（2 小时，无果）

**做了什么**：
- 逐行读 `builder.c`：PE 解析、节表创建、加密逻辑、stub_data 填充
- 逐行读 `stub.c`：PEB walk、导出表解析、verify_password、XTEA 解密
- 读 `config.h` / `sha256.h` / `peb_walk.h` / `xtea.h` / `winlock_compat.h`

**踩坑**：
- ❌ 试图"用眼睛找 bug"：代码逻辑都正确，节表/数据目录/stub_data 全部正确
- ❌ 反复怀疑 PEB_LDR_DATA 结构体偏移错误 — 其实是正确的（Windows 10 19041）
- ❌ 怀疑 hash 碰撞 — 其实没有
- ❌ 怀疑 salt 只初始化 4 字节 — 实际 `memcpy(sd->salt, salt, 16)` 全量复制

**教训**：纯静态分析无法发现 runtime optimizer bug。当"代码看起都正确"时，必须用 runtime 手段定位。

### 第二步：验证输出 PE 结构（1 小时）

**做了什么**：
- 用 Python/v1 脚本 dump 输出 PE 的 headers、节表、数据目录
- 用 Python 验证 stub_data.salt/pwd_hash 与 BCrypt 输出完全一致

**踩坑**：
- ❌ Python 脚本读取 `SizeOfOptionalHeader` 用错了偏移！  
  错：`struct.unpack_from("<H", data, elf + 0x10)`  
  对：`struct.unpack_from("<H", data, elf + 4 + 16)`  
  前者是 `e_lfanew + 16`，后者才是 `FileHeader + 16 = e_lfanew + 20`  
  差 4 字节导致误判 `opt_sz=0x74`（实际 0xE0），差点误导认为 MinGW PE 头部无效

**教训**：PE 解析脚本极易出偏移错误，每读一个字段都要验证偏移是否正确。
用成熟的工具（dumpbin/pev/readpe）做交叉验证。

### 第三步：验证 112 项 reloc 修补（0.5 小时）

**做了什么**：
- 对输出 PE 逐一检查 4 个 fn 指针的 reloc 修补值
- 全部正确：`0x12EF4 + 0x435000 = 0x447EF4` ✅
- 验证 fs:`[0x30]` PEB 读取指令存在 ✅

**结论**：.reloc 修补正确，stub 代码应该能正确访问所有全局变量。

### 第四步：cdb 调试（1.5 小时，最重要的步骤）

**做了什么**：
- 64 位 cdb 附加 WOW64 进程 → 不正确（停在 LdrInitShimEngineDynamic）
- 32 位 cdb 附加 → 正确！显示进程先加载所有 DLL，然后 `bp kernel32!ExitProcess` 命中

**关键输出**：
```
KERNEL32!ExitProcess
hellomfc+0x461d0     ← 在 .lock 节内调用 ExitProcess
KERNEL32!BaseThreadInitThunk
ntdll!RtlGetAppContainerNamedObjectPath
```

**分析**：
- ExitProcess 被正确调用（说明 fn.ExitProcess 正确解析）
- 调用地址在 .lock 节 → stub 代码在运行
- exit code = 2 说明 stub 主动进入 `fail:` 路径

**踩坑**：
- ❌ 64 位 cdb 调试 WOW64 进程会停在 WOW64 breakpoint，然后 process exit  
  误判为 "loader initialization crash" → 浪费大量时间
- ✅ 32 位 cdb 才能正确调试 WOW64 进程的 32 位代码

**教训**：调试 WOW64 进程必须用 32 位调试器！

### 第五步：插入 debug_step 定位失败点（0.5 小时，关键突破）

**做了什么**：
- 在 stub.c 中加 `volatile int debug_step = 0`
- 每个 `goto fail` 前设不同值：10/20/30/31
- `fail:` 路径改为 `ExitProcess(debug_step)`

**结果**：exit code = **30** → fail 点在 **test mode verify_password**

**分析**：
- 10（PEB walk）和 20（API resolve）没有触发 → PEB walk 和 导出表解析正确
- 30（verify_password hash mismatch）→ **SHA-256 hash 不匹配！**

**这个步骤是找到根因的关键**。之前所有的静态分析和 PE 结构验证都没有定位到这个点。

### 第六步：隔离 SHA-256 optimizer bug（0.5 小时，最终根因）

**做了什么**：
- `sha256.h` 的 WINLOCK_FN 宏加 `optimize("O0")`
- 重建 stub，测试 → hellomfcx86 正常运行！✅

**结论**：MinGW x86 `-O2` 产生错误的 `sha256_transform` 或 `sha256_final` 机器码。

---

## 三、本次调试使用的工具清单

| 工具 | 用途 | 成功/失败 |
|------|------|-----------|
| 眼睛 | 代码审查 | ❌ 未发现 optimizer bug |
| Python | PE 结构验证 | ✅ 可用于验证已知字段 |
| Python + hashlib | SHA-256 交叉校验 | ✅ 确认 builder 输出正确 |
| 64 位 cdb | WOW64 进程调试 | ❌ 误导（不能用于 WOW64） |
| 32 位 cdb | WOW64 进程调试 | ✅ 正确显示调用栈 |
| `debug_step` 变量 | 运行时定位失败点 | ✅ 关键突破 |
| `optimize("O0")` 隔离 | 验证 optimizer bug | ✅ 最终确认 |

---

## 四、踩坑记录（经验教训）

### 坑 1：静态分析无法发现 optimizer bug

**症状**：代码看起完全正确、SHA-256 实现经过 host 测试验证

**教训**：
- 同一个 C 源码在不同编译器/优化级别下行为可能不同
- "实现已测试过"不意味着"这个优化级别下也正确"
- 遇到"代码正确但运行时行为异常"时，考虑 optimizer bug

### 坑 2：错误使用 64 位 cdb 调试 WOW64 进程

**症状**：在 LdrInitShimEngineDynamic 处停止，process 立即退出

**教训**：
- WOW64（32 位进程在 64 位 Windows 上）必须用 32 位 cdb
- 64 位 cdb 看到的只是 WOW64 层的初始化，不是 32 位进程的真实执行

### 坑 3：PE 解析脚本偏移错误

**症状**：错误读取 SizeOfOptionalHeader（0x74 而非 0xE0）

**教训**：
- 每个 PE 字段的偏移都要对照规范验证
- `windows.h` 的 struct 布局可能和手写 `struct.unpack_from` 偏移不同
- 交叉验证：用 dumpbin / pev 确认

### 坑 4：PowerShell 输出被 CLIXML 污染

**症状**：`Write-Host` 输出夹杂 `#< CLIXML` 和 `Set-PSReadLineOption` 错误

**教训**：
- PowerShell 的 stdout/stderr 在处理非标准事件时会产生混乱
- 替代方案：
  - `cmd /c "command > file 2>&1"` 重定向到文件再用 type 读
  - `python -c "..."` 直接写文件
  - git-bash / msys2 shell

### 坑 5：忽略"其他样本都通过"的线索

**症状**：所有 x64 和简单 x86 样本都通过，只有 MFC x86 失败

**教训**：
- 如果大多数测试通过，少数有特定特征的失败（如 MFC x86），
  不要从通用代码路径入手查，应从 **差异** 入手
- MFC 类 app 加载更多 DLL（mfc140u, VCRUNTIME140），但这不是根因
- **真正的差异**是 MinGW x86 -O2 编译的 SHA-256 有 bug，MFC app 正好触发了

### 坑 6：过早在"数据一致性"上花大量时间

**做了什么**：验证 stub_data.salt/pwd_hash 在输出 PE 中的值正确、验证 SHA-256 三端一致

**教训**：
- builder 端的 hash 计算正确不能推断 stub 端的 hash 计算也正确
- "数据正确"不等同于"代码正确"

---

## 五、推荐的调试流程（未来参考）

### 当遇到"process exits with unexpected code"时：

```
1. 问题范围确认
   ├── 哪些样本/模式通过？哪些不通过？
   ├── 通过和不通过的差异是什么？
   └── 是否与编译工具链相关？

2. 基础验证（Python 脚本）
   ├── 输出 PE headers / 节表 / 数据目录
   ├── 关键字段（EP, SizeOfImage, NumberOfSections）
   └── stub_data 字段（magic, flags, oep_rva, salt, hash）

3. 运行时定位（debug_step + cdb）
   ├── 在 stub 各关键路径加 debug_step
   ├── 用 32 位 cdb 设断点在 ExitProcess
   └── 根据 exit code 定位到具体失败步骤

4. 隔离验证
   ├── 改变优化级别（-O0 vs -O2）
   ├── 改变编译器（MinGW vs MSVC）
   └── 确认根因后做最小化修复

5. 回归测试
   ├── 完整 e2e 矩阵
   └── 对比修复前后的通过率
```

### 关键经验总结

- **输出 PE 正确 ≠ stub 运行时正确** — 数据一致性验证只能排除数据问题
- **"代码看起都正确"不一定正确** — optimizer bug 不看源码
- **32 位 cdb 是调试 WOW64 进程的必要工具** — 64 位 cdb 会给出误导结果
- **debug variables 是最简单的运行时定位手段** — 在可疑路径插入 step 变量，比分析堆栈更直接
- **编译器差异是最容易被忽视的 bug 来源** — 同一个 .c 文件在不同编译器下行为不同

---

## 六、附录：关键命令速查

```powershell
# 32 位 cdb 调试 ExitProcess
"C:\Program Files (x86)\Windows Kits\8.1\Debuggers\x86\cdb.exe" `
    -c "sxd ld; sxd bp; sxd ibp; bp kernel32!ExitProcess; g; kbn; q" `
    -o "path\to\packed.exe"

# MinGW x86 重建 stub
$gcc = "C:\Home\Develop\msys64\mingw32\bin\gcc.exe"
$objcopy = "C:\Home\Develop\msys64\mingw32\bin\objcopy.exe"
& $gcc -Wall -Wextra -O2 -ffreestanding -fno-stack-protector -fno-pic -fno-pie `
    -DWINLOCK_STUB -Icommon -c inplace/stub.c -o stub.o
& $gcc -nostdlib -nostartfiles -Wl,-subsystem,windows -Wl,-e,stub_entry `
    -Wl,-T,inplace/stub.ld -Wl,--gc-sections -Wl,--build-id=none `
    -Wl,--image-base=0x10000 stub.o -o stub.exe
& $objcopy -O binary -j .lock stub.exe stub.bin

# Python SHA-256 校验
python -c "import hashlib; data=open('packed.exe','rb').read(); salt=data[0x45350:0x45350+16]; print(hashlib.sha256(b'test123'+salt).hexdigest())"
```
