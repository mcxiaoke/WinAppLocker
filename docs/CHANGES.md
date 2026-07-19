# 变更记录

## 变更记录 2026-07-19 10:40

packer 日志详细度调整 + WinLock stub 改名 + IconCopier 字符串名 bug 修复

1. **加密开始日志补充 PE 信息**：GUI `btnPack_Click` 和 CLI `RunCliPack` 在调用 `PackCore.Pack`
   之前先用 `PeReader.Parse` 读取所选 exe 的 PE 关键属性，拼接成 `PE=[x64/GUI ASLR=True DEP=True
   CFG=True HEVA=True TLS=True Signed=True Reloc=True .NET=False size=4735888]` 形式，
   追加到 "开始加密" 日志行尾。这样即便用户中途清空了 `lblPeInfo` 显示，日志里也保留该
   exe 的关键属性用于事后排查。

2. **日志级别区分（[INFO] / [WARN]）**：`PackCore` 的 `logger` 回调是单个 `Action<string>`，
   无法直接传级别枚举。改为按消息前缀约定区分：包含 `WARN:` / `ERROR:` / `[stderr]` 的消息
   走 `AppLogger.Warn`，其余走 `AppLogger.Info`。IconCopier 的所有错误信息前缀改为
   `[IconCopier] WARN:` 以匹配此约定。

3. **WinLock builder 加 `--debug` 参数**：新增 `g_debug` 全局标志和 `DBG(fmt, ...)` 可变参数宏。
   所有 `[*]` 详情日志（PE 解析、节列表、reloc patch、stub_data 填充等）从 `printf` 改为
   `DBG()`，只在 `-v` / `--debug` 时输出。`[+]` / `[-]` / `[!]` 关键日志保持 always-on。
   目的：避免 packer 把 builder 的 stdout 全部记入 AppLogger 时日志过载。

4. **WinLock stub 文件名加 `winlock_` 前缀**：分发目录统一改名：
   - `stub_x64.bin` → `winlock_stub_x64.bin`
   - `stub_x86.bin` → `winlock_stub_x86.bin`
   - `stub_x86.exe` → `winlock_stub_x86.exe`
   - `builder.exe` → `winlock_builder.exe`（已沿用）
   
   `build.ps1` 拷贝 WinLock 产物到 `dotnet/packer/stub/` 时按新名拷贝；
   `winlock_builder.exe.meta.json` 的 `components` 字段同步更新引用新名；
   `builder.c` 的 stub 搜索路径优先用新名，向后兼容旧名 `stub_x{64,86}.bin` /
   `stub_x86.exe`（开发者直接 `make` 产出的源文件名）。

5. **IconCopier 修复 `FindResourceW(RT_GROUP_ICON) failed: 1814`**：
   - **根因**：`EnumResourceNamesW` 回调返回的 `lpName` 字符串只在回调期间有效，回调返回后
     字符串可能失效（特别是字符串名如 `"IDR_MAINFRAME"`）。旧实现把 `lpName` 的 `IntPtr`
     直接保存，回调结束后 `FindResourceW` 用失效指针找不到资源（ERROR_RESOURCE_NAME_NOT_FOUND=1814）。
   - **修复**：新增 `ResourceName` struct，在回调中检测 `lpName` 类型（IS_INTRESOURCE：
     高位 WORD == 0 表示整数 ID），若是字符串则用 `Marshal.StringToHGlobalUni` 复制到
     long-lived 非托管内存。`finally` 块中调用 `mainGroupName.Free()` 释放。
   - **验证**：Doubao.exe（字符串名 `"IDR_MAINFRAME"` 主图标）打包后日志显示
     `主图标 group="IDR_MAINFRAME", 引用 8 个 RT_ICON，共 10 个资源将写入`，无 1814 错误。

6. **README 补充 Stub 自动选择标准章节**：新增 "Stub 自动选择标准" 章节，说明
   `StubRegistry.Select` 的三级优先级（用户指定 > 按子系统匹配 > 任意可用）、
   `IsAvailable` / `SupportsMachine` 约束、WinLock 不被自动选中的原因、以及
   WinLock 对输入 PE 的限制条件（.NET / Console / DLL / ARM 等不支持情况）。

## 变更记录 2026-07-19 09:58 

packer 新增操作日志与 PE 信息展示

1. **操作日志**：所有关键操作（GUI 启动、stub 加载、打包开始/成功/失败、CLI 调用、PE 信息查询）
   均写入按天滚动的日志文件 `packer_YYYYMMDD.log`。日志目录优先选 `WinAppLocker.exe`
   同级 `logs/` 子目录；若无写权限，自动回退到 `%LOCALAPPDATA%\WinAppLocker\logs\`。
   日志写入通过 `lock` 保护线程安全，所有 IO 异常被吞掉，日志失败不影响主流程。

2. **PE 信息展示**：选择 exe 后在"执行加密操作"按钮上方小字位置自动展示 PE 关键信息，
   包括架构 (x86/x64/arm/arm64)、子系统 (GUI/Console)、ASLR / DEP / CFG / HighEntropyVA、
   TLS 回调、Authenticode 签名、重定位表、.NET CLR 托管、文件大小。.NET 或带签名程序
   用警告色（OrangeRed）提示。同时新增 CLI 命令 `--pe-info <exe>` 用于命令行查看。