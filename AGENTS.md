# 通用约定

## 一些说明

- 所有回答都使用中文表述，为关键逻辑和代码添加简明的中文注释  
- 持久化写入的文档放到docs目录，除非用户明确指定其它位置，每次功能改动后在 docs/CHANGES.md 顶部追加简明概要，包括日期时间  
- 如果开发阶段改动很大，请列出计划分步实施，修改后需要测试，不破坏已有的功能  
- 可以使用系统已有的任何开发工具，可以自行搜索和使用系统PATH里已有的工具  
- 如果访问网络出现问题，可以使用本地代理 127.0.0.1:7890  
- PowerShell优先使用pwsh，直接Powershell里运行复杂命令容易出参数或编码问题，优先写临时脚本，用pwsh或python或node或bash运行  

## 开发工具

- 开发工具 系统已经安装Visual Studio 2026 在默认目录，git/node/bun/npm/python/uv/pip/rust/go 都已安装
- 工具VENV C:\Home\Develop\venv 里面安装了一个常用包，包括invisible_playwright可以替代playwright
- CoreUtils C:\Home\Tools\coreutils\ 和 C:\Home\Develop\Git\git-bash.exe 可直接使用
- MSYS64 C:\Home\Develop\msys64 和 W64DevKit C:\Home\Develop\w64devkit 可直接使用，欠缺的包可自行安装
- 调试工具 C:\Home\Develop\WinDbg 和 C:\Home\Develop\x64dbg，上一项环境里的工具也可以使用

# 项目特定

## 必要的说明

- 开发过程不需要考虑旧版本的兼容性，不需要针对旧特性的兼容代码
- 测试用的临时文件放temp目录，保留的临时脚本和代码放到tests目录
- 测试样本PE文件都在 temp/samples 目录，如果找不到就用系统命令找
- 如果遇到难以解决的问题，可以看看 F:\Temp\pe 这里的源码，找有没有现成的方案

## 项目地图

不确定文件 / 工具 / 样本在哪时，**不要凭记忆去猜**

| 类别 | 位置 | 说明 |
|------|------|------|
| 测试样本(PE) | `temp/samples/` | 所有 PE 测试样本 |
| 测试代码/脚本 | `tests/` | 保留的脚本 |
| 临时文件 | `temp/` | 临时产物，不用提交 |
| 构建产物 | `dist/` | 编译输出 exe/json |
| 文档 | `docs/` | DEVENV.md(工具全表) / CHANGES.md |
| 开发工具全表 | `docs/DEVENV.md` | 编译器/调试器等 |



