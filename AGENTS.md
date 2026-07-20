# 必要的说明

- 开发过程不需要考虑旧版本的兼容性，不需要针对旧特性的兼容代码
- 所有回答都使用中文表述，为关键逻辑和代码添加简明的中文注释
- 持久化写入的文档放到docs目录，除非用户明确指定其它目录
- 测试用的临时文件放temp目录，保留的临时脚本和代码放到tests目录
- 如果某个开发阶段改动很大，请列出计划分步实施，修改后需要运行测试，确保不破坏已有的功能
- 每次功能改动任务完成后在 docs/CHANGES.md 中追加功能和改动简明概要，包括日期时间
- 可以使用系统已有的任何开发工具，可以自行搜索和使用系统PATH里已有的工具
- PowerShell优先使用新版pwsh，如果有问题，建议优先用python或node或bash写脚本
- 查找项目里的文件，如果使用内置工具找不到，可以使用系统的列目录和文件命令
- 如果访问网络出现问题，可以使用本地代理 127.0.0.1:7890

# 开发工具

- 开发工具 系统已经安装Visual Studio 2026 在默认目录，git/node/bun/npm/python/uv/pip/rust/go 都已安装
- 工具VENV C:\Home\Develop\venv 里面安装了一个常用包，包括invisible_playwright可以替代playwright
- CoreUtils C:\Home\Tools\coreutils\ 和 C:\Home\Develop\Git\git-bash.exe 可直接使用
- MSYS64 C:\Home\Develop\msys64 和 W64DevKit C:\Home\Develop\w64devkit 可直接使用，欠缺的包可自行安装
- 调试工具 C:\Home\Develop\WinDbg 和 C:\Home\Develop\x64dbg，上一项环境里的工具也可以使用

# 特别说明

- 直接在Powershell里运行复杂命令很容易出参数或编码问题，有些命令还会被判定为高危险，需要用户手工确认很麻烦，应该写临时脚本，用pwsh或python或node或bash运行，可以提高开发效率
- 开发PE相关功能时，如果遇到难以解决的问题，可以看看 F:\Temp\pe 这里的源码，找有没有现成的方案，也可以网络搜索解决办法和参考代码


