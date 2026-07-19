# 必要的说明

- 所有回答都使用中文表述，为关键逻辑和可能造成理解困难的代码添加简明准确的中文注释
- 持久化写入的文档放到docs目录，除非用户明确指定，如果是子项目相关文档，就写入到子项目的docs目录
- 子项目测试用的临时文件放到子项目的temp目录，子项目保留的临时脚本和临时代码放到子项目tests目录
- 如果需要删除项目中不需要保留的文件，可以用移动到temp目录代替，因为高风险命令需要手动确认很麻烦
- 如果某个开发阶段改动很大，请列出计划分步实施，修改后需要运行测试，确保不破坏已有的功能
- 每次功能改动任务完成后在 docs/CHANGES.md 中追加功能和修复改动**简明**概要，包括日期时间
- 可以使用系统已有的任何开发工具，可以自行搜索和使用系统PATH里已有的工具
- PowerShell优先使用新版pwsh，如果有问题，建议优先用python或node或bash写脚本
- 如果一个问题过于复杂很长时间都无法解决，请停下来总结并报告给用户，询问用户的意见
- 查找项目里的文件，如果使用内置工具找不到，可以使用系统的列目录和文件命令
- 如果访问网络出现问题，可以使用本地代理 127.0.0.1:7890

# 已有的开发工具

- 开发工具 系统已经安装Visual Studio 2026 在默认目录，git/node/bun/npm/python/uv/pip/rust/go 都已安装
- 工具VENV C:\Home\Develop\venv 里面安装了一个常用包，包括invisible_playwright可以替代playwright
- CoreUtils C:\Home\Tools\coreutils\ 和 C:\Home\Develop\Git\git-bash.exe 可直接使用
- MSYS64 C:\Home\Develop\msys64 和 W64DevKit C:\Home\Develop\w64devkit 可直接使用，欠缺的包可自行安装
- 调试工具 C:\Home\Develop\WinDbg 和 C:\Home\Develop\x64dbg，上一项环境里的工具也可以使用


