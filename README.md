# WinAppLocker

整体是一个给PE文件简单加密的工具，加密后的PE文件运行时会弹出密码对话框，输入密码后会启动原有程序，不修改原有PE的功能，仅支持Windows系统，支持X86和X64的EXE，不支持.NET的可执行程序，不支持DLL

子项目packer目前已作为可选stub集成到dotnet WinAppLocker主项目

- 子目录 packer 是PE加密码工具（原地修改PE文件）
- 子目录 dotnet 是主项目，包括GUI，临时文件释放的PE加密码工具
- 子目录 rust 是已废弃的PE加密工具，已停止开发，不用关注
- 子目录 temp\samples 存放着测试用的EXE文件