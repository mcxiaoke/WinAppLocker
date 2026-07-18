#!/usr/bin/env python3
"""枚举 WinLock 密码框的子窗口结构，帮助调试 pywinauto 控件查找"""
import sys
import time
from pywinauto.application import Application
from pywinauto.timings import TimeoutError as PWTimeoutError

DLG_TITLE = "WinLock - Password Required"

exe = sys.argv[1] if len(sys.argv) > 1 else r"test\hellogui_locked.exe"
print(f"[*] 启动 {exe}")
app = Application().start(exe)
print(f"[*] PID = {app.process}")

try:
    dlg = app.window(title=DLG_TITLE)
    dlg.wait("ready", timeout=10)
    print(f"[+] 密码框已出现")
    print("=== 控件树 ===")
    dlg.print_control_identifiers()
finally:
    app.kill()
