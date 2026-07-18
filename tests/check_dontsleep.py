#!/usr/bin/env python3
"""启动加壳后的程序，输入密码，然后列出所有窗口标题"""
import sys
import time
from pywinauto.application import Application

DLG_TITLE = "WinLock - Password Required"
exe = sys.argv[1] if len(sys.argv) > 1 else r"test\DontSleep_locked.exe"
pwd = sys.argv[2] if len(sys.argv) > 2 else "hello123"

print(f"[*] 启动 {exe}")
app = Application().start(exe)
print(f"[*] PID = {app.process}")

try:
    dlg = app.window(title=DLG_TITLE)
    dlg.wait("ready", timeout=15)
    print(f"[+] 密码框已出现")
    edit = dlg.child_window(class_name="Edit")
    edit.set_edit_text(pwd)
    dlg.child_window(title="OK", class_name="Button").click()
    print(f"[*] 已输入密码并点 OK")

    # 等待密码框消失
    time.sleep(3)

    # 列出该进程的所有窗口
    print("=== 进程的所有窗口 ===")
    try:
        windows = app.windows()
        for w in windows:
            print(f"  - '{w.window_text()}' (class={w.class_name()})")
    except Exception as e:
        print(f"  枚举失败: {e}")

    # 列出系统所有可见窗口（标题非空）
    print("=== 系统所有可见窗口 ===")
    from pywinauto import findwindows
    try:
        all_wins = findwindows.find_elements(active_only=True)
        for w in all_wins:
            if w.name:
                print(f"  - '{w.name}'")
    except Exception as e:
        print(f"  枚举失败: {e}")

    # 检查进程是否还在
    if app.process_has_exited():
        print(f"[-] 进程已退出，exit code = {app.exit_code()}")
    else:
        print(f"[+] 进程仍在运行")
finally:
    try:
        app.kill()
    except Exception:
        pass
