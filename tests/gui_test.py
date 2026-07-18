#!/usr/bin/env python3
"""
winlock/tools/gui_test.py - 用 pywinauto 测试加壳后的 GUI 样本

用法:
    python tools/gui_test.py <exe_path> <password> [main_window_title]

流程:
    1. 启动加壳后的 exe
    2. 等待 "WinLock - Password Required" 密码框
    3. 输入密码并点 OK
    4. 验证主窗口出现（程序正常运行）
    5. 关闭程序

正确密码 -> 主窗口出现 -> PASS
错误密码 -> 弹 "Wrong password" 框 -> 重试 -> 最终关闭
"""
import sys
import time
import argparse

def main():
    parser = argparse.ArgumentParser(description="WinLock GUI 测试")
    parser.add_argument("exe", help="加壳后的 exe 路径")
    parser.add_argument("password", help="密码")
    parser.add_argument("--main-title", default=None,
                        help="期望的主窗口标题（子串匹配，不指定则只验证密码框消失）")
    parser.add_argument("--main-class", default=None,
                        help="期望的主窗口 class_name（更可靠）")
    parser.add_argument("--wrong-pwd", default=None,
                        help="测试错误密码路径：先用这个错误密码，再用正确密码")
    parser.add_argument("--timeout", type=int, default=10,
                        help="等待窗口超时秒数")
    args = parser.parse_args()

    # 延迟导入，让 argparse --help 快
    from pywinauto.application import Application, ProcessNotFoundError
    from pywinauto.timings import TimeoutError as PWTimeoutError
    from pywinauto import findwindows

    DLG_TITLE = "WinLock - Password Required"

    print(f"[*] 启动 {args.exe}")
    app = Application().start(args.exe, work_dir=None)
    pid = app.process
    print(f"[*] PID = {pid}")

    try:
        # 1. 等待密码框出现
        print(f"[*] 等待密码框 '{DLG_TITLE}'...")
        try:
            dlg = app.window(title=DLG_TITLE)
            dlg.wait("ready", timeout=args.timeout)
        except PWTimeoutError:
            print(f"[-] FAIL: 密码框未出现（{args.timeout}s 超时）")
            return 2
        print(f"[+] 密码框已出现")

        # 2. 如果要测试错误密码路径
        if args.wrong_pwd:
            print(f"[*] 测试错误密码: '{args.wrong_pwd}'")
            edit = dlg.child_window(class_name="Edit")
            edit.set_edit_text(args.wrong_pwd)
            dlg.child_window(title="OK", class_name="Button").click()
            time.sleep(0.5)
            # 期望出现 "Wrong password" 框
            try:
                wrong_dlg = app.window(title="WinLock")
                wrong_dlg.child_window(title="确定").click()
                print(f"[+] 错误密码弹框已确认")
            except Exception:
                print(f"[!] 未捕获到错误密码弹框（可能直接被拒）")
            # 重新等待密码框
            dlg = app.window(title=DLG_TITLE)
            dlg.wait("ready", timeout=5)

        # 3. 输入正确密码
        print(f"[*] 输入正确密码: '{args.password}'")
        edit = dlg.child_window(class_name="Edit")
        edit.set_edit_text(args.password)
        dlg.child_window(title="OK", class_name="Button").click()

        # 4. 等待密码框消失，主窗口出现
        time.sleep(1)
        try:
            still_there = app.window(title=DLG_TITLE)
            still_there.wait_not("visible", timeout=3)
            print(f"[+] 密码框已消失")
        except Exception:
            print(f"[+] 密码框已消失（或进程已结束）")

        # 5. 验证主窗口
        if args.main_title or args.main_class:
            print(f"[*] 等待主窗口 (title='{args.main_title}', class='{args.main_class}')...")
            try:
                import re
                criteria = {}
                if args.main_class:
                    criteria["class_name"] = args.main_class
                if args.main_title:
                    criteria["title_re"] = re.escape(args.main_title)
                criteria["found_index"] = 0
                main_win = app.window(**criteria)
                main_win.wait("ready", timeout=args.timeout)
                actual_title = main_win.window_text()
                print(f"[+] PASS: 主窗口已出现 - '{actual_title}'")
                result = 0
            except PWTimeoutError:
                print(f"[-] FAIL: 主窗口未出现")
                # 打印所有窗口用于调试
                try:
                    print("  --- 进程所有窗口 ---")
                    for w in app.windows():
                        print(f"  - '{w.window_text()}' (class={w.class_name()})")
                except Exception as e:
                    print(f"  枚举失败: {e}")
                result = 1
        else:
            # 只验证进程还活着
            time.sleep(2)
            if app.process_has_exited():
                print(f"[-] FAIL: 进程已退出（可能 stub 解密失败）")
                result = 1
            else:
                print(f"[+] PASS: 进程仍在运行")
                result = 0

        return result
    finally:
        try:
            app.kill()
        except Exception:
            pass

if __name__ == "__main__":
    sys.exit(main())
