"""
test_apps_batch.py - 批量加壳测试

依赖：winlock/.venv 下的 pywinauto + psutil
  - 用 uv pip install psutil 安装（pywinauto 已预装）

流程：对每个样本 exe：
  1. builder 加壳 → <name>_locked.exe（输出到原 exe 同目录）
  2. 在原目录启动 _locked.exe（保证依赖 DLL 能找到）
  3. 用 Win32 API 找到 "WinLock - Password Required" 密码框
  4. 向 Edit 控件发送密码，点击 OK 按钮（用 SendMessage，可靠）
  5. 等待主程序窗口出现（轮询进程树的所有可见窗口）
  6. 杀掉整个进程树
"""

import os
import sys
import time
import subprocess
import ctypes
from ctypes import wintypes

import psutil
from pywinauto import Desktop


# ---- Win32 API 绑定（用于密码框操作，避免 pywinauto API 差异）----

user32 = ctypes.WinDLL("user32", use_last_error=True)

WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL
user32.EnumChildWindows.argtypes = [wintypes.HWND, WNDENUMPROC, wintypes.LPARAM]
user32.EnumChildWindows.restype = wintypes.BOOL
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = wintypes.INT
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, wintypes.INT]
user32.GetWindowTextW.restype = wintypes.INT
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, wintypes.INT]
user32.GetClassNameW.restype = wintypes.INT
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
# 注意：SendMessageW 既要传整数 lParam（BM_CLICK）又要传字符串指针（WM_SETTEXT），
# 一个 argtypes 绑定无法同时支持两种类型，所以用两个独立的函数指针绑定
_user32_str = ctypes.WinDLL("user32", use_last_error=True)
_user32_int = ctypes.WinDLL("user32", use_last_error=True)

_user32_str.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, ctypes.c_wchar_p]
_user32_str.SendMessageW.restype = wintypes.LPARAM
_user32_int.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_user32_int.SendMessageW.restype = wintypes.LPARAM

WM_SETTEXT = 0x000C
BM_CLICK = 0x00F5

DIALOG_TITLE = "WinLock - Password Required"


def _get_window_text(hwnd):
    length = user32.GetWindowTextLengthW(hwnd)
    if length == 0:
        return ""
    buf = ctypes.create_unicode_buffer(length + 2)
    user32.GetWindowTextW(hwnd, buf, length + 2)
    return buf.value


def _get_window_class(hwnd):
    buf = ctypes.create_unicode_buffer(64)
    user32.GetClassNameW(hwnd, buf, 64)
    return buf.value


def _get_window_pid(hwnd):
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def find_password_dialog_hwnd(timeout_sec=15, proc=None):
    """用 EnumWindows 找密码框窗口句柄。
    如果传入 proc（subprocess.Popen），进程退出时立即返回 None。"""
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        # 如果目标进程已退出，无需再等
        if proc is not None and proc.poll() is not None:
            return None
        found = []
        def cb(hwnd, _):
            if not user32.IsWindowVisible(hwnd):
                return True
            if _get_window_text(hwnd) == DIALOG_TITLE:
                found.append(hwnd)
                return False
            return True
        user32.EnumWindows(WNDENUMPROC(cb), 0)
        if found:
            return found[0]
        time.sleep(0.2)
    return None


def _find_child(parent, cls_name=None, text=None):
    """在子窗口中按 class/text 查找"""
    found = []
    def cb(hwnd, _):
        cls = _get_window_class(hwnd)
        txt = _get_window_text(hwnd)
        if cls_name is not None and cls != cls_name:
            return True
        if text is not None and txt != text:
            return True
        found.append(hwnd)
        return False
    user32.EnumChildWindows(parent, WNDENUMPROC(cb), 0)
    return found[0] if found else None


def input_password_and_ok(dialog_hwnd, password):
    """在密码框中输入密码并点 OK（用 SendMessage，最可靠）"""
    edit = _find_child(dialog_hwnd, "Edit", None)
    if not edit:
        return False, "edit not found"

    # 发送密码文本
    _user32_str.SendMessageW(edit, WM_SETTEXT, 0, password)

    # 找 OK 按钮
    ok_btn = _find_child(dialog_hwnd, "Button", "OK")
    if not ok_btn:
        # 退化：找第一个 Button
        ok_btn = _find_child(dialog_hwnd, "Button", None)
        if not ok_btn:
            return False, "OK button not found"

    _user32_int.SendMessageW(ok_btn, BM_CLICK, 0, 0)
    return True, "ok"


def get_process_windows(pid_set):
    """枚举进程树中所有可见窗口"""
    result = []
    def cb(hwnd, _):
        if not user32.IsWindowVisible(hwnd):
            return True
        title = _get_window_text(hwnd)
        if title == DIALOG_TITLE:
            return True
        wpid = _get_window_pid(hwnd)
        if wpid in pid_set:
            cls = _get_window_class(hwnd)
            result.append((wpid, cls, title))
        return True
    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return result


# ---- 进程管理 ----

def kill_process_tree(root_pid):
    """杀掉整个进程树"""
    try:
        parent = psutil.Process(root_pid)
        for child in parent.children(recursive=True):
            try:
                child.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        parent.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass


def kill_by_name(name):
    """按进程名杀进程（不带扩展名）"""
    for p in psutil.process_iter(["name", "pid"]):
        try:
            if p.info["name"] and p.info["name"].lower() == (name + ".exe").lower():
                kill_process_tree(p.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    time.sleep(0.5)


def get_descendant_pids(root_pid):
    """获取进程树所有 PID"""
    pids = {root_pid}
    try:
        parent = psutil.Process(root_pid)
        for child in parent.children(recursive=True):
            pids.add(child.pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return pids


# ---- 主测试逻辑 ----

BUILDER = r"F:\Temp\pe\winlock\builder\builder.exe"
PASSWORD = "test"

SAMPLES = [
    ("avidemux", r"C:\Home\Apps\Avidemux\avidemux.exe"),
    ("Doubao",    r"C:\Home\Apps\Doubao\Doubao.exe"),
    ("HeidiSQL",  r"C:\Home\Apps\HeidiSQL\heidisql.exe"),
    ("MPC-BE",    r"C:\Home\Apps\MPC-BE\mpc-be64.exe"),
    ("NTLite",    r"C:\Home\Apps\NTLite\NTLite.exe"),
    ("Quark",     r"C:\Home\Apps\Quark\quark.exe"),
    ("Shotcut",   r"C:\Home\Apps\Shotcut\shotcut.exe"),
    ("Wireshark", r"C:\Home\Apps\Wireshark\Wireshark.exe"),
    ("XnViewMP",  r"C:\Home\Apps\XnViewMP\xnviewmp.exe"),
    ("totalcmd",  r"C:\Home\Apps\totalcmd\tcrun64.exe"),
]


def main():
    results = []
    for name, exe in SAMPLES:
        print()
        print("=" * 70)
        print(f"[{name}] {exe}")
        print("=" * 70)

        if not os.path.exists(exe):
            print("[SKIP] exe not found")
            results.append((name, "SKIP", "exe not found"))
            continue

        out_dir = os.path.dirname(exe)
        base = os.path.splitext(os.path.basename(exe))[0]
        out_exe = os.path.join(out_dir, base + "_locked.exe")

        # 清理旧文件 + 杀残留进程
        try:
            os.remove(out_exe)
        except OSError:
            pass
        kill_by_name(base + "_locked")
        kill_by_name(base)

        # 1. 加壳
        print("[1] Packing...")
        pack = subprocess.run(
            [BUILDER, "-i", exe, "-o", out_exe, "-p", PASSWORD],
            capture_output=True, text=True
        )
        if pack.returncode != 0 or not os.path.exists(out_exe):
            print(f"[FAIL] pack failed (exit={pack.returncode})")
            for line in pack.stdout.splitlines()[-3:]:
                print(f"    {line}")
            for line in pack.stderr.splitlines()[-3:]:
                print(f"    {line}")
            results.append((name, "PACK_FAIL", f"exit={pack.returncode}"))
            continue

        size_kb = os.path.getsize(out_exe) // 1024
        print(f"[OK] packed: {out_exe} ({size_kb} KB)")

        # 2. 启动（工作目录设为 exe 所在目录，保证依赖 DLL 能找到）
        print("[2] Launching...")
        try:
            proc = subprocess.Popen(
                [out_exe],
                cwd=out_dir,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
        except OSError as e:
            print(f"[FAIL] launch failed: {e}")
            results.append((name, "LAUNCH_FAIL", str(e)))
            continue

        print(f"[OK] PID={proc.pid}")
        time.sleep(3)

        # 3. 输入密码
        print("[3] Sending password...")
        dlg_hwnd = find_password_dialog_hwnd(timeout_sec=15, proc=proc)
        if not dlg_hwnd:
            # 检查进程是否还在运行（可能被杀软拦了）
            if proc.poll() is not None:
                print(f"[FAIL] process exited (code={proc.poll()}) before dialog appeared")
                results.append((name, "CRASH", f"exit code {proc.poll()}"))
                continue
            print("[FAIL] password dialog not found (process still running)")
            kill_process_tree(proc.pid)
            results.append((name, "PWD_FAIL", "dialog not found"))
            continue

        ok, msg = input_password_and_ok(dlg_hwnd, PASSWORD)
        print(f"    {'OK' if ok else 'ERR'}: {msg}")
        if not ok:
            kill_process_tree(proc.pid)
            results.append((name, "PWD_FAIL", msg))
            continue

        # 等密码框关闭
        time.sleep(2)

        # 4. 等待主程序窗口（轮询 25 秒）
        print("[4] Waiting for main app window (up to 25s)...")
        main_windows = []
        for i in range(25):
            time.sleep(1)
            ret = proc.poll()
            if ret is not None:
                print(f"[FAIL] process exited with code {ret}")
                break
            pid_set = get_descendant_pids(proc.pid)
            main_windows = get_process_windows(pid_set)
            if main_windows:
                time.sleep(1)
                break

        if proc.poll() is not None:
            results.append((name, "CRASH", f"exit code {proc.poll()}"))
            continue

        # 最终再枚举一次
        pid_set = get_descendant_pids(proc.pid)
        main_windows = get_process_windows(pid_set)

        print(f"[OK] {len(main_windows)} visible windows across {len(pid_set)} processes:")
        for wpid, cls, txt in main_windows[:3]:
            print(f"    pid={wpid} cls={cls} txt='{txt}'")

        # 5. 杀掉进程树
        kill_process_tree(proc.pid)
        time.sleep(0.5)

        if main_windows:
            print("[OK] SUCCESS - main window detected")
            results.append((name, "OK", f"{len(main_windows)} windows"))
        else:
            print("[WARN] no visible window (may be CLI or delayed startup)")
            results.append((name, "NO_WINDOW", "process running but no window"))

    # 总结
    print()
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    print(f"{'Name':<12} {'Result':<12} {'Reason'}")
    print("-" * 70)
    for name, result, reason in results:
        print(f"{name:<12} {result:<12} {reason}")


if __name__ == "__main__":
    main()
