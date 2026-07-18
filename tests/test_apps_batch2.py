"""test_apps_batch2.py - 测试后半批样本"""
import os, sys, time, subprocess, ctypes
from ctypes import wintypes
import psutil

user32 = ctypes.WinDLL("user32", use_last_error=True)
_user32_str = ctypes.WinDLL("user32", use_last_error=True)
_user32_int = ctypes.WinDLL("user32", use_last_error=True)

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
_user32_str.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, ctypes.c_wchar_p]
_user32_str.SendMessageW.restype = wintypes.LPARAM
_user32_int.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_user32_int.SendMessageW.restype = wintypes.LPARAM

WM_SETTEXT = 0x000C
BM_CLICK = 0x00F5
DIALOG_TITLE = "WinLock - Password Required"

def _gwtext(h):
    n = user32.GetWindowTextLengthW(h)
    if not n: return ""
    b = ctypes.create_unicode_buffer(n+2)
    user32.GetWindowTextW(h, b, n+2)
    return b.value

def _gwcls(h):
    b = ctypes.create_unicode_buffer(64)
    user32.GetClassNameW(h, b, 64)
    return b.value

def _gwpid(h):
    p = wintypes.DWORD()
    user32.GetWindowThreadProcessId(h, ctypes.byref(p))
    return p.value

def find_dlg(timeout_sec=15, proc=None):
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if proc and proc.poll() is not None: return None
        found = []
        def cb(h, _):
            if not user32.IsWindowVisible(h): return True
            if _gwtext(h) == DIALOG_TITLE:
                found.append(h); return False
            return True
        user32.EnumWindows(WNDENUMPROC(cb), 0)
        if found: return found[0]
        time.sleep(0.2)
    return None

def find_child(parent, cls=None, text=None):
    found = []
    def cb(h, _):
        c = _gwcls(h); t = _gwtext(h)
        if cls and c != cls: return True
        if text and t != text: return True
        found.append(h); return False
    user32.EnumChildWindows(parent, WNDENUMPROC(cb), 0)
    return found[0] if found else None

def input_pwd(dlg, pwd):
    edit = find_child(dlg, "Edit")
    if not edit: return False, "edit not found"
    _user32_str.SendMessageW(edit, WM_SETTEXT, 0, pwd)
    ok = find_child(dlg, "Button", "OK") or find_child(dlg, "Button")
    if not ok: return False, "no buttons"
    _user32_int.SendMessageW(ok, BM_CLICK, 0, 0)
    return True, "ok"

def enum_proc_wins(pid_set):
    res = []
    def cb(h, _):
        if not user32.IsWindowVisible(h): return True
        t = _gwtext(h)
        if t == DIALOG_TITLE: return True
        p = _gwpid(h)
        if p in pid_set:
            res.append((p, _gwcls(h), t))
        return True
    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return res

def kill_tree(pid):
    try:
        pr = psutil.Process(pid)
        for c in pr.children(recursive=True):
            try: c.kill()
            except: pass
        pr.kill()
    except: pass

def kill_name(n):
    for p in psutil.process_iter(["name","pid"]):
        try:
            if p.info["name"] and p.info["name"].lower() == (n+".exe").lower():
                kill_tree(p.info["pid"])
        except: pass
    time.sleep(0.5)

def desc_pids(root):
    pids = {root}
    try:
        pr = psutil.Process(root)
        for c in pr.children(recursive=True): pids.add(c.pid)
    except: pass
    return pids

BUILDER = r"F:\Temp\pe\winlock\builder\builder.exe"
PASSWORD = "test"

SAMPLES = [
    ("Shotcut",   r"C:\Home\Apps\Shotcut\shotcut.exe"),
    ("Wireshark", r"C:\Home\Apps\Wireshark\Wireshark.exe"),
    ("XnViewMP",  r"C:\Home\Apps\XnViewMP\xnviewmp.exe"),
    ("totalcmd",  r"C:\Home\Apps\totalcmd\tcrun64.exe"),
]

def main():
    results = []
    for name, exe in SAMPLES:
        print(); print("="*70); print(f"[{name}] {exe}"); print("="*70)
        if not os.path.exists(exe):
            print("[SKIP]"); results.append((name,"SKIP","exe not found")); continue
        out_dir = os.path.dirname(exe)
        base = os.path.splitext(os.path.basename(exe))[0]
        out_exe = os.path.join(out_dir, base + "_locked.exe")
        try: os.remove(out_exe)
        except: pass
        kill_name(base + "_locked"); kill_name(base)

        print("[1] Packing...")
        pack = subprocess.run([BUILDER,"-i",exe,"-o",out_exe,"-p",PASSWORD], capture_output=True, text=True)
        if pack.returncode != 0 or not os.path.exists(out_exe):
            print(f"[FAIL] pack exit={pack.returncode}")
            for l in pack.stdout.splitlines()[-3:]: print(f"    {l}")
            results.append((name,"PACK_FAIL",f"exit={pack.returncode}")); continue
        print(f"[OK] packed {os.path.getsize(out_exe)//1024} KB")

        print("[2] Launching...")
        try:
            proc = subprocess.Popen([out_exe], cwd=out_dir,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        except OSError as e:
            print(f"[FAIL] launch: {e}"); results.append((name,"LAUNCH_FAIL",str(e))); continue
        print(f"[OK] PID={proc.pid}")
        time.sleep(3)

        print("[3] Sending password (30s timeout for slow starters)...")
        dlg = find_dlg(timeout_sec=30, proc=proc)
        if not dlg:
            if proc.poll() is not None:
                print(f"[FAIL] process exited code={proc.poll()}")
                results.append((name,"CRASH",f"exit {proc.poll()}")); continue
            print("[FAIL] no dialog")
            kill_tree(proc.pid); results.append((name,"PWD_FAIL","dialog not found")); continue
        ok, msg = input_pwd(dlg, PASSWORD)
        print(f"    {'OK' if ok else 'ERR'}: {msg}")
        if not ok:
            kill_tree(proc.pid); results.append((name,"PWD_FAIL",msg)); continue
        time.sleep(2)

        print("[4] Waiting for main window (up to 30s)...")
        wins = []
        for _ in range(30):
            time.sleep(1)
            if proc.poll() is not None:
                print(f"[FAIL] exited code={proc.poll()}"); break
            wins = enum_proc_wins(desc_pids(proc.pid))
            if wins: time.sleep(1); break
        if proc.poll() is not None:
            results.append((name,"CRASH",f"exit {proc.poll()}")); continue
        wins = enum_proc_wins(desc_pids(proc.pid))
        print(f"[OK] {len(wins)} windows:")
        for p,c,t in wins[:3]: print(f"    pid={p} cls={c} txt='{t}'")
        kill_tree(proc.pid); time.sleep(0.5)
        if wins:
            print("[OK] SUCCESS"); results.append((name,"OK",f"{len(wins)} wins"))
        else:
            print("[WARN] no window"); results.append((name,"NO_WINDOW","no window"))

    print(); print("="*70); print("Summary"); print("="*70)
    print(f"{'Name':<12} {'Result':<12} Reason")
    print("-"*70)
    for n,r,re in results: print(f"{n:<12} {r:<12} {re}")

if __name__ == "__main__":
    main()
