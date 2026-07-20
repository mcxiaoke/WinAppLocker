"""用 cdb 调试 DontSleep reflective，hook ucrtbase!_wfopen 看打开什么文件"""
import subprocess
import time
import ctypes
from ctypes import wintypes
import struct

# 先准备 cdb 脚本
# _wfopen 签名：FILE* _wfopen(const wchar_t* filename, const wchar_t* mode)
# x64 ABI: rcx=filename, rdx=mode
# 我们在 _wfopen 入口断点，打印 rcx 指向的字符串
cmd_content = r'''bu ucrtbase!_wfopen ".printf \"[_wfopen] filename=%msu, mode=%msu\n\", @rcx, @rdx; gu; .printf \"  -> ret=%p\n\", @rax; g"
bu msvcrt!_wfopen ".printf \"[msvcrt!_wfopen] filename=%msu, mode=%msu\n\", @rcx, @rdx; gu; .printf \"  -> ret=%p\n\", @rax; g"
bu user32!MessageBoxA ".printf \"[MessageBoxA] text=%ma, caption=%ma\n\", @rdx, @r8; g"
bu user32!MessageBoxW ".printf \"[MessageBoxW] text=%msu, caption=%msu\n\", @rdx, @r8; g"
g
'''
with open(r'C:\Home\Projects\applocker\temp\cdb_wfopen_cmds.txt', 'w', encoding='ascii') as f:
    f.write(cmd_content)

# 用 cdb 启动 DontSleep
exe = r'C:\Home\Projects\applocker\temp\samples\DontSleep_locked_refl.exe'
cwd = r'C:\Home\Projects\applocker\temp\samples'
log_file = r'C:\Home\Projects\applocker\temp\cdb_wfopen.log'
cmd_file = r'C:\Home\Projects\applocker\temp\cdb_wfopen_cmds.txt'

import os
if os.path.exists(log_file):
    os.remove(log_file)

cdb = r'C:\Home\Develop\WinDbg\x64\cdb.exe'
# 用 -g 跳过 initial breakpoint，-cf 跑脚本（脚本末尾 g 让程序继续）
proc = subprocess.Popen(
    [cdb, '-g', '-cf', cmd_file, '-logo', log_file, exe],
    cwd=cwd,
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    creationflags=0x08000000  # CREATE_NO_WINDOW
)
print(f'cdb PID={proc.pid}, waiting for password dialog...')

# 等密码对话框
time.sleep(3)

# 用 SendMessage 输入密码
user32 = ctypes.WinDLL('user32', use_last_error=True)
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL
user32.EnumChildWindows.argtypes = [wintypes.HWND, WNDENUMPROC, wintypes.LPARAM]
user32.EnumChildWindows.restype = wintypes.BOOL
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, wintypes.INT]
user32.GetWindowTextW.restype = wintypes.INT
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, wintypes.INT]
user32.GetClassNameW.restype = wintypes.INT
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
# SendMessageW 既要传 string 又要传 IntPtr，用两个绑定
u_str = ctypes.WinDLL('user32', use_last_error=True)
u_int = ctypes.WinDLL('user32', use_last_error=True)
u_str.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, ctypes.c_wchar_p]
u_str.SendMessageW.restype = wintypes.LPARAM
u_int.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
u_int.SendMessageW.restype = wintypes.LPARAM

dlg = 0
edit = 0
btn = 0

def find_dlg(h, l):
    global dlg
    pid = wintypes.DWORD(0)
    user32.GetWindowThreadProcessId(h, ctypes.byref(pid))
    if pid.value == proc.pid and user32.IsWindowVisible(h):
        buf = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(h, buf, 256)
        if 'Password' in buf.value:
            dlg = h
            return False
    return True

user32.EnumWindows(WNDENUMPROC(find_dlg), 0)
print(f'dlg={dlg}')
if not dlg:
    print('no password dialog found')
    proc.terminate()
    exit(1)

def find_children(h, l):
    global edit, btn
    buf = ctypes.create_unicode_buffer(64)
    user32.GetClassNameW(h, buf, 64)
    if buf.value == 'Edit':
        edit = h
    elif buf.value == 'Button':
        text = ctypes.create_unicode_buffer(64)
        user32.GetWindowTextW(h, text, 64)
        if text.value == 'OK':
            btn = h
    return True

user32.EnumChildWindows(dlg, WNDENUMPROC(find_children), 0)
print(f'edit={edit}, btn={btn}')

# 输入密码
WM_SETTEXT = 0x000C
BM_CLICK = 0x00F5
u_str.SendMessageW(edit, WM_SETTEXT, 0, 'hello123')
u_int.SendMessageW(btn, BM_CLICK, 0, 0)
print('password sent')

# 等错误对话框
time.sleep(8)

# 终止 cdb
if proc.poll() is None:
    proc.terminate()
    time.sleep(1)

print('===== cdb log =====')
with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()
# 只打印关键行
for line in content.splitlines():
    if any(kw in line for kw in ['_wfopen', 'MessageBox', 'filename', 'mode', 'text=', 'caption=']):
        print(line)
