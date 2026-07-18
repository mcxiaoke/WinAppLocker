# test_qq_watch_dlg.ps1 - 启动 qq_locked 输密码后监控所有弹窗(包括 MessageBox)
$ErrorActionPreference = 'Continue'

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class WLQ3 {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    public delegate bool EnumChildProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumChildProc cb, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, string s);
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
    public const uint WM_SETTEXT = 0x000C;
    public const uint BM_CLICK = 0x00F5;

    public static IntPtr FindByTitle(string title) {
        IntPtr found = IntPtr.Zero;
        EnumProc cb = (h, l) => {
            if (!IsWindowVisible(h)) return true;
            int len = GetWindowTextLength(h);
            if (len != title.Length) return true;
            StringBuilder sb = new StringBuilder(len+2);
            GetWindowText(h, sb, len+2);
            if (sb.ToString() == title) { found = h; return false; }
            return true;
        };
        EnumWindows(cb, IntPtr.Zero);
        return found;
    }
    public static IntPtr FindChild(IntPtr parent, string cls) {
        IntPtr found = IntPtr.Zero;
        EnumChildProc cb = (h, l) => {
            StringBuilder sb = new StringBuilder(64);
            GetClassName(h, sb, 64);
            if (sb.ToString() == cls) { found = h; return false; }
            return true;
        };
        EnumChildWindows(parent, cb, IntPtr.Zero);
        return found;
    }
    public static IntPtr FindChildByText(IntPtr parent, string text) {
        IntPtr found = IntPtr.Zero;
        EnumChildProc cb = (h, l) => {
            int len = GetWindowTextLength(h);
            StringBuilder sb = new StringBuilder(len+2);
            GetWindowText(h, sb, len+2);
            if (sb.ToString() == text) { found = h; return false; }
            return true;
        };
        EnumChildWindows(parent, cb, IntPtr.Zero);
        return found;
    }

    // 枚举所有顶级可见窗口(用于检测新弹出的错误对话框)
    public static string[] DumpTopWindows() {
        var result = new System.Collections.Generic.List<string>();
        EnumProc cb = (h, l) => {
            if (!IsWindowVisible(h)) return true;
            int len = GetWindowTextLength(h);
            if (len == 0) return true;
            StringBuilder sb = new StringBuilder(len+2);
            GetWindowText(h, sb, len+2);
            StringBuilder cls = new StringBuilder(64);
            GetClassName(h, cls, 64);
            IntPtr parent = GetParent(h);
            result.Add(string.Format("hwnd=0x{0:X} cls={1} title='{2}' parent=0x{3:X}",
                (long)h, cls.ToString(), sb.ToString(), (long)parent));
            return true;
        };
        EnumWindows(cb, IntPtr.Zero);
        return result.ToArray();
    }
}
"@

$exe = 'C:\Home\Apps\QQ\Bin\qq_locked.exe'
$workdir = 'C:\Home\Apps\QQ\Bin'
$title = 'WinLock - Password Required'

Write-Host "[1] Starting qq_locked.exe ..."
$proc = Start-Process -FilePath $exe -WorkingDirectory $workdir -PassThru
$rootPid = $proc.Id
Write-Host "    Root PID = $rootPid"

# 等 WinLock 密码框
$deadline = (Get-Date).AddSeconds(15)
$hwnd = [IntPtr]::Zero
while ((Get-Date) -lt $deadline) {
    $hwnd = [WLQ3]::FindByTitle($title)
    if ($hwnd -ne [IntPtr]::Zero) { break }
    if (-not (Get-Process -Id $rootPid -ErrorAction SilentlyContinue)) { Write-Host "[!] exited"; exit 1 }
    Start-Sleep -Milliseconds 200
}
if ($hwnd -eq [IntPtr]::Zero) { Write-Host "[ERR] no dialog"; exit 1 }
Write-Host ("[OK] WinLock dialog hwnd=0x{0:X}" -f [int64]$hwnd)

# 输密码点 OK
$edit = [WLQ3]::FindChild($hwnd, "Edit")
[WLQ3]::SendMessage($edit, [WLQ3]::WM_SETTEXT, [IntPtr]::Zero, "test123") | Out-Null
$ok = [WLQ3]::FindChildByText($hwnd, "OK")
Write-Host ("[OK] Clicking OK hwnd=0x{0:X}" -f [int64]$ok)
[WLQ3]::SendMessage($ok, [uint32]0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null

# 点 OK 之前的窗口快照
$before = [WLQ3]::DumpTopWindows() | ForEach-Object { $_ }

# 监控 30 秒,每 1 秒扫一次,看是否出现新窗口
Write-Host "[2] Monitoring for new windows (30s) ..."
for ($i = 0; $i -lt 30; $i += 1) {
    Start-Sleep -Seconds 1
    $now = [WLQ3]::DumpTopWindows()
    # 找新出现的窗口
    foreach ($w in $now) {
        if ($before -notcontains $w) {
            Write-Host ("    [{0,2}s] NEW: {1}" -f $i, $w) -ForegroundColor Yellow
            $before += $w  # 避免重复报
        }
    }
    # 检查进程是否退出
    if (-not (Get-Process -Id $rootPid -ErrorAction SilentlyContinue)) {
        Write-Host "    [${i}s] root process EXITED"
        break
    }
}

Write-Host "[3] Final window dump:"
[WLQ3]::DumpTopWindows() | ForEach-Object { Write-Host "    $_" }

Write-Host "[4] Killing ..."
taskkill /T /F /PID $rootPid 2>&1 | Out-Null
Get-Process -Name 'qq_locked','qq','QQ' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Write-Host "[DONE]"
