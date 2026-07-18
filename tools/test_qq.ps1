# test_qq_fixed.ps1 - 测试 QQ 加壳后输入密码能否正常启动
$ErrorActionPreference = 'Continue'

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class WLQQ {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    public delegate bool EnumChildProc(IntPtr h, IntPtr l);

    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumChildProc cb, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
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
}
"@

$exe = 'C:\Home\Apps\QQ\Bin\qq_locked.exe'
$workdir = 'C:\Home\Apps\QQ\Bin'
$password = 'test123'
$title = 'WinLock - Password Required'

Write-Host "[1] Starting qq_locked.exe ..."
$proc = Start-Process -FilePath $exe -WorkingDirectory $workdir -PassThru
$rootPid = $proc.Id
Write-Host "    Root PID = $rootPid"

# 等密码框
Write-Host "[2] Waiting for password dialog ..."
$deadline = (Get-Date).AddSeconds(15)
$hwnd = [IntPtr]::Zero
while ((Get-Date) -lt $deadline) {
    $hwnd = [WLQQ]::FindByTitle($title)
    if ($hwnd -ne [IntPtr]::Zero) { break }
    $alive = Get-Process -Id $rootPid -ErrorAction SilentlyContinue
    if (-not $alive) { Write-Host "[!] Root exited early"; break }
    Start-Sleep -Milliseconds 200
}
if ($hwnd -eq [IntPtr]::Zero) {
    Write-Host "[ERR] no password dialog"
    taskkill /T /F /PID $rootPid 2>&1 | Out-Null
    Get-Process -Name 'qq_locked' -ErrorAction SilentlyContinue | Stop-Process -Force
    exit 1
}
Write-Host ("[OK] dialog hwnd=0x{0:X}" -f [int64]$hwnd)

# 输入密码
$edit = [WLQQ]::FindChild($hwnd, "Edit")
Write-Host ("[OK] Edit hwnd=0x{0:X}" -f [int64]$edit)
[WLQQ]::SendMessage($edit, [WLQQ]::WM_SETTEXT, [IntPtr]::Zero, $password) | Out-Null

$ok = [WLQQ]::FindChildByText($hwnd, "OK")
Write-Host ("[OK] OK hwnd=0x{0:X}, clicking" -f [int64]$ok)
[WLQQ]::SendMessage($ok, [uint32]0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null

# 监控 40 秒,看 QQ 启动情况 + "initialize failed" 弹窗
Write-Host "[3] Monitoring for 40s after password ..."
for ($i = 0; $i -lt 40; $i += 2) {
    Start-Sleep -Seconds 2
    # 找所有顶级窗口,看是否有错误对话框
    $allTop = Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | Select-Object Id, ProcessName, MainWindowTitle, @{N='WS_MB';E={[int]($_.WorkingSet64/1MB)}}
    $qqProcs = Get-Process -Name 'qq_locked','qq','QQ','QQExternal','QQApp','CefSubProcess','TXPlatform','QQScLauncher' -ErrorAction SilentlyContinue
    Write-Host ("    [{0,2}s] qq_procs={1}" -f $i, $qqProcs.Count)
    $allTop | Where-Object { $_.MainWindowTitle -match 'error|fail|initial|QQ|WinLock|错误' } | ForEach-Object {
        Write-Host ("        Window: PID={0} Name={1} Title='{2}'" -f $_.Id, $_.ProcessName, $_.MainWindowTitle)
    }
}

Write-Host "[4] Final state:"
$qqProcs = Get-Process -Name 'qq_locked','qq','QQ','QQExternal','QQApp','CefSubProcess','TXPlatform','QQScLauncher' -ErrorAction SilentlyContinue
Write-Host "    Total QQ processes: $($qqProcs.Count)"
$qqProcs | ForEach-Object { Write-Host ("      PID={0} Name={1} WS={2}MB Title='{3}'" -f $_.Id, $_.ProcessName, [int]($_.WorkingSet64/1MB), $_.MainWindowTitle) }

Write-Host "[5] Killing all ..."
taskkill /T /F /PID $rootPid 2>&1 | Out-Null
Get-Process -Name 'qq_locked','qq','QQ','QQExternal','QQApp','CefSubProcess','TXPlatform','QQScLauncher' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Write-Host "[DONE]"
