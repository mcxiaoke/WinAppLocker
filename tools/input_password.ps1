# input_password.ps1 - 给 WinLock 密码框发送密码并点 OK
# 用法：powershell -File input_password.ps1 -Password <password> [-Timeout 10]

param(
    [Parameter(Mandatory=$true)]
    [string]$Password,

    [int]$Timeout = 10
)

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class WinLock {
    public delegate bool EnumChildProc(IntPtr hwnd, IntPtr lParam);
    public delegate bool EnumTopProc(IntPtr hwnd, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumTopProc cb, IntPtr lp);

    [DllImport("user32.dll")]
    public static extern bool EnumChildWindows(IntPtr parent, EnumChildProc cb, IntPtr lp);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetClassName(IntPtr h, StringBuilder s, int n);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);

    [DllImport("user32.dll")]
    public static extern int GetWindowTextLength(IntPtr h);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr SendMessage(IntPtr h, uint msg, IntPtr w, string s);

    [DllImport("user32.dll")]
    public static extern IntPtr SendMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);

    public const uint WM_SETTEXT = 0x000C;
    public const uint BM_CLICK   = 0x00F5;

    public static IntPtr FindChild(IntPtr parent, string className, string text) {
        IntPtr found = IntPtr.Zero;
        EnumChildProc cb = (h, lp) => {
            StringBuilder cls = new StringBuilder(64);
            GetClassName(h, cls, 64);
            int len = GetWindowTextLength(h);
            StringBuilder txt = new StringBuilder(len + 2);
            GetWindowText(h, txt, len + 2);
            bool classMatch = (className == null) || (cls.ToString() == className);
            bool textMatch  = (text == null) || (txt.ToString() == text);
            if (classMatch && textMatch) {
                found = h;
                return false;
            }
            return true;
        };
        EnumChildWindows(parent, cb, IntPtr.Zero);
        return found;
    }

    public static IntPtr FindTopByTitle(string title) {
        IntPtr found = IntPtr.Zero;
        EnumTopProc cb = (h, lp) => {
            int len = GetWindowTextLength(h);
            if (len != title.Length) return true;
            StringBuilder txt = new StringBuilder(len + 2);
            GetWindowText(h, txt, len + 2);
            if (txt.ToString() == title) {
                found = h;
                return false;
            }
            return true;
        };
        EnumWindows(cb, IntPtr.Zero);
        return found;
    }
}
"@

$title = "WinLock - Password Required"
$deadline = (Get-Date).AddSeconds($Timeout)
$hwnd = [IntPtr]::Zero

while ((Get-Date) -lt $deadline) {
    $hwnd = [WinLock]::FindTopByTitle($title)
    if ($hwnd -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 200
}

if ($hwnd -eq [IntPtr]::Zero) {
    Write-Host "[ERR] password dialog not found within $Timeout s" -ForegroundColor Red
    exit 1
}

Write-Host ("[OK] dialog hwnd=0x{0:X}" -f [int64]$hwnd)

$edit = [IntPtr]::Zero
$deadline2 = (Get-Date).AddSeconds(3)
while ((Get-Date) -lt $deadline2) {
    $edit = [WinLock]::FindChild($hwnd, "Edit", $null)
    if ($edit -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 100
}
if ($edit -eq [IntPtr]::Zero) {
    Write-Host "[ERR] edit box not found" -ForegroundColor Red
    exit 2
}

Write-Host ("[OK] edit hwnd=0x{0:X}" -f [int64]$edit)
[WinLock]::SendMessage($edit, [WinLock]::WM_SETTEXT, [IntPtr]::Zero, $Password) | Out-Null
Write-Host ("[OK] sent password: '$Password'")

$ok = [IntPtr]::Zero
$deadline3 = (Get-Date).AddSeconds(3)
while ((Get-Date) -lt $deadline3) {
    $ok = [WinLock]::FindChild($hwnd, "Button", "OK")
    if ($ok -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 100
}
if ($ok -eq [IntPtr]::Zero) {
    Write-Host "[ERR] OK button not found" -ForegroundColor Red
    exit 3
}

Write-Host ("[OK] OK button hwnd=0x{0:X}, clicking..." -f [int64]$ok)
[WinLock]::SendMessage($ok, [uint32]0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
Write-Host "[DONE] OK clicked" -ForegroundColor Green
exit 0
