<#
.SYNOPSIS
  启动反射式加壳后的 EXE，验证 Notepad4 窗口是否出现。
.DESCRIPTION
  stub 的 printf 输出在它自己 AllocConsole 创建的 console 窗口里，
  父进程无法用 RedirectStandardOutput 捕获。
  本脚本仅检查：
    1. EXE 启动后进程是否存活
    2. 是否出现 Notepad4 窗口（说明反射式加载成功跳到 OEP）
  如果失败，结束进程并报告。
#>

param(
    [string]$Exe = "C:\Home\Projects\applocker\packer\test\Notepad4_reflective.exe",
    [int]$WaitSec = 5
)

if (-not (Test-Path $Exe)) {
    Write-Host "[-] EXE not found: $Exe" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Launching: $Exe"
Write-Host "[*] Will wait $WaitSec seconds, then check process/window state"

# Start-Process 不重定向，让 stub 自己的 AllocConsole 显示日志窗口
$proc = Start-Process -FilePath $Exe -PassThru -WindowStyle Normal
Write-Host "[+] Process started, PID=$($proc.Id)"

Start-Sleep -Seconds $WaitSec

# 检查进程状态
if ($proc.HasExited) {
    Write-Host "[!] Process exited early, exit code = $($proc.ExitCode)" -ForegroundColor Yellow
    exit 2
} else {
    Write-Host "[+] Process still running after $WaitSec seconds" -ForegroundColor Green
}

# 检查是否有 Notepad4 窗口（说明反射式加载成功跳到 OEP）
$npProcs = Get-Process | Where-Object {
    $_.ProcessName -match "Notepad4" -or $_.MainWindowTitle -match "Notepad4"
}

if ($npProcs) {
    Write-Host "[+] SUCCESS: Found Notepad4 process/window:" -ForegroundColor Green
    $npProcs | Format-Table Id, ProcessName, MainWindowTitle, @{Name="MemMB";Expression={[math]::Round($_.WorkingSet64/1MB, 1)}} -AutoSize
    $result = 0
} else {
    Write-Host "[!] FAIL: No Notepad4 window found (reflective load may have failed)" -ForegroundColor Red
    Write-Host "[*] Top 10 processes by memory (for diagnostics):"
    Get-Process | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 10 |
        Format-Table Id, ProcessName, MainWindowTitle, @{Name="MemMB";Expression={[math]::Round($_.WorkingSet64/1MB, 1)}} -AutoSize
    $result = 3
}

# 清理：杀掉启动的进程及其子进程
if (-not $proc.HasExited) {
    Write-Host "[*] Terminating process tree (PID=$($proc.Id))..."
    taskkill /F /T /PID $proc.Id 2>&1 | Out-Null
}

# 同时清理可能残留的 Notepad4 进程
Get-Process | Where-Object { $_.ProcessName -match "Notepad4" } | ForEach-Object {
    Write-Host "[*] Cleaning up residual PID=$($_.Id)"
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}

Write-Host "[*] Done (exit code = $result)"
exit $result
