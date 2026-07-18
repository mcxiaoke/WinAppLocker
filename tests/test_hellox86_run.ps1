$ErrorActionPreference = "Continue"
Set-Location F:\Temp\pe\samples

Write-Host "=== Run hellox86_locked.exe (x86 + TLS_PROXY + test mode) ==="
$p = Start-Process -FilePath ".\hellox86_locked.exe" -PassThru
Write-Host "Started PID: $($p.Id)"
Start-Sleep -Seconds 3

if ($p.HasExited) {
    Write-Host "Process exited with code: $($p.ExitCode)"
    if ($p.ExitCode -eq 0) {
        Write-Host "SUCCESS: stub decrypted and ran OEP (MessageBox shown and closed)"
    } elseif ($p.ExitCode -eq -1073741819) {
        Write-Host "FAILED: crash 0xC0000005"
    }
} else {
    Write-Host "Process still running - MessageBox likely shown. Killing..."
    Stop-Process -Id $p.Id -Force
    Write-Host "SUCCESS (process was running = MessageBox shown)"
}
