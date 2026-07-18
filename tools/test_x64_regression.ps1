$ErrorActionPreference = "Continue"
Set-Location F:\Temp\pe\samples

Write-Host "=== x64 regression: run hellogui_locked.exe ==="
$p = Start-Process -FilePath ".\hellogui_locked.exe" -PassThru
Write-Host "Started PID: $($p.Id)"
Start-Sleep -Seconds 2

Write-Host "Sending password 'test'..."
& powershell -ExecutionPolicy Bypass -File F:\Temp\pe\winlock\tools\input_password.ps1 -Password test -Timeout 8

Start-Sleep -Seconds 3
if ($p.HasExited) {
    Write-Host "Process exited with code: $($p.ExitCode)"
} else {
    Write-Host "Process still running - GUI launched successfully!"
    Stop-Process -Id $p.Id -Force
}
