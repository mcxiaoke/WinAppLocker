$ErrorActionPreference = "Continue"
Set-Location F:\Temp\pe\samples

Write-Host "=== Check file exists ==="
Get-ChildItem helloguix86_locked.exe | Select-Object Name,Length,LastWriteTime

Write-Host ""
Write-Host "=== Run helloguix86_locked.exe (test mode) ==="
$proc = Start-Process -FilePath ".\helloguix86_locked.exe" -NoNewWindow -Wait -PassThru
Write-Host "exit code: $($proc.ExitCode)"
