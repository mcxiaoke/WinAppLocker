$ErrorActionPreference = "Continue"
$env:Path = "C:\Home\Develop\w64devkit\bin;$env:Path"
Set-Location F:\Temp\pe\winlock

Write-Host "=== Pack helloguix86.exe (normal mode, password=test) ==="
& builder\builder.exe -i F:\Temp\pe\samples\helloguix86.exe -o F:\Temp\pe\samples\helloguix86_locked.exe -p test 2>&1
Write-Host "builder exit: $LASTEXITCODE"

Write-Host ""
Write-Host "=== Run locked exe (will show password dialog) ==="
Write-Host "Starting process, waiting 4s to check if dialog appears..."
$p = Start-Process -FilePath "F:\Temp\pe\samples\helloguix86_locked.exe" -PassThru
Start-Sleep -Seconds 4
if ($p.HasExited) {
    Write-Host "Process exited with code: $($p.ExitCode)"
} else {
    Write-Host "Process still running - dialog likely shown. Killing..."
    Stop-Process -Id $p.Id -Force
    Write-Host "Killed."
}
