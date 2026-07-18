$ErrorActionPreference = "Continue"
$env:Path = "C:\Home\Develop\w64devkit\bin;C:\Home\Develop\msys64\mingw32\bin;$env:Path"
Set-Location F:\Temp\pe\winlock

Write-Host "=== make all-x86 ==="
& "C:\Home\Develop\w64devkit\bin\make.exe" all-x86 2>&1
Write-Host "make exit: $LASTEXITCODE"

Write-Host ""
Write-Host "=== Result ==="
Get-ChildItem stub\stub_x86.* | Select-Object Name,Length,LastWriteTime
