$ErrorActionPreference = "Continue"
Set-Location F:\Temp\pe\samples

Write-Host "=== gdb debug hellox86_locked.exe (x86 + TLS_PROXY + password mode) ==="
$gdb = "C:\Home\Develop\w64devkit\bin\gdb.exe"
$gdbArgs = @(
    "-batch",
    "-ex","set pagination off",
    "-ex","break ExitProcess",
    "-ex","run",
    "-ex","bt",
    "-ex","info registers",
    "-ex","quit",
    ".\hellox86_locked.exe"
)
& $gdb $gdbArgs 2>&1 | Select-Object -First 50
Write-Host "gdb exit: $LASTEXITCODE"
