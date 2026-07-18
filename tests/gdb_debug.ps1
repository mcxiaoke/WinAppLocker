$ErrorActionPreference = "Continue"
Set-Location F:\Temp\pe\samples

Write-Host "=== gdb debug helloguix86_locked.exe ==="
$gdb = "C:\Home\Develop\w64devkit\bin\gdb.exe"
$gdbArgs = @(
    "-batch",
    "-ex","set pagination off",
    "-ex","run",
    "-ex","bt",
    "-ex","info registers",
    "-ex","x/10i `$pc",
    "-ex","quit",
    ".\helloguix86_locked.exe"
)
& $gdb $gdbArgs 2>&1
Write-Host "gdb exit: $LASTEXITCODE"
