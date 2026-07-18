$ErrorActionPreference = "Continue"
Set-Location F:\Temp\pe\winlock
$gcc = "C:\Home\Develop\msys64\mingw32\bin\gcc.exe"

Write-Host "=== Step 1: compile stub_x86.o ==="
$compileOut = "F:\Temp\pe\winlock\compile_out.txt"
$compileErr = "F:\Temp\pe\winlock\compile_err.txt"
& $gcc -Wall -Wextra -Wno-cast-function-type -O2 -ffreestanding -fno-stack-protector -fno-pic -fno-pie -fno-asynchronous-unwind-tables -fno-exceptions -fno-ident -mno-sse -mno-sse2 -DWINLOCK_STUB -c stub/stub.c -o stub/stub_x86.o 1>$compileOut 2>$compileErr
Write-Host "compile exit: $LASTEXITCODE"
Write-Host "--- stdout ---"
Get-Content $compileOut -ErrorAction SilentlyContinue
Write-Host "--- stderr ---"
Get-Content $compileErr -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== Step 2: link stub_x86.exe ==="
$linkOut = "F:\Temp\pe\winlock\link_out.txt"
$linkErr = "F:\Temp\pe\winlock\link_err.txt"
$argList = @(
    "-nostdlib","-nostartfiles",
    "-Wl,-subsystem,windows",
    "-Wl,-e,_stub_entry",
    "-Wl,--image-base=0x10000",
    "-Wl,-T,stub/stub.ld",
    "-Wl,--gc-sections",
    "-Wl,--build-id=none",
    "-Wl,--dynamicbase",
    "stub/stub_x86.o",
    "-o","stub/stub_x86.exe"
)
& $gcc $argList 1>$linkOut 2>$linkErr
Write-Host "link exit: $LASTEXITCODE"
Write-Host "--- stdout ---"
Get-Content $linkOut -ErrorAction SilentlyContinue
Write-Host "--- stderr ---"
Get-Content $linkErr -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== Result ==="
Get-ChildItem stub/stub_x86.* | Select-Object Name,Length,LastWriteTime
