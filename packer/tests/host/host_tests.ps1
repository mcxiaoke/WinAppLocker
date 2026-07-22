# host_tests.ps1 - 编译并运行 packer/tests/host/ 下的 C 单元测试
#
# 用法：
#   .\host_tests.ps1              # 默认 MSVC x64
#   .\host_tests.ps1 -UseMinGW    # 用 MinGW gcc
#
# 说明：
#   - 测试不接入 CMake，独立编译（host 模式，不定义 WINLOCK_PIC）
#   - 仅依赖 common/*.h 头文件，无外部库
#   - 失败任一测试 → 脚本退出码 1

param(
    [switch]$UseMinGW
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$commonDir = (Resolve-Path "$root\..\..\common").Path
$workDir = "$root\..\..\..\temp\host_tests"

if (-not (Test-Path $workDir)) { New-Item -ItemType Directory -Path $workDir | Out-Null }

Write-Host "==> host 单元测试" -ForegroundColor Cyan

# 选择编译器
function Invoke-Compile {
    param([string]$src, [string]$outExe, [string[]]$extraArgs)
    # 统一转为绝对正斜杠路径（cl /I 和 gcc -I 都接受正斜杠）
    $commonDirFwd = (Resolve-Path $commonDir).Path -replace '\\', '/'
    $srcFwd = (Resolve-Path $src).Path -replace '\\', '/'
    $outExeFwd = $outExe -replace '\\', '/'
    if ($UseMinGW) {
        $gcc = (Get-Command gcc -ErrorAction SilentlyContinue).Source
        if (-not $gcc) { throw "gcc 不在 PATH" }
        & $gcc "$srcFwd" "-I$commonDirFwd" "-o" "$outExeFwd" "-O2" "-std=c11" $extraArgs
    } else {
        $cl = (Get-Command cl -ErrorAction SilentlyContinue).Source
        if (-not $cl) { throw "cl 不在 PATH（请先运行 vcvars64.bat）" }
        & $cl "$srcFwd" "/I$commonDirFwd" "/Fe:$outExeFwd" "/O2" "/utf-8" "/nologo" $extraArgs
    }
    if ($LASTEXITCODE -ne 0) { throw "编译失败: $src" }
}

# 清理旧的 obj 文件（MSVC 会生成 .obj）
Get-ChildItem $workDir -Filter "*.obj" -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem $workDir -Filter "*.o" -ErrorAction SilentlyContinue | Remove-Item -Force

$tests = @(
    @{ Name = "SHA-256"; Src = "$root\host_sha256_test.c"; Exe = "$workDir\host_sha256_test.exe" }
    @{ Name = "XTEA";    Src = "$root\host_xtea_test.c";    Exe = "$workDir\host_xtea_test.exe" }
)

$totalPass = $true
foreach ($t in $tests) {
    Write-Host "`n---- 编译 $($t.Name) ----" -ForegroundColor Yellow
    Invoke-Compile -src $t.Src -outExe $t.Exe

    Write-Host "---- 运行 $($t.Name) ----" -ForegroundColor Yellow
    & $t.Exe
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[FAIL] $($t.Name) 测试失败" -ForegroundColor Red
        $totalPass = $false
    } else {
        Write-Host "[OK] $($t.Name) 全部通过" -ForegroundColor Green
    }
}

# 清理 MSVC 产生的 .obj（在当前目录或 workDir）
Get-ChildItem $workDir -Filter "*.obj" -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem $workDir -Filter "*.o" -ErrorAction SilentlyContinue | Remove-Item -Force

Write-Host "`n=== 总结果 ===" -ForegroundColor Cyan
if ($totalPass) {
    Write-Host "所有 host 测试通过" -ForegroundColor Green
    exit 0
} else {
    Write-Host "存在失败" -ForegroundColor Red
    exit 1
}
