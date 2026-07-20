# WinLock packer 构建脚本（inplace stub 用 MinGW，其余用 MSVC x64 + x86）
#
# 用法：
#   .\build.ps1               # 默认 Release，构建 x64 + x86
#   .\build.ps1 -Debug        # Debug 配置（注意：PIC stub 的 /GS- 与 /RTC1 冲突，
#                            #  Debug 下 stub target 会失败，仅 builder 可编）
#   .\build.ps1 -Clean        # 清理 build/ 和 dist/ 后重新构建
#   .\build.ps1 -SkipX64      # 跳过 x64 构建，只构建 x86
#   .\build.ps1 -SkipX86      # 跳过 x86 构建，只构建 x64
#   .\build.ps1 -SkipMinGW    # 跳过 MinGW 构建 inplace stub（用 MSVC 版本）
#
# 流程：
#   1. MSVC vcvarsall → cmake build（builder + reflective stub + inplace stub 备份）
#   2. MinGW 构建 inplace stub（x64），覆盖 MSVC 产物
#   3. 汇集产物到 dist/（平级，不带子目录）
#
# 产物（dist/）：
#   builder_inplace.exe          - inplace 加壳器（x64，运行时按输入 PE 选 stub）
#   stub_inplace_x64.bin          - inplace x64 stub（MinGW 构建，TLS callback 完整）
#   stub_inplace_x64.exe          - inplace x64 stub exe（MinGW 构建，builder 读 .reloc 用）
#   stub_inplace_x86.bin          - inplace x86 stub（MSVC 构建）
#   stub_inplace_x86.exe          - inplace x86 stub exe（MSVC 构建）
#   builder_reflective.exe        - reflective 加壳器（x64）
#   stub_reflective_x64.exe       - reflective x64 stub
#   stub_reflective_x86.exe       - reflective x86 stub
#
# 设计：
#   - builder 只输出 x64 版本（builder 不依赖架构，x86 builder 仅 32 位 OS 才需要，
#     现代 Windows 都是 64 位，x64 builder 通过 WOW64 也能加壳 x86 PE）
#   - stub 同时输出 x64 和 x86 版本（带 _xXX 后缀区分）
#   - x64 和 x86 用独立 CMakeLists-x64.txt / CMakeLists-x86.txt，不掺混
#   - CMake 必须读 CMakeLists.txt（不支持自定义文件名），
#     临时复制 CMakeLists-xXX.txt 为 CMakeLists.txt，try/finally 保证清理

param(
    [switch]$Debug,
    [switch]$Release,
    [switch]$Clean,
    [switch]$SkipX64,
    [switch]$SkipX86,
    [switch]$SkipMinGW
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {

$config = if ($Debug) { "Debug" } else { "Release" }
Write-Host "==> WinLock packer 构建（MSVC x64 + x86, Ninja）" -ForegroundColor Cyan
Write-Host "    配置: $config"

# ---- vcvarsall.bat 路径 ----
$vcvarsall = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat"
if (-not (Test-Path $vcvarsall)) {
    throw "vcvarsall.bat 不存在: $vcvarsall（请确认 Visual Studio 2026 安装路径）"
}

# 辅助函数：调用 vcvarsall.bat 注入环境变量到当前 PowerShell session
# 参数：
#   $vcvarsArch - vcvarsall.bat 的参数（"x64" 或 "x86"）
#                注意：x86 构建仍用 x64 host 交叉编译，所以两个架构都传 "x64"
function Invoke-Vcvarsall([string]$vcvarsArch) {
    Write-Host "==> 设置 MSVC 环境: vcvarsall.bat $vcvarsArch" -ForegroundColor Cyan
    # 先在同一个 cmd 进程里 /clean_env 清理上一轮 vcvarsall 的环境污染，
    # 再设置新架构，最后输出 set 结果。避免 PATH 等变量累积导致"路径太长"错误。
    # 注意：cmd 中用 & 无条件串联（不用 &&，因为 /clean_env 可能在无残留时报错）
    $envOutput = & cmd /c "`"$vcvarsall`" /clean_env >nul 2>&1 & `"$vcvarsall`" $vcvarsArch >nul 2>&1 & set" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "vcvarsall.bat $vcvarsArch 调用失败" }
    foreach ($line in $envOutput) {
        if ($line -match '^([^=]+)=(.*)$') {
            # 用 .NET API 避免 PowerShell Env: provider 把 [ ] 等字符当通配符
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }
    $clPath = (Get-Command cl.exe -ErrorAction SilentlyContinue).Source
    Write-Host "    cl.exe: $clPath" -ForegroundColor DarkGray
}

# 辅助函数：构建一个架构
# 参数：
#   $arch         - 目标架构 "x64" 或 "x86"
#   $cmakelistSrc - 源 CMakeLists 文件名
#   $buildDir     - build 输出目录
function Build-Arch([string]$arch, [string]$cmakelistSrc, [string]$buildDir) {
    Write-Host ""
    Write-Host "======== 构建 $arch ========" -ForegroundColor Cyan

    # 1. 设置 MSVC 环境
    #    x86 构建用 x64 host 交叉编译（HostX64\x86\cl.exe），
    #    因为系统未安装 x86 host 工具集（vcvarsall.bat x86 会失败）
    #    vcvarsall.bat x64_x86 设置 x64->x86 交叉编译环境
    $vcvarsArg = if ($arch -eq "x86") { "x64_x86" } else { "x64" }
    Invoke-Vcvarsall $vcvarsArg

    # 2. 清理
    if ($Clean -and (Test-Path $buildDir)) {
        Write-Host "==> 清理 build 目录: $buildDir" -ForegroundColor Yellow
        Remove-Item $buildDir -Recurse -Force
    }
    if (-not (Test-Path $buildDir)) {
        New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
    }

    # 3. 临时把 CMakeLists-xXX.txt 复制为 CMakeLists.txt
    $tempCmake = Join-Path $root "CMakeLists.txt"
    if (Test-Path $tempCmake) {
        throw "存在意外文件 $tempCmake，请手动删除后重试"
    }
    Copy-Item (Join-Path $root $cmakelistSrc) $tempCmake -Force

    try {
        # 4. CMake configure
        #    x86 交叉编译：host 是 x64，target 是 Win32，通过 vcvarsall x64_x86 设置环境
        #    不使用 -A Win32（Ninja 不支持）
        Write-Host "==> CMake configure ($arch, Ninja)..." -ForegroundColor Cyan
        $cmakeArgs = @("-S", $root, "-B", $buildDir, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=$config")
        Write-Host "    $ cmake $($cmakeArgs -join ' ')" -ForegroundColor DarkGray
        & cmake @cmakeArgs 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        if ($LASTEXITCODE -ne 0) { throw "cmake configure ($arch) 失败" }

        # 5. CMake build（编译所有 target）
        Write-Host "==> CMake build ($arch)..." -ForegroundColor Cyan
        & cmake --build $buildDir -j
        if ($LASTEXITCODE -ne 0) { throw "cmake build ($arch) 失败" }
    } finally {
        # 6. 清理临时 CMakeLists.txt（无论成功失败都要清理）
        if (Test-Path $tempCmake) { Remove-Item $tempCmake -Force }
    }

    Write-Host "==> $arch 构建完成" -ForegroundColor Green
}

# 辅助函数：MinGW 构建 inplace stub (x64 + x86)
# 使用 MSYS64 工具链（mingw64/mingw32），输出到 build/mingw/，
# 产物覆盖 MSVC 的 stub_inplace_xXX.bin/.exe
function Build-InplaceMinGW {
    Write-Host ""

    $msys = "C:\Home\Develop\msys64"
    $commonDir = Join-Path $root "common"
    $inplaceDir = Join-Path $root "inplace"
    $stubLd = Join-Path $inplaceDir "stub.ld"
    $stubC = Join-Path $inplaceDir "stub.c"
    $buildDir = Join-Path $root "build\mingw"

    if (-not (Test-Path $buildDir)) {
        New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
    }

    # 通用编译参数
    $commonCflags = @(
        "-Wall", "-Wextra", "-Wno-cast-function-type",
        "-O2", "-ffreestanding",
        "-fno-stack-protector", "-fno-pic", "-fno-pie",
        "-fno-asynchronous-unwind-tables", "-fno-exceptions", "-fno-ident",
        "-DWINLOCK_STUB",
        "-I", $commonDir
    )

    # 通用链接参数
    $commonLdflags = @(
        "-nostdlib", "-nostartfiles",
        "-Wl,-subsystem,windows", "-Wl,-e,stub_entry",
        "-Wl,-T,$stubLd",
        "-Wl,--gc-sections", "-Wl,--build-id=none"
    )

    # 架构定义: name, mingw_bin, extra_cflags, msvc_build_dir
    $archs = @(
        @{ Name="x64"; MingwBin="$msys\mingw64\bin"; ImageBase="0x10000";
           ExtraCflags=@("-mno-red-zone", "-mno-sse", "-mno-sse2"); MsvcDir="build\x64" },
        @{ Name="x86"; MingwBin="$msys\mingw32\bin"; ImageBase="0x10000";
           ExtraCflags=@(); MsvcDir="build\x86" }
    )

    foreach ($arch in $archs) {
        $archName = $arch.Name
        $gcc = Join-Path $arch.MingwBin "gcc.exe"
        $objcopy = Join-Path $arch.MingwBin "objcopy.exe"

        if (-not (Test-Path $gcc)) {
            Write-Host "    [警告] MinGW $archName gcc 不存在: $gcc，跳过" -ForegroundColor Yellow
            continue
        }

        Write-Host "======== MinGW 构建 inplace stub ($archName) ========" -ForegroundColor Cyan

        # 确保 mingw bin 在 PATH 最前面
        $env:Path = "$($arch.MingwBin);$env:Path"

        $objFile = Join-Path $buildDir "stub_$archName.o"
        $exeFile = Join-Path $buildDir "stub_inplace_$archName.exe"
        $binFile = Join-Path $buildDir "stub_inplace_$archName.bin"

        # 编译
        $cflags = $commonCflags + $arch.ExtraCflags
        Write-Host "    编译 $stubC ..."
        & $gcc @cflags -c $stubC -o $objFile 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        if ($LASTEXITCODE -ne 0) { throw "MinGW $archName 编译失败" }

        # 链接
        $ldflags = $commonLdflags + @("-Wl,--image-base=$($arch.ImageBase)")
        Write-Host "    链接 $exeFile ..."
        & $gcc @cflags @ldflags $objFile -o $exeFile 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        if ($LASTEXITCODE -ne 0) { throw "MinGW $archName 链接失败" }

        # 提取 .lock 节为 bin
        Write-Host "    提取 .lock 节 -> $binFile ..."
        & $objcopy -O binary -j .lock $exeFile $binFile 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        if ($LASTEXITCODE -ne 0) { throw "MinGW $archName objcopy 失败" }

        $binSize = (Get-Item $binFile).Length
        $exeSize = (Get-Item $exeFile).Length
        Write-Host "    stub_inplace_$($archName).bin: $binSize bytes" -ForegroundColor DarkGray
        Write-Host "    stub_inplace_$($archName).exe: $exeSize bytes" -ForegroundColor DarkGray

        # 覆盖 MSVC 产物
        $msvcDir = Join-Path $root $arch.MsvcDir
        if (Test-Path $msvcDir) {
            Copy-Item $binFile (Join-Path $msvcDir "stub_inplace_$($archName).bin") -Force
            Copy-Item $exeFile (Join-Path $msvcDir "stub_inplace_$($archName).exe") -Force
            Write-Host "    已覆盖 MSVC $($arch.MsvcDir)/ 中的 inplace stub 产物" -ForegroundColor DarkGray
        }

        Write-Host "==> MinGW $archName inplace stub 构建完成" -ForegroundColor Green
    }
}

# ---- 构建 x64 ----
if (-not $SkipX64) {
    Build-Arch "x64" "CMakeLists-x64.txt" (Join-Path $root "build\x64")
}

# ---- 构建 x86 ----
if (-not $SkipX86) {
    Build-Arch "x86" "CMakeLists-x86.txt" (Join-Path $root "build\x86")
}

# ---- MinGW 构建 inplace stub (x64) ----
# MSVC 的 /OPT:REF 会移除 TLS callback 代码（.lock$tlscb 节），
# MinGW 用 __attribute__((used)) + KEEP() 天然保留，且产物体积更小（7.5KB vs 24.5KB）
if (-not $SkipMinGW) {
    Build-InplaceMinGW
}

# ---- 汇集产物到 dist/ ----
$distDir = Join-Path $root "dist"
if ($Clean -and (Test-Path $distDir)) {
    Remove-Item $distDir -Recurse -Force
}
if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Path $distDir -Force | Out-Null
}
Write-Host ""
Write-Host "==> 汇集产物到 $distDir ..." -ForegroundColor Cyan

# 产物清单：
#   builder 只输出 x64 版本（builder 不依赖架构，运行时按输入 PE 选 stub）
#   stub 同时输出 x64 和 x86 版本（带 _xXX 后缀）
$artifacts = @()
if (-not $SkipX64) {
    $artifacts += @(
        @{ Src = "$root\build\x64\builder_inplace.exe";     Dst = "builder_inplace.exe" },
        @{ Src = "$root\build\x64\stub_inplace_x64.exe";    Dst = "stub_inplace_x64.exe" },
        @{ Src = "$root\build\x64\stub_inplace_x64.bin";    Dst = "stub_inplace_x64.bin" },
        @{ Src = "$root\build\x64\builder_reflective.exe";  Dst = "builder_reflective.exe" },
        @{ Src = "$root\build\x64\stub_reflective_x64.exe"; Dst = "stub_reflective_x64.exe" }
    )
}
if (-not $SkipX86) {
    $artifacts += @(
        @{ Src = "$root\build\x86\stub_inplace_x86.exe";    Dst = "stub_inplace_x86.exe" },
        @{ Src = "$root\build\x86\stub_inplace_x86.bin";   Dst = "stub_inplace_x86.bin" },
        @{ Src = "$root\build\x86\stub_reflective_x86.exe"; Dst = "stub_reflective_x86.exe" }
    )
}

foreach ($a in $artifacts) {
    if (Test-Path $a.Src) {
        Copy-Item $a.Src (Join-Path $distDir $a.Dst) -Force
        $sz = (Get-Item (Join-Path $distDir $a.Dst)).Length
        Write-Host ("    + {0,8} bytes  {1}" -f $sz, $a.Dst) -ForegroundColor DarkGray
    } else {
        Write-Host "    [缺失] $($a.Src)" -ForegroundColor Yellow
    }
}

# ---- 列出 dist/ 最终产物 ----
Write-Host ""
Write-Host "==> dist/ 最终产物清单:" -ForegroundColor Green
Get-ChildItem $distDir -File | ForEach-Object {
    Write-Host ("    {0,10} bytes  {1}" -f $_.Length, $_.Name)
}

Write-Host ""
Write-Host "==> 构建完成" -ForegroundColor Green

} finally {
    Pop-Location
}
