# ============================================================
# msvc_setup.cmake - MSVC 工具链路径 + binutils 查找封装
#
# 职责：
#   1. 自动探测 Visual Studio 安装路径（vswhere），推导 vcvars64.bat
#   2. 查找 w64devkit / msys2 mingw32 的 binutils（objcopy / nm）
#      这些工具与编译器无关，后续阶段 stub 提取 .text2 节仍需要
#   3. 查找 Python3（用于 cmake/extract_lock_section.py 提取 .text2 节）
#
# 设计原则：
#   - VS 路径用 vswhere 自动探测，不再写死绝对路径
#   - binutils 路径作为 CACHE 变量，用户可用 -DW64DEVKIT_BIN=... 覆盖
#   - x64 binutils（w64devkit）必需；x86 binutils（msys2 mingw32）可选
#   - 找不到工具时给出明确错误提示
# ============================================================

# ---- 自动探测 Visual Studio 安装路径（vswhere） ----
# vswhere 是 VS 自带的标准工具，固定在以下路径：
#   C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe
# 用 -latest 取最新安装，-property installationPath 输出根目录
# 探测失败时 fallback 到默认 Community 版路径（向后兼容）
set(WINLOCK_VSWHERE
    "C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe")

if(EXISTS "${WINLOCK_VSWHERE}")
    execute_process(
        COMMAND "${WINLOCK_VSWHERE}" -latest -property installationPath
        OUTPUT_VARIABLE WINLOCK_VS_INSTALL_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
endif()

# 推导 vcvars64.bat 路径：${VS_INSTALL}/VC/Auxiliary/Build/vcvars64.bat
if(WINLOCK_VS_INSTALL_PATH)
    set(_vcvars64_default "${WINLOCK_VS_INSTALL_PATH}/VC/Auxiliary/Build/vcvars64.bat")
else()
    # fallback：默认 Community 版路径（老版本兼容）
    set(_vcvars64_default
        "C:/Program Files/Microsoft Visual Studio/18/Community/VC/Auxiliary/Build/vcvars64.bat")
endif()

# CACHE 变量：用户可用 -DWINLOCK_VCVARS64=... 覆盖
set(WINLOCK_VCVARS64 "${_vcvars64_default}"
    CACHE FILEPATH "Path to vcvars64.bat (for Ninja generator or manual cl.exe)")

if(NOT EXISTS "${WINLOCK_VCVARS64}")
    message(WARNING "vcvars64.bat not found at: ${WINLOCK_VCVARS64}\n"
                    "  If using Ninja generator, ensure vcvars64.bat is called first.\n"
                    "  If using Visual Studio generator, this warning can be ignored.\n"
                    "  Override with -DWINLOCK_VCVARS64=<path>")
endif()

# ---- 查找 Python3（用于 cmake/extract_lock_section.py 提取多 .text2 节） ----
# MSVC link.exe 不合并不同特性的 .text2$X 子节（LNK4078），
# 导致 objcopy -j .text2 输出包含中间 padding（25KB 而非 5KB）。
# 用 Python 脚本按 VA 顺序拼接所有 .text2 节的 raw data（无 padding）。
find_package(Python3 COMPONENTS Interpreter QUIET)
if(NOT Python3_Interpreter_FOUND)
    message(FATAL_ERROR "Python3 not found. Required for extract_lock_section.py")
endif()

# ---- binutils 路径根目录 ----
set(W64DEVKIT_BIN "C:/Home/Develop/w64devkit/bin"
    CACHE PATH "w64devkit bin directory (x64 objcopy/nm)")
set(MSYS_MINGW32_BIN "C:/Home/Develop/msys64/mingw32/bin"
    CACHE PATH "msys2 mingw32 bin directory (x86 objcopy/nm)")

# ---- 查找 x64 binutils（必需） ----
# stub 阶段用 objcopy -O binary -j .text2 提取 stub.bin，nm 查符号偏移
find_program(OBJCOPY_X64
    NAMES objcopy
    PATHS ${W64DEVKIT_BIN}
    NO_DEFAULT_PATH
    DOC "x64 objcopy (from w64devkit) for stub .text2 extraction")
if(NOT OBJCOPY_X64)
    find_program(OBJCOPY_X64 NAMES objcopy DOC "x64 objcopy (fallback search)")
endif()

find_program(NM_X64
    NAMES nm
    PATHS ${W64DEVKIT_BIN}
    NO_DEFAULT_PATH
    DOC "x64 nm (from w64devkit) for stub symbol offset lookup")
if(NOT NM_X64)
    find_program(NM_X64 NAMES nm DOC "x64 nm (fallback search)")
endif()

# 阶段 2 builder 不需要 binutils，仅 stub 阶段 3 需要，故用 WARNING 而非 FATAL_ERROR
if(NOT OBJCOPY_X64 OR NOT NM_X64)
    message(WARNING
        "x64 binutils not found (stub 阶段 3 需要，builder 阶段 2 不受影响).\n"
        "  W64DEVKIT_BIN=${W64DEVKIT_BIN}\n"
        "  OBJCOPY_X64=${OBJCOPY_X64}\n"
        "  NM_X64=${NM_X64}\n"
        "  Override with -DW64DEVKIT_BIN=<path> or ensure w64devkit installed.")
endif()

# ---- 查找 x86 binutils（可选，仅 WINLOCK_BUILD_X86=ON 时需要） ----
if(WINLOCK_BUILD_X86)
    find_program(OBJCOPY_X86
        NAMES objcopy
        PATHS ${MSYS_MINGW32_BIN}
        NO_DEFAULT_PATH
        DOC "x86 objcopy (from msys2 mingw32) for x86 stub extraction")
    if(NOT OBJCOPY_X86)
        find_program(OBJCOPY_X86 NAMES objcopy DOC "x86 objcopy (fallback search)")
    endif()

    find_program(NM_X86
        NAMES nm
        PATHS ${MSYS_MINGW32_BIN}
        NO_DEFAULT_PATH
        DOC "x86 nm (from msys2 mingw32) for x86 stub symbol lookup")
    if(NOT NM_X86)
        find_program(NM_X86 NAMES nm DOC "x86 nm (fallback search)")
    endif()

    if(NOT OBJCOPY_X86 OR NOT NM_X86)
        message(WARNING
            "x86 binutils not found (x86 stub 阶段 3 需要).\n"
            "  MSYS_MINGW32_BIN=${MSYS_MINGW32_BIN}\n"
            "  OBJCOPY_X86=${OBJCOPY_X86}\n"
            "  NM_X86=${NM_X86}\n"
            "  阶段 2 builder 不受影响。用 -DWINLOCK_BUILD_X86=OFF 可关闭此警告。")
    endif()
endif()

# 导出变量给父 CMakeLists.txt
message(STATUS "[msvc_setup] vcvars64.bat: ${WINLOCK_VCVARS64}")
message(STATUS "[msvc_setup] W64DEVKIT_BIN:  ${W64DEVKIT_BIN}")
message(STATUS "[msvc_setup] MSYS_MINGW32:   ${MSYS_MINGW32_BIN}")
