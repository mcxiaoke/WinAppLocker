# ============================================================
# CMakeLists.txt - winlock packer 顶层
#
# 用法：
#   cmake -S . -B build/x64 -G Ninja -DCMAKE_BUILD_TYPE=Release -DWINLOCK_ARCH=x64
#         （需先调用 vcvars64.bat 设置 MSVC 环境）
#   cmake -S . -B build/x86 -G Ninja -DCMAKE_BUILD_TYPE=Release -DWINLOCK_ARCH=x86
#         （需先调用 vcvarsall.bat x64_x86 设置 x64->x86 交叉编译环境）
#
# 设计要点：
#   - 顶层按 WINLOCK_ARCH 用 include() 引入 x64/cmake_config.cmake 或 x86/cmake_config.cmake
#   - 用 include() 而非 add_subdirectory()：避免嵌套目录导致产物落在 build/x64/x64/
#   - 消除 build.ps1 临时复制 CMakeLists-xXX.txt 为 CMakeLists.txt 的 hack
# ============================================================

cmake_minimum_required(VERSION 3.20)
project(winlock_packer C ASM_MASM)

# 顶层源码目录
set(WINLOCK_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

if(NOT DEFINED WINLOCK_ARCH)
    set(WINLOCK_ARCH "x64" CACHE STRING "Target arch: x64 or x86")
endif()

# 强制 MSVC
if(NOT MSVC)
    message(FATAL_ERROR "This project requires MSVC. Run vcvars64.bat / vcvarsall.bat first.")
endif()

# 引入公用脚本（vcvars / binutils 路径 + extract_lock_section.py）
include(${WINLOCK_ROOT}/cmake/msvc_setup.cmake)

# 全局头文件目录
include_directories(${WINLOCK_ROOT}/common)

# 全局 MSVC 编译选项
# /utf-8           源码与执行字符集均按 UTF-8 处理
# /Zc:preprocessor 启用一致预处理器
# /MT              静态 CRT（仅 builder 用，stub/loader 用 PIC 选项覆盖）
add_compile_options(
    $<$<COMPILE_LANGUAGE:C>:/utf-8>
    $<$<COMPILE_LANGUAGE:C>:/Zc:preprocessor>
    $<$<COMPILE_LANGUAGE:C>:/MT>
)
add_compile_definitions(
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_DEPRECATION
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

# ---- 按 WINLOCK_ARCH 引入对应配置（include 不创建子目录，产物直接落在 -B 指定目录）----
# 子目录的 CMakeLists.inc 用变量 ARCH 表示架构（x64 或 x86），
# 用变量 SUFFIX 表示文件名后缀（_x64 或 _x86）
if(WINLOCK_ARCH STREQUAL "x64")
    set(ARCH "x64")
    set(SUFFIX "_x64")
    add_compile_definitions(_WIN64)
    include(${WINLOCK_ROOT}/inplace/CMakeLists.inc)
    include(${WINLOCK_ROOT}/reflective/CMakeLists.inc)
    message(STATUS "=== winlock_packer x64 CMake configuration complete ===")
    message(STATUS "MSVC version: ${MSVC_VERSION}")
    message(STATUS "OBJCOPY_X64:  ${OBJCOPY_X64}")
    message(STATUS "NM_X64:       ${NM_X64}")
elseif(WINLOCK_ARCH STREQUAL "x86")
    set(ARCH "x86")
    set(SUFFIX "_x86")
    include(${WINLOCK_ROOT}/inplace/CMakeLists.inc)
    include(${WINLOCK_ROOT}/reflective/CMakeLists.inc)
    message(STATUS "=== winlock_packer x86 CMake configuration complete ===")
    message(STATUS "MSVC version: ${MSVC_VERSION}")
    message(STATUS "OBJCOPY_X86:  ${OBJCOPY_X86}")
    message(STATUS "NM_X86:       ${NM_X86}")
else()
    message(FATAL_ERROR "Unknown WINLOCK_ARCH: ${WINLOCK_ARCH} (expected x64 or x86)")
endif()
