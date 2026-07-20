# ============================================================
# winlock_packer - MSVC 构建系统顶层
#
# 方案 A 核心：强制 MSVC，弃用 GCC（stub 阶段 3+ 用 MASM/inline asm）
# binutils（objcopy/nm）继续用 w64devkit/msys2，与编译器无关
#
# 目录结构：
#   packer/CMakeLists.txt          <- 本文件（顶层）
#   packer/cmake/msvc_setup.cmake  <- vcvars / binutils 路径封装
#   packer/builder/CMakeLists.txt  <- 阶段 2（builder + builder_reflective）
#   packer/stub/CMakeLists.txt     <- 阶段 3 启用（stub PIC + MASM）
#   packer/reflective/CMakeLists.txt <- 阶段 4 启用（loader 反射式）
# ============================================================

cmake_minimum_required(VERSION 3.20)
project(winlock_packer C ASM_MASM)

# ---- 强制 MSVC（方案 A 核心） ----
# 不用 MSVC 直接报错，提示用户从 x64 Native Tools 命令行或 vcvars64.bat 运行
if(NOT MSVC)
    message(FATAL_ERROR
        "This project requires MSVC. Run from 'x64 Native Tools Command Prompt for VS 2026'\n"
        "or call vcvars64.bat before cmake.\n"
        "Detected CMAKE_C_COMPILER: ${CMAKE_C_COMPILER_ID}")
endif()

# ---- 选项 ----
option(WINLOCK_BUILD_X86 "Build x86 stub/loader (needs msys2 mingw32 binutils)" ON)
option(WINLOCK_BUILD_TESTS "Build test programs" ON)

# ---- 引入 vcvars / binutils 路径封装 ----
include(${CMAKE_SOURCE_DIR}/cmake/msvc_setup.cmake)

# ---- 全局包含目录 ----
# common/ 下有 config.h / xtea.h / sha256.h / peb_walk.h / winlock_compat.h / pe_meta.h
include_directories(${CMAKE_SOURCE_DIR}/common)

# ---- 全局 MSVC 编译选项 ----
# /utf-8             源码与执行字符集均按 UTF-8 处理（源文件含中文注释，
#                    MSVC 默认用系统代码页 936 解析会导致 C4819 警告 + 语法错误）
# /Zc:preprocessor   启用一致预处理器（支持 ##__VA_ARGS__，builder.c 的 DBG 宏需要）
# _CRT_SECURE_NO_WARNINGS  关闭 fopen/wcscpy 等 CRT 安全警告 C4996
# _CRT_NONSTDC_NO_DEPRECATE  关闭 strdup 等 POSIX 函数弃用警告
# NOMINMAX / WIN32_LEAN_AND_MEAN  精简 windows.h，避免 min/max 宏
add_compile_options(/utf-8 /Zc:preprocessor)
add_compile_definitions(
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_DEPRECATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)
# 默认静态链接 CRT（/MT），生成的 exe 无需 vcruntime140.dll
add_compile_options(/MT)

# ---- 子目录 ----
# 阶段 2：builder（纯 C，无 GCC 扩展，最简单的迁移）
add_subdirectory(builder)
# add_subdirectory(stub)        # 阶段 3 启用（stub PIC + MASM 汇编）
# add_subdirectory(reflective)  # 阶段 4 启用（loader 反射式）

if(WINLOCK_BUILD_TESTS)
    # add_subdirectory(tests)    # 后续阶段启用
endif()

message(STATUS "=== winlock_packer CMake configuration complete ===")
message(STATUS "MSVC version: ${MSVC_VERSION}")
message(STATUS "Architecture: ${CMAKE_C_COMPILER_ARCHITECTURE_ID}")
message(STATUS "OBJCOPY_X64:  ${OBJCOPY_X64}")
message(STATUS "NM_X64:       ${NM_X64}")
if(WINLOCK_BUILD_X86)
    message(STATUS "OBJCOPY_X86:  ${OBJCOPY_X86}")
    message(STATUS "NM_X86:       ${NM_X86}")
endif()
