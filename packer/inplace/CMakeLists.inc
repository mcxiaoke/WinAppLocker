# ============================================================
# inplace/CMakeLists.inc - inplace 模式（builder + stub）
#
# 由顶层 CMakeLists-x64.txt 或 CMakeLists-x86.txt include()，根据 ARCH 变量决定
# 编译 x64 还是 x86 target。一次只编译一个架构的 stub。
#
# 变量：
#   ARCH    = "x64" 或 "x86"
#   SUFFIX  = "_x64" 或 "_x86"
#
# 产物 target：
#   builder_inplace           - 加壳器（不分架构，与输入 PE 解耦）
#   stub_inplace_${ARCH}      - stub（PIC，.lock 节提取）
#
# 设计要点：
#   1. builder_inplace 总是编译（每个架构都各自编一份）
#   2. stub target 名带 ${ARCH} 后缀（stub_inplace_x64 / stub_inplace_x86）
#   3. stub PIC 选项与 reflective/loader PIC 选项保持一致
#   4. x86 stub 额外 /FIXED:NO 保留 .reloc 节 + 复制 stub exe 给 builder 读
# ============================================================

# ---- builder_inplace（加壳器） ----
add_executable(builder_inplace
    ${WINLOCK_ROOT}/inplace/builder.c
)
target_link_libraries(builder_inplace PRIVATE advapi32)
target_compile_options(builder_inplace PRIVATE
    $<$<COMPILE_LANGUAGE:C>:/O2>
    $<$<COMPILE_LANGUAGE:C>:/W3>
)

# ---- stub_inplace_${ARCH}（PIC 自包含 stub） ----
# stub target 名带架构后缀，便于在 dist/ 区分
add_executable(stub_inplace_${ARCH} WIN32
    ${WINLOCK_ROOT}/inplace/stub.c
    ${WINLOCK_ROOT}/inplace/stub_asm_${ARCH}.asm
)

target_compile_definitions(stub_inplace_${ARCH} PRIVATE
    WINLOCK_STUB
    WINLOCK_PIC
)

# 编译选项：
#   /O1              - 体积优先优化（PIC stub 体积敏感）
#   /GS-             - 关闭 stack cookie（避免引用 __security_cookie）
#   /Gs1048576       - 关闭栈探针（阈值 1MB，避免引用 __chkstk）
#   /GL-             - 关闭 LTCG（避免引入额外 CRT 依赖）
#   /Zl              - 不在 .obj 中引用默认库（配合 /NODEFAULTLIB）
#   /Gy              - 函数级链接（/OPT:REF 才能去掉未用函数）
target_compile_options(stub_inplace_${ARCH} PRIVATE
    $<$<COMPILE_LANGUAGE:C>:/O1>
    $<$<COMPILE_LANGUAGE:C>:/GS->
    $<$<COMPILE_LANGUAGE:C>:/Gs1048576>
    $<$<COMPILE_LANGUAGE:C>:/GL->
    $<$<COMPILE_LANGUAGE:C>:/Zl>
    $<$<COMPILE_LANGUAGE:C>:/Gy>
)

# 链接选项：
#   /NODEFAULTLIB    - 不链接任何默认库（PIC 自包含）
#   /ENTRY:stub_entry - 自定义入口（不用 mainCRTStartup）
#   /SUBSYSTEM:WINDOWS - GUI 子系统
#   /BASE:0x10000    - 镜像基址（避免撞输入 PE 的 0x400000 或 0x140000000）
#   /DYNAMICBASE:NO  - 关闭 ASLR（stub 用绝对地址，需固定基址）
#   /OPT:REF /OPT:ICF - 去除未引用函数 + 合并相同 COMDAT
#
# x86 额外 /FIXED:NO：
#   保留 .reloc 节（builder 加壳 x86 PE 时需读它做预 patch）。
#   x64 用 RIP-relative 是 PIC，不需要 .reloc。
if(ARCH STREQUAL "x86")
    target_link_options(stub_inplace_${ARCH} PRIVATE
        /NODEFAULTLIB
        /ENTRY:stub_entry
        /SUBSYSTEM:WINDOWS
        /BASE:0x10000
        /DYNAMICBASE:NO
        /FIXED:NO
        /OPT:REF
        /OPT:ICF
    )
else()
    target_link_options(stub_inplace_${ARCH} PRIVATE
        /NODEFAULTLIB
        /ENTRY:stub_entry
        /SUBSYSTEM:WINDOWS
        /BASE:0x10000
        /DYNAMICBASE:NO
        /OPT:REF
        /OPT:ICF
    )
endif()

# 提取 .lock 节为 stub_inplace_${ARCH}.bin（用 Python 脚本替代 objcopy，
# 因为 MSVC link.exe 不合并不同特性的 .lock$X 子节）
add_custom_command(TARGET stub_inplace_${ARCH} POST_BUILD
    COMMAND ${Python3_EXECUTABLE}
            ${WINLOCK_ROOT}/cmake/extract_lock_section.py
            $<TARGET_FILE:stub_inplace_${ARCH}>
            ${CMAKE_CURRENT_BINARY_DIR}/stub_inplace_${ARCH}.bin
    COMMENT "Extracting .lock sections -> stub_inplace_${ARCH}.bin"
    VERBATIM
)

# x86 额外复制 stub_inplace_x86.exe 到 build 目录（builder 加壳 x86 PE 时读 .reloc 用）
if(ARCH STREQUAL "x86")
    add_custom_command(TARGET stub_inplace_${ARCH} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:stub_inplace_${ARCH}>
                ${CMAKE_CURRENT_BINARY_DIR}/stub_inplace_${ARCH}.exe
        COMMENT "Copy stub_inplace_x86.exe for builder .reloc reading"
        VERBATIM
    )
endif()
