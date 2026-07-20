# ============================================================
# reflective/CMakeLists.inc - reflective 模式（builder_reflective + loader stub）
#
# 由顶层 CMakeLists-x64.txt 或 CMakeLists-x86.txt include()，根据 ARCH 变量决定
# 编译 x64 还是 x86 target。
#
# 变量：
#   ARCH    = "x64" 或 "x86"
#   SUFFIX  = "_x64" 或 "_x86"
#
# 产物 target：
#   builder_reflective        - reflective 加壳器（不分架构）
#   stub_reflective_${ARCH}   - reflective stub（PIC 自包含 loader）
#
# 命名：原 loader_x64.exe / loader_x86.exe 改名为 stub_reflective_x64.exe /
#       stub_reflective_x86.exe，与 inplace/stub_inplace_* 风格统一
# ============================================================

# ---- builder_reflective（加壳器） ----
add_executable(builder_reflective
    ${WINLOCK_ROOT}/reflective/builder_reflective.c
)
target_link_libraries(builder_reflective PRIVATE advapi32)
target_compile_options(builder_reflective PRIVATE
    $<$<COMPILE_LANGUAGE:C>:/O2>
    $<$<COMPILE_LANGUAGE:C>:/W3>
)

# ---- stub_reflective_${ARCH}（PIC 自包含 reflective loader） ----
# target 名：stub_reflective_x64 或 stub_reflective_x86
# 产物文件名：stub_reflective_x64.exe / stub_reflective_x86.exe
# 注意：x86 不再需要 aulldvrm.asm（64 位除法用纯 C 位运算实现，见 loader.c 的 pic_u64_divmod）
set(stub_srcs
    ${WINLOCK_ROOT}/reflective/loader.c
    ${WINLOCK_ROOT}/reflective/loader_asm_${ARCH}.asm
)

add_executable(stub_reflective_${ARCH} WIN32 ${stub_srcs})

# 编译选项：与 stub_inplace_${ARCH} 一致（PIC 自包含）
# /Zi /Zo: 生成调试信息（PDB），调试时用
target_compile_options(stub_reflective_${ARCH} PRIVATE
    $<$<COMPILE_LANGUAGE:C>:/O2>
    $<$<COMPILE_LANGUAGE:C>:/GS->
    $<$<COMPILE_LANGUAGE:C>:/Gs1048576>
    $<$<COMPILE_LANGUAGE:C>:/GL->
    $<$<COMPILE_LANGUAGE:C>:/Zl>
    $<$<COMPILE_LANGUAGE:C>:/guard:cf->
    $<$<COMPILE_LANGUAGE:C>:/Gy>
    $<$<COMPILE_LANGUAGE:C>:/Zi>
    $<$<COMPILE_LANGUAGE:C>:/Zo>
)

# 链接选项：
#   /BASE:0x140000000 (x64) / 0x10000 (x86) - 镜像基址与之前保持一致
#   /GUARD:NO       - 关闭 CFG（link.exe 语法，与 cl.exe 的 /guard:cf- 配合）
if(ARCH STREQUAL "x86")
    # x86 reflective stub 需要 /FIXED:NO 保留 .reloc（与 inplace x86 同理）
    # /DEBUG: 生成 PDB（调试用）
    target_link_options(stub_reflective_${ARCH} PRIVATE
        /NODEFAULTLIB
        /ENTRY:loader_main
        /SUBSYSTEM:WINDOWS
        /BASE:0x10000
        /DYNAMICBASE:NO
        /FIXED:NO
        /OPT:REF
        /OPT:ICF
        /GUARD:NO
        /DEBUG
    )
else()
    target_link_options(stub_reflective_${ARCH} PRIVATE
        /NODEFAULTLIB
        /ENTRY:loader_main
        /SUBSYSTEM:WINDOWS
        /BASE:0x140000000
        /DYNAMICBASE:NO
        /OPT:REF
        /OPT:ICF
        /GUARD:NO
        /DEBUG
    )
endif()

target_link_libraries(stub_reflective_${ARCH} PRIVATE user32 kernel32)

# stub_reflective_${ARCH}.exe 即是最终产物（与 inplace 不同：reflective 不需要提取 .lock 节，
# builder_reflective 直接读 stub 的整个 PE 文件）
