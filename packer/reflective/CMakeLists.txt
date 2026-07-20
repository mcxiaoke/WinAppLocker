# ============================================================
# reflective/CMakeLists.txt - 阶段 4：Reflective loader 的 MSVC 迁移
#
# 目标：编译 loader.c + loader_asm_xXX.asm 为 loader_x64.exe / loader_x86.exe
#       （builder_reflective 加壳时用作 stub）
#
# 当前阶段（步骤 C3b 完全 PIC 化）：
#   - /NODEFAULTLIB /ENTRY:loader_main 完全剥离 CRT
#   - /GS- 关闭 stack cookie（避免引用 __security_cookie）
#   - /Gs1048576 关闭栈探针（避免引用 __chkstk）
#   - /guard:cf- 关闭 CFG（避免引用 __guard_check_icall_fptr）
#   - /GL- 关闭 LTCG（避免引入额外 CRT 依赖）
#   - /Zl 不在 .obj 中引用默认库
#   - 体积从 C3 的 127KB 降到预期 15-25KB
#
# 关键设计：
#   1. loader.c 同时支持 GCC 和 MSVC 编译（用 #ifdef _MSC_VER 切换）：
#      - jump_to_oep 内联汇编（GCC）→ extern 调用 .asm（MSVC）
#      - __attribute__((section(".CRT$XLB"))) → WINLOCK_SECTION_CRT_XLB 宏
#      - main/WinMain → loader_main (void WINAPI) + ExitProcess
#   2. loader_asm_x64.asm / loader_asm_x86.asm 用 MASM 编译
#   3. 不像 stub 那样需要提取 .lock 节，loader 直接用 PE 整体作为 stub
#   4. /SUBSYSTEM:WINDOWS 让 loader 不弹 console（GUI 程序用）
# ============================================================

# ---- x64 loader ----
add_executable(loader_x64 WIN32
    loader.c
    loader_asm_x64.asm
)

target_compile_definitions(loader_x64 PRIVATE
    _WIN64
)
# 注意：不定义 WINLOCK_PIC（loader 不做 .lock 节提取，用普通 .text 节）
# xtea.h / sha256.h 在未定义 WINLOCK_PIC 时走 host 模式，函数为普通 static inline

# 编译选项：
#   /O2              速度优先（loader 不像 stub 那样体积敏感）
#   /GS-             关闭 stack cookie（避免引用 __security_cookie）
#   /Gs1048576       关闭栈探针（阈值设大，避免引用 __chkstk）
#   /GL-             关闭 LTCG（避免引入额外 CRT 依赖）
#   /Zl              不在 .obj 中引用默认库（配合 /NODEFAULTLIB）
#   /guard:cf-       关闭 CFG（避免生成 Guard CF 表，引用 __guard_check_icall_fptr）
#   /Gy              函数级链接（/OPT:REF 才能去掉未用函数）
# 用 $<$<COMPILE_LANGUAGE:C>:...> 限定只传给 C 编译器，避免传给 MASM
target_compile_options(loader_x64 PRIVATE
    $<$<COMPILE_LANGUAGE:C>:/O2>
    $<$<COMPILE_LANGUAGE:C>:/GS->
    $<$<COMPILE_LANGUAGE:C>:/Gs1048576>
    $<$<COMPILE_LANGUAGE:C>:/GL->
    $<$<COMPILE_LANGUAGE:C>:/Zl>
    $<$<COMPILE_LANGUAGE:C>:/guard:cf->
    $<$<COMPILE_LANGUAGE:C>:/Gy>
)

# 链接选项：
#   /NODEFAULTLIB    不链接任何默认库（CRT/kernel32 等都不链，需显式指定）
#   /ENTRY:loader_main 自定义入口（跳过 mainCRTStartup，不依赖 CRT 启动代码）
#   /SUBSYSTEM:WINDOWS  GUI 子系统（不弹 console）
#   /BASE:0x140000000   镜像基址（与 MinGW 基线一致，避免撞上输入 PE 的 0x400000）
#   /DYNAMICBASE:NO     关闭 ASLR（loader 自己处理重定位）
#   /OPT:REF             去掉未引用函数（配合 /Gy）
#   /OPT:ICF             合并相同 COMDAT 函数
#   /GUARD:NO            链接阶段禁用 CFG（避免生成 Guard CF 表）
#                       注意：cl.exe 用 /guard:cf-（带-后缀），link.exe 用 /GUARD:NO
target_link_options(loader_x64 PRIVATE
    /NODEFAULTLIB
    /ENTRY:loader_main
    /SUBSYSTEM:WINDOWS
    /BASE:0x140000000
    /DYNAMICBASE:NO
    /OPT:REF
    /OPT:ICF
    /GUARD:NO
)

# 显式链接 user32 + kernel32（/NODEFAULTLIB 后需手动指定）
# - user32: DialogBoxIndirectParamW / GetDlgItemTextW / EndDialog / MessageBoxW
# - kernel32: 通过 user32 间接依赖，但显式链接更稳定
target_link_libraries(loader_x64 PRIVATE user32 kernel32)

# 复制 loader_x64.exe 到 builder 期望的目录（与 stub 共用 ../reflective/）
# builder_reflective 默认在 ../reflective/ 找 loader_x64.exe
# CMake 默认输出在 build-msvc-x64/reflective/，需要复制到源码目录
add_custom_command(TARGET loader_x64 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:loader_x64>
            ${CMAKE_CURRENT_SOURCE_DIR}/loader_x64.exe
    COMMENT "Copy loader_x64.exe to source dir (for builder_reflective)"
    VERBATIM
)

# ---- x86 loader（可选，需 WINLOCK_BUILD_X86=ON + -A Win32） ----
# x86 编译需用 CMake -A Win32 重新配置（生成 Win32 平台的 .sln）
# 此时 CMAKE_SIZEOF_VOID_P == 4，会自动编译 loader_x86
if(WINLOCK_BUILD_X86 AND CMAKE_SIZEOF_VOID_P EQUAL 4)
    add_executable(loader_x86 WIN32
        loader.c
        loader_asm_x86.asm
    )

    target_compile_definitions(loader_x86 PRIVATE
    )
    # 注意：不定义 WINLOCK_PIC（与 x64 一致，loader 用普通 .text 节）

    target_compile_options(loader_x86 PRIVATE
        $<$<COMPILE_LANGUAGE:C>:/O2>
        $<$<COMPILE_LANGUAGE:C>:/GS->
        $<$<COMPILE_LANGUAGE:C>:/Gs1048576>
        $<$<COMPILE_LANGUAGE:C>:/GL->
        $<$<COMPILE_LANGUAGE:C>:/Zl>
        $<$<COMPILE_LANGUAGE:C>:/guard:cf->
        $<$<COMPILE_LANGUAGE:C>:/Gy>
    )

    # x86 链接选项：
    #   /FIXED:NO 必须配合 /DYNAMICBASE:NO（与 stub_x86 一样）
    #   - /DYNAMICBASE:NO  关闭 ASLR
    #   - /FIXED:NO        保留 .reloc 节（builder 读它做预 patch，
    #                     因为 loader_x86 用绝对地址引用静态数据）
    #   /BASE:0x10000     与 MinGW 基线一致（loader_x86.exe 自身 ImageBase）
    target_link_options(loader_x86 PRIVATE
        /NODEFAULTLIB
        /ENTRY:loader_main
        /SUBSYSTEM:WINDOWS
        /BASE:0x10000
        /DYNAMICBASE:NO
        /FIXED:NO
        /OPT:REF
        /OPT:ICF
        /GUARD:NO
    )

    target_link_libraries(loader_x86 PRIVATE user32 kernel32)

    add_custom_command(TARGET loader_x86 POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:loader_x86>
                ${CMAKE_CURRENT_SOURCE_DIR}/loader_x86.exe
        COMMENT "Copy loader_x86.exe to source dir (for builder_reflective)"
        VERBATIM
    )
endif()
