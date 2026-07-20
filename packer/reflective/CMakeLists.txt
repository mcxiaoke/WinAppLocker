# ============================================================
# reflective/CMakeLists.txt - 阶段 4：Reflective loader 的 MSVC 迁移
#
# 目标：编译 loader.c + loader_asm_xXX.asm 为 loader_x64.exe / loader_x86.exe
#       （builder_reflective 加壳时用作 stub）
#
# 当前阶段（步骤 C 起步）：
#   - MSVC + /MT 静态 CRT 编译（不剥离 CRT，先验证工具链能处理 loader.c + .asm）
#   - 后续 C3b 步骤才用 /NODEFAULTLIB 完全剥离 CRT，实现真正的 PIC 化
#
# 关键设计：
#   1. loader.c 同时支持 GCC 和 MSVC 编译（用 #ifdef _MSC_VER 切换）：
#      - jump_to_oep 内联汇编（GCC）→ extern 调用 .asm（MSVC）
#      - __attribute__((section(".CRT$XLB"))) → WINLOCK_SECTION_CRT_XLB 宏
#   2. loader_asm_x64.asm / loader_asm_x86.asm 用 MASM 编译
#      （与 stub_asm_xXX.asm 结构一致，但多一个 ret_addr 参数）
#   3. 不像 stub 那样需要提取 .lock 节，loader 直接用 PE 整体作为 stub
#   4. /SUBSYSTEM:WINDOWS 让 loader 不弹 console（GUI 程序用）
#      console 程序加壳后继承输入 PE 的 Subsystem，由 builder_reflective 设置
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
#   /O2        速度优先（loader 不像 stub 那样体积敏感）
#   /MT        静态 CRT（与 builder 一致，避免运行时缺 VCRUNTIME140.dll）
#   /Gy        函数级链接（/OPT:REF 才能去掉未用函数）
# 用 $<$<COMPILE_LANGUAGE:C>:...> 限定只传给 C 编译器，避免传给 MASM
target_compile_options(loader_x64 PRIVATE
    $<$<COMPILE_LANGUAGE:C>:/O2>
    $<$<COMPILE_LANGUAGE:C>:/Gy>
)

# 链接选项：
#   /SUBSYSTEM:WINDOWS  GUI 子系统（不弹 console）
#   /BASE:0x140000000   镜像基址（与 MinGW 基线一致，避免撞上输入 PE 的 0x400000）
#                       注意：曾用 /BASE:0x10000 导致系统在 0x400000 附近映射
#                       shared section，使 DontSleep (preferred_base=0x400000)
#                       的 VirtualAlloc 失败 → fallback_relocations → msvcrt
#                       _initterm 越界 AV。改为高地址与 MinGW 一致后修复。
#   /DYNAMICBASE:NO     关闭 ASLR（loader 自己处理重定位）
#   /OPT:REF             去掉未引用函数（配合 /Gy）
#   /OPT:ICF             合并相同 COMDAT 函数
target_link_options(loader_x64 PRIVATE
    /SUBSYSTEM:WINDOWS
    /BASE:0x140000000
    /DYNAMICBASE:NO
    /OPT:REF
    /OPT:ICF
)

# 链接 user32（DialogBoxParamW / LoadStringW / MsgBox 等）
target_link_libraries(loader_x64 PRIVATE user32)

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
        $<$<COMPILE_LANGUAGE:C>:/Gy>
    )

    # x86 链接选项：
    #   /FIXED:NO 必须配合 /DYNAMICBASE:NO（与 stub_x86 一样）
    #   - /DYNAMICBASE:NO 关闭 ASLR
    #   - /FIXED:NO       保留 .reloc 节（builder 读它做预 patch，
    #                     因为 loader_x86 用绝对地址引用静态数据）
    #   /BASE:0x10000     与 MinGW 基线一致（loader_x86.exe 自身 ImageBase）
    target_link_options(loader_x86 PRIVATE
        /SUBSYSTEM:WINDOWS
        /BASE:0x10000
        /DYNAMICBASE:NO
        /FIXED:NO
        /OPT:REF
        /OPT:ICF
    )

    target_link_libraries(loader_x86 PRIVATE user32)

    add_custom_command(TARGET loader_x86 POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:loader_x86>
                ${CMAKE_CURRENT_SOURCE_DIR}/loader_x86.exe
        COMMENT "Copy loader_x86.exe to source dir (for builder_reflective)"
        VERBATIM
    )
endif()
