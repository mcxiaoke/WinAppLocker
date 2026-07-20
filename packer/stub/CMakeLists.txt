# ============================================================
# stub/CMakeLists.txt - 阶段 3：Inplace stub 的 MSVC 迁移（PIC 自包含）
#
# 目标：编译 stub.c + stub_asm_x64.asm 为 stub_x64.exe，
#       然后用 objcopy 提取 .lock 节为 stub_x64.bin
#
# 关键设计：
#   1. PIC 自包含（无 CRT）：
#      - /NODEFAULTLIB 不链接任何默认库
#      - /ENTRY:stub_entry 自定义入口（不用 mainCRTStartup）
#      - /GS- 关闭 stack cookie（避免 __security_cookie 引用 CRT）
#      - /Gs1048576 关闭栈探针（避免 __chkstk 引用 CRT）
#      - /GL- 关闭 LTCG（避免引入额外 CRT 依赖）
#      - /Zl 不在 obj 中引用默认库
#   2. 节布局（替代 stub.ld 链接脚本）：
#      - 用 /MERGE 把 .lock$text / .lock$data / .lock$rdata 等子节
#        合并成单一 .lock 节（stub_entry 用魔数定位，不依赖节内顺序）
#      - 注意：MSVC 的 #pragma code_seg(".lock$text") 产生 .lock$text 节
#              GCC 的 __attribute__((section(".lock.text"))) 产生 .lock.text 节
#              两者命名不同，对应到 winlock_compat.h 的宏定义
#   3. 不用 /ORDER（对自定义节无效），依赖 config.h 的 STUB_*_MAGIC 魔数定位
#   4. objcopy 继续用 w64devkit binutils（与编译器无关，详见 2.2 节）
#
# MSVC link.exe 不支持 GCC stub.ld 的 /DISCARD/，但 /NODEFAULTLIB + 无 CRT
# 已让 .CRT* / .eh_frame 等节不再生成。.pdata/.xdata 由 cl.exe 自动生成
# 用于 SEH，但 /NODEFAULTLIB 下没人注册它们，不影响运行。
# ============================================================

# ---- x64 stub ----
# 编译 stub.c + stub_asm_x64.asm 为 stub_x64.exe，然后提取 .lock 节为 stub_x64.bin
add_executable(stub_x64 WIN32
    stub.c
    stub_asm_x64.asm
)

# 编译定义：
#   WINLOCK_STUB  - stub 模式（启用 stub 专属代码路径）
#   WINLOCK_PIC   - PIC 自包含模式（影响 xtea.h 等是否进 .lock 节）
target_compile_definitions(stub_x64 PRIVATE
    WINLOCK_STUB
    WINLOCK_PIC
    _WIN64
)

# 编译选项：
#   /O1              - 体积优先优化（PIC stub 体积敏感）
#   /GS-             - 关闭 stack cookie（避免引用 __security_cookie）
#   /Gs1048576       - 关闭栈探针（阈值设大，避免引用 __chkstk）
#   /GL-             - 关闭 LTCG（避免引入额外 CRT 依赖）
#   /Zl              - 不在 .obj 中引用默认库
#   /Gy              - 函数级链接（/OPT:REF 才能去掉未用函数）
#   /Oy-             - 关闭帧指针省略（调试 stub 时便于回溯栈）
# 用 $<$<COMPILE_LANGUAGE:C>:...> 限定只传给 C 编译器，
# 避免传给 ASM_MASM（ml64.exe），触发 A4018 警告
target_compile_options(stub_x64 PRIVATE
    $<$<COMPILE_LANGUAGE:C>:/O1>
    $<$<COMPILE_LANGUAGE:C>:/GS->
    $<$<COMPILE_LANGUAGE:C>:/Gs1048576>
    $<$<COMPILE_LANGUAGE:C>:/GL->
    $<$<COMPILE_LANGUAGE:C>:/Zl>
    $<$<COMPILE_LANGUAGE:C>:/Gy>
)

# 链接选项：
#   /NODEFAULTLIB    - 不链接任何默认库（CRT/kernel32/user32 等都不链）
#   /ENTRY:stub_entry - 自定义入口为 stub_entry（不是 mainCRTStartup）
#   /SUBSYSTEM:WINDOWS - GUI 子系统（不弹 console）
#   /BASE:0x10000    - 镜像基址（与 stub.ld 的 --image-base=0x10000 一致，
#                     避免撞上输入 PE 的 0x400000 或 0x140000000）
#   /DYNAMICBASE:NO  - 关闭 ASLR（PIC stub 自处理重定位，不需 OS ASLR）
#   /OPT:REF         - 去掉未引用函数（配合 /Gy）
#   /OPT:ICF         - 合并相同 COMDAT 函数
#   /DEBUG:NONE      - 不生成调试信息（减小体积）
#
# 注意：不需要 /MERGE 把 .lock$text 等合并到 .lock。
#   COFF 节名约定中 `$` 是分组符（link.exe 自动处理）：
#   .lock$text / .lock$data / .lock$rdata 等同前缀节会自动合并成 .lock 节，
#   按 `$` 后字母序排列。link.exe 不支持带 `$` 的 /MERGE 参数（LNK1184）。
target_link_options(stub_x64 PRIVATE
    /NODEFAULTLIB
    /ENTRY:stub_entry
    /SUBSYSTEM:WINDOWS
    /BASE:0x10000
    /DYNAMICBASE:NO
    /OPT:REF
    /OPT:ICF
)

# 用 Python 脚本提取 .lock 节为 stub_x64.bin
# 替代 objcopy -O binary -j .lock，原因：
#   MSVC link.exe 不合并不同特性的 .lock$X 子节（LNK4078 警告），
#   导致 PE 中有多个独立的 .lock 节（.lock$text / .lock$rdata / .lock$data）。
#   objcopy -j .lock 会按 VA 范围输出，中间用 0 填充，bin 体积膨胀 5 倍。
#   Python 脚本按 VA 顺序拼接各节的 raw data（无 padding），与 GCC stub.ld
#   的 KEEP(*(.lock.*)) 行为一致。
add_custom_command(TARGET stub_x64 POST_BUILD
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_SOURCE_DIR}/cmake/extract_lock_section.py
            $<TARGET_FILE:stub_x64>
            ${CMAKE_CURRENT_BINARY_DIR}/stub_x64.bin
    COMMENT "Extracting .lock sections -> stub_x64.bin"
    VERBATIM
)

# ---- x86 stub（可选，需 WINLOCK_BUILD_X86=ON + -A Win32） ----
# x86 编译需用 CMake -A Win32 重新配置（生成 Win32 平台的 .sln）
# 此时 CMAKE_SIZEOF_VOID_P == 4，会自动编译 stub_x86
if(WINLOCK_BUILD_X86 AND CMAKE_SIZEOF_VOID_P EQUAL 4)
    add_executable(stub_x86 WIN32
        stub.c
        stub_asm_x86.asm
    )

    target_compile_definitions(stub_x86 PRIVATE
        WINLOCK_STUB
        WINLOCK_PIC
    )

    target_compile_options(stub_x86 PRIVATE
        $<$<COMPILE_LANGUAGE:C>:/O1>
        $<$<COMPILE_LANGUAGE:C>:/GS->
        $<$<COMPILE_LANGUAGE:C>:/Gs1048576>
        $<$<COMPILE_LANGUAGE:C>:/GL->
        $<$<COMPILE_LANGUAGE:C>:/Zl>
        $<$<COMPILE_LANGUAGE:C>:/Gy>
    )

    # x86 入口名带下划线前缀（__cdecl name decoration）
    target_link_options(stub_x86 PRIVATE
        /NODEFAULTLIB
        /ENTRY:_stub_entry
        /SUBSYSTEM:WINDOWS
        /BASE:0x10000
        /DYNAMICBASE:NO
        /OPT:REF
        /OPT:ICF
    )

    add_custom_command(TARGET stub_x86 POST_BUILD
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/cmake/extract_lock_section.py
                $<TARGET_FILE:stub_x86>
                ${CMAKE_CURRENT_BINARY_DIR}/stub_x86.bin
        COMMENT "Extracting .lock sections -> stub_x86.bin"
        VERBATIM
    )
endif()
