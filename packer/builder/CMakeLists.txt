# ============================================================
# builder/CMakeLists.txt - 阶段 2：纯 C builder 的 MSVC 迁移
#
# 两个目标：
#   builder              - in-place 加壳器（加密 .text + 新增 .lock 节）
#   builder_reflective   - 反射式加壳器（原 PE 整体嵌入 .payload 节）
#
# MSVC 兼容性分析（阶段 1 调研 + 阶段 2 验证）：
#   1. ##__VA_ARGS__（builder.c:57, builder_reflective.c:38 的 DBG 宏）
#      → GCC 扩展，MSVC 传统预处理器不支持
#      → 用 /Zc:preprocessor 启用一致预处理器解决，无需改源码
#   2. strdup / fopen / wcscpy 等 CRT 函数
#      → MSVC C4996 安全警告
#      → 顶层已加 _CRT_SECURE_NO_WARNINGS + _CRT_NONSTDC_NO_DEPRECATE
#   3. xtea.h 的 __attribute__((section, noinline))
#      → 仅 #ifdef WINLOCK_PIC 下生效，builder 不定义 WINLOCK_PIC，无影响
#   4. CryptoAPI（CryptGenRandom / CryptCreateHash / CryptHashData 等）
#      → 在 advapi32.lib，MSVC 不默认链接，需显式添加
#      → 注意：代码注释写 "BCrypt" 但实际用的是 Wincrypt API，不需要 bcrypt.lib
#   5. Resource API（LoadLibraryExW / UpdateResourceW 等，仅 builder_reflective）
#      → 在 kernel32.lib，MSVC 默认链接
#   6. 无 getopt / 无其他 MinGW 特有函数（手写 argv 解析）
#
# 结论：源码零修改，仅靠编译选项 + 链接库即可迁移
# ============================================================

# ---- In-place builder ----
# 加密 .text 节 + 新增 .lock 节 + 写入 stub.bin
# 依赖：common/config.h, common/xtea.h
add_executable(builder builder.c)

# 链接库：
#   advapi32 - CryptoAPI（CryptGenRandom 随机数 + CryptCreateHash SHA-256）
#   kernel32 - 默认链接（WideCharToMultiByte 等），显式列出便于清晰
target_link_libraries(builder PRIVATE advapi32)

# 编译选项：
#   /O2              - 优化（与 MinGW -O2 对齐）
#   /W3              - 警告等级 3（不用 /W4 避免现有代码噪音过大）
#   /MT              - 静态链接 CRT（顶层已全局设置，此处冗余但显式）
#   /Zc:preprocessor - 一致预处理器，支持 ##__VA_ARGS__（DBG 宏关键依赖）
target_compile_options(builder PRIVATE /O2 /W3 /MT /Zc:preprocessor)

# ---- Reflective builder ----
# 原 PE 整体嵌入 stub EXE 的 .payload 节
# 依赖：reflective/payload.h, common/config.h, common/xtea.h
add_executable(builder_reflective builder_reflective.c)

# 链接库：
#   advapi32 - CryptoAPI（与 builder 相同的随机数 + SHA-256）
#   kernel32 - 默认链接（Resource API：LoadLibraryExW / UpdateResourceW 等）
target_link_libraries(builder_reflective PRIVATE advapi32)

target_compile_options(builder_reflective PRIVATE /O2 /W3 /MT /Zc:preprocessor)
