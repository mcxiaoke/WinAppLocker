/*
 * winlock/common/winlock_compat.h - 编译器抽象层：GCC/MSVC 双兼容
 *
 * 集中所有 GCC/MSVC 差异宏，用于 stub.c / loader.c 的节区属性统一管理。
 * MSVC 迁移后只需改这一个文件。
 *
 * GCC 分支的宏展开与原始 __attribute__ 写法完全一致，保证 stub 二进制不变。
 */
#ifndef WINLOCK_COMPAT_H
#define WINLOCK_COMPAT_H

#ifdef _MSC_VER
  /* MSVC: 用 __pragma 包裹式宏（可在宏内使用 #pragma） */
  #define WINLOCK_SECTION_TEXT    __pragma(code_seg(".lock$text")) __declspec(noinline)
  #define WINLOCK_SECTION_DATA    __pragma(data_seg(".lock$data")) __declspec(align(16))
  #define WINLOCK_SECTION_RDATA   __pragma(const_seg(".lock$rdata"))
  #define WINLOCK_SECTION_ENTRY   __pragma(code_seg(".lock$entry")) __declspec(noinline)
  #define WINLOCK_SECTION_TLSCBM  __pragma(const_seg(".lock$tlscbm")) __declspec(align(16))
  #define WINLOCK_SECTION_TLSCB   __pragma(code_seg(".lock$tlscb")) __declspec(noinline)
  #define WINLOCK_SECTION_CRT_XLB __pragma(section(".CRT$XLB", read)) __declspec(allocate(".CRT$XLB"))
  /* TLS callback 数组边界（XLA=起始 NULL, XLZ=结束 NULL），让链接器合并 .CRT$XLA<XLB<XLZ */
  #define WINLOCK_SECTION_CRT_XLA __pragma(section(".CRT$XLA", read)) __declspec(allocate(".CRT$XLA"))
  #define WINLOCK_SECTION_CRT_XLZ __pragma(section(".CRT$XLZ", read)) __declspec(allocate(".CRT$XLZ"))
  /* TLS directory 结构节（_tls_used 放这里，链接器据此设置 DataDirectory[9]） */
  #define WINLOCK_SECTION_TLS_DIR __pragma(section(".rdata$T", read)) __declspec(allocate(".rdata$T"))
  #define WINLOCK_UNREACHABLE()   __assume(0)
  #define WINLOCK_NOINLINE        __declspec(noinline)
  #define WINLOCK_USED            /* MSVC 不需要 used 属性 */
  #define WINLOCK_OPTIMIZE_OFF    __pragma(optimize("", off))
  #define WINLOCK_OPTIMIZE_ON     __pragma(optimize("", on))
  #include <intrin.h>
  #define WINLOCK_SFENCE()        _mm_sfence()
#else
  /* GCC: 保持原样，与原始 __attribute__ 写法一致 */
  #define WINLOCK_SECTION_TEXT    __attribute__((section(".lock.text"), used, noinline))
  #define WINLOCK_SECTION_DATA    __attribute__((section(".lock.data"), used, aligned(16)))
  #define WINLOCK_SECTION_RDATA   __attribute__((section(".lock.rdata"), used, aligned(2)))
  #define WINLOCK_SECTION_ENTRY   __attribute__((section(".lock.entry"), used, noinline))
  #define WINLOCK_SECTION_TLSCBM  __attribute__((section(".lock.tlscbm"), used, aligned(16)))
  #define WINLOCK_SECTION_TLSCB   __attribute__((section(".lock.tlscb"), used, noinline))
  #define WINLOCK_SECTION_CRT_XLB __attribute__((section(".CRT$XLB"), used))
  /* TLS callback 数组边界（XLA=起始 NULL, XLZ=结束 NULL），让链接器合并 .CRT$XLA<XLB<XLZ */
  #define WINLOCK_SECTION_CRT_XLA __attribute__((section(".CRT$XLA"), used))
  #define WINLOCK_SECTION_CRT_XLZ __attribute__((section(".CRT$XLZ"), used))
  /* TLS directory 结构节（_tls_used 放这里，链接器据此设置 DataDirectory[9]） */
  #define WINLOCK_SECTION_TLS_DIR __attribute__((section(".rdata$T"), used))
  #define WINLOCK_UNREACHABLE()   __builtin_unreachable()
  #define WINLOCK_NOINLINE        __attribute__((noinline))
  #define WINLOCK_USED            __attribute__((used))
  #define WINLOCK_OPTIMIZE_OFF    __attribute__((optimize("O0")))
  #define WINLOCK_OPTIMIZE_ON
  #define WINLOCK_SFENCE()        __asm__ __volatile__("sfence" ::: "memory")
#endif

#endif /* WINLOCK_COMPAT_H */
