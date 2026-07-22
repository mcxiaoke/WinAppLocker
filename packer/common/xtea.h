/*
 * winlock/common/xtea.h - XTEA 加密/解密共享实现
 *
 * 从 4 处重复实现抽取：
 *   - builder/builder.c:61-83         (xtea_encrypt_block + xtea_encrypt_buf)
 *   - builder/builder_reflective.c:164-188 (同上)
 *   - stub/stub.c:354-381             (xtea_decrypt_block + xtea_decrypt_buf)
 *   - reflective/loader.c:276-301     (同上)
 *
 * 设计：
 *   - #ifdef WINLOCK_PIC 区分 PIC 模式（stub 用，函数进 .lock.text 节）
 *     和 host 模式（builder/loader 用，普通 static inline）
 *   - PIC 模式用 section + noinline 属性（不带 used，避免未调用的 encrypt
 *     函数被强制 emit 到 stub 二进制中导致体积膨胀）
 *   - 加密和解密都放在同一个头文件
 *   - XTEA_DELTA / XTEA_ROUNDS 常量从 config.h 引用
 *
 * stub.c 只调用 decrypt 函数，encrypt 函数因 static inline + 无 used 属性
 * 而不会被 emit，保证 stub 二进制体积不变。
 */
#ifndef XTEA_H
#define XTEA_H

#include <stdint.h>
#include <stddef.h>
#include "config.h"   /* XTEA_DELTA / XTEA_ROUNDS */

/* PIC stub 模式：函数进 .lock.text 节；host 模式：普通 static inline。
 * 注意：不带 used 属性 —— 未调用的 encrypt 函数不应被 emit 到 stub 二进制。
 *
 * MSVC 与 GCC 的节名约定不同（见 winlock_compat.h）：
 *   - GCC:   __attribute__((section(".lock.text")))   → 节名 .lock.text
 *   - MSVC:  #pragma code_seg(".lock$text")           → 节名 .lock$text
 * 链接时 GCC 用 stub.ld KEEP(*(.lock.text))，MSVC 用 /MERGE:.lock$text=.lock
 */
#ifdef WINLOCK_PIC
  #ifdef _MSC_VER
    /* MSVC: 与 winlock_compat.h 的 WINLOCK_SECTION_TEXT 一致，无 used 概念
     * /OPT:REF 会自动移除未引用函数（如 stub 不用的 xtea_encrypt_*） */
    #define WINLOCK_XTEA_FN __pragma(code_seg(".lock$text")) __declspec(noinline)
  #else
    /* GCC: section + noinline 不带 used，--gc-sections 移除未调用函数
     * 加 unused 属性：stub 只用解密不用加密，避免 unused-function 警告 */
    #define WINLOCK_XTEA_FN __attribute__((section(".lock.text"), noinline, unused))
  #endif
#else
  #define WINLOCK_XTEA_FN
#endif

/* ---- XTEA 加密（builder 端使用） ---- */

/* XTEA 加密单个 8 字节块 */
WINLOCK_XTEA_FN
static void xtea_encrypt_block(uint32_t* v, const uint32_t* key) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0;
    int i;
    for (i = 0; i < XTEA_ROUNDS; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += XTEA_DELTA;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    v[0] = v0; v[1] = v1;
}

/* XTEA 加密缓冲区：8 字节块加密，尾部不足 8 字节按字节异或 key 字节 */
WINLOCK_XTEA_FN
static void xtea_encrypt_buf(uint8_t* data, size_t size, const uint32_t* key) {
    size_t n_blocks = size / 8;
    size_t i;
    for (i = 0; i < n_blocks; i++) {
        xtea_encrypt_block((uint32_t*)(data + i * 8), key);
    }
    size_t tail_off = n_blocks * 8;
    uint8_t* k = (uint8_t*)key;
    for (i = 0; i < size - tail_off; i++) {
        data[tail_off + i] ^= k[i];
    }
}

/* ---- XTEA 解密（stub / loader 端使用） ---- */

/* XTEA 解密单个 8 字节块（与 xtea_encrypt_block 互逆） */
WINLOCK_XTEA_FN
static void xtea_decrypt_block(uint32_t* v, const uint32_t* key) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = XTEA_DELTA * XTEA_ROUNDS;  /* 0xC6EF3720 */
    int i;
    for (i = 0; i < XTEA_ROUNDS; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= XTEA_DELTA;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0; v[1] = v1;
}

/* XTEA 解密缓冲区：8 字节块解密，尾部不足 8 字节按字节异或 key 字节
 * 与 xtea_encrypt_buf 互逆（同样的尾部处理） */
WINLOCK_XTEA_FN
static void xtea_decrypt_buf(uint8_t* data, size_t size, const uint32_t* key) {
    size_t n_blocks = size / 8;
    size_t i;
    for (i = 0; i < n_blocks; i++) {
        xtea_decrypt_block((uint32_t*)(data + i * 8), key);
    }
    size_t tail_off = n_blocks * 8;
    uint8_t* k = (uint8_t*)key;
    for (i = 0; i < size - tail_off; i++) {
        data[tail_off + i] ^= k[i];
    }
}

#undef WINLOCK_XTEA_FN

#endif /* XTEA_H */
