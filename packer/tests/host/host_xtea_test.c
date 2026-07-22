/*
 * host_xtea_test.c - XTEA 加密/解密 host 模式单元测试
 *
 * 编译：cl host_xtea_test.c /Fe:host_xtea_test.exe /O2 /utf-8
 *       或 gcc host_xtea_test.c -o host_xtea_test.exe -O2
 *
 * 不定义 WINLOCK_PIC → xtea.h 走 host 模式分支（普通 static 函数）
 * 覆盖：单块往返、缓冲区往返、边界大小（0/1/7/8/9/16/100）、尾部异或逻辑
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* host 模式：不定义 WINLOCK_PIC */
#include "xtea.h"

static int g_pass = 0;
static int g_fail = 0;

static void check_int(const char* name, int got, int expected) {
    if (got == expected) {
        printf("[PASS] %s (%d)\n", name, got);
        g_pass++;
    } else {
        printf("[FAIL] %s: got=%d expected=%d\n", name, got, expected);
        g_fail++;
    }
}

static void check_mem(const char* name, const uint8_t* got, const uint8_t* expected, size_t n) {
    if (memcmp(got, expected, n) == 0) {
        printf("[PASS] %s\n", name);
        g_pass++;
    } else {
        printf("[FAIL] %s\n  got:      ", name);
        for (size_t i = 0; i < n; i++) printf("%02x", got[i]);
        printf("\n  expected: ");
        for (size_t i = 0; i < n; i++) printf("%02x", expected[i]);
        printf("\n");
        g_fail++;
    }
}

int main(void) {
    /* XTEA 测试密钥：4×uint32 = 128 位 */
    uint32_t key[4] = { 0xDEADBEEFu, 0xCAFEBABEu, 0xFEEDFACEu, 0x12345678u };

    /* ---- 单块 encrypt → decrypt 往返 ---- */
    {
        uint32_t v[2] = { 0x11223344u, 0x55667788u };
        uint32_t orig[2] = { v[0], v[1] };
        xtea_encrypt_block(v, key);
        /* 加密后应该不等于原文 */
        check_int("xtea_encrypt_block changes data", (v[0] == orig[0] && v[1] == orig[1]), 0);
        xtea_decrypt_block(v, key);
        /* 解密后应还原 */
        check_int("xtea_decrypt_block restores v[0]", v[0] == orig[0], 1);
        check_int("xtea_decrypt_block restores v[1]", v[1] == orig[1], 1);
    }

    /* ---- 缓冲区 encrypt → decrypt 往返：各种大小 ---- */
    {
        size_t sizes[] = { 0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 100, 256 };
        size_t n_tests = sizeof(sizes) / sizeof(sizes[0]);
        for (size_t i = 0; i < n_tests; i++) {
            size_t sz = sizes[i];
            uint8_t* data = (uint8_t*)malloc(sz > 0 ? sz : 1);
            uint8_t* orig = (uint8_t*)malloc(sz > 0 ? sz : 1);
            /* 填入伪随机字节 */
            for (size_t j = 0; j < sz; j++) {
                data[j] = (uint8_t)((j * 31 + 7) & 0xFF);
                orig[j] = data[j];
            }

            /* 加密 */
            xtea_encrypt_buf(data, sz, key);
            /* 加密后应该不同（除非 sz=0） */
            int same_after_enc = (sz == 0) ? 1 : (memcmp(data, orig, sz) == 0);
            if (sz > 0) {
                char name[64];
                snprintf(name, sizeof(name), "xtea_encrypt_buf(size=%zu) changes data", sz);
                check_int(name, same_after_enc, 0);
            }

            /* 解密 */
            xtea_decrypt_buf(data, sz, key);
            char name[64];
            snprintf(name, sizeof(name), "xtea round-trip (size=%zu)", sz);
            check_mem(name, data, orig, sz);

            free(data);
            free(orig);
        }
    }

    /* ---- 全 0 数据往返 ---- */
    {
        uint8_t data[16] = {0};
        uint8_t orig[16] = {0};
        xtea_encrypt_buf(data, 16, key);
        /* 全 0 加密后应非全 0（除非 key 也是 0，这里不是） */
        int all_zero = 1;
        for (int i = 0; i < 16; i++) if (data[i] != 0) { all_zero = 0; break; }
        check_int("xtea_encrypt_buf(zeros) produces non-zero", all_zero, 0);

        xtea_decrypt_buf(data, 16, key);
        check_mem("xtea round-trip zeros", data, orig, 16);
    }

    /* ---- 全 0xFF 数据往返 ---- */
    {
        uint8_t data[16];
        uint8_t orig[16];
        memset(data, 0xFF, 16);
        memset(orig, 0xFF, 16);
        xtea_encrypt_buf(data, 16, key);
        xtea_decrypt_buf(data, 16, key);
        check_mem("xtea round-trip 0xFF", data, orig, 16);
    }

    /* ---- 尾部异或逻辑：非 8 倍数大小 ----
     * size=9 → 块 0 (8 字节) 加密，尾部 1 字节异或 key[0]
     * 解密同样：块 0 解密，尾部 1 字节异或 key[0]
     * 异或是可逆的，所以 round-trip 应该正确
     */
    {
        uint8_t data[9] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
        uint8_t orig[9] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
        xtea_encrypt_buf(data, 9, key);
        xtea_decrypt_buf(data, 9, key);
        check_mem("xtea round-trip size=9 (tail xor)", data, orig, 9);
    }

    /* ---- 不同 key 不同密文 ---- */
    {
        uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        uint32_t key2[4] = { 0, 0, 0, 0 };
        uint8_t out1[8], out2[8];
        memcpy(out1, data, 8);
        memcpy(out2, data, 8);
        xtea_encrypt_buf(out1, 8, key);
        xtea_encrypt_buf(out2, 8, key2);
        check_int("xtea different keys → different ciphertext", memcmp(out1, out2, 8) != 0, 1);
    }

    /* ---- 同 key 同数据确定 ---- */
    {
        uint8_t data[8] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
        uint8_t out1[8], out2[8];
        memcpy(out1, data, 8);
        memcpy(out2, data, 8);
        xtea_encrypt_buf(out1, 8, key);
        xtea_encrypt_buf(out2, 8, key);
        check_mem("xtea same inputs → same ciphertext", out1, out2, 8);
    }

    /* ---- 汇总 ---- */
    printf("\n=== XTEA host 测试结果 ===\n");
    printf("通过: %d\n", g_pass);
    printf("失败: %d\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
