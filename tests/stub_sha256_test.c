/*
 * winlock/tests/stub_sha256_test.c - 验证 stub 内 SHA-256 密码逻辑
 *
 * 这个测试程序和 stub.c 共享同一份 sha256.h 实现，
 * 可以独立验证 stub 运行时 hash 计算是否正确。
 *
 * 测试用例：
 *   1. SHA-256("abc") == ba7816bf...15ad  (FIPS 标准向量)
 *   2. SHA-256("")    == e3b0c442...b855  (空输入)
 *   3. utf16le_to_utf8("test123") == "test123"
 *   4. 端到端：模拟 builder 计算 hash -> stub verify_password 验证
 *
 * 编译：
 *   gcc -O2 -Wall stub_sha256_test.c -o stub_sha256_test.exe
 *
 * 用法：
 *   ./stub_sha256_test.exe                       # 跑内置标准测试
 *   ./stub_sha256_test.exe <password> <salt_hex> <expected_hash_hex>
 *                                               # 验证 builder 写入的 hash
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* 不定义 WINLOCK_PIC，函数进入普通 .text 节 */
#include "../stub/sha256.h"

/* ----- 辅助函数 ----- */

static void print_hex(const uint8_t* b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static int hex2bin(const char* hex, uint8_t* out, size_t out_max) {
    size_t n = 0;
    while (hex[0] && hex[1] && n < out_max) {
        /* 跳过空格 */
        if (hex[0] == ' ') { hex++; continue; }
        int hi, lo;
        char c = hex[0];
        if (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        else return -1;
        c = hex[1];
        if (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
        else return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return (int)n;
}

/* 模拟 stub 内的 verify_password hash 计算（v2 模式）
 * 输入：utf8 密码、salt、期望 hash
 * 输出：1=匹配 0=不匹配 */
static int stub_verify_hash(const char* pwd_utf8, const uint8_t* salt, const uint8_t* expected_hash) {
    uint8_t digest[32];
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t*)pwd_utf8, strlen(pwd_utf8));
    sha256_update(&ctx, salt, 16);
    sha256_final(&ctx, digest);
    return bytes_eq_const(digest, expected_hash, 32);
}

/* 模拟 builder 的 hash 计算（用 Windows BCrypt：CALG_SHA_256）
 * 这里我们用同一份 SHA-256 实现，所以结果必然一致。
 * 真正的验证是：与 PowerShell [SHA256]::Create().ComputeHash() 比较。 */
static void builder_compute_hash(const char* pwd_utf8, const uint8_t* salt, uint8_t* out) {
    uint8_t input[256];
    size_t pwd_len = strlen(pwd_utf8);
    if (pwd_len > 240) { fprintf(stderr, "password too long\n"); exit(1); }
    memcpy(input, pwd_utf8, pwd_len);
    memcpy(input + pwd_len, salt, 16);
    sha256_hash(input, pwd_len + 16, out);
}

/* ----- 测试用例 ----- */

static int test_sha256_vectors(void) {
    printf("[test] SHA-256 standard vectors...\n");
    int pass = 0, total = 0;

    /* "abc" -> ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad */
    {
        uint8_t out[32];
        const char* abc = "abc";
        sha256_hash((const uint8_t*)abc, 3, out);
        uint8_t expect[32];
        const char* hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        hex2bin(hex, expect, 32);
        total++;
        if (bytes_eq_const(out, expect, 32)) {
            printf("  [PASS] SHA-256(\"abc\") = "); print_hex(out, 32); printf("\n");
            pass++;
        } else {
            printf("  [FAIL] SHA-256(\"abc\")\n    got:      "); print_hex(out, 32);
            printf("\n    expected: "); print_hex(expect, 32); printf("\n");
        }
    }

    /* "" -> e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855 */
    {
        uint8_t out[32];
        sha256_hash((const uint8_t*)"", 0, out);
        uint8_t expect[32];
        const char* hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        hex2bin(hex, expect, 32);
        total++;
        if (bytes_eq_const(out, expect, 32)) {
            printf("  [PASS] SHA-256(\"\") = "); print_hex(out, 32); printf("\n");
            pass++;
        } else {
            printf("  [FAIL] SHA-256(\"\")\n");
        }
    }

    /* "test123" (7 bytes, ASCII == UTF-8) - 仅展示正确值，不计入 pass/total */
    {
        uint8_t out[32];
        sha256_hash((const uint8_t*)"test123", 7, out);
        printf("  [INFO] SHA-256(\"test123\") = "); print_hex(out, 32); printf("\n");
    }

    printf("  -> %d/%d passed\n", pass, total);
    return pass == total;
}

static int test_utf16le_to_utf8(void) {
    printf("[test] utf16le_to_utf8...\n");
    int pass = 0, total = 0;

    /* "test123" as UTF-16LE */
    {
        const wchar_t* src = L"test123";
        uint8_t out[64] = {0};
        size_t n = utf16le_to_utf8(src, out, sizeof(out));
        total++;
        if (n == 7 && memcmp(out, "test123", 7) == 0) {
            printf("  [PASS] \"test123\" -> %zu bytes: %.*s\n", n, (int)n, out);
            pass++;
        } else {
            printf("  [FAIL] got %zu bytes: %.*s\n", n, (int)n, out);
        }
    }

    /* "密码" as UTF-16LE -> UTF-8 should be 6 bytes */
    {
        const wchar_t* src = L"密码";
        uint8_t out[64] = {0};
        size_t n = utf16le_to_utf8(src, out, sizeof(out));
        total++;
        if (n == 6) {
            printf("  [PASS] \"密码\" -> %zu bytes UTF-8\n", n);
            pass++;
        } else {
            printf("  [FAIL] \"密码\" got %zu bytes\n", n);
        }
    }

    printf("  -> %d/%d passed\n", pass, total);
    return pass == total;
}

static int test_end_to_end(void) {
    printf("[test] end-to-end: builder hash -> stub verify_password...\n");
    int pass = 0, total = 0;

    /* 模拟 builder 端：随机 salt + 计算 hash */
    const char* password = "test123";
    uint8_t salt[16] = {
        0x9E, 0x55, 0x15, 0xE4, 0xEF, 0xC4, 0x7B, 0x48,
        0x6C, 0x17, 0x21, 0x32, 0x88, 0x26, 0x19, 0x2E
    };
    uint8_t pwd_hash[32];
    builder_compute_hash(password, salt, pwd_hash);
    printf("  password = '%s'\n  salt     = ", password);
    print_hex(salt, 16); printf("\n  hash     = ");
    print_hex(pwd_hash, 32); printf("\n");

    /* 期望值（来自 PowerShell 验证过） */
    {
        uint8_t expect[32];
        const char* hex = "E085D0B20B45705FB313147F870DE06E40F1131C8BBFC2E13AED722F542230A5";
        hex2bin(hex, expect, 32);
        total++;
        if (bytes_eq_const(pwd_hash, expect, 32)) {
            printf("  [PASS] builder hash matches PowerShell SHA-256\n");
            pass++;
        } else {
            printf("  [FAIL] hash mismatch\n    got:      ");
            print_hex(pwd_hash, 32);
            printf("\n    expected: ");
            print_hex(expect, 32);
            printf("\n");
        }
    }

    /* stub verify_password 应接受正确密码 */
    total++;
    if (stub_verify_hash("test123", salt, pwd_hash)) {
        printf("  [PASS] stub accepts correct password\n");
        pass++;
    } else {
        printf("  [FAIL] stub rejected correct password\n");
    }

    /* stub verify_password 应拒绝错误密码 */
    total++;
    if (!stub_verify_hash("wrong", salt, pwd_hash)) {
        printf("  [PASS] stub rejects wrong password\n");
        pass++;
    } else {
        printf("  [FAIL] stub accepted wrong password\n");
    }

    /* stub verify_password 应拒绝空密码 */
    total++;
    if (!stub_verify_hash("", salt, pwd_hash)) {
        printf("  [PASS] stub rejects empty password\n");
        pass++;
    } else {
        printf("  [FAIL] stub accepted empty password\n");
    }

    printf("  -> %d/%d passed\n", pass, total);
    return pass == total;
}

int main(int argc, char** argv) {
    if (argc == 4) {
        /* 命令行模式：验证 builder 写入的 hash
         *   stub_sha256_test.exe <password> <salt_hex> <expected_hash_hex>
         * 用法：
         *   stub_sha256_test.exe test123 "9E 55 15 E4 ..." "E0 85 D0 B2 ..."
         */
        const char* password = argv[1];
        uint8_t salt[16];
        uint8_t expected_hash[32];
        int salt_len = hex2bin(argv[2], salt, sizeof(salt));
        int hash_len = hex2bin(argv[3], expected_hash, sizeof(expected_hash));
        if (salt_len != 16) {
            fprintf(stderr, "salt must be 16 bytes, got %d\n", salt_len);
            return 1;
        }
        if (hash_len != 32) {
            fprintf(stderr, "hash must be 32 bytes, got %d\n", hash_len);
            return 1;
        }
        printf("password: '%s'\n", password);
        printf("salt:     "); print_hex(salt, 16); printf("\n");
        printf("expected: "); print_hex(expected_hash, 32); printf("\n");

        /* 计算 stub 视角的 hash */
        uint8_t stub_digest[32];
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (const uint8_t*)password, strlen(password));
        sha256_update(&ctx, salt, 16);
        sha256_final(&ctx, stub_digest);
        printf("stub:     "); print_hex(stub_digest, 32); printf("\n");

        if (bytes_eq_const(stub_digest, expected_hash, 32)) {
            printf("[MATCH] stub hash == expected hash\n");
            return 0;
        } else {
            printf("[MISMATCH] stub hash != expected hash\n");
            return 1;
        }
    }

    /* 默认：跑内置测试套件 */
    int all_pass = 1;
    printf("=== stub_sha256_test: verify stub SHA-256 password logic ===\n\n");
    all_pass &= test_sha256_vectors();
    printf("\n");
    all_pass &= test_utf16le_to_utf8();
    printf("\n");
    all_pass &= test_end_to_end();
    printf("\n");
    printf("=== Result: %s ===\n", all_pass ? "ALL PASS" : "SOME FAILED");
    return all_pass ? 0 : 1;
}
