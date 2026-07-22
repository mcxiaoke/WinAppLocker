/*
 * winlock/reflective/payload.h - 反射式 loader 的 payload 容器格式
 *
 * builder 把原 PE 整体（v2 XTEA 加密）打包成 reflective_payload_t，
 * 嵌入到 stub EXE 的 .payload 节中。stub 运行时按 version + flags 解析。
 *
 * 设计原则：
 *   - 紧凑二进制头（不用 JSON，stub 端解析简单）
 *   - 魔数 + 版本号，支持后续演进
 *   - flags 位域扩展功能（压缩/反调试/反 dump 等均为可选位）
 *   - v2：XTEA + SHA-256(pwd+salt)（复用 winlock in-place 加密栈）
 *   - v3：ChaCha20-Poly1305 + PBKDF2（后期升级）
 *
 * 字段对齐：8 字节对齐，所有 64-bit 字段自然对齐
 */
#ifndef WINLOCK_REFLECTIVE_PAYLOAD_H
#define WINLOCK_REFLECTIVE_PAYLOAD_H

#include <stdint.h>

/* ---- 魔数 "WLOCKR\0\0" 小端 uint64 ----
 * 字节序列: 57 4C 4F 43 4B 52 00 00  ("WLOCKR" + 2 个 NUL)
 * 用于 builder 和 stub 双向识别 payload 头 */
#define REFLECTIVE_PAYLOAD_MAGIC 0x0000524B434F4C57ULL

/* ---- 版本号 ----
 * v2: XTEA 加密 + SHA-256(pwd+salt) KDF（复用 in-place 加密栈）
 * v3: ChaCha20-Poly1305 + PBKDF2-HMAC-SHA256（后期升级）
 *
 * REFLECTIVE_PAYLOAD_VERSION = 当前版本号（v2），builder 默认写此版本
 * stub 只接受 v2（按 hdr->version 校验）
 */
#define REFLECTIVE_PAYLOAD_VERSION    2   /* 当前版本：v2 XTEA + SHA-256 */

/* ---- flags 位定义 ---- */
#define RFLAG_TEST_MODE    0x0002  /* bit1: 测试模式（跳过弹框，硬编码 "test123"） */
#define RFLAG_COMPRESS     0x0004  /* bit2: 启用压缩（v3+，LZ4） */
#define RFLAG_ENCRYPTED    0x0008  /* bit3: 启用加密（v2+，XTEA 或 ChaCha20） */
#define RFLAG_ANTIDEBUG    0x0010  /* bit4: 启用 PEB 反调试（后期） */
#define RFLAG_ERASE_HDR    0x0020  /* bit5: 跳 OEP 前清零新 image 的 PE headers（后期） */
#define RFLAG_SCRUB_FN     0x0040  /* bit6: 跳 OEP 前清零 stub 的函数指针表（后期） */

/* ---- payload 容器头（builder 写入 / stub 读取） ----
 * 紧跟在头后面的是 ciphertext（RFLAG_ENCRYPTED 始终设置）
 * 大小 = stored_size */
#pragma pack(push, 8)
typedef struct {
    uint64_t magic;            /* REFLECTIVE_PAYLOAD_MAGIC，stub 据此识别         */
    uint16_t version;          /* 结构版本号（v2=2）                              */
    uint16_t flags;            /* 见 RFLAG_* 位定义                                */
    uint16_t kdf_iters;        /* KDF 迭代轮数（v3+ PBKDF2 用，v2 填 0）          */
    uint16_t reserved16;       /* 对齐填充                                         */
    uint64_t original_size;    /* 原 PE 未压缩明文大小（字节）                    */
    uint64_t stored_size;      /* 存储的 payload 大小（加密后）                   */
    uint64_t oep_rva;          /* 原 PE AddressOfEntryPoint RVA（备份，方便调试） */
    uint64_t image_base;       /* 原 PE preferred ImageBase（preferred，非实际）  */
    uint8_t  salt[16];         /* KDF salt                                        */
    uint8_t  nonce[12];        /* AEAD nonce（v3+ 用，v2 填 0）                   */
    uint8_t  pwd_hash[32];     /* KDF(password, salt) 校验用                      */
    uint8_t  auth_tag[16];     /* AEAD tag（v3+ 用，v2 填 0）                     */
    uint32_t xtea_key[4];      /* XTEA 密钥                                       */
    uint32_t size_of_image;    /* 原 PE SizeOfImage（加密模式 reserve 用）         */
    uint64_t checksum;         /* XOR 所有 8B 字段（防篡改）                       */
    /* 后跟 payload_data[stored_size] 字节 */
} reflective_payload_t;
#pragma pack(pop)

/* 静态断言：保证结构大小可预测 */
/* sizeof(reflective_payload_t) 应为：
 *   8 + 2+2+2+2 + 8+8+8+8 + 16+12+32+16 + 16+4 + 8 = 152 字节
 * （v2 删除 password[32] 减 64 字节，原 v1=216） */
#define REFLECTIVE_PAYLOAD_HEADER_SIZE 152

#endif /* WINLOCK_REFLECTIVE_PAYLOAD_H */
