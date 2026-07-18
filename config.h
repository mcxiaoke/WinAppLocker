/*
 * winlock/config.h - 共享配置（builder 与 stub 共用）
 *
 * WinLock demo: 新增 .lock 节 + stub 门禁壳
 * - builder 加密 .text 节，新增 .lock 节，写入 PIC stub
 * - Windows loader 正常加载（处理 reloc/IAT/TLS/SEH/CFG/CRT）
 * - stub 在 EP 执行：弹密码框 -> 校验 -> 解密 .text -> 跳 OEP
 *
 * 只加密第一个可执行节（仅门禁壳，非完整加壳器），
 * 保留所有 DataDirectory，最大化兼容性。
 */
#ifndef WINLOCK_CONFIG_H
#define WINLOCK_CONFIG_H

#include <stdint.h>

/* ---- 节名（≤8字节，注意：objcopy 保留字 '.' 开头合法） ---- */
#define WINLOCK_SECTION_NAME  ".lock\0\0\0"

/* ---- 默认密码（宽字符） ---- */
#ifndef WINLOCK_DEFAULT_PASSWORD
#define WINLOCK_DEFAULT_PASSWORD L"hello123"
#endif

/* ---- XTEA 密钥（128位 = 4×uint32，演示值） ---- */
#ifndef WINLOCK_XTEA_KEY0
#define WINLOCK_XTEA_KEY0 0xDEADBEEFu
#define WINLOCK_XTEA_KEY1 0xCAFEBABEu
#define WINLOCK_XTEA_KEY2 0xFEEDFACEu
#define WINLOCK_XTEA_KEY3 0x12345678u
#endif

/* ---- XTEA 参数 ---- */
#define XTEA_DELTA   0x9E3779B9u
#define XTEA_ROUNDS  32

/* ---- stub_data 魔数（builder 在 stub.bin 中搜索此值定位 stub_data） ----
 * "WINLOCK!" -> 0x57 0x49 0x4E 0x4C 0x4F 0x43 0x4B 0x21
 * 小端 uint64: 0x214B434F4C4E4957
 */
#define STUB_DATA_MAGIC 0x214B434F4C4E4957ULL

/* ---- stub_entry 入口魔数（builder 搜索此值定位 stub_entry）
 * "ENTRYSTB" -> 0x45 0x4E 0x54 0x52 0x59 0x53 0x54 0x42
 * 小端 uint64: 0x42545359 52544E45
 */
#define STUB_ENTRY_MAGIC 0x4254535952544E45ULL

/* ---- stub_tls_callback 入口魔数（builder 搜索此值定位 stub_tls_callback）
 * "TLSCALLB" -> 0x54 0x4C 0x53 0x43 0x41 0x4C 0x4C 0x42
 * 小端 uint64: 0x424C4C4143534C54
 *
 * 用途：TLS_PROXY 模式下，builder 需要知道 stub_tls_callback 在 stub.bin
 *      中的偏移，以构造新 TLS callbacks 数组 [stub_tls_callback_VA, ...]。
 *      stub.c 在 stub_tls_callback 函数前放此 magic，builder 搜索定位。
 */
#define STUB_TLS_CB_MAGIC 0x424C4C4143534C54ULL

/* ---- 控件 ID ---- */
#define IDC_PWD_EDIT  1001

/* ---- stub_data 结构 v2（builder 写入 / stub 读取） ----
 * 注意：所有 RVA 字段都是相对虚拟地址，stub 运行时加 PEB.ImageBaseAddress
 *
 * v2 新增：
 *   - version: 2
 *   - salt[16] + pwd_hash[32]: SHA-256(password_utf8 + salt) 存 hash
 *     stub 计算 SHA-256(用户输入的密码转 UTF-8 + salt) 比对
 *   - max_retries: 最大重试次数
 *   - checksum: 简单 XOR 校验和（防 stub_data 被篡改）
 *   - password[] 保留（兼容 v1，flags.bit0=1 时忽略）
 *
 * flags 位定义：
 *   bit0: 1=用 hash 校验, 0=用明文 password
 *   bit1: 1=测试模式（跳过弹框，直接用硬编码 L"test123" 走 verify_password）
 *         用于 CI/自动化测试，验证 stub 完整流程无需 GUI 自动化
 *   bit2: 1=TLS callback 代理模式（stub_entry 跳过解密，由 stub_tls_callback 完成）
 *         builder 检测到原 PE 有 TLS callbacks 时启用
 *   bit3: 1=ASLR 启用（stub 解密 .text 后需重新应用 relocations）
 *         builder 保留 DYNAMIC_BASE 时启用
 */
#define STUB_DATA_VERSION 3
#define STUB_DEFAULT_MAX_RETRIES 3

/* flags 位掩码 */
#define STUB_FLAG_HASH         0x0001  /* 用 SHA-256 hash 校验（否则明文 password） */
#define STUB_FLAG_TEST_MODE    0x0002  /* 测试模式：跳过弹框，用硬编码密码 */
#define STUB_FLAG_TLS_PROXY    0x0004  /* TLS callback 代理模式 */
#define STUB_FLAG_ASLR         0x0008  /* ASLR 启用，需重新应用 relocations */

#pragma pack(push, 8)
typedef struct {
    uint64_t magic;            /* STUB_DATA_MAGIC，builder 据此定位         */
    uint16_t version;         /* 结构版本号 (v3 = 3)                        */
    uint16_t flags;           /* bit0: hash; bit1: test; bit2: tls proxy; bit3: aslr */
    uint16_t max_retries;     /* 密码错误最大重试次数                       */
    uint16_t reserved16;
    uint64_t oep_rva;         /* 原 AddressOfEntryPoint                     */
    uint64_t text_rva;        /* 加密的第一个可执行节 RVA                   */
    uint64_t text_size;       /* 加密大小（= min(VSize,RawSize) & ~7）      */
    uint32_t text_raw_size;   /* 该节 SizeOfRawData                         */
    uint32_t text_protect;    /* 该节原保护（PAGE_EXECUTE_READ 等）         */
    uint32_t xtea_key[4];    /* XTEA 密钥（随机生成）                       */
    uint8_t  salt[16];       /* PBKDF2 / SHA-256 salt（随机生成）           */
    uint8_t  pwd_hash[32];   /* SHA-256(password_utf8 + salt)              */
    wchar_t  password[64];   /* 明文密码（v1 兼容，flags.bit0=0 时使用）   */
    /* v3 新增：重定位与 TLS 代理 */
    uint64_t image_base;     /* 原 PE OptionalHeader.ImageBase（preferred）*/
    uint64_t reloc_rva;      /* .reloc 节 RVA（0 = 无重定位表）            */
    uint32_t reloc_size;     /* .reloc 节 Size                              */
    uint32_t reserved32;     /* 对齐填充                                    */
    uint64_t orig_tls_callbacks; /* 原 PE TLS callbacks 数组 VA（0 = 无）  */
    uint64_t checksum;       /* XOR 所有 64-bit 字段（防篡改）             */
} stub_data_t;
#pragma pack(pop)

/* builder 和 stub 都需要 extern 声明 stub_data（stub 中定义） */
#ifdef WINLOCK_STUB
extern volatile stub_data_t stub_data;
#endif

#endif /* WINLOCK_CONFIG_H */
