/*
 * winlock/config.h - 共享配置（builder 与 stub 共用）
 *
 * WinLock demo: 新增 .text2 节 + stub 门禁壳
 * - builder 加密 .text 节，新增 .text2 节，写入 PIC stub
 * - Windows loader 正常加载（处理 reloc/IAT/TLS/SEH/CFG/CRT）
 * - stub 在 EP 执行：弹密码框 -> 校验 -> 解密 .text -> 跳 OEP
 *
 * 只加密第一个可执行节（仅门禁壳，非完整加壳器），
 * 保留所有 DataDirectory，最大化兼容性。
 */
#ifndef WINLOCK_CONFIG_H
#define WINLOCK_CONFIG_H

#include <stdint.h>

/* ---- 节名（≤8字节，伪装为看起来正常的额外代码节）
 *   原名 ".lock" 是 packer 强特征，改为 ".text2" 降低启发式可疑度。
 *   末尾 \0 填充到 8 字节（IMAGE_SECTION_HEADER.Name 固定 8 字节）。 */
#define WINLOCK_SECTION_NAME  ".text2\0\0"

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

/* ---- stub 身份标识常量（v5 新增）----
 * 编译期注入（CMake/MinGW -D）：stub_arch、stub_toolchain
 * POST_BUILD patch：stub_bin_ver、stub_build_time、stub_source_crc、stub_size、stub_githash
 */
#define STUB_ARCH_X86        1u
#define STUB_ARCH_X64        2u
#define STUB_TOOLCHAIN_MSVC  1u
#define STUB_TOOLCHAIN_MINGW 2u

/* stub 二进制版本，手动 bump：每次 stub 行为有变化时 +1 */
#ifndef STUB_BIN_VER
#define STUB_BIN_VER 0x0100u
#endif

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

/* ---- API / 模块名 DJB15 hash 常量（P1-1，借鉴 peldr） ----
 * 算法：h = 1993; for c in s: c = tolower(c); h = ((h<<4) - h) + c; h &= 0xFFFFFFFF
 * 大小写不敏感；用 tools/gen_api_hash.py 重新生成
 * 目的：避免在 .text2.rdata 中存明文 API 名（防 strings 抓取） */
#define WINLOCK_HASH_SEED 1993U
#define HASH_GETPROCADDRESS          0xAACF4941U
#define HASH_LOADLIBRARYA            0x124FBF05U
#define HASH_VIRTUALPROTECT           0x35051E8DU
#define HASH_EXITPROCESS              0x15AC1C58U
#define HASH_DIALOGBOXINDIRECTPARAMW  0x07C854A2U
#define HASH_ENDDIALOG                0xDB84676AU
#define HASH_GETDLGITEMTEXTW          0x08517DF5U
#define HASH_MESSAGEBOXW              0x000F09EAU
#define HASH_MOD_KERNEL32_DLL         0x6022D7CBU
#define HASH_MOD_USER32_DLL           0x20180C79U

/* ---- stub_data 结构 v2（builder 写入 / stub 读取） ----
 * 注意：所有 RVA 字段都是相对虚拟地址，stub 运行时加 PEB.ImageBaseAddress
 *
 * v2 新增：
 *   - salt[16] + pwd_hash[32]: SHA-256(password_utf8 + salt) 存 hash
 *     stub 计算 SHA-256(用户输入的密码转 UTF-8 + salt) 比对
 *   - max_retries: 最大重试次数
 *   - checksum: 简单 XOR 校验和（防 stub_data 被篡改）
 *
 * v6 变更：删除 password[64] 明文字段，强制 SHA-256 hash 校验
 *   （不再支持 v1 明文模式，简化结构 + 减小体积 128 字节）
 *
 * v4 新增：
 *   - security_cookie_rva: LOAD_CONFIG.SecurityCookie 的 RVA（0 = 无）
 *     stub 在解密 .text 后、跳 OEP 前用它初始化 cookie 为随机值
 *     （借鉴 AlushPacker 仅当 cookie 为默认值时才覆盖，
 *      借鉴 peldr 用 KUSER_SHARED_DATA.InterruptTime 作熵源，无 API 依赖）
 *
 * flags 位定义：
 *   bit1: 1=测试模式（跳过弹框，直接用硬编码 L"test123" 走 verify_password）
 *         用于 CI/自动化测试，验证 stub 完整流程无需 GUI 自动化
 *   bit2: 1=TLS callback 代理模式（stub_entry 跳过解密，由 stub_tls_callback 完成）
 *         builder 检测到原 PE 有 TLS callbacks 时启用
 *   bit3: 1=ASLR 启用（stub 解密 .text 后需重新应用 relocations）
 *         builder 保留 DYNAMIC_BASE 时启用
 *   bit4: 1=启用 PEB 反调试（P1-2）
 *         builder -d 时设置；默认关闭，避免开发调试受阻
 *         检查 PEB.BeingDebugged / NtGlobalFlag & 0x70 / KdDebuggerEnabled
 */
#define STUB_DATA_VERSION 6
#define STUB_DEFAULT_MAX_RETRIES 3

/* flags 位掩码（v6: 删除 STUB_FLAG_HASH，强制 hash 校验） */
#define STUB_FLAG_TEST_MODE    0x0002  /* 测试模式：跳过弹框，用硬编码密码 */
#define STUB_FLAG_TLS_PROXY    0x0004  /* TLS callback 代理模式 */
#define STUB_FLAG_ASLR         0x0008  /* ASLR 启用，需重新应用 relocations */
#define STUB_FLAG_ANTIDEBUG    0x0010  /* 启用 PEB 反调试（builder -d）*/

/* ---- stub 身份块（v5 新增，32 字节，8 字节对齐）----
 * 所有字段统一 stub_ 前缀；patch_stub_identity.py 在 POST_BUILD 阶段写入。
 * stub_arch / stub_toolchain 由 CMake/MinGW -D 编译期注入，
 * 其余 5 个字段由 patch_stub_identity.py 在 POST_BUILD patch。
 */
#pragma pack(push, 8)
typedef struct {
    uint32_t stub_arch;        /* 1=x86, 2=x64（编译期注入）*/
    uint32_t stub_toolchain;   /* 1=MSVC, 2=MinGW（编译期注入）*/
    uint32_t stub_bin_ver;     /* stub 二进制版本（POST_BUILD patch）*/
    uint32_t stub_build_time;  /* Unix 时间戳（POST_BUILD patch）*/
    uint32_t stub_source_crc;  /* 源码 CRC32（POST_BUILD patch）*/
    uint32_t stub_size;        /* stub.bin 文件大小（POST_BUILD patch）*/
    uint8_t  stub_githash[8];  /* git commit short hash ASCII（POST_BUILD patch，无 git 全 0）*/
} stub_identity_t;
#pragma pack(pop)

#pragma pack(push, 8)
typedef struct {
    uint64_t magic;            /* STUB_DATA_MAGIC，builder 据此定位         */
    uint16_t version;         /* 结构版本号 (v5 = 5)                        */
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
    /* v3 新增：重定位与 TLS 代理 */
    uint64_t image_base;     /* 原 PE OptionalHeader.ImageBase（preferred）*/
    uint64_t reloc_rva;      /* .reloc 节 RVA（0 = 无重定位表）            */
    uint32_t reloc_size;     /* .reloc 节 Size                              */
    uint32_t reserved32;     /* 对齐填充                                    */
    uint64_t orig_tls_callbacks; /* 原 PE TLS callbacks 数组 VA（0 = 无）  */
    /* v4 新增：SecurityCookie 初始化（P0-1）
     *   - builder 读取 LOAD_CONFIG.SecurityCookie VA 并减去 ImageBase 得到 RVA
     *   - stub 在解密 .text 后用 img_base + rva 计算 cookie 地址
     *   - 0 表示无 LOAD_CONFIG 或无 SecurityCookie 字段，跳过初始化 */
    uint64_t security_cookie_rva; /* LOAD_CONFIG.SecurityCookie 的 RVA（0 = 无）*/
    /* v5 新增：身份块（32 字节，放末尾、checksum 之前）
     *   - 编译期只填 stub_arch / stub_toolchain（CMake/MinGW -D 注入）
     *   - 其余字段初始化为 0，由 patch_stub_identity.py 在 POST_BUILD patch
     *   - identity 字段会自动并入 checksum 的 8 字节 XOR 链 */
    stub_identity_t identity;
    uint64_t checksum;       /* XOR 所有 64-bit 字段（防篡改）             */
} stub_data_t;
#pragma pack(pop)

/* stub_data_t 的 sizeof，手动维护（供 Python 脚本读取，避免硬编码漂移）
 * 当前 version=6，sizeof=192（v5=320，v6 删除 password[64] 减 128 字节）；
 * 每次结构变化时同步更新此宏和 STUB_DATA_VERSION */
#define STUB_DATA_SIZEOF 192

/* 编译期捕获 STUB_DATA_SIZEOF 与实际 sizeof 不一致
 * 用 typedef 数组技巧而非 _Static_assert：MSVC C 模式默认标准（C89/MS 扩展）
 * 不支持 C11 的 _Static_assert 关键字，且 stub.c 用 /Zl 不引用 CRT 无法用
 * static_assert 宏。typedef 数组在所有编译器（MSVC/GCC/Clang）都有效，
 * 当条件为 false 时数组大小为 -1 触发编译错误。*/
typedef char _static_assert_stub_data_sizeof[
    (sizeof(stub_data_t) == STUB_DATA_SIZEOF) ? 1 : -1];

/* builder 和 stub 都需要 extern 声明 stub_data（stub 中定义） */
#ifdef WINLOCK_STUB
extern volatile stub_data_t stub_data;
#endif

#endif /* WINLOCK_CONFIG_H */
