/*
 * winlock/builder/builder_reflective.c - 反射式 packer builder（MVP v1 明文模式）
 *
 * 流程：
 *   1. 读输入 PE 文件（任意架构：x86/x64/ARM64/.NET 都行，反射式不挑食）
 *   2. 解析 PE 头：ImageBase / SizeOfImage / OEP / Subsystem / Machine
 *   3. 构造 payload：reflective_payload_t 头 + 原 PE 文件完整数据（v1 明文）
 *   4. 按输入 PE 的架构选预编译 stub EXE：
 *        x64 -> stub_reflective_x64.exe
 *        x86 -> stub_reflective_x86.exe
 *      ARM64 -> 不支持（无 ARM64 工具链），报错退出
 *   5. 在 stub EXE 末尾追加 .payload 节：
 *      - 新增节头（.payload）
 *      - 节内容 = reflective_payload_t + 原 PE 数据
 *      - 更新 NumberOfSections / SizeOfImage
 *      - 修改 Subsystem 为原 PE 的 Subsystem（让 GUI 程序保持 GUI）
 *      - 清零 CheckSum
 *   6. 写输出 EXE
 *
 * MVP 简化：
 *   - 不加密、不压缩、不复制 .rsrc 节
 *   - 支持 x64 和 x86 输入 PE（ARM64 暂不支持）
 *   - 不处理 overlay（直接读整个文件作为 payload_data）
 *   - 不修改 stub 的 entry（stub 用默认 mainCRTStartup -> main()）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <wincrypt.h>

#include "payload.h"
#include "../common/config.h"   /* XTEA_DELTA / XTEA_ROUNDS */

static int g_debug = 1;
#define DBG(fmt, ...) do { if (g_debug) printf(fmt, ##__VA_ARGS__); } while (0)

/* ---- 文件 IO ---- */

static uint8_t* read_file(const char* path, size_t* out_size) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t* buf = (uint8_t*)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    *out_size = (size_t)sz;
    return buf;
}

static int write_file(const char* path, const uint8_t* buf, size_t size) {
    FILE* f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }
    if (fwrite(buf, 1, size, f) != size) {
        fclose(f); return -1;
    }
    fclose(f);
    return 0;
}

/* ---- 输入 PE 信息（架构无关解析）---- */

typedef struct {
    uint16_t machine;
    uint64_t image_base;
    uint32_t size_of_image;
    uint32_t entry_rva;
    uint16_t subsystem;
    uint32_t file_alignment;
    uint32_t section_alignment;
} pe_info_t;

/* 解析 PE 头，提取关键信息
 * 支持 x64 / x86 / ARM64（ARM64 用 NT_HEADERS64 布局读）
 * 返回 0 成功，-1 失败 */
static int parse_pe(const uint8_t* pe, size_t pe_size, pe_info_t* info) {
    if (pe_size < sizeof(IMAGE_DOS_HEADER)) return -1;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;
    if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > pe_size) return -1;

    IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)(pe + dos->e_lfanew);
    if (nt64->Signature != IMAGE_NT_SIGNATURE) return -1;

    if (nt64->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        /* x86 用 32 位 OptionalHeader 布局 */
        IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)nt64;
        info->machine           = nt32->FileHeader.Machine;
        info->image_base        = nt32->OptionalHeader.ImageBase;
        info->size_of_image     = nt32->OptionalHeader.SizeOfImage;
        info->entry_rva         = nt32->OptionalHeader.AddressOfEntryPoint;
        info->subsystem         = nt32->OptionalHeader.Subsystem;
        info->file_alignment    = nt32->OptionalHeader.FileAlignment;
        info->section_alignment = nt32->OptionalHeader.SectionAlignment;
    } else {
        /* x64 / ARM64 都用 64 位 OptionalHeader 布局 */
        info->machine           = nt64->FileHeader.Machine;
        info->image_base        = nt64->OptionalHeader.ImageBase;
        info->size_of_image     = nt64->OptionalHeader.SizeOfImage;
        info->entry_rva         = nt64->OptionalHeader.AddressOfEntryPoint;
        info->subsystem         = nt64->OptionalHeader.Subsystem;
        info->file_alignment    = nt64->OptionalHeader.FileAlignment;
        info->section_alignment = nt64->OptionalHeader.SectionAlignment;
    }
    return 0;
}

/* ---- 加密工具：随机数 / SHA-256 / UTF-8 转换 / XTEA 加密 ----
 * 与 packer/builder/builder.c 共用同一套算法（CryptGenRandom + CryptoAPI）
 * stub 端 (loader.c) 用 common/sha256.h 的纯 C SHA-256 实现来校验，
 * 两端算法必须字节级一致（参考 tests/stub_sha256_test.c 的回归测试） */

/* 用 CryptGenRandom 生成密码学安全随机字节（XTEA key + salt） */
static int gen_random_bytes(void* buf, size_t size) {
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL,
                               CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    BOOL ok = CryptGenRandom(hProv, (DWORD)size, (BYTE*)buf);
    CryptReleaseContext(hProv, 0);
    return ok ? 0 : -1;
}

/* 用 CryptoAPI 计算 SHA-256（与 stub 端 sha256.h 字节级一致） */
static int sha256_hash(const uint8_t* data, size_t len, uint8_t* out32) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL ok = FALSE;
    DWORD hash_len = 32;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES,
                               CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return -1;
    }
    if (CryptHashData(hHash, (BYTE*)data, (DWORD)len, 0)) {
        ok = CryptGetHashParam(hHash, HP_HASHVAL, out32, &hash_len, 0);
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return ok ? 0 : -1;
}

/* UTF-16 -> UTF-8（去除 null 终止符，返回字节数） */
static int wstr_to_utf8(const wchar_t* src, uint8_t* dst, size_t dst_max) {
    int n = WideCharToMultiByte(CP_UTF8, 0, src, -1,
                                 (LPSTR)dst, (int)dst_max, NULL, NULL);
    if (n <= 0) return -1;
    return n - 1;  /* 去掉 null terminator */
}

/* XTEA 加密（共享实现，host 模式：普通 static inline） */
#include "../common/xtea.h"

/* ---- 用法 ---- */

static void usage(const char* prog) {
    printf("WinLock Reflective Packer v1/v2\n");
    printf("Usage: %s <input.exe> <output.exe> [options]\n", prog);
    printf("Options:\n");
    printf("  -p <pwd>, --password <pwd>  Encrypt payload with password (enables v2 mode)\n");
    printf("                              Stub will prompt for password dialog on launch\n");
    printf("  -t, --test                  Test mode: use hardcoded 'test123' password,\n");
    printf("                              skip dialog (for CI/automation)\n");
    printf("  --stub <path>               Path to reflective stub EXE\n");
    printf("                              (default: auto-select by input PE arch:\n");
    printf("                               x64 -> stub_reflective_x64.exe\n");
    printf("                               x86 -> stub_reflective_x86.exe)\n");
    printf("  --no-icon                   Skip icon/version resource copy (use stub default)\n");
    printf("  --debug / -v                Verbose output\n");
    printf("\nFeatures:\n");
    printf("  - Without -p/-t: plaintext payload v1 (no encryption, no password)\n");
    printf("  - With -p/-t:    XTEA-encrypted payload v2 + SHA-256(pwd+salt) hash check\n");
    printf("  - Supports x86 and x64 input PE (ARM64 not supported)\n");
    printf("  - Auto-select stub by input PE architecture\n");
    printf("  - Inherits input PE subsystem (GUI stays GUI)\n");
    printf("  - Copies input PE icon + version info to output (Explorer shows original icon)\n");
}

/* ---- 图标/版本资源复制 ----
 *
 * 反射式加壳后，输出 EXE 在 Explorer 里显示的是 stub 的默认图标（MinGW 链接器
 * 生成的 generic 图标），不是原 PE 的图标。原因是 OS/Explorer 显示图标时只看
 * stub 自己的 .rsrc 节，不知道 .payload 节里嵌入的原 PE 资源。
 *
 * 解决方案：用 Windows UpdateResource API 把原 PE 的图标和版本资源复制到
 * 输出 EXE 的 .rsrc 节。这样 Explorer 显示原图标，文件属性显示原版本信息。
 *
 * 策略：全量复制 RT_GROUP_ICON + RT_ICON + RT_VERSION。
 *   - MinGW 编译的 stub 通常没有任何图标资源，直接复制不会冲突
 *   - 如果原 PE 有多个图标 group（如 doubao.exe 有 6 个），全部复制，
 *     Windows 按 ID 最小的整数 group 作为主图标显示
 *   - RT_VERSION 全量复制，让文件属性显示原 PE 的版本信息
 *
 * 注意：UpdateResource 只动 stub 的 .rsrc 节，不影响 .payload 节。
 *       失败不致命（图标错不影响程序运行），只打印警告。 */

static HANDLE g_res_update_handle = NULL;

/* EnumResourceNamesW 回调：把单个资源从原 PE 复制到输出 EXE
 * type/name 可能是整数 ID（MAKEINTRESOURCE）或字符串指针，直接传递即可 */
static BOOL CALLBACK copy_res_callback(HMODULE hMod, LPCWSTR type, LPWSTR name, LONG_PTR lParam) {
    (void)lParam;
    HRSRC hRes = FindResourceW(hMod, name, type);
    if (!hRes) return TRUE;  /* 继续枚举其他资源 */
    HGLOBAL hMem = LoadResource(hMod, hRes);
    if (!hMem) return TRUE;
    LPVOID pData = LockResource(hMem);
    DWORD size = SizeofResource(hMod, hRes);
    if (!pData || !size) return TRUE;

    /* 写入输出 EXE（type/name 直接传，UpdateResourceW 支持整数 ID 和字符串） */
    if (!UpdateResourceW(g_res_update_handle, type, name,
                         MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                         pData, size)) {
        /* 失败不中断，继续复制其他资源 */
    }
    return TRUE;
}

/* 从 src_path 复制图标和版本资源到 dst_path
 * 返回 0 成功，-1 失败（失败不致命，调用方可继续） */
static int copy_resources(const wchar_t* src_path, const wchar_t* dst_path) {
    /* 用 LOAD_LIBRARY_AS_DATAFILE 加载原 PE，不执行任何代码，只读资源 */
    HMODULE hSrc = LoadLibraryExW(src_path, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!hSrc) {
        printf("[-] copy_resources: LoadLibraryExW(src) failed: %lu\n", GetLastError());
        return -1;
    }

    HANDLE hUpdate = BeginUpdateResourceW(dst_path, FALSE);
    if (!hUpdate) {
        printf("[-] copy_resources: BeginUpdateResourceW failed: %lu\n", GetLastError());
        FreeLibrary(hSrc);
        return -1;
    }

    g_res_update_handle = hUpdate;

    /* 复制图标资源（RT_GROUP_ICON + RT_ICON）和版本信息（RT_VERSION）
     * RT_* 宏是 MAKEINTRESOURCE 返回 LPWSTR，需 cast 成 LPCWSTR 以匹配
     * EnumResourceNamesW 的第二个参数类型（MinGW GCC 严格类型检查） */
    EnumResourceNamesW(hSrc, (LPCWSTR)RT_GROUP_ICON, copy_res_callback, 0);
    EnumResourceNamesW(hSrc, (LPCWSTR)RT_ICON,       copy_res_callback, 0);
    EnumResourceNamesW(hSrc, (LPCWSTR)RT_VERSION,    copy_res_callback, 0);

    BOOL ok = EndUpdateResourceW(hUpdate, FALSE);  /* FALSE = 提交更新 */
    FreeLibrary(hSrc);
    if (!ok) {
        printf("[-] copy_resources: EndUpdateResourceW failed: %lu\n", GetLastError());
        return -1;
    }
    return 0;
}

/* char* 转 wchar_t*（路径转换，用于 Windows W 系列 API） */
static int char_to_wchar(const char* src, wchar_t* dst, int dst_elems) {
    int n = MultiByteToWideChar(CP_ACP, 0, src, -1, NULL, 0);
    if (n == 0 || n > dst_elems) return -1;
    MultiByteToWideChar(CP_ACP, 0, src, -1, dst, n);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char* in_path = argv[1];
    const char* out_path = argv[2];
    /* stub_path = NULL 表示按输入 PE 架构自动选；--stub 显式覆盖 */
    const char* stub_path = NULL;
    int user_specified_stub = 0;
    int copy_icon = 1;  /* 默认复制图标/版本资源，--no-icon 关闭 */

    /* 密码相关参数
     *   - pwd_arg: 用户用 -p 指定的密码
     *   - test_mode: -t 测试模式，硬编码 "test123"（不弹框，CI 用）
     *   - 两者都未指定：v1 明文模式（向后兼容）*/
    const char* pwd_arg = NULL;
    int test_mode = 0;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--stub") == 0 && i + 1 < argc) {
            stub_path = argv[++i];
            user_specified_stub = 1;
        } else if (strcmp(argv[i], "--no-icon") == 0) {
            copy_icon = 0;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--password") == 0) {
            if (i + 1 >= argc) {
                printf("[-] -p requires argument\n");
                return 1;
            }
            pwd_arg = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--test") == 0) {
            test_mode = 1;
        } else if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-v") == 0) {
            g_debug = 1;
        } else {
            printf("[-] Unknown arg: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    /* 密码确定逻辑：
     *   - test_mode 优先：固定 "test123"，忽略 -p
     *   - 否则用 -p 指定的密码
     *   - 都没指定：use_pwd = 0，走 v1 明文模式 */
    int use_pwd = test_mode || (pwd_arg != NULL);
    wchar_t password[64];
    if (test_mode) {
        MultiByteToWideChar(CP_ACP, 0, "test123", -1, password, 63);
        password[63] = 0;
        pwd_arg = NULL;  /* test_mode 忽略 -p */
        printf("[+] TEST MODE: using hardcoded 'test123' (no dialog)\n");
    } else if (pwd_arg) {
        int n = MultiByteToWideChar(CP_ACP, 0, pwd_arg, -1, password, 63);
        if (n <= 0) {
            printf("[-] Invalid password (conversion failed)\n");
            return 1;
        }
        password[63] = 0;
        printf("[+] Password mode: payload will be XTEA-encrypted\n");
    }

    /* 1. 读输入 PE */
    size_t in_size = 0;
    uint8_t* in_pe = read_file(in_path, &in_size);
    if (!in_pe) return 1;
    printf("[+] Read input PE: %s (%zu bytes)\n", in_path, in_size);

    /* 2. 解析输入 PE */
    pe_info_t info;
    if (parse_pe(in_pe, in_size, &info) != 0) {
        printf("[-] Failed to parse input PE (not a valid PE file?)\n");
        free(in_pe);
        return 1;
    }
    const char* arch_str = "unknown";
    const char* default_stub_path = NULL;
    if (info.machine == IMAGE_FILE_MACHINE_AMD64) {
        arch_str = "x64";
        default_stub_path = "stub_reflective_x64.exe";
    } else if (info.machine == IMAGE_FILE_MACHINE_I386) {
        arch_str = "x86";
        default_stub_path = "stub_reflective_x86.exe";
    } else if (info.machine == IMAGE_FILE_MACHINE_ARM64) {
        arch_str = "ARM64";
    }
    const char* subsys_str = "unknown";
    if (info.subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) subsys_str = "GUI";
    else if (info.subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) subsys_str = "CUI(console)";
    printf("[+] Input PE: arch=%s ImageBase=0x%llx SizeOfImage=0x%x OEP=0x%x Subsystem=%u(%s)\n",
           arch_str, (unsigned long long)info.image_base,
           info.size_of_image, info.entry_rva,
           info.subsystem, subsys_str);

    /* 3. 决定 stub 路径
     *    用户没指定时按输入 PE 架构选默认 stub */
    if (!user_specified_stub) {
        if (!default_stub_path) {
            printf("[-] Unsupported input PE architecture (Machine=0x%04x)\n", info.machine);
            printf("    Only x86 (0x014c) and x64 (0x8664) are supported.\n");
            free(in_pe);
            return 1;
        }
        stub_path = default_stub_path;
        printf("[+] Auto-selected stub: %s (by input PE arch=%s)\n", stub_path, arch_str);
    } else {
        printf("[+] User-specified stub: %s\n", stub_path);
    }

    /* 4. 构造 payload
     *    v1 明文：payload_data = 整个原 PE 文件（含 PE 头 + 所有节 + overlay）
     *              stub 运行时按 PE 结构解析，overlay 自动忽略
     *    v2 加密：payload_data = XTEA(in_pe) + 尾部异或 key 字节
     *              stored_size == original_size（XTEA 不改变大小）
     *              stub 弹密码框 → SHA-256(utf8+salt) 校验 → XTEA 解密 → map_image
     */
    size_t payload_data_size = in_size;
    size_t total_payload_size = sizeof(reflective_payload_t) + payload_data_size;
    uint8_t* payload = (uint8_t*)calloc(total_payload_size, 1);
    if (!payload) {
        printf("[-] Out of memory for payload (%zu bytes)\n", total_payload_size);
        free(in_pe);
        return 1;
    }

    reflective_payload_t* hdr = (reflective_payload_t*)payload;
    hdr->magic         = REFLECTIVE_PAYLOAD_MAGIC;
    hdr->kdf_iters     = 0;
    hdr->reserved16    = 0;
    hdr->original_size = (uint64_t)in_size;
    hdr->stored_size   = (uint64_t)in_size;  /* XTEA 不改变大小 */
    hdr->oep_rva       = (uint64_t)info.entry_rva;
    hdr->image_base    = info.image_base;
    hdr->reserved32    = 0;
    hdr->checksum      = 0;          /* 暂不校验 */

    /* 先把原 PE 字节拷贝到 payload_data 区域（v2 时会被原地加密覆盖）*/
    memcpy(payload + sizeof(reflective_payload_t), in_pe, in_size);

    if (use_pwd) {
        /* ---- v2: XTEA 加密 + SHA-256(pwd+salt) 校验 ---- */
        uint32_t key[4];
        uint8_t  salt[16];
        if (gen_random_bytes(key, sizeof(key)) != 0) {
            printf("[-] Failed to generate random XTEA key\n");
            free(payload); free(in_pe); return 1;
        }
        if (gen_random_bytes(salt, sizeof(salt)) != 0) {
            printf("[-] Failed to generate random salt\n");
            free(payload); free(in_pe); return 1;
        }
        DBG("[*] XTEA key: %08X %08X %08X %08X\n",
            key[0], key[1], key[2], key[3]);

        /* pwd_hash = SHA-256(utf8(password) + salt)
         * stub 端 (loader.c) 用 sha256.h 的纯 C 实现复算，必须字节级一致 */
        uint8_t pwd_utf8[256];
        int pwd_utf8_len = wstr_to_utf8(password, pwd_utf8, sizeof(pwd_utf8));
        if (pwd_utf8_len < 0) {
            printf("[-] Failed to convert password to UTF-8\n");
            free(payload); free(in_pe); return 1;
        }
        uint8_t hash_input[256 + 16];
        memcpy(hash_input, pwd_utf8, pwd_utf8_len);
        memcpy(hash_input + pwd_utf8_len, salt, 16);
        uint8_t pwd_hash[32];
        if (sha256_hash(hash_input, pwd_utf8_len + 16, pwd_hash) != 0) {
            printf("[-] Failed to compute SHA-256 of password\n");
            free(payload); free(in_pe); return 1;
        }
        DBG("[*] pwd_hash = ");
        for (int k = 0; k < 32; k++) DBG("%02X", pwd_hash[k]);
        DBG("\n");

        /* XTEA 加密 payload_data 区域（原地） */
        xtea_encrypt_buf(payload + sizeof(reflective_payload_t),
                         payload_data_size, key);

        /* 填入 v2 字段 */
        hdr->version = REFLECTIVE_PAYLOAD_VERSION_V2;
        hdr->flags   = RFLAG_ENCRYPTED | RFLAG_HASH;
        if (test_mode) hdr->flags |= RFLAG_TEST_MODE;
        memcpy(hdr->salt, salt, 16);
        memcpy(hdr->pwd_hash, pwd_hash, 32);
        hdr->xtea_key[0] = key[0];
        hdr->xtea_key[1] = key[1];
        hdr->xtea_key[2] = key[2];
        hdr->xtea_key[3] = key[3];

        printf("[+] Built payload v2: header=%zu data=%zu total=%zu (XTEA encrypted, %s)\n",
               sizeof(reflective_payload_t), payload_data_size, total_payload_size,
               test_mode ? "test mode" : "password required");
    } else {
        /* ---- v1: 明文（向后兼容） ---- */
        hdr->version = REFLECTIVE_PAYLOAD_VERSION;
        hdr->flags   = 0;
        /* salt/nonce/pwd_hash/auth_tag/xtea_key 全 0（calloc 已清零）*/

        printf("[+] Built payload v1: header=%zu data=%zu total=%zu (plaintext, no encryption)\n",
               sizeof(reflective_payload_t), payload_data_size, total_payload_size);
    }

    /* 4. 读 stub EXE */
    size_t stub_size = 0;
    uint8_t* stub = read_file(stub_path, &stub_size);
    if (!stub) {
        printf("[-] Failed to read stub: %s\n", stub_path);
        free(payload); free(in_pe);
        return 1;
    }
    printf("[+] Read stub: %s (%zu bytes)\n", stub_path, stub_size);

    /* 5. 解析 stub PE 头（stub 可能是 x86 或 x64，按 Machine 字段解析）*/
    IMAGE_DOS_HEADER* s_dos = (IMAGE_DOS_HEADER*)stub;
    if (s_dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Stub is not a valid PE (bad DOS magic)\n");
        free(stub); free(payload); free(in_pe);
        return 1;
    }
    /* FileHeader 在 IMAGE_NT_HEADERS32/64 里偏移相同（都在 Signature 之后），
     * 先读 FileHeader.Machine 决定后续用什么类型解析 OptionalHeader */
    IMAGE_NT_HEADERS32* s_nt32 = (IMAGE_NT_HEADERS32*)(stub + s_dos->e_lfanew);
    IMAGE_NT_HEADERS64* s_nt64 = (IMAGE_NT_HEADERS64*)(stub + s_dos->e_lfanew);
    if (s_nt32->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Stub is not a valid PE (bad NT signature)\n");
        free(stub); free(payload); free(in_pe);
        return 1;
    }
    WORD s_machine = s_nt32->FileHeader.Machine;
    int stub_is_x64 = (s_machine == IMAGE_FILE_MACHINE_AMD64);
    int stub_is_x86 = (s_machine == IMAGE_FILE_MACHINE_I386);
    if (!stub_is_x64 && !stub_is_x86) {
        printf("[-] Stub has unsupported Machine: 0x%04x (need x86 or x64)\n", s_machine);
        free(stub); free(payload); free(in_pe);
        return 1;
    }
    /* 检查 stub 架构与输入 PE 架构匹配（防止用 x64 stub 加壳 x86 PE） */
    if (s_machine != info.machine) {
        printf("[-] Stub arch (0x%04x) doesn't match input PE arch (0x%04x)\n",
               s_machine, info.machine);
        printf("    Use --stub to specify a matching stub, or omit --stub for auto-select.\n");
        free(stub); free(payload); free(in_pe);
        return 1;
    }

    /* 用统一的字段提取避免后续代码 #ifdef 分支 */
    WORD  s_n_sec;
    DWORD s_file_align, s_sec_align;
    DWORD s_size_of_image;
    IMAGE_SECTION_HEADER* s_sec;
    if (stub_is_x64) {
        s_n_sec         = s_nt64->FileHeader.NumberOfSections;
        s_file_align    = s_nt64->OptionalHeader.FileAlignment;
        s_sec_align     = s_nt64->OptionalHeader.SectionAlignment;
        s_size_of_image = s_nt64->OptionalHeader.SizeOfImage;
        s_sec           = IMAGE_FIRST_SECTION(s_nt64);
    } else {
        s_n_sec         = s_nt32->FileHeader.NumberOfSections;
        s_file_align    = s_nt32->OptionalHeader.FileAlignment;
        s_sec_align     = s_nt32->OptionalHeader.SectionAlignment;
        s_size_of_image = s_nt32->OptionalHeader.SizeOfImage;
        s_sec           = IMAGE_FIRST_SECTION(s_nt32);
    }

    /* 检查 stub 是否已有 .payload 节（避免重复加壳）*/
    for (WORD i = 0; i < s_n_sec; i++) {
        if (memcmp(s_sec[i].Name, ".payload", 8) == 0) {
            printf("[-] Stub already has .payload section (already packed?)\n");
            free(stub); free(payload); free(in_pe);
            return 1;
        }
    }

    /* 5.5 扩展 stub 的 TLS 模板大小（解决反射式加载 PE 的新线程 TLS 越界问题）
     *
     * 背景：
     *   - stub 是 EXE，TLS slot 0 归 stub 所有
     *   - 原 PE 是反射式加载，OS 不为它分配 TLS slot
     *   - loader.c 设置原 PE 的 __tls_index = 0，让它复用 stub 的 slot 0
     *   - 但 stub 的 TLS 模板很小（如 8 字节），原 PE 的 TLS 可能很大（如 708 字节）
     *   - 新线程创建时，OS 用 stub 的模板初始化 TLP[0]，数据块只有 stub 的大小
     *   - 原 PE 在新线程里访问 TLP[0] + offset（offset > stub 大小）会越界读垃圾数据
     *   - 导致 std::thread 等检查 TLS 标志的代码崩溃（如 __fastfail(7)）
     *
     * 解决方案：
     *   - 增大 stub 的 TLS SizeOfZeroFill，使总大小 >= 原 PE 的 TLS 总大小
     *   - 这样 OS 为每个新线程分配的 TLS 数据块足够大，原 PE 访问不会越界
     *   - ZeroFill 部分 OS 自动填 0，原 PE 的 TLS 初始化代码会正确设置值
     *
     * 注意：这里只扩展 ZeroFill 大小，不修改 raw data 模板内容。
     *       如果原 PE 的 TLS 模板有非 0 初始值，新线程里这些值会是 0 而不是原模板值。
     *       但大多数程序的 TLS 初始值为 0，且 CRT 初始化会重新设置，所以这是可接受的 MVP 方案。
     */
    if (stub_is_x64) {
        IMAGE_DATA_DIRECTORY* s_tls_dir =
            &s_nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        IMAGE_DATA_DIRECTORY* in_tls_dir =
            (IMAGE_DATA_DIRECTORY*)&((IMAGE_NT_HEADERS64*)(in_pe +
            ((IMAGE_DOS_HEADER*)in_pe)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

        if (s_tls_dir->VirtualAddress && s_tls_dir->Size &&
            in_tls_dir->VirtualAddress && in_tls_dir->Size) {
            /* 原 PE 有 TLS 目录 */
            IMAGE_TLS_DIRECTORY64* s_tls = (IMAGE_TLS_DIRECTORY64*)
                (stub + s_tls_dir->VirtualAddress);  /* 注意：stub 映射到 0 基址读 RVA */
            /* 实际上 stub 不是按 image base 加载到内存的，RVA 就是文件偏移（对于有文件数据的节）
             * 但 TLS 目录可能在 .rdata 节，有文件数据，所以 RVA ≈ 文件偏移（需要节表转换）*/

            /* 用节表把 stub 的 TLS RVA 转成文件偏移 */
            DWORD s_tls_foff = 0;
            for (WORD i = 0; i < s_n_sec; i++) {
                if (s_sec[i].VirtualAddress <= s_tls_dir->VirtualAddress &&
                    s_tls_dir->VirtualAddress < s_sec[i].VirtualAddress +
                    (s_sec[i].Misc.VirtualSize ? s_sec[i].Misc.VirtualSize : s_sec[i].SizeOfRawData)) {
                    s_tls_foff = s_tls_dir->VirtualAddress - s_sec[i].VirtualAddress + s_sec[i].PointerToRawData;
                    break;
                }
            }

            /* 用节表把输入 PE 的 TLS RVA 转成文件偏移 */
            IMAGE_DOS_HEADER* in_dos = (IMAGE_DOS_HEADER*)in_pe;
            IMAGE_NT_HEADERS64* in_nt64 = (IMAGE_NT_HEADERS64*)(in_pe + in_dos->e_lfanew);
            IMAGE_SECTION_HEADER* in_sec = IMAGE_FIRST_SECTION(in_nt64);
            WORD in_n_sec = in_nt64->FileHeader.NumberOfSections;

            DWORD in_tls_foff = 0;
            for (WORD i = 0; i < in_n_sec; i++) {
                if (in_sec[i].VirtualAddress <= in_tls_dir->VirtualAddress &&
                    in_tls_dir->VirtualAddress < in_sec[i].VirtualAddress +
                    (in_sec[i].Misc.VirtualSize ? in_sec[i].Misc.VirtualSize : in_sec[i].SizeOfRawData)) {
                    in_tls_foff = in_tls_dir->VirtualAddress - in_sec[i].VirtualAddress + in_sec[i].PointerToRawData;
                    break;
                }
            }

            if (s_tls_foff && in_tls_foff) {
                IMAGE_TLS_DIRECTORY64* s_tls = (IMAGE_TLS_DIRECTORY64*)(stub + s_tls_foff);
                IMAGE_TLS_DIRECTORY64* in_tls = (IMAGE_TLS_DIRECTORY64*)(in_pe + in_tls_foff);

                ULONGLONG s_image_base = s_nt64->OptionalHeader.ImageBase;
                ULONGLONG in_image_base = in_nt64->OptionalHeader.ImageBase;

                /* 计算 stub TLS 总大小（raw + zero fill） */
                DWORD s_raw_size = (DWORD)(s_tls->EndAddressOfRawData - s_tls->StartAddressOfRawData);
                DWORD s_total = s_raw_size + (DWORD)s_tls->SizeOfZeroFill;

                /* 计算原 PE TLS 总大小 */
                DWORD in_raw_size = (DWORD)(in_tls->EndAddressOfRawData - in_tls->StartAddressOfRawData);
                DWORD in_total = in_raw_size + (DWORD)in_tls->SizeOfZeroFill;

                if (in_total > s_total) {
                    /* 需要扩展 stub 的 TLS 数据块大小
                     * 1. 增加 SizeOfZeroFill 使总大小 >= 原 PE 的总大小
                     * 2. 扩展 .tls 节的 VirtualSize（OS 可能根据节大小分配 TLS 数据块） */
                    DWORD new_zero_fill = in_total - s_raw_size;
                    printf("[+] Extending stub TLS size: %u -> %u (raw=%u, new ZeroFill=%u)\n",
                           s_total, in_total, s_raw_size, new_zero_fill);
                    s_tls->SizeOfZeroFill = (ULONG)new_zero_fill;

                    /* 找到 .tls 节并扩展其 VirtualSize */
                    for (WORD i = 0; i < s_n_sec; i++) {
                        if (memcmp(s_sec[i].Name, ".tls", 4) == 0) {
                            DWORD old_vs = s_sec[i].Misc.VirtualSize;
                            if (in_total > old_vs) {
                                s_sec[i].Misc.VirtualSize = in_total;
                                printf("[+]   .tls section VirtualSize: 0x%x -> 0x%x\n",
                                       old_vs, in_total);
                            }
                            break;
                        }
                    }
                } else {
                    printf("[+] Stub TLS size (%u) >= payload TLS size (%u), no extension needed\n",
                           s_total, in_total);
                }
            }
        } else if (!s_tls_dir->VirtualAddress) {
            printf("[+] Stub has no TLS directory, skip TLS extension\n");
        } else if (!in_tls_dir->VirtualAddress) {
            printf("[+] Payload PE has no TLS directory, skip TLS extension\n");
        }
    }
    /* TODO: x86 TLS 扩展（x86 的 TLS 目录结构不同，后续支持） */

    /* 找最后一个节的 VA 结束位置和文件结束位置
     * 新节的 VA 必须在所有现有节之后，按 SectionAlignment 对齐
     * 新节的 RawOffset 必须在所有现有节之后，按 FileAlignment 对齐 */
    DWORD last_va_end = 0;
    DWORD last_raw_end = 0;
    for (WORD i = 0; i < s_n_sec; i++) {
        DWORD va_end = s_sec[i].VirtualAddress +
                       (s_sec[i].Misc.VirtualSize ? s_sec[i].Misc.VirtualSize : s_sec[i].SizeOfRawData);
        DWORD raw_end = s_sec[i].PointerToRawData + s_sec[i].SizeOfRawData;
        if (va_end > last_va_end) last_va_end = va_end;
        if (raw_end > last_raw_end) last_raw_end = raw_end;
    }
    /* stub EXE 文件实际末尾可能超过最后一个节的 raw_end（如 certificate 表）
     * 用 max(last_raw_end, stub_size) 作为文件末尾 */
    if (stub_size > last_raw_end) last_raw_end = (DWORD)stub_size;

    /* 6. 计算新 .payload 节的位置 */
    DWORD new_va           = (last_va_end + s_sec_align - 1) & ~(s_sec_align - 1);
    DWORD new_vsize        = (DWORD)total_payload_size;
    DWORD new_vsize_aligned= (new_vsize + s_sec_align - 1) & ~(s_sec_align - 1);
    DWORD new_raw_off      = (last_raw_end + s_file_align - 1) & ~(s_file_align - 1);
    DWORD new_raw_size     = (DWORD)((total_payload_size + s_file_align - 1) & ~(s_file_align - 1));

    printf("[+] New .payload section: VA=0x%lx VSize=0x%lx RawOff=0x%lx RawSize=0x%lx\n",
           (unsigned long)new_va, (unsigned long)new_vsize,
           (unsigned long)new_raw_off, (unsigned long)new_raw_size);

    /* 检查节表是否有空间（节表在第一个节之前，每个节头 40 字节）*/
    DWORD sec_table_start = (DWORD)((uint8_t*)s_sec - stub);
    DWORD sec_table_end = sec_table_start + s_n_sec * sizeof(IMAGE_SECTION_HEADER);
    DWORD first_sec_raw = 0xFFFFFFFF;
    for (WORD i = 0; i < s_n_sec; i++) {
        if (s_sec[i].PointerToRawData > 0 && s_sec[i].PointerToRawData < first_sec_raw) {
            first_sec_raw = s_sec[i].PointerToRawData;
        }
    }
    /* SizeOfHeaders 通常覆盖节表，但加一个新节头后可能溢出
     * 这里简化检查：节表末尾 + 新节头(40B) 不能超过第一个节的 raw offset */
    if (sec_table_end + sizeof(IMAGE_SECTION_HEADER) > first_sec_raw) {
        printf("[-] No room in section table for .payload (need %zu, have %lu)\n",
               sizeof(IMAGE_SECTION_HEADER), (unsigned long)(first_sec_raw - sec_table_end));
        /* MVP 简化：直接报错，不做节表扩展 */
        free(stub); free(payload); free(in_pe);
        return 1;
    }

    /* 7. 准备输出缓冲区
     *   [stub 原始数据] + [padding 到 new_raw_off] + [.payload 节] + [padding] */
    size_t out_size = new_raw_off + new_raw_size;
    uint8_t* out = (uint8_t*)calloc(out_size, 1);
    if (!out) {
        printf("[-] Out of memory for output (%zu bytes)\n", out_size);
        free(stub); free(payload); free(in_pe);
        return 1;
    }

    /* 拷贝 stub 数据 */
    memcpy(out, stub, stub_size);

    /* 重新解析指针到 out 缓冲区（避免悬空指针）
     * 按 stub 架构用对应 NT_HEADERS 类型 */
    IMAGE_DOS_HEADER* o_dos = (IMAGE_DOS_HEADER*)out;
    IMAGE_NT_HEADERS32* o_nt32 = (IMAGE_NT_HEADERS32*)(out + o_dos->e_lfanew);
    IMAGE_NT_HEADERS64* o_nt64 = (IMAGE_NT_HEADERS64*)(out + o_dos->e_lfanew);
    IMAGE_SECTION_HEADER* o_sec = stub_is_x64 ? IMAGE_FIRST_SECTION(o_nt64)
                                              : IMAGE_FIRST_SECTION(o_nt32);

    /* 8. 添加 .payload 节头 */
    IMAGE_SECTION_HEADER* new_sec = &o_sec[s_n_sec];
    memset(new_sec, 0, sizeof(*new_sec));
    memcpy(new_sec->Name, ".payload", 8);
    new_sec->VirtualAddress    = new_va;
    new_sec->Misc.VirtualSize  = new_vsize;
    new_sec->SizeOfRawData     = new_raw_size;
    new_sec->PointerToRawData  = new_raw_off;
    /* .payload 是数据节：READ 即可（loader 只读不写）
     * 设 WRITE 会让某些 AV 觉得可疑，所以只 READ */
    new_sec->Characteristics   = IMAGE_SCN_CNT_INITIALIZED_DATA
                               | IMAGE_SCN_MEM_READ;

    /* 9. 写入 payload 数据 */
    memcpy(out + new_raw_off, payload, total_payload_size);

    /* 10. 更新 PE 头（按 stub 架构访问 OptionalHeader）*/
    DWORD new_size_of_image = new_va + new_vsize_aligned;
    if (stub_is_x64) {
        o_nt64->FileHeader.NumberOfSections++;
        o_nt64->OptionalHeader.SizeOfImage = new_size_of_image;
        /* 继承原 PE 的 subsystem（让 GUI 程序保持 GUI）
         * stub 编译为 console subsystem 便于开发，输出 EXE 改为原 PE 的 subsystem */
        o_nt64->OptionalHeader.Subsystem = info.subsystem;
        /* 清零 CheckSum（让 OS 不校验，CRT 不依赖 CheckSum）*/
        o_nt64->OptionalHeader.CheckSum = 0;
    } else {
        o_nt32->FileHeader.NumberOfSections++;
        o_nt32->OptionalHeader.SizeOfImage = new_size_of_image;
        o_nt32->OptionalHeader.Subsystem = info.subsystem;
        o_nt32->OptionalHeader.CheckSum = 0;
    }

    /* 11. 写输出 */
    if (write_file(out_path, out, out_size) != 0) {
        printf("[-] Failed to write output: %s\n", out_path);
        free(out); free(stub); free(payload); free(in_pe);
        return 1;
    }

    WORD o_n_sec = stub_is_x64 ? o_nt64->FileHeader.NumberOfSections
                               : o_nt32->FileHeader.NumberOfSections;
    printf("[+] Wrote output: %s (%zu bytes)\n", out_path, out_size);
    printf("[+]   Subsystem: %u(%s) (inherited from input PE)\n",
           info.subsystem, subsys_str);
    printf("[+]   NumberOfSections: %u -> %u\n", s_n_sec, o_n_sec);
    printf("[+]   SizeOfImage: 0x%lx -> 0x%lx\n",
           (unsigned long)s_size_of_image, (unsigned long)new_size_of_image);
    printf("[+]   Entry: stub mainCRTStartup (unchanged)\n");

    /* 12. 复制原 PE 的图标和版本资源到输出 EXE
     *     让 Explorer 显示原图标，文件属性显示原版本信息
     *     失败不致命（图标错不影响程序运行） */
    if (copy_icon) {
        wchar_t in_path_w[MAX_PATH], out_path_w[MAX_PATH];
        if (char_to_wchar(in_path, in_path_w, MAX_PATH) == 0 &&
            char_to_wchar(out_path, out_path_w, MAX_PATH) == 0) {
            printf("[+] Copying icon/version resources from input PE...\n");
            if (copy_resources(in_path_w, out_path_w) == 0) {
                printf("[+]   Resources copied (Explorer will show original icon)\n");
            } else {
                printf("[!]   Resource copy failed (continuing, icon may be wrong)\n");
            }
        } else {
            printf("[!] Failed to convert paths to wide chars, skip resource copy\n");
        }
    } else {
        printf("[+] Skipping icon/version copy (--no-icon)\n");
    }

    printf("[+] Done. Output will run stub -> reflective load -> jump to original OEP\n");

    free(out); free(stub); free(payload); free(in_pe);
    return 0;
}
