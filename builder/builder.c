/*
 * winlock/builder/builder.c - PE 加壳器（v2）
 *
 * 修复与增强：
 *   - overlay 数据保留（避免堆崩溃）
 *   - Authenticode 签名剥离
 *   - 检测 TLS 回调 / .NET CLR / DLL，拒绝加壳
 *   - 清零 Bound Imports / Delay Import 中的标志（避免 loader 走捷径）
 *   - 随机生成 per-file XTEA key（用 RtlGenRandom）
 *   - 密码仍存明文（v3 改 SHA-256 hash）
 *
 * 流程：
 *   1. 读输入 PE
 *   2. 验证：x64 EXE，无 TLS 回调，无 CLR
 *   3. 找第一个可执行节
 *   4. 随机生成 XTEA key
 *   5. XTEA 加密该节 RawData
 *   6. 读 stub.bin，搜索 STUB_DATA_MAGIC，填充 stub_data
 *   7. 计算新 .lock 节位置（保留 overlay）
 *   8. 剥离 Authenticode 签名（清零 DataDirectory[4]）
 *   9. 清零 DataDirectory[11] (Bound Imports)
 *   10. 新增 .lock 节，写入 stub.bin
 *   11. 修改 AddressOfEntryPoint 指向 .lock
 *   12. 更新 SizeOfImage / NumberOfSections
 *   13. 写输出 PE（原 PE 数据 + overlay + .lock 节）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <wincrypt.h>
#include "../config.h"

/* ---- XTEA 加密 ---- */

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

/* ---- 随机数（用 CryptGenRandom） ---- */

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

/* ---- SHA-256 (用 Windows BCrypt) ---- */

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

/* ---- UTF-16 -> UTF-8 转换（builder 用 WideCharToMultiByte） ---- */

static int wstr_to_utf8(const wchar_t* src, uint8_t* dst, size_t dst_max) {
    int n = WideCharToMultiByte(CP_UTF8, 0, src, -1,
                                 (LPSTR)dst, (int)dst_max, NULL, NULL);
    if (n <= 0) return -1;
    /* n 包含 null terminator，去掉 */
    return n - 1;
}

/* ---- 辅助：节名转可打印字符串 ---- */

static void sec_name_str(const char* name8, char* out, size_t out_sz) {
    size_t i;
    for (i = 0; i < 8 && i < out_sz - 1; i++) {
        if (name8[i] == 0) break;
        out[i] = name8[i];
    }
    out[i] = 0;
}

/* ---- 辅助：从输入路径生成默认输出路径 <dir>/<base>_locked.exe ----
 * 例：C:\Tools\Bandizip\Bandizip.x64.exe -> C:\Tools\Bandizip\Bandizip.x64_locked.exe
 * 这样带依赖的 exe 加壳后仍在源目录测试，能找到同目录的 DLL */
static void make_default_output_path(const char* in_path, char* out, size_t out_sz) {
    /* 在 basename 中找最后一个 '.'（扩展名位置）*/
    const char* base = in_path;
    const char* p = in_path;
    while (*p) {
        if (*p == '\\' || *p == '/') base = p + 1;
        p++;
    }
    const char* ext = NULL;
    const char* q = base;
    while (*q) {
        if (*q == '.') ext = q;
        q++;
    }
    if (!ext) ext = q;  /* 无扩展名就放末尾 */
    size_t prefix_len = (size_t)(ext - in_path);
    const char* suffix = "_locked.exe";
    if (prefix_len + strlen(suffix) + 1 > out_sz) {
        /* 太长则简化处理 */
        snprintf(out, out_sz, "%s_locked.exe", in_path);
        return;
    }
    memcpy(out, in_path, prefix_len);
    strcpy(out + prefix_len, suffix);
}

/* ---- 主 ---- */

static void print_usage(const char* prog) {
    printf("WinLock v2 - PE Password Gate Packer\n");
    printf("\n");
    printf("Usage:\n");
    printf("  %s -i <input.exe> [-o <output.exe>] [-p <password>] [-t]\n", prog);
    printf("  %s <input.exe> <output.exe> [password] [--test]   (legacy)\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -i, --input <file>    Input PE EXE (x64)\n");
    printf("  -o, --output <file>   Output path (default: <dir>/<base>_locked.exe)\n");
    printf("  -p, --password <pwd>  Password (default: %ls)\n", WINLOCK_DEFAULT_PASSWORD);
    printf("  -t, --test            Test mode: stub uses hardcoded 'test123', no dialog\n");
    printf("                        (overrides -p; output defaults to source dir)\n");
    printf("  -h, --help            Show this help\n");
}

int main(int argc, char* argv[]) {
    const char* in_path = NULL;
    const char* out_path = NULL;
    const char* pwd_arg = NULL;
    int test_mode = 0;

    /* 检测是否带 '-' 参数（新式语法）*/
    int has_new_style = 0;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] != 0) {
            has_new_style = 1;
            break;
        }
    }

    if (has_new_style) {
        /* 新式参数：-i/-o/-p/-t */
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--input") == 0) {
                if (i + 1 >= argc) { printf("[-] -i requires argument\n"); return 1; }
                in_path = argv[++i];
            } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
                if (i + 1 >= argc) { printf("[-] -o requires argument\n"); return 1; }
                out_path = argv[++i];
            } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--password") == 0) {
                if (i + 1 >= argc) { printf("[-] -p requires argument\n"); return 1; }
                pwd_arg = argv[++i];
            } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--test") == 0) {
                test_mode = 1;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                print_usage(argv[0]);
                return 0;
            } else {
                printf("[-] Unknown option: %s\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        if (!in_path) {
            print_usage(argv[0]);
            return 1;
        }
    } else {
        /* 旧式位置参数（向后兼容） */
        const char* positional[3] = {NULL, NULL, NULL};
        int npos = 0;
        for (int i = 1; i < argc; i++) {
            if (npos < 3) positional[npos++] = argv[i];
        }
        if (npos < 2) {
            print_usage(argv[0]);
            return 1;
        }
        in_path  = positional[0];
        out_path = positional[1];
        if (npos >= 3) pwd_arg = positional[2];
    }

    /* 默认输出路径：<dir>/<base>_locked.exe（确保带依赖的 exe 在源目录可运行）*/
    char auto_out_path[1024];
    if (!out_path) {
        make_default_output_path(in_path, auto_out_path, sizeof(auto_out_path));
        out_path = auto_out_path;
    }

    /* 密码：测试模式固定为 "test123"，否则用 -p 或默认值 */
    wchar_t password[64];
    if (test_mode) {
        MultiByteToWideChar(CP_ACP, 0, "test123", -1, password, 63);
        password[63] = 0;
        pwd_arg = NULL;  /* 测试模式忽略 -p */
    } else if (pwd_arg) {
        int n = MultiByteToWideChar(CP_ACP, 0, pwd_arg, -1, password, 63);
        if (n <= 0) {
            printf("[-] Invalid password (conversion failed)\n");
            return 1;
        }
        password[63] = 0;
    } else {
        wcscpy(password, WINLOCK_DEFAULT_PASSWORD);
    }
    if (test_mode) {
        printf("[*] TEST MODE: stub will use hardcoded 'test123', no dialog\n");
    }

    /* 1. 读输入 PE */
    size_t in_size = 0;
    uint8_t* pe = read_file(in_path, &in_size);
    if (!pe) return 1;
    printf("[*] Loaded %s (%zu bytes = 0x%zX)\n", in_path, in_size, in_size);

    /* 2. 验证 PE */
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Bad DOS magic\n"); return 1;
    }
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Bad NT signature\n"); return 1;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("[-] Only x64 PE supported (got 0x%04X)\n",
               nt->FileHeader.Machine);
        return 1;
    }
    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        printf("[-] DLL not supported (use EXE)\n");
        return 1;
    }

    WORD n_sec = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* sec =
        (IMAGE_SECTION_HEADER*)((uint8_t*)nt + sizeof(IMAGE_NT_HEADERS));

    /* 检查 TLS 回调 */
    IMAGE_DATA_DIRECTORY* tls_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir->VirtualAddress != 0 && tls_dir->Size != 0) {
        printf("[!] TLS directory present (RVA=0x%X Size=0x%X)\n",
               tls_dir->VirtualAddress, tls_dir->Size);
        /* 尝试检查是否有 callback */
        BOOL has_callbacks = FALSE;
        for (WORD i = 0; i < n_sec; i++) {
            DWORD sva = sec[i].VirtualAddress;
            DWORD se  = sva + sec[i].Misc.VirtualSize;
            if (tls_dir->VirtualAddress >= sva && tls_dir->VirtualAddress < se) {
                IMAGE_TLS_DIRECTORY64* tls =
                    (IMAGE_TLS_DIRECTORY64*)(pe + sec[i].PointerToRawData
                                                  + (tls_dir->VirtualAddress - sva));
                if (tls->AddressOfCallBacks) {
                    /* AddressOfCallBacks 是 VA */
                    ULONGLONG img_base = nt->OptionalHeader.ImageBase;
                    ULONGLONG cb_va = tls->AddressOfCallBacks;
                    ULONGLONG cb_rva = cb_va - img_base;
                    /* 在节中找到 raw 指针 */
                    for (WORD j = 0; j < n_sec; j++) {
                        DWORD s2va = sec[j].VirtualAddress;
                        DWORD s2e  = s2va + sec[j].Misc.VirtualSize;
                        if (cb_rva >= s2va && cb_rva < s2e) {
                            uint64_t* callbacks =
                                (uint64_t*)(pe + sec[j].PointerToRawData
                                                + (cb_rva - s2va));
                            if (callbacks[0] != 0) {
                                has_callbacks = TRUE;
                            }
                            break;
                        }
                    }
                }
                break;
            }
        }
        if (has_callbacks) {
            printf("[-] PE has TLS callbacks. Not supported in v2.\n");
            printf("    Refusing to pack. (v3 will support TLS)\n");
            return 1;
        }
        printf("[+] TLS directory exists but no callbacks. OK.\n");
    }

    /* 检查 .NET CLR */
    IMAGE_DATA_DIRECTORY* clr_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    if (clr_dir->VirtualAddress != 0 && clr_dir->Size != 0) {
        printf("[-] .NET CLR detected. Cannot pack managed PE.\n");
        return 1;
    }

    printf("[*] PE: %u sections, ImageBase=0x%llX, EP RVA=0x%lX, SizeOfImage=0x%lX\n",
           n_sec,
           (unsigned long long)nt->OptionalHeader.ImageBase,
           (unsigned long)nt->OptionalHeader.AddressOfEntryPoint,
           (unsigned long)nt->OptionalHeader.SizeOfImage);
    printf("[*] DllCharacteristics=0x%04X, Subsystem=%u\n",
           nt->OptionalHeader.DllCharacteristics,
           nt->OptionalHeader.Subsystem);

    /* 打印所有节 */
    printf("[*] Sections:\n");
    DWORD last_raw_end = 0;
    DWORD last_va_end  = 0;
    for (WORD i = 0; i < n_sec; i++) {
        char nm[9] = {0};
        sec_name_str((const char*)sec[i].Name, nm, sizeof(nm));
        DWORD raw_end = sec[i].PointerToRawData + sec[i].SizeOfRawData;
        DWORD va_end  = sec[i].VirtualAddress + sec[i].Misc.VirtualSize;
        if (raw_end > last_raw_end) last_raw_end = raw_end;
        if (va_end  > last_va_end)  last_va_end  = va_end;
        printf("    [%u] %-8s VA=0x%lX VSize=0x%lX RawOff=0x%lX RawSize=0x%lX Char=0x%lX\n",
               i, nm,
               (unsigned long)sec[i].VirtualAddress,
               (unsigned long)sec[i].Misc.VirtualSize,
               (unsigned long)sec[i].PointerToRawData,
               (unsigned long)sec[i].SizeOfRawData,
               (unsigned long)sec[i].Characteristics);
    }

    /* overlay = 文件末尾超出最后节末尾的数据 */
    DWORD overlay_off = last_raw_end;
    size_t overlay_size = (in_size > overlay_off) ? (in_size - overlay_off) : 0;
    printf("[*] Overlay: offset=0x%lX size=0x%zX\n",
           (unsigned long)overlay_off, overlay_size);

    /* 检查 Authenticode 签名 */
    IMAGE_DATA_DIRECTORY* sec_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    if (sec_dir->VirtualAddress != 0 && sec_dir->Size != 0) {
        printf("[!] Authenticode signature present (off=0x%lX size=0x%lX). Will strip.\n",
               (unsigned long)sec_dir->VirtualAddress,
               (unsigned long)sec_dir->Size);
        /* 签名在 overlay 区，最后处理时去掉 */
        if (overlay_size > 0) {
            /* 签名通常就是 overlay 的全部或大部分，无法精确分割，
               简化处理：剥离整个 overlay，并清零 DataDirectory[4] */
            overlay_size = 0;
            printf("[!] Stripped overlay (signature) - %zu bytes\n",
                   (size_t)(in_size - overlay_off));
        }
    }

    /* 3. 找第一个可执行节 */
    IMAGE_SECTION_HEADER* text_sec = NULL;
    WORD text_sec_idx = 0;
    for (WORD i = 0; i < n_sec; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            text_sec = &sec[i];
            text_sec_idx = i;
            break;
        }
    }
    if (!text_sec) {
        for (WORD i = 0; i < n_sec; i++) {
            if (memcmp(sec[i].Name, ".text", 5) == 0) {
                text_sec = &sec[i];
                text_sec_idx = i;
                break;
            }
        }
    }
    if (!text_sec) {
        printf("[-] No executable section found\n");
        return 1;
    }
    char tnm[9] = {0};
    sec_name_str((const char*)text_sec->Name, tnm, sizeof(tnm));
    printf("[*] Target section [%u]: %s RVA=0x%lX VSize=0x%lX RawSize=0x%lX RawOff=0x%lX\n",
           text_sec_idx, tnm,
           (unsigned long)text_sec->VirtualAddress,
           (unsigned long)text_sec->Misc.VirtualSize,
           (unsigned long)text_sec->SizeOfRawData,
           (unsigned long)text_sec->PointerToRawData);

    /* 4. 保存原 EP / .text 信息 */
    uint64_t oep_rva      = nt->OptionalHeader.AddressOfEntryPoint;
    uint64_t text_rva     = text_sec->VirtualAddress;
    uint32_t text_raw_sz  = text_sec->SizeOfRawData;
    uint32_t text_virt_sz = text_sec->Misc.VirtualSize;
    uint32_t text_prot    = PAGE_EXECUTE_READ;
    if (text_sec->Characteristics & IMAGE_SCN_MEM_WRITE) {
        text_prot = (text_sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                  ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    } else if (!(text_sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
        text_prot = PAGE_READONLY;
    }

    /* 实际加密大小 = min(VirtualSize, RawSize)，向下对齐 8 字节
     * 原因：内存中节只映射 VirtualSize 字节，超出部分属于下一节。
     *       若 stub 解密整 RawSize 字节会越过节边界写坏下一节数据，
     *       导致程序跳到 OEP 时栈检查 (__security_cookie) 失败，
     *       触发 STATUS_STACK_BUFFER_OVERRUN (0xC0000409)。 */
    uint32_t enc_size = (text_virt_sz < text_raw_sz) ? text_virt_sz : text_raw_sz;
    enc_size &= ~7u;  /* XTEA 块对齐（8 字节） */
    if (enc_size != text_raw_sz) {
        printf("[!] VSize=0x%X RawSize=0x%X, using enc_size=0x%X (avoid overflow)\n",
               text_virt_sz, text_raw_sz, enc_size);
    }

    /* 5. 随机生成 XTEA key + salt */
    uint32_t key[4];
    uint8_t salt[16];
    if (gen_random_bytes(key, sizeof(key)) != 0) {
        printf("[-] Failed to generate random key\n");
        return 1;
    }
    if (gen_random_bytes(salt, sizeof(salt)) != 0) {
        printf("[-] Failed to generate random salt\n");
        return 1;
    }
    printf("[*] Generated random XTEA key: %08X %08X %08X %08X\n",
           key[0], key[1], key[2], key[3]);

    /* 计算密码 hash: SHA-256(utf8(password) + salt) */
    uint8_t pwd_utf8[256];
    int pwd_utf8_len = wstr_to_utf8(password, pwd_utf8, sizeof(pwd_utf8));
    if (pwd_utf8_len < 0) {
        printf("[-] Failed to convert password to UTF-8\n");
        return 1;
    }
    uint8_t pwd_hash[32];
    /* 拼接 utf8 + salt，然后 SHA-256 */
    uint8_t hash_input[256 + 16];
    memcpy(hash_input, pwd_utf8, pwd_utf8_len);
    memcpy(hash_input + pwd_utf8_len, salt, 16);
    if (sha256_hash(hash_input, pwd_utf8_len + 16, pwd_hash) != 0) {
        printf("[-] Failed to compute SHA-256 of password\n");
        return 1;
    }
    printf("[*] Password hash (SHA-256(utf8+salt)): ");
    for (int k = 0; k < 32; k++) printf("%02X", pwd_hash[k]);
    printf("\n");

    /* 6. XTEA 加密 .text RawData 前 enc_size 字节
     *    只加密内存中实际加载的部分（VirtualSize），不加密 RawSize 超出部分
     *    （那部分文件里有但运行时不加载，加密也无效，反而 stub 解密会越界） */
    printf("[*] Encrypting %u bytes (RawData) with XTEA\n", enc_size);
    xtea_encrypt_buf(pe + text_sec->PointerToRawData, enc_size, key);

    /* 7. 读 stub.bin */
    size_t stub_size = 0;
    uint8_t* stub = read_file("stub/stub.bin", &stub_size);
    if (!stub) {
        stub = read_file("stub.bin", &stub_size);
    }
    if (!stub) {
        /* 尝试相对路径 */
        char path[512];
        snprintf(path, sizeof(path), "%s/stub/stub.bin",
                 argc > 0 ? argv[0] : ".");
        stub = read_file(path, &stub_size);
    }
    if (!stub) {
        printf("[-] Cannot read stub.bin (run 'make stub/stub.bin' first)\n");
        return 1;
    }
    printf("[*] Loaded stub.bin (%zu bytes = 0x%zX)\n", stub_size, stub_size);

    /* 8. 在 stub.bin 中搜索 STUB_DATA_MAGIC */
    stub_data_t* sd = NULL;
    for (size_t off = 0; off + sizeof(stub_data_t) <= stub_size; off += 8) {
        if (*(uint64_t*)(stub + off) == STUB_DATA_MAGIC) {
            sd = (stub_data_t*)(stub + off);
            break;
        }
    }
    if (!sd) {
        printf("[-] STUB_DATA_MAGIC not found in stub.bin\n");
        return 1;
    }
    printf("[*] stub_data found at offset 0x%zX\n",
           (size_t)((uint8_t*)sd - stub));

    /* 填充 stub_data */
    sd->version       = STUB_DATA_VERSION;
    sd->flags         = STUB_FLAG_HASH;     /* 使用 hash 校验 */
    if (test_mode) {
        sd->flags    |= STUB_FLAG_TEST_MODE;  /* 测试模式：跳过弹框 */
    }
    sd->max_retries   = STUB_DEFAULT_MAX_RETRIES;
    sd->reserved16    = 0;
    sd->oep_rva       = oep_rva;
    sd->text_rva      = text_rva;
    sd->text_size      = enc_size;
    sd->text_raw_size = text_raw_sz;
    sd->text_protect  = text_prot;
    sd->xtea_key[0]   = key[0];
    sd->xtea_key[1]   = key[1];
    sd->xtea_key[2]   = key[2];
    sd->xtea_key[3]   = key[3];
    memcpy(sd->salt, salt, 16);
    memcpy(sd->pwd_hash, pwd_hash, 32);
    wcsncpy(sd->password, password, 63);  /* 保留明文兼容（生产应清零） */
    sd->password[63] = 0;
    /* 计算 checksum（XOR 所有 8 字节字段） */
    uint64_t* p = (uint64_t*)sd;
    uint64_t cs = 0;
    size_t sd_qwords = (sizeof(stub_data_t) - sizeof(uint64_t)) / sizeof(uint64_t);
    size_t qi;
    for (qi = 0; qi < sd_qwords; qi++) cs ^= p[qi];
    sd->checksum = cs;
    printf("[*] Password set to: '%ls' (stored as SHA-256 hash)\n", sd->password);

    /* 9. 计算新 .lock 节位置（保留 overlay） */
    DWORD file_align = nt->OptionalHeader.FileAlignment;
    DWORD sec_align = nt->OptionalHeader.SectionAlignment;

    /* new_raw_off = max(last_raw_end, in_size_without_overlay) aligned up */
    DWORD pe_data_end = overlay_off + (DWORD)overlay_size;  /* == in_size if no overlay */
    DWORD new_raw_off = (pe_data_end + file_align - 1) & ~(file_align - 1);
    DWORD new_raw_size = (DWORD)((stub_size + file_align - 1) & ~(file_align - 1));
    DWORD new_va = (last_va_end + sec_align - 1) & ~(sec_align - 1);
    DWORD new_vsize = (DWORD)stub_size;
    DWORD new_vsize_aligned = (new_vsize + sec_align - 1) & ~(sec_align - 1);

    printf("[*] New .lock section: RVA=0x%lX VSize=0x%lX RawOff=0x%lX RawSize=0x%lX\n",
           (unsigned long)new_va, (unsigned long)new_vsize,
           (unsigned long)new_raw_off, (unsigned long)new_raw_size);

    /* 10. 准备输出缓冲区
     *   [原 PE 数据 + overlay] + [padding] + [.lock 节] + [padding] */
    size_t out_size = new_raw_off + new_raw_size;
    uint8_t* out = (uint8_t*)calloc(out_size, 1);
    if (!out) {
        printf("[-] Out of memory (%zu bytes)\n", out_size);
        return 1;
    }

    /* 拷贝原 PE 数据（含 overlay） */
    size_t copy_size = pe_data_end;
    if (copy_size > in_size) copy_size = in_size;
    memcpy(out, pe, copy_size);

    /* 重新解析指针 */
    dos = (IMAGE_DOS_HEADER*)out;
    nt  = (IMAGE_NT_HEADERS*)(out + dos->e_lfanew);
    sec = (IMAGE_SECTION_HEADER*)((uint8_t*)nt + sizeof(IMAGE_NT_HEADERS));

    /* 11. 剥离 Authenticode 签名（清零 DataDirectory[4]） */
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress != 0) {
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
        printf("[+] Stripped Authenticode signature directory entry\n");
    }

    /* 12. 清零 Bound Imports（避免 loader 走捷径跳过 IAT 解析） */
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress != 0) {
        printf("[!] Bound Imports detected, clearing\n");
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
    }

    /* 13. 添加新 .lock 节头 */
    IMAGE_SECTION_HEADER* new_sec = &sec[n_sec];
    memset(new_sec, 0, sizeof(*new_sec));
    memcpy(new_sec->Name, WINLOCK_SECTION_NAME, 8);
    new_sec->VirtualAddress    = new_va;
    new_sec->Misc.VirtualSize  = new_vsize;
    new_sec->SizeOfRawData     = new_raw_size;
    new_sec->PointerToRawData = new_raw_off;
    new_sec->Characteristics   = IMAGE_SCN_CNT_CODE
                              | IMAGE_SCN_MEM_EXECUTE
                              | IMAGE_SCN_MEM_READ
                              | IMAGE_SCN_MEM_WRITE;

    /* 14. 拷贝 stub.bin 到新节 */
    memcpy(out + new_raw_off, stub, stub_size);
    /* 剩余填充由 calloc 自动清零 */

    /* 15. 更新 PE 头 */
    nt->FileHeader.NumberOfSections++;
    nt->OptionalHeader.SizeOfImage = new_va + new_vsize_aligned;
    nt->OptionalHeader.AddressOfEntryPoint = new_va;
    nt->OptionalHeader.CheckSum = 0;

    /* 禁用 ASLR (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)：
     * 原因：stub 解密 .text 节用文件原字节覆盖内存，会冲掉 loader 应用过的
     *       relocations（修改 .text 里绝对地址引用以匹配实际加载基址）。
     *       冲掉后跳 OEP 执行时，绝对地址指向错误位置 → STATUS_STACK_BUFFER_OVERRUN。
     * 解决：强制加载到固定 ImageBase（不清 ImageBase 字段），relocations 不被
     *       应用，stub 解密恢复的原文绝对地址刚好匹配实际加载基址。
     * stub 本身是 PIC，不受 ImageBase 影响。 */
    if (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
        WORD old = nt->OptionalHeader.DllCharacteristics;
        nt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
        nt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
        printf("[!] ASLR disabled (DllChar 0x%04X -> 0x%04X) to avoid reloc/decrypt conflict\n",
               old, nt->OptionalHeader.DllCharacteristics);
    }

    /* 16. 写输出文件 */
    if (write_file(out_path, out, out_size) != 0) {
        printf("[-] Failed to write %s\n", out_path);
        return 1;
    }

    printf("\n[+] ===== Pack complete =====\n");
    printf("[+] Output: %s (%zu bytes = 0x%zX)\n", out_path, out_size, out_size);
    printf("[+] New EP RVA = 0x%lX (was 0x%llX)\n",
           (unsigned long)nt->OptionalHeader.AddressOfEntryPoint,
           (unsigned long long)oep_rva);
    printf("[+] SizeOfImage = 0x%lX\n", (unsigned long)nt->OptionalHeader.SizeOfImage);
    printf("[+] Sections   = %u (added .lock)\n", nt->FileHeader.NumberOfSections);
    printf("[+] Password   : %ls\n", sd->password);
    printf("[+] Run        : %s\n", out_path);

    free(stub);
    free(pe);
    free(out);
    return 0;
}
