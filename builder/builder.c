/*
 * winlock/builder/builder.c - PE 加壳器（v3）
 *
 * v3 增强：
 *   - 支持 TLS callbacks：stub_tls_callback 代理模式
 *     builder 在 .lock 末尾追加 [stub_tls_callback_VA, NULL] callbacks 数组，
 *     修改原 PE TLS directory 的 AddressOfCallBacks 指向新数组。
 *     stub_tls_callback 在 loader 调用原 callbacks 之前解密 .text。
 *   - 支持 ASLR：保留 DYNAMIC_BASE，stub 解密 .text 后重新应用 relocations
 *     （仅 patch .text 范围，避免对 .rdata 等节双重 reloc）。
 *   - TLS_PROXY 模式禁用 ASLR（简化：避免 .lock 内 VA 引用与 reloc 冲突）。
 *
 * 修复与增强（v2 遗留）：
 *   - overlay 数据保留（避免堆崩溃）
 *   - Authenticode 签名剥离
 *   - 检测 .NET CLR / DLL，拒绝加壳
 *   - 清零 Bound Imports（避免 loader 走捷径）
 *   - 随机生成 per-file XTEA key
 *   - SHA-256 hash 密码校验
 *
 * 流程：
 *   1. 读输入 PE
 *   2. 验证：x64 EXE，无 CLR
 *   3. 找第一个可执行节，记录 .text 信息
 *   4. 检测 TLS callbacks，保存原 callback 列表（不拒绝）
 *   5. 随机生成 XTEA key + salt，计算 SHA-256(password+salt)
 *   6. XTEA 加密 .text 前 enc_size 字节
 *   7. 读 stub.bin，搜索 STUB_DATA_MAGIC 与 STUB_TLS_CB_MAGIC
 *   8. 填充 stub_data：v3 字段（image_base/reloc_rva/reloc_size/orig_tls_callbacks）
 *   9. 计算 .lock 节位置（保留 overlay），追加 callbacks 数组（若 TLS_PROXY）
 *   10. 剥离 Authenticode 签名，清零 Bound Imports
 *   11. 新增 .lock 节，写入 stub.bin + callbacks 数组
 *   12. 修改 AddressOfEntryPoint 指向 .lock
 *   13. 更新 SizeOfImage / NumberOfSections
 *   14. ASLR 处理：
 *       - TLS_PROXY 模式：禁用 ASLR
 *       - 非 TLS_PROXY 模式 + ASLR 启用：保留 ASLR，stub 重应用 reloc
 *   15. TLS_PROXY 模式：修改原 TLS directory 的 AddressOfCallBacks
 *   16. 写输出 PE
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

/* ---- 辅助：RVA -> 文件偏移（在原 PE 节表中查找）----
 * 返回 0 表示未找到（注意：0 也可能是合法偏移，调用方应先检查 RVA 是否合法） */
static DWORD rva_to_raw(IMAGE_SECTION_HEADER* sec, WORD n_sec, DWORD rva) {
    for (WORD i = 0; i < n_sec; i++) {
        DWORD sva = sec[i].VirtualAddress;
        /* 用 VirtualSize 优先，但若 VirtualSize < RawSize，用 RawSize 作上限
         * （某些 PE 用 SizeOfRawData 作为节实际大小）*/
        DWORD va_end = sva + (sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData);
        if (rva >= sva && rva < va_end) {
            return sec[i].PointerToRawData + (rva - sva);
        }
    }
    return 0;
}

/* ---- 辅助：在 stub.bin 中搜索 STUB_TLS_CB_MAGIC，返回 stub_tls_callback 偏移 ----
 * stub.c 把 magic 放在 16 字节 marker（8 字节 magic + 8 字节 zero pad）中，
 * function 紧跟其后，所以 function_offset = magic_offset + 16。
 * 返回 0 表示未找到。 */
static size_t find_stub_tls_cb_offset(const uint8_t* stub, size_t stub_size) {
    for (size_t off = 0; off + 16 <= stub_size; off += 8) {
        if (*(const uint64_t*)(stub + off) == STUB_TLS_CB_MAGIC) {
            return off + 16;
        }
    }
    return 0;
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

    /* 检查 TLS 回调（v3：不再拒绝，保存原 callback 列表用于 stub_tls_callback 代理）*/
    IMAGE_DATA_DIRECTORY* tls_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    /* TLS 信息结构 */
    struct {
        int      has_callbacks;          /* 是否有 TLS callbacks */
        uint64_t orig_callbacks[64];     /* 原 callback VA 列表（NULL 结尾）*/
        int      orig_callback_count;
        uint64_t orig_callbacks_array_va; /* 原 callbacks 数组的 VA（供 stub 调用）*/
        DWORD    aoc_field_rva;           /* AddressOfCallBacks 字段在 PE 中的 RVA */
    } tls_info = {0};

    if (tls_dir->VirtualAddress != 0 && tls_dir->Size != 0) {
        printf("[!] TLS directory present (RVA=0x%lX Size=0x%lX)\n",
               (unsigned long)tls_dir->VirtualAddress,
               (unsigned long)tls_dir->Size);

        /* 找 TLS directory 的 raw 指针 */
        DWORD tls_raw = rva_to_raw(sec, n_sec, tls_dir->VirtualAddress);
        if (tls_raw != 0) {
            IMAGE_TLS_DIRECTORY64* tls =
                (IMAGE_TLS_DIRECTORY64*)(pe + tls_raw);
            /* AddressOfCallBacks 字段在 IMAGE_TLS_DIRECTORY64 中的偏移 = 24 */
            tls_info.aoc_field_rva = tls_dir->VirtualAddress + 24;

            if (tls->AddressOfCallBacks) {
                ULONGLONG img_base = nt->OptionalHeader.ImageBase;
                ULONGLONG cb_va = tls->AddressOfCallBacks;
                ULONGLONG cb_rva = cb_va - img_base;
                tls_info.orig_callbacks_array_va = cb_va;

                DWORD cb_raw = rva_to_raw(sec, n_sec, (DWORD)cb_rva);
                if (cb_raw != 0) {
                    uint64_t* callbacks = (uint64_t*)(pe + cb_raw);
                    /* 复制原 callbacks（最多 63 个，留一个 NULL） */
                    while (tls_info.orig_callback_count < 63 &&
                           callbacks[tls_info.orig_callback_count] != 0) {
                        tls_info.orig_callbacks[tls_info.orig_callback_count] =
                            callbacks[tls_info.orig_callback_count];
                        tls_info.orig_callback_count++;
                    }
                    tls_info.orig_callbacks[tls_info.orig_callback_count] = 0;
                    if (tls_info.orig_callback_count > 0) {
                        tls_info.has_callbacks = 1;
                    }
                }
            }
        }

        if (tls_info.has_callbacks) {
            printf("[+] Found %d TLS callbacks (array VA=0x%llX)\n",
                   tls_info.orig_callback_count,
                   (unsigned long long)tls_info.orig_callbacks_array_va);
            for (int i = 0; i < tls_info.orig_callback_count; i++) {
                printf("    [%d] callback VA=0x%llX\n", i,
                       (unsigned long long)tls_info.orig_callbacks[i]);
            }
            printf("[*] Will use stub_tls_callback proxy mode (TLS_PROXY + disable ASLR)\n");
        } else {
            printf("[+] TLS directory exists but no callbacks. OK.\n");
        }
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

    /* 8a. 在 stub.bin 中搜索 STUB_TLS_CB_MAGIC，定位 stub_tls_callback */
    size_t stub_tls_cb_offset = find_stub_tls_cb_offset(stub, stub_size);
    if (tls_info.has_callbacks) {
        if (stub_tls_cb_offset == 0) {
            printf("[-] STUB_TLS_CB_MAGIC not found in stub.bin (TLS_PROXY mode required)\n");
            return 1;
        }
        printf("[*] stub_tls_callback at offset 0x%zX in stub.bin\n", stub_tls_cb_offset);
    }

    /* 填充 stub_data */
    sd->version       = STUB_DATA_VERSION;
    sd->flags         = STUB_FLAG_HASH;     /* 使用 hash 校验 */
    if (test_mode) {
        sd->flags    |= STUB_FLAG_TEST_MODE;  /* 测试模式：跳过弹框 */
    }
    if (tls_info.has_callbacks) {
        sd->flags    |= STUB_FLAG_TLS_PROXY;  /* TLS callback 代理模式 */
    } else if (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
        sd->flags    |= STUB_FLAG_ASLR;        /* 保留 ASLR，stub 重应用 reloc */
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
    /* v3 字段：重定位信息（始终填充，stub 根据 STUB_FLAG_ASLR 决定是否使用）*/
    sd->image_base = nt->OptionalHeader.ImageBase;
    {
        IMAGE_DATA_DIRECTORY* reloc_dir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        sd->reloc_rva  = reloc_dir->VirtualAddress;
        sd->reloc_size = reloc_dir->Size;
    }
    sd->reserved32 = 0;
    /* TLS_PROXY 模式：保存原 callbacks 数组 VA，stub_tls_callback 调用它们 */
    sd->orig_tls_callbacks = tls_info.has_callbacks
        ? tls_info.orig_callbacks_array_va : 0;
    /* 计算 checksum（XOR 所有 8 字节字段） */
    uint64_t* p = (uint64_t*)sd;
    uint64_t cs = 0;
    size_t sd_qwords = (sizeof(stub_data_t) - sizeof(uint64_t)) / sizeof(uint64_t);
    size_t qi;
    for (qi = 0; qi < sd_qwords; qi++) cs ^= p[qi];
    sd->checksum = cs;
    printf("[*] Password set to: '%ls' (stored as SHA-256 hash)\n", sd->password);
    printf("[*] stub_data flags=0x%04X (HASH=%d TEST=%d TLS_PROXY=%d ASLR=%d)\n",
           sd->flags,
           (sd->flags & STUB_FLAG_HASH)        ? 1 : 0,
           (sd->flags & STUB_FLAG_TEST_MODE)  ? 1 : 0,
           (sd->flags & STUB_FLAG_TLS_PROXY)  ? 1 : 0,
           (sd->flags & STUB_FLAG_ASLR)        ? 1 : 0);

    /* 9. 计算新 .lock 节位置（保留 overlay）
     *   .lock 节内容 = stub.bin + (TLS_PROXY 模式时追加 callbacks 数组)
     *   callbacks 数组 = [stub_tls_callback_VA, NULL]
     *   stub_tls_callback_VA = ImageBase + new_va + stub_tls_cb_offset
     *   callbacks_array_VA   = ImageBase + new_va + cb_array_offset_in_lock */
    DWORD file_align = nt->OptionalHeader.FileAlignment;
    DWORD sec_align = nt->OptionalHeader.SectionAlignment;

    /* callbacks 数组在 .lock 中的偏移（stub.bin 之后，8 字节对齐）*/
    size_t cb_array_offset_in_lock = (stub_size + 7) & ~((size_t)7);
    /* callbacks 数组大小：[stub_tls_callback_VA, NULL] = 2 * 8 字节
     *   （stub_tls_callback 调用原 callbacks via stub_data.orig_tls_callbacks，
     *    所以新数组只需要 stub_tls_callback + NULL，原 callbacks 不会被 loader 二次调用）*/
    size_t cb_array_size = tls_info.has_callbacks ? (2 * 8) : 0;
    size_t total_lock_size = cb_array_offset_in_lock + cb_array_size;
    if (!tls_info.has_callbacks) {
        total_lock_size = stub_size;  /* 不需要追加 callbacks 数组 */
    }

    /* new_raw_off = max(last_raw_end, in_size_without_overlay) aligned up */
    DWORD pe_data_end = overlay_off + (DWORD)overlay_size;  /* == in_size if no overlay */
    DWORD new_raw_off = (pe_data_end + file_align - 1) & ~(file_align - 1);
    DWORD new_raw_size = (DWORD)((total_lock_size + file_align - 1) & ~(file_align - 1));
    DWORD new_va = (last_va_end + sec_align - 1) & ~(sec_align - 1);
    DWORD new_vsize = (DWORD)total_lock_size;
    DWORD new_vsize_aligned = (new_vsize + sec_align - 1) & ~(sec_align - 1);

    /* 计算 stub_tls_callback VA（仅 TLS_PROXY 模式需要）*/
    uint64_t stub_tls_cb_va = 0;
    uint64_t new_cb_array_va = 0;
    if (tls_info.has_callbacks) {
        stub_tls_cb_va   = (uint64_t)nt->OptionalHeader.ImageBase
                         + new_va + stub_tls_cb_offset;
        new_cb_array_va  = (uint64_t)nt->OptionalHeader.ImageBase
                         + new_va + (uint64_t)cb_array_offset_in_lock;
        printf("[*] stub_tls_callback VA = 0x%llX (ImageBase + 0x%lX + 0x%zX)\n",
               (unsigned long long)stub_tls_cb_va,
               (unsigned long)new_va, stub_tls_cb_offset);
        printf("[*] new callbacks array VA = 0x%llX (offset in .lock = 0x%zX)\n",
               (unsigned long long)new_cb_array_va, cb_array_offset_in_lock);
    }

    printf("[*] New .lock section: RVA=0x%lX VSize=0x%lX RawOff=0x%lX RawSize=0x%lX\n",
           (unsigned long)new_va, (unsigned long)new_vsize,
           (unsigned long)new_raw_off, (unsigned long)new_raw_size);
    if (tls_info.has_callbacks) {
        printf("[*]   .lock content: stub.bin(0x%zX) + callbacks_array(0x%zX) = 0x%zX\n",
               stub_size, cb_array_size, total_lock_size);
    }

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

    /* 14. 拷贝 stub.bin 到新节，追加 callbacks 数组（TLS_PROXY 模式） */
    memcpy(out + new_raw_off, stub, stub_size);
    if (tls_info.has_callbacks) {
        /* 在 .lock 末尾追加新 callbacks 数组：[stub_tls_callback_VA, NULL]
         * Windows loader 会遍历此数组调用每个 callback。
         * stub_tls_callback 在 DLL_PROCESS_ATTACH 时解密 .text + 调原 callbacks。
         * 数组以 NULL 结尾，所以原 callbacks 不会被 loader 二次调用
         * （由 stub_tls_callback 通过 stub_data.orig_tls_callbacks 调用）。 */
        uint64_t* cb_array = (uint64_t*)(out + new_raw_off + cb_array_offset_in_lock);
        cb_array[0] = stub_tls_cb_va;  /* stub_tls_callback 入口 VA */
        cb_array[1] = 0;                /* NULL 结尾 */
        printf("[+] Wrote new callbacks array at .lock+0x%zX: [0x%llX, NULL]\n",
               cb_array_offset_in_lock, (unsigned long long)stub_tls_cb_va);
    }
    /* 剩余填充由 calloc 自动清零 */

    /* 15. 更新 PE 头 */
    nt->FileHeader.NumberOfSections++;
    nt->OptionalHeader.SizeOfImage = new_va + new_vsize_aligned;
    nt->OptionalHeader.AddressOfEntryPoint = new_va;
    nt->OptionalHeader.CheckSum = 0;

    /* ASLR 处理（v3 条件化）：
     * - TLS_PROXY 模式：禁用 ASLR。原因：新 callbacks 数组中的 stub_tls_callback_VA
     *   是绝对 VA，若 ASLR 启用需要 .reloc 覆盖此地址，但 .lock 节无 reloc 条目。
     *   禁用 ASLR 让 PE 加载到 preferred ImageBase，所有 VA 直接生效。
     *   绝大多数带 TLS callbacks 的程序（CRT 初始化等）不依赖 ASLR，禁用无影响。
     * - 非 TLS_PROXY 模式 + ASLR 启用：保留 ASLR，stub 解密 .text 后重新应用
     *   relocations（仅 patch .text 范围，避免对其他节双重 reloc）。
     *   STUB_FLAG_ASLR 已在 stub_data.flags 中设置。 */
    if (tls_info.has_callbacks) {
        if (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
            WORD old = nt->OptionalHeader.DllCharacteristics;
            nt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
            nt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
            printf("[!] ASLR disabled (TLS_PROXY mode, DllChar 0x%04X -> 0x%04X)\n",
                   old, nt->OptionalHeader.DllCharacteristics);
        }
    } else if (sd->flags & STUB_FLAG_ASLR) {
        printf("[+] ASLR preserved (stub will re-apply .text relocations)\n");
    } else if (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
        /* 这一支本不该触发（非 TLS_PROXY 时 DYNAMIC_BASE 应该走 STUB_FLAG_ASLR 路径）*/
        WORD old = nt->OptionalHeader.DllCharacteristics;
        nt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
        nt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
        printf("[!] ASLR disabled (fallback, DllChar 0x%04X -> 0x%04X)\n",
               old, nt->OptionalHeader.DllCharacteristics);
    }

    /* 15b. CFG (Control Flow Guard) 处理：
     *   原 PE 若启用 CFG（DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF），
     *   loader 在调用 EP 时会用 CFG dispatch 校验目标地址是否在 GFIDS 表中。
     *   我们把 EP 改为 .lock 节中的 stub_entry，不在 GFIDS 表里，
     *   → 触发 STATUS_STACK_BUFFER_OVERRUN (0xC0000409)。
     *   修复：清 GUARD_CF 位，让 loader 不对 EP 做 CFG dispatch 校验。
     *   副作用：原 PE 中 CFG 保护的间接调用目标不再被 loader 校验；
     *   但原 .text 已被 XTEA 加密，CFG 本来就保护不了密文，影响可忽略。
     *   参考：pe-packer 项目同样处理 CFG（patch GFIDS 表或禁用）。 */
    if (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) {
        WORD old = nt->OptionalHeader.DllCharacteristics;
        nt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_GUARD_CF;
        printf("[!] CFG disabled (DllChar 0x%04X -> 0x%04X); stub_entry not in GFIDS table\n",
               old, nt->OptionalHeader.DllCharacteristics);
    }

    /* 16. TLS_PROXY 模式：修改原 TLS directory 的 AddressOfCallBacks 字段
     *   让 Windows loader 调用我们的 stub_tls_callback，而不是原 callbacks。
     *   stub_tls_callback 在 DLL_PROCESS_ATTACH 时：
     *     1. 解析 kernel32 / 弹密码框 / 解密 .text
     *     2. 通过 stub_data.orig_tls_callbacks 调用原 callbacks
     *   stub_entry 在 TLS_PROXY 模式下只跳 OEP（解密已由 TLS callback 完成）。
     *   注意：AddressOfCallBacks 是 VA（不是 RVA），ASLR 已禁用所以 VA = ImageBase + RVA */
    if (tls_info.has_callbacks) {
        /* 在输出 PE 中找 AddressOfCallBacks 字段的文件偏移 */
        DWORD aoc_raw = rva_to_raw(sec, n_sec, tls_info.aoc_field_rva);
        if (aoc_raw == 0) {
            printf("[-] Cannot locate AddressOfCallBacks field in output PE\n");
            return 1;
        }
        uint64_t* aoc_field = (uint64_t*)(out + aoc_raw);
        uint64_t old_aoc = *aoc_field;
        *aoc_field = new_cb_array_va;
        printf("[+] TLS directory AddressOfCallBacks: 0x%llX -> 0x%llX (file off 0x%lX)\n",
               (unsigned long long)old_aoc,
               (unsigned long long)new_cb_array_va,
               (unsigned long)aoc_raw);
    }

    /* 17. 写输出文件 */
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
