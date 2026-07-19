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
#include "../common/config.h"

/* ---- 调试日志开关 ----
 * 默认只输出关键日志（[+] 成功、[-] 错误、[!] 警告、最终结果），
 * 详细日志（[*] 加载/解析/位置信息、节列表等）用 DBG() 宏包裹，
 * 只在 --debug / -v 时输出。
 * 目的：避免 packer 把 builder 的 stdout 全部记入 AppLogger 时日志过载。
 */
static int g_debug = 0;
#define DBG(fmt, ...) do { if (g_debug) printf(fmt, ##__VA_ARGS__); } while (0)

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

/* ---- 辅助：从 stub_xXX.exe 提取 .reloc 节信息（x86 需要） ----
 *
 * x86 stub 用绝对地址引用静态数据（非 PIC），必须读 stub_x86.exe 的 .reloc 节，
 * builder 据此预 patch stub.bin 的绝对地址到目标加载位置。
 *
 * 参数：
 *   exe_data        - stub_xXX.exe 完整文件数据
 *   exe_size        - exe 文件大小
 *   out_lock_rva    - 输出：stub .lock 节的 RVA
 *   out_lock_size   - 输出：stub .lock 节的 VirtualSize
 *   out_reloc_off   - 输出：.reloc 节在 exe 文件中的 raw offset
 *   out_reloc_size  - 输出：.reloc 节的 raw size
 *   out_image_base  - 输出：stub 编译时 ImageBase
 *
 * 返回 0 成功，-1 失败。 */
static int extract_stub_reloc_info(const uint8_t* exe_data, size_t exe_size,
                                   uint32_t* out_lock_rva, uint32_t* out_lock_size,
                                   uint32_t* out_reloc_off, size_t* out_reloc_size,
                                   uint64_t* out_image_base) {
    if (exe_size < sizeof(IMAGE_DOS_HEADER)) return -1;
    IMAGE_DOS_HEADER* s_dos = (IMAGE_DOS_HEADER*)exe_data;
    if (s_dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;
    if ((size_t)s_dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > exe_size) return -1;

    /* 按签名 + FileHeader 布局一致，先用 NT_HEADERS64 读 Machine */
    IMAGE_NT_HEADERS64* s_nt = (IMAGE_NT_HEADERS64*)(exe_data + s_dos->e_lfanew);
    if (s_nt->Signature != IMAGE_NT_SIGNATURE) return -1;

    int s_is_x64 = (s_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    uint64_t image_base;
    WORD n_sec;
    IMAGE_SECTION_HEADER* s_sec;

    if (s_is_x64) {
        image_base = s_nt->OptionalHeader.ImageBase;
        n_sec = s_nt->FileHeader.NumberOfSections;
        s_sec = (IMAGE_SECTION_HEADER*)((uint8_t*)s_nt + sizeof(DWORD)
                + sizeof(IMAGE_FILE_HEADER) + s_nt->FileHeader.SizeOfOptionalHeader);
    } else {
        IMAGE_NT_HEADERS32* s_nt32 = (IMAGE_NT_HEADERS32*)s_nt;
        image_base = s_nt32->OptionalHeader.ImageBase;
        n_sec = s_nt32->FileHeader.NumberOfSections;
        s_sec = (IMAGE_SECTION_HEADER*)((uint8_t*)s_nt + sizeof(DWORD)
                + sizeof(IMAGE_FILE_HEADER) + s_nt32->FileHeader.SizeOfOptionalHeader);
    }

    uint32_t lock_rva = 0, lock_size = 0;
    uint32_t reloc_off = 0, reloc_size = 0;
    for (WORD i = 0; i < n_sec; i++) {
        char name[9] = {0};
        memcpy(name, s_sec[i].Name, 8);
        if (strcmp(name, ".lock") == 0) {
            lock_rva = s_sec[i].VirtualAddress;
            lock_size = s_sec[i].Misc.VirtualSize;
            if (lock_size == 0) lock_size = s_sec[i].SizeOfRawData;
        } else if (strcmp(name, ".reloc") == 0) {
            reloc_off = s_sec[i].PointerToRawData;
            reloc_size = s_sec[i].SizeOfRawData;
        }
    }

    if (lock_rva == 0) return -1;
    *out_lock_rva = lock_rva;
    *out_lock_size = lock_size;
    *out_reloc_off = reloc_off;
    *out_reloc_size = reloc_size;
    *out_image_base = image_base;
    return 0;
}

/* ---- 辅助：预 patch stub.bin 的绝对地址到目标加载位置（x86） ----
 *
 * x86 stub 编译时用绝对地址引用 .lock 内的静态数据（如 STR_KERNEL32 的 VA）。
 * 编译时绝对地址 = stub_image_base + stub_lock_rva + offset_in_lock。
 * 目标绝对地址 = target_image_base + target_lock_rva + offset_in_lock。
 * delta = (target_image_base + target_lock_rva) - (stub_image_base + stub_lock_rva)。
 *
 * 遍历 stub 的 .reloc 表，对每个在 .lock 范围内的 patch 位置加上 delta。
 * patch 后 stub.bin 在目标位置加载时，所有绝对地址都指向正确位置。
 *
 * 前提：目标 PE 必须禁用 ASLR（加载到固定 ImageBase），否则 stub 绝对地址
 * 会因基址随机化而再次错位（builder 已对 x86 强制禁用 ASLR）。
 *
 * 参数：
 *   stub_buf          - stub.bin 数据（可写，通常已拷贝到 out 缓冲区）
 *   stub_size         - stub.bin 大小（.lock 节大小）
 *   reloc_data        - stub 的 .reloc 节数据
 *   reloc_size        - .reloc 节大小
 *   stub_image_base   - stub 编译时 ImageBase
 *   stub_lock_rva      - stub .lock 节在 stub exe 中的 RVA
 *   target_image_base - 目标 PE 的 ImageBase
 *   target_lock_rva   - 新 .lock 节在目标 PE 中的 RVA
 *
 * 返回：patch 的条目数，-1 表示错误。 */
static int patch_stub_relocations(uint8_t* stub_buf, size_t stub_size,
                                  const uint8_t* reloc_data, size_t reloc_size,
                                  uint64_t stub_image_base, uint32_t stub_lock_rva,
                                  uint64_t target_image_base, uint32_t target_lock_rva) {
    if (reloc_size == 0) return 0;  /* 无 reloc 表，无需 patch（x64 PIC 走此路径）*/

    uint64_t stub_base = stub_image_base + stub_lock_rva;
    uint64_t target_base = target_image_base + target_lock_rva;
    int64_t delta = (int64_t)(target_base - stub_base);

    if (delta == 0) return 0;  /* 无需 patch */

    const uint8_t* reloc = reloc_data;
    const uint8_t* reloc_end = reloc_data + reloc_size;
    IMAGE_BASE_RELOCATION* block = (IMAGE_BASE_RELOCATION*)reloc;
    int patch_count = 0;

    while ((uint8_t*)block + sizeof(IMAGE_BASE_RELOCATION) <= reloc_end
           && block->SizeOfBlock > 0) {
        DWORD block_rva = block->VirtualAddress;
        DWORD block_size = block->SizeOfBlock;
        if (block_size < sizeof(IMAGE_BASE_RELOCATION)) break;

        DWORD n_entries = (block_size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)(block + 1);

        for (DWORD i = 0; i < n_entries; i++) {
            WORD type = entries[i] >> 12;
            WORD offset = entries[i] & 0xFFF;
            DWORD patch_rva = block_rva + offset;

            /* 只 patch .lock 范围内的条目
             * （其他节如 .rdata 被 /DISCARD/ 了，不应有 reloc 条目）*/
            if (patch_rva < stub_lock_rva
                || patch_rva >= stub_lock_rva + stub_size) {
                continue;
            }

            DWORD off_in_lock = patch_rva - stub_lock_rva;
            uint8_t* patch_addr = stub_buf + off_in_lock;

            switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;  /* padding，跳过 */
                case IMAGE_REL_BASED_HIGHLOW:
                    /* x86 32 位绝对地址 */
                    *(uint32_t*)patch_addr += (uint32_t)delta;
                    patch_count++;
                    break;
                case IMAGE_REL_BASED_DIR64:
                    /* x64 64 位绝对地址（x64 stub 通常无此条目，因为 PIC）*/
                    *(uint64_t*)patch_addr += (uint64_t)delta;
                    patch_count++;
                    break;
                default:
                    /* 其他类型（HIGH/LOW）罕见，跳过 */
                    break;
            }
        }

        block = (IMAGE_BASE_RELOCATION*)((uint8_t*)block + block_size);
    }

    return patch_count;
}

/* ---- 双架构 PE 访问层 ----
 * builder 自身是 x64，IMAGE_NT_HEADERS 默认 = IMAGE_NT_HEADERS64。
 * 输入 PE 可能是 PE32 (x86) 或 PE32+ (x64)，需要按架构分别解析。
 *
 * FileHeader 在两种 NT_HEADERS 中布局一致（紧跟 Signature 之后），
 * 可以共用 (IMAGE_FILE_HEADER*)((uint8_t*)nt + 4)。
 *
 * OptionalHeader 字段：多数字段类型相同但偏移不同（PE32 vs PE32+）。
 * 用 g_nt64 / g_nt32 两个指针 + 宏 OH() / OH_U64() 分派。
 *
 * DataDirectory 在两种结构中布局一致（每项 8 字节 RVA+Size），
 * 只是起始偏移不同（PE32=0x60，PE32+=0x70），通过宏 OH_DATA_DIR(idx) 访问。 */
static int g_is_x64 = 1;                    /* 1=x64/PE32+，0=x86/PE32 */
static IMAGE_NT_HEADERS64* g_nt64 = NULL;   /* is_x64 时有效 */
static IMAGE_NT_HEADERS32* g_nt32 = NULL;   /* !is_x64 时有效 */

/* 访问 OptionalHeader 中同类型字段（DWORD/WORD 等）。
 * 用 *(cond ? &a : &b) 形式让三元表达式可作为 lvalue（C 标准不支持三元作为 lvalue，
 * 但通过指针解引用绕过；同时保持 OH(field) 既能读也能写）。 */
#define OH(field) (*(g_is_x64 ? &g_nt64->OptionalHeader.field : &g_nt32->OptionalHeader.field))
/* 访问 ImageBase（PE32 是 DWORD，PE32+ 是 ULONGLONG），统一转 uint64_t */
#define OH_IMG_BASE() (g_is_x64 \
    ? (uint64_t)g_nt64->OptionalHeader.ImageBase \
    : (uint64_t)g_nt32->OptionalHeader.ImageBase)
/* 访问 DataDirectory[idx]（两种结构布局一致，仅起始偏移不同） */
#define OH_DATA_DIR(idx) (g_is_x64 \
    ? &g_nt64->OptionalHeader.DataDirectory[idx] \
    : &g_nt32->OptionalHeader.DataDirectory[idx])
/* FileHeader（两种结构布局一致，可共用） */
#define OH_FILE() (g_is_x64 ? &g_nt64->FileHeader : &g_nt32->FileHeader)
/* 取 nt 指针（uint8_t* 基址，用于计算 sec 表偏移） */
#define OH_NT_BASE() (g_is_x64 ? (uint8_t*)g_nt64 : (uint8_t*)g_nt32)
/* OptionalHeader 大小（sizeof 在编译期已知） */
#define OH_SIZE() (g_is_x64 ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32))
/* TLS directory 中 AddressOfCallBacks 字段偏移
 *   PE32:  IMAGE_TLS_DIRECTORY32.AddressOfCallBacks @ offset 12 (DWORD VA)
 *   PE32+: IMAGE_TLS_DIRECTORY64.AddressOfCallBacks @ offset 24 (ULONGLONG VA) */
#define TLS_AOC_OFFSET() (g_is_x64 ? 24 : 12)
/* callbacks 数组元素大小（x86 4 字节指针，x64 8 字节指针） */
#define TLS_CB_ELEM_SIZE() (g_is_x64 ? 8 : 4)

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
    printf("  %s -i <input.exe> [-o <output.exe>] [-p <password>] [-t] [-d] [-v] [--stub-dir <path>]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -i, --input <file>    Input PE EXE (x86 or x64)\n");
    printf("  -o, --output <file>   Output path (default: <input_dir>/<base>_locked.exe)\n");
    printf("  -p, --password <pwd>  Password (default: %ls)\n", WINLOCK_DEFAULT_PASSWORD);
    printf("  -t, --test            Test mode: stub uses hardcoded 'test123', no dialog\n");
    printf("                        (overrides -p)\n");
    printf("  -d, --antidebug       Enable PEB anti-debug (default OFF for dev)\n");
    printf("                        Checks BeingDebugged / NtGlobalFlag / KdDebuggerEnabled\n");
    printf("  -v, --debug           Verbose log: print PE parse details, section list,\n");
    printf("                        relocation patch info, etc. (default OFF)\n");
    printf("  --stub-dir <path>     Directory to search winlock_stub_x64.bin /\n");
    printf("                        winlock_stub_x86.bin / winlock_stub_x86.exe\n");
    printf("                        (backward compat: stub_x64.bin / stub_x86.bin / stub_x86.exe)\n");
    printf("                        (default: ./stub/)\n");
    printf("  -h, --help            Show this help\n");
}

int main(int argc, char* argv[]) {
    const char* in_path = NULL;
    const char* out_path = NULL;
    const char* pwd_arg = NULL;
    const char* stub_dir = NULL;   /* --stub-dir 参数：覆盖 stub.bin 搜索目录 */
    int test_mode = 0;
    int antidebug = 0;

    /* 参数解析：支持 -i/-o/-p/-t/-d/-v/--stub-dir/-h，不再支持位置参数 */
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
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--antidebug") == 0) {
            antidebug = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--debug") == 0) {
            /* 详细日志模式：输出 PE 解析详情、节列表、reloc patch 信息等 */
            g_debug = 1;
        } else if (strcmp(argv[i], "--stub-dir") == 0) {
            /* 新增：指定 winlock_stub_x64.bin 等的搜索目录 */
            if (i + 1 >= argc) { printf("[-] --stub-dir requires argument\n"); return 1; }
            stub_dir = argv[++i];
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

    /* 默认输出路径：<input_dir>/<base>_locked.exe（确保带依赖的 exe 在源目录可运行）*/
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
        DBG("[*] TEST MODE: stub will use hardcoded 'test123', no dialog\n");
    }

    /* 1. 读输入 PE */
    size_t in_size = 0;
    uint8_t* pe = read_file(in_path, &in_size);
    if (!pe) return 1;
    DBG("[*] Loaded %s (%zu bytes = 0x%zX)\n", in_path, in_size, in_size);

    /* 2. 验证 PE + 检测架构 */
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Bad DOS magic\n"); return 1;
    }
    /* 先按 IMAGE_NT_HEADERS64 读 Signature + FileHeader（前 4+20 字节布局与 PE32 一致） */
    IMAGE_NT_HEADERS64* nt_probe = (IMAGE_NT_HEADERS64*)(pe + dos->e_lfanew);
    if (nt_probe->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Bad NT signature\n"); return 1;
    }
    /* 按 Machine 字段判断架构 */
    WORD machine = nt_probe->FileHeader.Machine;
    if (machine == IMAGE_FILE_MACHINE_AMD64) {
        g_is_x64 = 1;
        g_nt64 = nt_probe;
        g_nt32 = NULL;
    } else if (machine == IMAGE_FILE_MACHINE_I386) {
        g_is_x64 = 0;
        g_nt64 = NULL;
        g_nt32 = (IMAGE_NT_HEADERS32*)(pe + dos->e_lfanew);
    } else {
        printf("[-] Unsupported Machine 0x%04X (only x86 and x64)\n", machine);
        return 1;
    }
    DBG("[*] Architecture: %s (Machine=0x%04X)\n",
           g_is_x64 ? "x64 (PE32+)" : "x86 (PE32)", machine);

    IMAGE_FILE_HEADER* file_hdr = OH_FILE();
    if (file_hdr->Characteristics & IMAGE_FILE_DLL) {
        printf("[-] DLL not supported (use EXE)\n");
        return 1;
    }

    WORD n_sec = file_hdr->NumberOfSections;
    /* 节表紧接 OptionalHeader 之后；按架构用对应的 NT_HEADERS 大小 */
    IMAGE_SECTION_HEADER* sec =
        (IMAGE_SECTION_HEADER*)(OH_NT_BASE() + sizeof(DWORD) /*Signature*/
                                + sizeof(IMAGE_FILE_HEADER)
                                + OH_SIZE());

    /* 检查 TLS 回调（v3：不再拒绝，保存原 callback 列表用于 stub_tls_callback 代理）*/
    IMAGE_DATA_DIRECTORY* tls_dir = OH_DATA_DIR(IMAGE_DIRECTORY_ENTRY_TLS);

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
            /* AddressOfCallBacks 字段在 TLS directory 中的偏移：
             *   PE32:  IMAGE_TLS_DIRECTORY32 @ offset 12 (DWORD VA)
             *   PE32+: IMAGE_TLS_DIRECTORY64 @ offset 24 (ULONGLONG VA) */
            tls_info.aoc_field_rva = tls_dir->VirtualAddress + TLS_AOC_OFFSET();

            /* 读 AddressOfCallBacks VA（按架构） */
            uint64_t cb_va = 0;
            if (g_is_x64) {
                IMAGE_TLS_DIRECTORY64* tls =
                    (IMAGE_TLS_DIRECTORY64*)(pe + tls_raw);
                cb_va = tls->AddressOfCallBacks;
            } else {
                IMAGE_TLS_DIRECTORY32* tls =
                    (IMAGE_TLS_DIRECTORY32*)(pe + tls_raw);
                cb_va = (uint64_t)tls->AddressOfCallBacks;
            }

            if (cb_va) {
                uint64_t img_base = OH_IMG_BASE();
                uint64_t cb_rva = cb_va - img_base;
                tls_info.orig_callbacks_array_va = cb_va;

                DWORD cb_raw = rva_to_raw(sec, n_sec, (DWORD)cb_rva);
                if (cb_raw != 0) {
                    /* callbacks 数组：x86 是 4 字节指针，x64 是 8 字节指针 */
                    size_t elem_size = TLS_CB_ELEM_SIZE();
                    uint8_t* cb_bytes = pe + cb_raw;
                    /* 复制原 callbacks（最多 63 个，留一个 NULL） */
                    while (tls_info.orig_callback_count < 63) {
                        uint64_t cb = 0;
                        if (g_is_x64) {
                            cb = *(uint64_t*)(cb_bytes
                                + tls_info.orig_callback_count * 8);
                        } else {
                            cb = (uint64_t)*(uint32_t*)(cb_bytes
                                + tls_info.orig_callback_count * 4);
                        }
                        if (cb == 0) break;
                        tls_info.orig_callbacks[tls_info.orig_callback_count] = cb;
                        tls_info.orig_callback_count++;
                    }
                    tls_info.orig_callbacks[tls_info.orig_callback_count] = 0;
                    if (tls_info.orig_callback_count > 0) {
                        tls_info.has_callbacks = 1;
                    }
                    (void)elem_size;
                }
            }
        }

        if (tls_info.has_callbacks) {
            printf("[+] Found %d TLS callbacks (array VA=0x%llX)\n",
                   tls_info.orig_callback_count,
                   (unsigned long long)tls_info.orig_callbacks_array_va);
            for (int i = 0; i < tls_info.orig_callback_count; i++) {
                DBG("    [%d] callback VA=0x%llX\n", i,
                    (unsigned long long)tls_info.orig_callbacks[i]);
            }
            DBG("[*] Will use stub_tls_callback proxy mode (TLS_PROXY + disable ASLR)\n");
        } else {
            printf("[+] TLS directory exists but no callbacks. OK.\n");
        }
    }

    /* 检查 .NET CLR */
    IMAGE_DATA_DIRECTORY* clr_dir = OH_DATA_DIR(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    if (clr_dir->VirtualAddress != 0 && clr_dir->Size != 0) {
        printf("[-] .NET CLR detected. Cannot pack managed PE.\n");
        return 1;
    }

    DBG("[*] PE: %u sections, ImageBase=0x%llX, EP RVA=0x%lX, SizeOfImage=0x%lX\n",
           n_sec,
           (unsigned long long)OH_IMG_BASE(),
           (unsigned long)OH(AddressOfEntryPoint),
           (unsigned long)OH(SizeOfImage));
    DBG("[*] DllCharacteristics=0x%04X, Subsystem=%u\n",
           OH(DllCharacteristics),
           OH(Subsystem));

    /* 打印所有节 */
    DBG("[*] Sections:\n");
    DWORD last_raw_end = 0;
    DWORD last_va_end  = 0;
    for (WORD i = 0; i < n_sec; i++) {
        char nm[9] = {0};
        sec_name_str((const char*)sec[i].Name, nm, sizeof(nm));
        DWORD raw_end = sec[i].PointerToRawData + sec[i].SizeOfRawData;
        DWORD va_end  = sec[i].VirtualAddress + sec[i].Misc.VirtualSize;
        if (raw_end > last_raw_end) last_raw_end = raw_end;
        if (va_end  > last_va_end)  last_va_end  = va_end;
        DBG("    [%u] %-8s VA=0x%lX VSize=0x%lX RawOff=0x%lX RawSize=0x%lX Char=0x%lX\n",
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
    DBG("[*] Overlay: offset=0x%lX size=0x%zX\n",
           (unsigned long)overlay_off, overlay_size);

    /* 检查 Authenticode 签名 */
    IMAGE_DATA_DIRECTORY* sec_dir = OH_DATA_DIR(IMAGE_DIRECTORY_ENTRY_SECURITY);
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
    DBG("[*] Target section [%u]: %s RVA=0x%lX VSize=0x%lX RawSize=0x%lX RawOff=0x%lX\n",
           text_sec_idx, tnm,
           (unsigned long)text_sec->VirtualAddress,
           (unsigned long)text_sec->Misc.VirtualSize,
           (unsigned long)text_sec->SizeOfRawData,
           (unsigned long)text_sec->PointerToRawData);

    /* 4. 保存原 EP / .text 信息 */
    uint64_t oep_rva      = OH(AddressOfEntryPoint);
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
    DBG("[*] Generated random XTEA key: %08X %08X %08X %08X\n",
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
    DBG("[*] Password hash (SHA-256(utf8+salt)): ");
    for (int k = 0; k < 32; k++) DBG("%02X", pwd_hash[k]);
    DBG("\n");

    /* 6. XTEA 加密 .text RawData 前 enc_size 字节
     *    只加密内存中实际加载的部分（VirtualSize），不加密 RawSize 超出部分
     *    （那部分文件里有但运行时不加载，加密也无效，反而 stub 解密会越界） */
    DBG("[*] Encrypting %u bytes (RawData) with XTEA\n", enc_size);
    xtea_encrypt_buf(pe + text_sec->PointerToRawData, enc_size, key);

    /* 7. 读 stub.bin（按输入 PE 架构选择 winlock_stub_x64.bin 或 winlock_stub_x86.bin；
     *    优先用 --stub-dir 指定目录，否则按原相对路径搜索。
     *    新命名约定：分发目录用 winlock_ 前缀避免与其他 stub 混淆；
     *    旧名 stub_x64.bin / stub_x86.bin / stub.bin 保留向后兼容（make 生成的源文件）。 */
    const char* stub_candidates[8];
    int n_candidates = 0;
    char stub_dir_path[512];
    if (stub_dir) {
        /* --stub-dir 优先：winlock_stub_x64.bin / winlock_stub_x86.bin */
        snprintf(stub_dir_path, sizeof(stub_dir_path), "%s/winlock_stub_%s.bin",
                 stub_dir, g_is_x64 ? "x64" : "x86");
        stub_candidates[n_candidates++] = strdup(stub_dir_path);
        /* 回退：旧命名 stub_x64.bin / stub_x86.bin */
        snprintf(stub_dir_path, sizeof(stub_dir_path), "%s/stub_%s.bin",
                 stub_dir, g_is_x64 ? "x64" : "x86");
        stub_candidates[n_candidates++] = strdup(stub_dir_path);
        if (g_is_x64) {
            /* x64 进一步回退：stub.bin */
            snprintf(stub_dir_path, sizeof(stub_dir_path), "%s/stub.bin", stub_dir);
            stub_candidates[n_candidates++] = strdup(stub_dir_path);
        }
    }
    if (g_is_x64) {
        stub_candidates[n_candidates++] = "stub/winlock_stub_x64.bin";
        stub_candidates[n_candidates++] = "winlock_stub_x64.bin";
        stub_candidates[n_candidates++] = "stub/stub_x64.bin";  /* 旧名回退 */
        stub_candidates[n_candidates++] = "stub_x64.bin";
        stub_candidates[n_candidates++] = "stub/stub.bin";  /* 最旧回退 */
        stub_candidates[n_candidates++] = "stub.bin";
    } else {
        stub_candidates[n_candidates++] = "stub/winlock_stub_x86.bin";
        stub_candidates[n_candidates++] = "winlock_stub_x86.bin";
        stub_candidates[n_candidates++] = "stub/stub_x86.bin";  /* 旧名回退 */
        stub_candidates[n_candidates++] = "stub_x86.bin";
    }
    size_t stub_size = 0;
    uint8_t* stub = NULL;
    for (int i = 0; i < n_candidates && !stub; i++) {
        stub = read_file(stub_candidates[i], &stub_size);
    }
    if (!stub) {
        /* 尝试基于 argv[0] 的相对路径 */
        char path[512];
        snprintf(path, sizeof(path), "%s/stub/winlock_stub_%s.bin",
                 argc > 0 ? argv[0] : ".", g_is_x64 ? "x64" : "x86");
        stub = read_file(path, &stub_size);
        if (!stub) {
            snprintf(path, sizeof(path), "%s/stub/stub_%s.bin",
                     argc > 0 ? argv[0] : ".", g_is_x64 ? "x64" : "x86");
            stub = read_file(path, &stub_size);
        }
    }
    if (!stub) {
        printf("[-] Cannot read winlock_stub_%s.bin (run 'make%s' first)\n",
               g_is_x64 ? "x64" : "x86",
               g_is_x64 ? "" : " all-x86");
        return 1;
    }
    DBG("[*] Loaded winlock_stub_%s.bin (%zu bytes = 0x%zX)\n",
           g_is_x64 ? "x64" : "x86", stub_size, stub_size);

    /* 7b. x86: 额外读 stub_x86.exe 获取 .reloc 节
     *   x86 stub 用绝对地址引用静态数据（非 PIC），必须预 patch 到目标位置。
     *   stub_x86.bin 是 objcopy 导出的 .lock raw bytes，没有 .reloc 节，
     *   所以需要从 stub_x86.exe 读取 .reloc 节 + .lock 节 RVA + ImageBase。
     *   x64 stub 用 RIP-relative 是 PIC，不需要 .reloc，跳过此步。 */
    uint8_t* stub_exe = NULL;
    size_t stub_exe_size = 0;
    uint8_t* stub_reloc_data = NULL;
    size_t stub_reloc_size = 0;
    uint64_t stub_image_base = 0;
    uint32_t stub_lock_rva = 0;
    uint32_t stub_lock_size = 0;
    if (!g_is_x64) {
        const char* exe_candidates[6];
        int n_exe = 0;
        char exe_dir_path[512];
        if (stub_dir) {
            /* --stub-dir 优先：winlock_stub_x86.exe，回退旧名 stub_x86.exe */
            snprintf(exe_dir_path, sizeof(exe_dir_path), "%s/winlock_stub_x86.exe", stub_dir);
            exe_candidates[n_exe++] = strdup(exe_dir_path);
            snprintf(exe_dir_path, sizeof(exe_dir_path), "%s/stub_x86.exe", stub_dir);
            exe_candidates[n_exe++] = strdup(exe_dir_path);
        }
        exe_candidates[n_exe++] = "stub/winlock_stub_x86.exe";
        exe_candidates[n_exe++] = "winlock_stub_x86.exe";
        exe_candidates[n_exe++] = "stub/stub_x86.exe";  /* 旧名回退 */
        exe_candidates[n_exe++] = "stub_x86.exe";
        for (int i = 0; i < n_exe && !stub_exe; i++) {
            stub_exe = read_file(exe_candidates[i], &stub_exe_size);
        }
        if (!stub_exe) {
            char path[512];
            snprintf(path, sizeof(path), "%s/stub/winlock_stub_x86.exe",
                     argc > 0 ? argv[0] : ".");
            stub_exe = read_file(path, &stub_exe_size);
            if (!stub_exe) {
                snprintf(path, sizeof(path), "%s/stub/stub_x86.exe",
                         argc > 0 ? argv[0] : ".");
                stub_exe = read_file(path, &stub_exe_size);
            }
        }
        if (!stub_exe) {
            printf("[-] Cannot read winlock_stub_x86.exe (needed for .reloc, run 'make all-x86')\n");
            return 1;
        }
        uint32_t reloc_off = 0;
        if (extract_stub_reloc_info(stub_exe, stub_exe_size,
                                    &stub_lock_rva, &stub_lock_size,
                                    &reloc_off, &stub_reloc_size,
                                    &stub_image_base) != 0) {
            printf("[-] Failed to parse winlock_stub_x86.exe PE structure\n");
            free(stub_exe);
            return 1;
        }
        if (stub_reloc_size == 0 || reloc_off == 0) {
            printf("[-] winlock_stub_x86.exe has no .reloc section (stub.ld 或 Makefile 配置错误)\n");
            free(stub_exe);
            return 1;
        }
        stub_reloc_data = stub_exe + reloc_off;
        DBG("[*] stub_x86.exe: ImageBase=0x%llX, .lock RVA=0x%lX (size 0x%lX), .reloc=0x%zX bytes\n",
               (unsigned long long)stub_image_base,
               (unsigned long)stub_lock_rva, (unsigned long)stub_lock_size,
               stub_reloc_size);
    }

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
    DBG("[*] stub_data found at offset 0x%zX\n",
           (size_t)((uint8_t*)sd - stub));

    /* 8a. 在 stub.bin 中搜索 STUB_TLS_CB_MAGIC，定位 stub_tls_callback */
    size_t stub_tls_cb_offset = find_stub_tls_cb_offset(stub, stub_size);
    if (tls_info.has_callbacks) {
        if (stub_tls_cb_offset == 0) {
            printf("[-] STUB_TLS_CB_MAGIC not found in stub.bin (TLS_PROXY mode required)\n");
            return 1;
        }
        DBG("[*] stub_tls_callback at offset 0x%zX in stub.bin\n", stub_tls_cb_offset);
    }

    /* 填充 stub_data */
    sd->version       = STUB_DATA_VERSION;
    sd->flags         = STUB_FLAG_HASH;     /* 使用 hash 校验 */
    if (test_mode) {
        sd->flags    |= STUB_FLAG_TEST_MODE;  /* 测试模式：跳过弹框 */
    }
    if (tls_info.has_callbacks) {
        sd->flags    |= STUB_FLAG_TLS_PROXY;  /* TLS callback 代理模式 */
    } else if (g_is_x64 && (OH(DllCharacteristics) & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) {
        /* x64: 保留 ASLR，stub 用 RIP-relative + 重应用 .text reloc。
         * x86: 不设置 ASLR flag，绝对地址由 builder 预 patch（见 step 14b），
         *      目标 PE 的 ASLR 在 step 15 被强制禁用。 */
        sd->flags    |= STUB_FLAG_ASLR;
    }
    if (antidebug) {
        sd->flags    |= STUB_FLAG_ANTIDEBUG;  /* P1-2: PEB 反调试（默认关闭）*/
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
    sd->image_base = OH_IMG_BASE();
    {
        IMAGE_DATA_DIRECTORY* reloc_dir = OH_DATA_DIR(IMAGE_DIRECTORY_ENTRY_BASERELOC);
        sd->reloc_rva  = reloc_dir->VirtualAddress;
        sd->reloc_size = reloc_dir->Size;
    }
    sd->reserved32 = 0;
    /* TLS_PROXY 模式：保存原 callbacks 数组 VA，stub_tls_callback 调用它们 */
    sd->orig_tls_callbacks = tls_info.has_callbacks
        ? tls_info.orig_callbacks_array_va : 0;
    /* v4 新增：读取 LOAD_CONFIG.SecurityCookie VA 并转换为 RVA
     *   - SecurityCookie 在 PE 文件里存的是基于 preferred ImageBase 的绝对地址
     *   - stub 运行时 img_base (PEB.ImageBaseAddress) 可能 != preferred，
     *     所以存 RVA，stub 用 img_base + rva 计算 cookie 实际位置
     *   - 这样 ASLR 模式也能正确工作（cookie 在 .data，由 OS loader patch，
     *     但 stub 用 img_base + rva 计算的地址就是 cookie 的实际位置）
     *   - SecurityCookie 字段在 LOAD_CONFIG 结构中的偏移：
     *       PE32+ (64 位): 0x58 (ULONGLONG)
     *       PE32  (32 位): 0x40 (DWORD)
     *     （winnt.h 的 IMAGE_LOAD_CONFIG_DIRECTORY32/64）
     *   - lc->Size 必须 >= 该偏移 + 字段大小，否则无 SecurityCookie 字段
     *   - 借鉴 AlushPacker：仅当 cookie 为 MSVC 默认值时 stub 才覆盖 */
    {
        IMAGE_DATA_DIRECTORY* lc_dir = OH_DATA_DIR(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
        sd->security_cookie_rva = 0;
        if (lc_dir->VirtualAddress != 0 && lc_dir->Size != 0) {
            DWORD lc_raw = rva_to_raw(sec, n_sec, lc_dir->VirtualAddress);
            if (lc_raw != 0) {
                uint8_t* lc = pe + lc_raw;
                DWORD lc_size = *(DWORD*)lc;  /* Size 字段（首 4 字节）*/
                uint64_t cookie_va = 0;
                int have_cookie = 0;
                if (g_is_x64) {
                    /* IMAGE_LOAD_CONFIG_DIRECTORY64.SecurityCookie @ 0x58, 8 字节 */
                    if (lc_size >= 0x60) {
                        cookie_va = *(uint64_t*)(lc + 0x58);
                        have_cookie = 1;
                    }
                } else {
                    /* IMAGE_LOAD_CONFIG_DIRECTORY32.SecurityCookie @ 0x40, 4 字节 */
                    if (lc_size >= 0x44) {
                        cookie_va = *(uint32_t*)(lc + 0x40);
                        have_cookie = 1;
                    }
                }
                if (have_cookie && cookie_va != 0) {
                    uint64_t img_base = OH_IMG_BASE();
                    if (cookie_va >= img_base) {
                        sd->security_cookie_rva = cookie_va - img_base;
                        DBG("[*] SecurityCookie VA=0x%llX RVA=0x%llX\n",
                               (unsigned long long)cookie_va,
                               (unsigned long long)sd->security_cookie_rva);
                    } else {
                        printf("[!] SecurityCookie VA=0x%llX < ImageBase=0x%llX, skip\n",
                               (unsigned long long)cookie_va,
                               (unsigned long long)img_base);
                    }
                }
            }
        }
    }
    /* 计算 checksum（XOR 所有 8 字节字段） */
    uint64_t* p = (uint64_t*)sd;
    uint64_t cs = 0;
    size_t sd_qwords = (sizeof(stub_data_t) - sizeof(uint64_t)) / sizeof(uint64_t);
    size_t qi;
    for (qi = 0; qi < sd_qwords; qi++) cs ^= p[qi];
    sd->checksum = cs;
    DBG("[*] Password set to: '%ls' (stored as SHA-256 hash)\n", sd->password);
    DBG("[*] stub_data flags=0x%04X (HASH=%d TEST=%d TLS_PROXY=%d ASLR=%d ANTIDEBUG=%d)\n",
           sd->flags,
           (sd->flags & STUB_FLAG_HASH)        ? 1 : 0,
           (sd->flags & STUB_FLAG_TEST_MODE)  ? 1 : 0,
           (sd->flags & STUB_FLAG_TLS_PROXY)  ? 1 : 0,
           (sd->flags & STUB_FLAG_ASLR)        ? 1 : 0,
           (sd->flags & STUB_FLAG_ANTIDEBUG)  ? 1 : 0);

    /* 9. 计算新 .lock 节位置（保留 overlay）
     *   .lock 节内容 = stub.bin + (TLS_PROXY 模式时追加 callbacks 数组)
     *   callbacks 数组 = [stub_tls_callback_VA, NULL]
     *   stub_tls_callback_VA = ImageBase + new_va + stub_tls_cb_offset
     *   callbacks_array_VA   = ImageBase + new_va + cb_array_offset_in_lock */
    DWORD file_align = OH(FileAlignment);
    DWORD sec_align = OH(SectionAlignment);

    /* callbacks 数组在 .lock 中的偏移（按架构对齐：x86 4 字节，x64 8 字节）*/
    size_t cb_align = TLS_CB_ELEM_SIZE();
    size_t cb_array_offset_in_lock = (stub_size + cb_align - 1) & ~(cb_align - 1);
    /* callbacks 数组大小：[stub_tls_callback_VA, NULL] = 2 * elem_size 字节
     *   （stub_tls_callback 调用原 callbacks via stub_data.orig_tls_callbacks，
     *    所以新数组只需要 stub_tls_callback + NULL，原 callbacks 不会被 loader 二次调用）*/
    size_t cb_array_size = tls_info.has_callbacks ? (2 * cb_align) : 0;
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
        stub_tls_cb_va   = OH_IMG_BASE() + new_va + stub_tls_cb_offset;
        new_cb_array_va  = OH_IMG_BASE() + new_va + (uint64_t)cb_array_offset_in_lock;
        DBG("[*] stub_tls_callback VA = 0x%llX (ImageBase + 0x%lX + 0x%zX)\n",
               (unsigned long long)stub_tls_cb_va,
               (unsigned long)new_va, stub_tls_cb_offset);
        DBG("[*] new callbacks array VA = 0x%llX (offset in .lock = 0x%zX)\n",
               (unsigned long long)new_cb_array_va, cb_array_offset_in_lock);
    }

    DBG("[*] New .lock section: RVA=0x%lX VSize=0x%lX RawOff=0x%lX RawSize=0x%lX\n",
           (unsigned long)new_va, (unsigned long)new_vsize,
           (unsigned long)new_raw_off, (unsigned long)new_raw_size);
    if (tls_info.has_callbacks) {
        DBG("[*]   .lock content: stub.bin(0x%zX) + callbacks_array(0x%zX) = 0x%zX\n",
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

    /* 重新解析指针（在 out 缓冲区中重新设置 g_nt64/g_nt32） */
    dos = (IMAGE_DOS_HEADER*)out;
    if (g_is_x64) {
        g_nt64 = (IMAGE_NT_HEADERS64*)(out + dos->e_lfanew);
    } else {
        g_nt32 = (IMAGE_NT_HEADERS32*)(out + dos->e_lfanew);
    }
    sec = (IMAGE_SECTION_HEADER*)(OH_NT_BASE() + sizeof(DWORD) /*Signature*/
                                   + sizeof(IMAGE_FILE_HEADER)
                                   + OH_SIZE());

    /* 11. 剥离 Authenticode 签名（清零 DataDirectory[4]） */
    {
        IMAGE_DATA_DIRECTORY* d = OH_DATA_DIR(IMAGE_DIRECTORY_ENTRY_SECURITY);
        if (d->VirtualAddress != 0) {
            d->VirtualAddress = 0;
            d->Size = 0;
            printf("[+] Stripped Authenticode signature directory entry\n");
        }
    }

    /* 12. 清零 Bound Imports（避免 loader 走捷径跳过 IAT 解析） */
    {
        IMAGE_DATA_DIRECTORY* d = OH_DATA_DIR(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
        if (d->VirtualAddress != 0) {
            printf("[!] Bound Imports detected, clearing\n");
            d->VirtualAddress = 0;
            d->Size = 0;
        }
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

    /* 14b. x86: 预 patch stub 的绝对地址到目标加载位置
     *   x86 stub 用绝对地址引用静态数据（非 PIC），编译时绝对地址基于
     *   stub_image_base + stub_lock_rva。嵌入目标 PE 后实际加载位置是
     *   target_image_base + new_va，必须遍历 stub 的 .reloc 表把所有
     *   绝对地址引用加上 delta = (target_base - stub_base)。
     *   patch 后 stub 在目标 PE 加载到固定 ImageBase 时绝对地址全部正确。
     *   注意：patch 必须在 callbacks 数组写入之前（callbacks 数组本身不是
     *   stub 的 .reloc 条目，是 builder 独立写入的，不需要 patch）。 */
    if (!g_is_x64 && stub_reloc_data) {
        uint64_t target_base = OH_IMG_BASE() + new_va;
        uint64_t stub_base = stub_image_base + stub_lock_rva;
        int n_patched = patch_stub_relocations(out + new_raw_off, stub_size,
                                               stub_reloc_data, stub_reloc_size,
                                               stub_image_base, stub_lock_rva,
                                               OH_IMG_BASE(), new_va);
        if (n_patched < 0) {
            printf("[-] Failed to patch stub relocations\n");
            free(stub_exe);
            return 1;
        }
        printf("[+] Patched %d stub relocations: delta=0x%llX (stub_base=0x%llX -> target_base=0x%llX)\n",
               n_patched,
               (unsigned long long)(int64_t)(target_base - stub_base),
               (unsigned long long)stub_base,
               (unsigned long long)target_base);
    }
    if (tls_info.has_callbacks) {
        /* 在 .lock 末尾追加新 callbacks 数组：[stub_tls_callback_VA, NULL]
         * Windows loader 会遍历此数组调用每个 callback。
         * stub_tls_callback 在 DLL_PROCESS_ATTACH 时解密 .text + 调原 callbacks。
         * 数组以 NULL 结尾，所以原 callbacks 不会被 loader 二次调用
         * （由 stub_tls_callback 通过 stub_data.orig_tls_callbacks 调用）。
         * x86 callbacks 数组元素是 4 字节（DWORD VA），x64 是 8 字节（ULONGLONG VA）。 */
        uint8_t* cb_addr = out + new_raw_off + cb_array_offset_in_lock;
        if (g_is_x64) {
            uint64_t* cb_array = (uint64_t*)cb_addr;
            cb_array[0] = stub_tls_cb_va;  /* stub_tls_callback 入口 VA */
            cb_array[1] = 0;                /* NULL 结尾 */
        } else {
            uint32_t* cb_array = (uint32_t*)cb_addr;
            cb_array[0] = (uint32_t)stub_tls_cb_va;
            cb_array[1] = 0;
        }
        printf("[+] Wrote new callbacks array at .lock+0x%zX: [0x%llX, NULL] (%zu-bit)\n",
               cb_array_offset_in_lock, (unsigned long long)stub_tls_cb_va,
               cb_align * 8);
    }
    /* 剩余填充由 calloc 自动清零 */

    /* 15. 更新 PE 头 */
    OH_FILE()->NumberOfSections++;
    OH(SizeOfImage) = new_va + new_vsize_aligned;
    OH(AddressOfEntryPoint) = new_va;
    OH(CheckSum) = 0;

    /* ASLR 处理（v3 条件化）：
     * - x86（无论是否 TLS_PROXY）：强制禁用 ASLR。原因：x86 stub 用绝对地址
     *   引用静态数据（非 PIC），builder 在 step 14b 预 patch stub 绝对地址到
     *   目标 ImageBase + new_va。若 ASLR 启用，加载基址随机化，预 patch 的
     *   绝对地址会错位。禁用 ASLR 让 PE 加载到 preferred ImageBase，
     *   预 patch 的绝对地址直接生效。
     *   副作用：原 PE 的 .text 等 reloc 条目不再被 loader 应用；但 stub
     *   解密 .text 后不重应用 reloc（x86 不设 STUB_FLAG_ASLR），所以 .text
     *   里的绝对地址回到 preferred ImageBase 基准，与实际加载基址一致。正确。
     * - x64 + TLS_PROXY：禁用 ASLR。原因：新 callbacks 数组中的
     *   stub_tls_callback_VA 是绝对 VA，.lock 节无 reloc 条目覆盖。
     * - x64 + 非 TLS_PROXY + ASLR：保留 ASLR，stub 解密 .text 后重新应用
     *   relocations（仅 patch .text 范围，避免双重 reloc）。
     *   STUB_FLAG_ASLR 已在 stub_data.flags 中设置。 */
    if (!g_is_x64) {
        /* x86: 强制禁用 ASLR（stub 绝对地址已预 patch 到 preferred ImageBase）*/
        if (OH(DllCharacteristics) & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
            WORD old_dc = OH(DllCharacteristics);
            WORD new_dc = old_dc & ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
            new_dc &= ~IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
            OH(DllCharacteristics) = new_dc;
            printf("[!] ASLR disabled (x86 stub uses absolute addresses, DllChar 0x%04X -> 0x%04X)\n",
                   old_dc, new_dc);
        }
    } else if (tls_info.has_callbacks) {
        /* x64 + TLS_PROXY：禁用 ASLR */
        if (OH(DllCharacteristics) & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
            WORD old_dc = OH(DllCharacteristics);
            WORD new_dc = old_dc & ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
            new_dc &= ~IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
            OH(DllCharacteristics) = new_dc;
            printf("[!] ASLR disabled (TLS_PROXY mode, DllChar 0x%04X -> 0x%04X)\n",
                   old_dc, new_dc);
        }
    } else if (sd->flags & STUB_FLAG_ASLR) {
        printf("[+] ASLR preserved (stub will re-apply .text relocations)\n");
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
    if (OH(DllCharacteristics) & IMAGE_DLLCHARACTERISTICS_GUARD_CF) {
        WORD old_dc = OH(DllCharacteristics);
        WORD new_dc = old_dc & ~IMAGE_DLLCHARACTERISTICS_GUARD_CF;
        OH(DllCharacteristics) = new_dc;
        printf("[!] CFG disabled (DllChar 0x%04X -> 0x%04X); stub_entry not in GFIDS table\n",
               old_dc, new_dc);
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
        /* 按架构写入：x86 是 4 字节 VA (DWORD)，x64 是 8 字节 VA (ULONGLONG) */
        uint64_t old_aoc;
        if (g_is_x64) {
            uint64_t* aoc_field = (uint64_t*)(out + aoc_raw);
            old_aoc = *aoc_field;
            *aoc_field = new_cb_array_va;
        } else {
            uint32_t* aoc_field = (uint32_t*)(out + aoc_raw);
            old_aoc = *aoc_field;
            *aoc_field = (uint32_t)new_cb_array_va;
        }
        printf("[+] TLS directory AddressOfCallBacks: 0x%llX -> 0x%llX (file off 0x%lX, %zu-bit)\n",
               (unsigned long long)old_aoc,
               (unsigned long long)new_cb_array_va,
               (unsigned long)aoc_raw, cb_align * 8);
    }

    /* 17. 写输出文件 */
    if (write_file(out_path, out, out_size) != 0) {
        printf("[-] Failed to write %s\n", out_path);
        return 1;
    }

    printf("\n[+] ===== Pack complete =====\n");
    printf("[+] Output: %s (%zu bytes = 0x%zX)\n", out_path, out_size, out_size);
    printf("[+] New EP RVA = 0x%lX (was 0x%llX)\n",
           (unsigned long)OH(AddressOfEntryPoint),
           (unsigned long long)oep_rva);
    printf("[+] SizeOfImage = 0x%lX\n", (unsigned long)OH(SizeOfImage));
    printf("[+] Sections   = %u (added .lock)\n", OH_FILE()->NumberOfSections);
    printf("[+] Password   : %ls\n", sd->password);
    printf("[+] Run        : %s\n", out_path);

    free(stub);
    free(stub_exe);  /* x86 时分配，x64 时为 NULL */
    free(pe);
    free(out);
    return 0;
}
