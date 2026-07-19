/*
 * winlock/builder/builder_reflective.c - 反射式 packer builder（MVP v1 明文模式）
 *
 * 流程：
 *   1. 读输入 PE 文件（任意架构：x86/x64/ARM64/.NET 都行，反射式不挑食）
 *   2. 解析 PE 头：ImageBase / SizeOfImage / OEP / Subsystem / Machine
 *   3. 构造 payload：reflective_payload_t 头 + 原 PE 文件完整数据（v1 明文）
 *   4. 读预编译 stub EXE（reflective/loader_x64.exe）
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
 *   - stub 用 x64（loader.c 只编译 x64）
 *   - 不处理 overlay（直接读整个文件作为 payload_data）
 *   - 不修改 stub 的 entry（stub 用默认 mainCRTStartup -> main()）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

#include "../reflective/payload.h"

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

/* ---- 用法 ---- */

static void usage(const char* prog) {
    printf("WinLock Reflective Packer MVP v1\n");
    printf("Usage: %s <input.exe> <output.exe> [--stub <stub.exe>] [--debug|-v]\n", prog);
    printf("  --stub <path>   Path to reflective stub EXE (default: ../reflective/loader_x64.exe)\n");
    printf("  --debug / -v    Verbose output\n");
    printf("\nFeatures:\n");
    printf("  - Plaintext payload (no encryption, MVP v1)\n");
    printf("  - Supports any PE architecture (x86/x64/ARM64/.NET)\n");
    printf("  - Inherits input PE subsystem (GUI stays GUI)\n");
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char* in_path = argv[1];
    const char* out_path = argv[2];
    /* 默认 stub 路径：相对于 builder/ 目录的 ../reflective/loader_x64.exe
     * 也可通过 --stub 覆盖 */
    const char* stub_path = "../reflective/loader_x64.exe";

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--stub") == 0 && i + 1 < argc) {
            stub_path = argv[++i];
        } else if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-v") == 0) {
            g_debug = 1;
        } else {
            printf("[-] Unknown arg: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
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
    if (info.machine == IMAGE_FILE_MACHINE_AMD64) arch_str = "x64";
    else if (info.machine == IMAGE_FILE_MACHINE_I386) arch_str = "x86";
    else if (info.machine == IMAGE_FILE_MACHINE_ARM64) arch_str = "ARM64";
    const char* subsys_str = "unknown";
    if (info.subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) subsys_str = "GUI";
    else if (info.subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) subsys_str = "CUI(console)";
    printf("[+] Input PE: arch=%s ImageBase=0x%llx SizeOfImage=0x%x OEP=0x%x Subsystem=%u(%s)\n",
           arch_str, (unsigned long long)info.image_base,
           info.size_of_image, info.entry_rva,
           info.subsystem, subsys_str);

    /* 3. 构造 payload
     *    v1 明文：payload_data = 整个原 PE 文件（含 PE 头 + 所有节 + overlay）
     *    stub 运行时按 PE 结构解析，overlay 自动忽略 */
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
    hdr->version       = REFLECTIVE_PAYLOAD_VERSION;
    hdr->flags         = 0;          /* v1 明文，无加密 */
    hdr->kdf_iters     = 0;
    hdr->reserved16    = 0;
    hdr->original_size = (uint64_t)in_size;
    hdr->stored_size   = (uint64_t)in_size;  /* v1: stored == original */
    hdr->oep_rva       = (uint64_t)info.entry_rva;
    hdr->image_base    = info.image_base;
    /* salt/nonce/pwd_hash/auth_tag/xtea_key 全 0（calloc 已清零）*/
    hdr->reserved32    = 0;
    hdr->checksum      = 0;          /* v1 暂不校验 */

    memcpy(payload + sizeof(reflective_payload_t), in_pe, in_size);
    printf("[+] Built payload: header=%zu data=%zu total=%zu (plaintext v1)\n",
           sizeof(reflective_payload_t), payload_data_size, total_payload_size);

    /* 4. 读 stub EXE */
    size_t stub_size = 0;
    uint8_t* stub = read_file(stub_path, &stub_size);
    if (!stub) {
        printf("[-] Failed to read stub: %s\n", stub_path);
        free(payload); free(in_pe);
        return 1;
    }
    printf("[+] Read stub: %s (%zu bytes)\n", stub_path, stub_size);

    /* 5. 解析 stub PE 头（stub 是 x64，用 NT_HEADERS64）*/
    IMAGE_DOS_HEADER* s_dos = (IMAGE_DOS_HEADER*)stub;
    if (s_dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Stub is not a valid PE (bad DOS magic)\n");
        free(stub); free(payload); free(in_pe);
        return 1;
    }
    IMAGE_NT_HEADERS64* s_nt = (IMAGE_NT_HEADERS64*)(stub + s_dos->e_lfanew);
    if (s_nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Stub is not a valid PE (bad NT signature)\n");
        free(stub); free(payload); free(in_pe);
        return 1;
    }
    if (s_nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("[-] Stub is not x64 (MVP only supports x64 stub)\n");
        free(stub); free(payload); free(in_pe);
        return 1;
    }

    WORD  s_n_sec      = s_nt->FileHeader.NumberOfSections;
    DWORD s_file_align = s_nt->OptionalHeader.FileAlignment;
    DWORD s_sec_align  = s_nt->OptionalHeader.SectionAlignment;
    IMAGE_SECTION_HEADER* s_sec = IMAGE_FIRST_SECTION(s_nt);

    /* 检查 stub 是否已有 .payload 节（避免重复加壳）*/
    for (WORD i = 0; i < s_n_sec; i++) {
        if (memcmp(s_sec[i].Name, ".payload", 8) == 0) {
            printf("[-] Stub already has .payload section (already packed?)\n");
            free(stub); free(payload); free(in_pe);
            return 1;
        }
    }

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

    /* 重新解析指针到 out 缓冲区（避免悬空指针）*/
    IMAGE_DOS_HEADER* o_dos = (IMAGE_DOS_HEADER*)out;
    IMAGE_NT_HEADERS64* o_nt = (IMAGE_NT_HEADERS64*)(out + o_dos->e_lfanew);
    IMAGE_SECTION_HEADER* o_sec = IMAGE_FIRST_SECTION(o_nt);

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

    /* 10. 更新 PE 头 */
    o_nt->FileHeader.NumberOfSections++;
    o_nt->OptionalHeader.SizeOfImage = new_va + new_vsize_aligned;
    /* 继承原 PE 的 subsystem（让 GUI 程序保持 GUI）
     * stub 编译为 console subsystem 便于开发，输出 EXE 改为原 PE 的 subsystem */
    o_nt->OptionalHeader.Subsystem = info.subsystem;
    /* 清零 CheckSum（让 OS 不校验，CRT 不依赖 CheckSum）*/
    o_nt->OptionalHeader.CheckSum = 0;

    /* 11. 写输出 */
    if (write_file(out_path, out, out_size) != 0) {
        printf("[-] Failed to write output: %s\n", out_path);
        free(out); free(stub); free(payload); free(in_pe);
        return 1;
    }

    printf("[+] Wrote output: %s (%zu bytes)\n", out_path, out_size);
    printf("[+]   Subsystem: %u(%s) (inherited from input PE)\n",
           info.subsystem, subsys_str);
    printf("[+]   NumberOfSections: %u -> %u\n",
           s_n_sec, o_nt->FileHeader.NumberOfSections);
    printf("[+]   SizeOfImage: 0x%lx -> 0x%lx\n",
           (unsigned long)s_nt->OptionalHeader.SizeOfImage,
           (unsigned long)o_nt->OptionalHeader.SizeOfImage);
    printf("[+]   Entry: stub mainCRTStartup (unchanged)\n");
    printf("[+] Done. Output will run stub -> reflective load -> jump to original OEP\n");

    free(out); free(stub); free(payload); free(in_pe);
    return 0;
}
