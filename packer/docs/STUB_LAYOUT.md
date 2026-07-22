# Stub 节布局契约（N10）

本文档定义 inplace stub 的 `.text2` 节内 `stub_data_t` 结构布局契约，
作为 C 端（config.h）和 Python 端（patch_stub_identity.py / inspect_stub.py）
的**单一事实来源**。任何字段变更必须同步更新此文档。

## 1. 节布局概览

```
.text2 节（inplace stub.bin）
┌─────────────────────────────────────────────────────────┐
│  stub_entry  (stub_asm_x64.asm / stub_asm_x86.asm)      │
│  ...                                                     │
│  stub_data   (config.h: stub_data_t, STUB_DATA_SIZEOF)  │← builder 按 magic 搜索
│  ...                                                     │
│  stub_tls_callback (可选, STUB_TLS_CB_MAGIC 标记)        │← builder 按 magic 搜索
└─────────────────────────────────────────────────────────┘
```

- **节名**：`.text2`（inplace）/ `.rdata2`（reflective 的 stub EXE 用）
- **对齐**：`#pragma pack(push, 8)`，8 字节对齐
- **magic**：`STUB_DATA_MAGIC = 0x214B434F4C4E4957ULL`（"WINLOCK!" ASCII，小端）

## 2. stub_data_t 字段表（v6，STUB_DATA_SIZEOF = 192）

| 偏移  | 大小 | 字段                  | 类型          | 说明                          |
|-------|------|-----------------------|---------------|-------------------------------|
| 0     | 8    | magic                 | uint64_t      | STUB_DATA_MAGIC，builder 据此定位 |
| 8     | 2    | version               | uint16_t      | STUB_DATA_VERSION = 6         |
| 10    | 2    | flags                 | uint16_t      | STUB_FLAG_* 位掩码            |
| 12    | 2    | max_retries           | uint16_t      | 密码错误最大重试次数          |
| 14    | 2    | reserved16            | uint16_t      | 保留                          |
| 16    | 8    | oep_rva               | uint64_t      | 原 AddressOfEntryPoint        |
| 24    | 8    | text_rva              | uint64_t      | 加密的第一个可执行节 RVA      |
| 32    | 8    | text_size             | uint64_t      | 加密大小                      |
| 40    | 4    | text_raw_size         | uint32_t      | 该节 SizeOfRawData            |
| 44    | 4    | text_protect          | uint32_t      | 该节原保护属性                |
| 48    | 16   | xtea_key[4]           | uint32_t[4]   | XTEA 密钥                     |
| 64    | 16   | salt[16]              | uint8_t[16]   | SHA-256 salt                  |
| 80    | 32   | pwd_hash[32]          | uint8_t[32]   | SHA-256(password_utf8 + salt) |
| 112   | 8    | image_base            | uint64_t      | 原 PE ImageBase（preferred）  |
| 120   | 8    | reloc_rva             | uint64_t      | .reloc 节 RVA                 |
| 128   | 4    | reloc_size            | uint32_t      | .reloc 节 Size                |
| 132   | 4    | reserved32            | uint32_t      | 对齐填充                      |
| 136   | 8    | orig_tls_callbacks    | uint64_t      | 原 PE TLS callbacks 数组 VA   |
| 144   | 8    | security_cookie_rva   | uint64_t      | LOAD_CONFIG.SecurityCookie RVA|
| 152   | 32   | identity              | stub_identity_t | 身份块（见下表）             |
| 184   | 8    | checksum              | uint64_t      | XOR 所有 64-bit 字段（防篡改）|

**总计：192 字节**

## 3. stub_identity_t 字段表（32 字节，偏移 152）

| 偏移  | 大小 | 字段              | 类型         | 注入时机                |
|-------|------|-------------------|--------------|-------------------------|
| 0     | 4    | stub_arch         | uint32_t     | 编译期（CMake/MinGW -D）|
| 4     | 4    | stub_toolchain    | uint32_t     | 编译期（CMake/MinGW -D）|
| 8     | 4    | stub_bin_ver      | uint32_t     | POST_BUILD patch        |
| 12    | 4    | stub_build_time   | uint32_t     | POST_BUILD patch        |
| 16    | 4    | stub_source_crc   | uint32_t     | POST_BUILD patch        |
| 20    | 4    | stub_size         | uint32_t     | POST_BUILD patch        |
| 24    | 8    | stub_githash[8]   | uint8_t[8]   | POST_BUILD patch        |

**stub_arch**：1=x86, 2=x64
**stub_toolchain**：1=MSVC, 2=MinGW

## 4. Python 端偏移推导（不硬编码）

Python 脚本（patch_stub_identity.py / inspect_stub.py）通过以下公式推导偏移：

```python
# 从 config.h 解析（parse_config_h 函数）
stub_data_size = int(re.search(r"#define\s+STUB_DATA_SIZEOF\s+(\d+)", content).group(1))
# 当前值：192

# identity 在 stub_data_t 内的偏移
identity_offset = stub_data_size - CHECKSUM_SIZE - IDENTITY_SIZE
# = 192 - 8 - 32 = 152

# checksum 在 stub_data_t 内的偏移
checksum_offset = stub_data_size - CHECKSUM_SIZE
# = 192 - 8 = 184
```

**关键约束**：
- `IDENTITY_SIZE = 32` 固定（stub_identity_t 结构稳定，不随版本变化）
- `CHECKSUM_SIZE = 8` 固定（uint64_t）
- `stub_data_size` 从 config.h 解析，结构变化时只需更新 config.h 的 `STUB_DATA_SIZEOF`

## 5. 编译期校验

config.h 中的 `_Static_assert` 保证 STUB_DATA_SIZEOF 与实际 sizeof 一致：

```c
static char stub_data_sizeof_check[
    (sizeof(stub_data_t) == STUB_DATA_SIZEOF) ? 1 : -1];
```

如果结构体字段增减导致 sizeof 变化但宏未更新，编译会失败。

## 6. 变更流程

修改 stub_data_t 时必须同步：
1. **config.h**：更新 `STUB_DATA_VERSION`（递增）和 `STUB_DATA_SIZEOF`（新 sizeof）
2. **本文档**：更新第 2 节字段表（偏移、大小）
3. **builder.c**：更新填充逻辑
4. **stub.c**：更新读取逻辑
5. **Clean build + e2e 测试**：验证 STUB_DATA_SIZEOF 与 sizeof 一致

**不需要手动更新**（自动从 config.h 推导）：
- patch_stub_identity.py
- inspect_stub.py
- check_stub_freshness.py

## 7. 相关文件

| 文件 | 职责 |
|------|------|
| `common/config.h` | stub_data_t / stub_identity_t 定义，STUB_DATA_SIZEOF 宏 |
| `inplace/stub.c` | stub_data 运行时读取（verify_password / apply_relocations） |
| `inplace/builder.c` | stub_data 字段填充（PE 解析 / 加密 / TLS） |
| `cmake/patch_stub_identity.py` | POST_BUILD 注入 identity 字段 |
| `cmake/inspect_stub.py` | 反查 stub 身份字段（.bin / .exe） |
| `cmake/check_stub_freshness.py` | 校验 stub_source_crc 是否新鲜 |
