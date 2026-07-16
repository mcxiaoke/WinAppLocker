# EXELock 加密文件格式规范

> **状态**：设计稿，开发阶段不考虑向后兼容，要改直接改
> **架构目标**：x64-only / RunPE 内存执行 / 重点支持 Win GUI EXE / 加密强度可调可扩展

---

## 1. 设计目标

EXELock 的加密文件 = **原生 Stub 程序** + **EXELock Payload**。本规范定义 payload 的二进制布局。

### 1.1 核心需求

1. **支持 Win GUI EXE**：payload 携带原 EXE 的子系统类型、机器类型、原始文件名，stub 据此正确处理 GUI/Console 程序
2. **加密强度可调**：迭代次数、算法等参数全部写入 payload，用户可在 GUI 中自定义
3. **扩展性**：header 用 TLV 扩展区，未来新增字段不破坏 stub 解析（开发期不考虑兼容旧格式，但为后续稳定期留扩展位）
4. **完整性校验**：header 自带 CRC32，密文有 AEAD tag，可选 AAD 绑定 header

### 1.2 非目标

- 不考虑 v0（demo）格式兼容
- 不追求抗离线爆破的强密码学（EXE 加密场景下，密码强度本身才是关键，KDF 只防彩虹表）；KDF 默认用 PBKDF2，迭代次数可调，不引入 Argon2id（启动时占 256MB 内存不可接受）
- 不支持 x86

---

## 2. 整体文件布局

```
┌──────────────────────────────────────────────────────────┐
│  Stub EXE 原生内容（PE 头 / 节区 / 资源 / ...）           │
│  长度可变，由 stub 自身 PE 结构决定                       │
├──────────────────────────────────────────────────────────┤
│  EXELock Payload（本规范定义）                            │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Payload Header（固定头 64B + 可变扩展区，见 §3）   │  │
│  ├────────────────────────────────────────────────────┤  │
│  │  Salt（KDF 盐，长度由 salt_len 字段决定）          │  │
│  ├────────────────────────────────────────────────────┤  │
│  │  Nonce / IV（长度由 nonce_len 字段决定）           │  │
│  ├────────────────────────────────────────────────────┤  │
│  │  Ciphertext（加密后的原 EXE 字节流，含 AEAD tag）  │  │
│  ├────────────────────────────────────────────────────┤  │
│  │  Footer（24B，magic + payload_len + magic）        │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

**定位策略**：stub 读取自身文件末尾 24 字节 footer，校验 magic 后用 `payload_len` 反向定位 header 起始。stub 不需要知道自身 PE 大小，packer 只需 append。

---

## 3. Payload Header

Header = **固定头（64 字节）** + **扩展区（TLV，可变长）**。

### 3.1 固定头（64 字节，小端序）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|------|------|------|------|------|
| 0  | 8  | `magic` | `[u8; 8]` | 固定 `b"EXELOCK!"` |
| 8  | 2  | `format_version` | `u16` | 格式版本号，当前 = `1` |
| 10 | 2  | `header_size` | `u16` | 整个 header 字节数（固定头 + 扩展区），最小 64 |
| 12 | 4  | `header_crc32` | `u32` | header（固定头除本字段 4 字节 + 扩展区）的 CRC32 |
| 16 | 4  | `flags` | `u32` | 位域，见 §3.3 |
| 20 | 2  | `algorithm_id` | `u16` | 算法注册表 ID，见 §6 |
| 22 | 2  | `kdf_id` | `u16` | KDF 注册表 ID，见 §7 |
| 24 | 4  | `kdf_iterations` | `u32` | KDF 迭代次数 |
| 28 | 2  | `salt_len` | `u16` | Salt 字节数，默认 16 |
| 30 | 2  | `nonce_len` | `u16` | Nonce/IV 字节数，算法相关 |
| 32 | 8  | `ciphertext_len` | `u64` | 密文字节数（含 AEAD tag） |
| 40 | 8  | `plaintext_len` | `u64` | 原始 EXE 字节数 |
| 48 | 4  | `plaintext_crc32` | `u32` | 原始 EXE 的 CRC32，解密后二次校验 |
| 52 | 4  | `original_subsystem` | `u32` | 原 EXE 的 PE Subsystem（2=GUI, 3=Console） |
| 56 | 2  | `original_machine` | `u16` | 原 EXE 的 PE Machine（0x8664=x64） |
| 58 | 2  | `reserved` | `u16` | 保留，置 0 |
| 60 | 4  | `extension_offset` | `u32` | 扩展区起始相对 header 起的偏移（无扩展则 = `header_size`） |

> **header_crc32 的作用**：CRC32 不是密码学校验（密文已有 GCM tag），仅用于**意外损坏检测**与**降低 stub 崩溃概率**。真正的密码学防篡改依赖 AEAD tag + 可选 AAD。

### 3.2 扩展区（TLV，可变长）

固定头之后紧跟扩展区，由若干 TLV 条目组成。每条：

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 2 | `tag` | 扩展字段 ID |
| 2 | 4 | `length` | value 字节数 |
| 6 | `length` | `value` | 字段值 |

扩展区以 `tag = 0x0000`（`EXT_END`，`length` 必须为 0）终止。stub 遇到未知 tag **必须跳过**（按 `length` 跳过）。

**已定义扩展字段**：

| Tag | 名称 | 长度 | 说明 |
|-----|------|------|------|
| `0x0000` | `EXT_END` | 0 | 扩展区终止符 |
| `0x0001` | `EXT_ORIGINAL_NAME` | 变长 | 原 EXE 文件名（UTF-8），stub 用于重建进程名 / 任务栏显示 |
| `0x0002` | `EXT_ORIGINAL_TIMESTAMP` | 8 | 原 EXE 的修改时间（Unix 秒，u64 LE） |
| `0x0003` | `EXT_AAD` | 变长 | AEAD 的附加认证数据，见 §8 |
| `0x0004` | `EXT_ORIGINAL_HASH` | 32 | 原始 EXE 的 SHA-256，强校验（可选） |
| `0x0005` | `EXT_BUILD_INFO` | 变长 | packer 构建信息（版本号、构建时间），用于诊断 |
| `0x0006` | `EXT_PADDING` | 变长 | 填充字节，用于掩盖原文件大小指纹（未来） |
| `0x0007` | `EXT_KDF_EXTRA` | 变长 | KDF 的额外参数（如未来加 scrypt/bcrypt 时的 cost 参数） |
| `0x0008–0x7FFF` | — | — | 保留给官方扩展 |
| `0x8000–0xFFFF` | — | — | 用户自定义扩展（高位 1 表示私有） |

> **关键**：未来用户想在 GUI 里自定义 KDF cost、添加 license 信息、嵌入元数据等，全部走扩展区，**不动固定头**。这是扩展性的核心保障。

### 3.3 Flags 位域

| 位 | 名称 | 含义 | MVP |
|----|------|------|-----|
| bit 0 | `FLAG_HAS_EXTENSION` | 存在扩展区（`extension_offset < header_size`） | ✅ |
| bit 1 | `FLAG_ORIGINAL_IS_GUI` | 原 EXE 是 GUI 程序（`original_subsystem == 2` 的别名） | ✅ |
| bit 2 | `FLAG_USE_AAD` | 启用 AEAD AAD（`EXT_AAD` 存在） | ✅ |
| bit 3 | `FLAG_ANTI_DEBUG` | stub 启用反调试 | 推迟 |
| bit 4 | `FLAG_ANTI_DUMP` | stub 启用反 dump（擦除 PE 头等） | 推迟 |
| bit 5 | `FLAG_ERASE_PAYLOAD` | 解密后立即擦除 payload 区与 header | ✅ |
| bit 6 | `FLAG_PRESERVE_ORIGINAL_NAME` | stub 用 `EXT_ORIGINAL_NAME` 作为映像名 | ✅ |
| bit 7–31 | — | 保留 | — |

stub 忽略未知位，仅检查自己支持的位。MVP 阶段 stub 遇到 `FLAG_ANTI_DEBUG` / `FLAG_ANTI_DUMP` 时忽略（视为未启用），不报错。

---

## 4. Win GUI EXE 支持策略

这是本规范的核心设计点之一。stub 根据原 EXE 的子系统类型采取不同行为。

### 4.1 `original_subsystem` 取值（来自原 EXE 的 `IMAGE_OPTIONAL_HEADER.Subsystem`）

| 值 | 含义 | stub 行为 |
|----|------|----------|
| 2 | `WINDOWS_GUI` | 原 EXE 无控制台。stub 必须用 GUI 子系统，否则会闪黑窗 |
| 3 | `WINDOWS_CUI` | 原 EXE 是控制台程序。stub 需将控制台让渡给原程序 |
| 9 | `WINDOWS_CE_GUI` | 罕见，按 GUI 处理 |

### 4.2 GUI 程序的"黑窗闪烁"问题

被保护的是 GUI 程序（游戏、工具软件）时，若 stub 编译为 console 子系统，启动会弹出黑色 cmd 窗口，体验很差。

**方案**：
- packer 读取原 EXE 的 `Subsystem`，写入 `original_subsystem`
- 若原 EXE 是 GUI，packer **优先选择 GUI 版 stub**（提供 `stub_gui.exe` 与 `stub_console.exe` 两个变体，由 build.rs 嵌入 packer）
- stub 自身子系统必须与原 EXE 匹配
- 密码输入框统一用 Win32 `DialogBox` 自绘（不依赖控制台），无论 stub 是 GUI 还是 console 都能正常弹出

### 4.3 RunPE 与 GUI 的特殊处理

RunPE 内存加载时，stub 在自身进程内分配内存、加载 PE、跳转 OEP。对 GUI 程序：

- 进程映像名建议用 `EXT_ORIGINAL_NAME`（任务管理器显示原程序名）
- 不要 `AllocConsole`，否则 GUI 程序会多出一个控制台窗口
- 输入法、DPI 感知等由原 EXE 自身 manifest 决定，stub 不干预

---

## 5. Footer（24 字节，固定）

位于文件最末尾，stub 反向定位 payload 的唯一入口。

| 偏移 | 长度 | 字段 | 值 / 类型 | 说明 |
|------|------|------|----------|------|
| 0  | 8  | `magic_a` | `b"EXELOCK!"` | 头部 magic |
| 8  | 8  | `payload_len` | `u64 LE` | 整个 payload（header + salt + nonce + ciphertext + footer）总字节数 |
| 16 | 8  | `magic_b` | `b"EL2END!!"` | 尾部 magic |

stub 读取自身文件末尾 24 字节，校验 `magic_a` 与 `magic_b` 都匹配后，从 `file_size - payload_len` 处读取 header。24 字节中有 16 字节 magic，误识别概率约 2^-128。

---

## 6. 算法注册表（`algorithm_id`）

| ID | 名称 | Nonce 长度 | Tag 长度 | 状态 |
|----|------|-----------|---------|------|
| 0x0001 | `AES-256-GCM` | 12 | 16 | ✅ 默认 |
| 0x0002 | `ChaCha20-Poly1305` | 12 | 16 | ✅ 备选（无 AES-NI 时更快） |
| 0x0003 | `AES-128-GCM` | 12 | 16 | ⚠️ 较弱，保留 |
| 0x0004 | `SM4-GCM`（国密） | 12 | 16 | 📋 规划（feature 控制） |
| 0x0005 | `XChaCha20-Poly1305` | 24 | 16 | 📋 规划（nonce 24 字节） |
| 其他 | — | — | — | 未知，stub 拒绝执行并报错 |

**关键规则**：
- stub 严格按 `algorithm_id` 分发，不硬编码算法
- `nonce_len` 字段是权威来源（XChaCha20 的 24 字节 nonce 才能被正确处理）
- 未知 ID 一律拒绝

---

## 7. KDF 注册表（`kdf_id`）

| ID | 名称 | 参数字段 | 说明 |
|----|------|---------|------|
| 0x0001 | `PBKDF2-HMAC-SHA256` | `kdf_iterations` | 默认，性能/安全平衡好 |
| 0x0002 | `PBKDF2-HMAC-SHA512` | `kdf_iterations` | 更高安全余量，稍慢 |
| 0x0003 | `Scrypt` | `EXT_KDF_EXTRA`（N/r/p） | 抗 GPU/ASIC，未来可选 |
| 其他 | — | — | 未知，stub 拒绝 |

**不引入 Argon2id 的理由**：
- EXE 加密场景不需要抗 ASIC 强破解，密码强度本身是关键
- Argon2id 默认 256MB 内存占用严重拖慢启动（用户双击 EXE 等 1.5s 才弹密码框，体验差）
- PBKDF2 + 足够迭代次数已足够防彩虹表与普通字典攻击
- 未来若真需要，通过 `EXT_KDF_EXTRA` 扩展即可，不破坏格式

---

## 8. 加密强度预设

packer（GUI）提供预设简化用户选择，预设本身**不写入 payload**，只把实际生效的字段写入。这样 stub 不需要理解"预设"概念。

| 预设 | 算法 | KDF | 迭代次数 | AAD | 擦除 payload | 参考解密耗时 | 适用场景 |
|------|------|-----|---------|-----|-------------|------------|---------|
| `fast` | AES-256-GCM | PBKDF2-SHA256 | 100,000 | 否 | 否 | < 50ms | 个人工具，启动速度优先 |
| `balanced` | AES-256-GCM | PBKDF2-SHA256 | 600,000 | 是 | 是 | ~200ms | 默认，符合 OWASP 2023 |
| `secure` | ChaCha20-Poly1305 | PBKDF2-SHA512 | 2,000,000 | 是 | 是 | ~700ms | 高价值目标，启动稍慢可接受 |
| `custom` | 用户指定 | 用户指定 | 用户指定 | 用户指定 | 用户指定 | — | 高级用户，GUI 完全开放 |

> MVP 阶段不提供反调试/反 dump 选项（推迟），GUI 中这两个复选框先不显示，或显示但置灰标注"未来版本"。

**预设可被 GUI 中的高级选项覆盖**：用户在 GUI 里改迭代次数、算法等，会自动切到 `custom`。

**GUI 暴露给用户的加密参数**（全部写入 payload）：
- 算法选择（下拉框）
- KDF 选择（下拉框）
- 迭代次数（数字输入，最小值 100,000，最大值 100,000,000）
- 是否启用 AAD（复选框）
- 是否擦除 payload（复选框）
- Salt 长度（高级，默认 16）
- 反调试 / 反 dump（MVP 不显示，未来版本再加）

> 这些参数本身就是 payload header 字段或扩展区，无需额外存储机制。**用户自定义参数 = 直接写 header**，这就是扩展性的体现。

---

## 9. AEAD 附加认证数据（AAD）

启用 `FLAG_USE_AAD` 时，stub 调用 `decrypt` 传入 `EXT_AAD` 内容作为 AAD。AAD 不加密但参与认证 tag 计算，**任何对 header 关键字段或 AAD 的篡改都会导致解密失败**。

**默认 AAD 构造**（packer 在 `FLAG_USE_AAD` 置位时自动生成）：

```
AAD = magic(8) || format_version(2) || algorithm_id(2) || kdf_id(2) 
    || kdf_iterations(4) || original_subsystem(4) || original_machine(2)
```

即固定头前 22 字节中影响安全决策的部分。这样攻击者无法通过篡改 `kdf_iterations` 让 stub 用低迭代次数解密。AAD 提供了对 header 自身的密码学绑定，比 §3.1 的 CRC32 强得多。

默认不启用 AAD（兼容性优先），`balanced` 与 `secure` 预设自动启用。

---

## 10. 完整二进制布局示例

以 1MB 的 GUI EXE、AES-256-GCM、PBKDF2 600k 迭代、启用 AAD 为例：

```
偏移          内容                                   长度
----------   ------------------------------------   --------
0            Stub EXE 原生内容                       ~200 KB
~200KB       Payload Header (固定头 64B)             64
~200KB+64      - 扩展区 (EXT_ORIGINAL_NAME + EXT_AAD)  ~40
~200KB+104   Salt                                    16
~200KB+120   Nonce                                   12
~200KB+132   Ciphertext (1MB + 16B tag)              1,048,592
~1.2MB       Footer                                  24
```

总文件 ≈ 200KB + 1MB + 156B。

---

## 11. 安全注意事项

1. **header_crc32 不是安全边界**：CRC32 可被攻击者重算，真正防篡改依赖 GCM tag + 可选 AAD
2. **salt / nonce 必须由 packer 用密码学安全随机源生成**（`OsRng` / `BCryptGenRandom`），禁止时间戳派生
3. **plaintext_len / plaintext_crc32 泄露原文件大小**：若担心大小指纹，未来用 `EXT_PADDING`
4. **footer 是 stub 唯一信任的入口**：24 字节中 16 字节 magic，误识别概率约 2^-128
5. **stub 对 `kdf_iterations` 设上限**（如 100,000,000），防恶意文件触发 DoS
6. **密钥与明文必须清零**：用 `Zeroizing<Vec<u8>>`，drop 自动擦除

---

## 12. 参考实现校验清单

packer 实现完成后，应能通过以下断言：

- [ ] 生成的文件末尾 24 字节 = `magic_a + payload_len + magic_b`
- [ ] `header_crc32` 能通过校验
- [ ] 用对应算法/KDF/迭代次数能成功解密还原原始 EXE
- [ ] `plaintext_crc32` 与解密结果一致
- [ ] 篡改 header 任意 1 字节，stub 拒绝执行（CRC 失败）
- [ ] 篡改 ciphertext 任意 1 字节，stub 解密失败（GCM tag 失败）
- [ ] 启用 AAD 时，篡改 header 中 AAD 覆盖的字段，解密失败
- [ ] GUI 中切换 `fast/balanced/secure` 预设生成不同 `kdf_iterations` 与 `algorithm_id`
- [ ] GUI 中自定义迭代次数等参数后，payload header 字段同步变化
- [ ] GUI EXE 加密后，`original_subsystem == 2` 且 `FLAG_ORIGINAL_IS_GUI` 置位
- [ ] packer 自动根据原 EXE 子系统选择 `stub_gui` 或 `stub_console`
- [ ] MVP stub 遇到 `FLAG_ANTI_DEBUG` / `FLAG_ANTI_DUMP` 时忽略不报错
