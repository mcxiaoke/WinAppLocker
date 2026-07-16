# EXELock 项目架构文档

> **状态**：设计稿，开发阶段不考虑兼容性，要改直接改
> **配套文档**：[FORMAT.md](./FORMAT.md)（加密文件格式规范）

---

## 1. 项目目标与范围

### 1.1 核心目标

为 Windows x64 EXE 提供密码保护：加密后的 EXE 启动时需输入正确密码，密码错误则无法运行。

### 1.2 范围（MVP）

1. **RunPE 内存执行**：解密后的 EXE 不落地磁盘，全程在内存中加载执行
2. **重点支持 Win GUI EXE**：正确处理 GUI 子系统程序，无控制台闪烁
3. **可切换加密强度**：提供 `fast / balanced / secure` 预设，GUI 中也可完全自定义
4. **扩展性**：算法、KDF 可插拔，文件格式用 TLV 扩展区
5. **GUI 优先**：默认形态是 GUI 工具（egui + rfd），不维护 CLI（除非未来有自动化需求再加）
6. **擦除 payload**：解密后擦除内存中的 payload 区（简单防护）

**MVP 不做**（推迟到按需推进）：
- 反调试、反 dump（大幅增加复杂度且触发 Defender 误报）
- 密码错误次数限制
- 代码签名
- 延迟导入表支持

### 1.3 非目标

- 不支持 Linux/macOS（Windows 专用）
- 不支持 x86（仅 x64）
- 不支持 .NET 托管程序集（RunPE 后 CLR 无法初始化）
- 不实现加壳级别的反逆向（PE 节区注入是未来方向）
- 不引入 Argon2id（启动时 256MB 内存占用不可接受，EXE 加密场景用 PBKDF2 已足够）
- 开发阶段不考虑格式向后兼容

---

## 2. 语言选型

### 2.1 决策

**主语言：Rust（全栈）**

| 组件 | 语言 | 理由 |
|------|------|------|
| stub（壳） | Rust | 必须原生 PE + 低级内存操作 + 体积小 |
| exelock-crypto（共享） | Rust | 与 stub 复用，避免重复实现 |
| exelock-pe（PE 解析/加载） | Rust | goblin/pelite 生态成熟 |
| packer GUI | Rust + egui + rfd | 单一技术栈，单二进制发布 |

### 2.2 候选语言对比

本项目的硬约束是 **stub 必须是原生 PE 且能被 RunPE 加载**。

| 维度 | Rust | C++ | C# (.NET) | Go | Python |
|------|------|-----|-----------|----|--------|
| Stub 编译为原生 PE | ✅ | ✅ | ⚠️ 仅 NativeAOT | ✅ | ❌ |
| Stub 体积 | ~150-200KB | ~50KB | 5-10MB (AOT) | 2-5MB | 30-50MB |
| Stub 可被 RunPE 加载 | ✅ | ✅ | ⚠️ AOT 可，托管不行 | ❌ runtime 冲突 | ❌ |
| 内存安全 | ✅ 编译期 | ❌ 手动 | ✅ GC | ✅ GC | ✅ GC |
| PE 操作库生态 | goblin/pelite | 成熟 | 有限 | 弱 | 弱 |
| 低级内存操作 | ✅ windows-rs | ✅ 原生 | ✅ P/Invoke | ⚠️ 受限 | ❌ ctypes 脆弱 |
| GUI 工具开发 | egui/iced | Qt/WTL | WPF/WinForms（最佳） | Wails/Fyne | Tkinter/PyQt |
| 反编译难度 | 高 | 高 | 托管低/AOT 中 | 中 | 极低 |
| **Stub 可行性** | ✅ 强烈推荐 | ✅ 次选 | ⚠️ 仅 AOT | ❌ 不可行 | ❌ 不可行 |

**关键排除理由**：
- **Go**：runtime 接管线程调度，RunPE 跳转 OEP 后 goroutine 调度器与原 EXE 冲突崩溃
- **Python**：必须打包解释器，体积 30-50MB，极易反编译
- **C# 托管**：含 CLR header，无法被 RunPE 加载（CLR 无法二次初始化）
- **C# NativeAOT**：体积 5-10MB 过大，且 AOT 后反射受限
- **C++**：PE 加载器是内存不安全重灾区，开发效率低，与现有 Rust 代码栈不一致

**Rust 全栈的红利**：stub、共享 crypto/PE 模块、packer GUI 全用同一种语言，复用最大化，构建发布最简单。GUI 用 egui 虽然不如 WPF 精美，但足够做配置工具，且保持单二进制、单技术栈。

---

## 3. 整体架构

### 3.1 系统组件图

```
┌─────────────────────────────────────────────────────────────────┐
│                      构建期（开发机）                            │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  packer GUI  │ ─→ │exelock-crypto│    │   stub (Rust)    │  │
│  │  (egui+rfd)  │    │  (lib crate) │    │ 编译为两个变体：  │  │
│  └──────────────┘    └──────────────┘    │  stub_gui.exe    │  │
│         ↑                  ↑             │  stub_console.exe│  │
│         │                  │             └────────┬─────────┘  │
│      ┌──┴──┐          ┌────┴────┐                │            │
│      │ GUI │          │exelock- │     build.rs   │            │
│      │ opts│          │  pe     │  embed_bytes!  │            │
│      └─────┘          │(lib)    │                ↓            │
│                       └─────────┘     ┌──────────────────┐    │
│                                       │ packer 二进制     │    │
│                packer 读取 stub 模板 → │ (含两个 stub)    │    │
│                                       └────────┬─────────┘    │
│                                                ↓              │
│                                  ┌──────────────────────────┐ │
│                                  │  locked.exe              │ │
│                                  │ = stub + payload         │ │
│                                  └──────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              ↓ 分发到用户
┌─────────────────────────────────────────────────────────────────┐
│                      运行期（用户机）                            │
│                                                                 │
│  用户双击 locked.exe                                            │
│         │                                                       │
│         ↓                                                       │
│  ┌──────────────────────────────────────────┐                  │
│  │  stub 进程启动                           │                  │
│  │  1. 读取自身末尾 footer，反向定位 payload │                  │
│  │  2. 弹出密码对话框（Win32，非控制台）     │                  │
│  │  3. KDF 派生密钥                         │                  │
│  │  4. AEAD 解密 payload → 内存中明文 PE    │                  │
│  │  5. RunPE 内存加载（见 §6）              │                  │
│  │  6. 跳转到 OEP，原程序接管                │                  │
│  └──────────────────────────────────────────┘                  │
│         │                                                       │
│         ↓                                                       │
│  原程序在 stub 进程内运行（无子进程，无临时文件）              │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 关键设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| 解密后 EXE 落地 | ❌ 全程内存 | 临时文件可被复制，安全性为零 |
| 进程模型 | stub 自身进程内加载 | 不用 Process Hollowing，Defender 误报更低 |
| GUI 形态 | egui + rfd | 单二进制，单技术栈，足够做配置工具 |
| 加密 KDF | PBKDF2（可调迭代） | 不用 Argon2id，避免 256MB 启动内存占用 |
| 架构支持 | 仅 x64 | 简化实现，覆盖绝大多数现代 Windows |
| 兼容性 | 开发期不考虑 | 要改直接改 |
| Stub 体积 | < 2MB 即可 | 硬盘不值钱，优先用 `opt-level=3` 换密码学性能 |
| 反调试/反 dump | 推迟，非 MVP | 大幅增加复杂度且触发 Defender 误报，先不做 |
| 复杂度优先简化 | 是 | 凡大幅增加复杂度的功能优先简化或推迟 |

**总原则**：能用简单方案就不上复杂方案。复杂度高的功能（反调试、反 dump、延迟导入表、scrypt 等）一律推迟到 MVP 之后，遇到实际需求再加。

---

## 4. Workspace 与 Crate 划分

### 4.1 目标结构

```
applocker/
├── Cargo.toml                    # workspace 根
├── docs/
│   ├── FORMAT.md                 # 文件格式规范
│   └── ARCHITECTURE.md           # 本文档
├── crates/
│   ├── exelock-crypto/           # 共享加密库（packer + stub 都用）
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── algorithm.rs      # CryptoAlgorithm trait + 注册表
│   │       ├── kdf.rs            # Kdf trait + PBKDF2 实现
│   │       ├── aes_gcm.rs        # AES-256-GCM
│   │       ├── chacha20.rs       # ChaCha20-Poly1305
│   │       ├── sm4.rs            # SM4-GCM（feature 控制）
│   │       └── zeroize.rs        # 密钥/明文清零封装
│   ├── exelock-pe/               # PE 解析与加载库
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── parser.rs         # PE 解析（基于 goblin）
│   │       ├── subsystem.rs      # 读取 Subsystem/Machine
│   │       ├── relocations.rs    # 基址重定位
│   │       ├── imports.rs        # 导入表/IAT
│   │       ├── tls.rs            # TLS 回调
│   │       └── loader.rs         # RunPE 内存加载核心
│   └── exelock-payload/          # Payload 编解码（封装 FORMAT.md）
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── header.rs         # 固定头 + 扩展区 TLV
│           ├── footer.rs         # Footer 定位
│           ├── writer.rs         # packer 侧：组装 payload
│           └── reader.rs         # stub 侧：解析 payload
├── packer/                       # GUI 加密工具
│   ├── Cargo.toml
│   ├── build.rs                  # 编译期嵌入 stub 模板
│   ├── stubs/                    # 预编译 stub 二进制（gitignored）
│   │   ├── stub_gui.exe
│   │   └── stub_console.exe
│   └── src/
│       ├── main.rs               # egui 入口
│       ├── app.rs                # GUI 状态与界面
│       ├── pack.rs               # 加密核心逻辑（lib 化，与 UI 解耦）
│       ├── strength.rs           # 加密强度预设映射
│       └── stub_selector.rs      # 根据 Subsystem 选 stub
├── stub/                         # 运行时壳
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs               # 入口
│       ├── payload.rs            # 调用 exelock-payload 解析自身
│       ├── password_ui.rs        # Win32 密码对话框
│       ├── runner.rs             # 调用 exelock-pe 执行 RunPE
│       └── erase.rs              # 擦除 payload（MVP feature）
│   # MVP 之后再加：
│   #   anti_debug.rs             # 反调试（推迟）
│   #   anti_dump.rs              # 反 dump（推迟）
└── tests/                        # 集成测试
    └── ...
```

### 4.2 依赖关系

```
                    ┌──────────────────┐
                    │  exelock-crypto  │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ↓              ↓              ↓
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │  packer  │   │   stub   │   │  tests   │
        │ (GUI)    │   │          │   └──────────┘
        └────┬─────┘   └────┬─────┘
             │              │
             ↓              ↓
        ┌──────────────┐  ┌──────────────┐
        │ exelock-pe   │  │ exelock-pe   │
        │ (parser)     │  │(parser+loader)│
        └──────┬───────┘  └──────┬───────┘
               │                 │
               ↓                 ↓
        ┌─────────────────────────────┐
        │     exelock-payload         │
        │  (writer: packer 侧用)      │
        │  (reader: stub 侧用)        │
        └─────────────────────────────┘
```

**设计原则**：
- `exelock-crypto / exelock-payload / exelock-pe` 是共享核心库，packer 与 stub 都依赖
- stub 通过 `features` 控制是否包含 `loader`（RunPE）模块；packer 只用 `parser`，减小体积
- 彻底消除 demo 中 packer 与 stub 各写一份 PBKDF2+AES 的重复

### 4.3 Cargo workspace 配置要点

```toml
# Cargo.toml (根)
[workspace]
members = ["crates/*", "packer", "stub"]
resolver = "2"

[workspace.dependencies]
# 共享依赖版本统一管理
aes-gcm = "0.10"
chacha20poly1305 = "0.10"
pbkdf2 = "0.12"
sha2 = "0.10"
rand = "0.8"
zeroize = { version = "1.7", features = ["derive"] }
goblin = "0.8"
crc32fast = "1.4"
anyhow = "1.0"
thiserror = "1.0"
eframe = "0.29"        # egui
rfd = "0.15"           # 原生文件对话框
windows = { version = "0.51", features = [ /* 完整 features */ ] }

[profile.release]
opt-level = 3           # 密码学库需要 AES-NI 内联优化，体积放宽到 < 2MB
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
```

> 既然 stub 体积放宽到 < 2MB，不再为 stub 单独用 `opt-level = "z"`。全局 3 保证 AES-GCM 的 AES-NI 内联优化，大文件加解密性能更好。若实际产物超 2MB 再针对性瘦身。

---

## 5. 各组件职责详解

### 5.1 `exelock-crypto`（共享加密库）

**职责**：定义算法/KDF 接口，提供具体实现，封装密钥清零。

**关键 trait**：

```rust
pub trait CryptoAlgorithm: Send + Sync {
    fn id(&self) -> u16;                          // algorithm_id（写入 header）
    fn name(&self) -> &'static str;
    fn nonce_len(&self) -> usize;
    fn tag_len(&self) -> usize;
    fn encrypt(&self, plaintext: &[u8], key: &[u8], nonce: &[u8], aad: Option<&[u8]>)
        -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], key: &[u8], nonce: &[u8], aad: Option<&[u8]>)
        -> Result<Vec<u8>>;
}

pub trait Kdf: Send + Sync {
    fn id(&self) -> u16;                          // kdf_id
    fn name(&self) -> &'static str;
    fn derive(&self, password: &[u8], salt: &[u8], iterations: u32)
        -> Result<Zeroizing<Vec<u8>>>;
}
```

**关键改进**（相对 demo）：
- `algorithm_id` 与 `kdf_id` 由实现自报，确保与 payload header 一致
- 密钥类型用 `Zeroizing<Vec<u8>>`，drop 时自动清零
- AAD 参数显式传递
- 接口 `Send + Sync`，GUI 可异步调用

**注册表**：

```rust
pub fn algorithm_by_id(id: u16) -> Option<Box<dyn CryptoAlgorithm>> {
    match id {
        0x0001 => Some(Box::new(Aes256Gcm)),
        0x0002 => Some(Box::new(ChaCha20Poly1305)),
        #[cfg(feature = "sm4")]
        0x0004 => Some(Box::new(Sm4Gcm)),
        _ => None,   // 未知 ID 返回 None，stub 拒绝执行
    }
}

pub fn kdf_by_id(id: u16) -> Option<Box<dyn Kdf>> {
    match id {
        0x0001 => Some(Box::new(Pbkdf2Sha256)),
        0x0002 => Some(Box::new(Pbkdf2Sha512)),
        _ => None,
    }
}
```

### 5.2 `exelock-pe`（PE 解析与加载）

**职责**：PE 文件解析（packer 用）+ 内存加载（stub 用），按 feature 分隔。

**`parser` 模块**（packer + stub 都用）：
- 读取 PE 头（DOS / NT / Optional Header）
- 提取 `Subsystem`、`Machine`、入口点、节区表
- 校验 PE 有效性
- 用于 packer 决定选哪个 stub、写入 `original_subsystem`
- 检测 .NET CLR header，若存在拒绝加密

**`loader` 模块**（仅 stub 用，feature = "loader"）：

RunPE 核心步骤：

```rust
pub fn run_pe_in_place(plaintext_pe: &[u8], command_line: &str) -> Result<u32> {
    // 1. 解析 PE 头，校验 MZ/PE 签名
    // 2. VirtualAlloc 分配内存（按 ImageSize，可执行）
    // 3. 复制 PE 头与各节区
    // 4. 处理基址重定位（若实际基址 != 期望基址）
    // 5. 处理导入表：LoadLibrary + GetProcAddress 填充 IAT
    // 6. 处理 TLS 回调（如有）
    // 7. 设置各节区内存页权限（RX / RW / R）
    // 8. 擦除自身 PE 头（反 dump，可选）
    // 9. 跳转到 OEP
    //    - 命令行参数通过 PEB 传递，需重写 GetCommandLineW
    // 10. 原程序运行至退出，返回 exit code
}
```

**关键技术难点与对策**：

| 难点 | 对策 | 优先级 |
|------|------|--------|
| 基址重定位 | 完整实现 `IMAGE_BASE_RELOCATION`，遍历所有块 | 必须 |
| 导入表（IAT） | 区分 bound/unbound，对每个 DLL 调 `LoadLibraryW` | 必须 |
| TLS 回调 | 必须在 OEP 前调用，否则含 TLS 的程序崩溃 | 必须 |
| SEH/异常处理表 | x64 需注册 `RUNTIME_FUNCTION`（`RtlAddFunctionTable`） | 必须 |
| 命令行参数 | 重写 PEB->ProcessParameters，或 hook `GetCommandLineW` | 必须 |
| ASLR | 若原 EXE 启用动态基址，尝试在任意基址加载（重定位） | 必须 |
| .NET 程序 | 检测 CLR header，packer 侧拒绝加密 | 必须 |
| 延迟导入表 | **先不实现**，遇到实际程序报错再补 | 推迟 |
| 反 dump / 擦除 PE 头 | **推迟**，非 MVP | 推迟 |

### 5.3 `exelock-payload`（Payload 编解码）

**职责**：封装 [FORMAT.md](./FORMAT.md) 定义的二进制格式。

**writer API**（packer 用）：

```rust
pub struct PayloadBuilder {
    header: PayloadHeader,
    extensions: Vec<Extension>,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl PayloadBuilder {
    pub fn new(algorithm_id: u16, kdf_id: u16, kdf_iterations: u32) -> Self;
    pub fn set_original_pe_info(&mut self, subsystem: u32, machine: u16, name: Option<&str>);
    pub fn set_plaintext_meta(&mut self, len: u64, crc32: u32);
    pub fn add_extension(&mut self, tag: u16, value: Vec<u8>);  // 用户自定义扩展
    pub fn set_flags(&mut self, flags: u32);
    pub fn build(self) -> Vec<u8>;  // 完整 payload（header+salt+nonce+cipher+footer）
}
```

**reader API**（stub 用）：

```rust
pub struct Payload {
    pub header: PayloadHeader,
    pub extensions: ExtensionMap,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Payload {
    pub fn from_file_tail(data: &[u8]) -> Result<Self>;  // 从完整 EXE 字节解析
    pub fn extension(&self, tag: u16) -> Option<&[u8]>;
}
```

### 5.4 `packer`（GUI 工具）

**职责**：读取原 EXE → 解析 PE 元数据 → 选择 stub → 加密 → 组装输出。

**GUI 界面**（egui + rfd）：

```
┌─────────────────────────────────────────────┐
│  EXELock                                    │
├─────────────────────────────────────────────┤
│  原 EXE: [app.exe          ] [浏览]        │
│  输出:   [app_locked.exe  ] [浏览]        │
│  密码:    [**************         ]        │
│  确认:    [**************         ]        │
│                                             │
│  加密强度: ( ) fast  (•) balanced          │
│            ( ) secure  ( ) 自定义           │
│                                             │
│  ▶ 高级选项                                 │
│    算法:    [AES-256-GCM            ▼]    │
│    KDF:     [PBKDF2-SHA256          ▼]    │
│    迭代:    [600000                 ]     │
│    Salt长度:[16                      ]     │
│    ☐ 启用 AAD                              │
│    ☑ 擦除 payload                          │
│    Stub:    [Auto                   ▼]    │
│    （反调试/反 dump：未来版本）             │
│                                             │
│  [进度条 ████████░░░░ 60%]                 │
│                                             │
│         [取消]  [加密]                      │
└─────────────────────────────────────────────┘
```

**关键交互逻辑**：
- 选 `fast/balanced/secure` 预设时，高级选项自动填充预设值但仍可编辑
- 用户编辑任意高级选项 → 自动切到 `custom`
- `浏览` 按钮用 rfd 弹原生文件对话框
- 加密过程在后台线程，通过 channel 更新进度条
- 加密完成后弹出 rfd 消息框提示成功/失败

**核心逻辑与 UI 解耦**：

```rust
// packer/src/pack.rs
pub struct PackOptions {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub password: String,
    pub algorithm_id: u16,
    pub kdf_id: u16,
    pub kdf_iterations: u32,
    pub salt_len: u16,
    pub use_aad: bool,
    pub erase_payload: bool,
    pub stub_preference: StubPreference,
    pub custom_extensions: Vec<(u16, Vec<u8>)>,  // 用户自定义 TLV 扩展
    // MVP 之后再加：anti_debug, anti_dump
}

pub fn pack(opts: &PackOptions, progress: impl FnMut(f32)) -> Result<()>;
```

`pack()` 是纯函数式核心逻辑，GUI 与未来可能加的 CLI 都调用它。

**stub 选择逻辑**（`stub_selector.rs`）：

```rust
pub fn select_stub(original_subsystem: u32, preference: StubPreference) -> &'static [u8] {
    let want_gui = match preference {
        StubPreference::Auto => original_subsystem == 2,  // 原 EXE 是 GUI
        StubPreference::Gui => true,
        StubPreference::Console => false,
    };
    if want_gui { STUB_GUI } else { STUB_CONSOLE }
}
```

两个 stub 二进制通过 `build.rs` + `include_bytes!` 嵌入 packer。

### 5.5 `stub`（运行时壳）

**职责**：解析自身 payload → 弹密码框 → 解密 → RunPE。

**入口流程**（伪代码）：

```rust
fn main() -> u32 {
    let own_bytes = read_self_exe();
    let payload = Payload::from_file_tail(&own_bytes)?;

    // 弹密码框（Win32 DialogBox，非控制台）
    let password = password_ui::prompt()?;
    let pwd = Zeroizing::new(password.into_bytes());

    // KDF 派生密钥
    let kdf = kdf_by_id(payload.header.kdf_id)?;
    let key = kdf.derive(&pwd, &payload.salt, payload.header.kdf_iterations)?;

    // AEAD 解密
    let algo = algorithm_by_id(payload.header.algorithm_id)?;
    let aad = if payload.header.flags & FLAG_USE_AAD != 0 {
        Some(payload.extension(EXT_AAD).unwrap_or(&[]))
    } else { None };
    let plaintext_pe = algo.decrypt(&payload.ciphertext, &key, &payload.nonce, aad)?;
    drop(key);  // 立即 drop 触发 zeroize

    // 二次校验
    verify_plaintext(&plaintext_pe, &payload.header)?;

    // 擦除 payload 区（可选，feature 控制）
    #[cfg(feature = "erase-payload")]
    erase::payload_in_memory(&own_bytes);

    // RunPE 内存加载
    let command_line = std::env::args().collect::<Vec<_>>().join(" ");
    let exit_code = run_pe_in_place(&plaintext_pe, &command_line)?;

    // 清零明文 PE
    drop(Zeroizing::new(plaintext_pe));
    exit_code
}
```

> 反调试与反 dump 模块推迟到 MVP 之后，MVP 阶段 stub 不含这些 feature。

**stub 子系统的编译期切换**：

通过两个 bin target 共用同一份 `src/main.rs`，`build.rs` 根据 `CARGO_BIN_NAME` 注入 `#![windows_subsystem = "windows"]`：

```toml
# stub/Cargo.toml
[[bin]]
name = "stub_gui"
path = "src/main.rs"

[[bin]]
name = "stub_console"
path = "src/main.rs"
```

---

## 6. RunPE 内存加载核心设计

### 6.1 进程模型选择

**决策：stub 自身进程内加载**（不用 Process Hollowing）

| 方案 | 优点 | 缺点 |
|------|------|------|
| **A. 同进程加载（采用）** | 无子进程；无 hollowing 痕迹；Defender 误报略低 | stub 自身的栈/堆/线程仍存在，需小心清理 |
| B. Process Hollowing | 进程映像名可控；隔离性好 | hollowing 是经典恶意行为，Defender 高误报 |

选择 A 的原因：
1. Defender 对 Process Hollowing 检测极敏感（ETW + 内存扫描）
2. 同进程加载更接近"正常 loader"行为
3. 子进程方案仍需解决 stub 自身资源回收，复杂度并不低

### 6.2 同进程加载的清理工作

stub 在跳转到 OEP 前的清理（按优先级）：

| 步骤 | 优先级 | 说明 |
|------|--------|------|
| 重写 `GetCommandLineW` 返回值 | 必须 | 让原程序看到正确命令行 |
| 修改 PEB 的 `ImageBasePath` | 必须 | 用 `EXT_ORIGINAL_NAME`，任务管理器显示原程序名 |
| 擦除 payload 区 | 可选 | `FLAG_ERASE_PAYLOAD`，简单实现 |
| 擦除 stub 自身 PE 头 | 推迟 | 反 dump，MVP 不做 |
| 擦除 stub 自身栈/堆痕迹 | 推迟 | 复杂度高，MVP 不做 |

### 6.3 GUI EXE 的特殊处理

参见 [FORMAT.md §4](./FORMAT.md#4-win-gui-exe-支持策略)。核心要点：

- packer 读取原 EXE 的 `Subsystem`，写入 `original_subsystem`
- 若原 EXE 是 GUI，packer 选 `stub_gui.exe`（windows 子系统），避免控制台闪烁
- stub 跳转到 OEP 后，原 EXE 自身的 manifest / DPI 感知 / 窗口创建逻辑接管，stub 不干预
- 密码对话框用 `DialogBoxIndirectParam` 自绘，不依赖任何外部资源

### 6.4 已知不支持的程序类型

1. **.NET 托管程序**（含 CLR header）：RunPE 后无法初始化 CLR。packer 检测到时拒绝加密并明确提示
2. **packed EXE**（已被 UPX/Themida 等加壳）：双层壳易崩，packer 检测并警告
3. **驱动程序**（.sys）：内核态加载完全不同
4. **UWP/Store 应用**：打包格式不同

packer 在加密前做这些检查，给出明确警告或拒绝。

---

## 7. 加密强度切换机制

### 7.1 预设表（packer 内部常量）

```rust
pub struct StrengthPreset {
    pub name: &'static str,
    pub algorithm_id: u16,
    pub kdf_id: u16,
    pub kdf_iterations: u32,
    pub use_aad: bool,
    pub erase_payload: bool,
    // MVP 之后再加：anti_debug, anti_dump
}

pub const PRESETS: &[StrengthPreset] = &[
    StrengthPreset {
        name: "fast",
        algorithm_id: 0x0001,  // AES-256-GCM
        kdf_id: 0x0001,        // PBKDF2-SHA256
        kdf_iterations: 100_000,
        use_aad: false,
        erase_payload: false,
    },
    StrengthPreset {
        name: "balanced",
        algorithm_id: 0x0001,
        kdf_id: 0x0001,
        kdf_iterations: 600_000,  // OWASP 2023 推荐
        use_aad: true,
        erase_payload: true,
    },
    StrengthPreset {
        name: "secure",
        algorithm_id: 0x0002,  // ChaCha20-Poly1305
        kdf_id: 0x0002,        // PBKDF2-SHA512
        kdf_iterations: 2_000_000,
        use_aad: true,
        erase_payload: true,
    },
];
```

### 7.2 参数覆盖优先级

```
GUI 高级选项的显式值 > 预设默认值
```

用户在 GUI 中改任意高级选项 → 自动切到 `custom`，完全使用用户值。

### 7.3 预设不写入 payload

预设本身只是 packer 的便利封装，最终写入 payload 的是**实际生效的字段值**（`algorithm_id / kdf_id / kdf_iterations / flags`）。stub 完全不感知"预设"概念，只按字段执行。这保证 stub 简单稳定。

### 7.4 用户自定义参数的扩展性

GUI 暴露给用户的加密参数**全部对应 payload 字段**：

| GUI 选项 | payload 字段 | MVP |
|---------|-------------|-----|
| 算法 | `algorithm_id` | ✅ |
| KDF | `kdf_id` | ✅ |
| 迭代次数 | `kdf_iterations` | ✅ |
| Salt 长度 | `salt_len` | ✅ |
| 启用 AAD | `FLAG_USE_AAD` + `EXT_AAD` | ✅ |
| 擦除 payload | `FLAG_ERASE_PAYLOAD` | ✅ |
| 自定义扩展 | `EXT_*`（TLV 扩展区） | ✅ |
| 反调试 | `FLAG_ANTI_DEBUG` | 推迟 |
| 反 dump | `FLAG_ANTI_DUMP` | 推迟 |

用户改参数 = 直接改 header 字段，无需额外存储机制。未来要加新参数（如 scrypt cost）走 `EXT_KDF_EXTRA` 扩展区，不破坏格式。

---

## 8. 扩展性设计

### 8.1 三层扩展点

| 层级 | 扩展点 | 扩展方式 | 示例 |
|------|--------|---------|------|
| 算法 | `CryptoAlgorithm` trait | 实现 trait + 注册到 `algorithm_by_id` | 新增 SM4、Camellia |
| KDF | `Kdf` trait | 实现 trait + 注册到 `kdf_by_id` | 新增 scrypt、bcrypt |
| Payload 元数据 | 扩展区 TLV（`EXT_*`） | packer 写入，stub 跳过未知 tag | 新增 `EXT_PADDING`、`EXT_LICENSE` |

### 8.2 Feature flag 控制 stub 能力

MVP 阶段 stub 尽量精简，反调试/反 dump 等高复杂度功能用 feature 控制，默认关闭：

```toml
# stub/Cargo.toml
[features]
default = ["erase-payload"]
erase-payload = []                # MVP：擦除 payload 区，简单
sm4 = ["exelock-crypto/sm4"]      # 可选算法
# 以下为 MVP 之后的功能，默认不启用
anti-debug = []                   # 推迟：反调试
anti-dump = []                    # 推迟：擦除 PE 头等
```

MVP 阶段只构建一个 stub（含 `erase-payload`），不再为不同预设打包不同 stub。等真正需要瘦身时再分变体。

### 8.3 算法注册表的演进

新增算法的流程：

1. 在 `exelock-crypto` 实现新算法（如 `Sm4Gcm`）
2. 在 [FORMAT.md §6](./FORMAT.md#6-算法注册表algorithm_id) 注册表分配新 ID
3. 在 `algorithm_by_id` 添加 match 分支（用 feature 控制）
4. 旧 stub 遇到新 ID 拒绝执行并提示"需升级 stub"，不会崩溃

---

## 9. 构建与发布

### 9.1 构建 stub 模板

packer 需要预编译两个 stub 二进制（gui / console）并嵌入：

```bash
# build-stubs.ps1
cargo build --release -p stub --bin stub_gui
cargo build --release -p stub --bin stub_console
copy target\release\stub_gui.exe    packer\stubs\
copy target\release\stub_console.exe packer\stubs\
```

packer 的 `build.rs` 检查 `stubs/` 目录并 `include_bytes!`：

```rust
// packer/build.rs
fn main() {
    println!("cargo:rerun-if-changed=stubs/stub_gui.exe");
    println!("cargo:rerun-if-changed=stubs/stub_console.exe");
    // 若文件缺失，触发警告提示运行 build-stubs.ps1
}
```

### 9.2 构建 packer

```bash
cargo build --release -p packer
# 产物：target/release/exelock.exe（已内嵌两个 stub 模板）
```

### 9.3 发布物

- `exelock.exe`（packer GUI，含两个 stub 模板，约 3-5MB）
- 用户只需这一个文件即可加密任意 x64 EXE
- stub 体积放宽到 < 2MB，packer 体积无硬性限制

### 9.4 Defender 误报应对

RunPE 行为模式与恶意软件相似，可能触发 Defender 启发式查杀。应对：

1. **代码签名**：生产发布建议代码签名，显著降低误报
2. **白名单提交**：向 Microsoft Defender 提交白名单
3. **文档告知**：README 显著位置提示用户可能误报
4. **签名 manifest**：packer 与 stub 都加 application manifest（UAC、DPI 感知）

---

## 10. .NET 程序的处理策略

.NET 程序（C#/VB.NET 编译的 EXE）含 CLR header，RunPE 后无法初始化 CLR，会崩溃。

**处理**：
1. packer 解析 PE，检查 `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` 是否非空
2. 若检测到 .NET，packer **拒绝加密**并明确提示"暂不支持 .NET 程序"
3. 不做半成品方案（如降级到临时文件），避免"加密成功但运行崩溃"的糟糕体验

未来若要支持，需要单独的 .NET stub（基于 Assembly.Load），作为独立 feature，不在当前范围。

---

## 11. 安全考虑

### 11.1 威胁模型

| 威胁 | 防护能力 | 说明 |
|------|---------|------|
| 普通用户无密码运行 | ✅ 阻止 | 密码错误无法解密 |
| 离线爆破密码 | ⚠️ 取决于强度 | PBKDF2 迭代次数可调，密码强度本身是关键 |
| 运行期复制明文 EXE | ✅ 阻止 | 全程内存，无临时文件 |
| 内存 dump 获取明文 | ❌ MVP 不防 | 反 dump 推迟，专业工具可 dump |
| 调试器附加分析 | ❌ MVP 不防 | 反调试推迟 |
| 杀软误报 | ⚠️ 持续对抗 | RunPE 行为启发式触发，需签名 + 白名单（未来） |

### 11.2 安全增强清单

**MVP 阶段**：
- [x] 密钥用 `Zeroizing` 包裹，drop 自动清零
- [x] 明文 PE 解密后用 `Zeroizing<Vec<u8>>`，运行结束清零
- [x] PBKDF2 默认 600k 迭代（balanced 预设）
- [x] AEAD AAD 绑定 header 关键字段
- [x] 擦除 payload 区（feature 控制）
- [x] 密码对话框用 Win32（非控制台），无明文回显

**推迟到 MVP 之后**：
- [ ] 反调试模块（feature 控制）
- [ ] 反 dump：擦除 stub 自身 PE 头
- [ ] 密码错误次数限制 + 指数退避
- [ ] 代码签名

### 11.3 已知无法解决的问题

- **内存 dump**：管理员权限 + 进程内存 dump 工具可提取明文 PE。这是 RunPE 方案的固有局限，反 dump 只能提高门槛
- **Defender 误报**：RunPE 行为模式与恶意软件高度相似，需长期对抗
- **调试器分析**：MVP 无反调试，专业逆向可直接附加

---

## 12. 测试策略

### 12.1 单元测试

| 模块 | 测试重点 |
|------|---------|
| `exelock-crypto` | 各算法 round-trip、错误密钥失败、AAD 篡改失败、nonce 长度边界 |
| `exelock-crypto/kdf` | PBKDF2 各迭代次数、不同 salt 长度 |
| `exelock-payload` | writer/reader round-trip、footer 反向定位、TLV 扩展区解析、未知 tag 跳过 |
| `exelock-pe/parser` | 解析 GUI/Console PE、损坏 PE 拒绝、.NET 检测 |
| `exelock-pe/loader` | 加载简单 PE 后入口点正确执行 |

### 12.2 集成测试

- **端到端**：packer 加密 → 运行 locked.exe → 输入密码 → 原 EXE 正常运行 → 退出码正确
- **GUI 子系统**：加密 notepad.exe，运行后窗口正常出现，无控制台闪烁
- **Console 子系统**：加密 ping.exe，运行后输出正常
- **命令行透传**：加密后传入参数，原 EXE 收到正确参数
- **错误密码**：输入错误密码，stub 拒绝运行
- **强度切换**：fast/balanced/secure 三档都能正确加解密
- **算法切换**：AES / ChaCha20 都能正确加解密
- **AAD 启用/禁用**：两种模式都能正确加解密，AAD 模式下篡改 header 失败
- **自定义参数**：GUI 中改迭代次数等，生成的 payload header 字段同步变化

### 12.3 兼容性测试矩阵

| 原 EXE 类型 | 测试用例 | 期望 |
|-----------|---------|------|
| Win32 GUI x64 | notepad.exe, calc.exe | ✅ |
| Win32 Console x64 | ping.exe | ✅ |
| 含 TLS 回调 | 部分游戏/保护软件 | ✅ 必须支持 |
| .NET x64 | 任意 C# EXE | ❌ packer 拒绝并提示 |
| 已加壳 | UPX 压缩的 EXE | ⚠️ 警告但允许 |
| 大文件 | > 100MB EXE | ✅ 内存够即可 |

---

## 13. 实施路线图

按"复杂度优先简化"原则，先做 MVP（能加密 + 能运行），再加增强功能。

### 13.1 MVP 阶段（必须完成才能发布）

| 阶段 | 内容 | 依赖 |
|------|------|------|
| **alpha1** | `exelock-crypto`（trait + 注册表 + zeroize + PBKDF2/AES/ChaCha20） | FORMAT.md 定稿 |
| **alpha2** | `exelock-payload`（writer + reader + footer + TLV 扩展区） | alpha1 |
| **alpha3** | `exelock-pe/parser`（PE 解析、子系统提取、.NET 检测） | — |
| **alpha4** | `packer` GUI 基础（egui 界面 + 加密流程，不含 RunPE） | alpha1-3 |
| **beta1** | `exelock-pe/loader`（RunPE 核心实现，必须项见 §5.2 难点表） | alpha3 |
| **beta2** | `stub`（payload 解析 + 密码对话框 + RunPE 调用 + erase-payload） | alpha2, beta1 |
| **rc1** | 集成测试 + 兼容性矩阵验证 | beta2 |
| **release** | MVP 正式发布 | rc1 |

### 13.2 MVP 之后（按需推进，非必须）

| 功能 | 触发条件 |
|------|---------|
| 反调试模块 | 实际遇到逆向分析需求 |
| 反 dump（擦除 PE 头） | 实际遇到 dump 攻击 |
| 密码错误次数限制 + 退避 | 实际遇到暴力试密码 |
| 延迟导入表支持 | 实际遇到程序加载失败 |
| 代码签名 | 用户反馈 Defender 误报严重 |
| CLI 入口 | 有 CI 批量加密需求 |
| Stub 体积瘦身 | 实际产物 > 2MB 再做 |

每阶段完成后更新本文档与 FORMAT.md。

---

## 14. 开放问题

已基本收敛，剩余小问题留待实现时决定：

1. **擦除 payload 的具体实现**：是用 `SecureZeroMemory` 还是 `volatile write`？实现时选简单的
2. **密码对话框样式**：用 `DialogBoxIndirectParam` 自绘还是更简单的 `MessageBox` + 自定义钩子？实现时优先选简单方案
3. **stub 双变体（gui/console）的构建脚本**：用 `build.rs` 注入 `windows_subsystem` 还是用两个 `[[bin]]` + cfg？实现时验证哪种更顺

复杂度优先简化原则：遇到拿不准的设计，先选最简单可行的方案，跑通再优化。

---

## 附录 A：术语表

| 术语 | 含义 |
|------|------|
| stub | 运行时壳，负责解密并加载原 EXE |
| packer | 加密工具（GUI），生成受保护 EXE |
| payload | 加密后的原 EXE 数据 + 元数据，附加在 stub 末尾 |
| RunPE | 在内存中手动加载 PE 文件并执行，不落地磁盘 |
| OEP | Original Entry Point，原 EXE 的入口点 |
| IAT | Import Address Table，导入地址表 |
| KDF | Key Derivation Function，密钥派生函数 |
| AEAD | Authenticated Encryption with Associated Data |
| AAD | Additional Authenticated Data，AEAD 的附加认证数据 |
| TLS | Thread Local Storage，线程本地存储（PE 中的 TLS 回调） |
| Hollowing | Process Hollowing，进程镂空技术（本项目不采用） |
| Subsystem | PE 头中的子系统字段，区分 GUI/Console |
| rfd | Rusty File Dialogs，Rust 的原生文件对话框库 |
| egui | Rust 的即时模式 GUI 库 |
