# 实现指南与进阶路线

## 一、方案选型建议

根据你的需求，我推荐分三个阶段实现：

### 阶段一：入门版（当前代码）- 封装器+临时文件执行
**实现难度：⭐⭐ | 开发时间：1-2天**
- ✅ 优点：实现简单、兼容性100%、不破坏原EXE结构
- ❌ 缺点：运行时临时文件可能被提取
- 适用场景：个人使用、内部工具、快速验证

### 阶段二：进阶版 - 封装器+纯内存执行(RunPE)
**实现难度：⭐⭐⭐⭐ | 开发时间：1-2周**
- ✅ 优点：全程内存执行、不落地磁盘、安全性高
- ❌ 缺点：需要完整实现PE加载器、兼容性问题
- 适用场景：商业软件、需要较高安全性

### 阶段三：专业版 - 真正PE加壳
**实现难度：⭐⭐⭐⭐⭐ | 开发时间：1-2月**
- ✅ 优点：安全性最高、难以脱壳、无额外进程
- ❌ 缺点：实现复杂、容易触发杀软、兼容性问题多
- 适用场景：专业软件保护产品

---

## 二、编程语言详细对比

| 维度 | Rust | C++ | C# | Python |
|------|------|-----|----|--------|
| 编译后体积 | ~100KB | ~50KB | ~10MB+需要.NET | ~50MB+ |
| 运行时依赖 | 无 | 无 | 需要.NET | 需要Python环境 |
| 内存安全 | ✅ 编译期保证 | ❌ 容易出问题 | ✅ GC管理 | ✅ GC管理 |
| 逆向难度 | 高 | 高 | 低(易反编译) | 极低 |
| Windows API支持 | ✅ windows crate | ✅ 原生 | ✅ P/Invoke | ⚠️ ctypes |
| 密码学库 | ✅ RustCrypto成熟 | ✅ OpenSSL/BCrypt | ✅ .NET内置 | ✅ pycryptodome |
| 开发效率 | 较高 | 低 | 高 | 最高 |
| 性能 | 接近C++ | 最高 | 中等 | 低 |
| **推荐指数** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ | ⭐ |

**结论：优先选择Rust，次选C++。**

---

## 三、核心技术要点详解

### 3.1 为什么选择AES-256-GCM？
- **认证加密**：不仅加密，还能校验完整性，防止篡改
- **性能优秀**：AES-NI硬件加速，加解密速度极快
- **行业标准**：NIST标准，经过充分密码学分析
- **避免ECB/CBC缺陷**：不需要自己处理填充和MAC

### 3.2 为什么用PBKDF2派生密钥？
- 不要直接用密码做密钥！
- PBKDF2通过多次迭代增加暴力破解难度
- 随机盐防止彩虹表攻击
- 迭代次数建议：10万~100万次（平衡速度和安全性）

### 3.3 RunPE内存加载核心步骤
```
1. 验证PE头(MZ/PE签名)
2. 解析NT头、节表
3. VirtualAlloc分配内存
4. 复制PE头和各个节区
5. 处理重定位表(基址重定位)
6. 处理导入表(加载DLL、填充IAT)
7. 处理TLS回调
8. 设置内存页权限
9. 跳转到OEP(原始入口点)执行
```

---

## 四、进阶安全增强

### 4.1 反调试技术
```rust
// 1. IsDebuggerPresent API检测
if unsafe { IsDebuggerPresent() }.as_bool() { std::process::exit(1); }

// 2. NtQueryInformationProcess检测
// 3. 检查远程调试端口
// 4. 时间差检测（单步执行会变慢）
// 5. INT 2D 反调试
// 6. 硬件断点检测
```

### 4.2 反Dump技术
- 运行时擦除PE头
- 动态加解密代码页（执行完加密回去）
- 内存页权限动态切换
- Hook NtQueryVirtualMemory

### 4.3 反虚拟机/沙箱
- 检查CPU特征数
- 检查内存大小
- 检查MAC地址厂商
- 检查运行时间
- 检查常见虚拟机进程/文件

### 4.4 密码输入增强
- 不要用简单的控制台输入
- 创建自定义密码对话框
- 输入时禁用截屏
- 密码框使用SecureString
- 增加密码错误次数限制和延迟

---

## 五、常见坑点和注意事项

### 5.1 杀软误报问题
这是加壳工具的通病！
- 内存执行、修改内存权限等行为会被启发式查杀
- 建议：
  1. 加数字签名
  2. 提交杀软白名单
  3. 不要使用过于激进的反调试
  4. 临时文件方案误报率远低于RunPE

### 5.2 兼容性问题
- 32位/64位必须匹配：不能加密64位EXE用32位Stub加载
- C++异常处理需要正确设置
- .NET程序不能用原生PE加载器，需要特殊处理
- 有TLS回调的程序需要特殊处理
- 启用了ASLR的程序需要正确处理重定位

### 5.3 法律和合规
- 此技术仅用于保护你自己拥有版权的软件
- 不要用于恶意软件或绕过授权
- 加密后的程序不要包含恶意代码

---

## 六、编译和使用步骤

```bash
# 1. 安装Rust (https://rustup.rs)
# 选择x86_64-pc-windows-msvc工具链

# 2. 编译Stub（先编译stub！）
cd stub
cargo build --release
# 生成的文件在 target/release/stub.exe

# 3. 复制stub.exe到packer目录
copy target/release/stub.exe ../packer/

# 4. 编译Packer
cd ../packer
cargo build --release
# 生成的文件在 target/release/exe-lock.exe

# 5. 加密你的EXE
exe-lock.exe pack -i your_app.exe -p your_password -o your_app_locked.exe
```

---

## 七、参考资源

### PE格式学习
- PE Format官方文档: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- 《加密与解密》(第4版) - 段钢
- 看雪学院: https://www.kanxue.com

### Rust Windows开发
- windows-rs: https://github.com/microsoft/windows-rs
- Rust PE操作库: `pelite`, `portex`, `goblin`

### 开源加壳项目参考
- UPX: https://github.com/upx/upx (最著名的开源压缩壳)
- VMProtect: 商业保护壳标杆
- Themida: 商业级虚拟化保护
