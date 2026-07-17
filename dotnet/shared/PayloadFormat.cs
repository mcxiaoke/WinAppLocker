// Payload 二进制格式常量
// 所有多字节整数使用小端序
namespace WinAppLocker.Shared
{
    /// <summary>
    /// payload 头部 + 尾部 + 算法 ID 等常量。
    /// stub 与 packer 共享此定义，但不共享其它代码。
    /// </summary>
    public static class PayloadFormat
    {
        // ---- Magic ----
        public const string HeaderMagicStr = "WALOCK\x01\x00";
        public static readonly byte[] HeaderMagic = new byte[]
        {
            (byte)'W', (byte)'A', (byte)'L', (byte)'O',
            (byte)'C', (byte)'K', 0x01, 0x00
        };

        public const string FooterMagicAStr = "WALEND\xAA\xAA";
        public const string FooterMagicBStr = "WALEND\xBB\xBB";
        public static readonly byte[] FooterMagicA = new byte[]
        {
            (byte)'W', (byte)'A', (byte)'L', (byte)'E',
            (byte)'N', (byte)'D', 0xAA, 0xAA
        };
        public static readonly byte[] FooterMagicB = new byte[]
        {
            (byte)'W', (byte)'A', (byte)'L', (byte)'E',
            (byte)'N', (byte)'D', 0xBB, 0xBB
        };

        // ---- Sizes ----
        public const int HeaderSize = 64;
        public const int FooterSize = 32;

        // ---- Versions ----
        public const ushort PayloadVersion = 1;

        // ---- Algorithm IDs ----
        public const ushort AlgoAes256Gcm = 1;          // 预留，未使用
        public const ushort AlgoAes256CbcHmacSha256 = 2; // 当前实现

        // ---- KDF IDs ----
        public const ushort KdfPbkdf2Sha256 = 1;

        // ---- Flags ----
        public const uint FlagUseAad = 0x01;       // 预留
        public const uint FlagEraseTemp = 0x02;    // 预留
        public const uint FlagHasExtensions = 0x04; // 有 Extension TLV 区域

        // ---- Extension TLV Tags ----
        // 设计文档定义的扩展区，放在 Ciphertext 之后、Footer 之前
        // 每个条目：tag[2] len[2] value[len]
        public const ushort ExtTagOriginalName = 1;    // 原始 EXE 文件名（UTF-8，不含路径）
        public const ushort ExtTagPackerVersion = 2;    // 打包器版本签名（UTF-8，如 "WinAppLocker v0.1.0"）
        public const ushort ExtTagOriginalSize = 3;     // 原始文件大小（u64，与 PlaintextLen 冗余但可用于校验）

        // ---- 默认参数 ----
        // PBKDF2-HMAC-SHA256 迭代次数：OWASP 2023 推荐下限约 250K-600K
        // 200K 在现代 CPU 上约 600ms，兼顾安全与启动速度
        public const int DefaultKdfIterations = 200_000;
        public const int DefaultSaltLen = 16;
        public const int AesCbcIvLen = 16;          // AES-CBC IV 长度
        public const int HmacSha256TagLen = 32;     // HMAC-SHA256 输出长度
        public const int AesKeyLen = 32;            // AES-256 密钥长度
        public const int AesBlockSize = 16;        // AES 块大小

        // ---- 版本标记（packer 搜索 stub 字节中的 UTF-16 编码）----
        public const string VersionBlobStart = "WAL_VER|";
        public const string VersionBlobEnd = "|WAL_END";
    }
}
