using System;
using AsmResolver.PE;
using AsmResolver.PE.File;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// 原 EXE 信息：子系统 / 机器类型 / 是否 .NET。
    /// </summary>
    internal sealed class PeInfo
    {
        public ushort Subsystem;
        public ushort Machine;
        public bool IsDotNet;
        public bool IsGui => Subsystem == (ushort)SubSystem.WindowsGui;
    }

    /// <summary>
    /// stub 选择偏好（按子系统）。
    /// Auto = 根据 PE 子系统自动选择；Gui/Console = 强制；Test = 测试 stub（内置密码）。
    /// 注意：与 StubManifest.StubKind（加壳方案）不同，此处仅表示子系统偏好。
    /// </summary>
    public enum StubPreference
    {
        Auto = 0,
        Gui = 1,
        Console = 2,
        Test = 3
    }

    /// <summary>
    /// PE 解析：使用 AsmResolver.PE 6.0 提取子系统、机器类型、检测 .NET 托管。
    /// </summary>
    internal static class PeReader
    {
        public static PeInfo Parse(byte[] peBytes)
        {
            var peFile = PEFile.FromBytes(peBytes);
            var peImage = PEImage.FromFile(peFile);

            var info = new PeInfo
            {
                Subsystem = (ushort)peFile.OptionalHeader.SubSystem,
                Machine = (ushort)peFile.FileHeader.Machine,
                IsDotNet = peImage.DotNetDirectory != null
            };
            return info;
        }
    }
}
