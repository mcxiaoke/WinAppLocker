using System;
using System.IO;
using WinAppLocker.Packer;
using Xunit;

namespace WinAppLocker.Packer.Tests
{
    /// <summary>
    /// PeReader 测试：依赖 temp/samples 目录下的 PE 样本。
    /// 样本由项目根 temp/samples/ 提供。
    /// </summary>
    public class PeReaderTests
    {
        // 测试样本根目录：项目根/temp/samples
        private static readonly string SamplesDir = FindSamplesDir();

        private static string FindSamplesDir()
        {
            // 测试运行目录在 dotnet/tests/WinAppLocker.Packer.Tests/bin/Debug/net472/
            // 向上 5 层到项目根，再进 temp/samples
            string dir = AppDomain.CurrentDomain.BaseDirectory;
            for (int i = 0; i < 8; i++)
            {
                string candidate = Path.Combine(dir, "temp", "samples");
                if (Directory.Exists(candidate)) return candidate;
                dir = Path.GetFullPath(Path.Combine(dir, ".."));
            }
            return null;
        }

        private static byte[] ReadSample(string name)
        {
            if (SamplesDir == null) return null;
            string path = Path.Combine(SamplesDir, name);
            return File.Exists(path) ? File.ReadAllBytes(path) : null;
        }

        // 仅当样本存在时才执行，否则跳过
        private static byte[] RequireSample(string name)
        {
            byte[] data = ReadSample(name);
            if (data == null)
                Assert.Fail($"测试样本缺失: temp/samples/{name}");
            return data;
        }

        [Fact]
        public void Parse_X64Gui()
        {
            byte[] pe = RequireSample("helloguix64.exe");
            var info = PeReader.Parse(pe);
            Assert.Equal(0x8664, info.Machine);
            Assert.Equal(2, info.Subsystem);
            Assert.True(info.IsGui);
            Assert.False(info.IsDotNet);
        }

        [Fact]
        public void Parse_X86Gui()
        {
            byte[] pe = RequireSample("helloguix86.exe");
            var info = PeReader.Parse(pe);
            Assert.Equal(0x014c, info.Machine);
            Assert.Equal(2, info.Subsystem);
            Assert.True(info.IsGui);
        }

        [Fact]
        public void Parse_X64Console()
        {
            byte[] pe = RequireSample("helloclivsx64.exe");
            var info = PeReader.Parse(pe);
            Assert.Equal(0x8664, info.Machine);
            Assert.Equal(3, info.Subsystem);
            Assert.False(info.IsGui);
        }

        [Fact]
        public void Parse_X86Console()
        {
            byte[] pe = RequireSample("helloclivsx86.exe");
            var info = PeReader.Parse(pe);
            Assert.Equal(0x014c, info.Machine);
            Assert.Equal(3, info.Subsystem);
            Assert.False(info.IsGui);
        }

        [Fact]
        public void Parse_DotNetAssembly()
        {
            // hellowinforms.exe 是 .NET WinForms 程序
            byte[] pe = RequireSample("hellowinforms.exe");
            var info = PeReader.Parse(pe);
            Assert.True(info.IsDotNet);
            Assert.True(info.IsGui);  // WinForms 子系统是 GUI
        }

        [Fact]
        public void Parse_MachineName()
        {
            byte[] pe64 = RequireSample("helloguix64.exe");
            Assert.Equal("x64", PeReader.Parse(pe64).MachineName);

            byte[] pe86 = RequireSample("helloguix86.exe");
            Assert.Equal("x86", PeReader.Parse(pe86).MachineName);
        }

        [Fact]
        public void Parse_SubsystemName()
        {
            byte[] pe = RequireSample("helloguix64.exe");
            Assert.Equal("GUI", PeReader.Parse(pe).SubsystemName);

            byte[] peConsole = RequireSample("helloclivsx64.exe");
            Assert.Equal("Console", PeReader.Parse(peConsole).SubsystemName);
        }

        [Fact]
        public void Parse_FileSize()
        {
            byte[] pe = RequireSample("helloguix64.exe");
            var info = PeReader.Parse(pe);
            Assert.Equal(pe.Length, info.FileSize);
        }

        [Fact]
        public void Parse_NotChromium_RegularSample()
        {
            // 普通样本不是 Chromium 系
            byte[] pe = RequireSample("helloguix64.exe");
            var info = PeReader.Parse(pe);
            Assert.False(info.IsChromiumLike);
        }

        [Fact]
        public void Parse_Notepad4_NotChromium()
        {
            byte[] pe = RequireSample("Notepad4.exe");
            if (pe == null) return;
            var info = PeReader.Parse(pe);
            Assert.False(info.IsChromiumLike);
            Assert.True(info.IsGui);
            Assert.Equal("x64", info.MachineName);
        }

        [Fact]
        public void Parse_AsOrDep_UsuallyTrueForModernExe()
        {
            // 现代编译器默认开 ASLR/DEP
            byte[] pe = RequireSample("helloguix64.exe");
            var info = PeReader.Parse(pe);
            Assert.True(info.IsAslr, "现代 EXE 应开 ASLR");
            Assert.True(info.IsDep, "现代 EXE 应开 DEP");
        }

        [Fact]
        public void Parse_HasReloc_ForDynamicBase()
        {
            // 开了 ASLR 的 EXE 通常有 .reloc
            byte[] pe = RequireSample("helloguix64.exe");
            var info = PeReader.Parse(pe);
            if (info.IsAslr)
                Assert.True(info.HasReloc, "ASLR EXE 应有 .reloc");
        }
    }
}
