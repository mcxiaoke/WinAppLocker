using System;
using System.Runtime.InteropServices;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// 用于把原 EXE 的图标/版本资源复制到 stub 输出 exe 的 Win32 API。
    /// 走 BeginUpdateResource / UpdateResource / EndUpdateResource 路径。
    /// </summary>
    internal static class NativeMethods
    {
        public const uint DONT_RESOLVE_DLL_REFERENCES = 0x00000001;
        public const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
        public const uint LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020;

        public const uint RT_ICON = 3;
        public const uint RT_GROUP_ICON = 14;
        public const uint RT_VERSION = 16;
        public const uint RT_MANIFEST = 24;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr FindResourceW(IntPtr hModule, IntPtr lpName, uint lpType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LockResource(IntPtr hResData);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool EnumResourceNamesW(IntPtr hModule, uint lpType,
            EnumResNameDelegate lpEnumFunc, IntPtr lParam);

        public delegate bool EnumResNameDelegate(IntPtr hModule, uint lpType, IntPtr lpName, IntPtr lParam);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr BeginUpdateResource(string pFileName, bool bDeleteExistingResources);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool UpdateResourceW(IntPtr hUpdate, uint lpType, IntPtr lpName,
            ushort wLanguage, IntPtr lpData, uint cbData);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool EndUpdateResource(IntPtr hUpdate, bool fDiscard);
    }
}
