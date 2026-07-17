param([string]$exe = "C:\Home\Apps\Doubao\app\doubao.exe")

$src = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class ResEnum {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool FreeLibrary(IntPtr hModule);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool EnumResourceNamesW(IntPtr hModule, uint lpcType, EnumResNameProc lpEnumFunc, IntPtr lParam);
    delegate bool EnumResNameProc(IntPtr hModule, IntPtr lpcType, IntPtr lpName, IntPtr lParam);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr FindResourceW(IntPtr hModule, IntPtr lpName, uint lpType);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr LockResource(IntPtr hResData);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);

    public class GroupInfo {
        public string NameDisplay;
        public uint Size;
        public short IconCount;
    }

    public static List<GroupInfo> EnumGroups(string path) {
        var result = new List<GroupInfo>();
        IntPtr hMod = LoadLibraryEx(path, IntPtr.Zero, 0x22);
        if (hMod == IntPtr.Zero) return result;
        try {
            EnumResNameProc cb = (m, t, name, l) => {
                var info = new GroupInfo();
                long v = name.ToInt64();
                info.NameDisplay = (v < 0x10000 && v > 0) ? ("ID=" + v) : ("STR=" + Marshal.PtrToStringUni(name));
                IntPtr hRes = FindResourceW(hMod, name, 14);
                IntPtr hData = LoadResource(hMod, hRes);
                IntPtr ptr = LockResource(hData);
                uint size = SizeofResource(hMod, hRes);
                info.Size = size;
                info.IconCount = Marshal.ReadInt16(ptr, 4);
                result.Add(info);
                return true;
            };
            EnumResourceNamesW(hMod, 14, cb, IntPtr.Zero);
            GC.KeepAlive(cb);

            int iconTotal = 0;
            EnumResNameProc cb2 = (m, t, name, l) => { iconTotal++; return true; };
            EnumResourceNamesW(hMod, 3, cb2, IntPtr.Zero);
            GC.KeepAlive(cb2);
            Console.WriteLine("RT_ICON total = " + iconTotal);
        } finally { FreeLibrary(hMod); }
        return result;
    }
}
"@

Add-Type -TypeDefinition $src -Language CSharp

Write-Host "=== $exe ==="
$groups = [ResEnum]::EnumGroups($exe)
$i = 0
foreach ($g in $groups) {
    Write-Host ("[{0}] {1}  size={2}  iconCount={3}" -f $i, $g.NameDisplay, $g.Size, $g.IconCount)
    $i++
}
