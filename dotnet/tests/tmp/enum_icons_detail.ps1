param([string]$exe = "C:\Home\Apps\Doubao\app\doubao.exe")

$src = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class ResEnum2 {
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

    public class GroupDetail {
        public string NameDisplay;
        public short IconCount;
        public List<int> IconIds = new List<int>();
        public List<uint> IconSizes = new List<uint>();
    }

    public static List<GroupDetail> EnumGroupsDetail(string path) {
        var result = new List<GroupDetail>();
        IntPtr hMod = LoadLibraryEx(path, IntPtr.Zero, 0x22);
        if (hMod == IntPtr.Zero) return result;
        try {
            var names = new List<IntPtr>();
            EnumResNameProc cb = (m, t, name, l) => { names.Add(name); return true; };
            EnumResourceNamesW(hMod, 14, cb, IntPtr.Zero);
            GC.KeepAlive(cb);

            foreach (var name in names) {
                IntPtr hRes = FindResourceW(hMod, name, 14);
                IntPtr hData = LoadResource(hMod, hRes);
                IntPtr ptr = LockResource(hData);
                uint grpSize = SizeofResource(hMod, hRes);
                short count = Marshal.ReadInt16(ptr, 4);
                var detail = new GroupDetail();
                long v = name.ToInt64();
                detail.NameDisplay = (v < 0x10000 && v > 0) ? ("ID=" + v) : ("STR=" + Marshal.PtrToStringUni(name));
                detail.IconCount = count;
                IntPtr entry = ptr + 6;
                for (int i = 0; i < count; i++) {
                    ushort iconId = (ushort)Marshal.ReadInt16(entry, 12);
                    detail.IconIds.Add(iconId);
                    IntPtr hIconRes = FindResourceW(hMod, new IntPtr(iconId), 3);
                    if (hIconRes != IntPtr.Zero) {
                        uint sz = SizeofResource(hMod, hIconRes);
                        detail.IconSizes.Add(sz);
                    } else {
                        detail.IconSizes.Add(0);
                    }
                    entry += 14;
                }
                result.Add(detail);
            }
        } finally { FreeLibrary(hMod); }
        return result;
    }
}
"@

Add-Type -TypeDefinition $src -Language CSharp

Write-Host "=== $exe ==="
$groups = [ResEnum2]::EnumGroupsDetail($exe)
$i = 0
foreach ($g in $groups) {
    Write-Host ("[{0}] {1}  iconCount={2}" -f $i, $g.NameDisplay, $g.IconCount)
    for ($j = 0; $j -lt $g.IconIds.Count; $j++) {
        Write-Host ("    RT_ICON ID={0}  size={1}" -f $g.IconIds[$j], $g.IconSizes[$j])
    }
    $i++
}
