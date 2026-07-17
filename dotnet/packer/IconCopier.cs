using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using WinAppLocker.Shared;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// 把原 EXE 的 RT_GROUP_ICON / RT_ICON / RT_VERSION 资源复制到 stub 输出 exe。
    /// 使用 LoadLibraryEx(LOAD_LIBRARY_AS_DATAFILE) 读 + BeginUpdateResource/UpdateResource/EndUpdateResource 写。
    /// 失败不影响主流程，只记日志。
    /// </summary>
    internal static class IconCopier
    {
        public static void CopyIconAndVersion(string srcExe, string dstExe, Action<string> logger)
        {
            try
            {
                CopyResources(srcExe, dstExe, new uint[]
                {
                    NativeMethods.RT_GROUP_ICON,
                    NativeMethods.RT_ICON,
                    NativeMethods.RT_VERSION,
                    NativeMethods.RT_MANIFEST
                }, logger);
            }
            catch (Exception ex)
            {
                logger?.Invoke($"[IconCopier] WARN: {ex.Message}");
            }
        }

        private static void CopyResources(string srcExe, string dstExe, uint[] types, Action<string> logger)
        {
            // 1. 用 LoadLibraryEx 把 src 作为数据文件加载
            IntPtr hSrc = NativeMethods.LoadLibraryEx(srcExe, IntPtr.Zero,
                NativeMethods.LOAD_LIBRARY_AS_DATAFILE | NativeMethods.LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            if (hSrc == IntPtr.Zero)
            {
                logger?.Invoke($"[IconCopier] LoadLibraryEx failed: {Marshal.GetLastWin32Error()}");
                return;
            }

            try
            {
                // 2. 收集所有要复制的资源
                var collected = new List<ResourceItem>();
                foreach (uint type in types)
                {
                    EnumerateResources(hSrc, type, collected, logger);
                }

                if (collected.Count == 0)
                {
                    logger?.Invoke("[IconCopier] no resources found");
                    return;
                }

                // 3. 用 UpdateResource 写到 dst
                IntPtr hUpdate = NativeMethods.BeginUpdateResource(dstExe, false);
                if (hUpdate == IntPtr.Zero)
                {
                    logger?.Invoke($"[IconCopier] BeginUpdateResource failed: {Marshal.GetLastWin32Error()}");
                    return;
                }

                try
                {
                    foreach (var r in collected)
                    {
                        // 不复制 RT_MANIFEST：原 EXE 的 manifest 描述自身依赖，应用到 stub 会破坏 stub
                        if (r.Type == NativeMethods.RT_MANIFEST) continue;

                        bool ok = NativeMethods.UpdateResourceW(hUpdate, r.Type, r.Name, r.Lang, r.DataPtr, r.DataSize);
                        if (!ok)
                        {
                            logger?.Invoke($"[IconCopier] UpdateResource failed for type={r.Type}: {Marshal.GetLastWin32Error()}");
                        }
                    }

                    if (!NativeMethods.EndUpdateResource(hUpdate, false))
                    {
                        logger?.Invoke($"[IconCopier] EndUpdateResource failed: {Marshal.GetLastWin32Error()}");
                    }
                }
                catch
                {
                    // 失败时丢弃所有更新
                    NativeMethods.EndUpdateResource(hUpdate, true);
                    throw;
                }
                finally
                {
                    // 释放非托管内存
                    foreach (var r in collected)
                    {
                        if (r.DataPtr != IntPtr.Zero) Marshal.FreeHGlobal(r.DataPtr);
                    }
                }
            }
            finally
            {
                NativeMethods.FreeLibrary(hSrc);
            }
        }

        private struct ResourceItem
        {
            public uint Type;
            public IntPtr Name;
            public ushort Lang;
            public IntPtr DataPtr;
            public uint DataSize;
        }

        private static void EnumerateResources(IntPtr hSrc, uint type,
            List<ResourceItem> collected, Action<string> logger)
        {
            NativeMethods.EnumResourceNamesW(hSrc, type,
                (hModule, lpType, lpName, lParam) =>
                {
                    // lpName 可能是字符串指针或整数 ID
                    // 我们只复制整数 ID 资源（icon/version 都是整数 ID）
                    // 但如果 lpName 高位是 0，说明是整数 ID

                    // 获取资源数据
                    IntPtr hResInfo = NativeMethods.FindResourceW(hSrc, lpName, type);
                    if (hResInfo == IntPtr.Zero) return true;

                    IntPtr hResData = NativeMethods.LoadResource(hSrc, hResInfo);
                    if (hResData == IntPtr.Zero) return true;

                    IntPtr lpData = NativeMethods.LockResource(hResData);
                    uint size = NativeMethods.SizeofResource(hSrc, hResInfo);

                    if (lpData == IntPtr.Zero || size == 0) return true;

                    // 复制到 managed buffer（UpdateResource 调用时数据必须可用，但 LockResource 的指针在 FreeLibrary 前一直有效，
                    // 实际上 UpdateResource 会在 EndUpdateResource 时真正使用，所以需要先复制到托管内存）
                    byte[] data = new byte[size];
                    Marshal.Copy(lpData, data, 0, (int)size);
                    IntPtr copiedPtr = Marshal.AllocHGlobal((int)size);
                    Marshal.Copy(data, 0, copiedPtr, (int)size);

                    collected.Add(new ResourceItem
                    {
                        Type = type,
                        Name = lpName,
                        Lang = 0,  // 默认语言
                        DataPtr = copiedPtr,
                        DataSize = size
                    });
                    return true;
                }, IntPtr.Zero);
        }
    }
}
