using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using WinAppLocker.Shared;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// 把原 EXE 的图标 + 版本资源复制到 stub 输出 exe。
    ///
    /// 关键策略（修复 doubao 等多图标 exe 提取错误的问题）：
    /// 原 exe 可能含多个 RT_GROUP_ICON（如 doubao.exe 有 6 个：IDR_MAINFRAME 主图标
    /// + IDR_X001_APP_LIST / IDR_X003_INCOGNITO / 文档关联图标等）。
    /// 旧实现把所有 RT_GROUP_ICON + RT_ICON 都复制过去，导致：
    ///   - stub 自己 ID=32512 的 RT_GROUP_ICON 没被覆盖（原 exe 是字符串名 group）
    ///   - 原 exe 的 RT_ICON ID 1/2/3 覆盖了 stub 的 RT_ICON ID 1/2/3
    ///   - stub 的 ID=32512 group 引用了错的 RT_ICON → 显示错的图标
    ///
    /// 正确做法：
    ///   1. 按 EnumResourceNamesW 顺序取**第一个** RT_GROUP_ICON（Windows 主图标规则：
    ///      整数 ID 升序在前，字符串名 Unicode 字符序在后；标准 exe 的 ID=1 在最前，
    ///      doubao 这类全字符串名的 exe 第一个是 IDR_MAINFRAME，都是主图标）
    ///   2. 把它写入 stub 的 **ID=32512** 位置（覆盖 .NET SDK 生成的 stub 默认 app.ico）
    ///   3. 解析该 group 的 GRPICONDIRENTRY，收集它引用的所有 RT_ICON ID
    ///   4. 只复制这些 RT_ICON，不动其它（避免 ID 冲突污染 stub）
    ///   5. RT_VERSION 仍然全量复制（不冲突）
    /// </summary>
    internal static class IconCopier
    {
        public static void CopyIconAndVersion(string srcExe, string dstExe, Action<string> logger)
        {
            try
            {
                CopyMainIconAndVersion(srcExe, dstExe, logger);
            }
            catch (Exception ex)
            {
                logger?.Invoke($"[IconCopier] WARN: {ex.Message}");
            }
        }

        private static void CopyMainIconAndVersion(string srcExe, string dstExe, Action<string> logger)
        {
            // 1. 用 LoadLibraryEx 把 src 作为数据文件加载
            IntPtr hSrc = NativeMethods.LoadLibraryEx(srcExe, IntPtr.Zero,
                NativeMethods.LOAD_LIBRARY_AS_DATAFILE | NativeMethods.LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            if (hSrc == IntPtr.Zero)
            {
                logger?.Invoke($"[IconCopier] LoadLibraryEx failed: {Marshal.GetLastWin32Error()}");
                return;
            }

            var collected = new List<ResourceItem>();
            try
            {
                // 2. 找原 exe 的第一个 RT_GROUP_ICON（Windows 主图标）
                IntPtr mainGroupName = FindFirstResourceName(hSrc, NativeMethods.RT_GROUP_ICON, logger);
                if (mainGroupName == IntPtr.Zero)
                {
                    logger?.Invoke("[IconCopier] no RT_GROUP_ICON in source");
                    return;
                }

                // 3. 加载主图标 group 数据
                IntPtr hGrpResInfo = NativeMethods.FindResourceW(hSrc, mainGroupName, NativeMethods.RT_GROUP_ICON);
                if (hGrpResInfo == IntPtr.Zero)
                {
                    logger?.Invoke($"[IconCopier] FindResourceW(RT_GROUP_ICON) failed: {Marshal.GetLastWin32Error()}");
                    return;
                }
                IntPtr hGrpData = NativeMethods.LoadResource(hSrc, hGrpResInfo);
                IntPtr grpData = NativeMethods.LockResource(hGrpData);
                uint grpSize = NativeMethods.SizeofResource(hSrc, hGrpResInfo);
                if (grpData == IntPtr.Zero || grpSize < 6)
                {
                    logger?.Invoke("[IconCopier] RT_GROUP_ICON data invalid");
                    return;
                }
                // GRPICONDIR: reserved(2) type(2) count(2) + GRPICONDIRENTRY[14 bytes each]
                short iconCount = Marshal.ReadInt16(grpData, 4);
                if (iconCount <= 0)
                {
                    logger?.Invoke("[IconCopier] RT_GROUP_ICON count <= 0");
                    return;
                }

                // 4. 收集主 group 引用的所有 RT_ICON ID
                var iconIds = new List<ushort>();
                IntPtr entryPtr = grpData + 6;
                for (int i = 0; i < iconCount; i++)
                {
                    // GRPICONDIRENTRY 末尾 2 字节是 RT_ICON 的整数 ID
                    ushort iconId = (ushort)Marshal.ReadInt16(entryPtr, 12);
                    iconIds.Add(iconId);
                    entryPtr += 14;
                }

                // 5. 复制主 group 数据 → stub 的 ID=32512（覆盖 .NET SDK 生成的 stub 默认 app.ico）
                //    .NET SDK 用 <ApplicationIcon> 生成的 RT_GROUP_ICON ID 是 32512（0x7F00），
                //    Windows 资源管理器用这个 ID 作为 exe 主图标显示
                const int STUB_DEFAULT_ICON_GROUP_ID = 32512;
                AddCollected(collected, NativeMethods.RT_GROUP_ICON, new IntPtr(STUB_DEFAULT_ICON_GROUP_ID),
                             grpData, grpSize);

                // 6. 复制主 group 引用的所有 RT_ICON（用原 ID）
                foreach (ushort iconId in iconIds)
                {
                    IntPtr hIconResInfo = NativeMethods.FindResourceW(hSrc, new IntPtr(iconId), NativeMethods.RT_ICON);
                    if (hIconResInfo == IntPtr.Zero) continue;
                    IntPtr hIconData = NativeMethods.LoadResource(hSrc, hIconResInfo);
                    IntPtr iconData = NativeMethods.LockResource(hIconData);
                    uint iconSize = NativeMethods.SizeofResource(hSrc, hIconResInfo);
                    if (iconData == IntPtr.Zero || iconSize == 0) continue;
                    AddCollected(collected, NativeMethods.RT_ICON, new IntPtr(iconId) /*MAKEINTRESOURCE(iconId)*/,
                                 iconData, iconSize);
                }

                // 7. 复制 RT_VERSION（原 exe 版本信息，不冲突，全量复制）
                EnumerateResources(hSrc, NativeMethods.RT_VERSION, collected, logger);

                if (collected.Count == 0)
                {
                    logger?.Invoke("[IconCopier] nothing to copy");
                    return;
                }

                logger?.Invoke($"[IconCopier] 主图标 group=主, 引用 {iconIds.Count} 个 RT_ICON，共 {collected.Count} 个资源将写入");

                // 8. 用 UpdateResource 写到 dst
                WriteCollected(dstExe, collected, logger);
            }
            finally
            {
                // 释放非托管内存
                foreach (var r in collected)
                {
                    if (r.DataPtr != IntPtr.Zero) Marshal.FreeHGlobal(r.DataPtr);
                }
                NativeMethods.FreeLibrary(hSrc);
            }
        }

        /// <summary>按 EnumResourceNamesW 枚举顺序返回第一个资源名（IntPtr）。</summary>
        private static IntPtr FindFirstResourceName(IntPtr hSrc, uint type, Action<string> logger)
        {
            IntPtr firstName = IntPtr.Zero;
            NativeMethods.EnumResNameDelegate cb = (m, t, name, l) =>
            {
                firstName = name;
                return false; // stop at first
            };
            NativeMethods.EnumResourceNamesW(hSrc, type, cb, IntPtr.Zero);
            GC.KeepAlive(cb); // 防止委托在 native 回调期间被 GC 回收
            return firstName;
        }

        private static void AddCollected(List<ResourceItem> collected, uint type, IntPtr name,
                                         IntPtr srcData, uint size)
        {
            byte[] data = new byte[size];
            Marshal.Copy(srcData, data, 0, (int)size);
            IntPtr copiedPtr = Marshal.AllocHGlobal((int)size);
            Marshal.Copy(data, 0, copiedPtr, (int)size);
            collected.Add(new ResourceItem
            {
                Type = type,
                Name = name,
                Lang = 0,
                DataPtr = copiedPtr,
                DataSize = size
            });
        }

        private static void WriteCollected(string dstExe, List<ResourceItem> collected, Action<string> logger)
        {
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
                NativeMethods.EndUpdateResource(hUpdate, true);
                throw;
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
            NativeMethods.EnumResNameDelegate cb = (hModule, lpType, lpName, lParam) =>
            {
                IntPtr hResInfo = NativeMethods.FindResourceW(hSrc, lpName, type);
                if (hResInfo == IntPtr.Zero) return true;

                IntPtr hResData = NativeMethods.LoadResource(hSrc, hResInfo);
                if (hResData == IntPtr.Zero) return true;

                IntPtr lpData = NativeMethods.LockResource(hResData);
                uint size = NativeMethods.SizeofResource(hSrc, hResInfo);

                if (lpData == IntPtr.Zero || size == 0) return true;

                AddCollected(collected, type, lpName, lpData, size);
                return true;
            };
            NativeMethods.EnumResourceNamesW(hSrc, type, cb, IntPtr.Zero);
            GC.KeepAlive(cb);
        }
    }
}
