using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Patched.Shared.UserTrees;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace Patched.Shared.IdeExtensions;

/// <summary>
/// PAT-2017: what an already-open file handle really is, on Windows. .NET has no
/// O_NOFOLLOW, so the IDE extension scan checks every path component for a reparse point
/// before it opens anything (see <see cref="IdeExtensionScanLogic"/>) and then, because a
/// user can swap a directory for a junction between that check and the open, asks the
/// handle itself: it must be a single-link, non-directory file whose final path (every
/// junction and symlink resolved by the kernel) is exactly the path the scan meant to open.
/// A junction planted mid-scan, or a hard link to a file the user could not otherwise read,
/// fails that and the file is treated as unreadable.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WindowsFileIdentity
{
    private const uint FileReadAttributes     = 0x80;
    private const uint FileShareAll           = 0x7;
    private const uint OpenExisting           = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileAttributeDirectory = 0x10;
    private const uint FileAttributeDevice    = 0x40;
    private const uint FileAttributeReparsePoint = 0x400;
    private const uint FileListDirectory      = 0x1;
    private const uint FileShareReadWrite     = 0x3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int  FileFullDirectoryInfo  = 14;
    private const int  FileFullDirectoryRestartInfo = 15;
    private const int  ErrorNoMoreFiles       = 18;
    private const int  DirectoryBufferBytes   = 64 * 1024;
    private const uint FsctlGetReparsePoint   = 0x000900A8;
    private const uint IoReparseTagMountPoint = 0xA0000003;
    private const uint IoReparseTagSymlink    = 0xA000000C;
    private const uint SymlinkFlagRelative    = 0x1;
    private const int  ReparseBufferBytes     = 16 * 1024;

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint     FileAttributes;
        public FILETIME CreationTime;
        public FILETIME LastAccessTime;
        public FILETIME LastWriteTime;
        public uint     VolumeSerialNumber;
        public uint     FileSizeHigh;
        public uint     FileSizeLow;
        public uint     NumberOfLinks;
        public uint     FileIndexHigh;
        public uint     FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation info);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, [Out] char[] buffer, uint length, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, [Out] byte[] buffer, uint size);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetLongPathNameW(string shortPath, [Out] char[] buffer, uint length);

    // PAT-2052: FSCTL_GET_REPARSE_POINT only. It is the one documented way to read a link's
    // target from a handle opened on the link itself, so the link's own location can be
    // verified first; .NET's LinkTarget makes the same call but only by path.
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle device, uint ioControlCode, IntPtr inBuffer, uint inBufferSize,
        [Out] byte[] outBuffer, uint outBufferSize, out uint bytesReturned, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(
        string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    /// <summary>
    /// True only when <paramref name="handle"/> is a regular file with exactly one link whose
    /// kernel-resolved final path equals <paramref name="expectedFinalPath"/> (case-insensitive).
    /// Any failure to answer is false.
    /// </summary>
    public static bool IsExpectedRegularFile(SafeFileHandle handle, string expectedFinalPath)
    {
        try
        {
            if (!GetFileInformationByHandle(handle, out var info)) return false;
            if ((info.FileAttributes & (FileAttributeDirectory | FileAttributeReparsePoint)) != 0) return false;
            if (info.NumberOfLinks != 1) return false;
            var final = FinalPath(handle);
            return final is not null
                && string.Equals(final, Path.TrimEndingDirectorySeparator(expectedFinalPath), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// The kernel-resolved final path of a trusted root directory, or null when it cannot be
    /// read or is not the directory it names. PAT-2040: the root is opened with
    /// FILE_FLAG_OPEN_REPARSE_POINT and without FILE_SHARE_DELETE, a reparse point is refused,
    /// and the final path must equal the root's own full path (with any 8.3 short names
    /// expanded), so a root swapped for a junction, or reached through one, is never recorded
    /// as the place files under it are expected to be.
    /// </summary>
    public static string? FinalPathOfDirectory(string directory)
    {
        try
        {
            var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
            using var handle = CreateFileW(ExtendedLengthPath(full), FileReadAttributes, FileShareReadWrite, IntPtr.Zero,
                OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (handle.IsInvalid) return null;
            if (!GetFileInformationByHandle(handle, out var info)) return null;
            if ((info.FileAttributes & FileAttributeDirectory) == 0 || (info.FileAttributes & FileAttributeReparsePoint) != 0)
                return null;
            var final = FinalPath(handle);
            var intended = LongPath(full);
            return final is not null && intended is not null
                && string.Equals(final, intended, StringComparison.OrdinalIgnoreCase)
                ? final
                : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// <paramref name="path"/> with every 8.3 short name spelled in full. GetLongPathName names
    /// each component as it is, a junction included, and never resolves one, so a junction on
    /// the way still makes the final path differ. Null when it cannot be read.
    /// </summary>
    private static string? LongPath(string path)
    {
        var extended = ExtendedLengthPath(path);
        var result = CallGrowingOnce(buffer => GetLongPathNameW(extended, buffer, (uint)buffer.Length));
        return result is null ? null : Normalise(result);
    }

    /// <summary>
    /// PAT-2056: the path to hand a raw Win32 call. Without a \\?\ prefix CreateFileW and
    /// GetLongPathNameW refuse anything from MAX_PATH up unless the machine has opted into long
    /// paths (LongPathsEnabled is 0 by default), so a deep tree would be unlistable however
    /// large the buffers. Like .NET's own file APIs, a full path of 248 characters or more gets
    /// the prefix (\\?\UNC\ for a share) after <see cref="Path.GetFullPath(string)"/> has
    /// normalised it; a shorter one, or one already carrying a device prefix, is passed
    /// unchanged. Every caller still compares the handle's final path with the one it expected.
    /// A path that already carries a \\?\ or \\.\ prefix skips normalisation entirely, so never
    /// pass one built from unverified input (a listed name, a link target): only verified roots
    /// joined to listed names may reach this.
    /// </summary>
    internal static string ExtendedLengthPath(string path)
    {
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\\.\", StringComparison.Ordinal))
            return path;
        var full = Path.GetFullPath(path);
        if (full.Length < MaxShortDirectoryPath) return path;
        return full.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + full[2..] : @"\\?\" + full;
    }

    /// <summary>The length at which .NET itself starts adding \\?\ (MAX_PATH less room for an 8.3 name).</summary>
    private const int MaxShortDirectoryPath = 248;

    /// <summary>
    /// PAT-2056: the longest path, in characters with its terminator, that any Win32 call here
    /// is asked to return (an extended-length path is at most 32,767 characters).
    /// </summary>
    internal const int MaxPathChars = 32768;

    /// <summary>The first buffer a path call gets; enough for all but deep trees.</summary>
    internal const int InitialPathChars = 1024;

    /// <summary>
    /// PAT-2056: runs a Win32 call that writes a path into the buffer it is given and returns
    /// either the characters written (less than the buffer, terminator not counted), 0 on
    /// failure, or the size the buffer needs (terminator counted) when it is too small, as
    /// GetFinalPathNameByHandleW and GetLongPathNameW both do. A too-small first buffer is
    /// grown once to exactly the size asked for, so a path deeper than
    /// <see cref="InitialPathChars"/> (nested node_modules) is still verified. Null on a
    /// failure, on a size past <see cref="MaxPathChars"/>, or when the second call still does
    /// not fit (the path grew in between): a path that cannot be read in full is never
    /// answered in part.
    /// </summary>
    internal static string? CallGrowingOnce(Func<char[], uint> call)
    {
        var buffer = new char[InitialPathChars];
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var length = call(buffer);
            if (length == 0) return null;
            if (length < buffer.Length) return new string(buffer, 0, (int)length);
            if (length > MaxPathChars) return null;
            buffer = new char[length];
        }
        return null;
    }

    /// <summary>
    /// PAT-2040: the entries of the directory at <paramref name="path"/>, read from a handle
    /// to that directory and never by path, so a directory swapped for a junction after the
    /// caller checked it cannot be listed through. The handle is opened with
    /// FILE_FLAG_OPEN_REPARSE_POINT (a junction or symlink at the path is opened as itself and
    /// refused, never followed) and without FILE_SHARE_DELETE (the directory cannot be renamed
    /// or deleted while it is held); it must be a non-reparse directory whose kernel-resolved
    /// final path equals <paramref name="expectedFinalPath"/> (case-insensitive), which
    /// refuses a junction anywhere on the way to it. Only then is it enumerated, through
    /// GetFileInformationByHandleEx(FileFullDirectoryInfo). Each entry's kind comes from its
    /// own attributes (a reparse point is <see cref="FsKind.Symlink"/>, never followed) and a
    /// file's length from its directory entry. "." and ".." are left out. Null when the
    /// directory cannot be opened, fails a check or cannot be read to the end. PAT-2052: null
    /// too, and the enumeration stopped there, as soon as it holds more than
    /// <paramref name="maxEntries"/> entries, so a directory filled with a million names costs
    /// one bounded read and is reported unreadable, never listed short as though complete.
    /// </summary>
    public static List<(string Name, FsKind Kind, long Length)>? ListDirectory(
        string path, string expectedFinalPath, int maxEntries = UserTreeReader.DefaultMaxEntriesPerListing)
    {
        try
        {
            using var handle = CreateFileW(ExtendedLengthPath(path), FileListDirectory | FileReadAttributes, FileShareReadWrite, IntPtr.Zero,
                OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (handle.IsInvalid) return null;
            if (!GetFileInformationByHandle(handle, out var info)) return null;
            if ((info.FileAttributes & FileAttributeDirectory) == 0 || (info.FileAttributes & FileAttributeReparsePoint) != 0)
                return null;
            var final = FinalPath(handle);
            if (final is null
                || !string.Equals(final, Path.TrimEndingDirectorySeparator(expectedFinalPath), StringComparison.OrdinalIgnoreCase))
                return null;

            var rows = new List<(string, FsKind, long)>();
            var buffer = new byte[DirectoryBufferBytes];
            var infoClass = FileFullDirectoryRestartInfo;
            while (true)
            {
                if (!GetFileInformationByHandleEx(handle, infoClass, buffer, (uint)buffer.Length))
                    return Marshal.GetLastWin32Error() == ErrorNoMoreFiles ? rows : null;
                infoClass = FileFullDirectoryInfo;
                if (!ParseFullDirectoryInfo(buffer, rows)) return null;
                if (rows.Count > maxEntries) return null;
            }
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Appends the FILE_FULL_DIR_INFO records in <paramref name="buffer"/>: NextEntryOffset at
    /// 0, EndOfFile at 40, FileAttributes at 56, FileNameLength (bytes) at 60, FileName (UTF-16)
    /// at 68. False on a record that runs past the buffer.
    /// </summary>
    internal static bool ParseFullDirectoryInfo(ReadOnlySpan<byte> buffer, List<(string Name, FsKind Kind, long Length)> rows)
    {
        const int NameOffset = 68;
        var offset = 0;
        while (true)
        {
            if (offset < 0 || offset + NameOffset > buffer.Length) return false;
            var record = buffer[offset..];
            var next = BinaryPrimitives.ReadUInt32LittleEndian(record);
            var length = BinaryPrimitives.ReadInt64LittleEndian(record[40..]);
            var attributes = BinaryPrimitives.ReadUInt32LittleEndian(record[56..]);
            var nameBytes = BinaryPrimitives.ReadUInt32LittleEndian(record[60..]);
            if (nameBytes % 2 != 0 || NameOffset + (long)nameBytes > record.Length) return false;
            var name = Encoding.Unicode.GetString(record.Slice(NameOffset, (int)nameBytes));
            if (name is not ("." or ".."))
            {
                var kind = (attributes & FileAttributeReparsePoint) != 0 ? FsKind.Symlink
                    : (attributes & FileAttributeDirectory) != 0 ? FsKind.Dir
                    : (attributes & FileAttributeDevice) != 0 ? FsKind.Other
                    : FsKind.File;
                rows.Add((name, kind, kind == FsKind.File ? Math.Max(0, length) : 0));
            }
            if (next == 0) return true;
            if (next > int.MaxValue - offset) return false;
            offset += (int)next;
        }
    }

    /// <summary>
    /// PAT-2052: the raw target of the junction or symlink at <paramref name="path"/>, read
    /// from a handle on the link itself and never by path. The handle is opened with
    /// FILE_FLAG_OPEN_REPARSE_POINT (the link is opened as itself, never followed) and must be
    /// a reparse point whose kernel-resolved final path equals
    /// <paramref name="expectedFinalPath"/> (case-insensitive), which refuses a link reached
    /// through a junction anywhere above it: a directory swapped after the caller listed it
    /// can never make this read another profile's link. Only then is the reparse data read
    /// (FSCTL_GET_REPARSE_POINT) and parsed by <see cref="ParseReparseTarget"/>. Null when the
    /// link cannot be opened, fails a check or is not a junction or symlink.
    /// </summary>
    public static string? ReadLinkTarget(string path, string expectedFinalPath)
    {
        try
        {
            using var handle = CreateFileW(ExtendedLengthPath(path), FileReadAttributes, FileShareReadWrite, IntPtr.Zero,
                OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (handle.IsInvalid) return null;
            if (!GetFileInformationByHandle(handle, out var info)) return null;
            if ((info.FileAttributes & FileAttributeReparsePoint) == 0) return null;
            var final = FinalPath(handle);
            if (final is null
                || !string.Equals(final, Path.TrimEndingDirectorySeparator(expectedFinalPath), StringComparison.OrdinalIgnoreCase))
                return null;
            var buffer = new byte[ReparseBufferBytes];
            if (!DeviceIoControl(handle, FsctlGetReparsePoint, IntPtr.Zero, 0, buffer, (uint)buffer.Length, out var returned, IntPtr.Zero))
                return null;
            return ParseReparseTarget(buffer.AsSpan(0, (int)Math.Min(returned, (uint)buffer.Length)));
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// The substitute name of a REPARSE_DATA_BUFFER for a mount point (junction) or symlink:
    /// ReparseTag at 0, ReparseDataLength at 4, SubstituteNameOffset at 8, SubstituteNameLength
    /// at 10, then the path buffer at 16 (mount point) or 20 (symlink, after its Flags at 16).
    /// An absolute target loses its \??\ prefix (\??\UNC\ becomes \\); a relative symlink's
    /// target is returned as written. Null for any other tag, or a name that runs past the
    /// data or the buffer.
    /// </summary>
    internal static string? ParseReparseTarget(ReadOnlySpan<byte> data)
    {
        if (data.Length < 16) return null;
        var tag = BinaryPrimitives.ReadUInt32LittleEndian(data);
        var dataLength = BinaryPrimitives.ReadUInt16LittleEndian(data[4..]);
        if (8 + dataLength > data.Length) return null;
        int pathBuffer;
        var relative = false;
        if (tag == IoReparseTagMountPoint)
        {
            pathBuffer = 16;
        }
        else if (tag == IoReparseTagSymlink)
        {
            if (data.Length < 20) return null;
            pathBuffer = 20;
            relative = (BinaryPrimitives.ReadUInt32LittleEndian(data[16..]) & SymlinkFlagRelative) != 0;
        }
        else
        {
            return null;
        }
        var offset = BinaryPrimitives.ReadUInt16LittleEndian(data[8..]);
        var length = BinaryPrimitives.ReadUInt16LittleEndian(data[10..]);
        if (length == 0 || offset % 2 != 0 || length % 2 != 0 || pathBuffer + offset + length > 8 + dataLength) return null;
        var name = Encoding.Unicode.GetString(data.Slice(pathBuffer + offset, length));
        if (relative) return name;
        if (name.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase)) return @"\\" + name[8..];
        if (name.StartsWith(@"\??\", StringComparison.Ordinal)) return name[4..];
        return name;
    }

    private static string? FinalPath(SafeFileHandle handle)
    {
        var result = CallGrowingOnce(buffer => GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0));
        return result is null ? null : Normalise(result);
    }

    private static string Normalise(string path)
    {
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) path = @"\\" + path[8..];
        else if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) path = path[4..];
        return Path.TrimEndingDirectorySeparator(path);
    }
}
