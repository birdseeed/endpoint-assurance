using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using Patched.Shared.IdeExtensions;

namespace Patched.Shared.UserTrees;

/// <summary>One local user profile handed to a user-tree scan.</summary>
/// <param name="User">DOMAIN\user, or the SID when it cannot be resolved.</param>
/// <param name="UserId">The profile SID.</param>
/// <param name="ProfileRoot">The profile directory, e.g. C:\Users\alice.</param>
internal sealed record UserProfileSource(string User, string? UserId, string ProfileRoot);

/// <summary>What is at a path, from its attributes, never following a reparse point.</summary>
internal enum FsKind { Absent, Dir, Symlink, File, Other, Error }

/// <summary>PAT-2019: reads up to destination.Length bytes at offset; returns the count read.</summary>
internal delegate int RangeReader(long offset, Span<byte> destination);

/// <summary>A directory could not be listed.</summary>
internal sealed class UnlistableDirectoryException : Exception;

/// <summary>
/// PAT-2018: the file-safety primitives for a collector that runs as SYSTEM over trees an
/// ordinary user owns. The same rules PAT-2017 put in <see cref="IdeExtensionScanLogic"/>,
/// lifted into one shared place so a new collector does not grow a third copy: .NET has no
/// O_NOFOLLOW, so every path component is checked for a reparse point before anything is
/// opened; every file must then be a non-reparse regular file under a size cap; and after it
/// is opened the handle must be a single-link file whose kernel-resolved final path is the
/// path the scan meant (<see cref="WindowsFileIdentity.IsExpectedRegularFile"/> on Windows),
/// which closes the window in which a user swaps a checked directory for a junction.
///
/// PAT-2033: this is the only copy. <see cref="IdeExtensionScanLogic"/> reads through it too.
///
/// PAT-2052: one reader belongs to one scan. It caches every verified listing it takes, keyed
/// by the final path the listing was verified against, so <see cref="KindAt"/> and
/// <see cref="Walk"/> no longer re-list every ancestor on every call. A cached listing lives
/// exactly as long as the reader, which a scan creates for itself and drops when it returns,
/// so no listing outlives the scan that took it. Each listing is capped at
/// <see cref="DefaultMaxEntriesPerListing"/> entries: past that the directory is unlistable
/// (Error, so partial), never a truncated list taken as complete.
/// </summary>
internal sealed class UserTreeReader
{
    public const int DefaultTextCap = 512;

    /// <summary>
    /// PAT-2052: entries one listing may hold before the directory is treated as unlistable.
    /// Every directory a collector lists (a profile's AppData\Local, a node_modules, a
    /// site-packages, an Ollama blob store, a browser's Extensions) holds hundreds or, for a
    /// large flat node_modules, a few thousand entries; 100,000 is well over an order of
    /// magnitude above any of them, while still bounding one listing to roughly 150 64 KB
    /// directory reads, tens of milliseconds, and about 10 MB, so a user who fills a directory
    /// with a million names costs the scan one bounded read, not an unbounded one.
    /// </summary>
    public const int DefaultMaxEntriesPerListing = 100_000;

    /// <summary>
    /// PAT-2052: total entries the per-scan listing cache may hold (a few tens of MB at most).
    /// Past it the oldest listings are dropped and would be taken again if asked for, so the
    /// cache bounds memory without ever serving anything but a verified listing.
    /// </summary>
    public const int MaxCachedEntries = 500_000;

    private static readonly Regex UserInfo =
        new(@"([A-Za-z][A-Za-z0-9+.-]*://)[^/?#\s]*@", RegexOptions.CultureInvariant);

    private readonly Func<SafeFileHandle, string, bool>? _verifyOpenedFile;
    private readonly Func<string, string?>? _resolveRootFinalPath;
    private readonly Func<string, string, List<(string Name, FsKind Kind, long Length)>?> _listOpenedDirectory;
    private readonly Func<string, string, string?> _readOpenedLink;
    private readonly int _maxEntriesPerListing;
    private readonly int _maxCachedEntries;
    private readonly List<(string Full, string Final)> _roots = [];
    // Ordinal, not ignoring case: in a case-sensitive directory "foo" and "Foo" are two
    // directories, and the final-path check compares ignoring case, so a case-folded key would
    // answer one with the other's listing (PAT-2052 review).
    private readonly Dictionary<string, (string Name, FsKind Kind, long Length)[]?> _listings =
        new(StringComparer.Ordinal);
    private readonly Queue<string> _listingOrder = new();
    private int _cachedEntries;

    /// <param name="verifyOpenedFile">
    /// Checks an opened handle against the path the scan meant to open. Pass
    /// <see cref="WindowsFileIdentity.IsExpectedRegularFile"/> on Windows; null elsewhere,
    /// where the scan runs only under test.
    /// </param>
    /// <param name="resolveRootFinalPath">
    /// Kernel-resolved final path of a trusted root directory, so the expected final path of a
    /// file under it is spelled as the kernel spells it; null from it refuses the root. Null
    /// here means <see cref="WindowsFileIdentity.FinalPathOfDirectory"/> on Windows, always
    /// (PAT-2040); elsewhere, where the scan runs only under test, a root is its full path.
    /// </param>
    /// <param name="listOpenedDirectory">
    /// PAT-2040: lists a directory from a handle to it, given (path, expected final path), or
    /// null when it cannot or the handle is not that directory. Null here means
    /// <see cref="WindowsFileIdentity.ListDirectory"/> on Windows, always, so no collector
    /// can forget it; elsewhere, where the scan runs only under test, the path is enumerated.
    /// </param>
    /// <param name="maxEntriesPerListing">
    /// PAT-2052: a listing with more entries than this is unlistable. Lowered only by tests.
    /// </param>
    /// <param name="maxCachedEntries">
    /// PAT-2052: the listing cache's entry budget (<see cref="MaxCachedEntries"/>). Lowered only by tests.
    /// </param>
    public UserTreeReader(
        Func<SafeFileHandle, string, bool>? verifyOpenedFile,
        Func<string, string?>? resolveRootFinalPath,
        Func<string, string, List<(string Name, FsKind Kind, long Length)>?>? listOpenedDirectory = null,
        int maxEntriesPerListing = DefaultMaxEntriesPerListing,
        int maxCachedEntries = MaxCachedEntries)
    {
        _verifyOpenedFile = verifyOpenedFile;
        _resolveRootFinalPath = resolveRootFinalPath
            ?? (OperatingSystem.IsWindows() ? WindowsFileIdentity.FinalPathOfDirectory : null);
        _maxEntriesPerListing = maxEntriesPerListing;
        _maxCachedEntries = maxCachedEntries;
        _listOpenedDirectory = listOpenedDirectory ?? DefaultLister(maxEntriesPerListing);
        _readOpenedLink = OperatingSystem.IsWindows() ? WindowsFileIdentity.ReadLinkTarget : ReadLinkByPath;
    }

    /// <summary>
    /// The lister a reader uses when none is passed: the verified-handle listing
    /// (<see cref="WindowsFileIdentity.ListDirectory"/>) on Windows, always; elsewhere, where
    /// the scan runs only under test, an enumeration by path. Both stop, and answer null,
    /// past <paramref name="maxEntries"/>. Tests wrap it to count or interrupt listings.
    /// </summary>
    internal static Func<string, string, List<(string Name, FsKind Kind, long Length)>?> DefaultLister(
        int maxEntries = DefaultMaxEntriesPerListing)
    {
        if (OperatingSystem.IsWindows()) return WindowsLister(maxEntries);
        return (path, _) => EnumeratePath(path, maxEntries);
    }

    [SupportedOSPlatform("windows")]
    private static Func<string, string, List<(string Name, FsKind Kind, long Length)>?> WindowsLister(int maxEntries) =>
        (path, expected) => WindowsFileIdentity.ListDirectory(path, expected, maxEntries);

    /// <summary>
    /// Registers a trusted root (a profile directory, Program Files). A file under it is
    /// expected to have the root's final path plus the same relative path. PAT-2040: false,
    /// and nothing registered, when the root's final path cannot be verified (on Windows,
    /// <see cref="WindowsFileIdentity.FinalPathOfDirectory"/> refuses a root that is, or is
    /// reached through, a junction). The caller must then treat the root as refused and read
    /// nothing under it; the root's own spelling is never used in its place.
    /// </summary>
    public bool AddRoot(string root)
    {
        var full = Path.TrimEndingDirectorySeparator(root);
        string final;
        if (_resolveRootFinalPath is { } resolve)
        {
            if (resolve(full) is not { } resolved) return false;
            final = resolved;
        }
        else
        {
            final = full;
        }
        _roots.Add((full, final));
        return true;
    }

    /// <summary>
    /// Text safe to send: non-empty after trimming, no control characters, at most
    /// <paramref name="cap"/> characters, with any URL userinfo (user:password@) removed.
    /// </summary>
    public static string? CleanText(string? value, int cap = DefaultTextCap)
    {
        if (value is null) return null;
        value = value.Trim();
        if (value.Length == 0 || value.Length > cap) return null;
        foreach (var c in value)
            if (c < 0x20 || c == 0x7F) return null;
        return UserInfo.Replace(value, "$1");
    }

    /// <summary>A path with no control characters, else "&lt;unprintable&gt;".</summary>
    public static string CleanPath(string path) =>
        path.All(c => c >= 0x20 && c != 0x7F) ? path : "<unprintable>";

    /// <summary>
    /// What is at <paramref name="path"/>, from its attributes read by path, never following a
    /// reparse point at the path itself. PAT-2050: an earlier component that is a junction IS
    /// followed, so this is only for a root before <see cref="AddRoot"/>, which verifies it.
    /// Below a registered root use <see cref="KindAt"/> or <see cref="Walk"/>.
    /// </summary>
    public static FsKind KindOf(string path)
    {
        try
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0) return FsKind.Symlink;
            if ((attributes & FileAttributes.Directory) != 0) return FsKind.Dir;
            if ((attributes & FileAttributes.Device) != 0) return FsKind.Other;
            return FsKind.File;
        }
        catch (FileNotFoundException) { return FsKind.Absent; }
        catch (DirectoryNotFoundException) { return FsKind.Absent; }
        catch { return FsKind.Error; }
    }

    private static FsKind KindOf(FileSystemInfo info)
    {
        try
        {
            var attributes = info.Attributes;
            if ((attributes & FileAttributes.ReparsePoint) != 0 || info.LinkTarget is not null) return FsKind.Symlink;
            if ((attributes & FileAttributes.Directory) != 0) return FsKind.Dir;
            if ((attributes & FileAttributes.Device) != 0) return FsKind.Other;
            return FsKind.File;
        }
        catch { return FsKind.Error; }
    }

    /// <summary>
    /// Sorted (name, kind) for one directory, dot entries skipped, never following a reparse
    /// point. Throws <see cref="UnlistableDirectoryException"/> when it cannot be listed.
    /// PAT-2040: on Windows the directory is opened first and listed from that handle, after
    /// the handle is shown to be the directory the scan meant (see
    /// <see cref="WindowsFileIdentity.ListDirectory"/>), so a checked directory swapped for a
    /// junction into another profile is refused rather than listed through.
    /// </summary>
    public List<(string Name, FsKind Kind)> ListDir(string path) =>
        ListDirWithLengths(path).Select(e => (e.Name, e.Kind)).ToList();

    /// <summary>
    /// PAT-2019: <see cref="ListDir"/> plus each regular file's length, taken from the directory
    /// entry the enumeration already returned: a stat, never an open, so a model file of any
    /// size costs nothing to measure. Anything that is not a plain file has length 0; an entry
    /// whose attributes or length cannot be read is <see cref="FsKind.Error"/>. Throws
    /// <see cref="UnlistableDirectoryException"/> when the directory cannot be listed.
    /// </summary>
    public List<(string Name, FsKind Kind, long Length)> ListDirWithLengths(string path)
    {
        var rows = ListAll(path).Where(r => !r.Name.StartsWith('.')).ToList();
        rows.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));
        return rows;
    }

    /// <summary>
    /// Every entry of one directory, dot entries included, from the verified-handle listing on
    /// Windows. Throws <see cref="UnlistableDirectoryException"/> when it cannot be listed.
    /// PAT-2052: each directory is listed at most once per reader. The listing, or the fact
    /// that it could not be taken, is cached under the final path it was verified against, so
    /// a directory that cannot be listed (a swapped junction, one over the entry cap) costs
    /// one attempt, not one per question asked below it. More than
    /// <see cref="DefaultMaxEntriesPerListing"/> entries (or the reader's own cap) is
    /// unlistable whatever the lister returned.
    /// </summary>
    private IReadOnlyList<(string Name, FsKind Kind, long Length)> ListAll(string path)
    {
        var expected = ExpectedFinalPath(Path.TrimEndingDirectorySeparator(path));
        if (!_listings.TryGetValue(expected, out var rows))
        {
            var listed = _listOpenedDirectory(path, expected);
            rows = listed is null || listed.Count > _maxEntriesPerListing ? null : listed.ToArray();
            Remember(expected, rows);
        }
        return rows ?? throw new UnlistableDirectoryException();
    }

    private void Remember(string expected, (string Name, FsKind Kind, long Length)[]? rows)
    {
        var cost = Math.Max(1, rows?.Length ?? 0);
        while (_cachedEntries + cost > _maxCachedEntries && _listingOrder.TryDequeue(out var oldest))
        {
            if (_listings.Remove(oldest, out var dropped)) _cachedEntries -= Math.Max(1, dropped?.Length ?? 0);
        }
        _listings[expected] = rows;
        _listingOrder.Enqueue(expected);
        _cachedEntries += cost;
    }

    /// <summary>
    /// PAT-2050: what is at <paramref name="path"/>, decided only by the verified-handle
    /// listing of its parent (<see cref="ListDirWithLengths"/>'s source), never by the path.
    /// A path test follows a junction on an earlier component, so a directory swapped for a
    /// junction into another profile after <see cref="AddRoot"/> would make the answer
    /// Absent or not according to that profile's contents. Here a parent that is, or is
    /// reached through, a junction is refused whatever it points at, and the answer is
    /// <see cref="FsKind.Error"/>: never Absent, so nothing is closed on it, and the same for
    /// every target. Absent only when the parent was listed and the name is not in it, or the
    /// parent itself is Absent by the same rule one level up.
    /// </summary>
    public FsKind KindAt(string path)
    {
        var full = Path.TrimEndingDirectorySeparator(path);
        var parent = Path.GetDirectoryName(full);
        var name = Path.GetFileName(full);
        if (string.IsNullOrEmpty(parent) || string.IsNullOrEmpty(name)) return FsKind.Error;
        try
        {
            return Find(ListAll(parent), name);
        }
        catch (UnlistableDirectoryException)
        {
            // An unlistable parent proves nothing about the name, unless the parent is itself
            // shown absent by a listing of its own parent.
            return KindAt(parent) == FsKind.Absent ? FsKind.Absent : FsKind.Error;
        }
    }

    /// <summary>
    /// The kind of <paramref name="name"/> in one listing: an exact match, else the one entry
    /// equal to it ignoring case (NTFS resolves names that way), else Absent. Two entries that
    /// differ only in case (a case-sensitive directory) with neither exact is Error: which one
    /// a path would reach cannot be told from the listing.
    /// </summary>
    internal static FsKind Find(IReadOnlyList<(string Name, FsKind Kind, long Length)> rows, string name)
    {
        FsKind? folded = null;
        var foldedCount = 0;
        foreach (var row in rows)
        {
            if (string.Equals(row.Name, name, StringComparison.Ordinal)) return row.Kind;
            if (string.Equals(row.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                folded = row.Kind;
                foldedCount++;
            }
        }
        return foldedCount switch
        {
            0 => FsKind.Absent,
            1 => folded!.Value,
            _ => FsKind.Error,
        };
    }

    /// <summary>
    /// The enumeration by path, for a platform with no handle lister (tests off Windows). Null
    /// when it cannot be listed or holds more than <paramref name="maxEntries"/> entries.
    /// </summary>
    private static List<(string Name, FsKind Kind, long Length)>? EnumeratePath(string path, int maxEntries)
    {
        try
        {
            var rows = new List<(string, FsKind, long)>();
            var opts = new EnumerationOptions
            {
                AttributesToSkip = 0,
                IgnoreInaccessible = false,
                RecurseSubdirectories = false,
                ReturnSpecialDirectories = false,
            };
            foreach (var info in new DirectoryInfo(path).EnumerateFileSystemInfos("*", opts))
            {
                var kind = KindOf(info);
                long length = 0;
                if (kind == FsKind.File)
                {
                    try { length = ((FileInfo)info).Length; }
                    catch { kind = FsKind.Error; }
                }
                rows.Add((info.Name, kind, length));
                if (rows.Count > maxEntries) return null;
            }
            return rows;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// PAT-2019: the length of a plain file at <paramref name="path"/>: ("open", length), or
    /// ("missing", null) when nothing is there, or ("unreadable", null) when something is there
    /// that the reader refuses (a reparse point, a directory, a hard link, a file locked
    /// against it or one failing the post-open identity check). PAT-2040: the two are kept
    /// apart, because a refused file is on disk and must never be counted as absent.
    /// PAT-2033: the length comes from the handle <see cref="OpenRegular"/> returns, after the
    /// same post-open identity check a read gets, never from the path, which a user could swap
    /// for a link between the check and the stat. The file is opened, never read, so a model
    /// file of any size costs nothing. PAT-2050: <paramref name="listedKind"/> is as for
    /// <see cref="OpenRegular"/>.
    /// </summary>
    public (string Status, long? Length) StatLength(string path, FsKind? listedKind = null)
    {
        var (status, handle) = OpenRegular(path, long.MaxValue, listedKind);
        if (handle is null) return (status, null);
        using (handle)
        {
            try
            {
                return ("open", RandomAccess.GetLength(handle));
            }
            catch
            {
                return ("unreadable", null);
            }
        }
    }

    /// <summary>
    /// Checks every component of <paramref name="parts"/> below <paramref name="anchor"/> and
    /// stops at the first that is not a plain directory: (Dir, full path) when all of them
    /// are, else (that component's kind, its path). PAT-2050: each component's kind comes from
    /// the verified-handle listing of the directory above it (<see cref="KindAt"/>), starting
    /// with the anchor, never from a path test that would follow a junction on an earlier
    /// component. A directory that cannot be listed, the anchor included (a registered root
    /// swapped for a junction since <see cref="AddRoot"/>), stops the walk with
    /// (<see cref="FsKind.Error"/>, that directory), whatever the junction points at, so a
    /// walk is Absent only on the authority of a listing of the real parent.
    /// </summary>
    public (FsKind Kind, string Path) Walk(string anchor, params string[] parts)
    {
        var p = anchor;
        foreach (var part in parts.SelectMany(q => q.Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries)))
        {
            IReadOnlyList<(string Name, FsKind Kind, long Length)> rows;
            try
            {
                rows = ListAll(p);
            }
            catch (UnlistableDirectoryException)
            {
                return (FsKind.Error, p);
            }
            p = Path.Combine(p, part);
            var k = Find(rows, part);
            if (k != FsKind.Dir) return (k, p);
        }
        return (FsKind.Dir, p);
    }

    /// <summary>
    /// The absolute, normalised target of a link or junction, read from the link itself and
    /// never followed; null when there is none or it cannot be read. PAT-2052: on Windows the
    /// target is read from a handle opened on the link itself, whose final path must be the
    /// one this reader expects for <paramref name="path"/>
    /// (<see cref="WindowsFileIdentity.ReadLinkTarget"/>), never by path: a directory above
    /// the link swapped for a junction after the caller listed it makes this null whatever the
    /// junction points at, so another profile's link is never read. Call it only for a name a
    /// listing from this reader showed as <see cref="FsKind.Symlink"/>.
    /// </summary>
    public string? LinkTarget(string path)
    {
        try
        {
            var full = Path.TrimEndingDirectorySeparator(path);
            var target = _readOpenedLink(full, ExpectedFinalPath(full));
            if (string.IsNullOrEmpty(target)) return null;
            if (target.StartsWith(@"\??\", StringComparison.Ordinal) || target.StartsWith(@"\\?\", StringComparison.Ordinal))
                target = target[4..];
            if (!Path.IsPathRooted(target))
                target = Path.Combine(Path.GetDirectoryName(full) ?? "", target);
            return Path.TrimEndingDirectorySeparator(Path.GetFullPath(target));
        }
        catch
        {
            return null;
        }
    }

    /// <summary>A link's target read by path, for a platform with no handle reader (tests off Windows).</summary>
    private static string? ReadLinkByPath(string path, string expectedFinalPath)
    {
        try
        {
            return new DirectoryInfo(path).LinkTarget ?? new FileInfo(path).LinkTarget;
        }
        catch
        {
            return null;
        }
    }

    private string ExpectedFinalPath(string path)
    {
        var best = (Full: "", Final: "");
        foreach (var root in _roots)
        {
            if (root.Full.Length > best.Full.Length
                && path.StartsWith(root.Full, StringComparison.OrdinalIgnoreCase)
                && (path.Length == root.Full.Length || path[root.Full.Length] == Path.DirectorySeparatorChar))
                best = root;
        }
        return best.Full.Length == 0 ? path : best.Final + path[best.Full.Length..];
    }

    /// <summary>
    /// ("open", handle) or ("missing"|"unreadable", null). Refuses a reparse point, a
    /// directory, a device or anything over <paramref name="cap"/> before opening, and a
    /// handle that fails the post-open identity check after. PAT-2050: "missing" only on the
    /// authority of a verified listing of the parent directory that does not have the file
    /// (<see cref="KindAt"/>); a parent that cannot be listed is "unreadable", and so is a
    /// file the listing has but the open then cannot find. <paramref name="listedKind"/> is
    /// the file's kind from a listing the caller already took of its parent with this reader
    /// (<see cref="ListDir"/> or <see cref="ListDirWithLengths"/>), so a caller working
    /// through a large directory does not list it again for every file; null lists it here.
    /// </summary>
    public (string Status, SafeFileHandle? Handle) OpenRegular(string path, long cap, FsKind? listedKind = null)
    {
        var kind = listedKind ?? KindAt(path);
        if (kind == FsKind.Absent) return ("missing", null);
        if (kind != FsKind.File) return ("unreadable", null);
        SafeFileHandle handle;
        try
        {
            handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        }
        catch { return ("unreadable", null); }
        try
        {
            if (_verifyOpenedFile is { } verify && !verify(handle, ExpectedFinalPath(path)))
            {
                handle.Dispose();
                return ("unreadable", null);
            }
            if (RandomAccess.GetLength(handle) > cap)
            {
                handle.Dispose();
                return ("unreadable", null);
            }
            return ("open", handle);
        }
        catch
        {
            handle.Dispose();
            return ("unreadable", null);
        }
    }

    /// <summary>
    /// PAT-2019: reads fixed ranges of an opened file with <paramref name="read"/>, a callback
    /// that gets (offset, destination) and returns the bytes read, so a caller can parse a large
    /// binary's headers (a PE version resource) without loading the file. Same refusals as
    /// <see cref="OpenRegular"/>. ("read", result), or ("missing"|"unreadable"|the callback's
    /// own status, default).
    /// </summary>
    public (string Status, T? Result) ReadRanges<T>(string path, long cap, Func<RangeReader, (string Status, T? Result)> read)
    {
        var (status, handle) = OpenRegular(path, cap);
        if (handle is null) return (status, default);
        using (handle)
        {
            try
            {
                return read((offset, destination) => RandomAccess.Read(handle, destination, offset));
            }
            catch
            {
                return ("unreadable", default);
            }
        }
    }

    /// <summary>("read", bytes) for the whole file, or ("missing"|"unreadable", null).</summary>
    public (string Status, byte[]? Data) ReadFile(string path, int cap) => Read(path, cap, cap, whole: true);

    /// <summary>
    /// ("read", bytes) for at most the first <paramref name="headCap"/> bytes of a file that is
    /// refused outright past <paramref name="fileCap"/>; or ("missing"|"unreadable", null).
    /// </summary>
    public (string Status, byte[]? Data) ReadHead(string path, long fileCap, int headCap) =>
        Read(path, fileCap, headCap, whole: false);

    private (string Status, byte[]? Data) Read(string path, long fileCap, int limit, bool whole)
    {
        var (status, handle) = OpenRegular(path, fileCap);
        if (handle is null) return (status, null);
        using (handle)
        {
            try
            {
                var buffer = new byte[(int)Math.Min(limit + 1L, RandomAccess.GetLength(handle) + 1)];
                var total = 0;
                while (true)
                {
                    if (total == buffer.Length)
                    {
                        if (buffer.Length > limit)
                        {
                            if (whole) return ("unreadable", null);
                            break;
                        }
                        Array.Resize(ref buffer, (int)Math.Min(limit + 1L, buffer.Length * 2L));
                    }
                    var read = RandomAccess.Read(handle, buffer.AsSpan(total), total);
                    if (read == 0) break;
                    total += read;
                    if (total > limit)
                    {
                        if (whole) return ("unreadable", null);
                        total = limit;
                        break;
                    }
                }
                return ("read", buffer.AsSpan(0, Math.Min(total, limit)).ToArray());
            }
            catch
            {
                return ("unreadable", null);
            }
        }
    }
}
