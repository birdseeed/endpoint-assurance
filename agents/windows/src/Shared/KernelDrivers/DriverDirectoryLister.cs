namespace Patched.Shared.KernelDrivers;

/// <summary>
/// PAT-2263: lists the *.sys files directly in one directory (%SystemRoot%\System32\drivers).
/// Reparse points are deliberately listed, not skipped: skipping one would silently drop a
/// driver, so it is listed and the opener refuses it, which records it unhashed. Directories
/// are not files and are skipped. Bounded: a directory with more than
/// <paramref name="maxEntries"/> matching names is unreadable, never a truncated list taken
/// as complete.
/// </summary>
internal static class DriverDirectoryLister
{
    public const int DefaultMaxEntries = 20_000;

    public static DriverDirectoryListing List(string directory, int maxEntries = DefaultMaxEntries)
    {
        try
        {
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = false,
                IgnoreInaccessible = false,
                ReturnSpecialDirectories = false,
                MatchType = MatchType.Simple,
                MatchCasing = MatchCasing.CaseInsensitive,
                AttributesToSkip = FileAttributes.Directory,
            };
            var files = new List<string>();
            foreach (var file in Directory.EnumerateFiles(directory, "*.sys", options))
            {
                // EnumerateFiles also matches *.sysx under the Windows 8.3 rules; keep exact.
                if (!file.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)) continue;
                files.Add(file);
                if (files.Count > maxEntries) return DriverDirectoryListing.Unreadable;
            }
            files.Sort(StringComparer.OrdinalIgnoreCase);
            return new DriverDirectoryListing(false, files);
        }
        catch (Exception)
        {
            return DriverDirectoryListing.Unreadable;
        }
    }
}
