namespace Patched.Shared.KernelDrivers;

/// <summary>
/// PAT-2263: turns a driver path as Windows records it (a service's ImagePath, or a loaded
/// module's name from the kernel's module list) into the one local drive-letter path the
/// collector will open, or null. Pure: <paramref name="systemRoot"/> is passed in.
///
/// Forms handled, case-insensitively: <c>\SystemRoot\...</c>; <c>System32\...</c> and any
/// other relative path (relative to %SystemRoot%, which is how the I/O manager reads a
/// relative ImagePath); <c>%SystemRoot%\...</c> and <c>%windir%\...</c>; <c>\??\C:\...</c> and
/// <c>\\?\C:\...</c>; <c>\Windows\...</c> (rooted, no drive: the system drive); <c>C:\...</c>;
/// and surrounding double quotes. A service with no ImagePath is
/// <c>%SystemRoot%\System32\drivers\&lt;service&gt;.sys</c>, the I/O manager's default.
///
/// Anything else is unsupported and gets null, never a guess: a UNC or device path, any other
/// environment variable, a relative path that climbs (<c>..</c>), a stream (<c>:</c> after the
/// drive), control characters, or over <see cref="Contract.KernelDriverBudget.MaxPathLength"/>.
/// The opener re-checks the path; this only decides what a path means.
/// </summary>
internal static class DriverPathResolver
{
    public static string? DefaultImagePath(string serviceName, string systemRoot) =>
        Resolve($@"\SystemRoot\System32\drivers\{serviceName}.sys", systemRoot);

    public static string? Resolve(string? raw, string systemRoot)
    {
        if (string.IsNullOrWhiteSpace(raw) || !IsDriveRoot(systemRoot)) return null;
        var path = raw.Trim();
        if (path.Length >= 2 && path[0] == '"' && path[^1] == '"') path = path[1..^1].Trim();
        if (path.Length == 0 || path.Any(char.IsControl) || path.Contains('/')) return null;
        var root = systemRoot.TrimEnd('\\');

        if (StartsWith(path, @"\??\") || StartsWith(path, @"\\?\")) path = path[4..];
        else if (StartsWith(path, @"\SystemRoot\")) path = root + path[@"\SystemRoot".Length..];
        else if (StartsWith(path, @"%SystemRoot%\")) path = root + path[@"%SystemRoot%".Length..];
        else if (StartsWith(path, @"%windir%\")) path = root + path[@"%windir%".Length..];
        else if (path.StartsWith(@"\\", StringComparison.Ordinal)) return null;
        else if (path[0] == '\\') path = root[..2] + path;
        else if (!(path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\'))
            path = root + "\\" + path;

        return IsLocalDrivePath(path) ? path : null;
    }

    /// <summary>A drive-letter absolute path with no dot segments, streams, wildcards or empty parts.</summary>
    internal static bool IsLocalDrivePath(string path)
    {
        if (path.Length < 4 || path.Length > Contract.KernelDriverBudget.MaxPathLength) return false;
        if (!char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\') return false;
        if (path.Any(char.IsControl) || path.Contains('/') || path[2..].Contains(':') || path.Contains('%')) return false;
        return path[3..].Split('\\').All(p =>
            p.Length > 0 && p is not "." and not ".." && !p.EndsWith(' ') && !p.EndsWith('.') &&
            p.IndexOfAny(['*', '?', '"', '<', '>', '|']) < 0);
    }

    private static bool IsDriveRoot(string systemRoot) =>
        IsLocalDrivePath(systemRoot.TrimEnd('\\'));

    private static bool StartsWith(string path, string prefix) =>
        path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
}
