using System.Text;
using System.Text.RegularExpressions;
using Patched.Shared.Contract;

namespace Patched.Shared.Apps;

// Read-only boundary: null means absent; denied/failed reads throw. The production
// adapter owns native handles. No load-hive or write operation exists on this seam.
internal interface IAppRegistryKey : IDisposable
{
    IEnumerable<string> GetSubKeyNames();
    IAppRegistryKey? OpenSubKey(string path);
    object? GetValue(string name);
}
internal interface IAppRegistryReader
{
    IAppRegistryKey OpenMachine();
    IAppRegistryKey OpenUsers();
    string? ResolveAccountName(string sid);
    // The profile directory registered for the SID, or null when it is not known.
    // Defaulted so a reader without profile metadata simply sends no home.
    string? ResolveProfilePath(string sid) => null;
    bool Is64BitOperatingSystem { get; }
}

internal static class RegistryAppCollection
{
    internal const string NativePath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    internal const string WowPath = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

    internal static AppCollectionResult Scan(IAppRegistryReader reader,
        Func<string, string?, string, string> normalizeVersion,
        Action<Exception>? onFailure = null)
    {
        var machineResult = AppCollectionLogic.Run(() =>
        {
            using var machine = reader.OpenMachine();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            return new[] { NativePath, WowPath }.Select(path => ReadSource(machine, path,
                path == WowPath && !reader.Is64BitOperatingSystem, seen, normalizeVersion, onFailure)).ToArray();
        }, onFailure);
        var rows = machineResult.Apps.ToList();
        var states = new Dictionary<string, string>(StringComparer.Ordinal);
        var seenByUser = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        // Every profile path seen for an account; null marks a SID with none. home
        // is sent only when all of an account's loaded SIDs agree on one path.
        var homes = new Dictionary<string, HashSet<string?>>(StringComparer.Ordinal);
        try
        {
            using var users = reader.OpenUsers();
            foreach (var sid in users.GetSubKeyNames())
            {
                if (!Regex.IsMatch(sid, @"\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z", RegexOptions.CultureInvariant))
                    continue;
                string account;
                try { account = reader.ResolveAccountName(sid) ?? sid; }
                catch { account = sid; }
                account = account.Trim();
                // Same bounds as the platform; never truncate two identities together.
                if (account.Length == 0 || account.EnumerateRunes().Count() > 128 || account.Any(char.IsControl))
                {
                    Report(onFailure, new IOException("Per-user account identity is invalid; scope withheld"));
                    continue;
                }
                if (!seenByUser.TryGetValue(account, out var seen))
                    seenByUser[account] = seen = new(StringComparer.OrdinalIgnoreCase);
                if (!homes.TryGetValue(account, out var accountHomes))
                    homes[account] = accountHomes = new(StringComparer.Ordinal);
                accountHomes.Add(ProfilePath(reader, sid));
                var state = AppCollectionStatus.Partial;
                try
                {
                    // Only a currently loaded hive grants authority. A hive disappearing
                    // between enumeration and open is a failed read, never empty success.
                    using var hive = users.OpenSubKey(sid) ?? throw new IOException("Loaded user hive became unavailable");
                    var sources = new[] { NativePath, WowPath }.Select(path => ReadSource(hive, path,
                        absentIsEmpty: true, seen, (_, _, observedVersion) => observedVersion, onFailure)).ToArray();
                    rows.AddRange(sources.SelectMany(source => source.Apps).Select(app => app with { UserAccount = account }));
                    if (sources.All(source => source.Readable && source.Skipped == 0)) state = AppCollectionStatus.Complete;
                }
                catch (Exception ex) { Report(onFailure, ex); }
                // Several loaded SIDs may translate to one account; any failure wins.
                states[account] = states.GetValueOrDefault(account) == AppCollectionStatus.Partial
                    ? AppCollectionStatus.Partial : state;
            }
        }
        catch (Exception ex)
        {
            // Incomplete HKU enumeration might hide a second SID for an observed
            // account. Keep rows but withhold every previously collected authority.
            foreach (var account in states.Keys.ToArray()) states[account] = AppCollectionStatus.Partial;
            // The same hidden SID could carry a second profile path.
            homes.Clear();
            Report(onFailure, ex);
        }
        return AppCollectionResult.Create(rows, machineResult.Status, machineResult.Skipped,
            machineResult.UnreadableSources) with
        {
            Users = states.Select(pair => new InventoryAppUserStatus
                { UserAccount = pair.Key, CollectionStatus = pair.Value, Home = UnambiguousHome(homes, pair.Key) }).ToArray(),
        };
    }

    private static string? UnambiguousHome(Dictionary<string, HashSet<string?>> homes, string account) =>
        homes.TryGetValue(account, out var paths) && paths.Count == 1 ? paths.Single() : null;

    // Metadata only: a profile path that cannot be read or is not a clean absolute
    // path is "not known", never a failure of the user's inventory.
    private static string? ProfilePath(IAppRegistryReader reader, string sid)
    {
        string? path;
        try { path = reader.ResolveProfilePath(sid); }
        catch { return null; }
        if (string.IsNullOrWhiteSpace(path) || path != path.Trim() || path.Length > 1024 ||
            path.Any(char.IsControl) || path.Contains('%')) return null;
        path = path.TrimEnd('\\');
        return path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\' ? path : null;
    }

    private static void Report(Action<Exception>? callback, Exception error)
    {
        try { callback?.Invoke(error); } catch { /* reporting cannot strengthen authority */ }
    }

    private static AppSourceResult ReadSource(IAppRegistryKey hive, string path, bool absentIsEmpty,
        HashSet<string> seen, Func<string, string?, string, string> normalizeVersion,
        Action<Exception>? onFailure)
    {
        IAppRegistryKey? uninstall = null;
        try
        {
            return AppCollectionLogic.ReadSource(path,
                () => { uninstall = hive.OpenSubKey(path); return uninstall?.GetSubKeyNames(); },
                keyName => ReadEntry(uninstall!, keyName, path == WowPath, seen, normalizeVersion),
                absentIsEmpty, onFailure, (_, ex) => onFailure?.Invoke(ex));
        }
        finally { uninstall?.Dispose(); }
    }

    private static InventoryApp? ReadEntry(IAppRegistryKey uninstall, string keyName, bool is32Bit,
        HashSet<string> seen, Func<string, string?, string, string> normalizeVersion)
    {
        using var key = uninstall.OpenSubKey(keyName)
            ?? throw new IOException("Listed application key could not be opened");
        var name = key.GetValue("DisplayName")?.ToString();
        var version = key.GetValue("DisplayVersion")?.ToString();
        var publisher = key.GetValue("Publisher")?.ToString();
        if (string.IsNullOrWhiteSpace(publisher)) publisher = null;
        if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(version)) return null;
        if (key.GetValue("SystemComponent") is int systemComponent && systemComponent == 1) return null;
        version = normalizeVersion(name, publisher, version);
        if (!seen.Add($"{name}|{version}")) return null;
        return new() { Name = name, Version = version, Identifier = keyName, Publisher = publisher,
            Architecture = is32Bit ? "x86" : "x86_64" };
    }
}
