using System.Text.RegularExpressions;

namespace Patched.Shared.Metering;

/// <summary>Conservative, read-only correlation. Absence of a record never proves non-use.</summary>
public static class MeteringMatcher
{
    // Closed list: captured service/runtime icons and conventional installer icons.
    // Do not turn this into a substring classifier for arbitrary product names.
    private static readonly HashSet<string> NonAppExecutables = new(StringComparer.OrdinalIgnoreCase)
    {
        "officeclicktorun.exe", "officec2rclient.exe", "msedgewebview2.exe",
        "patched.service.exe", "uninstall.exe", "unins000.exe", "setup.exe",
        "vc_redist.x64.exe", "vc_redist.x86.exe",
    };
    private static readonly Dictionary<string, string> OfficeIds = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Microsoft.Office.WINWORD.EXE.15"] = "winword.exe",
        ["Microsoft.Office.OUTLOOK.EXE.15"] = "outlook.exe",
    };

    // These are the exact product and App Paths shape observed on WINDOWS11.
    // A language pack, extensibility component or unrelated Office16 path is not the suite.
    public static IReadOnlyList<string> BindOfficeExecutables(string identifier, string? installLocation,
        IEnumerable<string> appPaths)
    {
        string? root = Normalize(installLocation);
        if (!identifier.Equals("O365ProPlusRetail - en-us", StringComparison.OrdinalIgnoreCase) || root is null ||
            !Regex.IsMatch(root, @"^[a-z]:\\program files(?: \(x86\))?\\microsoft office$")) return [];
        return appPaths.Select(Normalize).Where(p => p is not null && OfficeIds.Values.Any(exe =>
                p == root + @"\root\office16\" + exe))
            .Select(p => p!).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public static IReadOnlyDictionary<string, AppUsage> Match(
        IEnumerable<UserAssistUsage> usages, IEnumerable<MeteredApp> apps, bool sourceAvailable = true)
    {
        // The two registry views can describe the same identity. Retain both
        // sets of hints, but count a matching observation only once for that identity.
        var appGroups = apps.GroupBy(a => a.Identifier, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.ToArray()).ToArray();
        var targets = appGroups.Select(group => group.SelectMany(Targets).Distinct().ToArray()).ToArray();
        // A missing or conflicting hint cannot borrow no-record authority from
        // whichever view happened to be enumerated first.
        var consistentTargets = appGroups.Select((group, i) => targets[i].Length > 0 &&
            group.All(app => new HashSet<string>(Targets(app), StringComparer.Ordinal).SetEquals(targets[i]))).ToArray();
        var observations = appGroups.Select(_ => new Dictionary<(int Hive, string Exe), UserAssistUsage>()).ToArray();
        var ambiguous = new HashSet<int>();

        foreach (var usage in usages)
        {
            if (string.IsNullOrWhiteSpace(usage.Path) || (usage.RunCount <= 0 && usage.LastUsed is null)) continue;
            string? direct = Executable(usage.Path);
            var matches = new List<(int Index, string Exe)>();
            for (int i = 0; i < appGroups.Length; i++)
            {
                var group = appGroups[i];
                var app = group[0];
                string? matched = null;
                if (direct is not null && targets[i].Length > 0)
                {
                    if (targets[i].Contains(direct)) matched = direct;
                    // Edge's ARP icon can name a versioned executable while
                    // UserAssist names its unversioned launcher, or vice versa.
                    // Only the same canonical installation root is equivalent.
                    if (app.Identifier.Equals("Microsoft Edge", StringComparison.OrdinalIgnoreCase) &&
                        EdgeInstallationRoot(direct) is { } edgeRoot)
                        matched = targets[i].FirstOrDefault(target => EdgeInstallationRoot(target) == edgeRoot) ?? matched;
                }
                else if (usage.Path.Equals("MSEdge", StringComparison.OrdinalIgnoreCase) &&
                    app.Identifier.Equals("Microsoft Edge", StringComparison.OrdinalIgnoreCase))
                {
                    matched = targets[i].FirstOrDefault(IsEdgeExecutable);
                }
                else if (OfficeIds.TryGetValue(usage.Path, out string? officeExe))
                {
                    matched = group.SelectMany(candidate => BindOfficeExecutables(candidate.Identifier,
                            candidate.InstallLocation, candidate.OfficeExePaths))
                        .FirstOrDefault(p => p.EndsWith("\\" + officeExe, StringComparison.Ordinal));
                }
                if (matched is not null) matches.Add((i, matched));
            }
            // An executable claimed by distinct inventory identities is ambiguous.
            if (matches.Count != 1)
            {
                foreach (var candidate in matches) ambiguous.Add(candidate.Index);
                continue;
            }
            var match = matches[0];
            var key = (usage.UserHive, match.Exe);
            if (observations[match.Index].TryGetValue(key, out var existing))
                observations[match.Index][key] = existing with
                {
                    RunCount = Math.Max(existing.RunCount, usage.RunCount),
                    LastUsed = Later(existing.LastUsed, usage.LastUsed),
                };
            else observations[match.Index][key] = usage;
        }

        var result = new Dictionary<string, AppUsage>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < appGroups.Length; i++)
        {
            var seen = observations[i].Values;
            string evidence = seen.Count > 0 ? MeteringEvidence.Recorded : !sourceAvailable ? MeteringEvidence.Unavailable :
                consistentTargets[i] && !ambiguous.Contains(i) ? MeteringEvidence.NoRecord : MeteringEvidence.Unmapped;
            // All-zero counts with a valid timestamp retain the timestamp, without inventing a count.
            long count = seen.Sum(u => (long)Math.Max(0, u.RunCount));
            result[appGroups[i][0].Identifier] = new(seen.Select(u => u.LastUsed).DefaultIfEmpty().Max(),
                seen.Count == 0 ? null : (int)Math.Min(count, int.MaxValue), evidence);
        }
        return result;
    }

    private static IEnumerable<string> Targets(MeteredApp app)
    {
        if (Executable(app.ExePath) is { } exe) yield return exe;
        foreach (var office in BindOfficeExecutables(app.Identifier, app.InstallLocation, app.OfficeExePaths))
            yield return office;
    }

    private static DateTimeOffset? Later(DateTimeOffset? a, DateTimeOffset? b) => a is null ? b : b is null || a >= b ? a : b;

    private static bool IsEdgeExecutable(string p) => EdgeInstallationRoot(p) is not null;

    private static string? EdgeInstallationRoot(string p)
    {
        var match = Regex.Match(p,
            @"^(?<root>[a-z]:\\program files(?: \(x86\))?\\microsoft\\edge\\application)\\(?:[0-9]+(?:\.[0-9]+){3}\\)?msedge\.exe$");
        return match.Success ? match.Groups["root"].Value : null;
    }

    private static string? Executable(string? value)
    {
        string? p = Normalize(value);
        if (p is null || !p.EndsWith(".exe", StringComparison.Ordinal) ||
            NonAppExecutables.Contains(p[(p.LastIndexOf('\\') + 1)..])) return null;
        return p;
    }

    private static string? Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        string p = value.Trim().Replace('/', '\\').TrimEnd('\\').ToLowerInvariant();
        if (p.Length < 4 || p[0] is < 'a' or > 'z' || p[1] != ':' || p[2] != '\\' ||
            p[3..].Contains(':') || p.Any(char.IsControl) || p.Contains('%') ||
            p.Split('\\').Any(part => part is "." or ".." or "")) return null;
        return p;
    }
}
