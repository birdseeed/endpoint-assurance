using System.Text;
using System.Text.RegularExpressions;

namespace Patched.Shared.InstallationEvidence;

// What one HKLM Uninstall entry says about where its files are. Every value is a hint an
// installer wrote, never an authoritative identity, so ExecutableResolver only accepts one
// that is unambiguous and inside a machine-wide install root. The init-only members were
// added by PAT-2129; an entry without them resolves exactly as PAT-2116 did.
internal sealed record UninstallLocation(int Index, string? DisplayIcon, string? InstallLocation)
{
    internal string? DisplayName { get; init; }
    internal string? Publisher { get; init; }
    internal string? UninstallString { get; init; }
    // The entry is a WiX Burn bundle registration (BundleProviderKey is set).
    internal bool BurnBundle { get; init; }
    // The ARP subkey name, when the entry says WindowsInstaller=1 and the name is a GUID.
    internal string? MsiProductCode { get; init; }
}

internal sealed record ResolutionRoots(string WindowsDirectory, IReadOnlyList<string> ProgramFilesRoots);

// executable_resolution on the wire. A method names how an executable was tied to the row;
// a reason (PAT-2129) says why none was. Every value fits the platform's
// observed_executable_resolution CHECK (migration 0188): ^[a-z][a-z0-9_]{0,63}$.
internal static class ExecutableResolutions
{
    internal const string ReviewedTarget = "reviewed_target";
    internal const string DisplayIcon = "display_icon";
    internal const string InstallLocationSingleExe = "install_location_single_exe";
    internal const string InstallLocationNamedExe = "install_location_named_exe";
    internal const string UninstallDirectoryNamedExe = "uninstall_directory_named_exe";
    internal const string MsiComponentSingleExe = "msi_component_single_exe";
    internal const string MsiComponentNamedExe = "msi_component_named_exe";

    // No executable, and none expected: a known runtime or SDK bundle (see NotApplicable).
    internal const string NotApplicable = "not_applicable";
    internal const string NoHint = "unresolved_no_hint";
    internal const string Ambiguous = "unresolved_ambiguous";
    internal const string NotFound = "unresolved_not_found";
    internal const string OutsideRoots = "unresolved_outside_roots";
    internal const string ListingUnavailable = "unresolved_listing_unavailable";
    internal const string RegistryUnavailable = "unresolved_registry_unavailable";
    // Resolution never ran for the row: a collection failure, budget, limit or reviewed-
    // target outcome decided it first. The row's errors say which.
    internal const string NotAttempted = "unresolved_not_attempted";

    private static readonly Regex Code = new("^[a-z][a-z0-9_]{0,63}$", RegexOptions.CultureInvariant);
    internal static bool IsValidCode(string? value) => value is not null && Code.IsMatch(value);
}

internal sealed record ExecutableResolution(int Index, string? InstallPath, string? ExecutablePath, string? Method, string? Error)
{
    internal bool Resolved => ExecutablePath is not null;
    // Why nothing was resolved, as sent in executable_resolution. Null when resolved.
    internal string? Reason { get; init; }
    // executable_resolution for this row: the method, else the reason.
    internal string Code => Method ?? Reason ?? ExecutableResolutions.NoHint;

    internal static ExecutableResolution Failed(int index, string error, string reason) =>
        new(index, null, null, null, error) { Reason = reason };
}

// PAT-2116 / PAT-2129: resolve an installed app's main executable from its Uninstall entry,
// in a bounded and defensible way, or say why not. The rules, in order:
//
//   1. DisplayIcon, when it names an .exe (quotes and a trailing ",<icon index>" removed)
//      that is a safe local path strictly inside a Program Files root, not under the
//      Windows directory, not uninstaller-named, and, when InstallLocation is also usable,
//      inside InstallLocation. A DisplayIcon that is not inside a present InstallLocation is
//      not trusted as this install's file and falls through.
//   2. InstallLocation, when it is a safe local directory strictly inside a Program Files
//      root and not under the Windows directory:
//      a. its top level holds exactly one candidate .exe: install_location_single_exe;
//      b. else the first of its top level, cmd\ and bin\ that holds exactly one candidate
//         whose name matches the product name: install_location_named_exe.
//   3. With no InstallLocation at all, the directory of UninstallString's file, when that
//      directory is strictly inside a Program Files root: 2b only, never 2a
//      (uninstall_directory_named_exe). WIN-STAGING's UTM Guest Tools shows why: its
//      uninstaller's directory holds exactly one other exe, a bundled vc_redist.arm64.exe.
//   4. For a Windows Installer product, the component key paths the product registered
//      (read by the helper from its cached package): exactly one candidate, all of them
//      inside the roots (msi_component_single_exe), else exactly one whose name matches
//      the product name (msi_component_named_exe).
//   5. Otherwise unresolved with a reason: not_applicable for a known runtime or SDK bundle
//      that installs no executable of its own, else listing_unavailable, ambiguous,
//      not_found, outside_roots or no_hint, in that order of precedence.
//
// A candidate is an .exe that is not uninstaller-named and not a bundled redistributable.
// A name match compares letters and digits only, case-insensitively, after dropping
// trailing version, architecture and channel qualifiers from the display name
// ("PowerToys (Preview) ARM64" matches PowerToys.exe; "QEMU guest agent" does not match
// qemu-ga.exe, and stays unresolved). There is no fuzzy matching and no recursion past
// cmd\ and bin\.
//
// Finally, one executable claimed by more than one entry in the same scan is ambiguous for
// all of them (a plug-in or bootstrapper whose icon is the host application's exe must not
// borrow the host's signer). Nothing here guesses: every failure is reported unknown.
//
// The roots matter: HKLM Uninstall values are admin-written, but a directory outside
// Program Files may be user-writable, and the helper reads the file as LocalSystem. The
// Windows directory is excluded because shared OS binaries (msiexec.exe, rundll32.exe,
// %WINDIR%\Installer\{GUID}\*.exe icon stubs) would lend Microsoft's signature to
// third-party entries.
internal static class ExecutableResolver
{
    // An executable list this long is ambiguous anyway; the lister may stop early, and a
    // list that reached the bound is never used to claim a unique match.
    internal const int MaximumListedExecutables = 64;
    internal const int MaximumTargets = 1024;

    // Conventional sub-folders searched for a name-matched executable, after the top level.
    // Git for Windows puts cmd\ (not bin\) on PATH, so cmd\ comes first.
    internal static readonly string[] NamedExecutableFolders = ["", "cmd", "bin"];

    internal static IReadOnlyList<ExecutableResolution> ResolveAll(IReadOnlyList<UninstallLocation> entries,
        ResolutionRoots roots, Func<string, IReadOnlyList<string>?> listExecutables, Action<int>? onEntry = null,
        Func<string, IReadOnlyList<string>?>? msiComponentExecutables = null)
    {
        var resolved = entries.Select(e =>
        {
            onEntry?.Invoke(e.Index);
            return Resolve(e, roots, listExecutables, msiComponentExecutables);
        }).ToArray();
        var shared = resolved.Where(r => r.Resolved)
            .GroupBy(r => r.ExecutablePath!, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return resolved.Select(r => r.Resolved && shared.Contains(r.ExecutablePath!)
            ? ExecutableResolution.Failed(r.Index, "executable_ambiguous", ExecutableResolutions.Ambiguous) : r).ToArray();
    }

    // What the rules saw when none of them resolved, for the reason code.
    private sealed class Outcome
    {
        internal bool Outside;
        internal bool Ambiguous;
        internal bool NotFound;
        internal bool ListingFailed;
    }

    internal static ExecutableResolution Resolve(UninstallLocation entry, ResolutionRoots roots,
        Func<string, IReadOnlyList<string>?> listExecutables, Func<string, IReadOnlyList<string>?>? msiComponentExecutables = null)
    {
        var seen = new Outcome();
        var product = NormaliseProductName(entry.DisplayName);

        string? installDir = null;
        if (NormaliseDirectory(entry.InstallLocation) is { } location)
        {
            if (IsInsideRoots(location, roots)) installDir = location;
            else seen.Outside = true;
        }

        // 1. DisplayIcon.
        if (ParseDisplayIcon(entry.DisplayIcon) is { } icon && IsExecutableName(icon))
        {
            if (!IsInsideRoots(icon, roots)) seen.Outside = true;
            else if (!IsUninstaller(FileNameOf(icon)) &&
                (installDir is null || IsStrictlyInside(icon, installDir)))
                return new(entry.Index, installDir ?? ParentOf(icon), icon, ExecutableResolutions.DisplayIcon, null);
        }

        // 2. InstallLocation.
        if (installDir is not null)
        {
            var names = List(listExecutables, installDir);
            if (names is null)
            {
                seen.ListingFailed = true;
            }
            else
            {
                var candidates = Candidates(names);
                // A listing that reached the bound may hide a second candidate.
                var complete = names.Count < MaximumListedExecutables;
                if (candidates.Length == 1 && complete &&
                    Accept(entry.Index, installDir, installDir + "\\" + candidates[0],
                        ExecutableResolutions.InstallLocationSingleExe, seen) is { } single)
                    return single;
                if (candidates.Length > 1 || !complete) seen.Ambiguous = true;
                else seen.NotFound = true;
                if (FindNamed(installDir, names, product, listExecutables, seen) is { } named &&
                    Accept(entry.Index, installDir, named, ExecutableResolutions.InstallLocationNamedExe, seen) is { } byName)
                    return byName;
            }
        }
        // 3. The uninstaller's directory, name-matched only.
        else if (string.IsNullOrWhiteSpace(entry.InstallLocation) &&
            UninstallDirectory(entry.UninstallString) is { } uninstallDir)
        {
            if (!IsInsideRoots(uninstallDir, roots)) seen.Outside = true;
            else
            {
                var names = List(listExecutables, uninstallDir);
                if (names is null) seen.ListingFailed = true;
                else
                {
                    if (FindNamed(uninstallDir, names, product, listExecutables, seen) is { } named &&
                        Accept(entry.Index, uninstallDir, named, ExecutableResolutions.UninstallDirectoryNamedExe, seen) is { } byName)
                        return byName;
                    seen.NotFound = true;
                }
            }
        }

        // 4. Windows Installer component key paths.
        if (entry.MsiProductCode is { } productCode && msiComponentExecutables is not null)
        {
            if (FromMsiComponents(entry.Index, productCode, installDir, product, roots, msiComponentExecutables, seen) is { } msi)
                return msi;
        }

        // 5. Nothing resolved.
        if (NotApplicable(entry, installDir))
            return ExecutableResolution.Failed(entry.Index, "executable_not_applicable", ExecutableResolutions.NotApplicable);
        if (seen.ListingFailed)
            return ExecutableResolution.Failed(entry.Index, "executable_listing_unavailable", ExecutableResolutions.ListingUnavailable);
        if (seen.Ambiguous)
            return ExecutableResolution.Failed(entry.Index, "executable_ambiguous", ExecutableResolutions.Ambiguous);
        if (seen.NotFound)
            return ExecutableResolution.Failed(entry.Index, "executable_not_found", ExecutableResolutions.NotFound);
        return seen.Outside
            ? ExecutableResolution.Failed(entry.Index, "executable_outside_supported_roots", ExecutableResolutions.OutsideRoots)
            : ExecutableResolution.Failed(entry.Index, "executable_unresolved", ExecutableResolutions.NoHint);
    }

    private static IReadOnlyList<string>? List(Func<string, IReadOnlyList<string>?> listExecutables, string directory)
    {
        try { return listExecutables(directory); }
        catch { return null; }
    }

    private static ExecutableResolution? Accept(int index, string installDir, string path, string method, Outcome seen)
    {
        if (InstallationEvidenceCatalogue.SafePath(path))
            return new(index, installDir, path, method, null);
        seen.NotFound = true;
        return null;
    }

    // The candidate file names in one listing: plain names only, .exe, not an uninstaller,
    // not a bundled redistributable. Distinct, case-insensitively.
    private static string[] Candidates(IEnumerable<string> names) => names
        .Where(n => n.Length > 0 && n.IndexOfAny(['\\', '/', ':']) < 0 && IsExecutableName(n) && IsCandidateName(n))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

    // Rule 2b/3: the first of the top level, cmd\ and bin\ with exactly one name-matched
    // candidate. A folder whose listing reached the bound or failed is never used to claim
    // a unique match; a second match in the same folder is ambiguous and stops the search.
    private static string? FindNamed(string directory, IReadOnlyList<string> topLevel, string? product,
        Func<string, IReadOnlyList<string>?> listExecutables, Outcome seen)
    {
        if (product is null) return null;
        foreach (var folder in NamedExecutableFolders)
        {
            var path = folder.Length == 0 ? directory : directory + "\\" + folder;
            var names = folder.Length == 0 ? topLevel : List(listExecutables, path);
            // A missing cmd\ or bin\ lists as null too: nothing there to match.
            if (names is null) continue;
            var matches = Candidates(names).Where(n => NameMatches(n, product)).ToArray();
            if (matches.Length == 0) continue;
            if (matches.Length > 1 || names.Count >= MaximumListedExecutables)
            {
                seen.Ambiguous = true;
                return null;
            }
            return path + "\\" + matches[0];
        }
        return null;
    }

    private static ExecutableResolution? FromMsiComponents(int index, string productCode, string? installDir, string? product,
        ResolutionRoots roots, Func<string, IReadOnlyList<string>?> msiComponentExecutables, Outcome seen)
    {
        IReadOnlyList<string>? paths;
        try { paths = msiComponentExecutables(productCode); }
        catch { paths = null; }
        if (paths is null) { seen.ListingFailed = true; return null; }
        if (paths.Count >= MaximumListedExecutables) { seen.Ambiguous = true; return null; }

        var exes = paths.Where(p => p is not null && IsExecutableName(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var usable = exes.Where(p => InstallationEvidenceCatalogue.SafePath(p) && IsInsideRoots(p, roots) &&
                (installDir is null || IsStrictlyInside(p, installDir)))
            .ToArray();
        if (usable.Length < exes.Length) seen.Outside = true;
        var candidates = usable.Where(p => IsCandidateName(FileNameOf(p))).ToArray();
        if (candidates.Length == 0) { seen.NotFound = true; return null; }

        if (candidates.Length == 1 && usable.Length == exes.Length)
            return new(index, installDir ?? ParentOf(candidates[0]), candidates[0], ExecutableResolutions.MsiComponentSingleExe, null);
        var named = product is null ? [] : candidates.Where(p => NameMatches(FileNameOf(p), product)).ToArray();
        if (named.Length == 1)
            return new(index, installDir ?? ParentOf(named[0]), named[0], ExecutableResolutions.MsiComponentNamedExe, null);
        seen.Ambiguous = true;
        return null;
    }

    // Known runtime and SDK bundles that install no executable of their own: a Burn bundle
    // published by Microsoft Corporation with no InstallLocation, named exactly as the
    // Visual C++ Redistributable or the .NET SDK bundles name themselves. Their files are
    // DLLs in System32 (the VC++ runtime MSI) or tools under dotnet\sdk\<version>\, and
    // dotnet.exe belongs to the separate .NET Host package. Evidence from WIN-STAGING
    // (PAT-2129); a new pattern needs the same evidence, never a guess. The outcome is only
    // ever a reason code: it never attaches a signature to anything.
    private static readonly Regex[] NotApplicableNames =
    [
        new(@"^Microsoft Visual C\+\+ \d{4}(-\d{4})? Redistributable \((x86|x64|arm64)\) - \d+(\.\d+){1,3}$",
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase),
        new(@"^Microsoft \.NET SDK \d+\.\d+\.\d+ \((x86|x64|arm64)\)$",
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase),
    ];

    internal static bool NotApplicable(UninstallLocation entry, string? installDir) =>
        entry.BurnBundle && installDir is null && string.IsNullOrWhiteSpace(entry.InstallLocation) &&
        string.Equals(entry.Publisher?.Trim(), "Microsoft Corporation", StringComparison.Ordinal) &&
        entry.DisplayName is { Length: > 0 and <= 256 } name &&
        NotApplicableNames.Any(pattern => pattern.IsMatch(name.Trim()));

    // "C:\App\app.exe", C:\App\app.exe,0 and "C:\App\app.exe",-101 all name C:\App\app.exe.
    // A comma not followed by a bare integer is part of the path. Anything that is not then
    // a safe local absolute path is rejected (environment variables are expanded by the
    // registry read, never here).
    internal static string? ParseDisplayIcon(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw.Length > 1024) return null;
        var value = raw.Trim();
        if (value.StartsWith('"'))
        {
            var close = value.IndexOf('"', 1);
            if (close < 0) return null;
            var rest = value[(close + 1)..].Trim();
            if (rest.Length > 0 && !IsIconIndex(rest)) return null;
            value = value[1..close];
        }
        else
        {
            var comma = value.LastIndexOf(',');
            if (comma > 0 && IsIconIndex(value[comma..])) value = value[..comma].TrimEnd();
        }
        return InstallationEvidenceCatalogue.SafePath(value) ? value : null;
    }

    // The directory holding UninstallString's file: the quoted path when it is quoted (with
    // or without an .exe extension, as NSIS writes "...\Uninstall utm-guest-tools"), else
    // the text up to the first ".exe" followed by the end or a space. "MsiExec.exe /X{...}"
    // is not an absolute path and yields nothing. The directory must itself be safe.
    internal static string? UninstallDirectory(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw.Length > 1024) return null;
        var value = raw.Trim();
        string path;
        if (value.StartsWith('"'))
        {
            var close = value.IndexOf('"', 1);
            if (close < 0) return null;
            path = value[1..close];
        }
        else
        {
            var exe = value.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (exe < 0) return null;
            var end = exe + 4;
            if (end < value.Length && value[end] != ' ') return null;
            path = value[..end];
        }
        if (!InstallationEvidenceCatalogue.SafePath(path)) return null;
        var slash = path.LastIndexOf('\\');
        if (slash < 3) return null;
        var directory = path[..slash];
        return InstallationEvidenceCatalogue.SafePath(directory) ? directory : null;
    }

    private static bool IsIconIndex(string suffix)
    {
        if (!suffix.StartsWith(',')) return false;
        var number = suffix[1..].Trim();
        if (number.StartsWith('-')) number = number[1..];
        return number.Length is > 0 and <= 10 && number.All(char.IsAsciiDigit);
    }

    internal static string? NormaliseDirectory(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw.Length > 1024) return null;
        var value = raw.Trim();
        if (value.Length >= 2 && value.StartsWith('"') && value.EndsWith('"')) value = value[1..^1].Trim();
        value = value.TrimEnd('\\');
        return value.Length > 3 && InstallationEvidenceCatalogue.SafePath(value) ? value : null;
    }

    // Trailing qualifiers dropped from a display name before it is matched to a file name:
    // a version ("2.5", "v1.2.3"), an architecture or a release channel, bare or in
    // parentheses. A closed list, so "Foo (Plugin)" keeps its qualifier and never matches
    // its host's foo.exe.
    private static readonly HashSet<string> Qualifiers = new(StringComparer.OrdinalIgnoreCase)
    {
        "x64", "x86", "arm64", "amd64", "aarch64", "64-bit", "32-bit", "64bit", "32bit", "win64", "win32",
        "preview", "beta",
    };

    private static readonly Regex VersionToken = new(@"^v?\d+(\.\d+)*$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    // The letters and digits of a display name after trailing qualifiers are dropped,
    // lower-cased; null when fewer than two remain.
    internal static string? NormaliseProductName(string? displayName)
    {
        if (string.IsNullOrWhiteSpace(displayName) || displayName.Length > 256) return null;
        var tokens = displayName.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).ToList();
        while (tokens.Count > 1)
        {
            var last = tokens[^1];
            var inner = last.Length > 2 && last.StartsWith('(') && last.EndsWith(')') ? last[1..^1] : last;
            if (!Qualifiers.Contains(inner) && !VersionToken.IsMatch(inner)) break;
            tokens.RemoveAt(tokens.Count - 1);
        }
        var name = LettersAndDigits(string.Join(' ', tokens));
        return name.Length >= 2 ? name : null;
    }

    internal static bool NameMatches(string fileName, string product)
    {
        var stem = fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? fileName[..^4] : fileName;
        return LettersAndDigits(stem) == product;
    }

    private static string LettersAndDigits(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var c in value)
            if (char.IsLetterOrDigit(c)) builder.Append(char.ToLowerInvariant(c));
        return builder.ToString();
    }

    // Inside a Program Files root (never the root itself) and not under the Windows directory.
    internal static bool IsInsideRoots(string path, ResolutionRoots roots) =>
        !IsStrictlyInside(path, roots.WindowsDirectory) &&
        !string.Equals(path.TrimEnd('\\'), roots.WindowsDirectory.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) &&
        roots.ProgramFilesRoots.Any(root => root.Length >= 4 && IsStrictlyInside(path, root));

    internal static bool IsStrictlyInside(string path, string directory)
    {
        var prefix = directory.TrimEnd('\\') + "\\";
        return path.Length > prefix.Length && path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsExecutableName(string path) => path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);

    private static bool IsCandidateName(string fileName) => !IsUninstaller(fileName) && !IsBundledRedistributable(fileName);

    // Inno Setup (unins000.exe), NSIS (uninst.exe, Uninstall.exe) and similar. The
    // uninstaller is the installer's artefact, often signed differently or not at all,
    // and never the application being inventoried.
    internal static bool IsUninstaller(string fileName)
    {
        var name = fileName.ToLowerInvariant();
        return name.StartsWith("unins", StringComparison.Ordinal) || name.Contains("uninstall", StringComparison.Ordinal);
    }

    // A redistributable installer shipped beside an app (vc_redist.arm64.exe in UTM Guest
    // Tools, vcredist_x64.exe elsewhere) is Microsoft's file, never the app's.
    internal static bool IsBundledRedistributable(string fileName) =>
        fileName.Contains("redist", StringComparison.OrdinalIgnoreCase);

    // Windows separators on every host: Path.GetFileName does not split on '\\' off Windows.
    private static string ParentOf(string path) => path[..path.LastIndexOf('\\')];
    private static string FileNameOf(string path) => path[(path.LastIndexOf('\\') + 1)..];
}
