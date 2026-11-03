using System.Runtime.Versioning;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Patched.Shared.Apps;
using Patched.Shared.Contract;

namespace Patched.Service;

/// <summary>
/// Scans HKLM and every loaded real-user HKU Uninstall key for installed applications.
/// Covers both 64-bit and 32-bit (WOW6432Node) registrations.
/// Returns cross-platform InventoryApp records for the schema v3 apps array, with
/// collection_status.apps for machine rows and apps_users for each observed user.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class InstalledAppScanner
{
    private const string PatchedAgentDisplayName = "Patched Agent";
    private const string PatchedManufacturer     = "Patched";

    private static readonly Regex InformationalVersionPattern = new(
        @"\A(?<major>0|[1-9][0-9]{0,2})\.(?<minor>0|[1-9][0-9]{0,2})\.(?<patch>0|[1-9][0-9]{0,4})(?:\.(?<revision>[1-9][0-9]?))?\+[0-9A-Fa-f]{40}\z",
        RegexOptions.CultureInvariant);

    private readonly ILogger<InstalledAppScanner> _log;

    public InstalledAppScanner(ILogger<InstalledAppScanner> log) => _log = log;

    /// <summary>The rows only, for callers that do not report completeness.</summary>
    public IReadOnlyList<InventoryApp> Scan() => ScanWithStatus().Apps;

    /// <summary>
    /// PAT-2066: the rows and collection_status.apps from one scan (rules in
    /// <see cref="AppCollectionLogic"/>). Complete only when both HKLM Uninstall views were
    /// enumerated and every subkey read; a hive, key or value that throws or cannot be
    /// opened makes it partial instead of being dropped silently, and a scan that throws
    /// outright is unavailable for the machine scope. Loaded user hives have separate
    /// authority and rows; one user failure never degrades another scope. Never throws.
    /// </summary>
    public AppCollectionResult ScanWithStatus()
    {
        var result = RegistryAppCollection.Scan(new AppRegistryReader(_log),
            (name, publisher, version) => NormalizePatchedAgentVersion(name, publisher, version,
                IsPatchedAgentEntry(name, publisher) ? ReadRunningServiceInformationalVersion() : null),
            ex => _log.LogWarning(ex, "InstalledAppScanner: application source could not be read"));

        if (result.Status == AppCollectionStatus.Partial)
        {
            _log.LogWarning(
                "InstalledAppScanner: collection_status.apps=partial, skipped={Skipped} unreadable_sources={Sources}",
                result.Skipped, string.Join(",", result.UnreadableSources));
        }
        else if (result.Status == AppCollectionStatus.Unavailable)
        {
            _log.LogWarning(
                "InstalledAppScanner: collection_status.apps=unavailable, unreadable_sources={Sources}",
                string.Join(",", result.UnreadableSources));
        }

        _log.LogDebug("InstalledAppScanner: found {Count} installed apps, status={Status}",
            result.Apps.Count, result.Status);
        return result;
    }

    internal static string NormalizePatchedAgentVersion(
        string displayName,
        string? publisher,
        string displayVersion,
        string? informationalProductVersion)
    {
        if (!IsPatchedAgentEntry(displayName, publisher))
            return displayVersion;

        return SemanticReleaseFromInformationalVersion(informationalProductVersion) ?? displayVersion;
    }

    private static bool IsPatchedAgentEntry(string displayName, string? publisher) =>
        string.Equals(displayName, PatchedAgentDisplayName, StringComparison.Ordinal) &&
        string.Equals(publisher, PatchedManufacturer, StringComparison.Ordinal);

    private static string? ReadRunningServiceInformationalVersion()
    {
        try
        {
            var executablePath = Environment.ProcessPath;
            return string.IsNullOrWhiteSpace(executablePath)
                ? null
                : FileVersionInfo.GetVersionInfo(executablePath).ProductVersion;
        }
        catch
        {
            return null;
        }
    }

    internal static string? SemanticReleaseFromInformationalVersion(string? informationalProductVersion)
    {
        if (string.IsNullOrWhiteSpace(informationalProductVersion))
            return null;

        var match = InformationalVersionPattern.Match(informationalProductVersion);
        if (!match.Success)
            return null;

        var major = int.Parse(match.Groups["major"].Value);
        var minor = int.Parse(match.Groups["minor"].Value);
        var patch = int.Parse(match.Groups["patch"].Value);
        var revision = match.Groups["revision"];
        // The release resolver encodes beta revisions into the MSI patch field.
        // Three-part versions retain the pre-existing inventory acceptance bound.
        if (major > 253 || minor > 255 || patch > (revision.Success ? 654 : 65535))
            return null;

        return revision.Success
            ? $"{major}.{minor}.{patch}.{revision.Value}"
            : $"{major}.{minor}.{patch}";
    }
}
