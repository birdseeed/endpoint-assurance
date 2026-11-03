using System.Runtime.Versioning;
using Microsoft.Win32;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Patched.Shared.OsUpdate;

namespace Patched.Service;

/// <summary>
/// Detects pending OS updates via the Windows Update Agent (WUA) COM API and
/// delegates state-computation to <see cref="OsUpdateStateEngine"/> which mirrors
/// the macOS patched-update.sh OS UPDATE AWARENESS block (PAT-273 parity).
///
/// IMPORTANT: detection only.  This class never installs or forces an update.
/// COM calls are made via late binding (dynamic) to avoid shipping a COM interop
/// assembly.  If WUA is unavailable (access denied, COM failure, etc.) the method
/// returns state=unknown and logs the exception -- it does NOT propagate.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class OsUpdateChecker
{
    public static string OsUpdateDeepLink => "ms-settings:windowsupdate";

    private readonly ILogger<OsUpdateChecker> _log;

    public OsUpdateChecker(ILogger<OsUpdateChecker> log) => _log = log;

    public OsUpdateInfo? ComputeOsUpdate(OsUpdatePolicy policy, int deferralCount)
    {
        var now = DateTimeOffset.UtcNow;
        var (installedOs, installedBuild) = GetInstalledOs();
        if (string.IsNullOrEmpty(installedOs))
        {
            _log.LogWarning("OsUpdateChecker: could not determine installed OS version - returning unknown");
            return OsUpdateStateEngine.MakeUnknown(now);
        }
        WuaQueryResult wua;
        try { wua = QueryWua(); }
        catch (Exception ex)
        {
            _log.LogError(ex, "OsUpdateChecker: WUA query failed - returning unknown");
            return OsUpdateStateEngine.MakeUnknown(now, installedOs);
        }
        return OsUpdateStateEngine.ComputeFromInputs(new OsUpdateInputs
        {
            InstalledOs        = installedOs,
            InstalledBuild     = installedBuild,
            PendingOsUpdate    = wua.PendingOsUpdate,
            LatestOs           = wua.LatestOs,
            SecurityRelevant   = wua.SecurityRelevant,
            ActivelyExploited  = wua.ActivelyExploited,
            ReleaseDate        = wua.ReleaseDate,
            Policy             = policy,
            DeferralCount      = deferralCount,
            Now                = now,
        });
    }

    // PAT-906: the pending os_defer count (deferralCount above) comes from
    // TriggerWatcher.CountOsDeferrals. It used to live here as a separate raw
    // scan of the trigger directory; that scan was first unvalidated (any local
    // user could inflate the count feeding OsUpdateStateEngine's escalation
    // policy) and then, once validated, still starvable (its per-pass ceiling
    // was consumed before validation and rejected decoys were never deleted, so
    // 2048+ planted invalid files sorting ahead of a real os_defer trigger hid
    // it from every call, permanently). Counting now runs TriggerWatcher's
    // single hardened walk so the two paths cannot drift apart again.

    private WuaQueryResult QueryWua()
    {
        dynamic updateSession = Activator.CreateInstance(
            Type.GetTypeFromProgID("Microsoft.Update.Session")
            ?? throw new InvalidOperationException("Microsoft.Update.Session ProgID not found"))!;
        dynamic searcher = updateSession.CreateUpdateSearcher();
        dynamic results  = searcher.Search("IsInstalled=0 AND IsHidden=0 AND Type='Software' AND BrowseOnly=0");
        bool pendingOsUpdate = false, securityRelevant = false, activelyExploited = false;
        string? latestOs = null;
        DateTimeOffset? releaseDate = null;
        var updates = results.Updates;
        for (int i = 0; i < updates.Count; i++)
        {
            dynamic update = updates.Item(i);
            string title = (string)(update.Title ?? "");
            if (!IsWindowsOsUpdate(title, update)) continue;
            pendingOsUpdate = true;
            string severity = "";
            try { severity = (string)(update.MsrcSeverity ?? ""); } catch { }
            if (!string.IsNullOrEmpty(severity)) securityRelevant = true;
            if (string.Equals(severity, "Critical", StringComparison.OrdinalIgnoreCase))
                activelyExploited = true;
            try
            {
                DateTime ldc = (DateTime)(update.LastDeploymentChangeTime);
                if (ldc != DateTime.MinValue)
                {
                    var c = new DateTimeOffset(ldc, TimeSpan.Zero);
                    if (!releaseDate.HasValue || c < releaseDate.Value) releaseDate = c;
                }
            }
            catch { }
            if (latestOs is null) latestOs = ParseLatestOsFromTitle(title);
        }
        return new WuaQueryResult { PendingOsUpdate=pendingOsUpdate, SecurityRelevant=securityRelevant,
            ActivelyExploited=activelyExploited, LatestOs=latestOs, ReleaseDate=releaseDate };
    }

    private static bool IsWindowsOsUpdate(string title, dynamic update)
    {
        if (title.Contains("Windows 11", StringComparison.OrdinalIgnoreCase)
         || title.Contains("Windows 10", StringComparison.OrdinalIgnoreCase)
         || title.Contains("Feature Update", StringComparison.OrdinalIgnoreCase))
            return true;
        try
        {
            var categories = update.Categories;
            for (int j = 0; j < categories.Count; j++)
            {
                dynamic cat = categories.Item(j);
                string catName = (string)(cat.Name ?? "");
                if (catName.Contains("Windows", StringComparison.OrdinalIgnoreCase)
                 && (catName.Contains("Update", StringComparison.OrdinalIgnoreCase)
                  || catName.Contains("Upgrade", StringComparison.OrdinalIgnoreCase)))
                    return true;
            }
        }
        catch { }
        return false;
    }

    internal static string? ParseLatestOsFromTitle(string title)
    {
        var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            {"24H2",26100}, {"23H2",22631}, {"22H2",22621}, {"21H2",22000},
        };
        foreach (var (code, build) in map)
            if (title.Contains(code, StringComparison.OrdinalIgnoreCase))
                return $"10.0.{build}.0";
        return null;
    }

    private (string version, int build) GetInstalledOs()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key is null) return ("", 0);
            var currentBuild = key.GetValue("CurrentBuild")?.ToString() ?? "";
            var ubr = key.GetValue("UBR");
            if (!int.TryParse(currentBuild, out var buildInt)) return ("", 0);
            var ubrInt = ubr is int u ? u : 0;
            return ($"10.0.{buildInt}.{ubrInt}", buildInt);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "OsUpdateChecker: could not read Windows version from registry");
            return ("", 0);
        }
    }
}

internal sealed record WuaQueryResult
{
    public bool            PendingOsUpdate   { get; init; }
    public bool            SecurityRelevant  { get; init; }
    public bool            ActivelyExploited { get; init; }
    public string?         LatestOs          { get; init; }
    public DateTimeOffset? ReleaseDate       { get; init; }
}
