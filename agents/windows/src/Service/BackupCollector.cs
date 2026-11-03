using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Patched.Shared.BackupStatus;
using Patched.Shared.Contract;

namespace Patched.Service;

/// <summary>
/// PAT-680: Windows backup status — File History, OneDrive sync, and third-party
/// tools (Acronis / Veeam / Backup Exec) detected by service-key presence.
/// Parity with the macOS backup.sh collector (PAT-679): same precedence order
/// (a real, timestamped backup mechanism beats presence-only signals, which beat
/// sync-only), same payload shape, same "never throw" contract — every collection
/// path is wrapped so a single failure never aborts the wider inventory run.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class BackupCollector
{
    // Separator allows up to 6 non-alphanumeric chars (covers JSON-style
    // `"LastBackupTime": "..."` and key=value forms with padding around `=`);
    // the value class includes `+` and lowercase `t` so an offset like
    // "2026-07-08t09:15:00+02:00" isn't silently truncated at the `+`, which
    // would otherwise get misread as bare UTC and skew last_backup_days_ago.
    private static readonly Regex LastBackupTimeRegex = new(
        @"LastBackupTime[^0-9A-Za-z]{0,6}([0-9TtZz:+\-\.]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Known third-party backup service names -> backup_type id (sc query equivalent).</summary>
    private static readonly (string ServiceName, string BackupType)[] ThirdPartyServices =
    [
        ("AcronisManagedMachineService", "acronis"),
        ("AcronisAgent",                 "acronis"),
        ("VeeamBackupSvc",               "veeam"),
        ("VeeamEndpointBackupSvc",       "veeam"),
        ("BackupExecManagementService",  "backup_exec"),
        ("beserver",                     "backup_exec"),
    ];

    private static readonly string[] IgnoredSids = ["S-1-5-18", "S-1-5-19", "S-1-5-20"];

    private readonly ILogger<BackupCollector> _log;

    public BackupCollector(ILogger<BackupCollector> log) => _log = log;

    public InventoryBackupStatus Collect()
    {
        try
        {
            return CollectInner();
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "BackupCollector: collection failed — emitting no-backup status");
            return NoBackup("Backup status collection failed");
        }
    }

    private InventoryBackupStatus CollectInner()
    {
        var now = DateTimeOffset.UtcNow;

        // Enumerated once and shared: File History and OneDrive both need the
        // loaded-user-SID list, and HKEY_USERS enumeration is otherwise repeated
        // on every run where File History doesn't resolve (the common case).
        var loadedSids = EnumerateLoadedUserSids().ToList();

        return TryCollectFileHistory(now, loadedSids)
            ?? TryCollectThirdParty()
            ?? TryCollectOneDrive(loadedSids)
            ?? NoBackup("No backup solution detected");
    }

    // -------------------------------------------------------------------------
    // File History
    // -------------------------------------------------------------------------

    /// <summary>
    /// File History is a per-user feature: HKLM SystemRestore presence just gates
    /// whether the feature exists on this Windows build at all, while the actual
    /// last-backup timestamp lives in each loaded user's Config file. Returns null
    /// (not "no backup") when no loaded user has a parseable timestamp, so the
    /// caller falls through to the next detection method — most Windows hosts don't
    /// have File History configured, and that must not read as an error.
    /// </summary>
    private InventoryBackupStatus? TryCollectFileHistory(DateTimeOffset now, IReadOnlyList<string> loadedSids)
    {
        if (!SystemRestoreFeaturePresent())
            return null;

        foreach (var profilePath in ResolveProfilePaths(loadedSids))
        {
            var configPath = Path.Combine(profilePath,
                "AppData", "Local", "Microsoft", "Windows", "FileHistory", "Configuration", "Config");

            string content;
            try
            {
                if (!File.Exists(configPath)) continue;
                content = File.ReadAllText(configPath);
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "BackupCollector: could not read File History config at {Path}", configPath);
                continue;
            }

            var match = LastBackupTimeRegex.Match(content);
            if (!match.Success) continue;

            if (!BackupStatusLogic.TryParseLastBackupTime(match.Groups[1].Value, out var lastBackupAt))
                continue;

            var daysAgo = BackupStatusLogic.ComputeDaysAgo(lastBackupAt, now);
            return new InventoryBackupStatus
            {
                HasBackup         = true,
                BackupType        = "file_history",
                LastBackupAt      = lastBackupAt.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                LastBackupDaysAgo = daysAgo,
                Stale             = BackupStatusLogic.IsStale(daysAgo),
                SyncOnly          = false,
            };
        }

        return null;
    }

    private bool SystemRestoreFeaturePresent()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore");
            return key is not null;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "BackupCollector: SystemRestore key read failed");
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Third-party: Acronis / Veeam / Backup Exec
    // -------------------------------------------------------------------------

    /// <summary>
    /// Presence-only detection via service-key existence under
    /// SYSTEM\CurrentControlSet\Services (same registry-presence approach as
    /// SecurityToolDetector). None of these products expose a single reliable
    /// command for "last completed backup" the way tmutil does on macOS, so —
    /// mirroring the macOS third-party decision (PAT-679) — last_backup_at stays
    /// null rather than guessing from vendor-specific log formats.
    /// </summary>
    private InventoryBackupStatus? TryCollectThirdParty()
    {
        foreach (var (serviceName, backupType) in ThirdPartyServices)
        {
            if (!ServiceKeyExists(serviceName)) continue;

            return new InventoryBackupStatus
            {
                HasBackup  = true,
                BackupType = backupType,
                Notes      = $"{backupType} detected; last backup timestamp not available",
            };
        }

        return null;
    }

    private bool ServiceKeyExists(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{serviceName}");
            return key is not null;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "BackupCollector: service key read failed for {Service}", serviceName);
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // OneDrive
    // -------------------------------------------------------------------------

    /// <summary>
    /// OneDrive is sync, not backup (design decision carried over from PAT-679) —
    /// presence-only check against each loaded user's Business1 account hive.
    /// </summary>
    private InventoryBackupStatus? TryCollectOneDrive(IReadOnlyList<string> loadedSids)
    {
        foreach (var sid in loadedSids)
        {
            try
            {
                using var key = Registry.Users.OpenSubKey(
                    $@"{sid}\SOFTWARE\Microsoft\OneDrive\Accounts\Business1");
                if (key?.GetValue("LastUpdated") is null) continue;

                return new InventoryBackupStatus
                {
                    HasBackup  = false,
                    BackupType = "onedrive_sync",
                    SyncOnly   = true,
                    Notes      = "OneDrive sync detected; sync is not a substitute for backup",
                };
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "BackupCollector: OneDrive registry read failed for {Sid}", sid);
            }
        }

        return null;
    }

    // -------------------------------------------------------------------------
    // Loaded user enumeration
    // -------------------------------------------------------------------------

    /// <summary>
    /// SIDs currently loaded under HKEY_USERS — i.e. users with an active session.
    /// The service runs as LocalSystem, so per-user hives (the HKCU the ticket's
    /// registry paths refer to) are only reachable this way, not via
    /// Registry.CurrentUser, which would resolve to LocalSystem's own hive.
    /// Well-known system SIDs and the "_Classes"/".DEFAULT" companion keys are
    /// filtered out — they're not real user sessions.
    /// </summary>
    private IEnumerable<string> EnumerateLoadedUserSids()
    {
        string[] names;
        try
        {
            names = Registry.Users.GetSubKeyNames();
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "BackupCollector: could not enumerate HKEY_USERS");
            yield break;
        }

        foreach (var name in names)
        {
            if (name.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
            if (name.Equals(".DEFAULT", StringComparison.OrdinalIgnoreCase)) continue;
            if (IgnoredSids.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;
            yield return name;
        }
    }

    /// <summary>Resolves each loaded user SID to its profile directory via HKLM ProfileList.</summary>
    private IEnumerable<string> ResolveProfilePaths(IReadOnlyList<string> loadedSids)
    {
        foreach (var sid in loadedSids)
        {
            string? profilePath = null;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
                profilePath = key?.GetValue("ProfileImagePath")?.ToString();
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "BackupCollector: ProfileList read failed for {Sid}", sid);
            }

            if (!string.IsNullOrEmpty(profilePath))
                yield return profilePath;
        }
    }

    private static InventoryBackupStatus NoBackup(string notes) => new()
    {
        HasBackup = false,
        Notes     = notes,
    };
}
