using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32;

namespace Patched.Service;

/// <summary>
/// Enumerates every real user profile registered under HKLM ProfileList
/// (S-1-5-21-* SIDs only — excludes LocalSystem/LocalService/NetworkService and
/// other well-known service SIDs), regardless of current session state, with each
/// SID translated to its DOMAIN\user / MACHINE\user account name via LSA.
///
/// Shared by the browser-extension inventory scanner (PAT-827) and the
/// profile-aware removal pass (PAT-829): both walk every on-disk profile, not just
/// loaded sessions, because extension state lives entirely on disk (manifest.json /
/// extensions.json / prefs) with no registry hive required. Restricting to loaded
/// sessions would silently under-report — and under-remove — across the estate.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WindowsUserProfiles
{
    /// <summary>One enumerated profile: its SID, on-disk root, and resolved account name.</summary>
    internal readonly record struct Profile(string Sid, string ProfilePath, string UserAccount);

    /// <summary>
    /// Yields each usable profile. <paramref name="log"/> receives debug diagnostics
    /// for unreadable ProfileList entries; enumeration never throws. UserAccount
    /// falls back to the raw SID when LSA translation fails (orphaned/deleted account).
    /// </summary>
    public static IEnumerable<Profile> Enumerate(ILogger log)
    {
        string[] sids;
        try
        {
            using var profileList = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            sids = profileList?.GetSubKeyNames() ?? Array.Empty<string>();
        }
        catch (Exception ex)
        {
            log.LogDebug(ex, "WindowsUserProfiles: could not enumerate ProfileList");
            yield break;
        }

        foreach (var sid in sids)
        {
            if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;

            string? profilePath = null;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
                profilePath = key?.GetValue("ProfileImagePath")?.ToString();
            }
            catch (Exception ex)
            {
                log.LogDebug(ex, "WindowsUserProfiles: ProfileList read failed for {Sid}", sid);
            }

            if (string.IsNullOrEmpty(profilePath) || !Directory.Exists(profilePath)) continue;

            yield return new Profile(sid, profilePath, ResolveAccountName(sid, log) ?? sid);
        }
    }

    /// <summary>
    /// PAT-2017: the same profiles as <see cref="Enumerate"/>, plus whether the list itself
    /// was read. <see cref="Enumerate"/> yields nothing when HKLM ProfileList cannot be
    /// opened, which is indistinguishable from "no users"; a collector whose empty result
    /// is evidence (absence requires authority, PAT-1710) needs the difference, so this
    /// returns null for an unreadable list instead of an empty one. A single SID whose
    /// ProfileImagePath cannot be read is counted in <c>Unreadable</c> rather than dropped
    /// silently.
    /// </summary>
    public static (IReadOnlyList<Profile> Profiles, int Unreadable)? Snapshot(ILogger log)
    {
        string[] sids;
        try
        {
            using var profileList = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (profileList is null) return null;
            sids = profileList.GetSubKeyNames();
        }
        catch (Exception ex)
        {
            log.LogDebug(ex, "WindowsUserProfiles: could not enumerate ProfileList");
            return null;
        }

        var profiles = new List<Profile>();
        var unreadable = 0;
        foreach (var sid in sids)
        {
            if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;
            string? profilePath;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
                profilePath = key?.GetValue("ProfileImagePath")?.ToString();
            }
            catch (Exception ex)
            {
                log.LogDebug(ex, "WindowsUserProfiles: ProfileList read failed for {Sid}", sid);
                unreadable++;
                continue;
            }
            if (string.IsNullOrEmpty(profilePath))
            {
                unreadable++;
                continue;
            }
            // A registered profile whose directory is gone is not a user to scan; the scan
            // itself tells a missing directory from an unreadable one.
            profiles.Add(new Profile(sid, profilePath, ResolveAccountName(sid, log) ?? sid));
        }
        return (profiles, unreadable);
    }

    internal static string? ResolveAccountName(string sid, ILogger log)
    {
        try
        {
            return new SecurityIdentifier(sid).Translate(typeof(NTAccount)) is NTAccount account
                ? account.Value
                : null;
        }
        catch (Exception ex)
        {
            log.LogDebug(ex, "WindowsUserProfiles: SID translation failed for {Sid}", sid);
            return null;
        }
    }
}
