using System.Globalization;

namespace Patched.Shared.BackupStatus;

/// <summary>
/// PAT-680: pure, platform-neutral helpers for Windows backup status. Lives in Shared
/// (no Windows TFM) so it can be covered by Shared.Tests running on macOS CI without
/// any registry/file-system dependency — mirrors the HardwareHealthLogic split (PAT-685).
/// BackupCollector (Service) calls these helpers after obtaining raw values from the
/// registry / File History config file.
/// </summary>
internal static class BackupStatusLogic
{
    /// <summary>Threshold, in days, above which a last backup is flagged stale.</summary>
    public const int StaleThresholdDays = 7;

    /// <summary>
    /// Days between <paramref name="lastBackupAt"/> and <paramref name="now"/>, clamped to
    /// 0. Collection can start slightly before a backup module runs, so a backup that
    /// completes during the same run can be fractionally "later" than <paramref name="now"/>
    /// on some code paths — flooring a small negative span would otherwise read as -1 days
    /// ago (same clamp rationale as the macOS collector, PAT-679).
    /// </summary>
    public static int ComputeDaysAgo(DateTimeOffset lastBackupAt, DateTimeOffset now)
        => Math.Max(0, (now - lastBackupAt).Days);

    /// <summary>True when <paramref name="daysAgo"/> exceeds <see cref="StaleThresholdDays"/>.</summary>
    public static bool IsStale(int daysAgo) => daysAgo > StaleThresholdDays;

    /// <summary>
    /// Parses a raw LastBackupTime value pulled from the File History Config file.
    /// Accepts either an ISO-8601 timestamp or a Win32 FILETIME (100-ns ticks since
    /// 1601-01-01 UTC, as returned by <c>DateTimeOffset.ToFileTime</c>) — both forms
    /// appear across Windows versions/config formats. Returns false (and leaves
    /// <paramref name="value"/> at its default) for anything unparseable rather than
    /// throwing, so a malformed or unexpected config file degrades to "not detected"
    /// instead of aborting collection.
    /// </summary>
    public static bool TryParseLastBackupTime(string? raw, out DateTimeOffset value)
    {
        value = default;
        if (string.IsNullOrWhiteSpace(raw))
            return false;

        raw = raw.Trim();

        if (DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out value))
            return true;

        if (long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var fileTime)
            && fileTime > 0)
        {
            try
            {
                value = DateTimeOffset.FromFileTime(fileTime);
                return true;
            }
            catch (ArgumentOutOfRangeException)
            {
                value = default;
                return false;
            }
        }

        return false;
    }
}
