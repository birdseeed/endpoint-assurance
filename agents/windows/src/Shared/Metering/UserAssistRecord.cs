namespace Patched.Shared.Metering;

/// <summary>
/// Parses a single UserAssist <c>Count</c> value into a <see cref="UserAssistUsage"/>.
///
/// Win7+ layout (72-byte struct): run count is a DWORD at offset 4; the last-run
/// time is a FILETIME (8 bytes) at offset 60 (0x3C). The legacy XP layout (16 bytes)
/// carried the count at offset 4 (with a +5 bias) and the FILETIME at offset 8 — we
/// tolerate it defensively. The value name is the ROT13-encoded executable path.
/// </summary>
public static class UserAssistRecord
{
    private const int ModernRunCountOffset = 4;
    private const int ModernFiletimeOffset = 60;
    private const int LegacyFiletimeOffset = 8;

    /// <summary>
    /// Decode + parse one entry. Returns null for session/aggregate rows
    /// (UEME_CTLSESSION and the UEME_* counters) or unparseable data.
    /// </summary>
    public static UserAssistUsage? TryParse(string rot13Name, byte[]? data)
    {
        if (string.IsNullOrEmpty(rot13Name)) return null;

        string path = Rot13.Decode(rot13Name);
        // Session/aggregate bookkeeping rows are not application launches.
        if (path.StartsWith("UEME_", StringComparison.OrdinalIgnoreCase)) return null;

        if (data is null || data.Length < 16) return null;

        bool modern = data.Length >= ModernFiletimeOffset + 8;

        int runCount = BitConverter.ToInt32(data, ModernRunCountOffset);
        if (!modern && runCount > 5) runCount -= 5;     // legacy XP bias
        if (runCount < 0) runCount = 0;

        int ftOffset = modern ? ModernFiletimeOffset : LegacyFiletimeOffset;
        DateTimeOffset? lastUsed = null;
        if (data.Length >= ftOffset + 8)
        {
            long ft = BitConverter.ToInt64(data, ftOffset);
            lastUsed = FileTimeToUtc(ft);
        }

        return new UserAssistUsage { Path = path, RunCount = runCount, LastUsed = lastUsed };
    }

    /// <summary>FILETIME (100ns ticks since 1601-01-01 UTC) → DateTimeOffset, or null.</summary>
    public static DateTimeOffset? FileTimeToUtc(long fileTime)
    {
        // 0 = never run; negative / out-of-range = corrupt. FromFileTimeUtc throws on those.
        if (fileTime <= 0) return null;
        try
        {
            return new DateTimeOffset(DateTime.FromFileTimeUtc(fileTime), TimeSpan.Zero);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }
}
