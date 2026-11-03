using Patched.Shared.BackupStatus;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// Platform-neutral tests for <see cref="BackupStatusLogic"/>.
///
/// All tests call the static helpers directly — no registry, no file I/O.
/// <see cref="BackupStatusLogic"/> lives in Patched.Shared (net8.0, no Windows TFM)
/// so these run on any OS including macOS CI.
/// </summary>
public sealed class BackupStatusLogicTests
{
    // -------------------------------------------------------------------------
    // ComputeDaysAgo
    // -------------------------------------------------------------------------

    [Fact]
    public void ComputeDaysAgo_TwoDaysAgo_ReturnsTwo()
    {
        var now  = new DateTimeOffset(2026, 7, 10, 9, 0, 0, TimeSpan.Zero);
        var last = new DateTimeOffset(2026, 7, 8, 9, 0, 0, TimeSpan.Zero);
        Assert.Equal(2, BackupStatusLogic.ComputeDaysAgo(last, now));
    }

    [Fact]
    public void ComputeDaysAgo_SameInstant_ReturnsZero()
    {
        var now = new DateTimeOffset(2026, 7, 10, 9, 0, 0, TimeSpan.Zero);
        Assert.Equal(0, BackupStatusLogic.ComputeDaysAgo(now, now));
    }

    [Fact]
    public void ComputeDaysAgo_SlightlyInFuture_ClampsToZero()
    {
        // A backup completing fractionally after `now` was captured must not read
        // as -1 days ago (same clamp rationale as the macOS collector, PAT-679).
        var now  = new DateTimeOffset(2026, 7, 10, 9, 0, 0, TimeSpan.Zero);
        var last = now.AddMinutes(5);
        Assert.Equal(0, BackupStatusLogic.ComputeDaysAgo(last, now));
    }

    [Fact]
    public void ComputeDaysAgo_ExactlySevenDays_ReturnsSeven()
    {
        var now  = new DateTimeOffset(2026, 7, 10, 9, 0, 0, TimeSpan.Zero);
        var last = now.AddDays(-7);
        Assert.Equal(7, BackupStatusLogic.ComputeDaysAgo(last, now));
    }

    // -------------------------------------------------------------------------
    // IsStale
    // -------------------------------------------------------------------------

    [Fact]
    public void IsStale_SevenDays_ReturnsFalse()
    {
        // Boundary: exactly 7 days is still fresh per the ticket's ">7 days" rule.
        Assert.False(BackupStatusLogic.IsStale(7));
    }

    [Fact]
    public void IsStale_EightDays_ReturnsTrue()
    {
        Assert.True(BackupStatusLogic.IsStale(8));
    }

    [Fact]
    public void IsStale_Zero_ReturnsFalse()
    {
        Assert.False(BackupStatusLogic.IsStale(0));
    }

    [Fact]
    public void IsStale_ThirtyDays_ReturnsTrue()
    {
        Assert.True(BackupStatusLogic.IsStale(30));
    }

    // -------------------------------------------------------------------------
    // TryParseLastBackupTime
    // -------------------------------------------------------------------------

    [Fact]
    public void TryParseLastBackupTime_Null_ReturnsFalse()
    {
        Assert.False(BackupStatusLogic.TryParseLastBackupTime(null, out _));
    }

    [Fact]
    public void TryParseLastBackupTime_Empty_ReturnsFalse()
    {
        Assert.False(BackupStatusLogic.TryParseLastBackupTime("", out _));
    }

    [Fact]
    public void TryParseLastBackupTime_Whitespace_ReturnsFalse()
    {
        Assert.False(BackupStatusLogic.TryParseLastBackupTime("   ", out _));
    }

    [Fact]
    public void TryParseLastBackupTime_Garbage_ReturnsFalse()
    {
        Assert.False(BackupStatusLogic.TryParseLastBackupTime("not-a-date", out _));
    }

    [Fact]
    public void TryParseLastBackupTime_Iso8601Utc_Parses()
    {
        var ok = BackupStatusLogic.TryParseLastBackupTime("2026-07-08T09:15:00Z", out var value);
        Assert.True(ok);
        Assert.Equal(new DateTimeOffset(2026, 7, 8, 9, 15, 0, TimeSpan.Zero), value);
    }

    [Fact]
    public void TryParseLastBackupTime_Iso8601NoZone_AssumesUtc()
    {
        var ok = BackupStatusLogic.TryParseLastBackupTime("2026-07-08T09:15:00", out var value);
        Assert.True(ok);
        Assert.Equal(new DateTimeOffset(2026, 7, 8, 9, 15, 0, TimeSpan.Zero), value);
    }

    [Fact]
    public void TryParseLastBackupTime_WindowsFileTimeTicks_Parses()
    {
        // A Win32 FILETIME value (100-ns ticks since 1601-01-01 UTC) for
        // 2026-07-08T09:15:00Z, as produced by DateTimeOffset.ToFileTime().
        var expected = new DateTimeOffset(2026, 7, 8, 9, 15, 0, TimeSpan.Zero);
        var fileTime = expected.ToFileTime();

        var ok = BackupStatusLogic.TryParseLastBackupTime(fileTime.ToString(), out var value);
        Assert.True(ok);
        Assert.Equal(expected, value);
    }

    [Fact]
    public void TryParseLastBackupTime_ZeroTicks_ReturnsFalse()
    {
        Assert.False(BackupStatusLogic.TryParseLastBackupTime("0", out _));
    }

    [Fact]
    public void TryParseLastBackupTime_NegativeTicks_ReturnsFalse()
    {
        Assert.False(BackupStatusLogic.TryParseLastBackupTime("-100", out _));
    }

    [Fact]
    public void TryParseLastBackupTime_TrimsWhitespace()
    {
        var ok = BackupStatusLogic.TryParseLastBackupTime("  2026-07-08T09:15:00Z  ", out var value);
        Assert.True(ok);
        Assert.Equal(new DateTimeOffset(2026, 7, 8, 9, 15, 0, TimeSpan.Zero), value);
    }
}
