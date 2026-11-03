using Patched.Shared.Apps;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-2066: platform-neutral tests for <see cref="AppCollectionLogic"/>. No registry: each
/// Uninstall key is a delegate, so every failure route runs on macOS CI. The Windows scanner
/// passes one source per HKLM view (64-bit, then WOW6432Node).
/// </summary>
public sealed class AppCollectionLogicTests
{
    private const string Hklm64 = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string Hklm32 = @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

    private static InventoryApp App(string id) => new() { Name = id, Version = "1.0", Identifier = id };

    // "skip:" entries are excluded by design (reader returns null); "bad:" entries throw.
    private static InventoryApp? Read(string key) => key switch
    {
        _ when key.StartsWith("skip:", StringComparison.Ordinal) => null,
        _ when key.StartsWith("bad:", StringComparison.Ordinal)  => throw new System.Security.SecurityException("denied"),
        _ => App(key),
    };

    private static AppSourceResult Source(string name, params string[] keys) =>
        AppCollectionLogic.ReadSource<string>(name, () => keys, Read);

    private static IEnumerable<string> ThrowsAfter(params string[] first)
    {
        foreach (var item in first)
            yield return item;
        throw new IOException("enumeration failed");
    }

    private static string[] Ids(AppCollectionResult r) => r.Apps.Select(a => a.Identifier).ToArray();

    [Fact]
    public void EveryHiveEnumerated_EveryKeyRead_IsComplete()
    {
        var result = AppCollectionLogic.Combine([Source(Hklm64, "A", "B"), Source(Hklm32, "C")]);

        Assert.Equal(AppCollectionStatus.Complete, result.Status);
        Assert.Equal(new[] { "A", "B", "C" }, Ids(result));
        Assert.Equal(0, result.Skipped);
        Assert.Empty(result.UnreadableSources);
    }

    [Fact]
    public void EmptyHives_ReadCleanly_AreComplete_WithEmptyList()
    {
        var result = AppCollectionLogic.Combine([Source(Hklm64), Source(Hklm32)]);

        Assert.Equal(AppCollectionStatus.Complete, result.Status);
        Assert.Empty(result.Apps);
    }

    [Fact]
    public void EntryExcludedByDesign_IsNotAFailure()
    {
        // No display name, a system component or a duplicate: scope, not a skipped read.
        var result = AppCollectionLogic.Combine([Source(Hklm64, "A", "skip:kb"), Source(Hklm32)]);

        Assert.Equal(AppCollectionStatus.Complete, result.Status);
        Assert.Equal(new[] { "A" }, Ids(result));
    }

    [Fact]
    public void KeyThatThrows_IsPartial_OtherRowsStillSent()
    {
        var skippedKeys = new List<string>();
        var bad = AppCollectionLogic.ReadSource<string>(Hklm64, () => ["A", "bad:locked", "B"], Read,
            onSkipped: (key, _) => skippedKeys.Add(key));
        var result = AppCollectionLogic.Combine([bad, Source(Hklm32, "C")]);

        Assert.Equal(AppCollectionStatus.Partial, result.Status);
        Assert.Equal(new[] { "A", "B", "C" }, Ids(result));
        Assert.Equal(1, result.Skipped);
        Assert.Equal(new[] { "bad:locked" }, skippedKeys);
    }

    [Fact]
    public void ValueReadThatThrows_IsPartial()
    {
        // The reader reads DisplayName, DisplayVersion and Publisher; any of them throwing
        // surfaces here as the read delegate throwing.
        var source = AppCollectionLogic.ReadSource<string>(Hklm64, () => ["A", "B"],
            key => key == "B" ? throw new IOException("value read failed") : App(key));

        var result = AppCollectionLogic.Combine([source, Source(Hklm32)]);
        Assert.Equal(AppCollectionStatus.Partial, result.Status);
        Assert.Equal(new[] { "A" }, Ids(result));
    }

    [Fact]
    public void HiveThatCannotBeOpened_IsPartial_OtherHiveStillSent()
    {
        Exception? logged = null;
        var denied = AppCollectionLogic.ReadSource<string>(Hklm32,
            () => throw new UnauthorizedAccessException("denied"), Read, onUnreadable: ex => logged = ex);

        var result = AppCollectionLogic.Combine([Source(Hklm64, "A"), denied]);

        Assert.Equal(AppCollectionStatus.Partial, result.Status);
        Assert.Equal(new[] { "A" }, Ids(result));
        Assert.Equal(new[] { Hklm32 }, result.UnreadableSources);
        Assert.IsType<UnauthorizedAccessException>(logged);
    }

    [Fact]
    public void HiveThatThrowsMidEnumeration_IsPartial_KeepsRowsAlreadyRead()
    {
        var failing = AppCollectionLogic.ReadSource<string>(Hklm64, () => ThrowsAfter("A"), Read);

        Assert.False(failing.Readable);
        var result = AppCollectionLogic.Combine([failing, Source(Hklm32, "C")]);
        Assert.Equal(AppCollectionStatus.Partial, result.Status);
        Assert.Equal(new[] { "A", "C" }, Ids(result));
    }

    [Fact]
    public void MissingHive_IsPartial_UnlessAbsenceIsExpected()
    {
        var missing = AppCollectionLogic.ReadSource<string>(Hklm32, () => null, Read);
        Assert.Equal(AppCollectionStatus.Partial, AppCollectionLogic.Combine([Source(Hklm64, "A"), missing]).Status);

        // The 32-bit view does not exist on a 32-bit OS: nothing was missed.
        var expected = AppCollectionLogic.ReadSource<string>(Hklm32, () => null, Read, absentIsEmpty: true);
        Assert.Equal(AppCollectionStatus.Complete, AppCollectionLogic.Combine([Source(Hklm64, "A"), expected]).Status);
    }

    [Fact]
    public void NoHiveReadable_IsUnavailable_WithEmptyList()
    {
        var a = AppCollectionLogic.ReadSource<string>(Hklm64, () => ThrowsAfter("A"), Read);
        var b = AppCollectionLogic.ReadSource<string>(Hklm32, () => throw new UnauthorizedAccessException(), Read);

        var result = AppCollectionLogic.Combine([a, b]);

        Assert.Equal(AppCollectionStatus.Unavailable, result.Status);
        Assert.Empty(result.Apps);
    }

    [Fact]
    public void WholeScanThrows_IsUnavailable_WithEmptyList()
    {
        Exception? logged = null;
        var result = AppCollectionLogic.Run(() => throw new InvalidOperationException("registry gone"),
            onUnavailable: ex => logged = ex);

        Assert.Equal(AppCollectionStatus.Unavailable, result.Status);
        Assert.Empty(result.Apps);
        Assert.IsType<InvalidOperationException>(logged);
    }

    [Fact]
    public void Run_CleanScan_IsComplete()
    {
        var result = AppCollectionLogic.Run(() => [Source(Hklm64, "A"), Source(Hklm32, "B")]);
        Assert.Equal(AppCollectionStatus.Complete, result.Status);
        Assert.Equal(new[] { "A", "B" }, Ids(result));
    }

    [Fact]
    public void ThrowingLogCallbacks_DoNotChangeTheOutcome()
    {
        var source = AppCollectionLogic.ReadSource<string>(Hklm64, () => ["A", "bad:x"], Read,
            onSkipped: (_, _) => throw new InvalidOperationException("logger broke"));
        var denied = AppCollectionLogic.ReadSource<string>(Hklm32, () => throw new IOException(), Read,
            onUnreadable: _ => throw new InvalidOperationException("logger broke"));

        var result = AppCollectionLogic.Combine([source, denied]);
        Assert.Equal(AppCollectionStatus.Partial, result.Status);
        Assert.Equal(new[] { "A" }, Ids(result));

        var failed = AppCollectionLogic.Run(() => throw new IOException(),
            onUnavailable: _ => throw new InvalidOperationException("logger broke"));
        Assert.Equal(AppCollectionStatus.Unavailable, failed.Status);
    }

    [Fact]
    public void WireValues_MatchThePlatformEnum_AndMacOs()
    {
        Assert.Equal("complete", AppCollectionStatus.Complete);
        Assert.Equal("partial", AppCollectionStatus.Partial);
        Assert.Equal("unavailable", AppCollectionStatus.Unavailable);
    }
}
