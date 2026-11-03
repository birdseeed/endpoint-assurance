using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1066 P0 non-author-review: exercises AgentHealthStore's reparse-point
/// defence, mirroring <see cref="BrowserExtensionBlocklistEnforcerStateIoTests"/>'s
/// (PAT-1044) exact test shape for the analogous SaveState/LoadState checks — this
/// store's WriteAtomic/TryReadStore now follow that same pattern 1:1 (see
/// AgentHealthStore.cs's WriteAtomic/TryReadStore doc comments).
///
/// AgentHealthStore's storePathOverride constructor parameter (test-only, mirrors
/// BrowserExtensionBlocklistEnforcer's StateFilePath test seam) points every test
/// here at a scratch file instead of the real
/// %ProgramData%\Patched\agent-health.json.
///
/// The reparse-point tests do real Windows filesystem-security work (planting an
/// NTFS symlink) and only run meaningfully on Windows — the project's actual CI
/// gate, windows-build.yml, is windows-latest only. They skip (return early)
/// rather than run when not on Windows, matching
/// BrowserExtensionBlocklistEnforcerStateIoTests' convention. A symlink-creation
/// failure ON Windows (e.g. missing Developer Mode/elevation) is NOT swallowed as
/// a silent skip — see <see cref="CreateSymlinkOrFail"/>/
/// <see cref="CreateDirectorySymlinkOrFail"/> — for the same reason that
/// precedent gives: a catch-and-return would read as a normal xUnit PASS,
/// indistinguishable from the security check having actually run.
/// windows-latest GitHub-hosted runners run elevated by default, so this should
/// not fire in CI.
///
/// KNOWN GAP (pre-existing, carried forward from the PAT-1044 precedent, not
/// introduced here): these tests only construct the symlink reparse-point vehicle
/// (via File.CreateSymbolicLink / Directory.CreateSymbolicLink), not an NTFS
/// junction (IO_REPARSE_TAG_MOUNT_POINT) — no junction-creation helper exists
/// anywhere in this repo's test suite. AgentHealthStore.IsReparsePoint checks
/// FileAttributes.ReparsePoint, which is set uniformly for both tag types, so the
/// detection logic covers junctions; only the test construction does not exercise
/// that path. See BrowserExtensionBlocklistEnforcerStateIoTests' doc comment for
/// the full reasoning — left out of this diff as the same disclosed, pre-existing
/// scope boundary, not silently omitted.
/// </summary>
public sealed class AgentHealthStoreReparsePointTests : IDisposable
{
    private readonly string _root;
    private readonly string _storePath;

    public AgentHealthStoreReparsePointTests()
    {
        _root      = Path.Combine(Path.GetTempPath(), $"patched-agenthealth-test-{Guid.NewGuid():N}");
        _storePath = Path.Combine(_root, "agent-health.json");
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
                Directory.Delete(_root, recursive: true);
        }
        catch
        {
            // Best-effort cleanup; a leftover temp dir from a test run isn't worth failing over.
        }
    }

    private AgentHealthStore MakeStore() =>
        new(NullLogger<AgentHealthStore>.Instance, _storePath);

    /// <summary>
    /// Creates a file symlink, or fails the test loudly if the environment can't —
    /// same reasoning as BrowserExtensionBlocklistEnforcerStateIoTests.CreateSymlinkOrFail.
    /// </summary>
    private static void CreateSymlinkOrFail(string linkPath, string targetPath)
    {
        try
        {
            File.CreateSymbolicLink(linkPath, targetPath);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            Assert.Fail(
                $"Could not create the symlink precondition this test needs ({ex.GetType().Name}: " +
                $"{ex.Message}). windows-latest GitHub-hosted runners run elevated by default, so " +
                "this should not happen in CI — investigate the runner environment rather than " +
                "treating this as an inconclusive skip.");
        }
    }

    /// <summary>Directory-symlink counterpart to <see cref="CreateSymlinkOrFail"/> — same reasoning.</summary>
    private static void CreateDirectorySymlinkOrFail(string linkPath, string targetPath)
    {
        try
        {
            Directory.CreateSymbolicLink(linkPath, targetPath);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            Assert.Fail(
                $"Could not create the directory-symlink precondition this test needs " +
                $"({ex.GetType().Name}: {ex.Message}). windows-latest GitHub-hosted runners run " +
                "elevated by default, so this should not happen in CI — investigate the runner " +
                "environment rather than treating this as an inconclusive skip.");
        }
    }

    // -------------------------------------------------------------------------
    // Write side (WriteAtomic, exercised via RecordFailure)
    // -------------------------------------------------------------------------

    [Fact]
    public void RecordFailure_ReparsePointAtTmpPath_RefusesAndLeavesLinkUntouched()
    {
        if (!OperatingSystem.IsWindows()) return;

        Directory.CreateDirectory(_root);
        var target = Path.Combine(_root, "attacker-target.txt");
        File.WriteAllText(target, "attacker-controlled");

        var tmpPath = _storePath + ".tmp";
        CreateSymlinkOrFail(tmpPath, target);

        var store = MakeStore();
        var ex = Record.Exception(() =>
            store.RecordFailure("capability_missing", "sample_capability", "not_available"));

        Assert.Null(ex);

        // Refused: no store file was ever created at the real destination.
        Assert.False(File.Exists(_storePath));

        // The planted link itself must be untouched — still a reparse point,
        // still pointing at the original target, target content unmodified.
        Assert.True((File.GetAttributes(tmpPath) & FileAttributes.ReparsePoint) != 0);
        Assert.Equal("attacker-controlled", File.ReadAllText(target));
    }

    [Fact]
    public void RecordFailure_ReparsePointAtFinalPath_RefusesAndLeavesLinkUntouched()
    {
        if (!OperatingSystem.IsWindows()) return;

        Directory.CreateDirectory(_root);
        var target = Path.Combine(_root, "attacker-target-2.txt");
        File.WriteAllText(target, "attacker-controlled");

        CreateSymlinkOrFail(_storePath, target);

        var store = MakeStore();
        var ex = Record.Exception(() =>
            store.RecordFailure("capability_missing", "sample_capability", "not_available"));

        Assert.Null(ex);

        // Refused: the planted link at the final destination is still a reparse
        // point, still pointing at the original target, target content
        // unmodified — proves the move never happened.
        Assert.True((File.GetAttributes(_storePath) & FileAttributes.ReparsePoint) != 0);
        Assert.Equal("attacker-controlled", File.ReadAllText(target));

        // The freshly-written tmp file must not be left behind after the refusal.
        Assert.False(File.Exists(_storePath + ".tmp"));
    }

    [Fact]
    public void RecordFailure_ReparsePointAtContainingDirectory_RefusesAndLeavesLinkUntouched()
    {
        if (!OperatingSystem.IsWindows()) return;

        Directory.CreateDirectory(_root);
        var realTargetDir = Path.Combine(_root, "attacker-real-dir");
        Directory.CreateDirectory(realTargetDir);

        var linkedDir = Path.Combine(_root, "linked-state-dir");
        CreateDirectorySymlinkOrFail(linkedDir, realTargetDir);

        var storePathThroughLink = Path.Combine(linkedDir, "agent-health.json");
        var store = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, storePathThroughLink);

        var ex = Record.Exception(() =>
            store.RecordFailure("capability_missing", "sample_capability", "not_available"));

        Assert.Null(ex);

        // Refused before Directory.CreateDirectory, before the ".tmp" write,
        // before the move: nothing was ever written into the real target
        // directory the link points at.
        Assert.Empty(Directory.GetFileSystemEntries(realTargetDir));

        // The planted directory link itself must be untouched — still a reparse
        // point, still pointing at the same real target.
        Assert.True((File.GetAttributes(linkedDir) & FileAttributes.ReparsePoint) != 0);
    }

    // -------------------------------------------------------------------------
    // Read side (TryReadStore, exercised via BuildPayloadSection/RecordFailure).
    // A reparse point maps to Corrupt here, NOT "fresh empty" — see
    // AgentHealthStore.TryReadStore's doc comment for why this deliberately
    // differs from the PAT-1044 LoadState precedent.
    // -------------------------------------------------------------------------

    [Fact]
    public void BuildPayloadSection_ReparsePointAtFinalPath_ReturnsNull_NotFreshEmpty()
    {
        if (!OperatingSystem.IsWindows()) return;

        Directory.CreateDirectory(_root);
        var target = Path.Combine(_root, "attacker-target-3.txt");
        File.WriteAllText(target, "{\"Active\":{},\"EverSucceeded\":{}}");

        CreateSymlinkOrFail(_storePath, target);

        var store = MakeStore();
        var section = store.BuildPayloadSection();

        // Must be null (Corrupt / "no opinion"), never a non-null empty-degraded
        // section — that would be a false explicit all-clear read straight through
        // the planted link.
        Assert.Null(section);
    }

    [Fact]
    public void RecordFailure_ReparsePointAtFinalPathReadSide_DoesNotThrow_LeavesLinkUntouched()
    {
        if (!OperatingSystem.IsWindows()) return;

        Directory.CreateDirectory(_root);
        var target = Path.Combine(_root, "attacker-target-4.txt");
        File.WriteAllText(target, "{\"Active\":{},\"EverSucceeded\":{}}");

        CreateSymlinkOrFail(_storePath, target);

        var store = MakeStore();
        var ex = Record.Exception(() =>
            store.RecordFailure("capability_missing", "sample_capability", "not_available"));

        Assert.Null(ex);

        // Read refused as Corrupt before ever reaching a write — nothing was
        // ever attempted through the link, so it is still exactly the planted
        // reparse point, pointing at the original target.
        Assert.True((File.GetAttributes(_storePath) & FileAttributes.ReparsePoint) != 0);
        Assert.Equal("{\"Active\":{},\"EverSucceeded\":{}}", File.ReadAllText(target));
    }

    [Fact]
    public void BuildPayloadSection_ReparsePointAtContainingDirectory_ReturnsNull_NotFreshEmpty()
    {
        if (!OperatingSystem.IsWindows()) return;

        Directory.CreateDirectory(_root);
        var realTargetDir = Path.Combine(_root, "attacker-real-dir-2");
        Directory.CreateDirectory(realTargetDir);
        var plantedStoreFile = Path.Combine(realTargetDir, "agent-health.json");
        File.WriteAllText(plantedStoreFile, "{\"Active\":{},\"EverSucceeded\":{}}");

        var linkedDir = Path.Combine(_root, "linked-state-dir-2");
        CreateDirectorySymlinkOrFail(linkedDir, realTargetDir);

        var storePathThroughLink = Path.Combine(linkedDir, "agent-health.json");
        var store = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, storePathThroughLink);

        var section = store.BuildPayloadSection();

        // Refused before ever reaching the leaf file check — the
        // attacker-planted content behind the link must never be parsed, and
        // must never produce a "fresh empty" false all-clear either.
        Assert.Null(section);
    }
}
