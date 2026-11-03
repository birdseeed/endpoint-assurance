using Microsoft.Extensions.Logging.Abstractions;
using Patched.Shared.BrowserExtensions;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1044: exercises the real SaveState/LoadState file-I/O path — the existing
/// <see cref="BrowserExtensionBlocklistEnforcerTests"/> subclass overrides both as
/// no-ops for its own dry-run tests, so it never touched real I/O at all.
///
/// <see cref="Patched.Shared.Paths.PathConstants.ExtensionBlocklistStateFile"/> is a
/// fixed <c>static readonly</c> under %ProgramData% with no seam to redirect it, so
/// this introduces <see cref="BrowserExtensionBlocklistEnforcer.StateFilePath"/> (a
/// virtual property, mirroring the existing internal-virtual seam already used for
/// <c>LoadState</c>/<c>SaveState</c>) that <see cref="RealIoTestEnforcer"/> overrides
/// to point at a scratch directory instead.
///
/// The reparse-point tests do real Windows filesystem-security work (planting an
/// NTFS symlink) and only run meaningfully on Windows — the project's actual CI gate,
/// windows-build.yml, is windows-latest only. They skip (return early) rather than
/// run when not on Windows, matching the existing convention in
/// SecureStagingDirectoryTests.cs. Unlike that precedent, though, a symlink-creation
/// failure ON Windows (e.g. missing Developer Mode/elevation) is NOT swallowed as a
/// second silent skip here — see <see cref="CreateSymlinkOrFail"/>/
/// <see cref="CreateDirectorySymlinkOrFail"/>: a non-author-review finding on this
/// same ticket pointed out that catch-and-return reads as a normal PASS in xUnit,
/// indistinguishable from the security check having actually run. windows-latest
/// GitHub-hosted runners run elevated by default, so this should not fire in CI; if it
/// ever does, it now fails loudly instead of silently certifying nothing was checked.
/// <see cref="SaveState_NoReparsePoint_RoundTrips"/> is plain file I/O and runs on any OS.
///
/// KNOWN GAP (pre-existing, not introduced here): these tests only construct the
/// symlink reparse-point vehicle (via <see cref="File.CreateSymbolicLink(string, string)"/>
/// / <see cref="Directory.CreateSymbolicLink(string, string)"/>), not an NTFS junction
/// (IO_REPARSE_TAG_MOUNT_POINT). No junction-creation helper exists anywhere in this
/// repo's test suite today — grepped `windows/tests/` for "junction"/"mklink"/
/// "CreateSymbolicLink" and found none — and the one existing reparse-point precedent,
/// <c>SecureStagingDirectoryTests.cs</c>, has the identical gap: its own comment claims
/// junctions and symlinks are equivalent test vehicles, but it too only ever constructs
/// a symlink. <see cref="BrowserExtensionBlocklistEnforcer.IsReparsePoint"/> checks
/// <see cref="FileAttributes.ReparsePoint"/>, which is set uniformly for both tag
/// types, so the detection logic covers junctions; only the test construction does not
/// exercise that path. Building a junction from C# requires either shelling out
/// (`mklink /J` / `cmd.exe`) or raw <c>DeviceIoControl</c> P/Invoke with
/// <c>FSCTL_SET_REPARSE_POINT</c> — a new piece of test infrastructure this repo has
/// never needed before. Left out of this diff as a design decision beyond a single
/// bug-fix ticket's scope; flagged here rather than silently mirrored.
/// </summary>
public sealed class BrowserExtensionBlocklistEnforcerStateIoTests : IDisposable
{
    private readonly string _root;
    private readonly string _stateFile;

    public BrowserExtensionBlocklistEnforcerStateIoTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"patched-extblocklist-test-{Guid.NewGuid():N}");
        _stateFile = Path.Combine(_root, "extension-blocklist-state.json");
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

    private sealed class RealIoTestEnforcer(string stateFilePath)
        : BrowserExtensionBlocklistEnforcer(NullLogger<BrowserExtensionBlocklistEnforcer>.Instance)
    {
        internal override string StateFilePath => stateFilePath;
    }

    private static ExtensionBlocklistState MakeState()
    {
        var state = new ExtensionBlocklistState();
        state.Browsers["chrome"] = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"];
        return state;
    }

    /// <summary>
    /// Creates a file symlink, or fails the test loudly if the environment can't. A
    /// non-author-review finding: silently returning here (as this test class used to)
    /// makes a real environment problem (missing Developer Mode/elevation on a Windows
    /// runner) read as a normal xUnit PASS — indistinguishable from the reparse-point
    /// check actually having been exercised. windows-latest GitHub-hosted runners run
    /// elevated by default, so this is expected to always succeed there; if it doesn't,
    /// that is itself worth knowing loudly, not swallowing.
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

    // Regression guard: the ordinary, no-reparse-point case must still save and load
    // correctly. Runs on any OS — plain file I/O, nothing Windows-specific.
    [Fact]
    public void SaveState_NoReparsePoint_RoundTrips()
    {
        var enforcer = new RealIoTestEnforcer(_stateFile);
        var state = MakeState();

        enforcer.SaveState(state);

        Assert.True(File.Exists(_stateFile));
        Assert.False(File.Exists(_stateFile + ".tmp")); // renamed away, not left behind

        var loaded = enforcer.LoadState();
        Assert.Equal(state.Browsers["chrome"], loaded.Browsers["chrome"]);
    }

    // PAT-1044 acceptance criterion: a reparse point pre-planted at the ".tmp"
    // intermediate path must cause SaveState to refuse outright and leave the
    // planted link untouched (not deleted, not written through).
    [Fact]
    public void SaveState_ReparsePointAtTmpPath_RefusesAndLeavesLinkUntouched()
    {
        if (!OperatingSystem.IsWindows()) return;

        Directory.CreateDirectory(_root);
        var target = Path.Combine(_root, "attacker-target.txt");
        File.WriteAllText(target, "attacker-controlled");

        var tmpPath = _stateFile + ".tmp";
        CreateSymlinkOrFail(tmpPath, target);

        var enforcer = new RealIoTestEnforcer(_stateFile);
        enforcer.SaveState(MakeState());

        // Refused: no state file was ever created at the real destination.
        Assert.False(File.Exists(_stateFile));

        // The planted link itself must be untouched — still a reparse point, still
        // pointing at the original target, target content unmodified.
        Assert.True((File.GetAttributes(tmpPath) & FileAttributes.ReparsePoint) != 0);
        Assert.Equal("attacker-controlled", File.ReadAllText(target));
    }

    // PAT-1044 acceptance criterion: a reparse point pre-planted at the FINAL
    // destination path must also cause SaveState to refuse the move, not just the
    // intermediate ".tmp" write.
    [Fact]
    public void SaveState_ReparsePointAtFinalPath_RefusesAndLeavesLinkUntouched()
    {
        if (!OperatingSystem.IsWindows()) return;

        Directory.CreateDirectory(_root);
        var target = Path.Combine(_root, "attacker-target-2.txt");
        File.WriteAllText(target, "attacker-controlled");

        CreateSymlinkOrFail(_stateFile, target);

        var enforcer = new RealIoTestEnforcer(_stateFile);
        enforcer.SaveState(MakeState());

        // Refused: the planted link at the final destination is still a reparse
        // point, still pointing at the original target, target content unmodified —
        // proves the move never happened.
        Assert.True((File.GetAttributes(_stateFile) & FileAttributes.ReparsePoint) != 0);
        Assert.Equal("attacker-controlled", File.ReadAllText(target));

        // The freshly-written tmp file must not be left behind after the refusal.
        Assert.False(File.Exists(_stateFile + ".tmp"));
    }

    // Lower-severity read-side check (PAT-1044): LoadState must not read through a
    // reparse point planted at the state-file path either.
    [Fact]
    public void LoadState_ReparsePointAtPath_ReturnsEmptyStateWithoutReadingThroughLink()
    {
        if (!OperatingSystem.IsWindows()) return;

        Directory.CreateDirectory(_root);
        var target = Path.Combine(_root, "attacker-target-3.txt");
        File.WriteAllText(target, "{\"browsers\":{\"firefox\":[\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"]}}");

        CreateSymlinkOrFail(_stateFile, target);

        var enforcer = new RealIoTestEnforcer(_stateFile);
        var loaded = enforcer.LoadState();

        Assert.Empty(loaded.Browsers);
    }

    // PAT-1044 non-author-review finding: checking only the leaf ".tmp"/final-path
    // files isn't sufficient — if the CONTAINING directory itself is a pre-planted
    // reparse point, Directory.CreateDirectory on an already-existing path is a no-op
    // from its perspective, and the write actually lands inside whatever that
    // directory points to. This plants the symlink one level up, at the directory,
    // not at the state file itself.
    [Fact]
    public void SaveState_ReparsePointAtContainingDirectory_RefusesAndLeavesLinkUntouched()
    {
        if (!OperatingSystem.IsWindows()) return;

        Directory.CreateDirectory(_root);
        var realTargetDir = Path.Combine(_root, "attacker-real-dir");
        Directory.CreateDirectory(realTargetDir);

        var linkedDir = Path.Combine(_root, "linked-state-dir");
        CreateDirectorySymlinkOrFail(linkedDir, realTargetDir);

        var stateFileThroughLink = Path.Combine(linkedDir, "extension-blocklist-state.json");
        var enforcer = new RealIoTestEnforcer(stateFileThroughLink);

        enforcer.SaveState(MakeState());

        // Refused before Directory.CreateDirectory, before the ".tmp" write, before
        // the move: nothing was ever written into the real target directory the link
        // points at.
        Assert.Empty(Directory.GetFileSystemEntries(realTargetDir));

        // The planted directory link itself must be untouched — still a reparse
        // point, still pointing at the same real target.
        Assert.True((File.GetAttributes(linkedDir) & FileAttributes.ReparsePoint) != 0);
    }

    // Read-side counterpart of the directory-level check.
    [Fact]
    public void LoadState_ReparsePointAtContainingDirectory_ReturnsEmptyStateWithoutReadingThroughLink()
    {
        if (!OperatingSystem.IsWindows()) return;

        Directory.CreateDirectory(_root);
        var realTargetDir = Path.Combine(_root, "attacker-real-dir-2");
        Directory.CreateDirectory(realTargetDir);
        var plantedStateFile = Path.Combine(realTargetDir, "extension-blocklist-state.json");
        File.WriteAllText(
            plantedStateFile,
            "{\"browsers\":{\"firefox\":[\"cccccccccccccccccccccccccccccccc\"]}}");

        var linkedDir = Path.Combine(_root, "linked-state-dir-2");
        CreateDirectorySymlinkOrFail(linkedDir, realTargetDir);

        var stateFileThroughLink = Path.Combine(linkedDir, "extension-blocklist-state.json");
        var enforcer = new RealIoTestEnforcer(stateFileThroughLink);

        var loaded = enforcer.LoadState();

        // Refused before ever reaching the leaf file check — the attacker-planted
        // content behind the link must never be parsed into state.
        Assert.Empty(loaded.Browsers);
    }
}
