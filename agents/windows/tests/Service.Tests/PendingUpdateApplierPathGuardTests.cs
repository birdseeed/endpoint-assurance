using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1334: <c>updates\</c> is the one privileged staging root
/// <c>PendingUpdateApplier</c> deletes from as LocalSystem without ever running
/// <c>SecureStagingDirectory.EnsureHardened(Chain)</c> on it first — unlike the
/// decommission/catalogue/choco/winget/self-update-restart paths. This covers the
/// <see cref="Patched.Shared.Security.PathSafety"/> guard added at both delete
/// sites (<c>PruneStaleStagedDirectories</c>, <c>DeleteStagedDirectory</c>):
///  - the real defect — <c>updates\</c> ITSELF replaced by a symlink/junction
///    (an ANCESTOR of every staged directory), which .NET's
///    <c>Directory.GetDirectories</c> resolves THROUGH, making a naive recursive
///    delete destructive against the real target (verified empirically on the
///    Windows staging VM, see PathSafety's class doc comment);
///  - containment — a marker `version` value that escapes <c>_updatesDir</c>
///    (e.g. via "..") must not delete outside it;
///  - non-regression — plain staged directories are still pruned/deleted exactly
///    as before, and the currently-pending version is still skipped.
///
/// Uses <see cref="Directory.CreateSymbolicLink"/> rather than an NTFS junction
/// (unlike <c>ExtensionRemovalLogicTests.RealJunctionAtExtensionDir_IsRefused_AndLeftIntact</c>,
/// which needs `mklink /J` and is Windows-only): a directory symlink is a real
/// reparse point (<c>FileAttributes.ReparsePoint</c>) on both Windows and macOS,
/// so — unlike that junction test — this one is NOT gated behind
/// <c>OperatingSystem.IsWindows()</c> and is expected to actually exercise the
/// guard on macOS CI too.
/// </summary>
public sealed class PendingUpdateApplierPathGuardTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"patched-pending-update-guard-{Guid.NewGuid():N}");

    public PendingUpdateApplierPathGuardTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private string PendingFile => Path.Combine(_dir, "pending-agent-update.json");
    private string UpdatesDir => Path.Combine(_dir, "updates");
    private AgentHealthStore NewHealth() => new(NullLogger<AgentHealthStore>.Instance, Path.Combine(_dir, "health.json"));

    private PendingUpdateApplier NewApplier(
        AgentHealthStore health, CapturingLogger<PendingUpdateApplier> log,
        string? trustedRootOverride = null) =>
        new(log, health, new FakeLauncher(returnValue: true),
            currentVersion: "0.13.20", PendingFile, UpdatesDir, trustedRootOverride,
            trustOverride: SignedMarkerFixture.Trust, // PAT-2396
            trustVerifierOverride: FakeStagedUpdateTrustVerifier.Trusted()); // PAT-2400: temp staging

    // -------------------------------------------------------------------------
    // The real defect: updates\ itself replaced by a symlink (an ANCESTOR of
    // every staged directory) must refuse the whole prune pass rather than
    // delete through it.
    // -------------------------------------------------------------------------
    [Fact]
    public void Prune_UpdatesDirIsSymlinkAncestor_RefusesAndCanarySurvives()
    {
        var real = Path.Combine(_dir, "real");
        Directory.CreateDirectory(Path.Combine(real, "v1"));
        var canary = Path.Combine(real, "v1", "canary.txt");
        File.WriteAllText(canary, "must not be deleted");

        Directory.CreateSymbolicLink(UpdatesDir, real);
        Assert.True((File.GetAttributes(UpdatesDir) & FileAttributes.ReparsePoint) != 0); // sanity

        var health = NewHealth();
        var log = new CapturingLogger<PendingUpdateApplier>();
        // No pending-agent-update.json ⇒ Apply() goes straight to
        // PruneStaleStagedDirectories(currentPendingVersion: null).
        NewApplier(health, log, trustedRootOverride: _dir).Apply();

        Assert.True(File.Exists(canary), "the real target's contents must survive an ancestor-symlink prune attempt");
        Assert.True(Directory.Exists(Path.Combine(real, "v1")), "the real target's directory must survive");
        Assert.Contains(log.Warnings, m => m.Contains("refusing to prune") && m.Contains(UpdatesDir));
    }

    // -------------------------------------------------------------------------
    // Containment: a marker version escaping _updatesDir via ".." must not
    // delete a directory outside it, and must log the refusal.
    // -------------------------------------------------------------------------
    [Fact]
    public void DeleteStagedDirectory_VersionEscapesUpdatesDir_RefusesAndSiblingSurvives()
    {
        Directory.CreateDirectory(UpdatesDir);
        var sibling = Path.Combine(_dir, "evil");
        Directory.CreateDirectory(sibling);
        var canary = Path.Combine(sibling, "canary.txt");
        File.WriteAllText(canary, "must not be deleted");

        var health = NewHealth();
        var log = new CapturingLogger<PendingUpdateApplier>();
        var bytes = Encoding.UTF8.GetBytes("real msi contents");
        // The marker's version escapes _updatesDir; setting currentVersion equal
        // to it would (pre-PAT-1339) drive the "running version matches the
        // pending update" branch, which calls
        // CleanupStagedDirectory → DeleteStagedDirectory(marker.Version) — the
        // exact call this guard protects, and also the one place a
        // hostile/malformed version string (from a pre-PAT-1261 or otherwise
        // corrupt marker) would otherwise reach Path.Combine unchecked.
        //
        // PAT-1339 closes this one layer earlier: IsSafeVersionSegment now
        // refuses "../evil" at marker-read time, before DoApply ever reaches the
        // version-match branch, so DeleteStagedDirectory's own PathSafety guard
        // below is no longer reachable via this attack shape at all — it stays
        // in place as defense-in-depth (see PendingUpdateApplierTests'
        // PAT-1339 marker-validation coverage for the earlier-layer refusal
        // itself; this test now only proves the deeper guard is never NEEDED to
        // do the work, because the outcome — sibling survives — still holds).
        var installerPath = Path.Combine(sibling, "patched-agent.msi");
        File.WriteAllBytes(installerPath, bytes);
        WriteMarker(version: "../evil", installerPath, Sha256Hex(bytes));

        var applier = new PendingUpdateApplier(
            log, health, new FakeLauncher(returnValue: true),
            currentVersion: "../evil", PendingFile, UpdatesDir, trustedRootOverride: _dir,
            trustVerifierOverride: FakeStagedUpdateTrustVerifier.Trusted()); // PAT-2400: temp staging
        applier.Apply();

        Assert.True(File.Exists(canary), "a directory outside _updatesDir must never be deleted");
        Assert.True(Directory.Exists(sibling));
        // Refused at the new, earlier marker-validation layer (PAT-1339) rather
        // than at DeleteStagedDirectory's own guard.
        Assert.Contains(log.Errors, m => m.Contains("not a safe path segment"));
        Assert.True(health.BuildPayloadSection()!.Degraded.Any(e =>
            e.Kind == "self_update" && e.Subject == "apply" && e.Reason == "marker_version_unsafe"));
    }

    [Fact]
    public void PruneStaleStagedDirectories_ChildEscapesViaTraversalName_RefusesAndSurvives()
    {
        Directory.CreateDirectory(UpdatesDir);
        var sibling = Path.Combine(_dir, "evil2");
        Directory.CreateDirectory(sibling);
        var canary = Path.Combine(sibling, "canary.txt");
        File.WriteAllText(canary, "must not be deleted");

        // Directory.GetDirectories can't itself return a traversal name, but
        // PruneStaleStagedDirectories' containment check is exercised the same
        // way DeleteStagedDirectory's is: build the escaping path exactly as
        // that method would from a hostile "name" and confirm PathSafety
        // refuses it. Simulated here via a symlinked child that *looks*
        // contained by name but whose target lies outside _updatesDir — the
        // reparse-point half of the same guard.
        var linkedChild = Path.Combine(UpdatesDir, "0.13.19");
        Directory.CreateSymbolicLink(linkedChild, sibling);

        var health = NewHealth();
        var log = new CapturingLogger<PendingUpdateApplier>();
        NewApplier(health, log, trustedRootOverride: _dir).Apply();

        Assert.True(File.Exists(canary), "a symlinked child pointing outside _updatesDir must never be deleted through");
        Assert.True(Directory.Exists(sibling));
        Assert.Contains(log.Warnings, m => m.Contains("refusing to prune") && m.Contains(linkedChild));
    }

    // -------------------------------------------------------------------------
    // Non-regression: a plain staged directory under a plain updates\ is still
    // pruned/deleted exactly as before, and the currently-pending version is
    // still skipped.
    // -------------------------------------------------------------------------
    [Fact]
    public void Prune_PlainUpdatesDir_StillPrunesStaleAndKeepsPendingVersion()
    {
        Directory.CreateDirectory(Path.Combine(UpdatesDir, "0.13.18"));
        Directory.CreateDirectory(Path.Combine(UpdatesDir, "0.13.19"));

        var health = NewHealth();
        var log = new CapturingLogger<PendingUpdateApplier>();
        var bytes = Encoding.UTF8.GetBytes("current pending msi");
        var pendingDir = Path.Combine(UpdatesDir, "0.13.21");
        Directory.CreateDirectory(pendingDir);
        var pendingPath = Path.Combine(pendingDir, "patched-agent.msi");
        File.WriteAllBytes(pendingPath, bytes);
        WriteMarker("0.13.21", pendingPath, Sha256Hex(bytes));

        NewApplier(health, log, trustedRootOverride: _dir).Apply();

        Assert.False(Directory.Exists(Path.Combine(UpdatesDir, "0.13.18")));
        Assert.False(Directory.Exists(Path.Combine(UpdatesDir, "0.13.19")));
        Assert.True(Directory.Exists(pendingDir)); // still pending — kept
        Assert.DoesNotContain(log.Warnings, m => m.Contains("refusing"));
    }

    [Fact]
    public void DeleteStagedDirectory_PlainVersion_StillRemovedAfterSuccessfulApply()
    {
        var bytes = Encoding.UTF8.GetBytes("real msi contents");
        var dir = Path.Combine(UpdatesDir, "0.13.21");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "patched-agent.msi");
        File.WriteAllBytes(path, bytes);
        WriteMarker("0.13.21", path, Sha256Hex(bytes));

        var health = NewHealth();
        var log = new CapturingLogger<PendingUpdateApplier>();
        // currentVersion equals the marker's version here, so Apply() takes the
        // already-applied branch and calls CleanupStagedDirectory → DeleteStagedDirectory.
        var applier = new PendingUpdateApplier(
            log, health, new FakeLauncher(returnValue: true),
            currentVersion: "0.13.21", PendingFile, UpdatesDir, trustedRootOverride: _dir,
            trustVerifierOverride: FakeStagedUpdateTrustVerifier.Trusted()); // PAT-2400: temp staging

        applier.Apply();

        Assert.False(Directory.Exists(dir));
        Assert.DoesNotContain(log.Warnings, m => m.Contains("refusing"));
    }

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    private static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();

    private void WriteMarker(string version, string installerPath, string sha256, int attempts = 0)
    {
        var obj = new System.Text.Json.Nodes.JsonObject
        {
            ["version"]        = version,
            ["installer_path"] = installerPath,
            ["sha256"]         = sha256,
            ["staged_at"]      = DateTimeOffset.UtcNow.ToString("O"),
            ["attempts"]       = attempts,
        };
        SignedMarkerFixture.AddEnvelope(obj, version, sha256); // PAT-2396
        File.WriteAllText(PendingFile, obj.ToJsonString());
    }

    private sealed class FakeLauncher(bool returnValue) : IPendingUpdateLauncher
    {
        public List<string> Calls { get; } = new();

        public bool LaunchDetached(string installerPath)
        {
            Calls.Add(installerPath);
            return returnValue;
        }
    }

    /// <summary>Captures every logged message by level, mirroring
    /// AuditEventShipperEnforcementAuditDurabilityTests' CapturingLogger&lt;T&gt;.</summary>
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];
        public List<string> Warnings { get; } = [];
        public List<string> Errors { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var message = formatter(state, exception);
            Messages.Add(message);
            if (logLevel == LogLevel.Warning) Warnings.Add(message);
            if (logLevel == LogLevel.Error) Errors.Add(message);
        }
    }
}
