using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1261 coverage for the applier that finally consumes the pending-update
/// marker BootstrapUpdater stages: hash re-verification, backward compatibility
/// with pre-hash markers, bounded retry (no boot loop), success detection via
/// running-version comparison, staged-directory cleanup, and degraded-health
/// reporting on every bail-out path. The process launch itself is asserted only
/// via <see cref="FakeLauncher"/> — never actually executed.
/// </summary>
public sealed class PendingUpdateApplierTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"patched-pending-update-{Guid.NewGuid():N}");

    public PendingUpdateApplierTests()
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

    private static string Sha256Hex(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static bool IsDegraded(AgentHealthStore health, string reason) =>
        health.BuildPayloadSection()!.Degraded.Any(e =>
            e.Kind == "self_update" && e.Subject == "apply" && e.Reason == reason);

    private static bool HasAnyDegraded(AgentHealthStore health) =>
        health.BuildPayloadSection()!.Degraded.Any(e => e.Kind == "self_update" && e.Subject == "apply");

    private PendingUpdateApplier NewApplier(
        string currentVersion, AgentHealthStore health, FakeLauncher launcher) =>
        new(NullLogger<PendingUpdateApplier>.Instance, health, launcher, currentVersion, PendingFile, UpdatesDir,
            trustOverride: SignedMarkerFixture.Trust, // PAT-2396
            trustVerifierOverride: FakeStagedUpdateTrustVerifier.Trusted()); // PAT-2400: temp staging

    /// <summary>Stages a fake installer under updates\&lt;version&gt;\patched-agent.msi and
    /// returns its full path.</summary>
    private string StageInstaller(string version, byte[] bytes)
    {
        string dir = Path.Combine(UpdatesDir, version);
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "patched-agent.msi");
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private void WriteMarker(string version, string installerPath, string? sha256, int attempts = 0)
    {
        var obj = new JsonObject
        {
            ["version"]         = version,
            ["installer_path"]  = installerPath,
            ["staged_at"]       = DateTimeOffset.UtcNow.ToString("O"),
            ["attempts"]        = attempts,
        };
        if (sha256 is not null)
        {
            obj["sha256"] = sha256;
            SignedMarkerFixture.AddEnvelope(obj, version, sha256); // PAT-2396
        }
        File.WriteAllText(PendingFile, obj.ToJsonString());
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 1: a valid marker + matching SHA-256 launches exactly
    // one detached msiexec.
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_ValidMarkerMatchingHash_LaunchesMsiexecExactlyOnce()
    {
        var bytes = Encoding.UTF8.GetBytes("real msi contents");
        var path = StageInstaller("0.13.21", bytes);
        WriteMarker("0.13.21", path, Sha256Hex(bytes));
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);

        NewApplier(currentVersion: "0.13.20", health, launcher).Apply();

        Assert.Single(launcher.Calls);
        Assert.Equal(path, launcher.Calls[0]);
        // Marker is retained (outcome unknown until the next restart) but its
        // attempt count is bumped so a later failed apply is bounded.
        Assert.True(File.Exists(PendingFile));
        var marker = JsonDocument.Parse(File.ReadAllText(PendingFile)).RootElement;
        Assert.Equal(1, marker.GetProperty("attempts").GetInt32());
        Assert.False(HasAnyDegraded(health));
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 2: a hash mismatch executes nothing, deletes the
    // staged file, clears the marker, records a distinct degraded reason.
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_HashMismatch_ExecutesNothing_DeletesFile_ClearsMarker_ReportsDegraded()
    {
        var declared = Encoding.UTF8.GetBytes("declared contents");
        var actual   = Encoding.UTF8.GetBytes("attacker swapped these bytes on disk");
        var path = StageInstaller("0.13.21", actual);
        WriteMarker("0.13.21", path, Sha256Hex(declared));
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);

        NewApplier(currentVersion: "0.13.20", health, launcher).Apply();

        Assert.Empty(launcher.Calls);
        Assert.False(File.Exists(path));
        Assert.False(File.Exists(PendingFile));
        Assert.True(IsDegraded(health, "hash_mismatch"));
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 3: a marker with no hash field (0.13.20-and-earlier)
    // executes nothing and is cleared.
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_MarkerMissingHashField_ExecutesNothing_IsCleared_BackwardCompatible()
    {
        var bytes = Encoding.UTF8.GetBytes("real msi contents");
        var path = StageInstaller("0.13.21", bytes);
        WriteMarker("0.13.21", path, sha256: null);
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);

        NewApplier(currentVersion: "0.13.20", health, launcher).Apply();

        Assert.Empty(launcher.Calls);
        Assert.False(File.Exists(PendingFile));
        Assert.True(IsDegraded(health, "marker_missing_hash"));
        // With the marker cleared there is no longer a "currently pending"
        // version, so the now-orphaned staged directory is pruned immediately
        // rather than left to occupy disk (at ~160 MB each) until some later
        // cycle happens to overwrite it — BootstrapUpdater re-downloads fresh
        // from scratch next time regardless, it never reuses this file.
        Assert.False(File.Exists(path));
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 4: a missing installer file executes nothing and
    // records a distinct degraded reason.
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_MissingInstallerFile_ExecutesNothing_ReportsDegraded()
    {
        string missingPath = Path.Combine(UpdatesDir, "0.13.21", "patched-agent.msi");
        WriteMarker("0.13.21", missingPath, Sha256Hex(Encoding.UTF8.GetBytes("whatever")));
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);

        NewApplier(currentVersion: "0.13.20", health, launcher).Apply();

        Assert.Empty(launcher.Calls);
        Assert.True(IsDegraded(health, "installer_missing"));
        // Marker retained: BootstrapUpdater's own "already staged" check fails
        // once the file is gone, so its next check-and-stage cycle re-downloads
        // and rewrites the marker on its own.
        Assert.True(File.Exists(PendingFile));
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 5: attempts are bounded — after the cap, no further
    // launches, and a distinct degraded reason.
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_FailingInstall_StopsLaunchingAfterMaxAttempts()
    {
        var bytes = Encoding.UTF8.GetBytes("real msi contents");
        var path = StageInstaller("0.13.21", bytes);
        WriteMarker("0.13.21", path, Sha256Hex(bytes));
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);
        var applier = NewApplier(currentVersion: "0.13.20", health, launcher);

        // Simulate the MSI failing every time: the version never converges, so
        // every restart re-enters DoApply with the same stale version.
        for (int i = 0; i < PendingUpdateApplier.MaxAttempts; i++)
            applier.Apply();

        Assert.Equal(PendingUpdateApplier.MaxAttempts, launcher.Calls.Count);

        // One more restart: attempts are now exhausted — no further launch.
        applier.Apply();

        Assert.Equal(PendingUpdateApplier.MaxAttempts, launcher.Calls.Count); // unchanged
        Assert.True(IsDegraded(health, "attempts_exhausted"));
        Assert.True(File.Exists(PendingFile)); // left in place, not silently deleted
    }

    [Fact]
    public void Apply_MsiexecLaunchFails_ReportsDistinctDegradedReason()
    {
        var bytes = Encoding.UTF8.GetBytes("real msi contents");
        var path = StageInstaller("0.13.21", bytes);
        WriteMarker("0.13.21", path, Sha256Hex(bytes));
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: false);

        NewApplier(currentVersion: "0.13.20", health, launcher).Apply();

        Assert.Single(launcher.Calls);
        Assert.True(IsDegraded(health, "msiexec_launch_failed"));
    }

    // -------------------------------------------------------------------------
    // PAT-1534: a marker for a version OLDER than what's running is a stale
    // marker (left over from an earlier release, or one that never advanced
    // across a restart), not something worth retrying — Windows Installer will
    // only ever refuse the downgrade. Reproduces the exact WIN-STAGING shape:
    // running 0.13.30, marker still pointing at 0.13.28.
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_MarkerVersionOlderThanRunning_ClearsMarker_ExecutesNothing_ReportsDistinctDegradedReason()
    {
        var bytes = Encoding.UTF8.GetBytes("stale older msi");
        var path = StageInstaller("0.13.28", bytes);
        WriteMarker("0.13.28", path, Sha256Hex(bytes));
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);

        NewApplier(currentVersion: "0.13.30", health, launcher).Apply();

        Assert.Empty(launcher.Calls); // never spends an attempt on a guaranteed-failing downgrade
        Assert.False(File.Exists(PendingFile));
        Assert.True(IsDegraded(health, "marker_not_newer"));
        // Orphaned staged directory pruned immediately, same as every other
        // clear-marker bail-out path.
        Assert.False(File.Exists(path));
    }

    // -------------------------------------------------------------------------
    // PAT-1534: the same stale-marker shape must not survive a service restart
    // by resetting its attempt count — the marker is CLEARED, not left for
    // another cycle to re-discover and retry again.
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_MarkerVersionOlderThanRunning_DoesNotConsumeRetryBudget_AcrossRepeatedRestarts()
    {
        var bytes = Encoding.UTF8.GetBytes("stale older msi");
        var path = StageInstaller("0.13.28", bytes);
        WriteMarker("0.13.28", path, Sha256Hex(bytes), attempts: 2); // as found live: "attempt 2/3"
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);
        var applier = NewApplier(currentVersion: "0.13.30", health, launcher);

        applier.Apply();
        applier.Apply(); // a second restart must not resurrect or re-retry a cleared marker

        Assert.Empty(launcher.Calls);
        Assert.False(File.Exists(PendingFile));
    }

    // -------------------------------------------------------------------------
    // PAT-1534: a marker version this class cannot parse as a version number is
    // treated the same as a confirmed downgrade — fail closed, don't execute
    // something it cannot prove is actually newer.
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_MarkerVersionUnparsable_ClearsMarker_ExecutesNothing_FailsClosed()
    {
        var bytes = Encoding.UTF8.GetBytes("whatever msi");
        var path = StageInstaller("not-a-version", bytes);
        WriteMarker("not-a-version", path, Sha256Hex(bytes));
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);

        NewApplier(currentVersion: "0.13.30", health, launcher).Apply();

        Assert.Empty(launcher.Calls);
        Assert.False(File.Exists(PendingFile));
        Assert.True(IsDegraded(health, "marker_not_newer"));
    }

    // -------------------------------------------------------------------------
    // PAT-1534 regression guard: a genuinely newer marker must still apply
    // normally — the new check must not reject the common case.
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_MarkerVersionNewerThanRunning_StillLaunchesMsiexec()
    {
        var bytes = Encoding.UTF8.GetBytes("real newer msi contents");
        var path = StageInstaller("0.13.31", bytes);
        WriteMarker("0.13.31", path, Sha256Hex(bytes));
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);

        NewApplier(currentVersion: "0.13.30", health, launcher).Apply();

        Assert.Single(launcher.Calls);
        Assert.Equal(path, launcher.Calls[0]);
        Assert.False(HasAnyDegraded(health));
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 6: running version == marker version clears the
    // marker, removes the staged directory, and records success.
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_RunningVersionMatchesMarker_ClearsMarker_RemovesStagedDir_RecordsSuccess()
    {
        var bytes = Encoding.UTF8.GetBytes("real msi contents");
        var path = StageInstaller("0.13.21", bytes);
        WriteMarker("0.13.21", path, Sha256Hex(bytes), attempts: 1);
        var health = NewHealth();
        health.RecordFailure("self_update", "apply", "msiexec_launch_failed"); // a fault from a prior attempt
        var launcher = new FakeLauncher(returnValue: true);

        NewApplier(currentVersion: "0.13.21", health, launcher).Apply();

        Assert.Empty(launcher.Calls); // nothing left to execute — already applied
        Assert.False(File.Exists(PendingFile));
        Assert.False(Directory.Exists(Path.Combine(UpdatesDir, "0.13.21")));
        Assert.False(HasAnyDegraded(health)); // the prior fault is cleared, not just left stale
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 7: stale staged directories for OTHER versions are
    // pruned, whether or not there is currently a pending marker.
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_PrunesStaleStagedDirectories_KeepsOnlyCurrentlyPendingVersion()
    {
        var pendingBytes = Encoding.UTF8.GetBytes("current pending msi");
        var pendingPath = StageInstaller("0.13.21", pendingBytes);
        Directory.CreateDirectory(Path.Combine(UpdatesDir, "0.13.19")); // empty stub from a failed attempt
        StageInstaller("0.13.20", Encoding.UTF8.GetBytes("old stale msi"));
        WriteMarker("0.13.21", pendingPath, Sha256Hex(pendingBytes));
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);

        NewApplier(currentVersion: "0.13.20", health, launcher).Apply();

        Assert.False(Directory.Exists(Path.Combine(UpdatesDir, "0.13.19")));
        Assert.False(Directory.Exists(Path.Combine(UpdatesDir, "0.13.20")));
        Assert.True(Directory.Exists(Path.Combine(UpdatesDir, "0.13.21"))); // still pending — kept
    }

    [Fact]
    public void Apply_NoMarkerPresent_PrunesEveryStagedDirectory()
    {
        Directory.CreateDirectory(Path.Combine(UpdatesDir, "0.13.18"));
        StageInstaller("0.13.19", Encoding.UTF8.GetBytes("leftover"));
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);

        NewApplier(currentVersion: "0.13.20", health, launcher).Apply();

        Assert.Empty(launcher.Calls);
        Assert.False(Directory.Exists(Path.Combine(UpdatesDir, "0.13.18")));
        Assert.False(Directory.Exists(Path.Combine(UpdatesDir, "0.13.19")));
    }

    // -------------------------------------------------------------------------
    // Test doubles
    // -------------------------------------------------------------------------

    private sealed class FakeLauncher(bool returnValue) : IPendingUpdateLauncher
    {
        public List<string> Calls { get; } = new();

        public bool LaunchDetached(string installerPath)
        {
            Calls.Add(installerPath);
            return returnValue;
        }
    }
}
