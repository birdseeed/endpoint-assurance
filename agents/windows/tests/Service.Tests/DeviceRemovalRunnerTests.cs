using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1066: unit tests for the agent_health recording DeviceRemovalRunner.RunAsync
/// added around its existing device-id gate (~line 40 today).
///
/// DeviceRemovalRunner, DeviceRemovalTasksClient, RegistryUninstallLookup and
/// UninstallExecutor are all sealed with no virtual seams (unlike InstallRunner), so
/// these tests exercise the real production DeviceRemovalTasksClient rather than a
/// test double, using its postureCachePathOverride constructor parameter (added
/// alongside this ticket, mirroring PostureReader's own pre-existing cachePath
/// override, for exactly this reason) to point ReadDeviceId() at a temp posture.json
/// instead of the real PathConstants.PostureStatusFile — %ProgramData% on Windows,
/// but on this macOS/Linux CI host that resolves under /usr/share, which is
/// SIP-protected and not writable by a non-privileged test process. RunAsync itself
/// is exercised unmodified; only the posture-cache read is redirected.
///
/// RegistryUninstallLookup/UninstallExecutor are passed null! because
/// FetchPendingAsync (given a null! IHttpClientFactory) throws inside its own
/// try/catch and returns an empty task list, so RunAsync returns right after
/// recording success/failure — before ever reaching ProcessOneAsync — so neither
/// dependency is actually invoked in any of these tests.
/// </summary>
public sealed class DeviceRemovalRunnerTests
{
    private static DeviceRemovalRunner MakeRunner(string tmpDir, AgentHealthStore agentHealth) =>
        new(
            NullLogger<DeviceRemovalRunner>.Instance,
            new DeviceRemovalTasksClient(
                NullLogger<DeviceRemovalTasksClient>.Instance, null!, null!,
                postureCachePathOverride: Path.Combine(tmpDir, "posture.json")),
            null!,
            null!,
            agentHealth);

    private static AgentHealthStore MakeStore(string tmpDir) =>
        new(NullLogger<AgentHealthStore>.Instance, Path.Combine(tmpDir, "agent-health.json"));

    private static void WritePostureWithDeviceId(string tmpDir, string deviceId) =>
        File.WriteAllText(Path.Combine(tmpDir, "posture.json"),
            "{\"device\":{\"id\":\"" + deviceId + "\"}}");

    [Fact]
    public async Task RunAsync_NoDeviceId_RecordsFailure_NoDeviceId()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            // No posture.json written under tmpDir -> ReadDeviceId() returns null.
            var agentHealth = MakeStore(tmpDir);
            var runner = MakeRunner(tmpDir, agentHealth);

            await runner.RunAsync(CancellationToken.None);

            var section = agentHealth.BuildPayloadSection();
            Assert.NotNull(section);
            var entry = Assert.Single(section!.Degraded);
            Assert.Equal("directive_skipped", entry.Kind);
            Assert.Equal("device_removal",    entry.Subject);
            Assert.Equal("no_device_id",      entry.Reason);
            Assert.Equal(1,                   entry.Count);
            Assert.False(entry.EverSucceeded);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public async Task RunAsync_NoDeviceId_RepeatedCycles_BumpsCount_NeverSetsEverSucceeded()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var agentHealth = MakeStore(tmpDir);
            var runner = MakeRunner(tmpDir, agentHealth);

            await runner.RunAsync(CancellationToken.None);
            await runner.RunAsync(CancellationToken.None);
            await runner.RunAsync(CancellationToken.None);

            var entry = Assert.Single(agentHealth.BuildPayloadSection()!.Degraded);
            Assert.Equal(3, entry.Count);
            Assert.False(entry.EverSucceeded);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public async Task RunAsync_HasDeviceId_RecordsSuccess_RegardlessOfPendingTaskCount()
    {
        // A posture.json with a device id makes ReadDeviceId() non-null.
        // FetchPendingAsync will fail closed to an empty list (null! IHttpClientFactory),
        // so RunAsync returns right after recording success — exactly the "can this
        // device be addressed at all" signal PAT-1066 asks for, independent of whether
        // any task happened to be pending this cycle.
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            WritePostureWithDeviceId(tmpDir, "device-abc-123");
            var agentHealth = MakeStore(tmpDir);
            var runner = MakeRunner(tmpDir, agentHealth);

            await runner.RunAsync(CancellationToken.None);

            var section = agentHealth.BuildPayloadSection();
            Assert.NotNull(section);
            Assert.Empty(section!.Degraded);   // success clears/never creates an active fault
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public async Task RunAsync_ResolveThenRecur_PreservesEverSucceededTrue()
    {
        // The single most safety-critical property (brief acceptance criterion 6),
        // exercised through DeviceRemovalRunner's real call sequence rather than
        // driving AgentHealthStore directly: fail (no device id) -> succeed (device
        // id appears) -> fail again (device id disappears, e.g. a stale/cleared
        // posture cache) must still show ever_succeeded=true on the final read.
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var agentHealth = MakeStore(tmpDir);
            var runner = MakeRunner(tmpDir, agentHealth);
            var posturePath = Path.Combine(tmpDir, "posture.json");

            // 1. Fail: no posture cache yet.
            await runner.RunAsync(CancellationToken.None);

            // 2. Succeed: posture cache appears with a device id.
            WritePostureWithDeviceId(tmpDir, "device-abc-123");
            await runner.RunAsync(CancellationToken.None);

            // 3. Fail again: posture cache goes away.
            File.Delete(posturePath);
            await runner.RunAsync(CancellationToken.None);

            var entry = Assert.Single(agentHealth.BuildPayloadSection()!.Degraded);
            Assert.Equal("no_device_id", entry.Reason);
            Assert.True(entry.EverSucceeded, "ever_succeeded must stay true after a resolve-then-recur cycle");
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    // -------------------------------------------------------------------------
    // PAT-1066 P2 non-author-review — RecordDeviceIdentityHealth, the extracted
    // health-only method Worker.cs calls directly on cycles where the full
    // device-removal engine is gated out by tier/mode (so a report-tier tenant
    // doesn't assert a false all-clear forever, and a downgraded-then-restored
    // tenant's fault can actually clear). PatchedWorker.RunCycleAsync itself is
    // too DI-heavy to construct here (same reasoning as WorkerTierGateTests.cs),
    // so these tests call RecordDeviceIdentityHealth directly, exactly as
    // Worker.cs's health-only branch does.
    //
    // Acceptance criterion (a) — never reaches the actuating removal logic: this
    // holds by construction, not just by observation — RecordDeviceIdentityHealth
    // is a synchronous, non-async method (no CancellationToken, returns string?
    // directly) and therefore cannot itself await DeviceRemovalTasksClient's async
    // FetchPendingAsync/ReportAsync calls or reach ProcessOneAsync; RunAsync only
    // reaches those AFTER calling this same method and finding a non-null id.
    // -------------------------------------------------------------------------

    [Fact]
    public void RecordDeviceIdentityHealth_NoDeviceId_RecordsFailure_ReturnsNull()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            // No posture.json written under tmpDir -> ReadDeviceId() returns null.
            var agentHealth = MakeStore(tmpDir);
            var runner = MakeRunner(tmpDir, agentHealth);

            var result = runner.RecordDeviceIdentityHealth();

            Assert.Null(result);
            var entry = Assert.Single(agentHealth.BuildPayloadSection()!.Degraded);
            Assert.Equal("directive_skipped", entry.Kind);
            Assert.Equal("device_removal",    entry.Subject);
            Assert.Equal("no_device_id",      entry.Reason);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void RecordDeviceIdentityHealth_HasDeviceId_RecordsSuccess_ReturnsDeviceId()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            WritePostureWithDeviceId(tmpDir, "device-abc-123");
            var agentHealth = MakeStore(tmpDir);
            var runner = MakeRunner(tmpDir, agentHealth);

            var result = runner.RecordDeviceIdentityHealth();

            Assert.Equal("device-abc-123", result);
            Assert.Empty(agentHealth.BuildPayloadSection()!.Degraded);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void RecordDeviceIdentityHealth_HealthOnlyPath_ResolveThenRecur_PreservesEverSucceededTrue()
    {
        // PAT-1066 P2 acceptance criterion (c): the device-identity health signal
        // depends only on the posture cache, not on tier — so the health-only path
        // ITSELF (no RunAsync, no full engine, no "managed"-tier cycle required
        // — PAT-1599: formerly "patch") can
        // observe a fail -> succeed -> fail-again sequence and still preserve
        // ever_succeeded=true, exactly matching the resolve-then-recur invariant
        // RunAsync's own equivalent test proves for the gated path.
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var agentHealth = MakeStore(tmpDir);
            var runner = MakeRunner(tmpDir, agentHealth);
            var posturePath = Path.Combine(tmpDir, "posture.json");

            // 1. Fail: no posture cache yet — called directly, not via RunAsync.
            Assert.Null(runner.RecordDeviceIdentityHealth());

            // 2. Succeed: posture cache appears with a device id.
            WritePostureWithDeviceId(tmpDir, "device-abc-123");
            Assert.Equal("device-abc-123", runner.RecordDeviceIdentityHealth());

            // 3. Fail again: posture cache goes away (e.g. tenant downgraded, then
            // the cache itself went stale/cleared).
            File.Delete(posturePath);
            Assert.Null(runner.RecordDeviceIdentityHealth());

            var entry = Assert.Single(agentHealth.BuildPayloadSection()!.Degraded);
            Assert.Equal("no_device_id", entry.Reason);
            Assert.True(entry.EverSucceeded,
                "ever_succeeded must stay true after a resolve-then-recur cycle driven entirely " +
                "through the health-only path, independent of tier/RunAsync");
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }
}
