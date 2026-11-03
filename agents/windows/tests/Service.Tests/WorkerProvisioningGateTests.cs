using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1766: PatchedWorker.WaitForProvisioningAsync, the startup gate for a device
/// with no usable credentials and no enrolment token. PAT-1764 made that process exit
/// 2 before the host started, which failed the MSI's StartServices (1920) and rolled
/// back the install or upgrade (1603) on WIN-STAGING. The service now stays running,
/// reports the state and polls until a token or credentials appear.
///
/// Same approach as WorkerMidRunSuspensionTests: the extracted static gate is driven
/// directly with CredentialStore.CreateForTests, whose provisioningSource stands in
/// for re-running the startup load, so nothing touches the host.
/// </summary>
public sealed class WorkerProvisioningGateTests : IDisposable
{
    private const string Secret = "dGVzdC1obWFjLXNlY3JldC0zMi1ieXRlcy1sb25nIQ==";
    private static readonly TimeSpan Tick = TimeSpan.FromMilliseconds(5);
    private static readonly TimeSpan NoReminder = TimeSpan.FromHours(1);

    private readonly string _tempDir;
    private readonly string _suspendedFile;
    private readonly AgentHealthStore _health;

    public WorkerProvisioningGateTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-worker-provisioning-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _suspendedFile = Path.Combine(_tempDir, "suspended");
        _health = new AgentHealthStore(
            NullLogger<AgentHealthStore>.Instance, Path.Combine(_tempDir, "agent-health.json"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { /* best effort */ }
    }

    private sealed class CapturingLogger : ILogger
    {
        private readonly object _gate = new();
        private readonly List<(LogLevel Level, string Message)> _entries = [];

        public IReadOnlyList<(LogLevel Level, string Message)> Entries
        {
            get { lock (_gate) return _entries.ToList(); }
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (_gate) _entries.Add((logLevel, formatter(state, exception)));
        }
    }

    private CredentialStore Unprovisioned(Func<CredentialStore?> source) =>
        CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", hmacSecret: "", tenantId: "", provisioningSource: source);

    private CredentialStore WithToken(string token) =>
        CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", hmacSecret: "", tenantId: "", enrollmentToken: token);

    private CredentialStore StoredBlankPair(Func<CredentialStore?> source) =>
        CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", hmacSecret: "", tenantId: "",
            provisioningSource: source, storedCredentialPairPresent: true);

    [Fact]
    public async Task UsablePair_ReturnsImmediately_NeverReloads_LogsNothing()
    {
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "bearer", hmacSecret: Secret,
            provisioningSource: () => throw new InvalidOperationException("must not reload"));
        var log = new CapturingLogger();

        await PatchedWorker.WaitForProvisioningAsync(creds, _health, log, Tick, NoReminder, CancellationToken.None)
            .WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Empty(log.Entries);
    }

    [Fact]
    public async Task EnrolmentTokenPresent_ReturnsImmediately_LogsNothing()
    {
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", hmacSecret: "", enrollmentToken: "pending-token",
            provisioningSource: () => throw new InvalidOperationException("must not reload"));
        var log = new CapturingLogger();

        await PatchedWorker.WaitForProvisioningAsync(creds, _health, log, Tick, NoReminder, CancellationToken.None)
            .WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Empty(log.Entries);
    }

    [Fact]
    public async Task NothingAppears_ReportsCriticalOnce_KeepsWaiting_KeepsChecking()
    {
        var reloads = new PollProbe();
        var creds = Unprovisioned(() => { reloads.Record(); return null; });
        var log = new CapturingLogger();

        // PAT-2423: cancelled after three counted rechecks, not on a 150 ms timer that
        // a slow runner could hit before the second recheck.
        await reloads.AssertStillWaitingAfterAsync(3, ct =>
            PatchedWorker.WaitForProvisioningAsync(creds, _health, log, Tick, NoReminder, ct));

        Assert.True(creds.AwaitingProvisioning);
        Assert.True(reloads.Count >= 2, $"expected repeated rechecks, got {reloads.Count}");
        var entry = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Critical, entry.Level);
        Assert.Contains("no Patched agent identity", entry.Message);
        Assert.Contains("is running but collects and sends nothing", entry.Message);
        Assert.DoesNotContain(_health.BuildPayloadSection()!.Degraded,
            e => e.Kind == DeviceCredentialHealth.Kind && e.Subject == DeviceCredentialHealth.Subject);
    }

    [Fact]
    public async Task StoredBlankPair_RecordsCredentialsEmptyOnce_WhileItKeepsWaiting()
    {
        var creds = StoredBlankPair(() => null);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            PatchedWorker.WaitForProvisioningAsync(
                creds, _health, new CapturingLogger(), Tick, NoReminder, cts.Token));

        var fault = Assert.Single(_health.BuildPayloadSection()!.Degraded,
            e => e.Kind == DeviceCredentialHealth.Kind && e.Subject == DeviceCredentialHealth.Subject);
        Assert.Equal(DeviceCredentialHealth.CredentialsEmptyReason, fault.Reason);
        Assert.Equal(1, fault.Count);
    }

    [Fact]
    public async Task TokenAppearsOnALaterCheck_Returns_StoreHoldsTheToken_ReportsProvisioned()
    {
        var reloads = 0;
        var creds = Unprovisioned(() => Interlocked.Increment(ref reloads) >= 3 ? WithToken("dropped-token") : null);
        var log = new CapturingLogger();

        await PatchedWorker.WaitForProvisioningAsync(creds, _health, log, Tick, NoReminder, CancellationToken.None)
            .WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(3, reloads);
        Assert.False(creds.AwaitingProvisioning);
        Assert.Equal("dropped-token", creds.EnrollmentToken);
        Assert.Collection(log.Entries,
            e => Assert.Equal(LogLevel.Critical, e.Level),
            e =>
            {
                Assert.Equal(LogLevel.Information, e.Level);
                Assert.Equal(AgentProvisioning.ProvisionedMessage, e.Message);
                Assert.DoesNotContain("dropped-token", e.Message);
            });
    }

    [Fact]
    public async Task CredentialsAppear_Returns_StoreHoldsTheUsablePair()
    {
        var creds = Unprovisioned(() =>
            CredentialStore.CreateForTests(_suspendedFile, bearerToken: "added-bearer", hmacSecret: Secret, tenantId: "added-tenant"));

        await PatchedWorker.WaitForProvisioningAsync(creds, _health, new CapturingLogger(), Tick, NoReminder, CancellationToken.None)
            .WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal("added-tenant", creds.TenantId);
        Assert.Equal("added-bearer", creds.BearerToken);
        Assert.Equal(Secret, creds.HmacSecret);
        Assert.True(CredentialStore.IsUsablePair(creds.BearerToken, creds.HmacSecret));
    }

    [Fact]
    public async Task StoredBlankPair_UsableCredentialsAppear_ClearsTheFault()
    {
        var creds = StoredBlankPair(() => CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "added-bearer", hmacSecret: Secret,
            tenantId: "added-tenant", storedCredentialPairPresent: true));

        await PatchedWorker.WaitForProvisioningAsync(
                creds, _health, new CapturingLogger(), Tick, NoReminder, CancellationToken.None)
            .WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(CredentialStore.IsUsablePair(creds.BearerToken, creds.HmacSecret));
        Assert.DoesNotContain(_health.BuildPayloadSection()!.Degraded,
            e => e.Kind == DeviceCredentialHealth.Kind && e.Subject == DeviceCredentialHealth.Subject);
        Assert.NotNull(_health.GetLastSuccess(DeviceCredentialHealth.Kind, DeviceCredentialHealth.Subject));
    }

    [Fact]
    public async Task ReloadThrows_LogsTypeOnlyWarning_KeepsWaiting_ThenRecovers()
    {
        const string SecretLookingText = "should-never-be-logged";
        var reloads = 0;
        var creds = Unprovisioned(() => Interlocked.Increment(ref reloads) == 1
            ? throw new IOException(SecretLookingText)
            : WithToken("dropped-token"));
        var log = new CapturingLogger();

        await PatchedWorker.WaitForProvisioningAsync(creds, _health, log, Tick, NoReminder, CancellationToken.None)
            .WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal("dropped-token", creds.EnrollmentToken);
        var warning = Assert.Single(log.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains(nameof(IOException), warning.Message);
        Assert.All(log.Entries, e => Assert.DoesNotContain(SecretLookingText, e.Message));
    }

    [Fact]
    public async Task StillUnprovisionedAfterReminderInterval_RepeatsTheReportAsError()
    {
        var reloads = new PollProbe();
        var creds = Unprovisioned(() => { reloads.Record(); return null; });
        var log = new CapturingLogger();

        // PAT-2423: counted, not timed. This used a 20 ms reminder interval under a
        // 200 ms cancellation timer. With a zero interval the reminder is due on every
        // recheck, so the first recheck logs it; the wait is cancelled after the third.
        await reloads.AssertStillWaitingAfterAsync(3, ct =>
            PatchedWorker.WaitForProvisioningAsync(creds, _health, log, Tick, TimeSpan.Zero, ct));

        Assert.Equal(LogLevel.Critical, log.Entries[0].Level);
        var reminders = log.Entries.Where(e => e.Level == LogLevel.Error).ToList();
        Assert.NotEmpty(reminders);
        Assert.All(reminders, e => Assert.Contains("no Patched agent identity", e.Message));
    }

    [Fact]
    public void ExecuteAsync_RunsTheProvisioningGateFirst_BeforeSuspensionAndEnrolment()
    {
        // The gate only protects startup if nothing identity-dependent runs before it,
        // and it must precede the suspension gate so a token it finds reaches that
        // gate's enrol-past-a-stale-marker path.
        var source = File.ReadAllText(Path.Combine(ServiceSourceDir(), "Worker.cs"));
        var execute = source.IndexOf("protected override async Task ExecuteAsync", StringComparison.Ordinal);
        Assert.True(execute >= 0);

        int First(string call)
        {
            var index = source.IndexOf(call, execute, StringComparison.Ordinal);
            Assert.True(index >= 0, $"{call} not found in ExecuteAsync");
            return index;
        }

        var gate = First("await WaitForProvisioningAsync(_creds");
        Assert.True(gate < First("await WaitOutSuspensionAsync(_creds"));
        Assert.True(gate < First("_enroller.TryEnrolAsync(ct)"));
        Assert.True(gate < First("RunDecommissionCheckSafeAsync(ct)"));
        Assert.True(gate < First("_pendingUpdateApplier.Apply()"));
        Assert.True(gate < First("_bootstrapUpdater.CheckAndStageAsync(ct)"));
    }

    [Fact]
    public void Program_NoLongerExitsBeforeTheHostRuns()
    {
        var program = File.ReadAllText(Path.Combine(ServiceSourceDir(), "Program.cs"));

        Assert.DoesNotContain("CheckAgentIdentity", program);
        Assert.DoesNotContain("host.Dispose()", program);
    }

    private static string ServiceSourceDir([CallerFilePath] string thisFile = "")
    {
        var dir = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(thisFile)!, "..", "..", "src", "Service"));
        Assert.True(Directory.Exists(dir), $"service sources not found at {dir}; this test must run from a source checkout");
        return dir;
    }
}
