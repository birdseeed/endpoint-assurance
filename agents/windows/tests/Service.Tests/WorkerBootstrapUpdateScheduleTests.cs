using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Patched.Shared.Verification;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1269 coverage for <see cref="PatchedWorker.RunPeriodicBootstrapUpdateCheckAsync"/>
/// — the extracted, testable scheduling decision behind the tick loop's periodic
/// self-update check (BootstrapUpdater.CheckAndStageAsync used to run only once, at
/// service start; a running endpoint never discovered a new release without a
/// restart otherwise — confirmed live on WIN-STAGING).
///
/// PatchedWorker itself has 17 constructor dependencies and no existing test
/// harness builds the whole thing (see WorkerTierGateTests), so this exercises the
/// static helper directly with a real <see cref="BootstrapUpdater"/> wired to a
/// fake HTTP handler — the same test-double shape BootstrapUpdaterTests uses,
/// duplicated locally rather than shared, matching this repo's existing
/// per-test-file fixture convention (see PendingUpdateApplierTests). The fake
/// handler always returns 503: this test only needs to prove whether
/// CheckAndStageAsync's network call happened at all, not what it did with a
/// successful response — that success-path behaviour is BootstrapUpdaterTests'
/// job.
/// </summary>
public sealed class WorkerBootstrapUpdateScheduleTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"patched-worker-bootstrap-{Guid.NewGuid():N}");
    private readonly string _suspendedFile;
    private readonly ArtifactTrust _trust;

    public WorkerBootstrapUpdateScheduleTests()
    {
        Directory.CreateDirectory(_dir);
        _suspendedFile = Path.Combine(_dir, "suspended");
        var privateKey = new Ed25519PrivateKeyParameters(new SecureRandom());
        _trust = new ArtifactTrust("test-artifact-key", privateKey.GeneratePublicKey().GetEncoded());
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private BootstrapUpdater NewUpdater(HttpMessageHandler handler) =>
        new(NullLogger<BootstrapUpdater>.Instance,
            new Factory(handler),
            CredentialStore.CreateForTests(_suspendedFile),
            () => new AgentConfig { TenantId = "test-tenant", ConfigVersion = 153, UpdateAuthorityVerified = true },
            new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, Path.Combine(_dir, "health.json")),
            _trust,
            // PAT-1293: every fake handler in this file returns 503, so
            // CheckAndStageAsync never reaches the point of staging a marker or
            // scheduling a restart — this fake is never actually invoked here,
            // just required to satisfy BootstrapUpdater's constructor.
            new NoOpRestartScheduler(),
            pendingUpdateFileOverride: Path.Combine(_dir, "pending-agent-update.json"),
            updatesDirOverride: Path.Combine(_dir, "updates"));

    /// <summary>See BootstrapUpdaterTests.FakeRestartScheduler for the fuller
    /// fake used where the restart-scheduling call actually matters; this file's
    /// fake handler always 503s, so BootstrapUpdater never reaches that call.</summary>
    private sealed class NoOpRestartScheduler : IPendingUpdateRestartScheduler
    {
        public bool EnsureScheduled() => true;
    }

    // -------------------------------------------------------------------------
    // Not yet due: no network call, next-check time unchanged.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task RunPeriodicBootstrapUpdateCheckAsync_NotYetDue_DoesNotCallCheckAndStageAsync_LeavesNextCheckUnchanged()
    {
        var handler = new CountingHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var updater = NewUpdater(handler);
        var now = DateTimeOffset.UtcNow;
        var nextCheck = now.AddMinutes(30); // still 30 minutes out
        var interval = TimeSpan.FromHours(1);

        var result = await PatchedWorker.RunPeriodicBootstrapUpdateCheckAsync(
            updater, now, nextCheck, interval, NullLogger<PatchedWorker>.Instance, CancellationToken.None);

        Assert.Equal(0, handler.RequestCount);
        Assert.Equal(nextCheck, result); // unchanged — still due 30 minutes from "now"
    }

    // -------------------------------------------------------------------------
    // PAT-1269 acceptance criterion: the periodic call fires on schedule.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task RunPeriodicBootstrapUpdateCheckAsync_Due_CallsCheckAndStageAsync_AdvancesNextCheckByInterval()
    {
        var handler = new CountingHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var updater = NewUpdater(handler);
        var now = DateTimeOffset.UtcNow;
        var nextCheck = now.AddSeconds(-1); // already due
        var interval = TimeSpan.FromHours(1);

        var result = await PatchedWorker.RunPeriodicBootstrapUpdateCheckAsync(
            updater, now, nextCheck, interval, NullLogger<PatchedWorker>.Instance, CancellationToken.None);

        // CheckAndStageAsync ran — proven by the network call actually happening
        // (this fixture supplies verified update authority, so the envelope
        // fetch runs once the scheduling deadline is reached).
        Assert.Equal(1, handler.RequestCount);
        Assert.Equal(now.Add(interval), result);
    }

    // -------------------------------------------------------------------------
    // Exactly-at-boundary counts as due (">=", not ">").
    // -------------------------------------------------------------------------
    [Fact]
    public async Task RunPeriodicBootstrapUpdateCheckAsync_ExactlyAtNextCheck_CountsAsDue()
    {
        var handler = new CountingHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var updater = NewUpdater(handler);
        var now = DateTimeOffset.UtcNow;
        var interval = TimeSpan.FromHours(1);

        var result = await PatchedWorker.RunPeriodicBootstrapUpdateCheckAsync(
            updater, now, nextCheck: now, interval, NullLogger<PatchedWorker>.Instance, CancellationToken.None);

        Assert.Equal(1, handler.RequestCount);
        Assert.Equal(now.Add(interval), result);
    }

    // -------------------------------------------------------------------------
    // Repeated calls at a cadence shorter than the interval only fire once per
    // interval — proves this cannot become a tight retry loop no matter how often
    // the tick loop itself runs (PatchedWorker's real tick is 15s; the self-update
    // check interval is 1h).
    // -------------------------------------------------------------------------
    [Fact]
    public async Task RunPeriodicBootstrapUpdateCheckAsync_RepeatedTicksWithinInterval_FiresOnlyOnce()
    {
        var handler = new CountingHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var updater = NewUpdater(handler);
        var start = DateTimeOffset.UtcNow;
        var interval = TimeSpan.FromHours(1);
        var nextCheck = start;

        // Simulate several 15s ticks, only the first of which is due.
        for (int i = 0; i < 5; i++)
        {
            var tickTime = start.AddSeconds(15 * i);
            nextCheck = await PatchedWorker.RunPeriodicBootstrapUpdateCheckAsync(
                updater, tickTime, nextCheck, interval, NullLogger<PatchedWorker>.Instance, CancellationToken.None);
        }

        Assert.Equal(1, handler.RequestCount);
    }

    // -------------------------------------------------------------------------
    // PAT-2399: an untrusted install directory refuses staging. The check is still
    // consumed for this interval, so the refusal is re-evaluated hourly, not per tick.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task RunPeriodicBootstrapUpdateCheckAsync_Due_UntrustedInstall_DoesNotStage_AdvancesNextCheck()
    {
        var handler = new CountingHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var now = DateTimeOffset.UtcNow;
        var interval = TimeSpan.FromHours(1);
        var asked = 0;

        var result = await PatchedWorker.RunPeriodicBootstrapUpdateCheckAsync(
            NewUpdater(handler), now, now, interval, NullLogger<PatchedWorker>.Instance, CancellationToken.None,
            installTrusted: () => { asked++; return false; });

        Assert.Equal(0, handler.RequestCount);
        Assert.Equal(1, asked);
        Assert.Equal(now.Add(interval), result);
    }

    private sealed class Factory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler);
    }

    private sealed class CountingHandler(Func<HttpRequestMessage, HttpResponseMessage> route) : HttpMessageHandler
    {
        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            RequestCount++;
            return Task.FromResult(route(request));
        }
    }
}
