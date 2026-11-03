using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1204: tests for PatchedWorker.WaitOutSuspensionAsync — the gate the main run
/// loop in PatchedWorker.ExecuteAsync now calls at the top of every tick (mirroring
/// the identical gate at startup), closing the gap where a device revoked (401 ->
/// CredentialStore.MarkSuspended()) WHILE the loop was already past startup and
/// actively ticking kept calling RunCycleSafeAsync (collection + enforcement) every
/// TriggerPollInterval until a full service restart — even though
/// AgentConfigManager's independent background poll would eventually have cleared
/// the marker on its own if the device were reinstated.
///
/// Same constraint as WorkerTierGateTests: PatchedWorker's constructor has 17
/// dependencies and no test in this repo constructs the whole thing, so — exactly
/// like ActuatingTierAllows — the gate logic is exercised directly via the
/// extracted, internal, static WaitOutSuspensionAsync (visible to this assembly via
/// Service.csproj's InternalsVisibleTo) instead of driving PatchedWorker.ExecuteAsync
/// end to end. WaitOutSuspensionAsync IS the exact code the main loop now runs at the
/// top of every iteration before touching anything else, so proving it blocks while
/// IsSuspended is true and returns promptly once it clears is equivalent to proving
/// the loop-level "stops enforcing/collecting on the next iteration, resumes after
/// recovery" behaviour the ticket asks for — nothing else sits between this gate and
/// the trigger-drain / scheduled-run code that would otherwise call RunCycleSafeAsync.
///
/// Same isolation approach as AgentEnrollerRecoveryTests: a RecordingHandler stands
/// in for the network, and CredentialStore.CreateForTests(...) keeps every instance
/// off the real Windows Credential Manager / %ProgramData%\Patched\creds / registry.
/// </summary>
public sealed class WorkerMidRunSuspensionTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _suspendedFile;

    public WorkerMidRunSuspensionTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-worker-midrun-suspend-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _suspendedFile = Path.Combine(_tempDir, "suspended");
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup; a leftover temp dir from a test run isn't worth failing over.
        }
    }

    /// <summary>Never answers with anything but Gone — no test here needs a real /v1/enrol success.</summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            RequestCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Gone) { Content = new StringContent("") });
        }
    }

    private sealed class FakeHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;
        public FakeHttpClientFactory(HttpMessageHandler handler) => _handler = handler;
        public HttpClient CreateClient(string name) =>
            new(_handler) { BaseAddress = new Uri("https://patched-1204-test.invalid") };
    }

    [Fact]
    public async Task WaitOutSuspensionAsync_NotSuspended_ReturnsImmediatelyWithoutTouchingEnroller()
    {
        // Models every ordinary tick: the device was never suspended, so the gate the
        // loop now runs every TriggerPollInterval must be a true no-op — it must not
        // block, delay, or make any network call via AgentEnroller.
        var creds = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "already-enrolled-bearer");
        Assert.False(creds.IsSuspended);

        var handler  = new RecordingHandler();
        var enroller = new AgentEnroller(NullLogger<AgentEnroller>.Instance, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.version"));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)); // safety net only

        var sw = System.Diagnostics.Stopwatch.StartNew();
        await PatchedWorker.WaitOutSuspensionAsync(
            creds, enroller, NullLogger<PatchedWorker>.Instance,
            pollInterval: TimeSpan.FromMilliseconds(5),
            enrollmentRecheckInterval: TimeSpan.FromMilliseconds(5),
            cts.Token);
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds < 1000, $"expected an immediate no-op, took {sw.ElapsedMilliseconds}ms");
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task WaitOutSuspensionAsync_SuspendedMidRun_BlocksInsteadOfLettingTheLoopContinue()
    {
        // Models the exact scenario the ticket describes: the device was fine at
        // startup and through prior iterations (already-enrolled, has a bearer
        // token), then gets revoked between two run-loop iterations — nothing
        // rewrites BearerToken or EnrollmentToken, only the suspended marker
        // appears, exactly as CredentialStore.MarkSuspended() does from a 401.
        var creds = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "already-enrolled-bearer");
        Assert.False(creds.IsSuspended);

        creds.MarkSuspended(); // simulates the mid-run 401 -> MarkSuspended() the ticket describes
        Assert.True(creds.IsSuspended);

        var handler  = new RecordingHandler();
        var enroller = new AgentEnroller(NullLogger<AgentEnroller>.Instance, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.version"));

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(60));

        // The gate must not return while still suspended — a real caller (the main
        // loop) would proceed straight into trigger-draining / scheduled-run
        // handling (and eventually RunCycleSafeAsync) the instant this call
        // returns, so "still blocked when cancellation fires" is exactly the
        // "does not continue enforcing" property under test.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            PatchedWorker.WaitOutSuspensionAsync(
                creds, enroller, NullLogger<PatchedWorker>.Instance,
                pollInterval: TimeSpan.FromMilliseconds(5),
                enrollmentRecheckInterval: TimeSpan.FromMilliseconds(5),
                cts.Token));

        Assert.True(creds.IsSuspended);

        // Already-enrolled (has a bearer token) is the revocation cause, not the
        // enrollment-token cause — CredentialStore.RefreshEnrollmentToken's own
        // bearer-token guard means WaitForRecoveryAsync must never probe
        // /v1/enrol for this device; it only waits for something external
        // (AgentConfigManager's poll) to clear the marker.
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task WaitOutSuspensionAsync_ClearedByIndependentPoll_ReturnsAndLetsTheNextTickResume()
    {
        // AgentConfigManager runs as its own independent BackgroundService and
        // calls CredentialStore.ClearSuspended() itself the moment a
        // signature-verified 200 arrives — this test stands in for that external
        // clear (exactly as AgentEnrollerRecoveryTests'
        // WaitForRecoveryAsync_AlreadyEnrolledRevokedDevice_NeverConsultsEnrollmentTokenSource
        // does) rather than re-implementing agent-config polling here. Proves the
        // loop-level gate resumes normal operation "within one poll interval" of
        // reinstatement, per the ticket's acceptance bar, instead of staying
        // parked once the underlying cause is gone.
        var creds = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "already-enrolled-bearer");
        creds.MarkSuspended();

        var handler  = new RecordingHandler();
        var enroller = new AgentEnroller(NullLogger<AgentEnroller>.Instance, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.version"));

        _ = Task.Run(async () =>
        {
            await Task.Delay(15);
            creds.ClearSuspended(); // stand-in for AgentConfigManager's verified-200 clear
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)); // safety net only

        await PatchedWorker.WaitOutSuspensionAsync(
            creds, enroller, NullLogger<PatchedWorker>.Instance,
            pollInterval: TimeSpan.FromMilliseconds(5),
            enrollmentRecheckInterval: TimeSpan.FromMilliseconds(5),
            cts.Token); // must return normally once cleared, letting the caller (loop) fall through and resume

        Assert.False(creds.IsSuspended);
        Assert.Equal(0, handler.RequestCount);
    }
}
