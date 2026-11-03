using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1203: tests for AgentEnroller.WaitForRecoveryAsync — the replacement
/// for the "Task.Delay(Timeout.Infinite); return;" one-way latch PatchedWorker
/// used to hit on a terminal /v1/enrol rejection (410/401). Proves:
///
///  1. A terminal enrollment failure leaves the device in the WAIT state
///     (IsSuspended stays true, WaitForRecoveryAsync blocks) rather than
///     returning immediately — the "not a hard exit" requirement.
///  2. A token that never changes is retried at most once, never on every
///     subsequent tick — the busy-retry-with-a-stale-token failure mode this
///     ticket also flagged in macOS's patched-enroll.sh.
///  3. A genuinely NEW token appearing mid-wait triggers a retry that, on
///     success, clears the suspended marker and lets the method return so
///     the caller can resume normal operation.
///  4. The loop respects the poll interval instead of busy-looping.
///
/// Same isolation approach as AgentConfigFetcherSuspendedTests: a
/// RecordingHandler stands in for the network, and
/// CredentialStore.CreateForTests(...) (extended by this ticket with a
/// bearerToken override and an injectable enrollment-token source) keeps
/// every instance off the real Windows Credential Manager / %ProgramData%\
/// Patched\creds / registry.
/// </summary>
public sealed class AgentEnrollerRecoveryTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _suspendedFile;

    public AgentEnrollerRecoveryTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-enroller-recovery-test-{Guid.NewGuid():N}");
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

    /// <summary>Counts requests and always answers with a fixed status/body, both mutable per-test.</summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public HttpStatusCode ResponseStatus { get; set; } = HttpStatusCode.Gone;
        public string ResponseBody { get; set; } = "";

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            RequestCount++;
            var resp = new HttpResponseMessage(ResponseStatus) { Content = new StringContent(ResponseBody) };
            return Task.FromResult(resp);
        }
    }

    private sealed class FakeHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;
        public FakeHttpClientFactory(HttpMessageHandler handler) => _handler = handler;
        public HttpClient CreateClient(string name) =>
            new(_handler) { BaseAddress = new Uri("https://patched-1203-test.invalid") };
    }

    /// <summary>PAT-1763: the scratch-path enroller; the floor never lands in %ProgramData%\Patched.</summary>
    private AgentEnroller NewEnroller(HttpMessageHandler handler, CredentialStore creds) =>
        new(NullLogger<AgentEnroller>.Instance, new FakeHttpClientFactory(handler), creds,
            Path.Combine(_tempDir, "agent-config.version"));

    private static string EnrolSuccessBody(string tenantId, string bearerToken, string hmacSecret) =>
        JsonSerializer.Serialize(new { tenant_id = tenantId, bearer_token = bearerToken, hmac_secret = hmacSecret });

    [Fact]
    public async Task WaitForRecoveryAsync_NoEnrollmentTokenEverAppears_BlocksInsteadOfReturningImmediately()
    {
        var creds = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", enrollmentTokenSource: () => null);
        creds.MarkSuspended();
        Assert.True(creds.IsSuspended);

        var handler  = new RecordingHandler();
        var enroller = NewEnroller(handler, creds);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(60));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            enroller.WaitForRecoveryAsync(
                pollInterval: TimeSpan.FromMilliseconds(5),
                enrollmentRecheckInterval: TimeSpan.FromMilliseconds(5),
                cts.Token));

        // Never returned normally — it was still blocked (suspended) when
        // cancellation fired, i.e. this is a wait state, not a hard exit.
        Assert.True(creds.IsSuspended);
        Assert.Equal(0, handler.RequestCount); // no token ever appeared -> never even tried
    }

    [Fact]
    public async Task WaitForRecoveryAsync_StaleTokenNeverChanges_OnlyRetriesEnrollmentOnce()
    {
        // Same token on every recheck — models a device parked with the
        // already-rejected token still sitting on disk (no admin action
        // yet). Must NOT re-POST /v1/enrol on every tick, mirroring the exact
        // stale-token retry loop this ticket flagged in the macOS
        // patched-enroll.sh 410/401 branch.
        var polls = new PollProbe();
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "",
            enrollmentTokenSource: () => { polls.Record(); return "already-rejected-token"; });
        creds.MarkSuspended();

        var handler = new RecordingHandler { ResponseStatus = HttpStatusCode.Gone };
        var enroller = NewEnroller(handler, creds);

        // PAT-2423: counted, not timed. This used to cancel on an 80 ms timer, which
        // on a slow runner can fire before the first tick has sent anything. The
        // first re-read sends the token and gets the 410; the five ticks after it
        // re-read the same token.
        await polls.AssertStillWaitingAfterAsync(6, ct =>
            enroller.WaitForRecoveryAsync(
                pollInterval: TimeSpan.FromMilliseconds(5),
                enrollmentRecheckInterval: TimeSpan.FromMilliseconds(5),
                ct));

        // The token never changed after the first rejection, so exactly one
        // /v1/enrol call should have happened, not one per tick.
        Assert.Equal(1, handler.RequestCount);
        Assert.True(creds.IsSuspended);
    }

    [Fact]
    public async Task WaitForRecoveryAsync_FreshTokenAppears_RetriesSucceeds_ClearsSuspensionAndReturns()
    {
        string? currentToken = null; // no token yet — admin hasn't acted
        var writer = new InMemoryAgentCredentialWriter();
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", enrollmentTokenSource: () => currentToken, credentialWriter: writer);
        creds.MarkSuspended();

        var handler = new RecordingHandler
        {
            ResponseStatus = HttpStatusCode.OK,
            ResponseBody   = EnrolSuccessBody("tenant-1", "new-bearer-token", "aGVsbG8td29ybGQtaG1hYy1zZWNyZXQhISE="),
        };
        // PAT-1756: a successful enrolment now resets the agent-config
        // anti-rollback floor, so point it at a scratch path. PAT-1763: every
        // enroller in this file uses the scratch-path constructor, and the store's
        // in-memory credential writer records what the enrolment stored, so the
        // test never touches the real Windows Credential Manager, file store or
        // registry provisioning key.
        var enroller = NewEnroller(handler, creds);

        // Flip in a fresh token shortly after the wait starts, simulating an
        // admin dropping one while the device is parked.
        _ = Task.Run(async () =>
        {
            await Task.Delay(15);
            currentToken = "brand-new-token";
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)); // safety net only

        await enroller.WaitForRecoveryAsync(
            pollInterval: TimeSpan.FromMilliseconds(5),
            enrollmentRecheckInterval: TimeSpan.FromMilliseconds(5),
            cts.Token); // must return normally, not throw/hang

        // The retry was actually attempted against the new token, and the
        // wait loop exited (proving WaitForRecoveryAsync doesn't hang once
        // TryEnrolAsync stops returning false).
        Assert.True(handler.RequestCount >= 1);
        Assert.False(creds.IsSuspended);

        Assert.Equal(new[] { "tenant-1" }, writer.PersistedTenants);
        Assert.Equal("new-bearer-token", creds.BearerToken);
    }

    [Fact]
    public async Task WaitForRecoveryAsync_RespectsPollInterval_DoesNotBusyLoop()
    {
        var creds = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", enrollmentTokenSource: () => null);
        creds.MarkSuspended();

        var handler  = new RecordingHandler();
        var enroller = NewEnroller(handler, creds);

        var pollInterval = TimeSpan.FromMilliseconds(40);
        using var cts = new CancellationTokenSource(pollInterval * 3 + TimeSpan.FromMilliseconds(20));

        var sw = System.Diagnostics.Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            enroller.WaitForRecoveryAsync(pollInterval, TimeSpan.FromMinutes(5), cts.Token));
        sw.Stop();

        // A busy loop would return almost instantly; a loop that honours
        // pollInterval needs at least ~2 full ticks before the 3rd delay is
        // cancelled mid-flight.
        Assert.True(sw.ElapsedMilliseconds >= pollInterval.TotalMilliseconds * 2,
            $"expected at least {pollInterval.TotalMilliseconds * 2}ms, took {sw.ElapsedMilliseconds}ms — loop is not respecting pollInterval");
    }

    [Fact]
    public async Task WaitForRecoveryAsync_AlreadyEnrolledRevokedDevice_NeverConsultsEnrollmentTokenSource()
    {
        // Revocation-suspended device: BearerToken is already set. This
        // method must not probe the enrollment-token source at all for that
        // cause (RefreshEnrollmentToken's own bearer-token guard) — it can
        // only ever wait for IsSuspended to clear via some other path
        // (AgentConfigManager, exercised elsewhere). Simulate that external
        // clear directly, so the loop exits promptly without this test
        // needing a real agent-config round trip.
        var creds = CredentialStore.CreateForTests(
            _suspendedFile,
            bearerToken: "already-enrolled-bearer",
            enrollmentTokenSource: () => throw new InvalidOperationException(
                "must not consult the enrollment-token source for a revocation-suspended (already-enrolled) device"));
        creds.MarkSuspended();

        var handler  = new RecordingHandler();
        var enroller = NewEnroller(handler, creds);

        _ = Task.Run(async () =>
        {
            await Task.Delay(15);
            creds.ClearSuspended(); // stand-in for AgentConfigManager's verified-200 clear
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)); // safety net only

        await enroller.WaitForRecoveryAsync(
            pollInterval: TimeSpan.FromMilliseconds(5),
            enrollmentRecheckInterval: TimeSpan.FromMilliseconds(5),
            cts.Token);

        Assert.False(creds.IsSuspended);
        Assert.Equal(0, handler.RequestCount);
    }
}
