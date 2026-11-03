using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1760: enrolment recovery gaps found by code reading after PAT-1754 and PAT-1764.
///
///  1. A suspended marker on a device with no bearer token, and an enrolment token that
///     was never rejected, used to block enrolment for good: PatchedWorker waited out the
///     suspension first, and RefreshEnrollmentToken never signals a retry for the token
///     loaded at start. The marker cannot describe credentials that do not exist, so it
///     no longer gates enrolment. A device that holds credentials still waits.
///  2. The startup decommission check and the self-update check sent requests with no
///     bearer token or HMAC secret after a transient enrolment failure. They now send
///     nothing without the credential snapshot, as the fetchers do.
///  3. A 200 from /v1/enrol whose credentials could not be stored counted as enrolled,
///     so WaitForRecoveryAsync cleared the marker and the loop retried the consumed
///     token. It is now not-enrolled, the marker stays, and the consumed token is not
///     sent again.
///
/// Runs the same code PatchedWorker.ExecuteAsync runs at startup, in the same order
/// (WaitOutSuspensionAsync, then TryEnrolAsync), against CredentialStore.CreateForTests
/// and a counting HTTP handler, so nothing touches Credential Manager, the registry or
/// %ProgramData%\Patched.
/// </summary>
public sealed class EnrolmentRecoveryGapsTests : IDisposable
{
    private const string EnrolledTenant = "tenant-1760";
    private const string HmacSecret = "aGVsbG8td29ybGQtaG1hYy1zZWNyZXQhISE=";

    private static readonly TimeSpan Poll = TimeSpan.FromMilliseconds(5);

    /// <summary>
    /// PAT-2423: how many recovery poll cycles a "still waiting, nothing resent" test
    /// lets run before it cancels the wait. Counted with <see cref="PollProbe"/>, not
    /// timed, so the count is the same on a slow runner.
    /// </summary>
    private const int PollsToObserve = 5;

    private readonly string _tempDir;
    private readonly string _suspendedFile;
    private readonly string _floorFile;

    public EnrolmentRecoveryGapsTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-enrol-gaps-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _suspendedFile = Path.Combine(_tempDir, "suspended");
        _floorFile = Path.Combine(_tempDir, "agent-config.version");
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
            // Best-effort cleanup.
        }
    }

    private sealed class CountingHandler(HttpStatusCode status, string body = "") : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public List<string> Paths { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            RequestCount++;
            Paths.Add(request.RequestUri?.AbsolutePath ?? "");
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body) });
        }
    }

    private sealed class FakeHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler) { BaseAddress = new Uri("https://patched-1760-test.invalid") };
    }

    private sealed class FakeHandoff : IDecommissionHandoff
    {
        public int Calls { get; private set; }
        public bool EnsureStaged(bool purge, int directiveVersion) { Calls++; return true; }
        public bool TriggerNow() { Calls++; return true; }
        public bool EnsureDeregistered() { Calls++; return true; }
    }

    private static string EnrolSuccessBody() =>
        JsonSerializer.Serialize(new { tenant_id = EnrolledTenant, bearer_token = "new-bearer", hmac_secret = HmacSecret });

    /// <summary>
    /// PAT-1763: credentials an enrolment stores go to the store's in-memory writer
    /// (pass one to CreateForTests to inspect it or make it fail), never the host.
    /// </summary>
    private AgentEnroller NewEnroller(CredentialStore creds, HttpMessageHandler handler) =>
        new(NullLogger<AgentEnroller>.Instance, new FakeHttpClientFactory(handler), creds, _floorFile);

    // ---------------------------------------------------------------------
    // 1. A stale suspended marker does not gate enrolment on a device with
    //    no credentials; a device with credentials stays suspended.
    // ---------------------------------------------------------------------

    [Fact]
    public async Task StaleMarker_NoCredentials_TokenPresent_StartupEnrolsAndClearsTheMarker()
    {
        // The token was present at process start (as LoadForStartup loads it) and
        // the refresh source returns the same value, so RefreshEnrollmentToken can
        // never signal a retry. Before PAT-1760 the startup gate waited forever.
        var writer = new InMemoryAgentCredentialWriter();
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "",
            enrollmentTokenSource: () => "never-rejected-token",
            enrollmentToken: "never-rejected-token", credentialWriter: writer);
        creds.MarkSuspended();

        var handler = new CountingHandler(HttpStatusCode.OK, EnrolSuccessBody());
        var enroller = NewEnroller(creds, handler);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));

        await PatchedWorker.WaitOutSuspensionAsync(
            creds, enroller, NullLogger<PatchedWorker>.Instance, Poll, Poll, cts.Token);
        Assert.True(creds.IsSuspended); // the gate itself never clears the marker

        Assert.True(await enroller.TryEnrolAsync(cts.Token));

        Assert.Equal(1, handler.RequestCount);
        Assert.Equal(new[] { "/v1/enrol" }, handler.Paths);
        Assert.Equal(new[] { EnrolledTenant }, writer.PersistedTenants);
        Assert.False(creds.IsSuspended);
    }

    [Fact]
    public async Task StaleMarker_CredentialsPresent_StaysSuspended_EvenWithAnEnrolmentTokenPresent()
    {
        // A device that holds credentials and was really rejected. Even with an
        // enrolment token sitting alongside, the marker describes its credentials,
        // so the gate must wait and nothing may call /v1/enrol.
        var writer = new InMemoryAgentCredentialWriter { FailWith = new InvalidOperationException("must not persist") };
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "enrolled-bearer",
            enrollmentTokenSource: () => "some-token",
            enrollmentToken: "some-token", credentialWriter: writer);
        creds.MarkSuspended();

        var handler = new CountingHandler(HttpStatusCode.OK, EnrolSuccessBody());
        var enroller = NewEnroller(creds, handler);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(80));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            PatchedWorker.WaitOutSuspensionAsync(
                creds, enroller, NullLogger<PatchedWorker>.Instance, Poll, Poll, cts.Token));

        Assert.True(creds.IsSuspended);
        Assert.Equal(0, handler.RequestCount);
        Assert.False(PatchedWorker.SuspendedMarkerCannotGateEnrolment(creds));
    }

    [Fact]
    public async Task StaleMarker_NoCredentials_NoToken_StillWaits()
    {
        // Nothing to enrol with: skipping the wait would only let the device run
        // without credentials. It keeps waiting for a fresh token.
        var creds = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", enrollmentTokenSource: () => null);
        creds.MarkSuspended();

        var handler = new CountingHandler(HttpStatusCode.OK, EnrolSuccessBody());
        var enroller = NewEnroller(creds, handler);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(80));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            PatchedWorker.WaitOutSuspensionAsync(
                creds, enroller, NullLogger<PatchedWorker>.Instance, Poll, Poll, cts.Token));

        Assert.True(creds.IsSuspended);
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task MarkerFromARealRejection_AfterRestart_TriesTheTokenOnce_ThenWaitsWithoutRetrying()
    {
        // The documented cost of item 1: after a restart a token that really was
        // rejected looks the same as a stale marker, so it is tried once more.
        // The 410 re-suspends, and WaitForRecoveryAsync does not send it again.
        var polls = new PollProbe();
        var writer = new InMemoryAgentCredentialWriter { FailWith = new InvalidOperationException("must not persist") };
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "",
            enrollmentTokenSource: () => { polls.Record(); return "rejected-token"; },
            enrollmentToken: "rejected-token", credentialWriter: writer);
        creds.MarkSuspended();

        var handler = new CountingHandler(HttpStatusCode.Gone);
        var enroller = NewEnroller(creds, handler);

        using var startup = new CancellationTokenSource(TimeSpan.FromSeconds(30)); // safety net only

        await PatchedWorker.WaitOutSuspensionAsync(
            creds, enroller, NullLogger<PatchedWorker>.Instance, Poll, Poll, startup.Token);
        Assert.False(await enroller.TryEnrolAsync(startup.Token));
        Assert.True(creds.IsSuspended);
        Assert.Equal(1, handler.RequestCount);

        // PAT-2423: the token is re-read on every one of these cycles and is still the
        // rejected one, so none of them may send it.
        await polls.AssertStillWaitingAfterAsync(PollsToObserve, ct => enroller.WaitForRecoveryAsync(Poll, Poll, ct));

        Assert.Equal(1, handler.RequestCount);
        Assert.True(creds.IsSuspended);
    }

    // ---------------------------------------------------------------------
    // 1b (review round 2). "Enrolled" is DeviceCredentials.Present everywhere:
    //     a bearer token with an unusable HMAC secret is not enrolled, so a
    //     present or newly provisioned token recovers it; a usable pair still
    //     waits.
    // ---------------------------------------------------------------------

    [Theory]
    [InlineData("   ")]
    [InlineData("\t")]
    [InlineData("")]
    public async Task UnusableSecret_Marker_TokenPresentAtStart_EnrolsAndClearsTheMarker(string hmacSecret)
    {
        var writer = new InMemoryAgentCredentialWriter();
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "stored-bearer", hmacSecret: hmacSecret,
            enrollmentTokenSource: () => "fresh-token", enrollmentToken: "fresh-token", credentialWriter: writer);
        creds.MarkSuspended();

        var handler = new CountingHandler(HttpStatusCode.OK, EnrolSuccessBody());
        var enroller = NewEnroller(creds, handler);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));

        // Startup order: the gate must not wait, and TryEnrolAsync must not treat
        // the non-empty bearer token as "already enrolled".
        await PatchedWorker.WaitOutSuspensionAsync(
            creds, enroller, NullLogger<PatchedWorker>.Instance, Poll, Poll, cts.Token);
        Assert.True(await enroller.TryEnrolAsync(cts.Token));

        Assert.Equal(new[] { "/v1/enrol" }, handler.Paths);
        Assert.Equal(new[] { EnrolledTenant }, writer.PersistedTenants);
        Assert.False(creds.IsSuspended);
    }

    [Fact]
    public async Task UnusableSecret_Marker_TokenProvisionedLater_RecoversInsteadOfLoopingSuspended()
    {
        // The review's case: bearer non-empty, whitespace secret, marker, and a
        // token that only appears after the wait has started. The token refresh
        // must not short-circuit on the bearer token alone.
        string? currentToken = null;
        var writer = new InMemoryAgentCredentialWriter();
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "stored-bearer", hmacSecret: "   ",
            enrollmentTokenSource: () => currentToken, credentialWriter: writer);
        creds.MarkSuspended();

        var handler = new CountingHandler(HttpStatusCode.OK, EnrolSuccessBody());
        var enroller = NewEnroller(creds, handler);

        _ = Task.Run(async () =>
        {
            await Task.Delay(20);
            currentToken = "fresh-token";
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)); // safety net only

        await PatchedWorker.WaitOutSuspensionAsync(
            creds, enroller, NullLogger<PatchedWorker>.Instance, Poll, Poll, cts.Token);

        Assert.Equal(new[] { "/v1/enrol" }, handler.Paths);
        Assert.Equal(new[] { EnrolledTenant }, writer.PersistedTenants);
        Assert.False(creds.IsSuspended);
    }

    [Fact]
    public async Task UnusableSecret_Marker_NoToken_WaitsSendsNothingAndKeepsCheckingForAToken()
    {
        var tokenReads = new PollProbe();
        var writer = new InMemoryAgentCredentialWriter { FailWith = new InvalidOperationException("must not persist") };
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "stored-bearer", hmacSecret: "   ",
            enrollmentTokenSource: () => { tokenReads.Record(); return null; }, credentialWriter: writer);
        creds.MarkSuspended();

        var handler = new CountingHandler(HttpStatusCode.Unauthorized);
        var enroller = NewEnroller(creds, handler);

        // Blocks: no collection can follow while the marker is there. The refresh is
        // not short-circuited by the bearer token, so a token provisioned later would
        // be seen: this fails unless the enrolment-token source is re-read
        // PollsToObserve times while waiting (PAT-2423: counted, not timed).
        await tokenReads.AssertStillWaitingAfterAsync(PollsToObserve, ct =>
            PatchedWorker.WaitOutSuspensionAsync(
                creds, enroller, NullLogger<PatchedWorker>.Instance, Poll, Poll, ct));

        // Nothing else on the worker's startup path sends either.
        var fetcher = new AgentConfigFetcher(
            NullLogger<AgentConfigFetcher>.Instance, new FakeHttpClientFactory(handler), creds,
            Path.Combine(_tempDir, "agent-config.json"), _floorFile);
        Assert.Null(await fetcher.FetchAsync(CancellationToken.None));
        // PAT-1765: the check runs, told there are no credentials, so it cannot report.
        var credentialsSeen = new List<bool>();
        await PatchedWorker.RunDecommissionCheckForTickAsync(
            creds, (present, _) => { credentialsSeen.Add(present); return Task.CompletedTask; }, NullLogger<PatchedWorker>.Instance, CancellationToken.None);
        Assert.True(await enroller.TryEnrolAsync(CancellationToken.None)); // no token: nothing to try, nothing sent

        Assert.Equal(0, handler.RequestCount);
        Assert.Equal(new[] { false }, credentialsSeen);
        Assert.True(creds.IsSuspended);
        Assert.True(tokenReads.Count >= PollsToObserve, "expected the enrolment-token source to be re-read while waiting");
    }

    [Fact]
    public async Task UsablePair_Marker_StillWaits_AndNeverConsultsTheTokenSource()
    {
        var writer = new InMemoryAgentCredentialWriter { FailWith = new InvalidOperationException("must not persist") };
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "enrolled-bearer", hmacSecret: HmacSecret,
            enrollmentTokenSource: () => throw new InvalidOperationException("a usable pair must not look for a token"), credentialWriter: writer);
        creds.MarkSuspended();

        var handler = new CountingHandler(HttpStatusCode.OK, EnrolSuccessBody());
        var enroller = NewEnroller(creds, handler);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(80));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            PatchedWorker.WaitOutSuspensionAsync(
                creds, enroller, NullLogger<PatchedWorker>.Instance, Poll, Poll, cts.Token));

        Assert.True(creds.IsSuspended);
        Assert.Equal(0, handler.RequestCount);
        Assert.True(await enroller.TryEnrolAsync(CancellationToken.None)); // already enrolled
        Assert.Equal(0, handler.RequestCount);
    }

    public static IEnumerable<object?[]> UnusableEnrolResponses() => new[]
    {
        new object?[] { "   ", HmacSecret },
        new object?[] { "",    HmacSecret },
        new object?[] { null,  HmacSecret },
        new object?[] { "new-bearer", "   " },
        new object?[] { "new-bearer", "\t" },
        new object?[] { "new-bearer", null },
    };

    [Theory]
    [MemberData(nameof(UnusableEnrolResponses))]
    public async Task EnrolResponse_UnusableBearerOrSecret_IsNotEnrolled_StoresNothing_AndSuspends(string? bearer, string? secret)
    {
        AgentConfigRollbackFloor.Write(_floorFile, "previous-tenant", 12);
        var polls = new PollProbe();
        var writer = new InMemoryAgentCredentialWriter();
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "",
            enrollmentTokenSource: () => { polls.Record(); return "fresh-token"; },
            enrollmentToken: "fresh-token", credentialWriter: writer);
        var body = JsonSerializer.Serialize(new { tenant_id = EnrolledTenant, bearer_token = bearer, hmac_secret = secret });
        var handler = new CountingHandler(HttpStatusCode.OK, body);
        var enroller = NewEnroller(creds, handler);

        Assert.False(await enroller.TryEnrolAsync(CancellationToken.None));

        Assert.Equal(1, handler.RequestCount);
        Assert.Empty(writer.Written);
        Assert.True(creds.IsSuspended);
        Assert.Equal("", creds.BearerToken);
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed("previous-tenant", 12), AgentConfigRollbackFloor.Read(_floorFile));

        // The consumed token is not sent again while waiting.
        await polls.AssertStillWaitingAfterAsync(PollsToObserve, ct => enroller.WaitForRecoveryAsync(Poll, Poll, ct));
        Assert.Equal(1, handler.RequestCount);
        Assert.Empty(writer.Written);
    }

    // ---------------------------------------------------------------------
    // 2. The startup decommission check sends nothing without credentials.
    //    (The self-update check's equivalent lives in BootstrapUpdaterTests,
    //    which owns the artifact signing fixtures.)
    // ---------------------------------------------------------------------

    private (DecommissionRunner Runner, FakeHandoff Handoff) NewDecommissionRunner(CredentialStore creds, HttpMessageHandler handler)
    {
        var health = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, Path.Combine(_tempDir, "agent-health.json"));
        var reporter = new DecommissionStatusReporter(
            NullLogger<DecommissionStatusReporter>.Instance, new FakeHttpClientFactory(handler), creds,
            maxAttempts: 1, retryDelay: TimeSpan.Zero);
        var handoff = new FakeHandoff();
        var runner = new DecommissionRunner(
            NullLogger<DecommissionRunner>.Instance, health, reporter, handoff,
            Path.Combine(_tempDir, "decommission-initiated.json"));
        return (runner, handoff);
    }

    private static AgentConfig DueDecommission() =>
        AgentConfig.Defaults with { ConfigVersion = 9, Decommission = new DecommissionPolicy { ModeRaw = "immediate" } };

    public static IEnumerable<object[]> MissingCredentials() => new[]
    {
        new object[] { "",   "dGVzdC1obWFjLXNlY3JldC0zMi1ieXRlcy1sb25nIQ==" },
        new object[] { "  ", "dGVzdC1obWFjLXNlY3JldC0zMi1ieXRlcy1sb25nIQ==" },
        new object[] { "enrolled-bearer", "" },
        new object[] { "enrolled-bearer", "   " },
        new object[] { "enrolled-bearer", "\t" },
    };

    [Theory]
    [InlineData("", HmacSecret)]
    [InlineData("   ", HmacSecret)]
    [InlineData("enrolled-bearer", "")]
    [InlineData("enrolled-bearer", "   ")]
    [InlineData("enrolled-bearer", "\t")]
    public void DeviceCredentials_BlankBearerOrSecret_IsNotAUsableSnapshot(string bearerToken, string hmacSecret)
    {
        // Review fix: a whitespace secret decodes to an empty HMAC key, so it is
        // not a credential any more than an empty one is.
        var creds = CredentialStore.ForTesting("test-tenant", bearerToken, hmacSecret);

        Assert.False(DeviceCredentials.TryRead(creds, out _, out _));
        Assert.False(DeviceCredentials.Present(creds));
    }

    [Fact]
    public void DeviceCredentials_BearerAndSecretPresent_IsAUsableSnapshot()
    {
        var creds = CredentialStore.ForTesting("test-tenant", "enrolled-bearer", HmacSecret);

        Assert.True(DeviceCredentials.TryRead(creds, out var bearer, out var secret));
        Assert.Equal("enrolled-bearer", bearer);
        Assert.Equal(HmacSecret, secret);
        Assert.True(DeviceCredentials.Present(creds));
    }

    [Theory]
    [MemberData(nameof(MissingCredentials))]
    public async Task DecommissionCheck_NoCredentialSnapshot_SendsNoRequestAndStagesNothing(string bearerToken, string hmacSecret)
    {
        var creds = CredentialStore.ForTesting("test-tenant", bearerToken, hmacSecret);
        var handler = new CountingHandler(HttpStatusCode.Unauthorized);
        var (runner, handoff) = NewDecommissionRunner(creds, handler);
        int checks = 0;

        // PAT-1765: the check runs (so a staged trigger can be retried) but a due
        // directive with no marker is not reported or staged without credentials.
        await PatchedWorker.RunDecommissionCheckForTickAsync(
            creds,
            async (present, token) => { checks++; await runner.RunAsync(DueDecommission(), present, token); },
            NullLogger<PatchedWorker>.Instance,
            CancellationToken.None);

        Assert.Equal(1, checks);
        Assert.Equal(0, handler.RequestCount);
        Assert.Equal(0, handoff.Calls);
    }

    [Fact]
    public async Task DecommissionCheck_WithCredentials_RunsAndReports()
    {
        // Control for the test above: the same due directive with credentials does
        // reach the platform, so a zero count there is the gate, not the fixture.
        var creds = CredentialStore.ForTesting("test-tenant", "enrolled-bearer", HmacSecret);
        var handler = new CountingHandler(HttpStatusCode.OK, """{"decommission":"superseded"}""");
        var (runner, _) = NewDecommissionRunner(creds, handler);

        await PatchedWorker.RunDecommissionCheckForTickAsync(
            creds, (present, token) => runner.RunAsync(DueDecommission(), present, token),
            NullLogger<PatchedWorker>.Instance, CancellationToken.None);

        Assert.Equal(new[] { "/v1/agent-decommission-status" }, handler.Paths);
    }

    // ---------------------------------------------------------------------
    // 3. A failed credential write after a 200 is not-enrolled, keeps the
    //    marker, and never resends the consumed token.
    // ---------------------------------------------------------------------

    [Fact]
    public async Task CredentialWriteFails_ReturnsNotEnrolled_AndLeavesTheDeviceSuspended()
    {
        var writer = new InMemoryAgentCredentialWriter { FailWith = new InvalidOperationException("credential store unavailable") };
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", enrollmentTokenSource: () => "fresh-token", enrollmentToken: "fresh-token", credentialWriter: writer);
        var handler = new CountingHandler(HttpStatusCode.OK, EnrolSuccessBody());
        var enroller = NewEnroller(creds, handler);

        Assert.False(await enroller.TryEnrolAsync(CancellationToken.None));

        Assert.Equal(1, handler.RequestCount);
        Assert.True(creds.IsSuspended);
        Assert.Equal("", creds.BearerToken);
    }

    [Fact]
    public async Task CredentialWriteFails_DuringRecovery_KeepsTheMarker_AndDoesNotResendTheConsumedToken()
    {
        // PAT-2423: this used to set the token from a background task after 15 ms and
        // cancel the wait on a 250 ms timer. On a slow runner the timer fired before a
        // poll saw the token, and the test failed with 0 requests. The token now appears
        // on a counted re-read, and the wait is cancelled after a counted number more.
        const int TokenAppearsOnRead = 3; // no token for the first two cycles, as when an admin drops one later
        var polls = new PollProbe();
        var writer = new InMemoryAgentCredentialWriter { FailWith = new InvalidOperationException("credential store unavailable") };
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "",
            enrollmentTokenSource: () => polls.Record() >= TokenAppearsOnRead ? "fresh-token" : null, // consumed by the first 200
            credentialWriter: writer);
        creds.MarkSuspended();

        var handler = new CountingHandler(HttpStatusCode.OK, EnrolSuccessBody());
        var enroller = NewEnroller(creds, handler);

        // Before PAT-1760 the failed write read as enrolled, the marker was
        // cleared and this returned normally. Now it keeps waiting: the cycle that
        // first reads the token sends it once, and each of the PollsToObserve cycles
        // after it reads the same token again and must not send it.
        await polls.AssertStillWaitingAfterAsync(TokenAppearsOnRead + PollsToObserve, ct =>
            enroller.WaitForRecoveryAsync(Poll, Poll, ct));

        Assert.True(creds.IsSuspended);
        Assert.Equal(1, handler.RequestCount);
        Assert.Equal(new[] { "/v1/enrol" }, handler.Paths);
    }
}
