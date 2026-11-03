using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1765: enrolment hardening leftovers after PAT-1760 and PAT-1763. Each case is a
/// way a device went dark or noisy during a rollout without a clear signal.
///
/// Runs against CredentialStore.CreateForTests and a recording HTTP handler, with the
/// suspended marker and anti-rollback floor under a scratch directory, so nothing
/// touches Credential Manager, the registry or %ProgramData%\Patched.
/// </summary>
public sealed class EnrolmentHardeningTests : IDisposable
{
    private const string EnrolledTenant = "tenant-1765";
    private const string HmacSecret = "aGVsbG8td29ybGQtaG1hYy1zZWNyZXQhISE=";

    private static readonly TimeSpan Poll = TimeSpan.FromMilliseconds(5);

    private readonly string _tempDir;
    private readonly string _suspendedFile;
    private readonly string _floorFile;

    public EnrolmentHardeningTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-enrol-hardening-test-{Guid.NewGuid():N}");
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

    /// <summary>Answers each request from <see cref="Respond"/> and records the path.</summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly object _gate = new();
        private readonly List<string> _paths = new();

        public Func<HttpRequestMessage, HttpResponseMessage> Respond { get; set; } =
            _ => new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("") };

        public int RequestCount { get { lock (_gate) return _paths.Count; } }
        public List<string> Paths { get { lock (_gate) return new List<string>(_paths); } }

        public static RecordingHandler Always(HttpStatusCode status, string body = "") =>
            new() { Respond = _ => new HttpResponseMessage(status) { Content = new StringContent(body) } };

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            lock (_gate) _paths.Add(request.RequestUri?.AbsolutePath ?? "");
            return Task.FromResult(Respond(request));
        }
    }

    private sealed class FakeHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler) { BaseAddress = new Uri("https://patched-1765-test.invalid") };
    }

    private static string EnrolSuccessBody() =>
        JsonSerializer.Serialize(new { tenant_id = EnrolledTenant, bearer_token = "new-bearer", hmac_secret = HmacSecret });

    private AgentEnroller NewEnroller(
        CredentialStore creds, HttpMessageHandler handler, AgentHealthStore? health = null) =>
        health is null
            ? new(NullLogger<AgentEnroller>.Instance, new FakeHttpClientFactory(handler), creds, _floorFile)
            : new(NullLogger<AgentEnroller>.Instance, new FakeHttpClientFactory(handler), creds, _floorFile, health);

    private AgentHealthStore NewHealth(string name) => new(
        NullLogger<AgentHealthStore>.Instance, Path.Combine(_tempDir, $"{name}.json"));

    /// <summary>
    /// A suspended-marker path whose parent is a plain file, so MarkSuspended's
    /// Directory.CreateDirectory throws on every platform, the way an unwritable creds
    /// directory does on a real device.
    /// </summary>
    private string UnwritableMarkerPath()
    {
        var blocker = Path.Combine(_tempDir, "creds-is-a-file");
        File.WriteAllText(blocker, "not a directory");
        return Path.Combine(blocker, "suspended");
    }

    // ---------------------------------------------------------------------
    // Item 12. A whitespace-only enrolment token is never sent.
    // ---------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\r\n")]
    public async Task WhitespaceEnrolmentToken_IsNotSent_AndDoesNotBypassASuspendedMarker(string blank)
    {
        var creds = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", enrollmentToken: blank);
        var handler = RecordingHandler.Always(HttpStatusCode.Unauthorized);
        var enroller = NewEnroller(creds, handler);

        Assert.True(await enroller.TryEnrolAsync(CancellationToken.None)); // nothing to try
        Assert.Equal(0, handler.RequestCount);
        Assert.False(creds.IsSuspended);

        Assert.False(DeviceCredentials.HasEnrollmentToken(creds));
        Assert.False(PatchedWorker.SuspendedMarkerCannotGateEnrolment(creds));
    }

    // ---------------------------------------------------------------------
    // Item 1. A suspended-marker write that throws does not stop the service.
    // ---------------------------------------------------------------------

    public static IEnumerable<object[]> TerminalEnrolResponses() => new[]
    {
        new object[] { HttpStatusCode.Gone, "" },
        new object[] { HttpStatusCode.Unauthorized, "" },
        new object[] { HttpStatusCode.OK, JsonSerializer.Serialize(new { tenant_id = EnrolledTenant, bearer_token = "   ", hmac_secret = HmacSecret }) },
    };

    [Theory]
    [MemberData(nameof(TerminalEnrolResponses))]
    public async Task MarkerWriteThrows_TryEnrolReturnsNotEnrolled_InsteadOfThrowing_AndDoesNotResendTheToken(HttpStatusCode status, string body)
    {
        var markerPath = UnwritableMarkerPath();
        var creds = CredentialStore.CreateForTests(
            markerPath, bearerToken: "", enrollmentTokenSource: () => "spent-token", enrollmentToken: "spent-token");
        Assert.ThrowsAny<IOException>(() => creds.MarkSuspended()); // the fixture really is unwritable

        var handler = RecordingHandler.Always(status, body);
        var enroller = NewEnroller(creds, handler);

        // Before PAT-1765 the IOException escaped here, then PatchedWorker.ExecuteAsync,
        // and the host stopped the service.
        Assert.False(await enroller.TryEnrolAsync(CancellationToken.None));
        Assert.Equal(1, handler.RequestCount);
        Assert.False(creds.IsSuspended); // the marker could not be written

        // The same process never sends the spent token again: not from the worker's
        // pending-enrolment retry, and not from the recovery wait, which still blocks.
        Assert.False(await enroller.TryEnrolAsync(CancellationToken.None));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(80));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => enroller.WaitForRecoveryAsync(Poll, Poll, cts.Token));
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task MarkerWriteThrows_CredentialWriteFailure_ReturnsNotEnrolled_InsteadOfThrowing()
    {
        var writer = new InMemoryAgentCredentialWriter { FailWith = new InvalidOperationException("credential store unavailable") };
        var creds = CredentialStore.CreateForTests(
            UnwritableMarkerPath(), bearerToken: "", enrollmentToken: "fresh-token", credentialWriter: writer);
        var handler = RecordingHandler.Always(HttpStatusCode.OK, EnrolSuccessBody());
        var enroller = NewEnroller(creds, handler);

        Assert.False(await enroller.TryEnrolAsync(CancellationToken.None));
        Assert.False(await enroller.TryEnrolAsync(CancellationToken.None));
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task SpentTokenRecoveryWait_RecordsOneEnrolmentTokenSpentFaultAcrossPolls()
    {
        var health = NewHealth("spent-token-health");
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", enrollmentTokenSource: () => "spent-token", enrollmentToken: "spent-token");
        var handler = RecordingHandler.Always(HttpStatusCode.Gone);
        var enroller = NewEnroller(creds, handler, health);

        Assert.False(await enroller.TryEnrolAsync(CancellationToken.None));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            enroller.WaitForRecoveryAsync(Poll, Poll, cts.Token));

        var fault = Assert.Single(health.BuildPayloadSection()!.Degraded,
            e => e.Kind == DeviceCredentialHealth.Kind && e.Subject == DeviceCredentialHealth.Subject);
        Assert.Equal(DeviceCredentialHealth.EnrollmentTokenSpentReason, fault.Reason);
        Assert.Equal(1, fault.Count);
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task MarkerWriteThrows_AFreshTokenStillRecoversTheDevice()
    {
        var health = NewHealth("spent-token-recovery-health");
        string? currentToken = "spent-token";
        var creds = CredentialStore.CreateForTests(
            UnwritableMarkerPath(), bearerToken: "", enrollmentTokenSource: () => currentToken, enrollmentToken: "spent-token");
        var handler = new RecordingHandler();
        handler.Respond = _ => handler.RequestCount == 1
            ? new HttpResponseMessage(HttpStatusCode.Gone) { Content = new StringContent("") }
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(EnrolSuccessBody()) };
        var enroller = NewEnroller(creds, handler, health);

        Assert.False(await enroller.TryEnrolAsync(CancellationToken.None));

        _ = Task.Run(async () =>
        {
            await Task.Delay(20);
            currentToken = "fresh-token";
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)); // safety net only
        // ClearSuspended also fails on this path; that must not throw either.
        await enroller.WaitForRecoveryAsync(Poll, Poll, cts.Token);

        Assert.Equal(2, handler.RequestCount);
        Assert.True(DeviceCredentials.Present(creds));
        Assert.DoesNotContain(health.BuildPayloadSection()!.Degraded,
            e => e.Kind == DeviceCredentialHealth.Kind && e.Subject == DeviceCredentialHealth.Subject);
        Assert.NotNull(health.GetLastSuccess(DeviceCredentialHealth.Kind, DeviceCredentialHealth.Subject));
    }

    // ---------------------------------------------------------------------
    // Item 11. A 200 that consumed the token but is unusable is not retried.
    // ---------------------------------------------------------------------

    public static IEnumerable<object[]> ConsumedButUnusableBodies() => new[]
    {
        new object[] { JsonSerializer.Serialize(new { tenant_id = "", bearer_token = "new-bearer", hmac_secret = HmacSecret }) },
        new object[] { JsonSerializer.Serialize(new { tenant_id = "   ", bearer_token = "new-bearer", hmac_secret = HmacSecret }) },
        new object[] { JsonSerializer.Serialize(new { tenant_id = (string?)null, bearer_token = "new-bearer", hmac_secret = HmacSecret }) },
        new object[] { JsonSerializer.Serialize(new { bearer_token = "new-bearer", hmac_secret = HmacSecret }) },
        new object[] { "" },
        new object[] { "not json" },
        new object[] { "[]" },
        new object[] { """{"tenant_id":42,"bearer_token":"new-bearer","hmac_secret":"x"}""" },
    };

    [Theory]
    [MemberData(nameof(ConsumedButUnusableBodies))]
    public async Task Enrol200_UnusableBody_IsNotEnrolled_StoresNothing_Suspends_AndNeverResendsTheToken(string body)
    {
        AgentConfigRollbackFloor.Write(_floorFile, "previous-tenant", 12);
        var writer = new InMemoryAgentCredentialWriter();
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", enrollmentTokenSource: () => "fresh-token", enrollmentToken: "fresh-token", credentialWriter: writer);
        var handler = RecordingHandler.Always(HttpStatusCode.OK, body);
        var enroller = NewEnroller(creds, handler);

        // Before PAT-1765 this returned true ("will retry") and the next poll resent
        // the consumed token.
        Assert.False(await enroller.TryEnrolAsync(CancellationToken.None));

        Assert.True(creds.IsSuspended);
        Assert.Empty(writer.Written);
        Assert.Equal("", creds.BearerToken);
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed("previous-tenant", 12), AgentConfigRollbackFloor.Read(_floorFile));

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(80));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => enroller.WaitForRecoveryAsync(Poll, Poll, cts.Token));
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task Enrol5xx_IsStillTransient()
    {
        // Control: only a 200 consumes the token. A 503 keeps the "retry next poll" path.
        var creds = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", enrollmentToken: "fresh-token");
        var handler = RecordingHandler.Always(HttpStatusCode.ServiceUnavailable);
        var enroller = NewEnroller(creds, handler);

        Assert.True(await enroller.TryEnrolAsync(CancellationToken.None));
        Assert.True(await enroller.TryEnrolAsync(CancellationToken.None));
        Assert.Equal(2, handler.RequestCount);
        Assert.False(creds.IsSuspended);
    }

    // ---------------------------------------------------------------------
    // Item 2. 400, 402, 409 and 429 from /v1/enrol back off exponentially.
    // ---------------------------------------------------------------------

    private sealed class ManualClock
    {
        public DateTimeOffset Now { get; set; } = new(2026, 9, 15, 12, 0, 0, TimeSpan.Zero);
        public void Advance(TimeSpan by) => Now = Now.Add(by);
    }

    [Theory]
    [InlineData(1, 30)]
    [InlineData(2, 60)]
    [InlineData(3, 120)]
    [InlineData(7, 1920)]
    [InlineData(8, 3600)]   // 3840s capped at an hour
    [InlineData(50, 3600)]
    public void BackoffDelay_DoublesFrom30Seconds_CappedAtOneHour(int step, int expectedSeconds) =>
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), AgentEnroller.BackoffDelay(step));

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.PaymentRequired)]
    [InlineData(HttpStatusCode.Conflict)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public async Task BackoffStatus_WaitsOutEachStep_KeepsTheToken_AndNeverSuspends(HttpStatusCode status)
    {
        var clock = new ManualClock();
        var creds = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", enrollmentToken: "kept-token");
        var handler = RecordingHandler.Always(status);
        var enroller = new AgentEnroller(
            NullLogger<AgentEnroller>.Instance, new FakeHttpClientFactory(handler), creds, _floorFile, () => clock.Now);

        // The worker calls TryEnrolAsync every 15-second tick. Walk the ticks and
        // record which ones reach the server.
        var sentAtSeconds = new List<int>();
        for (int second = 0; second <= 900; second += 15)
        {
            clock.Now = new DateTimeOffset(2026, 9, 15, 12, 0, 0, TimeSpan.Zero).AddSeconds(second);
            int before = handler.RequestCount;
            Assert.True(await enroller.TryEnrolAsync(CancellationToken.None)); // still transient
            if (handler.RequestCount > before)
                sentAtSeconds.Add(second);
        }

        // Before PAT-1765 every one of the 61 ticks sent a request.
        // Attempts at 0, then +30s, +60s, +120s, +240s, +480s.
        Assert.Equal(new[] { 0, 30, 90, 210, 450 }, sentAtSeconds);
        Assert.False(creds.IsSuspended);
        Assert.Equal("kept-token", creds.EnrollmentToken);
    }

    [Fact]
    public async Task Backoff_ResetsAfterASuccessfulEnrolment()
    {
        var clock = new ManualClock();
        string? currentToken = "first-token";
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", enrollmentTokenSource: () => currentToken, enrollmentToken: "first-token");
        var handler = new RecordingHandler();
        var status = HttpStatusCode.Conflict;
        handler.Respond = _ => new HttpResponseMessage(status)
        {
            Content = new StringContent(status == HttpStatusCode.OK ? EnrolSuccessBody() : ""),
        };
        var enroller = new AgentEnroller(
            NullLogger<AgentEnroller>.Instance, new FakeHttpClientFactory(handler), creds, _floorFile, () => clock.Now);

        for (int i = 0; i < 4; i++)
        {
            Assert.True(await enroller.TryEnrolAsync(CancellationToken.None));
            clock.Advance(AgentEnroller.BackoffDelay(i + 1));
        }
        Assert.Equal(4, handler.RequestCount);

        status = HttpStatusCode.OK;
        Assert.True(await enroller.TryEnrolAsync(CancellationToken.None));
        Assert.True(DeviceCredentials.Present(creds));
        Assert.Equal(5, handler.RequestCount);

        // The backoff is cleared: the step counter restarts from one next time.
        Assert.Equal(0, enroller.BackoffStep);
    }

    [Fact]
    public async Task Backoff_ADifferentTokenIsTriedStraightAway()
    {
        // 402 and 409 are about the tenant the token belongs to, so a token provisioned
        // for another tenant must not wait out the old token's backoff.
        var clock = new ManualClock();
        string? currentToken = "old-tenant-token";
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", enrollmentTokenSource: () => currentToken, enrollmentToken: "old-tenant-token");
        creds.MarkSuspended(); // lets RefreshEnrollmentToken be driven through the recovery wait
        var handler = new RecordingHandler();
        handler.Respond = _ => handler.RequestCount <= 3
            ? new HttpResponseMessage(HttpStatusCode.Conflict) { Content = new StringContent("") }
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(EnrolSuccessBody()) };
        var enroller = new AgentEnroller(
            NullLogger<AgentEnroller>.Instance, new FakeHttpClientFactory(handler), creds, _floorFile, () => clock.Now);

        for (int i = 0; i < 3; i++)
        {
            if (i > 0)
                clock.Advance(AgentEnroller.BackoffDelay(i));
            Assert.True(await enroller.TryEnrolAsync(CancellationToken.None));
        }
        Assert.Equal(3, enroller.BackoffStep);
        Assert.True(await enroller.TryEnrolAsync(CancellationToken.None)); // inside step 3's window
        Assert.Equal(3, handler.RequestCount);

        currentToken = "new-tenant-token";
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)); // safety net only
        await enroller.WaitForRecoveryAsync(Poll, Poll, cts.Token);

        Assert.Equal(4, handler.RequestCount);
        Assert.True(DeviceCredentials.Present(creds));
        Assert.Equal(0, enroller.BackoffStep);
    }

    // ---------------------------------------------------------------------
    // Item 3. Without credentials a staged removal's trigger is still retried;
    //         only the unacknowledged report is gated.
    // ---------------------------------------------------------------------

    private sealed class CountingHandoff : IDecommissionHandoff
    {
        public int StageCalls { get; private set; }
        public int TriggerCalls { get; private set; }
        public int DeregisterCalls { get; private set; }
        public bool EnsureStaged(bool purge, int directiveVersion) { StageCalls++; return true; }
        public bool TriggerNow() { TriggerCalls++; return true; }
        public bool EnsureDeregistered() { DeregisterCalls++; return true; }
    }

    private sealed class CountingReporter : IDecommissionStatusReporter
    {
        public int Calls { get; private set; }
        public Task<DecommissionReportOutcome> ReportAcknowledgedAsync(DecommissionPolicy policy, int directiveVersion, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(DecommissionReportOutcome.Proceed);
        }
    }

    private string DecommissionMarkerFile => Path.Combine(_tempDir, "decommission-initiated.json");

    private (DecommissionRunner Runner, CountingHandoff Handoff, CountingReporter Reporter) NewDecommissionRunner()
    {
        var health = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, Path.Combine(_tempDir, "agent-health.json"));
        var handoff = new CountingHandoff();
        var reporter = new CountingReporter();
        var runner = new DecommissionRunner(NullLogger<DecommissionRunner>.Instance, health, reporter, handoff, DecommissionMarkerFile);
        return (runner, handoff, reporter);
    }

    private static AgentConfig DueDecommission() =>
        AgentConfig.Defaults with { ConfigVersion = 9, Decommission = new DecommissionPolicy { ModeRaw = "immediate" } };

    [Theory]
    [InlineData("", HmacSecret)]
    [InlineData("enrolled-bearer", "   ")]
    public async Task StagedButUntriggeredRemoval_NoCredentials_RetriesTheTrigger(string bearer, string secret)
    {
        File.WriteAllText(DecommissionMarkerFile,
            """{"initiated_at":"2026-09-15T12:00:00+00:00","purge":false,"directive_version":9,"report_outcome":"Proceed","triggered":false}""");
        var creds = CredentialStore.ForTesting("test-tenant", bearer, secret);
        var (runner, handoff, reporter) = NewDecommissionRunner();

        await PatchedWorker.RunDecommissionCheckForTickAsync(
            creds, (present, token) => runner.RunAsync(DueDecommission(), present, token),
            NullLogger<PatchedWorker>.Instance, CancellationToken.None);

        // Before PAT-1765 the whole check was skipped and the trigger never retried.
        Assert.Equal(1, handoff.TriggerCalls);
        Assert.Equal(0, handoff.StageCalls);
        Assert.Equal(0, reporter.Calls);
        using var marker = JsonDocument.Parse(File.ReadAllText(DecommissionMarkerFile));
        Assert.True(marker.RootElement.GetProperty("triggered").GetBoolean());
    }

    [Fact]
    public async Task DueDirectiveWithNoMarker_NoCredentials_IsNotReportedOrStaged()
    {
        var creds = CredentialStore.ForTesting("test-tenant", "", HmacSecret);
        var (runner, handoff, reporter) = NewDecommissionRunner();

        await PatchedWorker.RunDecommissionCheckForTickAsync(
            creds, (present, token) => runner.RunAsync(DueDecommission(), present, token),
            NullLogger<PatchedWorker>.Instance, CancellationToken.None);

        Assert.Equal(0, reporter.Calls);
        Assert.Equal(0, handoff.StageCalls);
        Assert.Equal(0, handoff.TriggerCalls);
        Assert.False(File.Exists(DecommissionMarkerFile));
    }

    [Fact]
    public async Task DueDirectiveWithNoMarker_WithCredentials_IsReportedAndStaged()
    {
        // Control for the test above.
        var creds = CredentialStore.ForTesting("test-tenant", "enrolled-bearer", HmacSecret);
        var (runner, handoff, reporter) = NewDecommissionRunner();

        await PatchedWorker.RunDecommissionCheckForTickAsync(
            creds, (present, token) => runner.RunAsync(DueDecommission(), present, token),
            NullLogger<PatchedWorker>.Instance, CancellationToken.None);

        Assert.Equal(1, reporter.Calls);
        Assert.Equal(1, handoff.StageCalls);
        Assert.Equal(1, handoff.TriggerCalls);
    }
}
