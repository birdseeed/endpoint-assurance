using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1779: a 429 from /v1/enrol carries the server's Retry-After, and the PAT-1765
/// exponential backoff now waits max(computed backoff, Retry-After), capped at the
/// existing one-hour cap. Other backoff statuses ignore the header.
///
/// Runs against CredentialStore.CreateForTests, a scratch suspended marker and floor,
/// a recording handler and a manual clock.
/// </summary>
public sealed class EnrolmentRetryAfterTests : IDisposable
{
    private static readonly DateTimeOffset Start = new(2026, 9, 15, 12, 0, 0, TimeSpan.Zero);

    private readonly string _tempDir;
    private readonly string _suspendedFile;
    private readonly string _floorFile;

    public EnrolmentRetryAfterTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-enrol-retry-after-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _suspendedFile = Path.Combine(_tempDir, "suspended");
        _floorFile = Path.Combine(_tempDir, "agent-config.version");
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { /* best effort */ }
    }

    // ------------------------------------------------------------------ //
    // The delay decision                                                   //
    // ------------------------------------------------------------------ //

    [Theory]
    [InlineData(1, 120, 120)]     // asks for longer than step 1's 30s: honoured
    [InlineData(1, 10, 30)]       // asks for less: the computed backoff stands
    [InlineData(3, 120, 120)]     // equal to step 3's 120s: computed
    [InlineData(1, 0, 30)]        // zero: ignored
    [InlineData(1, 7200, 3600)]   // past the cap: capped at one hour
    [InlineData(8, 60, 3600)]     // step 8 is already at the cap
    public void Delta_429_IsMaxOfComputedAndRetryAfter_CappedAtOneHour(int step, int retryAfterSeconds, int expectedSeconds)
    {
        var header = new RetryConditionHeaderValue(TimeSpan.FromSeconds(retryAfterSeconds));

        var (delay, _) = AgentEnroller.BackoffDelayHonouringRetryAfter(step, 429, header, Start);

        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), delay);
    }

    [Theory]
    [InlineData(600, 600)]     // HTTP-date ten minutes ahead
    [InlineData(10, 30)]       // ahead, but sooner than the computed 30s
    [InlineData(-300, 30)]     // in the past: ignored
    [InlineData(86400, 3600)]  // a day ahead: capped
    public void HttpDate_429_IsReadAgainstTheClock(int secondsAhead, int expectedSeconds)
    {
        var header = new RetryConditionHeaderValue(Start.AddSeconds(secondsAhead));

        var (delay, _) = AgentEnroller.BackoffDelayHonouringRetryAfter(1, 429, header, Start);

        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), delay);
    }

    [Theory]
    [InlineData(400)]
    [InlineData(402)]
    [InlineData(409)]
    public void OtherBackoffStatuses_IgnoreRetryAfter(int status)
    {
        var header = new RetryConditionHeaderValue(TimeSpan.FromSeconds(900));

        var (delay, honoured) = AgentEnroller.BackoffDelayHonouringRetryAfter(1, status, header, Start);

        Assert.Equal(AgentEnroller.BackoffDelay(1), delay);
        Assert.Null(honoured);
    }

    [Fact]
    public void NoHeader_IsTheComputedBackoff()
    {
        var (delay, honoured) = AgentEnroller.BackoffDelayHonouringRetryAfter(2, 429, null, Start);

        Assert.Equal(AgentEnroller.BackoffDelay(2), delay);
        Assert.Null(honoured);
    }

    // ------------------------------------------------------------------ //
    // Through TryEnrolAsync on the worker's 15-second tick                 //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task Enrol429_WithRetryAfterSeconds_SendsNothingUntilItElapses_AndKeepsTheToken()
    {
        var clock = Start;
        var creds = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", enrollmentToken: "kept-token");
        var handler = new RecordingHandler(() =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.TooManyRequests) { Content = new StringContent("") };
            resp.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(300));
            return resp;
        });
        var enroller = new AgentEnroller(
            NullLogger<AgentEnroller>.Instance, new FakeHttpClientFactory(handler), creds, _floorFile, () => clock);

        var sentAtSeconds = await WalkTicksAsync(enroller, handler, secondsToWalk: 900, setClock: t => clock = t);

        // Without Retry-After the steps would be 0, 30, 90, 210, 450. With 300s
        // requested on every answer: 0, 300, 600 (step 3's 120s < 300s), 900.
        Assert.Equal(new[] { 0, 300, 600, 900 }, sentAtSeconds);
        Assert.False(creds.IsSuspended);
        Assert.Equal("kept-token", creds.EnrollmentToken);
    }

    [Fact]
    public async Task Enrol429_WithRetryAfterDate_WaitsUntilThatDate()
    {
        var clock = Start;
        var creds = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", enrollmentToken: "kept-token");
        var handler = new RecordingHandler(() =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.TooManyRequests) { Content = new StringContent("") };
            resp.Headers.RetryAfter = new RetryConditionHeaderValue(clock.AddSeconds(450));
            return resp;
        });
        var enroller = new AgentEnroller(
            NullLogger<AgentEnroller>.Instance, new FakeHttpClientFactory(handler), creds, _floorFile, () => clock);

        var sentAtSeconds = await WalkTicksAsync(enroller, handler, secondsToWalk: 600, setClock: t => clock = t);

        Assert.Equal(new[] { 0, 450 }, sentAtSeconds);
    }

    private static async Task<List<int>> WalkTicksAsync(
        AgentEnroller enroller, RecordingHandler handler, int secondsToWalk, Action<DateTimeOffset> setClock)
    {
        var sent = new List<int>();
        for (int second = 0; second <= secondsToWalk; second += 15)
        {
            setClock(Start.AddSeconds(second));
            int before = handler.RequestCount;
            Assert.True(await enroller.TryEnrolAsync(CancellationToken.None)); // transient, never suspends
            if (handler.RequestCount > before)
                sent.Add(second);
        }
        return sent;
    }

    private sealed class RecordingHandler(Func<HttpResponseMessage> respond) : HttpMessageHandler
    {
        private int _count;
        public int RequestCount => Volatile.Read(ref _count);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref _count);
            return Task.FromResult(respond());
        }
    }

    private sealed class FakeHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false) { BaseAddress = new Uri("https://patched-1779-test.invalid") };
    }
}
