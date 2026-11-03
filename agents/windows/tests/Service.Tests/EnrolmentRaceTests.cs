using System.Net;
using System.Reflection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1754: on WIN-STAGING (windows-agent-v0.13.33) AgentConfigManager polled
/// /v1/agent-config one second after service start, before PatchedWorker had
/// exchanged the enrollment token. The request carried no bearer token, the
/// server answered 401, and the fetcher wrote creds\suspended. Enrolment then
/// succeeded, but the marker stayed until the next 15-minute poll.
///
/// Proves:
///   1. With no bearer token the fetcher sends no request and writes no marker.
///   2. A 401 on a request that carried no bearer token does not suspend; a
///      401 on a request that carried one still does (PAT-1042 / PAT-1745).
///   3. AgentConfigManager sends nothing before enrolment and fetches within
///      the short enrolment recheck once credentials appear, not a full poll
///      interval later.
/// </summary>
public sealed class EnrolmentRaceTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _suspendedFile;

    public EnrolmentRaceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-enrol-race-test-{Guid.NewGuid():N}");
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
            // Best-effort cleanup.
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task AgentConfigFetcher_NoBearerToken_SendsNoRequestAndDoesNotSuspend(string bearerToken)
    {
        var creds = CredentialStore.CreateForTests(_suspendedFile, bearerToken: bearerToken);
        // Answers 401 if anything is sent, which is what the server did on v0.13.33.
        var handler = new CountingHandler(HttpStatusCode.Unauthorized);
        var fetcher = new AgentConfigFetcher(
            NullLogger<AgentConfigFetcher>.Instance, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));

        var result = await fetcher.FetchAsync(CancellationToken.None);

        Assert.Null(result);
        Assert.Equal(0, handler.RequestCount);
        Assert.False(creds.IsSuspended);
        Assert.False(File.Exists(_suspendedFile));
    }

    [Theory]
    [InlineData("   ")]
    [InlineData("\t")]
    public async Task AgentConfigFetcher_WhitespaceHmacSecret_SendsNoRequest(string hmacSecret)
    {
        // PAT-1760 review: a whitespace secret decodes to an empty HMAC key, so a
        // request would carry a real bearer token with an invalid signature and
        // draw a 401 that suspends the device. No request is sent.
        var creds = CredentialStore.ForTesting("test-tenant", "test-bearer", hmacSecret);
        var handler = new CountingHandler(HttpStatusCode.Unauthorized);
        var fetcher = new AgentConfigFetcher(
            NullLogger<AgentConfigFetcher>.Instance, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));

        Assert.False(fetcher.HasDeviceCredentials);
        Assert.Null(await fetcher.FetchAsync(CancellationToken.None));
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task AgentConfigFetcher_BearerTokenWithoutHmacSecret_SendsNoRequest()
    {
        // Models the instant inside CredentialStore.UpdateFromEnrolment after
        // BearerToken is assigned but before HmacSecret is. ForTesting keeps the
        // store in memory; no request is sent, so its real suspended-marker path
        // is never written.
        var creds = CredentialStore.ForTesting("test-tenant", "test-bearer", "");
        var handler = new CountingHandler(HttpStatusCode.Unauthorized);
        var fetcher = new AgentConfigFetcher(
            NullLogger<AgentConfigFetcher>.Instance, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));

        Assert.False(fetcher.HasDeviceCredentials);
        Assert.Null(await fetcher.FetchAsync(CancellationToken.None));
        Assert.Equal(0, handler.RequestCount);
    }

    /// <summary>
    /// The signature must come from the HMAC secret snapshot FetchAsync took,
    /// not from a second read of the CredentialStore. A store change cannot be
    /// staged at a precise point inside FetchAsync, so SendRequestAsync is called
    /// directly with a snapshot that differs from the store: the request must
    /// verify against the snapshot and not against the store's secret.
    /// </summary>
    [Fact]
    public async Task AgentConfigFetcher_SignsWithSnapshotSecret_NotASecondStoreRead()
    {
        var creds = CredentialStore.CreateForTests(_suspendedFile);
        const string snapshotSecret = "c25hcHNob3Qtc2VjcmV0LWRpZmZlcnMtZnJvbS1zdG9yZQ==";
        Assert.NotEqual(snapshotSecret, creds.HmacSecret);

        var handler = new CountingHandler(HttpStatusCode.NotModified);
        var fetcher = new AgentConfigFetcher(
            NullLogger<AgentConfigFetcher>.Instance, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));
        var method = typeof(AgentConfigFetcher).GetMethod(
            "SendRequestAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;

        using var _ = await (Task<HttpResponseMessage>)method.Invoke(
            fetcher, new object[] { 0, "snapshot-bearer", snapshotSecret, CancellationToken.None })!;

        var request = handler.LastRequest!;
        Assert.Equal("snapshot-bearer", request.Headers.Authorization?.Parameter);
        AssertSignedWith(request, HmacSigner.EndpointAgentConfig, snapshotSecret, notWith: creds.HmacSecret);
    }

    internal static void AssertSignedWith(HttpRequestMessage request, string endpoint, string secret, string notWith)
    {
        string ts = request.Headers.GetValues("X-Patched-Timestamp").Single();
        string nonce = request.Headers.GetValues("X-Patched-Nonce").Single();
        string sig = request.Headers.GetValues(HmacSigner.SignatureHeader).Single();
        Assert.True(HmacSigner.VerifySignature(secret, "GET", endpoint, ts, nonce, ReadOnlySpan<byte>.Empty, sig),
            "request was not signed with the snapshot HMAC secret");
        Assert.False(HmacSigner.VerifySignature(notWith, "GET", endpoint, ts, nonce, ReadOnlySpan<byte>.Empty, sig),
            "request was signed with a second read of the CredentialStore secret");
    }

    [Fact]
    public void AgentConfigFetcher_401OnTokenlessRequest_DoesNotSuspend()
    {
        var creds = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "");
        var log = new CapturingLogger<AgentConfigFetcher>();
        var fetcher = new AgentConfigFetcher(log, new FakeHttpClientFactory(new CountingHandler(HttpStatusCode.OK)), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));

        fetcher.HandleUnauthorized(bearerTokenSent: "");
        fetcher.HandleUnauthorized(bearerTokenSent: null);
        fetcher.HandleUnauthorized(bearerTokenSent: " ");

        Assert.False(creds.IsSuspended);
        Assert.False(File.Exists(_suspendedFile));
        Assert.Empty(log.Errors);
        Assert.DoesNotContain(log.Messages, m => m.StartsWith("PATCHED_AUTH_REJECTED:"));
        Assert.All(log.Warnings, w => Assert.Contains("carried no bearer token", w));
        Assert.Equal(3, log.Warnings.Count);
    }

    [Fact]
    public void AgentConfigFetcher_401OnTokenedRequest_StillSuspends()
    {
        var creds = CredentialStore.CreateForTests(_suspendedFile);
        var log = new CapturingLogger<AgentConfigFetcher>();
        var fetcher = new AgentConfigFetcher(log, new FakeHttpClientFactory(new CountingHandler(HttpStatusCode.OK)), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));

        fetcher.HandleUnauthorized(bearerTokenSent: "test-bearer");

        Assert.True(creds.IsSuspended);
        string error = Assert.Single(log.Errors);
        Assert.Equal(AgentConfigFetcher.AuthRejectedLogMessage, error);
    }

    [Fact]
    public async Task AgentConfigFetcher_401OnTokenedRequestThroughFetchAsync_StillSuspends()
    {
        var creds = CredentialStore.CreateForTests(_suspendedFile);
        var handler = new CountingHandler(HttpStatusCode.Unauthorized);
        var fetcher = new AgentConfigFetcher(
            NullLogger<AgentConfigFetcher>.Instance, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));

        Assert.Null(await fetcher.FetchAsync(CancellationToken.None));

        Assert.Equal(1, handler.RequestCount);
        Assert.Equal("test-bearer", handler.LastAuthorizationParameter);
        Assert.True(creds.IsSuspended);
    }

    [Fact]
    public async Task AgentConfigManager_BeforeEnrolment_SendsNothing_ThenFetchesPromptlyOnceEnrolled()
    {
        // The fetcher's own store is enrolled so the prompt fetch really goes
        // out; the manager's enrolment view is the flag below, standing in for
        // CredentialStore.UpdateFromEnrolment so the test controls exactly when
        // enrolment completes.
        var creds = CredentialStore.CreateForTests(_suspendedFile);
        var handler = new CountingHandler(HttpStatusCode.NotModified);
        var fetcher = new AgentConfigFetcher(
            NullLogger<AgentConfigFetcher>.Instance, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));

        int enrolled = 0;
        using var manager = new AgentConfigManager(
            NullLogger<AgentConfigManager>.Instance,
            fetcher,
            pollInterval: TimeSpan.FromHours(1),              // a poll-driven fetch cannot happen in this test
            enrolmentRecheckInterval: TimeSpan.FromMilliseconds(20),
            hasDeviceCredentials: () => Volatile.Read(ref enrolled) == 1);

        await manager.StartAsync(CancellationToken.None);
        try
        {
            // Several recheck intervals before enrolment: nothing is sent.
            await Task.Delay(200);
            Assert.Equal(0, handler.RequestCount);

            Volatile.Write(ref enrolled, 1);

            Assert.True(await WaitUntilAsync(() => handler.RequestCount >= 1, TimeSpan.FromSeconds(5)),
                "expected the first agent-config fetch within the enrolment recheck interval after enrolment");

            // Once fetched, the loop is back on the one-hour poll interval.
            await Task.Delay(200);
            Assert.Equal(1, handler.RequestCount);
            Assert.False(creds.IsSuspended);
        }
        finally
        {
            await manager.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public void AgentConfigManager_EnrolmentRecheckInterval_IsShortLocalCadence()
    {
        Assert.Equal(TimeSpan.FromSeconds(15), AgentConfigManager.EnrolmentRecheckInterval);
    }

    internal static async Task<bool> WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (condition()) return true;
            await Task.Delay(10);
        }
        return condition();
    }

    /// <summary>Counts requests and answers every one with a fixed status.</summary>
    internal sealed class CountingHandler(HttpStatusCode status) : HttpMessageHandler
    {
        private int _count;
        public int RequestCount => Volatile.Read(ref _count);
        public string? LastAuthorizationParameter { get; private set; }
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref _count);
            LastRequest = request;
            LastAuthorizationParameter = request.Headers.Authorization?.Parameter;
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent("") });
        }
    }

    internal sealed class FakeHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false) { BaseAddress = new Uri("https://patched-1754-test.invalid") };
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];
        public List<string> Errors { get; } = [];
        public List<string> Warnings { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var message = formatter(state, exception);
            Messages.Add(message);
            if (logLevel == LogLevel.Error) Errors.Add(message);
            if (logLevel == LogLevel.Warning) Warnings.Add(message);
        }
    }
}
