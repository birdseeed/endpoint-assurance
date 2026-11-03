using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1042 P1 (non-author review, round 3): revocation is a per-DEVICE auth
/// flag, not a change to the tenant's agent-config CONTENT — the realistic
/// reinstatement case (an admin re-permits the device) does not bump
/// config_version at all. Before this fix, a suspended device's probe kept
/// sending If-None-Match, so a reinstated device would get 304 Not Modified
/// forever (content genuinely unchanged) and FetchAsync's 304 branch never
/// checks IsSuspended or clears the marker — the device would stay suspended
/// indefinitely, the exact bug class PAT-1042 exists to fix, one status code
/// later than the original inert-feature bug. The fix: SendRequestAsync now
/// omits If-None-Match while IsSuspended, forcing the server to answer with a
/// full 200 the moment credentials work again.
///
/// What this file proves, and how:
///   - The header-suppression logic itself (SendRequestAsync omits
///     If-None-Match while suspended, still sends it otherwise) — fully unit
///     tested below via a RecordingHandler that captures the outgoing
///     HttpRequestMessage, and a CredentialStore.CreateForTests(...) instance
///     (an internal PAT-1042 test seam) so neither test touches the real
///     %ProgramData%\Patched\creds or Windows Credential Manager.
///     SendRequestAsync is private; invoked via reflection with an explicit
///     lastVersion argument rather than through the public FetchAsync, which
///     would instead read lastVersion from PathConstants.AgentConfigVersionFile
///     — a fixed, non-overridable real path that reads back 0/absent on any
///     dev machine, making "would normally send If-None-Match" untestable
///     through that entry point without an unrelated, larger change to make
///     that path injectable too.
///   - "A still-401 keeps [the marker]" — via the full public FetchAsync
///     (no reflection needed): a 401 response short-circuits before any
///     signature verification, so it needs no real key material.
///
/// What this file does NOT prove, and why: that a genuinely verified 200
/// actually reaches ClearSuspended() end-to-end. VerifyAndCache's Ed25519
/// check is inlined against the hardcoded Ed25519Verifier.PinnedPubKeyBase64
/// — unlike the macOS side (where verify-agent-config.py is a swappable
/// subprocess a test can substitute a stub for), there is no seam here to
/// inject a test keypair, and the real private key lives only on
/// patched-api-01 (see verify-agent-config.py's own header comment for the
/// macOS equivalent of this same boundary). That the clear runs after a
/// verified commit was already proved by construction in the previous
/// PAT-1042 round (ClearSuspended() sits right after the commit succeeds in
/// VerifyAndCache); this round's fix is specifically that the request now
/// even asks for a 200 instead of accepting a 304 forever. The full
/// reinstatement round-trip needs staging VM verification
/// (Andy@192.168.64.5).
/// </summary>
public sealed class AgentConfigFetcherSuspendedTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _suspendedFile;

    public AgentConfigFetcherSuspendedTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-acf-suspended-test-{Guid.NewGuid():N}");
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

    /// <summary>Captures the last outgoing request and always answers with a fixed status/body.</summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        private int _requestCount;
        public HttpRequestMessage? LastRequest { get; private set; }
        public HttpStatusCode ResponseStatus { get; set; } = HttpStatusCode.OK;
        public string ResponseBody { get; set; } = "{}";
        public int RequestCount => Volatile.Read(ref _requestCount);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref _requestCount);
            LastRequest = request;
            var resp = new HttpResponseMessage(ResponseStatus) { Content = new StringContent(ResponseBody) };
            return Task.FromResult(resp);
        }
    }

    private sealed class FakeHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;
        public FakeHttpClientFactory(HttpMessageHandler handler) => _handler = handler;
        public HttpClient CreateClient(string name) =>
            new(_handler) { BaseAddress = new Uri("https://patched-1042-test.invalid") };
    }

    // Reflection helper: SendRequestAsync(int lastVersion, CancellationToken ct) is
    // private — see the file header for why this needs to be called directly
    // rather than through the public FetchAsync.
    // PAT-1754: SendRequestAsync now takes the bearer token and HMAC secret
    // FetchAsync read once, so the enrolment check, header, signature and 401
    // decision share one snapshot. The defaults are CreateForTests' values.
    private static Task<HttpResponseMessage> InvokeSendRequestAsync(
        AgentConfigFetcher fetcher, int lastVersion, CancellationToken ct,
        string bearerToken = "test-bearer", string hmacSecret = "dGVzdC1obWFjLXNlY3JldC0zMi1ieXRlcy1sb25nIQ==")
    {
        var method = typeof(AgentConfigFetcher).GetMethod(
            "SendRequestAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;
        return (Task<HttpResponseMessage>)method.Invoke(fetcher, new object[] { lastVersion, bearerToken, hmacSecret, ct })!;
    }

    [Fact]
    public async Task SendRequestAsync_WhenSuspended_OmitsIfNoneMatch()
    {
        var creds = CredentialStore.CreateForTests(_suspendedFile);
        creds.MarkSuspended();
        Assert.True(creds.IsSuspended);

        var handler = new RecordingHandler();
        var fetcher = new AgentConfigFetcher(
            NullLogger<AgentConfigFetcher>.Instance, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));

        // lastVersion=5 alone would normally be enough to add If-None-Match
        // (lastVersion > 0) — proving the omission is IsSuspended-driven, not
        // just an accident of lastVersion being 0/absent.
        await InvokeSendRequestAsync(fetcher, lastVersion: 5, CancellationToken.None);

        Assert.NotNull(handler.LastRequest);
        Assert.Empty(handler.LastRequest!.Headers.IfNoneMatch);
    }

    [Fact]
    public async Task SendRequestAsync_WhenNotSuspended_StillSendsIfNoneMatch()
    {
        var creds = CredentialStore.CreateForTests(_suspendedFile);
        Assert.False(creds.IsSuspended);

        var handler = new RecordingHandler();
        var fetcher = new AgentConfigFetcher(
            NullLogger<AgentConfigFetcher>.Instance, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));

        await InvokeSendRequestAsync(fetcher, lastVersion: 5, CancellationToken.None);

        Assert.NotNull(handler.LastRequest);
        var etag = Assert.Single(handler.LastRequest!.Headers.IfNoneMatch);
        Assert.Equal(new EntityTagHeaderValue("\"5\""), etag);
    }

    [Fact]
    public async Task FetchAsync_WhenSuspendedAndServerStillReturns401_MarkerStaysAndReturnsNull()
    {
        var creds = CredentialStore.CreateForTests(_suspendedFile);
        creds.MarkSuspended();
        Assert.True(creds.IsSuspended);

        var handler = new RecordingHandler { ResponseStatus = HttpStatusCode.Unauthorized, ResponseBody = "" };
        var fetcher = new AgentConfigFetcher(
            NullLogger<AgentConfigFetcher>.Instance, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));

        var result = await fetcher.FetchAsync(CancellationToken.None);

        Assert.Null(result);
        Assert.NotNull(handler.LastRequest);
        Assert.Empty(handler.LastRequest!.Headers.IfNoneMatch); // still suppressed on the probe itself
        Assert.True(creds.IsSuspended); // still rejected (cause undisclosed): marker stays (re-affirmed by MarkSuspended)
    }

    /// <summary>
    /// PAT-1745: a 401 from /v1/agent-config is deliberately generic on the
    /// server (expired or unknown credential, revoked tenant, clock skew,
    /// nonce replay, secret mismatch and device revocation all look the
    /// same). The agent must still suspend on it, but must not log it as a
    /// revocation. Starts from a healthy, non-suspended device so the marker
    /// write is proved to come from the 401 itself.
    /// </summary>
    [Fact]
    public async Task FetchAsync_401OnHealthyDevice_SuspendsAndLogsAuthRejectedWithoutAssertingRevocation()
    {
        var creds = CredentialStore.CreateForTests(_suspendedFile);
        Assert.False(creds.IsSuspended);

        var handler = new RecordingHandler { ResponseStatus = HttpStatusCode.Unauthorized, ResponseBody = "unauthorized" };
        var log = new CapturingLogger<AgentConfigFetcher>();
        var fetcher = new AgentConfigFetcher(log, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));

        var result = await fetcher.FetchAsync(CancellationToken.None);

        Assert.Null(result);
        Assert.True(creds.IsSuspended); // suspend-on-401 behaviour unchanged
        Assert.True(File.Exists(_suspendedFile));

        string error = Assert.Single(log.Errors);
        Assert.StartsWith("PATCHED_AUTH_REJECTED:", error);
        Assert.Contains("HTTP 401", error);
        Assert.Contains("does not disclose the reason", error);
        Assert.Contains("credential expired or unknown", error);
        Assert.Contains("tenant or device revoked", error);
        Assert.Contains("clock skew", error);
        Assert.Contains("HMAC secret mismatch", error);
        Assert.DoesNotContain(log.Messages, m => m.Contains("PATCHED_DEVICE_REVOKED"));
    }

    // -------------------------------------------------------------------
    // PAT-1779: a suspended-marker write that throws on a 401 never escapes
    // -------------------------------------------------------------------

    /// <summary>
    /// A suspended-marker path whose parent is a plain file, so MarkSuspended's
    /// Directory.CreateDirectory throws on every platform, the way an unwritable creds
    /// directory does on a real device. Same fixture as EnrolmentHardeningTests.
    /// </summary>
    private string UnwritableMarkerPath()
    {
        var blocker = Path.Combine(_tempDir, "creds-is-a-file");
        File.WriteAllText(blocker, "not a directory");
        return Path.Combine(blocker, "suspended");
    }

    [Fact]
    public async Task FetchAsync_401_MarkerWriteThrows_ReportsFailure_LogsError_AndDoesNotThrow()
    {
        var creds = CredentialStore.CreateForTests(UnwritableMarkerPath());
        Assert.ThrowsAny<IOException>(() => creds.MarkSuspended()); // the fixture really is unwritable

        var handler = new RecordingHandler { ResponseStatus = HttpStatusCode.Unauthorized, ResponseBody = "" };
        var log = new CapturingLogger<AgentConfigFetcher>();
        var fetcher = new AgentConfigFetcher(log, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));

        // Before PAT-1779 the IOException escaped FetchAsync.
        var result = await fetcher.FetchAsync(CancellationToken.None);

        Assert.Null(result);
        Assert.Equal(1, handler.RequestCount);
        Assert.False(creds.IsSuspended);
        Assert.Equal(2, log.Errors.Count);
        Assert.StartsWith("PATCHED_AUTH_REJECTED:", log.Errors[0]);
        Assert.Contains("could not write the suspended marker", log.Errors[1]);
    }

    [Fact]
    public async Task AgentConfigManager_401_MarkerWriteThrows_PollLoopKeepsRunning_WithNoUnexpectedError()
    {
        var creds = CredentialStore.CreateForTests(UnwritableMarkerPath());
        var handler = new RecordingHandler { ResponseStatus = HttpStatusCode.Unauthorized, ResponseBody = "" };
        var fetcher = new AgentConfigFetcher(
            NullLogger<AgentConfigFetcher>.Instance, new FakeHttpClientFactory(handler), creds,
            Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));
        var managerLog = new CapturingLogger<AgentConfigManager>();
        var manager = new AgentConfigManager(
            managerLog, fetcher, TimeSpan.FromMilliseconds(5), TimeSpan.FromMilliseconds(5), () => true);

        await manager.StartAsync(CancellationToken.None);
        var deadline = DateTime.UtcNow.AddSeconds(10); // safety net only
        while (handler.RequestCount < 3 && DateTime.UtcNow < deadline)
            await Task.Delay(5);
        await manager.StopAsync(CancellationToken.None);

        Assert.True(handler.RequestCount >= 3, $"the poll loop stopped after {handler.RequestCount} request(s)");
        Assert.NotNull(manager.ExecuteTask);
        Assert.False(manager.ExecuteTask!.IsFaulted);
        lock (managerLog.Messages)
            Assert.DoesNotContain(managerLog.Errors, m => m.Contains("unexpected error during fetch"));
    }

    /// <summary>Captures formatted log messages by level so tests can assert on log content.</summary>
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];
        public List<string> Errors { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var message = formatter(state, exception);
            lock (Messages)
            {
                Messages.Add(message);
                if (logLevel == LogLevel.Error) Errors.Add(message);
            }
        }
    }

    [Fact]
    public async Task FetchAsync_UnauthenticatedRevocationWithMalformedTypedFieldChangesNoAuthorityState()
    {
        var creds = CredentialStore.CreateForTests(_suspendedFile);
        AgentConfig current = AgentConfig.Deserialize("""
        {
          "tenant_id": "test-tenant",
          "config_version": 4,
          "legacy_app_execution_enabled": true,
          "app_control_authority": "enforce"
        }
        """)!;
        const string payload = """
        {
          "tenant_id": "test-tenant",
          "config_version": 999,
          "legacy_app_execution_enabled": false,
          "app_control_authority": "report",
          "proxy": { "port": "not-a-port" }
        }
        """;
        string envelope = JsonSerializer.Serialize(new
        {
            signed_payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload)),
            key_id = Ed25519Verifier.PinnedKeyId,
            signature = Convert.ToBase64String(new byte[64]),
        });
        var handler = new RecordingHandler
        {
            ResponseStatus = HttpStatusCode.OK,
            ResponseBody = envelope,
        };
        var fetcher = new AgentConfigFetcher(
            NullLogger<AgentConfigFetcher>.Instance,
            new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));

        AgentConfig? result = await fetcher.FetchAsync(CancellationToken.None);
        if (result is not null)
            current = result;

        Assert.Null(result);
        Assert.False(creds.IsSuspended);
        Assert.Equal(4, current.ConfigVersion);
        Assert.True(LegacyAppExecutionGate.Allows(current));
        Assert.True(AppControlAuthorityGate.AllowsDestructiveAction(current.AppControlAuthority));
    }
}
