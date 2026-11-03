using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1155 — windows/tests/Shared.Tests/HmacSignerTests.cs proves
/// HmacSigner.ComputeSignature reproduces the two authoritative v3 test
/// vectors in isolation. It does NOT prove that a real caller places the
/// exact same timestamp/nonce it signed into the X-Patched-Timestamp /
/// X-Patched-Nonce headers of the request it actually sends — a future edit
/// to AgentConfigFetcher.SendRequestAsync (windows/src/Service/AgentConfigFetcher.cs,
/// the Windows counterpart of endpoint/patched-fetch-config.sh; see
/// AgentConfigFetcherSuspendedTests.cs for the existing macOS/Windows parity
/// pairing on this same class) could change what gets signed without
/// changing what lands in the headers (or vice versa), and HmacSignerTests
/// would keep passing — it never looks at an HttpRequestMessage at all.
///
/// This file drives the real AgentConfigFetcher.FetchAsync end to end
/// through a RecordingHandler (same fake-HttpMessageHandler pattern as
/// AgentConfigFetcherSuspendedTests.cs), captures the X-Patched-Timestamp /
/// X-Patched-Nonce / X-Patched-Signature headers from the ACTUAL outgoing
/// request, and independently recomputes the v3 signature via
/// HmacSigner.ComputeSignature — a primitive already proven correct in
/// isolation by HmacSignerTests.cs — over ONLY those captured header
/// values (never anything the fetcher held internally). If a future wiring
/// bug made SendRequestAsync sign one timestamp/nonce pair but emit a
/// different pair in the headers, the recompute would stop matching the
/// captured X-Patched-Signature and this test would fail, even though
/// HmacSignerTests.cs would still be green.
///
/// The handler always answers 304 so FetchAsync returns null on the fast
/// path — no Ed25519 verification or config commit is exercised here (out
/// of scope, same boundary as AgentConfigFetcherSuspendedTests.cs).
/// </summary>
public sealed class AgentConfigFetcherHmacWiringTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _suspendedFile;

    public AgentConfigFetcherHmacWiringTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-acf-hmac-wiring-test-{Guid.NewGuid():N}");
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
        public HttpRequestMessage? LastRequest { get; private set; }
        public HttpStatusCode ResponseStatus { get; set; } = HttpStatusCode.NotModified;
        public string ResponseBody { get; set; } = "";

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
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
            new(_handler) { BaseAddress = new Uri("https://patched-1155-test.invalid") };
    }

    [Fact]
    public async Task FetchAsync_HeadersMatchWhatWasSigned()
    {
        var creds = CredentialStore.CreateForTests(_suspendedFile);
        var handler = new RecordingHandler();
        var fetcher = new AgentConfigFetcher(
            NullLogger<AgentConfigFetcher>.Instance, new FakeHttpClientFactory(handler), creds, Path.Combine(_tempDir, "agent-config.json"), Path.Combine(_tempDir, "agent-config.version"));

        var result = await fetcher.FetchAsync(CancellationToken.None);

        Assert.Null(result); // 304 short-circuit; not the property under test here
        Assert.NotNull(handler.LastRequest);

        string capturedTs = Assert.Single(handler.LastRequest!.Headers.GetValues("X-Patched-Timestamp"));
        string capturedNonce = Assert.Single(handler.LastRequest!.Headers.GetValues("X-Patched-Nonce"));
        string capturedSig = Assert.Single(handler.LastRequest!.Headers.GetValues(HmacSigner.SignatureHeader));

        Assert.False(string.IsNullOrEmpty(capturedTs));
        Assert.False(string.IsNullOrEmpty(capturedNonce));
        Assert.False(string.IsNullOrEmpty(capturedSig));

        // Sanity that the header really is a fresh unix timestamp, not just
        // some string that happens to be non-empty.
        long capturedTsValue = long.Parse(capturedTs);
        long nowTs = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Assert.InRange(capturedTsValue, nowTs - 300, nowTs + 300);

        // The core wiring proof: recomputing the v3 HMAC over ONLY the
        // captured header timestamp/nonce (CredentialStore.CreateForTests'
        // fixed placeholder secret) reproduces the exact X-Patched-Signature
        // header value that was actually sent.
        string recomputed = HmacSigner.ComputeSignature(
            creds.HmacSecret, "GET", HmacSigner.EndpointAgentConfig, capturedTs, capturedNonce, ReadOnlySpan<byte>.Empty);
        Assert.Equal(recomputed, capturedSig);

        // Negative control: proves the assertion above is not vacuously
        // true. Recomputing over a DIFFERENT nonce than the one actually
        // captured must NOT reproduce the captured signature — if it did,
        // ComputeSignature would be ignoring the nonce and the check above
        // would prove nothing.
        string mismatched = HmacSigner.ComputeSignature(
            creds.HmacSecret, "GET", HmacSigner.EndpointAgentConfig, capturedTs, capturedNonce + "-tampered", ReadOnlySpan<byte>.Empty);
        Assert.NotEqual(mismatched, capturedSig);
    }
}
