using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Posture;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1285: PostureFetcher used to cache the raw GET /v1/posture envelope
/// verbatim, unverified — a platform divergence from macOS
/// (patched-fetch-posture.sh + verify-posture.py verify then cache only the
/// decoded payload before it ever touches disk). These tests drive the real
/// PostureFetcher.FetchAsync end to end through a fake HttpMessageHandler and
/// assert: a verified envelope commits only the decoded inner payload (never
/// the envelope bytes), a bad signature / wrong key_id / malformed envelope is
/// rejected without caching anything and reports degraded health via
/// AgentHealthStore, and a cache file written by this fetcher round-trips
/// correctly back through PostureReader (the reader's envelope-handling branch
/// stays for old cache files, but the "decode directly" branch is what a
/// freshly-written file now takes).
/// </summary>
public sealed class PostureFetcherTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"patched-posture-fetcher-{Guid.NewGuid():N}");
    private readonly string _suspendedFile;
    private readonly Ed25519PrivateKeyParameters _privateKey;
    private readonly string _pubKeyBase64;
    private const string TestKeyId = "test-posture-key-0001";

    public PostureFetcherTests()
    {
        Directory.CreateDirectory(_dir);
        _suspendedFile = Path.Combine(_dir, "suspended");

        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.GenerateKeyPair();
        _privateKey = (Ed25519PrivateKeyParameters)kp.Private;
        _pubKeyBase64 = Convert.ToBase64String(((Ed25519PublicKeyParameters)kp.Public).GetEncoded());
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    private string CacheFile => Path.Combine(_dir, "posture.json");
    private AgentHealthStore NewHealth() => new(NullLogger<AgentHealthStore>.Instance, Path.Combine(_dir, "health.json"));

    private PostureFetcher NewFetcher(HttpMessageHandler handler, AgentHealthStore health,
        string? pinnedKeyId = null, string? pinnedPublicKeyBase64 = null) =>
        new(NullLogger<PostureFetcher>.Instance, new Factory(handler),
            CredentialStore.CreateForTests(_suspendedFile), health,
            pinnedKeyId ?? TestKeyId, pinnedPublicKeyBase64 ?? _pubKeyBase64,
            stateDirOverride: _dir, cachePathOverride: CacheFile);

    private static byte[] PosturePayload(string generatedAt, int appCount = 61) => Encoding.UTF8.GetBytes(
        JsonSerializer.Serialize(new
        {
            schema_version = 1,
            generated_at = generatedAt,
            device = new { id = "a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", os = "Windows" },
            tier = "assurance",
            app_count = appCount,
            compliance = new { platform = "Windows", benchmarks = Array.Empty<object>() },
            evidence = new { coverage_window_days = 30, scans_logged = 27, recent_scan_times = Array.Empty<string>() },
        }));

    private string Envelope(byte[] payload, string? keyId = null, bool corruptSignature = false)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, _privateKey);
        signer.BlockUpdate(payload, 0, payload.Length);
        return JsonSerializer.Serialize(new
        {
            signed_payload = Convert.ToBase64String(payload),
            signature = Convert.ToBase64String(corruptSignature ? new byte[64] : signer.GenerateSignature()),
            key_id = keyId ?? TestKeyId,
        });
    }

    private sealed class Factory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler) { BaseAddress = new Uri("https://posture-test.invalid") };
    }

    private sealed class StaticHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            LastRequest = request;
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body) });
        }
    }

    // -------------------------------------------------------------------
    // Happy path: verify, then cache only the decoded payload
    // -------------------------------------------------------------------

    [Fact]
    public async Task FetchAsync_VerifiedEnvelope_CachesOnlyDecodedPayload_NotTheEnvelope()
    {
        byte[] payload = PosturePayload("2026-12-17T08:13:58Z");
        string envelope = Envelope(payload);
        var health = NewHealth();
        var fetcher = NewFetcher(new StaticHandler(HttpStatusCode.OK, envelope), health);

        var result = await fetcher.FetchAsync(CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(61, result!.AppCount);

        // The cache on disk is the bare decoded payload, byte-for-byte — never
        // the outer {signed_payload, key_id, signature} envelope.
        byte[] cached = File.ReadAllBytes(CacheFile);
        Assert.Equal(payload, cached);
        using (var doc = JsonDocument.Parse(cached))
        {
            Assert.False(doc.RootElement.TryGetProperty("signed_payload", out _));
            Assert.False(doc.RootElement.TryGetProperty("signature", out _));
        }

        // A verified fetch reports healthy — no degraded entry for posture.
        Assert.DoesNotContain(health.BuildPayloadSection()!.Degraded,
            e => e.Kind == "sync_never_succeeded" && e.Subject == "posture");
    }

    [Fact]
    public async Task FetchAsync_VerifiedFetch_ClearsAPriorDegradedFlag()
    {
        var health = NewHealth();
        health.RecordFailure("sync_never_succeeded", "posture", "fetch_failed");

        byte[] payload = PosturePayload("2026-12-17T08:13:58Z");
        var fetcher = NewFetcher(new StaticHandler(HttpStatusCode.OK, Envelope(payload)), health);

        Assert.NotNull(await fetcher.FetchAsync(CancellationToken.None));
        Assert.DoesNotContain(health.BuildPayloadSection()!.Degraded,
            e => e.Kind == "sync_never_succeeded" && e.Subject == "posture");
    }

    // -------------------------------------------------------------------
    // Fail closed: verification/structural rejection never caches anything
    // and reports degraded health.
    // -------------------------------------------------------------------

    [Theory]
    [InlineData("bad-signature")]
    [InlineData("wrong-key-id")]
    [InlineData("malformed-envelope")]
    [InlineData("not-json")]
    public async Task FetchAsync_RejectedEnvelope_CachesNothing_AndReportsDegraded(string scenario)
    {
        byte[] payload = PosturePayload("2026-12-17T08:13:58Z");
        string body = scenario switch
        {
            "bad-signature"      => Envelope(payload, corruptSignature: true),
            "wrong-key-id"       => Envelope(payload, keyId: "some-other-key-id"),
            "malformed-envelope" => JsonSerializer.Serialize(new { key_id = TestKeyId }), // missing signed_payload/signature
            "not-json"           => "{not-json",
            _                    => throw new InvalidOperationException(scenario),
        };

        var health = NewHealth();
        var fetcher = NewFetcher(new StaticHandler(HttpStatusCode.OK, body), health);

        var result = await fetcher.FetchAsync(CancellationToken.None);

        Assert.Null(result);
        Assert.False(File.Exists(CacheFile));

        var entry = Assert.Single(health.BuildPayloadSection()!.Degraded,
            e => e.Kind == "sync_never_succeeded" && e.Subject == "posture");
        Assert.NotNull(entry.Reason);
    }

    [Fact]
    public async Task FetchAsync_RejectedEnvelope_LeavesExistingCacheUntouched()
    {
        byte[] original = PosturePayload("2026-12-17T08:13:58Z");
        File.WriteAllBytes(CacheFile, original);

        var health = NewHealth();
        var fetcher = NewFetcher(new StaticHandler(HttpStatusCode.OK, Envelope(PosturePayload("2026-12-18T00:00:00Z"), corruptSignature: true)), health);

        Assert.Null(await fetcher.FetchAsync(CancellationToken.None));
        Assert.Equal(original, File.ReadAllBytes(CacheFile));
        Assert.Single(health.BuildPayloadSection()!.Degraded,
            e => e.Kind == "sync_never_succeeded" && e.Subject == "posture");
    }

    [Fact]
    public async Task FetchAsync_VerifiedButWrongSchemaVersion_CachesNothing_AndReportsDegraded()
    {
        byte[] payload = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            schema_version = 2,
            generated_at = "2026-12-17T08:13:58Z",
            device = new { id = "a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", os = "Windows" },
        }));
        var health = NewHealth();
        var fetcher = NewFetcher(new StaticHandler(HttpStatusCode.OK, Envelope(payload)), health);

        Assert.Null(await fetcher.FetchAsync(CancellationToken.None));
        Assert.False(File.Exists(CacheFile));
        Assert.Single(health.BuildPayloadSection()!.Degraded,
            e => e.Kind == "sync_never_succeeded" && e.Subject == "posture");
    }

    // -------------------------------------------------------------------
    // Routine network/HTTP failures: quiet (no degraded flag), matching the
    // pre-existing fail-safe convention — these are the expected offline case.
    // -------------------------------------------------------------------

    [Fact]
    public async Task FetchAsync_HttpErrorStatus_KeepsLastGood_NoDegradedFlag()
    {
        byte[] original = PosturePayload("2026-12-17T08:13:58Z");
        File.WriteAllBytes(CacheFile, original);
        var health = NewHealth();

        var fetcher = NewFetcher(new StaticHandler(HttpStatusCode.ServiceUnavailable, ""), health);
        Assert.Null(await fetcher.FetchAsync(CancellationToken.None));
        Assert.Equal(original, File.ReadAllBytes(CacheFile));
        Assert.Empty(health.BuildPayloadSection()!.Degraded);
    }

    // -------------------------------------------------------------------
    // Round-trip: a cache file written by the updated PostureFetcher still
    // reads correctly via PostureReader (the "not envelope, decode directly"
    // branch PAT-1273 already added).
    // -------------------------------------------------------------------

    [Fact]
    public async Task WrittenCache_ReadsCorrectlyViaPostureReader()
    {
        byte[] payload = PosturePayload("2026-12-17T08:13:58Z", appCount: 42);
        var health = NewHealth();
        var fetcher = NewFetcher(new StaticHandler(HttpStatusCode.OK, Envelope(payload)), health);

        Assert.NotNull(await fetcher.FetchAsync(CancellationToken.None));

        var snap = new PostureReader(
            CacheFile,
            now: () => DateTimeOffset.Parse("2026-12-17T10:00:00Z"),
            pinnedKeyId: TestKeyId,
            pinnedPublicKeyBase64: _pubKeyBase64).Read();

        Assert.True(snap.HasPosture);
        Assert.Null(snap.Error);
        Assert.Equal(42, snap.Posture!.AppCount);
    }

    // -------------------------------------------------------------------
    // PAT-1765: no request without a usable credential pair
    // -------------------------------------------------------------------

    [Theory]
    [InlineData("", "dGVzdC1obWFjLXNlY3JldC0zMi1ieXRlcy1sb25nIQ==")]
    [InlineData("   ", "dGVzdC1obWFjLXNlY3JldC0zMi1ieXRlcy1sb25nIQ==")]
    [InlineData("enrolled-bearer", "")]
    [InlineData("enrolled-bearer", "   ")]
    public async Task FetchAsync_NoUsableCredentialPair_SendsNothing_AndKeepsTheCache(string bearer, string secret)
    {
        File.WriteAllText(CacheFile, "last-good");
        var handler = new StaticHandler(HttpStatusCode.OK, Envelope(PosturePayload("2026-09-15T12:00:00Z")));
        var fetcher = new PostureFetcher(
            NullLogger<PostureFetcher>.Instance, new Factory(handler),
            CredentialStore.CreateForTests(_suspendedFile, bearerToken: bearer, hmacSecret: secret), NewHealth(),
            TestKeyId, _pubKeyBase64, stateDirOverride: _dir, cachePathOverride: CacheFile);

        Assert.Null(await fetcher.FetchAsync(CancellationToken.None));

        Assert.Null(handler.LastRequest);
        Assert.Equal("last-good", File.ReadAllText(CacheFile));
    }
}
