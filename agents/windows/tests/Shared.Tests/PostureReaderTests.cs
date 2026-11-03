using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Patched.Shared.Posture;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// Desktop chain U0: the PostureReader last-known-good cache. Mirrors the macOS
/// PostureStore tests — missing file is honest first-run (not an error), a present
/// cache renders however old, corrupt cache surfaces an error, and staleness is
/// flagged off an injected clock.
/// </summary>
public class PostureReaderTests : IDisposable
{
    private readonly string _dir;
    private readonly string _cache;

    public PostureReaderTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "posture-reader-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _cache = Path.Combine(_dir, "posture.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private static string PostureJson(string generatedAt) => $$"""
    {
      "schema_version": 1,
      "generated_at": "{{generatedAt}}",
      "device": { "id": "a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "os": "Windows" },
      "tier": "assurance",
      "app_count": 61,
      "compliance": { "platform": "Windows", "benchmarks": [] },
      "evidence": { "coverage_window_days": 30, "scans_logged": 27, "recent_scan_times": [] }
    }
    """;

    [Fact]
    public void MissingCache_IsFirstRunNotError()
    {
        var snap = new PostureReader(_cache).Read();
        Assert.False(snap.HasPosture);
        Assert.Null(snap.Error);     // no file = honest first-run
        Assert.False(snap.IsStale);
    }

    [Fact]
    public void PresentCache_RendersPosture()
    {
        File.WriteAllText(_cache, PostureJson("2026-12-17T08:13:58Z"));
        var snap = new PostureReader(_cache, now: () => DateTimeOffset.Parse("2026-12-17T10:00:00Z")).Read();

        Assert.True(snap.HasPosture);
        Assert.Equal(61, snap.Posture!.AppCount);
        Assert.Null(snap.Error);
        Assert.False(snap.IsStale);
    }

    [Fact]
    public void CorruptCache_SurfacesError()
    {
        File.WriteAllText(_cache, "{ not json");
        var snap = new PostureReader(_cache).Read();

        Assert.False(snap.HasPosture);
        Assert.NotNull(snap.Error);
    }

    [Fact]
    public void OldCache_IsStaleButStillRendered()
    {
        File.WriteAllText(_cache, PostureJson("2026-12-01T00:00:00Z"));
        var snap = new PostureReader(_cache, now: () => DateTimeOffset.Parse("2026-12-17T00:00:00Z")).Read();

        Assert.True(snap.HasPosture);   // last-known-good still rendered
        Assert.True(snap.IsStale);      // but flagged stale (older than 36h)
    }

    [Fact]
    public void FutureTimestamp_ClampsAgeToZero()
    {
        File.WriteAllText(_cache, PostureJson("2026-12-17T12:00:00Z"));
        var snap = new PostureReader(_cache, now: () => DateTimeOffset.Parse("2026-12-17T08:00:00Z")).Read();

        Assert.True(snap.HasPosture);
        Assert.Equal(TimeSpan.Zero, snap.Age);
        Assert.False(snap.IsStale);
    }

    // -------------------------------------------------------------------
    // PAT-1273: the on-disk cache is normally a signed envelope
    // ({signed_payload, key_id, signature}), not the bare posture payload.
    // PostureFetcher caches the raw GET /v1/posture response as is. These
    // tests inject a test keypair via the pinnedKeyId/pinnedPublicKeyBase64
    // constructor overrides (the real pinned key's private half is a server
    // secret no test can sign against), mirroring the seam
    // verify-posture.py's own tests use to patch its module constants.
    // -------------------------------------------------------------------

    private const string TestKeyId = "test-key-0001";

    private static (Ed25519PrivateKeyParameters priv, string pubKeyBase64) GenerateTestKeyPair()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.GenerateKeyPair();
        var pub = (Ed25519PublicKeyParameters)kp.Public;
        return ((Ed25519PrivateKeyParameters)kp.Private, Convert.ToBase64String(pub.GetEncoded()));
    }

    private static string SignEnvelope(Ed25519PrivateKeyParameters priv, string keyId, byte[] payload)
    {
        var signer = new Ed25519Signer();
        signer.Init(forSigning: true, priv);
        signer.BlockUpdate(payload, 0, payload.Length);
        byte[] sig = signer.GenerateSignature();

        var envelope = new
        {
            signed_payload = Convert.ToBase64String(payload),
            key_id         = keyId,
            signature      = Convert.ToBase64String(sig),
        };
        return JsonSerializer.Serialize(envelope);
    }

    [Fact]
    public void ValidEnvelope_DecodesAndVerifies_RendersRealPosture()
    {
        var (priv, pubKeyBase64) = GenerateTestKeyPair();
        byte[] payload = Encoding.UTF8.GetBytes(PostureJson("2026-12-17T08:13:58Z"));
        File.WriteAllText(_cache, SignEnvelope(priv, TestKeyId, payload));

        var snap = new PostureReader(
            _cache,
            now: () => DateTimeOffset.Parse("2026-12-17T10:00:00Z"),
            pinnedKeyId: TestKeyId,
            pinnedPublicKeyBase64: pubKeyBase64).Read();

        Assert.True(snap.HasPosture);
        Assert.Null(snap.Error);
        Assert.Equal(61, snap.Posture!.AppCount);
        Assert.Equal("a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", snap.Posture!.Device.Id);
    }

    [Fact]
    public void EnvelopeWithBadSignature_ReportsDegraded_NotEmptyPosture()
    {
        var (priv, pubKeyBase64) = GenerateTestKeyPair();
        byte[] payload = Encoding.UTF8.GetBytes(PostureJson("2026-12-17T08:13:58Z"));
        string json = SignEnvelope(priv, TestKeyId, payload);

        // Corrupt the signature so it no longer verifies against signed_payload.
        using var doc = JsonDocument.Parse(json);
        var tampered = new
        {
            signed_payload = doc.RootElement.GetProperty("signed_payload").GetString(),
            key_id         = TestKeyId,
            signature      = Convert.ToBase64String(new byte[64]), // all-zero signature
        };
        File.WriteAllText(_cache, JsonSerializer.Serialize(tampered));

        var snap = new PostureReader(
            _cache,
            pinnedKeyId: TestKeyId,
            pinnedPublicKeyBase64: pubKeyBase64).Read();

        // Distinguishable degraded signal: not the honest "no cache yet" empty
        // record (that has Error == null) and not a Posture silently deserialized
        // from the still-encoded envelope bytes.
        Assert.False(snap.HasPosture);
        Assert.NotNull(snap.Error);
    }

    [Fact]
    public void EnvelopeWithUnexpectedKeyId_ReportsDegraded_NotEmptyPosture()
    {
        var (priv, pubKeyBase64) = GenerateTestKeyPair();
        byte[] payload = Encoding.UTF8.GetBytes(PostureJson("2026-12-17T08:13:58Z"));
        File.WriteAllText(_cache, SignEnvelope(priv, "some-other-key-id", payload));

        var snap = new PostureReader(
            _cache,
            pinnedKeyId: TestKeyId,
            pinnedPublicKeyBase64: pubKeyBase64).Read();

        Assert.False(snap.HasPosture);
        Assert.NotNull(snap.Error);
    }

    [Fact]
    public void RealEnvelopeShape_DefaultPinnedKey_RejectsUnknownSigner_NeverSilentlyEmpty()
    {
        // Without any override, a PostureReader() constructed the way production
        // code constructs it (TrayController, MainWindow, DeviceRemovalTasksClient
        // all do `new PostureReader()` / `new PostureReader(pathOverride)`) checks
        // against the real pinned key. A self-signed test envelope can never
        // satisfy that, so this proves the fail-closed default: an unverifiable
        // envelope is reported as a degraded read, never as an empty-but-valid
        // Posture (the exact ambiguity PAT-1273 exists to close).
        var (priv, _) = GenerateTestKeyPair();
        byte[] payload = Encoding.UTF8.GetBytes(PostureJson("2026-12-17T08:13:58Z"));
        File.WriteAllText(_cache, SignEnvelope(priv, "not-the-real-pinned-key-id", payload));

        var snap = new PostureReader(_cache).Read();

        Assert.False(snap.HasPosture);
        Assert.NotNull(snap.Error);
    }
}
