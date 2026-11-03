using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Patched.Shared.Paths;
using PostureModel = Patched.Shared.Posture.Posture;

namespace Patched.Service;

/// <summary>
/// Fetches GET /v1/posture, Ed25519-verifies the signed envelope, and atomically
/// caches the DECODED inner payload as world-readable posture.json for the tray +
/// Self Service to read (desktop chain U0). Reuses the one existing credential
/// path — the same bearer + HMAC store the inventory poster uses — so no second
/// secret path is introduced (GitHub-Non-Author-Review). The GET signs an empty body, exactly like
/// <see cref="AgentConfigFetcher"/>.
///
/// PAT-1285: posture is signed with the same pinned key as agent-config (parity
/// with verify-posture.py / verify-agent-config.py on macOS), so this fetcher now
/// verifies the {signed_payload, key_id, signature} envelope before ever writing
/// anything to disk — mirroring patched-fetch-posture.sh + verify-posture.py,
/// which verify then cache only the decoded payload, never the raw envelope. This
/// closes a platform divergence: previously the Windows writer cached the raw,
/// unverified envelope verbatim and only <see cref="Patched.Shared.Posture.PostureReader"/>
/// verified it at read time (PAT-1273). PostureReader's envelope-detecting branch
/// stays in place unchanged for backward compatibility with any envelope-shaped
/// cache file already on disk from before this fix shipped; its "not envelope,
/// decode directly" branch is what now reads every freshly-written cache file.
///
/// Fail closed: a verification or structural failure never caches anything and is
/// reported via <see cref="AgentHealthStore"/> so a persistently failing verify is
/// visible rather than indistinguishable from a healthy, merely-stale cache. Plain
/// network/HTTP failures are not flagged degraded here — they are the routine,
/// expected case (offline laptop, transient outage) and PostureReader's own
/// staleness signal already covers "the cache hasn't updated in a while".
/// </summary>
internal sealed class PostureFetcher
{
    /// <summary>agent_health bucket: one (kind, subject) pair, the fetch failure in the reason.</summary>
    private const string HealthKind    = "sync_never_succeeded";
    private const string HealthSubject = "posture";

    private static readonly string[] RequiredEnvelopeFields = { "signed_payload", "key_id", "signature" };

    private readonly ILogger<PostureFetcher> _log;
    private readonly IHttpClientFactory      _httpFactory;
    private readonly CredentialStore         _creds;
    private readonly AgentHealthStore        _agentHealth;
    private readonly string                  _pinnedKeyId;
    private readonly byte[]                  _pinnedPublicKey;
    private readonly string                  _stateDir;
    private readonly string                  _cachePath;

    public PostureFetcher(
        ILogger<PostureFetcher> log,
        IHttpClientFactory      httpFactory,
        CredentialStore         creds,
        AgentHealthStore        agentHealth)
        : this(log, httpFactory, creds, agentHealth, pinnedKeyId: null, pinnedPublicKeyBase64: null,
               stateDirOverride: null, cachePathOverride: null)
    {
    }

    /// <param name="pinnedKeyId">
    /// Override the expected envelope key_id (tests only). Defaults to
    /// <see cref="Ed25519Verifier.PinnedKeyId"/>; production code never supplies
    /// this, so the real trust anchor is never reachable from a caller's environment.
    /// </param>
    /// <param name="pinnedPublicKeyBase64">
    /// Override the Ed25519 public key used to verify the envelope signature
    /// (tests only, paired with <paramref name="pinnedKeyId"/> — mirrors the same
    /// seam <see cref="Patched.Shared.Posture.PostureReader"/> exposes, since no
    /// test can produce a signature the real pinned key accepts). Defaults to
    /// <see cref="Ed25519Verifier.PinnedPubKeyBase64"/>.
    /// </param>
    /// <param name="stateDirOverride">
    /// Override the directory the cache file is written under (tests only).
    /// Defaults to <see cref="PathConstants.StateDir"/>; production code never
    /// supplies this.
    /// </param>
    /// <param name="cachePathOverride">
    /// Override the cache file path (tests only), so a unit test can assert on
    /// the exact bytes committed without touching the real %ProgramData%\Patched
    /// path. Defaults to <see cref="PathConstants.PostureStatusFile"/>.
    /// </param>
    internal PostureFetcher(
        ILogger<PostureFetcher> log,
        IHttpClientFactory      httpFactory,
        CredentialStore         creds,
        AgentHealthStore        agentHealth,
        string?                 pinnedKeyId,
        string?                 pinnedPublicKeyBase64,
        string?                 stateDirOverride = null,
        string?                 cachePathOverride = null)
    {
        _log             = log;
        _httpFactory     = httpFactory;
        _creds           = creds;
        _agentHealth     = agentHealth;
        _pinnedKeyId     = pinnedKeyId ?? Ed25519Verifier.PinnedKeyId;
        _pinnedPublicKey = Convert.FromBase64String(pinnedPublicKeyBase64 ?? Ed25519Verifier.PinnedPubKeyBase64);
        _stateDir        = stateDirOverride ?? PathConstants.StateDir;
        _cachePath       = cachePathOverride ?? PathConstants.PostureStatusFile;
    }

    /// <summary>
    /// Fetch + cache. Returns the freshly fetched posture on success, or null if
    /// anything failed (caller keeps last-known-good on disk).
    /// </summary>
    public async Task<PostureModel?> FetchAsync(CancellationToken ct)
    {
        // PAT-1765: the same credential-pair check the other fetchers make (PAT-1754,
        // PAT-1760). Without it an unusable pair sent an invalidly signed request every
        // run cycle. The snapshot signs and authorises this one request.
        if (!DeviceCredentials.TryRead(_creds, out var bearerToken, out var hmacSecret))
        {
            _log.LogWarning("posture: device credentials not present (no usable bearer token and HMAC secret); no request sent, keeping last-good cache");
            return null;
        }

        HttpResponseMessage resp;
        try
        {
            resp = await SendRequestAsync(bearerToken, hmacSecret, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            _log.LogWarning(ex, "posture: fetch failed (network) — keeping last-good cache");
            return null;
        }

        using (resp)
        {
            if (resp.StatusCode != HttpStatusCode.OK)
            {
                _log.LogWarning("posture: fetch returned HTTP {Code} — keeping last-good cache",
                    (int)resp.StatusCode);
                return null;
            }

            byte[] body = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            return VerifyAndCache(body);
        }
    }

    private async Task<HttpResponseMessage> SendRequestAsync(string bearerToken, string hmacSecret, CancellationToken ct)
    {
        var client = _httpFactory.CreateClient("patched");

        // GET has no body — HMAC over an empty byte array, matching AgentConfigFetcher
        // and patched-upload.sh fetch_posture().
        // PAT-707: timestamp + nonce are also required by the server auth chain
        // (ValidateTimestamp → CheckAndStoreNonce) — omitting them causes 401.
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        string nonce     = Guid.NewGuid().ToString("N");
        string sig       = HmacSigner.ComputeSignature(hmacSecret, "GET", HmacSigner.EndpointPosture, timestamp, nonce, ReadOnlySpan<byte>.Empty);

        var req = new HttpRequestMessage(HttpMethod.Get, "/v1/posture");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
        req.Headers.TryAddWithoutValidation(HmacSigner.SignatureHeader, sig);
        req.Headers.TryAddWithoutValidation("X-Patched-Timestamp", timestamp);
        req.Headers.TryAddWithoutValidation("X-Patched-Nonce", nonce);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        return await client.SendAsync(req, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Verify the {signed_payload, key_id, signature} envelope, then atomically
    /// commit only the decoded, verified inner payload — never the outer envelope
    /// bytes. Mirrors <see cref="AgentConfigFetcher.VerifyAndCache"/> and
    /// verify-posture.py's structural-checks-then-signature-then-decode order.
    /// Any rejection leaves the existing cache untouched and records degraded
    /// health via <see cref="AgentHealthStore"/> so a persistently failing verify
    /// is never indistinguishable from a healthy cache that simply hasn't been
    /// refetched yet.
    /// </summary>
    private PostureModel? VerifyAndCache(byte[] body)
    {
        JsonDocument envelope;
        try
        {
            envelope = JsonDocument.Parse(body);
        }
        catch (JsonException ex)
        {
            return Reject($"response is not valid JSON: {ex.Message}");
        }

        using (envelope)
        {
            var root = envelope.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return Reject("response is not a JSON object");

            foreach (var field in RequiredEnvelopeFields)
            {
                if (!root.TryGetProperty(field, out _))
                    return Reject($"missing required field: '{field}'");
            }

            string keyId = root.GetProperty("key_id").GetString() ?? "";
            if (keyId != _pinnedKeyId)
                return Reject($"key_id mismatch (got '{keyId}', expected '{_pinnedKeyId}')");

            byte[] signedPayload;
            try
            {
                signedPayload = Convert.FromBase64String(root.GetProperty("signed_payload").GetString() ?? "");
            }
            catch (FormatException)
            {
                return Reject("signed_payload is not valid base64");
            }

            byte[] signature;
            try
            {
                signature = Convert.FromBase64String(root.GetProperty("signature").GetString() ?? "");
            }
            catch (FormatException)
            {
                return Reject("signature is not valid base64");
            }

            // Verify over the raw signed bytes — no client-side reconstruction.
            if (!Ed25519Verifier.Verify(_pinnedPublicKey, signedPayload, signature))
                return Reject("Ed25519 signature is invalid");

            var posture = PostureModel.Deserialize(signedPayload);
            if (posture is null)
                return Reject("verified signed_payload is not valid posture JSON");
            if (posture.SchemaVersion != 1)
                return Reject($"unexpected schema_version {posture.SchemaVersion}");

            // Commit only the decoded, verified inner payload — the on-disk cache
            // is never the envelope from this point on, matching the macOS writer.
            try
            {
                Directory.CreateDirectory(_stateDir);
                string tmp = _cachePath + ".tmp";
                File.WriteAllBytes(tmp, signedPayload);
                File.Move(tmp, _cachePath, overwrite: true);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "posture: verified but failed to write cache — keeping last-good cache");
                _agentHealth.RecordFailure(HealthKind, HealthSubject, "cache_write_failed");
                return null;
            }

            _agentHealth.RecordSuccess(HealthKind, HealthSubject);
            _log.LogInformation("posture: verified and cached — tier={Tier} apps={Apps} generated_at={At:o}",
                posture.Tier, posture.AppCount, posture.GeneratedAt);
            return posture;
        }
    }

    /// <summary>
    /// Log the rejection, record degraded health (a verification/structural
    /// failure is a meaningful signal, unlike a routine network blip), and return
    /// null so the caller keeps whatever was already cached.
    /// </summary>
    private PostureModel? Reject(string reason)
    {
        _log.LogWarning("posture: rejected — {Reason}; keeping last-good cache", reason);
        _agentHealth.RecordFailure(HealthKind, HealthSubject, reason);
        return null;
    }
}
