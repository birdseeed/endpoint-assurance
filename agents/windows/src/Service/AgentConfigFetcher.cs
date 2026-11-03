using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Patched.Shared.Paths;

namespace Patched.Service;

/// <summary>
/// Fetches, Ed25519-verifies, and atomically caches the per-tenant agent config.
/// Security-sensitive — this is the channel by which tier / proxy / OS-update
/// policy reaches the endpoint, so unsigned or tampered config must never be
/// trusted. Mirrors patched-fetch-config.sh + verify-agent-config.py exactly.
///
/// Fail-safe: any error (network, HTTP, structural, signature, rollback) results
/// in the cache being left untouched and null returned — the caller keeps its
/// last-known-good config.
/// </summary>
public sealed class AgentConfigFetcher
{
    /// <summary>
    /// PAT-1745: logged on a 401 from /v1/agent-config. The server does not say
    /// why it rejected the request, so this names the possible causes rather
    /// than asserting one. Kept word-for-word in step with the macOS line in
    /// endpoint/patched-fetch-config.sh.
    /// </summary>
    internal const string AuthRejectedLogMessage =
        "PATCHED_AUTH_REJECTED: /v1/agent-config returned HTTP 401. The server does not disclose the reason. " +
        "Possible causes: credential expired or unknown, tenant or device revoked, clock skew outside the replay window, " +
        "nonce replay, or bearer token and HMAC secret mismatch. Entering suspended state until a signature-verified 200";

    private readonly ILogger<AgentConfigFetcher> _log;
    private readonly IHttpClientFactory          _httpFactory;
    private readonly CredentialStore             _creds;
    private readonly string                      _agentConfigFile;
    private readonly string                      _rollbackFloorFile;
    private readonly Func<byte[], AgentConfig?>  _deserialize;

    public AgentConfigFetcher(
        ILogger<AgentConfigFetcher> log,
        IHttpClientFactory          httpFactory,
        CredentialStore             creds)
        : this(log, httpFactory, creds, PathConstants.AgentConfigFile, PathConstants.AgentConfigVersionFile)
    {
    }

    /// <summary>
    /// Test seam: the same fetcher with the config cache and the anti-rollback
    /// floor redirected to scratch paths, so tests never touch
    /// %ProgramData%\Patched. Production always uses the public constructor.
    /// </summary>
    internal AgentConfigFetcher(
        ILogger<AgentConfigFetcher> log,
        IHttpClientFactory          httpFactory,
        CredentialStore             creds,
        string                      agentConfigFile,
        string                      rollbackFloorFile)
        : this(log, httpFactory, creds, agentConfigFile, rollbackFloorFile, bytes => AgentConfig.Deserialize(bytes))
    {
    }

    /// <summary>
    /// Test seam (PAT-1763): as above, with the typed deserialization replaced so a
    /// test can model a signature-verified payload that does not deserialize.
    /// </summary>
    internal AgentConfigFetcher(
        ILogger<AgentConfigFetcher> log,
        IHttpClientFactory          httpFactory,
        CredentialStore             creds,
        string                      agentConfigFile,
        string                      rollbackFloorFile,
        Func<byte[], AgentConfig?>  deserialize)
    {
        _log               = log;
        _httpFactory       = httpFactory;
        _creds             = creds;
        _agentConfigFile   = agentConfigFile;
        _rollbackFloorFile = rollbackFloorFile;
        _deserialize       = deserialize;
    }

    /// <summary>
    /// PAT-1763: the cached agent-config.json this fetcher commits to.
    /// AgentConfigManager loads its start-up config from the same path.
    /// </summary>
    internal string CachedConfigFile => _agentConfigFile;

    internal AgentConfig? LoadVerifiedUpdateAuthority()
    {
        try
        {
            var proof = new FileInfo(_agentConfigFile + ".envelope");
            var canonical = new FileInfo(_agentConfigFile);
            if (!proof.Exists || !canonical.Exists || proof.Length > 4 * 1024 * 1024 || canonical.Length > 1024 * 1024) return null;
            if (OperatingSystem.IsWindows()) Patched.Shared.Security.SecureStagingDirectory.VerifyTrusted(proof.DirectoryName!);
            if ((proof.Attributes & FileAttributes.ReparsePoint) != 0 || (canonical.Attributes & FileAttributes.ReparsePoint) != 0)
                return null;
            return VerifiedUpdateConfigCache.Match(File.ReadAllBytes(proof.FullName), File.ReadAllBytes(canonical.FullName),
                _creds.TenantId, AgentConfigRollbackFloor.Read(_rollbackFloorFile),
                bytes => Ed25519Verifier.TryVerifyEnvelope(bytes, out var payload) ? payload : null);
        }
        catch { return null; }
    }

    /// <summary>
    /// PAT-1763: the tenant this device is enrolled in right now, the tenant every
    /// verified config is bound to. Empty while enrolment is pending.
    /// </summary>
    internal string EnrolledTenantId => _creds.TenantId;

    /// <summary>
    /// Fetch + verify + cache. Returns the freshly verified config on success,
    /// or null if nothing changed (304) or anything failed (caller keeps last-good).
    /// </summary>
    public async Task<AgentConfig?> FetchAsync(CancellationToken ct)
    {
        // PAT-1754: read the bearer token once and use that one value for the
        // enrolment check, the request header and the 401 decision below, so
        // enrolment completing mid-call cannot make them disagree.
        if (!DeviceCredentials.TryRead(_creds, out string bearerToken, out string hmacSecret))
        {
            // On a fresh install this service starts before PatchedWorker has
            // exchanged the enrollment token. A request now could not be
            // authenticated, would be rejected with 401 and prove nothing about
            // the device, so none is sent. AgentConfigManager rechecks shortly.
            _log.LogDebug("agent-config: not enrolled yet (device credentials not present), skipping fetch; no request sent");
            return null;
        }

        // PAT-1756: the If-None-Match validator comes from the stored floor only
        // when that floor applies to the enrolled tenant. The floor used for the
        // anti-rollback decision is read again after tenant binding, below.
        int? conditionalGetVersion = AgentConfigRollbackFloor.ConditionalGetVersion(
            AgentConfigRollbackFloor.Read(_rollbackFloorFile), _creds.TenantId);
        // A legacy plaintext cache has no restart-verifiable update authority.
        // Request a full envelope rather than remaining stuck behind a 304.
        if (LoadVerifiedUpdateAuthority() is null) conditionalGetVersion = null;

        HttpResponseMessage resp;
        try
        {
            resp = await SendRequestAsync(conditionalGetVersion, bearerToken, hmacSecret, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            _log.LogWarning(ex, "agent-config: fetch failed (network) — keeping last-good config");
            return null;
        }

        using (resp)
        {
            if (resp.StatusCode == HttpStatusCode.NotModified)
            {
                _log.LogInformation("agent-config: not modified (304) — cached config unchanged");
                return null;
            }

            if (resp.StatusCode == HttpStatusCode.Unauthorized)
            {
                HandleUnauthorized(bearerToken);
                return null;
            }

            if (resp.StatusCode != HttpStatusCode.OK)
            {
                _log.LogWarning("agent-config: fetch returned HTTP {Code} — keeping last-good config",
                    (int)resp.StatusCode);
                return null;
            }

            byte[] body = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            return VerifyAndCache(body);
        }
    }

    /// <summary>
    /// True once this device holds its enrolled credentials. AgentConfigManager
    /// reads it to choose between the enrolment recheck and the normal poll interval.
    /// </summary>
    internal bool HasDeviceCredentials => DeviceCredentials.Present(_creds);

    /// <summary>
    /// Handles a 401 from /v1/agent-config. <paramref name="bearerTokenSent"/>
    /// is the bearer token the rejected request actually carried.
    ///
    /// PAT-1745: the server returns the same bare 401 for every authentication
    /// failure on purpose, so the response never leaks why. Revocation is only
    /// one of those causes; asserting it sent PAT-1604's diagnosis down the
    /// wrong path for a lost credential. A 401 on a request that carried a
    /// token logs what is actually known and suspends, unchanged.
    ///
    /// PAT-1754: a 401 on a request that carried no bearer token says nothing
    /// about this device's credentials, only that the agent sent a request it
    /// could not authenticate. It must never write the suspended marker. On
    /// v0.13.33 exactly this suspended a freshly installed device for up to
    /// 15 minutes, because this service raced enrolment. FetchAsync no longer
    /// sends such a request; this guard is defence in depth at the point the
    /// marker is written.
    ///
    /// PAT-1779: the marker write is guarded, as PAT-1765 did for AgentEnroller. With an
    /// unwritable creds directory MarkSuspended throws; that used to escape FetchAsync and
    /// reach AgentConfigManager's last-resort catch as an "unexpected error". It is now
    /// logged as an error here and never thrown, and FetchAsync reports the fetch as
    /// failed (null), so the poll loop carries on and the next 401 tries the write again.
    /// </summary>
    internal void HandleUnauthorized(string? bearerTokenSent)
    {
        if (!DeviceCredentials.HasBearerToken(bearerTokenSent))
        {
            _log.LogWarning(
                "agent-config: HTTP 401 on a request that carried no bearer token. This is a local precondition failure " +
                "(device not enrolled), not a rejection of this device's credentials; suspended marker not written");
            return;
        }

        _log.LogError(AuthRejectedLogMessage);
        try
        {
            _creds.MarkSuspended();
        }
        catch (Exception ex)
        {
            _log.LogError(ex,
                "agent-config: could not write the suspended marker after HTTP 401. The service keeps running and the next agent-config poll tries again; " +
                "until the marker is written the other senders are not held back by it. Check that the agent can write its credentials directory");
        }
    }

    private async Task<HttpResponseMessage> SendRequestAsync(
        int? conditionalGetVersion, string bearerToken, string hmacSecret, CancellationToken ct)
    {
        var client = _httpFactory.CreateClient("patched");

        // GET has no body — the HMAC is computed over an empty byte array,
        // exactly as in patched-fetch-config.sh / patched-upload.sh fetch_agent_config().
        // PAT-707: timestamp + nonce are also required by the server auth chain
        // (ValidateTimestamp → CheckAndStoreNonce) — omitting them causes 401.
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        string nonce     = Guid.NewGuid().ToString("N");
        string sig       = HmacSigner.ComputeSignature(hmacSecret, "GET", HmacSigner.EndpointAgentConfig, timestamp, nonce, ReadOnlySpan<byte>.Empty);

        var req = new HttpRequestMessage(HttpMethod.Get, "/v1/agent-config");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
        req.Headers.TryAddWithoutValidation(HmacSigner.SignatureHeader, sig);
        req.Headers.TryAddWithoutValidation("X-Patched-Timestamp", timestamp);
        req.Headers.TryAddWithoutValidation("X-Patched-Nonce", nonce);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        // PAT-1042 P1 (non-author review round 3): revocation is a per-device
        // auth flag, not a change to the tenant's agent-config CONTENT — the
        // realistic reinstatement case (an admin re-permits the device) does
        // not bump config_version at all. Sending If-None-Match while
        // suspended would let the server answer 304 Not Modified forever
        // (content genuinely hasn't changed), and FetchAsync's 304 branch
        // above never checks IsSuspended or calls ClearSuspended — so a fully
        // reinstated device would stay suspended indefinitely, the exact bug
        // class this ticket exists to fix, just one status code later than
        // the original inert-feature bug. Suppress the conditional GET while
        // suspended so the server is FORCED to answer with a full, verifiable
        // 200 the moment credentials work again — a still-revoked device gets
        // 401 either way (marker stays via MarkSuspended above), a reinstated
        // one now gets a verifiable 200 VerifyAndCache's ClearSuspended() call
        // can act on. Mirrors patched-fetch-config.sh's identical
        // If-None-Match suppression. Only suppressed while suspended: the
        // normal (non-suspended) path still sends the conditional GET, so
        // this does not regress bandwidth in the common healthy-device case.
        bool suppressConditionalGet = _creds.IsSuspended;
        if (suppressConditionalGet)
        {
            _log.LogWarning("agent-config: device suspended — suppressing If-None-Match so a reinstated device gets a verifiable 200 instead of a 304 that would never clear the marker");
        }

        // Only send If-None-Match when a usable floor for the enrolled tenant is
        // on disk (PAT-1756: never another tenant's version, never a corrupt
        // floor's), and never while suspended (see above).
        if (!suppressConditionalGet && conditionalGetVersion is int etagVersion)
        {
            req.Headers.IfNoneMatch.Add(new EntityTagHeaderValue($"\"{etagVersion}\""));
        }

        return await client.SendAsync(req, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Mirror of verify-agent-config.py: structural checks, key binding,
    /// Ed25519 verification over the exact signed bytes, then
    /// <see cref="CommitSignatureVerifiedPayload"/> for tenant binding,
    /// anti-rollback and the atomic commit + floor advance.
    /// </summary>
    private AgentConfig? VerifyAndCache(byte[] body)
    {
        if (!Ed25519Verifier.TryVerifyEnvelope(body, out var signedPayload))
            return Reject("signed envelope is malformed or Ed25519 signature is invalid");
        var config = CommitSignatureVerifiedPayload(signedPayload, Ed25519Verifier.PinnedKeyId);
        if (config is not null)
        {
            try
            {
                // Proof last: a crash or partial replacement cannot authorise
                // different plaintext bytes on restart. Every load re-verifies.
                string proof = _agentConfigFile + ".envelope";
                string directory = Path.GetDirectoryName(proof)!;
                if (OperatingSystem.IsWindows()) Patched.Shared.Security.SecureStagingDirectory.VerifyTrusted(directory);
                if ((File.Exists(proof) && (File.GetAttributes(proof) & FileAttributes.ReparsePoint) != 0) ||
                    (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("update proof path is a reparse point");
                string temporary = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".update-proof.tmp");
                try
                {
                    using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        stream.Write(body);
                        stream.Flush(flushToDisk: true);
                    }
                    File.Move(temporary, proof, overwrite: true);
                }
                finally { if (File.Exists(temporary)) File.Delete(temporary); }
                config = config with { UpdateAuthorityVerified = true };
            }
            catch
            {
                _log.LogWarning("agent-config: update authority proof could not be persisted; self-update waits for verified policy");
            }
        }
        if (config is not null && !InstallationEvidenceStore.AcceptVerifiedEnvelope(body, signedPayload))
            _log.LogWarning("agent-config: installation-evidence cache persistence failed; collection remains gated by the protected cache and delivery floor");
        return config;
    }

    /// <summary>
    /// Steps (f) to (k), reached only from <see cref="VerifyAndCache"/> after
    /// the Ed25519 signature over <paramref name="signedPayload"/> has
    /// verified. Private on purpose: it must never be callable with bytes that
    /// have not been verified. Tests reach it by reflection with scratch paths.
    ///
    /// Order matters and is part of the security contract (PAT-1756): tenant
    /// binding (g) runs before the anti-rollback floor (h) is consulted, so the
    /// tenant that selects the floor is the one bound in the verified payload
    /// and already proven equal to the device's enrolled tenant.
    ///
    /// PAT-1763: every check, including the typed deserialization (i), runs
    /// before anything is written. A verified payload that does not deserialize
    /// used to be rejected only after agent-config.json had been replaced and the
    /// floor advanced, which moved the floor for a config the agent never applied.
    /// The macOS verifier already refuses before its caller writes anything.
    /// </summary>
    private AgentConfig? CommitSignatureVerifiedPayload(byte[] signedPayload, string keyId)
    {
        // (f) Parse the verified config from the signed bytes.
        JsonDocument configDoc;
        try
        {
            configDoc = JsonDocument.Parse(signedPayload);
        }
        catch (JsonException ex)
        {
            return Reject($"parse signed_payload JSON: {ex.Message}");
        }

        using (configDoc)
        {
            var cfg = configDoc.RootElement;
            if (cfg.ValueKind != JsonValueKind.Object)
                return Reject("signed_payload is not a JSON object");

            // (g) Tenant binding — from the verified payload, not the outer envelope.
            string tenantId = cfg.TryGetProperty("tenant_id", out var tid) && tid.ValueKind == JsonValueKind.String
                ? tid.GetString() ?? ""
                : "";
            if (string.IsNullOrEmpty(_creds.TenantId))
                return Reject("local tenant-id credential is empty; tenant binding cannot be verified");
            if (tenantId != _creds.TenantId)
                return Reject("tenant_id in signed_payload does not match local tenant-id credential");

            // (h) Anti-rollback, keyed by tenant (PAT-1756). Only reached once
            // (g) has proven tenantId (from the verified payload) equals the
            // enrolled tenant. The floor is read here rather than reusing the
            // read FetchAsync made for If-None-Match, so an enrolment reset
            // that lands while the request is in flight is honoured.
            if (!cfg.TryGetProperty("config_version", out var verProp) ||
                verProp.ValueKind != JsonValueKind.Number ||
                !verProp.TryGetInt32(out int newVersion))
                return Reject("config_version is not an integer");
            var floorDecision = AgentConfigRollbackFloor.Evaluate(
                AgentConfigRollbackFloor.Read(_rollbackFloorFile), tenantId, newVersion);
            if (!floorDecision.Accept)
                return Reject(floorDecision.Message);
            _log.LogInformation("agent-config: {FloorDecision}", floorDecision.Message);

            // (i) Deserialize the verified canonical JSON before anything is written
            // (PAT-1763). The typed config must carry the same tenant and version the
            // checks above bound, or the cache and floor would describe a config the
            // agent does not hold.
            AgentConfig? config;
            try
            {
                config = _deserialize(signedPayload);
            }
            catch (Exception ex)
            {
                return Reject($"verified config could not be deserialized ({ex.GetType().Name}); cache and floor left unchanged");
            }
            if (config is null)
                return Reject("verified config could not be deserialized; cache and floor left unchanged");
            if (config.TenantId != tenantId || config.ConfigVersion != newVersion)
                return Reject("verified config deserialized to a different tenant_id or config_version than the payload binds; cache and floor left unchanged");

            // (j+k) Atomic commit: write the verified canonical bytes (not the outer envelope),
            // then advance the floor, keyed to the verified tenant (crash-safe order: config is
            // durable before the floor moves; both writes are temp file + rename).
            try
            {
                string? configDir = Path.GetDirectoryName(_agentConfigFile);
                if (!string.IsNullOrEmpty(configDir))
                    Directory.CreateDirectory(configDir);
                string tmp = _agentConfigFile + ".tmp";
                File.WriteAllBytes(tmp, signedPayload);
                File.Move(tmp, _agentConfigFile, overwrite: true);
                AgentConfigRollbackFloor.Write(_rollbackFloorFile, tenantId, newVersion);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "agent-config: verified but failed to write cache — keeping last-good config");
                return null;
            }

            _log.LogInformation(
                "agent-config: accepted version={Version} tier={Tier} key_id={KeyId}",
                newVersion, config.Tier, keyId);

            // PAT-1042: a signature-verified 200 is proof this device has
            // working credentials again — the mirror image of the 401
            // handler above that calls MarkSuspended. Clear only here,
            // after the commit above is durably in place and the config
            // has deserialized successfully, never on a bare/unverified
            // 200. Resumes normal enforcement immediately (no
            // consecutive-success threshold), which also self-heals a
            // transient or mistaken 401 for free.
            if (_creds.IsSuspended)
            {
                _creds.ClearSuspended();
                _log.LogInformation("device reinstated — suspended marker cleared");
            }

            return config;
        }
    }

    private AgentConfig? Reject(string reason)
    {
        _log.LogWarning("agent-config: rejected: {Reason}", reason);
        return null;
    }
}
