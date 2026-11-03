using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Patched.Shared.Paths;
using Patched.Shared.Security;
using Patched.Shared.Verification;

namespace Patched.Service;

/// <summary>
/// Bootstrap self-update check (PAT-108, rebuilt PAT-1248). Runs at service start, before
/// the first inventory cycle. Checks if a newer collector version is available, verifies
/// it, and writes a pending-update marker for the installer.
///
/// The service itself cannot replace its own binary while running on Windows, so this
/// class stops short of applying the update — it prepares the artifact and signals to
/// the installer/Intune that a new version is ready. The update is applied on next
/// service restart by the bootstrapper executable (or Intune re-detection).
///
/// PAT-1248: this used to bail out immediately, unconditionally, because nothing in the
/// repo ever wrote %ProgramData%\Patched\creds\artifact-key — self-update had never once
/// worked. The obvious fix (write that key at install time) was rejected: it was
/// ARTIFACT_SIGNING_KEY, a *symmetric* HMAC secret also used to sign the release MSI
/// itself for out-of-band human verification (tools/verify-agent-release.py); it is
/// deliberately absent from every endpoint, because shipping a symmetric secret to every
/// device would let one compromised endpoint forge artifacts estate-wide.
///
/// Instead this verifies a signed *artifact-metadata* envelope (version / platform /
/// channel / artifact_url / artifact_sha256) with the pinned Ed25519 public key in
/// <see cref="ArtifactTrust"/> — the same signed-envelope pattern already used for the
/// agent-config channel, each with its OWN distinct key
/// (PAT-516 key separation; see docs/signing-key-architecture.md and
/// verifier/sign-artifact-metadata.py). Verification is MANDATORY — "H7: an artifact that
/// will be installed as SYSTEM must be integrity- and authenticity-checked" still holds;
/// only the primitive changed, from a symmetric HMAC nothing could safely deliver, to an
/// asymmetric signature whose public half is safe to ship in every build.
///
/// Fail-safe: any error leaves the service running on the current version, and — PAT-1248
/// — reports a degraded reason via <see cref="AgentHealthStore"/> rather than logging at
/// LogDebug and vanishing. A no-op that logs nothing is indistinguishable from success.
///
/// PAT-1338: the per-version stage directory under <see cref="PathConstants.AgentUpdatesDir"/>
/// is now established through <see cref="SecureStagingDirectory.EnsureHardenedChain"/>
/// anchored at <see cref="PathConstants.StateDir"/>, like every other privileged staging
/// root (decommission / chocolatey / winget / self-update-restart). It used
/// to be a bare <c>Directory.CreateDirectory</c>, making <c>updates\</c> the ONLY such
/// root whose DACL was never established or verified at the moment of use — it relied
/// purely on ACEs inherited from StateDir, an inheritance that only holds if StateDir was
/// hardened before <c>updates\</c> and each per-version child first came into existence,
/// and which nothing afterwards ever re-checked. <see cref="StateDirectoryBootstrap"/>
/// deliberately does not enumerate or repair descendants, because "each privileged
/// operation establishes and verifies its own fixed child chain"; this was the operation
/// that never did. PAT-1334 closed the reparse-point half at the two privileged deletes
/// in <see cref="PendingUpdateApplier"/>; this closes the DACL half at creation. A
/// ~160 MB MSI is written here and later executed by LocalSystem, so an untrusted stage
/// directory aborts the update (fail closed) rather than being "repaired" and used.
/// </summary>
internal sealed class BootstrapUpdater
{
    // PAT-1248: (kind, subject) pair for every bail-out path below, using the
    // "one pair, many distinct reasons" agent_health convention so a single
    // BuildPayloadSection() entry represents "is self-update currently healthy",
    // with the `reason` string carrying which specific check failed.
    private const string HealthKind = "self_update";
    private const string HealthSubject = "artifact";

    // PAT-1269: distinct subject from HealthSubject ("artifact") for the
    // "a periodic check is deferring because a different version is already
    // pending apply" signal — see the deferral branch in DoCheckAndStageAsync.
    // Kept separate rather than folded into HealthSubject's own RecordSuccess/
    // RecordFailure calls for the same reason PendingUpdateApplier's "apply"
    // subject is kept separate from this class's "artifact" subject (see that
    // class's doc comment): RecordSuccess(HealthSubject) already fires moments
    // earlier in the SAME call, the instant the envelope verifies — a
    // RecordFailure(HealthSubject, ...) for the deferral immediately afterwards
    // would clobber that success and misreport "the check itself failed" when
    // what actually happened is the check succeeded and then found itself
    // blocked. This is the signal PAT-1269 exists to make visible: without it, a
    // permanently stuck marker (PendingUpdateApplier gives up after
    // MaxAttempts and deliberately retains it) makes every later, genuinely
    // newer release defer silently forever — exactly the fail-safe-invisible
    // shape of PAT-912/PAT-837/PAT-1249. A one-off deferral clears within an
    // hour (the next periodic check, once the pending one applies on a
    // restart); a deferral that PERSISTS across many checks is the thing worth
    // alerting on, and BuildPayloadSection's existing count/first_seen/last_seen
    // fields already carry "how many consecutive checks has this been stuck"
    // and "since when" for free.
    private const string DeferredHealthSubject = "deferred";

    // PAT-1293: distinct subject from HealthSubject ("artifact") for "was the
    // one-shot restart task that lets PendingUpdateApplier actually consume this
    // marker successfully scheduled". Kept separate for the same reason
    // DeferredHealthSubject is kept separate, immediately above: RecordSuccess
    // for HealthSubject fires moments earlier in the SAME call the instant the
    // marker is written, and a RecordFailure for a scheduling problem right after
    // would otherwise clobber that unrelated success (or vice versa on the next
    // check). This is also intentionally distinct from PendingUpdateApplier's own
    // "apply" subject — a failure to SCHEDULE the restart and a failure to APPLY
    // the update once restarted are different faults with different remedies.
    private const string RestartHealthSubject = "restart_schedule";

    // Sentinel the release workflow substitutes at build time. See ResolveCurrentVersion.
    internal const string UnsubstitutedVersionPlaceholder = "0.0.0";

    /// <summary>Response field carrying the signed envelope (PAT-1252 kept the
    /// endpoint additive, so the envelope is nested rather than the whole body).</summary>
    private const string EnvelopeField = "artifact_metadata_signature";

    private static readonly string[] RequiredEnvelopeFields = ["signed_payload", "key_id", "signature"];
    private static readonly System.Text.RegularExpressions.Regex Sha256Hex =
        new("^[0-9a-fA-F]{64}$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>
    /// PAT-1248: previously a hardcoded "0.0.0" literal that nothing in the build ever
    /// substituted (the comment said "Substituted at build time by CI"; nothing did), so
    /// version comparison against the server's reported available version could never
    /// converge. Resolved from the assembly's InformationalVersion attribute, which IS
    /// substituted at publish time by windows-agent-release.yml's
    /// "-p:InformationalVersion=&lt;version&gt;+&lt;commit-sha&gt;"
    /// (see windows/installer/resolve-release-version.sh). The "+&lt;sha&gt;" SemVer
    /// build-metadata suffix is stripped so this compares like-for-like against the plain
    /// X.Y.Z the server reports.
    /// </summary>
    private static readonly string CurrentVersion = ResolveCurrentVersion();

    private readonly ILogger<BootstrapUpdater>       _log;
    private readonly IHttpClientFactory              _httpFactory;
    private readonly CredentialStore                 _creds;
    private readonly Func<AgentConfig>               _currentConfig;
    private readonly AgentHealthStore                _agentHealth;
    private readonly ArtifactTrust                   _trust;
    private readonly IPendingUpdateRestartScheduler  _restartScheduler;

    // Pending-update marker written after a successful download + verification.
    // PAT-1338: the same constants PendingUpdateApplier already consumes, rather
    // than a second Path.Combine of the same two literals — the applier reads the
    // marker this class writes and prunes the directory this class stages into, so
    // the two must never be able to drift apart.
    public static readonly string PendingUpdateFile = PathConstants.PendingAgentUpdateFile;

    // Directory where pending updates are staged.
    private static readonly string UpdatesDir = PathConstants.AgentUpdatesDir;

    private readonly string _pendingUpdateFile;
    private readonly string _updatesDir;
    private readonly string _hardeningRoot;

    public BootstrapUpdater(
        ILogger<BootstrapUpdater>      log,
        IHttpClientFactory             httpFactory,
        CredentialStore                creds,
        AgentConfigManager             configManager,
        AgentHealthStore               agentHealth,
        IPendingUpdateRestartScheduler restartScheduler)
        : this(log, httpFactory, creds, () => configManager.Current, agentHealth, ArtifactTrust.Production,
               restartScheduler, PendingUpdateFile, UpdatesDir, PathConstants.StateDir)
    {
    }

    /// <summary>
    /// Test-only seam: <paramref name="currentConfig"/> replaces the full
    /// <see cref="AgentConfigManager"/> dependency (heavy to construct — it reads
    /// %ProgramData% on construction) with a plain delegate, and
    /// <paramref name="trust"/>/<paramref name="pendingUpdateFileOverride"/>/
    /// <paramref name="updatesDirOverride"/> redirect trust material and staging paths to
    /// a scratch temp directory instead of the real production locations.
    ///
    /// <paramref name="hardeningRootOverride"/> (PAT-1338) is the trusted anchor
    /// <see cref="SecureStagingDirectory.EnsureHardenedChain"/> walks down from when
    /// establishing the per-version stage directory. Production passes
    /// <see cref="PathConstants.StateDir"/>. It exists so a test can anchor the chain at
    /// its own scratch root and still run the REAL hardening code — deliberately NOT an
    /// opt-out switch that lets tests skip the guard: a control no test can trip is a
    /// control that cannot fail, which is the exact shape of PAT-912/PAT-837/PAT-960.
    /// EnsureHardenedChain refuses any <c>dir</c> that is not under <c>root</c>
    /// (ArgumentException), so a scratch staging path simply needs its own matching
    /// anchor rather than a bypass.
    ///
    /// When null it is derived as the parent of <paramref name="updatesDirOverride"/>,
    /// mirroring <see cref="PendingUpdateApplier"/>'s <c>trustedRootOverride</c> (PAT-1334)
    /// and reproducing the real StateDir/updates relationship one level up in a scratch
    /// temp directory.
    /// </summary>
    internal BootstrapUpdater(
        ILogger<BootstrapUpdater>      log,
        IHttpClientFactory             httpFactory,
        CredentialStore                creds,
        Func<AgentConfig>              currentConfig,
        AgentHealthStore               agentHealth,
        ArtifactTrust                  trust,
        IPendingUpdateRestartScheduler restartScheduler,
        string?                        pendingUpdateFileOverride = null,
        string?                        updatesDirOverride = null,
        string?                        hardeningRootOverride = null)
    {
        _log            = log;
        _httpFactory    = httpFactory;
        _creds          = creds;
        _currentConfig  = currentConfig;
        _agentHealth    = agentHealth;
        _trust          = trust;
        _restartScheduler   = restartScheduler;
        _pendingUpdateFile = pendingUpdateFileOverride ?? PendingUpdateFile;
        _updatesDir         = updatesDirOverride ?? UpdatesDir;
        _hardeningRoot      = hardeningRootOverride
            ?? Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(_updatesDir))
            ?? _updatesDir;
    }

    /// <summary>
    /// Check for and stage a newer agent version. Returns true if a pending update
    /// was staged; false if already current or any error occurred (fail-safe).
    /// Never throws — all errors are caught and logged (and, PAT-1248, reported as
    /// degraded health rather than only logged).
    /// </summary>
    public async Task<bool> CheckAndStageAsync(CancellationToken ct)
    {
        try
        {
            return await DoCheckAndStageAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "bootstrap-updater: check failed — continuing on current version");
            _agentHealth.RecordFailure(HealthKind, HealthSubject, "unexpected_exception");
            return false;
        }
    }

    private async Task<bool> DoCheckAndStageAsync(CancellationToken ct)
    {
        // PAT-1248: refuse to trust anything while the production key is still the
        // shipped-inert placeholder (Andy has not yet generated
        // ARTIFACT_METADATA_SIGNING_KEY — see docs/signing-key-runbook.md). Checked
        // explicitly, first, so this degrades with an unambiguous "not provisioned"
        // reason instead of surfacing as a generic signature failure indistinguishable
        // from a real attack.
        if (!_trust.IsKeyMaterialProvisioned)
            return Fail("artifact_trust_not_provisioned");

        // PAT-1760: both requests below need the device's bearer token and HMAC
        // secret. PatchedWorker runs this check at startup even after a transient
        // enrolment failure, when the device holds neither, and a request then
        // could only be rejected. Send nothing, as the fetchers do (PAT-1754), and
        // leave health untouched: a skipped check neither proves nor disproves the
        // self-update path. The two values are read once and used for both
        // requests, never re-read from the store.
        if (!DeviceCredentials.TryRead(_creds, out string bearerToken, out string hmacSecret))
        {
            _log.LogInformation("bootstrap-updater: not enrolled yet (device credentials not present), skipping update check; no request sent");
            return false;
        }

        var config = _currentConfig();
        var policy = UpdateChannelPolicy.Resolve(config, _creds.TenantId, _creds.CanonicalDeviceId);
        string channel = policy.Channel;
        string? pinnedVersion = policy.PinnedVersion;
        _agentHealth.RecordUpdateChannel(policy, _creds.TenantId, _creds.CanonicalDeviceId);

        // PAT-2351: config polling runs concurrently with startup. The reporting
        // default must not authorise a stable download before verified policy is
        // available. The normal hourly check retries after config acceptance.
        if (!policy.HasAuthority)
            return Fail("update_policy_unverified");

        string artifactUrl = $"{PathConstants.ApiUrl}/v1/agent/artifact?platform=windows&channel={Uri.EscapeDataString(channel)}";
        if (!string.IsNullOrEmpty(pinnedVersion))
            artifactUrl += $"&version={Uri.EscapeDataString(pinnedVersion)}";

        var client = _httpFactory.CreateClient("patched");
        // PAT-1136: this endpoint previously sent no X-Patched-Timestamp / X-Patched-Nonce
        // headers at all (unlike every other signed caller and its macOS counterpart,
        // patched-bootstrap.sh, which does send them) — a pre-existing parity gap. The v2
        // signature below is computed over timestamp+nonce+body, so those values MUST also
        // be sent as headers for the server to reproduce the same digest; added here to
        // close that gap rather than sign values the request never actually carries.
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        string nonce     = Guid.NewGuid().ToString("N");
        string sig        = HmacSigner.ComputeSignature(hmacSecret, "GET", HmacSigner.EndpointAgentArtifact, timestamp, nonce, ReadOnlySpan<byte>.Empty);
        var req = new HttpRequestMessage(HttpMethod.Get, artifactUrl);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
        req.Headers.TryAddWithoutValidation(HmacSigner.SignatureHeader, sig);
        req.Headers.TryAddWithoutValidation("X-Patched-Timestamp", timestamp);
        req.Headers.TryAddWithoutValidation("X-Patched-Nonce", nonce);

        using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            return Fail($"artifact_endpoint_returned_{(int)resp.StatusCode}");

        byte[] envelopeBytes = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);

        if (!TryVerifyEnvelope(envelopeBytes, out byte[] payload, out string signedPayloadBase64,
                out string signatureBase64, out string reason))
            return Fail(reason);

        if (!TryReadArtifactMetadata(payload, channel, out string availableVersion, out string downloadUrl,
                out string expectedSha256, out reason))
            return Fail(reason);

        // H7: constrain the download to the expected TLS host. The artifact metadata
        // came from a verified, Ed25519-signed envelope; the binary MUST come from the
        // same HTTPS API origin so a tampered/spoofed artifact_url — even a validly
        // signed one for a different purpose — cannot redirect a SYSTEM download to an
        // attacker-controlled server.
        if (!IsAllowedArtifactUrl(downloadUrl))
        {
            _log.LogError("bootstrap-updater: artifact_url is not an allowed HTTPS host on the "
                + "API origin — refusing to download ({Url})", downloadUrl);
            return Fail("artifact_url_not_allowed");
        }

        // Verification succeeded end-to-end: the self-update path is healthy, whether or
        // not an update actually needs staging below.
        _agentHealth.RecordSuccess(HealthKind, HealthSubject);

        if (availableVersion == CurrentVersion)
        {
            _log.LogDebug("bootstrap-updater: already at version {Version}", CurrentVersion);
            // PAT-1269: nothing to stage this cycle, so there is no pending-version
            // conflict to report either — clear any stale deferral from an earlier
            // cycle (e.g. the previously-stuck version's apply finally succeeded and
            // CurrentVersion caught up).
            _agentHealth.RecordSuccess(HealthKind, DeferredHealthSubject);
            return false;
        }

        _log.LogInformation("bootstrap-updater: update available {Current} → {Available}",
            CurrentVersion, availableVersion);

        // Check if we already staged this version.
        string stageDir  = Path.Combine(_updatesDir, availableVersion);
        string stageFile = Path.Combine(stageDir, "patched-agent.msi");
        // PAT-2396: "already staged" used to mean only "a file exists at the stage path
        // and a marker names this version", which blessed a marker and installer this
        // class never wrote. It now holds only when the marker carries a signed envelope
        // that verifies, that envelope and the marker both name the version and SHA-256
        // the envelope just fetched and verified above names, and the bytes on disk hash
        // to that value. Anything less falls through and is restaged from the origin.
        if (IsStagedAndVerified(stageFile, availableVersion, expectedSha256))
        {
            _log.LogInformation("bootstrap-updater: version {Version} already staged", availableVersion);
            // PAT-1269: staged for exactly the version the server is offering —
            // not blocked on anything, so clear any stale deferral.
            _agentHealth.RecordSuccess(HealthKind, DeferredHealthSubject);
            return true;
        }

        // PAT-1269: this check now also runs periodically (previously start-only —
        // see PatchedWorker), so unlike before, a marker for a DIFFERENT version can
        // genuinely still be sitting here unconsumed, waiting for PendingUpdateApplier
        // to apply it on the next restart, the next time this method runs. Defer
        // rather than stage over it: downloading a second ~160 MB installer here
        // would overwrite pending-agent-update.json out from under an update that is
        // already verified and waiting to apply, and PendingUpdateApplier's own
        // pruning (PruneStaleStagedDirectories) keeps only the version the marker
        // names, so the just-downloaded newer one could be deleted the moment the
        // pending one's apply attempt runs. Scoped to a DIFFERENT version on purpose
        // — when the marker's version equals availableVersion, the block above
        // already handles the common case (short-circuit, no re-download) and the
        // uncommon one (stage file went missing — e.g. PendingUpdateApplier found
        // installer_missing and deliberately retained the marker for this exact
        // repair path, see its class doc comment) needs to fall through and
        // re-download, not be blocked here too.
        // Ordinal — matching IsStagedAndVerified (the same-version short-circuit
        // just above), which also compares Ordinal. The two checks classify the
        // same pair (pendingVersion, availableVersion) and MUST agree, or a value
        // that the short-circuit above judges "different" (so it falls through to
        // here) could be judged "the same" by this guard using a looser comparison,
        // silently skipping the deferral RecordFailure below — the one signal
        // PAT-1269 added specifically to make a stuck marker visible. Chosen as
        // Ordinal rather than OrdinalIgnoreCase because these are machine-generated
        // version strings (windows-agent-release.yml's -p:InformationalVersion, see
        // ResolveCurrentVersion/ParseSemanticVersion) with no legitimate source of
        // case variation to normalise away — a mismatch here is either the same
        // value or a genuine anomaly worth surfacing, not a formatting quirk to
        // treat as equal. Both non-author reviewers flagged the original
        // Ordinal/OrdinalIgnoreCase split between these two checks independently.
        if (TryReadPendingMarkerVersion(out string? pendingVersion)
            && !string.Equals(pendingVersion, availableVersion, StringComparison.Ordinal))
        {
            _log.LogInformation(
                "bootstrap-updater: deferring stage of {Available} — version {Pending} is already pending apply",
                availableVersion, pendingVersion);
            // PAT-1269: make the deferral visible rather than silent. Without this,
            // a marker PendingUpdateApplier has permanently given up on (attempts
            // exhausted — see its MaxAttempts doc comment) makes every future,
            // genuinely newer release defer forever with nothing anywhere saying
            // so — the same fail-safe-invisible shape as PAT-912/PAT-837/PAT-1249,
            // just in the update rail itself, where a wedged endpoint stops
            // receiving every future fix including security ones. The reason
            // string names BOTH versions so the entry says what is actually stuck,
            // not just that something is. A one-off deferral (an apply legitimately
            // in flight) clears on the very next successful branch above or below
            // within one BootstrapUpdateCheckInterval; a deferral that keeps
            // recurring bumps Count and keeps LastSeen fresh via RecordFailure's
            // existing semantics, so "stuck for N consecutive checks since
            // <first_seen>" is visible without any new plumbing.
            _agentHealth.RecordFailure(HealthKind, DeferredHealthSubject,
                $"pending_version_{pendingVersion}_blocks_stage_of_{availableVersion}");
            return true;
        }

        // PAT-1269: reached only when nothing blocked staging this cycle — clear any
        // stale deferral before proceeding to download (mirrors the two RecordSuccess
        // calls above for the earlier "nothing to do" exits).
        _agentHealth.RecordSuccess(HealthKind, DeferredHealthSubject);

        // Download the artifact. PAT-1260: this now lives behind
        // /v1/agent/artifact/download on the API (the anonymous GitHub Releases
        // URL it replaces 404'd — Patched-LTD/updater is a private repo), which
        // requires the same per-device Bearer + HMAC as the envelope fetch
        // above, signed over its OWN endpoint ID (EndpointAgentArtifactDownload)
        // so a captured signature for one endpoint cannot be replayed against
        // the other. A FRESH timestamp/nonce pair is required here — reusing
        // the envelope fetch's above would replay an already-spent nonce.
        // PAT-1338: establish + verify the stage directory's trust boundary BEFORE a
        // single byte of a SYSTEM-executed installer lands in it. Fail closed — an
        // untrusted or reparse-pointed directory aborts the update; it is never
        // "repaired" and used (see SecureStagingDirectory's class doc for why
        // re-applying a DACL onto a possibly-attacker-planted directory would only
        // legitimise it).
        if (!TryEstablishStageDirectory(stageDir))
            return Fail("stage_directory_untrusted");

        string tmpFile = stageFile + ".tmp";

        string dlTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        string dlNonce     = Guid.NewGuid().ToString("N");
        string dlSig       = HmacSigner.ComputeSignature(hmacSecret, "GET",
            HmacSigner.EndpointAgentArtifactDownload, dlTimestamp, dlNonce, ReadOnlySpan<byte>.Empty);
        var dlReq = new HttpRequestMessage(HttpMethod.Get, downloadUrl);
        dlReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
        dlReq.Headers.TryAddWithoutValidation(HmacSigner.SignatureHeader, dlSig);
        dlReq.Headers.TryAddWithoutValidation("X-Patched-Timestamp", dlTimestamp);
        dlReq.Headers.TryAddWithoutValidation("X-Patched-Nonce", dlNonce);

        // PAT-1260 non-author-review finding: the "patched" client above carries
        // a 30-second Timeout, which is correct for the small JSON envelope
        // fetch but WRONG here — HttpClient.Timeout bounds the entire operation
        // including reading the response body, even under
        // HttpCompletionOption.ResponseHeadersRead, so reusing "client" would
        // demand >5.3 MB/s sustained throughput for a ~160 MB MSI and fail on
        // any ordinary connection. A dedicated named client with its own,
        // generous-but-still-bounded Timeout (PatchedHttpClientTimeouts.Artifact,
        // registered in Program.cs) exists for exactly this call.
        var artifactClient = _httpFactory.CreateClient("patched-artifact");

        // ResponseHeadersRead + a direct stream-to-disk copy: the MSI is
        // ~160 MB and must never be buffered whole in memory. A non-success
        // status gets its own distinct, greppable failure reason (surfaced via
        // AgentHealthStore) instead of falling through to a generic caught
        // HttpRequestException — that opacity is the reason this bug took
        // several releases to pin down (found on WIN-STAGING, 2026-08-11: a
        // plain 404 with no context beyond the raw HTTP log line).
        using (var dlResp = await artifactClient.SendAsync(dlReq, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
        {
            if (!dlResp.IsSuccessStatusCode)
                return Fail($"artifact_download_returned_{(int)dlResp.StatusCode}");

            using var dl = await dlResp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var fs = File.Create(tmpFile);
            await dl.CopyToAsync(fs, ct).ConfigureAwait(false);
        }

        // PAT-1248: SHA-256 integrity check against the value from the VERIFIED signed
        // envelope (not an unauthenticated field) — this is now the artifact
        // authenticity+integrity control, replacing the old artifact-key HMAC.
        string actualSha256 = ComputeSha256(tmpFile);
        if (!string.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            _log.LogError("bootstrap-updater: SHA-256 mismatch for version {Version} — discarding", availableVersion);
            File.Delete(tmpFile);
            _agentHealth.RecordFailure(HealthKind, HealthSubject, "artifact_sha256_mismatch");
            return false;
        }

        // H7 (Authenticode) — FOLLOW-UP, gated on MSI signing (see sign-hook.bat /
        // signtool and the L-set signing item). Once the Patched MSI is signed and
        // the expected publisher name is known, add an Authenticode gate here using
        // the existing fail-closed verifier before staging:
        //     var r = _authenticode.Verify(tmpFile, ExpectedMsiPublisher);
        //     if (!r.Passed) { File.Delete(tmpFile); return false; }
        // That requires the Developer signing identity (a human decision), so it is
        // intentionally not enforced yet. Until then the mandatory Ed25519-verified
        // artifact metadata + SHA-256 above is the artifact authenticity+integrity
        // control.

        File.Move(tmpFile, stageFile, overwrite: true);
        _log.LogInformation("bootstrap-updater: version {Version} staged at {Path}", availableVersion, stageFile);

        // Write pending-update marker. PAT-1261: carries sha256 (the VERIFIED
        // expectedSha256 from the signed envelope, not a value re-derived from the
        // possibly-tampered file on disk) so PendingUpdateApplier — which runs as
        // LocalSystem and executes an installer off disk on a later service start —
        // has something to re-verify the staged bytes against before ever running
        // them. A marker with no hash (written by 0.13.20 or earlier, before this
        // field existed) is treated by the applier as unverifiable, never as
        // trust-everything.
        //
        // PAT-2396: also carries the signed envelope itself, verbatim. The fields above
        // are only claims; the envelope is what PendingUpdateApplier re-verifies them
        // against, so a marker nothing signed can no longer vouch for itself.
        var marker = new
        {
            version = availableVersion,
            installer_path = stageFile,
            sha256 = expectedSha256,
            staged_at = DateTimeOffset.UtcNow,
            signed_payload = signedPayloadBase64,
            signature = signatureBase64,
            key_id = _trust.KeyId,
        };
        string tmp = _pendingUpdateFile + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(marker));
        File.Move(tmp, _pendingUpdateFile, overwrite: true);

        _agentHealth.RecordSuccess(HealthKind, HealthSubject);
        _log.LogInformation("bootstrap-updater: pending update marker written — apply on next service restart");

        // PAT-1293: the marker above is necessary but not sufficient — Windows
        // services cannot replace their own running binary, and PendingUpdateApplier
        // (the class that DOES apply it) only ever runs at service START. Nothing
        // else in the product ever decides to restart the service: no timer, no
        // watchdog, no self-stop, and the MSI's own crash-recovery ServiceConfig
        // restarts only on FAILURE, never on a healthy staged-update exit. Every
        // endpoint that appeared to self-update during development was in fact
        // bounced by a human running Stop-Service/Start-Service by hand — this is
        // the third instance of the same "correct code, never invoked" shape
        // (PAT-1261, PAT-1269), so this closes the actual end of the rail rather
        // than moving the wall back again. Registering the restart here, right next
        // to the marker write it exists to act on, and from the running SERVICE
        // rather than the MSI, is the approach Andy already decided on (PAT-1293
        // brief) — an MSI-registered task would only land on machines running a
        // NEW installer, and those machines don't need an unattended trigger at
        // all, since a human is already there running it.
        if (!_restartScheduler.EnsureScheduled())
        {
            // Fail-safe: registration failure must never crash or block the
            // service, exactly like every other engine here. But it must NOT be
            // silent — CLAUDE.md's standing rule is that anything which can
            // silently disable itself must report degraded, not stay quiet, and
            // "update staged but restart never scheduled" is precisely the
            // invisible-failure shape (PAT-912/PAT-837/PAT-960 precedent) that
            // produced PAT-1261, PAT-1269, and this very ticket. A silent
            // registration failure here would recreate the bug one layer further
            // out — the marker would exist, staging would look successful, and the
            // update would still never apply, with nothing anywhere recording why.
            _log.LogError(
                "bootstrap-updater: pending update staged for version {Version}, but the restart task " +
                "could not be scheduled — the update will not apply until the service is restarted by " +
                "some other means", availableVersion);
            _agentHealth.RecordFailure(HealthKind, RestartHealthSubject, "restart_task_registration_failed");
        }
        else
        {
            _agentHealth.RecordSuccess(HealthKind, RestartHealthSubject);
        }

        return true;
    }

    /// <summary>
    /// Verifies the signed-envelope wire format shared with the agent-config
    /// channel: {signed_payload, signature, key_id}, base64-encoded,
    /// verified with the pinned <see cref="ArtifactTrust"/> public key. Returns the
    /// verified (decoded) payload bytes on success.
    /// </summary>
    private bool TryVerifyEnvelope(
        byte[] envelopeBytes, out byte[] payload, out string signedPayloadBase64,
        out string signatureBase64, out string reason)
    {
        payload = [];
        signedPayloadBase64 = "";
        signatureBase64 = "";
        reason = "";
        try
        {
            using var envelope = JsonDocument.Parse(envelopeBytes);
            var response = envelope.RootElement;
            if (response.ValueKind != JsonValueKind.Object)
            {
                reason = "artifact_response_not_json_object";
                return false;
            }

            // PAT-1258: the envelope is a NAMED FIELD of the response, not the
            // response itself. PAT-1252 kept /v1/agent/artifact additive so the
            // legacy version/artifact_url/artifact_hmac fields stay put for
            // endpoints that update on their own schedule, which means the
            // envelope lives under artifact_metadata_signature alongside them.
            // This code originally read {signed_payload, signature, key_id}
            // straight off the root, from an earlier plan where the envelope
            // WAS the response body. The two sides were built against different
            // versions of that decision and nothing caught it until a real
            // endpoint fetched a real signed release and reported
            // artifact_envelope_missing_field.
            //
            // A missing field here means the server has no envelope for this
            // release (every release before 0.13.16, and any cut before the key
            // was provisioned). That is a legitimate state and must fail closed
            // rather than fall back to the unverified legacy fields.
            if (!response.TryGetProperty(EnvelopeField, out var root)
                || root.ValueKind != JsonValueKind.Object)
            {
                reason = "artifact_envelope_absent";
                return false;
            }

            foreach (var field in RequiredEnvelopeFields)
            {
                if (!root.TryGetProperty(field, out _))
                {
                    reason = "artifact_envelope_missing_field";
                    return false;
                }
            }

            string keyId = root.GetProperty("key_id").GetString() ?? "";
            if (!string.Equals(keyId, _trust.KeyId, StringComparison.Ordinal))
            {
                reason = "artifact_key_id_mismatch";
                return false;
            }

            // PAT-2396: kept verbatim so the marker can carry exactly what was verified.
            signedPayloadBase64 = root.GetProperty("signed_payload").GetString() ?? "";
            signatureBase64     = root.GetProperty("signature").GetString() ?? "";

            try { payload = Convert.FromBase64String(signedPayloadBase64); }
            catch (FormatException) { reason = "artifact_signed_payload_not_base64"; return false; }

            byte[] signature;
            try { signature = Convert.FromBase64String(signatureBase64); }
            catch (FormatException) { reason = "artifact_signature_not_base64"; return false; }

            if (!_trust.Verify(payload, signature))
            {
                reason = "artifact_signature_invalid";
                return false;
            }

            return true;
        }
        catch (JsonException)
        {
            reason = "artifact_response_not_valid_json";
            return false;
        }
    }

    /// <summary>
    /// Extracts and validates the artifact metadata from the VERIFIED envelope payload.
    /// <paramref name="requestedChannel"/> is cross-checked against the signed payload's
    /// own "channel" so a validly-signed envelope for a different channel can never be
    /// substituted for the one actually requested (domain separation).
    /// </summary>
    private static bool TryReadArtifactMetadata(
        byte[] payload,
        string requestedChannel,
        out string version,
        out string artifactUrl,
        out string artifactSha256,
        out string reason)
    {
        version = "";
        artifactUrl = "";
        artifactSha256 = "";
        reason = "";
        try
        {
            using var doc = JsonDocument.Parse(payload);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                reason = "artifact_metadata_not_json_object";
                return false;
            }

            string platform = GetString(root, "platform");
            if (!string.Equals(platform, "windows", StringComparison.OrdinalIgnoreCase))
            {
                reason = "artifact_metadata_platform_mismatch";
                return false;
            }

            string channel = GetString(root, "channel");
            if (!string.Equals(channel, requestedChannel, StringComparison.OrdinalIgnoreCase))
            {
                reason = "artifact_metadata_channel_mismatch";
                return false;
            }

            version = GetString(root, "version");
            artifactUrl = GetString(root, "artifact_url");
            artifactSha256 = GetString(root, "artifact_sha256");

            // H7: SHA-256 is MANDATORY for an artifact that will be installed as SYSTEM.
            // A verified envelope missing any of these fields is rejected (fail closed) —
            // we never stage an installer we cannot integrity-verify.
            if (string.IsNullOrEmpty(version) || string.IsNullOrEmpty(artifactUrl) || string.IsNullOrEmpty(artifactSha256))
            {
                reason = "artifact_metadata_missing_required_field";
                return false;
            }
            if (!Sha256Hex.IsMatch(artifactSha256))
            {
                reason = "artifact_metadata_malformed_sha256";
                return false;
            }

            return true;
        }
        catch (JsonException)
        {
            reason = "artifact_metadata_not_valid_json";
            return false;
        }
    }

    private static string GetString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? ""
            : "";

    /// <summary>
    /// PAT-1338: creates <paramref name="stageDir"/> the way every other privileged
    /// staging root in this agent is created — through
    /// <see cref="SecureStagingDirectory.EnsureHardenedChain"/>, anchored at
    /// <see cref="_hardeningRoot"/> (<see cref="PathConstants.StateDir"/> in production).
    /// Every level from that anchor down to the per-version leaf is created with an
    /// explicit protected SYSTEM+Administrators-only DACL if missing, and verified —
    /// not a reparse point, owned by SYSTEM/Administrators, and granting no
    /// write-capable ACE to any other principal — if already present.
    ///
    /// Returns false (caller aborts the update) rather than throwing, so the failure
    /// carries its own distinct, greppable AgentHealthStore reason instead of being
    /// absorbed into CheckAndStageAsync's generic "unexpected_exception". Genuine IO
    /// errors are deliberately NOT caught here: those keep classifying exactly as they
    /// did when this was a bare Directory.CreateDirectory.
    /// </summary>
    private bool TryEstablishStageDirectory(string stageDir)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                SecureStagingDirectory.EnsureHardenedChain(stageDir, _hardeningRoot);
                return true;
            }

            // The shipping agent is Windows-only (net10.0-windows, MSI-installed
            // service), so the branch above is the only one production ever takes.
            // This one exists because the Windows suite is also built and run
            // cross-target on macOS during development (AGENTS.md, "known-red tests"),
            // where System.Security.AccessControl throws PlatformNotSupportedException
            // for every DACL/owner read — the same reason RollingFileLogger already
            // carries an OperatingSystem.IsWindows() guard around its own
            // Windows-only file check.
            //
            // Deliberately not a blanket bypass: the containment and reparse-point-chain
            // halves of the same guard are platform-neutral (PathSafety, PAT-1329/1334),
            // so they still run here and this path still fails closed. Only the ACL
            // half — which physically cannot execute off Windows — is absent.
            if (!PathSafety.IsContained(_hardeningRoot, stageDir) ||
                PathSafety.HasReparsePointInChain(_hardeningRoot, stageDir))
            {
                _log.LogError(
                    "bootstrap-updater: refusing to stage into {Dir} — fails containment/reparse-point "
                    + "check against trusted root {Root}", stageDir, _hardeningRoot);
                return false;
            }

            Directory.CreateDirectory(stageDir);
            return true;
        }
        catch (SecureStagingDirectory.UntrustedDirectoryException ex)
        {
            // Names the path and the specific invariant that failed (reparse point,
            // untrusted owner, or a write-capable ACE for a non-admin principal) —
            // the exception message carries all three shapes.
            _log.LogError(ex,
                "bootstrap-updater: refusing to stage version artifact into {Dir} — it is not a trusted "
                + "SYSTEM/Administrators-only directory under {Root}", stageDir, _hardeningRoot);
            return false;
        }
        catch (ArgumentException ex)
        {
            // EnsureHardenedChain's containment check: stageDir resolved outside the
            // trusted root. Only reachable if _updatesDir/_hardeningRoot are wired
            // inconsistently, but refusing beats staging outside the boundary.
            _log.LogError(ex,
                "bootstrap-updater: refusing to stage version artifact into {Dir} — not contained by the "
                + "trusted root {Root}", stageDir, _hardeningRoot);
            return false;
        }
    }

    private bool Fail(string reason)
    {
        _log.LogWarning("bootstrap-updater: {Reason} — skipping update check, continuing on current version", reason);
        _agentHealth.RecordFailure(HealthKind, HealthSubject, reason);
        return false;
    }

    /// <summary>
    /// PAT-2396: true only when the pending-update marker and the file at
    /// <paramref name="stageFile"/> are provably the update the envelope verified in
    /// this very check describes. See the call site. Fail-safe: anything missing,
    /// unreadable or mismatched is "not staged", which restages rather than trusts.
    /// </summary>
    private bool IsStagedAndVerified(string stageFile, string version, string expectedSha256)
    {
        try
        {
            if (!File.Exists(stageFile) || !File.Exists(_pendingUpdateFile)) return false;

            using var doc = JsonDocument.Parse(File.ReadAllText(_pendingUpdateFile));
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return false;

            if (!string.Equals(GetString(root, "version"), version, StringComparison.Ordinal)) return false;
            if (!string.Equals(GetString(root, "sha256"), expectedSha256, StringComparison.OrdinalIgnoreCase)) return false;

            if (!StagedUpdateEnvelope.TryVerify(
                    _trust,
                    GetString(root, StagedUpdateEnvelope.KeyIdField),
                    GetString(root, StagedUpdateEnvelope.PayloadField),
                    GetString(root, StagedUpdateEnvelope.SignatureField),
                    out var metadata, out _)
                || !StagedUpdateEnvelope.Matches(metadata, version, expectedSha256, out _))
            {
                return false;
            }

            return string.Equals(ComputeSha256(stageFile), expectedSha256, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// PAT-1269: reads back just the "version" field of the pending-update marker,
    /// if one exists and parses. Used by the "different version already pending"
    /// deferral in <see cref="DoCheckAndStageAsync"/>; the same-version short-circuit
    /// is <see cref="IsStagedAndVerified"/> (PAT-2396). Fail-safe like every
    /// other marker read in this class: a missing or unparseable file is "no marker
    /// known", never an exception.
    /// </summary>
    private bool TryReadPendingMarkerVersion(out string? version)
    {
        version = null;
        try
        {
            if (!File.Exists(_pendingUpdateFile)) return false;
            using var doc = JsonDocument.Parse(File.ReadAllText(_pendingUpdateFile));
            if (!doc.RootElement.TryGetProperty("version", out var vp)) return false;
            version = vp.GetString();
            return version is not null;
        }
        catch { return false; }
    }

    /// <summary>Internal (not private): PAT-1261's <see cref="PendingUpdateApplier"/>
    /// reuses this exact routine to re-verify the staged installer's bytes at apply
    /// time, rather than duplicating a second SHA-256-over-a-file helper.</summary>
    internal static string ComputeSha256(string filePath)
    {
        using var fs = File.OpenRead(filePath);
        byte[] hash = SHA256.HashData(fs);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>GitHub Releases hosts. `github.com` serves the release download
    /// URL; it 302s to `objects.githubusercontent.com`, which HttpClient follows,
    /// so both must be allowed or the redirect is refused mid-download.</summary>
    private static readonly string[] ReleaseDownloadHosts =
        ["github.com", "objects.githubusercontent.com"];

    /// <summary>Path prefix every Patched-LTD release download shares. Checked so
    /// allowing github.com does not allow the whole of GitHub.</summary>
    private const string ReleasePathPrefix = "/Patched-LTD/";

    // H7, as amended by PAT-1259.
    //
    // The original rule was: download only from the same HTTPS host that served
    // the authenticated metadata, i.e. the API origin. Its stated reason was that
    // a tampered or spoofed artifact_url must not be able to redirect a SYSTEM
    // download to an attacker-controlled server.
    //
    // That reason no longer rests on the host. Since PAT-1248 the artifact_url is
    // inside the Ed25519-signed payload, alongside artifact_sha256, both verified
    // against the pinned public key BEFORE this check runs and the hash re-checked
    // against the downloaded bytes after. Spoofing the URL now requires the
    // private key, which lives only in a GitHub Actions secret and is deliberately
    // absent from the API. So the signature defeats the exact threat the host pin
    // was defending against.
    //
    // Meanwhile the pin blocked the real topology: releases are published to
    // GitHub Releases, so the signed artifact_url legitimately points at
    // github.com and every self-update was refused (found on WIN-STAGING,
    // 2026-08-11).
    //
    // Andy's ruling, 2026-08-11: allow GitHub Releases under the Patched-LTD path
    // and keep HTTPS, the signature and the SHA-256 doing the real work, rather
    // than proxying artifacts through the API or dropping the host check entirely.
    // This stays defence in depth: it is deliberately NOT "any HTTPS host".
    private static bool IsAllowedArtifactUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;
        if (uri.Scheme != Uri.UriSchemeHttps)
            return false;

        // The API origin remains allowed: it is still the right answer if
        // artifacts are ever served from the platform directly.
        if (Uri.TryCreate(PathConstants.ApiUrl, UriKind.Absolute, out var api)
            && string.Equals(uri.Host, api.Host, StringComparison.OrdinalIgnoreCase))
            return true;

        foreach (var host in ReleaseDownloadHosts)
        {
            if (!string.Equals(uri.Host, host, StringComparison.OrdinalIgnoreCase))
                continue;

            // github.com must be scoped to our org. objects.githubusercontent.com
            // serves opaque, signed, expiring blob paths that carry no org segment,
            // so a path check there would reject every real redirect; the signed
            // artifact_sha256 is what constrains what those bytes may be.
            if (string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase))
                return uri.AbsolutePath.StartsWith(ReleasePathPrefix, StringComparison.Ordinal);

            return true;
        }

        return false;
    }

    /// <summary>
    /// Strips the SemVer build-metadata suffix ("+&lt;commit-sha&gt;") the release
    /// workflow appends to InformationalVersion, or falls back to
    /// <see cref="UnsubstitutedVersionPlaceholder"/> if the assembly carries no version
    /// metadata at all (should only happen for a build that skipped CI's -p:Version
    /// entirely, which the release workflow never does).
    /// </summary>
    internal static string ParseSemanticVersion(string? informationalVersion)
    {
        if (string.IsNullOrWhiteSpace(informationalVersion))
            return UnsubstitutedVersionPlaceholder;
        int plus = informationalVersion.IndexOf('+');
        string semantic = plus >= 0 ? informationalVersion[..plus] : informationalVersion;
        return string.IsNullOrWhiteSpace(semantic) ? UnsubstitutedVersionPlaceholder : semantic;
    }

    internal static string ResolveCurrentVersion() =>
        ParseSemanticVersion(typeof(BootstrapUpdater).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion);
}
