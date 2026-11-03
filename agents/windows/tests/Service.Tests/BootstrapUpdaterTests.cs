using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Patched.Shared.Security;
using Patched.Shared.Verification;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1248 coverage for the rebuilt self-update check: signed-envelope verification,
/// SHA-256 integrity, host allowlisting, and degraded-health reporting on every
/// bail-out path. Supersedes the never-working artifact-key HMAC design.
/// </summary>
public sealed class BootstrapUpdaterTests : IDisposable
{
    private const string DownloadUrl = "https://api.patched.im/v1/agent/artifact-download/x.msi";
    private const string OtherHostDownloadUrl = "https://evil.example.com/x.msi";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"patched-bootstrap-{Guid.NewGuid():N}");
    private readonly string _stateDir;
    private readonly string _suspendedFile;
    private readonly Ed25519PrivateKeyParameters _privateKey = new(new SecureRandom());
    private readonly ArtifactTrust _trust;

    public BootstrapUpdaterTests()
    {
        Directory.CreateDirectory(_dir);
        // PAT-1338: a scratch stand-in for %ProgramData%\Patched — the trusted anchor
        // BootstrapUpdater's EnsureHardenedChain call walks down from. It is a real
        // directory with a real protected DACL on Windows (see HardenAsStateRoot), so
        // the REAL hardening code runs in these tests rather than being switched off:
        // the seam is the ANCHOR, never an opt-out. updates\ therefore sits one level
        // below it, exactly as it does in production.
        _stateDir = Path.Combine(_dir, "state");
        Directory.CreateDirectory(_stateDir);
        HardenAsStateRoot(_stateDir);
        _suspendedFile = Path.Combine(_dir, "suspended");
        _trust = new ArtifactTrust("test-artifact-key", _privateKey.GeneratePublicKey().GetEncoded());
    }

    /// <summary>
    /// PAT-1338: gives a scratch directory the same trust shape production's
    /// %ProgramData%\Patched has — owner Administrators, protected DACL granting
    /// SYSTEM and Administrators only — so <see cref="SecureStagingDirectory.VerifyTrusted"/>
    /// accepts it. Same pattern SecureStagingDirectoryTests uses (SetOwner to
    /// BuiltinAdministratorsSid on a temp directory); without it, a %TEMP% path
    /// carries an inherited write-capable ACE for the running user and the real
    /// guard would — correctly — refuse it.
    ///
    /// No-op off Windows: the ACL APIs throw PlatformNotSupportedException there,
    /// which is also why BootstrapUpdater's own hardening call is Windows-gated.
    /// </summary>
    private static void HardenAsStateRoot(string dir)
    {
        if (!OperatingSystem.IsWindows()) return;

        var info = new DirectoryInfo(dir);
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (var sid in new[]
                 {
                     new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                 })
        {
            acl.AddAccessRule(new FileSystemAccessRule(
                sid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }
        info.SetAccessControl(acl);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private string PendingFile => Path.Combine(_dir, "pending-agent-update.json");
    private string UpdatesDir => Path.Combine(_stateDir, "updates");
    private AgentHealthStore NewHealth() => new(NullLogger<AgentHealthStore>.Instance, Path.Combine(_dir, "health.json"));

    /// <summary>PAT-1269: stages a fake installer under updates\&lt;version&gt;\
    /// patched-agent.msi, mirroring PendingUpdateApplierTests' helper of the same
    /// shape — used to simulate a version already staged by a PREVIOUS check before
    /// this test's own CheckAndStageAsync call runs.</summary>
    private string StageInstaller(string version, byte[] bytes)
    {
        string dir = Path.Combine(UpdatesDir, version);
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "patched-agent.msi");
        File.WriteAllBytes(path, bytes);
        return path;
    }

    /// <summary>PAT-1269: writes a pending-agent-update.json marker directly,
    /// mirroring PendingUpdateApplierTests' helper — used to simulate a marker left
    /// over from a PREVIOUS, not-yet-applied CheckAndStageAsync call.</summary>
    private void WriteMarker(string version, string installerPath, string sha256)
    {
        // PAT-2396: a marker the real updater wrote carries the signed envelope it
        // verified; the "already staged" check no longer accepts one without it.
        byte[] payload = MetadataPayload(version, artifactSha256: sha256);
        var marker = new
        {
            version,
            installer_path = installerPath,
            sha256,
            staged_at = DateTimeOffset.UtcNow,
            signed_payload = Convert.ToBase64String(payload),
            signature = Convert.ToBase64String(SignedMarkerFixture.Sign(payload, _privateKey)),
            key_id = _trust.KeyId,
        };
        File.WriteAllText(PendingFile, JsonSerializer.Serialize(marker));
    }

    private static byte[] ArtifactBytes(string content = "fake msi contents") => Encoding.UTF8.GetBytes(content);
    private static string Sha256Hex(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static byte[] MetadataPayload(
        string version, string platform = "windows", string channel = "stable",
        string? artifactUrl = null, string? artifactSha256 = null) =>
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            version,
            platform,
            channel,
            artifact_url = artifactUrl ?? DownloadUrl,
            artifact_sha256 = artifactSha256 ?? Sha256Hex(ArtifactBytes()),
        }));

    /// <summary>
    /// Builds a realistic /v1/agent/artifact response: the legacy fields PAT-1252
    /// deliberately kept, with the signed envelope NESTED under
    /// artifact_metadata_signature. Nesting is the whole point (PAT-1258) — these
    /// fixtures previously returned a bare envelope, which is why the client
    /// reading the root went unnoticed until a real endpoint hit it.
    /// </summary>
    private string Envelope(byte[] payload, string? keyId = null, bool corruptSignature = false)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, _privateKey);
        signer.BlockUpdate(payload, 0, payload.Length);
        return JsonSerializer.Serialize(new
        {
            version = "9.9.9",
            artifact_url = DownloadUrl,
            artifact_sha256 = "not-checked-here",
            artifact_hmac = "legacy-field-retained-by-pat-1252",
            published_at = "2026-08-11T00:00:00Z",
            artifact_metadata_signature = new
            {
                signed_payload = Convert.ToBase64String(payload),
                signature = Convert.ToBase64String(corruptSignature ? new byte[64] : signer.GenerateSignature()),
                key_id = keyId ?? _trust.KeyId,
            },
        });
    }

    /// <summary>A response with the legacy fields but NO envelope: every release
    /// before 0.13.16, and any cut before the signing key existed.</summary>
    private static string ResponseWithoutEnvelope() => JsonSerializer.Serialize(new
    {
        version = "9.9.9",
        artifact_url = DownloadUrl,
        artifact_sha256 = "not-checked-here",
        artifact_hmac = "legacy-field-retained-by-pat-1252",
        published_at = "2026-08-11T00:00:00Z",
    });

    private BootstrapUpdater NewUpdater(
        HttpMessageHandler handler, AgentHealthStore health,
        ArtifactTrust? trust = null, AgentConfig? config = null, CredentialStore? creds = null,
        IPendingUpdateRestartScheduler? restartScheduler = null) =>
        NewUpdater(handler, health, out _, trust, config, creds, restartScheduler);

    /// <summary>
    /// PAT-1260: overload that hands back the <see cref="Factory"/> test double
    /// so a test can inspect <see cref="Factory.RequestedClientNames"/> - which
    /// named HttpClient(s) BootstrapUpdater actually asked IHttpClientFactory
    /// for, and in what order. Proves the artifact download is requested on a
    /// distinctly-named client ("patched-artifact") rather than reusing
    /// "patched" (whose 30s Timeout the download must not inherit).
    /// </summary>
    private BootstrapUpdater NewUpdater(
        HttpMessageHandler handler, AgentHealthStore health, out Factory factory,
        ArtifactTrust? trust = null, AgentConfig? config = null, CredentialStore? creds = null,
        IPendingUpdateRestartScheduler? restartScheduler = null)
    {
        factory = new Factory(handler);
        return new(NullLogger<BootstrapUpdater>.Instance,
            factory,
            creds ?? CredentialStore.CreateForTests(_suspendedFile),
            () => config ?? VerifiedStableConfig,
            health,
            trust ?? _trust,
            // PAT-1293: defaults to a scheduler that always succeeds, so every
            // pre-existing test in this file (none of which cares about the
            // restart-scheduling side effect) keeps behaving exactly as before.
            // Tests that DO care about scheduling pass a FakeRestartScheduler
            // explicitly — see the PAT-1293 section below.
            restartScheduler ?? new FakeRestartScheduler(succeeds: true),
            pendingUpdateFileOverride: PendingFile,
            updatesDirOverride: UpdatesDir,
            // PAT-1338: anchors the REAL EnsureHardenedChain call at this fixture's
            // hardened scratch state root instead of %ProgramData%\Patched. Passed
            // explicitly rather than relying on the constructor's parent-of-updatesDir
            // derivation so the intent is visible at the call site.
            hardeningRootOverride: _stateDir);
    }

    private static bool IsDegraded(AgentHealthStore health, string reason) =>
        health.BuildPayloadSection()!.Degraded.Any(e =>
            e.Kind == "self_update" && e.Subject == "artifact" && e.Reason == reason);

    private static bool HasAnyDegraded(AgentHealthStore health) =>
        health.BuildPayloadSection()!.Degraded.Any(e => e.Kind == "self_update" && e.Subject == "artifact");

    private static AgentConfig VerifiedStableConfig => new()
    {
        TenantId = "test-tenant", ConfigVersion = 153, UpdateChannel = "stable", UpdateAuthorityVerified = true
    };

    /// <summary>PAT-1269: the distinct "self_update"/"deferred" (kind, subject) pair
    /// — separate from "self_update"/"artifact" above on purpose, see
    /// BootstrapUpdater.DeferredHealthSubject's doc comment.</summary>
    private static bool IsDeferredDegraded(AgentHealthStore health, string reason) =>
        health.BuildPayloadSection()!.Degraded.Any(e =>
            e.Kind == "self_update" && e.Subject == "deferred" && e.Reason == reason);

    private static bool HasAnyDeferredDegraded(AgentHealthStore health) =>
        health.BuildPayloadSection()!.Degraded.Any(e => e.Kind == "self_update" && e.Subject == "deferred");

    // -------------------------------------------------------------------------
    // Acceptance criterion 2: a correctly signed envelope + matching SHA-256
    // stages the update.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task CheckAndStageAsync_VerifiedEnvelopeAndMatchingSha256_StagesUpdateAndReportsHealthy()
    {
        var artifact = ArtifactBytes();
        var payload = MetadataPayload("9.9.9", artifactSha256: Sha256Hex(artifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), artifact));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.True(staged);
        Assert.True(File.Exists(PendingFile));
        var marker = JsonDocument.Parse(File.ReadAllText(PendingFile)).RootElement;
        Assert.Equal("9.9.9", marker.GetProperty("version").GetString());
        var stagedFile = marker.GetProperty("installer_path").GetString()!;
        Assert.True(File.Exists(stagedFile));
        Assert.Equal(artifact, File.ReadAllBytes(stagedFile));
        // PAT-1261: the marker now carries the VERIFIED sha256 (from the signed
        // envelope) so PendingUpdateApplier has something to re-verify the staged
        // file against before ever executing it.
        Assert.Equal(Sha256Hex(artifact), marker.GetProperty("sha256").GetString());
        Assert.False(HasAnyDegraded(health));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StartupBeforeVerifiedConfig_DoesNotRequestOrStageDefaultStable(bool legacyBetaCache)
    {
        // PAT-2351: the manager and worker start independently. Before the first
        // verified response, a missing cache or a legacy beta cache without its
        // envelope must not turn the reporting default into update authority.
        string configFile = Path.Combine(_dir, "agent-config.json");
        var credentials = CredentialStore.CreateForTests(_suspendedFile);
        if (legacyBetaCache)
        {
            File.WriteAllBytes(configFile, JsonSerializer.SerializeToUtf8Bytes(new
            {
                tenant_id = credentials.TenantId,
                config_version = 153,
                update_channel = "beta"
            }));
        }
        var configHandler = new RoutingHandler(_ => throw new InvalidOperationException(
            "The concurrent config fetch has not completed in this startup interleaving."));
        var fetcher = new AgentConfigFetcher(NullLogger<AgentConfigFetcher>.Instance,
            new Factory(configHandler), credentials, configFile, Path.Combine(_dir, "agent-config.version"));
        using var manager = new AgentConfigManager(NullLogger<AgentConfigManager>.Instance, fetcher);
        Assert.False(manager.Current.UpdateAuthorityVerified);
        Assert.Equal(legacyBetaCache ? "beta" : null, manager.Current.UpdateChannel);

        // Serve a genuinely signed stable artifact so the test observes staging,
        // not a coincidental refusal caused by missing network or invalid trust.
        var artifact = ArtifactBytes();
        var handler = new RoutingHandler(req => Route(req,
            Envelope(MetadataPayload("0.14.5", artifactSha256: Sha256Hex(artifact))), artifact));
        var scheduler = new FakeRestartScheduler(succeeds: true);
        var updater = new BootstrapUpdater(NullLogger<BootstrapUpdater>.Instance,
            new Factory(handler), credentials, () => manager.Current, NewHealth(), _trust, scheduler,
            pendingUpdateFileOverride: PendingFile, updatesDirOverride: UpdatesDir,
            hardeningRootOverride: _stateDir);

        bool staged = await updater.CheckAndStageAsync(CancellationToken.None);

        Assert.True(handler.Requests.Count == 0 && !staged && !File.Exists(PendingFile) &&
                    !Directory.Exists(UpdatesDir) && scheduler.CallCount == 0,
            $"Unverified startup policy acted: requests=[{string.Join(", ", handler.Requests.Select(r => r.RequestUri))}], " +
            $"staged={staged}, marker={File.Exists(PendingFile)}, updatesDirectory={Directory.Exists(UpdatesDir)}, " +
            $"scheduledRestarts={scheduler.CallCount}.");
    }

    [Fact]
    public async Task StartupWithVerifiedCachedBetaPolicy_StagesBetaWithoutConfigFetch()
    {
        var config = RestoreVerifiedBetaCache();
        var artifact = ArtifactBytes();
        var handler = new RoutingHandler(req => Route(req,
            Envelope(MetadataPayload("0.15.1.3", channel: "beta")), artifact));
        var scheduler = new FakeRestartScheduler(succeeds: true);

        Assert.True(await NewUpdater(handler, NewHealth(), config: config, restartScheduler: scheduler)
            .CheckAndStageAsync(CancellationToken.None));

        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains("channel=beta", handler.Requests[0].RequestUri!.Query);
        Assert.Equal("0.15.1.3", JsonDocument.Parse(File.ReadAllText(PendingFile)).RootElement.GetProperty("version").GetString());
        Assert.Equal(1, scheduler.CallCount);
    }

    [Fact]
    public async Task UnverifiedStartup_RecoversOnNormalHourlyCheckAfterVerifiedBetaArrives()
    {
        AgentConfig current = AgentConfig.Defaults;
        var artifact = ArtifactBytes();
        var handler = new RoutingHandler(req => Route(req,
            Envelope(MetadataPayload("0.15.1.3", channel: "beta")), artifact));
        var health = NewHealth();
        var scheduler = new FakeRestartScheduler(succeeds: true);
        var updater = new BootstrapUpdater(NullLogger<BootstrapUpdater>.Instance,
            new Factory(handler), CredentialStore.CreateForTests(_suspendedFile), () => current, health, _trust, scheduler,
            pendingUpdateFileOverride: PendingFile, updatesDirOverride: UpdatesDir, hardeningRootOverride: _stateDir);
        var start = DateTimeOffset.UtcNow;
        var interval = TimeSpan.FromHours(1);
        var nextCheck = await PatchedWorker.RunPeriodicBootstrapUpdateCheckAsync(
            updater, start, start, interval, NullLogger<PatchedWorker>.Instance, CancellationToken.None);
        Assert.True(IsDegraded(health, "update_policy_unverified"));
        Assert.Empty(handler.Requests);
        Assert.False(File.Exists(PendingFile));
        Assert.Equal(0, scheduler.CallCount);
        Assert.Equal(start.Add(interval), nextCheck);

        current = RestoreVerifiedBetaCache();
        nextCheck = await PatchedWorker.RunPeriodicBootstrapUpdateCheckAsync(
            updater, start.AddSeconds(15), nextCheck, interval, NullLogger<PatchedWorker>.Instance, CancellationToken.None);
        Assert.Empty(handler.Requests);
        Assert.Equal(0, scheduler.CallCount);

        nextCheck = await PatchedWorker.RunPeriodicBootstrapUpdateCheckAsync(
            updater, start.Add(interval), nextCheck, interval, NullLogger<PatchedWorker>.Instance, CancellationToken.None);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains("channel=beta", handler.Requests[0].RequestUri!.Query);
        Assert.True(File.Exists(PendingFile));
        Assert.False(HasAnyDegraded(health));
        Assert.Equal(1, scheduler.CallCount);
        Assert.Equal(start.AddHours(2), nextCheck);
    }

    private AgentConfig RestoreVerifiedBetaCache()
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new
            { tenant_id = "test-tenant", config_version = 153, update_channel = "beta" });
        // Use the cache's existing verifier seam with a real test-key signature.
        // Production's fetcher supplies its pinned-key verifier to the same Match.
        using var response = JsonDocument.Parse(Envelope(payload));
        byte[] envelope = JsonSerializer.SerializeToUtf8Bytes(response.RootElement.GetProperty("artifact_metadata_signature"));
        string cache = Path.Combine(_stateDir, "agent-config.json");
        File.WriteAllBytes(cache, payload);
        File.WriteAllBytes(cache + ".envelope", envelope);
        return Assert.IsType<AgentConfig>(VerifiedUpdateConfigCache.Match(
            File.ReadAllBytes(cache + ".envelope"), File.ReadAllBytes(cache), "test-tenant",
            AgentConfigRollbackFloor.StoredFloor.Keyed("test-tenant", 153), proof =>
            {
                using var document = JsonDocument.Parse(proof);
                var root = document.RootElement;
                byte[] signed = Convert.FromBase64String(root.GetProperty("signed_payload").GetString()!);
                return root.GetProperty("key_id").GetString() == _trust.KeyId &&
                    Ed25519Verifier.Verify(_privateKey.GeneratePublicKey().GetEncoded(), signed,
                        Convert.FromBase64String(root.GetProperty("signature").GetString()!)) ? signed : null;
            }));
    }

    [Theory]
    [InlineData("stable")]
    [InlineData("beta")]
    public async Task VerifiedVersionPin_PreservesExplicitArtifactSelection(string channel)
    {
        var config = VerifiedStableConfig with { UpdateChannel = channel, PinnedVersion = "0.14.5" };
        var handler = new RoutingHandler(req => Route(req,
            Envelope(MetadataPayload("0.14.5", channel: channel)), ArtifactBytes()));

        Assert.True(await NewUpdater(handler, NewHealth(), config: config).CheckAndStageAsync(CancellationToken.None));

        Assert.Contains("channel=" + channel, handler.Requests[0].RequestUri!.Query);
        Assert.Contains("version=0.14.5", handler.Requests[0].RequestUri!.Query);
        Assert.Equal("0.14.5", JsonDocument.Parse(File.ReadAllText(PendingFile)).RootElement.GetProperty("version").GetString());
    }

    [Theory]
    [InlineData("foreign_tenant")]
    [InlineData("foreign_device")]
    [InlineData("duplicate_channel")]
    public async Task RejectedVerifiedPolicy_DoesNotRequestOrStageFallbackStable(string rejection)
    {
        var config = rejection switch
        {
            "foreign_tenant" => VerifiedStableConfig with { TenantId = "other-tenant" },
            "foreign_device" => VerifiedStableConfig with { DeviceId = "00000000-0000-0000-0000-000000002006" },
            _ => AgentConfig.Deserialize("{\"tenant_id\":\"test-tenant\",\"config_version\":153,\"update_channel\":\"stable\",\"update_channel\":\"beta\"}")!
                with { UpdateAuthorityVerified = true }
        };
        var handler = new RoutingHandler(req => Route(req, Envelope(MetadataPayload("0.14.5")), ArtifactBytes()));
        var health = NewHealth();
        var scheduler = new FakeRestartScheduler(succeeds: true);

        Assert.False(await NewUpdater(handler, health, config: config, restartScheduler: scheduler)
            .CheckAndStageAsync(CancellationToken.None));

        Assert.Empty(handler.Requests);
        Assert.False(File.Exists(PendingFile));
        Assert.Equal(0, scheduler.CallCount);
        Assert.True(IsDegraded(health, "update_policy_unverified"));
    }

    [Theory]
    [InlineData(true, true, "beta", "device_override")]
    [InlineData(true, false, "stable", "tenant")]
    [InlineData(false, true, "stable", null)]
    public async Task ActualArtifactRequestUsesOnlyVerifiedOwnOverride(bool verified, bool own, string expected, string? source)
    {
        const string id = "00000000-0000-0000-0000-000000002005";
        const string other = "00000000-0000-0000-0000-000000002006";
        var credentials = CredentialStore.CreateForTests(_suspendedFile);
        credentials.UpdateFromEnrolment("tenant", "test-bearer", credentials.HmacSecret, id);
        var config = AgentConfig.Deserialize(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
        {
            tenant_id = "tenant",
            config_version = 4,
            update_channel = "stable",
            pinned_version = "1.2.3",
            device_channel_overrides = new Dictionary<string, string> { [own ? id : other] = "beta" }
        }))! with
        { UpdateAuthorityVerified = verified };
        var handler = new RoutingHandler(_ => new HttpResponseMessage(System.Net.HttpStatusCode.NotFound));
        var health = NewHealth();
        await NewUpdater(handler, health, config: config, creds: credentials).CheckAndStageAsync(CancellationToken.None);
        if (!verified)
        {
            Assert.Empty(handler.Requests);
            Assert.True(IsDegraded(health, "update_policy_unverified"));
            return;
        }
        var request = Assert.Single(handler.Requests);
        Assert.Contains("channel=" + expected, request.RequestUri!.Query);
        Assert.Equal(verified, request.RequestUri.Query.Contains("version=1.2.3"));
        var report = health.BuildPayloadSection("tenant", id)!.UpdateChannel;
        Assert.Equal(expected, report!.EffectiveChannel); Assert.Equal(source, report.Source);
    }

    // -------------------------------------------------------------------------
    // PAT-1293: a successfully staged marker must also schedule the one-shot
    // restart task so PendingUpdateApplier ever gets a chance to consume it —
    // that call site, and the fail-safe/degraded-visible handling of its
    // result, is exactly what closes PAT-1261/PAT-1269's "correct code, never
    // invoked" shape.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task CheckAndStageAsync_SuccessfulStage_SchedulesRestartTask()
    {
        var artifact = ArtifactBytes();
        var payload = MetadataPayload("9.9.9", artifactSha256: Sha256Hex(artifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), artifact));
        var health = NewHealth();
        var scheduler = new FakeRestartScheduler(succeeds: true);

        var staged = await NewUpdater(handler, health, restartScheduler: scheduler)
            .CheckAndStageAsync(CancellationToken.None);

        Assert.True(staged);
        Assert.Equal(1, scheduler.CallCount);
    }

    [Fact]
    public async Task CheckAndStageAsync_SuccessfulStage_RestartScheduledOk_ReportsHealthyOnDistinctSubject()
    {
        var artifact = ArtifactBytes();
        var payload = MetadataPayload("9.9.9", artifactSha256: Sha256Hex(artifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), artifact));
        var health = NewHealth();

        await NewUpdater(handler, health, restartScheduler: new FakeRestartScheduler(succeeds: true))
            .CheckAndStageAsync(CancellationToken.None);

        Assert.False(health.BuildPayloadSection()!.Degraded.Any(
            e => e.Kind == "self_update" && e.Subject == "restart_schedule"));
    }

    /// <summary>
    /// The core of the ticket: a registration failure must be fail-safe (never
    /// throws, the marker stays staged, CheckAndStageAsync still reports the
    /// staging outcome as successful) AND visibly degraded — never a silent
    /// no-op. Distinct (kind, subject) from the artifact-check's own
    /// RecordSuccess moments earlier in the same call, so this failure cannot be
    /// clobbered by (or itself clobber) that unrelated signal.
    /// </summary>
    [Fact]
    public async Task CheckAndStageAsync_SuccessfulStage_RestartSchedulingFails_IsFailSafeAndVisiblyDegraded()
    {
        var artifact = ArtifactBytes();
        var payload = MetadataPayload("9.9.9", artifactSha256: Sha256Hex(artifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), artifact));
        var health = NewHealth();
        var scheduler = new FakeRestartScheduler(succeeds: false);

        var staged = await NewUpdater(handler, health, restartScheduler: scheduler)
            .CheckAndStageAsync(CancellationToken.None);

        // Fail-safe: the marker itself was staged successfully and staging still
        // reports true — a restart-scheduling failure must never be conflated
        // with a staging failure, or retried by re-downloading a perfectly good
        // artifact.
        Assert.True(staged);
        Assert.True(File.Exists(PendingFile));
        Assert.Equal(1, scheduler.CallCount);

        // Visibly degraded: NOT silent. Distinct subject from "artifact" (which
        // is healthy — the check itself succeeded) so this fault is separately
        // greppable and cannot be papered over by the artifact check's own
        // RecordSuccess a moment earlier in the same call.
        Assert.True(health.BuildPayloadSection()!.Degraded.Any(
            e => e.Kind == "self_update" && e.Subject == "restart_schedule" &&
                 e.Reason == "restart_task_registration_failed"));
        Assert.False(HasAnyDegraded(health)); // "artifact" subject is still healthy
    }

    // -------------------------------------------------------------------------
    // PAT-1260: the artifact download itself is now authenticated (the API
    // requires Bearer + HMAC, unlike the anonymous GitHub Releases URL it
    // replaces), signed over its OWN endpoint ID so a captured signature for
    // one endpoint cannot be replayed against the other, and with a FRESH
    // timestamp/nonce distinct from the envelope fetch's.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task CheckAndStageAsync_DownloadRequest_CarriesFreshBearerAndHmacHeaders()
    {
        var artifact = ArtifactBytes();
        var payload = MetadataPayload("9.9.9", artifactSha256: Sha256Hex(artifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), artifact));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.True(staged);
        var downloadPath = new Uri(DownloadUrl).AbsolutePath;
        var downloadReq = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == downloadPath);
        var envelopeReq = handler.Requests.Single(r => r.RequestUri!.AbsolutePath != downloadPath);

        Assert.Equal("Bearer", downloadReq.Headers.Authorization?.Scheme);
        Assert.Equal("test-bearer", downloadReq.Headers.Authorization?.Parameter);
        Assert.True(downloadReq.Headers.Contains(HmacSigner.SignatureHeader));
        Assert.True(downloadReq.Headers.Contains("X-Patched-Timestamp"));
        Assert.True(downloadReq.Headers.Contains("X-Patched-Nonce"));

        string sig   = downloadReq.Headers.GetValues(HmacSigner.SignatureHeader).Single();
        string ts    = downloadReq.Headers.GetValues("X-Patched-Timestamp").Single();
        string nonce = downloadReq.Headers.GetValues("X-Patched-Nonce").Single();
        const string hmacSecret = "dGVzdC1obWFjLXNlY3JldC0zMi1ieXRlcy1sb25nIQ==";

        // Endpoint-bound: verifies against the download endpoint ID but NOT the
        // envelope-fetch one — proves this is a fresh signature for this
        // request, not a resend of the envelope fetch's.
        Assert.True(HmacSigner.VerifySignature(
            hmacSecret, "GET", HmacSigner.EndpointAgentArtifactDownload, ts, nonce, ReadOnlySpan<byte>.Empty, sig));
        Assert.False(HmacSigner.VerifySignature(
            hmacSecret, "GET", HmacSigner.EndpointAgentArtifact, ts, nonce, ReadOnlySpan<byte>.Empty, sig));

        // Fresh nonce: not a replay of the envelope fetch's already-spent nonce.
        string envNonce = envelopeReq.Headers.GetValues("X-Patched-Nonce").Single();
        Assert.NotEqual(envNonce, nonce);
    }

    [Fact]
    public async Task CheckAndStageAsync_DownloadReturns401_DoesNotStage_ReportsDistinctDegradedReason()
    {
        var payload = MetadataPayload("9.9.9");
        var downloadPath = new Uri(DownloadUrl).AbsolutePath;
        var handler = new RoutingHandler(req =>
            req.RequestUri!.AbsolutePath == downloadPath
                ? new HttpResponseMessage(HttpStatusCode.Unauthorized)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Envelope(payload)) });
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.False(File.Exists(PendingFile));
        // Distinct, greppable reason — not the generic "unexpected_exception"
        // an unhandled HttpRequestException would have produced.
        Assert.True(IsDegraded(health, "artifact_download_returned_401"));
    }

    // -------------------------------------------------------------------------
    // PAT-1260 non-author-review finding: the artifact download must NOT run
    // on the "patched" client, whose 30s Timeout bounds the whole download
    // (including the body, even under ResponseHeadersRead) and would fail on
    // any ordinary connection for a ~160 MB file. This proves the code path is
    // actually split onto a distinctly-named client ("patched-artifact") -
    // see PatchedHttpClientTimeoutsTests for proof that client's registered
    // Timeout is genuinely different (and still bounded), and the workflow/
    // Program.cs wiring check for proof the two are actually connected.
    // Asserting the real multi-minute timeout end-to-end would mean either
    // waiting it out or reimplementing HttpClient's internal timeout
    // enforcement in the test - not attempted here.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task CheckAndStageAsync_ArtifactDownload_UsesDistinctlyNamedClient_NotThePatchedClient()
    {
        var artifact = ArtifactBytes();
        var payload = MetadataPayload("9.9.9", artifactSha256: Sha256Hex(artifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), artifact));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health, out var factory).CheckAndStageAsync(CancellationToken.None);

        Assert.True(staged);
        Assert.Contains("patched", factory.RequestedClientNames);
        Assert.Contains("patched-artifact", factory.RequestedClientNames);
        // Two distinct names, not one client name requested twice.
        Assert.Equal(2, factory.RequestedClientNames.Distinct().Count());
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 1: tampered artifact / wrong-key signature / SHA
    // mismatch / missing envelope each refuse to stage. Tested individually below.
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CheckAndStageAsync_TamperedArtifactBytes_ShaMismatch_DoesNotStage_ReportsDegraded()
    {
        var declaredArtifact = ArtifactBytes("declared contents");
        var servedArtifact = ArtifactBytes("attacker swapped these bytes in transit");
        var payload = MetadataPayload("9.9.9", artifactSha256: Sha256Hex(declaredArtifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), servedArtifact));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.False(File.Exists(PendingFile));
        Assert.True(IsDegraded(health, "artifact_sha256_mismatch"));
    }

    [Fact]
    public async Task CheckAndStageAsync_SignatureFromWrongKey_DoesNotStage_ReportsDegraded()
    {
        var otherKey = new Ed25519PrivateKeyParameters(new SecureRandom());
        var payload = MetadataPayload("9.9.9");
        var signer = new Ed25519Signer();
        signer.Init(true, otherKey);
        signer.BlockUpdate(payload, 0, payload.Length);
        // Nested under artifact_metadata_signature like the real response
        // (PAT-1252 additive shape, PAT-1258).
        var envelope = JsonSerializer.Serialize(new
        {
            version = "9.9.9",
            artifact_url = DownloadUrl,
            artifact_metadata_signature = new
            {
                signed_payload = Convert.ToBase64String(payload),
                signature = Convert.ToBase64String(signer.GenerateSignature()),
                key_id = _trust.KeyId, // claims the pinned key id, but signed by a different key
            },
        });
        var handler = new RoutingHandler(req => Route(req, envelope, ArtifactBytes()));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.False(File.Exists(PendingFile));
        Assert.True(IsDegraded(health, "artifact_signature_invalid"));
    }

    [Fact]
    public async Task CheckAndStageAsync_CorruptedSignature_DoesNotStage_ReportsDegraded()
    {
        var payload = MetadataPayload("9.9.9");
        var handler = new RoutingHandler(req => Route(req, Envelope(payload, corruptSignature: true), ArtifactBytes()));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.True(IsDegraded(health, "artifact_signature_invalid"));
    }

    [Fact]
    public async Task CheckAndStageAsync_KeyIdDoesNotMatchPin_DoesNotStage_ReportsDegraded()
    {
        var payload = MetadataPayload("9.9.9");
        var handler = new RoutingHandler(req => Route(req, Envelope(payload, keyId: "ecd47f2c5b3d5705"), ArtifactBytes()));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.True(IsDegraded(health, "artifact_key_id_mismatch"));
    }

    [Theory]
    [InlineData("{not-json")]
    [InlineData("{}")]
    [InlineData("""{"signed_payload":"","signature":""}""")] // missing key_id
    public async Task CheckAndStageAsync_MissingOrMalformedEnvelope_DoesNotStage_ReportsDegraded(string body)
    {
        var handler = new RoutingHandler(req => Route(req, body, ArtifactBytes()));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.False(File.Exists(PendingFile));
        Assert.True(HasAnyDegraded(health));
    }

    // -------------------------------------------------------------------------
    // Additional bail-out paths PAT-1248 requires to surface degraded health.
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CheckAndStageAsync_ArtifactEndpointNon2xx_DoesNotStage_ReportsDegraded()
    {
        var handler = new RoutingHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.True(IsDegraded(health, "artifact_endpoint_returned_503"));
    }

    [Fact]
    public async Task CheckAndStageAsync_UnprovisionedProductionTrust_DoesNotStage_ReportsDegraded_NeverCallsNetwork()
    {
        var handler = new RoutingHandler(_ => throw new InvalidOperationException(
            "must not make any network call while the production key is unprovisioned"));
        var health = NewHealth();

        // PAT-1255: build an explicitly unprovisioned anchor rather than leaning
        // on ArtifactTrust.Production still holding placeholders. It no longer
        // does, and a test written against the singleton silently stopped
        // covering anything the moment the real key was provisioned.
        var unprovisioned = new ArtifactTrust(
            ArtifactTrust.UnprovisionedPlaceholderKeyId,
            Convert.FromBase64String(ArtifactTrust.UnprovisionedPlaceholderPublicKeyBase64));

        var staged = await NewUpdater(handler, health, trust: unprovisioned)
            .CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.True(IsDegraded(health, "artifact_trust_not_provisioned"));
    }

    [Theory]
    // PAT-1259: releases live on GitHub Releases, so the signed artifact_url
    // legitimately points there. github.com is scoped to the Patched-LTD path;
    // objects.githubusercontent.com is where github.com 302s to and serves
    // opaque signed blob paths with no org segment, so it is allowed on host
    // alone and constrained by the signed artifact_sha256 instead.
    [InlineData("https://github.com/Patched-LTD/updater/releases/download/windows-agent-v0.13.17/PatchedAgent-0.13.17.msi", true)]
    [InlineData("https://objects.githubusercontent.com/github-production-release-asset/12345/abcdef", true)]
    [InlineData("https://api.patched.im/v1/agent/artifact-download/x.msi", true)]
    // Another org's releases must not be reachable just because github.com is.
    [InlineData("https://github.com/evil-org/updater/releases/download/v1/x.msi", false)]
    [InlineData("https://github.com/Patched-LTD-evil/updater/releases/download/v1/x.msi", false)]
    // Neither must an unrelated host, nor plain HTTP anywhere.
    [InlineData("https://evil.example.com/x.msi", false)]
    [InlineData("http://github.com/Patched-LTD/updater/releases/download/v1/x.msi", false)]
    [InlineData("https://github.com.evil.example.com/Patched-LTD/x.msi", false)]
    public async Task CheckAndStageAsync_ArtifactUrlHostAllowlist(string artifactUrl, bool allowed)
    {
        var payload = MetadataPayload("9.9.9", artifactUrl: artifactUrl);
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), ArtifactBytes(), artifactUrl));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        if (allowed)
        {
            Assert.False(IsDegraded(health, "artifact_url_not_allowed"));
        }
        else
        {
            Assert.False(staged);
            Assert.True(IsDegraded(health, "artifact_url_not_allowed"));
        }
    }

    [Fact]
    public async Task CheckAndStageAsync_ResponseWithoutEnvelope_DoesNotStage_ReportsDegraded()
    {
        // PAT-1258: the regression test for the bug that shipped. The server keeps
        // serving the legacy fields (PAT-1252 kept the endpoint additive), so a
        // response with no envelope is well-formed JSON full of plausible values.
        // It must fail closed rather than fall back to the unverified legacy
        // artifact_url/artifact_hmac, which is exactly the trust boundary
        // PAT-1248 moved away from.
        var handler = new RoutingHandler(req => Route(req, ResponseWithoutEnvelope(), ArtifactBytes()));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.False(File.Exists(PendingFile));
        Assert.True(IsDegraded(health, "artifact_envelope_absent"));
    }

    [Fact]
    public async Task CheckAndStageAsync_ArtifactUrlOnDisallowedHost_DoesNotStage_ReportsDegraded()
    {
        var payload = MetadataPayload("9.9.9", artifactUrl: OtherHostDownloadUrl);
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), ArtifactBytes(), OtherHostDownloadUrl));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.False(File.Exists(PendingFile));
        Assert.True(IsDegraded(health, "artifact_url_not_allowed"));
    }

    [Fact]
    public async Task CheckAndStageAsync_PlatformMismatch_DoesNotStage_ReportsDegraded()
    {
        var payload = MetadataPayload("9.9.9", platform: "macos");
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), ArtifactBytes()));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.True(IsDegraded(health, "artifact_metadata_platform_mismatch"));
    }

    [Fact]
    public async Task CheckAndStageAsync_ChannelMismatch_DoesNotStage_ReportsDegraded()
    {
        var payload = MetadataPayload("9.9.9", channel: "beta");
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), ArtifactBytes()));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health, config: VerifiedStableConfig)
            .CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.True(IsDegraded(health, "artifact_metadata_channel_mismatch"));
    }

    [Fact]
    public async Task CheckAndStageAsync_MalformedSha256InPayload_DoesNotStage_ReportsDegraded()
    {
        var payload = MetadataPayload("9.9.9", artifactSha256: "not-a-real-sha");
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), ArtifactBytes()));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.True(IsDegraded(health, "artifact_metadata_malformed_sha256"));
    }

    // -------------------------------------------------------------------------
    // Already-current version: verification succeeds (healthy), nothing to stage.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task CheckAndStageAsync_AlreadyCurrentVersion_NoStagingButHealthy()
    {
        // In a `dotnet test` run CurrentVersion resolves via the assembly's
        // InformationalVersion attribute, which is NOT the literal placeholder — so to
        // exercise "already current" deterministically, compare against whatever this
        // test binary actually resolves to, rather than assuming a fixed value.
        var currentVersion = BootstrapUpdater.ResolveCurrentVersion();
        var samePayload = MetadataPayload(currentVersion);
        var handler = new RoutingHandler(req => Route(req, Envelope(samePayload), ArtifactBytes()));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.False(File.Exists(PendingFile));
        Assert.False(HasAnyDegraded(health)); // fully verified — just nothing to do
    }

    // -------------------------------------------------------------------------
    // PAT-1269: same-version already-staged short-circuit — no re-download. This
    // path existed before PAT-1269 (BootstrapUpdater has always been re-runnable)
    // but was never exercised by a test until the check itself became periodic.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task CheckAndStageAsync_SameVersionAlreadyStaged_ShortCircuits_NoRedownload()
    {
        var artifact = ArtifactBytes();
        string sha = Sha256Hex(artifact);
        StageInstaller("9.9.9", artifact);
        WriteMarker("9.9.9", Path.Combine(UpdatesDir, "9.9.9", "patched-agent.msi"), sha);

        var payload = MetadataPayload("9.9.9", artifactSha256: sha);
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), artifact));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.True(staged);
        var downloadPath = new Uri(DownloadUrl).AbsolutePath;
        Assert.DoesNotContain(handler.Requests, r => r.RequestUri!.AbsolutePath == downloadPath);
        Assert.False(HasAnyDegraded(health));
    }

    // -------------------------------------------------------------------------
    // PAT-1269 acceptance criterion: a periodic check cannot stage over an
    // already-staged pending update — including when the server now reports a
    // NEWER version than the one already pending apply (only possible now that
    // this check can genuinely run again before PendingUpdateApplier has consumed
    // a previous marker on a restart).
    // -------------------------------------------------------------------------
    [Fact]
    public async Task CheckAndStageAsync_DifferentVersionAlreadyPending_Defers_DoesNotDownloadOrOverwriteMarker()
    {
        var pendingArtifact = ArtifactBytes("pending 0.13.23 contents");
        string pendingSha = Sha256Hex(pendingArtifact);
        string pendingPath = StageInstaller("0.13.23", pendingArtifact);
        WriteMarker("0.13.23", pendingPath, pendingSha);

        // Server now reports a NEWER release, 0.13.24, while 0.13.23 still sits
        // unconsumed (PendingUpdateApplier only runs at the next restart).
        var newerArtifact = ArtifactBytes("newer 0.13.24 contents");
        var payload = MetadataPayload("0.13.24", artifactSha256: Sha256Hex(newerArtifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), newerArtifact));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        // Reports "there is something pending" (true) without touching the newer
        // download or the existing marker/staged file.
        Assert.True(staged);
        var downloadPath = new Uri(DownloadUrl).AbsolutePath;
        Assert.DoesNotContain(handler.Requests, r => r.RequestUri!.AbsolutePath == downloadPath);
        Assert.False(Directory.Exists(Path.Combine(UpdatesDir, "0.13.24")));

        var marker = JsonDocument.Parse(File.ReadAllText(PendingFile)).RootElement;
        Assert.Equal("0.13.23", marker.GetProperty("version").GetString());
        Assert.Equal(pendingSha, marker.GetProperty("sha256").GetString());
        Assert.True(File.Exists(pendingPath));
        Assert.False(HasAnyDegraded(health)); // envelope still verified cleanly — healthy, just deferred

        // PAT-1269: the deferral itself must be VISIBLE, on the distinct
        // "self_update"/"deferred" pair, naming both the version that's stuck
        // pending and the version it's blocking — otherwise a permanently-stuck
        // marker (PendingUpdateApplier gives up after MaxAttempts) makes every
        // future release defer silently forever with nothing anywhere saying so.
        Assert.True(IsDeferredDegraded(health, "pending_version_0.13.23_blocks_stage_of_0.13.24"));
    }

    // -------------------------------------------------------------------------
    // PAT-1269: a deferral that resolves (the pending version finally applied, so
    // the marker is gone by the next check) must clear the degraded signal — a
    // one-off deferral is normal and must not look identical to a permanently
    // stuck one that never got the chance to clear.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task CheckAndStageAsync_DeferredThenMarkerClears_NextNormalCheckClearsDegradedSignal()
    {
        var pendingArtifact = ArtifactBytes("pending 0.13.23 contents");
        var pendingPath = StageInstaller("0.13.23", pendingArtifact);
        WriteMarker("0.13.23", pendingPath, Sha256Hex(pendingArtifact));

        var newerArtifact = ArtifactBytes("newer 0.13.24 contents");
        var deferPayload = MetadataPayload("0.13.24", artifactSha256: Sha256Hex(newerArtifact));
        var deferHandler = new RoutingHandler(req => Route(req, Envelope(deferPayload), newerArtifact));
        var health = NewHealth();

        await NewUpdater(deferHandler, health).CheckAndStageAsync(CancellationToken.None);
        Assert.True(HasAnyDeferredDegraded(health)); // stuck, as proven above

        // The pending 0.13.23 update applied on a restart (PendingUpdateApplier
        // cleared the marker and its staged directory) and this endpoint is now
        // running 0.13.24 itself, which happens to be exactly what the server is
        // still offering ("already at current version" branch).
        File.Delete(PendingFile);
        Directory.Delete(Path.Combine(UpdatesDir, "0.13.23"), recursive: true);
        var currentVersion = BootstrapUpdater.ResolveCurrentVersion();
        var caughtUpPayload = MetadataPayload(currentVersion);
        var caughtUpHandler = new RoutingHandler(req => Route(req, Envelope(caughtUpPayload), ArtifactBytes()));

        await NewUpdater(caughtUpHandler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(HasAnyDeferredDegraded(health));
    }

    // -------------------------------------------------------------------------
    // PAT-1269 review fix: IsPendingUpdateMarked (the same-version short-circuit)
    // and the deferral guard must use the SAME StringComparison, or a marker whose
    // case differs from the server's reported version gets judged "different" by
    // one check and "the same" by the other — either silently skipping a real
    // deferral (a false all-clear on a genuinely stuck marker) or, as here, the
    // more benign direction: consistently agreeing it IS different and deferring.
    // Both checks now use Ordinal, so a case-only difference is treated as a
    // different version by BOTH — proving they agree rather than disagree.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task CheckAndStageAsync_PendingMarkerDiffersOnlyByCase_BothChecksAgreeItIsADifferentVersion()
    {
        var pendingArtifact = ArtifactBytes("pending contents");
        string pendingPath = StageInstaller("0.13.24A", pendingArtifact);
        WriteMarker("0.13.24A", pendingPath, Sha256Hex(pendingArtifact));

        // Server reports the same digits/letters but different case — a contrived
        // input (real release versions are pure digits with no case to differ on),
        // used purely to prove the short-circuit and the deferral guard classify
        // this pair identically now that both compare Ordinal.
        var newerArtifact = ArtifactBytes("newer contents");
        var payload = MetadataPayload("0.13.24a", artifactSha256: Sha256Hex(newerArtifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), newerArtifact));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        // Not silently treated as "already staged" (the short-circuit's Ordinal
        // comparison correctly says these differ) — it defers instead, and the
        // deferral guard's ALSO-Ordinal comparison agrees they differ, so the
        // stuck-marker signal fires rather than being silently swallowed.
        Assert.True(staged);
        var downloadPath = new Uri(DownloadUrl).AbsolutePath;
        Assert.DoesNotContain(handler.Requests, r => r.RequestUri!.AbsolutePath == downloadPath);
        Assert.True(IsDeferredDegraded(health, "pending_version_0.13.24A_blocks_stage_of_0.13.24a"));
    }

    // -------------------------------------------------------------------------
    // PAT-1269: the pre-existing repair path must survive the new deferral guard —
    // PendingUpdateApplier deliberately RETAINS a marker whose staged file has gone
    // missing (installer_missing) so the NEXT check-and-stage cycle re-downloads it
    // (see PendingUpdateApplier's class doc comment). That must still work even
    // though the marker's version equals availableVersion here, which the new
    // deferral guard is deliberately scoped to NOT match.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task CheckAndStageAsync_MarkerPresentButStageFileMissing_SameVersion_StillRedownloads()
    {
        var artifact = ArtifactBytes();
        string sha = Sha256Hex(artifact);
        // Marker exists for 9.9.9, but nothing is actually staged on disk.
        WriteMarker("9.9.9", Path.Combine(UpdatesDir, "9.9.9", "patched-agent.msi"), sha);

        var payload = MetadataPayload("9.9.9", artifactSha256: sha);
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), artifact));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.True(staged);
        var downloadPath = new Uri(DownloadUrl).AbsolutePath;
        Assert.Contains(handler.Requests, r => r.RequestUri!.AbsolutePath == downloadPath);
        Assert.True(File.Exists(Path.Combine(UpdatesDir, "9.9.9", "patched-agent.msi")));
    }

    // -------------------------------------------------------------------------
    // PAT-1269 acceptance criterion: a transient failure (network unreachable) is
    // absorbed — never throws, leaves the service on its current version, reports
    // degraded rather than staging anything. Proves the periodic caller can safely
    // await this every tick without a try/catch of its own.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task CheckAndStageAsync_NetworkUnreachable_AbsorbsFailure_DoesNotThrow_ReportsDegraded()
    {
        var handler = new RoutingHandler(_ => throw new HttpRequestException("connection refused"));
        var health = NewHealth();

        bool staged = false;
        var ex = await Record.ExceptionAsync(async () =>
            staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None));

        Assert.Null(ex);
        Assert.False(staged);
        Assert.False(File.Exists(PendingFile));
        Assert.True(IsDegraded(health, "unexpected_exception"));
    }

    // -------------------------------------------------------------------------
    // PAT-1269: last-check visibility — every clean verification (staged or not)
    // stamps AgentHealthStore's last_success ledger, so "has this endpoint checked
    // in lately" is answerable from agent-health.json without inferring it from a
    // version number nobody watches.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task CheckAndStageAsync_SuccessfulCheck_StampsLastSuccessOnAgentHealth()
    {
        var currentVersion = BootstrapUpdater.ResolveCurrentVersion();
        var payload = MetadataPayload(currentVersion);
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), ArtifactBytes()));
        var health = NewHealth();
        var before = DateTimeOffset.UtcNow;

        await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        var lastSuccess = health.GetLastSuccess("self_update", "artifact");
        Assert.NotNull(lastSuccess);
        Assert.InRange(lastSuccess!.Value, before.AddSeconds(-5), DateTimeOffset.UtcNow.AddSeconds(5));
    }

    // -------------------------------------------------------------------------
    // ParseSemanticVersion / ResolveCurrentVersion — PAT-1248 acceptance criterion 4.
    // -------------------------------------------------------------------------
    [Theory]
    [InlineData("0.13.15+abcdef1234567890abcdef1234567890abcdef12", "0.13.15")]
    [InlineData("0.13.15", "0.13.15")]
    [InlineData(null, "0.0.0")]
    [InlineData("", "0.0.0")]
    [InlineData("   ", "0.0.0")]
    [InlineData("+onlymetadata", "0.0.0")]
    public void ParseSemanticVersion_StripsBuildMetadataOrFallsBackToPlaceholder(string? input, string expected)
    {
        Assert.Equal(expected, BootstrapUpdater.ParseSemanticVersion(input));
    }

    [Fact]
    public void ResolveCurrentVersion_LiveAssembly_IsNotTheUnsubstitutedPlaceholder()
    {
        // PAT-1248 regression guard: CurrentVersion used to be a hardcoded "0.0.0"
        // string literal that nothing in the build ever substituted, so the updater
        // could never detect it was out of date. This assembly is built with the
        // same SDK default (or windows-agent-release.yml's explicit
        // -p:InformationalVersion=<version>+<sha>) a real release build uses; if the
        // resolved value is still "0.0.0" here, the substitution wiring is broken.
        Assert.NotEqual(BootstrapUpdater.UnsubstitutedVersionPlaceholder, BootstrapUpdater.ResolveCurrentVersion());
    }

    // -------------------------------------------------------------------------
    // PAT-1338: updates\ and its per-version children must be established AND
    // verified with the same guarantee as every other privileged staging root —
    // SecureStagingDirectory.EnsureHardenedChain anchored at StateDir — rather than
    // trusting ACEs inherited from StateDir that nothing ever re-checks. These
    // exercise the REAL hardening call on the REAL stage-creation path (no fake, no
    // opt-out); the fixture only redirects the anchor to a scratch state root.
    //
    // Windows-only by the repo's established convention (an early
    // OperatingSystem.IsWindows() return, as in SecureStagingDirectoryTests):
    // System.Security.AccessControl throws PlatformNotSupportedException on macOS,
    // so these are proven on the windows-build.yml runner and the Windows staging
    // VM, never on a macOS host.
    // -------------------------------------------------------------------------

    /// <summary>
    /// Happy path: a normal successful stage leaves updates\ AND updates\&lt;version&gt;
    /// passing the full trust check — not a reparse point, owned by SYSTEM or
    /// Administrators, and granting no write-capable ACE to any other principal.
    /// Before PAT-1338 the directory was created with a bare
    /// Directory.CreateDirectory and nothing asserted any of that.
    ///
    /// Honest scope: this one is a non-regression assertion, not the fail-closed
    /// control. Verified by mutation on the Windows staging VM (2026-08-14) — with
    /// the EnsureHardenedChain call removed, this test still PASSES, because a plain
    /// CreateDirectory under an already-correctly-hardened parent inherits the right
    /// ACEs and lands with an Administrators owner. That is exactly the ticket's
    /// point: inherited-and-never-verified looks identical to established-and-verified
    /// right up until something adversarial is in the way. The three adversarial tests
    /// below are the ones that go red without the guard.
    /// </summary>
    [Fact]
    public async Task CheckAndStageAsync_StageDirectoryAndUpdatesRoot_AreHardenedAndVerifiable()
    {
        if (!OperatingSystem.IsWindows()) return;

        var artifact = ArtifactBytes();
        var payload = MetadataPayload("9.9.9", artifactSha256: Sha256Hex(artifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), artifact));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.True(staged);
        var stageDir = Path.Combine(UpdatesDir, "9.9.9");
        Assert.True(Directory.Exists(stageDir));
        Assert.True(File.Exists(Path.Combine(stageDir, "patched-agent.msi")));

        // The whole chain, not just the leaf: an intermediate segment created
        // implicitly by recursive CreateDirectory is exactly the gap PAT-857's
        // EnsureHardenedChain exists to close, and updates\ is that segment here.
        SecureStagingDirectory.VerifyTrusted(UpdatesDir);
        SecureStagingDirectory.VerifyTrusted(stageDir);

        // Explicit, non-inherited DACL granting nothing to a standard user — the
        // property VerifyTrusted enforces, asserted directly so this test still
        // fails loudly if VerifyTrusted itself is ever loosened.
        var rules = new DirectoryInfo(stageDir)
            .GetAccessControl(AccessControlSections.Access)
            .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        Assert.DoesNotContain(rules.Cast<FileSystemAccessRule>(), rule =>
            rule.AccessControlType == AccessControlType.Allow &&
            (rule.FileSystemRights & (FileSystemRights.WriteData | FileSystemRights.CreateFiles |
                                      FileSystemRights.CreateDirectories | FileSystemRights.Delete)) != 0 &&
            !((SecurityIdentifier)rule.IdentityReference).IsWellKnown(WellKnownSidType.LocalSystemSid) &&
            !((SecurityIdentifier)rule.IdentityReference).IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));

        Assert.False(HasAnyDegraded(health));
    }

    /// <summary>
    /// THE fail-closed assertion: a stage directory pre-planted by an unprivileged
    /// local user — present, a plain directory, but granting that user write access —
    /// must abort the update. No MSI written, no marker written, degraded reported
    /// on a distinct greppable reason. Warn-and-continue here would hand a
    /// standard user a file that LocalSystem later executes.
    /// </summary>
    [Fact]
    public async Task CheckAndStageAsync_StageDirectoryGrantsWriteToNonAdmin_FailsClosed_DoesNotStage()
    {
        if (!OperatingSystem.IsWindows()) return;

        // Model the attacker with the running user's own SID, exactly as
        // SecureStagingDirectoryTests.StateDirectoryBootstrap_AttackerOwnedRoot does:
        // on an elevated runner a freshly created directory is Administrators-owned,
        // so the interesting invariant to break is the DACL, not the owner.
        var attackerSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Unable to determine the current Windows user SID.");
        Assert.False(attackerSid.IsWellKnown(WellKnownSidType.LocalSystemSid));
        Assert.False(attackerSid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));

        var stageDir = Path.Combine(UpdatesDir, "9.9.9");
        Directory.CreateDirectory(stageDir);
        var planted = new DirectoryInfo(stageDir);
        var acl = planted.GetAccessControl(AccessControlSections.Access);
        acl.AddAccessRule(new FileSystemAccessRule(
            attackerSid,
            FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        planted.SetAccessControl(acl);

        var artifact = ArtifactBytes();
        var payload = MetadataPayload("9.9.9", artifactSha256: Sha256Hex(artifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), artifact));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.False(File.Exists(Path.Combine(stageDir, "patched-agent.msi")));
        Assert.False(File.Exists(Path.Combine(stageDir, "patched-agent.msi.tmp")));
        Assert.False(File.Exists(PendingFile));
        Assert.True(IsDegraded(health, "stage_directory_untrusted"));

        // Refused, never "repaired": re-applying our DACL over an attacker-planted
        // directory would legitimise it (SecureStagingDirectory's class doc).
        Assert.Contains(
            new DirectoryInfo(stageDir).GetAccessControl(AccessControlSections.Access)
                .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>(),
            rule => ((SecurityIdentifier)rule.IdentityReference) == attackerSid);
    }

    /// <summary>
    /// The reparse-point half at the CREATION end (PAT-1334 covered it at the two
    /// delete sites). A real NTFS junction planted where the per-version stage
    /// directory will be created must abort the update rather than have a ~160 MB
    /// MSI written through it into an attacker-chosen target.
    ///
    /// Uses `mklink /J` — a junction, not Directory.CreateSymbolicLink — because a
    /// junction needs no privilege at all to create, which is precisely why it is
    /// the realistic attack primitive here. Same reasoning as
    /// ExtensionRemovalLogicTests.RealJunctionAtExtensionDir_IsRefused_AndLeftIntact.
    /// </summary>
    [Fact]
    public async Task CheckAndStageAsync_StageDirectoryIsJunction_FailsClosed_TargetUntouched()
    {
        if (!OperatingSystem.IsWindows()) return;

        var target = Path.Combine(_dir, "junction-target");
        Directory.CreateDirectory(target);
        var canary = Path.Combine(target, "canary.txt");
        File.WriteAllText(canary, "must not be written through");

        Directory.CreateDirectory(UpdatesDir);
        var stageDir = Path.Combine(UpdatesDir, "9.9.9");
        Assert.True(TryCreateJunction(stageDir, target), "mklink /J failed — cannot exercise the junction case");
        Assert.True((File.GetAttributes(stageDir) & FileAttributes.ReparsePoint) != 0);

        var artifact = ArtifactBytes();
        var payload = MetadataPayload("9.9.9", artifactSha256: Sha256Hex(artifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), artifact));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.False(File.Exists(PendingFile));
        Assert.True(IsDegraded(health, "stage_directory_untrusted"));
        Assert.False(File.Exists(Path.Combine(target, "patched-agent.msi")));
        Assert.Equal("must not be written through", File.ReadAllText(canary));
    }

    /// <summary>
    /// The ancestor case, which a leaf-only check misses entirely: updates\ ITSELF
    /// planted as a junction. EnsureHardenedChain walks every level from the anchor
    /// down, so the refusal happens before the per-version child is ever touched.
    /// </summary>
    [Fact]
    public async Task CheckAndStageAsync_UpdatesRootIsJunctionAncestor_FailsClosed_TargetUntouched()
    {
        if (!OperatingSystem.IsWindows()) return;

        var target = Path.Combine(_dir, "updates-junction-target");
        Directory.CreateDirectory(target);
        var canary = Path.Combine(target, "canary.txt");
        File.WriteAllText(canary, "must not be written through");

        Assert.True(TryCreateJunction(UpdatesDir, target), "mklink /J failed — cannot exercise the junction case");

        var artifact = ArtifactBytes();
        var payload = MetadataPayload("9.9.9", artifactSha256: Sha256Hex(artifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), artifact));
        var health = NewHealth();

        var staged = await NewUpdater(handler, health).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.False(File.Exists(PendingFile));
        Assert.True(IsDegraded(health, "stage_directory_untrusted"));
        Assert.False(Directory.Exists(Path.Combine(target, "9.9.9")));
        Assert.Equal("must not be written through", File.ReadAllText(canary));
    }

    /// <summary>
    /// Proves the seam cannot be used as a bypass: the hardening root is an ANCHOR,
    /// not an on/off switch. A staging path that is not under the anchor is refused
    /// by EnsureHardenedChain's own containment check — so no caller (test or
    /// production) can point staging somewhere unverifiable and have it proceed.
    /// Runs everywhere: the containment half is platform-neutral.
    /// </summary>
    [Fact]
    public async Task CheckAndStageAsync_StagingOutsideTheHardeningRoot_FailsClosed()
    {
        var artifact = ArtifactBytes();
        var payload = MetadataPayload("9.9.9", artifactSha256: Sha256Hex(artifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), artifact));
        var health = NewHealth();
        var escaped = Path.Combine(_dir, "outside-the-anchor");

        var updater = new BootstrapUpdater(
            NullLogger<BootstrapUpdater>.Instance,
            new Factory(handler),
            CredentialStore.CreateForTests(_suspendedFile),
            () => VerifiedStableConfig,
            health,
            _trust,
            new FakeRestartScheduler(succeeds: true),
            pendingUpdateFileOverride: PendingFile,
            updatesDirOverride: escaped,
            hardeningRootOverride: _stateDir);

        var staged = await updater.CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.False(File.Exists(PendingFile));
        Assert.False(File.Exists(Path.Combine(escaped, "9.9.9", "patched-agent.msi")));
        Assert.True(IsDegraded(health, "stage_directory_untrusted"));
    }

    /// <summary>Creates a real NTFS junction via cmd's mklink /J (no .NET API
    /// exists for junctions, and unlike a symlink it needs no privilege).</summary>
    private static bool TryCreateJunction(string linkPath, string targetPath)
    {
        using var proc = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c mklink /J \"{linkPath}\" \"{targetPath}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        });
        if (proc is null) return false;
        proc.WaitForExit();
        return proc.ExitCode == 0 && Directory.Exists(linkPath);
    }

    // -------------------------------------------------------------------------
    // PAT-1760: PatchedWorker runs this check at startup even after a transient
    // enrolment failure. Without the credential snapshot nothing is sent and
    // health is left alone, as the fetchers do (PAT-1754).
    // -------------------------------------------------------------------------
    [Theory]
    [InlineData("", "dGVzdC1obWFjLXNlY3JldC0zMi1ieXRlcy1sb25nIQ==")]
    [InlineData("   ", "dGVzdC1obWFjLXNlY3JldC0zMi1ieXRlcy1sb25nIQ==")]
    [InlineData("enrolled-bearer", "")]
    [InlineData("enrolled-bearer", "   ")]
    [InlineData("enrolled-bearer", "\t")]
    public async Task CheckAndStageAsync_NoCredentialSnapshot_SendsNoRequest(string bearerToken, string hmacSecret)
    {
        var artifact = ArtifactBytes();
        var payload = MetadataPayload("9.9.9", artifactSha256: Sha256Hex(artifact));
        var handler = new RoutingHandler(req => Route(req, Envelope(payload), artifact));
        var health = NewHealth();
        var creds = CredentialStore.ForTesting("test-tenant", bearerToken, hmacSecret);

        var staged = await NewUpdater(handler, health, creds: creds).CheckAndStageAsync(CancellationToken.None);

        Assert.False(staged);
        Assert.Empty(handler.Requests);
        Assert.False(File.Exists(PendingFile));
        Assert.False(HasAnyDegraded(health));
    }

    [Fact]
    public async Task PeriodicCheck_NoCredentialSnapshot_SendsNoRequest()
    {
        // The hourly tick goes through the same gate as the startup check.
        var handler = new RoutingHandler(req => Route(req, ResponseWithoutEnvelope(), ArtifactBytes()));
        var creds = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "");
        var updater = NewUpdater(handler, NewHealth(), creds: creds);
        var now = DateTimeOffset.UtcNow;

        await PatchedWorker.RunPeriodicBootstrapUpdateCheckAsync(
            updater, now, now, TimeSpan.FromHours(1), NullLogger<PatchedWorker>.Instance, CancellationToken.None);

        Assert.Empty(handler.Requests);
    }

    // -------------------------------------------------------------------------
    // Test doubles
    // -------------------------------------------------------------------------

    private static HttpResponseMessage Route(
        HttpRequestMessage req, string envelopeJson, byte[] artifactBytes, string downloadUrl = DownloadUrl)
    {
        var downloadPath = new Uri(downloadUrl).AbsolutePath;
        if (req.RequestUri!.AbsolutePath == downloadPath)
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(artifactBytes) };
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(envelopeJson) };
    }

    private sealed class Factory(HttpMessageHandler handler) : IHttpClientFactory
    {
        /// <summary>Every client name requested, in call order. Both "patched"
        /// and "patched-artifact" route to the same underlying test handler
        /// (there is only one fake server here) - this list is what lets a
        /// test tell the two calls apart.</summary>
        public List<string> RequestedClientNames { get; } = new();

        public HttpClient CreateClient(string name)
        {
            RequestedClientNames.Add(name);
            return new HttpClient(handler);
        }
    }

    private sealed class RoutingHandler(Func<HttpRequestMessage, HttpResponseMessage> route) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            return Task.FromResult(route(request));
        }
    }

    /// <summary>
    /// PAT-1293: test double for <see cref="IPendingUpdateRestartScheduler"/> — the
    /// real <see cref="PendingUpdateRestartScheduler"/> shells out to schtasks.exe
    /// and is Windows-only ([SupportedOSPlatform]), so BootstrapUpdater's own tests
    /// (which run on any host) exercise the CALLING CONTRACT (was it invoked, what
    /// did BootstrapUpdater do with a true/false result) against this fake, never
    /// the real scheduler. Mirrors how PendingUpdateApplierTests fakes
    /// IPendingUpdateLauncher for the same reason.
    /// </summary>
    private sealed class FakeRestartScheduler(bool succeeds) : IPendingUpdateRestartScheduler
    {
        public int CallCount { get; private set; }

        public bool EnsureScheduled()
        {
            CallCount++;
            return succeeds;
        }
    }
}
