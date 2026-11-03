using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Patched.Shared.Verification;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2396 (PAT-2368 candidate W1): pending-update state that nothing authenticated.
///
/// <see cref="PendingUpdateApplier"/> runs as LocalSystem at service start, before the
/// fresh <see cref="BootstrapUpdater"/> check (Worker.cs), and executes whatever
/// <c>updates\&lt;version&gt;\patched-agent.msi</c> the marker names. Every check it makes
/// on the way is answerable from the marker and the files beside it: the path shape, the
/// reparse-point chain, "newer than running", and a SHA-256 that the marker itself
/// supplies. None of them ties the marker to the Ed25519-signed artifact metadata
/// BootstrapUpdater verified, and none inspects who owns or may write the marker, the
/// installer or the directories between them. StateDirectoryBootstrap repairs the root
/// DACL only, and Program.cs discards its "had to repair" result.
///
/// So a marker and installer that were already under the state root when the root was
/// writable by a non-admin (a root created by a release before PAT-1223 hardened it at
/// startup) are applied exactly like a staged update. The two failing cases below pin
/// that; the control pins the behaviour that must survive the fix.
///
/// What this file proves and does not prove: it is portable, so it exercises the
/// applier's decision with a recording launcher and never a real msiexec. It says nothing
/// about real Windows ACL inheritance, whether a standard user can in fact write to a
/// legacy root, LocalSystem context, or installed upgrade behaviour. Those need the
/// disposable-VM evidence the ticket asks for.
///
/// Launch is asserted only through <see cref="RecordingLauncher"/>. No installer is ever
/// executed; the "MSI" files are short text stand-ins.
/// </summary>
public sealed class PendingUpdateApplierLegacyStateTrustTests : IDisposable
{
    private const string DownloadUrl    = "https://api.patched.im/v1/agent/artifact-download/x.msi";
    private const string RunningVersion = "0.15.1";
    private const string StagedVersion  = "9.9.9";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"patched-pat2396-{Guid.NewGuid():N}");
    private readonly string _stateDir;
    private readonly Ed25519PrivateKeyParameters _privateKey = new(new SecureRandom());
    private readonly ArtifactTrust _trust;

    public PendingUpdateApplierLegacyStateTrustTests()
    {
        Directory.CreateDirectory(_dir);
        // Stand-in for %ProgramData%\Patched. Created plain here, as a legacy install
        // left it; each test decides when (and whether) it gets the protected DACL.
        _stateDir = Path.Combine(_dir, "state");
        Directory.CreateDirectory(_stateDir);
        _trust = new ArtifactTrust("test-artifact-key", _privateKey.GeneratePublicKey().GetEncoded());
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    // Production layout: the marker sits directly under StateDir, updates\ one level below.
    private string PendingFile => Path.Combine(_stateDir, "pending-agent-update.json");
    private string UpdatesDir  => Path.Combine(_stateDir, "updates");
    private string InstallerPath(string version) => Path.Combine(UpdatesDir, version, "patched-agent.msi");

    private AgentHealthStore NewHealth() =>
        new(NullLogger<AgentHealthStore>.Instance, Path.Combine(_dir, "health.json"));

    private static string Sha256Hex(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static bool HasAnyApplyDegraded(AgentHealthStore health) =>
        health.BuildPayloadSection()!.Degraded.Any(e => e.Kind == "self_update" && e.Subject == "apply");

    /// <summary>
    /// The one place this file constructs the applier. A fix that gives the applier an
    /// independent trust anchor (the artifact trust key, a child-chain verifier) will
    /// need to hand it this fixture's equivalent here; the assertions in the tests
    /// below must not need to change.
    /// </summary>
    private PendingUpdateApplier NewApplier(AgentHealthStore health, RecordingLauncher launcher) =>
        new(NullLogger<PendingUpdateApplier>.Instance, health, launcher, RunningVersion,
            PendingFile, UpdatesDir, trustedRootOverride: _stateDir, trustOverride: _trust,
            trustVerifierOverride: FakeStagedUpdateTrustVerifier.Trusted()); // PAT-2400: temp staging

    /// <summary>
    /// Same shape as BootstrapUpdaterTests.HardenAsStateRoot (PAT-1338): owner
    /// Administrators, protected DACL granting SYSTEM and Administrators only. This is
    /// the end state StateDirectoryBootstrap's root-only repair leaves the root in.
    /// No-op off Windows, where the ACL APIs are unavailable.
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

    // -------------------------------------------------------------------------
    // Failing today. Marker and installer planted under a pre-existing, still
    // writable state root; the root is then repaired, exactly as
    // StateDirectoryBootstrap does at the next service start, and the applier runs.
    //
    // The marker is the best forgery available against the current applier: the
    // exact field set BootstrapUpdater writes, the exact path it stages to, a
    // version newer than the running one, and the true SHA-256 of the planted
    // bytes. Nothing signed anywhere vouches for it.
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_MarkerAndInstallerPlantedUnderLegacyRoot_ThenRootRepaired_NeverLaunches_DiscardsPlantedState()
    {
        byte[] planted = Encoding.UTF8.GetBytes("attacker-supplied installer stand-in");
        string plantedPath = InstallerPath(StagedVersion);
        Directory.CreateDirectory(Path.GetDirectoryName(plantedPath)!);
        File.WriteAllBytes(plantedPath, planted);
        File.WriteAllText(PendingFile, JsonSerializer.Serialize(new
        {
            version        = StagedVersion,
            installer_path = plantedPath,
            sha256         = Sha256Hex(planted),
            staged_at      = DateTimeOffset.UtcNow,
        }));

        // The root-only repair. Descendants are not enumerated or repaired.
        HardenAsStateRoot(_stateDir);

        var health = NewHealth();
        var launcher = new RecordingLauncher();

        NewApplier(health, launcher).Apply();

        Assert.Empty(launcher.Calls);
        // Rejected, not merely skipped: the marker must not survive to be retried on
        // the next start, the planted file must not remain at the path the applier
        // executes from, and the refusal must be visible in agent health.
        Assert.False(File.Exists(PendingFile), "planted marker was left in place");
        Assert.False(File.Exists(plantedPath), "planted installer was left at the apply path");
        Assert.True(HasAnyApplyDegraded(health), "refusal was not reported via agent health");
    }

    // -------------------------------------------------------------------------
    // Failing today. A genuinely staged update whose installer bytes AND marker
    // hash are then replaced together. PAT-1261's re-verify catches a swapped
    // installer on its own (see PendingUpdateApplierTests' hash-mismatch case) but
    // not this, because the hash it compares against comes from the same writable
    // marker. Only the sha256 field is rewritten, so anything else BootstrapUpdater
    // put in the marker, now or after a fix, is preserved as an attacker would
    // preserve it.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Apply_StagedInstallerAndMarkerHashReplacedTogether_NeverLaunches()
    {
        HardenAsStateRoot(_stateDir);
        string stagedPath = await StageLegitimatelyAsync(Encoding.UTF8.GetBytes("signed release stand-in"));

        byte[] swapped = Encoding.UTF8.GetBytes("attacker-supplied replacement stand-in");
        File.WriteAllBytes(stagedPath, swapped);
        var marker = JsonNode.Parse(File.ReadAllText(PendingFile))!.AsObject();
        marker["sha256"] = Sha256Hex(swapped);
        File.WriteAllText(PendingFile, marker.ToJsonString());

        var health = NewHealth();
        var launcher = new RecordingLauncher();

        NewApplier(health, launcher).Apply();

        Assert.Empty(launcher.Calls);
        Assert.True(HasAnyApplyDegraded(health), "refusal was not reported via agent health");
    }

    // -------------------------------------------------------------------------
    // Control: passes today and must keep passing. An update staged by the real
    // BootstrapUpdater from a signed envelope, into a hardened root, untouched
    // afterwards, is applied through the launcher exactly once.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Apply_UpdateStagedByBootstrapUpdaterFromSignedEnvelope_Untouched_LaunchesExactlyOnce()
    {
        HardenAsStateRoot(_stateDir);
        string stagedPath = await StageLegitimatelyAsync(Encoding.UTF8.GetBytes("signed release stand-in"));

        var health = NewHealth();
        var launcher = new RecordingLauncher();

        NewApplier(health, launcher).Apply();

        Assert.Single(launcher.Calls);
        Assert.Equal(stagedPath, launcher.Calls[0]);
        Assert.True(File.Exists(PendingFile));
        Assert.False(HasAnyApplyDegraded(health));
    }

    // -------------------------------------------------------------------------
    // Legitimate staging: the real BootstrapUpdater, a fake HTTP origin, and an
    // envelope signed with this fixture's own Ed25519 key.
    // -------------------------------------------------------------------------

    private async Task<string> StageLegitimatelyAsync(byte[] artifact)
    {
        byte[] payload = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            version         = StagedVersion,
            platform        = "windows",
            channel         = "stable",
            artifact_url    = DownloadUrl,
            artifact_sha256 = Sha256Hex(artifact),
        }));

        var updater = new BootstrapUpdater(
            NullLogger<BootstrapUpdater>.Instance,
            new Factory(new RoutingHandler(req => Route(req, Envelope(payload), artifact))),
            CredentialStore.CreateForTests(Path.Combine(_dir, "suspended")),
            () => new AgentConfig
            {
                TenantId = "test-tenant", ConfigVersion = 153, UpdateChannel = "stable", UpdateAuthorityVerified = true,
            },
            NewHealth(),
            _trust,
            new AlwaysScheduledRestart(),
            pendingUpdateFileOverride: PendingFile,
            updatesDirOverride: UpdatesDir,
            hardeningRootOverride: _stateDir);

        bool staged = await updater.CheckAndStageAsync(CancellationToken.None);

        // Setup guard: if staging itself did not happen, the test using it says
        // nothing about the applier, so fail here with the reason rather than later.
        string stagedPath = InstallerPath(StagedVersion);
        Assert.True(staged, "fixture: BootstrapUpdater did not stage the signed update");
        Assert.True(File.Exists(stagedPath), "fixture: staged installer is missing");
        Assert.True(File.Exists(PendingFile), "fixture: pending-update marker is missing");
        return stagedPath;
    }

    /// <summary>The /v1/agent/artifact response shape: legacy fields with the signed
    /// envelope nested under artifact_metadata_signature (PAT-1258).</summary>
    private string Envelope(byte[] payload)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, _privateKey);
        signer.BlockUpdate(payload, 0, payload.Length);
        return JsonSerializer.Serialize(new
        {
            version = StagedVersion,
            artifact_url = DownloadUrl,
            artifact_sha256 = "not-checked-here",
            artifact_hmac = "legacy-field-retained-by-pat-1252",
            published_at = "2026-08-11T00:00:00Z",
            artifact_metadata_signature = new
            {
                signed_payload = Convert.ToBase64String(payload),
                signature = Convert.ToBase64String(signer.GenerateSignature()),
                key_id = _trust.KeyId,
            },
        });
    }

    private static HttpResponseMessage Route(HttpRequestMessage req, string envelopeJson, byte[] artifactBytes)
    {
        if (req.RequestUri!.AbsolutePath == new Uri(DownloadUrl).AbsolutePath)
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(artifactBytes) };
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(envelopeJson) };
    }

    // -------------------------------------------------------------------------
    // Test doubles
    // -------------------------------------------------------------------------

    private sealed class Factory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler);
    }

    private sealed class RoutingHandler(Func<HttpRequestMessage, HttpResponseMessage> route) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(route(request));
    }

    private sealed class AlwaysScheduledRestart : IPendingUpdateRestartScheduler
    {
        public bool EnsureScheduled() => true;
    }

    /// <summary>Records what WOULD be handed to msiexec. Never starts a process.</summary>
    private sealed class RecordingLauncher : IPendingUpdateLauncher
    {
        public List<string> Calls { get; } = new();

        public bool LaunchDetached(string installerPath)
        {
            Calls.Add(installerPath);
            return true;
        }
    }
}
