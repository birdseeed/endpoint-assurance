using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Patched.Shared.Verification;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2396: the signed artifact-metadata envelope is the trust anchor for a staged
/// update. Covers each way the envelope in the marker can fail to vouch for the marker
/// (absent, wrong version, wrong platform, wrong hash, bad signature, wrong key), the
/// upgrade path for a marker written before the envelope was carried, and
/// BootstrapUpdater's "already staged" check no longer accepting state it cannot verify.
///
/// The frozen reproduction for the original candidate lives in
/// PendingUpdateApplierLegacyStateTrustTests. Portable: nothing here speaks to Windows
/// ownership, DACLs or LocalSystem. No installer is executed; launches are recorded.
/// </summary>
public sealed class PendingUpdateEnvelopeTrustTests : IDisposable
{
    private const string DownloadUrl    = "https://api.patched.im/v1/agent/artifact-download/x.msi";
    private const string RunningVersion = "0.15.1";
    private const string StagedVersion  = "9.9.9";

    private static readonly byte[] Genuine = Encoding.UTF8.GetBytes("signed release stand-in");

    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"patched-pat2396-envelope-{Guid.NewGuid():N}");
    private readonly string _stateDir;

    public PendingUpdateEnvelopeTrustTests()
    {
        Directory.CreateDirectory(_dir);
        _stateDir = Path.Combine(_dir, "state");
        Directory.CreateDirectory(_stateDir);
        HardenAsStateRoot(_stateDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private static ArtifactTrust Trust => SignedMarkerFixture.Trust;

    private string PendingFile => Path.Combine(_stateDir, "pending-agent-update.json");
    private string UpdatesDir  => Path.Combine(_stateDir, "updates");
    private string StagedPath  => Path.Combine(UpdatesDir, StagedVersion, "patched-agent.msi");

    private AgentHealthStore NewHealth() =>
        new(NullLogger<AgentHealthStore>.Instance, Path.Combine(_dir, $"health-{Guid.NewGuid():N}.json"));

    private static string Sha256Hex(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static bool IsApplyDegraded(AgentHealthStore health, string reason) =>
        health.BuildPayloadSection()!.Degraded.Any(e =>
            e.Kind == "self_update" && e.Subject == "apply" && e.Reason == reason);

    private PendingUpdateApplier NewApplier(AgentHealthStore health, RecordingLauncher launcher, ArtifactTrust? trust) =>
        new(NullLogger<PendingUpdateApplier>.Instance, health, launcher, RunningVersion,
            PendingFile, UpdatesDir, trustedRootOverride: _stateDir, trustOverride: trust,
            trustVerifierOverride: FakeStagedUpdateTrustVerifier.Trusted()); // PAT-2400: temp staging

    /// <summary>Same shape as BootstrapUpdaterTests.HardenAsStateRoot (PAT-1338).
    /// No-op off Windows.</summary>
    private static void HardenAsStateRoot(string dir)
    {
        if (!OperatingSystem.IsWindows()) return;

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
        new DirectoryInfo(dir).SetAccessControl(acl);
    }

    private JsonObject ReadMarker() => JsonNode.Parse(File.ReadAllText(PendingFile))!.AsObject();

    private void RewriteMarker(Action<JsonObject> change)
    {
        var marker = ReadMarker();
        change(marker);
        File.WriteAllText(PendingFile, marker.ToJsonString());
    }

    private static void StripEnvelope(JsonObject marker)
    {
        marker.Remove("signed_payload");
        marker.Remove("signature");
        marker.Remove("key_id");
    }

    /// <summary>Applies whatever is on disk and asserts it was refused outright: no
    /// launch, marker cleared, nothing left at the apply path, the named reason.</summary>
    private void AssertRejected(string expectedReason, ArtifactTrust? trust = null, bool useDefaultTrust = false)
    {
        var health = NewHealth();
        var launcher = new RecordingLauncher();

        NewApplier(health, launcher, useDefaultTrust ? null : trust ?? Trust).Apply();

        Assert.Empty(launcher.Calls);
        Assert.False(File.Exists(PendingFile), "rejected marker was left in place");
        Assert.False(File.Exists(StagedPath), "rejected installer was left at the apply path");
        Assert.True(IsApplyDegraded(health, expectedReason),
            "expected self_update/apply reason " + expectedReason + ", got: " +
            string.Join(",", health.BuildPayloadSection()!.Degraded.Select(e => $"{e.Kind}/{e.Subject}/{e.Reason}")));
    }

    // -------------------------------------------------------------------------
    // The marker BootstrapUpdater writes
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Stage_MarkerCarriesTheVerifiedEnvelopeVerbatim()
    {
        var (payload, signature) = await StageAsync(Genuine);

        var marker = ReadMarker();
        Assert.Equal(Convert.ToBase64String(payload), marker["signed_payload"]!.GetValue<string>());
        Assert.Equal(Convert.ToBase64String(signature), marker["signature"]!.GetValue<string>());
        Assert.Equal(Trust.KeyId, marker["key_id"]!.GetValue<string>());
        // The pre-existing fields are unchanged, so an older applier still reads it.
        Assert.Equal(StagedVersion, marker["version"]!.GetValue<string>());
        Assert.Equal(StagedPath, marker["installer_path"]!.GetValue<string>());
        Assert.Equal(Sha256Hex(Genuine), marker["sha256"]!.GetValue<string>());
    }

    [Fact]
    public async Task Apply_LaunchFails_AttemptRewriteKeepsEnvelope_SoTheRetryIsStillVerifiable()
    {
        await StageAsync(Genuine);
        var before = ReadMarker();

        var launcher = new RecordingLauncher(returnValue: false);
        NewApplier(NewHealth(), launcher, Trust).Apply();
        NewApplier(NewHealth(), launcher, Trust).Apply();

        Assert.Equal(2, launcher.Calls.Count);
        var after = ReadMarker();
        Assert.Equal(2, after["attempts"]!.GetValue<int>());
        foreach (var field in new[] { "signed_payload", "signature", "key_id" })
            Assert.Equal(before[field]!.GetValue<string>(), after[field]!.GetValue<string>());
    }

    // -------------------------------------------------------------------------
    // Applier: each way the envelope can fail to vouch for the marker
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Apply_LegacyFormatMarker_GenuineInstaller_IsDiscardedNotApplied()
    {
        // What an agent older than PAT-2396 wrote for a real update: hash, no envelope.
        await StageAsync(Genuine);
        RewriteMarker(StripEnvelope);

        AssertRejected("marker_envelope_absent");
    }

    [Theory]
    [InlineData("signed_payload")]
    [InlineData("signature")]
    [InlineData("key_id")]
    public async Task Apply_MarkerMissingAnyOneEnvelopeField_IsRejected(string field)
    {
        await StageAsync(Genuine);
        RewriteMarker(m => m.Remove(field));

        AssertRejected("marker_envelope_absent");
    }

    [Fact]
    public async Task Apply_EnvelopeSignedForADifferentVersion_IsRejected()
    {
        // A real signature, over metadata for another release, attached to this marker.
        await StageAsync(Genuine);
        RewriteMarker(m => SignedMarkerFixture.AddEnvelope(m, "9.9.8", Sha256Hex(Genuine)));

        AssertRejected("marker_envelope_version_mismatch");
    }

    [Fact]
    public async Task Apply_EnvelopeSignedForAnotherPlatform_IsRejected()
    {
        await StageAsync(Genuine);
        RewriteMarker(m => SignedMarkerFixture.AddEnvelope(
            m, SignedMarkerFixture.Payload(StagedVersion, Sha256Hex(Genuine), platform: "macos")));

        AssertRejected("marker_envelope_platform_mismatch");
    }

    [Fact]
    public async Task Apply_EnvelopeHashDiffersFromMarkerAndFile_IsRejected()
    {
        // Installer and marker hash replaced together; the envelope still names the
        // genuine hash. The marker and the file agree with each other and with nothing signed.
        await StageAsync(Genuine);
        byte[] swapped = Encoding.UTF8.GetBytes("replacement stand-in");
        File.WriteAllBytes(StagedPath, swapped);
        RewriteMarker(m => m["sha256"] = Sha256Hex(swapped));

        AssertRejected("marker_envelope_hash_mismatch");
    }

    [Fact]
    public async Task Apply_EnvelopePayloadRewrittenToMatch_SignatureNoLongerVerifies_IsRejected()
    {
        // The next step up: rewrite the payload to name the swapped hash and keep the
        // old signature.
        await StageAsync(Genuine);
        byte[] swapped = Encoding.UTF8.GetBytes("replacement stand-in");
        File.WriteAllBytes(StagedPath, swapped);
        RewriteMarker(m =>
        {
            m["sha256"] = Sha256Hex(swapped);
            m["signed_payload"] = Convert.ToBase64String(
                SignedMarkerFixture.Payload(StagedVersion, Sha256Hex(swapped)));
        });

        AssertRejected("marker_envelope_signature_invalid");
    }

    [Fact]
    public async Task Apply_SignatureBytesTampered_IsRejected()
    {
        await StageAsync(Genuine);
        RewriteMarker(m =>
        {
            byte[] signature = Convert.FromBase64String(m["signature"]!.GetValue<string>());
            signature[0] ^= 0x01;
            m["signature"] = Convert.ToBase64String(signature);
        });

        AssertRejected("marker_envelope_signature_invalid");
    }

    [Fact]
    public async Task Apply_EnvelopeSignedByAnotherKeyClaimingThePinnedKeyId_IsRejected()
    {
        await StageAsync(Genuine);
        byte[] payload = SignedMarkerFixture.Payload(StagedVersion, Sha256Hex(Genuine));
        var otherKey = new Ed25519PrivateKeyParameters(new SecureRandom());
        RewriteMarker(m => SignedMarkerFixture.AddEnvelope(m, payload, SignedMarkerFixture.Sign(payload, otherKey)));

        AssertRejected("marker_envelope_signature_invalid");
    }

    [Fact]
    public async Task Apply_EnvelopeNamesAnotherKeyId_IsRejected()
    {
        await StageAsync(Genuine);
        RewriteMarker(m => m["key_id"] = "some-other-key");

        AssertRejected("marker_envelope_key_id_mismatch");
    }

    [Fact]
    public async Task Apply_EnvelopeFieldsNotBase64_IsRejected()
    {
        await StageAsync(Genuine);
        RewriteMarker(m => m["signed_payload"] = "not base64 !!");

        AssertRejected("marker_envelope_not_base64");
    }

    [Fact]
    public async Task Apply_NoTrustOverride_UsesThePinnedProductionKey_SoATestSignedMarkerIsRejected()
    {
        // The seam is an anchor, not a switch: leaving it out does not disable the
        // check, it verifies against the production key, which never signed this.
        await StageAsync(Genuine);

        AssertRejected("marker_envelope_key_id_mismatch", useDefaultTrust: true);
    }

    [Fact]
    public async Task Apply_TrustIsTheUnprovisionedPlaceholder_IsRejected()
    {
        await StageAsync(Genuine);
        var placeholder = new ArtifactTrust(
            ArtifactTrust.UnprovisionedPlaceholderKeyId,
            Convert.FromBase64String(ArtifactTrust.UnprovisionedPlaceholderPublicKeyBase64));
        RewriteMarker(m => m["key_id"] = placeholder.KeyId);

        AssertRejected("marker_envelope_trust_not_provisioned", trust: placeholder);
    }

    // -------------------------------------------------------------------------
    // BootstrapUpdater: "already staged" must be verified, not assumed
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CheckAndStage_GenuinelyStagedAndUntouched_StillShortCircuits_NoRedownload()
    {
        await StageAsync(Genuine);

        var (staged, downloads) = await CheckAndStageAsync(Genuine);

        Assert.True(staged);
        Assert.Equal(0, downloads);
    }

    [Fact]
    public async Task CheckAndStage_SameVersionMarkerWithoutEnvelope_IsNotBlessed_Restages()
    {
        await StageAsync(Genuine);
        RewriteMarker(StripEnvelope);

        var (staged, downloads) = await CheckAndStageAsync(Genuine);

        Assert.True(staged);
        Assert.Equal(1, downloads);
        Assert.NotNull(ReadMarker()["signed_payload"]);
    }

    [Fact]
    public async Task CheckAndStage_SameVersionPlantedInstallerAndSelfConsistentMarker_IsNotBlessed_ReplacedByOriginBytes()
    {
        await StageAsync(Genuine);
        byte[] planted = Encoding.UTF8.GetBytes("attacker-supplied installer stand-in");
        File.WriteAllBytes(StagedPath, planted);
        RewriteMarker(m =>
        {
            StripEnvelope(m);
            m["sha256"] = Sha256Hex(planted);
        });

        var (staged, downloads) = await CheckAndStageAsync(Genuine);

        Assert.True(staged);
        Assert.Equal(1, downloads);
        Assert.Equal(Genuine, File.ReadAllBytes(StagedPath));
        Assert.Equal(Sha256Hex(Genuine), ReadMarker()["sha256"]!.GetValue<string>());
    }

    [Fact]
    public async Task CheckAndStage_ValidMarkerButInstallerBytesReplaced_IsNotBlessed_ReplacedByOriginBytes()
    {
        await StageAsync(Genuine);
        File.WriteAllBytes(StagedPath, Encoding.UTF8.GetBytes("attacker-supplied installer stand-in"));

        var (staged, downloads) = await CheckAndStageAsync(Genuine);

        Assert.True(staged);
        Assert.Equal(1, downloads);
        Assert.Equal(Genuine, File.ReadAllBytes(StagedPath));
    }

    [Fact]
    public async Task CheckAndStage_MarkerEnvelopeIsForADifferentHashThanTheOriginNowSigns_Restages()
    {
        // Marker and file are internally consistent and validly signed, but for other
        // bytes than the envelope just fetched names (a release re-cut under the same
        // version). Not provably the offered update, so it is restaged.
        byte[] earlier = Encoding.UTF8.GetBytes("earlier cut stand-in");
        await StageAsync(earlier);

        var (staged, downloads) = await CheckAndStageAsync(Genuine);

        Assert.True(staged);
        Assert.Equal(1, downloads);
        Assert.Equal(Genuine, File.ReadAllBytes(StagedPath));
    }

    // -------------------------------------------------------------------------
    // The upgrade path: a legitimately staged legacy-format marker is pending when
    // the PAT-2396 agent first starts. Worker order is Apply, then CheckAndStage.
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Upgrade_LegacyFormatMarkerPending_DiscardedThenRestagedThenApplied()
    {
        await StageAsync(Genuine);
        RewriteMarker(StripEnvelope);

        // Start 1: the applier refuses it, then the updater restages from the origin.
        var launcher = new RecordingLauncher();
        NewApplier(NewHealth(), launcher, Trust).Apply();
        Assert.Empty(launcher.Calls);
        Assert.False(File.Exists(PendingFile));

        var (staged, downloads) = await CheckAndStageAsync(Genuine);
        Assert.True(staged);
        Assert.Equal(1, downloads);

        // Start 2: the restaged update is applied.
        var health = NewHealth();
        NewApplier(health, launcher, Trust).Apply();
        Assert.Single(launcher.Calls);
        Assert.Equal(StagedPath, launcher.Calls[0]);
    }

    // -------------------------------------------------------------------------
    // The real BootstrapUpdater against a fake origin
    // -------------------------------------------------------------------------

    /// <summary>Stages <paramref name="artifact"/> as <see cref="StagedVersion"/> and
    /// returns the signed payload and signature the origin served.</summary>
    private async Task<(byte[] Payload, byte[] Signature)> StageAsync(byte[] artifact)
    {
        byte[] payload = SignedMarkerFixture.Payload(StagedVersion, Sha256Hex(artifact));
        var (staged, _) = await CheckAndStageAsync(artifact);

        Assert.True(staged, "fixture: BootstrapUpdater did not stage the signed update");
        Assert.True(File.Exists(StagedPath), "fixture: staged installer is missing");
        Assert.True(File.Exists(PendingFile), "fixture: pending-update marker is missing");
        return (payload, SignedMarkerFixture.Sign(payload));
    }

    /// <summary>One check against an origin offering <paramref name="artifact"/> as
    /// <see cref="StagedVersion"/>. Returns the result and how many times the installer
    /// bytes were requested.</summary>
    private async Task<(bool Staged, int Downloads)> CheckAndStageAsync(byte[] artifact)
    {
        byte[] payload = SignedMarkerFixture.Payload(StagedVersion, Sha256Hex(artifact));
        string response = JsonSerializer.Serialize(new
        {
            version = StagedVersion,
            artifact_url = DownloadUrl,
            artifact_metadata_signature = new
            {
                signed_payload = Convert.ToBase64String(payload),
                signature = Convert.ToBase64String(SignedMarkerFixture.Sign(payload)),
                key_id = Trust.KeyId,
            },
        });

        int downloads = 0;
        var handler = new RoutingHandler(req =>
        {
            if (req.RequestUri!.AbsolutePath == new Uri(DownloadUrl).AbsolutePath)
            {
                downloads++;
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(artifact) };
            }
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response) };
        });

        var updater = new BootstrapUpdater(
            NullLogger<BootstrapUpdater>.Instance,
            new Factory(handler),
            CredentialStore.CreateForTests(Path.Combine(_dir, "suspended")),
            () => new AgentConfig
            {
                TenantId = "test-tenant", ConfigVersion = 153, UpdateChannel = "stable", UpdateAuthorityVerified = true,
            },
            NewHealth(),
            Trust,
            new AlwaysScheduledRestart(),
            pendingUpdateFileOverride: PendingFile,
            updatesDirOverride: UpdatesDir,
            hardeningRootOverride: _stateDir);

        bool staged = await updater.CheckAndStageAsync(CancellationToken.None);
        return (staged, downloads);
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
    private sealed class RecordingLauncher(bool returnValue = true) : IPendingUpdateLauncher
    {
        public List<string> Calls { get; } = new();

        public bool LaunchDetached(string installerPath)
        {
            Calls.Add(installerPath);
            return returnValue;
        }
    }
}
