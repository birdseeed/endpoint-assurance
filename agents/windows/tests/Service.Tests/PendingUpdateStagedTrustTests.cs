using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Config;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2400: the applier's decisions about owner/DACL trust of the staged update,
/// recovery from a planted staging directory, and channel binding. Portable: the
/// verdicts come from <see cref="FakeStagedUpdateTrustVerifier"/>, so this proves what
/// the applier does with a verdict, not that Windows produces it. The rules behind a
/// verdict are covered on Windows by SecureStagingDirectoryTests (DescribeUntrusted_*).
/// No installer is executed; launches are recorded.
/// </summary>
public sealed class PendingUpdateStagedTrustTests : IDisposable
{
    private const string RunningVersion = "0.15.1";
    private const string StagedVersion  = "9.9.9";
    private static readonly byte[] Msi = Encoding.UTF8.GetBytes("signed release stand-in");

    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"patched-pat2400-{Guid.NewGuid():N}");
    private readonly string _stateDir;
    private readonly AgentHealthStore _health;
    private readonly RecordingLauncher _launcher = new();
    private readonly FakeStagedUpdateTrustVerifier _verifier = new();

    public PendingUpdateStagedTrustTests()
    {
        _stateDir = Path.Combine(_dir, "state");
        Directory.CreateDirectory(_stateDir);
        _health = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, Path.Combine(_dir, "health.json"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private string PendingFile => Path.Combine(_stateDir, "pending-agent-update.json");
    private string UpdatesDir  => Path.Combine(_stateDir, "updates");
    private string VersionDir  => Path.Combine(UpdatesDir, StagedVersion);
    private string StagedPath  => Path.Combine(VersionDir, "patched-agent.msi");

    private string PathOf(string staged) => staged switch
    {
        "updates_root" => UpdatesDir,
        "version_dir"  => VersionDir,
        "installer"    => StagedPath,
        _              => PendingFile,
    };

    private PendingUpdateApplier NewApplier(Func<UpdateChannelPolicy>? channelPolicy = null) =>
        new(NullLogger<PendingUpdateApplier>.Instance, _health, _launcher, RunningVersion,
            PendingFile, UpdatesDir, trustedRootOverride: _stateDir, trustOverride: SignedMarkerFixture.Trust,
            trustVerifierOverride: _verifier, channelPolicy: channelPolicy);

    /// <summary>What BootstrapUpdater leaves behind after a verified stage.</summary>
    private void Stage(string channel = "stable")
    {
        Directory.CreateDirectory(VersionDir);
        File.WriteAllBytes(StagedPath, Msi);
        string sha256 = Convert.ToHexString(SHA256.HashData(Msi)).ToLowerInvariant();
        var marker = new JsonObject
        {
            ["version"]        = StagedVersion,
            ["installer_path"] = StagedPath,
            ["sha256"]         = sha256,
            ["staged_at"]      = DateTimeOffset.UtcNow.ToString("O"),
        };
        SignedMarkerFixture.AddEnvelope(marker, SignedMarkerFixture.Payload(StagedVersion, sha256, channel: channel));
        File.WriteAllText(PendingFile, marker.ToJsonString());
    }

    private string Reasons(string subject = "apply") => string.Join(",", _health.BuildPayloadSection()!.Degraded
        .Where(e => e.Kind == "self_update" && e.Subject == subject).Select(e => e.Reason));

    private static readonly string Full = "tenant";
    private static UpdateChannelPolicy Verified(string channel) => new(channel, Full, null, 7);

    // -------------------------------------------------------------------------
    // B: fail closed before the launcher
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("updates_root", "untrusted_owner")]
    [InlineData("updates_root", "untrusted_acl")]
    [InlineData("updates_root", "reparse_point")]
    [InlineData("version_dir", "untrusted_owner")]
    [InlineData("version_dir", "untrusted_acl")]
    [InlineData("version_dir", "reparse_point")]
    [InlineData("installer", "untrusted_owner")]
    [InlineData("installer", "untrusted_acl")]
    [InlineData("installer", "reparse_point")]
    [InlineData("marker", "untrusted_owner")]
    [InlineData("marker", "untrusted_acl")]
    [InlineData("marker", "reparse_point")]
    [InlineData("installer", "unverifiable")]
    public void UntrustedStagedObject_IsRefusedBeforeTheLauncherAndRemoved(string staged, string why)
    {
        Stage();
        _verifier.Untrusted(PathOf(staged), why);

        NewApplier().Apply();

        Assert.Empty(_launcher.Calls);
        Assert.Equal($"staged_{staged}_{why}", Reasons());
        Assert.Contains(Path.GetFullPath(PathOf(staged)), _verifier.Removed);
        Assert.False(File.Exists(PendingFile), "marker for an untrusted staging was left in place");
        Assert.False(File.Exists(StagedPath), "untrusted installer was left at the apply path");
    }

    [Fact]
    public void TrustedStaging_ChecksAllFourObjectsThenLaunchesExactlyOnce()
    {
        Stage();
        List<string>? checkedBeforeLaunch = null;
        _launcher.OnLaunch = () => checkedBeforeLaunch = [.. _verifier.Checked];

        NewApplier().Apply();

        Assert.Equal([StagedPath], _launcher.Calls);
        Assert.Equal("", Reasons());
        Assert.NotNull(checkedBeforeLaunch);
        foreach (string staged in new[] { "updates_root", "version_dir", "installer", "marker" })
            Assert.Contains(Path.GetFullPath(PathOf(staged)), checkedBeforeLaunch!);
        Assert.Empty(_verifier.Removed);
    }

    // -------------------------------------------------------------------------
    // C: recovery
    // -------------------------------------------------------------------------

    [Fact]
    public void PlantedUpdatesRootWithNoMarker_IsRemovedAndTheNextStageApplies()
    {
        Directory.CreateDirectory(Path.Combine(UpdatesDir, "planted"));
        _verifier.Untrusted(UpdatesDir, "untrusted_owner");

        NewApplier().Apply();

        Assert.Equal("staged_updates_root_untrusted_owner", Reasons());
        Assert.False(Directory.Exists(UpdatesDir), "planted updates root survived");

        Stage(); // BootstrapUpdater's next cycle recreates the chain and restages
        NewApplier().Apply();

        Assert.Equal([StagedPath], _launcher.Calls);
    }

    [Fact]
    public void RemovalFailure_StaysClosedWithADistinctReasonOnEveryStart()
    {
        Stage();
        _verifier.Untrusted(UpdatesDir, "untrusted_owner").RemovalFailure = "removal_failed";

        NewApplier().Apply();

        Assert.Empty(_launcher.Calls);
        Assert.Equal("staged_updates_root_untrusted_owner_removal_failed", Reasons());
        Assert.False(File.Exists(PendingFile));

        Stage(); // even if something restaged into it, the root is still untrusted
        NewApplier().Apply();

        Assert.Empty(_launcher.Calls);
        Assert.Equal("staged_updates_root_untrusted_owner_removal_failed", Reasons());
        Assert.Equal(2, _verifier.Removed.Count(p => p == Path.GetFullPath(UpdatesDir)));
    }

    [Fact]
    public void FullQuarantine_StaysClosedWithItsOwnReason()
    {
        Stage();
        _verifier.Untrusted(UpdatesDir, "acl_unreadable").RemovalFailure = "quarantine_full";

        NewApplier().Apply();

        Assert.Empty(_launcher.Calls);
        Assert.Equal("staged_updates_root_acl_unreadable_quarantine_full", Reasons());
    }

    [Theory]
    [InlineData(true)]  // operator removed the directory by hand
    [InlineData(false)] // it is there and trusted again
    public void RecoveredUpdatesRoot_ClearsTheStaleStagedReason(bool rootAbsent)
    {
        Directory.CreateDirectory(UpdatesDir);
        _verifier.Untrusted(UpdatesDir, "acl_unreadable").RemovalFailure = "removal_failed";
        NewApplier().Apply();
        Assert.Equal("staged_updates_root_acl_unreadable_removal_failed", Reasons());

        if (rootAbsent) Directory.Delete(UpdatesDir, recursive: true);
        _verifier.Trust(UpdatesDir);
        NewApplier().Apply();

        Assert.Equal("", Reasons());
    }

    [Theory]
    [InlineData("marker_not_newer")]
    [InlineData("marker_envelope_signature_invalid")]
    [InlineData("attempts_exhausted")]
    public void TrustedUpdatesRoot_LeavesAnUnrelatedApplyReasonAlone(string unrelated)
    {
        _health.RecordFailure("self_update", "apply", unrelated);

        NewApplier().Apply();

        Assert.Equal(unrelated, Reasons());
    }

    [Fact]
    public void UnremovableUntrustedChild_IsReportedOnItsOwnSubjectUntilItIsGone()
    {
        string planted = Path.Combine(UpdatesDir, "9.9.10");
        Directory.CreateDirectory(planted);
        _verifier.Untrusted(planted, "untrusted_owner").RemovalFailure = "quarantine_full";

        NewApplier().Apply();
        Assert.Equal("untrusted_child_quarantine_full", Reasons("staged_cleanup"));
        Assert.Equal("", Reasons());

        _verifier.RemovalFailure = null;
        NewApplier().Apply();
        Assert.Equal("", Reasons("staged_cleanup"));
    }

    [Fact]
    public void PlantedSiblingVersionDirectory_IsRemovedThroughTheSeamNotRecursedInto()
    {
        string planted = Path.Combine(UpdatesDir, "9.9.10");
        Directory.CreateDirectory(planted);
        _verifier.Untrusted(planted, "untrusted_owner").RemovalFailure = "removal_failed";

        NewApplier().Apply();

        Assert.Contains(Path.GetFullPath(planted), _verifier.Removed);
        Assert.True(Directory.Exists(planted), "the applier deleted an untrusted directory itself");
    }

    [Fact]
    public void Removal_NeverLeavesTheUpdatesTreeOrCrossesALink()
    {
        Stage();
        string outside = Path.Combine(_stateDir, "creds");
        Directory.CreateDirectory(outside);
        string elsewhere = Path.Combine(_dir, "elsewhere");
        Directory.CreateDirectory(Path.Combine(elsewhere, "victim"));
        string link = Path.Combine(UpdatesDir, "link");
        Directory.CreateSymbolicLink(link, elsewhere);
        var applier = NewApplier();

        Assert.Equal("removal_failed", applier.RemoveUntrusted(outside));
        Assert.Equal("removal_failed", applier.RemoveUntrusted(_stateDir));
        Assert.Equal("removal_failed", applier.RemoveUntrusted(Path.Combine(UpdatesDir, "..", "creds")));
        Assert.Equal("removal_failed", applier.RemoveUntrusted(Path.Combine(link, "victim")));
        Assert.Empty(_verifier.Removed);

        Assert.Null(applier.RemoveUntrusted(link)); // the link itself is ours to unlink
        Assert.Null(applier.RemoveUntrusted(PendingFile));
        Assert.True(Directory.Exists(Path.Combine(elsewhere, "victim")));
    }

    // -------------------------------------------------------------------------
    // D: channel binding
    // -------------------------------------------------------------------------

    [Fact]
    public void VerifiedPolicy_RefusesAnEnvelopeForAnotherChannel()
    {
        Stage(channel: "beta");

        NewApplier(() => Verified("stable")).Apply();

        Assert.Empty(_launcher.Calls);
        Assert.Equal("marker_envelope_channel_mismatch", Reasons());
        Assert.False(File.Exists(PendingFile));
        Assert.False(File.Exists(StagedPath));
    }

    [Theory]
    [InlineData("stable")]
    [InlineData("beta")]
    public void VerifiedPolicy_AppliesAnEnvelopeForItsOwnChannel(string channel)
    {
        Stage(channel);

        NewApplier(() => Verified(channel)).Apply();

        Assert.Equal([StagedPath], _launcher.Calls);
        Assert.Equal("", Reasons());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NoVerifiedPolicy_KeepsApplyingWhateverSignedChannelWasStaged(bool reportingDefault)
    {
        // SafeDefault says "stable" for reporting only; it has no authority and must
        // not be read as a stable policy that refuses this beta envelope.
        Stage(channel: "beta");

        NewApplier(reportingDefault ? () => UpdateChannelPolicy.SafeDefault : null).Apply();

        Assert.Equal([StagedPath], _launcher.Calls);
        Assert.Equal("", Reasons());
    }

    // -------------------------------------------------------------------------
    // A: production never runs on a permissive verifier
    // -------------------------------------------------------------------------

    [Fact]
    public void ProductionConstructor_WiresTheRealVerifierAndNoOtherImplementationShips()
    {
        // DI can only use a public constructor, and there must be exactly one. It does
        // not read its config or credential arguments until Apply, so null is enough
        // to see what it wires.
        var ctor = Assert.Single(typeof(PendingUpdateApplier).GetConstructors());
        Assert.DoesNotContain(ctor.GetParameters(), p => p.ParameterType == typeof(IStagedUpdateTrustVerifier));

        var applier = (PendingUpdateApplier)ctor.Invoke(
            [NullLogger<PendingUpdateApplier>.Instance, _health, _launcher, null, null]);
        Assert.IsType<WindowsStagedUpdateTrustVerifier>(applier.TrustVerifier);

        // The default of the internal constructor is the same real verifier, never a pass.
        var viaSeam = new PendingUpdateApplier(NullLogger<PendingUpdateApplier>.Instance, _health, _launcher,
            RunningVersion, PendingFile, UpdatesDir);
        Assert.IsType<WindowsStagedUpdateTrustVerifier>(viaSeam.TrustVerifier);

        var shipped = typeof(PendingUpdateApplier).Assembly.GetTypes()
            .Where(t => !t.IsInterface && typeof(IStagedUpdateTrustVerifier).IsAssignableFrom(t));
        Assert.Equal([typeof(WindowsStagedUpdateTrustVerifier)], shipped);
    }

    [Fact]
    public void RealVerifier_TrustsNothingWhereItCannotReadAnAcl()
    {
        if (OperatingSystem.IsWindows()) return; // Windows verdicts: SecureStagingDirectoryTests

        Stage();
        var real = new WindowsStagedUpdateTrustVerifier(NullLogger.Instance);

        Assert.Equal("unverifiable", real.WhyUntrusted(UpdatesDir, isDirectory: true));
        Assert.Equal("unverifiable", real.WhyUntrusted(StagedPath, isDirectory: false));
    }

    [Fact]
    public void RealVerifier_Removal_UnlinksOrMovesAsideAndNeverDescends()
    {
        Stage();
        var real = new WindowsStagedUpdateTrustVerifier(NullLogger.Instance);
        string elsewhere = Path.Combine(_dir, "elsewhere");
        Directory.CreateDirectory(elsewhere);
        File.WriteAllText(Path.Combine(elsewhere, "victim"), "must survive");
        string link = Path.Combine(UpdatesDir, "link");
        Directory.CreateSymbolicLink(link, elsewhere);

        Assert.Null(real.Remove(link, _stateDir));
        Assert.False(Directory.Exists(link));
        Assert.True(File.Exists(Path.Combine(elsewhere, "victim")));

        Assert.Null(real.Remove(PendingFile, _stateDir));
        Assert.False(File.Exists(PendingFile));

        Assert.Null(real.Remove(UpdatesDir, _stateDir));
        Assert.False(Directory.Exists(UpdatesDir));
        string quarantine = Assert.Single(Directory.GetDirectories(_stateDir));
        Assert.StartsWith(WindowsStagedUpdateTrustVerifier.QuarantinePrefix, Path.GetFileName(quarantine));
        Assert.True(File.Exists(Path.Combine(quarantine, StagedVersion, "patched-agent.msi")),
            "the untrusted tree was descended into instead of moved whole");

        Assert.Null(real.Remove(UpdatesDir, _stateDir)); // already gone
    }

    private sealed class RecordingLauncher : IPendingUpdateLauncher
    {
        public List<string> Calls { get; } = [];
        public Action? OnLaunch { get; set; }

        public bool LaunchDetached(string installerPath)
        {
            OnLaunch?.Invoke();
            Calls.Add(installerPath);
            return true;
        }
    }
}
