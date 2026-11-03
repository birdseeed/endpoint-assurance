using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1339: <c>PendingUpdateApplier</c> reads both marker fields (<c>Version</c>,
/// <c>InstallerPath</c>) with no validation at read time — PAT-1334 only guarded
/// the two privileged recursive deletes that already existed, and nothing ever
/// validated <c>InstallerPath</c> at all. <c>InstallerPath</c> flows straight into
/// <see cref="IPendingUpdateLauncher.LaunchDetached"/>, which runs
/// `msiexec /i "&lt;path&gt;" /qn /norestart` AS LOCALSYSTEM — a marker naming
/// <c>C:\Users\Public\evil.msi</c> (plus that file's own true SHA-256, since the
/// hash re-verify is self-referential and does not defend against this) would be
/// accepted and executed.
///
/// This covers the new marker-read-time validation added in
/// <c>PendingUpdateApplier.IsSafeVersionSegment</c>/<c>IsTrustedInstallerPath</c>:
/// the out-of-tree InstallerPath refusal (the exploit that actually matters — the
/// launcher must never be called), the Version safe-path-segment rules mirroring
/// <c>ExtensionRemovalLogic.IsSafePathSegment</c> (PAT-1329 Defect A), a real
/// junctioned installer path, the degraded-health signal with the new distinct
/// reasons, and the no-regression case for a well-formed marker.
/// </summary>
public sealed class PendingUpdateApplierMarkerValidationTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"patched-pending-update-marker-{Guid.NewGuid():N}");

    public PendingUpdateApplierMarkerValidationTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private string PendingFile => Path.Combine(_dir, "pending-agent-update.json");
    private string UpdatesDir => Path.Combine(_dir, "updates");
    private AgentHealthStore NewHealth() => new(NullLogger<AgentHealthStore>.Instance, Path.Combine(_dir, "health.json"));

    private static string Sha256Hex(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static bool IsDegraded(AgentHealthStore health, string reason) =>
        health.BuildPayloadSection()!.Degraded.Any(e =>
            e.Kind == "self_update" && e.Subject == "apply" && e.Reason == reason);

    private PendingUpdateApplier NewApplier(
        string currentVersion, AgentHealthStore health, FakeLauncher launcher) =>
        new(NullLogger<PendingUpdateApplier>.Instance, health, launcher, currentVersion, PendingFile, UpdatesDir,
            trustedRootOverride: _dir, trustOverride: SignedMarkerFixture.Trust, // PAT-2396
            trustVerifierOverride: FakeStagedUpdateTrustVerifier.Trusted()); // PAT-2400: temp staging

    /// <summary>Stages a fake installer under updates\&lt;version&gt;\patched-agent.msi
    /// (BootstrapUpdater's exact staging shape) and returns its full path.</summary>
    private string StageInstaller(string version, byte[] bytes)
    {
        string dir = Path.Combine(UpdatesDir, version);
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "patched-agent.msi");
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private void WriteMarker(string version, string installerPath, string? sha256, int attempts = 0)
    {
        var obj = new JsonObject
        {
            ["version"]        = version,
            ["installer_path"] = installerPath,
            ["staged_at"]      = DateTimeOffset.UtcNow.ToString("O"),
            ["attempts"]       = attempts,
        };
        if (sha256 is not null)
        {
            obj["sha256"] = sha256;
            SignedMarkerFixture.AddEnvelope(obj, version, sha256); // PAT-2396
        }
        File.WriteAllText(PendingFile, obj.ToJsonString());
    }

    // -------------------------------------------------------------------------
    // The exploit that actually matters: an out-of-tree InstallerPath, even
    // paired with that file's own TRUE hash (defeating the self-referential
    // SHA-256 re-verify), must be refused AND — this is the assertion that
    // proves it, not just a return value — the launcher must never be invoked.
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_OutOfTreeInstallerPath_IsRefused_AndLauncherIsNeverInvoked()
    {
        var outside = Path.Combine(_dir, "Public");
        Directory.CreateDirectory(outside);
        var evilPath = Path.Combine(outside, "evil.msi");
        var evilBytes = Encoding.UTF8.GetBytes("attacker-controlled installer");
        File.WriteAllBytes(evilPath, evilBytes);

        // The marker's own hash matches evilPath exactly — the self-referential
        // case the ticket calls out. If the launcher fires here, the guard did
        // nothing.
        WriteMarker(version: "9.9.9", evilPath, Sha256Hex(evilBytes));
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);

        NewApplier(currentVersion: "0.13.20", health, launcher).Apply();

        Assert.Empty(launcher.Calls); // the assertion that actually matters
        Assert.True(File.Exists(evilPath), "the out-of-tree file itself is never touched by this guard");
        Assert.False(File.Exists(PendingFile), "a marker failing validation is treated as hostile and cleared");
        Assert.True(IsDegraded(health, "marker_installer_path_untrusted"));
    }

    // -------------------------------------------------------------------------
    // Version safety: separators, "..", rootedness, reserved device names.
    // -------------------------------------------------------------------------
    [Theory]
    [InlineData("1.2\\3")]     // backslash separator
    [InlineData("1.2/3")]      // forward-slash separator
    [InlineData("..")]         // exact traversal segment
    [InlineData("C:\\Windows\\System32")] // drive-qualified + rooted
    [InlineData("CON")]        // reserved DOS device name
    [InlineData("con")]        // reserved DOS device name, case-insensitive
    [InlineData("LPT1")]       // reserved DOS device name
    [InlineData("   ")]        // whitespace-only
    public void Apply_UnsafeVersion_IsRefused_AndLauncherIsNeverInvoked(string unsafeVersion)
    {
        WriteMarker(version: unsafeVersion, Path.Combine(UpdatesDir, "whatever", "patched-agent.msi"),
            Sha256Hex(Encoding.UTF8.GetBytes("irrelevant")));
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);

        NewApplier(currentVersion: "0.13.20", health, launcher).Apply();

        Assert.Empty(launcher.Calls);
        Assert.False(File.Exists(PendingFile));
        Assert.True(IsDegraded(health, "marker_version_unsafe"));
    }

    // -------------------------------------------------------------------------
    // A real junctioned installer path: the per-version directory itself
    // replaced with an NTFS junction into an attacker-controlled directory
    // holding its own same-named, correctly-hashed patched-agent.msi. String
    // equality against the expected path passes (Path.GetFullPath does not
    // resolve reparse points) — only the reparse-point-chain check catches this,
    // which is why the exact-match check alone is not sufficient. Windows-only,
    // real reparse point, per repo convention (see
    // ExtensionRemovalLogicTests.RealJunctionAtExtensionDir_IsRefused_AndLeftIntact).
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_JunctionedInstallerVersionDirectory_IsRefused_AndLauncherIsNeverInvoked()
    {
        if (!OperatingSystem.IsWindows()) return;

        Directory.CreateDirectory(UpdatesDir);
        var junctionTarget = Path.Combine(_dir, "junction-target");
        Directory.CreateDirectory(junctionTarget);
        var evilBytes = Encoding.UTF8.GetBytes("attacker installer via junction");
        var evilMsiInTarget = Path.Combine(junctionTarget, "patched-agent.msi");
        File.WriteAllBytes(evilMsiInTarget, evilBytes);

        var versionDir = Path.Combine(UpdatesDir, "9.9.9");
        var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe",
            $"/c mklink /J \"{versionDir}\" \"{junctionTarget}\"")
        { UseShellExecute = false, CreateNoWindow = true };
        using (var p = System.Diagnostics.Process.Start(psi)!) p.WaitForExit();
        Assert.True((File.GetAttributes(versionDir) & FileAttributes.ReparsePoint) != 0); // sanity

        var installerPath = Path.Combine(versionDir, "patched-agent.msi");
        WriteMarker(version: "9.9.9", installerPath, Sha256Hex(evilBytes));
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);

        NewApplier(currentVersion: "0.13.20", health, launcher).Apply();

        Assert.Empty(launcher.Calls);
        Assert.True((File.GetAttributes(versionDir) & FileAttributes.ReparsePoint) != 0, "the junction itself is left intact");
        Assert.True(File.Exists(evilMsiInTarget), "the attacker-controlled target is never touched");
        Assert.True(IsDegraded(health, "marker_installer_path_untrusted"));
    }

    // -------------------------------------------------------------------------
    // No-regression: a well-formed marker (exact BootstrapUpdater staging
    // shape) still applies exactly as before the new validation was added.
    // -------------------------------------------------------------------------
    [Fact]
    public void Apply_WellFormedMarker_PassesValidation_StillLaunchesExactlyAsBefore()
    {
        var bytes = Encoding.UTF8.GetBytes("real msi contents");
        var path = StageInstaller("0.13.21", bytes);
        WriteMarker("0.13.21", path, Sha256Hex(bytes));
        var health = NewHealth();
        var launcher = new FakeLauncher(returnValue: true);

        NewApplier(currentVersion: "0.13.20", health, launcher).Apply();

        Assert.Single(launcher.Calls);
        Assert.Equal(path, launcher.Calls[0]);
        Assert.False(IsDegraded(health, "marker_version_unsafe"));
        Assert.False(IsDegraded(health, "marker_installer_path_untrusted"));
    }

    // -------------------------------------------------------------------------
    // Pure unit coverage of the validation predicates, independent of Apply()'s
    // wider control flow.
    // -------------------------------------------------------------------------
    [Theory]
    [InlineData("0.13.21", true)]
    [InlineData("9.9.9-rc1", true)]
    [InlineData("", false)]
    [InlineData(" ", false)]
    [InlineData(".", false)]
    [InlineData("..", false)]
    [InlineData("a/b", false)]
    [InlineData("a\\b", false)]
    [InlineData("C:evil", false)]
    [InlineData("NUL", false)]
    [InlineData("nul", false)]
    [InlineData("COM9", false)]
    [InlineData("COM9.txt", false)]
    // PAT-1339 non-author review: these six are rejected by the explicit
    // Windows-invalid character set rather than Path.GetInvalidFileNameChars(),
    // which is host-dependent -- on macOS it returns only '\0' and '/', so
    // every case below would have WRONGLY passed on this machine while being
    // rejected in production. Since the suite is routinely run cross-target
    // (AGENTS.md), that would have made a macOS green run dishonest evidence
    // about a security check. They must fail identically on both hosts.
    [InlineData("ver<sion", false)]
    [InlineData("ver>sion", false)]
    [InlineData("ver\"sion", false)]
    [InlineData("ver|sion", false)]
    [InlineData("ver?sion", false)]
    [InlineData("ver*sion", false)]
    [InlineData("ver\u0001sion", false)]  // control character
    [InlineData("ver\tsion", false)]       // tab is a control character too
    // Windows strips trailing dots and spaces from a path component, so these
    // resolve on disk to something other than the string that was validated.
    // Rejected outright rather than relying on canonicalisation cancelling the
    // divergence out. (PAT-1339 non-author review finding.)
    [InlineData("9.9.9 ", false)]
    [InlineData("9.9.9.", false)]
    [InlineData("9.9.9  ", false)]
    public void IsSafeVersionSegment_MatchesExpectedShape(string? version, bool expected)
    {
        Assert.Equal(expected, PendingUpdateApplier.IsSafeVersionSegment(version));
    }

    private sealed class FakeLauncher(bool returnValue) : IPendingUpdateLauncher
    {
        public List<string> Calls { get; } = new();

        public bool LaunchDetached(string installerPath)
        {
            Calls.Add(installerPath);
            return returnValue;
        }
    }
}
