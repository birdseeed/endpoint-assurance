using Microsoft.Extensions.Logging.Abstractions;
using Patched.Engine;
using Patched.Service;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Patched.Verifier;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-858: per-entry isolation in InventoryCollector.ProcessEntryAsync.
///
/// Root cause: ResolveInstallPathAsync/Verify were unguarded, so one bad
/// entry (a file locked by AV, a disk hiccup, a transient CLI failure) could throw
/// out of CollectAsync's foreach — which has no try/catch of its own — aborting
/// every remaining app in the same cycle, and (before Worker.cs's RunCycleSafeAsync
/// wrapper) crashing the whole BackgroundService.
///
/// Strategy: a fake IPackageEngine throws from ResolveInstallPathAsync for one
/// specific packageId and behaves normally for another, exercising the new
/// try/catch around the resolve/verify block directly — no winget.exe,
/// no real Authenticode signature needed. AuthenticodeVerifier itself is a sealed,
/// Windows-only class with no test seam; the "good" entry's installer path points
/// at a file that doesn't exist, so its own verification fails gracefully (a normal
/// VerificationFailed result, not a throw) — this test only needs to prove that
/// entry is *still reported*, not that it succeeds.
/// </summary>
public sealed class InventoryCollectorTests : IDisposable
{
    private readonly string _allowlistPath;

    public InventoryCollectorTests()
    {
        _allowlistPath = Path.Combine(Path.GetTempPath(), $"patched-inventory-test-allowlist-{Guid.NewGuid():N}.json");
        File.WriteAllText(_allowlistPath, """
            [
              {"label":"bad","name":"Bad App","winget_id":"Bad.App","expected_publisher":"Bad Publisher"},
              {"label":"good","name":"Good App","winget_id":"Good.App","expected_publisher":"Good Publisher"}
            ]
            """);
    }

    public void Dispose()
    {
        try { File.Delete(_allowlistPath); } catch { /* best-effort */ }
        try { File.Delete(_allowlistPath + ".sig"); } catch { /* best-effort */ }
    }

    private sealed class ThrowsForOneEngine : IPackageEngine
    {
        private readonly string _throwForWingetId;

        public ThrowsForOneEngine(string throwForWingetId) => _throwForWingetId = throwForWingetId;

        public Task<PackageCheckResult> CheckAsync(string packageId, CancellationToken ct) =>
            Task.FromResult(new PackageCheckResult
            {
                PackageId        = packageId,
                IsInstalled      = true,
                InstalledVersion = "1.0.0",
                AvailableVersion = "2.0.0",
            });

        public Task<string?> ResolveInstallPathAsync(string packageId, CancellationToken ct)
        {
            if (packageId == _throwForWingetId)
                throw new IOException($"simulated staging failure for {packageId}");
            return Task.FromResult<string?>(Path.Combine(Path.GetTempPath(), "patched-inventory-test-nonexistent.exe"));
        }

        public Task<PackageInstallResult> InstallAsync(
            string packageId, CancellationToken ct,
            BlockingProcessAction blockingAction = BlockingProcessAction.NotifyOnly,
            string? pinnedVersion = null) =>
            Task.FromResult(new PackageInstallResult { PackageId = packageId, Success = true, InstalledVersion = pinnedVersion });
    }

    // Sets PATCHED_ALLOW_UNSIGNED_ALLOWLIST=1 for the load, mirroring
    // Engine.Tests/AllowlistTestSupport.cs's UnsignedAllowlistScope — no other test
    // in this assembly currently touches AllowlistLoader, so a lightweight
    // try/finally here (rather than a shared xunit collection) is sufficient.
    private static IDisposable UnsignedAllowlistScope()
    {
        const string var = "PATCHED_ALLOW_UNSIGNED_ALLOWLIST";
        var previous = Environment.GetEnvironmentVariable(var);
        Environment.SetEnvironmentVariable(var, "1");
        return new DisposableAction(() => Environment.SetEnvironmentVariable(var, previous));
    }

    private sealed class DisposableAction(Action onDispose) : IDisposable
    {
        public void Dispose() => onDispose();
    }

    [Fact]
    public async Task CollectAsync_OneEntryThrowsDuringResolve_OtherEntryStillReported()
    {
        using var _ = UnsignedAllowlistScope();

        var allowlist  = new AllowlistLoader(NullLogger<AllowlistLoader>.Instance, _allowlistPath);
        var engine     = new ThrowsForOneEngine(throwForWingetId: "Bad.App");
        var verifier   = new AuthenticodeVerifier(NullLogger<AuthenticodeVerifier>.Instance);
        var collector  = new InventoryCollector(
            NullLogger<InventoryCollector>.Instance, allowlist, engine, verifier);

        var results = await collector.CollectAsync(
            targetLabels: null, RunMode.Deploy, policy: null, CancellationToken.None);

        // Both entries must be present — the throwing entry must not have skipped
        // (or worse, aborted) processing of the other one.
        Assert.Equal(2, results.Count);

        var bad = results.Single(r => r.Label == "bad");
        Assert.Equal(AppState.Error, bad.State);
        Assert.Equal("error", bad.LastAction);
        Assert.Contains("simulated staging failure", bad.Message);

        var good = results.Single(r => r.Label == "good");
        // "good"'s ResolveInstallPathAsync always returns the same nonexistent path
        // (see ThrowsForOneEngine), so its own Authenticode verification deterministically
        // fails gracefully — File.Exists is false, AuthenticodeVerifier.Verify returns
        // Blocked_MissingExpectedSigner without throwing — landing in the ordinary
        // "Authenticode verification FAILED" branch, NOT the new catch block. Asserting
        // the exact state (rather than just "not equal to the bad entry's message")
        // proves the two entries took genuinely different code paths: "bad" threw and
        // was caught, "good" completed its own normal verification-failure branch.
        Assert.Equal(AppState.VerificationFailed, good.State);
        Assert.Equal("verification_failed", good.LastAction);
        Assert.NotEqual(AppState.Error, good.State);
        Assert.DoesNotContain("simulated staging failure", good.Message ?? "");
    }

    [Fact]
    public async Task CollectAsync_NoThrows_BothEntriesReportNormally()
    {
        using var _ = UnsignedAllowlistScope();

        var allowlist = new AllowlistLoader(NullLogger<AllowlistLoader>.Instance, _allowlistPath);
        // A sentinel packageId that never matches either allowlisted winget_id, so
        // neither entry throws.
        var engine    = new ThrowsForOneEngine(throwForWingetId: "Nonexistent.Package");
        var verifier  = new AuthenticodeVerifier(NullLogger<AuthenticodeVerifier>.Instance);
        var collector = new InventoryCollector(
            NullLogger<InventoryCollector>.Instance, allowlist, engine, verifier);

        var results = await collector.CollectAsync(
            targetLabels: null, RunMode.Deploy, policy: null, CancellationToken.None);

        Assert.Equal(2, results.Count);
        Assert.DoesNotContain(results, r => r.LastAction == "error");
    }

}
