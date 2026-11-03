// DEPRECATED — PAT-1531: legacy package status and execution source retained for
// reference only; excluded from the Windows assurance-only Service build.
using Patched.Engine;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Patched.Shared.Paths;
using Patched.Verifier;

namespace Patched.Service;

/// <summary>
/// Collects installed-app state for the allowlisted apps and computes
/// AppEntry records to populate update-status.json.
/// The winget COM engine drives version resolution; the Authenticode verifier
/// runs fail-closed before any install (PAT-305).
/// </summary>
internal sealed class InventoryCollector
{
    /// <summary>Platform key used to match per-app update-policy overrides (PAT-381).</summary>
    private const string PolicyPlatform = "windows";

    private readonly ILogger<InventoryCollector> _log;
    private readonly AllowlistLoader             _allowlist;
    private readonly IPackageEngine              _engine;
    private readonly AuthenticodeVerifier        _verifier;

    public InventoryCollector(
        ILogger<InventoryCollector> log,
        AllowlistLoader             allowlist,
        IPackageEngine              engine,
        AuthenticodeVerifier        verifier)
    {
        _log         = log;
        _allowlist   = allowlist;
        _engine      = engine;
        _verifier    = verifier;
    }

    /// <summary>
    /// Collect status for all (or a named subset) of the allowlist.
    /// In Deploy mode, verifies + installs; in Scan/ScanOnly mode, just reads versions.
    /// The per-tenant app-update policy (PAT-381) gates installs per app; a null
    /// policy leaves every managed app enabled (fail-open, mirroring macOS).
    /// The blocking-process policy (PAT-296) controls behaviour when a running app
    /// must be closed before it can be updated.
    /// </summary>
    public async Task<IReadOnlyList<AppEntry>> CollectAsync(
        IReadOnlyList<string>?                              targetLabels,
        RunMode                                             mode,
        PerAppPatchPolicy?                                  policy,
        CancellationToken                                   ct,
        AgentConfig                                         config,
        BlockingProcessPolicy?                              blockingPolicy   = null,
        int                                                 deviceRing       = 3,
        IReadOnlyDictionary<string, RingPromotion>?         ringPromotions   = null,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, ScopedRingPromotion>>? ringPromotionsScoped = null,
        IReadOnlyDictionary<string, IReadOnlyList<string>>? blockedVersions  = null)
    {
        // PAT-2245: the PAT-1061 install-freshness gate and the PAT-495 per-label
        // SHA-256 pin were retired with the signed feed that backed them. The legacy
        // app-execution gate and mandatory Authenticode verification below remain;
        // this whole file is excluded from the shipping Service.
        var effectiveMode = mode is RunMode.Deploy or RunMode.ScanAndInstall
            ? LegacyAppExecutionGate.Allows(config)
                ? mode
                : DenyLegacyAppExecution(mode)
            : mode;

        var entries   = _allowlist.Entries;
        var toProcess = targetLabels is { Count: > 0 }
            ? entries.Where(e => targetLabels.Contains(e.Label, StringComparer.Ordinal)).ToList()
            : entries;

        var results = new List<AppEntry>(toProcess.Count);

        foreach (var entry in toProcess)
        {
            ct.ThrowIfCancellationRequested();
            var appEntry = await ProcessEntryAsync(entry, effectiveMode, policy,
                blockingPolicy ?? BlockingProcessPolicy.Defaults, ct,
                deviceRing, ringPromotions, ringPromotionsScoped, blockedVersions);
            results.Add(appEntry);
        }

        return results;
    }

    /// <summary>
    /// PAT-1481's final daemon seam for direct/Self Service deployment,
    /// scheduled updates and mandatory-install execution. A denied executor
    /// remains a scan so inventory and assurance observations are retained.
    /// </summary>
    private RunMode DenyLegacyAppExecution(RunMode requestedMode)
    {
        _log.LogWarning(
            "Legacy app-execution gate disabled — downgrading {Mode} to scan-only; existing tier, ring and verification gates remain required when enabled",
            requestedMode);
        return RunMode.ScanOnly;
    }

    private async Task<AppEntry> ProcessEntryAsync(
        WindowsAllowlistEntry                               entry,
        RunMode                                             mode,
        PerAppPatchPolicy?                                  policy,
        BlockingProcessPolicy                               blockingPolicy,
        CancellationToken                                   ct,
        int                                                 deviceRing      = 3,
        IReadOnlyDictionary<string, RingPromotion>?         ringPromotions  = null,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, ScopedRingPromotion>>? ringPromotionsScoped = null,
        IReadOnlyDictionary<string, IReadOnlyList<string>>? blockedVersions = null)
    {
        _log.LogDebug("Processing {Label} ({WingetId})", entry.Label, entry.WingetId);

        PackageCheckResult check;
        try
        {
            check = await _engine.CheckAsync(entry.WingetId, ct);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Version check failed for {Label}", entry.Label);
            return BuildEntry(entry, AppState.Error, installedVersion: null,
                availableVersion: null, lastAction: "error",
                message: ex.Message);
        }

        if (!check.IsInstalled)
        {
            return BuildEntry(entry, AppState.NotInstalled,
                installedVersion: null, availableVersion: check.AvailableVersion,
                lastAction: "not_installed");
        }

        var state = check.HasUpdate ? AppState.UpdateAvailable : AppState.UpToDate;

        if (mode == RunMode.ScanOnly)
        {
            return BuildEntry(entry, state,
                installedVersion:  check.InstalledVersion,
                availableVersion:  check.AvailableVersion,
                lastAction:        check.HasUpdate ? "update_available" : "already_current",
                verifiedSigner:    null);   // skip verification on scan-only
        }

        if (mode == RunMode.ScanAndInstall && !check.HasUpdate)
        {
            return BuildEntry(entry, AppState.UpToDate,
                installedVersion: check.InstalledVersion,
                availableVersion: check.AvailableVersion,
                lastAction:       "already_current");
        }

        // PAT-381: per-tenant app-update policy gate (parity with macOS
        // patched-update.sh policy_allows). Reached only when an install would
        // otherwise happen (Deploy, or ScanAndInstall with an update available).
        // A disabled app is reported with its true state but NOT installed; the
        // policy decision is recorded in provenance (skipped_policy + source).
        if (!PerAppPatchPolicy.AllowsOrDefault(policy, PolicyPlatform, entry.WingetId, entry.Label))
        {
            var src = policy!.SourceFor(PolicyPlatform, entry.WingetId, entry.Label);
            _log.LogInformation(
                "Policy gate: {Label} ({WingetId}) updates disabled (source={Source}) — skipping install",
                entry.Label, entry.WingetId, src);
            return BuildEntry(entry, state,
                installedVersion:  check.InstalledVersion,
                availableVersion:  check.AvailableVersion,
                lastAction:        check.HasUpdate ? "update_available" : "already_current",
                policySource:      src,
                policyDisabled:    true);
        }

        // PAT-508: blocked-version gate. If the available version is in blocked_versions
        // for this label, refuse to install. The kill switch is activated by pushing a
        // signed agent-config update containing the blocked version. Fail-open: null
        // blockedVersions = no versions blocked.
        //
        // PAT-898: a blocked version is a verification refusal, so it is reported with the
        // shared VerificationFailed state (the same representation the macOS daemon uses)
        // carrying failure_reason: blocked_version and last_action: version_blocked. This
        // keeps the update-status contract platform-neutral: one state for a refused
        // install, distinguished by failure_reason, rather than a Windows-only state.
        if (blockedVersions is not null
            && blockedVersions.TryGetValue(entry.Label, out var blockedList)
            && !string.IsNullOrEmpty(check.AvailableVersion)
            && blockedList.Any(b => string.Equals(b, check.AvailableVersion, StringComparison.OrdinalIgnoreCase)))
        {
            _log.LogError(
                "PATCHED_VERIFICATION_FAILED label={Label} version={Version} reason=blocked_version "
                + "— install refused (blocked in agent-config)",
                entry.Label, check.AvailableVersion);
            return BuildEntry(entry, AppState.VerificationFailed,
                installedVersion:  check.InstalledVersion,
                availableVersion:  check.AvailableVersion,
                lastAction:        "version_blocked",
                failureReason:     FailureReason.BlockedVersion);
        }

        // PAT-296: blocking-process policy — check whether a blocking process deferral
        // is still within its postpone window. If so, skip this install run.
        // The winget engine drives blocking-process detection; we honour the policy
        // before handing off to it to avoid a force-quit the tenant did not authorise.
        //
        // Deferral window check: if a deferral was recorded and the defer_window_seconds
        // have not elapsed, skip this app and report its current scan state. The agent
        // records a new deferral on first encounter of a blocking process; subsequent
        // runs within the window are silently skipped (no further deferral credit spent).
        var deferralFile  = PathConstants.BlockingDeferralFile(entry.Label);
        var deferralState = BlockingDeferralState.Load(deferralFile);
        var deferWindow   = TimeSpan.FromSeconds(blockingPolicy.EffectiveDeferWindowSeconds);

        if (deferralState.Count > 0 && !deferralState.DeferWindowElapsed(deferWindow))
        {
            // Still within the deferral postpone window — skip this run.
            _log.LogInformation(
                "BlockingProcess: {Label} within defer window (count={Count}/{Max}) — skipping install",
                entry.Label, deferralState.Count, blockingPolicy.EffectiveMaxDeferrals);
            return BuildEntry(entry, state,
                installedVersion:  check.InstalledVersion,
                availableVersion:  check.AvailableVersion,
                lastAction:        check.HasUpdate ? "update_available" : "already_current");
        }

        // PAT-506: deployment ring gate — skip install if version not yet approved for this ring.
        if (!RingPromotionGate.Allows(entry.Label, "windows", deviceRing, ringPromotionsScoped, ringPromotions))
        {
            _log.LogInformation(
                "Ring gate: {Label} device_ring={Ring} — skipping install",
                entry.Label, deviceRing);
            return BuildEntry(entry, state,
                installedVersion:  check.InstalledVersion,
                availableVersion:  check.AvailableVersion,
                lastAction:        check.HasUpdate ? "update_available" : "already_current",
                ringGated:         true);
        }

        // Deploy path — verify before ANY install (PAT-305, fail-closed).
        //
        // PAT-858: resolve/verify/hash-check wrapped in one try/catch so a failure
        // processing THIS entry (a file locked by AV, a disk hiccup, an installer
        // deleted mid-cycle, a transient winget/choco CLI error) degrades to an Error
        // state for this app only and returns normally from ProcessEntryAsync — it must
        // never propagate out. CollectAsync's foreach has no try/catch of its own, so an
        // unhandled exception here would previously abort every remaining app in this
        // cycle, and (before the RunCycleSafeAsync wrapper added in Worker.cs) could
        // crash the whole BackgroundService.
        string installPath;
        VerificationResult verification;
        try
        {
            var resolvedPath = await _engine.ResolveInstallPathAsync(entry.WingetId, ct);
            if (resolvedPath is null)
            {
                _log.LogWarning("Could not resolve install path for {Label}; skipping", entry.Label);
                return BuildEntry(entry, AppState.Error,
                    installedVersion:  check.InstalledVersion,
                    availableVersion:  check.AvailableVersion,
                    lastAction:        "error",
                    message:           "Could not resolve package installer path");
            }
            installPath = resolvedPath;

            verification = _verifier.Verify(installPath, entry.ExpectedPublisher);
            if (!verification.IsValid)
            {
                _log.LogError("Authenticode verification FAILED for {Label}: {Reason} — blocking install",
                    entry.Label, verification.FailureReason);
                return BuildEntry(entry, AppState.VerificationFailed,
                    installedVersion:  check.InstalledVersion,
                    availableVersion:  check.AvailableVersion,
                    lastAction:        "verification_failed",
                    failureReason:     verification.FailureReason,
                    verifiedSigner:    verification.ActualPublisher);
            }

            _log.LogInformation("Verification OK for {Label}: publisher={Publisher}",
                entry.Label, verification.ActualPublisher);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Resolve/verify failed for {Label}", entry.Label);
            return BuildEntry(entry, AppState.Error,
                installedVersion:  check.InstalledVersion,
                availableVersion:  check.AvailableVersion,
                lastAction:        "error",
                message:           ex.Message);
        }

        // Install — pass the resolved blocking-process action so the engine can honour
        // the tenant's policy when a blocking process is encountered. The engine is
        // responsible for acting on the action; the agent never force-quits directly.
        // Safe default: NotifyOnly (engine skips rather than force-quitting).
        try
        {
            var installResult = await _engine.InstallAsync(
                entry.WingetId,
                ct,
                blockingAction: blockingPolicy.ResolvedAction,
                // H6: pin to the exact version we resolved + verified above so the
                // install cannot pull a different/newer artifact than was verified.
                pinnedVersion:  check.AvailableVersion);
            var newVersion = installResult.InstalledVersion ?? check.AvailableVersion;

            // PAT-296: successful install — reset deferral count for this label.
            BlockingDeferralState.Reset(deferralFile);

            return BuildEntry(entry, AppState.UpToDate,
                installedVersion:  newVersion,
                availableVersion:  check.AvailableVersion,
                lastAction:        check.IsInstalled ? "already_current" : "installed",
                verifiedSigner:    verification.ActualPublisher);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Install failed for {Label}", entry.Label);
            return BuildEntry(entry, AppState.Error,
                installedVersion:  check.InstalledVersion,
                availableVersion:  check.AvailableVersion,
                lastAction:        "error",
                message:           ex.Message,
                verifiedSigner:    verification.ActualPublisher);
        }
    }

    private static AppEntry BuildEntry(
        WindowsAllowlistEntry entry,
        AppState              state,
        string?               installedVersion  = null,
        string?               availableVersion  = null,
        string?               lastAction        = null,
        FailureReason?        failureReason     = null,
        string?               verifiedSigner    = null,
        string?               message           = null,
        string?               policySource      = null,
        bool                  policyDisabled    = false,
        bool                  ringGated         = false)
    {
        return new AppEntry
        {
            Label            = entry.Label,
            Name             = entry.Name,
            State            = state,
            InstalledVersion = installedVersion,
            AvailableVersion = availableVersion,
            LastAction       = lastAction,
            LastActionAt     = DateTimeOffset.UtcNow,
            FailureReason    = failureReason,
            VerifiedSigner   = verifiedSigner,
            Message          = message,
            WingetId         = entry.WingetId,
            PolicySource     = policySource,
            PolicyDisabled   = policyDisabled,
            RingGated        = ringGated,
        };
    }
}
