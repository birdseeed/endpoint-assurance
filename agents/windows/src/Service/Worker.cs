using Patched.Shared.Auth;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Patched.Shared.Paths;

namespace Patched.Service;

/// <summary>
/// Main service loop. Runs on a configurable schedule (default 03:00 daily)
/// and also responds to trigger files dropped by the tray app.
///
/// Assurance sequencing:
///   1. Ensure trigger directory exists and has correct DACL  (PAT-307)
///   2. Collect and upload inventory evidence
///   3. Refresh posture and check agent health
///   4. Write update-status.json atomically
/// </summary>
internal sealed class PatchedWorker : BackgroundService
{
    private static readonly TimeSpan DefaultScanInterval = TimeSpan.FromHours(24);
    private static readonly TimeSpan TriggerPollInterval  = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan QueueRetryTimeout = TimeSpan.FromSeconds(5);

    // PAT-1203: how often AgentEnroller.WaitForRecoveryAsync re-reads the
    // enrollment-token sources while suspended. Deliberately much longer than
    // TriggerPollInterval — dropping a fresh single-use enrollment token is a
    // rare, deliberate admin action (nothing like the on-box user triggers
    // TriggerPollInterval exists to catch quickly), and every successful
    // refresh costs one real HTTP call to /v1/enrol, unlike the cheap local
    // File.Exists() the revocation side of the same wait loop performs every
    // tick. 5 minutes bounds recovery to "well within the same admin session"
    // without probing Credential Manager / disk / registry needlessly for the
    // far more common revoked-but-already-enrolled suspended case (which
    // RefreshEnrollmentToken also short-circuits out of directly).
    private static readonly TimeSpan EnrollmentTokenRecheckInterval = TimeSpan.FromMinutes(5);

    // PAT-1766: while the device is not provisioned (no usable credentials and no
    // enrolment token), the startup gate re-runs the credential load on the same
    // 5-minute cadence as the suspended token recheck: these are local reads, and a
    // token or credential drop is a deliberate admin action. The not-provisioned
    // report is repeated once a day so it stays in the retained file logs of a
    // service that runs for weeks in this state.
    private static readonly TimeSpan ProvisioningReminderInterval = TimeSpan.FromHours(24);

    // PAT-1269: how often the tick loop re-runs BootstrapUpdater.CheckAndStageAsync
    // after the one-shot startup check. Before this, a running endpoint never
    // discovered a new release without a restart — confirmed live on WIN-STAGING,
    // where a manual restart staged windows-agent-v0.13.24 immediately and nothing
    // in this loop ever called the check again.
    //
    // Weighed against the other two cadences already on this loop: TriggerPollInterval
    // (15s) is for local, cheap, no-network work (drain a trigger dir, check a
    // suspended marker file) — running an authenticated GET that often would be pure
    // waste for a check whose answer changes at most once per release. The scheduled
    // full run (_nextScheduledRun, driven by tenant-configured scan_cadence) is the
    // wrong anchor in the other direction: cadence can be daily or weekly per tenant,
    // and tying self-update to it would leave a running endpoint on a stale agent
    // build for up to a week even though this check costs far less than a full scan
    // (one small signed-envelope GET, versus a full inventory collect + enforcement
    // pass). An hour is the fastest interval ScanCadenceToInterval below already
    // treats as a legitimate polling rate ("hourly" is real tenant-facing
    // vocabulary, not invented for this), so it reuses an existing convention rather
    // than adding a new one, and it bounds how far a running endpoint's agent build
    // can drift from the latest release to about an hour (plus however long the
    // apply-triggering restart takes — see the PAT-1269 ticket's Part 2 analysis) —
    // regardless of the tenant's own scan_cadence.
    private static readonly TimeSpan BootstrapUpdateCheckInterval = TimeSpan.FromHours(1);

    private readonly ILogger<PatchedWorker>  _log;
    private readonly CredentialStore         _creds;
    private readonly AgentEnroller           _enroller;
    private readonly TriggerAcl              _triggerAcl;
    private readonly TriggerWatcher          _triggerWatcher;
    private readonly StatusWriter            _statusWriter;
    private readonly ProvenancePoster        _provenance;
    private readonly AuditEventShipper       _auditEvents;
    private readonly InventoryPoster         _inventoryPoster;
    private readonly AgentHealthStore        _agentHealth;
    private readonly AssuranceCapabilityHealth _assuranceCapabilityHealth;
    private readonly AgentConfigManager      _config;
    private readonly DecommissionRunner      _decommission;
    private readonly PostureFetcher          _posture;
    private readonly OsUpdateChecker         _osUpdateChecker;
    private readonly AdminEnforcer           _adminEnforcer;
    private readonly BootstrapUpdater        _bootstrapUpdater;
    private readonly PendingUpdateApplier    _pendingUpdateApplier;
    private readonly InstallIntegrityGate    _installIntegrity;
    private readonly AppAllowlistEnforcer    _appAllowlistEnforcer;
    private readonly BrowserExtensionBlocklistEnforcer _extensionBlocklistEnforcer;
    private readonly BrowserExtensionRemover  _extensionRemover;

    // Scheduled-run wall-clock: aim for 03:00 local time.
    private DateTimeOffset _nextScheduledRun;

    // PAT-1269: next periodic self-update check. Seeded one BootstrapUpdateCheckInterval
    // out from construction (not "now") so the very next tick doesn't immediately
    // re-run a check that startup (ExecuteAsync, below) is about to do anyway.
    //
    // Compared and seeded in UTC (DateTimeOffset.UtcNow), unlike _nextScheduledRun
    // above (DateTimeOffset.Now, local) — deliberately different, not an
    // oversight. _nextScheduledRun has a genuine wall-clock anchor (it targets
    // 03:00 local time via ComputeNextScheduledRun), so local time is the correct
    // frame for it. This field has no such anchor: it only ever needs "has one
    // BootstrapUpdateCheckInterval elapsed since the last check", a pure duration
    // comparison with nothing to do with the local wall clock. Using local time
    // for a duration-only comparison exposes it to DST transitions — the clock
    // can jump forward or back under it, making the comparison skip a check or
    // fire one early/twice. UTC has no DST, so the elapsed-time comparison stays
    // correct across every transition. Do not "fix" this back to .Now to match
    // the neighbouring field above; the two fields are solving different problems.
    private DateTimeOffset _nextBootstrapUpdateCheck;

    public PatchedWorker(
        ILogger<PatchedWorker>  log,
        CredentialStore         creds,
        AgentEnroller           enroller,
        TriggerAcl              triggerAcl,
        TriggerWatcher          triggerWatcher,
        StatusWriter            statusWriter,
        ProvenancePoster        provenance,
        AuditEventShipper       auditEvents,
        InventoryPoster         inventoryPoster,
        AgentHealthStore        agentHealth,
        AssuranceCapabilityHealth assuranceCapabilityHealth,
        AgentConfigManager      config,
        DecommissionRunner      decommission,
        PostureFetcher          posture,
        OsUpdateChecker         osUpdateChecker,
        AdminEnforcer           adminEnforcer,
        BootstrapUpdater        bootstrapUpdater,
        PendingUpdateApplier    pendingUpdateApplier,
        InstallIntegrityGate    installIntegrity,
        AppAllowlistEnforcer    appAllowlistEnforcer,
        BrowserExtensionBlocklistEnforcer extensionBlocklistEnforcer,
        BrowserExtensionRemover extensionRemover)
    {
        _log                  = log;
        _creds                = creds;
        _enroller             = enroller;
        _triggerAcl           = triggerAcl;
        _triggerWatcher       = triggerWatcher;
        _statusWriter         = statusWriter;
        _provenance           = provenance;
        _auditEvents          = auditEvents;
        _inventoryPoster      = inventoryPoster;
        _agentHealth          = agentHealth;
        _assuranceCapabilityHealth = assuranceCapabilityHealth;
        _config               = config;
        _decommission         = decommission;
        _posture              = posture;
        _osUpdateChecker      = osUpdateChecker;
        _adminEnforcer        = adminEnforcer;
        _bootstrapUpdater     = bootstrapUpdater;
        _pendingUpdateApplier = pendingUpdateApplier;
        _installIntegrity     = installIntegrity;
        _appAllowlistEnforcer = appAllowlistEnforcer;
        _extensionBlocklistEnforcer = extensionBlocklistEnforcer;
        _extensionRemover     = extensionRemover;

        _nextScheduledRun = ComputeNextScheduledRun(DateTimeOffset.Now);
        _nextBootstrapUpdateCheck = DateTimeOffset.UtcNow.Add(BootstrapUpdateCheckInterval);
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _log.LogInformation("Patched Agent starting");

        // PAT-2399: checked first, before the provisioning wait below can park this method
        // for days, so an untrusted install directory is in the log and in agent-health from
        // the first second. It gates nothing here; each privileged step below asks again.
        _installIntegrity.Verify("privileged agent actions");

        // PAT-1766: a device with no identity (no usable credentials, no enrolment
        // token) used to make the process exit 2 before the host started, so an MSI
        // install or upgrade onto it failed StartServices (1920) and rolled back
        // (1603): a device that lost an unused token could never self-update onto the
        // release that fixes it. The service now starts, reports the not-provisioned
        // state and waits here, before the suspension gate, enrolment, decommission,
        // self-update and collection, until a token or usable credentials appear.
        // Nothing is collected or sent while it waits. Runs before the suspension gate
        // so a device with a stale suspended marker and no identity is reported as
        // unprovisioned, and so a token found here reaches that gate's
        // enrol-past-the-marker path.
        await WaitForProvisioningAsync(_creds, _agentHealth, _log, EnrollmentTokenRecheckInterval, ProvisioningReminderInterval, ct)
            .ConfigureAwait(false);

        // PAT-1042 (revises PAT-544): this used to halt the loop forever via
        // Task.Delay(Timeout.Infinite) — a one-way latch. AgentConfigManager
        // (registered as its own independent BackgroundService in Program.cs,
        // NOT nested inside this one) already polls agent-config every 15
        // minutes regardless of this branch, and AgentConfigFetcher.VerifyAndCache
        // already calls CredentialStore.ClearSuspended() the moment a
        // signature-verified 200 arrives — so the platform reinstating this
        // device was always detectable. The bug was that THIS loop never woke
        // up to notice: even after the marker was gone, PatchedWorker stayed
        // parked forever and enforcement/collection never resumed without a
        // full service restart.
        //
        // Corrected design: quarantine-but-keep-checking-in. While suspended,
        // collection/enforcement/upload (RunCycleAsync) still does not run —
        // that part of the old posture is intentionally unchanged — but instead
        // of sleeping forever this loop re-checks IsSuspended (a cheap local
        // File.Exists, not a network call) at the same cadence as the trigger
        // poll and falls through into the normal enrollment + run-cycle flow
        // below the moment the marker is gone. It deliberately does NOT call
        // AgentConfigFetcher itself: that fetch is already running
        // unconditionally from AgentConfigManager's own loop, and
        // AgentConfigFetcher has no internal request-serialisation lock (unlike
        // the mkdir-based lock in macOS's patched-fetch-config.sh), so a second
        // concurrent caller here would only double the request rate and risk a
        // race, not add any reachability this loop didn't already have via
        // AgentConfigManager.
        //
        // PAT-1203: the wait is now delegated to AgentEnroller.WaitForRecoveryAsync,
        // which does everything described above for the revocation cause
        // unchanged, AND ALSO retries enrollment when a fresh single-use token
        // appears — the one cause the pre-PAT-1203 loop could never clear on
        // its own (an enrollment-suspended device has no bearer token, so
        // AgentConfigManager's poll can never authenticate). This also closes
        // a restart gap: IsSuspended is checked here on every ExecuteAsync
        // entry, so a device that hits terminal enrollment failure, gets
        // suspended, and is then restarted (box reboot, manual service
        // restart) used to land right back in an unrecoverable wait here too;
        // now the same recovery path applies regardless of whether the
        // process stayed up or was restarted. See AgentEnroller.WaitForRecoveryAsync
        // for the full design.
        await WaitOutSuspensionAsync(_creds, _enroller, _log, TriggerPollInterval, EnrollmentTokenRecheckInterval, ct)
            .ConfigureAwait(false);

        // Attempt enrollment if a single-use token is present but no bearer-token
        // exists yet. On transient failure we proceed and retry each poll.
        //
        // PAT-1203 (revises the original comment here, "On terminal failure the
        // device enters suspended state and the service halts."): a terminal
        // 410/401 now enters the same suspended-and-waiting state as the block
        // above instead of halting — AgentEnroller.WaitForRecoveryAsync blocks
        // here until either an admin drops a fresh token that enrolls
        // successfully, or the process is cancelled for shutdown. Falls
        // through into normal startup (trigger dir, bootstrap check, first-run
        // scan, main loop) once recovered; never returns from ExecuteAsync.
        if (!await _enroller.TryEnrolAsync(ct).ConfigureAwait(false))
        {
            _log.LogError("Enrollment failed terminally on startup — device is now suspended; waiting for a fresh enrollment token instead of halting");
            await _enroller.WaitForRecoveryAsync(TriggerPollInterval, EnrollmentTokenRecheckInterval, ct).ConfigureAwait(false);
            _log.LogInformation("Enrollment retry succeeded — resuming normal startup sequence");
        }

        // Ensure the trigger directory exists with the correct DACL on every start.
        _triggerAcl.EnsureTriggerDirectory();

        // PAT-1110: decommission is the ONLY irreversible directive in the contract
        // and is checked before everything else below, including the bootstrap
        // update check — an operator-issued removal must not wait behind any other
        // startup work. Runs unconditionally (not tier-gated, not RunMode-gated) —
        // see DecommissionRunner's own doc comment for why.
        await RunDecommissionCheckSafeAsync(ct);

        // PAT-1261: apply any update BootstrapUpdater already staged on a PREVIOUS
        // start before checking for a NEW one below — see PendingUpdateApplier's
        // class doc comment for why this runs first (a marker left over from a
        // prior successful launch needs to see this restart's version match before
        // BootstrapUpdater's own "already staged" short-circuit gets a chance to
        // reason about it). Fail-safe — never throws, reports via AgentHealthStore.
        //
        // PAT-2399: applying a staged MSI and staging a new one both end in code running
        // as SYSTEM, so neither happens from an install directory that fails the check.
        // Re-read here rather than reusing the answer from the top of this method.
        var installTrusted = _installIntegrity.Verify("self-update apply and staging");
        if (installTrusted)
            _pendingUpdateApplier.Apply();

        // PAT-108: check for bootstrap update at service start. Fail-safe — any error
        // leaves the service running on the current version. PAT-1269: this start-time
        // check still runs unconditionally (a restart should pick up an update
        // promptly, not wait up to BootstrapUpdateCheckInterval) — the tick loop below
        // additionally re-runs this same check periodically so an endpoint that never
        // restarts still discovers new releases.
        if (installTrusted)
            _ = await _bootstrapUpdater.CheckAndStageAsync(ct).ConfigureAwait(false);

        // Proxy and WUA: WUA respects the system WinHTTP proxy by default, so
        // auto-detected proxies work without any extra wiring. The manual-proxy
        // case (DynamicWebProxy on the Patched HttpClient, PAT-309) cannot be
        // forwarded to the COM WUA session without setting IUpdateSession3.WebProxy
        // — a Windows-only COM interface not worth the complexity for a minority
        // configuration. Documented known gap; revisit if manual-proxy tenants
        // report WUA connectivity failures.

        // First-run scan only when fully enrolled (bearer token present).
        // If enrollment is still pending after a transient startup failure,
        // the main loop will retry on the next TriggerPollInterval tick.
        //
        // PAT-1760: also not while a suspended marker is present. Startup can now
        // reach this point with a marker still on disk (enrolment ran past a marker
        // that described no credentials, and clearing it failed); the loop's own
        // suspension gate handles that device on its first tick.
        //
        // PAT-1760 review: "fully enrolled" is DeviceCredentials.Present (usable bearer
        // token and HMAC secret), not a non-empty bearer token.
        if (DeviceCredentials.Present(_creds) && !_creds.IsSuspended)
        {
            await RunCycleSafeAsync(trigger: null, mode: RunMode.ScanOnly, ct);
        }
        else if (DeviceCredentials.Present(_creds))
        {
            _log.LogWarning("Suspended marker still present after startup; first-run scan deferred to the main loop's suspension gate");
        }
        else
        {
            _log.LogWarning("Enrollment pending (transient startup failure) — first-run scan deferred");
        }

        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(TriggerPollInterval, ct).ConfigureAwait(false);

            // PAT-1204: mid-run suspension re-check. The startup gate above (and the
            // enrollment-retry gate below) only catch suspension that already existed
            // before/at the moment those code paths ran; neither one is revisited once
            // this loop is past startup and actively ticking. A device revoked (401 ->
            // CredentialStore.MarkSuspended()) while the loop is mid-run — i.e. between
            // two iterations, not during a cycle already in flight — would otherwise
            // keep calling RunCycleSafeAsync (collection + enforcement) every tick until
            // a full service restart, even though AgentConfigManager's independent
            // background poll would eventually clear the marker on its own if the device
            // is reinstated. macOS doesn't have this gap: patched-update.sh /
            // patched-upload.sh are short-lived cron-triggered scripts that re-check the
            // suspended marker on every invocation, so every "run" naturally re-checks;
            // this loop is long-running, so it must re-check explicitly instead. Reusing
            // WaitOutSuspensionAsync (see below) keeps this symmetric with the startup
            // gate: same detection, same wait-for-recovery path, same log shape. Falls
            // through (no `continue`) into the rest of this tick once recovery
            // completes, exactly like the startup gate falls through into enrollment —
            // nothing below this point should be skipped once the device is no longer
            // suspended.
            await WaitOutSuspensionAsync(_creds, _enroller, _log, TriggerPollInterval, EnrollmentTokenRecheckInterval, ct)
                .ConfigureAwait(false);

            // PAT-1110: re-checked on every ~15s poll tick, independent of the
            // scheduled/deploy run cadence below (which can be up to 24h apart) —
            // mode="immediate" means "may remove itself on the next successful
            // verification of this directive", not "on the next scheduled scan".
            // Runs after the suspension gate above (same ordering as startup: wait
            // out suspension, then decommission) so a suspended-and-since-reinstated
            // device gets a fair decommission check on the same tick it resumes,
            // rather than the check being skipped by a stale suspension state.
            await RunDecommissionCheckSafeAsync(ct);

            // Retry enrollment if still pending from a transient startup failure.
            //
            // PAT-1203: a terminal failure here used to `break` out of this loop
            // entirely, which fell straight through to "Patched Agent stopping"
            // below and returned from ExecuteAsync — the same one-way latch as
            // the startup path above, just reached from the retry path instead.
            // Now it waits for recovery in place (see
            // AgentEnroller.WaitForRecoveryAsync) and `continue`s: on the next
            // tick, BearerToken is set (recovered) so this whole branch is
            // skipped and normal operation resumes.
            // PAT-1760 review: pending means no usable credential pair, the same rule as
            // AgentEnroller.TryEnrolAsync's early return, so this branch and that call
            // always agree on whether /v1/enrol is attempted.
            // PAT-1765: a usable token, the same IsNullOrWhiteSpace rule TryEnrolAsync applies.
            if (DeviceCredentials.HasEnrollmentToken(_creds) && !DeviceCredentials.Present(_creds))
            {
                if (!await _enroller.TryEnrolAsync(ct).ConfigureAwait(false))
                {
                    _log.LogError("Enrollment failed terminally in retry — device is now suspended; waiting for a fresh enrollment token instead of stopping the service");
                    await _enroller.WaitForRecoveryAsync(TriggerPollInterval, EnrollmentTokenRecheckInterval, ct).ConfigureAwait(false);
                    _log.LogInformation("Enrollment retry succeeded — suspended marker cleared, resuming normal operation");
                }
                continue;
            }

            // Consume pending trigger files.
            var triggers = _triggerWatcher.DrainTriggers();
            foreach (var trigger in triggers)
            {
                if (trigger.IsOsDefer)
                {
                    _log.LogInformation("OS defer marker received from {User}", trigger.RequestedBy);
                    // Decrement deferrals_remaining in the current status and rewrite.
                    await HandleOsDeferAsync(ct);
                    continue;
                }
                if (trigger.IsScanRequest)
                {
                    // desktop chain U5: local, user-initiated scan — collect + refresh
                    // posture, never install. Runs a ScanOnly cycle regardless of tier.
                    _log.LogInformation("Scan-now trigger from {User}", trigger.RequestedBy);
                    await RunCycleSafeAsync(trigger: null, RunMode.ScanOnly, ct);
                    continue;
                }
                if (trigger.IsUninstallRequest)
                {
                    _log.LogWarning("Ignoring legacy uninstall trigger from {User}: Windows assurance build contains no uninstall runner", trigger.RequestedBy);
                    continue;
                }
                if (trigger.IsDeployRequest)
                {
                    _log.LogWarning("Ignoring legacy deploy trigger from {User}: Windows assurance build contains no installer runner", trigger.RequestedBy);
                }
            }

            // Scheduled full run. Cadence is driven by the scan_cadence field from
            // agent-config (PAT-537); falls back to 24 h if absent or unrecognised.
            if (DateTimeOffset.Now >= _nextScheduledRun)
            {
                _log.LogInformation("Starting scheduled run");
                await RunCycleSafeAsync(trigger: null, RunMode.ScanOnly, ct);
                var interval = ScanCadenceToInterval(_config.Current.ScanCadence);
                _nextScheduledRun = ComputeNextScheduledRun(DateTimeOffset.Now, interval);
            }

            // PAT-1269: periodic self-update check, independent of the scheduled
            // full-run cadence above — see BootstrapUpdateCheckInterval's own doc
            // comment for why it runs on its own hourly clock rather than being tied
            // to scan_cadence. The call itself is delegated to the extracted, internal,
            // static RunPeriodicBootstrapUpdateCheckAsync purely for testability — same
            // rationale as WaitOutSuspensionAsync/ActuatingTierAllows further down:
            // PatchedWorker's constructor has 17 dependencies and no existing test
            // harness builds the whole thing.
            //
            // BootstrapUpdater.CheckAndStageAsync is already fully fail-safe (its own
            // doc comment: "any error leaves the service running on the current
            // version") and, as of PAT-1269, defers instead of re-staging when a
            // DIFFERENT version is already pending apply (see
            // BootstrapUpdater.DoCheckAndStageAsync) — both matter more now that this
            // can genuinely run again before PendingUpdateApplier has consumed a
            // previous marker on a restart. A transient failure here (network down,
            // API 5xx) is absorbed by that same catch-and-record-degraded and simply
            // retried at the next hourly tick — never a tight retry loop, because this
            // whole block only fires once per BootstrapUpdateCheckInterval. That is
            // enforced (not just assumed) by RunPeriodicBootstrapUpdateCheckAsync's own
            // try/catch — see its doc comment. DateTimeOffset.UtcNow, not .Now — see
            // _nextBootstrapUpdateCheck's own doc comment for why this timer is UTC
            // while _nextScheduledRun above is local.
            _nextBootstrapUpdateCheck = await RunPeriodicBootstrapUpdateCheckAsync(
                _bootstrapUpdater, DateTimeOffset.UtcNow, _nextBootstrapUpdateCheck, BootstrapUpdateCheckInterval, _log, ct,
                installTrusted: () => _installIntegrity.Verify("self-update staging"))
                .ConfigureAwait(false);

            // PAT-1231: retry persisted inventory independently of the next
            // full collection cycle, but only after local Self Service triggers
            // and scheduled work. This keeps a slow/unreachable inventory path
            // from delaying user actions, enforcement, or the next decommission
            // check. The singleton poster stays serial with this worker; a
            // second hosted queue-pump service could race file deletion.
            await DrainInventoryQueueSafeAsync(ct).ConfigureAwait(false);

            // PAT-1249: same rationale as the inventory retry above, applied to
            // the provenance queue pump — drains one persisted provenance
            // payload per tick (including records stranded before this pump
            // existed) so a backlog recovers steadily instead of bursting
            // straight back into the rate limiter that produced it.
            await DrainProvenanceQueueSafeAsync(ct).ConfigureAwait(false);
        }

        _log.LogInformation("Patched Agent stopping");
    }

    /// <summary>
    /// Queue-only retries are bounded and fail-safe so they cannot materially
    /// delay local work or a later decommission check. Cancellation remains a
    /// normal shutdown signal.
    /// </summary>
    private async Task DrainInventoryQueueSafeAsync(CancellationToken ct)
    {
        await DrainInventoryQueueForTickAsync(
            _creds,
            _inventoryPoster.DrainQueueAsync,
            _log,
            ct).ConfigureAwait(false);
    }

    /// <summary>
    /// PAT-1249: the provenance twin of <see cref="DrainInventoryQueueSafeAsync"/>,
    /// reusing the same bounded, fail-safe queue-only-retry helper.
    /// </summary>
    private async Task DrainProvenanceQueueSafeAsync(CancellationToken ct)
    {
        await DrainInventoryQueueForTickAsync(
            _creds,
            _provenance.DrainQueueAsync,
            _log,
            ct,
            queueName: "Provenance").ConfigureAwait(false);
    }

    /// <summary>
    /// <paramref name="queueName"/> (PAT-1249) is purely a logging label — this
    /// helper started life inventory-only, but its bounded/fail-safe shape is
    /// generic, so <see cref="DrainProvenanceQueueSafeAsync"/> reuses it rather
    /// than duplicating the retry/timeout logic. Defaults to "Inventory" so
    /// every pre-existing call site (and the tests pinned to this name) keeps
    /// its exact original log wording.
    /// </summary>
    internal static async Task DrainInventoryQueueForTickAsync(
        CredentialStore creds,
        Func<CancellationToken, Task> drainQueue,
        ILogger log,
        CancellationToken ct,
        TimeSpan? timeout = null,
        string queueName = "Inventory")
    {
        // PAT-1760 review: drains POST signed payloads, so they need a usable pair,
        // not just a non-empty bearer token.
        if (!DeviceCredentials.Present(creds))
            return;

        using var retryCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        retryCts.CancelAfter(timeout ?? QueueRetryTimeout);

        try
        {
            await drainQueue(retryCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            log.LogWarning("{QueueName} queue retry exceeded its bounded {Timeout} timeout — retaining queued payloads for the next tick",
                queueName, timeout ?? QueueRetryTimeout);
        }
        catch (Exception ex)
        {
            log.LogError(ex, "{QueueName} queue retry threw unexpectedly — retaining queued payloads for the next tick", queueName);
        }
    }

    /// <summary>
    /// PAT-858: wraps <see cref="RunCycleAsync"/> so a single unhandled exception during
    /// a run — a file locked by AV, a disk hiccup, an installer deleted mid-cycle — never
    /// escapes <see cref="ExecuteAsync"/>. The .NET Generic Host treats an unhandled
    /// exception from a hosted service's <c>ExecuteAsync</c> as fatal and stops the host;
    /// <c>Product.wxs</c> only configures two auto-restarts
    /// (<c>ThirdFailureActionType="none"</c>), so a recurring trigger permanently disables
    /// the agent on that endpoint. Every call site in <see cref="ExecuteAsync"/> must go
    /// through this wrapper, not <see cref="RunCycleAsync"/> directly.
    /// </summary>
    /// <summary>
    /// PAT-1110: wraps <see cref="DecommissionRunner.RunAsync"/> with the same
    /// unhandled-exception discipline as <see cref="RunCycleSafeAsync"/> (PAT-858) —
    /// DecommissionRunner.RunAsync is already fail-safe internally, but this extra
    /// layer means a defect in it can never take down the BackgroundService the way
    /// an uncaught exception from ExecuteAsync does.
    /// </summary>
    private async Task RunDecommissionCheckSafeAsync(CancellationToken ct)
    {
        await RunDecommissionCheckForTickAsync(
            _creds,
            (credentialsPresent, token) => _decommission.RunAsync(_config.Current, credentialsPresent, token),
            _log,
            ct).ConfigureAwait(false);
    }

    /// <summary>
    /// PAT-1760: the body of <see cref="RunDecommissionCheckSafeAsync"/>, static so
    /// the credential gate is unit testable without constructing PatchedWorker
    /// (same rationale as <see cref="WaitOutSuspensionAsync"/>).
    ///
    /// ExecuteAsync runs this check at startup and on every tick, including after a
    /// transient enrolment failure, when the device holds no bearer token or HMAC
    /// secret. A due directive's "acknowledged" report would then go out unsigned and
    /// be rejected, and the runner would read that rejection as the platform calling
    /// the removal off, so that report needs the credential snapshot.
    ///
    /// PAT-1765: the check itself always runs, and <paramref name="runCheck"/> is told
    /// whether credentials are present. PAT-1760 skipped the whole check without them,
    /// which also skipped DecommissionRunner's network-free retry of the immediate
    /// trigger for a removal already authorised and staged. The runner gates only the
    /// unacknowledged report.
    /// </summary>
    internal static async Task RunDecommissionCheckForTickAsync(
        CredentialStore                      creds,
        Func<bool, CancellationToken, Task>  runCheck,
        ILogger                              log,
        CancellationToken                    ct)
    {
        try
        {
            await runCheck(DeviceCredentials.Present(creds), ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            log.LogError(ex, "decommission: check failed unexpectedly; agent remains running, will retry next cycle");
        }
    }

    private async Task RunCycleSafeAsync(TriggerRequest? trigger, RunMode mode, CancellationToken ct)
    {
        try
        {
            await RunCycleAsync(trigger, mode, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw; // graceful shutdown must still propagate
        }
        catch (Exception ex)
        {
            _log.LogError(ex,
                "Run cycle failed unexpectedly (mode={Mode}); service continues, will retry next cycle",
                mode);
        }
    }

    /// <summary>
    /// PAT-1481: runs one App-Control-authority-gated, fail-safe enforcement action.
    /// Skips when <paramref name="authority"/> does not allow a destructive action;
    /// otherwise invokes
    /// <paramref name="action"/> and posts the resulting audit events, logging (never
    /// throwing) on an unexpected failure. Shared by AdminEnforcer and
    /// BrowserExtensionRemover in <see cref="RunCycleAsync"/> so the Tier gate and the
    /// fail-safe wrapper are defined once instead of copy-pasted per call site.
    ///
    /// The authority is intentionally independent of the projected package tier.
    /// Neither this helper nor its callers can enable a retained package executor.
    ///
    /// Only appropriate for one-way actions with nothing to roll back (both of these:
    /// removing an unapproved local admin, deleting a browser extension). Do NOT use
    /// this for an action that also reconciles/clears state it previously applied — see
    /// <see cref="RunFailSafeEnforcementAsync"/> and the non-author-review finding on
    /// BrowserExtensionBlocklistEnforcer that motivated the distinction.
    /// </summary>
    private async Task RunAuthorityGatedEnforcementAsync(
        string                                            name,
        AppControlAuthority                               authority,
        Func<IReadOnlyList<EnforcementAuditEvent>>        action,
        CancellationToken                                 ct)
    {
        if (!AppControlAuthorityGate.AllowsDestructiveAction(authority))
        {
            _log.LogInformation(
                "APP CONTROL AUTHORITY: '{Authority}' does not permit destructive endpoint actuation " +
                "({Name}); enforce is required. Refusing.", authority, name);
            return;
        }

        await RunFailSafeEnforcementAsync(name, action, ct);
    }

    /// <summary>
    /// PAT-858: runs one fail-safe enforcement action unconditionally (no Tier skip) and
    /// posts the resulting audit events, logging (never throwing) on an unexpected
    /// failure. Use this when the action itself needs to run on every cycle regardless
    /// of Tier because it also reconciles/rolls back state it previously applied — a
    /// below-patch tenant must not just stop gaining new enforcement, it must not
    /// continue enforcing stale state either. The Tier decision belongs INSIDE the
    /// action in that case (see BrowserExtensionBlocklistEnforcer.Enforce's
    /// actuationAllowed parameter), not as an outer skip here.
    /// </summary>
    private async Task RunFailSafeEnforcementAsync(
        string                                      name,
        Func<IReadOnlyList<EnforcementAuditEvent>>  action,
        CancellationToken                           ct)
    {
        try
        {
            var events = action();
            await _auditEvents.PostEnforcementAuditAsync(events, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "{Name}: unexpected error during enforcement — will retry next cycle", name);
        }
    }

    private async Task RunCycleAsync(
        TriggerRequest? trigger,
        RunMode         mode,
        CancellationToken ct)
    {
        var startedAt   = DateTimeOffset.UtcNow;
        var triggerName = trigger is not null ? "manual" : "scheduled";
        if (trigger is not null && !_statusWriter.HasEverWritten)
            triggerName = "first-run";

        var config = _config.Current;

        _log.LogInformation("Run cycle start — trigger={Trigger} mode={Mode}", triggerName, mode);

        // PAT-1531: status no longer synthesises package update entries from the
        // quarantined installer engine. InventoryPoster below remains the source of
        // installed-software observations; remediation is handed to the customer's
        // management or ticketing platform.
        IReadOnlyList<AppEntry> appResults = [];

        var finishedAt = DateTimeOffset.UtcNow;

        // PAT-300/913: detect BitLocker + removable-storage status and record which
        // controls actually ran a determination; non-fatal if WMI unavailable.
        var compliance         = StatusWriter.DetectComplianceFindings();
        var complianceFindings = compliance.Findings;

        // PAT-537: run OS update detection via WUA COM API (PAT-308).
        // PAT-906: the pending-deferral count comes from the same TriggerWatcher
        // singleton that drains the directory, so counting shares the hardened
        // walk and its locked-file quarantine state (see TriggerWatcher docs).
        var policy       = config.OsUpdatePolicy ?? new OsUpdatePolicy();
        var deferralCount = _triggerWatcher.CountOsDeferrals();
        OsUpdateInfo? osUpdate = null;
        try { osUpdate = _osUpdateChecker.ComputeOsUpdate(policy, deferralCount); }
        catch (Exception ex) { _log.LogWarning(ex, "OS update check failed — omitting from status"); }
        // PAT-1833: no freshness/future-timestamp bound is applied here, unlike
        // macOS's 48h window in patched_os_update_merge_into_payload. That bound
        // exists on macOS because patched-upload.sh reads a status file a
        // separate daily-cron process wrote, possibly hours earlier. Here,
        // OsUpdateChecker.ComputeOsUpdate stamps CheckedAt from DateTimeOffset
        // .UtcNow inside this same call, synchronously, in the same worker tick
        // that posts it a few lines below — there is no persisted intermediate
        // step that could go stale or produce a future timestamp.

        var status = _statusWriter.Build(
            startedAt:          startedAt,
            finishedAt:         finishedAt,
            trigger:            triggerName,
            appEntries:         appResults,
            nextRun:            _nextScheduledRun,
            osUpdate:           osUpdate,
            complianceFindings: complianceFindings.Count > 0 ? complianceFindings : null,
            requestedDeployLabels: null);

        _statusWriter.WriteAtomic(status);
        _log.LogInformation("update-status.json written — overall={State}", status.OverallState);

        // Refresh the posture cache (desktop chain U0) so the tray sees
        // the freshest server-derived posture. Fail-safe: PostureFetcher swallows
        // network/HTTP errors and keeps last-known-good. PAT-1066 P2: independent of
        // InventoryPoster.PostAsync (moved to the end of this method below), which
        // this fetch does not depend on having run first this cycle.
        try
        {
            await _posture.FetchAsync(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "posture: refresh failed — keeping last-good cache");
        }

        await _auditEvents.FlushAsync(ct);

        // PAT-552: Application Control — approved-admins enforcement.
        // Runs only when the signed App Control authority is enforce. This is separate
        // from tier so the assurance tier (PAT-1599: formerly report_deploy) can
        // safely contain all legacy package paths while retaining narrowly
        // authorised application controls.
        // Events are posted directly to /v1/inventory/enforcement-audit (PAT-603).
        await RunAuthorityGatedEnforcementAsync(
            "AdminEnforcer", config.AppControlAuthority, () => _adminEnforcer.Enforce(config.AppControl), ct);

        // PAT-552: Application Control — app-allowlist check (alert-only v1).
        // Scans installed apps against the signed app_allowlist; reports unlisted
        // apps as app_block_skipped events without taking any blocking action.
        // AppAllowlistEnforcer.Enforce() is fail-safe: it never throws.
        //
        // Not Tier-gated (PAT-858): this path never blocks or removes anything, only
        // reports advisory findings, and advisory findings are meant to surface below
        // Tier 3 too (they're the Tier 3 sales surface per root AGENTS.md). Gating it
        // would suppress advisory visibility for no security benefit.
        try
        {
            var allowlistEvents = _appAllowlistEnforcer.Enforce(config.AppControl);
            await _auditEvents.PostEnforcementAuditAsync(allowlistEvents, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogError(ex, "AppAllowlistEnforcer: unexpected error during enforcement — will retry next cycle");
        }

        // PAT-828: Browser Extension Control — managed-policy blocklist enforcement.
        // Pushes Chrome/Edge/Firefox registry policy blocking the tenant's
        // unapproved extensions (app_control.extension_blocklist) and posts one
        // enforcement_audit event per browser it changes. Device-global, so a
        // single push covers every user and browser profile. Fail-safe: never throws.
        //
        // This call always runs because BrowserExtensionBlocklistEnforcer also
        // reconciles (clears) any blocklist policy it previously pushed when the desired
        // set shrinks. A report-authority tenant must not just stop gaining NEW enforcement —
        // leaving a PREVIOUSLY pushed blocklist in place is itself still actuating
        // enforcement below its authority. So the authority decision is threaded INTO Enforce
        // via actuationAllowed: when false it reconciles down to empty (rolling back any
        // stale policy) instead of being skipped entirely.
        await RunFailSafeEnforcementAsync(
            "BrowserExtensionBlocklistEnforcer",
            () => _extensionBlocklistEnforcer.Enforce(
                config.AppControl, AppControlAuthorityGate.AllowsBlocklist(config.AppControlAuthority)),
            ct);

        // PAT-829: Browser Extension Control — profile-aware, audited removal.
        // The destructive escalation path after the blocklist: deletes the tenant's
        // listed extensions (app_control.extension_removals) from the user profiles
        // each directive's scope selects, and posts one extension_removed audit event
        // per artifact actually removed. Fail-safe: never throws. One-way (a removed
        // extension isn't reinstalled), so unlike the blocklist above there's no
        // reconciliation-on-downgrade concern here.
        //
        // A one-way removal requires the separate enforce authority.
        await RunAuthorityGatedEnforcementAsync(
            "BrowserExtensionRemover", config.AppControlAuthority,
            () => _extensionRemover.Remove(config.AppControl), ct);

        // PAT-1531 retains PAT-1066's health contract without reintroducing the
        // removed runner/engine: device identity is observed from cached posture,
        // and package execution is explicitly reported as not shipped. Decommission
        // health is recorded independently by DecommissionRunner earlier in the tick.
        _assuranceCapabilityHealth.Record();

        // POST inventory to /v1/inventory (PAT-336): device + compliance + app inventory.
        // PAT-743: reuse the complianceFindings already computed above rather
        // than re-querying WMI a second time. PAT-1833 does the same for the
        // OsUpdateInfo already computed from WUA for update-status.json: pass that
        // exact object through, and omit os_update when the check was unavailable.
        // Guarded so an unexpected exception (e.g. BuildPayload failure, HMAC key
        // format error) surfaces in the rolling file log rather than crashing the
        // BackgroundService and restarting the service silently.
        //
        // PAT-1066 P2 non-author-review: moved to the END of the cycle (was
        // previously right after WriteAtomic, above) — every uploaded payload used
        // to reflect the PREVIOUS cycle's health snapshot (device-removal and
        // install-run, both above, hadn't executed yet this cycle when the old
        // position posted), a full scan-interval of lag; worse, a fresh install or a
        // wiped state directory posted an explicit degraded:[] all-clear before
        // either probe had ever run once. Nothing between the old position and here
        // (posture fetch, provenance POSTs, audit event shipping, AdminEnforcer,
        // AppAllowlistEnforcer, browser extension blocklist/removal, uninstalls,
        // device removals, installs) depends on inventory having already been
        // POSTed this cycle before it runs, so relocating this block changes only
        // the freshness of the agent_health section it carries, not any other
        // behaviour.
        try
        {
            await _inventoryPoster.PostAsync(complianceFindings, compliance.ControlsAssessed, osUpdate, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogError(ex, "InventoryPoster.PostAsync threw unexpectedly — will retry next cycle");
        }
    }

    private async Task HandleOsDeferAsync(CancellationToken ct)
    {
        var current = _statusWriter.CurrentStatus;
        if (current?.OsUpdate is null) return;

        var remaining = Math.Max(0, current.OsUpdate.DeferralsRemaining - 1);
        var updated = current with
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            OsUpdate = current.OsUpdate with { DeferralsRemaining = remaining },
        };
        _statusWriter.WriteAtomic(updated);
        await Task.CompletedTask;
    }

    /// <summary>
    /// PAT-1204: the single suspension gate — checks <see cref="CredentialStore.IsSuspended"/>
    /// and, if true, blocks in <see cref="AgentEnroller.WaitForRecoveryAsync"/> until the
    /// device recovers (revocation cleared by AgentConfigManager's independent poll, or a
    /// fresh enrollment token retried successfully), logging start and completion. A no-op
    /// when not suspended.
    ///
    /// Extracted to a single static method — not duplicated inline — so the startup gate
    /// (top of <see cref="ExecuteAsync"/>) and the mid-run re-check at the top of every main
    /// loop tick can never drift out of sync, and so this decision is directly unit
    /// testable via an injected <see cref="CredentialStore"/> + <see cref="AgentEnroller"/>
    /// pair without needing to construct <see cref="PatchedWorker"/> itself. Same rationale
    /// as <see cref="ActuatingTierAllows"/> below: PatchedWorker's constructor has 17
    /// dependencies and no existing test harness builds the whole thing (see
    /// WorkerTierGateTests), so gate logic that can be pulled out of the instance and
    /// tested standalone is worth doing — visible to Service.Tests via the same
    /// InternalsVisibleTo grant.
    ///
    /// Takes <paramref name="creds"/> / <paramref name="enroller"/> / <paramref name="log"/>
    /// as parameters (rather than reading the instance fields directly) purely for that
    /// testability; every production call site passes this instance's own _creds /
    /// _enroller / _log.
    /// </summary>
    internal static async Task WaitOutSuspensionAsync(
        CredentialStore    creds,
        AgentEnroller      enroller,
        ILogger            log,
        TimeSpan           pollInterval,
        TimeSpan           enrollmentRecheckInterval,
        CancellationToken  ct)
    {
        if (!creds.IsSuspended)
            return;

        // PAT-1760: the marker records that the server rejected this device's
        // credentials or its enrolment token. A device with no usable credential
        // pair has no credentials for it to describe, so when an enrolment token is
        // present the marker must not keep enrolment from running. The case:
        // creds\suspended left behind with no usable pair and a token that was never
        // rejected. The token matches the one loaded at start, so
        // RefreshEnrollmentToken never signals a retry and WaitForRecoveryAsync would
        // wait forever.
        //
        // Returning here leaves the marker in place. The caller goes straight to
        // enrolment with the token present: the startup TryEnrolAsync, or the
        // pending-enrolment branch of the main loop, which `continue`s before any
        // collection. The condition matches both callers exactly (no usable pair per
        // DeviceCredentials.Present, enrolment token present), so no path reaches a
        // run cycle while the marker is still there. On success AgentEnroller stores the new credentials and
        // clears the marker; a 410/401 rewrites it and WaitForRecoveryAsync waits for
        // a different token. The cost: a token that really was rejected is tried once
        // more per service start, one /v1/enrol call. A device that holds a usable pair
        // never takes this branch, so a real rejection of its credentials stays
        // suspended until a signature-verified agent-config 200 clears it.
        if (SuspendedMarkerCannotGateEnrolment(creds))
        {
            log.LogWarning("Suspended marker present, but this device holds no credentials for it to describe and an enrolment token is present. Trying enrolment instead of waiting; the marker stays until enrolment stores new credentials");
            return;
        }

        log.LogWarning("Device is suspended — collection/enforcement paused; AgentConfigManager keeps probing agent-config independently and will clear the marker on the next signature-verified 200, and a fresh enrollment token (if this is an enrollment-suspended device) will be retried automatically");
        await enroller.WaitForRecoveryAsync(pollInterval, enrollmentRecheckInterval, ct).ConfigureAwait(false);
        log.LogInformation("Device reinstated — suspended marker cleared, resuming normal enforcement/collection");
    }

    /// <summary>
    /// PAT-1766: the not-provisioned gate. A no-op when <paramref name="creds"/> holds a
    /// usable credential pair or an enrolment token. Otherwise logs
    /// <see cref="AgentProvisioning.NotProvisionedMessage"/> as Critical (Application
    /// event log source "Patched Agent" and the rolling file log), then every
    /// <paramref name="recheckInterval"/> calls <see cref="CredentialStore.RefreshProvisioning"/>
    /// until it finds a token or credentials, repeating the report as an Error every
    /// <paramref name="reminderInterval"/>. A failed re-read is logged by exception type
    /// only (never a value) and retried on the next interval. Returns once provisioned;
    /// cancellation propagates. Static for the same testability reason as
    /// <see cref="WaitOutSuspensionAsync"/>.
    /// </summary>
    internal static async Task WaitForProvisioningAsync(
        CredentialStore   creds,
        AgentHealthStore  agentHealth,
        ILogger           log,
        TimeSpan          recheckInterval,
        TimeSpan          reminderInterval,
        CancellationToken ct)
    {
        if (!creds.AwaitingProvisioning)
        {
            if (DeviceCredentials.Present(creds))
                DeviceCredentialHealth.ClearIfActive(agentHealth);
            return;
        }

        ObserveProvisioningCredentialHealth(creds, agentHealth);

        log.LogCritical("{Message}", AgentProvisioning.NotProvisionedMessage(recheckInterval));
        var nextReminder = DateTimeOffset.UtcNow.Add(reminderInterval);

        while (true)
        {
            await Task.Delay(recheckInterval, ct).ConfigureAwait(false);

            bool provisioned;
            try
            {
                provisioned = creds.RefreshProvisioning();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                log.LogWarning(
                    "Could not re-read the agent credential sources while waiting to be provisioned ({Error}); trying again in {Interval}",
                    ex.GetType().Name, recheckInterval);
                provisioned = false;
            }

            ObserveProvisioningCredentialHealth(creds, agentHealth);

            if (provisioned)
            {
                log.LogInformation("{Message}", AgentProvisioning.ProvisionedMessage);
                return;
            }

            if (DateTimeOffset.UtcNow >= nextReminder)
            {
                log.LogError("{Message}", AgentProvisioning.NotProvisionedMessage(recheckInterval));
                nextReminder = DateTimeOffset.UtcNow.Add(reminderInterval);
            }
        }
    }

    /// <summary>
    /// PAT-1781: an absent identity remains PAT-1766's not-provisioned state. Only
    /// an actually stored bearer/HMAC pair whose values are unusable produces the
    /// cross-platform credentials_empty fault. The health row itself suppresses
    /// duplicate writes on subsequent ticks; a usable pair clears it.
    /// </summary>
    private static void ObserveProvisioningCredentialHealth(
        CredentialStore creds, AgentHealthStore agentHealth)
    {
        if (DeviceCredentials.Present(creds))
        {
            DeviceCredentialHealth.ClearIfActive(agentHealth);
        }
        else if (creds.StoredCredentialPairPresent)
        {
            DeviceCredentialHealth.RecordFailureIfChanged(
                agentHealth, DeviceCredentialHealth.CredentialsEmptyReason);
        }
    }

    /// <summary>
    /// PAT-1760: true when a suspended marker cannot describe this device's
    /// credentials because it holds no usable pair (DeviceCredentials.Present is
    /// false: an empty bearer token, or an unusable HMAC secret) and an enrolment
    /// token is present to try. The same condition under which
    /// <see cref="AgentEnroller.TryEnrolAsync"/> actually calls /v1/enrol and the
    /// main loop's pending-enrolment branch runs.
    /// </summary>
    internal static bool SuspendedMarkerCannotGateEnrolment(CredentialStore creds) =>
        !DeviceCredentials.Present(creds) && DeviceCredentials.HasEnrollmentToken(creds);

    /// <summary>
    /// PAT-1269: runs <see cref="BootstrapUpdater.CheckAndStageAsync"/> if-and-only-if
    /// <paramref name="now"/> has reached <paramref name="nextCheck"/>, then returns the
    /// next due time (unchanged if it didn't run). Extracted to a static method — same
    /// rationale as <see cref="WaitOutSuspensionAsync"/> above — so the scheduling
    /// decision is directly unit testable via an injected <see cref="BootstrapUpdater"/>
    /// instance, without constructing <see cref="PatchedWorker"/> itself (17
    /// dependencies, no existing test harness builds the whole thing).
    ///
    /// An async method cannot take a <c>ref</c> parameter, so unlike
    /// <c>_nextScheduledRun</c>'s in-place update this returns the new value instead;
    /// every call site re-assigns its own <c>_nextBootstrapUpdateCheck</c> field from
    /// the result — the same "return the next due time" shape
    /// <see cref="ComputeNextScheduledRun"/> already uses below.
    ///
    /// Wraps the call in the same try/catch shape as <see cref="RunCycleSafeAsync"/> and
    /// <see cref="DrainInventoryQueueForTickAsync"/> above (PAT-858's rationale: an
    /// unhandled exception from this BackgroundService's ExecuteAsync is fatal to the
    /// whole service, and Product.wxs only configures two auto-restarts before giving
    /// up). CheckAndStageAsync is documented fail-safe and already catches its own
    /// exceptions, so this catch should never fire in practice — but that guarantee
    /// belongs to BootstrapUpdater, a different class, and this call site must not
    /// silently rely on it staying true forever. Enforcing it here too means a future
    /// change that lets an exception escape CheckAndStageAsync degrades to "logged and
    /// retried next tick" instead of taking down collection, enforcement and the queue
    /// drains that share this loop.
    /// </summary>
    internal static async Task<DateTimeOffset> RunPeriodicBootstrapUpdateCheckAsync(
        BootstrapUpdater   bootstrapUpdater,
        DateTimeOffset     now,
        DateTimeOffset     nextCheck,
        TimeSpan           interval,
        ILogger            log,
        CancellationToken  ct,
        Func<bool>?        installTrusted = null)
    {
        if (now < nextCheck)
            return nextCheck;

        try
        {
            // PAT-2399: asked only when a check is due, so an untrusted install directory
            // is re-read (and re-reported) once per interval, and staging is skipped.
            if (installTrusted is null || installTrusted())
                _ = await bootstrapUpdater.CheckAndStageAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw; // graceful shutdown must still propagate
        }
        catch (Exception ex)
        {
            log.LogError(ex,
                "bootstrap-updater: periodic check threw unexpectedly (should be unreachable — "
                + "CheckAndStageAsync is documented fail-safe); service continues, will retry next tick");
        }

        return now.Add(interval);
    }

    /// <summary>
    /// <summary>
    /// Converts the scan_cadence string from agent-config to a run interval.
    /// Recognised values: "hourly", "6h", "12h", "daily" (default), "weekly".
    /// Unknown values fall back to the 24h default.
    /// </summary>
    // PAT-1599: the signed agent-config's tier vocabulary collapsed from three
    // values (report_deploy/patch/managed) to two (assurance/managed) — "assurance
    // observes, managed acts", one bit, not a ladder. There is no more "patch" rung,
    // so both predicates below are now the same check. Retained for the
    // package-tier UI compatibility tests. App Control no longer calls either
    // predicate: its authority is AppControlAuthority, not tier.
    //
    // Both methods are kept, rather than collapsed to one, because they still
    // express different intent at their call sites: ActuatingTierAllows is the
    // general actuating-tier gate, DestructiveActuatingTierAllows is the stricter
    // gate PAT-1263 put specifically in front of the two one-way destructive paths
    // (AdminEnforcer.Enforce, BrowserExtensionRemover.Remove). They happen to have
    // identical bodies under today's 2-value scheme, but the names still document
    // which callers are on the destructive path versus the general one, which
    // matters for audit trails on customer-endpoint actuation even when the checks
    // themselves are not currently distinguishable. Both fail closed: only the
    // exact literal "managed" passes; null, empty, unknown and any other string
    // (including the now-retired "patch" and "report_deploy") refuse.
    internal static bool ActuatingTierAllows(string? tier) => tier == "managed";

    internal static bool DestructiveActuatingTierAllows(string? tier) => tier == "managed";

    private static TimeSpan ScanCadenceToInterval(string? cadence) =>
        cadence?.ToLowerInvariant() switch
        {
            "hourly"  => TimeSpan.FromHours(1),
            "6h"      => TimeSpan.FromHours(6),
            "12h"     => TimeSpan.FromHours(12),
            "daily"   => DefaultScanInterval,
            "weekly"  => TimeSpan.FromDays(7),
            _         => DefaultScanInterval,
        };

    private static DateTimeOffset ComputeNextScheduledRun(DateTimeOffset now, TimeSpan? interval = null)
    {
        // For sub-daily cadences use a simple offset from now.
        // For daily (and longer) cadences aim for 03:00 local time.
        var span = interval ?? DefaultScanInterval;
        if (span < TimeSpan.FromHours(24))
            return now.Add(span);

        var next3am = now.Date.AddDays(1).AddHours(3);
        return new DateTimeOffset(next3am, now.Offset);
    }
}

public enum RunMode
{
    ScanOnly,       // report installed vs available version; no install
    ScanAndInstall, // full scheduled run: scan + install updates
    Deploy,         // explicit user request: verify + install named labels
}
