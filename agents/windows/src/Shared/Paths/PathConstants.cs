namespace Patched.Shared.Paths;

/// <summary>
/// Canonical paths under %ProgramData%\Patched.
/// Mirrors macOS /Library/Application Support/Patched/.
/// </summary>
public static class PathConstants
{
    private static readonly string ProgramData =
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

    /// <summary>Root state directory: %ProgramData%\Patched.</summary>
    public static string StateDir { get; } =
        Path.Combine(ProgramData, "Patched");

    /// <summary>Contract file the service writes and the tray reads.</summary>
    public static string UpdateStatusFile { get; } =
        Path.Combine(StateDir, "update-status.json");

    /// <summary>Uninstall-engine status file (PAT-379); mirrors the macOS uninstall-status.json.</summary>
    public static string UninstallStatusFile { get; } =
        Path.Combine(StateDir, "uninstall-status.json");

    /// <summary>Install-engine status file (PAT-661); mirrors the macOS install-status.json.</summary>
    public static string InstallStatusFile { get; } =
        Path.Combine(StateDir, "install-status.json");

    /// <summary>
    /// PAT-1066: persisted agent_health store (active degraded-capability faults +
    /// the durable ever_succeeded ledger) — the Windows twin of the macOS
    /// .agent-health.json sidecar (PAT-1065). Read/written only by
    /// <see cref="Patched.Service.AgentHealthStore"/>; the payload wire shape it
    /// produces (not this file's own shape) is the real contract, documented in
    /// go-service/docs/PAYLOAD_SCHEMA.md.
    /// </summary>
    public static string AgentHealthFile { get; } =
        Path.Combine(StateDir, "agent-health.json");

    /// <summary>
    /// Device-posture cache (desktop chain U0). The Service fetches GET /v1/posture
    /// and writes this atomically, world-readable; the tray reads it as
    /// last-known-good. Mirrors the macOS posture.json cache.
    /// </summary>
    public static string PostureStatusFile { get; } =
        Path.Combine(StateDir, "posture.json");

    /// <summary>Credential file fallback store (file-based alternative to Credential Manager).</summary>
    public static string CredsDir { get; } =
        Path.Combine(StateDir, "creds");

    /// <summary>ACL-hardened trigger drop directory (PAT-307).</summary>
    public static string TriggerDir { get; } =
        Path.Combine(StateDir, "triggers");

    /// <summary>
    /// Root for SYSTEM-only download staging directories (PAT-857). Unlike
    /// <see cref="TriggerDir"/>, nothing but SYSTEM/Administrators is ever granted
    /// write access here — see <c>Patched.Shared.Security.SecureStagingDirectory</c>.
    /// Engines create per-run or per-package subdirectories under this root so an
    /// installer artifact can never be staged in a standard-user-writable location
    /// (like the LocalSystem service's %TEMP%, which resolves to C:\Windows\Temp).
    /// </summary>
    public static string StagingDir { get; } =
        Path.Combine(StateDir, "staging");

    /// <summary>Queued provenance files waiting for network retry.</summary>
    public static string ProvenanceQueueDir { get; } =
        Path.Combine(StateDir, "provenance-queue");

    /// <summary>Queued inventory payloads waiting for network retry.</summary>
    public static string InventoryQueueDir { get; } =
        Path.Combine(StateDir, "inventory-queue");

    /// <summary>
    /// PAT-499: ring-buffer queue for structured audit events bound for /v1/events.
    /// Capped at 1000 files; oldest dropped on overflow to bound disk use.
    /// </summary>
    public static string EventsQueueDir { get; } =
        Path.Combine(StateDir, "events-queue");

    /// <summary>Service log file.</summary>
    public static string LogFile { get; } =
        Path.Combine(StateDir, "logs", "patched-agent.log");

    /// <summary>Curated winget allowlist (deployed by installer).</summary>
    public static string AllowlistFile { get; } =
        Path.Combine(StateDir, "windows-allowlist.json");

    /// <summary>Verified agent-config cache (PAT-310).</summary>
    public static string AgentConfigFile { get; } =
        Path.Combine(StateDir, "agent-config.json");

    /// <summary>Last-accepted agent-config version (anti-rollback + ETag source).</summary>
    public static string AgentConfigVersionFile { get; } =
        Path.Combine(StateDir, "agent-config.version");

    /// <summary>Pending tray deploys (crash-survival journal).</summary>
    public static string PendingDeploysFile { get; } =
        Path.Combine(StateDir, "pending-deploys.json");

    /// <summary>
    /// PAT-1077: durable pending-batch file for POST /v1/inventory/enforcement-audit
    /// (PAT-603). Mirrors the macOS .enforcement-audit-pending.json sidecar (PAT-1037):
    /// AuditEventShipper.PostEnforcementAuditAsync merges each cycle's newly-collected
    /// events onto whatever is left here from a prior failed POST, commits the merge
    /// atomically BEFORE attempting the POST, and clears this file only once the server
    /// confirms ingestion of the full combined batch — so a failed POST after an
    /// already-applied, unrecoverable enforcement action (an admin removed, an extension
    /// deleted from disk, ...) delays the audit record, never loses it.
    /// </summary>
    public static string PendingEnforcementAuditFile { get; } =
        Path.Combine(StateDir, "pending-enforcement-audit.json");

    /// <summary>
    /// PAT-828: records which browser-extension ids the agent currently manages
    /// per browser, so blocklist reconciliation removes only our own registry
    /// entries — never a third party's (GPO/admin) policy. Mirrors the macOS
    /// extension-blocklist-state.json sidecar.
    /// </summary>
    public static string ExtensionBlocklistStateFile { get; } =
        Path.Combine(StateDir, "extension-blocklist-state.json");

    /// <summary>
    /// PAT-296. Per-app blocking-process deferral state file.
    /// Persists deferral count + last_deferred_at across service restarts.
    /// Resets (deleted) on successful update.
    /// </summary>
    public static string BlockingDeferralFile(string label) =>
        Path.Combine(StateDir, $"blocking-deferrals-{label}.json");

    public static readonly string ApiUrl =
        Environment.GetEnvironmentVariable("PATCHED_API_URL") ?? "https://api.patched.im";

    /// <summary>
    /// PAT-1248: REMOVED. This used to point at %ProgramData%\Patched\creds\artifact-key,
    /// a symmetric HMAC key the doc comment claimed was "written by the installer" — it
    /// never was; nothing in the repo ever wrote it, which is why self-update never once
    /// worked (BootstrapUpdater bailed at LogDebug on every start). The fix was not to
    /// finally write this file: that key, ARTIFACT_SIGNING_KEY, also signs the release
    /// MSI for out-of-band human verification and is deliberately never shipped to any
    /// endpoint — one compromised device with it could forge artifacts estate-wide.
    /// BootstrapUpdater now verifies an Ed25519-signed artifact-metadata envelope with
    /// the pinned public key in Patched.Shared.Verification.ArtifactTrust instead; no
    /// per-device secret file is needed at all.
    /// </summary>

    /// <summary>PAT-108: pending agent update marker (written by BootstrapUpdater).</summary>
    public static string PendingAgentUpdateFile { get; } =
        Path.Combine(StateDir, "pending-agent-update.json");

    /// <summary>
    /// PAT-108: directory where pending agent updates are staged.
    ///
    /// PAT-1338: hardened (SYSTEM/Administrators-only, see
    /// Patched.Shared.Security.SecureStagingDirectory) like every other privileged
    /// staging root — <see cref="Patched.Service.BootstrapUpdater"/> establishes this
    /// directory and its per-version child through EnsureHardenedChain anchored at
    /// <see cref="StateDir"/> before writing the installer. Until then it relied purely
    /// on ACEs inherited from StateDir, which nothing ever verified at the moment of
    /// use; a ~160 MB MSI is written here and later executed by LocalSystem.
    /// </summary>
    public static string AgentUpdatesDir { get; } =
        Path.Combine(StateDir, "updates");

    /// <summary>
    /// PAT-1110: hardened (SYSTEM/Administrators-only, see
    /// Patched.Shared.Security.SecureStagingDirectory) staging directory for the
    /// self-removal handoff script. Never writable by a non-admin principal — the
    /// same reasoning macOS applies to its BUNDLE_DIR: a hijackable handoff for the
    /// product's only irreversible action is a local privilege escalation.
    /// </summary>
    public static string DecommissionDir { get; } =
        Path.Combine(StateDir, "decommission");

    /// <summary>PAT-1110: the detached removal script written into <see cref="DecommissionDir"/>.</summary>
    public static string DecommissionScriptFile { get; } =
        Path.Combine(DecommissionDir, "remove-agent.ps1");

    /// <summary>
    /// PAT-1110 (second contract round): single-use credential snapshot (api_url,
    /// bearer_token, hmac_secret) staged into the same hardened
    /// <see cref="DecommissionDir"/> so the detached removal script can make its own
    /// authenticated terminal-status POST after the .NET service (and its own
    /// CredentialStore/Windows Credential Manager access) has already been stopped.
    /// The script deletes this file itself once it has been read, regardless of the
    /// purge flag — it is bridging material for one script run, not persisted agent
    /// state, so it is never left behind either way.
    /// </summary>
    public static string DecommissionReportCredsFile { get; } =
        Path.Combine(DecommissionDir, "report-creds.json");

    /// <summary>
    /// PAT-1110: marker written once a removal handoff has been scheduled, so
    /// DecommissionRunner does not re-register/re-trigger the scheduled task on
    /// every ~15s poll tick while waiting for it to stop the service. Deliberately
    /// NOT under DecommissionDir (which purge=true deletes as part of the local
    /// state directory) — see DecommissionRunner for why the marker's own lifetime
    /// doesn't need to survive purge (the agent is gone either way once purge runs).
    /// </summary>
    public static string DecommissionMarkerFile { get; } =
        Path.Combine(StateDir, "decommission-initiated.json");

    /// <summary>PAT-1110: name of the scheduled task the handoff registers.</summary>
    public const string DecommissionTaskName = "PatchedAgentDecommission";

    /// <summary>
    /// PAT-1293: hardened (SYSTEM/Administrators-only, see
    /// Patched.Shared.Security.SecureStagingDirectory) staging directory for the
    /// self-update restart task's script. Same TOCTOU reasoning as
    /// <see cref="DecommissionDir"/> — a SYSTEM-run script's own directory must
    /// never be writable by a non-admin principal, even though (unlike decommission)
    /// this script carries no credentials of its own, only a service-name/marker-path
    /// bounce.
    /// </summary>
    public static string SelfUpdateRestartDir { get; } =
        Path.Combine(StateDir, "self-update-restart");

    /// <summary>
    /// PAT-1293: the one-shot restart script written into
    /// <see cref="SelfUpdateRestartDir"/> — see
    /// <see cref="Patched.Service.PendingUpdateRestartScript"/> for what it does.
    /// </summary>
    public static string SelfUpdateRestartScriptFile { get; } =
        Path.Combine(SelfUpdateRestartDir, "restart-agent.ps1");

    /// <summary>
    /// PAT-1293 (round 2, non-author review): the Task Scheduler XML task
    /// definition registered via <c>schtasks /Create /XML</c>, written into the
    /// same hardened <see cref="SelfUpdateRestartDir"/> as the script — it is an
    /// input to a SYSTEM/HighestAvailable task, so its ACLs matter exactly as
    /// much as the script's. Replaces the original design, which passed
    /// <c>/SC ONCE /ST /SD</c> directly on the schtasks command line: schtasks
    /// parses <c>/SD</c> using the SYSTEM's regional short-date order, which
    /// fails registration outright on any non-US-date-order locale (en-GB
    /// included — see <see cref="Patched.Service.PendingUpdateRestartTaskXml"/>).
    /// The XML schema's &lt;StartBoundary&gt; is ISO-8601 by specification,
    /// removing that dependency rather than working around it.
    /// </summary>
    public static string SelfUpdateRestartTaskXmlFile { get; } =
        Path.Combine(SelfUpdateRestartDir, "restart-task.xml");

    /// <summary>
    /// PAT-1293: name of the one-shot, self-deleting scheduled task that bounces the
    /// service so <see cref="Patched.Service.PendingUpdateApplier"/> gets a chance to
    /// apply a pending self-update marker. See
    /// <see cref="Patched.Service.PendingUpdateRestartScheduler"/>.
    /// </summary>
    public const string SelfUpdateRestartTaskName = "PatchedAgentSelfUpdateRestart";
}
