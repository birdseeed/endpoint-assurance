using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Patched.Shared.Paths;
using Patched.Shared.Security;
using Patched.Shared.Verification;

namespace Patched.Service;

/// <summary>
/// PAT-1261: applies the pending-update marker <see cref="BootstrapUpdater"/> writes
/// after staging + verifying a newer agent MSI. BootstrapUpdater deliberately stops
/// short of applying it — "the service itself cannot replace its own binary while
/// running on Windows" — and until this class existed, nothing ever consumed the
/// marker: the update downloaded, verified, staged, and then sat there forever.
/// Verified live on WIN-STAGING 2026-08-11 (PAT-1261 brief): a marker written, a
/// service restart, "already staged" logged, still on the old version.
///
/// Design (already decided — see the PAT-1261 brief, not relitigated here): a
/// short-lived DETACHED process spawned by the service at startup, not a second
/// scheduled task. The agent's recorded preference is that periodic work is hosted
/// inside this same service process so that no second scheduled task or PowerShell
/// credential path exists — adding a scheduled task here would cut against that
/// preference for no reason: a detached child is sufficient. Stopping a Windows service does NOT kill its child
/// processes — there is no job object tying them together — so an msiexec this
/// service launches survives the service being stopped by that very install.
///
/// Flow:
///   1. Service starts, before/independently of the normal update check (see
///      PatchedWorker), calls <see cref="Apply"/>.
///   2. If the marker's version already matches the running version, the PREVIOUS
///      start's launch already succeeded (msiexec stopped this service, replaced
///      the binaries, restarted it — this process IS that restart). Clear the
///      marker, clean up the staged directory, record success.
///   3. Otherwise, confirm the marker's version is actually newer than the
///      running version (PAT-1534) — a stale marker for an OLDER version is
///      cleared, not retried, since Windows Installer will only ever refuse it.
///      Then re-verify the staged file's SHA-256 against the marker's
///      (re-verify — never trust the marker's own claim about itself, since the
///      applier runs as LocalSystem executing a file off disk) and, if it matches
///      and the bounded attempt budget isn't exhausted, launch
///      `msiexec /i "&lt;path&gt;" /qn /norestart` DETACHED — UseShellExecute=false,
///      not awaited, not tied to this process's lifetime — and let the MSI's own
///      ServiceControl element do the stop/replace/restart.
///
/// Fail-safe throughout: every bail-out path reports a DISTINCT, greppable reason
/// via <see cref="AgentHealthStore"/> rather than logging at LogDebug and vanishing
/// — a staged-but-never-applied update is exactly the class of silent no-op this
/// ticket exists to stop being invisible. Uses a SEPARATE (kind, subject) pair from
/// BootstrapUpdater's own self_update/artifact — see <see cref="HealthSubject"/> —
/// so this class's degraded state and BootstrapUpdater's cannot clobber each other
/// when both run back-to-back on the same service start.
///
/// PAT-1334: the two privileged recursive deletes here (<see cref="PruneStaleStagedDirectories"/>,
/// <see cref="DeleteStagedDirectory"/>) run against <c>updates\</c>. When PAT-1334
/// landed, that was the one staging root nothing ever ran
/// <c>SecureStagingDirectory.EnsureHardened(Chain)</c> on — unlike the
/// decommission/choco/winget/self-update-restart paths, it relied purely on
/// ACLs inherited from <see cref="PathConstants.StateDir"/>. PAT-1338 has since closed
/// that at the creation end (<see cref="BootstrapUpdater"/> now establishes the chain
/// with EnsureHardenedChain anchored at StateDir), but the guards below stay: this
/// class runs on a service start that may long postdate the staging, deletes
/// recursively as LocalSystem, and can be reached on a device whose <c>updates\</c>
/// predates PAT-1338 entirely. Both sites are guarded with
/// <see cref="Patched.Shared.Security.PathSafety"/>'s
/// containment + reparse-point-chain checks (the same PAT-1329 pattern
/// <c>ExtensionRemovalLogic</c> uses) before deleting anything; see that class's
/// doc comment for the empirical .NET behaviour (junction as leaf vs. immediate
/// child vs. ancestor) that motivates walking the whole chain rather than
/// checking only the leaf.
/// </summary>
internal sealed class PendingUpdateApplier
{
    // Distinct subject from BootstrapUpdater's "self_update"/"artifact": that pair
    // is written to (RecordSuccess on a clean verified check, RecordFailure on any
    // bail-out) on EVERY service start, immediately after this class runs on the
    // very same start. Sharing the pair would mean a genuine applier failure could
    // be silently overwritten a moment later by BootstrapUpdater's own unrelated
    // RecordSuccess/RecordFailure call for the artifact-check phase — exactly the
    // "no-op that logs nothing" failure mode this ticket exists to eliminate, just
    // one call deeper. Same "self_update" kind, so both still surface together
    // under one grep.
    private const string HealthKind    = "self_update";
    private const string HealthSubject = "apply";

    // PAT-2400: every reason the owner/DACL gate records on the pair above starts with
    // this, which is what lets it withdraw its own reason and no other. Untrusted
    // staged directories that are not the pending update are reported on their own
    // subject, so a cleanup problem never overwrites the apply outcome.
    private const string StagedReasonPrefix   = "staged_";
    private const string CleanupHealthSubject = "staged_cleanup";

    // PAT-1261: a failing MSI must not become a boot loop — launching a 160 MB
    // installer on every service restart forever. 3 is a small, deliberately
    // arbitrary bound: enough to ride out one or two transient failures (a
    // locked file, a momentary AV hold) without indefinitely retrying a
    // deterministically-failing install.
    internal const int MaxAttempts = 3;

    private readonly ILogger<PendingUpdateApplier> _log;
    private readonly AgentHealthStore               _agentHealth;
    private readonly IPendingUpdateLauncher          _launcher;
    private readonly string                          _currentVersion;
    private readonly string                          _pendingUpdateFile;
    private readonly string                          _updatesDir;
    private readonly string                          _trustedRoot;
    private readonly ArtifactTrust                   _trust;
    private readonly IStagedUpdateTrustVerifier      _trustVerifier;
    private readonly Func<UpdateChannelPolicy>?      _channelPolicy;

    /// <summary>
    /// The only public constructor, so the only one DI can use. PAT-2400: it wires the
    /// real owner/DACL verifier itself rather than resolving one from the container, so
    /// there is no registration that could bind a permissive implementation. The channel
    /// policy is resolved at apply time, not here; neither argument is read until then.
    /// </summary>
    public PendingUpdateApplier(
        ILogger<PendingUpdateApplier> log,
        AgentHealthStore              agentHealth,
        IPendingUpdateLauncher        launcher,
        AgentConfigManager            configManager,
        CredentialStore               creds)
        : this(log, agentHealth, launcher, BootstrapUpdater.ResolveCurrentVersion(),
               PathConstants.PendingAgentUpdateFile, PathConstants.AgentUpdatesDir,
               PathConstants.StateDir,
               channelPolicy: () => UpdateChannelPolicy.Resolve(configManager.Current, creds.TenantId, creds.CanonicalDeviceId))
    {
    }

    /// <summary>The verifier in use. Read by the guard test only.</summary>
    internal IStagedUpdateTrustVerifier TrustVerifier => _trustVerifier;

    /// <summary>
    /// Test-only seam: <paramref name="currentVersion"/> replaces
    /// <see cref="BootstrapUpdater.ResolveCurrentVersion"/>'s live-assembly read
    /// with a fixed string, and <paramref name="pendingUpdateFileOverride"/>/
    /// <paramref name="updatesDirOverride"/> redirect staging paths to a scratch
    /// temp directory instead of the real %ProgramData% locations. Mirrors
    /// BootstrapUpdater's own test constructor shape.
    ///
    /// <paramref name="trustedRootOverride"/> (PAT-1334) is the root that
    /// <see cref="PathSafety.HasReparsePointInChain"/> walks down from —
    /// production always passes <see cref="PathConstants.StateDir"/>, the
    /// nearest ancestor already established/verified elsewhere. When null (the
    /// default — existing call sites don't need to know about this), it's
    /// derived as the parent of <paramref name="updatesDirOverride"/>, matching
    /// the real StateDir/updates relationship one level up in a scratch temp
    /// directory.
    ///
    /// <paramref name="trustOverride"/> (PAT-2396) is the key the marker's signed
    /// envelope is verified with. Production passes <see cref="ArtifactTrust.Production"/>,
    /// which is also what null means here, so there is no value that switches the
    /// check off: a test that wants a marker applied has to sign it with a key it
    /// hands over, the same anchor-not-opt-out shape as BootstrapUpdater's own seam.
    ///
    /// <paramref name="trustVerifierOverride"/> (PAT-2400) replaces the Windows owner/DACL
    /// verifier with a test double. Null means the real one, which trusts nothing off
    /// Windows, so a test has to state the verdicts it wants rather than inherit a pass.
    /// <paramref name="channelPolicy"/> supplies the device's channel policy at apply
    /// time; null means none is known, the same as a policy without authority.
    /// </summary>
    internal PendingUpdateApplier(
        ILogger<PendingUpdateApplier> log,
        AgentHealthStore              agentHealth,
        IPendingUpdateLauncher        launcher,
        string                        currentVersion,
        string                        pendingUpdateFileOverride,
        string                        updatesDirOverride,
        string?                       trustedRootOverride = null,
        ArtifactTrust?                trustOverride = null,
        IStagedUpdateTrustVerifier?   trustVerifierOverride = null,
        Func<UpdateChannelPolicy>?    channelPolicy = null)
    {
        _trustVerifier     = trustVerifierOverride ?? new WindowsStagedUpdateTrustVerifier(log);
        _channelPolicy     = channelPolicy;
        _trust             = trustOverride ?? ArtifactTrust.Production;
        _log               = log;
        _agentHealth       = agentHealth;
        _launcher          = launcher;
        _currentVersion    = currentVersion;
        _pendingUpdateFile = pendingUpdateFileOverride;
        _updatesDir        = updatesDirOverride;
        _trustedRoot       = trustedRootOverride
            ?? Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(updatesDirOverride))
            ?? updatesDirOverride;
    }

    /// <summary>
    /// Looks for a pending-update marker and, if present, applies it (or clears it,
    /// or retries it, or gives up on it — see the class doc comment). Never throws;
    /// every failure is caught, logged, and reported via <see cref="AgentHealthStore"/>
    /// rather than allowed to affect service startup.
    /// </summary>
    public void Apply()
    {
        try
        {
            DoApply();
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "pending-update-applier: unexpected error — leaving marker as-is, will retry next start");
            _agentHealth.RecordFailure(HealthKind, HealthSubject, "unexpected_exception");
        }
    }

    private void DoApply()
    {
        // PAT-2400: an updates\ root that is not SYSTEM/Administrators-only is taken out
        // of the way on every start, marker or not. Left in place it makes every later
        // stage fail closed with stage_directory_untrusted for good; a root planted
        // before the state-root DACL was repaired never had a marker to trip over.
        if (!StagedObjectTrusted(_updatesDir, isDirectory: true, "updates_root", absentIsFine: true))
        {
            ClearMarker();
            return;
        }

        // The root is trusted or gone, so a staged_updates_root_* reason from an earlier
        // start no longer describes this device. Only that reason is withdrawn: the pair
        // holds one reason, and a marker_* or other apply reason is not this check's.
        _agentHealth.ClearFailure(HealthKind, HealthSubject, StagedReasonPrefix + "updates_root_");

        if (!File.Exists(_pendingUpdateFile))
        {
            // Nothing is pending, so no staged_* verdict about a pending update stands.
            _agentHealth.ClearFailure(HealthKind, HealthSubject, StagedReasonPrefix);
            // Nothing pending. Still worth pruning: a version staged by a PREVIOUS
            // marker that has since been cleared (success, hash mismatch, missing
            // hash) leaves its 160 MB directory behind otherwise.
            PruneStaleStagedDirectories(currentPendingVersion: null);
            return;
        }

        Marker? marker;
        try
        {
            marker = JsonSerializer.Deserialize<Marker>(File.ReadAllText(_pendingUpdateFile));
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "pending-update-applier: marker file is corrupt/unreadable — clearing it rather than acting on unknown content");
            ClearMarker();
            _agentHealth.RecordFailure(HealthKind, HealthSubject, "marker_unreadable");
            PruneStaleStagedDirectories(currentPendingVersion: null);
            return;
        }

        if (marker is null || string.IsNullOrEmpty(marker.Version) || string.IsNullOrEmpty(marker.InstallerPath))
        {
            _log.LogWarning("pending-update-applier: marker is missing required fields (version/installer_path) — clearing it");
            ClearMarker();
            _agentHealth.RecordFailure(HealthKind, HealthSubject, "marker_malformed");
            PruneStaleStagedDirectories(currentPendingVersion: null);
            return;
        }

        // PAT-1339: validate BOTH marker fields here, at marker-read time, before
        // EITHER is used anywhere below — not just before the specific use that
        // would otherwise be unsafe. Mirrors ExtensionRemovalLogic's PAT-1329
        // Defect A pattern (validate at parse time; reject, don't sanitise) but
        // applied one layer earlier than PAT-1334's belt-and-braces PathSafety
        // checks in PruneStaleStagedDirectories/DeleteStagedDirectory below: those
        // defend the two privileged deletes against a hostile Version, but nothing
        // previously validated Version or InstallerPath at the point the marker is
        // actually read — including the use that matters most, InstallerPath
        // flowing straight into _launcher.LaunchDetached, which runs
        // `msiexec /i "<path>" /qn /norestart` AS LOCALSYSTEM.
        //
        // The SHA-256 re-verify further down does NOT cover this gap: it is
        // self-referential — the marker supplies both the path and the expected
        // hash — so a marker naming an attacker-controlled path together with
        // that path's own true hash passes it cleanly. That check defends
        // against tampering with a legitimately staged installer after staging
        // (PAT-1261); this is a different threat, a marker that never named a
        // legitimate installer at all.
        //
        // A marker failing either check is corrupt or hostile, not a best-effort
        // cleanup being skipped (contrast PAT-1334's PruneStaleStagedDirectories/
        // DeleteStagedDirectory refusals just below, which deliberately report NO
        // AgentHealthStore fault so a refused opportunistic cleanup never
        // overwrites a genuinely successful apply) — so this DOES report
        // degraded, each with a reason distinct from every PAT-1334/PAT-1261
        // reason in this file.
        if (!IsSafeVersionSegment(marker.Version))
        {
            _log.LogError(
                "pending-update-applier: marker version {Version} is not a safe path segment — " +
                "refusing to act on it, clearing marker", marker.Version);
            ClearMarker();
            _agentHealth.RecordFailure(HealthKind, HealthSubject, "marker_version_unsafe");
            PruneStaleStagedDirectories(currentPendingVersion: null);
            return;
        }

        if (!IsTrustedInstallerPath(marker.InstallerPath, marker.Version, out string expectedInstallerPath))
        {
            _log.LogError(
                "pending-update-applier: marker installer_path {Path} for version {Version} failed " +
                "validation (expected exactly {Expected}) — refusing to act on it, clearing marker",
                marker.InstallerPath, marker.Version, expectedInstallerPath);
            ClearMarker();
            _agentHealth.RecordFailure(HealthKind, HealthSubject, "marker_installer_path_untrusted");
            PruneStaleStagedDirectories(currentPendingVersion: null);
            return;
        }

        // Success detection FIRST, before anything else: if the version this
        // process is actually running already matches the marker's pending
        // version, a PREVIOUS start's msiexec launch already did its job — it
        // stopped this very service, replaced the binaries, and restarted it, and
        // this is that restart. There is nothing left to verify or execute.
        if (string.Equals(marker.Version, _currentVersion, StringComparison.OrdinalIgnoreCase))
        {
            _log.LogInformation(
                "pending-update-applier: running version {Version} matches the pending update — it applied successfully",
                marker.Version);
            CleanupStagedDirectory(marker.Version);
            ClearMarker();
            _agentHealth.RecordSuccess(HealthKind, HealthSubject);
            PruneStaleStagedDirectories(currentPendingVersion: null);
            return;
        }

        // PAT-1534: BootstrapUpdater's own "already at version" check (above,
        // mirrored in BootstrapUpdater.CheckAndStageAsync) only compares for
        // EQUALITY — it never confirms the version it is about to stage is
        // actually NEWER than what's running, trusting the server. This class
        // inherited that same gap on the apply side: nothing here validated
        // marker.Version was newer than _currentVersion before spending an
        // attempt on it. A stale marker for an OLDER version (left over from an
        // earlier release, or one that never advanced across a restart) retried
        // forever — Windows Installer correctly refuses the downgrade every time
        // (MsiInstaller event 10005, "a newer version ... is already installed"),
        // while the real newer release BootstrapUpdater wants to stage stayed
        // deferred behind it indefinitely ("version {X} is already pending
        // apply", logged just above in BootstrapUpdater).
        //
        // Fail closed on an unparsable version: IsSafeVersionSegment above only
        // proves marker.Version is a safe PATH COMPONENT, not a well-formed
        // version number, so a marker this class cannot parse — and therefore
        // cannot prove is newer — is treated the same as a confirmed downgrade:
        // cleared, never executed.
        if (!Version.TryParse(marker.Version, out var pendingVersion) ||
            !Version.TryParse(_currentVersion, out var runningVersion) ||
            pendingVersion.CompareTo(runningVersion) <= 0)
        {
            _log.LogError(
                "pending-update-applier: marker version {Pending} is not newer than the running version {Running} — clearing stale marker instead of retrying",
                marker.Version, _currentVersion);
            ClearMarker();
            _agentHealth.RecordFailure(HealthKind, HealthSubject, "marker_not_newer");
            PruneStaleStagedDirectories(currentPendingVersion: null);
            return;
        }

        // Backward compatibility: a marker written by 0.13.20 or earlier (before
        // PAT-1261 added the hash field) has nothing to re-verify against. A
        // missing hash is "not verifiable", not "trust it anyway" — clear it and
        // let BootstrapUpdater re-stage (and this time write a hash-bearing
        // marker) on its next check, rather than executing an installer this
        // class cannot authenticate.
        if (string.IsNullOrEmpty(marker.Sha256))
        {
            _log.LogWarning(
                "pending-update-applier: marker for version {Version} has no sha256 (pre-PAT-1261 marker) — not verifiable, clearing without executing",
                marker.Version);
            ClearMarker();
            _agentHealth.RecordFailure(HealthKind, HealthSubject, "marker_missing_hash");
            PruneStaleStagedDirectories(currentPendingVersion: null);
            return;
        }

        // PAT-2396: the independent trust anchor. Everything checked above, and the
        // SHA-256 re-verify below, is answerable from the marker and the files beside
        // it, so a marker and installer that were already under the state root while it
        // was writable by a non-admin (StateDirectoryBootstrap repairs the root DACL
        // only, and trusts no descendant) passed all of it. The marker must now carry
        // the Ed25519-signed artifact-metadata envelope BootstrapUpdater verified, it
        // must verify against the pinned key here, and its signed version, platform and
        // SHA-256 must be the ones this marker claims. Only then does the marker's
        // sha256 mean "the hash a signed release has", which is what the re-verify
        // below needs it to mean.
        //
        // A marker with no envelope is not verifiable: either a pre-PAT-2396 agent
        // wrote it or nothing legitimate did, and the two are indistinguishable. Same
        // rule as the missing-hash branch above: discard it and let BootstrapUpdater
        // restage from the origin, never execute it.
        //
        // PAT-2400: with verified channel policy in hand (PAT-2351's signed config
        // cache, loaded before this runs), the signed channel must also be this device's.
        // Without it the channel stays unbound, as before, and that is logged below.
        var channelPolicy = _channelPolicy?.Invoke();
        if (!StagedUpdateEnvelope.TryVerify(_trust, marker.KeyId, marker.SignedPayload, marker.Signature,
                out var signedMetadata, out string envelopeReason)
            || !StagedUpdateEnvelope.Matches(signedMetadata, marker.Version, marker.Sha256, out envelopeReason)
            || !StagedUpdateEnvelope.ChannelPermitted(signedMetadata, channelPolicy, out envelopeReason))
        {
            _log.LogError(
                "pending-update-applier: marker for version {Version} is not backed by a valid signed " +
                "artifact-metadata envelope ({Reason}) — refusing to execute {Path}, discarding it for restaging",
                marker.Version, envelopeReason, marker.InstallerPath);
            // InstallerPath passed IsTrustedInstallerPath above: exactly
            // updates\<version>\patched-agent.msi, no reparse point in its chain.
            try { File.Delete(marker.InstallerPath); }
            catch (Exception ex) { _log.LogWarning(ex, "pending-update-applier: failed to delete unverified installer {Path}", marker.InstallerPath); }
            ClearMarker();
            _agentHealth.RecordFailure(HealthKind, HealthSubject, "marker_" + envelopeReason);
            PruneStaleStagedDirectories(currentPendingVersion: null);
            return;
        }

        if (!File.Exists(marker.InstallerPath))
        {
            // Marker deliberately RETAINED (not cleared): BootstrapUpdater's own
            // "already staged" check (BootstrapUpdater.IsStagedAndVerified)
            // fails the moment the file is gone, so its NEXT check-and-stage cycle
            // re-downloads and rewrites the marker (with a fresh attempt count) on
            // its own — no special recovery path needed here beyond staying
            // visibly degraded until that happens.
            _log.LogError(
                "pending-update-applier: staged installer missing at {Path} for version {Version}",
                marker.InstallerPath, marker.Version);
            _agentHealth.RecordFailure(HealthKind, HealthSubject, "installer_missing");
            PruneStaleStagedDirectories(marker.Version);
            return;
        }

        if (channelPolicy is not { HasAuthority: true })
        {
            _log.LogWarning(
                "pending-update-applier: no verified update-channel policy at apply time; the signed " +
                "channel '{Channel}' of version {Version} is not bound to this device's channel",
                signedMetadata.Channel, marker.Version);
        }

        // PAT-2400: nothing but SYSTEM and Administrators may own or be able to write
        // the root, the version directory, the installer or the marker. Checked before
        // the hash so the hash below describes bytes no other principal can then
        // replace by path; the launch follows with no wait in between. Not excluded: a
        // write handle opened while an object was still writable and held since, and
        // the by-path gap between these reads and msiexec opening the file, which only
        // an administrator or a holder of such a handle can use.
        if (!StagedObjectTrusted(_updatesDir, isDirectory: true, "updates_root", absentIsFine: false)
            || !StagedObjectTrusted(Path.Combine(_updatesDir, marker.Version), isDirectory: true, "version_dir", absentIsFine: false)
            || !StagedObjectTrusted(marker.InstallerPath, isDirectory: false, "installer", absentIsFine: false)
            || !StagedObjectTrusted(_pendingUpdateFile, isDirectory: false, "marker", absentIsFine: false))
        {
            ClearMarker();
            PruneStaleStagedDirectories(currentPendingVersion: null);
            return;
        }
        _agentHealth.ClearFailure(HealthKind, HealthSubject, StagedReasonPrefix);

        // H7: re-verify the bytes actually on disk against the hash from the
        // VERIFIED signed envelope (carried into the marker by BootstrapUpdater, and
        // since PAT-2396 proved equal to the envelope's own artifact_sha256 just above),
        // rather than trusting that the file staged earlier is still the file
        // staged earlier. The directory ACLs already block an unprivileged local
        // user from planting a file here, but this runs as LocalSystem executing
        // an installer off disk — that is the load-bearing control, not a backstop.
        // A mismatch is treated as hostile: refuse to execute, delete the file,
        // clear the marker, report degraded.
        string actualSha256 = BootstrapUpdater.ComputeSha256(marker.InstallerPath);
        if (!string.Equals(actualSha256, marker.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            _log.LogError(
                "pending-update-applier: SHA-256 mismatch for staged {Path} (version {Version}) — refusing to execute, treating as hostile",
                marker.InstallerPath, marker.Version);
            try { File.Delete(marker.InstallerPath); }
            catch (Exception ex) { _log.LogWarning(ex, "pending-update-applier: failed to delete tampered installer {Path}", marker.InstallerPath); }
            ClearMarker();
            _agentHealth.RecordFailure(HealthKind, HealthSubject, "hash_mismatch");
            PruneStaleStagedDirectories(currentPendingVersion: null);
            return;
        }

        // Bounded retry: only launches that actually got this far (verified hash,
        // file present) count against the budget — a transiently-missing file or
        // an already-resolved hash mismatch above never increments this, so this
        // check guards specifically against "msiexec itself keeps failing to
        // install", the boot-loop scenario the ticket calls out.
        if (marker.Attempts >= MaxAttempts)
        {
            _log.LogError(
                "pending-update-applier: version {Version} failed to apply after {Attempts} attempts — giving up; marker left in place, not retrying further",
                marker.Version, marker.Attempts);
            _agentHealth.RecordFailure(HealthKind, HealthSubject, "attempts_exhausted");
            PruneStaleStagedDirectories(marker.Version);
            return;
        }

        // Persist the incremented attempt count BEFORE launching, not after.
        // msiexec's own install stops this very service moments later — there is
        // no safe window to "launch, then record the attempt" without risking an
        // uncounted retry if the process is killed between those two steps.
        marker.Attempts += 1;
        WriteMarker(marker);

        bool launched;
        try
        {
            launched = _launcher.LaunchDetached(marker.InstallerPath);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "pending-update-applier: failed to launch msiexec for {Path}", marker.InstallerPath);
            launched = false;
        }

        if (!launched)
        {
            _agentHealth.RecordFailure(HealthKind, HealthSubject, "msiexec_launch_failed");
            PruneStaleStagedDirectories(marker.Version);
            return;
        }

        _log.LogWarning(
            "pending-update-applier: launched detached msiexec /i \"{Path}\" /qn /norestart for version {Version} (attempt {Attempt}/{Max})",
            marker.InstallerPath, marker.Version, marker.Attempts, MaxAttempts);
        // Deliberately no AgentHealthStore call on the success-of-launch path:
        // whether the install actually worked is unknown until the NEXT restart
        // (see the version-match branch above), and this is not itself a fault.
        PruneStaleStagedDirectories(marker.Version);
    }

    // -------------------------------------------------------------------------
    // Marker field validation (PAT-1339)
    // -------------------------------------------------------------------------

    /// <summary>DOS device namespace reserved names — case-insensitive, and
    /// reserved even with an extension appended ("CON.txt" is still CON).
    /// Windows treats these specially wherever they appear as a path component,
    /// so a marker naming one as <c>Version</c> must be rejected outright rather
    /// than silently mis-handled somewhere downstream.</summary>
    /// <summary>The characters Windows rejects in a filename, named explicitly
    /// rather than read from <see cref="Path.GetInvalidFileNameChars"/>, which
    /// answers the *host's* rules — a much shorter list on macOS, where this
    /// suite is routinely run cross-target. Control characters are checked
    /// separately alongside this. Separators and ':' are handled before this
    /// point with their own dedicated messages.</summary>
    private static readonly char[] InvalidNameChars = ['<', '>', '"', '|', '?', '*'];

    private static readonly HashSet<string> ReservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    /// <summary>
    /// PAT-1339: true when <paramref name="version"/> is safe to use as exactly
    /// one path component. Mirrors <c>ExtensionRemovalLogic.IsSafePathSegment</c>
    /// (PAT-1329 Defect A) — same manual character checks, same
    /// reject-don't-sanitise philosophy, for the same reason: this class has a
    /// Windows TFM but is unit-tested cross-target on macOS
    /// (<c>-p:EnableWindowsTargeting=true</c>, see AGENTS.md's "known-red tests"
    /// section), where <c>Path.IsPathRooted</c> / <c>Path.GetInvalidPathChars</c>
    /// answer the HOST OS's rules, not Windows'. Deliberately not calling either
    /// — a drive-qualified or backslash-rooted value must be rejected identically
    /// whether this runs in the macOS test process or the Windows box that
    /// actually executes it. "Not rooted" falls out of the separator and colon
    /// checks below rather than a dedicated check: a Windows path is rooted only
    /// via a leading separator or a drive letter followed by ':', and both are
    /// already rejected outright.
    ///
    /// Additionally (beyond IsSafePathSegment) rejects the DOS reserved device
    /// names — not a concern for ExtensionId/Profile, but Version here ultimately
    /// names a staging directory an installer is executed from, and "CON" flows
    /// through Path.Combine no differently from any ordinary name.
    /// </summary>
    internal static bool IsSafeVersionSegment(string? version)
    {
        if (string.IsNullOrWhiteSpace(version)) return false;
        if (version is "." or "..") return false;
        if (version.IndexOfAny(['/', '\\']) >= 0) return false; // separator, incl. UNC (\\server\share)
        if (version.Contains(':')) return false;                 // drive-qualified (C:) or NTFS ADS

        // Deliberately NOT Path.GetInvalidFileNameChars(): that is host-dependent.
        // On Windows it returns the full set below plus the control characters; on
        // macOS it returns only '\0' and '/'. Since the whole suite is routinely run
        // cross-target on macOS (see AGENTS.md), using it would make this security
        // check weaker under test than it is in production, and a test asserting a
        // rejection here would pass or fail purely on which machine ran it. Naming
        // the Windows-invalid set explicitly makes the behaviour identical
        // everywhere, so a macOS run is honest evidence about the shipped rule.
        // (PAT-1339 non-author review finding.)
        if (version.IndexOfAny(InvalidNameChars) >= 0) return false;
        foreach (var c in version)
            if (char.IsControl(c)) return false;

        // Windows silently STRIPS trailing dots and spaces from a path component:
        // "9.9.9 " and "9.9.9." both resolve to "9.9.9" on disk. That divergence
        // between the string we validated and the directory actually used is the
        // classic normalisation gap, so reject rather than reason about whether
        // canonicalising both sides happens to cancel it out. BootstrapUpdater
        // never writes a Version like this, so nothing legitimate is lost.
        // (PAT-1339 non-author review finding.)
        if (version[^1] is ' ' or '.') return false;

        string bareName = version.Contains('.') ? version[..version.IndexOf('.')] : version;
        if (ReservedDeviceNames.Contains(bareName)) return false;

        return true;
    }

    /// <summary>
    /// PAT-1339: the path <see cref="BootstrapUpdater"/> always stages to for a
    /// given version — confirmed against its source: <c>stageDir =
    /// Path.Combine(_updatesDir, availableVersion)</c>,
    /// <c>stageFile = Path.Combine(stageDir, "patched-agent.msi")</c>, and the
    /// marker it writes carries <c>installer_path = stageFile</c> verbatim.
    /// BootstrapUpdater is the only writer of this marker.
    /// </summary>
    private string ExpectedInstallerPath(string version) =>
        Path.Combine(_updatesDir, version, "patched-agent.msi");

    /// <summary>
    /// PAT-1339: true only when <paramref name="installerPath"/> is BOTH
    /// contained within <see cref="_updatesDir"/> with no reparse point anywhere
    /// in its chain from <see cref="_trustedRoot"/> (the same two
    /// <see cref="PathSafety"/> primitives PAT-1334 already uses at the two
    /// privileged deletes below) AND canonicalises to EXACTLY
    /// <see cref="ExpectedInstallerPath"/> for <paramref name="version"/>.
    /// Containment alone would still accept any other file BootstrapUpdater
    /// never wrote (e.g. a same-directory decoy under a different name); the
    /// exact-match check closes that. Conversely, the exact-match string
    /// comparison alone would NOT be enough on its own: <c>Path.GetFullPath</c>
    /// normalises the string but does not resolve reparse points, so a planted
    /// junction/symlink somewhere in the chain (most concretely, the per-version
    /// directory itself replaced with a junction into an attacker directory
    /// containing its own same-named "patched-agent.msi") can make the string
    /// equality pass while still redirecting execution elsewhere — exactly what
    /// the reparse-point-chain check exists to catch and the string check
    /// cannot.
    /// </summary>
    private bool IsTrustedInstallerPath(string installerPath, string version, out string expectedPath)
    {
        expectedPath = ExpectedInstallerPath(version);

        if (!PathSafety.IsContained(_updatesDir, installerPath)) return false;
        if (PathSafety.HasReparsePointInChain(_trustedRoot, installerPath)) return false;

        try
        {
            string fullActual   = Path.TrimEndingDirectorySeparator(Path.GetFullPath(installerPath));
            string fullExpected = Path.TrimEndingDirectorySeparator(Path.GetFullPath(expectedPath));
            return string.Equals(fullActual, fullExpected, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Removes the just-applied version's staged directory (installer +
    /// its folder) after a confirmed-successful apply.</summary>
    private void CleanupStagedDirectory(string version) => DeleteStagedDirectory(version);

    /// <summary>
    /// Removes every staged-update subdirectory under updates\ EXCEPT
    /// <paramref name="currentPendingVersion"/> (when non-null). At ~160 MB per
    /// staged MSI, WIN-STAGING accumulated three releases' worth of stubs and one
    /// full MSI before this existed — left unpruned, that fills a disk. Best-effort
    /// per-directory: one undeletable directory (e.g. a file still locked by the
    /// msiexec this same call may have just launched) must not stop the others
    /// from being pruned.
    /// </summary>
    private void PruneStaleStagedDirectories(string? currentPendingVersion)
    {
        if (!Directory.Exists(_updatesDir))
            return;

        // PAT-1334: BootstrapUpdater now hardens this chain at creation time
        // (PAT-1338), but this runs on a later service start, deletes
        // recursively as LocalSystem, and can meet an updates\ staged by a
        // pre-PAT-1338 build. If _updatesDir itself has become a reparse point
        // (planted, or an ancestor swapped out from under it), enumerating it
        // returns paths THROUGH the link — see PathSafety's class doc, the
        // "junction as an ancestor" case, empirically DESTRUCTIVE: recursively
        // deleting an entry from that enumeration wipes the real target's
        // contents. Refuse the whole pass rather than delete anything.
        if (PathSafety.HasReparsePointInChain(_trustedRoot, _updatesDir))
        {
            _log.LogWarning(
                "pending-update-applier: refusing to prune {Dir} — reparse point in its chain from {Root}",
                _updatesDir, _trustedRoot);
            return;
        }

        IEnumerable<string> dirs;
        try { dirs = Directory.GetDirectories(_updatesDir); }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "pending-update-applier: failed to enumerate {Dir} for pruning", _updatesDir);
            return;
        }

        string? cleanupFailure = null;
        foreach (var dir in dirs)
        {
            string name = Path.GetFileName(dir);
            if (currentPendingVersion is not null &&
                string.Equals(name, currentPendingVersion, StringComparison.OrdinalIgnoreCase))
                continue;

            // PAT-2400: an untrusted child is never recursed into (see
            // WindowsStagedUpdateTrustVerifier); it is unlinked or moved aside whole.
            // A planted directory named for a future version would otherwise block
            // that version's stage for good.
            string? untrusted = _trustVerifier.WhyUntrusted(dir, isDirectory: true);
            if (untrusted is not null)
            {
                string? failure = untrusted == "absent" ? null : RemoveUntrusted(dir);
                cleanupFailure ??= failure;
                _log.LogWarning(
                    "pending-update-applier: staged directory {Dir} is untrusted ({Reason}); removal: {Removal}",
                    dir, untrusted, failure ?? "done");
                continue;
            }

            // Belt-and-braces per child, same two checks as above: containment
            // guards a name that somehow escapes _updatesDir, the chain walk
            // guards a junction planted as this specific child (or a
            // component under it) between the enumeration above and this
            // delete. Best-effort contract preserved: skip only this one
            // directory, keep pruning the rest.
            if (!PathSafety.IsContained(_updatesDir, dir) ||
                PathSafety.HasReparsePointInChain(_trustedRoot, dir))
            {
                _log.LogWarning(
                    "pending-update-applier: refusing to prune {Dir} — fails containment/reparse-point check",
                    dir);
                continue;
            }

            try
            {
                Directory.Delete(dir, recursive: true);
                _log.LogInformation("pending-update-applier: pruned stale staged update directory {Dir}", dir);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "pending-update-applier: failed to prune stale staged update directory {Dir}", dir);
            }
        }

        // PAT-2400: an untrusted child left in place blocks staging of the version it
        // is named for and, at the quarantine cap, needs an operator. Say so, and
        // withdraw it on the first pass that finds nothing stuck.
        if (cleanupFailure is not null)
            _agentHealth.RecordFailure(HealthKind, CleanupHealthSubject, "untrusted_child_" + cleanupFailure);
        else
            _agentHealth.ClearFailure(HealthKind, CleanupHealthSubject, "untrusted_child_");
    }

    private void DeleteStagedDirectory(string version)
    {
        string dir = Path.Combine(_updatesDir, version);
        if (!Directory.Exists(dir))
            return;

        // PAT-1334: same guard as PruneStaleStagedDirectories — this also
        // covers a marker whose `version` string contains path separators or
        // "..", since a Path.Combine escape would fail IsContained here even
        // though nothing upstream currently validates `version` the way
        // ExtensionRemovalLogic validates ExtensionId/Profile (PAT-1329
        // Defect A). Deliberately no AgentHealthStore call on this refusal:
        // the self_update/apply (kind, subject) pair carries the apply
        // outcome for this service start, and a refused best-effort cleanup
        // on an otherwise successful apply must not overwrite that success
        // with a degraded report.
        if (!PathSafety.IsContained(_updatesDir, dir) ||
            PathSafety.HasReparsePointInChain(_trustedRoot, dir))
        {
            _log.LogWarning(
                "pending-update-applier: refusing to remove staged directory {Dir} — fails containment/reparse-point check",
                dir);
            return;
        }

        try
        {
            Directory.Delete(dir, recursive: true);
            _log.LogInformation("pending-update-applier: removed staged directory {Dir} after successful apply", dir);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "pending-update-applier: failed to remove staged directory {Dir} after successful apply", dir);
        }
    }

    /// <summary>
    /// PAT-2400: one staged object's trust verdict. True when trusted. Otherwise the
    /// object is removed so the path can be restaged, and a distinct degraded reason is
    /// recorded: <c>staged_&lt;object&gt;_&lt;why&gt;</c>, with <c>_removal_failed</c>
    /// appended when it is still there. The caller stops; nothing is launched.
    /// </summary>
    private bool StagedObjectTrusted(string path, bool isDirectory, string name, bool absentIsFine)
    {
        string? why = _trustVerifier.WhyUntrusted(path, isDirectory);
        if (why is null || (absentIsFine && why == "absent"))
            return true;

        string? failure = why == "absent" ? null : RemoveUntrusted(path);
        string reason = $"{StagedReasonPrefix}{name}_{why}" + (failure is null ? "" : "_" + failure);
        _log.LogError(
            "pending-update-applier: staged {Object} {Path} is not trusted ({Why}); refusing to apply. " +
            "Removal for restaging: {Removal}", name, path, why, failure ?? "done");
        _agentHealth.RecordFailure(HealthKind, HealthSubject, reason);
        return false;
    }

    /// <summary>
    /// PAT-2400: hands an untrusted object to the verifier for removal, but only the
    /// updates root, something inside it, or the marker file, and only when no reparse
    /// point lies between the trusted root and the object's parent. The object itself
    /// may be a link: unlinking it does not follow it.
    /// </summary>
    internal string? RemoveUntrusted(string path)
    {
        string full, parent;
        try
        {
            full   = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
            parent = Path.GetDirectoryName(full) ?? "";
        }
        catch { return "removal_failed"; }

        bool ours = SamePath(full, _updatesDir) || SamePath(full, _pendingUpdateFile) ||
                    PathSafety.IsContained(_updatesDir, full);
        if (!ours || parent.Length == 0 || PathSafety.HasReparsePointInChain(_trustedRoot, parent))
        {
            _log.LogError(
                "pending-update-applier: refusing to remove {Path}: outside the staged-update tree under {Root}, or reached through a link",
                path, _trustedRoot);
            return "removal_failed";
        }

        return _trustVerifier.Remove(full, _trustedRoot);
    }

    private static bool SamePath(string fullPath, string other) =>
        string.Equals(fullPath, Path.TrimEndingDirectorySeparator(Path.GetFullPath(other)), StringComparison.OrdinalIgnoreCase);

    private void ClearMarker()
    {
        try
        {
            if (File.Exists(_pendingUpdateFile))
                File.Delete(_pendingUpdateFile);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "pending-update-applier: failed to clear marker {File}", _pendingUpdateFile);
        }
    }

    /// <summary>Atomic write: temp file in the same directory, then File.Move with
    /// overwrite — same pattern as BootstrapUpdater's own marker write.</summary>
    private void WriteMarker(Marker marker)
    {
        string tmp = _pendingUpdateFile + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(marker));
        File.Move(tmp, _pendingUpdateFile, overwrite: true);
    }

    /// <summary>
    /// Wire shape of pending-agent-update.json. Field names match BootstrapUpdater's
    /// writer exactly (snake_case, since that anonymous type's C# property names ARE
    /// the JSON names — no naming policy is applied anywhere in this pipeline).
    /// <see cref="Sha256"/> is nullable specifically to distinguish "field absent"
    /// (a pre-PAT-1261 marker — see the backward-compatibility branch above) from
    /// any other value; <see cref="Attempts"/> defaults to 0 so a fresh marker
    /// (which never carries this field, only the applier's own rewrite does) parses
    /// as attempt zero rather than throwing.
    /// </summary>
    private sealed class Marker
    {
        [JsonPropertyName("version")]         public string  Version       { get; set; } = "";
        [JsonPropertyName("installer_path")]  public string  InstallerPath { get; set; } = "";
        [JsonPropertyName("sha256")]          public string? Sha256        { get; set; }
        [JsonPropertyName("staged_at")]       public DateTimeOffset StagedAt { get; set; }
        [JsonPropertyName("attempts")]        public int     Attempts      { get; set; }

        // PAT-2396: the signed envelope, verbatim. Nullable for the same reason as
        // Sha256: absent means "written before this existed, or planted". Declared here
        // so the attempt-count rewrite (WriteMarker) carries them through unchanged.
        [JsonPropertyName(StagedUpdateEnvelope.PayloadField)]   public string? SignedPayload { get; set; }
        [JsonPropertyName(StagedUpdateEnvelope.SignatureField)] public string? Signature     { get; set; }
        [JsonPropertyName(StagedUpdateEnvelope.KeyIdField)]     public string? KeyId         { get; set; }
    }
}

/// <summary>
/// Seam so <see cref="PendingUpdateApplier"/> is unit-testable without actually
/// launching msiexec.exe — tests assert what WOULD be executed via a fake that
/// records the call, never the real process. Production DI binds this to
/// <see cref="MsiexecPendingUpdateLauncher"/>.
/// </summary>
internal interface IPendingUpdateLauncher
{
    /// <summary>
    /// Launches `msiexec /i "&lt;installerPath&gt;" /qn /norestart` DETACHED from
    /// the calling process (UseShellExecute=false, not waited on, not tied to this
    /// process's lifetime) — see <see cref="PendingUpdateApplier"/>'s class doc
    /// comment for why detachment is required (stopping a Windows service does not
    /// kill its child processes). Returns true once the process has actually
    /// started; never throws — a launch failure (missing msiexec.exe, access
    /// denied, ...) is caught and reported as false so the caller can record a
    /// distinct degraded reason.
    /// </summary>
    bool LaunchDetached(string installerPath);
}

/// <summary>
/// Production <see cref="IPendingUpdateLauncher"/>: an actual detached
/// `msiexec /i "&lt;path&gt;" /qn /norestart`. Windows-only (Process launch of a
/// Windows executable) — mirrors <see cref="DecommissionHandoff"/>'s
/// SupportedOSPlatform annotation for the same reason.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class MsiexecPendingUpdateLauncher : IPendingUpdateLauncher
{
    private readonly ILogger<MsiexecPendingUpdateLauncher> _log;

    public MsiexecPendingUpdateLauncher(ILogger<MsiexecPendingUpdateLauncher> log)
    {
        _log = log;
    }

    public bool LaunchDetached(string installerPath)
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName        = "msiexec.exe",
                    Arguments       = $"/i \"{installerPath}\" /qn /norestart",
                    UseShellExecute = false,
                    CreateNoWindow  = true,
                },
            };
            // Start() returns once the OS process exists; disposing the managed
            // Process object below (end of using block) releases only this
            // process's handle to it, it does not terminate the launched
            // process — msiexec keeps running fully detached from this service.
            return proc.Start();
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "pending-update-applier: failed to start msiexec.exe for {Path}", installerPath);
            return false;
        }
    }
}
