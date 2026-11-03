using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Patched.Shared.Auth;
using Patched.Shared.Paths;
using Patched.Shared.Security;

namespace Patched.Service;

/// <summary>
/// PAT-1110: schedules the detached removal handoff — see
/// <see cref="DecommissionHandoffScript"/> for what the script itself does, and the
/// self-removal-problem section of the PAT-1110 brief for why a scheduled task is
/// used instead of an MSI custom action (PAT-599 precedent: a custom action DLL
/// failed 1603/1154 on ARM64).
///
/// The handoff script's OWN staging path must not be writable by a non-admin
/// principal — a hijackable handoff for the product's only irreversible action is a
/// local privilege escalation. <see cref="PathConstants.DecommissionDir"/> is hardened
/// via <see cref="SecureStagingDirectory"/> (SYSTEM/Administrators only, fails closed
/// on a pre-planted reparse point/junction) — the same TOCTOU-hardening reasoning
/// PAT-857 already applied to download staging, and the Windows equivalent of the
/// admin-only BUNDLE_DIR reasoning on the macOS side. The same hardened directory also
/// holds the single-use report-credentials snapshot (second contract round) the
/// script needs for its own authenticated terminal-status POST — leaking a bearer
/// token/HMAC secret to a non-admin principal would be at least as bad as a hijacked
/// script, so it gets the identical protection, not a separate weaker one.
///
/// Round-2 non-author review (item 5): staging (<see cref="EnsureStaged"/>, which
/// creates the ONSTART-triggered scheduled task) and triggering it immediately
/// (<see cref="TriggerNow"/>) are deliberately SEPARATE operations, not one atomic
/// call. <see cref="DecommissionRunner"/> writes its durable "committed" marker
/// in between the two — AFTER staging succeeds (the task is armed; a reboot at any
/// point from here on will run it regardless) but BEFORE the immediate trigger is
/// even attempted. This closes a narrow but real crash-recovery race: with a single
/// combined call, a service crash landing between a successful /Run and the marker
/// write would leave the marker absent while removal is already under way, so a
/// restart could re-enter the acknowledge/report flow and call
/// <see cref="EnsureDeregistered"/> against a task whose detached process may
/// already be executing — deleting the (by then irrelevant) task DEFINITION while
/// the already-launched instance keeps running regardless, and misreporting
/// "aborted, service remains installed" for a removal that is, in fact, proceeding.
/// Splitting the two calls and recording the marker between them means a crash
/// anywhere at or after successful staging is always recovered by retrying ONLY the
/// trigger (see DecommissionRunner.ActuateAsync), never by re-entering the
/// report/abort path for a directive that is already committed.
///
/// IMPORTANT — this does not make an in-flight removal abortable, and does not
/// pretend to: once the detached PowerShell process is actually executing (msiexec
/// under way), deleting the scheduled task's definition cannot stop it — that
/// post-launch irreversibility is inherent to any detached self-removal design, on
/// any OS. The platform already authorized removal (the acknowledge→proceed
/// handshake completes before <see cref="EnsureStaged"/> is ever called) before this
/// class does anything at all; nothing after that point claims to be cancellable.
///
/// NOT independently unit-testable: registering/triggering a real Windows scheduled
/// task requires a live Task Scheduler service (Windows-only, admin-only). Covered by
/// <see cref="DecommissionHandoffScript"/>'s own tests (the pure content this class
/// stages) and by <see cref="IDecommissionHandoff"/> test doubles in
/// DecommissionRunnerTests, which exercise the calling contract without touching the
/// OS.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DecommissionHandoff : IDecommissionHandoff
{
    private readonly ILogger<DecommissionHandoff> _log;
    private readonly CredentialStore              _creds;
    private readonly string                       _decommissionDir;
    private readonly string                       _scriptFile;
    private readonly string                       _reportCredsFile;
    private readonly string                       _stateDir;

    public DecommissionHandoff(ILogger<DecommissionHandoff> log, CredentialStore creds)
        : this(log, creds, PathConstants.DecommissionDir, PathConstants.DecommissionScriptFile,
               PathConstants.DecommissionReportCredsFile, PathConstants.StateDir)
    {
    }

    /// <summary>
    /// PAT-1774: test seam — the same staging/deregistration logic with every
    /// %ProgramData%\Patched path it writes (the hardened decommission directory, the
    /// staged removal script, the single-use report-creds snapshot, and the hardening
    /// trust anchor) redirected to a scratch tree, so a test can exercise the file
    /// I/O in this class (<see cref="EnsureStaged"/>/<see cref="WriteReportCredsSnapshot"/>/
    /// <see cref="EnsureDeregistered"/>) without ever touching the real
    /// %ProgramData%\Patched\decommission. schtasks.exe calls are unaffected — see the
    /// class doc comment: this class remains NOT independently unit-testable
    /// end-to-end without a live Windows Task Scheduler. Production always uses the
    /// public constructor.
    /// </summary>
    internal DecommissionHandoff(
        ILogger<DecommissionHandoff> log,
        CredentialStore              creds,
        string                       decommissionDir,
        string                       scriptFile,
        string                       reportCredsFile,
        string                       stateDir)
    {
        _log             = log;
        _creds           = creds;
        _decommissionDir = decommissionDir;
        _scriptFile      = scriptFile;
        _reportCredsFile = reportCredsFile;
        _stateDir        = stateDir;
    }

    /// <summary>
    /// Stages the removal script (and its single-use report-credentials snapshot)
    /// into the hardened decommission directory, then registers (idempotently — /F
    /// overwrites any prior definition, so a re-attempt after a transient
    /// schtasks.exe failure is safe) a SYSTEM, highest-privilege scheduled task with
    /// an ONSTART trigger — so an interruption anywhere from this point on resumes
    /// on the machine's next boot without waiting for anyone to notice.
    ///
    /// Deliberately does NOT trigger the task — see <see cref="TriggerNow"/> and the
    /// class doc comment for why that is a separate call with the caller's durable
    /// marker write required in between. Returns true once the task has been staged
    /// (created, armed for at-latest-next-boot execution). Never throws — callers
    /// (<see cref="DecommissionRunner"/>) treat a false return as a fault to record
    /// and retry next cycle, exactly like every other fail-safe engine in this
    /// service.
    /// </summary>
    /// <param name="directiveVersion">
    /// Embedded into the script so its own terminal-status report (after the .NET
    /// service that captured this value is long stopped) still carries the correct
    /// directive_version — see DecommissionStatusReporter's identical parameter.
    /// </param>
    public bool EnsureStaged(bool purge, int directiveVersion)
    {
        try
        {
            SecureStagingDirectory.EnsureHardenedChain(_decommissionDir, _stateDir);

            WriteReportCredsSnapshot();

            string script = DecommissionHandoffScript.Build(
                PathConstants.DecommissionTaskName, purge, _stateDir,
                directiveVersion, _reportCredsFile);
            File.WriteAllText(_scriptFile, script);

            string createArgs =
                $"/Create /TN \"{PathConstants.DecommissionTaskName}\" /SC ONSTART " +
                $"/RU SYSTEM /RL HIGHEST /F " +
                $"/TR \"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass " +
                $"-File \\\"{_scriptFile}\\\"\"";

            if (!RunSchtasks(createArgs))
            {
                _log.LogError("decommission: schtasks /Create failed — handoff not staged");
                return false;
            }

            _log.LogWarning(
                "decommission: removal handoff staged (task={Task}, purge={Purge}) — armed for " +
                "at-latest-next-boot execution via ONSTART regardless of the immediate trigger's outcome",
                PathConstants.DecommissionTaskName, purge);
            return true;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "decommission: failed to stage removal handoff");
            return false;
        }
    }

    /// <summary>
    /// Triggers the already-staged scheduled task to run immediately, rather than
    /// waiting for the machine's next boot. Separate from <see cref="EnsureStaged"/>
    /// — see the class doc comment for why, and <see cref="DecommissionRunner"/> for
    /// how a failed trigger is retried on a later poll cycle without ever
    /// re-staging or re-reporting. Never throws; a false return means the task is
    /// still armed (ONSTART will run it on next boot regardless) but did not start
    /// immediately — the caller should retry this call, not treat it as fatal.
    /// </summary>
    public bool TriggerNow()
    {
        try
        {
            if (!RunSchtasks($"/Run /TN \"{PathConstants.DecommissionTaskName}\""))
            {
                _log.LogError(
                    "decommission: schtasks /Run failed — task remains armed for next boot (ONSTART) " +
                    "but did not start immediately; will retry the immediate trigger next cycle");
                return false;
            }

            _log.LogWarning(
                "decommission: removal handoff triggered immediately (task={Task})",
                PathConstants.DecommissionTaskName);
            return true;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "decommission: failed to trigger removal handoff");
            return false;
        }
    }

    /// <summary>
    /// Second contract round: called on a 409/aborted acknowledge-report, so a
    /// superseded/cancelled directive can never leave a task registered with an
    /// ONSTART trigger that would remove the agent on the machine's next reboot
    /// regardless of the cancellation. Safe to call unconditionally, including when
    /// nothing was ever registered ("nothing armed" either way). Only ever reachable
    /// BEFORE <see cref="DecommissionRunner"/> writes its committed marker — see the
    /// class doc comment: once staged and marked, this class is never asked to
    /// deregister again for that directive, precisely because a removal that has
    /// reached that point may already be irreversibly in flight.
    ///
    /// /Delete's OWN exit code is not trusted as proof the task is gone — "delete on
    /// an unknown task name fails harmlessly" means a nonzero exit here is
    /// ambiguous between "genuinely failed to remove an armed task" and "there was
    /// nothing to delete", and those two are NOT the same outcome for this method's
    /// contract. <see cref="QueryTaskState"/> is the actual source of truth, and
    /// (round-2 item 4) itself distinguishes a genuine "not found" result from any
    /// OTHER query failure (access denied, scheduler error, malformed output) —
    /// only a confirmed "not found" counts as absent; everything else fails closed
    /// as "still present / unknown". Only once the task is CONFIRMED absent is the
    /// report-creds snapshot removed. If the task cannot be confirmed absent, this
    /// fails closed — returns false so the caller can record a fault, and
    /// deliberately KEEPS the report-creds snapshot, since a task that is still
    /// armed (or whose state could not be determined) may yet fire and needs it to
    /// authenticate its own terminal report; deleting the creds here would strand
    /// that eventual run with a task it can no longer report from.
    /// Never throws.
    /// </summary>
    /// <returns>
    /// True once the task is CONFIRMED not registered (and the report-creds
    /// snapshot, if any, has been removed). False if the task is still registered,
    /// or its state could not be confirmed either way — the caller should record a
    /// fault rather than treat the abort as fully clean.
    /// </returns>
    public bool EnsureDeregistered()
    {
        try
        {
            RunSchtasks($"/Delete /TN \"{PathConstants.DecommissionTaskName}\" /F");
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "decommission: failed to run schtasks /Delete on abort");
        }

        if (QueryTaskState(PathConstants.DecommissionTaskName) != TaskQueryResult.Absent)
        {
            _log.LogError(
                "decommission: scheduled task '{Task}' not confirmed absent after /Delete on abort — " +
                "could not fully disarm the handoff; report-creds snapshot is being KEPT so a " +
                "reboot-fired run can still authenticate its terminal report",
                PathConstants.DecommissionTaskName);
            return false;
        }

        try
        {
            if (File.Exists(_reportCredsFile))
                File.Delete(_reportCredsFile);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "decommission: failed to remove report-creds snapshot on abort");
        }

        return true;
    }

    /// <summary>Outcome of <see cref="QueryTaskState"/>. Internal (not private): <see cref="ClassifyQueryResult"/> is directly unit tested — see DecommissionHandoffTests.</summary>
    internal enum TaskQueryResult
    {
        /// <summary>schtasks confirmed, by its well-known "not found" result, that no task with this name is registered.</summary>
        Absent,

        /// <summary>schtasks confirmed the task IS registered.</summary>
        Present,

        /// <summary>
        /// The query itself failed for some reason OTHER than "not found" (access
        /// denied, Task Scheduler service unavailable, a timeout, malformed/
        /// unrecognised output, ...). Deliberately NOT folded into either Absent or
        /// Present — round-2 non-author review item 4: treating every nonzero exit
        /// as "absent" would let the abort path delete the report-creds snapshot
        /// while an ONSTART removal task might still be fully armed. Callers must
        /// treat this exactly like <see cref="Present"/> (fail closed).
        /// </summary>
        Unknown,
    }

    /// <summary>
    /// Ground truth for whether the decommission scheduled task is currently
    /// registered — <c>schtasks /Query /TN</c>. Round-2 item 4: a nonzero exit code
    /// alone does not mean "not found" — access-denied, a Task Scheduler service
    /// error, or unrecognised/malformed output are also nonzero and must NOT be
    /// read the same way. Only schtasks' own well-known "cannot find the file
    /// specified" not-found message (English locale — this codebase already assumes
    /// English schtasks/msiexec output elsewhere, e.g. the installer tooling) is
    /// treated as a confirmed <see cref="TaskQueryResult.Absent"/>; every other
    /// nonzero-exit reason returns <see cref="TaskQueryResult.Unknown"/>, and a
    /// timeout or thrown exception also returns <see cref="TaskQueryResult.Unknown"/>
    /// — fails CLOSED, the same "an unreadable answer is not a yes" discipline
    /// <see cref="DecommissionStatusReporter"/> applies to the platform's response,
    /// applied here to the local Task Scheduler state <see cref="EnsureDeregistered"/>
    /// depends on.
    /// </summary>
    private TaskQueryResult QueryTaskState(string taskName)
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName               = "schtasks.exe",
                    Arguments              = $"/Query /TN \"{taskName}\"",
                    UseShellExecute        = false,
                    CreateNoWindow         = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                },
            };
            proc.Start();
            proc.WaitForExit((int)TimeSpan.FromSeconds(30).TotalMilliseconds);
            if (!proc.HasExited)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                _log.LogError("decommission: schtasks.exe /Query timed out ({Task})", taskName);
                return TaskQueryResult.Unknown;
            }

            string stderr = proc.StandardError.ReadToEnd();
            var result = ClassifyQueryResult(proc.ExitCode, stderr);
            if (result == TaskQueryResult.Unknown)
            {
                _log.LogError(
                    "decommission: schtasks /Query exited {Code} for an unrecognised reason (not the " +
                    "known 'task not found' message) — treating as Unknown, not Absent: {Stderr}",
                    proc.ExitCode, stderr);
            }
            return result;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "decommission: failed to query scheduled task state ({Task})", taskName);
            return TaskQueryResult.Unknown;
        }
    }

    /// <summary>
    /// Pure classification of an already-captured schtasks /Query exit code +
    /// stderr — split out from <see cref="QueryTaskState"/> (which does the actual
    /// process I/O and cannot run outside a real Windows host) so the
    /// exit-code/message logic itself is directly unit testable. Internal (not
    /// private): see DecommissionHandoffTests for the "query-failure is NOT the
    /// same as absent" regression proof (round-2 non-author review item 4).
    /// </summary>
    internal static TaskQueryResult ClassifyQueryResult(int exitCode, string stderr)
    {
        if (exitCode == 0)
            return TaskQueryResult.Present;

        if (stderr.Contains("cannot find the file specified", StringComparison.OrdinalIgnoreCase))
            return TaskQueryResult.Absent;

        // Any other nonzero exit — access denied, Task Scheduler service error,
        // malformed/localised output, or simply an unrecognised message — is NOT a
        // confirmed absence. See the enum's own doc comment: this is the whole
        // point of round-2 item 4.
        return TaskQueryResult.Unknown;
    }

    /// <summary>
    /// Writes the single-use credential snapshot the detached script authenticates
    /// its own terminal-status POST with, since the script runs after the .NET
    /// service's own CredentialStore/Windows Credential Manager access is gone
    /// (the service that owns it is stopped partway through that same script).
    /// Written into the SecureStagingDirectory-hardened decommission dir — same
    /// directory-ACL protection as the script itself (see class doc comment) — but
    /// that alone would be a downgrade from how this exact bearer token/HMAC secret
    /// is protected everywhere else (<see cref="CredentialStore"/>, Windows
    /// Credential Manager, DPAPI-protected at rest via
    /// <c>CRED_PERSIST_LOCAL_MACHINE</c>). So the JSON blob is ALSO encrypted with
    /// DPAPI (<see cref="ProtectedData.Protect"/>, <see
    /// cref="DataProtectionScope.LocalMachine"/>) before being written — the same
    /// protection level, not a weaker one relying on filesystem ACLs alone.
    /// <c>LocalMachine</c> scope (not <c>CurrentUser</c>) is required because the
    /// detached script runs as SYSTEM via the scheduled task, not as whatever
    /// principal happened to be logged in when the service staged this file. The
    /// detached PowerShell script decrypts it the same way — see
    /// <see cref="DecommissionHandoffScript"/>'s terminal-report step — before
    /// parsing it as JSON. The script keeps this file until its own terminal report
    /// has actually been delivered (or its bounded cross-boot retry budget is
    /// exhausted — see DecommissionHandoffScript), deleting it itself once that
    /// happens, regardless of purge; <see cref="EnsureDeregistered"/> is the
    /// abort-path backstop for the case where the script never runs at all.
    /// </summary>
    private void WriteReportCredsSnapshot()
    {
        var snapshot = new
        {
            api_url      = PathConstants.ApiUrl,
            bearer_token = _creds.BearerToken,
            hmac_secret  = _creds.HmacSecret,
        };
        byte[] plaintext = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(snapshot));
        byte[] encrypted = ProtectedData.Protect(plaintext, optionalEntropy: null, DataProtectionScope.LocalMachine);

        string tmp = _reportCredsFile + ".tmp";
        File.WriteAllBytes(tmp, encrypted);
        File.Move(tmp, _reportCredsFile, overwrite: true);
    }

    private bool RunSchtasks(string arguments)
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName               = "schtasks.exe",
                    Arguments              = arguments,
                    UseShellExecute        = false,
                    CreateNoWindow         = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                },
            };
            proc.Start();
            proc.WaitForExit((int)TimeSpan.FromSeconds(30).TotalMilliseconds);
            if (!proc.HasExited)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                _log.LogError("decommission: schtasks.exe timed out ({Args})", arguments);
                return false;
            }
            if (proc.ExitCode != 0)
            {
                string stderr = proc.StandardError.ReadToEnd();
                _log.LogError("decommission: schtasks.exe exited {Code} ({Args}): {Stderr}",
                    proc.ExitCode, arguments, stderr);
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "decommission: failed to run schtasks.exe ({Args})", arguments);
            return false;
        }
    }
}

/// <summary>
/// Seam so <c>DecommissionRunner</c> is unit-testable without a real Windows Task
/// Scheduler. Production DI binds this to <see cref="DecommissionHandoff"/>.
/// </summary>
public interface IDecommissionHandoff
{
    /// <summary>Stages the removal task (creates it, armed via ONSTART) but does NOT trigger it. See DecommissionHandoff.EnsureStaged.</summary>
    bool EnsureStaged(bool purge, int directiveVersion);

    /// <summary>Triggers an already-staged task to run immediately. See DecommissionHandoff.TriggerNow.</summary>
    bool TriggerNow();

    /// <summary>
    /// Second contract round: abort-path backstop — see
    /// DecommissionHandoff.EnsureDeregistered. Returns false when the task could not
    /// be confirmed removed (still armed, or unconfirmed) — the caller should record
    /// a fault rather than treat the abort as fully clean.
    /// </summary>
    bool EnsureDeregistered();
}
