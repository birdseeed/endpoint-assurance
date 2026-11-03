using System.Diagnostics;
using System.Runtime.Versioning;
using Patched.Shared.Paths;
using Patched.Shared.Security;

namespace Patched.Service;

/// <summary>
/// PAT-1293: schedules the one-shot restart that lets
/// <see cref="PendingUpdateApplier"/>.Apply() (service-start only, see
/// <c>Worker.ExecuteAsync</c>) get a chance to consume a pending self-update marker
/// <see cref="BootstrapUpdater"/> has already staged. See
/// <see cref="PendingUpdateRestartScript"/> for what the script itself does.
///
/// The bug this closes: BootstrapUpdater discovers a release, downloads it, and
/// writes <c>pending-agent-update.json</c>, but PendingUpdateApplier only ever
/// consumes that marker at service START — nothing in the product ever decided to
/// perform the restart itself. No timer, no watchdog, no self-stop; the MSI's
/// ServiceConfig only restarts on crash, not on a healthy staged-update exit. Every
/// endpoint that appeared to "self-update" during development was in fact bounced by
/// a human running Stop-Service/Start-Service — this is the third instance of the
/// same "correct code, never invoked" shape (PAT-1261, PAT-1269), and this ticket is
/// the one that reaches the actual end of the rail instead of moving the wall back
/// again.
///
/// Registered by the SERVICE, not the MSI — Andy's explicit decision (PAT-1293
/// brief), not re-litigated here. An MSI-registered task only lands on a machine
/// that runs a NEW installer, and those are exactly the machines that cannot need an
/// unattended trigger (a human is already there running the installer). Registering
/// from the running service means the mechanism travels with any build that
/// contains it — including the very update this same service instance just staged —
/// and keeps the restart trigger physically next to the marker write it exists to
/// act on (see the call site in BootstrapUpdater.cs).
///
/// Follows <see cref="DecommissionHandoff"/>'s established shape closely:
/// schtasks.exe via a RunSchtasks-style helper with a timeout, exit-code logging,
/// and a never-throws contract; <c>/F</c> for idempotent re-registration; a script
/// staged into a <see cref="SecureStagingDirectory"/>-hardened directory and
/// invoked with <c>-NoProfile -NonInteractive -ExecutionPolicy Bypass -File</c>;
/// and a pure, separately-testable content builder
/// (<see cref="PendingUpdateRestartScript"/>).
///
/// Registration itself goes through a Task Scheduler XML definition
/// (<c>schtasks /Create /TN "&lt;name&gt;" /XML "&lt;path&gt;" /F</c>, built by
/// <see cref="PendingUpdateRestartTaskXml"/>) rather than <c>/SC ONCE /ST /SD /RU
/// /RL</c> directly on the command line — non-author review round 2 caught that
/// <c>/SD</c> is parsed against the SYSTEM's own regional short-date order, which
/// silently fails registration on any non-US-date-order locale, en-GB included
/// (the common case among this company's own endpoints). See
/// <see cref="PendingUpdateRestartTaskXml"/>'s class doc comment for the full
/// reasoning; schtasks.exe remains the mechanism either way, so the
/// DecommissionHandoff precedent above still holds — only the INPUT format
/// changed.
///
/// Deliberately ONE-SHOT (a single <c>&lt;TimeTrigger&gt;</c>), not ONSTART: a boot
/// already applies the marker via <c>Worker.ExecuteAsync</c>'s normal
/// <see cref="PendingUpdateApplier"/>.Apply() call at service start. An ONSTART
/// trigger here would be redundant machinery duplicating a path that already
/// exists.
///
/// NOT independently unit-testable end-to-end: registering a real Windows scheduled
/// task requires a live Task Scheduler service (Windows-only, admin-only).
/// <see cref="PendingUpdateRestartTaskXml.Build"/> — the task-definition XML,
/// including the <c>&lt;StartBoundary&gt;</c> start-time math and its
/// midnight-rollover case — IS pure and is directly unit tested (see
/// PendingUpdateRestartTaskXmlTests), <see cref="BuildCreateArgs"/> (the much
/// smaller schtasks argument string that now only names the XML file) has its own
/// tests (PendingUpdateRestartSchedulerTests), and
/// <see cref="PendingUpdateRestartScript"/> covers the script content itself
/// (PendingUpdateRestartScriptTests). Fail-safe registration behaviour (never
/// throws, records a degraded signal rather than staying silent) is covered from
/// the BootstrapUpdater side, via a fake <see cref="IPendingUpdateRestartScheduler"/>
/// — see BootstrapUpdaterTests.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PendingUpdateRestartScheduler : IPendingUpdateRestartScheduler
{
    // PAT-1293: 5 minutes lets an in-flight inventory or install cycle finish
    // rather than being cut off the instant an update stages — see the call site
    // in BootstrapUpdater.cs. The service stops gracefully (BackgroundService
    // cancellation propagates through the worker's own await points), and this
    // restart is a background service bounce the user never sees (not an
    // interactive session, not a maintenance-window action), so it does not need
    // to wait for an off-hours window — but firing INSTANTLY would cut off
    // whatever the service happens to be mid-way through the moment an update
    // finishes staging.
    internal static readonly TimeSpan RestartDelay = TimeSpan.FromMinutes(5);

    private readonly ILogger<PendingUpdateRestartScheduler> _log;
    private readonly string                                 _restartDir;
    private readonly string                                 _scriptFile;
    private readonly string                                 _taskXmlFile;
    private readonly string                                 _stateDir;

    public PendingUpdateRestartScheduler(ILogger<PendingUpdateRestartScheduler> log)
        : this(log, PathConstants.SelfUpdateRestartDir, PathConstants.SelfUpdateRestartScriptFile,
               PathConstants.SelfUpdateRestartTaskXmlFile, PathConstants.StateDir)
    {
    }

    /// <summary>
    /// PAT-1774: test seam — the same scheduling logic with every %ProgramData%\Patched
    /// path it writes (the hardened restart-staging directory, the restart script, the
    /// task-definition XML, and the hardening trust anchor) redirected to a scratch
    /// tree, mirroring <see cref="DecommissionHandoff"/>'s identical seam (see this
    /// class's own doc comment: it follows DecommissionHandoff's established shape).
    /// schtasks.exe calls are unaffected — this class remains NOT independently
    /// unit-testable end-to-end without a live Windows Task Scheduler. Production
    /// always uses the public constructor.
    /// </summary>
    internal PendingUpdateRestartScheduler(
        ILogger<PendingUpdateRestartScheduler> log,
        string                                 restartDir,
        string                                 scriptFile,
        string                                 taskXmlFile,
        string                                 stateDir)
    {
        _log         = log;
        _restartDir  = restartDir;
        _scriptFile  = scriptFile;
        _taskXmlFile = taskXmlFile;
        _stateDir    = stateDir;
    }

    /// <summary>
    /// Stages the restart script and registers (idempotently — <c>/F</c> overwrites
    /// any prior definition, so a re-attempt after a transient schtasks.exe failure
    /// is safe) a SYSTEM, highest-privilege, one-shot scheduled task that fires
    /// <see cref="RestartDelay"/> from now.
    ///
    /// Never throws — fail-safe, the same contract as every other engine in this
    /// service. Returns false on any failure; the caller (BootstrapUpdater) is
    /// responsible for recording the degraded signal via AgentHealthStore, exactly
    /// as DecommissionRunner does for IDecommissionHandoff.EnsureStaged's own bool
    /// result — this class only logs and reports success/failure, it does not own
    /// the health-store call itself.
    /// </summary>
    public bool EnsureScheduled()
    {
        try
        {
            SecureStagingDirectory.EnsureHardenedChain(_restartDir, _stateDir);

            // Reuses DecommissionHandoffScript.ServiceName rather than a second
            // "Patched Agent" literal here — one constant, one place that could
            // ever drift from Product.wxs's actual ServiceInstall Name.
            string script = PendingUpdateRestartScript.Build(
                PathConstants.SelfUpdateRestartTaskName,
                PathConstants.PendingAgentUpdateFile,
                DecommissionHandoffScript.ServiceName);
            File.WriteAllText(_scriptFile, script);

            // PAT-1293 round 2: the task definition itself is now XML, not
            // command-line flags — see PendingUpdateRestartTaskXml's class doc
            // comment for why (the original /SC ONCE /ST /SD design silently
            // failed to register on non-US-date-order locales). Written into the
            // SAME hardened directory as the script: it is an input to a
            // SYSTEM/HighestAvailable task, so it needs the identical TOCTOU
            // protection. Encoding.Unicode (UTF-16 with BOM) matches the XML
            // declaration PendingUpdateRestartTaskXml.Build emits — a mismatched
            // declared-vs-actual encoding is grounds for a parser to reject the
            // file outright.
            string xml = PendingUpdateRestartTaskXml.Build(
                PathConstants.SelfUpdateRestartTaskName,
                _scriptFile,
                DateTime.Now);
            File.WriteAllText(_taskXmlFile, xml, System.Text.Encoding.Unicode);

            string createArgs = BuildCreateArgs(
                PathConstants.SelfUpdateRestartTaskName,
                _taskXmlFile);

            if (!RunSchtasks(createArgs))
            {
                _log.LogError("self-update-restart: schtasks /Create failed — restart not scheduled");
                return false;
            }

            _log.LogWarning(
                "self-update-restart: restart task scheduled (task={Task}) — will bounce the " +
                "service in {Delay} so the pending update can apply on the next start",
                PathConstants.SelfUpdateRestartTaskName, RestartDelay);
            return true;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "self-update-restart: failed to schedule restart task");
            return false;
        }
    }

    /// <summary>
    /// Pure construction of the <c>schtasks /Create</c> argument string — split out
    /// from <see cref="EnsureScheduled"/> so it is directly testable without a real
    /// schtasks.exe process or a live Task Scheduler, mirroring
    /// <see cref="DecommissionHandoff"/>'s own inline-string-construction shape.
    ///
    /// PAT-1293 round 2: deliberately just <c>/TN</c> + <c>/XML</c> + <c>/F</c> now
    /// — the trigger time, principal, and run level all live in the XML document
    /// at <paramref name="xmlPath"/> (see <see cref="PendingUpdateRestartTaskXml"/>)
    /// rather than as command-line flags, specifically BECAUSE the earlier
    /// flag-based form (<c>/SC ONCE /ST /SD /RU /RL</c>) had a locale-dependent
    /// <c>/SD</c> parse that failed registration outright on non-US-date-order
    /// Windows installs. <c>/F</c> is kept for the same idempotent-re-registration
    /// reason the original design used it.
    /// </summary>
    internal static string BuildCreateArgs(string taskName, string xmlPath) =>
        $"/Create /TN \"{taskName}\" /XML \"{xmlPath}\" /F";

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
                _log.LogError("self-update-restart: schtasks.exe timed out ({Args})", arguments);
                return false;
            }
            if (proc.ExitCode != 0)
            {
                string stderr = proc.StandardError.ReadToEnd();
                _log.LogError("self-update-restart: schtasks.exe exited {Code} ({Args}): {Stderr}",
                    proc.ExitCode, arguments, stderr);
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "self-update-restart: failed to run schtasks.exe ({Args})", arguments);
            return false;
        }
    }
}

/// <summary>
/// Seam so <see cref="BootstrapUpdater"/> is unit-testable without a real Windows
/// Task Scheduler. Production DI binds this to <see cref="PendingUpdateRestartScheduler"/>.
/// </summary>
public interface IPendingUpdateRestartScheduler
{
    /// <summary>
    /// Schedules the one-shot restart task. See
    /// <see cref="PendingUpdateRestartScheduler.EnsureScheduled"/>. Never throws; a
    /// false return means the restart was NOT scheduled — the caller
    /// (BootstrapUpdater, PAT-1293) records a degraded/fault signal via
    /// AgentHealthStore rather than treating it as fatal, and rather than letting
    /// it pass silently: an update staged with no restart ever scheduled is
    /// exactly the invisible-failure shape this whole ticket exists to close.
    /// </summary>
    bool EnsureScheduled();
}
