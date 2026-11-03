// DEPRECATED — PAT-1531: retained source for a separately reviewed future boundary;
// excluded from the Windows assurance-only Service build.
using System.Runtime.Versioning;
using Patched.Shared.Config;
using Patched.Shared.Removal;

namespace Patched.Service;

/// <summary>
/// PAT-781 per-device removal-task engine — the device-scoped counterpart to
/// <see cref="RemovalRunner"/> (PAT-379, tenant-wide allowlist). It is a new trigger
/// path into the SAME uninstall engine: it reuses <see cref="RegistryUninstallLookup"/>,
/// <see cref="UninstallExecutor"/>, <see cref="UninstallPlanner"/> and
/// <see cref="BaselineProtection"/> verbatim, and differs only in where tasks come
/// from (a device-scoped queue) and where results go (the report endpoint, not
/// provenance/uninstall-status.json).
///
/// On each scheduled pass it polls the pending queue, executes every task, and posts
/// the outcomes back. Fail-safe: it never throws into the worker.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class DeviceRemovalRunner
{
    private readonly ILogger<DeviceRemovalRunner> _log;
    private readonly DeviceRemovalTasksClient     _client;
    private readonly RegistryUninstallLookup      _lookup;
    private readonly UninstallExecutor            _executor;
    private readonly AgentHealthStore             _agentHealth;

    public DeviceRemovalRunner(
        ILogger<DeviceRemovalRunner> log,
        DeviceRemovalTasksClient     client,
        RegistryUninstallLookup      lookup,
        UninstallExecutor            executor,
        AgentHealthStore             agentHealth)
    {
        _log         = log;
        _client      = client;
        _lookup      = lookup;
        _executor    = executor;
        _agentHealth = agentHealth;
    }

    public async Task RunAsync(CancellationToken ct, AgentConfig config)
    {
        // PAT-1481: per-device removal tasks are a separate queue and must not
        // bypass the tenant-wide pending-removals containment gate.
        if (!LegacyAppExecutionGate.Allows(config))
        {
            _log.LogWarning("Legacy app-execution gate disabled — skipping device-removal task execution");
            return;
        }

        var deviceId = RecordDeviceIdentityHealth();
        if (deviceId is null)
            return;

        var tasks = await _client.FetchPendingAsync(deviceId, ct).ConfigureAwait(false);
        if (tasks.Count == 0)
        {
            _log.LogInformation("Device removal: no pending tasks.");
            return;
        }

        _log.LogInformation("Device removal: {Count} pending task(s).", tasks.Count);

        var reports = new List<DeviceRemovalReport>(tasks.Count);
        foreach (var task in tasks)
        {
            ct.ThrowIfCancellationRequested();
            var (outcome, detail) = await ProcessOneAsync(task.AppName, ct).ConfigureAwait(false);
            var state = DeviceRemovalStateMap.ToReportState(outcome);
            _log.LogInformation("Device removal: {App} (task {TaskId}) -> {State}",
                task.AppName, task.TaskId, state);
            reports.Add(new DeviceRemovalReport { TaskId = task.TaskId, State = state, Detail = detail });
        }

        await _client.ReportAsync(deviceId, reports, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// PAT-1066 P2 non-author-review: extracted out of <see cref="RunAsync"/> so
    /// Worker.cs can call the health-only observation (device-identity presence) on
    /// cycles where the full device-removal engine is gated out by tier/mode,
    /// without running any of the actuating removal logic below — otherwise (1) an
    /// assurance-tier tenant's agent would assert <c>degraded: []</c> on every cycle,
    /// because the code that would ever detect and record a real fault never runs
    /// below the actuating tier, and (2) a tenant downgraded from "managed" (PAT-1599:
    /// the former "patch" tier is retired) mid-fault could never clear it, since
    /// <c>RecordSuccess</c> for (directive_skipped, device_removal) would never run
    /// again.
    ///
    /// Records failure (reason no_device_id) and returns null if the posture cache
    /// has no usable device id yet; records success and returns the id otherwise.
    /// No other side effects — no fetching, no processing. <see cref="RunAsync"/>
    /// calls this itself at its own top, so its existing behaviour/tests
    /// (same recording, same early-return-on-null) are unaffected.
    /// </summary>
    internal string? RecordDeviceIdentityHealth()
    {
        var deviceId = _client.ReadDeviceId();
        if (deviceId is null)
        {
            _log.LogInformation("Device removal: no device id in posture cache yet — skipping.");
            // PAT-1066: a directive-bearing channel (server-queued per-device removal
            // tasks) is being skipped because the device has no usable identity to
            // address itself with yet. Distinct from macOS's directive_skipped/
            // log_upload/device_id_mismatch (server named an id and it didn't match) —
            // here we don't have an id at all yet — hence the new reason, no_device_id,
            // rather than reusing device_id_mismatch.
            _agentHealth.RecordFailure("directive_skipped", "device_removal", "no_device_id");
            return null;
        }

        // Every cycle we reach this point, the device has a usable id and can be
        // addressed by device-scoped directives — regardless of whether there
        // happen to be zero or more pending tasks this cycle. That is the
        // capability being measured, not "did a task execute".
        _agentHealth.RecordSuccess("directive_skipped", "device_removal");
        return deviceId;
    }

    /// <summary>
    /// Runs the engine for one app and returns its outcome plus a short human detail.
    /// Mirrors <see cref="RemovalRunner"/>'s ladder — baseline guard → installed check
    /// (idempotent) → running check (close/defer) → resolve (OS-native, winget fallback)
    /// → execute → VERIFY by re-inspection (never the exit code) → classify — but reuses
    /// the shared engine components rather than duplicating any removal mechanics.
    /// The user_removable posture gate is intentionally NOT applied here: this is an
    /// operator-directed removal of one app on one device, not a self-service action.
    /// </summary>
    private async Task<(RemovalOutcome outcome, string detail)> ProcessOneAsync(string appName, CancellationToken ct)
    {
        // Hard safety invariant — never remove an OS/security baseline app, even when
        // an operator queued it explicitly.
        if (BaselineProtection.IsProtected(appName, publisher: null))
        {
            _log.LogWarning("Device removal: {App} is baseline-protected — refusing.", appName);
            return (RemovalOutcome.SkippedBaselineProtected, "baseline-protected: refusing to remove a Windows/security baseline app");
        }

        // Device tasks carry only an app name; the operator picked it from this device's
        // reported inventory (same registry DisplayName), so an exact match is correct.
        var program = _lookup.Find(appName, "exact_name");

        // Idempotent: not installed → the desired end state already holds.
        if (program is null)
        {
            _log.LogInformation("Device removal: {App} not installed — already removed.", appName);
            return (RemovalOutcome.AlreadyRemoved, "not installed at run time (already removed)");
        }

        // Running → ask it to close; defer (retry) if it will not.
        if (_executor.IsRunning(appName, program.InstallLocation) &&
            !await _executor.RequestCloseAndWaitAsync(appName, program.InstallLocation, ct).ConfigureAwait(false))
        {
            _log.LogInformation("Device removal: {App} still running — deferring.", appName);
            return (RemovalOutcome.DeferredAppRunning, "app was running and did not close; will retry next cycle");
        }

        // Resolve the method — winget is only consulted when the registry has nothing usable.
        bool needsWinget = string.IsNullOrWhiteSpace(program.QuietUninstallString)
                           && !UninstallPlanner.IsMsi(program)
                           && string.IsNullOrWhiteSpace(program.UninstallString);
        bool wingetKnows = needsWinget && await _executor.WingetKnowsAsync(appName, ct).ConfigureAwait(false);

        var resolved = UninstallPlanner.Resolve(program, wingetKnows, catalogueRecipe: null);
        if (resolved.Method == RemovalMethod.Unresolvable)
        {
            _log.LogWarning("Device removal: no method for {App} — manual removal required.", appName);
            return (RemovalOutcome.ManualRemovalRequired, "no removal method could be resolved");
        }

        _log.LogInformation("Device removal: {App} via {Method}", appName, resolved.Method);
        int exit = await _executor.ExecuteAsync(resolved, appName, ct).ConfigureAwait(false);
        _log.LogDebug("Device removal: {App} executor exit={Exit} (verify is authoritative)", appName, exit);

        // VERIFY by re-inspection, never by exit code.
        var after = _lookup.Find(appName, "exact_name");
        if (after is not null)
        {
            var outcome = UninstallPlanner.ClassifyStillPresent(after);
            return (outcome, $"still present after {resolved.Method}");
        }
        if (program.InstallLocation is { } loc && SafeDirExists(loc))
            return (RemovalOutcome.RemovedResidual, $"program entry removed via {resolved.Method}; install files remain");

        return (RemovalOutcome.Removed, $"removed via {resolved.Method}");
    }

    private static bool SafeDirExists(string path)
    {
        try { return Directory.Exists(path); } catch { return false; }
    }
}
