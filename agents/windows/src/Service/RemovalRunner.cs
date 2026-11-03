// DEPRECATED — PAT-1531: retained source for a separately reviewed future boundary;
// excluded from the Windows assurance-only Service build.
using System.Runtime.Versioning;
using System.Text.Json;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Patched.Shared.Paths;
using Patched.Shared.Removal;

namespace Patched.Service;

/// <summary>
/// PAT-379 uninstall-execution engine — the Windows parity mirror of the macOS
/// patched-uninstall.sh (PAT-376). On the scheduled enforcement run it:
///   1. fetches the pending-removal queue (24 h hold is server-side);
///   2. for each app: baseline-safety guard → installed check (idempotent) →
///      running check (close/defer) → method resolution (OS-native first,
///      catalogue/winget fallback) → execute with timeout → VERIFY by re-checking
///      the registry/install state (never the exit code) → classify residual /
///      transient / hard;
///   3. posts an app_uninstall provenance record per attempt;
///   4. writes %ProgramData%\Patched\uninstall-status.json atomically.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class RemovalRunner
{
    private const string Platform = "windows";

    private readonly ILogger<RemovalRunner>  _log;
    private readonly PendingRemovalsFetcher  _fetcher;
    private readonly RegistryUninstallLookup _lookup;
    private readonly UninstallExecutor       _executor;
    private readonly ProvenancePoster        _provenance;
    private readonly DeviceCollector         _device;
    private readonly CredentialStore         _creds;

    public RemovalRunner(
        ILogger<RemovalRunner>  log,
        PendingRemovalsFetcher  fetcher,
        RegistryUninstallLookup lookup,
        UninstallExecutor       executor,
        ProvenancePoster        provenance,
        DeviceCollector         device,
        CredentialStore         creds)
    {
        _log        = log;
        _fetcher    = fetcher;
        _lookup     = lookup;
        _executor   = executor;
        _provenance = provenance;
        _device     = device;
        _creds      = creds;
    }

    /// <param name="targetIds">
    /// App identifiers (names) from the trigger. When non-null, only entries whose
    /// Name matches one of these (case-insensitive) are processed. Pass null on
    /// scheduled enforcement runs to process all pending removals.
    /// </param>
    public async Task RunAsync(IReadOnlyList<string>? targetIds, CancellationToken ct,
        AgentConfig config)
    {
        // PAT-1481: this is the direct and scheduled pending-removals seam.
        // Do not fetch or execute a legacy removal without the signed, exact-true
        // containment grant; existing posture, baseline and planner gates remain
        // mandatory once it is granted.
        if (!LegacyAppExecutionGate.Allows(config))
        {
            _log.LogWarning("Legacy app-execution gate disabled — skipping pending-removal execution");
            return;
        }

        var startedAt = DateTimeOffset.UtcNow;
        var items = await _fetcher.FetchAsync(ct).ConfigureAwait(false);
        if (items.Count == 0)
        {
            _log.LogInformation("Uninstall: no pending removals.");
            return;
        }

        // Only act on items targeting this OS; "macos" entries would just report
        // already_removed here and pollute the dashboard, so skip them outright.
        var mine = items.Where(i =>
            string.Equals(i.Platform, Platform, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(i.Platform, "any", StringComparison.OrdinalIgnoreCase)).ToList();

        // When the trigger named specific identifiers, restrict to those entries.
        // Any ID absent from the server queue is not queued or not policy-removable.
        if (targetIds is { Count: > 0 })
        {
            mine = mine
                .Where(i => targetIds.Any(id =>
                    string.Equals(id, i.Name, StringComparison.OrdinalIgnoreCase)))
                .ToList();
            if (mine.Count == 0)
            {
                _log.LogWarning(
                    "Uninstall: none of [{Ids}] are in the server pending-removal queue — not queued or not policy-removable.",
                    string.Join(", ", targetIds));
                return;
            }
        }

        _log.LogInformation("Uninstall: {Mine}/{Total} pending removals apply to Windows.",
            mine.Count, items.Count);

        var device       = _device.CollectDevice();
        var hwUuid       = device.HwUuid;
        var computerName = string.IsNullOrWhiteSpace(device.Hostname) ? Environment.MachineName : device.Hostname;

        var results = new List<RemovalResult>(mine.Count);
        foreach (var item in mine)
        {
            ct.ThrowIfCancellationRequested();
            var result = await ProcessOneAsync(item, hwUuid, computerName, ct).ConfigureAwait(false);
            results.Add(result);
        }

        WriteStatus(startedAt, DateTimeOffset.UtcNow, results);
        _log.LogInformation("Uninstall run complete: {Count} processed.", results.Count);
    }

    private async Task<RemovalResult> ProcessOneAsync(
        PendingRemoval item, string? hwUuid, string computerName, CancellationToken ct)
    {
        _log.LogInformation("Uninstall: processing {Name} (entry {EntryId}, queued {QueuedAt:o})",
            item.Name, item.EntryId, item.QueuedAt);

        var method       = RemovalMethod.None;
        string? detail   = null;
        VerifyResult verify = VerifyResult.NotChecked;
        RemovalOutcome outcome;

        // 1a. Engine-side user_removable policy gate (posture cache). The server queue
        //     is authoritative but we also enforce this in the daemon so that a UI that
        //     mis-classifies an app cannot bypass the policy. Fail-open if posture missing.
        if (!IsUserRemovable(item.Name))
        {
            _log.LogWarning("Uninstall: {Name} has user_removable=false in posture — removal refused.", item.Name);
            outcome = RemovalOutcome.SkippedUserPolicy;
        }
        // 1b. Safety: never remove an OS/runtime/security baseline app.
        else if (BaselineProtection.IsProtected(item.Name, item.Publisher))
        {
            _log.LogWarning("Uninstall: {Name} is baseline-protected — ignoring removal intent.", item.Name);
            outcome = RemovalOutcome.SkippedBaselineProtected;
        }
        else
        {
            var program = _lookup.Find(item.Name, item.MatchMode);

            // 2. Idempotent: not installed → already removed.
            if (program is null)
            {
                _log.LogInformation("Uninstall: {Name} not installed — already removed.", item.Name);
                outcome = RemovalOutcome.AlreadyRemoved;
                verify  = VerifyResult.Gone;
            }
            // 3. Running → request close, defer if it won't close.
            else if (_executor.IsRunning(item.Name, program.InstallLocation) &&
                     !await _executor.RequestCloseAndWaitAsync(item.Name, program.InstallLocation, ct).ConfigureAwait(false))
            {
                _log.LogInformation("Uninstall: {Name} still running — deferring to next cycle.", item.Name);
                outcome = RemovalOutcome.DeferredAppRunning;
            }
            else
            {
                // 4. Resolve method (winget fallback checked only when registry has nothing usable).
                bool needsWinget = string.IsNullOrWhiteSpace(program.QuietUninstallString)
                                   && !UninstallPlanner.IsMsi(program)
                                   && string.IsNullOrWhiteSpace(program.UninstallString);
                bool wingetKnows = needsWinget && await _executor.WingetKnowsAsync(item.Name, ct).ConfigureAwait(false);

                var resolved = UninstallPlanner.Resolve(program, wingetKnows, catalogueRecipe: null);
                method = resolved.Method;
                detail = string.IsNullOrEmpty(resolved.Detail) ? null : resolved.Detail;

                if (resolved.Method == RemovalMethod.Unresolvable)
                {
                    _log.LogWarning("Uninstall: no method for {Name} — manual removal required.", item.Name);
                    outcome = RemovalOutcome.ManualRemovalRequired;
                }
                else
                {
                    _log.LogInformation("Uninstall: {Name} via {Method}", item.Name, resolved.Method);
                    int exit = await _executor.ExecuteAsync(resolved, item.Name, ct).ConfigureAwait(false);
                    _log.LogDebug("Uninstall: {Name} executor exit={Exit} (verify is authoritative)", item.Name, exit);

                    // 5. VERIFY by re-inspection, never by exit code.
                    var after = _lookup.Find(item.Name, item.MatchMode);
                    if (after is not null)
                    {
                        verify  = VerifyResult.StillPresent;
                        outcome = UninstallPlanner.ClassifyStillPresent(after);
                    }
                    else if (program.InstallLocation is { } loc && SafeDirExists(loc))
                    {
                        verify  = VerifyResult.Residual;
                        outcome = RemovalOutcome.RemovedResidual;
                    }
                    else
                    {
                        verify  = VerifyResult.Gone;
                        outcome = RemovalOutcome.Removed;
                    }
                    _log.LogInformation("Uninstall: {Name} verify={Verify} outcome={Outcome}",
                        item.Name, verify, outcome);
                }
            }
        }

        await _provenance.PostUninstallAsync(new UninstallProvenance
        {
            TenantId  = _creds.TenantId,
            Device    = new() { HwUuid = hwUuid, ComputerName = computerName },
            App       = new()
            {
                EntryId   = item.EntryId,
                Name      = item.Name,
                Publisher = item.Publisher,
                Platform  = item.Platform,
                MatchMode = item.MatchMode,
            },
            Uninstall = new()
            {
                Method       = method,
                MethodDetail = detail,
                QueuedAt     = item.QueuedAt,
                WindowHours  = 24,
            },
            Outcome      = outcome,
            VerifyResult = verify,
            FailureClass = FailureClassFor(outcome),
            RecordedAt   = DateTimeOffset.UtcNow,
        }, ct).ConfigureAwait(false);

        return new RemovalResult
        {
            EntryId      = item.EntryId,
            Name         = item.Name,
            Outcome      = outcome,
            VerifyResult = verify,
            Method       = method,
            RecordedAt   = DateTimeOffset.UtcNow,
        };
    }

    /// <summary>transient → retry next cycle; hard → surface as a finding; else null.</summary>
    private static string? FailureClassFor(RemovalOutcome o) => o switch
    {
        RemovalOutcome.DeferredAppRunning
            or RemovalOutcome.FailedTransient
            or RemovalOutcome.RemovedResidual              => "transient",
        RemovalOutcome.ManualRemovalRequired
            or RemovalOutcome.FailedHard
            or RemovalOutcome.AuthorityRefused
            or RemovalOutcome.SkippedBaselineProtected
            or RemovalOutcome.SkippedUserPolicy            => "hard",
        _                                                  => null,
    };

    /// <summary>
    /// Returns false when posture cache says user_removable=false for this app name.
    /// Fails open (returns true) when the posture file is absent or unreadable —
    /// the server queue is the authoritative gate; this is a belt-and-braces check.
    /// </summary>
    private bool IsUserRemovable(string appName)
    {
        try
        {
            if (!File.Exists(PathConstants.PostureStatusFile)) return true;
            using var fs  = File.OpenRead(PathConstants.PostureStatusFile);
            using var doc = System.Text.Json.JsonDocument.Parse(fs);
            if (!doc.RootElement.TryGetProperty("app_policy", out var policy)) return true;
            if (!policy.TryGetProperty("apps", out var apps)) return true;
            foreach (var app in apps.EnumerateArray())
            {
                if (app.TryGetProperty("app_name", out var nameEl) &&
                    string.Equals(nameEl.GetString(), appName, StringComparison.OrdinalIgnoreCase))
                {
                    return !app.TryGetProperty("user_removable", out var ur) || ur.GetBoolean();
                }
            }
            return true; // not in policy store — treat as removable
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Uninstall: could not read user_removable for {Name} — proceeding (fail-open)", appName);
            return true;
        }
    }

    private static bool SafeDirExists(string path)
    {
        try { return Directory.Exists(path); } catch { return false; }
    }

    private void WriteStatus(DateTimeOffset started, DateTimeOffset finished, IReadOnlyList<RemovalResult> results)
    {
        try
        {
            var status = new UninstallStatus
            {
                SchemaVersion = 1,
                GeneratedAt   = DateTimeOffset.UtcNow,
                LastRun       = new UninstallRunInfo { StartedAt = started, FinishedAt = finished },
                Removals      = results,
            };
            Directory.CreateDirectory(PathConstants.StateDir);
            string json = JsonSerializer.Serialize(status, ContractJsonOptions.Write);
            string tmp  = PathConstants.UninstallStatusFile + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, PathConstants.UninstallStatusFile, overwrite: true);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Uninstall: failed to write uninstall-status.json");
        }
    }
}
