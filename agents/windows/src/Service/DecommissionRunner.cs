using System.Text.Json;
using System.Text.Json.Serialization;
using Patched.Shared.Config;
using Patched.Shared.Paths;
using Patched.Shared.Removal;

namespace Patched.Service;

/// <summary>
/// PAT-1110: evaluates the signed decommission directive on every cycle and, when
/// due, reports a non-terminal "acknowledged" status then hands off to the detached
/// removal script — UNLESS the platform's response is a 409 (directive superseded or
/// cancelled), which is now the sole cancellation path and must abort with nothing
/// left armed. This is the actuation point Worker.cs calls — the same "read a
/// verified field off the signed config as a local gate" shape Worker.cs already uses
/// for the tier gate (PAT-310), extended rather than duplicated.
///
/// The genuine terminal outcome ("removed") is reported separately, by the detached
/// script itself after it verifies removal complete — see DecommissionHandoffScript.
/// This class never reports a terminal status; it only ever reports "acknowledged".
///
/// FAIL CLOSED: <see cref="DecommissionEvaluator"/> already guarantees "not due" for
/// anything not cleanly resolvable, and everything this class reads
/// (<c>config.Decommission</c>) only ever reflects an <c>AgentConfig</c> that already
/// passed <c>AgentConfigFetcher</c>'s Ed25519 + tenant + anti-rollback verification —
/// a config that fails ANY of those checks is rejected wholesale and this class never
/// sees it (the last-known-good config, or <c>AgentConfig.Defaults</c> whose
/// <see cref="AgentConfig.Decommission"/> is null, is what <c>RunAsync</c> is called
/// with instead). Nothing here can be triggered by an unsigned or locally-modified
/// config file on disk (PAT-1035 precedent) — see DecommissionRunnerTests and
/// Shared.Tests/DecommissionPolicyTests's EndToEnd_* cases for the tests proving it.
///
/// Runs UNCONDITIONALLY — not gated on tier or RunMode. Decommission is a tenant-wide
/// directive independent of the assurance/managed (PAT-1599; formerly
/// report_deploy/patch/managed) capability tier; gating it on "managed" would make
/// assurance-tier devices immune to an operator-issued decommission, which is not
/// how the directive is meant to work.
///
/// Round-2 non-author review (item 5) — marker ordering / commit semantics:
/// <see cref="IDecommissionHandoff.EnsureStaged"/> (creates the ONSTART-triggered
/// task) and <see cref="IDecommissionHandoff.TriggerNow"/> (runs it immediately) are
/// separate calls, and the durable "committed" marker is written BETWEEN them —
/// after staging succeeds, before the first trigger attempt. This is deliberate:
/// once staged, a reboot at ANY point runs the task regardless of anything this
/// process does afterward, so the marker must exist before that point is reached,
/// not after. It also means that once staged and marked, this class NEVER again
/// calls <see cref="IDecommissionStatusReporter.ReportAcknowledgedAsync"/> or
/// <see cref="IDecommissionHandoff.EnsureDeregistered"/> for that directive — the
/// platform already authorized removal (the acknowledge→proceed handshake completes
/// BEFORE staging is ever attempted), and a staged task may already be executing by
/// the time any later cycle would run, so re-entering the report/abort path could
/// misreport "aborted" for a removal that is, in fact, proceeding. IMPORTANT: this
/// does not make an in-flight removal abortable and does not claim to — see
/// DecommissionHandoff's class doc comment for the same point from the staging
/// side. A subsequent cycle that finds a staged-but-not-yet-triggered marker
/// retries ONLY the trigger (see <see cref="ActuateAsync"/>), never the report or
/// the staging.
/// </summary>
internal sealed class DecommissionRunner
{
    private readonly ILogger<DecommissionRunner> _log;
    private readonly AgentHealthStore             _agentHealth;
    private readonly IDecommissionStatusReporter  _reporter;
    private readonly IDecommissionHandoff         _handoff;
    private readonly string                       _markerFile;

    private static readonly JsonSerializerOptions MarkerReadOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    /// <param name="markerFileOverride">Test-only seam; production uses <see cref="PathConstants.DecommissionMarkerFile"/>.</param>
    public DecommissionRunner(
        ILogger<DecommissionRunner> log,
        AgentHealthStore             agentHealth,
        IDecommissionStatusReporter  reporter,
        IDecommissionHandoff         handoff,
        string?                      markerFileOverride = null)
    {
        _log         = log;
        _agentHealth = agentHealth;
        _reporter    = reporter;
        _handoff     = handoff;
        _markerFile  = markerFileOverride ?? PathConstants.DecommissionMarkerFile;
    }

    /// <summary>
    /// Fail-safe: never throws into the worker's poll loop. For a caller that has
    /// already established the device holds its credential pair; the worker uses the
    /// overload that says whether it does.
    /// </summary>
    public Task RunAsync(AgentConfig config, CancellationToken ct) =>
        RunAsync(config, credentialsPresent: true, ct);

    /// <summary>
    /// PAT-1765: <paramref name="credentialsPresent"/> gates only the step that needs
    /// them, the signed "acknowledged" report for a due directive with no handoff
    /// marker yet. PAT-1760 skipped the whole check without credentials, which also
    /// skipped the network-free retry of <see cref="IDecommissionHandoff.TriggerNow"/>
    /// for a removal the platform had already authorised and this agent had already
    /// staged. That retry now runs with or without credentials. Fail-safe: never throws
    /// into the worker's poll loop.
    /// </summary>
    public async Task RunAsync(AgentConfig config, bool credentialsPresent, CancellationToken ct)
    {
        try
        {
            var decision = DecommissionEvaluator.Evaluate(
                config.Decommission, DateTimeOffset.UtcNow, AgentBuildInfo.BuildFloor);

            switch (decision.Outcome)
            {
                case DecommissionOutcome.NotDue:
                    _agentHealth.RecordSuccess("decommission", "directive");
                    return;

                case DecommissionOutcome.Fault:
                    _log.LogWarning("decommission: fault — {Reason} — agent remains running", decision.FaultReason);
                    _agentHealth.RecordFailure("decommission", "directive", decision.FaultReason ?? "unknown");
                    return;

                case DecommissionOutcome.Due:
                    // Capture config_version HERE, at the point of deciding to act —
                    // not read back later from cached config, which the detached
                    // removal may already have deleted by the time any retry runs
                    // (see ActuateAsync / DecommissionStatusReporter).
                    await ActuateAsync(config.Decommission!, config.ConfigVersion, credentialsPresent, ct).ConfigureAwait(false);
                    return;
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "decommission: unexpected error during evaluation — agent remains running, will retry next cycle");
        }
    }

    private async Task ActuateAsync(DecommissionPolicy policy, int directiveVersion, bool credentialsPresent, CancellationToken ct)
    {
        var marker = ReadMarker();

        if (marker is not null)
        {
            // Already staged (and the platform already authorized this — see class
            // doc comment) on a previous cycle. NEVER re-report or re-stage from
            // here: only retry the immediate trigger if it has not yet succeeded.
            if (marker.Triggered)
            {
                _log.LogInformation("decommission: handoff already initiated and triggered — awaiting stop by the scheduled task");
                return;
            }

            _log.LogInformation("decommission: handoff staged but not yet confirmed triggered — retrying the immediate trigger");
            if (_handoff.TriggerNow())
            {
                WriteMarker(marker with { Triggered = true });
            }
            else
            {
                _agentHealth.RecordFailure("decommission", "directive", "immediate_trigger_failed");
            }
            return;
        }

        // PAT-1760, narrowed by PAT-1765 to this branch: without the credential pair the
        // acknowledged report would go out unsigned and be rejected, and a rejection reads
        // as the platform calling the removal off. Nothing is sent or staged; the
        // directive is re-evaluated on the first tick after enrolment stores credentials.
        if (!credentialsPresent)
        {
            _log.LogDebug("decommission: directive is due but device credentials are not present, so the acknowledged report is not sent yet; nothing staged");
            return;
        }

        _log.LogWarning(
            "decommission: directive is due (purge={Purge}, config_version={Version}) — reporting " +
            "acknowledged status before handing off to detached removal", policy.Purge, directiveVersion);

        // Phase 1 of the two-phase report contract (second contract round): a
        // non-terminal "acknowledged" report, the last point removal can be called
        // off. The platform's response — not any local re-evaluation — is now the
        // sole cancellation mechanism, and only reachable from THIS branch (no
        // marker yet) — see class doc comment for why a staged directive never
        // re-enters this call.
        var outcome = await _reporter.ReportAcknowledgedAsync(policy, directiveVersion, ct).ConfigureAwait(false);

        switch (outcome)
        {
            case DecommissionReportOutcome.Aborted:
                // 409: the directive we acted on has been superseded or cancelled.
                // MUST NOT proceed. Never retried — see DecommissionStatusReporter.
                // EnsureDeregistered is a backstop, not a no-op-because-unreachable
                // call: nothing should be armed at this point (no marker exists yet,
                // so staging was never attempted on this or any prior cycle for this
                // directive), but calling it unconditionally means an abort can
                // never leave a stale ONSTART-triggered task armed regardless of how
                // this method is reached, now or after a future change to the call
                // graph above.
                _log.LogError(
                    "decommission: directive_version={Version} superseded — aborting, service remains " +
                    "installed and running", directiveVersion);
                if (!_handoff.EnsureDeregistered())
                {
                    // The task could not be confirmed removed — it may still be
                    // armed with an ONSTART trigger despite the directive being
                    // superseded. Recorded as its own distinct fault (separate
                    // "deregister" subject) from "directive_superseded" below, since
                    // an operator needs to know these are two different problems:
                    // the directive was cancelled, AND the cancellation could not be
                    // fully enforced locally.
                    _agentHealth.RecordFailure("decommission", "deregister", "task_deregistration_failed");
                }
                _agentHealth.RecordFailure("decommission", "directive", "directive_superseded");
                return;

            case DecommissionReportOutcome.Unreported:
                // No channel remains once the agent is gone — this log line (and the
                // agent_health fault below) is the only record of "unreported" that
                // can exist. Proceed with removal regardless: network reachability
                // must never be a way to indefinitely block an operator-issued
                // decommission. Distinct from Aborted: this is "we don't know",
                // not "the platform said no".
                _log.LogError(
                    "decommission: acknowledged status could not be reported after retries — proceeding " +
                    "with removal unreported");
                _agentHealth.RecordFailure("decommission", "status_report", "unreported_before_removal");
                break; // fall through to staging

            case DecommissionReportOutcome.Proceed:
                break; // fall through to staging
        }

        if (!_handoff.EnsureStaged(policy.Purge, directiveVersion))
        {
            _log.LogError("decommission: handoff staging failed — will retry next cycle");
            _agentHealth.RecordFailure("decommission", "directive", "handoff_scheduling_failed");
            return;
        }

        // Durable "committed" record, written BEFORE the first trigger attempt —
        // see class doc comment (round-2 item 5) for why this ordering is the whole
        // point: the task is now armed and will run at latest on next boot
        // regardless of what happens to this process from here on, so the record of
        // that commitment must already be on disk before the trigger is even tried,
        // not after.
        var staged = new HandoffMarker
        {
            InitiatedAt      = DateTimeOffset.UtcNow,
            Purge            = policy.Purge,
            DirectiveVersion = directiveVersion,
            ReportOutcome    = outcome.ToString(),
            Triggered        = false,
        };
        WriteMarker(staged);

        if (_handoff.TriggerNow())
        {
            WriteMarker(staged with { Triggered = true });
        }
        else
        {
            // Not fatal: the ONSTART trigger guarantees eventual execution on next
            // boot regardless, and the next poll cycle retries ONLY the trigger
            // (see the marker-present branch above) — no re-report, no re-stage.
            _agentHealth.RecordFailure("decommission", "directive", "immediate_trigger_failed");
        }
    }

    /// <summary>
    /// Durable record of a staged (committed) decommission handoff. See the class
    /// doc comment (round-2 item 5) for why <see cref="Triggered"/> exists and why
    /// this is written before the first trigger attempt, not after.
    /// </summary>
    private sealed record HandoffMarker
    {
        [JsonPropertyName("initiated_at")]
        public DateTimeOffset InitiatedAt { get; init; }

        [JsonPropertyName("purge")]
        public bool Purge { get; init; }

        [JsonPropertyName("directive_version")]
        public int DirectiveVersion { get; init; }

        [JsonPropertyName("report_outcome")]
        public string ReportOutcome { get; init; } = "";

        /// <summary>
        /// True once <see cref="IDecommissionHandoff.TriggerNow"/> has succeeded at
        /// least once for this directive. False (including for a marker written
        /// before this field existed, which deserializes to the default) means the
        /// task is staged/armed but the immediate trigger has not yet been
        /// confirmed — the next cycle retries ONLY the trigger, never re-reports or
        /// re-stages.
        /// </summary>
        [JsonPropertyName("triggered")]
        public bool Triggered { get; init; }
    }

    /// <summary>
    /// Reads back the committed-handoff marker, or null if none exists yet.
    /// Deliberately fails toward "retry the trigger" rather than "assume fully
    /// done" on anything short of a clean read + parse: an unreadable/corrupt
    /// marker on a machine that is ALREADY mid-decommission must never be read as
    /// "nothing to do" — see <see cref="ActuateAsync"/>'s null-vs-Triggered=false
    /// handling. <see cref="IDecommissionHandoff.TriggerNow"/> is safe to call
    /// again even if the task already ran or is already running (schtasks reports
    /// a harmless error in either case), so retrying it on an ambiguous read is the
    /// safe direction to fail in — the same discipline WriteMarker's own doc
    /// comment already established for a failed WRITE.
    /// </summary>
    private HandoffMarker? ReadMarker()
    {
        if (!File.Exists(_markerFile))
            return null;

        try
        {
            string json = File.ReadAllText(_markerFile);
            var marker = JsonSerializer.Deserialize<HandoffMarker>(json, MarkerReadOptions);
            if (marker is not null)
                return marker;

            _log.LogWarning("decommission: marker file parsed to null — treating as staged-but-not-triggered");
            return new HandoffMarker { Triggered = false };
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "decommission: failed to read/parse handoff marker — treating as staged-but-not-triggered");
            return new HandoffMarker { Triggered = false };
        }
    }

    private void WriteMarker(HandoffMarker marker)
    {
        try
        {
            // Explicit null/empty check rather than the null-forgiving operator:
            // Path.GetDirectoryName returns null for a root path or other malformed
            // input, and `!` only suppresses the compiler warning — it does nothing
            // at runtime, so Directory.CreateDirectory(null) would still throw
            // ArgumentNullException. Handled the same fail-safe way as every other
            // failure mode in this method (log and treat as best-effort, never
            // crash into the caller), rather than falling through to the generic
            // catch below by accident.
            string? markerDir = Path.GetDirectoryName(_markerFile);
            if (string.IsNullOrEmpty(markerDir))
            {
                _log.LogError(
                    "decommission: marker file path '{MarkerFile}' has no parent directory — cannot write handoff marker",
                    _markerFile);
                return;
            }

            Directory.CreateDirectory(markerDir);
            string tmp = _markerFile + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(marker));
            File.Move(tmp, _markerFile, overwrite: true);
        }
        catch (Exception ex)
        {
            // Best-effort: if the marker can't be written, the next cycle simply
            // re-enters the report/stage flow from scratch instead of skipping it —
            // the safe direction to fail in. (A failure writing the FIRST,
            // triggered=false marker is the one case this can degrade below the
            // ideal ordering in the class doc comment; logged loudly because of that.)
            _log.LogWarning(ex, "decommission: failed to write handoff marker — next cycle may re-attempt from scratch");
        }
    }
}
