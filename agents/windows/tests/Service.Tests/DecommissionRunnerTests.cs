using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Config;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1110. DecommissionRunner orchestration: evaluate -> health record -> (when
/// due) report "acknowledged" -> act on the platform's response.
///
/// Second contract round (2026-08): the platform can answer the pre-removal report
/// with a definitive 409 ("directive superseded/cancelled") — the sole cancellation
/// path in the design. <see cref="ModeImmediate_ReportAborted_LeavesServiceInstalled_DeregistersAnyArmedTask"/>
/// is the required proof that a 409 leaves the service installed AND the scheduled
/// task deregistered, with nothing armed for a later boot.
///
/// Round-2 non-author review (item 5): staging (<see cref="IDecommissionHandoff.EnsureStaged"/>)
/// and triggering (<see cref="IDecommissionHandoff.TriggerNow"/>) are now separate
/// calls, with DecommissionRunner's durable marker written in between — see
/// <see cref="ModeImmediate_ReportProceed_WritesMarkerBeforeTriggering_ThenTriggers"/>
/// and <see cref="ModeImmediate_TriggerFails_StaysStagedButUntriggered_RetriesOnlyTriggerNextCycle"/>
/// for the ordering and retry-only-the-trigger proof.
///
/// Uses a fake <see cref="IDecommissionStatusReporter"/> (rather than the real
/// <see cref="DecommissionStatusReporter"/> against a stub HTTP handler) because the
/// real reporter needs a working <c>CredentialStore</c>, whose only public factories
/// call Windows Credential Manager via a raw DllImport with no try/catch around the
/// call itself — unusable on this non-Windows CI host (see
/// DecommissionStatusReporterTests' own doc comment). The fake lets every
/// <see cref="DecommissionReportOutcome"/> branch be exercised deterministically,
/// which is exactly what this class's own branching logic needs proven.
/// </summary>
public class DecommissionRunnerTests
{
    private sealed class FakeHandoff : IDecommissionHandoff
    {
        public int StageCalls { get; private set; }
        public int TriggerCalls { get; private set; }
        public int DeregisterCalls { get; private set; }
        public bool? LastPurge { get; private set; }
        public int? LastDirectiveVersion { get; private set; }
        public bool StageReturnValue { get; set; } = true;
        public bool TriggerReturnValue { get; set; } = true;
        public bool DeregisterReturnValue { get; set; } = true;

        /// <summary>Order in which this fake's own methods were called — proves ordering, not just call counts.</summary>
        public List<string> CallOrder { get; } = new();

        public bool EnsureStaged(bool purge, int directiveVersion)
        {
            CallOrder.Add("stage");
            StageCalls++;
            LastPurge = purge;
            LastDirectiveVersion = directiveVersion;
            return StageReturnValue;
        }

        public bool TriggerNow()
        {
            CallOrder.Add("trigger");
            TriggerCalls++;
            return TriggerReturnValue;
        }

        public bool EnsureDeregistered()
        {
            CallOrder.Add("deregister");
            DeregisterCalls++;
            return DeregisterReturnValue;
        }
    }

    private sealed class FakeReporter : IDecommissionStatusReporter
    {
        public int Calls { get; private set; }
        public DecommissionReportOutcome Outcome { get; set; } = DecommissionReportOutcome.Proceed;
        public int? LastDirectiveVersion { get; private set; }

        public Task<DecommissionReportOutcome> ReportAcknowledgedAsync(
            DecommissionPolicy policy, int directiveVersion, CancellationToken ct)
        {
            Calls++;
            LastDirectiveVersion = directiveVersion;
            return Task.FromResult(Outcome);
        }
    }

    private static (DecommissionRunner runner, AgentHealthStore health, FakeHandoff handoff, FakeReporter reporter, string markerFile)
        MakeRunner(string tmpDir)
    {
        var health = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, Path.Combine(tmpDir, "agent-health.json"));
        var reporter = new FakeReporter();
        var handoff = new FakeHandoff();
        var markerFile = Path.Combine(tmpDir, "decommission-initiated.json");
        var runner = new DecommissionRunner(
            NullLogger<DecommissionRunner>.Instance, health, reporter, handoff, markerFile);
        return (runner, health, handoff, reporter, markerFile);
    }

    private static AgentConfig ConfigWith(DecommissionPolicy? policy, int version = 5) =>
        AgentConfig.Defaults with { ConfigVersion = version, Decommission = policy };

    [Fact]
    public async Task ModeNone_RecordsSuccess_NeverCallsReporterOrHandoff()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var (runner, health, handoff, reporter, _) = MakeRunner(tmpDir);
            await runner.RunAsync(ConfigWith(new DecommissionPolicy { ModeRaw = "none" }), CancellationToken.None);

            Assert.Equal(0, reporter.Calls);
            Assert.Equal(0, handoff.StageCalls);
            Assert.Equal(0, handoff.TriggerCalls);
            Assert.Equal(0, handoff.DeregisterCalls);
            Assert.Empty(health.BuildPayloadSection()!.Degraded);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public async Task AbsentDecommission_RecordsFault_NeverCallsReporterOrHandoff()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var (runner, health, handoff, reporter, _) = MakeRunner(tmpDir);
            await runner.RunAsync(ConfigWith(null), CancellationToken.None);

            Assert.Equal(0, reporter.Calls);
            Assert.Equal(0, handoff.StageCalls);
            var entry = Assert.Single(health.BuildPayloadSection()!.Degraded);
            Assert.Equal("decommission", entry.Kind);
            Assert.Equal("directive",    entry.Subject);
            Assert.Contains("absent", entry.Reason);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public async Task UnrecognisedMode_RecordsFault_NeverCallsReporterOrHandoff()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var (runner, health, handoff, reporter, _) = MakeRunner(tmpDir);
            await runner.RunAsync(
                ConfigWith(new DecommissionPolicy { ModeRaw = "wipe_everything" }), CancellationToken.None);

            Assert.Equal(0, reporter.Calls);
            Assert.Equal(0, handoff.StageCalls);
            var entry = Assert.Single(health.BuildPayloadSection()!.Degraded);
            Assert.Contains("unrecognised", entry.Reason);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public async Task ExpiryWithAbsurdTimestamp_RecordsFault_NeverCallsReporterOrHandoff()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var (runner, health, handoff, reporter, _) = MakeRunner(tmpDir);
            await runner.RunAsync(
                ConfigWith(new DecommissionPolicy { ModeRaw = "expiry", ExpiresAtRaw = "1999-01-01T00:00:00Z" }),
                CancellationToken.None);

            Assert.Equal(0, reporter.Calls);
            Assert.Equal(0, handoff.StageCalls);
            var entry = Assert.Single(health.BuildPayloadSection()!.Degraded);
            Assert.Contains("predates", entry.Reason);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public async Task ModeImmediate_ReportProceed_WritesMarkerBeforeTriggering_ThenTriggers()
    {
        // Round-2 item 5: the marker must be durably written BEFORE the immediate
        // trigger is even attempted, not after — proven here via the fake's own
        // CallOrder log, not just final call counts.
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var (runner, health, handoff, reporter, markerFile) = MakeRunner(tmpDir);
            reporter.Outcome = DecommissionReportOutcome.Proceed;

            await runner.RunAsync(
                ConfigWith(new DecommissionPolicy { ModeRaw = "immediate", Purge = true }, version: 99),
                CancellationToken.None);

            Assert.Equal(1, reporter.Calls);
            Assert.Equal(99, reporter.LastDirectiveVersion);
            Assert.Equal(1, handoff.StageCalls);
            Assert.True(handoff.LastPurge);
            Assert.Equal(99, handoff.LastDirectiveVersion);
            Assert.Equal(1, handoff.TriggerCalls);
            Assert.Equal(0, handoff.DeregisterCalls);
            Assert.Equal(new[] { "stage", "trigger" }, handoff.CallOrder);
            Assert.True(File.Exists(markerFile));
            Assert.Contains("\"triggered\":true", File.ReadAllText(markerFile));
            Assert.Empty(health.BuildPayloadSection()!.Degraded);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public async Task ModeImmediate_TriggerFails_StaysStagedButUntriggered_RetriesOnlyTriggerNextCycle()
    {
        // Round-2 item 5: if the immediate trigger fails after staging succeeded,
        // the marker must already exist (triggered=false) -- the next cycle must
        // retry ONLY TriggerNow, never re-report or re-stage.
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var (runner, health, handoff, reporter, markerFile) = MakeRunner(tmpDir);
            reporter.Outcome = DecommissionReportOutcome.Proceed;
            handoff.TriggerReturnValue = false;
            var config = ConfigWith(new DecommissionPolicy { ModeRaw = "immediate" }, version: 7);

            await runner.RunAsync(config, CancellationToken.None);

            Assert.Equal(1, handoff.StageCalls);
            Assert.Equal(1, handoff.TriggerCalls);
            Assert.True(File.Exists(markerFile));
            Assert.Contains("\"triggered\":false", File.ReadAllText(markerFile));
            var fault = health.BuildPayloadSection()!.Degraded.Single(e => e.Subject == "directive");
            Assert.Equal("immediate_trigger_failed", fault.Reason);

            // Next cycle: marker already exists -- must retry ONLY the trigger.
            handoff.TriggerReturnValue = true;
            await runner.RunAsync(config, CancellationToken.None);

            Assert.Equal(1, reporter.Calls);        // never re-reported
            Assert.Equal(1, handoff.StageCalls);     // never re-staged
            Assert.Equal(2, handoff.TriggerCalls);   // retried
            Assert.Contains("\"triggered\":true", File.ReadAllText(markerFile));
            // The marker now correctly reflects triggered=true; the earlier fault
            // is not auto-cleared by a later success (same behaviour the existing
            // "handoff_scheduling_failed" fault already has — faults clear via the
            // NotDue path, see FaultThenValidNone_ClearsTheFault, not implicitly).
            Assert.Single(health.BuildPayloadSection()!.Degraded);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public async Task ModeImmediate_ReportUnreported_StillProceedsToHandoff_RecordsUnreportedFault()
    {
        // Network reachability must never be a way to indefinitely block an
        // operator-issued decommission — an Unreported outcome (retry budget
        // exhausted without a definitive answer) still proceeds, unlike Aborted.
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var (runner, health, handoff, reporter, markerFile) = MakeRunner(tmpDir);
            reporter.Outcome = DecommissionReportOutcome.Unreported;

            await runner.RunAsync(ConfigWith(new DecommissionPolicy { ModeRaw = "immediate" }), CancellationToken.None);

            Assert.Equal(1, handoff.StageCalls);
            Assert.Equal(1, handoff.TriggerCalls);
            Assert.Equal(0, handoff.DeregisterCalls);
            Assert.True(File.Exists(markerFile));

            var entry = health.BuildPayloadSection()!.Degraded.Single(e => e.Subject == "status_report");
            Assert.Equal("decommission",  entry.Kind);
            Assert.Equal("unreported_before_removal", entry.Reason);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    // -------------------------------------------------------------------------
    // THE required test: a 409 (Aborted) must leave the service installed
    // (handoff never staged) AND ensure the scheduled task is deregistered,
    // with nothing armed for a later boot.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task ModeImmediate_ReportAborted_LeavesServiceInstalled_DeregistersAnyArmedTask()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var (runner, health, handoff, reporter, markerFile) = MakeRunner(tmpDir);
            reporter.Outcome = DecommissionReportOutcome.Aborted;

            await runner.RunAsync(
                ConfigWith(new DecommissionPolicy { ModeRaw = "immediate", Purge = true }, version: 12),
                CancellationToken.None);

            // Service left installed: the handoff that would stop/remove it was
            // NEVER staged or triggered.
            Assert.Equal(0, handoff.StageCalls);
            Assert.Equal(0, handoff.TriggerCalls);

            // Nothing left armed for a later boot: the abort path unconditionally
            // ensures the scheduled task is deregistered.
            Assert.Equal(1, handoff.DeregisterCalls);

            // No handoff marker: this was never "in flight", so a later,
            // non-superseded directive is free to be acted on from scratch.
            Assert.False(File.Exists(markerFile));

            // A 409 is definitive — reported exactly once, not retried into
            // submission within this single RunAsync call.
            Assert.Equal(1, reporter.Calls);

            var entry = Assert.Single(health.BuildPayloadSection()!.Degraded);
            Assert.Equal("decommission",          entry.Kind);
            Assert.Equal("directive",             entry.Subject);
            Assert.Equal("directive_superseded",  entry.Reason);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    // -------------------------------------------------------------------------
    // Non-author review (PAT-1110 P1-B): EnsureDeregistered can now fail — the
    // scheduled task could not be confirmed removed. That must surface as its own
    // distinct fault, separate from "directive_superseded", never silently swallowed.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task ModeImmediate_ReportAborted_DeregisterFails_RecordsBothFaults()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var (runner, health, handoff, reporter, markerFile) = MakeRunner(tmpDir);
            reporter.Outcome = DecommissionReportOutcome.Aborted;
            handoff.DeregisterReturnValue = false;

            await runner.RunAsync(
                ConfigWith(new DecommissionPolicy { ModeRaw = "immediate", Purge = true }, version: 12),
                CancellationToken.None);

            Assert.Equal(1, handoff.DeregisterCalls);
            Assert.False(File.Exists(markerFile));

            var degraded = health.BuildPayloadSection()!.Degraded;
            Assert.Equal(2, degraded.Count);

            var deregisterFault = degraded.Single(e => e.Subject == "deregister");
            Assert.Equal("decommission", deregisterFault.Kind);
            Assert.Equal("task_deregistration_failed", deregisterFault.Reason);

            var directiveFault = degraded.Single(e => e.Subject == "directive");
            Assert.Equal("directive_superseded", directiveFault.Reason);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public async Task ModeImmediate_ReportAborted_NextCycle_RetriesTheReport_NotPermanentlyGivenUp()
    {
        // No marker was written on abort, so the directive (still evaluating as
        // "due" from the signed config's point of view) is re-attempted next cycle.
        // If the platform still says superseded, this just aborts harmlessly again;
        // if a later config genuinely cancels it (mode reverts to "none"), the
        // evaluator itself will stop returning Due before this is ever reached again.
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var (runner, _, handoff, reporter, _) = MakeRunner(tmpDir);
            reporter.Outcome = DecommissionReportOutcome.Aborted;
            var config = ConfigWith(new DecommissionPolicy { ModeRaw = "immediate" });

            await runner.RunAsync(config, CancellationToken.None);
            await runner.RunAsync(config, CancellationToken.None);

            Assert.Equal(2, reporter.Calls);
            Assert.Equal(0, handoff.StageCalls);
            Assert.Equal(2, handoff.DeregisterCalls); // backstop called every abort, harmlessly
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public async Task ModeImmediate_SecondCycleAfterProceed_DoesNotReReportOrReTriggerHandoff()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var (runner, _, handoff, reporter, _) = MakeRunner(tmpDir);
            reporter.Outcome = DecommissionReportOutcome.Proceed;
            var config = ConfigWith(new DecommissionPolicy { ModeRaw = "immediate" });

            await runner.RunAsync(config, CancellationToken.None);
            await runner.RunAsync(config, CancellationToken.None); // e.g. the next ~15s poll tick
            await runner.RunAsync(config, CancellationToken.None);

            Assert.Equal(1, reporter.Calls);        // not re-asked once acknowledged and acted on
            Assert.Equal(1, handoff.StageCalls);     // not re-staged on every poll
            Assert.Equal(1, handoff.TriggerCalls);   // not re-triggered on every poll once confirmed
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public async Task ModeImmediate_HandoffStagingFails_RecordsFault_NoMarker_RetriesNextCycle()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var (runner, health, handoff, reporter, markerFile) = MakeRunner(tmpDir);
            reporter.Outcome = DecommissionReportOutcome.Proceed;
            handoff.StageReturnValue = false;
            var config = ConfigWith(new DecommissionPolicy { ModeRaw = "immediate" });

            await runner.RunAsync(config, CancellationToken.None);
            Assert.False(File.Exists(markerFile));
            Assert.Equal(1, handoff.StageCalls);
            Assert.Equal(0, handoff.TriggerCalls); // never triggers what was never staged

            // No marker was written, so the next cycle must retry the handoff rather
            // than silently giving up on an operator-issued, verified removal.
            await runner.RunAsync(config, CancellationToken.None);
            Assert.Equal(2, handoff.StageCalls);
            Assert.Equal(2, reporter.Calls); // acknowledged is re-reported each retry too

            var entry = health.BuildPayloadSection()!.Degraded.Single(e => e.Subject == "directive");
            Assert.Equal("handoff_scheduling_failed", entry.Reason);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public async Task FaultThenValidNone_ClearsTheFault()
    {
        // Resolve-then-recur, mirroring the AgentHealthStore invariant PAT-1066
        // established for DeviceRemovalRunner: a transient bad config (e.g. a
        // temporary server-side bug producing an unrecognised mode) must clear once
        // a valid config is verified again, and must not have poisoned ever_succeeded.
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var (runner, health, _, _, _) = MakeRunner(tmpDir);

            await runner.RunAsync(ConfigWith(new DecommissionPolicy { ModeRaw = "garbage" }), CancellationToken.None);
            Assert.Single(health.BuildPayloadSection()!.Degraded);

            await runner.RunAsync(ConfigWith(new DecommissionPolicy { ModeRaw = "none" }), CancellationToken.None);
            Assert.Empty(health.BuildPayloadSection()!.Degraded);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }
}
