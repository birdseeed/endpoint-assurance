using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1293. Pure content assertions on the generated self-update restart script —
/// the shape and ordering of what runs in the one-shot scheduled task. Cannot
/// exercise the script AGAINST a real Windows service/Task Scheduler from this (or
/// any) CI host; mirrors DecommissionHandoffScriptTests' identical caveat for the
/// identical reason. This proves the generator emits the right instructions in the
/// right order, not that PowerShell/Stop-Service/Start-Service/schtasks actually do
/// what the instructions say.
/// </summary>
public class PendingUpdateRestartScriptTests
{
    private const string TaskName    = "PatchedAgentSelfUpdateRestart";
    private const string MarkerFile  = @"C:\ProgramData\Patched\pending-agent-update.json";
    private const string ServiceName = "Patched Agent";

    private static string BuildScript(
        string taskName = TaskName, string markerFile = MarkerFile, string serviceName = ServiceName) =>
        PendingUpdateRestartScript.Build(taskName, markerFile, serviceName);

    [Fact]
    public void Build_ChecksMarkerBeforeTouchingTheService()
    {
        string script = BuildScript();

        int markerCheckIdx = script.IndexOf("if (-not (Test-Path $markerFile)) {", StringComparison.Ordinal);
        int stopIdx        = script.IndexOf("Stop-Service -Name $serviceName", StringComparison.Ordinal);

        Assert.True(markerCheckIdx >= 0 && stopIdx > markerCheckIdx);
    }

    [Fact]
    public void Build_MarkerAlreadyGone_DeletesTaskAndExits_WithoutTouchingTheService()
    {
        string script = BuildScript();

        int markerCheckIdx = script.IndexOf("if (-not (Test-Path $markerFile)) {", StringComparison.Ordinal);
        int deleteInBranchIdx = script.IndexOf("schtasks.exe /Delete /TN $taskName /F", markerCheckIdx, StringComparison.Ordinal);
        int exitIdx        = script.IndexOf("exit 0", markerCheckIdx, StringComparison.Ordinal);
        int stopIdx        = script.IndexOf("Stop-Service -Name $serviceName", StringComparison.Ordinal);

        // The delete-and-exit for the "already applied" branch must be entirely
        // INSIDE the marker-gone check, and strictly before the service is ever
        // touched — an already-healthy running service must never be bounced for
        // no reason just because this task happened to fire.
        Assert.True(markerCheckIdx >= 0);
        Assert.True(deleteInBranchIdx > markerCheckIdx && deleteInBranchIdx < stopIdx);
        Assert.True(exitIdx > deleteInBranchIdx && exitIdx < stopIdx);
    }

    // -------------------------------------------------------------------------
    // The core ordering the ticket cares about: marker check, then stop, then
    // start, then self-delete — in that order, every time.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_StopsThenStartsTheService_ThenSelfDeletesLast_InOrder()
    {
        string script = BuildScript();

        int markerCheckIdx = script.IndexOf("if (-not (Test-Path $markerFile)) {", StringComparison.Ordinal);
        int stopIdx        = script.IndexOf("Stop-Service -Name $serviceName", StringComparison.Ordinal);
        int startIdx       = script.IndexOf("Start-Service -Name $serviceName", StringComparison.Ordinal);
        // The task's OWN self-delete, after the service bounce — distinct from
        // the "marker already gone" branch's earlier delete-and-exit found above.
        int selfDeleteIdx  = script.LastIndexOf("schtasks.exe /Delete /TN $taskName /F", StringComparison.Ordinal);

        Assert.True(markerCheckIdx >= 0 && stopIdx >= 0 && startIdx >= 0 && selfDeleteIdx >= 0);
        Assert.True(markerCheckIdx < stopIdx);
        Assert.True(stopIdx < startIdx);
        Assert.True(startIdx < selfDeleteIdx);
    }

    [Fact]
    public void Build_StopServiceUsesForce()
    {
        string script = BuildScript();
        Assert.Contains("Stop-Service -Name $serviceName -Force", script);
    }

    [Fact]
    public void Build_NeverAddsAnOnStartTrigger()
    {
        // A boot already applies the marker via Worker.ExecuteAsync's normal
        // PendingUpdateApplier.Apply() call at service start — an ONSTART trigger
        // here (or any schtasks-registration content at all, since registration
        // itself lives in PendingUpdateRestartScheduler, not this script) would be
        // redundant machinery duplicating that existing path.
        string script = BuildScript();
        Assert.DoesNotContain("ONSTART", script);
        Assert.DoesNotContain("/Create", script);
    }

    // -------------------------------------------------------------------------
    // Correct embedding of the three build parameters, including quoting/
    // escaping of paths that contain spaces and embedded single quotes.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_EmbedsTaskNameMarkerPathAndServiceName()
    {
        string script = BuildScript();

        Assert.Contains($"$taskName    = '{TaskName}'", script);
        Assert.Contains($"$markerFile  = '{MarkerFile}'", script);
        Assert.Contains($"$serviceName = '{ServiceName}'", script);
    }

    [Fact]
    public void Build_MarkerPathWithSpaces_IsEmbeddedVerbatim_NoExtraEscapingNeeded()
    {
        // Single-quoted PowerShell strings do not need spaces escaped — only
        // embedded single quotes (covered separately below). "C:\ProgramData\Patched"
        // has no spaces, but other shapes in this codebase do (e.g. "C:\Program
        // Files\Patched" for the decommission script's binary path) — this proves
        // a space-bearing path round-trips through Build unchanged.
        const string spacedMarker = @"C:\Program Files\Patched\pending-agent-update.json";
        string script = BuildScript(markerFile: spacedMarker);

        Assert.Contains($"$markerFile  = '{spacedMarker}'", script);
    }

    [Fact]
    public void Build_EscapesEmbeddedSingleQuotesInMarkerPath()
    {
        string script = BuildScript(markerFile: @"C:\Program Files\It's Patched\pending-agent-update.json");
        Assert.Contains("It''s Patched", script);
    }

    [Fact]
    public void Build_EscapesEmbeddedSingleQuotesInServiceName()
    {
        string script = BuildScript(serviceName: "Patched's Agent");
        Assert.Contains("Patched''s Agent", script);
    }

    [Fact]
    public void Build_EscapesEmbeddedSingleQuotesInTaskName()
    {
        string script = BuildScript(taskName: "Patched's Restart Task");
        Assert.Contains("Patched''s Restart Task", script);
    }
}
