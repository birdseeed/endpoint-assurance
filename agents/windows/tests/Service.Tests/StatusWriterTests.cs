using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// Tests for StatusWriter.Build() — the overall-state logic that classifies
/// the estate into up_to_date / updates_available / error.
/// No file I/O; no WMI; pure contract-computation tests.
/// </summary>
public sealed class StatusWriterTests
{
    private static readonly DateTimeOffset T0  = new(2026, 12, 11, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset T1  = T0.AddMinutes(1);
    private static readonly DateTimeOffset Next = T0.AddDays(1);

    private static StatusWriter MakeWriter() =>
        new(NullLogger<StatusWriter>.Instance);

    private static AppEntry App(AppState state, string label = "pkg") => new()
    {
        Label = label,
        Name  = label,
        State = state,
    };

    [Fact]
    public void Build_AllUpToDate_ReturnsUpToDate()
    {
        var writer = MakeWriter();
        var status = writer.Build(T0, T1, "scheduled",
            [App(AppState.UpToDate, "a"), App(AppState.Installed, "b")],
            Next);

        Assert.Equal(OverallState.UpToDate, status.OverallState);
        Assert.Equal(0, status.Counts!.UpdatesAvailable);
        Assert.Equal(0, status.Counts.Errors);
    }

    [Fact]
    public void Build_OneUpdateAvailable_ReturnsUpdatesAvailable()
    {
        var writer = MakeWriter();
        var status = writer.Build(T0, T1, "scheduled",
            [App(AppState.UpToDate), App(AppState.UpdateAvailable)],
            Next);

        Assert.Equal(OverallState.UpdatesAvailable, status.OverallState);
        Assert.Equal(1, status.Counts!.UpdatesAvailable);
        Assert.Equal(1, status.Counts.UpToDate);
    }

    [Fact]
    public void Build_OneError_ReturnsError()
    {
        var writer = MakeWriter();
        var status = writer.Build(T0, T1, "scheduled",
            [App(AppState.UpToDate), App(AppState.Error)],
            Next);

        Assert.Equal(OverallState.Error, status.OverallState);
        Assert.Equal(1, status.Counts!.Errors);
    }

    [Fact]
    public void Build_VerificationFailed_CountsAsError()
    {
        var writer = MakeWriter();
        var status = writer.Build(T0, T1, "scheduled",
            [App(AppState.VerificationFailed)],
            Next);

        Assert.Equal(OverallState.Error, status.OverallState);
        Assert.Equal(1, status.Counts!.Errors);
    }

    [Fact]
    public void Build_ErrorTakesPriorityOverUpdatesAvailable()
    {
        var writer = MakeWriter();
        var status = writer.Build(T0, T1, "scheduled",
            [App(AppState.UpdateAvailable), App(AppState.Error)],
            Next);

        // Error takes priority over updates_available.
        Assert.Equal(OverallState.Error, status.OverallState);
    }

    [Fact]
    public void Build_SchemaVersionIsAlways1()
    {
        var writer = MakeWriter();
        var status = writer.Build(T0, T1, "manual", [], Next);
        Assert.Equal(1, status.SchemaVersion);
    }

    [Fact]
    public void Build_TotalCountMatchesInputCount()
    {
        var writer = MakeWriter();
        var apps   = Enumerable.Range(0, 5).Select(i => App(AppState.UpToDate, $"pkg{i}")).ToList();
        var status = writer.Build(T0, T1, "scheduled", apps, Next);

        Assert.Equal(5, status.Counts!.Total);
        Assert.Equal(5, status.Apps.Count);
    }

    [Fact]
    public void Build_EmptyAppList_ReturnsUpToDate()
    {
        var writer = MakeWriter();
        var status = writer.Build(T0, T1, "first-run", [], Next);

        Assert.Equal(OverallState.UpToDate, status.OverallState);
        Assert.Equal(0, status.Counts!.Total);
    }

    [Fact]
    public void Build_DeployWithUnmatchedSingleLabel_ReturnsExplicitError()
    {
        var writer = MakeWriter();
        var status = writer.Build(T0, T1, "manual", [], Next,
            requestedDeployLabels: ["googlechrome"]);

        Assert.Equal(OverallState.Error, status.OverallState);
        var refusal = Assert.Single(status.Apps);
        Assert.Equal("googlechrome", refusal.Label);
        Assert.Equal(AppState.Error, refusal.State);
        Assert.Equal("error", refusal.LastAction);
        Assert.Contains("not in this endpoint's allowlist", refusal.Message);
        Assert.Equal(1, status.Counts!.Errors);
    }

    [Fact]
    public void Build_InstallAllReportsEveryMissingLabelWithoutReplacingRealResults()
    {
        var writer = MakeWriter();
        var status = writer.Build(T0, T1, "manual",
            [App(AppState.UpToDate, "googlechrome")], Next,
            requestedDeployLabels: ["googlechrome", "com.microsoft.Word", "slack"]);

        Assert.Equal(3, status.Apps.Count);
        Assert.Equal(2, status.Counts!.Errors);
        Assert.Contains(status.Apps, a => a.Label == "googlechrome" && a.State == AppState.UpToDate);
        Assert.Contains(status.Apps, a => a.Label == "com.microsoft.Word" && a.State == AppState.Error);
        Assert.Contains(status.Apps, a => a.Label == "slack" && a.State == AppState.Error);
    }

    [Fact]
    public void Build_EmptyDeployLabels_ReturnsSpecificRefusal()
    {
        var writer = MakeWriter();
        var status = writer.Build(T0, T1, "manual", [], Next,
            requestedDeployLabels: []);

        var refusal = Assert.Single(status.Apps);
        Assert.Equal("*", refusal.Label);
        Assert.Contains("did not contain any valid labels", refusal.Message);
        Assert.Equal(OverallState.Error, status.OverallState);
    }

    [Fact]
    public void Build_WildcardInstallAllWithNoResults_ReturnsSpecificRefusal()
    {
        var writer = MakeWriter();
        var status = writer.Build(T0, T1, "manual", [], Next,
            requestedDeployLabels: ["*"]);

        var refusal = Assert.Single(status.Apps);
        Assert.Contains("Install all request refused", refusal.Message);
        Assert.Equal(OverallState.Error, status.OverallState);
    }

    [Fact]
    public void Build_WildcardInstallAllWithResultsDoesNotInventError()
    {
        var writer = MakeWriter();
        var status = writer.Build(T0, T1, "manual",
            [App(AppState.UpToDate, "googlechrome")], Next,
            requestedDeployLabels: ["*"]);

        Assert.Single(status.Apps);
        Assert.Equal(OverallState.UpToDate, status.OverallState);
        Assert.Equal(0, status.Counts!.Errors);
    }

    [Fact]
    public void Build_LastRunTriggerIsPreserved()
    {
        var writer = MakeWriter();
        var status = writer.Build(T0, T1, "manual", [], Next);
        Assert.Equal("manual", status.LastRun!.Trigger);
        Assert.Equal(T0,       status.LastRun.StartedAt);
        Assert.Equal(T1,       status.LastRun.FinishedAt);
    }

    [Fact]
    public void Build_NextScheduledRunIsPreserved()
    {
        var writer = MakeWriter();
        var status = writer.Build(T0, T1, "scheduled", [], Next);
        Assert.Equal(Next, status.NextScheduledRun);
    }
}
