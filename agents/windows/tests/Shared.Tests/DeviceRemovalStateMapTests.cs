using System.Text.Json;
using Patched.Shared.Contract;
using Patched.Shared.Removal;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-781: the engine RemovalOutcome → server report-state mapping. The server
/// accepts exactly { in-progress, removed, residual, manual, failed }; every outcome
/// the device-task runner can produce must land on one of them, with terminal vs
/// retryable ("in-progress") chosen correctly.
/// </summary>
public class DeviceRemovalStateMapTests
{
    [Theory]
    [InlineData(RemovalOutcome.Removed,                  "removed")]
    [InlineData(RemovalOutcome.AlreadyRemoved,           "removed")]
    [InlineData(RemovalOutcome.RemovedResidual,          "residual")]
    [InlineData(RemovalOutcome.ManualRemovalRequired,    "manual")]
    [InlineData(RemovalOutcome.SkippedBaselineProtected, "manual")]
    [InlineData(RemovalOutcome.SkippedUserPolicy,        "manual")]
    [InlineData(RemovalOutcome.DeferredAppRunning,       "in-progress")]
    [InlineData(RemovalOutcome.FailedTransient,          "in-progress")]
    [InlineData(RemovalOutcome.FailedHard,               "failed")]
    [InlineData(RemovalOutcome.AuthorityRefused,         "failed")]
    [InlineData(RemovalOutcome.Unknown,                  "failed")]
    public void ToReportState_MapsOutcome(RemovalOutcome outcome, string expected)
    {
        Assert.Equal(expected, DeviceRemovalStateMap.ToReportState(outcome));
    }

    [Fact]
    public void EveryOutcome_MapsToAnAgentReportableState()
    {
        var reportable = new HashSet<string> { "in-progress", "removed", "residual", "manual", "failed" };
        foreach (RemovalOutcome outcome in Enum.GetValues<RemovalOutcome>())
            Assert.Contains(DeviceRemovalStateMap.ToReportState(outcome), reportable);
    }

    [Fact]
    public void AuthorityRefused_SerializesAsSnakeCaseTerminalOutcome()
    {
        var json = JsonSerializer.Serialize(RemovalOutcome.AuthorityRefused, ContractJsonOptions.Write);

        Assert.Equal("\"authority_refused\"", json);
        Assert.Equal(RemovalOutcome.AuthorityRefused,
            JsonSerializer.Deserialize<RemovalOutcome>(json, ContractJsonOptions.Read));
    }
}
