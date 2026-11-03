using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1531 regression coverage for PAT-1066 health semantics after the legacy
/// Windows runner and package engine are excluded from the assurance build.
/// </summary>
public sealed class AssuranceCapabilityHealthTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));

    public AssuranceCapabilityHealthTests() => Directory.CreateDirectory(_directory);

    private string PosturePath => Path.Combine(_directory, "posture.json");

    private AgentHealthStore NewHealth() =>
        new(NullLogger<AgentHealthStore>.Instance, Path.Combine(_directory, "agent-health.json"));

    private AssuranceCapabilityHealth NewReporter(AgentHealthStore health) =>
        new(NullLogger<AssuranceCapabilityHealth>.Instance, health, PosturePath);

    [Fact]
    public void Record_MissingDeviceIdentity_NeverReportsFalseAllClear_AndEngineAbsenceIsNotAFault()
    {
        var health = NewHealth();

        NewReporter(health).Record();

        var degraded = health.BuildPayloadSection()!.Degraded;
        Assert.Contains(degraded, entry =>
            entry.Kind == "directive_skipped"
            && entry.Subject == "device_removal"
            && entry.Reason == "no_device_id");
        // PAT-2422: the engine is absent from the assurance agent by design, so its
        // absence is not reported as a degraded reason. RetiredHealthReasonsTests
        // covers the entry older releases left in the store.
        Assert.DoesNotContain(degraded, entry => entry.Subject == "package_engine");
    }

    [Fact]
    public void RecordDeviceRemovalIdentity_UsablePostureClearsPriorFaultAndPreservesSuccessLedger()
    {
        var health = NewHealth();
        var reporter = NewReporter(health);

        reporter.RecordDeviceRemovalIdentity();
        Assert.Single(health.BuildPayloadSection()!.Degraded);

        File.WriteAllText(PosturePath, "{\"device\":{\"id\":\"device-abc-123\"}}");
        reporter.RecordDeviceRemovalIdentity();
        Assert.Empty(health.BuildPayloadSection()!.Degraded);

        File.Delete(PosturePath);
        reporter.RecordDeviceRemovalIdentity();

        var fault = Assert.Single(health.BuildPayloadSection()!.Degraded);
        Assert.Equal("no_device_id", fault.Reason);
        Assert.True(fault.EverSucceeded);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }
}
