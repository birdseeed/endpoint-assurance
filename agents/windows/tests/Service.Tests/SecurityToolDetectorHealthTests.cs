using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Contract;
using Patched.Shared.Compliance;
using Patched.Shared.DeviceClassification;
using Patched.Shared.SecurityTools;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2267: security_tools has no collection status on the wire, so a detection that could
/// not read a source is recorded in agent_health under (collection_partial, security_tools)
/// and cleared by the next complete detection. Readers are injected, so this runs on any OS.
/// </summary>
public sealed class SecurityToolDetectorHealthTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("patched-sectools-health-").FullName;
    private readonly AgentHealthStore _health;

    public SecurityToolDetectorHealthTests()
    {
        _health = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, Path.Combine(_root, "agent-health.json"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private SecurityToolDetector Detector(
        Func<SecurityCenterRead> securityCenter,
        Func<SecurityToolProbe>? defender = null,
        Func<string, SecurityToolProbe>? registry = null,
        Func<RegistryRead>? onboarding = null) =>
        new(NullLogger<SecurityToolDetector>.Instance, _health, securityCenter,
            defender ?? (() => SecurityToolProbe.Absent), registry ?? (_ => SecurityToolProbe.Absent),
            onboarding ?? (() => RegistryRead.Absent));

    private InventoryAgentHealthEntry? Entry() =>
        _health.BuildPayloadSection()!.Degraded.SingleOrDefault(d =>
            d.Kind == SecurityToolDetector.HealthKind && d.Subject == SecurityToolDetector.HealthSubject);

    [Fact]
    public void WmiFailure_RecordsUndetermined_AndClaimsNoTools()
    {
        var tools = Detector(() => throw new System.Runtime.InteropServices.COMException("RPC unavailable"))
            .Detect(DeviceClassValue.Workstation);

        Assert.Empty(tools);
        var entry = Entry();
        Assert.NotNull(entry);
        Assert.Equal(SecurityToolLogic.ReasonSecurityCenterFailed, entry.Reason);
    }

    [Fact]
    public void RegistryFailure_RecordsUndetermined()
    {
        Detector(() => SecurityCenterRead.Of(), registry: _ => SecurityToolProbe.Failed)
            .Detect(DeviceClassValue.Workstation);

        Assert.Equal(SecurityToolLogic.ReasonRegistryFailed, Entry()?.Reason);
    }

    [Fact]
    public void ServerWithoutSecurityCenter_IsHealthy_NotUndetermined()
    {
        var tools = Detector(() => SecurityCenterRead.Missing, defender: () => SecurityToolProbe.Present)
            .Detect(DeviceClassValue.Server);

        Assert.Equal([SecurityToolLogic.DefenderAntivirusId], tools.Select(t => t.Id));
        Assert.Null(Entry());
    }

    [Fact]
    public void ACompleteDetection_ClearsTheEntry()
    {
        Detector(() => SecurityCenterRead.Failed).Detect(DeviceClassValue.Workstation);
        Assert.NotNull(Entry());

        Detector(() => SecurityCenterRead.Of(new SecurityCenterProduct("ESET Security", 0x041000u)))
            .Detect(DeviceClassValue.Workstation);

        Assert.Null(Entry());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MdeUnusableRead_RecordsPartialHealth_AndCleanAbsentClearsIt(bool throws)
    {
        var tools = Detector(() => SecurityCenterRead.Of(),
            onboarding: () => throws ? throw new IOException("read failed") : RegistryRead.Present("1"))
            .Detect(DeviceClassValue.Workstation);

        Assert.Empty(tools);
        var entry = Entry();
        Assert.NotNull(entry);
        Assert.Equal("collection_partial", entry.Kind);
        Assert.Equal("security_tools", entry.Subject);
        Assert.Equal(SecurityToolLogic.ReasonMdeOnboardingFailed, entry.Reason);

        Detector(() => SecurityCenterRead.Of(), onboarding: () => RegistryRead.Absent)
            .Detect(DeviceClassValue.Workstation);
        Assert.Null(Entry());
    }

    [Fact]
    public void MdeOnboardedDword_ReportsMde_AndIsHealthy()
    {
        var tools = Detector(() => SecurityCenterRead.Missing,
            defender: () => SecurityToolProbe.Present, onboarding: () => RegistryRead.Present(1))
            .Detect(DeviceClassValue.Server);

        Assert.Equal(["defender-for-endpoint", SecurityToolLogic.DefenderAntivirusId], tools.Select(t => t.Id));
        Assert.Null(Entry());
    }
}
