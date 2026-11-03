using Patched.Shared.Contract;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// Desktop chain U5: the scan + uninstall trigger types added to TriggerRequest,
/// and their disambiguation from deploy/os_defer plus validator acceptance.
/// </summary>
public class TriggerScanUninstallTests
{
    [Fact]
    public void ScanTrigger_IsScanNotDeploy()
    {
        var t = new TriggerRequest { Type = "scan", RequestedBy = "u" };
        Assert.True(t.IsScanRequest);
        Assert.False(t.IsDeployRequest);
        Assert.False(t.IsUninstallRequest);
        Assert.False(t.IsOsDefer);
    }

    [Fact]
    public void UninstallTrigger_IsUninstallNotDeploy()
    {
        var t = new TriggerRequest { Type = "uninstall", Labels = new[] { "{GUID}" } };
        Assert.True(t.IsUninstallRequest);
        Assert.False(t.IsDeployRequest);   // typed trigger is not a deploy
        Assert.False(t.IsScanRequest);
    }

    [Fact]
    public void UninstallWithoutLabels_IsNotUninstall()
    {
        var t = new TriggerRequest { Type = "uninstall" };
        Assert.False(t.IsUninstallRequest);
    }

    [Fact]
    public void UntypedLabels_IsDeploy()
    {
        var t = new TriggerRequest { Labels = new[] { "googlechrome" } };
        Assert.True(t.IsDeployRequest);
        Assert.False(t.IsUninstallRequest);
        Assert.False(t.IsScanRequest);
    }

    [Theory]
    [InlineData("{\"type\":\"scan\",\"requested_by\":\"u\"}")]
    [InlineData("{\"type\":\"uninstall\",\"labels\":[\"{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\"]}")]
    [InlineData("{\"type\":\"uninstall\",\"labels\":[\"7-Zip\"]}")]
    public void Validator_AcceptsScanAndUninstall(string json)
    {
        bool ok = TriggerRequestValidator.TryValidate(json, json.Length, out var req, out var err);
        Assert.True(ok, err);
        Assert.NotNull(req);
    }

    [Fact]
    public void Validator_RejectsUninstallWithBadIdentifier()
    {
        var json = "{\"type\":\"uninstall\",\"labels\":[\"bad/../path\"]}";
        bool ok = TriggerRequestValidator.TryValidate(json, json.Length, out _, out var err);
        Assert.False(ok);
        Assert.NotNull(err);
    }

    [Fact]
    public void Validator_StillRejectsEmptyTrigger()
    {
        var json = "{\"requested_by\":\"u\"}";
        bool ok = TriggerRequestValidator.TryValidate(json, json.Length, out _, out _);
        Assert.False(ok);
    }
}
