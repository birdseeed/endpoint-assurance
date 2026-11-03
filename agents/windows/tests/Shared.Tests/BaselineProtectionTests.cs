using Patched.Shared.Removal;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>PAT-379: the Windows baseline-protection safety guard.</summary>
public class BaselineProtectionTests
{
    [Theory]
    [InlineData("Microsoft Edge")]
    [InlineData("Microsoft Edge WebView2 Runtime")]
    [InlineData("Microsoft Visual C++ 2015-2022 Redistributable (x64)")]
    [InlineData("Microsoft .NET Runtime - 8.0.6 (x64)")]
    [InlineData("Windows Desktop Runtime - 8.0.6")]
    [InlineData("Microsoft Defender")]
    [InlineData("Patched Agent")]
    [InlineData("microsoft edge")]   // case-insensitive
    public void IsProtected_BlocksBaselineApps(string name)
    {
        Assert.True(BaselineProtection.IsProtected(name));
    }

    [Theory]
    [InlineData("Google Chrome")]
    [InlineData("Slack")]
    [InlineData("Zoom")]
    [InlineData("7-Zip 23.01 (x64)")]
    public void IsProtected_AllowsOrdinaryApps(string name)
    {
        Assert.False(BaselineProtection.IsProtected(name));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void IsProtected_HandlesEmptyName(string? name)
    {
        Assert.False(BaselineProtection.IsProtected(name));
    }
}
