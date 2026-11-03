using Patched.Shared.Removal;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-379: the pure removal-decision core — method resolution, MSI detection, and
/// failure classification — mirroring the macOS engine's resolve_uninstall /
/// classify_failure.
/// </summary>
public class UninstallPlannerTests
{
    private const string Guid = "{B2D3F4A1-1234-4567-89AB-CDEF01234567}";

    private static InstalledProgram Prog(
        string name = "Acme App", string? quiet = null, string? uninstall = null,
        string key = "Acme App", bool msi = false, bool sysComp = false,
        string? publisher = null, string? installLoc = null) =>
        new()
        {
            Name = name, QuietUninstallString = quiet, UninstallString = uninstall,
            RegistryKeyName = key, WindowsInstaller = msi, SystemComponent = sysComp,
            Publisher = publisher, InstallLocation = installLoc,
        };

    [Fact]
    public void Resolve_PrefersQuietUninstallString()
    {
        var r = UninstallPlanner.Resolve(
            Prog(quiet: "\"C:\\App\\uninst.exe\" /S", uninstall: "\"C:\\App\\uninst.exe\""),
            wingetKnows: true, catalogueRecipe: "recipe");

        Assert.Equal(RemovalMethod.RegistryQuietUninstall, r.Method);
        Assert.Equal("\"C:\\App\\uninst.exe\" /S", r.Detail);
    }

    [Fact]
    public void Resolve_MsiByGuidKey_UsesProductCode()
    {
        var r = UninstallPlanner.Resolve(
            Prog(key: Guid, uninstall: $"MsiExec.exe /X{Guid}"),
            wingetKnows: false, catalogueRecipe: null);

        Assert.Equal(RemovalMethod.Msi, r.Method);
        Assert.Equal(Guid, r.Detail);
    }

    [Fact]
    public void Resolve_MsiByUninstallString_WhenKeyNotGuid()
    {
        var r = UninstallPlanner.Resolve(
            Prog(key: "SomeApp", uninstall: $"MsiExec.exe /X{Guid}"),
            wingetKnows: false, catalogueRecipe: null);

        Assert.Equal(RemovalMethod.Msi, r.Method);
        Assert.Equal(Guid, r.Detail);
    }

    [Fact]
    public void Resolve_FallsBackToUninstallString()
    {
        var r = UninstallPlanner.Resolve(
            Prog(uninstall: "\"C:\\App\\setup.exe\" --uninstall"),
            wingetKnows: false, catalogueRecipe: null);

        Assert.Equal(RemovalMethod.RegistryUninstall, r.Method);
        Assert.Equal("\"C:\\App\\setup.exe\" --uninstall", r.Detail);
    }

    [Fact]
    public void Resolve_WingetFallback_WhenRegistryHasNoUsableString()
    {
        var r = UninstallPlanner.Resolve(
            Prog(name: "Acme App"), wingetKnows: true, catalogueRecipe: "recipe");

        Assert.Equal(RemovalMethod.Winget, r.Method);
        Assert.Equal("Acme App", r.Detail);
    }

    [Fact]
    public void Resolve_CatalogueFallback_WhenWingetUnknown()
    {
        var r = UninstallPlanner.Resolve(
            Prog(name: "Acme App"), wingetKnows: false, catalogueRecipe: "remove-acme");

        Assert.Equal(RemovalMethod.Catalogue, r.Method);
        Assert.Equal("remove-acme", r.Detail);
    }

    [Fact]
    public void Resolve_Unresolvable_WhenNothingAvailable()
    {
        var r = UninstallPlanner.Resolve(Prog(), wingetKnows: false, catalogueRecipe: null);
        Assert.Equal(RemovalMethod.Unresolvable, r.Method);
    }

    [Fact]
    public void Resolve_NullProgram_UsesWingetThenUnresolvable()
    {
        Assert.Equal(RemovalMethod.Winget,
            UninstallPlanner.Resolve(null, wingetKnows: true, catalogueRecipe: null).Method);
        Assert.Equal(RemovalMethod.Unresolvable,
            UninstallPlanner.Resolve(null, wingetKnows: false, catalogueRecipe: null).Method);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void IsMsi_DetectsWindowsInstallerFlag(bool flag)
    {
        Assert.Equal(flag, UninstallPlanner.IsMsi(Prog(msi: flag, key: "SomeApp")));
    }

    [Fact]
    public void MsiProductCode_ExtractsFromKeyOrString()
    {
        Assert.Equal(Guid, UninstallPlanner.MsiProductCode(Prog(key: Guid)));
        Assert.Equal(Guid, UninstallPlanner.MsiProductCode(Prog(key: "X", uninstall: $"msiexec /x{Guid}")));
        Assert.Null(UninstallPlanner.MsiProductCode(Prog(key: "X", uninstall: "setup.exe /u")));
    }

    [Fact]
    public void ClassifyStillPresent_SystemComponentIsHard()
    {
        Assert.Equal(RemovalOutcome.FailedHard,
            UninstallPlanner.ClassifyStillPresent(Prog(sysComp: true)));
    }

    [Fact]
    public void ClassifyStillPresent_BaselineNameIsHard()
    {
        Assert.Equal(RemovalOutcome.FailedHard,
            UninstallPlanner.ClassifyStillPresent(Prog(name: "Microsoft Edge")));
    }

    [Fact]
    public void ClassifyStillPresent_OrdinaryAppIsTransient()
    {
        Assert.Equal(RemovalOutcome.FailedTransient,
            UninstallPlanner.ClassifyStillPresent(Prog(name: "Acme App")));
        Assert.Equal(RemovalOutcome.FailedTransient,
            UninstallPlanner.ClassifyStillPresent(null));
    }

    [Theory]
    [InlineData(VerifyResult.Gone, RemovalOutcome.Removed)]
    [InlineData(VerifyResult.Residual, RemovalOutcome.RemovedResidual)]
    public void OutcomeFor_MapsCleanVerifyResults(VerifyResult v, RemovalOutcome expected)
    {
        Assert.Equal(expected, UninstallPlanner.OutcomeFor(v));
    }
}
