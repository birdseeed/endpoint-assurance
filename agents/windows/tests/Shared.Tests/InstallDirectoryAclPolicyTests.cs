using Patched.Shared.Security;
using Xunit;
using Ace = Patched.Shared.Security.InstallDirectoryAclPolicy.Ace;

namespace Patched.Shared.Tests;

// PAT-2399: the rule that decides whether %ProgramFiles%\Patched and the service executable
// can be trusted before the service does privileged work. Pure, so it runs on every platform.
public sealed class InstallDirectoryAclPolicyTests
{
    private const string LocalSystem = InstallDirectoryAclPolicy.LocalSystemSid;
    private const string Admins = InstallDirectoryAclPolicy.AdministratorsSid;
    private const string TrustedInstaller = InstallDirectoryAclPolicy.TrustedInstallerSid;
    private const string CreatorOwner = "S-1-3-0";
    private const string Users = "S-1-5-32-545";
    private const string Everyone = "S-1-1-0";
    private const string AuthenticatedUsers = "S-1-5-11";
    private const string StandardUser = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    private const string AllAppPackages = "S-1-15-2-1";
    private const string AllRestrictedAppPackages = "S-1-15-2-2";

    private const uint Full = 0x001F01FF;            // (F) on the object
    private const uint GenericAll = 0x10000000;      // (F) on an inherit-only entry
    private const uint ReadExecute = 0x001200A9;     // (RX)
    private const uint GenericReadExecute = 0xA0000000; // (GR,GE)
    private const uint Modify = 0x001301BF;          // (M)

    private static Ace Allow(string sid, uint mask, bool inheritOnly = false) => new(sid, mask, true, inheritOnly);

    // C:\Program Files\Patched exactly as icacls read it on an installed Windows 11 device
    // running 0.15.1.6 (2026-10-05): every entry inherited from Program Files, owner SYSTEM.
    // This is the ACL a healthy device has. If the rule rejects it, every agent in the estate
    // loses self-update and its evidence helpers, so this is the test that matters most.
    internal static readonly Ace[] RealInstallDirectory =
    [
        Allow(TrustedInstaller, Full),
        Allow(TrustedInstaller, GenericAll, inheritOnly: true),      // (CI)(IO)(F)
        Allow(LocalSystem, Full),
        Allow(LocalSystem, GenericAll, inheritOnly: true),                // (OI)(CI)(IO)(F)
        Allow(Admins, Full),
        Allow(Admins, GenericAll, inheritOnly: true),
        Allow(Users, ReadExecute),
        Allow(Users, GenericReadExecute, inheritOnly: true),         // (OI)(CI)(IO)(GR,GE)
        Allow(CreatorOwner, GenericAll, inheritOnly: true),          // (OI)(CI)(IO)(F)
        Allow(AllAppPackages, ReadExecute),
        Allow(AllAppPackages, GenericReadExecute, inheritOnly: true),
        Allow(AllRestrictedAppPackages, ReadExecute),
        Allow(AllRestrictedAppPackages, GenericReadExecute, inheritOnly: true),
    ];

    // C:\Program Files\Patched\Patched.Service.exe on the same device.
    internal static readonly Ace[] RealServiceExecutable =
    [
        Allow(LocalSystem, Full), Allow(Admins, Full), Allow(Users, ReadExecute),
        Allow(AllAppPackages, ReadExecute), Allow(AllRestrictedAppPackages, ReadExecute),
    ];

    // What the MSI sets from this release on: D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU).
    private static readonly Ace[] MsiInstallDirectory = [Allow(LocalSystem, Full), Allow(Admins, Full), Allow(Users, ReadExecute)];

    [Fact]
    public void TheAclAHealthyInstalledDeviceHasToday_Passes()
    {
        Assert.Null(InstallDirectoryAclPolicy.Evaluate(false, LocalSystem, RealInstallDirectory));
        Assert.Null(InstallDirectoryAclPolicy.Evaluate(false, LocalSystem, RealServiceExecutable));
    }

    [Fact]
    public void TheExplicitAclTheMsiSets_Passes() =>
        Assert.Null(InstallDirectoryAclPolicy.Evaluate(false, LocalSystem, MsiInstallDirectory));

    [Theory]
    [InlineData(LocalSystem)]
    [InlineData(Admins)]
    [InlineData(TrustedInstaller)]
    public void TrustedOwnersPass(string owner) =>
        Assert.Null(InstallDirectoryAclPolicy.Evaluate(false, owner, RealInstallDirectory));

    [Theory]
    [InlineData(StandardUser)]
    [InlineData(Users)]
    [InlineData(CreatorOwner)]
    [InlineData(null)]
    public void AnyOtherOwnerIsUntrusted(string? owner)
    {
        var finding = InstallDirectoryAclPolicy.Evaluate(false, owner, RealInstallDirectory);
        Assert.Equal(InstallDirectoryAclPolicy.UntrustedOwner, finding?.Reason);
        Assert.Equal(owner, finding?.Sid);
    }

    [Theory]
    [InlineData(Users, Modify)]                  // Users with Modify
    [InlineData(Everyone, 0x00000002u)]          // Everyone: add file
    [InlineData(StandardUser, 0x00000116u)]      // a named standard user: write
    [InlineData(AuthenticatedUsers, 0x00000004u)]// add subdirectory
    [InlineData(Users, 0x00000040u)]             // delete child
    [InlineData(Users, 0x00010000u)]             // delete
    [InlineData(Users, 0x00040000u)]             // WRITE_DAC
    [InlineData(Users, 0x00080000u)]             // WRITE_OWNER
    [InlineData(Everyone, 0x40000000u)]          // GENERIC_WRITE left unmapped
    [InlineData(Everyone, GenericAll)]
    [InlineData(CreatorOwner, Full)]             // not inherit-only: judged like any other principal
    public void AWriteCapableAllowForAnyoneElseIsUntrusted(string sid, uint mask)
    {
        var finding = InstallDirectoryAclPolicy.Evaluate(false, LocalSystem, [.. RealInstallDirectory, Allow(sid, mask)]);
        Assert.Equal(new InstallDirectoryAclPolicy.Finding(InstallDirectoryAclPolicy.UntrustedAcl, sid, mask), finding);
        // The same grant on the executable is refused too.
        Assert.Equal(InstallDirectoryAclPolicy.UntrustedAcl,
            InstallDirectoryAclPolicy.Evaluate(false, LocalSystem, [.. RealServiceExecutable, Allow(sid, mask)])?.Reason);
    }

    // An inherit-only entry grants nothing on the directory, but it is copied onto every file
    // and folder later created inside it, which is where the next upgrade puts the service
    // executable. So a write-capable one for an untrusted principal is refused.
    [Theory]
    [InlineData(Users, Modify)]
    [InlineData(Users, 0x40000000u)]
    [InlineData(Everyone, GenericAll)]
    [InlineData(StandardUser, Full)]
    [InlineData("S-1-3-1", GenericAll)]          // CREATOR GROUP: a standard user's primary group
    public void AnInheritOnlyWriteEntryForAnUntrustedPrincipalIsUntrusted(string sid, uint mask) =>
        Assert.Equal(new InstallDirectoryAclPolicy.Finding(InstallDirectoryAclPolicy.UntrustedAcl, sid, mask),
            InstallDirectoryAclPolicy.Evaluate(false, LocalSystem, [.. RealInstallDirectory, Allow(sid, mask, inheritOnly: true)]));

    [Theory]
    [InlineData(Users, GenericReadExecute)]
    [InlineData(Everyone, ReadExecute)]
    [InlineData(LocalSystem, GenericAll)]
    [InlineData(CreatorOwner, GenericAll)]       // resolves to whoever created the child, who already needed write
    public void InheritOnlyEntriesThatCannotHandWriteToAnUntrustedPrincipalPass(string sid, uint mask) =>
        Assert.Null(InstallDirectoryAclPolicy.Evaluate(false, LocalSystem, [.. MsiInstallDirectory, Allow(sid, mask, inheritOnly: true)]));

    [Fact]
    public void ReadOnlyGrantsToAnyonePass() =>
        Assert.Null(InstallDirectoryAclPolicy.Evaluate(false, LocalSystem,
            [.. MsiInstallDirectory, Allow(Everyone, ReadExecute), Allow(StandardUser, ReadExecute)]));

    [Fact]
    public void DenyEntriesGrantNothing() =>
        Assert.Null(InstallDirectoryAclPolicy.Evaluate(false, LocalSystem,
            [.. RealInstallDirectory, new Ace(Users, Full, Allow: false, InheritOnly: false),
                new Ace(Everyone, GenericAll, Allow: false, InheritOnly: true)]));

    [Fact]
    public void AReparsePointIsRefusedWhateverItsAcl() =>
        Assert.Equal(InstallDirectoryAclPolicy.ReparsePoint,
            InstallDirectoryAclPolicy.Evaluate(true, LocalSystem, RealInstallDirectory)?.Reason);

    [Fact]
    public void AnAclThatCouldNotBeReadIsUnverifiableNotTrusted() =>
        Assert.Equal(InstallDirectoryAclPolicy.Unverifiable,
            InstallDirectoryAclPolicy.Evaluate(false, LocalSystem, null)?.Reason);
}
