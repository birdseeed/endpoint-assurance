using Patched.Shared.Contract;
using Patched.Shared.Compliance;
using Patched.Shared.DeviceClassification;
using Patched.Shared.SecurityTools;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-2267: platform-neutral tests for <see cref="SecurityToolLogic"/>. Windows Security
/// Center, the Defender status class and every registry key are delegates, so each failure
/// route runs on macOS CI. The rule under test is "absence requires authority": a source
/// that could not be read is undetermined and never reads as "no tools".
/// </summary>
public sealed class SecurityToolLogicTests
{
    // productState values seen on real devices: Defender on and up to date (0x061100),
    // Defender off / passive (0x060100), a third-party AV on (0x041000).
    private const uint DefenderOn   = 0x061100;
    private const uint DefenderOff  = 0x060100;
    private const uint ThirdPartyOn = 0x041000;

    private const string CrowdStrikeService = @"SYSTEM\CurrentControlSet\Services\CSFalconService";
    private const string BitdefenderKey     = @"SOFTWARE\Bitdefender";

    private static SecurityCenterProduct Av(string? name, object? state) => new(name, state);

    private static Func<string, SecurityToolProbe> Keys(
        IEnumerable<string>? present = null, IEnumerable<string>? failed = null)
    {
        var p = new HashSet<string>(present ?? [], StringComparer.OrdinalIgnoreCase);
        var f = new HashSet<string>(failed ?? [], StringComparer.OrdinalIgnoreCase);
        return path => f.Contains(path) ? SecurityToolProbe.Failed
            : p.Contains(path) ? SecurityToolProbe.Present
            : SecurityToolProbe.Absent;
    }

    private static readonly Func<string, SecurityToolProbe> NoKeys = Keys();

    private static SecurityToolSources Sources(
        string? deviceClass,
        Func<SecurityCenterRead> securityCenter,
        Func<SecurityToolProbe>? defender = null,
        Func<string, SecurityToolProbe>? registry = null,
        Func<RegistryRead>? onboarding = null) =>
        new(deviceClass, securityCenter, defender ?? (() => SecurityToolProbe.Absent), registry ?? NoKeys, onboarding);

    private static string[] Ids(SecurityToolDetection d) => d.Tools.Select(t => t.Id).ToArray();

    // ── Failed reads are undetermined, never "none" ──────────────────────────

    [Fact]
    public void SecurityCenterFailure_IsUndetermined_NeverAnAuthoritativeNone()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Failed));

        Assert.Empty(d.Tools);
        Assert.False(d.Complete);
        Assert.Contains(SecurityToolLogic.ReasonSecurityCenterFailed, d.Undetermined);
        Assert.NotNull(d.HealthReason);
    }

    [Fact]
    public void SecurityCenterReaderThatThrows_IsUndetermined()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => throw new UnauthorizedAccessException("denied")));

        Assert.False(d.Complete);
        Assert.Contains(SecurityToolLogic.ReasonSecurityCenterFailed, d.Undetermined);
    }

    [Fact]
    public void SecurityCenterFailure_StillReportsWhatOtherSourcesProved()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Failed,
            defender: () => SecurityToolProbe.Present,
            registry: Keys(present: [CrowdStrikeService])));

        Assert.Equal(["crowdstrike-falcon", SecurityToolLogic.DefenderAntivirusId], Ids(d));
        Assert.False(d.Complete);
    }

    [Fact]
    public void RegistryFailure_IsUndetermined_NeverAbsent()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(),
            registry: Keys(failed: [CrowdStrikeService])));

        Assert.Empty(d.Tools);
        Assert.False(d.Complete);
        Assert.Contains(SecurityToolLogic.ReasonRegistryFailed, d.Undetermined);
    }

    [Fact]
    public void RegistryReaderThatThrows_IsUndetermined()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(),
            registry: _ => throw new System.Security.SecurityException("denied")));

        Assert.False(d.Complete);
        Assert.Contains(SecurityToolLogic.ReasonRegistryFailed, d.Undetermined);
    }

    [Fact]
    public void OneFailedPath_DoesNotHideASecondPathThatProvesTheTool()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(),
            registry: Keys(present: [@"SOFTWARE\CrowdStrike\Windows Sensor"], failed: [CrowdStrikeService])));

        Assert.Equal(["crowdstrike-falcon"], Ids(d));
        Assert.True(d.Complete);
    }

    [Fact]
    public void EverySourceReadCleanly_WithNothingFound_IsACompleteEmptyList()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation, () => SecurityCenterRead.Of()));

        Assert.Empty(d.Tools);
        Assert.True(d.Complete);
        Assert.Null(d.HealthReason);
    }

    // ── Security Center as the primary source ────────────────────────────────

    [Fact]
    public void UnlistedVendorRegisteredInSecurityCenter_IsReportedWithASlugId()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av("ESET Security", ThirdPartyOn))));

        var tool = Assert.Single(d.Tools);
        Assert.Equal("eset-security", tool.Id);
        Assert.Equal("ESET Security", tool.Name);
        Assert.True(d.Complete);
    }

    [Fact]
    public void Defender_And_Bitdefender_MapToTheirExistingIdsAndNames()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(
                Av("Windows Defender", DefenderOff),
                Av("Bitdefender Endpoint Security Tools Antimalware", ThirdPartyOn))));

        Assert.Equal(["bitdefender", SecurityToolLogic.DefenderAntivirusId], Ids(d));
        Assert.Equal("Bitdefender", d.Tools[0].Name);
        Assert.Equal("Microsoft Defender Antivirus", d.Tools[1].Name);
    }

    [Theory]
    [InlineData("Windows Defender")]
    [InlineData("Microsoft Defender Antivirus")]
    [InlineData("  windows defender ")]
    public void DefenderAntivirus_IsNeverReportedAsDefenderForEndpoint(string displayName)
    {
        // Built-in Defender Antivirus is on every Windows client. Reporting it as the MDE
        // EDR product would mark every device EDR-covered on the platform's name match.
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av(displayName, DefenderOn))));

        Assert.Equal([SecurityToolLogic.DefenderAntivirusId], Ids(d));
        Assert.DoesNotContain("defender-for-endpoint", Ids(d));
    }

    [Theory]
    [InlineData("CrowdStrike Falcon Sensor", "crowdstrike-falcon")]
    [InlineData("Sentinel Agent", "sentinelone")]
    [InlineData("Sophos Anti-Virus", "sophos-endpoint")]
    [InlineData("Malwarebytes", "malwarebytes")]
    [InlineData("VMware Carbon Black Cloud", "carbon-black")]
    public void KnownVendorDisplayNames_MapToExistingIds(string displayName, string id)
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av(displayName, ThirdPartyOn))));

        Assert.Equal([id], Ids(d));
    }

    [Fact]
    public void AVendorPrefixMustEndAtAWordBoundary()
    {
        // "Bitdefenderish" is not Bitdefender; it gets its own slug.
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av("Bitdefenderish Guard", ThirdPartyOn))));

        Assert.Equal(["bitdefenderish-guard"], Ids(d));
    }

    [Fact]
    public void SameProductFromSecurityCenterAndRegistry_IsReportedOnce()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av("Bitdefender Antivirus Plus", ThirdPartyOn)),
            registry: Keys(present: [BitdefenderKey])));

        var tool = Assert.Single(d.Tools);
        Assert.Equal("bitdefender", tool.Id);
        Assert.Equal("Bitdefender", tool.Name);
    }

    [Fact]
    public void RegistryStillAddsToolsSecurityCenterDoesNotList()
    {
        // An EDR that does not register as AV (MDE alongside Defender) is only visible in the registry.
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av("Windows Defender", DefenderOn)),
            registry: Keys(present: [@"SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"]),
            onboarding: () => RegistryRead.Present(1)));

        Assert.Equal(["defender-for-endpoint", SecurityToolLogic.DefenderAntivirusId], Ids(d));
    }

    [Theory]
    [InlineData(DeviceClassValue.Workstation)]
    [InlineData(DeviceClassValue.Server)]
    public void MdeRegistryKeysWithoutOnboardingEvidence_DoNotProveDefenderForEndpoint(string deviceClass)
    {
        // PAT-2270: HOMESERVER has both keys, but no OnboardingState value and a stopped
        // Sense service. Key existence alone is not evidence of MDE onboarding. The
        // current key-only reader cannot supply that positive evidence at all.
        var d = SecurityToolLogic.Detect(Sources(deviceClass,
            () => SecurityCenterRead.Of(Av("Windows Defender", DefenderOn)),
            defender: () => SecurityToolProbe.Present,
            registry: Keys(present:
            [
                @"SOFTWARE\Microsoft\Windows Advanced Threat Protection",
                @"SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status",
            ])));

        Assert.DoesNotContain("defender-for-endpoint", Ids(d));
        Assert.Equal([SecurityToolLogic.DefenderAntivirusId], Ids(d));
        Assert.True(d.Complete);
    }

    [Theory]
    [InlineData(DeviceClassValue.Workstation)]
    [InlineData(DeviceClassValue.Server)]
    [InlineData(DeviceClassValue.DomainController)]
    public void MdeOnboardingDwordOne_ProvesMdeWithoutRegistryKeyProbes(string deviceClass)
    {
        var d = SecurityToolLogic.Detect(Sources(deviceClass, () => SecurityCenterRead.Of(),
            onboarding: () => RegistryRead.Present(1)));

        var tool = Assert.Single(d.Tools);
        Assert.Equal("defender-for-endpoint", tool.Id);
        Assert.Equal("Microsoft Defender for Endpoint", tool.Name);
        Assert.True(d.Complete);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(-1)]
    public void MdeNonOnboardedDword_IsACompleteAbsence(int value)
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation, () => SecurityCenterRead.Of(),
            onboarding: () => RegistryRead.Present(value)));

        Assert.Empty(d.Tools);
        Assert.True(d.Complete);
    }

    [Fact]
    public void MdeMissingKeyOrValue_IsACompleteAbsence()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation, () => SecurityCenterRead.Of(),
            onboarding: () => RegistryRead.Absent));

        Assert.Empty(d.Tools);
        Assert.True(d.Complete);
    }

    public static TheoryData<object> UnusableMdeValues => new()
    {
        "1", 1L, 1u, true, new byte[] { 1, 0, 0, 0 }, new string[] { "1" },
    };

    [Theory]
    [MemberData(nameof(UnusableMdeValues))]
    public void MdeWrongRegistryType_IsUndetermined(object value)
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation, () => SecurityCenterRead.Of(),
            onboarding: () => RegistryRead.Present(value)));

        Assert.Empty(d.Tools);
        Assert.False(d.Complete);
        Assert.Equal([SecurityToolLogic.ReasonMdeOnboardingFailed], d.Undetermined);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MdeFailedRead_IsUndetermined_EvenWithRegistryKeysPresent(bool throws)
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Server, () => SecurityCenterRead.Missing,
            defender: () => SecurityToolProbe.Present,
            registry: Keys(present: [@"SOFTWARE\Microsoft\Windows Advanced Threat Protection"]),
            onboarding: () => throws ? throw new UnauthorizedAccessException("denied") : RegistryRead.Failed));

        Assert.Equal([SecurityToolLogic.DefenderAntivirusId], Ids(d));
        Assert.False(d.Complete);
        Assert.Equal([SecurityToolLogic.ReasonMdeOnboardingFailed], d.Undetermined);
    }

    [Fact]
    public void SecurityCenterWorks_DefenderStatusIsNotAsked()
    {
        var asked = false;
        SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(),
            defender: () => { asked = true; return SecurityToolProbe.Present; }));

        Assert.False(asked);
    }

    // ── productState decoding ────────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("not a number")]
    [InlineData(-1)]
    [InlineData(0x1000000)]
    public void AnUnusableProductState_IsNotReported_AndMarksTheListIncomplete(object? state)
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av("Some AV", state))));

        Assert.Empty(d.Tools);
        Assert.False(d.Complete);
        Assert.Contains(SecurityToolLogic.ReasonSecurityCenterEntryUnusable, d.Undetermined);
    }

    [Fact]
    public void AProductStateWithoutTheAntivirusProviderBit_IsNotReported_AndNotComplete()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av("Some AV", 0x021000u))));

        Assert.Empty(d.Tools);
        Assert.False(d.Complete);
    }

    [Theory]
    [InlineData(0x061100u)]
    [InlineData(0x060100u)]
    [InlineData(0x041000u)]
    [InlineData(0x042000u)]
    public void AnyRegisteredState_OnOffSnoozedOrExpired_IsReported(uint state)
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av("ESET Security", state))));

        Assert.Equal(["eset-security"], Ids(d));
    }

    [Theory]
    [InlineData(0x041000)]        // int
    [InlineData(0x041000L)]       // long
    [InlineData("266240")]        // string decimal
    public void ProductState_AcceptsIntegralShapes(object state)
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av("ESET Security", state))));

        Assert.Single(d.Tools);
    }

    // ── display names and slugs ──────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("Evil\nCrowdStrike Falcon")]
    public void AnUnusableDisplayName_IsNotReported_AndMarksTheListIncomplete(string? name)
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av(name, ThirdPartyOn))));

        Assert.Empty(d.Tools);
        Assert.Contains(SecurityToolLogic.ReasonSecurityCenterEntryUnusable, d.Undetermined);
    }

    [Fact]
    public void ALongDisplayName_IsBounded_AndTheSlugIsBounded()
    {
        var name = "Vendor " + new string('x', 400);
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av(name, ThirdPartyOn))));

        var tool = Assert.Single(d.Tools);
        Assert.True(tool.Name.Length <= SecurityToolLogic.MaxNameLength);
        Assert.True(tool.Id.Length <= SecurityToolLogic.MaxIdLength);
    }

    [Fact]
    public void ANameWithNoAsciiLettersOrDigits_GetsAStableHashedId()
    {
        var a = SecurityToolLogic.SlugId("火绒安全");
        var b = SecurityToolLogic.SlugId("火绒安全");
        var c = SecurityToolLogic.SlugId("卡巴斯基");

        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
        Assert.StartsWith("av-", a);
        Assert.Matches("^[a-z0-9-]+$", a);
    }

    [Fact]
    public void ASlugThatWouldImpersonateAKnownId_IsNotMergedIntoIt()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av("defender-for-endpoint", ThirdPartyOn))));

        var tool = Assert.Single(d.Tools);
        Assert.NotEqual("defender-for-endpoint", tool.Id);
    }

    [Fact]
    public void OutputOrder_IsDeterministic()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av("Zeta AV", ThirdPartyOn), Av("Alpha AV", ThirdPartyOn),
                Av("Windows Defender", DefenderOff)),
            registry: Keys(present: [CrowdStrikeService])));

        Assert.Equal(["crowdstrike-falcon", SecurityToolLogic.DefenderAntivirusId, "alpha-av", "zeta-av"], Ids(d));
    }

    // ── Windows Server: SecurityCenter2 does not exist ───────────────────────

    [Theory]
    [InlineData(DeviceClassValue.Server)]
    [InlineData(DeviceClassValue.DomainController)]
    public void Server_DoesNotAskSecurityCenter_AndIsCompleteFromItsFallbacks(string deviceClass)
    {
        var askedSecurityCenter = false;
        var d = SecurityToolLogic.Detect(Sources(deviceClass,
            () => { askedSecurityCenter = true; return SecurityCenterRead.Missing; },
            defender: () => SecurityToolProbe.Present,
            registry: Keys(present: [CrowdStrikeService])));

        Assert.False(askedSecurityCenter);
        Assert.Equal(["crowdstrike-falcon", SecurityToolLogic.DefenderAntivirusId], Ids(d));
        Assert.True(d.Complete);
    }

    [Fact]
    public void Server_WithNothingInstalled_IsACompleteEmptyList_NotAMissingSecurityCenterFault()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Server, () => SecurityCenterRead.Missing));

        Assert.Empty(d.Tools);
        Assert.True(d.Complete);
    }

    [Fact]
    public void Server_DefenderStatusFailure_IsUndetermined()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Server,
            () => SecurityCenterRead.Missing,
            defender: () => SecurityToolProbe.Failed));

        Assert.False(d.Complete);
        Assert.Contains(SecurityToolLogic.ReasonDefenderStatusFailed, d.Undetermined);
    }

    [Theory]
    [InlineData(DeviceClassValue.Workstation)]
    [InlineData(DeviceClassValue.Unknown)]
    [InlineData(null)]
    public void MissingSecurityCenter_OffServer_FallsBack_ButIsNotComplete(string? deviceClass)
    {
        // A workstation without SecurityCenter2 is a broken WMI repository, and an unknown
        // class cannot prove it is a server, so neither may claim a complete list.
        var d = SecurityToolLogic.Detect(Sources(deviceClass,
            () => SecurityCenterRead.Missing,
            defender: () => SecurityToolProbe.Present));

        Assert.Equal([SecurityToolLogic.DefenderAntivirusId], Ids(d));
        Assert.False(d.Complete);
        Assert.Contains(SecurityToolLogic.ReasonSecurityCenterMissing, d.Undetermined);
    }

    // ── wire shape ───────────────────────────────────────────────────────────

    [Fact]
    public void ToolsAreThePlainIdAndNameContractRecord()
    {
        var d = SecurityToolLogic.Detect(Sources(DeviceClassValue.Workstation,
            () => SecurityCenterRead.Of(Av("ESET Security", ThirdPartyOn))));

        Assert.IsType<InventorySecurityTool>(d.Tools[0]);
    }
}
