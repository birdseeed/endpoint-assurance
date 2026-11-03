using Patched.Shared.Compliance;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1767: every HKLM-backed Windows compliance signal keeps present, absent and
/// failed apart. Absent is "NotConfigured"; a failed read is "Unknown" and never
/// "NotConfigured"; a present value keeps the signal's existing mapping.
/// </summary>
public class RegistrySignalMapperTests
{
    private static readonly RegistryRead Absent = RegistryRead.Absent;
    private static readonly RegistryRead Failed = RegistryRead.Failed;
    private static RegistryRead P(object v) => RegistryRead.Present(v);

    // ── RegistryRead.Capture ────────────────────────────────────────────────

    [Fact]
    public void Capture_Value_IsPresent()
    {
        var r = RegistryRead.Capture(() => 1);
        Assert.Equal(RegistryReadState.Present, r.State);
        Assert.True(r.TryGetInt(out var v));
        Assert.Equal(1, v);
    }

    [Fact]
    public void Capture_Null_IsAbsent()
    {
        Assert.Equal(RegistryReadState.Absent, RegistryRead.Capture(() => null).State);
    }

    [Theory]
    [InlineData(typeof(System.Security.SecurityException))]
    [InlineData(typeof(UnauthorizedAccessException))]
    [InlineData(typeof(IOException))]
    [InlineData(typeof(ObjectDisposedException))]
    public void Capture_Throw_IsFailed_AndReportsTheException(Type exceptionType)
    {
        Exception? seen = null;
        var thrown = exceptionType == typeof(ObjectDisposedException)
            ? new ObjectDisposedException("key")
            : (Exception)Activator.CreateInstance(exceptionType)!;

        var r = RegistryRead.Capture(() => throw thrown, ex => seen = ex);

        Assert.Equal(RegistryReadState.Failed, r.State);
        Assert.Same(thrown, seen);
        Assert.False(r.TryGetInt(out _));
    }

    [Fact]
    public void TryGetInt_NonDword_IsFalse()
    {
        Assert.False(P("1").TryGetInt(out _));
        Assert.False(Absent.TryGetInt(out _));
    }

    // ── single-value signals: present, absent, failed ───────────────────────

    public static TheoryData<string, object, string> SingleValuePresent => new()
    {
        { nameof(RegistrySignalMapper.Firewall), 1, "enabled" },
        { nameof(RegistrySignalMapper.Firewall), 0, "disabled" },
        { nameof(RegistrySignalMapper.Uac), 1, "Yes" },
        { nameof(RegistrySignalMapper.Uac), 0, "No" },
        { nameof(RegistrySignalMapper.RemoteDesktop), 0, "enabled" },
        { nameof(RegistrySignalMapper.RemoteDesktop), 1, "disabled" },
        { nameof(RegistrySignalMapper.SmbSigning), 1, "Yes" },
        { nameof(RegistrySignalMapper.SmbSigning), 0, "No" },
        { nameof(RegistrySignalMapper.Fips), 1, "Yes" },
        { nameof(RegistrySignalMapper.Fips), 0, "No" },
        { nameof(RegistrySignalMapper.Fips), 2, "Unknown" },
        { nameof(RegistrySignalMapper.SecureBoot), 1, "Yes" },
        { nameof(RegistrySignalMapper.SecureBoot), 0, "No" },
        { nameof(RegistrySignalMapper.SecureBoot), 2, "Unknown" },
        { nameof(RegistrySignalMapper.TlsDisabled), 0, "Yes" },
        { nameof(RegistrySignalMapper.TlsDisabled), 1, "No" },
        { nameof(RegistrySignalMapper.DefenderRealtime), 0, "enabled" },
        { nameof(RegistrySignalMapper.DefenderRealtime), 1, "disabled" },
    };

    public static TheoryData<string> SingleValueSignals => new()
    {
        nameof(RegistrySignalMapper.Firewall),
        nameof(RegistrySignalMapper.Uac),
        nameof(RegistrySignalMapper.RemoteDesktop),
        nameof(RegistrySignalMapper.SmbSigning),
        nameof(RegistrySignalMapper.Fips),
        nameof(RegistrySignalMapper.SecureBoot),
        nameof(RegistrySignalMapper.MandatoryAslr),
        nameof(RegistrySignalMapper.TlsDisabled),
        nameof(RegistrySignalMapper.DefenderRealtime),
    };

    private static string MapSingle(string signal, RegistryRead read) => signal switch
    {
        nameof(RegistrySignalMapper.Firewall) => RegistrySignalMapper.Firewall(read),
        nameof(RegistrySignalMapper.Uac) => RegistrySignalMapper.Uac(read),
        nameof(RegistrySignalMapper.RemoteDesktop) => RegistrySignalMapper.RemoteDesktop(read),
        nameof(RegistrySignalMapper.SmbSigning) => RegistrySignalMapper.SmbSigning(read),
        nameof(RegistrySignalMapper.Fips) => RegistrySignalMapper.Fips(read),
        nameof(RegistrySignalMapper.SecureBoot) => RegistrySignalMapper.SecureBoot(read),
        nameof(RegistrySignalMapper.MandatoryAslr) => RegistrySignalMapper.MandatoryAslr(read),
        nameof(RegistrySignalMapper.TlsDisabled) => RegistrySignalMapper.TlsDisabled(read),
        nameof(RegistrySignalMapper.DefenderRealtime) => RegistrySignalMapper.DefenderRealtime(read),
        _ => throw new ArgumentOutOfRangeException(nameof(signal)),
    };

    [Theory]
    [MemberData(nameof(SingleValuePresent))]
    public void SingleValue_Present_KeepsExistingMapping(string signal, object value, string expected)
    {
        Assert.Equal(expected, MapSingle(signal, P(value)));
    }

    [Theory]
    [MemberData(nameof(SingleValueSignals))]
    public void SingleValue_Absent_IsNotConfigured(string signal)
    {
        Assert.Equal("NotConfigured", MapSingle(signal, Absent));
    }

    [Theory]
    [MemberData(nameof(SingleValueSignals))]
    public void SingleValue_Failed_IsUnknown(string signal)
    {
        Assert.Equal("Unknown", MapSingle(signal, Failed));
    }

    [Theory]
    [MemberData(nameof(SingleValueSignals))]
    public void SingleValue_NonDword_IsUnknown(string signal)
    {
        Assert.Equal("Unknown", MapSingle(signal, P("1")));
    }

    // ── mandatory ASLR (kernel MitigationOptions, PAT-1770) ─────────────────

    /// <summary>A 24-byte MitigationOptions value with byte 1 set to <paramref name="byte1"/>.</summary>
    private static byte[] Mitigations(byte byte1, byte fill = 0x00)
    {
        var bytes = Enumerable.Repeat(fill, 24).ToArray();
        bytes[1] = byte1;
        return bytes;
    }

    [Fact]
    public void MandatoryAslr_ValueOrKeyAbsent_IsNotConfigured()
    {
        // The collector's reader returns Absent for a missing key and for a missing value.
        Assert.Equal("NotConfigured", RegistrySignalMapper.MandatoryAslr(Absent));
        Assert.Equal("NotConfigured", RegistrySignalMapper.MandatoryAslr(RegistryRead.Capture(() => null)));
    }

    [Theory]
    [InlineData(0x00, "NotConfigured")]
    [InlineData(0x01, "Yes")]
    [InlineData(0x02, "No")]
    [InlineData(0x03, "Unknown")]
    public void MandatoryAslr_ForceRelocateImagesField(int byte1, string expected)
    {
        Assert.Equal(expected, RegistrySignalMapper.MandatoryAslr(P(Mitigations((byte)byte1))));
    }

    [Theory]
    [InlineData(0xFD, 0xFF, "Yes")]           // byte 1 low bits 01, every other bit set
    [InlineData(0xFE, 0xFF, "No")]            // low bits 10
    [InlineData(0xFC, 0xFF, "NotConfigured")] // low bits 00
    [InlineData(0xFF, 0xFF, "Unknown")]       // low bits 11
    [InlineData(0x11, 0x22, "Yes")]
    [InlineData(0x02, 0x01, "No")]            // byte 0 bits must not leak into the field
    public void MandatoryAslr_IgnoresUnrelatedBitsAndBytes(int byte1, int fill, string expected)
    {
        Assert.Equal(expected, RegistrySignalMapper.MandatoryAslr(P(Mitigations((byte)byte1, (byte)fill))));
    }

    [Fact]
    public void MandatoryAslr_MinimumTwoBytes_IsRead()
    {
        Assert.Equal("Yes", RegistrySignalMapper.MandatoryAslr(P(new byte[] { 0x00, 0x01 })));
    }

    [Fact]
    public void MandatoryAslr_ShortArray_IsUnknown()
    {
        Assert.Equal("Unknown", RegistrySignalMapper.MandatoryAslr(P(Array.Empty<byte>())));
        Assert.Equal("Unknown", RegistrySignalMapper.MandatoryAslr(P(new byte[] { 0x01 })));
    }

    [Fact]
    public void MandatoryAslr_WrongType_IsUnknown()
    {
        // A DWORD is what the old MoveImages read saw; it is not evidence here.
        Assert.Equal("Unknown", RegistrySignalMapper.MandatoryAslr(P(1)));
        Assert.Equal("Unknown", RegistrySignalMapper.MandatoryAslr(P(0x100)));
        Assert.Equal("Unknown", RegistrySignalMapper.MandatoryAslr(P("0001")));
        Assert.Equal("Unknown", RegistrySignalMapper.MandatoryAslr(P(new[] { "00", "01" })));
    }

    [Fact]
    public void MandatoryAslr_ReadFailed_IsUnknown()
    {
        Assert.Equal("Unknown", RegistrySignalMapper.MandatoryAslr(Failed));
        Assert.Equal("Unknown", RegistrySignalMapper.MandatoryAslr(
            RegistryRead.Capture(() => throw new System.Security.SecurityException())));
    }

    // ── TLS 1.2 enabled (Enabled + DisabledByDefault) ───────────────────────

    [Fact]
    public void TlsEnabled_Present()
    {
        Assert.Equal("Yes", RegistrySignalMapper.TlsEnabled(P(1), P(0)));
        Assert.Equal("Yes", RegistrySignalMapper.TlsEnabled(P(1), Absent));
        Assert.Equal("Yes", RegistrySignalMapper.TlsEnabled(Absent, P(0)));
        Assert.Equal("No", RegistrySignalMapper.TlsEnabled(P(0), Absent));
        Assert.Equal("No", RegistrySignalMapper.TlsEnabled(Absent, P(1)));
        Assert.Equal("No", RegistrySignalMapper.TlsEnabled(P(1), P(1)));
    }

    [Fact]
    public void TlsEnabled_BothAbsent_IsNotConfigured()
    {
        Assert.Equal("NotConfigured", RegistrySignalMapper.TlsEnabled(Absent, Absent));
    }

    [Fact]
    public void TlsEnabled_EitherFailed_IsUnknown()
    {
        Assert.Equal("Unknown", RegistrySignalMapper.TlsEnabled(Failed, Absent));
        Assert.Equal("Unknown", RegistrySignalMapper.TlsEnabled(Absent, Failed));
        Assert.Equal("Unknown", RegistrySignalMapper.TlsEnabled(Failed, Failed));
        // A failed read wins even over a value that alone would say No.
        Assert.Equal("Unknown", RegistrySignalMapper.TlsEnabled(P(0), Failed));
        Assert.Equal("Unknown", RegistrySignalMapper.TlsEnabled(P("0"), Absent));
    }

    // ── auto_updates_enabled (policy NoAutoUpdate, policy AUOptions, local AUOptions) ──
    // PAT-1771. AUOptions levels per Microsoft Learn "Manage additional Windows Update
    // settings": 1 disabled, 2 notify before download, 3 auto download and notify
    // install, 4 auto download and scheduled install, 5 local admin chooses, 7 auto
    // download, notify install and restart (Server 2016+).

    private static readonly object NotAnInt = "4";

    /// <summary>A read that fails the test if the mapper consults it.</summary>
    private static RegistryRead MustNotRead() => throw new InvalidOperationException("source must not be read");

    private static string Au(RegistryRead noAuto, RegistryRead policy, RegistryRead local) =>
        RegistrySignalMapper.AutoUpdates(noAuto, policy, local);

    [Fact]
    public void AutoUpdates_NoAutoUpdate1_IsNo_AndReadsNothingElse()
    {
        Assert.Equal("No", RegistrySignalMapper.AutoUpdates(() => P(1), MustNotRead, MustNotRead));
    }

    [Fact]
    public void AutoUpdates_NoAutoUpdate0_AnAuOptionsLevelStillDecides()
    {
        Assert.Equal("Yes", Au(P(0), P(4), Absent));
        Assert.Equal("No", Au(P(0), P(2), Absent));
        Assert.Equal("Yes", Au(P(0), Absent, P(3)));
        Assert.Equal("No", Au(P(0), Absent, P(2)));
        Assert.Equal("No", Au(P(0), P(5), P(1)));
    }

    [Fact]
    public void AutoUpdates_NoAutoUpdate0_WithNoAuOptionsLevel_IsYes()
    {
        // Group Policy "Configure Automatic Updates: Enabled" with no level set.
        Assert.Equal("Yes", Au(P(0), Absent, Absent));
        Assert.Equal("Yes", Au(P(0), P(0), P(0)));
        Assert.Equal("Yes", Au(P(0), P(5), Absent));
    }

    [Fact]
    public void AutoUpdates_NoAutoUpdate0_FailedOrUnusableAuOptions_StaysUnknown()
    {
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => P(0), () => Failed, MustNotRead));
        Assert.Equal("Unknown", Au(P(0), Absent, Failed));
        Assert.Equal("Unknown", Au(P(0), P(5), Failed));
        Assert.Equal("Unknown", Au(P(0), P(NotAnInt), Absent));
        Assert.Equal("Unknown", Au(P(0), Absent, P(5)));
    }

    [Fact]
    public void AutoUpdates_NoAutoUpdateFailedOrUnusable_IsUnknown_AndReadsNothingElse()
    {
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => Failed, MustNotRead, MustNotRead));
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => P(2), MustNotRead, MustNotRead));
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => P(-1), MustNotRead, MustNotRead));
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => P("1"), MustNotRead, MustNotRead));
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => P(new byte[] { 1 }), MustNotRead, MustNotRead));
    }

    [Theory]
    [InlineData(1, "No")]   // disabled
    [InlineData(2, "No")]   // notify before download
    [InlineData(3, "Yes")]  // auto download, notify before install
    [InlineData(4, "Yes")]  // auto download, scheduled install
    [InlineData(7, "Yes")]  // auto download, notify install and restart (Server 2016+)
    [InlineData(6, "Unknown")]
    [InlineData(8, "Unknown")]
    [InlineData(-1, "Unknown")]
    public void AutoUpdates_PolicyAuOptions_Decides_AndDoesNotReadLocal(int level, string expected)
    {
        Assert.Equal(expected, RegistrySignalMapper.AutoUpdates(() => Absent, () => P(level), MustNotRead));
        Assert.Equal(expected, RegistrySignalMapper.AutoUpdates(() => P(0), () => P(level), MustNotRead));
    }

    [Fact]
    public void AutoUpdates_PolicyAuOptions_WinsOverLocal()
    {
        Assert.Equal("No", Au(Absent, P(2), P(4)));
        Assert.Equal("Yes", Au(Absent, P(4), P(1)));
        Assert.Equal("No", Au(Absent, P(1), P(3)));
    }

    [Fact]
    public void AutoUpdates_PolicyAuOptionsFailedOrUnusable_IsUnknown_AndDoesNotReadLocal()
    {
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => Absent, () => Failed, MustNotRead));
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => Absent, () => P(NotAnInt), MustNotRead));
    }

    [Fact]
    public void AutoUpdates_PolicyAuOptionsAbsentOr0_ContinuesToLocal()
    {
        foreach (var policy in new[] { Absent, P(0) })
        {
            Assert.Equal("Yes", Au(Absent, policy, P(4)));
            Assert.Equal("No", Au(Absent, policy, P(2)));
            Assert.Equal("NotConfigured", Au(Absent, policy, Absent));
            Assert.Equal("Unknown", Au(Absent, policy, Failed));
        }
    }

    [Theory]
    [InlineData(1, "No")]
    [InlineData(2, "No")]
    [InlineData(3, "Yes")]
    [InlineData(4, "Yes")]
    [InlineData(7, "Yes")]
    [InlineData(0, "NotConfigured")]
    [InlineData(5, "Unknown")]   // local admin chooses is a policy choice, not a local level
    [InlineData(6, "Unknown")]
    [InlineData(-1, "Unknown")]
    public void AutoUpdates_PolicyAuOptions5_ResolvesThroughLocalLevel(int local, string expected)
    {
        Assert.Equal(expected, Au(Absent, P(5), P(local)));
    }

    [Fact]
    public void AutoUpdates_PolicyAuOptions5_LocalAbsentFailedOrUnusable()
    {
        Assert.Equal("NotConfigured", Au(Absent, P(5), Absent));
        Assert.Equal("Unknown", Au(Absent, P(5), Failed));
        Assert.Equal("Unknown", Au(Absent, P(5), P(NotAnInt)));
    }

    [Theory]
    [InlineData(1, "No")]
    [InlineData(2, "No")]
    [InlineData(3, "Yes")]
    [InlineData(4, "Yes")]
    [InlineData(7, "Yes")]
    [InlineData(0, "NotConfigured")]
    [InlineData(5, "Unknown")]   // was "Yes" under the PAT-1767 >= 3 mapping
    [InlineData(6, "Unknown")]   // was "Yes" under the PAT-1767 >= 3 mapping
    [InlineData(-1, "Unknown")]
    public void AutoUpdates_LocalAuOptions_WithNoPolicy(int level, string expected)
    {
        Assert.Equal(expected, Au(Absent, Absent, P(level)));
    }

    [Fact]
    public void AutoUpdates_LocalAuOptions_AbsentFailedOrUnusable()
    {
        Assert.Equal("NotConfigured", Au(Absent, Absent, Absent));
        Assert.Equal("Unknown", Au(Absent, Absent, Failed));
        Assert.Equal("Unknown", Au(Absent, Absent, P(NotAnInt)));
    }

    // ── auto_updates_enabled with the MDM source (PAT-1780) ──
    // Update/AllowAutoUpdate levels per Microsoft Learn "Update Policy CSP": 0 notify
    // before download, 1 auto install and notify to schedule restart, 2 auto install and
    // restart (default), 3 auto install and restart at a set time, 4 auto install and
    // restart without end-user control, 5 turn off automatic updates.

    private static string Au4(RegistryRead noAuto, RegistryRead policy, RegistryRead mdm, RegistryRead local) =>
        RegistrySignalMapper.AutoUpdates(noAuto, policy, mdm, local);

    [Theory]
    [InlineData(0, "No")]   // notify before download
    [InlineData(1, "Yes")]  // auto install, user schedules the restart
    [InlineData(2, "Yes")]  // auto install and restart
    [InlineData(3, "Yes")]  // auto install and restart at a specified time
    [InlineData(4, "Yes")]  // auto install and restart without end-user control
    [InlineData(5, "No")]   // automatic updates turned off
    [InlineData(6, "Unknown")]
    [InlineData(7, "Unknown")]
    [InlineData(-1, "Unknown")]
    [InlineData(int.MaxValue, "Unknown")]
    public void AutoUpdates_MdmAllowAutoUpdate_EveryLevel_WithNoGroupPolicy_AndDoesNotReadLocal(int level, string expected)
    {
        Assert.Equal(expected, RegistrySignalMapper.AutoUpdates(() => Absent, () => Absent, () => P(level), MustNotRead));
        // AUOptions 0 is aunlNotConfigured, so Group Policy still configures nothing.
        Assert.Equal(expected, RegistrySignalMapper.AutoUpdates(() => Absent, () => P(0), () => P(level), MustNotRead));
    }

    [Fact]
    public void AutoUpdates_MdmFailedOrWrongType_IsUnknown_AndDoesNotFallThroughToLocal()
    {
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => Absent, () => Absent, () => Failed, MustNotRead));
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => Absent, () => Absent, () => P("2"), MustNotRead));
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => Absent, () => Absent, () => P(2L), MustNotRead));
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => Absent, () => Absent, () => P(new byte[] { 2, 0, 0, 0 }), MustNotRead));
        // Even a local level that would say Yes is never consulted.
        Assert.Equal("Unknown", Au4(Absent, Absent, Failed, P(4)));
    }

    [Fact]
    public void AutoUpdates_MdmAbsent_ContinuesToLocal()
    {
        Assert.Equal("Yes", Au4(Absent, Absent, Absent, P(4)));
        Assert.Equal("No", Au4(Absent, Absent, Absent, P(2)));
        Assert.Equal("NotConfigured", Au4(Absent, Absent, Absent, Absent));
        Assert.Equal("Unknown", Au4(Absent, Absent, Absent, Failed));
        Assert.Equal("Unknown", Au4(Absent, Absent, Absent, P(5)));
    }

    [Fact]
    public void AutoUpdates_Mdm_WinsOverLocal()
    {
        Assert.Equal("No", Au4(Absent, Absent, P(0), P(4)));
        Assert.Equal("No", Au4(Absent, Absent, P(5), P(3)));
        Assert.Equal("Yes", Au4(Absent, Absent, P(2), P(1)));
    }

    [Fact]
    public void AutoUpdates_GroupPolicyNotConfigured_FallsToMdm()
    {
        foreach (var policy in new[] { Absent, P(0) })
        {
            Assert.Equal("Yes", RegistrySignalMapper.AutoUpdates(() => Absent, () => policy, () => P(4), MustNotRead));
            Assert.Equal("No", RegistrySignalMapper.AutoUpdates(() => Absent, () => policy, () => P(0), MustNotRead));
        }
    }

    [Fact]
    public void AutoUpdates_GroupPolicyNoAutoUpdate1_WinsOverMdm_AndMdmIsNotRead()
    {
        Assert.Equal("No", RegistrySignalMapper.AutoUpdates(() => P(1), MustNotRead, MustNotRead, MustNotRead));
        Assert.Equal("No", Au4(P(1), Absent, P(2), P(4)));
    }

    [Theory]
    [InlineData(2, "No")]
    [InlineData(1, "No")]
    [InlineData(4, "Yes")]
    [InlineData(3, "Yes")]
    [InlineData(7, "Yes")]
    public void AutoUpdates_GroupPolicyAuOptionsLevel_WinsOverConflictingMdm_AndMdmIsNotRead(int gpLevel, string expected)
    {
        Assert.Equal(expected, RegistrySignalMapper.AutoUpdates(() => Absent, () => P(gpLevel), MustNotRead, MustNotRead));
        Assert.Equal(expected, RegistrySignalMapper.AutoUpdates(() => P(0), () => P(gpLevel), MustNotRead, MustNotRead));
        // The eager form with a conflicting MDM value gives the same Group Policy answer.
        Assert.Equal(expected, Au4(Absent, P(gpLevel), P(expected == "Yes" ? 5 : 2), Absent));
    }

    [Fact]
    public void AutoUpdates_GroupPolicyExplicitEnable_WinsOverMdm_AndMdmIsNotRead()
    {
        // NoAutoUpdate=0 with no level: Group Policy configured the area, so an MDM
        // "notify before download" does not override it (PAT-1771 outcome kept).
        Assert.Equal("Yes", RegistrySignalMapper.AutoUpdates(() => P(0), () => Absent, MustNotRead, () => Absent));
        Assert.Equal("No", RegistrySignalMapper.AutoUpdates(() => P(0), () => Absent, MustNotRead, () => P(2)));
        Assert.Equal("Yes", Au4(P(0), Absent, P(0), Absent));
        Assert.Equal("Yes", Au4(P(0), Absent, P(5), Absent));
    }

    [Fact]
    public void AutoUpdates_GroupPolicyAuOptions5_ResolvesThroughLocal_AndMdmIsNotRead()
    {
        Assert.Equal("Yes", RegistrySignalMapper.AutoUpdates(() => Absent, () => P(5), MustNotRead, () => P(4)));
        Assert.Equal("NotConfigured", RegistrySignalMapper.AutoUpdates(() => Absent, () => P(5), MustNotRead, () => Absent));
        Assert.Equal("No", Au4(Absent, P(5), P(4), P(2)));
    }

    [Fact]
    public void AutoUpdates_GroupPolicyFailedOrUnusable_IsUnknown_AndMdmIsNotRead()
    {
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => Failed, MustNotRead, MustNotRead, MustNotRead));
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => P(2), MustNotRead, MustNotRead, MustNotRead));
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => Absent, () => Failed, MustNotRead, MustNotRead));
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => Absent, () => P(NotAnInt), MustNotRead, MustNotRead));
        Assert.Equal("Unknown", RegistrySignalMapper.AutoUpdates(() => Absent, () => P(6), MustNotRead, MustNotRead));
    }

    // ── laps_enrolled ────────────────────────────────────────────────────────

    [Fact]
    public void Laps_Present()
    {
        Assert.Equal("Yes", RegistrySignalMapper.Laps(P(1), Absent));
        Assert.Equal("Yes", RegistrySignalMapper.Laps(P(2), Failed));
        Assert.Equal("Yes", RegistrySignalMapper.Laps(Absent, P(1)));
        Assert.Equal("Yes", RegistrySignalMapper.Laps(Failed, P(1)));
        Assert.Equal("No", RegistrySignalMapper.Laps(P(0), P(0)));
    }

    [Fact]
    public void Laps_BothAbsent_IsNotConfigured()
    {
        // PAT-1772: both reads succeeded and neither LAPS configuration exists.
        Assert.Equal("NotConfigured", RegistrySignalMapper.Laps(Absent, Absent));
    }

    [Fact]
    public void Laps_PresentButNotEnabled_IsNo_NotNotConfigured()
    {
        // A value that was read and found not to enable LAPS is a real "No",
        // not absence.
        Assert.Equal("No", RegistrySignalMapper.Laps(P(0), P(0)));
        Assert.Equal("No", RegistrySignalMapper.Laps(P(0), Absent));
        Assert.Equal("No", RegistrySignalMapper.Laps(Absent, P(0)));
    }

    [Fact]
    public void Laps_FailedWithoutPositiveEvidence_IsUnknown_NotNo()
    {
        Assert.Equal("Unknown", RegistrySignalMapper.Laps(Failed, Absent));
        Assert.Equal("Unknown", RegistrySignalMapper.Laps(Absent, Failed));
        Assert.Equal("Unknown", RegistrySignalMapper.Laps(P(0), Failed));
        Assert.Equal("Unknown", RegistrySignalMapper.Laps(P("1"), Absent));
    }

    // ── security_log_max_size_kb ─────────────────────────────────────────────

    [Fact]
    public void SecurityLogMaxSize_Present()
    {
        Assert.Equal(196_800, RegistrySignalMapper.SecurityLogMaxSizeKb(P(196_800), P(20_971_520)));
        Assert.Equal(20_480, RegistrySignalMapper.SecurityLogMaxSizeKb(Absent, P(20_971_520)));
    }

    [Fact]
    public void SecurityLogMaxSize_BothAbsent_IsNotConfigured()
    {
        Assert.Equal("NotConfigured", RegistrySignalMapper.SecurityLogMaxSizeKb(Absent, Absent));
    }

    [Fact]
    public void SecurityLogMaxSize_Failed_IsUnknown_AndPolicyFailureDoesNotFallThrough()
    {
        Assert.Equal("Unknown", RegistrySignalMapper.SecurityLogMaxSizeKb(Failed, P(20_971_520)));
        Assert.Equal("Unknown", RegistrySignalMapper.SecurityLogMaxSizeKb(Absent, Failed));
        Assert.Equal("Unknown", RegistrySignalMapper.SecurityLogMaxSizeKb(P("1024"), P(20_971_520)));
    }

    // ── ASR rules ────────────────────────────────────────────────────────────

    [Fact]
    public void AsrRule_Present()
    {
        Assert.Equal("Yes", RegistrySignalMapper.AsrRule(P("1"), Absent));
        Assert.Equal("No", RegistrySignalMapper.AsrRule(P("2"), P("1")));   // policy wins
        Assert.Equal("Yes", RegistrySignalMapper.AsrRule(Absent, P(1)));
        Assert.Equal("No", RegistrySignalMapper.AsrRule(Absent, P("0")));
    }

    [Fact]
    public void AsrRule_UnexpectedValueType_IsUnknown()
    {
        Assert.Equal("Unknown", RegistrySignalMapper.AsrRule(P(new byte[] { 1 }), Absent));
        Assert.Equal("Unknown", RegistrySignalMapper.AsrRule(P("enabled"), P("1")));
        Assert.Equal("Unknown", RegistrySignalMapper.AsrRule(P(1.0f), Absent));
        Assert.Equal("Yes", RegistrySignalMapper.AsrRule(P(" 1 "), Absent));
    }

    [Fact]
    public void AsrRule_BothAbsent_IsNotConfigured()
    {
        Assert.Equal("NotConfigured", RegistrySignalMapper.AsrRule(Absent, Absent));
    }

    [Fact]
    public void AsrRule_Failed_IsUnknown_AndPolicyFailureDoesNotFallThrough()
    {
        Assert.Equal("Unknown", RegistrySignalMapper.AsrRule(Failed, P("1")));
        Assert.Equal("Unknown", RegistrySignalMapper.AsrRule(Absent, Failed));
    }
}
