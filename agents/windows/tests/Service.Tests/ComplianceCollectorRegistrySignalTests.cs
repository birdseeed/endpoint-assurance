using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using Patched.Service;
using Patched.Shared.Compliance;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1767: the HKLM wiring behind the registry-backed compliance signals. The
/// collector reads HKLM through a <see cref="RegistryValueReader"/>; these tests swap
/// in a fake so each signal's key path and value name are exercised for a present
/// value, an absent value ("NotConfigured") and a failed read ("Unknown", or omitted
/// for the parser-backed batches), without touching the machine registry. The fake
/// needs no Windows API. <see cref="ReadValue_AgainstRealRegistry"/> checks the
/// production reader's absent and failed classification on Windows only.
/// </summary>
public sealed class ComplianceCollectorRegistrySignalTests : IDisposable
{
    private const string Fw = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
    private const string Schannel = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";
    private const string AsrPolicy = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
    private const string AsrConfig = @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
    private const string AsrRansomware = "c1db55ab-c21a-4637-bb3f-a12568109d35";
    private const string AsrPsexec = "d1e49aac-8f56-4280-b9ba-993a6d77406c";

    private const string Kernel = @"SYSTEM\CurrentControlSet\Control\Session Manager\kernel";
    private const string MemoryManagement = @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";

    private const string AuPolicy = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
    private const string AuLocal = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update";
    private const string MdmUpdate = @"SOFTWARE\Microsoft\PolicyManager\current\device\Update";
    private const string PolicyConflict = @"SOFTWARE\Microsoft\PolicyManager\current\device\ControlPolicyConflict";

    private readonly string _scratchPath = $@"Software\PatchedTests\PAT-1767\{Guid.NewGuid():N}";

    public void Dispose()
    {
        if (!OperatingSystem.IsWindows()) return;
        Registry.CurrentUser.DeleteSubKeyTree(_scratchPath, throwOnMissingSubKey: false);
    }

    /// <summary>A fake HKLM: named values are Present, everything else <paramref name="otherwise"/>.</summary>
    private sealed class FakeHklm(RegistryRead otherwise)
    {
        private readonly Dictionary<(string, string), RegistryRead> _values = new();
        public List<(string Key, string Value)> Requested { get; } = new();

        public FakeHklm Set(string keyPath, string valueName, RegistryRead read)
        {
            _values[(keyPath.ToUpperInvariant(), valueName.ToUpperInvariant())] = read;
            return this;
        }

        public RegistryRead Read(string keyPath, string valueName)
        {
            Requested.Add((keyPath, valueName));
            return _values.TryGetValue((keyPath.ToUpperInvariant(), valueName.ToUpperInvariant()), out var r) ? r : otherwise;
        }
    }

    private static Dictionary<string, object> Run(string method, FakeHklm hklm)
    {
        var collector = new ComplianceCollector(NullLogger<ComplianceCollector>.Instance, hklm.Read);
        var s = new Dictionary<string, object>();
        switch (method)
        {
            case nameof(ComplianceCollector.AddFirewall): collector.AddFirewall(s); break;
            case nameof(ComplianceCollector.AddDefender): collector.AddDefender(s); break;
            case nameof(ComplianceCollector.AddUac): collector.AddUac(s); break;
            case nameof(ComplianceCollector.AddAutoUpdates): collector.AddAutoUpdates(s); break;
            case nameof(ComplianceCollector.AddRemoteDesktop): collector.AddRemoteDesktop(s); break;
            case nameof(ComplianceCollector.AddSmbSigning): collector.AddSmbSigning(s); break;
            case nameof(ComplianceCollector.AddSecurityOptions): collector.AddSecurityOptions(s); break;
            case nameof(ComplianceCollector.AddServicesFeatures): collector.AddServicesFeatures(s); break;
            case nameof(ComplianceCollector.AddDefenderPolicy): collector.AddDefenderPolicy(s); break;
            case nameof(ComplianceCollector.AddFipsAndTls): collector.AddFipsAndTls(s); break;
            case nameof(ComplianceCollector.AddSecureBoot): collector.AddSecureBoot(s); break;
            case nameof(ComplianceCollector.AddExploitProtection): collector.AddExploitProtection(s); break;
            case nameof(ComplianceCollector.AddLaps): collector.AddLaps(s); break;
            case nameof(ComplianceCollector.AddEventLogSecurity): collector.AddEventLogSecurity(s); break;
            case nameof(ComplianceCollector.AddAsrRules): collector.AddAsrRules(s); break;
            default: throw new ArgumentOutOfRangeException(nameof(method));
        }
        return s;
    }

    // method, signal, key path, value name, present value, expected for that value
    public static TheoryData<string, string, string, string, object, string> StringSignals => new()
    {
        { nameof(ComplianceCollector.AddFirewall), "windows_firewall_domain", Fw + @"\DomainProfile", "EnableFirewall", 1, "enabled" },
        { nameof(ComplianceCollector.AddFirewall), "windows_firewall_private", Fw + @"\StandardProfile", "EnableFirewall", 0, "disabled" },
        { nameof(ComplianceCollector.AddFirewall), "windows_firewall_public", Fw + @"\PublicProfile", "EnableFirewall", 1, "enabled" },
        { nameof(ComplianceCollector.AddDefender), "defender_realtime", @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", 1, "disabled" },
        { nameof(ComplianceCollector.AddUac), "uac_enabled", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1, "Yes" },
        { nameof(ComplianceCollector.AddAutoUpdates), "auto_updates_enabled", AuLocal, "AUOptions", 2, "No" },
        { nameof(ComplianceCollector.AddAutoUpdates), "auto_updates_enabled", AuPolicy, "AUOptions", 4, "Yes" },
        { nameof(ComplianceCollector.AddAutoUpdates), "auto_updates_enabled", AuPolicy, "NoAutoUpdate", 1, "No" },
        { nameof(ComplianceCollector.AddAutoUpdates), "auto_updates_enabled", MdmUpdate, "AllowAutoUpdate", 1, "Yes" },
        { nameof(ComplianceCollector.AddAutoUpdates), "auto_updates_enabled", MdmUpdate, "AllowAutoUpdate", 0, "No" },
        { nameof(ComplianceCollector.AddRemoteDesktop), "remote_desktop_enabled", @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 0, "enabled" },
        { nameof(ComplianceCollector.AddSmbSigning), "smb_signing_required", @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature", 1, "Yes" },
        { nameof(ComplianceCollector.AddFipsAndTls), "fips_mode_enabled", @"SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy", "Enabled", 1, "Yes" },
        { nameof(ComplianceCollector.AddFipsAndTls), "tls10_client_disabled", Schannel + @"\TLS 1.0\Client", "Enabled", 0, "Yes" },
        { nameof(ComplianceCollector.AddFipsAndTls), "tls10_server_disabled", Schannel + @"\TLS 1.0\Server", "Enabled", 1, "No" },
        { nameof(ComplianceCollector.AddFipsAndTls), "tls11_client_disabled", Schannel + @"\TLS 1.1\Client", "Enabled", 0, "Yes" },
        { nameof(ComplianceCollector.AddFipsAndTls), "tls11_server_disabled", Schannel + @"\TLS 1.1\Server", "Enabled", 0, "Yes" },
        { nameof(ComplianceCollector.AddFipsAndTls), "tls12_client_enabled", Schannel + @"\TLS 1.2\Client", "Enabled", 0, "No" },
        { nameof(ComplianceCollector.AddFipsAndTls), "tls12_server_enabled", Schannel + @"\TLS 1.2\Server", "DisabledByDefault", 0, "Yes" },
        { nameof(ComplianceCollector.AddSecureBoot), "secure_boot_enabled", @"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled", 1, "Yes" },
        { nameof(ComplianceCollector.AddExploitProtection), "mandatory_aslr_enabled", Kernel, "MitigationOptions", new byte[] { 0x00, 0x01, 0x00, 0x00 }, "Yes" },
        { nameof(ComplianceCollector.AddExploitProtection), "mandatory_aslr_enabled", Kernel, "MitigationOptions", new byte[] { 0x00, 0x02, 0x00, 0x00 }, "No" },
        { nameof(ComplianceCollector.AddEventLogSecurity), "security_log_max_size_kb", @"SOFTWARE\Policies\Microsoft\Windows\EventLog\Security", "MaxSize", 196800, "196800" },
        { nameof(ComplianceCollector.AddEventLogSecurity), "security_log_max_size_kb", @"SYSTEM\CurrentControlSet\Services\EventLog\Security", "MaxSize", 20971520, "20480" },
        { nameof(ComplianceCollector.AddAsrRules), "asr_ransomware_enabled", AsrPolicy, AsrRansomware, "1", "Yes" },
        { nameof(ComplianceCollector.AddAsrRules), "asr_psexec_wmi_block_enabled", AsrConfig, AsrPsexec, 1, "Yes" },
    };

    // method, signal: every signal whose absent read is NotConfigured and failed read is Unknown
    public static TheoryData<string, string> TriStateSignals()
    {
        var data = new TheoryData<string, string>();
        var seen = new HashSet<string>();
        foreach (var row in StringSignals)
        {
            var method = (string)row[0];
            var signal = (string)row[1];
            if (seen.Add(signal))
                data.Add(method, signal);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(StringSignals))]
    public void Present_ReadsThatPathAndValue(string method, string signal, string keyPath, string valueName, object value, string expected)
    {
        var s = Run(method, new FakeHklm(RegistryRead.Absent).Set(keyPath, valueName, RegistryRead.Present(value)));
        Assert.Equal(expected, Convert.ToString(s[signal], System.Globalization.CultureInfo.InvariantCulture));
    }

    [Theory]
    [MemberData(nameof(TriStateSignals))]
    public void Absent_IsNotConfigured(string method, string signal)
    {
        var s = Run(method, new FakeHklm(RegistryRead.Absent));
        Assert.Equal("NotConfigured", s[signal]);
    }

    [Theory]
    [MemberData(nameof(TriStateSignals))]
    public void ReadThrows_IsUnknown_NeverNotConfigured(string method, string signal)
    {
        var s = Run(method, new FakeHklm(RegistryRead.Failed));
        Assert.Equal("Unknown", s[signal]);
    }

    // ── signals with their own absent semantics ─────────────────────────────

    [Fact]
    public void Laps_PresentAbsentFailed()
    {
        const string modern = @"SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config";
        const string legacy = @"SOFTWARE\Policies\Microsoft Services\AdmPwd";

        Assert.Equal("Yes", Run(nameof(ComplianceCollector.AddLaps),
            new FakeHklm(RegistryRead.Absent).Set(modern, "BackupDirectory", RegistryRead.Present(1)))["laps_enrolled"]);
        Assert.Equal("Yes", Run(nameof(ComplianceCollector.AddLaps),
            new FakeHklm(RegistryRead.Absent).Set(legacy, "AdmPwdEnabled", RegistryRead.Present(1)))["laps_enrolled"]);
        Assert.Equal("NotConfigured", Run(nameof(ComplianceCollector.AddLaps), new FakeHklm(RegistryRead.Absent))["laps_enrolled"]);
        Assert.Equal("Unknown", Run(nameof(ComplianceCollector.AddLaps), new FakeHklm(RegistryRead.Failed))["laps_enrolled"]);
    }

    [Fact]
    public void AsrRule_FailedPolicyRead_DoesNotReadConfiguration()
    {
        var hklm = new FakeHklm(RegistryRead.Absent)
            .Set(AsrPolicy, AsrRansomware, RegistryRead.Failed)
            .Set(AsrConfig, AsrRansomware, RegistryRead.Present("1"));

        var s = Run(nameof(ComplianceCollector.AddAsrRules), hklm);

        Assert.Equal("Unknown", s["asr_ransomware_enabled"]);
        Assert.DoesNotContain((AsrConfig, AsrRansomware), hklm.Requested);
    }

    [Fact]
    public void MandatoryAslr_ReadsOnlyKernelMitigationOptions_NotMoveImages()
    {
        // PAT-1770: a MoveImages value, even one the old read mapped to Yes, is ignored.
        var hklm = new FakeHklm(RegistryRead.Absent)
            .Set(MemoryManagement, "MoveImages", RegistryRead.Present(-1));

        var s = Run(nameof(ComplianceCollector.AddExploitProtection), hklm);

        Assert.Equal("NotConfigured", s["mandatory_aslr_enabled"]);
        Assert.Equal(new[] { (Kernel, "MitigationOptions") }, hklm.Requested);
    }

    [Fact]
    public void AutoUpdates_PolicyAuOptions_WinsOverLocal_AndLocalIsNotRead()
    {
        var hklm = new FakeHklm(RegistryRead.Absent)
            .Set(AuPolicy, "AUOptions", RegistryRead.Present(2))
            .Set(AuLocal, "AUOptions", RegistryRead.Present(4));

        Assert.Equal("No", Run(nameof(ComplianceCollector.AddAutoUpdates), hklm)["auto_updates_enabled"]);
        Assert.Equal(new[] { (AuPolicy, "NoAutoUpdate"), (AuPolicy, "AUOptions") }, hklm.Requested);
    }

    [Fact]
    public void AutoUpdates_PolicyAuOptions5_ResolvesThroughLocal()
    {
        var hklm = new FakeHklm(RegistryRead.Absent)
            .Set(AuPolicy, "AUOptions", RegistryRead.Present(5))
            .Set(AuLocal, "AUOptions", RegistryRead.Present(3));

        Assert.Equal("Yes", Run(nameof(ComplianceCollector.AddAutoUpdates), hklm)["auto_updates_enabled"]);
        Assert.Equal(new[] { (AuPolicy, "NoAutoUpdate"), (AuPolicy, "AUOptions"), (AuLocal, "AUOptions") }, hklm.Requested);
    }

    [Fact]
    public void AutoUpdates_FailedPolicyAuOptions_DoesNotReadLocal()
    {
        var hklm = new FakeHklm(RegistryRead.Absent)
            .Set(AuPolicy, "AUOptions", RegistryRead.Failed)
            .Set(AuLocal, "AUOptions", RegistryRead.Present(4));

        Assert.Equal("Unknown", Run(nameof(ComplianceCollector.AddAutoUpdates), hklm)["auto_updates_enabled"]);
        Assert.DoesNotContain((AuLocal, "AUOptions"), hklm.Requested);
    }

    [Fact]
    public void AutoUpdates_NoAutoUpdate1_ReadsNothingElse()
    {
        var hklm = new FakeHklm(RegistryRead.Failed).Set(AuPolicy, "NoAutoUpdate", RegistryRead.Present(1));

        Assert.Equal("No", Run(nameof(ComplianceCollector.AddAutoUpdates), hklm)["auto_updates_enabled"]);
        Assert.Equal(new[] { (AuPolicy, "NoAutoUpdate") }, hklm.Requested);
    }

    [Fact]
    public void AutoUpdates_NothingSet_ReadsGroupPolicyThenMdmThenLocal_InOrder()
    {
        var hklm = new FakeHklm(RegistryRead.Absent);

        Assert.Equal("NotConfigured", Run(nameof(ComplianceCollector.AddAutoUpdates), hklm)["auto_updates_enabled"]);
        Assert.Equal(new[]
        {
            (AuPolicy, "NoAutoUpdate"),
            (AuPolicy, "AUOptions"),
            (MdmUpdate, "AllowAutoUpdate"),
            (AuLocal, "AUOptions"),
        }, hklm.Requested);
    }

    [Fact]
    public void AutoUpdates_MdmAllowAutoUpdate_WinsOverLocal_AndLocalIsNotRead()
    {
        var hklm = new FakeHklm(RegistryRead.Absent)
            .Set(MdmUpdate, "AllowAutoUpdate", RegistryRead.Present(0))
            .Set(AuLocal, "AUOptions", RegistryRead.Present(4));

        Assert.Equal("No", Run(nameof(ComplianceCollector.AddAutoUpdates), hklm)["auto_updates_enabled"]);
        Assert.Equal(new[] { (AuPolicy, "NoAutoUpdate"), (AuPolicy, "AUOptions"), (MdmUpdate, "AllowAutoUpdate") }, hklm.Requested);
    }

    [Fact]
    public void AutoUpdates_FailedMdmRead_IsUnknown_AndDoesNotReadLocal()
    {
        var hklm = new FakeHklm(RegistryRead.Absent)
            .Set(MdmUpdate, "AllowAutoUpdate", RegistryRead.Failed)
            .Set(AuLocal, "AUOptions", RegistryRead.Present(4));

        Assert.Equal("Unknown", Run(nameof(ComplianceCollector.AddAutoUpdates), hklm)["auto_updates_enabled"]);
        Assert.DoesNotContain((AuLocal, "AUOptions"), hklm.Requested);
    }

    // MDMWinsOverGP absent, 0 and 1 give the same answer: Microsoft documents that the
    // ControlPolicyConflict CSP does not apply to the Update Policy CSP, so it is never read.
    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    [InlineData(1)]
    public void AutoUpdates_GroupPolicyLevel_WinsOverConflictingMdm_WhateverMdmWinsOverGP(int? mdmWinsOverGp)
    {
        var hklm = new FakeHklm(RegistryRead.Absent)
            .Set(AuPolicy, "AUOptions", RegistryRead.Present(2))
            .Set(MdmUpdate, "AllowAutoUpdate", RegistryRead.Present(4));
        if (mdmWinsOverGp is int v)
            hklm.Set(PolicyConflict, "MDMWinsOverGP", RegistryRead.Present(v));

        Assert.Equal("No", Run(nameof(ComplianceCollector.AddAutoUpdates), hklm)["auto_updates_enabled"]);
        Assert.Equal(new[] { (AuPolicy, "NoAutoUpdate"), (AuPolicy, "AUOptions") }, hklm.Requested);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    [InlineData(1)]
    public void AutoUpdates_GroupPolicyNotConfigured_FallsToMdm_WhateverMdmWinsOverGP(int? mdmWinsOverGp)
    {
        var hklm = new FakeHklm(RegistryRead.Absent)
            .Set(MdmUpdate, "AllowAutoUpdate", RegistryRead.Present(2))
            .Set(AuLocal, "AUOptions", RegistryRead.Present(1));
        if (mdmWinsOverGp is int v)
            hklm.Set(PolicyConflict, "MDMWinsOverGP", RegistryRead.Present(v));

        Assert.Equal("Yes", Run(nameof(ComplianceCollector.AddAutoUpdates), hklm)["auto_updates_enabled"]);
        Assert.DoesNotContain(hklm.Requested, r => r.Key == PolicyConflict);
    }

    // ── parser-backed batches: absent follows the parser, failed is omitted ──

    [Fact]
    public void SecurityOptions_PresentAbsentFailed()
    {
        const string policies = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

        var present = Run(nameof(ComplianceCollector.AddSecurityOptions),
            new FakeHklm(RegistryRead.Absent).Set(policies, "NoConnectedUser", RegistryRead.Present(3)));
        Assert.Equal("Yes", present["block_microsoft_accounts"]);
        Assert.Equal("NotConfigured", present["no_lm_hash"]);

        var absent = Run(nameof(ComplianceCollector.AddSecurityOptions), new FakeHklm(RegistryRead.Absent));
        Assert.Equal(8, absent.Count);
        Assert.All(absent.Values, v => Assert.Equal("NotConfigured", v));

        var failed = Run(nameof(ComplianceCollector.AddSecurityOptions), new FakeHklm(RegistryRead.Failed));
        Assert.Empty(failed);
    }

    [Fact]
    public void ServicesFeatures_PresentAbsentFailed()
    {
        var present = Run(nameof(ComplianceCollector.AddServicesFeatures),
            new FakeHklm(RegistryRead.Absent).Set(@"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", RegistryRead.Present(2)));
        Assert.Equal("No", present["smbv1_disabled"]);

        var absent = Run(nameof(ComplianceCollector.AddServicesFeatures), new FakeHklm(RegistryRead.Absent));
        Assert.Equal("NotConfigured", absent["smbv1_disabled"]);
        Assert.Equal(6, absent.Count);

        Assert.Empty(Run(nameof(ComplianceCollector.AddServicesFeatures), new FakeHklm(RegistryRead.Failed)));
    }

    [Fact]
    public void DefenderPolicy_PresentAbsentFailed()
    {
        var present = Run(nameof(ComplianceCollector.AddDefenderPolicy),
            new FakeHklm(RegistryRead.Absent).Set(@"SOFTWARE\Policies\Microsoft\Windows Defender", "PUAProtection", RegistryRead.Present(1)));
        Assert.Equal("Yes", present["defender_pua_protection"]);

        var absent = Run(nameof(ComplianceCollector.AddDefenderPolicy), new FakeHklm(RegistryRead.Absent));
        Assert.Equal("NotConfigured", absent["defender_pua_protection"]);
        Assert.Equal(6, absent.Count);

        Assert.Empty(Run(nameof(ComplianceCollector.AddDefenderPolicy), new FakeHklm(RegistryRead.Failed)));
    }

    // ── production reader against a real registry (Windows only) ─────────────

    [Fact]
    public void ReadValue_AgainstRealRegistry()
    {
        if (!OperatingSystem.IsWindows()) return;

        using (var root = Registry.CurrentUser.CreateSubKey(_scratchPath))
        {
            using (var key = root.CreateSubKey(@"Lsa\FIPSAlgorithmPolicy"))
                key.SetValue("Enabled", 1, RegistryValueKind.DWord);

            var present = ComplianceCollector.ReadValue(root, @"Lsa\FIPSAlgorithmPolicy", "Enabled");
            Assert.Equal(RegistryReadState.Present, present.State);
            Assert.Equal(1, present.Value);

            Assert.Equal(RegistryReadState.Absent, ComplianceCollector.ReadValue(root, @"Lsa\FIPSAlgorithmPolicy", "Missing").State);
            Assert.Equal(RegistryReadState.Absent, ComplianceCollector.ReadValue(root, @"Lsa\NoSuchKey", "Enabled").State);
        }

        // A closed key throws ObjectDisposedException on open: a failed read, not absence.
        var closed = Registry.CurrentUser.CreateSubKey(_scratchPath);
        closed.Dispose();
        Assert.Equal(RegistryReadState.Failed, ComplianceCollector.ReadValue(closed, @"Lsa\FIPSAlgorithmPolicy", "Enabled").State);
    }
}
