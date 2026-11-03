using System.Management;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Patched.Shared.Contract;
using Patched.Shared.Compliance;
using Patched.Shared.SecurityTools;

namespace Patched.Service;

/// <summary>
/// Detects installed AV/EDR security tools. PAT-2267: Windows Security Center
/// (<c>root\SecurityCenter2</c> <c>AntiVirusProduct</c>) is the primary source off Server,
/// the Defender status class stands in for it where it was not read, and the HKLM registry
/// table is always consulted as a secondary signal. The merge, id mapping and
/// absent-versus-failed decisions live in <see cref="SecurityToolLogic"/>; this class only
/// performs the reads.
///
/// security_tools on the wire is a required array of <c>{id, name}</c> with
/// <c>additionalProperties: false</c> and no collection status, so an incomplete detection
/// cannot be said in the array. It is recorded in agent_health under
/// (<see cref="HealthKind"/>, <see cref="HealthSubject"/>), the same channel
/// BrowserExtensionScanner uses, and cleared by the next complete detection. The array
/// still carries every tool that was positively seen.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class SecurityToolDetector
{
    internal const string HealthKind = "collection_partial";
    internal const string HealthSubject = "security_tools";

    private static readonly TimeSpan WmiTimeout = TimeSpan.FromSeconds(30);

    private readonly ILogger<SecurityToolDetector> _log;
    private readonly AgentHealthStore _agentHealth;
    private readonly Func<SecurityCenterRead> _securityCenter;
    private readonly Func<SecurityToolProbe> _defenderStatus;
    private readonly Func<string, SecurityToolProbe> _registryKey;
    private readonly Func<RegistryRead> _mdeOnboarding;

    public SecurityToolDetector(ILogger<SecurityToolDetector> log, AgentHealthStore agentHealth)
        : this(log, agentHealth, null, null, null) { }

    /// <summary>Tests: any reader left null is the production one.</summary>
    internal SecurityToolDetector(
        ILogger<SecurityToolDetector> log,
        AgentHealthStore agentHealth,
        Func<SecurityCenterRead>? securityCenter,
        Func<SecurityToolProbe>? defenderStatus,
        Func<string, SecurityToolProbe>? registryKey,
        Func<RegistryRead>? mdeOnboarding = null)
    {
        _log = log;
        _agentHealth = agentHealth;
        _securityCenter = securityCenter ?? ReadSecurityCenter;
        _defenderStatus = defenderStatus ?? ReadDefenderStatus;
        _registryKey = registryKey ?? ProbeRegistryKey;
        _mdeOnboarding = mdeOnboarding ?? ReadMdeOnboarding;
    }

    /// <summary>
    /// <paramref name="deviceClass"/> is this cycle's resolved device_class; a server or
    /// domain controller is not asked for SecurityCenter2, which Windows Server lacks. Never
    /// throws: a failure becomes an agent_health entry and the tools that were seen.
    /// </summary>
    public IReadOnlyList<InventorySecurityTool> Detect(string? deviceClass)
    {
        SecurityToolDetection detection;
        try
        {
            detection = SecurityToolLogic.Detect(
                new SecurityToolSources(deviceClass, _securityCenter, _defenderStatus, _registryKey, _mdeOnboarding));
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "SecurityToolDetector: detection failed, security_tools is undetermined");
            RecordHealth("detection_failed");
            return [];
        }

        if (detection.Complete)
        {
            RecordHealth(null);
        }
        else
        {
            _log.LogWarning(
                "SecurityToolDetector: security_tools is incomplete ({Reason}); {Count} tool(s) positively seen are still reported",
                detection.HealthReason, detection.Tools.Count);
            RecordHealth(detection.HealthReason);
        }
        return detection.Tools;
    }

    private void RecordHealth(string? reason)
    {
        try
        {
            if (reason is null) _agentHealth.RecordSuccess(HealthKind, HealthSubject);
            else _agentHealth.RecordFailure(HealthKind, HealthSubject, reason);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "SecurityToolDetector: could not record collection health");
        }
    }

    // ── production readers ───────────────────────────────────────────────────

    private RegistryRead ReadMdeOnboarding() => RegistryRead.Capture(() =>
    {
        using var key = Registry.LocalMachine.OpenSubKey(SecurityToolLogic.MdeStatusPath);
        var value = key?.GetValue(SecurityToolLogic.MdeOnboardingValue, null,
            RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (value is null)
            return null;
        // Do not coerce strings, QWORDs or binary values into a DWORD. The pure
        // decision also rejects unusable values, but the OS type is authoritative.
        if (key!.GetValueKind(SecurityToolLogic.MdeOnboardingValue) != RegistryValueKind.DWord)
            throw new InvalidDataException("MDE OnboardingState is not REG_DWORD");
        return value;
    }, ex => _log.LogWarning(ex, "SecurityToolDetector: MDE onboarding read failed"));

    private SecurityCenterRead ReadSecurityCenter()
    {
        try
        {
            var products = new List<SecurityCenterProduct>();
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(@"root\SecurityCenter2"),
                new ObjectQuery("SELECT displayName, productState FROM AntiVirusProduct"),
                new System.Management.EnumerationOptions { Timeout = WmiTimeout });
            foreach (ManagementBaseObject obj in searcher.Get())
            {
                using (obj)
                    products.Add(new SecurityCenterProduct(obj["displayName"] as string, obj["productState"]));
            }
            return new SecurityCenterRead(SecurityCenterReadState.Read, products);
        }
        catch (ManagementException ex) when (IsMissing(ex))
        {
            _log.LogDebug("SecurityToolDetector: SecurityCenter2 is not present ({Status})", ex.ErrorCode);
            return SecurityCenterRead.Missing;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "SecurityToolDetector: SecurityCenter2 query failed");
            return SecurityCenterRead.Failed;
        }
    }

    /// <summary>
    /// Defender Antivirus presence from <c>MSFT_MpComputerStatus</c>. A missing namespace or
    /// class (the Defender feature is not installed, as on some Server builds) is absent; an
    /// instance with a product version is present; anything that throws is failed.
    /// </summary>
    private SecurityToolProbe ReadDefenderStatus()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(@"root\Microsoft\Windows\Defender"),
                new ObjectQuery("SELECT AMProductVersion FROM MSFT_MpComputerStatus"),
                new System.Management.EnumerationOptions { Timeout = WmiTimeout });
            foreach (ManagementBaseObject obj in searcher.Get())
            {
                using (obj)
                {
                    if (obj["AMProductVersion"] is string v && !string.IsNullOrWhiteSpace(v))
                        return SecurityToolProbe.Present;
                }
            }
            return SecurityToolProbe.Absent;
        }
        catch (ManagementException ex) when (IsMissing(ex))
        {
            return SecurityToolProbe.Absent;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "SecurityToolDetector: Defender status query failed");
            return SecurityToolProbe.Failed;
        }
    }

    private static bool IsMissing(ManagementException ex) =>
        ex.ErrorCode is ManagementStatus.InvalidNamespace or ManagementStatus.InvalidClass;

    /// <summary>A missing key is absent; any exception (access denied, I/O) is failed, never absent.</summary>
    private SecurityToolProbe ProbeRegistryKey(string path)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            return key is null ? SecurityToolProbe.Absent : SecurityToolProbe.Present;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "SecurityToolDetector: registry read failed: HKLM\\{Path}", path);
            return SecurityToolProbe.Failed;
        }
    }
}
