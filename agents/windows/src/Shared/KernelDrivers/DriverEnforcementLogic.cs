using Patched.Shared.Compliance;
using Patched.Shared.Contract;
using Patched.Shared.DeviceClassification;

namespace Patched.Shared.KernelDrivers;

/// <summary>
/// PAT-2263: the <c>enforcement</c> object of the <c>kernel_drivers</c> block, from raw
/// reads. Absent and failed are kept apart throughout: a failed read is "unknown", never
/// "off" or "not set".
/// </summary>
internal static class DriverEnforcementLogic
{
    public const string BlocklistEnabled   = "enabled";
    public const string BlocklistDisabled  = "disabled";
    public const string BlocklistNotSet    = "not_set";
    public const string HvciRunning        = "running";
    public const string HvciConfigured     = "configured";
    public const string HvciOff            = "off";
    public const string SacOn              = "on";
    public const string SacEvaluation      = "evaluation";
    public const string SacOff             = "off";
    public const string SacNotPresent      = "not_present";
    public const string CiEnforced         = "enforced";
    public const string CiAudit            = "audit";
    public const string CiOff              = "off";
    public const string Yes                = "yes";
    public const string No                 = "no";
    public const string Unknown            = "unknown";

    /// <param name="blocklist">HKLM\SYSTEM\CurrentControlSet\Control\CI\Config VulnerableDriverBlocklistEnable.</param>
    /// <param name="smartAppControl">HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy VerifiedAndReputablePolicyState.</param>
    /// <param name="hvciStatus">Win32_DeviceGuard HypervisorEnforcedCodeIntegrityStatus.</param>
    /// <param name="codeIntegrityPolicyStatus">Win32_DeviceGuard CodeIntegrityPolicyEnforcementStatus.</param>
    public static InventoryDriverEnforcement Build(
        RegistryRead blocklist,
        RegistryRead smartAppControl,
        SourceRead hvciStatus,
        SourceRead codeIntegrityPolicyStatus)
    {
        var list = blocklist.State switch
        {
            RegistryReadState.Absent => BlocklistNotSet,
            RegistryReadState.Present when blocklist.TryGetInt(out var v) => v switch
            {
                1 => BlocklistEnabled,
                0 => BlocklistDisabled,
                _ => Unknown,
            },
            _ => Unknown,
        };
        var sac = smartAppControl.State switch
        {
            RegistryReadState.Absent => SacNotPresent,
            RegistryReadState.Present when smartAppControl.TryGetInt(out var v) => v switch
            {
                1 => SacOn,
                2 => SacEvaluation,
                0 => SacOff,
                _ => Unknown,
            },
            _ => Unknown,
        };
        var hvci = WmiInt(hvciStatus) switch
        {
            2 => HvciRunning,
            1 => HvciConfigured,
            0 => HvciOff,
            _ => Unknown,
        };
        var ci = WmiInt(codeIntegrityPolicyStatus) switch
        {
            2 => CiEnforced,
            1 => CiAudit,
            0 => CiOff,
            _ => Unknown,
        };

        // Smart App Control in evaluation mode is not counted either way: whether it forces
        // the blocklist is not documented, so it can only leave the answer unknown.
        string enforced;
        if (list == BlocklistEnabled || hvci == HvciRunning || sac == SacOn)
            enforced = Yes;
        else if (list == BlocklistDisabled && hvci is HvciOff or HvciConfigured && sac is SacOff or SacNotPresent)
            enforced = No;
        else
            enforced = Unknown;

        return new InventoryDriverEnforcement
        {
            VulnerableDriverBlocklist = list,
            Hvci = hvci,
            SmartAppControl = sac,
            CodeIntegrityPolicy = ci,
            BlocklistEnforced = enforced,
        };
    }

    /// <summary>A WMI uint32 status as an int, or null when absent, failed or not an integer.</summary>
    private static int? WmiInt(SourceRead read)
    {
        if (read.State != SourceReadState.Present) return null;
        return read.Value switch
        {
            int i => i,
            uint u when u <= int.MaxValue => (int)u,
            ushort s => s,
            byte b => b,
            long l when l is >= 0 and <= int.MaxValue => (int)l,
            _ => null,
        };
    }
}
