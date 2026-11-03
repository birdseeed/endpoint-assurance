using Microsoft.Extensions.Logging;
using System.Management;
using System.Runtime.Versioning;

namespace Patched.Shared.Auth;

/// <summary>
/// PAT-736: process-wide cache of the WMI hardware UUID
/// (Win32_ComputerSystemProduct.UUID). Registered as a singleton so the slow
/// WMI query runs once per process; DeviceIdentityHandler is transient (the
/// HttpClientFactory builds a fresh handler per pipeline) and reads from here.
/// Fail-open: null when WMI is unavailable.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DeviceIdProvider
{
    public string? DeviceId { get; }

    public DeviceIdProvider(ILogger<DeviceIdProvider> log)
    {
        DeviceId = ReadHwUuid(log);
    }

    private static string? ReadHwUuid(ILogger log)
    {
        try
        {
            using var mos = new ManagementObjectSearcher(
                "SELECT UUID FROM Win32_ComputerSystemProduct");
            foreach (ManagementObject obj in mos.Get())
            {
                var uuid = obj["UUID"]?.ToString();
                if (!string.IsNullOrWhiteSpace(uuid) && uuid != "Unknown")
                    return uuid;
            }
        }
        catch (Exception ex)
        {
            log.LogDebug(ex, "DeviceIdProvider: could not read WMI UUID — X-Patched-Device-Id will be omitted");
        }
        return null;
    }
}
