using System.Runtime.Versioning;
using Microsoft.Win32;

namespace Patched.Shared.DeviceClassification;

/// <summary>
/// PAT-1959: the one definition of where InstallationType is read from, shared by the
/// Service (which sends it as <c>installation_type</c>) and the Tray (which asks whether
/// this machine has a desktop at all). Two copies of the key path would be two things to
/// keep in step.
///
/// Read-only, HKLM, no write of any kind. This is collection, not actuation.
/// </summary>
[SupportedOSPlatform("windows")]
public static class InstallationTypeProbe
{
    public const string KeyPath   = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    public const string ValueName = "InstallationType";

    /// <summary>
    /// Reads the value. A missing key or value is
    /// <see cref="SourceReadState.Absent"/>; any exception (a permission problem, a
    /// damaged hive) is <see cref="SourceReadState.Failed"/>. Never throws.
    /// </summary>
    public static SourceRead Read(Action<Exception>? onFailure = null) =>
        SourceRead.Capture(
            () =>
            {
                using var key = Registry.LocalMachine.OpenSubKey(KeyPath, writable: false);
                return key?.GetValue(ValueName);
            },
            onFailure);
}
