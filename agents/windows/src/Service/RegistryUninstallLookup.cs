using System.Runtime.Versioning;
// DEPRECATED — PAT-1531: legacy removal source retained for reference only;
// excluded from the Windows assurance-only Service build.
using Microsoft.Win32;
using Patched.Shared.Removal;

namespace Patched.Service;

/// <summary>
/// Reads HKLM Uninstall keys (64- and 32-bit hives) into <see cref="InstalledProgram"/>
/// records and resolves a queued removal's app name to the matching entry. The
/// uninstall analogue of <see cref="InstalledAppScanner"/>, but it also surfaces the
/// QuietUninstallString / UninstallString / InstallLocation the engine needs.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RegistryUninstallLookup
{
    private static readonly string[] UninstallPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];

    private readonly ILogger<RegistryUninstallLookup> _log;

    public RegistryUninstallLookup(ILogger<RegistryUninstallLookup> log) => _log = log;

    /// <summary>All installed programs visible in the HKLM Uninstall hives.</summary>
    public IReadOnlyList<InstalledProgram> ScanAll()
    {
        var results = new List<InstalledProgram>();
        foreach (var regPath in UninstallPaths)
            ScanHive(regPath, results);
        return results;
    }

    /// <summary>
    /// Best match for a queued removal name. match_mode "exact_name" compares the
    /// DisplayName case-insensitively; any other mode falls back to substring.
    /// Returns null when nothing matches (i.e. already removed).
    /// </summary>
    public InstalledProgram? Find(string name, string matchMode)
    {
        bool exact = string.Equals(matchMode, "exact_name", StringComparison.OrdinalIgnoreCase);
        InstalledProgram? substringMatch = null;

        foreach (var p in ScanAll())
        {
            if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))
                return p;                              // exact wins outright
            if (!exact && substringMatch is null &&
                p.Name.Contains(name, StringComparison.OrdinalIgnoreCase))
                substringMatch = p;
        }
        return exact ? null : substringMatch;
    }

    private void ScanHive(string path, List<InstalledProgram> results)
    {
        RegistryKey? uninstall;
        try   { uninstall = Registry.LocalMachine.OpenSubKey(path); }
        catch { return; }
        if (uninstall is null) return;

        using (uninstall)
        {
            foreach (var keyName in uninstall.GetSubKeyNames())
            {
                try
                {
                    using var k = uninstall.OpenSubKey(keyName);
                    if (k is null) continue;

                    var name = k.GetValue("DisplayName")?.ToString();
                    if (string.IsNullOrWhiteSpace(name)) continue;

                    results.Add(new InstalledProgram
                    {
                        Name                 = name,
                        Publisher            = NullIfEmpty(k.GetValue("Publisher")?.ToString()),
                        RegistryKeyName      = keyName,
                        QuietUninstallString = NullIfEmpty(k.GetValue("QuietUninstallString")?.ToString()),
                        UninstallString      = NullIfEmpty(k.GetValue("UninstallString")?.ToString()),
                        InstallLocation      = NullIfEmpty(k.GetValue("InstallLocation")?.ToString()),
                        SystemComponent      = k.GetValue("SystemComponent") is int sc && sc == 1,
                        WindowsInstaller     = k.GetValue("WindowsInstaller") is int wi && wi == 1,
                    });
                }
                catch (Exception ex)
                {
                    _log.LogDebug(ex, "RegistryUninstallLookup: failed to read key {Key}", keyName);
                }
            }
        }
    }

    private static string? NullIfEmpty(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s;
}
