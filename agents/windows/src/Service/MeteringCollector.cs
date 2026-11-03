using System.Runtime.Versioning;
using Microsoft.Win32;
using Patched.Shared.Metering;

namespace Patched.Service;

/// <summary>
/// PAT-380 software-metering collector — the Windows parity mirror of the macOS
/// PAT-356 Spotlight collector. Correlates UserAssist execution history with the
/// installed-apps registry to produce per-app last_used_at / launch_count keyed by
/// the same identifier <see cref="InstalledAppScanner"/> reports, plus a device-level
/// metering_status. <see cref="InventoryPoster"/> folds the result into the payload.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class MeteringCollector
{
    private static readonly string[] UninstallPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];

    private readonly ILogger<MeteringCollector> _log;
    private readonly UserAssistReader           _userAssist;

    public MeteringCollector(ILogger<MeteringCollector> log, UserAssistReader userAssist)
    {
        _log        = log;
        _userAssist = userAssist;
    }

    public sealed record Result(string Status, IReadOnlyDictionary<string, AppUsage> ByIdentifier,
        int? UserHiveCount = null, int? RecordCount = null);

    public Result Collect()
    {
        var source = _userAssist.Read();
        try
        {
            var apps = ScanInstalledApps();
            var map = MeteringMatcher.Match(source.Usages, apps, source.Status == MeteringStatus.Ok);
            _log.LogInformation("Metering: {Hives} loaded user hives, {Records} usable records, status={Status}",
                source.UserHiveCount, source.RecordCount, source.Status);
            if (source.Status == MeteringStatus.Unavailable)
                _log.LogWarning("Metering: loaded profiles did not provide complete usable UserAssist evidence");
            return new(source.Status, map, source.UserHiveCount, source.RecordCount);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Metering: installed application hints could not be read");
            return new(MeteringStatus.Unavailable, new Dictionary<string, AppUsage>(), source.UserHiveCount, source.RecordCount);
        }
    }

    /// <summary>Registry Uninstall entries reduced to (identifier, InstallLocation, exe).</summary>
    private List<MeteredApp> ScanInstalledApps()
    {
        var apps = new List<MeteredApp>();
        var officePaths = ReadOfficeAppPaths();
        foreach (var path in UninstallPaths)
        {
            RegistryKey? hive = Registry.LocalMachine.OpenSubKey(path);
            if (hive is null) continue;

            using (hive)
            {
                foreach (var keyName in hive.GetSubKeyNames())
                {
                    try
                    {
                        using var k = hive.OpenSubKey(keyName);
                        if (k is null) throw new IOException("An uninstall key disappeared during metering");
                        if (k.GetValue("DisplayName") is null) continue;   // skip orphan keys

                        var installLoc = (k.GetValue("InstallLocation") as string)?.Trim();
                        var exe        = StripIconIndex(k.GetValue("DisplayIcon") as string);

                        apps.Add(new MeteredApp
                        {
                            Identifier      = keyName,
                            InstallLocation = string.IsNullOrWhiteSpace(installLoc) ? null : installLoc,
                            ExePath         = exe,
                            OfficeExePaths = MeteringMatcher.BindOfficeExecutables(keyName, installLoc, officePaths),
                        });
                    }
                    catch (Exception ex)
                    {
                        _log.LogWarning(ex, "Metering: failed to read an uninstall key");
                        throw;
                    }
                }
            }
        }
        return apps;
    }

    private static IReadOnlyList<string> ReadOfficeAppPaths()
    {
        var result = new List<string>();
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            foreach (string exe in new[] { "WINWORD.EXE", "OUTLOOK.EXE" })
            {
                using var key = machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\" + exe);
                if (key?.GetValue("", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string target)
                    result.Add(target);
            }
        }
        return result;
    }

    /// <summary>"C:\App\app.exe,0" → "C:\App\app.exe"; only keep .exe icons.</summary>
    private static string? StripIconIndex(string? displayIcon)
    {
        if (string.IsNullOrWhiteSpace(displayIcon)) return null;
        var s = displayIcon.Trim().Trim('"');
        int comma = s.LastIndexOf(',');
        if (comma > 0 && comma > s.LastIndexOf('\\')) s = s.Substring(0, comma);
        s = s.Trim().Trim('"');
        return s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? s : null;
    }
}
