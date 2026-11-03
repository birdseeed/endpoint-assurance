using System.Runtime.Versioning;
using Microsoft.Win32;
using Patched.Shared.Metering;

namespace Patched.Service;

/// <summary>Read-only loaded-profile UserAssist collection; never loads an offline hive.</summary>
[SupportedOSPlatform("windows")]
public sealed class UserAssistReader
{
    private const string ExplorerKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer";
    private readonly ILogger<UserAssistReader> _log;

    public UserAssistReader(ILogger<UserAssistReader> log) => _log = log;

    public UserAssistCollection Read() => UserAssistCollection.Read(
        () => Registry.Users.GetSubKeyNames(), ReadUserHive);

    private UserAssistHive ReadUserHive(string sid)
    {
        var usages = new List<UserAssistUsage>();
        try
        {
            using var advanced = Registry.Users.OpenSubKey($@"{sid}\{ExplorerKey}\Advanced");
            // Missing means no explicit opt-out, not proof that tracking works.
            object? tracking = advanced?.GetValue("Start_TrackProgs", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (tracking is not null)
            {
                if (advanced!.GetValueKind("Start_TrackProgs") != RegistryValueKind.DWord || tracking is not int n)
                    return new(usages, ReadFailed: true);
                if (n == 0) return new(usages, TrackingDisabled: true);
                if (n != 1) return new(usages, ReadFailed: true);
            }

            using var ua = Registry.Users.OpenSubKey($@"{sid}\{ExplorerKey}\UserAssist");
            if (ua is null) return new(usages);
            foreach (var guid in ua.GetSubKeyNames())
            {
                using var count = ua.OpenSubKey($@"{guid}\Count");
                if (count is null) continue;
                foreach (var name in count.GetValueNames())
                {
                    if (count.GetValue(name) is not byte[] data) continue;
                    var usage = UserAssistRecord.TryParse(name, data);
                    if (usage is null) continue;
                    // Never expand a user's known folder against LocalSystem's profile.
                    usages.Add(usage with { Path = KnownFolders.Expand(usage.Path, folder => folder switch
                    {
                        Environment.SpecialFolder.ProgramFiles or Environment.SpecialFolder.ProgramFilesX86 or
                        Environment.SpecialFolder.System => Environment.GetFolderPath(folder),
                        _ => "",
                    }) });
                }
            }
            return new(usages);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Metering: a loaded UserAssist hive could not be fully read");
            return new(usages, ReadFailed: true);
        }
    }
}
