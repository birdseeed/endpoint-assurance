using System.Runtime.Versioning;
using Microsoft.Win32;
using Patched.Shared.Apps;

namespace Patched.Service;

[SupportedOSPlatform("windows")]
internal sealed class AppRegistryReader(ILogger log) : IAppRegistryReader
{
    public bool Is64BitOperatingSystem => Environment.Is64BitOperatingSystem;
    public IAppRegistryKey OpenMachine() => new Key(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,
        Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32));
    public IAppRegistryKey OpenUsers() => new Key(RegistryKey.OpenBaseKey(RegistryHive.Users,
        Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32));
    public string? ResolveAccountName(string sid) => WindowsUserProfiles.ResolveAccountName(sid, log);
    // HKLM ProfileList only: never the user's hive, and never NTUSER.DAT.
    public string? ResolveProfilePath(string sid)
    {
        using var key = Registry.LocalMachine.OpenSubKey(
            $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}", writable: false);
        return key?.GetValue("ProfileImagePath")?.ToString();
    }
    private sealed class Key(RegistryKey key) : IAppRegistryKey
    {
        public IEnumerable<string> GetSubKeyNames() => key.GetSubKeyNames();
        public IAppRegistryKey? OpenSubKey(string path) => key.OpenSubKey(path, writable: false) is { } child
            ? new Key(child) : null;
        public object? GetValue(string name) => key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        public void Dispose() => key.Dispose();
    }
}
