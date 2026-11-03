using Patched.Shared.Apps;
using Xunit;

namespace Patched.Shared.Tests;

public sealed class PerUserAppVersionTests
{
    [Fact]
    public void RunningServiceVersionCanOnlyReplaceMachineAgentVersion()
    {
        var scan = RegistryAppCollection.Scan(new Reader(), (_, _, _) => "0.99.1");
        Assert.Equal("0.99.1", Assert.Single(scan.Apps, a => a.UserAccount is null).Version);
        Assert.Equal("1.2.3", Assert.Single(scan.Apps, a => a.UserAccount == "LAB\\synthetic").Version);
    }

    private sealed class Reader : IAppRegistryReader
    {
        public bool Is64BitOperatingSystem => true;
        public string? ResolveAccountName(string sid) => "LAB\\synthetic";
        public IAppRegistryKey OpenMachine() => new Hive();
        public IAppRegistryKey OpenUsers() => new Users();
    }
    private sealed class Users : IAppRegistryKey
    {
        public IEnumerable<string> GetSubKeyNames() => ["S-1-5-21-100-200-300-1001"];
        public IAppRegistryKey? OpenSubKey(string path) => new Hive();
        public object? GetValue(string name) => null;
        public void Dispose() { }
    }
    private sealed class Hive : IAppRegistryKey
    {
        public IEnumerable<string> GetSubKeyNames() => [];
        public IAppRegistryKey? OpenSubKey(string path) => path == RegistryAppCollection.NativePath ? new Uninstall() : null;
        public object? GetValue(string name) => null;
        public void Dispose() { }
    }
    private sealed class Uninstall : IAppRegistryKey
    {
        public IEnumerable<string> GetSubKeyNames() => ["SyntheticAgent"];
        public IAppRegistryKey? OpenSubKey(string path) => new Entry();
        public object? GetValue(string name) => null;
        public void Dispose() { }
    }
    private sealed class Entry : IAppRegistryKey
    {
        public IEnumerable<string> GetSubKeyNames() => [];
        public IAppRegistryKey? OpenSubKey(string path) => null;
        public object? GetValue(string name) => name switch
            { "DisplayName" => "Patched Agent", "Publisher" => "Patched", "DisplayVersion" => "1.2.3", _ => null };
        public void Dispose() { }
    }
}
