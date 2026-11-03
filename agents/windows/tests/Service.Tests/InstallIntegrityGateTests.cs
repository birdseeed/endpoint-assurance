using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Shared.Security;
using Xunit;
using Ace = Patched.Shared.Security.InstallDirectoryAclPolicy.Ace;

namespace Patched.Service.Tests;

// PAT-2399: the service verifies its own install directory and executable before privileged
// work, and an untrusted one is a logged, reported degraded state, never a silent refusal.
public sealed class InstallIntegrityGateTests : IDisposable
{
    private const string LocalSystem = InstallDirectoryAclPolicy.LocalSystemSid;
    private const string Admins = InstallDirectoryAclPolicy.AdministratorsSid;
    private const string Users = "S-1-5-32-545";
    private static readonly string[] Trustees = [LocalSystem, Admins, Users];   // ordinal order
    private static readonly string Install = Path.Combine(Path.GetTempPath(), "Patched");
    private static readonly string Exe = Path.Combine(Install, "Patched.Service.exe");
    // The MSI's explicit ACL. Kept in step with Product.wxs by test_install_directory_acl.py.
    private const string MsiSddl = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

    private static readonly InstallIntegrityGate.ObjectSecurity Healthy = new(false, LocalSystem,
        [new Ace(LocalSystem, 0x1F01FF, true, false), new Ace(Admins, 0x1F01FF, true, false), new Ace(Users, 0x1200A9, true, false)]);

    private readonly string _dir = Directory.CreateTempSubdirectory("patched-install-integrity-").FullName;
    private readonly ListLogger _log = new();
    private readonly AgentHealthStore _health;

    public InstallIntegrityGateTests() =>
        _health = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, Path.Combine(_dir, "agent-health.json"));

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private InstallIntegrityGate Gate(Func<string, bool, InstallIntegrityGate.ObjectSecurity> read) =>
        new(_log, _health, Exe, read);

    private static (string Kind, string Subject, string Reason)[] Faults(params (string Subject, string Reason)[] faults) =>
        [.. faults.Select(f => ("install_integrity", f.Subject, f.Reason))];

    private (string Kind, string Subject, string Reason)[] Degraded() =>
        [.. _health.BuildPayloadSection()!.Degraded.Select(d => (d.Kind, d.Subject, d.Reason))];

    [Fact]
    public void ATrustedInstallAllowsPrivilegedWorkAndReportsNothing()
    {
        var read = new List<(string Path, bool IsDirectory)>();
        var gate = Gate((path, isDirectory) => { read.Add((path, isDirectory)); return Healthy; });

        Assert.True(gate.Verify("self-update"));
        Assert.Equal([(Install, true), (Exe, false)], read);
        Assert.Empty(Degraded());
        Assert.Empty(_log.Entries);
        Assert.NotNull(_health.GetLastSuccess("install_integrity", "install_directory"));
        Assert.NotNull(_health.GetLastSuccess("install_integrity", "service_executable"));
    }

    [Fact]
    public void AnUntrustedDirectoryRefusesLogsAnErrorAndIsReportedUntilItIsFixed()
    {
        var directory = Healthy with { Aces = [.. Healthy.Aces, new Ace(Users, 0x1301BF, true, false)] };
        var gate = Gate((_, isDirectory) => isDirectory ? directory : Healthy);

        Assert.False(gate.Verify("self-update staging"));

        Assert.Equal(Faults(("install_directory", "untrusted_acl")), Degraded());
        var line = Assert.Single(_log.Entries);
        Assert.Equal(LogLevel.Error, line.Level);
        Assert.Contains("self-update staging", line.Message);
        Assert.Contains("untrusted_acl", line.Message);
        Assert.Contains($"principal={Users} rights=0x001301BF", line.Message);
        // The principal stays in the local log, never on the wire.
        Assert.DoesNotContain(Users, JsonSerializer.Serialize(_health.BuildPayloadSection()));

        // Re-read on every call: once an administrator repairs the ACL the fault clears.
        directory = Healthy;
        Assert.True(gate.Verify("self-update staging"));
        Assert.Empty(Degraded());
    }

    [Theory]
    [InlineData(true, "install_directory")]
    [InlineData(false, "service_executable")]
    public void EachObjectIsReportedUnderItsOwnSubject(bool directoryIsBad, string subject)
    {
        var bad = Healthy with { Owner = "S-1-5-21-1-2-3-1001" };
        Assert.False(Gate((_, isDirectory) => isDirectory == directoryIsBad ? bad : Healthy).Verify("helper"));
        Assert.Equal(Faults((subject, "untrusted_owner")), Degraded());
    }

    [Fact]
    public void AReparsePointIsRefused()
    {
        Assert.False(Gate((_, isDirectory) => isDirectory ? Healthy with { ReparsePoint = true } : Healthy).Verify("x"));
        Assert.Equal(Faults(("install_directory", "reparse_point")), Degraded());
    }

    [Fact]
    public void AnAclThatCannotBeReadIsUnverifiableAndRefusesRatherThanPassing()
    {
        Assert.False(Gate((_, _) => throw new UnauthorizedAccessException(@"C:\secret")).Verify("x"));
        Assert.Equal(Faults(("install_directory", "unverifiable"), ("service_executable", "unverifiable")),
            Degraded().Order().ToArray());
        Assert.All(_log.Entries, e => Assert.DoesNotContain("secret", e.Message));
    }

    [Fact]
    public void AnUnknownProcessPathIsUnverifiable()
    {
        Assert.False(new InstallIntegrityGate(_log, _health, null, (_, _) => Healthy).Verify("x"));
        Assert.Contains(("install_integrity", "install_directory", "unverifiable"), Degraded());
    }

    // ── Windows only: real ACLs on a real directory, through the production reader ──

    // Applies the MSI's SDDL to a temp directory that already holds a file, as a major upgrade
    // over a non-empty directory does. Returns the directory and the file.
    private (string Directory, string File) RealInstall()
    {
        var install = Directory.CreateDirectory(Path.Combine(_dir, "Patched")).FullName;
        var exe = Path.Combine(install, "Patched.Service.exe");
        File.WriteAllText(exe, "fixture");
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm(MsiSddl, AccessControlSections.Access);
        new DirectoryInfo(install).SetAccessControl(security);
        return (install, exe);
    }

    private static void Add(string directory, string sid, FileSystemRights rights, bool inheritOnly)
    {
        var info = new DirectoryInfo(directory);
        var security = info.GetAccessControl(AccessControlSections.Access);
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), rights,
            inheritOnly ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None,
            inheritOnly ? PropagationFlags.InheritOnly : PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(security);
    }

    // The owner of a temp directory is whoever runs the tests (Administrators when elevated, as
    // in CI; the user otherwise), so the DACL is judged with a trusted owner and the owner the
    // reader returns is checked against Windows separately.
    private static InstallDirectoryAclPolicy.Finding? AclFinding(string path, bool isDirectory)
    {
        var read = InstallIntegrityGate.ReadWindows(path, isDirectory);
        return InstallDirectoryAclPolicy.Evaluate(read.ReparsePoint, LocalSystem, read.Aces);
    }

    [WindowsFact]
    public void TheMsiAclOnARealDirectoryIsProtectedAndPassesForTheDirectoryAndTheFileInside()
    {
        var (install, exe) = RealInstall();

        var read = InstallIntegrityGate.ReadWindows(install, isDirectory: true);
        Assert.Equal(new DirectoryInfo(install).GetAccessControl().GetOwner(typeof(SecurityIdentifier))!.Value, read.Owner);
        Assert.Equal(Trustees, read.Aces.Select(a => a.Sid).Distinct().Order(StringComparer.Ordinal).ToArray());
        Assert.True(new DirectoryInfo(install).GetAccessControl().AreAccessRulesProtected);
        Assert.Null(AclFinding(install, isDirectory: true));
        // The file takes its ACL from the directory: nothing but SYSTEM, Administrators and Users.
        Assert.Null(AclFinding(exe, isDirectory: false));
        Assert.Equal(Trustees, InstallIntegrityGate.ReadWindows(exe, false).Aces.Select(a => a.Sid).Distinct()
            .Order(StringComparer.Ordinal).ToArray());
    }

    [WindowsTheory]
    [InlineData(false)]   // Users: Modify on the directory itself
    [InlineData(true)]    // Users: Modify, inherit-only, so on everything created inside it
    public void UsersModifyOnARealDirectoryIsUntrusted(bool inheritOnly)
    {
        var (install, _) = RealInstall();
        Add(install, Users, FileSystemRights.Modify, inheritOnly);

        var finding = AclFinding(install, isDirectory: true);
        Assert.Equal(InstallDirectoryAclPolicy.UntrustedAcl, finding?.Reason);
        Assert.Equal(Users, finding?.Sid);
    }

    [WindowsFact]
    public void UsersModifyOnTheRealExecutableIsUntrusted()
    {
        var (_, exe) = RealInstall();
        var info = new FileInfo(exe);
        var security = info.GetAccessControl(AccessControlSections.Access);
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(Users), FileSystemRights.Modify, AccessControlType.Allow));
        info.SetAccessControl(security);

        Assert.Equal(InstallDirectoryAclPolicy.UntrustedAcl, AclFinding(exe, isDirectory: false)?.Reason);
    }

    [WindowsFact]
    public void ARealDirectoryLinkIsAReparsePoint()
    {
        var (install, _) = RealInstall();
        var link = Path.Combine(_dir, "link");
        Directory.CreateSymbolicLink(link, install);

        Assert.True(InstallIntegrityGate.ReadWindows(link, isDirectory: true).ReparsePoint);
        Assert.Equal(InstallDirectoryAclPolicy.ReparsePoint, AclFinding(link, isDirectory: true)?.Reason);
    }

    [WindowsFact]
    public void TheGateRunsEndToEndAgainstARealDirectory()
    {
        var (install, exe) = RealInstall();
        Add(install, Users, FileSystemRights.Modify, inheritOnly: false);

        Assert.False(new InstallIntegrityGate(_log, _health, exe, InstallIntegrityGate.ReadWindows).Verify("x"));
        Assert.Contains(Degraded(), d => d is ("install_integrity", "install_directory", _));
    }

    private const string WindowsOnly = "Requires real Windows ACLs.";

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute() { if (!OperatingSystem.IsWindows()) Skip = WindowsOnly; }
    }

    private sealed class WindowsTheoryAttribute : TheoryAttribute
    {
        public WindowsTheoryAttribute() { if (!OperatingSystem.IsWindows()) Skip = WindowsOnly; }
    }

    private sealed class ListLogger : ILogger<InstallIntegrityGate>
    {
        internal List<(LogLevel Level, string Message)> Entries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Entries.Add((logLevel, formatter(state, exception)));
    }
}
