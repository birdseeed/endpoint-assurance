using System.Security.AccessControl;
using Patched.Shared.Security;

namespace Patched.Service;

/// <summary>
/// PAT-2399: verifies the directory this service runs from, and its own executable, before
/// privileged work that runs code from that directory or from staged content. The rule is
/// <see cref="InstallDirectoryAclPolicy"/>; the macOS equivalent is PAT-2395 / PAT-2398.
///
/// Why the service keeps running on a failure instead of refusing to start. A service that
/// will not start reports nothing: no inventory, no agent health, and to the platform it is
/// indistinguishable from a device that is switched off. So an untrusted install is a
/// degraded state that is logged as an error and recorded in agent health as
/// install_integrity / install_directory|service_executable / untrusted_owner|untrusted_acl|
/// reparse_point|unverifiable, which the next inventory upload carries. What is refused is
/// the work that would turn a writable directory into code execution as SYSTEM: applying a
/// staged self-update, staging a new one, and (through the same rule in the helper preflight)
/// launching the evidence helpers. Collection and reporting continue.
///
/// The objects are re-read on every call, so a repaired ACL clears the fault at the next
/// check without a restart and one broken after start-up is caught at the next check.
///
/// This is not a lock: the answer can change between the read and the work it gates, and a
/// replaced binary does not run this check at all. See InstallDirectoryAclPolicy for the limit.
/// </summary>
internal sealed class InstallIntegrityGate
{
    internal const string HealthKind = "install_integrity";
    internal const string DirectorySubject = "install_directory";
    internal const string ExecutableSubject = "service_executable";

    internal sealed record ObjectSecurity(bool ReparsePoint, string? Owner, IReadOnlyList<InstallDirectoryAclPolicy.Ace> Aces);

    private readonly ILogger<InstallIntegrityGate> _log;
    private readonly AgentHealthStore _health;
    private readonly string? _executable;
    private readonly Func<string, bool, ObjectSecurity> _read;

    // The running executable, not a fixed Program Files path: what matters is the code that is
    // actually running as SYSTEM, wherever an administrator had the MSI put it.
    public InstallIntegrityGate(ILogger<InstallIntegrityGate> log, AgentHealthStore health)
        : this(log, health, Environment.ProcessPath, ReadWindows) { }

    internal InstallIntegrityGate(ILogger<InstallIntegrityGate> log, AgentHealthStore health, string? executable,
        Func<string, bool, ObjectSecurity> read)
    {
        _log = log;
        _health = health;
        _executable = executable;
        _read = read;
    }

    /// <summary>
    /// True when both objects are trusted. Never throws. <paramref name="action"/> names the
    /// work being gated, for the log line only.
    /// </summary>
    internal bool Verify(string action)
    {
        var directory = string.IsNullOrEmpty(_executable) ? null : Path.GetDirectoryName(_executable);
        var directoryTrusted = Check(DirectorySubject, directory, isDirectory: true, action);
        var executableTrusted = Check(ExecutableSubject, _executable, isDirectory: false, action);
        return directoryTrusted && executableTrusted;
    }

    private bool Check(string subject, string? path, bool isDirectory, string action)
    {
        InstallDirectoryAclPolicy.Finding? finding;
        try
        {
            if (string.IsNullOrEmpty(path)) finding = new(InstallDirectoryAclPolicy.Unverifiable, null, 0);
            else
            {
                var read = _read(path, isDirectory);
                finding = InstallDirectoryAclPolicy.Evaluate(read.ReparsePoint, read.Owner, read.Aces);
            }
        }
        catch (Exception ex)
        {
            // The exception type only: a message can carry a path.
            _log.LogError("install-integrity: could not read {Subject} ({Error})", subject, ex.GetType().Name);
            finding = new(InstallDirectoryAclPolicy.Unverifiable, null, 0);
        }

        try
        {
            if (finding is not { } refused)
            {
                _health.RecordSuccess(HealthKind, subject);
                return true;
            }
            _log.LogError(
                "install-integrity: {Subject} {Path} is not trusted: {Reason} principal={Sid} rights=0x{Rights:X8}. " +
                "Refusing {Action}; inventory and health reporting continue. Expected owner SYSTEM, Administrators or " +
                "TrustedInstaller and no write access for anyone else (reinstalling the agent MSI resets the ACL).",
                subject, path ?? "unknown", refused.Reason, refused.Sid ?? "none", refused.Mask, action);
            _health.RecordFailure(HealthKind, subject, refused.Reason);
        }
        catch
        {
            // Reporting must not turn a verdict into a crash; the verdict below still stands.
        }
        return finding is null;
    }

    internal static ObjectSecurity ReadWindows(string path, bool isDirectory)
    {
        var attributes = File.GetAttributes(path);
        if (attributes.HasFlag(FileAttributes.ReparsePoint)) return new(true, null, []);
        if (attributes.HasFlag(FileAttributes.Directory) != isDirectory) throw new IOException("unexpected_object_type");
        const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Access;
        FileSystemSecurity security = isDirectory
            ? new DirectoryInfo(path).GetAccessControl(sections)
            : new FileInfo(path).GetAccessControl(sections);
        var (owner, entries) = WindowsInstallationEvidence.ReadAcl(security);
        return new(false, owner, [.. entries.Select(WindowsInstallationEvidence.ToPolicyAce)]);
    }
}
