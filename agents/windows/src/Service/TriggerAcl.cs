using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Patched.Shared.Paths;

namespace Patched.Service;

/// <summary>
/// Creates the ACL-hardened trigger directory on service start (PAT-307).
///
/// Windows equivalent of macOS sticky mode-1733 (sticky + rwx + wx + wx):
///
///   SYSTEM                GENERIC_ALL,         inherit (container + object)
///   BUILTIN\Administrators GENERIC_ALL,         inherit (container + object)
///   CREATOR OWNER         GENERIC_ALL,         inherit (object + container, inherit-only)
///   Authenticated Users   FILE_ADD_FILE only,  directory only (no inherit)
///                         — can create trigger files, NOT list/read/delete others'
///
/// The CREATOR OWNER ACE gives each file's author ownership of their own file,
/// replicating the sticky-bit "only owner can delete" semantic.
/// The service (SYSTEM) has full control and can read + delete any trigger.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TriggerAcl
{
    private readonly ILogger<TriggerAcl> _log;
    private readonly string              _triggerDir;

    public TriggerAcl(ILogger<TriggerAcl> log) : this(log, PathConstants.TriggerDir)
    {
    }

    /// <summary>
    /// PAT-1774: test seam — the same ACL logic with the trigger directory redirected
    /// to a scratch path, so a test can exercise <see cref="EnsureTriggerDirectory"/>
    /// (which creates a directory and sets a real DACL on it) without ever touching
    /// the real %ProgramData%\Patched\triggers. Production always uses the public
    /// constructor.
    /// </summary>
    internal TriggerAcl(ILogger<TriggerAcl> log, string triggerDir)
    {
        _log        = log;
        _triggerDir = triggerDir;
    }

    public void EnsureTriggerDirectory()
    {
        var dir = _triggerDir;
        if (!Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
            _log.LogInformation("Created trigger directory {Dir}", dir);
        }
        ApplyDacl(dir);
    }

    private void ApplyDacl(string dir)
    {
        var info = new DirectoryInfo(dir);
        var acl  = new DirectorySecurity();

        // Disable inheritance from parent so we control DACL explicitly.
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var authUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
        var creatorOwner = new SecurityIdentifier(WellKnownSidType.CreatorOwnerSid, null);

        // SYSTEM — full control, propagates into all children.
        acl.AddAccessRule(new FileSystemAccessRule(
            system,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        // Administrators — full control, propagates into all children.
        acl.AddAccessRule(new FileSystemAccessRule(
            admins,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        // CREATOR OWNER — full control on objects/containers they create (inherit-only, not on dir itself).
        acl.AddAccessRule(new FileSystemAccessRule(
            creatorOwner,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.InheritOnly,
            AccessControlType.Allow));

        // Authenticated Users — can only CREATE new files in this directory.
        // Does NOT get LIST, READ, DELETE_CHILD, or WRITE_DAC.
        // WriteData on a directory = permission to create a new file.
        acl.AddAccessRule(new FileSystemAccessRule(
            authUsers,
            FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Synchronize,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow));

        info.SetAccessControl(acl);
        _log.LogDebug("ACL applied to trigger directory {Dir}", dir);
    }
}
