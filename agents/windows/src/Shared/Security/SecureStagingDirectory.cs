using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Patched.Shared.Paths;

namespace Patched.Shared.Security;

/// <summary>
/// Hardens a staging directory used for SYSTEM-privileged downloads (winget/Chocolatey
/// installer artifacts) before anything is written into or read back from it. (PAT-857)
///
/// Root cause this guards against: for the LocalSystem service, <c>Path.GetTempPath()</c>
/// resolves to <c>C:\Windows\Temp</c>, a directory any authenticated user can create
/// subdirectories in. A predictable subpath there lets a standard user pre-create the
/// directory (or plant a reparse point/junction at that path) before the service ever
/// runs. <c>Directory.CreateDirectory</c> silently no-ops on an existing path and applies
/// no ACL/ownership check, so the file the agent is about to Authenticode-verify (or
/// SHA-256-check) can be swapped, or SYSTEM can be made to write through a junction into
/// an arbitrary directory (TOCTOU).
///
/// Mirrors the pattern <see cref="Patched.Service.TriggerAcl"/> already uses for the
/// trigger drop directory (explicit, non-inherited DACL applied on every use), but with
/// no "Authenticated Users" grant at all: nothing but SYSTEM/Administrators may write
/// here, ever. Every directory level between <see cref="PathConstants.StateDir"/>
/// (%ProgramData%\Patched itself) and the leaf staging directory is hardened
/// individually (see <see cref="EnsureHardenedChain"/>) rather than trusting that an
/// ancestor — including StateDir — was already created/verified by something else (a
/// fresh, damaged, or repaired install could reach this code before the MSI's own
/// StateDir ACL baseline is in place; a standard user able to pre-plant StateDir itself
/// as a junction, before it exists, is exactly the same TOCTOU one level up).
///
/// Fails closed: a directory that is a reparse point, or not owned by SYSTEM or
/// Administrators, is never "fixed" in place; the caller gets an exception and must
/// abort the operation.
/// </summary>
[SupportedOSPlatform("windows")]
public static class SecureStagingDirectory
{
    /// <summary>
    /// Random staging subdirectories created via <see cref="CreateRandomSubdirectory"/>
    /// older than this are purged the next time that root is used. Bounds disk growth —
    /// unlike the old deterministic %TEMP% path (one folder per package, overwritten on
    /// each attempt), a fresh GUID folder is created per call and nothing else ever
    /// deletes it. Generous relative to the seconds a download+verify cycle takes.
    /// </summary>
    private static readonly TimeSpan MaxStagingAge = TimeSpan.FromHours(1);

    /// <summary>Thrown when a staging directory fails the reparse-point or ownership check.</summary>
    public sealed class UntrustedDirectoryException(string message) : Exception(message);

    /// <summary>
    /// Ensures <paramref name="root"/> is hardened, purges any stale randomised
    /// subdirectories left under it from previous calls, then creates and returns a
    /// freshly randomised (GUID-named) subdirectory under it, hardened and verified
    /// before use.
    ///
    /// Use this when the caller doesn't need a path that's reproducible across calls
    /// (e.g. a single download-then-verify-then-return operation). This only hardens
    /// <paramref name="root"/> itself, not its ancestors — callers whose root sits
    /// several levels below a trusted anchor (e.g. <see cref="PathConstants.StateDir"/>)
    /// should call <see cref="EnsureHardenedChain"/> on <paramref name="root"/> first.
    /// </summary>
    public static string CreateRandomSubdirectory(string root)
    {
        EnsureHardened(root);
        PurgeStale(root);

        string dir;
        do
        {
            dir = Path.Combine(root, Guid.NewGuid().ToString("N"));
        } while (Directory.Exists(dir));

        // Do NOT pre-create `dir` here — EnsureHardened must see it as missing so it
        // takes the create-then-ApplyDacl branch itself. Creating it first would make
        // EnsureHardened's Directory.Exists(dir) check true and skip ApplyDacl entirely,
        // leaving this subdirectory without its own explicit protected DACL.
        EnsureHardened(dir);
        return dir;
    }

    /// <summary>
    /// Hardens every directory level from <paramref name="root"/> down to
    /// <paramref name="dir"/> (inclusive), individually, in parent-to-child order.
    /// <paramref name="dir"/> must be <paramref name="root"/> itself or a subdirectory
    /// of it.
    ///
    /// Applying the DACL only to a leaf directory and trusting the parent chain to have
    /// inherited it (or to already be hardened) leaves a gap: an intermediate segment
    /// created implicitly by <c>Directory.CreateDirectory</c>'s recursive parent creation
    /// never gets its own explicit, protected DACL, and a symlink/junction planted at an
    /// intermediate segment before it exists would be followed transparently by a
    /// leaf-only reparse-point check. Walking the whole chain closes both gaps.
    ///
    /// Production callers pass <see cref="PathConstants.StateDir"/> (%ProgramData%\Patched
    /// itself, NOT <see cref="PathConstants.StagingDir"/>) as <paramref name="root"/>, so
    /// StateDir is verified/hardened too — not just its "staging" child. Anchoring one
    /// level below StateDir would leave StateDir's own creation unguarded on a fresh or
    /// damaged install, reopening the same TOCTOU this class exists to close (PAT-857
    /// non-author-review finding).
    /// </summary>
    public static void EnsureHardenedChain(string dir, string root)
    {
        var fullDir  = Path.GetFullPath(dir);
        var fullRoot = Path.GetFullPath(root);

        if (!fullDir.Equals(fullRoot, StringComparison.OrdinalIgnoreCase) &&
            !fullDir.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"'{dir}' is not under the root '{root}'.", nameof(dir));
        }

        EnsureHardened(fullRoot);

        var relative = Path.GetRelativePath(fullRoot, fullDir);
        if (relative == ".") return;

        var current = fullRoot;
        foreach (var segment in relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
        {
            if (segment.Length == 0) continue;
            current = Path.Combine(current, segment);
            EnsureHardened(current);
        }
    }

    /// <summary>
    /// Ensures <paramref name="dir"/> exists and passes the pre-use trust check (not a
    /// reparse point, owned by SYSTEM or Administrators).
    ///
    /// If the directory does not exist, it is created and hardened (SYSTEM +
    /// Administrators full control only, DACL protected from inheritance) — this is our
    /// own brand-new object, so applying our DACL to it is safe.
    ///
    /// If the directory already exists, its ACL is deliberately left untouched, only
    /// verified. Re-applying (or "fixing") a DACL onto a directory that might have been
    /// planted by an attacker before this code ever ran would legitimise it; instead we
    /// fail closed and let the caller abort the operation.
    /// </summary>
    public static void EnsureHardened(string dir)
    {
        if (IsReparsePoint(dir))
        {
            throw new UntrustedDirectoryException(
                $"Refusing to use staging directory '{dir}': it already exists as a " +
                "reparse point or junction, not a plain directory. Not touching it.");
        }

        if (!Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);

            // Defensive re-check: the path should be a brand-new plain directory we
            // just created under an (assumed) hardened parent. This should never trip,
            // but if it somehow does, refuse rather than harden/trust it.
            if (IsReparsePoint(dir))
            {
                throw new UntrustedDirectoryException(
                    $"Refusing to use staging directory '{dir}': became a reparse point " +
                    "immediately after creation.");
            }

            ApplyDacl(dir);
        }

        // Pre-existing or freshly created, either way, verify before trusting it.
        VerifyTrusted(dir);
    }

    /// <summary>
    /// Establishes the protected DACL on a fixed, installer-provisioned state path.
    /// This is deliberately narrower than <see cref="EnsureHardened"/>: unlike
    /// per-operation staging paths, the MSI may already have created StateDir or one
    /// of its declared children with a trusted SYSTEM/Administrators owner but
    /// inherited write-capable ACEs from its parent. That is an installer baseline to
    /// correct, not an attacker path to legitimise.
    ///
    /// An existing directory is eligible for that repair only after it has proved to
    /// be a plain directory owned by SYSTEM or Administrators. A reparse point or an
    /// untrusted owner is never modified. Callers must use this only for a fixed,
    /// installer-owned directory, never for a
    /// caller-selected staging path. Credential ancestors pass repairExisting=false,
    /// which verifies existing directories without any DACL writes and refuses unsafe
    /// legacy contents. <paramref name="allowStandardUserRead"/> is
    /// reserved for that state root: the Tray and Self Service clients read selected
    /// root-level status contracts but must never gain write access or access to child
    /// directories such as creds.
    /// </summary>
    /// <returns>
    /// <see langword="true"/> when an existing trusted-owner directory carried an
    /// unsafe DACL before this call repaired it. Callers use that signal to avoid
    /// treating pre-existing contents as newly trustworthy merely because their
    /// containing directory is now protected.
    /// </returns>
    internal static bool EnsureHardenedTrustedInstallerDirectory(
        string dir, bool allowStandardUserRead = false, bool repairExisting = true)
    {
        if (!Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);

            if (IsReparsePoint(dir))
            {
                throw new UntrustedDirectoryException(
                    $"Refusing to use state directory '{dir}': became a reparse point " +
                    "immediately after creation.");
            }

            // Directory.CreateDirectory is not exclusive: refuse an attacker-owned
            // object that won the creation race before applying any privileged ACL.
            VerifyTrustedOwner(dir);
            ApplyDacl(dir, allowStandardUserRead);
            VerifyTrusted(dir);
            return false;
        }

        if (IsReparsePoint(dir))
        {
            throw new UntrustedDirectoryException(
                $"Refusing to use state directory '{dir}': it already exists as a " +
                "reparse point or junction. Not touching it.");
        }

        // Credential ancestors must never turn attacker-influenced legacy contents into
        // trusted input. Even an empty existing directory is verified without mutation.
        if (!repairExisting)
        {
            VerifyTrusted(dir);
            return false;
        }

        // Do this before changing the DACL. A standard user can neither create the
        // real ProgramData root nor set its owner to SYSTEM/Administrators; an
        // attacker-owned directory must therefore fail closed instead of being
        // upgraded to a trusted one merely because the service has started.
        VerifyTrustedOwner(dir);

        bool hadUnsafeDacl;
        try
        {
            VerifyTrusted(dir);
            hadUnsafeDacl = false;
        }
        catch (UntrustedDirectoryException)
        {
            // Ownership and reparse status were checked above. The only remaining
            // invariant VerifyTrusted can reject is a non-admin write-capable ACE.
            hadUnsafeDacl = true;
        }

        ApplyDacl(dir, allowStandardUserRead);

        // Includes a second reparse-point check plus the effective-DACL check. The
        // root is not usable until the repaired object has passed all invariants.
        VerifyTrusted(dir);
        return hadUnsafeDacl;
    }

    /// <summary>
    /// Raw Windows GENERIC_* access-mask bits (winnt.h). These are NOT members of
    /// <see cref="FileSystemRights"/> — that enum only models the object-specific
    /// (mapped) rights — but a raw ACE can still carry an un-mapped generic bit
    /// directly (e.g. an ACE built via a native API or tool that never called
    /// MapGenericMask). GENERIC_ALL/GENERIC_WRITE grant write capability just as much
    /// as any specific right; a check that only looked at named FileSystemRights
    /// members would treat such an ACE as read-only and wrongly trust it (PAT-857
    /// non-author-review finding).
    /// </summary>
    private const FileSystemRights GenericAll   = (FileSystemRights)0x10000000;
    private const FileSystemRights GenericWrite = (FileSystemRights)0x40000000;

    /// <summary>
    /// Any right that could be used to create, replace, delete, or otherwise tamper with
    /// a file or subdirectory — the named <see cref="FileSystemRights"/> members plus the
    /// raw GENERIC_ALL/GENERIC_WRITE bits (see <see cref="GenericAll"/>/<see cref="GenericWrite"/>).
    /// Deliberately excludes pure read/list/traverse/synchronize rights: a principal with
    /// only those cannot plant or swap a file, so granting them (e.g. an inherited
    /// "Users: Read &amp; Execute" from %ProgramData%'s own default ACL) is not a TOCTOU
    /// risk and must not fail-close a directory that is otherwise correctly hardened.
    /// </summary>
    private const FileSystemRights WriteCapableRights =
        FileSystemRights.WriteData | FileSystemRights.AppendData |
        FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories |
        FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership |
        GenericAll | GenericWrite;

    /// <summary>
    /// Verifies <paramref name="dir"/> is not a reparse point, is owned by SYSTEM or
    /// Administrators, AND that its effective DACL grants no write-capable access to any
    /// other principal. Does not modify anything. Throws
    /// <see cref="UntrustedDirectoryException"/> on failure (fail closed).
    ///
    /// Checking ownership alone is not enough (PAT-857 non-author-review finding): a
    /// directory can be *owned* by SYSTEM/Administrators while still carrying an ACE that
    /// grants some other principal (Users, Authenticated Users, Everyone) write access —
    /// inherited from a permissive ancestor, or added by another process/admin after the
    /// fact. Trusting owner alone would let a standard user still write into (and plant a
    /// file in) a directory that merely *looks* trusted. So every write-capable Allow ACE
    /// — explicit or inherited — must belong to SYSTEM or Administrators; a pure-read
    /// grant to some other principal (see <see cref="WriteCapableRights"/>) is harmless
    /// and allowed, since this chain now includes <see cref="PathConstants.StateDir"/>
    /// itself, which typically carries a benign inherited read grant from %ProgramData%'s
    /// own default ACL.
    /// </summary>
    public static void VerifyTrusted(string dir)
    {
        if (IsReparsePoint(dir))
        {
            throw new UntrustedDirectoryException(
                $"Staging directory '{dir}' is a reparse point or junction. Refusing to use it.");
        }

        VerifyTrustedOwner(dir);

        var info = new DirectoryInfo(dir);
        VerifyTrustedAccessRules(info.GetAccessControl(AccessControlSections.Access), dir, "directory");
    }

    /// <summary>
    /// PAT-2400: the same reparse-point, owner and DACL rules as <see cref="VerifyTrusted"/>
    /// (SYSTEM or Administrators own it; no other principal holds a write-capable Allow
    /// ACE), for a file or a directory, as a reason token instead of an exception. Null
    /// when trusted; otherwise <c>absent</c>, <c>reparse_point</c>, <c>wrong_type</c>,
    /// <c>untrusted_owner</c> or <c>untrusted_acl</c>. Modifies nothing. The ACL is read by
    /// path, so the reparse check is repeated after it; a swap inside that read is not
    /// excluded (no handle is held).
    /// </summary>
    internal static string? DescribeUntrusted(string path, bool isDirectory, bool requirePrivate = false)
    {
        FileAttributes attributes;
        try { attributes = File.GetAttributes(path); }
        catch (FileNotFoundException) { return "absent"; }
        catch (DirectoryNotFoundException) { return "absent"; }

        if ((attributes & FileAttributes.ReparsePoint) != 0) return "reparse_point";
        if (((attributes & FileAttributes.Directory) != 0) != isDirectory) return "wrong_type";

        const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Access;
        FileSystemSecurity acl = isDirectory
            ? new DirectoryInfo(path).GetAccessControl(sections)
            : new FileInfo(path).GetAccessControl(sections);
        if (IsReparsePoint(path)) return "reparse_point";

        string objectType = isDirectory ? "directory" : "file";
        try { VerifyTrustedOwner(acl, path, objectType); }
        catch (UntrustedDirectoryException) { return "untrusted_owner"; }
        try { VerifyTrustedAccessRules(acl, path, objectType); }
        catch (UntrustedDirectoryException) { return "untrusted_acl"; }
        if (requirePrivate)
        {
            try { VerifyPrivateAccessRules(acl, path); }
            catch (UntrustedDirectoryException) { return "exposed_acl"; }
        }
        return null;
    }

    private static void VerifyTrustedOwner(string dir) =>
        VerifyTrustedOwner(new DirectoryInfo(dir).GetAccessControl(AccessControlSections.Owner), dir, "directory");

    internal static void VerifyTrustedOwner(FileSystemSecurity acl, string path, string objectType)
    {
        var owner = acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;

        if (owner is null)
        {
            throw new UntrustedDirectoryException(
                $"Could not resolve an owner SID for state {objectType} '{path}'.");
        }

        var isSystem = owner.IsWellKnown(WellKnownSidType.LocalSystemSid);
        var isAdmins = owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
        if (!isSystem && !isAdmins)
        {
            throw new UntrustedDirectoryException(
                $"State {objectType} '{path}' is owned by '{owner.Value}', not SYSTEM or " +
                "Administrators. Refusing to trust it.");
        }
    }

    internal static void VerifyTrustedAccessRules(FileSystemSecurity acl, string path, string objectType)
    {
        // includeInherited: true — an inherited Allow ACE is just as usable by an
        // attacker as an explicit one; both must be checked.
        var rules = acl.GetAccessRules(
            includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));

        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            if ((rule.FileSystemRights & WriteCapableRights) == 0) continue; // read-only; harmless

            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (sid.IsWellKnown(WellKnownSidType.LocalSystemSid)) continue;
            if (sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)) continue;

            throw new UntrustedDirectoryException(
                $"State {objectType} '{path}' grants write-capable access to '{sid.Value}', " +
                "which is not SYSTEM or Administrators. Refusing to trust it.");
        }
    }

    /// <summary>Credential confidentiality: no Allow ACE, explicit or inherited,
    /// may grant any access to a principal other than SYSTEM or Administrators.
    /// Deny ACEs do not confer access and therefore do not weaken this policy.</summary>
    internal static void VerifyPrivateAccessRules(FileSystemSecurity acl, string path)
    {
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (sid.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
                sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)) continue;
            throw new UntrustedDirectoryException($"Credential path '{path}' grants access to another principal.");
        }
    }

    /// <summary>
    /// Best-effort cleanup of randomised subdirectories under <paramref name="root"/>
    /// older than <see cref="MaxStagingAge"/> (PAT-857). <see cref="CreateRandomSubdirectory"/>
    /// makes a fresh GUID-named folder on every call and nothing else reclaims it — unlike
    /// the old %TEMP% path, %ProgramData% is never cleared by the OS, so without this the
    /// staging root grows without bound over the service's lifetime. Deliberately tolerant
    /// of individual delete failures (e.g. a file still open from a concurrent operation)
    /// so one stuck directory never blocks staging a new download.
    /// </summary>
    private static void PurgeStale(string root)
    {
        if (!Directory.Exists(root)) return;

        var cutoff = DateTime.UtcNow - MaxStagingAge;
        foreach (var child in Directory.EnumerateDirectories(root))
        {
            try
            {
                if (IsReparsePoint(child)) continue; // never traverse/delete through a reparse point
                if (Directory.GetLastWriteTimeUtc(child) >= cutoff) continue;
                Directory.Delete(child, recursive: true);
            }
            catch
            {
                // Best-effort: a locked file or a race with the directory being used
                // right now must not block creating today's staging directory.
            }
        }
    }

    private static bool IsReparsePoint(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }

    private static void ApplyDacl(string dir, bool allowStandardUserRead = false)
    {
        var info = new DirectoryInfo(dir);
        var acl  = new DirectorySecurity();

        // Disable inheritance from parent so we control the DACL explicitly, same as
        // TriggerAcl.cs.
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

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

        if (allowStandardUserRead)
        {
            // Root-level status/cache files are read by the unprivileged Tray and
            // Self Service clients. ObjectInherit + NoPropagateInherit deliberately
            // applies this to files created directly under StateDir only: a child
            // directory may not pass it on to a file below it, so a subsequently
            // created creds/ or staging/ directory cannot expose secrets.
            acl.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
                InheritanceFlags.ObjectInherit,
                PropagationFlags.NoPropagateInherit,
                AccessControlType.Allow));
        }

        // No other principal gets anything: unlike the trigger directory, nothing here
        // needs a standard-user write grant.
        info.SetAccessControl(acl);
    }
}
