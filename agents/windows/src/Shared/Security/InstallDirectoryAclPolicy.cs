namespace Patched.Shared.Security;

/// <summary>
/// PAT-2399: who may write to %ProgramFiles%\Patched and to the service executable in it.
/// One rule for the directory and the file, and the only one: the start-up check
/// (InstallIntegrityGate) and the evidence-helper preflight (PAT-2116) both call it.
///
/// Pure on purpose (SID strings and raw access masks, no advapi32), so the rule is tested on
/// every platform against the ACL a real device has.
///
/// The rule:
///   * not a reparse point;
///   * owner is SYSTEM, Administrators or TrustedInstaller. An owner can always rewrite the
///     DACL, so an untrusted owner is an untrusted writer whatever the entries say;
///   * no ALLOW entry carrying a write-capable right for anyone else. Deny entries grant
///     nothing and are ignored.
///
/// TrustedInstaller is trusted because it is what Program Files hands every directory created
/// in it (so every device installed before this ticket has it) and it outranks Administrators.
/// The MSI's own ACL does not grant it: Windows Installer runs as SYSTEM, and Windows
/// servicing does not touch a third-party directory.
///
/// Inherit-only entries. One grants nothing on the directory itself, but Windows copies it
/// onto every file and folder later created inside, and that is where a major upgrade puts the
/// next service executable. So a write-capable inherit-only entry for an untrusted principal
/// is refused exactly like an effective one. The single exception is CREATOR OWNER (S-1-3-0),
/// which every Program Files directory carries: it is a placeholder that never matches a
/// token, and on a new child Windows replaces it with the child's owner, that is, whoever
/// created it. Creating a child needs an effective write right on the directory, which this
/// same rule already limits to the trusted principals, so the entry can only ever resolve to
/// one of them. That reasoning holds only while it is inherit-only; a CREATOR OWNER entry
/// that is not is judged like any other principal. CREATOR GROUP (S-1-3-1) gets no exception:
/// it resolves to the creator's primary group, which can contain other accounts.
///
/// Limit, stated once: this is detection and containment for an unmodified binary. If the
/// directory really is writable by an attacker the service executable may already have been
/// replaced, and a replaced binary does not run this check. The control is the explicit,
/// protected ACL the MSI sets (Product.wxs); this notices when it is not in force.
/// </summary>
public static class InstallDirectoryAclPolicy
{
    public const string LocalSystemSid = "S-1-5-18";
    public const string AdministratorsSid = "S-1-5-32-544";
    public const string TrustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    public const string CreatorOwnerSid = "S-1-3-0";

    // Fixed codes: these go on the wire as the agent-health reason.
    public const string UntrustedOwner = "untrusted_owner";
    public const string UntrustedAcl = "untrusted_acl";
    public const string ReparsePoint = "reparse_point";
    public const string Unverifiable = "unverifiable";

    /// <summary>
    /// Every right that lets its holder plant, replace, delete or re-permission an entry:
    /// write data / add file (0x2), append / add subdirectory (0x4), write EA (0x10), delete
    /// child (0x40), write attributes (0x100), DELETE, WRITE_DAC, WRITE_OWNER, and the
    /// unmapped GENERIC_ALL and GENERIC_WRITE bits an inherit-only entry carries.
    /// </summary>
    public const uint WriteMask = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x00010000 | 0x00040000 | 0x00080000 |
        0x10000000 | 0x40000000;

    public readonly record struct Ace(string Sid, uint Mask, bool Allow, bool InheritOnly);

    /// <summary>Sid and Mask are for the local log only, never the wire.</summary>
    public readonly record struct Finding(string Reason, string? Sid, uint Mask);

    public static bool IsTrusted(string? sid) => sid is LocalSystemSid or AdministratorsSid or TrustedInstallerSid;

    /// <summary>
    /// Null when the object is trusted, else the first reason it is not. A null
    /// <paramref name="aces"/> means the DACL could not be read, which is never a pass.
    /// </summary>
    public static Finding? Evaluate(bool reparsePoint, string? ownerSid, IEnumerable<Ace>? aces)
    {
        if (reparsePoint) return new(ReparsePoint, null, 0);
        if (aces is null) return new(Unverifiable, null, 0);
        if (!IsTrusted(ownerSid)) return new(UntrustedOwner, ownerSid, 0);
        foreach (var ace in aces)
        {
            if (!ace.Allow || (ace.Mask & WriteMask) == 0 || IsTrusted(ace.Sid)) continue;
            if (ace.InheritOnly && ace.Sid == CreatorOwnerSid) continue;
            return new(UntrustedAcl, ace.Sid, ace.Mask);
        }
        return null;
    }
}
