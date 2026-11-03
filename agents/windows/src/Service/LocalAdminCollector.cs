using System.ComponentModel;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Patched.Shared.Compliance;

namespace Patched.Service;

/// <summary>
/// PAT-1974: reads the members of the local Administrators group so the agent can report
/// the standing local administrator roster alongside the <c>local_admin_count</c>
/// compliance signal, at parity with the macOS collector (ADR-0007).
///
/// Read-only. Nothing here adds, removes or modifies a principal; the destructive
/// approved-admins pass is <see cref="AdminEnforcer"/>, a separate, tier-gated component
/// this collector deliberately does not depend on or reuse.
///
/// WHY NetLocalGroupGetMembers AND NOT THE TWO OBVIOUS ALTERNATIVES. Both of the
/// mechanisms already present in this repo fail the requirement that drove the ticket —
/// that a principal the device cannot resolve must still be reported, never silently
/// dropped (root AGENTS.md, "Absence requires authority"):
///
///   - WMI Win32_GroupUser, the association class ComplianceCollector uses elsewhere,
///     only links a group to Win32_Account instances the machine could resolve. A SID
///     left behind by a deleted account, or one belonging to an unreachable domain, has
///     no Win32_Account and simply does not appear in the association. The read would
///     report "complete" while undercounting, which is a false claim rather than a
///     degraded one.
///   - System.DirectoryServices.AccountManagement (already referenced, used by
///     AdminEnforcer) throws out of GroupPrincipal.GetMembers() part way through
///     enumeration when a member SID cannot be resolved, so one orphaned SID makes the
///     whole roster unreadable. Its FindByIdentity(ctx, "Administrators") is also a
///     literal English name lookup, which returns null on a localised Windows.
///
///   NetLocalGroupGetMembers at level 2 returns, for every member, the SID, the
///   SID_NAME_USE classification and the resolved DOMAIN\name — and returns the entry
///   classified SidTypeUnknown, with the SID's own string form in place of a resolved name,
///   rather than omitting it when resolution fails (verified against real Windows, PAT-1987
///   -- a synthetic unresolvable SID came back with lgrmi2_domainandname set to the SID
///   string itself, never empty or null). It is
///   what `net localgroup administrators` itself uses, needs no new package reference, and
///   makes no directory round-trip of its own beyond the SID lookup Windows already does.
///
/// The group is located by its well-known SID (S-1-5-32-544) translated to the local
/// name, not by the literal string "Administrators", so a localised Windows install is
/// read correctly.
///
/// PAT-1988 adds one further read, and only for the built-in Administrator (RID 500): the
/// account's own enabled state, so the server can tell a disabled built-in Administrator,
/// the common hardened-image state, from an enabled one, which is a real finding.
/// <c>builtin: true</c> on its own says nothing about that. The read is a WMI query keyed
/// on the SID rather than the account name — see <c>ReadLocalAccountState</c> for why the
/// name is the wrong key for this one account — and it is a sub-read: it cannot make the
/// roster unavailable, and it never reports "disabled" for an account it could not read.
///
/// Every decision about what the members mean lives in
/// <see cref="Patched.Shared.Compliance.LocalAdminLogic"/> so Shared.Tests covers it on
/// macOS CI; the enumeration is injectable for the same reason
/// <c>RegistryValueReader</c> is.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class LocalAdminCollector
{
    // NetLocalGroupGetMembers status codes and limits.
    private const int  NerrSuccess      = 0;
    private const int  ErrorMoreData    = 234;
    private const int  MaxPreferredLength = -1;   // MAX_PREFERRED_LENGTH: let netapi32 size the buffer
    private const int  LocalGroupMembersInfoLevel2 = 2;

    /// <summary>
    /// Upper bound on members read in one pass. A local Administrators group with more
    /// members than this is not a shape any real estate produces, and an unbounded loop
    /// over a hostile or corrupt SAM is not worth the risk; hitting it throws, which
    /// reports the collection unavailable rather than a truncated roster claimed complete.
    /// </summary>
    internal const int MaxMembers = 4096;

    /// <summary>
    /// PAT-1988: upper bound on local accounts walked while looking for one SID. Same
    /// reasoning as <see cref="MaxMembers"/>: a SAM with more local accounts than this is
    /// not a shape any real estate produces, and hitting it reports the enabled state
    /// unknown rather than walking an unbounded enumeration.
    /// </summary>
    internal const int MaxLocalAccountsScanned = 4096;

    /// <summary>
    /// PAT-1988: every local account and its disabled flag, in one query. The SID is
    /// matched in managed code instead of being interpolated into the WQL, so no
    /// OS-supplied string ever reaches the query text and there is no WQL injection surface
    /// to reason about. <c>LocalAccount=TRUE</c> is what keeps this off the domain:
    /// Win32_UserAccount unfiltered can enumerate the whole directory on a domain-joined
    /// machine and is slow enough to matter on an endpoint.
    /// </summary>
    private const string LocalAccountsQuery = "SELECT SID, Disabled FROM Win32_UserAccount WHERE LocalAccount=TRUE";

    private readonly ILogger<LocalAdminCollector> _log;
    private readonly Func<IEnumerable<LocalAdminMemberReading>> _enumerate;
    private readonly Func<string, LocalAccountStateRead> _readAccountState;

    public LocalAdminCollector(ILogger<LocalAdminCollector> log)
        : this(log, enumerate: null)
    {
    }

    /// <summary>
    /// Test seam: <paramref name="enumerate"/> replaces the real group read and
    /// <paramref name="readAccountState"/> the real enabled-state read. Production uses the
    /// public constructor.
    /// </summary>
    internal LocalAdminCollector(
        ILogger<LocalAdminCollector>               log,
        Func<IEnumerable<LocalAdminMemberReading>>? enumerate,
        Func<string, LocalAccountStateRead>?        readAccountState = null)
    {
        _log              = log;
        _enumerate        = enumerate ?? ReadBuiltinAdministrators;
        _readAccountState = readAccountState ?? ReadLocalAccountState;
    }

    /// <summary>
    /// Runs one collection. Never throws: any failure becomes an unavailable collection
    /// with an "Unknown" count, so it cannot break the wider inventory run.
    /// </summary>
    public LocalAdminCollectionResult Collect() =>
        LocalAdminLogic.Collect(
            _enumerate,
            ex => _log.LogDebug(
                ex, "LocalAdminCollector: local Administrators group could not be read; roster omitted, local_admin_count Unknown"),
            (member, reason) => _log.LogDebug(
                "LocalAdminCollector: member left out ({Reason}), local_admins partial", reason),
            _readAccountState);

    /// <summary>
    /// PAT-1988: reads whether the local account with <paramref name="sid"/> is disabled.
    /// Returns <see cref="LocalAccountStateRead.NotFound"/> when no local account carries
    /// that SID and <see cref="LocalAccountStateRead.Failed"/> on any error or an unusable
    /// value; the logic layer maps both to "unknown", never to "disabled".
    ///
    /// WHY WMI KEYED ON THE SID AND NOT netapi32's NetUserGetInfo, which this file already
    /// has the P/Invoke machinery for: NetUserGetInfo is keyed on the account *name*, and
    /// the built-in Administrator is the one account an estate routinely renames — CIS
    /// Windows L1 2.3.1.5 tells them to. A name-keyed read of this specific account would
    /// be wrong exactly where hardening has been applied, which is the population the
    /// signal exists to describe. The SID is the only identity of this account that cannot
    /// be renamed, so the read is keyed on it and the RID-500 SID comes from the group
    /// enumeration that already produced the entry.
    ///
    /// Win32_UserAccount.Disabled is what the SAM's UF_ACCOUNTDISABLE flag reports, the
    /// same bit "net user Administrator" prints as "Account active".
    /// </summary>
    private LocalAccountStateRead ReadLocalAccountState(string sid) =>
        LocalAccountStateRead.Capture(
            () =>
            {
                using var mos = new ManagementObjectSearcher(
                    new ManagementScope(@"\\.\root\CIMV2"), new ObjectQuery(LocalAccountsQuery));
                using var accounts = mos.Get();

                var scanned = 0;
                foreach (ManagementObject account in accounts)
                {
                    using (account)
                    {
                        if (++scanned > MaxLocalAccountsScanned)
                            throw new InvalidOperationException(
                                $"more than {MaxLocalAccountsScanned} local accounts; refusing to keep scanning for the built-in Administrator");

                        if (!string.Equals(
                                (account["SID"] as string)?.Trim(), sid, StringComparison.OrdinalIgnoreCase))
                            continue;

                        // The account is the right one; from here a value this code cannot
                        // read is a failure, not a licence to fall through to NotFound.
                        // Only a real CIM boolean counts: anything else would be a guess
                        // about the account whose state is the whole point of the read.
                        if (account["Disabled"] is not bool disabled)
                            throw new InvalidOperationException(
                                $"Win32_UserAccount for SID {sid} returned no usable Disabled value");
                        return disabled;
                    }
                }

                // Read fine, no local account with that SID: the domain's own RID-500 seen
                // in this machine's Administrators group, or a domain controller.
                return null;
            },
            ex => _log.LogDebug(
                ex, "LocalAdminCollector: built-in Administrator enabled state could not be read; account_state unknown"));

    /// <summary>
    /// Reads the built-in Administrators group through netapi32. Eager rather than lazy so
    /// every native buffer is freed before the caller sees a single row, and so a failure
    /// part way through is one exception at the call site rather than a half-read roster.
    /// Throws on any failure; <see cref="LocalAdminLogic.Collect"/> turns that into
    /// unavailable.
    /// </summary>
    private static List<LocalAdminMemberReading> ReadBuiltinAdministrators()
    {
        var groupName = BuiltinAdministratorsGroupName();
        var members   = new List<LocalAdminMemberReading>();
        var resume    = IntPtr.Zero;
        var entrySize = Marshal.SizeOf<LocalGroupMembersInfo2>();

        do
        {
            var status = NetLocalGroupGetMembers(
                serverName: null,
                localGroupName: groupName,
                level: LocalGroupMembersInfoLevel2,
                buffer: out var buffer,
                prefMaxLen: MaxPreferredLength,
                entriesRead: out var entriesRead,
                totalEntries: out _,
                resumeHandle: ref resume);

            if (status != NerrSuccess && status != ErrorMoreData)
                throw new Win32Exception(status, $"NetLocalGroupGetMembers failed for '{groupName}' (status {status})");

            try
            {
                for (var i = 0; i < entriesRead; i++)
                {
                    if (members.Count >= MaxMembers)
                        throw new InvalidOperationException(
                            $"local Administrators group reports more than {MaxMembers} members; refusing to truncate the roster");

                    var entry = Marshal.PtrToStructure<LocalGroupMembersInfo2>(buffer + (i * entrySize));
                    members.Add(new LocalAdminMemberReading
                    {
                        Name     = entry.DomainAndName,
                        Sid      = SidToString(entry.Sid),
                        SidUsage = entry.SidUsage,
                    });
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    NetApiBufferFree(buffer);
            }

            if (status == NerrSuccess)
                break;
        }
        while (resume != IntPtr.Zero);

        return members;
    }

    /// <summary>
    /// The local name of the built-in Administrators group, resolved from its well-known
    /// SID S-1-5-32-544. netapi32 takes a name, and the name is localised, so it is never
    /// hardcoded to the English "Administrators".
    /// </summary>
    private static string BuiltinAdministratorsGroupName()
    {
        var sid     = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var account = ((NTAccount)sid.Translate(typeof(NTAccount))).Value;
        // Translate yields "BUILTIN\Administrators"; netapi32 wants the bare group name.
        var slash = account.LastIndexOf('\\');
        return slash < 0 ? account : account[(slash + 1)..];
    }

    /// <summary>
    /// Converts a native SID pointer to its string form, or null when it cannot be read.
    /// A null here does not lose the member: the logic layer still reports it when the
    /// name resolved, and only drops it when neither name nor SID is usable.
    /// </summary>
    private static string? SidToString(IntPtr sid)
    {
        if (sid == IntPtr.Zero)
            return null;
        try
        {
            return new SecurityIdentifier(sid).Value;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// LOCALGROUP_MEMBERS_INFO_2 (lmaccess.h): the SID, its SID_NAME_USE classification,
    /// and the resolved DOMAIN\name. Level 2 is the only level that carries all three;
    /// level 3 drops the SID and level 0 drops the name.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LocalGroupMembersInfo2
    {
        public IntPtr Sid;
        public int    SidUsage;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? DomainAndName;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(
        string? serverName,
        string  localGroupName,
        int     level,
        out IntPtr buffer,
        int     prefMaxLen,
        out int entriesRead,
        out int totalEntries,
        ref IntPtr resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
}
