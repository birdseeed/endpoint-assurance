using Patched.Shared.Contract;

namespace Patched.Shared.Compliance;

/// <summary>
/// PAT-1974: one member of the local Administrators group exactly as the OS handed it
/// over, before any decision is taken about it. Kept deliberately dumb so every
/// judgement lives in <see cref="LocalAdminLogic"/> where Shared.Tests can cover it on
/// macOS CI, the same split as HardwareHealthLogic (PAT-1720) and CertCollectionLogic
/// (PAT-1732).
/// </summary>
internal sealed record LocalAdminMemberReading
{
    /// <summary>
    /// <c>DOMAIN\name</c> or <c>MACHINE\name</c> as the OS returned it. Null or empty
    /// when the SID could not be resolved to a name — normal on a device with no line of
    /// sight to the domain controller that owns the SID, and on an orphaned SID left
    /// behind by a deleted account.
    /// </summary>
    public string? Name { get; init; }

    /// <summary>String-form SID. Null only when even the SID could not be read.</summary>
    public string? Sid { get; init; }

    /// <summary>
    /// The Windows SID_NAME_USE value the lookup returned, or null when the OS did not
    /// classify the principal. Carried through as the raw integer so the mapping to a
    /// principal type stays a tested decision rather than a Windows-only one.
    /// </summary>
    public int? SidUsage { get; init; }
}

/// <summary>
/// PAT-1988: how one read of a local account's enabled state ended. Kept as a tri-state
/// for the same reason <see cref="RegistryReadState"/> is: a read that found no such local
/// account and a read that failed must not collapse into one null, and neither of them may
/// become "disabled".
/// </summary>
internal enum LocalAccountStateReadState
{
    /// <summary>The account was found and its disabled flag was read.</summary>
    Present,

    /// <summary>
    /// The read succeeded and no local account carries that SID. Normal for the domain's
    /// own RID-500 seen in a domain-joined machine's Administrators group, and on a domain
    /// controller, where the built-in Administrator is not a local account. It is not
    /// evidence the account is disabled.
    /// </summary>
    NotFound,

    /// <summary>The read threw, or returned a value of a type it cannot be read from.</summary>
    Failed,
}

/// <summary>
/// PAT-1988: the outcome of one local-account enabled-state read. The Service does the
/// Windows-only read and hands this to <see cref="LocalAdminLogic"/>, the same split
/// <see cref="RegistryRead"/> uses, so the mapping is covered on macOS CI.
/// </summary>
internal readonly record struct LocalAccountStateRead(LocalAccountStateReadState State, bool? Disabled = null)
{
    public static LocalAccountStateRead NotFound => new(LocalAccountStateReadState.NotFound);

    public static LocalAccountStateRead Failed => new(LocalAccountStateReadState.Failed);

    /// <summary><paramref name="disabled"/> is the account's disabled flag as the OS reports it.</summary>
    public static LocalAccountStateRead Present(bool disabled) =>
        new(LocalAccountStateReadState.Present, disabled);

    /// <summary>
    /// Runs a read. A null result means no local account carries the SID
    /// (<see cref="LocalAccountStateReadState.NotFound"/>); any exception is
    /// <see cref="LocalAccountStateReadState.Failed"/> and is passed to
    /// <paramref name="onFailure"/> for logging. Mirrors <see cref="RegistryRead.Capture"/>.
    /// </summary>
    public static LocalAccountStateRead Capture(Func<bool?> read, Action<Exception>? onFailure = null)
    {
        try
        {
            var disabled = read();
            return disabled is null ? NotFound : Present(disabled.Value);
        }
        catch (Exception ex)
        {
            onFailure?.Invoke(ex);
            return Failed;
        }
    }
}

/// <summary>
/// PAT-1974: outcome of one local-administrator enumeration. Both halves of the payload
/// come from this single object so the count and the roster cannot disagree: a run that
/// could not read the group reports "Unknown" for the count AND omits the accounts key.
/// Built only by <see cref="LocalAdminLogic"/> so the pairing cannot drift.
/// </summary>
internal sealed record LocalAdminCollectionResult
{
    private LocalAdminCollectionResult(InventoryLocalAdmins payload, object countSignal, int skipped)
    {
        Payload     = payload;
        CountSignal = countSignal;
        Skipped     = skipped;
    }

    /// <summary>The top-level <c>local_admins</c> object.</summary>
    public InventoryLocalAdmins Payload { get; }

    /// <summary>
    /// The value for the <c>local_admin_count</c> key in the flat compliance bag: a boxed
    /// <see cref="int"/> when the group was enumerated, or the exact string "Unknown" when
    /// it was not. Never a fabricated 0 — that reads as a device with no standing admins
    /// and passes the CIS 5.8 rule outright. "Unknown" is the Windows spelling of a failed
    /// read under the PAT-1767 signal value contract; the macOS agent spells it JSON null.
    /// </summary>
    public object CountSignal { get; }

    /// <summary>Members that could not be reported at all and were left out.</summary>
    public int Skipped { get; }

    internal static LocalAdminCollectionResult Create(InventoryLocalAdmins payload, object countSignal, int skipped) =>
        new(payload, countSignal, skipped);
}

/// <summary>
/// PAT-1974: platform-neutral routing for local-administrator collection, kept out of the
/// Windows-only reader so Shared.Tests can cover it on macOS CI.
///
/// ABSENCE REQUIRES AUTHORITY throughout. A failed enumeration reports an "Unknown" count
/// and omits the accounts key; it never sends 0 and never sends []. Mirrors
/// <c>_collect_local_admins</c> and <c>local_admins_payload</c> in macos/lib/auth.sh.
///
/// THREE DESIGN DECISIONS, settled here because they are all judgements about evidence:
///
/// 1. DIRECTORY-SOURCED GROUP PRINCIPALS ARE REPORTED, NOT COUNTED. "CONTOSO\Domain
///    Admins" in the local Administrators group is a real admin path, but its membership
///    is opaque from the device: it could be one person or fifty. Counting it as 1 would
///    be a number this agent cannot evidence, and dropping it would hide the path
///    entirely. So it appears in accounts with principal_type "group" and is excluded
///    from local_admin_count, which keeps its macOS meaning — individually provisioned
///    administrators. The server gets both facts and decides what to do with the group.
///
/// 2. AN UNRESOLVABLE SID IS REPORTED UNDER ITS OWN SID AND IS COUNTED. A SID that does
///    not resolve offline, or that belongs to a deleted account, is still evidence a
///    principal holds admin rights on this device; dropping it would undercount. It is
///    reported with principal_type "unresolved" and the raw SID as its name, and it is
///    counted, because the signal feeds a "no more than N admins" rule and an unknown
///    principal must not be the thing that lets a device pass.
///
/// 3. NO WINDOWS BUILT-IN IS EXCLUDED FROM THE COUNT; the RID-500 account is flagged
///    instead. macOS excludes root because root is the always-present superuser and its
///    login state is carried by the separate root_disabled signal. The Windows analogue
///    is the built-in Administrator (RID 500), but whether that account is enabled is
///    exactly the risk and cannot be read from group membership: excluding it would hide
///    an enabled built-in Administrator, the sharpest finding of the lot, while including
///    it only inflates a hardened image's count by a visible, explainable one. It is sent
///    with builtin=true, and PAT-1988 adds the account's own enabled state alongside it so
///    the server can tell a disabled built-in Administrator from an enabled one rather than
///    reasoning about the builtin flag alone. NT AUTHORITY\SYSTEM does not appear here at
///    all: it holds admin rights by SID, not by membership of this group.
///
/// PAT-1988, THE ENABLED-STATE READ IS A SUB-READ AND FAILS ALONE. It runs only for a
/// RID-500 entry, and neither a failure nor a missing account may cost the roster: a failed
/// sub-read makes that one entry's account_state "unknown" and leaves the collection status
/// and the count exactly as the enumeration found them. Losing a whole readable roster to
/// an optional signal would be a worse reading than not having the signal.
/// </summary>
internal static class LocalAdminLogic
{
    // SID_NAME_USE (winnt.h). Only the values that change a decision are named.
    private const int SidTypeUser           = 1;
    private const int SidTypeGroup          = 2;
    private const int SidTypeAlias          = 4;
    private const int SidTypeWellKnownGroup = 5;
    private const int SidTypeComputer       = 9;

    /// <summary>The RID of the platform's built-in administrator account.</summary>
    private const string BuiltinAdministratorRid = "500";

    /// <summary>
    /// Runs one collection. <paramref name="enumerate"/> opens the group and yields its
    /// members; an exception from the call itself or from iterating the sequence means
    /// the group was not read as a whole, which is <see cref="Unavailable"/>.
    /// <paramref name="onSkipped"/> is told about each member that could be neither named
    /// nor keyed, with the reason, so the caller can log it.
    /// <para>
    /// PAT-1988: <paramref name="readAccountState"/> reads one local account's enabled
    /// state by SID. It is called only for a RID-500 entry that carries a SID, and never
    /// for anything else, so an ordinary roster costs no extra read at all. Leaving it null
    /// leaves every entry's account_state null — the state was not looked for, which is a
    /// different claim from looked for and not established.
    /// </para>
    /// </summary>
    public static LocalAdminCollectionResult Collect(
        Func<IEnumerable<LocalAdminMemberReading>>   enumerate,
        Action<Exception>?                           onUnavailable = null,
        Action<LocalAdminMemberReading, string>?     onSkipped     = null,
        Func<string, LocalAccountStateRead>?         readAccountState = null)
    {
        ArgumentNullException.ThrowIfNull(enumerate);

        var accounts = new List<InventoryLocalAdmin>();
        var counted  = 0;
        var skipped  = 0;
        try
        {
            foreach (var member in enumerate())
            {
                var entry = Classify(member);
                if (entry is null)
                {
                    // Neither a name nor a SID came back. There is nothing to report and
                    // nothing to count, and guessing either would be an invented reading.
                    skipped++;
                    Notify(onSkipped, member, "member has neither a resolvable name nor a SID");
                    continue;
                }

                accounts.Add(WithAccountState(entry, readAccountState));
                if (entry.PrincipalType != LocalAdminPrincipalType.Group)
                    counted++;
            }
        }
        catch (Exception ex)
        {
            Notify(onUnavailable, ex);
            return Unavailable();
        }

        if (skipped > 0)
        {
            // Partial: the members that were read are sent so the server can upsert them,
            // but the count is not a number this run can stand behind, because at least
            // one principal in the group is unaccounted for. Accounts is omitted when
            // nothing at all was readable, for the same reason certificates is.
            return LocalAdminCollectionResult.Create(
                new InventoryLocalAdmins
                {
                    CollectionStatus = LocalAdminCollectionStatus.Partial,
                    Accounts         = accounts.Count > 0 ? accounts : null,
                },
                UnknownCount,
                skipped);
        }

        return LocalAdminCollectionResult.Create(
            new InventoryLocalAdmins
            {
                CollectionStatus = LocalAdminCollectionStatus.Complete,
                Accounts         = accounts,
            },
            counted,
            0);
    }

    /// <summary>The Windows spelling of a failed read for a compliance-bag value (PAT-1767).</summary>
    public const string UnknownCount = "Unknown";

    /// <summary>
    /// The group could not be read as a whole: accounts key omitted, status unavailable,
    /// count "Unknown". Never an empty accounts array and never 0.
    /// </summary>
    public static LocalAdminCollectionResult Unavailable() =>
        LocalAdminCollectionResult.Create(
            new InventoryLocalAdmins { CollectionStatus = LocalAdminCollectionStatus.Unavailable, Accounts = null },
            UnknownCount,
            0);

    /// <summary>
    /// Turns one raw member into a payload entry, or null when it carries neither a usable
    /// name nor a usable SID. See the class remarks for why each branch is what it is.
    /// </summary>
    internal static InventoryLocalAdmin? Classify(LocalAdminMemberReading member)
    {
        ArgumentNullException.ThrowIfNull(member);

        var sid  = Trimmed(member.Sid);
        var name = Trimmed(member.Name);

        // A principal the device could not name is reported under its SID rather than
        // dropped (decision 2). With no SID either there is nothing to report.
        if (name is null)
        {
            if (sid is null)
                return null;
            return new InventoryLocalAdmin
            {
                Name          = sid,
                PrincipalType = LocalAdminPrincipalType.Unresolved,
                Builtin       = IsBuiltinAdministrator(sid),
                Sid           = sid,
            };
        }

        var type = member.SidUsage switch
        {
            SidTypeUser or SidTypeComputer                        => LocalAdminPrincipalType.User,
            SidTypeGroup or SidTypeAlias or SidTypeWellKnownGroup  => LocalAdminPrincipalType.Group,
            // SidTypeDomain, SidTypeDeletedAccount, SidTypeInvalid, SidTypeUnknown,
            // SidTypeLabel and an absent classification all mean the device does not know
            // what this principal is, so it is not claimed to be either a person or a
            // group. It is still counted (decision 2).
            _                                                      => LocalAdminPrincipalType.Unresolved,
        };

        return new InventoryLocalAdmin
        {
            Name          = name,
            PrincipalType = type,
            Builtin       = sid is not null && IsBuiltinAdministrator(sid),
            Sid           = sid,
        };
    }

    /// <summary>
    /// PAT-1988: attaches the built-in Administrator's enabled state to its entry, and
    /// leaves every other entry untouched. The reader is called at most once per RID-500
    /// entry; a domain-joined machine can legitimately carry two (its own RID-500 and the
    /// domain's), and each is read under its own SID because only one of them is local.
    /// <para>
    /// The reader is expected to report a failure as
    /// <see cref="LocalAccountStateReadState.Failed"/> rather than by throwing, and the
    /// Service's reader does. The catch here is a backstop so an unexpected throw costs one
    /// entry's account_state and not the whole roster, which the caller's catch would
    /// otherwise turn into an unavailable collection. It is not silent: the entry carries
    /// <see cref="LocalAdminAccountState.Unknown"/>, which is the degraded state on the
    /// wire, not an absent one.
    /// </para>
    /// </summary>
    internal static InventoryLocalAdmin WithAccountState(
        InventoryLocalAdmin entry, Func<string, LocalAccountStateRead>? readAccountState)
    {
        if (readAccountState is null || !entry.Builtin || entry.Sid is null)
            return entry;

        LocalAccountStateRead read;
        try
        {
            read = readAccountState(entry.Sid);
        }
        catch (Exception)
        {
            read = LocalAccountStateRead.Failed;
        }

        return entry with { AccountState = MapAccountState(read) };
    }

    /// <summary>
    /// PAT-1988: the one mapping from a read to the wire value. A read that found the
    /// account reports what it found; a read that failed, or that found no local account
    /// with that SID, is <see cref="LocalAdminAccountState.Unknown"/> and never
    /// <see cref="LocalAdminAccountState.Disabled"/> — absence requires authority, and
    /// "disabled" is the value that makes a finding go away.
    /// </summary>
    internal static string MapAccountState(LocalAccountStateRead read) => read switch
    {
        { State: LocalAccountStateReadState.Present, Disabled: false } => LocalAdminAccountState.Enabled,
        { State: LocalAccountStateReadState.Present, Disabled: true }  => LocalAdminAccountState.Disabled,
        _                                                              => LocalAdminAccountState.Unknown,
    };

    /// <summary>
    /// True when the SID's RID is exactly 500, the built-in Administrator (decision 3).
    /// The last hyphen-separated component is compared whole. An <c>EndsWith("-500")</c>
    /// test would agree on every well-formed SID (<c>...-1500</c> does not end with
    /// <c>-500</c>), so this is a clarity and single-implementation choice, not a fix for a
    /// false match.
    /// </summary>
    internal static bool IsBuiltinAdministrator(string sid)
    {
        var lastHyphen = sid.LastIndexOf('-');
        if (lastHyphen < 0 || lastHyphen == sid.Length - 1)
            return false;
        return string.Equals(sid[(lastHyphen + 1)..], BuiltinAdministratorRid, StringComparison.Ordinal);
    }

    private static string? Trimmed(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var trimmed = value.Trim().Trim('\0').Trim();
        if (trimmed.Length == 0)
            return null;
        // A control character in a principal name would travel into the payload verbatim;
        // Postgres TEXT rejects NUL and nothing on either platform legitimately produces
        // one, so the entry is treated as unnamed rather than sent or truncated.
        foreach (var ch in trimmed)
            if (char.IsControl(ch))
                return null;
        return trimmed;
    }

    // A failing log callback must not turn a reading into an exception that breaks the
    // wider inventory run, nor change the collection outcome.
    private static void Notify(Action<Exception>? callback, Exception ex)
    {
        if (callback is null)
            return;
        try { callback(ex); } catch { /* swallowed on purpose; see above */ }
    }

    private static void Notify(
        Action<LocalAdminMemberReading, string>? callback, LocalAdminMemberReading member, string reason)
    {
        if (callback is null)
            return;
        try { callback(member, reason); } catch { /* swallowed on purpose; see above */ }
    }
}
