using Patched.Shared.Compliance;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1974: platform-neutral tests for <see cref="LocalAdminLogic"/>. The group read is a
/// delegate, so every route — including the failure ones that need no Windows at all —
/// runs on macOS CI. The three documented design decisions each have a test here, so a
/// change to any of them has to change a named test rather than slipping through.
/// </summary>
public sealed class LocalAdminLogicTests
{
    // SID_NAME_USE values as netapi32 reports them.
    private const int SidTypeUser           = 1;
    private const int SidTypeGroup          = 2;
    private const int SidTypeDomain         = 3;
    private const int SidTypeAlias          = 4;
    private const int SidTypeWellKnownGroup = 5;
    private const int SidTypeDeletedAccount = 6;
    private const int SidTypeUnknown        = 8;
    private const int SidTypeComputer       = 9;

    private const string MachineSidPrefix = "S-1-5-21-1111111111-2222222222-3333333333";

    private static LocalAdminMemberReading Member(string? name, string? sid, int? usage) =>
        new() { Name = name, Sid = sid, SidUsage = usage };

    private static LocalAdminCollectionResult Collect(params LocalAdminMemberReading[] members) =>
        LocalAdminLogic.Collect(() => members);

    private static IEnumerable<LocalAdminMemberReading> ThrowsAfter(IEnumerable<LocalAdminMemberReading> first)
    {
        foreach (var member in first)
            yield return member;
        throw new InvalidOperationException("group enumeration failed");
    }

    // -------------------------------------------------------------------------
    // Successful enumeration
    // -------------------------------------------------------------------------

    [Fact]
    public void EveryMemberRead_IsComplete_WithCountAndNames()
    {
        var result = Collect(
            Member(@"WIN-TEST\alice", $"{MachineSidPrefix}-1001", SidTypeUser),
            Member(@"WIN-TEST\bob",   $"{MachineSidPrefix}-1002", SidTypeUser));

        Assert.Equal(LocalAdminCollectionStatus.Complete, result.Payload.CollectionStatus);
        Assert.Equal(2, result.CountSignal);
        Assert.Equal(
            [@"WIN-TEST\alice", @"WIN-TEST\bob"],
            result.Payload.Accounts!.Select(a => a.Name));
        Assert.All(result.Payload.Accounts!, a => Assert.Equal(LocalAdminPrincipalType.User, a.PrincipalType));
        Assert.All(result.Payload.Accounts!, a => Assert.False(a.Builtin));
    }

    /// <summary>The count is a boxed int, not a string: the bag value has to stay numeric.</summary>
    [Fact]
    public void CountSignal_OnASuccessfulRead_IsAnInteger()
    {
        var result = Collect(Member(@"WIN-TEST\alice", $"{MachineSidPrefix}-1001", SidTypeUser));

        Assert.IsType<int>(result.CountSignal);
        Assert.Equal(1, result.CountSignal);
    }

    /// <summary>
    /// A group that genuinely holds no members is a real reading, so it is complete with an
    /// empty accounts array and a count of 0 — the one case where 0 is honest.
    /// </summary>
    [Fact]
    public void EmptyGroup_IsComplete_WithZeroAndAnEmptyArray()
    {
        var result = Collect();

        Assert.Equal(LocalAdminCollectionStatus.Complete, result.Payload.CollectionStatus);
        Assert.Equal(0, result.CountSignal);
        Assert.NotNull(result.Payload.Accounts);
        Assert.Empty(result.Payload.Accounts!);
    }

    [Fact]
    public void ComputerAccount_CountsAsAnIndividualPrincipal()
    {
        var result = Collect(Member(@"CONTOSO\WIN-TEST$", $"{MachineSidPrefix}-1105", SidTypeComputer));

        Assert.Equal(LocalAdminPrincipalType.User, result.Payload.Accounts![0].PrincipalType);
        Assert.Equal(1, result.CountSignal);
    }

    // -------------------------------------------------------------------------
    // Decision 1: directory-sourced group principals are reported, not counted
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(SidTypeGroup)]
    [InlineData(SidTypeAlias)]
    [InlineData(SidTypeWellKnownGroup)]
    public void DirectoryGroupPrincipal_IsReported_ButNotCounted(int usage)
    {
        var result = Collect(
            Member(@"CONTOSO\Domain Admins", "S-1-5-21-9-9-9-512", usage),
            Member(@"WIN-TEST\alice",        $"{MachineSidPrefix}-1001", SidTypeUser));

        Assert.Equal(LocalAdminCollectionStatus.Complete, result.Payload.CollectionStatus);

        // Reported: the admin path is visible, with its name and its kind.
        var group = Assert.Single(
            result.Payload.Accounts!.Where(a => a.PrincipalType == LocalAdminPrincipalType.Group));
        Assert.Equal(@"CONTOSO\Domain Admins", group.Name);
        Assert.Equal("S-1-5-21-9-9-9-512", group.Sid);

        // Not counted: its membership is opaque from the device, so it is not one admin.
        Assert.Equal(1, result.CountSignal);
    }

    /// <summary>A box whose only admin path is a domain group counts zero, and says so.</summary>
    [Fact]
    public void OnlyGroupPrincipals_CountZero_ButTheRosterStillCarriesThem()
    {
        var result = Collect(Member(@"CONTOSO\Domain Admins", "S-1-5-21-9-9-9-512", SidTypeGroup));

        Assert.Equal(0, result.CountSignal);
        Assert.Single(result.Payload.Accounts!);
    }

    // -------------------------------------------------------------------------
    // Decision 2: an unresolvable SID is reported under its SID, and is counted
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(SidTypeUnknown)]
    [InlineData(SidTypeDeletedAccount)]
    [InlineData(null)]
    public void UnresolvableSid_IsReportedUnderItsSid_AndCounted(int? usage)
    {
        var orphan = $"{MachineSidPrefix}-1500";
        var result = Collect(
            Member(null, orphan, usage),
            Member(@"WIN-TEST\alice", $"{MachineSidPrefix}-1001", SidTypeUser));

        Assert.Equal(LocalAdminCollectionStatus.Complete, result.Payload.CollectionStatus);

        var unresolved = Assert.Single(
            result.Payload.Accounts!.Where(a => a.PrincipalType == LocalAdminPrincipalType.Unresolved));
        Assert.Equal(orphan, unresolved.Name);   // the SID is the only name the device has
        Assert.Equal(orphan, unresolved.Sid);

        // Counted: it is evidence a principal holds admin rights, and an unknown principal
        // must not be the thing that lets a "no more than N admins" rule pass.
        Assert.Equal(2, result.CountSignal);
    }

    [Fact]
    public void EmptyName_IsTreatedAsUnresolved_NotAsABlankAccount()
    {
        var result = Collect(Member("   ", $"{MachineSidPrefix}-1600", SidTypeUser));

        var entry = Assert.Single(result.Payload.Accounts!);
        Assert.Equal(LocalAdminPrincipalType.Unresolved, entry.PrincipalType);
        Assert.Equal($"{MachineSidPrefix}-1600", entry.Name);
    }

    /// <summary>
    /// SidTypeDomain is neither a person nor a group we can enumerate, so it is not claimed
    /// to be either even though a name came back.
    /// </summary>
    [Fact]
    public void UnclassifiedUsageWithAName_IsUnresolved_ButKeepsTheName()
    {
        var result = Collect(Member(@"CONTOSO\", "S-1-5-21-9-9-9", SidTypeDomain));

        var entry = Assert.Single(result.Payload.Accounts!);
        Assert.Equal(LocalAdminPrincipalType.Unresolved, entry.PrincipalType);
        Assert.Equal(@"CONTOSO\", entry.Name);
        Assert.Equal(1, result.CountSignal);
    }

    /// <summary>
    /// Neither a name nor a SID: there is nothing to report and nothing to count, so it is
    /// left out AND the collection drops to partial. It never silently vanishes from a
    /// collection still claiming to be complete.
    /// </summary>
    [Fact]
    public void MemberWithNeitherNameNorSid_IsSkipped_AndMakesTheCollectionPartial()
    {
        string? reason = null;
        var result = LocalAdminLogic.Collect(
            () => new[]
            {
                Member(@"WIN-TEST\alice", $"{MachineSidPrefix}-1001", SidTypeUser),
                Member(null, null, SidTypeUnknown),
            },
            onSkipped: (_, r) => reason = r);

        Assert.Equal(LocalAdminCollectionStatus.Partial, result.Payload.CollectionStatus);
        Assert.Equal(1, result.Skipped);
        Assert.NotNull(reason);

        // The readable member is still sent so the server can upsert it...
        Assert.Single(result.Payload.Accounts!);
        // ...but the count is not a number this run can stand behind.
        Assert.Equal(LocalAdminLogic.UnknownCount, result.CountSignal);
    }

    [Fact]
    public void PartialWithNothingReadable_OmitsTheAccountsKey()
    {
        var result = Collect(Member(null, null, SidTypeUnknown));

        Assert.Equal(LocalAdminCollectionStatus.Partial, result.Payload.CollectionStatus);
        Assert.Null(result.Payload.Accounts);
        Assert.Equal(LocalAdminLogic.UnknownCount, result.CountSignal);
    }

    // -------------------------------------------------------------------------
    // Decision 3: the built-in administrator is flagged, not excluded
    // -------------------------------------------------------------------------

    [Fact]
    public void BuiltInAdministrator_IsFlagged_AndStillCounted()
    {
        var result = Collect(
            Member(@"WIN-TEST\Administrator", $"{MachineSidPrefix}-500", SidTypeUser),
            Member(@"WIN-TEST\alice",         $"{MachineSidPrefix}-1001", SidTypeUser));

        var builtin = Assert.Single(result.Payload.Accounts!.Where(a => a.Builtin));
        Assert.Equal(@"WIN-TEST\Administrator", builtin.Name);

        // Included: whether it is enabled is exactly the risk and cannot be read from
        // group membership, so excluding it would hide an enabled built-in Administrator.
        Assert.Equal(2, result.CountSignal);
    }

    /// <summary>
    /// RID 1500 is an ordinary account and must never be treated as the built-in
    /// Administrator. This is compared by the whole last RID component rather than a
    /// string suffix test on principle (PAT-1989): an EndsWith("-500") test would in fact
    /// still correctly reject "-1500" (it ends "1500", not "-500"), so this case alone
    /// does not distinguish the two approaches — the whole-component comparison is the
    /// single, shared, tested implementation, not a defect fix for this specific RID.
    /// </summary>
    [Fact]
    public void Rid1500_IsNotTheBuiltInAdministrator()
    {
        Assert.False(LocalAdminLogic.IsBuiltinAdministrator($"{MachineSidPrefix}-1500"));
        Assert.True(LocalAdminLogic.IsBuiltinAdministrator($"{MachineSidPrefix}-500"));
        Assert.False(LocalAdminLogic.IsBuiltinAdministrator("S-1-5-32-544"));
        Assert.False(LocalAdminLogic.IsBuiltinAdministrator("500"));
        Assert.False(LocalAdminLogic.IsBuiltinAdministrator($"{MachineSidPrefix}-"));
    }

    // -------------------------------------------------------------------------
    // PAT-1988: the built-in Administrator's enabled state
    // -------------------------------------------------------------------------

    private static LocalAdminMemberReading BuiltinAdmin() =>
        Member(@"WIN-TEST\Administrator", $"{MachineSidPrefix}-500", SidTypeUser);

    private static LocalAdminCollectionResult CollectWithState(
        Func<string, LocalAccountStateRead> readState, params LocalAdminMemberReading[] members) =>
        LocalAdminLogic.Collect(() => members, readAccountState: readState);

    private static InventoryLocalAdmin Builtin(LocalAdminCollectionResult result) =>
        Assert.Single(result.Payload.Accounts!.Where(a => a.Builtin));

    [Fact]
    public void BuiltInAdministratorEnabled_IsReportedEnabled()
    {
        var result = CollectWithState(_ => LocalAccountStateRead.Present(disabled: false), BuiltinAdmin());

        Assert.Equal(LocalAdminAccountState.Enabled, Builtin(result).AccountState);
    }

    [Fact]
    public void BuiltInAdministratorDisabled_IsReportedDisabled()
    {
        var result = CollectWithState(_ => LocalAccountStateRead.Present(disabled: true), BuiltinAdmin());

        Assert.Equal(LocalAdminAccountState.Disabled, Builtin(result).AccountState);
    }

    /// <summary>
    /// The assertion that matters most: a state that could not be read must not arrive as
    /// "disabled", which is the value that makes the finding go away. Both a failed read
    /// and an account the machine has no local row for are "unknown".
    /// </summary>
    [Theory]
    [InlineData(true)]   // the read threw
    [InlineData(false)]  // the read succeeded and no local account carries that SID
    public void BuiltInAdministratorStateUnreadable_IsUnknown_NeverDisabled(bool readFailed)
    {
        var read = readFailed ? LocalAccountStateRead.Failed : LocalAccountStateRead.NotFound;

        var builtin = Builtin(CollectWithState(_ => read, BuiltinAdmin()));

        Assert.Equal(LocalAdminAccountState.Unknown, builtin.AccountState);
        Assert.NotEqual(LocalAdminAccountState.Disabled, builtin.AccountState);
    }

    /// <summary>
    /// A Present read with no disabled flag cannot be built through
    /// <see cref="LocalAccountStateRead.Present"/>, but the record struct's own constructor
    /// allows it, so the mapping refuses to guess rather than defaulting to enabled.
    /// </summary>
    [Fact]
    public void PresentReadWithNoFlag_IsUnknown()
    {
        Assert.Equal(
            LocalAdminAccountState.Unknown,
            LocalAdminLogic.MapAccountState(new LocalAccountStateRead(LocalAccountStateReadState.Present)));
    }

    /// <summary>
    /// The reader is expected to report failure as a reading; if it throws instead, that
    /// costs one entry's state and not the roster. Losing a readable roster to an optional
    /// signal would be the worse reading.
    /// </summary>
    [Fact]
    public void ThrowingStateReader_CostsTheStateOnly_NotTheRoster()
    {
        var result = CollectWithState(
            _ => throw new UnauthorizedAccessException("WMI denied"),
            BuiltinAdmin(),
            Member(@"WIN-TEST\alice", $"{MachineSidPrefix}-1001", SidTypeUser));

        Assert.Equal(LocalAdminCollectionStatus.Complete, result.Payload.CollectionStatus);
        Assert.Equal(2, result.CountSignal);
        Assert.Equal(2, result.Payload.Accounts!.Count);
        Assert.Equal(LocalAdminAccountState.Unknown, Builtin(result).AccountState);
    }

    /// <summary>
    /// No reader means the state was never looked for, which is a different claim from
    /// looked for and not established. Null, not "unknown".
    /// </summary>
    [Fact]
    public void NoStateReader_LeavesTheStateNull_RatherThanClaimingAFailedRead()
    {
        Assert.Null(Builtin(Collect(BuiltinAdmin())).AccountState);
    }

    /// <summary>
    /// The read is for the built-in Administrator alone. An ordinary admin is not queried
    /// at all, so an ordinary roster costs no extra read, and its state stays null.
    /// </summary>
    [Fact]
    public void OrdinaryAccounts_AreNeverQueried_AndKeepANullState()
    {
        var queried = new List<string>();
        var result = CollectWithState(
            sid =>
            {
                queried.Add(sid);
                return LocalAccountStateRead.Present(disabled: false);
            },
            Member(@"WIN-TEST\alice",        $"{MachineSidPrefix}-1001", SidTypeUser),
            Member(@"CONTOSO\Domain Admins", "S-1-5-21-9-9-9-512",       SidTypeGroup),
            BuiltinAdmin());

        Assert.Equal([$"{MachineSidPrefix}-500"], queried);
        Assert.All(
            result.Payload.Accounts!.Where(a => !a.Builtin),
            a => Assert.Null(a.AccountState));
    }

    /// <summary>
    /// A domain-joined machine can carry both its own RID-500 and the domain's in the local
    /// Administrators group. Both are flagged builtin, so each is read under its own SID:
    /// only one of them is a local account, and answering for the wrong one would report a
    /// disabled local account's state against an enabled domain one.
    /// </summary>
    [Fact]
    public void BothRid500Accounts_AreReadUnderTheirOwnSid()
    {
        const string domainAdmin = "S-1-5-21-9-9-9-500";
        var result = CollectWithState(
            sid => sid == domainAdmin
                ? LocalAccountStateRead.NotFound
                : LocalAccountStateRead.Present(disabled: true),
            BuiltinAdmin(),
            Member(@"CONTOSO\Administrator", domainAdmin, SidTypeUser));

        var byState = result.Payload.Accounts!.ToDictionary(a => a.Sid!, a => a.AccountState);
        Assert.Equal(LocalAdminAccountState.Disabled, byState[$"{MachineSidPrefix}-500"]);
        Assert.Equal(LocalAdminAccountState.Unknown,  byState[domainAdmin]);
    }

    /// <summary>
    /// An unresolvable SID that happens to be RID 500 is still the built-in Administrator
    /// and is still worth reading: the name failing to resolve says nothing about the
    /// account's state.
    /// </summary>
    [Fact]
    public void UnresolvedBuiltinSid_IsStillRead()
    {
        var result = CollectWithState(
            _ => LocalAccountStateRead.Present(disabled: false),
            Member(null, $"{MachineSidPrefix}-500", SidTypeUnknown));

        var entry = Assert.Single(result.Payload.Accounts!);
        Assert.Equal(LocalAdminPrincipalType.Unresolved, entry.PrincipalType);
        Assert.Equal(LocalAdminAccountState.Enabled, entry.AccountState);
    }

    /// <summary>
    /// RID 1500 is an ordinary account and must not be queried as the built-in — the same
    /// trap <see cref="Rid1500_IsNotTheBuiltInAdministrator"/> guards on the flag itself.
    /// </summary>
    [Fact]
    public void Rid1500_IsNotQueriedAsTheBuiltIn()
    {
        var queried = new List<string>();
        var result = CollectWithState(
            sid =>
            {
                queried.Add(sid);
                return LocalAccountStateRead.Present(disabled: false);
            },
            Member(@"WIN-TEST\service", $"{MachineSidPrefix}-1500", SidTypeUser));

        Assert.Empty(queried);
        Assert.Null(Assert.Single(result.Payload.Accounts!).AccountState);
    }

    /// <summary>
    /// The state read decorates the entry and changes nothing else: not the count, not the
    /// collection status, not the builtin flag.
    /// </summary>
    [Fact]
    public void ReadingTheState_ChangesNeitherTheCountNorTheStatus()
    {
        var withRead = CollectWithState(
            _ => LocalAccountStateRead.Present(disabled: true),
            BuiltinAdmin(),
            Member(@"WIN-TEST\alice", $"{MachineSidPrefix}-1001", SidTypeUser));
        var without = Collect(
            BuiltinAdmin(),
            Member(@"WIN-TEST\alice", $"{MachineSidPrefix}-1001", SidTypeUser));

        Assert.Equal(without.CountSignal, withRead.CountSignal);
        Assert.Equal(without.Payload.CollectionStatus, withRead.Payload.CollectionStatus);
        Assert.Equal(2, withRead.CountSignal);
        Assert.True(Builtin(withRead).Builtin);
    }

    /// <summary>
    /// A disabled built-in Administrator is a fact about that account, not a reason to stop
    /// counting it. Excluding it from the count is the server's call, made from this state.
    /// </summary>
    [Fact]
    public void DisabledBuiltIn_IsStillCounted_TheServerDecidesWhatToDoWithIt()
    {
        var result = CollectWithState(_ => LocalAccountStateRead.Present(disabled: true), BuiltinAdmin());

        Assert.Equal(1, result.CountSignal);
    }

    [Fact]
    public void Capture_MapsANullReadToNotFound_AndAThrowToFailed()
    {
        Assert.Equal(LocalAccountStateReadState.NotFound, LocalAccountStateRead.Capture(() => null).State);
        Assert.Equal(LocalAccountStateReadState.Present, LocalAccountStateRead.Capture(() => true).State);
        Assert.True(LocalAccountStateRead.Capture(() => true).Disabled);

        // System.Management is Windows-only, so a plain exception stands in for the WMI
        // failure the Service's reader catches here.
        Exception? logged = null;
        var failed = LocalAccountStateRead.Capture(
            () => throw new InvalidOperationException("WMI unavailable"), ex => logged = ex);

        Assert.Equal(LocalAccountStateReadState.Failed, failed.State);
        Assert.Null(failed.Disabled);
        Assert.NotNull(logged);
    }

    // -------------------------------------------------------------------------
    // Failure: absence requires authority
    // -------------------------------------------------------------------------

    [Fact]
    public void GroupCannotBeOpened_IsUnavailable_WithUnknownCountAndNoAccountsKey()
    {
        Exception? logged = null;
        var result = LocalAdminLogic.Collect(
            () => throw new UnauthorizedAccessException("denied"),
            onUnavailable: ex => logged = ex);

        Assert.Equal(LocalAdminCollectionStatus.Unavailable, result.Payload.CollectionStatus);
        Assert.Null(result.Payload.Accounts);   // never [], which would claim zero admins
        Assert.Equal(LocalAdminLogic.UnknownCount, result.CountSignal);
        Assert.NotEqual((object)0, result.CountSignal);
        Assert.IsType<UnauthorizedAccessException>(logged);
    }

    /// <summary>Members read before the group failed are not a reading of the group.</summary>
    [Fact]
    public void EnumerationFailsMidway_IsUnavailable_NotPartial()
    {
        var result = LocalAdminLogic.Collect(
            () => ThrowsAfter([Member(@"WIN-TEST\alice", $"{MachineSidPrefix}-1001", SidTypeUser)]));

        Assert.Equal(LocalAdminCollectionStatus.Unavailable, result.Payload.CollectionStatus);
        Assert.Null(result.Payload.Accounts);
        Assert.Equal(LocalAdminLogic.UnknownCount, result.CountSignal);
    }

    /// <summary>A throwing log callback must not change the outcome or break the run.</summary>
    [Fact]
    public void ThrowingLogCallback_DoesNotChangeTheOutcome()
    {
        var result = LocalAdminLogic.Collect(
            () => throw new InvalidOperationException("boom"),
            onUnavailable: _ => throw new InvalidOperationException("logger exploded"));

        Assert.Equal(LocalAdminCollectionStatus.Unavailable, result.Payload.CollectionStatus);
        Assert.Equal(LocalAdminLogic.UnknownCount, result.CountSignal);
    }

    // -------------------------------------------------------------------------
    // Control characters
    // -------------------------------------------------------------------------

    [Fact]
    public void NameWithAControlCharacter_IsNotSentVerbatim()
    {
        var result = Collect(Member("WIN-TEST\\ali\0ce", $"{MachineSidPrefix}-1001", SidTypeUser));

        var entry = Assert.Single(result.Payload.Accounts!);
        Assert.Equal(LocalAdminPrincipalType.Unresolved, entry.PrincipalType);
        Assert.Equal($"{MachineSidPrefix}-1001", entry.Name);
    }
}
