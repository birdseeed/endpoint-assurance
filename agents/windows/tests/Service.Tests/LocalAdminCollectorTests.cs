using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Compliance;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1974: <see cref="LocalAdminCollector"/> wiring. The netapi32 read is behind the
/// same kind of injectable seam <c>RegistryValueReader</c> gives ComplianceCollector, so
/// these run on macOS: they cover that the collector routes an enumeration and a failure
/// to the right result and never throws out into the inventory run. The classification
/// rules themselves are covered by LocalAdminLogicTests in Shared.Tests.
///
/// NOT COVERED HERE, and not coverable off a real Windows box: the netapi32 read itself —
/// the well-known-SID group-name resolution, LOCALGROUP_MEMBERS_INFO_2 marshalling, the
/// ERROR_MORE_DATA resume loop, and what a domain-joined machine's Administrators group
/// actually contains.
/// </summary>
public sealed class LocalAdminCollectorTests
{
    private static LocalAdminCollector WithMembers(params LocalAdminMemberReading[] members) =>
        new(NullLogger<LocalAdminCollector>.Instance, () => members);

    private static LocalAdminMemberReading Member(string? name, string? sid, int? usage) =>
        new() { Name = name, Sid = sid, SidUsage = usage };

    [Fact]
    public void Collect_EnumerationSucceeds_ReturnsCountAndRoster()
    {
        var result = WithMembers(
            Member(@"WIN-TEST\alice", "S-1-5-21-1-2-3-1001", 1),
            Member(@"WIN-TEST\bob",   "S-1-5-21-1-2-3-1002", 1)).Collect();

        Assert.Equal(LocalAdminCollectionStatus.Complete, result.Payload.CollectionStatus);
        Assert.Equal(2, result.CountSignal);
        Assert.Equal(2, result.Payload.Accounts!.Count);
    }

    [Fact]
    public void Collect_EnumerationThrows_IsUnavailable_AndDoesNotPropagate()
    {
        var collector = new LocalAdminCollector(
            NullLogger<LocalAdminCollector>.Instance,
            () => throw new UnauthorizedAccessException("access denied"));

        var result = collector.Collect();

        Assert.Equal(LocalAdminCollectionStatus.Unavailable, result.Payload.CollectionStatus);
        Assert.Null(result.Payload.Accounts);
        Assert.Equal(LocalAdminLogic.UnknownCount, result.CountSignal);
    }

    /// <summary>
    /// The one assertion that matters most: a failed read must not land in the payload as
    /// a device with zero standing administrators, which passes CIS 5.8 outright.
    /// </summary>
    [Fact]
    public void Collect_EnumerationThrows_NeverReportsZeroOrAnEmptyRoster()
    {
        var result = new LocalAdminCollector(
            NullLogger<LocalAdminCollector>.Instance,
            () => throw new InvalidOperationException("WMI/netapi32 unavailable")).Collect();

        Assert.NotEqual((object)0, result.CountSignal);
        Assert.False(result.Payload.Accounts is { Count: 0 });
    }

    // -------------------------------------------------------------------------
    // PAT-1988: the built-in Administrator's enabled state
    //
    // The Win32_UserAccount query itself is not covered here and is not coverable off a
    // real Windows box: the WMI connection, the LocalAccount=TRUE filter and what a
    // domain-joined machine's SAM actually returns. What is covered is the wiring — that
    // the collector routes the state read for the right entry, that a failed read degrades
    // to "unknown" rather than to "disabled", and that it cannot cost the roster.
    // -------------------------------------------------------------------------

    private const string BuiltinSid = "S-1-5-21-1-2-3-500";

    private static LocalAdminCollector WithState(
        Func<string, LocalAccountStateRead> readState, params LocalAdminMemberReading[] members) =>
        new(NullLogger<LocalAdminCollector>.Instance, () => members, readState);

    [Theory]
    [InlineData(false, LocalAdminAccountState.Enabled)]
    [InlineData(true,  LocalAdminAccountState.Disabled)]
    public void Collect_BuiltinAdministrator_CarriesTheStateTheReadReturned(bool disabled, string expected)
    {
        var result = WithState(
            _ => LocalAccountStateRead.Present(disabled),
            Member(@"WIN-TEST\Administrator", BuiltinSid, 1)).Collect();

        Assert.Equal(expected, Assert.Single(result.Payload.Accounts!).AccountState);
    }

    /// <summary>
    /// The read is made against the SID the enumeration returned, not the account name.
    /// The built-in Administrator is the one account CIS hardening routinely renames, so a
    /// name-keyed read would be wrong exactly where hardening has been applied.
    /// </summary>
    [Fact]
    public void Collect_ReadsTheStateBySid_NotByName()
    {
        var queried = new List<string>();
        WithState(
            sid =>
            {
                queried.Add(sid);
                return LocalAccountStateRead.Present(disabled: true);
            },
            Member(@"WIN-TEST\RenamedRoot", BuiltinSid, 1)).Collect();

        Assert.Equal([BuiltinSid], queried);
    }

    /// <summary>
    /// A state read that fails must not become "disabled", which is the value that would
    /// let a server rule write the finding off as a hardened image.
    /// </summary>
    [Fact]
    public void Collect_StateReadFails_IsUnknown_NotDisabled()
    {
        var result = WithState(
            _ => LocalAccountStateRead.Failed,
            Member(@"WIN-TEST\Administrator", BuiltinSid, 1)).Collect();

        var builtin = Assert.Single(result.Payload.Accounts!);
        Assert.True(builtin.Builtin);
        Assert.Equal(LocalAdminAccountState.Unknown, builtin.AccountState);
    }

    /// <summary>
    /// The state read is a sub-read. A throwing reader costs that one entry's state and
    /// leaves the roster and the count exactly as the enumeration found them.
    /// </summary>
    [Fact]
    public void Collect_StateReadThrows_DoesNotCostTheRoster()
    {
        var result = WithState(
            _ => throw new UnauthorizedAccessException("WMI access denied"),
            Member(@"WIN-TEST\Administrator", BuiltinSid, 1),
            Member(@"WIN-TEST\alice",         "S-1-5-21-1-2-3-1001", 1)).Collect();

        Assert.Equal(LocalAdminCollectionStatus.Complete, result.Payload.CollectionStatus);
        Assert.Equal(2, result.CountSignal);
        Assert.Equal(LocalAdminAccountState.Unknown, result.Payload.Accounts![0].AccountState);
    }

    /// <summary>
    /// No RID-500 member means no state read at all: an ordinary roster costs nothing
    /// extra, and no entry claims a state that was never looked for.
    /// </summary>
    [Fact]
    public void Collect_NoBuiltinMember_MakesNoStateRead()
    {
        var calls = 0;
        var result = WithState(
            _ =>
            {
                calls++;
                return LocalAccountStateRead.Present(disabled: false);
            },
            Member(@"WIN-TEST\alice", "S-1-5-21-1-2-3-1001", 1)).Collect();

        Assert.Equal(0, calls);
        Assert.Null(Assert.Single(result.Payload.Accounts!).AccountState);
    }
}
