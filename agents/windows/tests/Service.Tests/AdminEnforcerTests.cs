using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-605: Unit tests for AdminEnforcer.
///
/// Strategy:
///   - AdminEnforcer.GetAdministrators() and RemoveFromAdministrators() are virtual,
///     so FakeAdminEnforcer overrides them to avoid Windows DirectoryServices P/Invoke.
///   - AdminEnforcer.Enforce() returns the audit event list; tests assert on it directly.
/// </summary>
public sealed class AdminEnforcerTests
{
    // -------------------------------------------------------------------------
    // Test double
    // -------------------------------------------------------------------------

    /// <summary>
    /// Test double that overrides the virtual I/O methods so tests never touch
    /// Windows DirectoryServices or Credential Manager.
    /// </summary>
    private sealed class FakeAdminEnforcer : AdminEnforcer
    {
        private readonly List<LocalGroupMember> _members;
        public readonly List<string>            Removed = [];

        /// <summary>
        /// PAT-1110 verification (2026-08): per-instance override for
        /// AdminEnforcer.IsDryRun(), replacing the old pattern of mutating the
        /// process-wide PATCHED_DRY_RUN environment variable around a single
        /// Enforce() call. That mutation raced against BrowserExtensionBlocklistEnforcerTests
        /// (which read/wrote the SAME variable) whenever xUnit ran the two test
        /// classes' collections concurrently — each test's own try/finally restored
        /// its own value afterward, but never closed the window DURING execution, so
        /// an unrelated concurrently-running test (in either class) could observe a
        /// transient "1" and silently skip real removal. Defaults to false so every
        /// existing (non-dry-run) test is unaffected.
        /// </summary>
        public bool DryRunOverride { get; set; }

        public FakeAdminEnforcer(List<LocalGroupMember> members)
            : base(NullLogger<AdminEnforcer>.Instance)
        {
            _members = members;
        }

        internal override bool IsDryRun() => DryRunOverride;

        internal override List<LocalGroupMember> GetAdministrators() => [.. _members];

        /// <summary>
        /// PAT-1994: SIDs whose removal throws, standing in for a principal that no longer
        /// resolves by SID (deleted between enumeration and removal).
        /// </summary>
        public HashSet<string> FailForSids { get; } = [];

        internal override void RemoveFromAdministrators(LocalGroupMember member)
        {
            if (FailForSids.Contains(member.Sid))
                throw new InvalidOperationException($"Could not resolve principal by SID {member.Sid}");
            Removed.Add(member.FullName);
        }
    }

    // Convenience: local-account name with machine prefix.
    private static string Local(string bare) => $"{Environment.MachineName}\\{bare}";

    private static LocalGroupMember LocalMember(string bare, string sid = "S-1-5-21-1-2-3-1001") =>
        new(Local(bare), sid, false);

    // -------------------------------------------------------------------------
    // Tests: feature gate
    // -------------------------------------------------------------------------

    [Fact]
    public void Enforce_WhenDisabled_DoesNothing()
    {
        var enforcer = new FakeAdminEnforcer([LocalMember("alice")]);
        var policy   = new AppControlPolicy { Enabled = false, ApprovedAdmins = ["alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(enforcer.Removed);
        Assert.Empty(events);
    }

    // -------------------------------------------------------------------------
    // Tests: lockout protection
    // -------------------------------------------------------------------------

    [Fact]
    public void Enforce_WhenApprovedAdminsEmpty_SkipsEnforcement_LockoutProtection()
    {
        var enforcer = new FakeAdminEnforcer([LocalMember("alice")]);
        var policy   = new AppControlPolicy { Enabled = true, ApprovedAdmins = [] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(enforcer.Removed);
        Assert.Empty(events);
    }

    // -------------------------------------------------------------------------
    // Tests: approved user not removed
    // -------------------------------------------------------------------------

    [Fact]
    public void Enforce_ApprovedUser_IsNotRemoved()
    {
        // Local account "MACHINENAME\alice" — normalised to bare "alice" for comparison.
        var enforcer = new FakeAdminEnforcer([LocalMember("alice")]);
        var policy   = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(enforcer.Removed);
        Assert.Empty(events);
    }

    [Fact]
    public void Enforce_ApprovedUser_CaseInsensitive()
    {
        var enforcer = new FakeAdminEnforcer([LocalMember("Alice")]);
        var policy   = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(enforcer.Removed);
        Assert.Empty(events);
    }

    [Fact]
    public void Enforce_DomainApprovedUser_BareName_IsNotRemoved()
    {
        // PAT-687: domain member "CORP\alice" with a bare approved name "alice"
        // must be kept (matched on the bare SAM name), not queued for removal.
        var domainMember = new LocalGroupMember("CORP\\alice", "S-1-5-21-9-9-9-1001", false);
        var enforcer = new FakeAdminEnforcer([domainMember]);
        var policy   = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(enforcer.Removed);
        Assert.Empty(events);
    }

    [Fact]
    public void Enforce_DomainApprovedUser_QualifiedName_IsNotRemoved()
    {
        // A fully-qualified approved name "CORP\alice" also matches.
        var domainMember = new LocalGroupMember("CORP\\alice", "S-1-5-21-9-9-9-1001", false);
        var enforcer = new FakeAdminEnforcer([domainMember]);
        var policy   = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["CORP\\alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(enforcer.Removed);
        Assert.Empty(events);
    }

    [Fact]
    public void Enforce_DomainQualifiedApproval_DoesNotMatchOtherDomainSameSam()
    {
        // "CORP\alice" approved must NOT keep "EVIL\alice" (different domain).
        var corp = new LocalGroupMember("CORP\\alice", "S-1-5-21-1-1-1-1001", false);
        var evil = new LocalGroupMember("EVIL\\alice", "S-1-5-21-2-2-2-1001", false);
        var enforcer = new FakeAdminEnforcer([corp, evil]);
        var policy   = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["CORP\\alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Single(enforcer.Removed);
        Assert.Equal("EVIL\\alice", enforcer.Removed[0]);
    }

    // -------------------------------------------------------------------------
    // Tests: unapproved user removed
    // -------------------------------------------------------------------------

    [Fact]
    public void Enforce_UnapprovedUser_IsRemoved_AndAdminRemovedEventEmitted()
    {
        var enforcer = new FakeAdminEnforcer(
        [
            LocalMember("alice",   "S-1-5-21-1-2-3-1001"),   // approved
            LocalMember("mallory", "S-1-5-21-1-2-3-1002"),   // not approved
        ]);
        var policy = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Single(enforcer.Removed);
        Assert.Equal(Local("mallory"), enforcer.Removed[0]);

        Assert.Single(events);
        Assert.Equal(EnforcementAuditEventTypes.AdminRemoved, events[0].EventType);
        Assert.Equal(Local("mallory"), events[0].Subject);
    }

    [Fact]
    public void Enforce_MultipleUnapprovedUsers_AllRemoved()
    {
        var enforcer = new FakeAdminEnforcer(
        [
            LocalMember("alice",   "S-1-5-21-1-2-3-1001"),
            LocalMember("bob",     "S-1-5-21-1-2-3-1002"),
            LocalMember("mallory", "S-1-5-21-1-2-3-1003"),
            LocalMember("eve",     "S-1-5-21-1-2-3-1004"),
        ]);
        var policy = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice", "bob"] };

        var events = enforcer.Enforce(policy);

        Assert.Equal(2, enforcer.Removed.Count);
        Assert.Contains(Local("mallory"), enforcer.Removed);
        Assert.Contains(Local("eve"), enforcer.Removed);
        Assert.Equal(2, events.Count);
        Assert.All(events, e => Assert.Equal(EnforcementAuditEventTypes.AdminRemoved, e.EventType));
    }

    // -------------------------------------------------------------------------
    // Tests: last-admin protection
    // -------------------------------------------------------------------------

    [Fact]
    public void Enforce_LastAdminProtection_NothingRemoved_SkipEventEmitted()
    {
        // Only one member, and she is not approved — removing would leave 0 admins.
        var enforcer = new FakeAdminEnforcer(
        [
            LocalMember("mallory", "S-1-5-21-1-2-3-1002"),
        ]);
        var policy = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(enforcer.Removed);

        Assert.Single(events);
        var ev = events[0];
        Assert.Equal(EnforcementAuditEventTypes.AdminRemovalSkipped, ev.EventType);
        var details = Assert.IsType<Dictionary<string, object?>>(ev.Details);
        Assert.Equal("last_admin_protection", details["reason"]);
    }

    // -------------------------------------------------------------------------
    // Tests: dry-run mode
    // -------------------------------------------------------------------------

    [Fact]
    public void Enforce_DryRun_NoRemoval_SkipEventsEmitted()
    {
        var enforcer = new FakeAdminEnforcer(
        [
            LocalMember("alice",   "S-1-5-21-1-2-3-1001"),
            LocalMember("mallory", "S-1-5-21-1-2-3-1002"),
        ]);
        var policy = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice"] };

        enforcer.DryRunOverride = true;
        IReadOnlyList<EnforcementAuditEvent> events = enforcer.Enforce(policy);

        // No actual removal.
        Assert.Empty(enforcer.Removed);

        // One skip event with reason=dry_run.
        Assert.Single(events);
        var ev = events[0];
        Assert.Equal(EnforcementAuditEventTypes.AdminRemovalSkipped, ev.EventType);
        var details = Assert.IsType<Dictionary<string, object?>>(ev.Details);
        Assert.Equal("dry_run", details["reason"]);
    }

    // -------------------------------------------------------------------------
    // Tests: safety rails — protected accounts
    // -------------------------------------------------------------------------

    [Fact]
    public void Enforce_BuiltInAdministrator_NeverRemoved()
    {
        // SID ending in -500 = built-in Administrator (IsBuiltInAdministrator = true).
        var enforcer = new FakeAdminEnforcer(
        [
            new(Local("Administrator"), "S-1-5-21-1-2-3-500", IsBuiltInAdministrator: true),
            LocalMember("alice", "S-1-5-21-1-2-3-1001"),
        ]);
        var policy = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(enforcer.Removed);
        Assert.Empty(events);
    }

    [Fact]
    public void Enforce_NtServiceAccount_NeverRemoved()
    {
        var enforcer = new FakeAdminEnforcer(
        [
            new("NT SERVICE\\IntuneManagementExtension", "S-1-5-80-1234", false),
            LocalMember("alice", "S-1-5-21-1-2-3-1001"),
        ]);
        var policy = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(enforcer.Removed);
        Assert.Empty(events);
    }

    [Fact]
    public void Enforce_NtAuthorityAccount_NeverRemoved()
    {
        var enforcer = new FakeAdminEnforcer(
        [
            new("NT AUTHORITY\\SYSTEM", "S-1-5-18", false),
            LocalMember("alice", "S-1-5-21-1-2-3-1001"),
        ]);
        var policy = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(enforcer.Removed);
        Assert.Empty(events);
    }

    [Fact]
    public void Enforce_AzureAdAccount_NeverRemoved()
    {
        var enforcer = new FakeAdminEnforcer(
        [
            new("AzureAD\\Bob", "S-1-12-1-9999", false),
            LocalMember("alice", "S-1-5-21-1-2-3-1001"),
        ]);
        var policy = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(enforcer.Removed);
        Assert.Empty(events);
    }

    // -------------------------------------------------------------------------
    // Tests: domain account matching
    // -------------------------------------------------------------------------

    [Fact]
    public void Enforce_DomainAccountMatchesByFullyQualifiedName()
    {
        var enforcer = new FakeAdminEnforcer(
        [
            new("CORP\\bob", "S-1-5-21-99-1-2-1001", false),
            LocalMember("alice", "S-1-5-21-1-2-3-1001"),
        ]);
        var policy = new AppControlPolicy
        {
            Enabled        = true,
            ApprovedAdmins = ["alice", "CORP\\bob"],
        };

        var events = enforcer.Enforce(policy);

        Assert.Empty(enforcer.Removed);
        Assert.Empty(events);
    }

    [Fact]
    public void Enforce_UnapprovedDomainUser_IsRemoved()
    {
        var enforcer = new FakeAdminEnforcer(
        [
            new("CORP\\mallory", "S-1-5-21-99-1-2-1002", false),
            LocalMember("alice", "S-1-5-21-1-2-3-1001"),
        ]);
        var policy = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Single(enforcer.Removed);
        Assert.Equal("CORP\\mallory", enforcer.Removed[0]);
    }

    // -------------------------------------------------------------------------
    // Tests: NormaliseName static helper
    // -------------------------------------------------------------------------

    [Fact]
    public void NormaliseName_BareUsername_Unchanged()
    {
        Assert.Equal("alice", AdminEnforcer.NormaliseName("alice"));
    }

    [Fact]
    public void NormaliseName_TrimsWhitespace()
    {
        Assert.Equal("alice", AdminEnforcer.NormaliseName("  alice  "));
    }

    [Fact]
    public void NormaliseName_LocalMachinePrefix_Stripped()
    {
        var input  = $"{Environment.MachineName}\\alice";
        var result = AdminEnforcer.NormaliseName(input);
        Assert.Equal("alice", result);
    }

    [Fact]
    public void NormaliseName_LocalMachinePrefix_CaseInsensitiveStrip()
    {
        var input  = $"{Environment.MachineName.ToUpperInvariant()}\\alice";
        var result = AdminEnforcer.NormaliseName(input);
        Assert.Equal("alice", result);
    }

    [Fact]
    public void NormaliseName_DomainPrefix_Preserved()
    {
        var result = AdminEnforcer.NormaliseName("CORP\\bob");
        Assert.Equal("CORP\\bob", result);
    }

    // -------------------------------------------------------------------------
    // Tests: PAT-1989 — built-in Administrator detection (whole RID, not a string suffix)
    //
    // GetAdministrators() itself cannot run off a real Windows box (PrincipalContext,
    // AccountManagement), so the per-member mapping it performs is the pure, internal
    // BuildMember(), which these exercise directly and then feed through Enforce() so the
    // decision is proved on the real path rather than on a helper nothing calls.
    // -------------------------------------------------------------------------

    [Fact]
    public void BuildMember_Rid500_IsTheBuiltInAdministrator()
    {
        var member = AdminEnforcer.BuildMember(
            "S-1-5-21-1-2-3-500", Environment.MachineName, "Administrator", null);

        Assert.True(member.IsBuiltInAdministrator);
        Assert.Equal("S-1-5-21-1-2-3-500", member.Sid);
        Assert.Equal(Local("Administrator"), member.FullName);
    }

    /// <summary>
    /// RID 1500 is an ordinary user account and must never be flagged as the built-in
    /// Administrator, because a member so flagged is skipped from enforcement entirely.
    ///
    /// PAT-1989 asked for this on the stated grounds that the previous
    /// <c>sid.EndsWith("-500", StringComparison.Ordinal)</c> matched it. It did not:
    /// "S-1-5-21-1-2-3-1500" ends in "1500", not "-500", and reintroducing the suffix test
    /// leaves every assertion in this class green. The case is pinned anyway because it is
    /// the one a reader reaches for, and pinning it costs nothing; what it must not do is
    /// pass for a reason nobody has checked.
    /// </summary>
    [Fact]
    public void BuildMember_Rid1500_IsNotTheBuiltInAdministrator()
    {
        var member = AdminEnforcer.BuildMember(
            "S-1-5-21-1-2-3-1500", Environment.MachineName, "mallory", null);

        Assert.False(member.IsBuiltInAdministrator);
    }

    [Theory]
    [InlineData("S-1-5-21-1-2-3-500",  true)]   // the built-in Administrator
    [InlineData("S-1-5-21-1-2-3-1500", false)]  // ordinary account
    [InlineData("S-1-5-21-1-2-3-2500", false)]
    [InlineData("S-1-5-21-1-2-3-5001", false)]
    [InlineData("S-1-5-32-544",        false)]  // the Administrators group itself
    [InlineData("S-1-5-18",            false)]  // NT AUTHORITY\SYSTEM
    [InlineData("500",                 false)]  // no RID separator at all
    [InlineData("S-1-5-21-1-2-3-",     false)]  // trailing separator, empty RID
    [InlineData("",                    false)]  // SID could not be read
    public void BuildMember_BuiltInFlag_ComparesTheWholeRid(string sid, bool expected)
    {
        var member = AdminEnforcer.BuildMember(sid, Environment.MachineName, "someone", null);

        Assert.Equal(expected, member.IsBuiltInAdministrator);
    }

    [Fact]
    public void BuildMember_NoSamAccountName_FallsBackToDisplayNameThenSid()
    {
        Assert.Equal(
            "Some Principal",
            AdminEnforcer.BuildMember("S-1-5-21-1-2-3-1001", "WIN-TEST", null, "Some Principal").FullName);

        Assert.Equal(
            "S-1-5-21-1-2-3-1001",
            AdminEnforcer.BuildMember("S-1-5-21-1-2-3-1001", "WIN-TEST", null, null).FullName);

        Assert.Equal(
            "",
            AdminEnforcer.BuildMember(null, "WIN-TEST", null, null).FullName);
    }

    /// <summary>
    /// End to end on the enforcement path: an unapproved ordinary account whose SID ends
    /// in "-1500" is removed rather than skipped as the protected built-in Administrator.
    /// This is the behaviour the ticket cares about, asserted on the path Enforce() really
    /// takes rather than on the predicate alone.
    /// </summary>
    [Fact]
    public void Enforce_UnapprovedRid1500Account_IsRemoved_NotProtectedAsBuiltIn()
    {
        var alice   = AdminEnforcer.BuildMember("S-1-5-21-1-2-3-1001", Environment.MachineName, "alice", null);
        var mallory = AdminEnforcer.BuildMember("S-1-5-21-1-2-3-1500", Environment.MachineName, "mallory", null);

        var enforcer = new FakeAdminEnforcer([alice, mallory]);
        var policy   = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Single(enforcer.Removed);
        Assert.Equal(Local("mallory"), enforcer.Removed[0]);
        Assert.Single(events);
        Assert.Equal(EnforcementAuditEventTypes.AdminRemoved, events[0].EventType);
        Assert.Equal(Local("mallory"), events[0].Subject);
    }

    /// <summary>
    /// The other half of the same rail, and the one with teeth: the real RID-500 account
    /// is still never removed, so swapping the local suffix test for the shared whole-RID
    /// comparison did not open a lockout path.
    /// </summary>
    [Fact]
    public void Enforce_UnapprovedRid500Account_IsStillProtected()
    {
        var alice   = AdminEnforcer.BuildMember("S-1-5-21-1-2-3-1001", Environment.MachineName, "alice", null);
        var builtIn = AdminEnforcer.BuildMember("S-1-5-21-1-2-3-500",  Environment.MachineName, "Administrator", null);

        var enforcer = new FakeAdminEnforcer([alice, builtIn]);
        var policy   = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Empty(enforcer.Removed);
        Assert.Empty(events);
    }

    // -------------------------------------------------------------------------
    // Tests: PAT-1989 — locale-independent Administrators group resolution
    //
    // The lookup itself needs a real PrincipalContext, so it cannot be executed here or on
    // macOS CI. What CAN be held is the property the ticket is about: that nothing in this
    // file resolves a group from a literal display name. The guard reads the shipping
    // source and fails if the name-based overload comes back, which was verified by
    // reintroducing the defect and watching it go red.
    // -------------------------------------------------------------------------

    /// <summary>
    /// No <c>FindByIdentity</c> call in AdminEnforcer.cs passes a string literal as the
    /// identity, in either the two-arg form (<c>FindByIdentity(ctx, "Administrators")</c>)
    /// or the explicit-type three-arg form
    /// (<c>FindByIdentity(ctx, IdentityType.Name, "Administrators")</c>) -- both are the
    /// same locale-fragile lookup, since the built-in Administrators group's display name
    /// is localised ("Administrateurs", "Administratoren"), and both returned null on a
    /// non-English install, so both GetAdministrators() and RemoveFromAdministrators()
    /// then threw.
    /// </summary>
    [Fact]
    public void AdminEnforcerSource_NeverResolvesAPrincipalFromAStringLiteral()
    {
        var code = CodeLinesOf(AdminEnforcerSource());

        var twoArgLiteral = System.Text.RegularExpressions.Regex
            .Matches(code, "FindByIdentity\\s*\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\s*,\\s*\"");
        var typedNameLiteral = System.Text.RegularExpressions.Regex
            .Matches(code, "FindByIdentity\\s*\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\s*,\\s*IdentityType\\.Name\\s*,\\s*\"");

        Assert.Empty(twoArgLiteral);
        Assert.Empty(typedNameLiteral);
    }

    /// <summary>
    /// The group is resolved by its well-known SID through the IdentityType overload, and
    /// from exactly one place, so the two call sites cannot drift apart again — the bug was
    /// that the same broken lookup existed twice and a fix to one would have missed the other.
    /// </summary>
    [Fact]
    public void AdminEnforcerSource_ResolvesTheGroupByWellKnownSid_FromOnePlace()
    {
        var code = CodeLinesOf(AdminEnforcerSource());

        Assert.Contains("WellKnownSidType.BuiltinAdministratorsSid", code, StringComparison.Ordinal);
        Assert.Contains("IdentityType.Sid", code, StringComparison.Ordinal);

        var groupLookups = System.Text.RegularExpressions.Regex
            .Matches(code, "GroupPrincipal\\.FindByIdentity\\s*\\(");

        Assert.Single(groupLookups);
    }

    /// <summary>
    /// The local suffix test must not come back. This has to be held at source level
    /// because it cannot be held behaviourally: <c>EndsWith("-500", Ordinal)</c> and the
    /// whole-RID comparison agree on every input, so no assertion about a returned value
    /// can tell them apart. Verified by reintroducing the suffix test — every behavioural
    /// test in this class stayed green and only this one went red.
    /// </summary>
    [Fact]
    public void AdminEnforcerSource_NeverTestsTheRidByStringSuffix()
    {
        var code = CodeLinesOf(AdminEnforcerSource());

        Assert.DoesNotContain("EndsWith(\"-500\"", code, StringComparison.Ordinal);
    }

    // -------------------------------------------------------------------------
    // Tests: PAT-1994 — the removal path resolves the principal by SID only
    //
    // Same constraint as PAT-1989: the lookup needs a real PrincipalContext. The guard holds
    // the property at source level, and was verified by reintroducing
    // FindByIdentity(ctx, member.FullName) and watching it go red.
    // -------------------------------------------------------------------------

    /// <summary>
    /// Every <c>FindByIdentity</c> call in AdminEnforcer.cs names
    /// <c>IdentityType.Sid</c> as its identity type. This rejects the untyped two-arg form
    /// (<c>FindByIdentity(ctx, member.FullName)</c>, the pre-PAT-1994 removal lookup, which
    /// tries every identity type against a display string) and every other typed form,
    /// whatever the identity argument is. An allowlist on the type, not a blocklist on
    /// particular name expressions.
    /// </summary>
    [Fact]
    public void AdminEnforcerSource_EveryPrincipalLookupIsBySid()
    {
        var code = CodeLinesOf(AdminEnforcerSource());

        var allLookups = System.Text.RegularExpressions.Regex
            .Matches(code, "FindByIdentity\\s*\\(");
        var sidLookups = System.Text.RegularExpressions.Regex
            .Matches(code, "FindByIdentity\\s*\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\s*,\\s*IdentityType\\.Sid\\s*,");

        // One for the group (PAT-1989), one for the member being removed (PAT-1994).
        Assert.Equal(2, allLookups.Count);
        Assert.Equal(allLookups.Count, sidLookups.Count);
    }

    /// <summary>
    /// The removal method itself resolves through <c>Principal.FindByIdentity</c> by SID,
    /// keyed on the value <see cref="AdminEnforcer.RemovalSidOf"/> returns, and never
    /// passes the member's name into a lookup.
    /// </summary>
    [Fact]
    public void AdminEnforcerSource_RemovalResolvesTheMemberBySid()
    {
        var code = CodeLinesOf(AdminEnforcerSource());

        var start = code.IndexOf("internal virtual void RemoveFromAdministrators(", StringComparison.Ordinal);
        Assert.True(start >= 0, "RemoveFromAdministrators not found in AdminEnforcer.cs");
        var end = code.IndexOf("group.Save();", start, StringComparison.Ordinal);
        Assert.True(end > start, "RemoveFromAdministrators body not found in AdminEnforcer.cs");
        var body = code[start..end];

        Assert.Contains("RemovalSidOf(member)", body, StringComparison.Ordinal);
        Assert.Matches(
            "Principal\\.FindByIdentity\\s*\\(\\s*ctx\\s*,\\s*IdentityType\\.Sid\\s*,\\s*sid\\s*\\)", body);
        Assert.DoesNotMatch("FindByIdentity\\s*\\([^)]*FullName", code);
    }

    [Fact]
    public void RemovalSidOf_ReturnsTheCollectedSid()
    {
        var member = new LocalGroupMember(Local("mallory"), "S-1-5-21-1-2-3-1003", false);

        Assert.Equal("S-1-5-21-1-2-3-1003", AdminEnforcer.RemovalSidOf(member));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("mallory")]
    [InlineData("S-1-5-21-not-a-sid")]
    [InlineData("S-1-5")]            // identifier authority with no sub-authority
    [InlineData("S-1-5-21-")]        // trailing separator
    public void RemovalSidOf_RefusesAMissingOrMalformedSid_RatherThanFallingBackToTheName(string sid)
    {
        var member = new LocalGroupMember(Local("mallory"), sid, false);

        var ex = Assert.Throws<InvalidOperationException>(() => AdminEnforcer.RemovalSidOf(member));
        Assert.Contains("removal resolves by SID only", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A member that no longer resolves by SID is reported as a removal_error skip and
    /// nothing else is affected: the other unapproved member is still removed, and no
    /// admin_removed event is emitted for the one that failed.
    /// </summary>
    [Fact]
    public void Enforce_MemberNoLongerResolvable_ReportedAsRemovalError_OthersUnaffected()
    {
        var enforcer = new FakeAdminEnforcer(
        [
            LocalMember("alice",   "S-1-5-21-1-2-3-1001"),
            LocalMember("mallory", "S-1-5-21-1-2-3-1003"),
            LocalMember("eve",     "S-1-5-21-1-2-3-1004"),
        ]);
        enforcer.FailForSids.Add("S-1-5-21-1-2-3-1003");
        var policy = new AppControlPolicy { Enabled = true, ApprovedAdmins = ["alice"] };

        var events = enforcer.Enforce(policy);

        Assert.Equal([Local("eve")], enforcer.Removed);
        var removed = Assert.Single(events, e => e.EventType == EnforcementAuditEventTypes.AdminRemoved);
        Assert.Equal(Local("eve"), removed.Subject);
        var skipped = Assert.Single(events, e => e.EventType == EnforcementAuditEventTypes.AdminRemovalSkipped);
        Assert.Equal(Local("mallory"), skipped.Subject);
        var details = Assert.IsType<Dictionary<string, object?>>(skipped.Details);
        Assert.Equal("removal_error", details["reason"]);
    }

    /// <summary>
    /// Comment lines are stripped before the guards look at the source, so a comment may
    /// quote the defective call it replaced (this file's do) without defeating the guard.
    /// </summary>
    private static string CodeLinesOf(string source) =>
        string.Join(
            '\n',
            source.Split('\n').Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal)));

    /// <summary>
    /// Reads the shipping AdminEnforcer.cs. Service.Tests.csproj copies it to
    /// 'source/AdminEnforcer.cs' beside the test binary on every build, so the first step
    /// of the walk hits whatever the runner's working directory; the walk up to a
    /// 'src/Service/AdminEnforcer.cs' in the tree is the fallback.
    ///
    /// Throws rather than skipping when neither is found. A guard that quietly passes when
    /// it cannot find the thing it guards is not a guard.
    /// </summary>
    private static string AdminEnforcerSource()
    {
        var start = AppContext.BaseDirectory;
        var dir   = new DirectoryInfo(start);
        while (dir is not null)
        {
            var beside = Path.Combine(dir.FullName, "source", "AdminEnforcer.cs");
            if (File.Exists(beside)) return File.ReadAllText(beside);

            var inTree = Path.Combine(dir.FullName, "src", "Service", "AdminEnforcer.cs");
            if (File.Exists(inTree)) return File.ReadAllText(inTree);

            dir = dir.Parent;
        }

        throw new FileNotFoundException(
            $"Could not locate AdminEnforcer.cs walking up from '{start}'. Service.Tests.csproj " +
            "copies it to 'source/AdminEnforcer.cs' beside the test binary; if that copy is " +
            "missing, check the None item in Service.Tests.csproj.");
    }
}
