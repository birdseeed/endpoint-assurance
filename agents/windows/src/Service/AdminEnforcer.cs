using System.DirectoryServices.AccountManagement;
using System.Runtime.Versioning;
using System.Security.Principal;
using Patched.Shared.Compliance;
using Patched.Shared.Config;
using Patched.Shared.Contract;

namespace Patched.Service;

/// <summary>
/// PAT-605 / PAT-551: Application Control — approved-admins enforcement.
///
/// On each run cycle (when app_control.enabled = true):
///   1. Reads the approved_admins list from the signed agent-config.
///   2. Enumerates current members of the local Administrators group.
///   3. Removes any member not on the approved list, subject to safety rails.
///   4. Returns enforcement audit events; the caller (Worker) posts them to
///      /v1/inventory/enforcement-audit via AuditEventShipper.PostEnforcementAuditAsync.
///
/// Safety rails (NEVER bypassed):
///   - Lockout protection: if approved_admins is empty → skip all enforcement.
///   - Last-admin protection: if removal would drop admin count to zero → skip all.
///   - Protected account patterns: built-in Administrator (RID exactly 500),
///     NT SERVICE\*, NT AUTHORITY\*, AzureAD\*, and the currently-running process account.
///   - Dry-run: $env:PATCHED_DRY_RUN = '1' → log only; emit admin_removal_skipped events.
///
/// Fail-safe: any individual removal failure is logged and skipped; never aborts the run cycle.
/// </summary>
[SupportedOSPlatform("windows")]
public class AdminEnforcer
{
    private readonly ILogger<AdminEnforcer> _log;

    // Accounts whose name prefix matches these patterns are unconditionally protected.
    private static readonly string[] ProtectedPrefixes =
    [
        "NT SERVICE\\",
        "NT AUTHORITY\\",
        "AZUREAD\\",
    ];

    public AdminEnforcer(ILogger<AdminEnforcer> log)
    {
        _log = log;
    }

    /// <summary>
    /// Runs the approved-admins enforcement pass.  Never throws — any failure is logged
    /// and skipped so it cannot break the collection run cycle.
    /// </summary>
    /// <param name="policy">The AppControlPolicy from the current signed agent-config.</param>
    /// <returns>
    /// The enforcement audit events produced during this pass.  The caller is responsible
    /// for shipping them to /v1/inventory/enforcement-audit.
    /// </returns>
    public IReadOnlyList<EnforcementAuditEvent> Enforce(AppControlPolicy policy)
    {
        var auditEvents = new List<EnforcementAuditEvent>();

        // 1. Feature gate.
        if (!policy.Enabled)
        {
            _log.LogDebug("AdminEnforcer: app_control.enabled=false — skipping");
            return auditEvents;
        }

        // 2. Lockout protection: never enforce with an empty approved list.
        if (policy.ApprovedAdmins.Count == 0)
        {
            _log.LogWarning(
                "AdminEnforcer: app_control.enabled=true but approved_admins is empty — " +
                "skipping enforcement (lockout protection)");
            return auditEvents;
        }

        bool dryRun = IsDryRun();

        if (dryRun)
            _log.LogInformation("AdminEnforcer: dry-run mode — will log removals but not apply them");

        List<LocalGroupMember> current;
        try
        {
            current = GetAdministrators();
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "AdminEnforcer: failed to enumerate Administrators group — skipping enforcement");
            return auditEvents;
        }

        _log.LogDebug("AdminEnforcer: {Count} current Administrators group members", current.Count);

        // Build a normalised set of approved names for case-insensitive lookup.
        var approvedSet = policy.ApprovedAdmins
            .Select(NormaliseName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Identify accounts to remove (not approved + not protected by safety rails).
        var toRemove = new List<LocalGroupMember>();
        var toSkip   = new List<(LocalGroupMember Member, string Reason)>();

        foreach (var member in current)
        {
            var normalised = NormaliseName(member.FullName);

            // Protected pattern check (NT SERVICE\*, NT AUTHORITY\*, AzureAD\*, etc.).
            if (IsProtectedPattern(member.FullName))
            {
                _log.LogDebug(
                    "AdminEnforcer: skipping protected-pattern account '{Name}'", member.FullName);
                continue;
            }

            // Built-in Administrator (RID exactly 500).
            if (member.IsBuiltInAdministrator)
            {
                _log.LogDebug(
                    "AdminEnforcer: skipping built-in Administrator account '{Name}'", member.FullName);
                continue;
            }

            // Running-process account.
            if (IsCurrentProcessAccount(member))
            {
                _log.LogDebug(
                    "AdminEnforcer: skipping current-process account '{Name}'", member.FullName);
                continue;
            }

            // Approved list check. Match on either the normalised full name
            // (e.g. "CORP\alice") OR the bare SAM name (e.g. "alice"), so a
            // policy of `approved_admins: [alice]` matches a domain member
            // "CORP\alice". Without the bare-SAM match, domain admins were
            // never matched and got queued for removal (PAT-687).
            if (approvedSet.Contains(normalised) || approvedSet.Contains(BareSamName(member.FullName)))
            {
                _log.LogDebug("AdminEnforcer: '{Name}' is in approved_admins — keeping", member.FullName);
                continue;
            }

            toRemove.Add(member);
        }

        // 3. Last-admin protection: check how many admins remain after proposed removals.
        int remainingCount = current.Count - toRemove.Count;
        if (remainingCount < 1)
        {
            _log.LogWarning(
                "AdminEnforcer: removing {Count} accounts would leave 0 Administrators — " +
                "aborting all removals (last-admin protection)", toRemove.Count);
            foreach (var m in toRemove)
                toSkip.Add((m, "last_admin_protection"));
            toRemove.Clear();
        }

        var occurredAt = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

        // 4. Execute removals (or dry-run log).
        foreach (var member in toRemove)
        {
            if (dryRun)
            {
                _log.LogInformation(
                    "AdminEnforcer [DRY RUN]: would remove '{Name}' from Administrators", member.FullName);
                toSkip.Add((member, "dry_run"));
            }
            else
            {
                try
                {
                    RemoveFromAdministrators(member);
                    _log.LogInformation(
                        "AdminEnforcer: removed '{Name}' from Administrators group", member.FullName);

                    auditEvents.Add(new EnforcementAuditEvent
                    {
                        EventType  = EnforcementAuditEventTypes.AdminRemoved,
                        Subject    = member.FullName,
                        Details    = new Dictionary<string, object?> { ["method"] = "GroupPrincipal", ["dry_run"] = false },
                        OccurredAt = occurredAt,
                    });
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "AdminEnforcer: failed to remove '{Name}' — skipping", member.FullName);
                    toSkip.Add((member, "removal_error"));
                }
            }
        }

        // 5. Emit skip events.
        foreach (var (member, reason) in toSkip)
        {
            auditEvents.Add(new EnforcementAuditEvent
            {
                EventType  = EnforcementAuditEventTypes.AdminRemovalSkipped,
                Subject    = member.FullName,
                Details    = new Dictionary<string, object?> { ["method"] = "GroupPrincipal", ["reason"] = reason },
                OccurredAt = occurredAt,
            });
        }

        return auditEvents;
    }

    // -------------------------------------------------------------------------
    // Internal helpers (internal for unit testing)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Whether dry-run mode is active ($env:PATCHED_DRY_RUN = '1'). Virtual so tests
    /// can override it directly on a per-instance basis instead of mutating the real
    /// process environment variable.
    ///
    /// PAT-1110 verification (2026-08): Environment.SetEnvironmentVariable is
    /// process-wide, and xUnit runs different test classes' collections in parallel
    /// by default. AdminEnforcerTests and BrowserExtensionBlocklistEnforcerTests both
    /// used to set/restore this same variable around a single Enforce() call — each
    /// test's own try/finally correctly restored its OWN value afterward, but that
    /// does not close the window DURING execution: a concurrently-running test in the
    /// other class (or any other test in this class that doesn't itself touch the
    /// variable, e.g. Enforce_MultipleUnapprovedUsers_AllRemoved) could observe "1"
    /// mid-flight and silently skip real removal, which is exactly the flake this
    /// seam exists to make structurally impossible rather than merely less likely.
    /// This was a latent, pre-existing cross-class race (not introduced by any one
    /// ticket) that a growing test assembly's changing thread-pool interleaving made
    /// visible. Fix: tests override this method per-instance instead of mutating
    /// shared process state at all — see FakeAdminEnforcer.DryRunOverride.
    /// </summary>
    internal virtual bool IsDryRun() =>
        string.Equals(Environment.GetEnvironmentVariable("PATCHED_DRY_RUN"), "1", StringComparison.Ordinal);

    /// <summary>
    /// Enumerate the local Administrators group members.
    /// Exposed as virtual so tests can override it without P/Invoke.
    /// </summary>
    internal virtual List<LocalGroupMember> GetAdministrators()
    {
        var results = new List<LocalGroupMember>();

        using var ctx   = new PrincipalContext(ContextType.Machine);
        using var group = OpenAdministratorsGroup(ctx);

        foreach (var member in group.GetMembers(recursive: false))
        {
            results.Add(BuildMember(member.Sid?.Value, member.Context?.Name, member.SamAccountName, member.Name));
            member.Dispose();
        }

        return results;
    }

    /// <summary>
    /// Remove a member from the local Administrators group.
    /// Exposed as virtual so tests can override it.
    ///
    /// PAT-1994: the principal is resolved by the exact SID the enumeration collected,
    /// never by <see cref="LocalGroupMember.FullName"/>. The previous
    /// <c>FindByIdentity(ctx, member.FullName)</c> passed no IdentityType, so
    /// AccountManagement tried every identity type in turn against a display string, which
    /// can resolve a different principal than the one enumerated (a renamed or localised
    /// account, or a name that matches another identity type first). On the destructive
    /// half of enforcement, the account removed must be the account found.
    ///
    /// When the SID is missing or malformed, or no longer resolves (the account was deleted
    /// between enumeration and removal), this throws. There is deliberately no fallback to a
    /// name lookup: a fallback would reintroduce exactly the ambiguity this removes. The
    /// caller logs the exception and records an <c>admin_removal_skipped</c> audit event with
    /// reason <c>removal_error</c>, so the outcome is reported rather than silently dropped,
    /// and nothing else is removed.
    /// </summary>
    internal virtual void RemoveFromAdministrators(LocalGroupMember member)
    {
        var sid = RemovalSidOf(member);

        using var ctx   = new PrincipalContext(ContextType.Machine);
        using var group = OpenAdministratorsGroup(ctx);
        using var principal = Principal.FindByIdentity(ctx, IdentityType.Sid, sid)
                           ?? throw new InvalidOperationException(
                               $"Could not resolve principal '{member.FullName}' by SID {sid}; " +
                               "it may have been deleted since enumeration. Not removed, and no " +
                               "name-based lookup was attempted");

        group.Members.Remove(principal);
        group.Save();
    }

    /// <summary>
    /// PAT-1994: the string-form SID <see cref="RemoveFromAdministrators"/> resolves the
    /// principal by. Throws when the enumeration could not read a SID (BuildMember stores ""
    /// then) or the value does not have the shape of a string-form SID, rather than letting
    /// the removal path reach for the name instead.
    ///
    /// A managed shape check rather than <c>new SecurityIdentifier(string)</c>, which throws
    /// PlatformNotSupportedException off Windows and so could not be tested on macOS CI. The
    /// value came from <c>SecurityIdentifier.Value</c> during enumeration, so it is already
    /// canonical; this only stops an empty or non-SID string reaching the lookup.
    /// </summary>
    internal static string RemovalSidOf(LocalGroupMember member)
    {
        if (string.IsNullOrWhiteSpace(member.Sid))
            throw new InvalidOperationException(
                $"Refusing to remove '{member.FullName}': no SID was collected for it, " +
                "and removal resolves by SID only");

        if (!StringFormSid.IsMatch(member.Sid))
            throw new InvalidOperationException(
                $"Refusing to remove '{member.FullName}': collected SID '{member.Sid}' is not " +
                "a well-formed SID, and removal resolves by SID only");

        return member.Sid;
    }

    private static readonly System.Text.RegularExpressions.Regex StringFormSid =
        new("^S-1-[0-9]+(-[0-9]+)+$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>
    /// PAT-1989: the universal well-known SID of the built-in Administrators group,
    /// S-1-5-32-544. The group's *display name* is localised — "Administrateurs",
    /// "Administratoren", "管理者" — so the previous
    /// <c>GroupPrincipal.FindByIdentity(ctx, "Administrators")</c> returned null on any
    /// non-English Windows install and the caller then threw. Its SID never changes,
    /// so the lookup below resolves the same group on every locale.
    ///
    /// Same fix as <see cref="LocalAdminCollector"/> (PAT-1974), which resolves the group
    /// by this SID for the read-only roster. That collector goes on to translate the SID
    /// to a name because netapi32's <c>NetLocalGroupGetMembers</c> takes a name;
    /// AccountManagement does not need the translation step, because
    /// <see cref="Principal.FindByIdentity(PrincipalContext, IdentityType, string)"/>
    /// accepts <see cref="IdentityType.Sid"/> and a string-form SID directly.
    /// </summary>
    internal static SecurityIdentifier BuiltinAdministratorsSid() =>
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    /// <summary>
    /// Opens the local Administrators group by its well-known SID. The single resolution
    /// point for both <see cref="GetAdministrators"/> and
    /// <see cref="RemoveFromAdministrators"/>, so the locale-independent lookup cannot be
    /// fixed in one of them and left broken in the other (it was, before PAT-1989).
    /// </summary>
    private static GroupPrincipal OpenAdministratorsGroup(PrincipalContext ctx) =>
        GroupPrincipal.FindByIdentity(ctx, IdentityType.Sid, BuiltinAdministratorsSid().Value)
        ?? throw new InvalidOperationException(
            "Local Administrators group (well-known SID S-1-5-32-544) not found");

    /// <summary>
    /// PAT-1989: builds the <see cref="LocalGroupMember"/> for one enumerated principal.
    /// Pure and internal so the built-in-Administrator decision — the one that decides
    /// whether an account is skipped from enforcement entirely — is covered by tests that
    /// cannot run the AccountManagement enumeration around it.
    ///
    /// The built-in test compares the whole last RID component via
    /// <see cref="LocalAdminLogic.IsBuiltinAdministrator"/>, the same helper the PAT-1974
    /// roster collector uses, replacing a local <c>sid.EndsWith("-500", Ordinal)</c>.
    ///
    /// STATED PRECISELY, because the ticket that asked for this change said otherwise and
    /// the claim has been in this repo's AGENTS.md: the suffix test did NOT also match RID
    /// 1500. "S-1-5-21-1-2-3-1500" ends in "1500", not "-500". The two predicates are in
    /// fact equivalent for every input — a string ending in the four characters "-500" can
    /// only have "500" as its last hyphen-separated component, and the one string whose
    /// last component is "500" without a preceding hyphen ("500" itself) is rejected by
    /// both. So this is a deduplication and clarity change, not a live defect fix: one
    /// tested implementation of "is this RID 500", shared with the collector, instead of
    /// two spellings of the same rule that a reader has to prove equal each time.
    /// </summary>
    /// <param name="sid">String-form SID of the principal, or null when it could not be read.</param>
    /// <param name="contextName">The principal's context name — the machine or domain.</param>
    /// <param name="samAccountName">The bare SAM account name, when the principal has one.</param>
    /// <param name="displayName">The principal's display name, used only when there is no SAM name.</param>
    internal static LocalGroupMember BuildMember(
        string? sid, string? contextName, string? samAccountName, string? displayName)
    {
        var sidValue  = sid ?? "";
        var isBuiltIn = LocalAdminLogic.IsBuiltinAdministrator(sidValue);

        // FullName from AccountManagement is "MACHINENAME\username" for local accounts,
        // "DOMAIN\username" for domain accounts. contextName is null only if the
        // enumerated principal's own Context was null (AccountManagement should never
        // hand back a member with no context, but this is unproven from a Mac) -- fall
        // back to the bare SAM name rather than build a malformed "\username" that would
        // only surface as a confusing failure later in RemoveFromAdministrators.
        var fullName = samAccountName is { Length: > 0 } sam
            ? contextName is { Length: > 0 } ctx ? $"{ctx}\\{sam}" : sam
            : displayName ?? sidValue;

        return new LocalGroupMember(fullName, sidValue, isBuiltIn);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Normalise a name for comparison against the approved_admins list.
    ///
    /// Rules:
    ///  - Trim whitespace.
    ///  - For local accounts (MACHINENAME\user), strip the machine-name prefix → "user".
    ///    This lets the policy specify bare names ("alice") that match "MYPC\alice".
    ///  - For domain accounts (DOMAIN\user where DOMAIN != local machine), keep as-is.
    ///    The policy can specify either "DOMAIN\alice" or "alice"; both match.
    ///  - Case-insensitive comparison is enforced at the call site.
    /// </summary>
    internal static string NormaliseName(string name)
    {
        name = name.Trim();
        var idx = name.IndexOf('\\');
        if (idx < 0) return name;

        var prefix = name[..idx];
        var bare   = name[(idx + 1)..];

        // Strip local machine prefix.
        if (string.Equals(prefix, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
            return bare;

        return name;
    }

    /// <summary>
    /// The bare SAM account name — everything after the last '\' in a
    /// "DOMAIN\user" or "MACHINE\user" string, or the whole string if there is
    /// no domain qualifier. Used so a bare approved name ("alice") matches a
    /// domain member ("CORP\alice").
    /// </summary>
    internal static string BareSamName(string name)
    {
        name = name.Trim();
        var idx = name.LastIndexOf('\\');
        return idx < 0 ? name : name[(idx + 1)..];
    }

    /// <summary>
    /// Returns true for system-service account patterns that must never be removed.
    /// Comparison is case-insensitive.
    /// </summary>
    private static bool IsProtectedPattern(string fullName)
    {
        foreach (var prefix in ProtectedPrefixes)
        {
            if (fullName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Returns true when the account matches the current process user ($env:USERNAME).
    /// This prevents the agent from locking itself out when run under a named account.
    /// (In production the agent runs as SYSTEM, which is in ProtectedPrefixes, so this
    ///  rail is a belt-and-suspenders guard for dev/test environments.)
    /// </summary>
    private static bool IsCurrentProcessAccount(LocalGroupMember member)
    {
        var current = Environment.GetEnvironmentVariable("USERNAME") ?? "";
        if (string.IsNullOrEmpty(current)) return false;

        // $env:USERNAME is the bare SAM name, so compare against both the
        // normalised full name and the member's bare SAM name.
        return string.Equals(NormaliseName(member.FullName), current, StringComparison.OrdinalIgnoreCase)
            || string.Equals(BareSamName(member.FullName), current, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>A member of the local Administrators group as returned by the enumeration.</summary>
/// <param name="FullName">
/// The account name as returned by the OS, e.g. "MYPC\alice" or "CORP\bob".
/// </param>
/// <param name="Sid">The string-form SID (e.g. "S-1-5-21-...-500").</param>
/// <param name="IsBuiltInAdministrator">
/// True for the built-in Administrator, decided by the shared
/// <see cref="LocalAdminLogic.IsBuiltinAdministrator"/> (PAT-1989) rather than a local
/// suffix test, so this doc never has to restate that rule's exact shape.
/// </param>
public sealed record LocalGroupMember(string FullName, string Sid, bool IsBuiltInAdministrator);
