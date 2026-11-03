using Patched.Shared.Config;
using Patched.Shared.Contract;

namespace Patched.Shared.OsUpdate;

/// <summary>
/// Pure state-computation logic for OS update awareness, mirroring the
/// macOS patched-update.sh OS UPDATE AWARENESS block (PAT-273 parity).
///
/// No platform dependencies: no COM, no registry, no file I/O.
/// Unit tests in Shared.Tests call <see cref="ComputeFromInputs"/> directly
/// and can run on any OS (including macOS CI).
/// </summary>
public static class OsUpdateStateEngine
{
    /// <summary>
    /// Given WUA query results and policy, produces an <see cref="OsUpdateInfo"/>.
    /// Called by <c>OsUpdateChecker.ComputeOsUpdate</c> (Windows service) and
    /// directly by unit tests.
    /// </summary>
    public static OsUpdateInfo ComputeFromInputs(OsUpdateInputs inputs)
    {
        var now             = inputs.Now;
        var policy          = inputs.Policy;
        var installedOs     = inputs.InstalledOs;
        var deferralBudget  = policy.DeferralBudget > 0 ? policy.DeferralBudget : 5;
        var deferralsRemain = Math.Max(0, deferralBudget - inputs.DeferralCount);
        var blockingWindow  = policy.BlockingWindowDays > 0 ? policy.BlockingWindowDays : 3;

        // Target OS: from policy, else latest detected from WUA. No fallback to
        // installed_os -- WUA frequently reports a pending update (e.g. a
        // cumulative update) with no version string attached. Falling back to
        // installed_os there made target_os == installed_os on a genuinely
        // pending update, which reads as "update required to the version you
        // already have" (PAT-2123, WIN-STAGING raw_payloads.id=275). Absent is
        // the honest answer: the agent doesn't know the target build.
        var targetOs = !string.IsNullOrWhiteSpace(policy.TargetOs)
            ? policy.TargetOs
            : inputs.LatestOs;

        // No pending OS update found — clean state.
        if (!inputs.PendingOsUpdate)
        {
            return new OsUpdateInfo
            {
                InstalledOs        = installedOs,
                LatestOs           = inputs.LatestOs,
                TargetOs           = targetOs,
                State              = OsUpdateState.UpToDate,
                Severity           = OsUpdateSeverity.None,
                SecurityRelevant   = false,
                ActivelyExploited  = false,
                Deadline           = null,
                DeferralsRemaining = deferralsRemain,
                ReleaseAgeDays     = ComputeReleaseAgeDays(inputs.ReleaseDate, now),
                CheckedAt          = now,
            };
        }

        // --- Deadline computation -----------------------------------------------
        // Policy deadline takes precedence; otherwise use release_date + grace_days.
        DateTimeOffset? deadline = null;
        if (!string.IsNullOrWhiteSpace(policy.Deadline))
        {
            if (DateTimeOffset.TryParse(policy.Deadline, out var pd))
                deadline = pd.ToUniversalTime();
        }
        else if (inputs.ReleaseDate.HasValue)
        {
            var graceDays      = policy.GraceDays > 0 ? policy.GraceDays : 14;
            var exploitedSkips = policy.ExploitedOverridesAge && inputs.ActivelyExploited;
            var effectiveGrace = exploitedSkips ? Math.Max(1, graceDays / 2) : graceDays;
            deadline = inputs.ReleaseDate.Value.AddDays(effectiveGrace);
        }

        // --- Release age --------------------------------------------------------
        var releaseAgeDays = ComputeReleaseAgeDays(inputs.ReleaseDate, now);

        // --- minimum_age_days gate: cap at recommended if update is too new ----
        var minAgeDays   = policy.MinimumAgeDays > 0 ? policy.MinimumAgeDays : 7;
        var exploitSkips = policy.ExploitedOverridesAge && inputs.ActivelyExploited;
        var withinMinAge = releaseAgeDays.HasValue
            && releaseAgeDays.Value < minAgeDays
            && !exploitSkips;

        OsUpdateState    state;
        OsUpdateSeverity severity;

        if (withinMinAge)
        {
            // Update is brand-new; don't push yet.
            state    = OsUpdateState.UpdateRecommended;
            severity = inputs.ActivelyExploited  ? OsUpdateSeverity.High
                     : inputs.SecurityRelevant   ? OsUpdateSeverity.Medium
                     : OsUpdateSeverity.Low;
            deadline = null; // suppress deadline for very-new updates
        }
        else if (deadline.HasValue && now >= deadline.Value)
        {
            state    = OsUpdateState.DeadlinePassed;
            severity = OsUpdateSeverity.Critical;
        }
        else if (deadline.HasValue)
        {
            var daysLeft = (deadline.Value - now).TotalDays;
            if (daysLeft <= blockingWindow || deferralsRemain == 0)
            {
                state    = OsUpdateState.UpdateRequired;
                severity = inputs.ActivelyExploited ? OsUpdateSeverity.Critical : OsUpdateSeverity.High;
            }
            else
            {
                state    = OsUpdateState.UpdateRequired;
                severity = inputs.ActivelyExploited  ? OsUpdateSeverity.High
                         : inputs.SecurityRelevant   ? OsUpdateSeverity.Medium
                         : OsUpdateSeverity.Low;
            }
        }
        else
        {
            // No deadline computable (no release_date and no policy deadline).
            state    = OsUpdateState.UpdateRecommended;
            severity = inputs.ActivelyExploited  ? OsUpdateSeverity.High
                     : inputs.SecurityRelevant   ? OsUpdateSeverity.Medium
                     : OsUpdateSeverity.Low;
        }

        return new OsUpdateInfo
        {
            InstalledOs        = installedOs,
            LatestOs           = inputs.LatestOs,
            TargetOs           = targetOs,
            State              = state,
            Severity           = severity,
            SecurityRelevant   = inputs.SecurityRelevant,
            ActivelyExploited  = inputs.ActivelyExploited,
            Deadline           = deadline,
            DeferralsRemaining = deferralsRemain,
            ReleaseAgeDays     = releaseAgeDays,
            CheckedAt          = now,
        };
    }

    /// <summary>
    /// Builds an OsUpdateInfo with state=unknown.  Used when WUA or the registry
    /// is unavailable.
    /// </summary>
    public static OsUpdateInfo MakeUnknown(DateTimeOffset now, string installedOs = "")
    {
        return new OsUpdateInfo
        {
            InstalledOs        = installedOs,
            LatestOs           = null,
            // PAT-2123: an unknown state has no known target; the installed
            // build would read as "update required to what you already have".
            TargetOs           = null,
            State              = OsUpdateState.Unknown,
            Severity           = OsUpdateSeverity.None,
            SecurityRelevant   = false,
            ActivelyExploited  = false,
            Deadline           = null,
            DeferralsRemaining = 5,
            ReleaseAgeDays     = null,
            CheckedAt          = now,
        };
    }

    private static int? ComputeReleaseAgeDays(DateTimeOffset? releaseDate, DateTimeOffset now)
        => releaseDate.HasValue ? (int)(now - releaseDate.Value).TotalDays : (int?)null;
}

/// <summary>
/// Aggregated WUA query result and registry data, in a COM-free struct.
/// Passed to <see cref="OsUpdateStateEngine.ComputeFromInputs"/> by both the
/// Windows service and unit tests.
/// </summary>
public sealed record OsUpdateInputs
{
    public required string InstalledOs      { get; init; }
    public int             InstalledBuild   { get; init; }
    public bool            PendingOsUpdate  { get; init; }
    public string?         LatestOs         { get; init; }
    public bool            SecurityRelevant { get; init; }
    public bool            ActivelyExploited{ get; init; }
    public DateTimeOffset? ReleaseDate      { get; init; }
    public required OsUpdatePolicy Policy  { get; init; }
    public int             DeferralCount   { get; init; }
    public DateTimeOffset  Now             { get; init; }
}
