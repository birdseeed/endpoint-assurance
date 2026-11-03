using Patched.Shared.Config;
using Patched.Shared.Contract;
using Patched.Shared.OsUpdate;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// Platform-neutral tests for <see cref="OsUpdateStateEngine.ComputeFromInputs"/>.
///
/// All tests call the static method directly — no WUA COM, no registry, no file I/O.
/// <see cref="OsUpdateStateEngine"/> lives in Patched.Shared (net8.0, no Windows TFM)
/// so these run on any OS including macOS CI.
/// </summary>
public sealed class OsUpdateStateEngineTests
{
    // Fixed clock so deadline arithmetic is deterministic.
    private static readonly DateTimeOffset Now = new(2026, 12, 11, 12, 0, 0, TimeSpan.Zero);

    private static OsUpdatePolicy DefaultPolicy() => new();  // all defaults: budget=5, grace=14, blocking=3

    // -------------------------------------------------------------------------
    // 1. No pending OS updates → up_to_date / none
    // -------------------------------------------------------------------------

    [Fact]
    public void NoPendingUpdates_ReturnsUpToDate_SeverityNone()
    {
        var inputs = new OsUpdateInputs
        {
            InstalledOs     = "10.0.22631.4602",
            Policy          = DefaultPolicy(),
            PendingOsUpdate = false,
            Now             = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Equal(OsUpdateState.UpToDate,   result.State);
        Assert.Equal(OsUpdateSeverity.None,     result.Severity);
        Assert.False(result.SecurityRelevant);
        Assert.False(result.ActivelyExploited);
        Assert.Null(result.Deadline);
        Assert.Equal("10.0.22631.4602", result.InstalledOs);
    }

    // -------------------------------------------------------------------------
    // 2. Security update available (no deadline) → update_recommended / medium
    // -------------------------------------------------------------------------

    [Fact]
    public void SecurityUpdateAvailable_NullReleaseDate_ReturnsUpdateRecommended_SeverityMedium()
    {
        // No release date → no deadline → update_recommended
        var inputs = new OsUpdateInputs
        {
            InstalledOs      = "10.0.22631.4602",
            LatestOs         = "10.0.26100.0",
            Policy           = DefaultPolicy(),
            PendingOsUpdate  = true,
            SecurityRelevant = true,
            ReleaseDate      = null,
            Now              = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Equal(OsUpdateState.UpdateRecommended, result.State);
        Assert.Equal(OsUpdateSeverity.Medium,          result.Severity);
        Assert.True(result.SecurityRelevant);
    }

    [Fact]
    public void SecurityUpdateAvailable_DeadlineWellInFuture_UpdateRequired_SeverityMedium()
    {
        // Release date 10 days ago, grace=30 days → deadline = Now+20 days → future, not in blocking window.
        var releaseDate = Now.AddDays(-10);
        var inputs = new OsUpdateInputs
        {
            InstalledOs      = "10.0.22631.4602",
            LatestOs         = "10.0.26100.0",
            Policy           = new OsUpdatePolicy { GraceDays = 30, DeferralBudget = 5, BlockingWindowDays = 3, MinimumAgeDays = 7 },
            PendingOsUpdate  = true,
            SecurityRelevant = true,
            ReleaseDate      = releaseDate,
            Now              = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        // Deadline = Now+20 days, daysLeft=20 > blocking_window=3, deferrals=5 → UpdateRequired/medium
        Assert.Equal(OsUpdateState.UpdateRequired, result.State);
        Assert.Equal(OsUpdateSeverity.Medium,       result.Severity);
        Assert.True(result.SecurityRelevant);
        Assert.False(result.ActivelyExploited);
    }

    // -------------------------------------------------------------------------
    // 3. Critical update + deadline 2 days away → update_required / high
    // -------------------------------------------------------------------------

    [Fact]
    public void Update_DeadlineIn2Days_NotExploited_ReturnsUpdateRequired_SeverityHigh()
    {
        // blocking_window_days default = 3; days_left = 2 → inside blocking window.
        var deadline    = Now.AddDays(2);
        var inputs = new OsUpdateInputs
        {
            InstalledOs      = "10.0.22631.4602",
            LatestOs         = "10.0.26100.0",
            Policy           = new OsUpdatePolicy
            {
                Deadline           = deadline.ToString("O"),
                DeferralBudget     = 5,
                BlockingWindowDays = 3,
                MinimumAgeDays     = 7,
            },
            PendingOsUpdate  = true,
            SecurityRelevant = true,
            ActivelyExploited= false,
            ReleaseDate      = Now.AddDays(-12),
            Now              = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Equal(OsUpdateState.UpdateRequired, result.State);
        Assert.Equal(OsUpdateSeverity.High,         result.Severity);
        Assert.True(result.SecurityRelevant);
        Assert.NotNull(result.Deadline);
    }

    [Fact]
    public void ActivelyExploited_DeadlineIn2Days_SeverityCritical()
    {
        var deadline = Now.AddDays(2);
        var inputs = new OsUpdateInputs
        {
            InstalledOs      = "10.0.22631.4602",
            LatestOs         = "10.0.26100.0",
            Policy           = new OsUpdatePolicy
            {
                Deadline           = deadline.ToString("O"),
                DeferralBudget     = 5,
                BlockingWindowDays = 3,
                MinimumAgeDays     = 7,
            },
            PendingOsUpdate  = true,
            SecurityRelevant = true,
            ActivelyExploited= true,
            ReleaseDate      = Now.AddDays(-12),
            Now              = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Equal(OsUpdateState.UpdateRequired, result.State);
        Assert.Equal(OsUpdateSeverity.Critical,    result.Severity);
        Assert.True(result.ActivelyExploited);
    }

    // -------------------------------------------------------------------------
    // 4. Deadline passed → deadline_passed / critical
    // -------------------------------------------------------------------------

    [Fact]
    public void DeadlinePassed_ReturnsDeadlinePassed_SeverityCritical()
    {
        var deadline = Now.AddDays(-1);  // 1 day ago
        var inputs = new OsUpdateInputs
        {
            InstalledOs      = "10.0.22631.4602",
            LatestOs         = "10.0.26100.0",
            Policy           = new OsUpdatePolicy
            {
                Deadline           = deadline.ToString("O"),
                DeferralBudget     = 5,
                BlockingWindowDays = 3,
                MinimumAgeDays     = 7,
            },
            PendingOsUpdate  = true,
            SecurityRelevant = true,
            ReleaseDate      = Now.AddDays(-20),
            Now              = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Equal(OsUpdateState.DeadlinePassed, result.State);
        Assert.Equal(OsUpdateSeverity.Critical,    result.Severity);
    }

    // -------------------------------------------------------------------------
    // 5. Deferral budget exhausted → deferrals_remaining = 0
    // -------------------------------------------------------------------------

    [Fact]
    public void DeferralBudgetExhausted_DeferralsRemainingIsZero_StateIsUpdateRequired()
    {
        var deadline = Now.AddDays(10); // well in the future (> blocking window)
        var inputs = new OsUpdateInputs
        {
            InstalledOs      = "10.0.22631.4602",
            LatestOs         = "10.0.26100.0",
            Policy           = new OsUpdatePolicy
            {
                Deadline           = deadline.ToString("O"),
                DeferralBudget     = 5,
                BlockingWindowDays = 3,
                MinimumAgeDays     = 7,
            },
            PendingOsUpdate  = true,
            SecurityRelevant = false,
            DeferralCount    = 5,  // budget = 5, count = 5 → remaining = 0
            ReleaseDate      = Now.AddDays(-10),
            Now              = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Equal(0, result.DeferralsRemaining);
        // With deferrals_remaining=0 and a future deadline, state must be update_required.
        Assert.Equal(OsUpdateState.UpdateRequired, result.State);
    }

    [Fact]
    public void DeferralBudget5Count3_DeferralsRemainingIs2()
    {
        var inputs = new OsUpdateInputs
        {
            InstalledOs     = "10.0.22631.4602",
            Policy          = new OsUpdatePolicy { DeferralBudget = 5 },
            PendingOsUpdate = false,
            DeferralCount   = 3,
            Now             = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Equal(2, result.DeferralsRemaining);
    }

    // -------------------------------------------------------------------------
    // 6. Within minimum_age_days → update_recommended (not required)
    // -------------------------------------------------------------------------

    [Fact]
    public void WithinMinimumAgeDays_CapsAtUpdateRecommended()
    {
        // Update released 3 days ago; minimum_age_days = 7 → too new.
        var inputs = new OsUpdateInputs
        {
            InstalledOs      = "10.0.22631.4602",
            LatestOs         = "10.0.26100.0",
            Policy           = new OsUpdatePolicy
            {
                MinimumAgeDays     = 7,
                GraceDays          = 14,
                DeferralBudget     = 5,
                BlockingWindowDays = 3,
            },
            PendingOsUpdate  = true,
            SecurityRelevant = true,
            ReleaseDate      = Now.AddDays(-3),
            Now              = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Equal(OsUpdateState.UpdateRecommended, result.State);
        Assert.Null(result.Deadline);  // deadline suppressed for brand-new updates
    }

    // -------------------------------------------------------------------------
    // 7. Non-security update available (no deadline) → update_recommended / low
    // -------------------------------------------------------------------------

    [Fact]
    public void NonSecurityUpdate_NullReleaseDate_ReturnsUpdateRecommended_SeverityLow()
    {
        var inputs = new OsUpdateInputs
        {
            InstalledOs      = "10.0.22631.4602",
            LatestOs         = "10.0.26100.0",
            Policy           = DefaultPolicy(),
            PendingOsUpdate  = true,
            SecurityRelevant = false,
            ActivelyExploited= false,
            ReleaseDate      = null,
            Now              = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Equal(OsUpdateState.UpdateRecommended, result.State);
        Assert.Equal(OsUpdateSeverity.Low,             result.Severity);
    }

    // -------------------------------------------------------------------------
    // 8. TargetOs resolution
    // -------------------------------------------------------------------------

    [Fact]
    public void PolicyTargetOs_TakesPrecedenceOverLatestOs()
    {
        var inputs = new OsUpdateInputs
        {
            InstalledOs = "10.0.22631.4602",
            LatestOs    = "10.0.26100.0",
            Policy      = new OsUpdatePolicy { TargetOs = "10.0.22631.5000" },
            Now         = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Equal("10.0.22631.5000", result.TargetOs);
    }

    [Fact]
    public void NoLatestOs_NoPolicyTarget_TargetOsIsNull()
    {
        // No pending update either -- confirms the fallback removal (PAT-2123)
        // is unconditional, not just gated on PendingOsUpdate.
        var inputs = new OsUpdateInputs
        {
            InstalledOs = "10.0.22631.4602",
            LatestOs    = null,
            Policy      = DefaultPolicy(),
            Now         = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Null(result.TargetOs);
    }

    // -------------------------------------------------------------------------
    // PAT-2123: WIN-STAGING (raw_payloads.id=275) reported target_os ==
    // installed_os with no latest_os on a pending cumulative update, which
    // reads as "update required to the version you already have." WUA often
    // knows an update is pending without knowing its version. target_os must
    // be null in that case, never fall back to installed_os -- and the state/
    // severity decision must be completely unaffected.
    // -------------------------------------------------------------------------

    [Fact]
    public void PendingUpdate_NoLatestOs_NoPolicyTarget_TargetOsIsNull_StateStaysUpdateRequired()
    {
        var deadline = Now.AddDays(2);
        var inputs = new OsUpdateInputs
        {
            InstalledOs      = "10.0.26200.8655",
            LatestOs         = null,
            Policy           = new OsUpdatePolicy
            {
                Deadline           = deadline.ToString("O"),
                DeferralBudget     = 5,
                BlockingWindowDays = 3,
                MinimumAgeDays     = 7,
            },
            PendingOsUpdate  = true,
            SecurityRelevant = true,
            ActivelyExploited= false,
            ReleaseDate      = Now.AddDays(-12),
            Now              = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Null(result.TargetOs);
        Assert.Equal(OsUpdateState.UpdateRequired, result.State);
        Assert.Equal(OsUpdateSeverity.High,        result.Severity);
    }

    [Fact]
    public void PendingUpdate_LatestOsSet_NoPolicyTarget_TargetOsIsLatestOs()
    {
        var inputs = new OsUpdateInputs
        {
            InstalledOs     = "10.0.22631.4602",
            LatestOs        = "10.0.26100.0",
            Policy          = DefaultPolicy(),
            PendingOsUpdate = true,
            Now             = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Equal("10.0.26100.0", result.TargetOs);
    }

    [Fact]
    public void NoPendingUpdate_TargetOsIrrelevant_StateStaysUpToDate()
    {
        var inputs = new OsUpdateInputs
        {
            InstalledOs     = "10.0.22631.4602",
            LatestOs        = null,
            Policy          = DefaultPolicy(),
            PendingOsUpdate = false,
            Now             = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Equal(OsUpdateState.UpToDate, result.State);
        Assert.Null(result.TargetOs);
    }

    // -------------------------------------------------------------------------
    // 9. release_age_days computation
    // -------------------------------------------------------------------------

    [Fact]
    public void ReleaseAgeDays_ComputedCorrectly()
    {
        var inputs = new OsUpdateInputs
        {
            InstalledOs = "10.0.22631.4602",
            Policy      = DefaultPolicy(),
            ReleaseDate = Now.AddDays(-10),
            Now         = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Equal(10, result.ReleaseAgeDays);
    }

    [Fact]
    public void NullReleaseDate_ReleaseAgeDaysIsNull()
    {
        var inputs = new OsUpdateInputs
        {
            InstalledOs = "10.0.22631.4602",
            Policy      = DefaultPolicy(),
            ReleaseDate = null,
            Now         = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Null(result.ReleaseAgeDays);
    }

    // -------------------------------------------------------------------------
    // 10. checked_at is always set to inputs.Now
    // -------------------------------------------------------------------------

    [Fact]
    public void MakeUnknown_HasNoTarget_NotTheInstalledBuild()
    {
        // PAT-2123: Windows Update unavailable is "target unknown", never the installed build.
        var info = OsUpdateStateEngine.MakeUnknown(DateTimeOffset.UtcNow, "10.0.26200.8655");
        Assert.Equal(OsUpdateState.Unknown, info.State);
        Assert.Equal("10.0.26200.8655", info.InstalledOs);
        Assert.Null(info.TargetOs);
    }

    [Fact]
    public void CheckedAt_AlwaysEqualsNow()
    {
        var inputs = new OsUpdateInputs
        {
            InstalledOs = "10.0.22631.4602",
            Policy      = DefaultPolicy(),
            Now         = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        Assert.Equal(Now, result.CheckedAt);
    }

    // -------------------------------------------------------------------------
    // 11. ExploitedOverridesAge halves the grace period
    // -------------------------------------------------------------------------

    [Fact]
    public void ExploitedOverridesAge_HalvesGracePeriod()
    {
        // grace_days=14, exploited=true, ExploitedOverridesAge=true
        // → effective_grace = max(1, 14/2) = 7
        // release_date = Now - 8 days → deadline = Now - 1 day → deadline_passed
        var releaseDate = Now.AddDays(-8);
        var inputs = new OsUpdateInputs
        {
            InstalledOs      = "10.0.22631.4602",
            LatestOs         = "10.0.26100.0",
            Policy           = new OsUpdatePolicy
            {
                GraceDays          = 14,
                ExploitedOverridesAge = true,
                DeferralBudget     = 5,
                BlockingWindowDays = 3,
                MinimumAgeDays     = 1,
            },
            PendingOsUpdate  = true,
            SecurityRelevant = true,
            ActivelyExploited= true,
            ReleaseDate      = releaseDate,
            Now              = Now,
        };

        var result = OsUpdateStateEngine.ComputeFromInputs(inputs);

        // Deadline should be release_date + 7 days = Now - 1 day → deadline_passed
        Assert.Equal(OsUpdateState.DeadlinePassed, result.State);
        Assert.Equal(OsUpdateSeverity.Critical,    result.Severity);
    }
}
