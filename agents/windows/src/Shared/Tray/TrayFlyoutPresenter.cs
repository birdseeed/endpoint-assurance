using Patched.Shared.Posture;
using PostureDoc = Patched.Shared.Posture.Posture;

namespace Patched.Shared.Tray;

// Desktop chain U4: platform-neutral presenter for the Windows tray flyout. The
// flyout is a glanceable status summary of the device's posture (no remote
// control, no inline acts). All logic is here and unit-tested on any OS; the
// NotifyIcon view (Windows-only) binds to TrayFlyoutVm and swaps its icon by
// TrayIconState.

/// <summary>Tray-icon glyph state — maps to tray-icon{,-update,-error}.ico.</summary>
public enum TrayIconState { Ok, UpdatesAvailable, Attention, Unknown }

/// <summary>Glanceable summary shown in the tray flyout.</summary>
public sealed record TrayFlyoutVm(
    TrayIconState IconState,
    string Headline,            // "Protected" / "3 updates available" / "Needs attention"
    string DetailLine,          // "CIS 87 of 134 · last scan 2 minutes ago"
    string TierLine,            // "Endpoint Assurance: Patched verifies and records"
    bool IsStale,
    int UpdateCount,
    int AttentionCount);        // critical findings + drift

public static class TrayFlyoutPresenter
{
    public static TrayFlyoutVm Build(PostureSnapshot snapshot, DateTimeOffset now)
    {
        var p = snapshot.Posture;
        if (p is null)
            return new TrayFlyoutVm(
                TrayIconState.Unknown,
                snapshot.Error is not null ? "Status unavailable" : "Waiting for Patched service",
                "No scan recorded yet", "", false, 0, 0);

        var bench = p.Compliance.Primary;
        int updates = (p.Updates ?? []).Count;
        int criticals = (p.Findings ?? []).Count(f =>
            f.Severity.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase));
        int drift = p.AppPolicy?.Drift.Count ?? 0;
        int attention = criticals + drift;

        var iconState = attention > 0 ? TrayIconState.Attention
                      : updates > 0   ? TrayIconState.UpdatesAvailable
                      : TrayIconState.Ok;

        string headline = attention > 0 ? "Needs attention"
                        : updates > 0   ? $"{updates} update{(updates == 1 ? "" : "s")} available"
                        : "Protected";

        var lastScan = p.Evidence.LastScan ?? p.Device.LastSeen;
        string scan = lastScan is { } ls
            ? $"last scan {RelativeTime(ls, now)}"
            : "continuous monitoring";
        string detail = bench is null ? scan : $"CIS {bench.CoverageText} · {scan}";

        string tierName = TierDisplayName(p.Tier);

        return new TrayFlyoutVm(
            IconState:       iconState,
            Headline:        headline,
            DetailLine:      detail,
            TierLine:        $"{tierName}: Patched verifies and records",
            IsStale:         snapshot.IsStale,
            UpdateCount:     updates,
            AttentionCount:  attention);
    }

    // PAT-1599: the tier vocabulary collapsed to two values, assurance/managed —
    // "assurance observes, managed acts", one bit, not a ladder, so there is no
    // longer a middle rung to label separately. "Managed Patching" (the old
    // "patch"-tier label) and "Full Endpoint Management" (the old "managed"-tier
    // label) both overstated the agent's actual managed-tier capability set
    // (removal, admin demotion, config enforcement — never automated patching or
    // deployment; the agent has no installer), so both collapse to the plain
    // "Managed" this ticket's ruling calls for.
    private static string TierDisplayName(string tier) => tier switch
    {
        "managed"                     => "Managed",
        _                              => "Endpoint Assurance",   // assurance / report / report_deploy / patch / unknown
    };

    /// <summary>Compact relative time ("2 minutes ago", "3 days ago").</summary>
    private static string RelativeTime(DateTimeOffset then, DateTimeOffset now)
    {
        var span = now - then;
        if (span < TimeSpan.Zero) span = TimeSpan.Zero;
        if (span.TotalSeconds < 60) return "just now";
        if (span.TotalMinutes < 60) return $"{(int)span.TotalMinutes} minute{Plur((int)span.TotalMinutes)} ago";
        if (span.TotalHours < 24) return $"{(int)span.TotalHours} hour{Plur((int)span.TotalHours)} ago";
        return $"{(int)span.TotalDays} day{Plur((int)span.TotalDays)} ago";

        static string Plur(int n) => n == 1 ? "" : "s";
    }
}
