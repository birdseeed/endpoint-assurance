using System.Text.Json.Serialization;

namespace Patched.Shared.Config;

/// <summary>
/// OS update policy block, mirroring the macOS os-update-policy.plist
/// (PAT-282 parity). Reserved for PAT-308 (Windows OS-update enforcement);
/// for now it is carried through verbatim so the signed canonical bytes match
/// the server and any future fields are preserved.
/// </summary>
public sealed record OsUpdatePolicy
{
    [JsonPropertyName("target_os")]
    public string? TargetOs { get; init; }

    [JsonPropertyName("minimum_age_days")]
    public int MinimumAgeDays { get; init; } = 7;

    [JsonPropertyName("grace_days")]
    public int GraceDays { get; init; } = 14;

    [JsonPropertyName("deadline")]
    public string? Deadline { get; init; }

    [JsonPropertyName("deferral_budget")]
    public int DeferralBudget { get; init; } = 5;

    [JsonPropertyName("defer_interval_hours")]
    public int DeferIntervalHours { get; init; } = 24;

    [JsonPropertyName("blocking_window_days")]
    public int BlockingWindowDays { get; init; } = 3;

    [JsonPropertyName("exploited_overrides_age")]
    public bool ExploitedOverridesAge { get; init; } = true;
}
