using System.Text.Json.Serialization;

namespace Patched.Shared.Interruption;

/// <summary>
/// PAT-1624: the numeric bounds on how long the never-interrupt gate is
/// allowed to keep the agent quiet. Content-equivalent with the macOS
/// <c>InterruptionPolicy</c>, same defaults, same managed-tier-only rule.
///
/// The gate itself is unconditional and applies at every tier, assurance
/// included: it is a restraint, not a capability. Only these four numbers are
/// tunable, and only at managed tier.
///
/// These bounds gate PRESENTATION, not the deadline. The deadline keeps running
/// underneath. A device that cannot be prompted for three days inside a
/// three-day blocking window reaches the deadline with the user never having
/// seen the prompt: the operator is told and decides. Patched does not force a
/// window over somebody's call to make a deadline.
/// </summary>
public sealed record InterruptionPolicy
{
    /// <summary>
    /// How many active hours of unbroken suppression the agent keeps trying to
    /// present for. This, not the attempt count, is the policy.
    /// </summary>
    public int SuppressionWindowHours { get; init; } = 8;

    /// <summary>
    /// Optional hard ceiling on consecutive suppressed attempts. Normally null,
    /// in which case the cap is derived from the window and the live retry
    /// interval, so changing the retry interval later cannot silently change
    /// the policy. An explicit value only ever tightens the derived cap.
    /// </summary>
    public int? MaxSuppressedAttempts { get; init; }

    /// <summary>
    /// Minimum gap between the fallback notifications that replace the window.
    /// More than once a day is nagging, and nagging trains dismissal.
    /// </summary>
    public int NotificationFallbackIntervalHours { get; init; } = 24;

    /// <summary>
    /// Distinct active days of unbroken suppression before the operator is
    /// signalled. Matches os_update_policy.blocking_window_days.
    /// </summary>
    public int OperatorSignalAfterDays { get; init; } = 3;

    public static readonly InterruptionPolicy Defaults = new();

    public TimeSpan SuppressionWindow => TimeSpan.FromHours(SuppressionWindowHours);
    public TimeSpan NotificationFallbackInterval => TimeSpan.FromHours(NotificationFallbackIntervalHours);

    /// <summary>
    /// The attempt count the window works out to at this retry interval. At the
    /// 2-hour retry and the default 8-hour window this is exactly 4.
    /// </summary>
    public int EffectiveAttemptCap(TimeSpan retryInterval)
    {
        if (retryInterval <= TimeSpan.Zero) return Math.Max(1, MaxSuppressedAttempts ?? 1);
        var derived = Math.Max(1, (int)Math.Ceiling(SuppressionWindow.TotalSeconds / retryInterval.TotalSeconds));
        return MaxSuppressedAttempts is null ? derived : Math.Max(1, Math.Min(MaxSuppressedAttempts.Value, derived));
    }

    /// <summary>
    /// Resolve the live policy from the signed config. Managed tier only:
    /// overrides delivered to any other tier are ignored outright rather than
    /// partially applied, so an assurance tenant runs exactly the shipped
    /// defaults whatever the config says. Out-of-range values are dropped field
    /// by field, never clamped to something the operator did not ask for.
    /// </summary>
    public static InterruptionPolicy Resolve(InterruptionPolicyOverrides? overrides, string? tier)
    {
        if (overrides is null) return Defaults;
        if (!string.Equals(tier?.Trim(), "managed", StringComparison.OrdinalIgnoreCase)) return Defaults;

        var policy = Defaults;
        if (overrides.SuppressionWindowHours is int window && window is >= 1 and <= 168)
            policy = policy with { SuppressionWindowHours = window };
        if (overrides.MaxSuppressedAttempts is int attempts && attempts is >= 1 and <= 1000)
            policy = policy with { MaxSuppressedAttempts = attempts };
        if (overrides.NotificationFallbackIntervalHours is int gap && gap is >= 1 and <= 168)
            policy = policy with { NotificationFallbackIntervalHours = gap };
        if (overrides.OperatorSignalAfterDays is int days && days is >= 1 and <= 365)
            policy = policy with { OperatorSignalAfterDays = days };
        return policy;
    }
}

/// <summary>
/// The <c>interruption_policy</c> block of agent-config.json. Every field is
/// optional: an absent field, a null, or an out-of-range value leaves the
/// shipped default in place rather than failing the whole config.
/// </summary>
public sealed record InterruptionPolicyOverrides
{
    [JsonPropertyName("suppression_window_hours")]
    public int? SuppressionWindowHours { get; init; }

    [JsonPropertyName("max_suppressed_attempts")]
    public int? MaxSuppressedAttempts { get; init; }

    [JsonPropertyName("notification_fallback_interval_hours")]
    public int? NotificationFallbackIntervalHours { get; init; }

    [JsonPropertyName("operator_signal_after_days")]
    public int? OperatorSignalAfterDays { get; init; }
}
