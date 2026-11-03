using System.Text.Json;
using System.Text.Json.Serialization;

namespace Patched.Shared.Config;

/// <summary>
/// Per-tenant policy controlling agent behaviour when a blocking process
/// (an app that must be closed before it can be updated) is running (PAT-296).
///
/// Mirrors the <c>blocking_process_policy</c> block in agent-config.schema.json.
/// Deserialised from the signed agent config delivered by GET /v1/agent-config.
///
/// Safe defaults are baked into property initialisers so that a missing or
/// partial block in the signed JSON leaves the agent in the most conservative
/// posture:
///   - action_on_timeout = NotifyOnly  (NEVER silently force-quit a running app)
///   - max_deferrals = 2
///   - timeout_seconds = 300
///   - defer_window_seconds = 3600
///
/// Any unrecognised <c>action_on_timeout</c> value MUST be treated as
/// <see cref="BlockingProcessAction.NotifyOnly"/> — see <see cref="ResolvedAction"/>.
/// </summary>
public sealed record BlockingProcessPolicy
{
    /// <summary>
    /// User-facing copy shown when a blocking process is running.
    /// null = use the agent's built-in default message.
    /// </summary>
    [JsonPropertyName("message")]
    public string? Message { get; init; }

    /// <summary>
    /// Seconds to wait for the blocking process to exit before applying
    /// <see cref="ActionOnTimeout"/>. Clamped to [30, 86400]. Default 300.
    /// </summary>
    [JsonPropertyName("timeout_seconds")]
    public int TimeoutSeconds { get; init; } = 300;

    /// <summary>
    /// Maximum number of times the user may defer the prompt per app per update cycle.
    /// 0 = no deferrals allowed. Default 2.
    /// Deferral count resets on successful update.
    /// </summary>
    [JsonPropertyName("max_deferrals")]
    public int MaxDeferrals { get; init; } = 2;

    /// <summary>
    /// How long (seconds) a single deferral postpones the update prompt.
    /// Clamped to [60, 86400]. Default 3600.
    /// </summary>
    [JsonPropertyName("defer_window_seconds")]
    public int DeferWindowSeconds { get; init; } = 3600;

    /// <summary>
    /// Raw string value of <c>action_on_timeout</c> from the config JSON.
    /// Use <see cref="ResolvedAction"/> to get the type-safe value with the
    /// notify_only fallback for unrecognised strings.
    /// </summary>
    [JsonPropertyName("action_on_timeout")]
    public string? ActionOnTimeoutRaw { get; init; }

    /// <summary>
    /// Type-safe resolved action. Any unrecognised value degrades to
    /// <see cref="BlockingProcessAction.NotifyOnly"/> — the agent must NEVER
    /// silently force-quit a running app due to an unexpected config value.
    /// </summary>
    [JsonIgnore]
    public BlockingProcessAction ResolvedAction => ActionOnTimeoutRaw switch
    {
        "prompt_then_quit" => BlockingProcessAction.PromptThenQuit,
        "skip_run"         => BlockingProcessAction.SkipRun,
        _                  => BlockingProcessAction.NotifyOnly,   // notify_only + any unknown
    };

    /// <summary>Effective timeout in seconds, clamped to [30, 86400].</summary>
    [JsonIgnore]
    public int EffectiveTimeoutSeconds => Math.Clamp(TimeoutSeconds, 30, 86_400);

    /// <summary>Effective deferral count (non-negative).</summary>
    [JsonIgnore]
    public int EffectiveMaxDeferrals => Math.Max(0, MaxDeferrals);

    /// <summary>Effective defer window in seconds, clamped to [60, 86400].</summary>
    [JsonIgnore]
    public int EffectiveDeferWindowSeconds => Math.Clamp(DeferWindowSeconds, 60, 86_400);

    /// <summary>
    /// Safe defaults used before any config has been fetched/verified, or when
    /// <c>blocking_process_policy</c> is absent from the signed JSON.
    /// action_on_timeout = NotifyOnly is the minimum-safe posture.
    /// </summary>
    public static BlockingProcessPolicy Defaults { get; } = new();
}

/// <summary>
/// What the agent does when <see cref="BlockingProcessPolicy.TimeoutSeconds"/> elapses
/// and the blocking process is still running.
/// </summary>
public enum BlockingProcessAction
{
    /// <summary>
    /// Surface a notification and skip updating this app on this run.
    /// SAFE DEFAULT — never force-quits a running app.
    /// </summary>
    NotifyOnly,

    /// <summary>
    /// Show a final user prompt; if the user confirms (or the prompt times out)
    /// quit the blocking app and proceed with the update.
    /// </summary>
    PromptThenQuit,

    /// <summary>
    /// Skip this update silently and retry on the next scheduled run.
    /// No notification is shown; no force-quit occurs.
    /// </summary>
    SkipRun,
}

/// <summary>
/// Tracks per-app deferral state on disk so deferrals survive service restarts.
/// Written to <c>%ProgramData%\Patched\blocking-deferrals-{label}.json</c>.
/// </summary>
public sealed record BlockingDeferralState
{
    /// <summary>Number of deferrals consumed for this app in the current update cycle.</summary>
    [JsonPropertyName("count")]
    public int Count { get; init; }

    /// <summary>UTC timestamp of the last deferral, ISO-8601. null if no deferral recorded.</summary>
    [JsonPropertyName("last_deferred_at")]
    public string? LastDeferredAt { get; init; }

    /// <summary>
    /// Returns true when the deferral postpone window has elapsed since the last
    /// deferral — the agent should re-prompt on this run.
    /// Returns true when no deferral has been recorded (first run).
    /// </summary>
    public bool DeferWindowElapsed(TimeSpan deferWindow)
    {
        if (string.IsNullOrEmpty(LastDeferredAt))
            return true;  // no deferral recorded -> window elapsed
        if (!DateTimeOffset.TryParse(LastDeferredAt, out var last))
            return true;  // parse error -> treat as elapsed (fail-open)
        return DateTimeOffset.UtcNow - last >= deferWindow;
    }

    private static readonly JsonSerializerOptions _opts = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = false,
    };

    /// <summary>Load state from disk. Returns an empty state if the file is absent or unreadable.</summary>
    public static BlockingDeferralState Load(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
                return new BlockingDeferralState();
            var json = File.ReadAllText(filePath);
            return JsonSerializer.Deserialize<BlockingDeferralState>(json, _opts)
                ?? new BlockingDeferralState();
        }
        catch
        {
            return new BlockingDeferralState();  // fail-open
        }
    }

    /// <summary>
    /// Return a new state with Count incremented and LastDeferredAt set to now.
    /// </summary>
    public BlockingDeferralState WithDeferral() => this with
    {
        Count          = Count + 1,
        LastDeferredAt = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
    };

    /// <summary>Persist this state to disk atomically (write-then-move).</summary>
    public void Save(string filePath)
    {
        var tmp = filePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, _opts));
        File.Move(tmp, filePath, overwrite: true);
    }

    /// <summary>Delete the deferral state file (call after a successful update).</summary>
    public static void Reset(string filePath)
    {
        try { File.Delete(filePath); }
        catch { /* non-fatal */ }
    }
}
