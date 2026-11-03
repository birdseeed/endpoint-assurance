using System.Text.Json.Serialization;

namespace Patched.Shared.Config;

/// <summary>
/// PAT-605 / PAT-551 Application Control policy delivered via signed agent-config.
/// Controls which local accounts are permitted to be members of the Administrators group.
///
/// Wire shape (agent-config JSON):
///   "app_control": {
///     "enabled": true,
///     "approved_admins": ["alice", "DOMAIN\\bob"],
///     "app_allowlist": []
///   }
/// </summary>
public sealed record AppControlPolicy
{
    /// <summary>
    /// Whether the app-control enforcement subsystem is active.
    /// false (default) = skip enforcement entirely.
    /// </summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; }

    /// <summary>
    /// Accounts permitted to remain in the local Administrators group.
    /// Names may be bare ("alice") or domain-qualified ("DOMAIN\\alice").
    ///
    /// Lockout protection: if this list is empty while Enabled is true, the agent
    /// skips enforcement entirely — it MUST NOT remove all admins.
    /// </summary>
    [JsonPropertyName("approved_admins")]
    public IReadOnlyList<string> ApprovedAdmins { get; init; } = [];

    /// <summary>
    /// Reserved for PAT-551 app allowlist work (future).  Parsed from the wire
    /// payload so the config round-trips cleanly; not used by PAT-605.
    /// </summary>
    [JsonPropertyName("app_allowlist")]
    public IReadOnlyList<string> AppAllowlist { get; init; } = [];

    /// <summary>
    /// PAT-828: browser extensions the tenant has marked "unapproved" and wants
    /// blocked via browser-managed policy (Chrome/Edge/Firefox). Populated
    /// server-side from the PAT-826 tenant_extension_policies store.
    ///
    /// Empty (default) = enforce nothing — the agent MUST NOT block an extension
    /// the config didn't explicitly list, exactly like <see cref="AppAllowlist"/>.
    /// </summary>
    [JsonPropertyName("extension_blocklist")]
    public IReadOnlyList<ExtensionBlocklistEntry> ExtensionBlocklist { get; init; } = [];

    /// <summary>
    /// PAT-829: browser extensions the tenant wants destructively removed from the
    /// device — the escalation path once a managed-policy blocklist
    /// (<see cref="ExtensionBlocklist"/>) isn't sufficient or isn't supported for a
    /// browser. Each entry carries an explicit removal scope. Populated server-side
    /// from the PAT-826 policy store + inventory context (PAT-125/827).
    ///
    /// Empty (default) = remove nothing — the agent MUST NOT delete an extension the
    /// config didn't explicitly list. Removal is also gated on <see cref="Enabled"/>.
    /// </summary>
    [JsonPropertyName("extension_removals")]
    public IReadOnlyList<ExtensionRemovalEntry> ExtensionRemovals { get; init; } = [];

    /// <summary>
    /// Safe defaults: enforcement disabled, no approved admins.
    /// The agent must never enforce unless the platform explicitly sets enabled=true.
    /// </summary>
    public static AppControlPolicy Defaults { get; } = new();
}

/// <summary>
/// PAT-828: one unapproved-extension entry in <see cref="AppControlPolicy.ExtensionBlocklist"/>.
/// Keyed on (browser, extension_id) to mirror the PAT-826 policy store, which is
/// the only stable identity a browser extension carries (no bundle_id/team_id).
///
/// Wire shape: { "browser": "chrome", "extension_id": "aaaa…" }
/// </summary>
public sealed record ExtensionBlocklistEntry
{
    /// <summary>Browser the block applies to: "chrome", "edge" or "firefox" (case-insensitive).</summary>
    [JsonPropertyName("browser")]
    public string Browser { get; init; } = "";

    /// <summary>The extension identifier, in that browser's own id form.</summary>
    [JsonPropertyName("extension_id")]
    public string ExtensionId { get; init; } = "";
}

/// <summary>
/// PAT-829: one destructive-removal directive in
/// <see cref="AppControlPolicy.ExtensionRemovals"/>. Identifies the extension by
/// (browser, extension_id) like <see cref="ExtensionBlocklistEntry"/>, plus an
/// explicit <see cref="Scope"/> bounding how widely the agent deletes it.
///
/// Wire shape:
///   { "browser":"chrome", "extension_id":"aaaa…", "scope":"one_profile",
///     "user_account":"MACHINE\\alice", "profile":"Default" }
///
/// <see cref="UserAccount"/> / <see cref="Profile"/> narrow the target and are
/// required by the correspondingly narrow scopes:
///   - "one_profile"  → user_account + profile (delete only that install)
///   - "one_user"     → user_account          (all of that user's profiles)
///   - "all_profiles" → (ignored)             (every user + profile on this device)
///   - "all_devices"  → (ignored)             (server fanned this out to every
///                                             device; locally identical to
///                                             all_profiles, audited as all_devices)
/// A directive whose scope requires context it doesn't carry is skipped — the
/// agent never widens a removal beyond what was explicitly targeted.
/// </summary>
public sealed record ExtensionRemovalEntry
{
    /// <summary>Approval boundary for one_observation; newer installs must never be removed.</summary>
    [JsonPropertyName("approved_before")]
    public string? ApprovedBefore { get; init; }

    /// <summary>Browser to remove from: "chrome", "edge" or "firefox" (case-insensitive).</summary>
    [JsonPropertyName("browser")]
    public string Browser { get; init; } = "";

    /// <summary>The extension identifier, in that browser's own id form.</summary>
    [JsonPropertyName("extension_id")]
    public string ExtensionId { get; init; } = "";

    /// <summary>Removal scope, including the observation-bound "one_observation" delivery scope.</summary>
    [JsonPropertyName("scope")]
    public string Scope { get; init; } = "";

    /// <summary>Target user_account (as inventoried); required for one_profile / one_user.</summary>
    [JsonPropertyName("user_account")]
    public string? UserAccount { get; init; }

    /// <summary>Target browser-profile directory name; required for one_profile.</summary>
    [JsonPropertyName("profile")]
    public string? Profile { get; init; }
}
