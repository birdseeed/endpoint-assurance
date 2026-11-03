using System.Text.Json.Serialization;

namespace Patched.Shared.Config;

/// <summary>
/// PAT-506: per-label deployment ring promotion entry. The platform sets
/// <see cref="ApprovedRing"/> from 0→3 as each ring's soak period succeeds.
/// A device installs only if its ring number ≤ <see cref="ApprovedRing"/>.
/// </summary>
public sealed record RingPromotion
{
    /// <summary>The version that has been approved up to <see cref="ApprovedRing"/>.</summary>
    [JsonPropertyName("version")]
    public string? Version { get; init; }

    /// <summary>Highest ring (0–3) this version has been promoted to. Absent = no gate.</summary>
    [JsonPropertyName("approved_ring")]
    public int ApprovedRing { get; init; } = 3;
}
