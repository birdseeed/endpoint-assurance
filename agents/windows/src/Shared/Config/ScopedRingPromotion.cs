using System.Text.Json.Serialization;

namespace Patched.Shared.Config;

/// <summary>PAT-1134 platform-aware ring decision. "nobody" is an explicit deny.</summary>
public sealed record ScopedRingPromotion
{
    [JsonPropertyName("approval")]
    public string Approval { get; init; } = "nobody";

    [JsonPropertyName("approved_ring")]
    public int? ApprovedRing { get; init; }

    [JsonPropertyName("version")]
    public string Version { get; init; } = "";

    public bool Allows(int deviceRing) =>
        string.Equals(Approval, "up_to_ring", StringComparison.Ordinal)
        && ApprovedRing is >= 0 and <= 3
        && deviceRing <= ApprovedRing.Value;
}
