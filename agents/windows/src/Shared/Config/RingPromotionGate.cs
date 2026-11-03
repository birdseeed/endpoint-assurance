namespace Patched.Shared.Config;

/// <summary>Central, fail-closed resolver for PAT-1134 rollout decisions.</summary>
public static class RingPromotionGate
{
    public static bool Allows(
        string label,
        string platform,
        int deviceRing,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, ScopedRingPromotion>>? scoped,
        IReadOnlyDictionary<string, RingPromotion>? legacy)
    {
        // Presence of the scoped object means the server has published the
        // platform-aware contract. Never consult a cross-platform legacy entry
        // after that point.
        if (scoped is not null)
        {
            if (!scoped.TryGetValue(platform, out var platformPromotions))
                return true;

            // A present platform section that failed to deserialize as an
            // object is malformed signed policy. Deny rather than falling
            // through to a permissive missing-label interpretation.
            if (platformPromotions is null)
                return false;

            if (!platformPromotions.TryGetValue(label, out var scopedPromotion))
                return true;

            // Unknown approval values and malformed rings deny. Only the
            // exact positive representation is permission to install.
            return scopedPromotion.Allows(deviceRing);
        }

        return legacy is null
            || !legacy.TryGetValue(label, out var legacyPromotion)
            || deviceRing <= legacyPromotion.ApprovedRing;
    }
}
