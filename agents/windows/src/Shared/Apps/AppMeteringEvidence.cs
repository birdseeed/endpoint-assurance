using Patched.Shared.Contract;
using Patched.Shared.Metering;

namespace Patched.Shared.Apps;

internal static class AppMeteringEvidence
{
    internal static IReadOnlyList<InventoryApp> Apply(IReadOnlyList<InventoryApp> apps,
        IReadOnlyDictionary<string, AppUsage> byIdentifier) => apps.Select(a =>
        string.IsNullOrEmpty(a.UserAccount) && byIdentifier.TryGetValue(a.Identifier, out var usage)
            ? a with { LastUsedAt = usage.LastUsed?.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                LaunchCount = usage.LaunchCount, UsageEvidence = usage.UsageEvidence }
            : string.IsNullOrEmpty(a.UserAccount)
                ? a with { UsageEvidence = MeteringEvidence.Unavailable }
                : a with { UsageEvidence = MeteringEvidence.Unavailable, LastUsedAt = null, LaunchCount = null }).ToArray();
}
