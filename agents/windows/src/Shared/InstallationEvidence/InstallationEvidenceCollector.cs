using Patched.Shared.Contract;

namespace Patched.Shared.InstallationEvidence;

// An authoritative reviewed native identity and fixed file location, never a package label,
// display-name heuristic, registry command line or tenant-supplied path.
internal sealed record ReviewedInstallationTarget(string IdentityKind, string IdentityValue,
    string AuthenticodeSubject, string InstallPath, string ExecutablePath);

internal sealed record InstallationEvidenceResult(IReadOnlyList<InventoryApp> Apps,
    InstallationEvidenceSummary Summary);

internal static class InstallationEvidenceCollector
{
    internal const int MaximumTargets = 24;
    internal static readonly TimeSpan PerTargetBudget = TimeSpan.FromSeconds(3);
    internal static readonly TimeSpan TotalBudget = TimeSpan.FromSeconds(15);

    internal static async Task<InstallationEvidenceResult> CollectVerifiedAsync(
        IReadOnlyList<InventoryApp> apps, InstallationEvidenceCatalogue? catalogue,
        Func<ReviewedInstallationTarget, TimeSpan, Task<AppInstallationEvidence>> probe,
        TimeProvider? timeProvider = null)
    {
        var clock = timeProvider ?? TimeProvider.System;
        var result = await CollectAsync(apps, catalogue?.Targets ?? [], probe, clock,
            catalogue is null ? null : () => catalogue.IsCurrent(clock.GetUtcNow())).ConfigureAwait(false);
        if (catalogue is null) return result;
        return result with
        {
            Apps = result.Apps.Select(app => app.InstallationEvidence is null || !string.IsNullOrEmpty(app.UserAccount) ? app : app with
            {
                InstallationEvidence = app.InstallationEvidence with
                {
                    CatalogueVersion = catalogue.CatalogueVersion,
                    DeliveryVersion = catalogue.DeliveryVersion,
                    ContentHash = catalogue.ContentHash,
                },
            }).ToArray(),
            Summary = result.Summary with
            {
                CatalogueVersion = catalogue.CatalogueVersion,
                DeliveryVersion = catalogue.DeliveryVersion,
                ContentHash = catalogue.ContentHash,
            },
        };
    }

    internal static async Task<InstallationEvidenceResult> CollectAsync(
        IReadOnlyList<InventoryApp> apps, IReadOnlyList<ReviewedInstallationTarget> targets,
        Func<ReviewedInstallationTarget, TimeSpan, Task<AppInstallationEvidence>> probe,
        TimeProvider? timeProvider = null, Func<bool>? isCurrent = null)
    {
        // Reviewed targets describe machine locations. Matching ARP identifiers do
        // not bind a user install to those privileged paths or their signatures.
        apps = apps.Select(app => string.IsNullOrEmpty(app.UserAccount) ? app : app with
            { InstallationEvidence = AppInstallationEvidence.PerUserUnverified() }).ToArray();
        InstallationEvidenceResult Unavailable(string reason) => new(apps, new()
        {
            CollectionStatus = "unavailable",
            Errors = [reason],
        });
        if (targets.Count == 0) return Unavailable("reviewed_targets_unavailable");
        if (targets.Count > MaximumTargets || targets.Any(t => !InstallationEvidenceCatalogue.ValidTarget(t)) ||
            targets.Select(t => t.IdentityValue).Distinct(StringComparer.OrdinalIgnoreCase).Count() != targets.Count)
            return Unavailable("reviewed_targets_invalid");

        var clock = timeProvider ?? TimeProvider.System;
        var started = clock.GetTimestamp();
        var result = apps.ToArray();
        var collected = new List<AppInstallationEvidence>();
        foreach (var target in targets)
        {
            var matches = Enumerable.Range(0, apps.Count).Where(i => string.IsNullOrEmpty(apps[i].UserAccount) && string.Equals(
                apps[i].Identifier, target.IdentityValue, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (matches.Length == 0) continue; // Not an authoritative absence observation.
            AppInstallationEvidence evidence;
            var remaining = TotalBudget - clock.GetElapsedTime(started);
            if (isCurrent?.Invoke() == false)
                evidence = AppInstallationEvidence.Unavailable("catalogue_not_current");
            else if (remaining <= TimeSpan.Zero)
                evidence = AppInstallationEvidence.Unavailable("collection_budget_exhausted");
            else
            {
                try
                {
                    // The probe owns a killable process: abandoning an in-process task would
                    // leave privileged IO running after the inventory deadline.
                    evidence = await probe(target, remaining < PerTargetBudget ? remaining : PerTargetBudget)
                        .ConfigureAwait(false);
                    if (isCurrent?.Invoke() == false)
                        evidence = AppInstallationEvidence.Unavailable("catalogue_not_current");
                }
                catch { evidence = AppInstallationEvidence.Unavailable("probe_failed"); }
            }
            // PAT-2129: a reviewed-target row that never reached the file read says so.
            if (evidence.ExecutableResolution is null)
                evidence = evidence with { ExecutableResolution = ExecutableResolutions.NotAttempted };
            collected.Add(evidence);
            foreach (var index in matches)
                result[index] = apps[index] with { InstallationEvidence = evidence };
        }
        if (collected.Count == 0) return Unavailable("no_reviewed_observations");
        return new(result, new()
        {
            CollectionStatus = collected.All(e => e.CollectionStatus == "complete") ? "complete"
                : collected.All(e => e.CollectionStatus == "unavailable") ? "unavailable" : "partial",
            Errors = collected.SelectMany(e => e.Errors).Distinct().Take(4).ToArray(),
        });
    }
}
