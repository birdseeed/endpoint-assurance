namespace Patched.Service;

/// <summary>
/// PAT-2422: the single place a retired agent-health reason is recorded.
///
/// A (kind, subject) pair belongs here once the shipped service no longer has any
/// code that records it. A store written by an older release can still hold an
/// active fault for such a pair, and because nothing will ever record the success
/// that clears it, the device would report itself degraded for good. That makes the
/// degraded signal useless for finding the devices that really are unhealthy.
/// <see cref="AgentHealthStore"/> therefore drops every pair listed here each time
/// it loads the store, and never puts one on the wire.
///
/// To retire a reason: remove its recorder from the shipped service, then add the
/// pair to <see cref="Pairs"/> with the ticket and why. Nothing else needs to change.
/// ci/test-windows-assurance-build-seam.py reads this list and fails the build if any
/// source compiled into Patched.Service still names a listed pair alongside a
/// RecordFailure or RecordSuccess call, so a pair cannot sit here while live code
/// depends on reporting it. Keep one pair per line in the form below: the guard
/// parses it.
/// </summary>
internal static class RetiredHealthReasons
{
    internal static readonly IReadOnlyList<(string Kind, string Subject)> Pairs = new[]
    {
        // PAT-2245: transport health of the signed app catalogue, which is no longer fetched.
        ("sync_never_succeeded", "catalogue"),
        // PAT-1531 / PAT-2422: the package engine is not part of the assurance agent by
        // design, so its absence is not a fault. The only recorder left is the quarantined
        // InstallRunner, which Service.csproj excludes from the shipped service. Restoring
        // an engine to the service means removing this line first; the guard enforces it.
        ("capability_missing", "package_engine"),
    };

    internal static bool IsRetired(string kind, string subject) => Pairs.Contains((kind, subject));

    /// <summary>
    /// Removes every retired pair from one store section (kind -&gt; subject -&gt; value),
    /// along with any kind left with no subjects. Returns true if anything was removed.
    /// Touches nothing that is not listed in <see cref="Pairs"/>.
    /// </summary>
    internal static bool RemoveFrom<T>(Dictionary<string, Dictionary<string, T>> section)
    {
        var removed = false;
        foreach (var (kind, subject) in Pairs)
        {
            if (!section.TryGetValue(kind, out var subjects) || !subjects.Remove(subject))
                continue;
            removed = true;
            if (subjects.Count == 0)
                section.Remove(kind);
        }
        return removed;
    }
}
