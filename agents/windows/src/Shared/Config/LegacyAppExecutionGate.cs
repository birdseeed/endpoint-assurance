namespace Patched.Shared.Config;

/// <summary>
/// PAT-1481's single fail-closed decision seam for retained legacy application
/// execution. This is a necessary, deliberately narrow permission, not a substitute
/// for an executor's existing tier, provenance, ring, queue or
/// operation-specific checks.
/// </summary>
public static class LegacyAppExecutionGate
{
    /// <summary>
    /// Only the exact JSON boolean true in the supplied config permits a quarantined
    /// legacy app executor to proceed. A missing config, an older config, null and
    /// any malformed value all deny.
    ///
    /// This deliberately evaluates only the already-deserialised value. It cannot
    /// attest to cache freshness, immutable config bytes or suspension because those
    /// facts are not part of <see cref="AgentConfig"/>. The shipping Windows Service
    /// excludes every legacy runner; this source-only safeguard must not be described
    /// as a runtime freshness/hash control. Any reviewed future reintroduction must
    /// pass one freshly verified snapshot plus revocation state to its final execution
    /// seam, as the macOS executors do.
    /// </summary>
    public static bool Allows(AgentConfig? config) => config?.LegacyAppExecutionEnabled == true;
}
