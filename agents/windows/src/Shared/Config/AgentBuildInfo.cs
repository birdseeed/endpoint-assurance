namespace Patched.Shared.Config;

/// <summary>
/// Build-time metadata. Mirrors the placeholder-pending-CI-substitution pattern
/// already used by <c>BootstrapUpdater.CurrentVersion</c> ("Substituted at build
/// time by CI") — that substitution is not wired into the release pipeline yet
/// either; see the release workflow follow-up noted there.
/// </summary>
public static class AgentBuildInfo
{
    /// <summary>
    /// PAT-1110: sanity floor for the decommission directive's <c>expires_at</c>
    /// (contracts/agent-config.schema.json). A signed <c>expires_at</c> earlier than
    /// this floor is either a malformed value or evidence of a badly wrong system
    /// clock, and must never be treated as "due" — see
    /// <see cref="Patched.Shared.Removal.DecommissionEvaluator"/>.
    ///
    /// Deliberately a fixed constant rather than a computed one (e.g. an assembly or
    /// file timestamp): self-contained single-file publish output doesn't reliably
    /// carry a meaningful PE build timestamp, and a filesystem last-write-time would
    /// make this check non-deterministic across install/copy operations and hard to
    /// unit test. A fixed floor is simple, deterministic, and only needs bumping
    /// occasionally (same maintenance shape as CurrentVersion above) — whoever cuts a
    /// release far enough in the future to make this stale should move it forward.
    /// </summary>
    public const string BuildFloorUtc = "2026-07-01T00:00:00Z";

    /// <summary>Parsed <see cref="BuildFloorUtc"/>. Never throws — the literal is a test-covered constant.</summary>
    public static DateTimeOffset BuildFloor { get; } = DateTimeOffset.Parse(BuildFloorUtc);
}
