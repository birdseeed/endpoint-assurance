using Patched.Shared.Paths;
using Patched.Shared.Security;

namespace Patched.Service;

/// <summary>
/// PAT-2245: the signed app catalogue is retired end to end, and the agent no longer
/// fetches, verifies or reads it. Releases before this one ran <c>CatalogueSyncService</c>,
/// which left <c>catalogue.json</c>, <c>catalogue.version</c> and <c>catalogue.etag</c>
/// under <see cref="PathConstants.StateDir"/>. Nothing refreshes or consumes them now,
/// so the service removes them once at every startup. With nothing left to remove this
/// is a handful of existence checks.
///
/// Best effort and never fatal: every failure is logged and returned, never thrown, so a
/// stale file can never stop the service from starting.
///
/// The service runs as SYSTEM, so a delete under %ProgramData% must not be redirectable
/// (the reasoning in <c>CredentialFileStorePurge</c>). Nothing is deleted unless the state
/// directory passes <see cref="SecureStagingDirectory.VerifyTrusted"/> (read-only, never
/// repairs), and a file whose path has a reparse point anywhere below the state directory
/// (<see cref="PathSafety.HasReparsePointInChain"/>, checked immediately before its delete)
/// is left alone and reported as refused. A directory carrying one of the names is not a
/// file this agent wrote and is also left alone.
/// </summary>
internal static class RetiredCatalogueCleanup
{
    /// <summary>The cache files the retired <c>CatalogueFetcher</c> wrote, by name.</summary>
    internal static readonly IReadOnlyList<string> CacheFileNames =
        ["catalogue.json", "catalogue.version", "catalogue.etag"];

    internal sealed record Result(IReadOnlyList<string> Removed, IReadOnlyList<string> Refused, IReadOnlyList<string> Failed);

    /// <summary>Production wiring: the real state directory and trust primitives.</summary>
    internal static Result RunProduction(ILogger log) => Run(
        log, PathConstants.StateDir, SecureStagingDirectory.VerifyTrusted, PathSafety.HasReparsePointInChain);

    /// <param name="verifyTrustedDirectory">Throws when the directory is not trusted.</param>
    /// <param name="hasReparsePointInChain">(trusted root, target) as <see cref="PathSafety.HasReparsePointInChain"/>.</param>
    internal static Result Run(
        ILogger log,
        string stateDir,
        Action<string> verifyTrustedDirectory,
        Func<string, string, bool> hasReparsePointInChain)
    {
        var removed = new List<string>();
        var refused = new List<string>();
        var failed = new List<string>();

        try
        {
            if (!Directory.Exists(stateDir))
                return new Result(removed, refused, failed);
            verifyTrustedDirectory(stateDir);
        }
        catch (Exception ex)
        {
            log.LogWarning(
                "Retired catalogue cleanup: state directory {Dir} is not trusted ({Error}); leaving any catalogue cache in place",
                stateDir, ex.GetType().Name);
            failed.Add(stateDir);
            return new Result(removed, refused, failed);
        }

        foreach (var name in CacheFileNames)
        {
            var path = Path.Combine(stateDir, name);
            try
            {
                // Before the existence check: a link to a missing or non-file target can
                // report as absent and must still be refused rather than skipped quietly.
                if (hasReparsePointInChain(stateDir, path))
                {
                    log.LogWarning(
                        "Retired catalogue cleanup: {Path} is or sits behind a reparse point; not deleting it", path);
                    refused.Add(path);
                    continue;
                }
                if (!File.Exists(path))
                    continue;

                File.Delete(path);
                if (File.Exists(path))
                {
                    log.LogWarning("Retired catalogue cleanup: {Path} still present after delete", path);
                    failed.Add(path);
                    continue;
                }
                log.LogInformation("Retired catalogue cleanup: removed {Path} (the signed app catalogue is retired)", path);
                removed.Add(path);
            }
            catch (Exception ex)
            {
                log.LogWarning(
                    "Retired catalogue cleanup: could not remove {Path} ({Error}); will retry at next startup",
                    path, ex.GetType().Name);
                failed.Add(path);
            }
        }

        return new Result(removed, refused, failed);
    }
}
