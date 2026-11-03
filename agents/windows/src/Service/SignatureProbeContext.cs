using Patched.Shared.InstallationEvidence;

namespace Patched.Service;

// PAT-2116: per-helper-run state for signature reads. Lives only inside the killable
// helper process: the parent's verdict cache arrives on stdin, and the two machine facts
// the verdict needs (the AuthRoot store and whether the catalog database answers) are
// read at most once per run, and only when a verdict actually asks for them.
internal sealed class SignatureProbeContext
{
    private readonly Dictionary<SignatureCacheKey, SignatureObservation> _cache;
    private readonly Lazy<HashSet<string>> _thirdPartyRoots;
    private readonly Lazy<bool> _catalogHealthy;

    private SignatureProbeContext(IEnumerable<SignatureCacheEntry> cache, Func<HashSet<string>> thirdPartyRoots,
        Func<bool> catalogHealthy)
    {
        _cache = new();
        foreach (var entry in cache)
            if (SignatureVerdictCache.Valid(entry.Key) && entry.Observation is not null)
                _cache[entry.Key] = entry.Observation;
        _thirdPartyRoots = new(thirdPartyRoots);
        _catalogHealthy = new(catalogHealthy);
    }

    internal static SignatureProbeContext Uncached() => Production([]);

    internal static SignatureProbeContext Production(IEnumerable<SignatureCacheEntry> cache) =>
        new(cache, WindowsInstallationEvidence.ReadThirdPartyRootThumbprints, ProbeCatalogDatabase);

    internal bool TryGetCached(SignatureCacheKey key, out SignatureObservation observation) =>
        _cache.TryGetValue(key, out observation!);

    internal bool InThirdPartyRootStore(string rootSha256) => _thirdPartyRoots.Value.Contains(rootSha256);

    internal bool CatalogDatabaseHealthy() => _catalogHealthy.Value;

    // The canary for the unsigned rule: a catalog database that cannot find the SHA-256
    // membership of a shipped, catalog-signed System32 binary cannot be trusted to say that
    // no catalog lists some other file. chkdsk.exe is in 12 catalogs on Windows 11 26100
    // (PAT-1981); powershell.exe is the fallback. Any failure is "not healthy", which only
    // ever withholds "unsigned" and turns it into "unknown".
    private static bool ProbeCatalogDatabase()
    {
        foreach (var relative in new[] { "chkdsk.exe", @"WindowsPowerShell\v1.0\powershell.exe" })
        {
            try
            {
                using var file = WindowsInstallationEvidence.OpenLocalFile(Path.Combine(Environment.SystemDirectory, relative));
                var handle = file.Stream.SafeFileHandle;
                var retained = false;
                try
                {
                    handle.DangerousAddRef(ref retained);
                    if (WindowsInstallationEvidence.CatalogPresenceFor(handle.DangerousGetHandle(), "SHA256") == CatalogPresence.Present)
                        return true;
                }
                finally
                {
                    if (retained) handle.DangerousRelease();
                }
            }
            catch
            {
                // Try the next canary; none answering is unhealthy.
            }
        }
        return false;
    }
}
