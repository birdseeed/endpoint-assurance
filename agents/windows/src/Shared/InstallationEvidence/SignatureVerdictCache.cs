using System.Text.Json.Serialization;

namespace Patched.Shared.InstallationEvidence;

// PAT-2116: a verdict is reused only for the same content (SHA-256), size and last-write
// time. The helper always re-hashes the file, so a changed file can never inherit an old
// verdict; what the cache saves is WinVerifyTrust, the chain build and the catalog walk.
internal sealed record SignatureCacheKey(
    [property: JsonPropertyName("sha256")] string Sha256,
    [property: JsonPropertyName("size")] long Size,
    [property: JsonPropertyName("mtime")] long LastWriteUtcTicks);

internal sealed record SignatureCacheEntry(
    [property: JsonPropertyName("key")] SignatureCacheKey Key,
    [property: JsonPropertyName("observation")] SignatureObservation Observation);

// Parent-process memory only: it is lost on service restart and never written to disk, so
// the helper keeps its no-filesystem-writes property. The helper receives a snapshot on
// stdin and reports new verdicts back; the parent is the only writer.
internal sealed class SignatureVerdictCache
{
    // The trust store and catalog database change without the file changing, so a verdict
    // expires. "unknown" is re-asked sooner: it is the verdict a transient failure produces.
    internal static readonly TimeSpan DefinitiveLifetime = TimeSpan.FromHours(24);
    internal static readonly TimeSpan UnknownLifetime = TimeSpan.FromHours(1);
    internal const int Capacity = 4096;

    private readonly TimeProvider _clock;
    private readonly object _gate = new();
    private readonly Dictionary<SignatureCacheKey, (SignatureObservation Observation, DateTimeOffset Expires)> _entries = new();

    internal SignatureVerdictCache(TimeProvider? clock = null) => _clock = clock ?? TimeProvider.System;

    internal int Count { get { lock (_gate) return _entries.Count; } }

    internal static bool Cacheable(SignatureObservation observation) => observation.State is
        SignatureStates.Valid or SignatureStates.Invalid or SignatureStates.Unsigned or SignatureStates.Unknown;

    internal bool TryGet(SignatureCacheKey key, out SignatureObservation observation)
    {
        lock (_gate)
        {
            if (_entries.TryGetValue(key, out var entry) && entry.Expires > _clock.GetUtcNow())
            {
                observation = entry.Observation;
                return true;
            }
            _entries.Remove(key);
            observation = null!;
            return false;
        }
    }

    internal void Set(SignatureCacheKey key, SignatureObservation observation)
    {
        if (!Valid(key) || !Cacheable(observation)) return;
        var now = _clock.GetUtcNow();
        var lifetime = observation.State == SignatureStates.Unknown ? UnknownLifetime : DefinitiveLifetime;
        lock (_gate)
        {
            _entries[key] = (observation, now + lifetime);
            if (_entries.Count <= Capacity) return;
            foreach (var expired in _entries.Where(e => e.Value.Expires <= now).Select(e => e.Key).ToArray())
                _entries.Remove(expired);
            while (_entries.Count > Capacity)
                _entries.Remove(_entries.MinBy(e => e.Value.Expires).Key);
        }
    }

    // Unexpired entries, for the helper's stdin.
    internal IReadOnlyList<SignatureCacheEntry> Snapshot()
    {
        var now = _clock.GetUtcNow();
        lock (_gate)
            return _entries.Where(e => e.Value.Expires > now)
                .Select(e => new SignatureCacheEntry(e.Key, e.Value.Observation)).ToArray();
    }

    internal static bool Valid(SignatureCacheKey? key) =>
        key is not null && InstallationEvidenceCatalogue.IsHash(key.Sha256) && key.Size > 0 && key.LastWriteUtcTicks > 0;
}
