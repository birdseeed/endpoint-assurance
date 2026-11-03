using Patched.Shared.Contract;

namespace Patched.Shared.Certificates;

/// <summary>
/// PAT-1732: outcome of one certificate collection. <see cref="Certificates"/> is null
/// exactly when the certificates key must be left out of the payload, and
/// <see cref="Status"/> is the collection_status.certificates wire value.
/// Built only by <see cref="CertCollectionLogic"/> so the pairing cannot drift.
/// </summary>
internal sealed record CertCollectionResult
{
    private CertCollectionResult(IReadOnlyList<InventoryCert>? certificates, string status, int skipped)
    {
        Certificates = certificates;
        Status       = status;
        Skipped      = skipped;
    }

    /// <summary>Certificates to send, or null to omit the certificates key.</summary>
    public IReadOnlyList<InventoryCert>? Certificates { get; }

    /// <summary>One of the <see cref="CertCollectionStatus"/> values.</summary>
    public string Status { get; }

    /// <summary>Certificates that could not be read and were left out.</summary>
    public int Skipped { get; }

    internal static CertCollectionResult Create(IReadOnlyList<InventoryCert>? certificates, string status, int skipped) =>
        new(certificates, status, skipped);
}

/// <summary>
/// PAT-1732: platform-neutral failure routing for certificate collection, kept out of
/// the Windows-only <c>CertCollector</c> so Shared.Tests can cover it on macOS CI (same
/// split as PAT-1720's HardwareHealthLogic).
///
/// ABSENCE REQUIRES AUTHORITY. The server reads the certificates key as: absent, no
/// opinion; [] with status complete, prune every stored row; a non-empty list with
/// status complete, upsert and prune the rest; status partial, upsert and prune
/// nothing; status unavailable, write nothing. So:
///   store cannot be opened or enumerated  -> unavailable, key omitted (never [])
///   one or more certificates unreadable   -> partial, readable ones sent; key omitted
///                                            when none were readable, so an older
///                                            server that ignores collection_status
///                                            cannot read [] as "prune every row"
///   every certificate read                -> complete, list sent ([] included)
/// Mirrors macos/lib/certs.sh.
/// </summary>
internal static class CertCollectionLogic
{
    /// <summary>
    /// Runs one collection. <paramref name="enumerate"/> opens the store and yields its
    /// entries; an exception from the call itself or from iterating the sequence means
    /// the store was not read as a whole. <paramref name="read"/> converts one entry; an
    /// exception means that one entry could not be read. There is deliberately no way to
    /// exclude an entry (PAT-1737): a certificate left out of a complete collection is
    /// pruned server-side, so every entry is either reported or counted as skipped.
    /// </summary>
    public static CertCollectionResult Collect<T>(
        Func<IEnumerable<T>>     enumerate,
        Func<T, InventoryCert>   read,
        Action<Exception>?       onUnavailable = null,
        Action<Exception>?       onSkipped     = null)
    {
        ArgumentNullException.ThrowIfNull(enumerate);
        ArgumentNullException.ThrowIfNull(read);

        var certs   = new List<InventoryCert>();
        var skipped = 0;
        try
        {
            foreach (var entry in enumerate())
            {
                InventoryCert cert;
                try
                {
                    cert = read(entry) ?? throw new InvalidOperationException("certificate reader returned no row");
                }
                catch (Exception ex)
                {
                    skipped++;
                    Notify(onSkipped, ex);
                    continue;
                }

                certs.Add(cert);
            }
        }
        catch (Exception ex)
        {
            Notify(onUnavailable, ex);
            return Unavailable();
        }

        return FromStore(certs, skipped);
    }

    // A failing log callback must not turn a reading into an exception that breaks the
    // wider inventory run, nor change the collection outcome.
    private static void Notify(Action<Exception>? callback, Exception ex)
    {
        if (callback is null)
            return;
        try
        {
            callback(ex);
        }
        catch
        {
            // Swallowed on purpose; see above.
        }
    }

    /// <summary>The store could not be read as a whole: key omitted, status unavailable.</summary>
    public static CertCollectionResult Unavailable() =>
        CertCollectionResult.Create(null, CertCollectionStatus.Unavailable, 0);

    /// <summary>
    /// PAT-1738: combines one <see cref="CertCollectionResult"/> per Windows store (My,
    /// Root, CA — each already run through <see cref="Collect{T}"/> independently) into
    /// the single certificates payload. A store that could not be opened or enumerated
    /// contributes no rows and is a partial-visibility signal, not a claim that store was
    /// empty: reporting <c>complete</c> when only some of the three stores were actually
    /// read would let the server prune stored rows for a store this run never looked at
    /// (root AGENTS.md, "Certificates report what they could read"). Only when every
    /// store is unavailable does the whole collection become unavailable.
    ///   every store unavailable                    -> unavailable, key omitted
    ///   one or two stores unavailable, rest read    -> partial (readable stores' rows sent)
    ///   all stores read, one or more certs unreadable in any of them -> partial
    ///   all stores read, every certificate in each read             -> complete
    /// A store that is fully readable and simply empty is not a failure and does not
    /// affect the outcome; it just contributes no rows.
    /// </summary>
    public static CertCollectionResult Combine(IReadOnlyList<CertCollectionResult> perStore)
    {
        ArgumentNullException.ThrowIfNull(perStore);
        if (perStore.Count == 0)
            throw new ArgumentException("at least one store result is required", nameof(perStore));

        if (perStore.All(r => r.Status == CertCollectionStatus.Unavailable))
            return Unavailable();

        var certs           = new List<InventoryCert>();
        var skipped         = 0;
        var anyUnavailable  = false;

        foreach (var result in perStore)
        {
            if (result.Status == CertCollectionStatus.Unavailable)
            {
                anyUnavailable = true;
                continue;
            }

            if (result.Certificates is not null)
                certs.AddRange(result.Certificates);

            skipped += result.Skipped;
        }

        if (!anyUnavailable && skipped == 0)
            return CertCollectionResult.Create(certs, CertCollectionStatus.Complete, 0);

        // Same omission rule as FromStore: never send [] under a non-complete status,
        // so an older server that ignores collection_status cannot read it as "prune all".
        return CertCollectionResult.Create(certs.Count > 0 ? certs : null, CertCollectionStatus.Partial, skipped);
    }

    /// <summary>
    /// The store was read. <paramref name="read"/> holds the certificates that were read;
    /// <paramref name="skipped"/> counts those that could not be.
    /// </summary>
    public static CertCollectionResult FromStore(IReadOnlyList<InventoryCert> read, int skipped)
    {
        ArgumentNullException.ThrowIfNull(read);
        ArgumentOutOfRangeException.ThrowIfNegative(skipped);

        if (skipped == 0)
            return CertCollectionResult.Create(read, CertCollectionStatus.Complete, 0);

        return CertCollectionResult.Create(read.Count > 0 ? read : null, CertCollectionStatus.Partial, skipped);
    }
}
