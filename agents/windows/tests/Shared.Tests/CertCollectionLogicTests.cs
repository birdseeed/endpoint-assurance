using Patched.Shared.Certificates;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1732: platform-neutral tests for <see cref="CertCollectionLogic"/>. No X509Store:
/// the store is a delegate, so every failure route runs on macOS CI.
/// </summary>
public sealed class CertCollectionLogicTests
{
    private static InventoryCert Cert(string cn) => Cert(cn, CertStoreNames.My);

    private static InventoryCert Cert(string cn, string store) => new()
    {
        Store              = store,
        SubjectCn          = cn,
        IssuerCn           = cn,
        Sha1               = cn.ToLowerInvariant(),
        NotAfter           = "2027-01-01T00:00:00Z",
        DaysUntilExpiry    = 100,
        ExtKeyUsage        = [],
        BasicConstraintsCa = false,
        IsSelfSigned       = true,
    };

    private static IEnumerable<string> ThrowsAfter(IEnumerable<string> first)
    {
        foreach (var item in first)
            yield return item;
        throw new InvalidOperationException("store enumeration failed");
    }

    [Fact]
    public void StoreCannotBeOpened_IsUnavailable_WithCertificatesNull()
    {
        Exception? logged = null;
        var result = CertCollectionLogic.Collect<string>(
            () => throw new UnauthorizedAccessException("denied"),
            Cert,
            onUnavailable: ex => logged = ex);

        Assert.Equal(CertCollectionStatus.Unavailable, result.Status);
        Assert.Null(result.Certificates);
        Assert.IsType<UnauthorizedAccessException>(logged);
    }

    [Fact]
    public void StoreOpenFailsLazily_OnFirstIteration_IsUnavailable()
    {
        var result = CertCollectionLogic.Collect(() => ThrowsAfter([]), Cert);

        Assert.Equal(CertCollectionStatus.Unavailable, result.Status);
        Assert.Null(result.Certificates);
    }

    /// <summary>Certificates read before the store failed are not a partial reading.</summary>
    [Fact]
    public void EnumerationFailsMidway_IsUnavailable_NotPartial()
    {
        var result = CertCollectionLogic.Collect(() => ThrowsAfter(["A", "B"]), Cert);

        Assert.Equal(CertCollectionStatus.Unavailable, result.Status);
        Assert.Null(result.Certificates);
    }

    [Fact]
    public void EveryCertificateRead_IsComplete_InStoreOrder()
    {
        var result = CertCollectionLogic.Collect(() => new[] { "A", "B" }, Cert);

        Assert.Equal(CertCollectionStatus.Complete, result.Status);
        Assert.Equal(new[] { "A", "B" }, result.Certificates!.Select(c => c.SubjectCn).ToArray());
        Assert.Equal(0, result.Skipped);
    }

    [Fact]
    public void EmptyStore_IsComplete_WithEmptyListNotNull()
    {
        var result = CertCollectionLogic.Collect(() => Array.Empty<string>(), Cert);

        Assert.Equal(CertCollectionStatus.Complete, result.Status);
        Assert.NotNull(result.Certificates);
        Assert.Empty(result.Certificates!);
    }

    /// <summary>
    /// PAT-1737: there is no exclusion path. A reader that yields no row is a failed read
    /// (partial, nothing pruned), never a silent omission from a complete collection.
    /// </summary>
    [Fact]
    public void ReaderReturningNoRow_IsSkipped_NotSilentlyExcluded()
    {
        var result = CertCollectionLogic.Collect(
            () => new[] { "Microsoft Update Root CA", "VPN" },
            s => s.StartsWith("Microsoft", StringComparison.Ordinal) ? null! : Cert(s));

        Assert.Equal(CertCollectionStatus.Partial, result.Status);
        Assert.Equal(1, result.Skipped);
        Assert.Equal(new[] { "VPN" }, result.Certificates!.Select(c => c.SubjectCn).ToArray());
    }

    [Fact]
    public void OneCertificateUnreadable_IsPartial_OthersSent()
    {
        var skippedLogs = 0;
        var result = CertCollectionLogic.Collect(
            () => new[] { "A", "BAD", "C" },
            s => s == "BAD" ? throw new FormatException("bad cert") : Cert(s),
            onSkipped: _ => skippedLogs++);

        Assert.Equal(CertCollectionStatus.Partial, result.Status);
        Assert.Equal(new[] { "A", "C" }, result.Certificates!.Select(c => c.SubjectCn).ToArray());
        Assert.Equal(1, result.Skipped);
        Assert.Equal(1, skippedLogs);
    }

    /// <summary>
    /// Nothing readable: omit the key rather than send [], which an older server that
    /// ignores collection_status would treat as "prune every row".
    /// </summary>
    [Fact]
    public void NoCertificateReadable_IsPartial_WithCertificatesNull()
    {
        var result = CertCollectionLogic.Collect(
            () => new[] { "BAD1", "BAD2" },
            _ => throw new FormatException("bad cert"));

        Assert.Equal(CertCollectionStatus.Partial, result.Status);
        Assert.Null(result.Certificates);
        Assert.Equal(2, result.Skipped);
    }

    [Fact]
    public void ThrowingLogCallbacks_DoNotChangeOutcome_OrEscape()
    {
        var unavailable = CertCollectionLogic.Collect<string>(
            () => throw new IOException("gone"),
            Cert,
            onUnavailable: _ => throw new InvalidOperationException("logger down"));
        Assert.Equal(CertCollectionStatus.Unavailable, unavailable.Status);

        var partial = CertCollectionLogic.Collect(
            () => new[] { "A", "BAD" },
            s => s == "BAD" ? throw new FormatException() : Cert(s),
            onSkipped: _ => throw new InvalidOperationException("logger down"));
        Assert.Equal(CertCollectionStatus.Partial, partial.Status);
        Assert.Single(partial.Certificates!);
    }

    [Fact]
    public void FromStore_RejectsNegativeSkipped()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CertCollectionLogic.FromStore([], -1));
    }

    [Fact]
    public void StatusValues_AreLowercaseWireValues()
    {
        Assert.Equal("complete", CertCollectionStatus.Complete);
        Assert.Equal("partial", CertCollectionStatus.Partial);
        Assert.Equal("unavailable", CertCollectionStatus.Unavailable);
    }

    // ---- Combine (PAT-1738: My/Root/CA merged into one collection_status.certificates) ----

    private static CertCollectionResult StoreResult(string store, params string[] cns) =>
        CertCollectionLogic.Collect(() => cns, cn => Cert(cn, store));

    [Fact]
    public void Combine_AllThreeStoresComplete_IsComplete_RowsFromEachStore()
    {
        var my   = StoreResult(CertStoreNames.My, "device-cert");
        var root = StoreResult(CertStoreNames.Root, "root-ca");
        var ca   = StoreResult(CertStoreNames.CA, "intermediate-ca");

        var combined = CertCollectionLogic.Combine([my, root, ca]);

        Assert.Equal(CertCollectionStatus.Complete, combined.Status);
        Assert.Equal(0, combined.Skipped);
        Assert.Equal(
            new[] { "device-cert", "root-ca", "intermediate-ca" },
            combined.Certificates!.Select(c => c.SubjectCn).ToArray());
        Assert.Equal(
            new[] { CertStoreNames.My, CertStoreNames.Root, CertStoreNames.CA },
            combined.Certificates!.Select(c => c.Store).ToArray());
    }

    [Fact]
    public void Combine_AllThreeStoresEmptyButReadable_IsComplete_WithEmptyList()
    {
        var my   = StoreResult(CertStoreNames.My);
        var root = StoreResult(CertStoreNames.Root);
        var ca   = StoreResult(CertStoreNames.CA);

        var combined = CertCollectionLogic.Combine([my, root, ca]);

        Assert.Equal(CertCollectionStatus.Complete, combined.Status);
        Assert.NotNull(combined.Certificates);
        Assert.Empty(combined.Certificates!);
    }

    /// <summary>
    /// One store failing to open outright, while the other two are fully readable, is
    /// partial visibility, not a full collection failure: reporting complete here would
    /// let the server prune stored rows for the store this run never actually read.
    /// </summary>
    [Fact]
    public void Combine_OneStoreUnavailable_OthersComplete_IsPartial_NotComplete()
    {
        var my   = StoreResult(CertStoreNames.My, "device-cert");
        var root = CertCollectionLogic.Unavailable();
        var ca   = StoreResult(CertStoreNames.CA, "intermediate-ca");

        var combined = CertCollectionLogic.Combine([my, root, ca]);

        Assert.Equal(CertCollectionStatus.Partial, combined.Status);
        Assert.Equal(0, combined.Skipped);
        Assert.Equal(
            new[] { "device-cert", "intermediate-ca" },
            combined.Certificates!.Select(c => c.SubjectCn).ToArray());
    }

    [Fact]
    public void Combine_AllThreeStoresUnavailable_IsUnavailable_WithCertificatesNull()
    {
        var combined = CertCollectionLogic.Combine(
            [CertCollectionLogic.Unavailable(), CertCollectionLogic.Unavailable(), CertCollectionLogic.Unavailable()]);

        Assert.Equal(CertCollectionStatus.Unavailable, combined.Status);
        Assert.Null(combined.Certificates);
    }

    /// <summary>
    /// Every store opened and every certificate in each was readable except one: partial,
    /// same as the single-store case, with rows from the healthy stores still sent.
    /// </summary>
    [Fact]
    public void Combine_AllStoresReadable_OneCertUnreadableInOne_IsPartial()
    {
        var my   = StoreResult(CertStoreNames.My, "device-cert");
        var root = CertCollectionLogic.Collect(
            () => new[] { "good-root", "BAD" },
            cn => cn == "BAD" ? throw new FormatException("bad cert") : Cert(cn, CertStoreNames.Root));
        var ca = StoreResult(CertStoreNames.CA, "intermediate-ca");

        var combined = CertCollectionLogic.Combine([my, root, ca]);

        Assert.Equal(CertCollectionStatus.Partial, combined.Status);
        Assert.Equal(1, combined.Skipped);
        Assert.Equal(
            new[] { "device-cert", "good-root", "intermediate-ca" },
            combined.Certificates!.Select(c => c.SubjectCn).ToArray());
    }

    [Fact]
    public void Combine_UnavailableStore_PlusNothingReadableElsewhere_OmitsCertificatesKey()
    {
        var my   = CertCollectionLogic.Unavailable();
        var root = CertCollectionLogic.Collect(() => new[] { "BAD" }, _ => throw new FormatException());
        var ca   = StoreResult(CertStoreNames.CA);

        var combined = CertCollectionLogic.Combine([my, root, ca]);

        Assert.Equal(CertCollectionStatus.Partial, combined.Status);
        Assert.Null(combined.Certificates);
        Assert.Equal(1, combined.Skipped);
    }

    [Fact]
    public void Combine_RejectsEmptyList()
    {
        Assert.Throws<ArgumentException>(() => CertCollectionLogic.Combine([]));
    }
}
