using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using Patched.Shared.Certificates;
using Patched.Shared.Contract;

namespace Patched.Service;

/// <summary>
/// Enumerates machine-level x509 certificates from LocalMachine\My, \Root and \CA for
/// the schema v3 inventory payload (PAT-641 / PAT-216, extended by PAT-1738).
///
/// Store scope and parity (PAT-1737, PAT-1738). Each agent reads a fixed set of
/// machine stores and reports every certificate in each of them, tagged with the
/// store it came from; neither filters by subject, issuer or any other certificate
/// text, because that text is chosen by whoever issued the certificate.
///   Windows: LocalMachine\My (device, VPN, 802.1X, MDM, code-signing and internally
///            issued certificates), LocalMachine\Root (trusted roots) and
///            LocalMachine\CA (intermediates). LocalMachine\AuthRoot is not
///            enumerated (PAT-1738 scope).
///   macOS:   /Library/Keychains/System.keychain (macos/lib/certs.sh), tagged
///            "System". Apple's built-in roots live in SystemRootCertificates.keychain,
///            which is not read, so they are out of scope by store choice.
/// Classifying well-known platform certificates is server-side work; this agent only
/// reports which store a row came from.
///
/// Failures never break the wider collection run, and never read as "no
/// certificates" (PAT-1732): a store that cannot be opened or enumerated is
/// unavailable and contributes no rows, a certificate that cannot be read is skipped.
/// The three stores are collected independently and then combined
/// (<see cref="CertCollectionLogic.Combine"/>): only when all three are unavailable is
/// the whole collection unavailable; if any store is unavailable while others are
/// read, or any certificate anywhere is unreadable, the collection is partial rather
/// than complete, because "complete" would let the server prune rows for a store this
/// run never actually looked at. Per-store routing lives in
/// <see cref="CertCollectionLogic"/>, the row mapping in <see cref="CertInventoryMapper"/>.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class CertCollector
{
    private static readonly (string Name, StoreName Store)[] Stores =
    [
        (CertStoreNames.My,   StoreName.My),
        (CertStoreNames.Root, StoreName.Root),
        (CertStoreNames.CA,   StoreName.CertificateAuthority),
    ];

    private readonly ILogger<CertCollector> _log;

    public CertCollector(ILogger<CertCollector> log) => _log = log;

    public CertCollectionResult Collect()
    {
        var now = DateTimeOffset.UtcNow;
        var perStore = new List<CertCollectionResult>(Stores.Length);

        foreach (var (name, store) in Stores)
        {
            string? firstSkipReason = null;
            var result = CertCollectionLogic.Collect(
                () => EnumerateStore(store),
                cert => ReadCert(cert, now, name),
                onUnavailable: ex => _log.LogWarning(ex,
                    "CertCollector: LocalMachine\\{Store} could not be read; that store's certificates omitted",
                    name),
                onSkipped: ex =>
                {
                    var reason = CertSkipReason.Of(ex);
                    firstSkipReason ??= reason;
                    _log.LogDebug(ex, "CertCollector: skipping cert in {Store}, reason={Reason}", name, reason);
                });

            // Same reason vocabulary as macos/lib/certs.sh, first reason kept (PAT-1739).
            if (result.Status == CertCollectionStatus.Partial)
            {
                _log.LogWarning(
                    "CertCollector: {Skipped} certificate(s) in {Store} could not be read; reason={Reason}",
                    result.Skipped, name, firstSkipReason ?? CertSkipReason.CertificateUnparseable);
            }

            perStore.Add(result);
        }

        var combined = CertCollectionLogic.Combine(perStore);
        if (combined.Status == CertCollectionStatus.Unavailable)
        {
            _log.LogWarning(
                "CertCollector: LocalMachine\\My, \\Root and \\CA could not be read; certificates omitted, collection_status unavailable");
        }

        return combined;
    }

    /// <summary>
    /// Opens one store on first iteration and closes it when enumeration ends, so an
    /// open or enumeration failure surfaces inside <see cref="CertCollectionLogic.Collect"/>.
    /// </summary>
    private static IEnumerable<X509Certificate2> EnumerateStore(StoreName store)
    {
        using var x509Store = new X509Store(store, StoreLocation.LocalMachine,
            OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        foreach (var cert in x509Store.Certificates)
            yield return cert;
    }

    /// <summary>Reads one certificate and disposes it. Every certificate is reported.</summary>
    private static InventoryCert ReadCert(X509Certificate2 cert, DateTimeOffset now, string store)
    {
        try
        {
            return CertInventoryMapper.FromX509(cert, now, store);
        }
        finally
        {
            cert.Dispose();
        }
    }
}
