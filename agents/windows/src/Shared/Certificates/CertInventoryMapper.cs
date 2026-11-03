using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Patched.Shared.Contract;

namespace Patched.Shared.Certificates;

/// <summary>
/// PAT-1737: converts one X.509 certificate into its inventory row. Kept out of the
/// Windows-only <c>CertCollector</c> so Shared.Tests can run it on macOS CI against real
/// certificates (same split as PAT-1732's <see cref="CertCollectionLogic"/>).
///
/// There is no exclusion here, and there must not be one. Every certificate the store
/// yields becomes a row. The subject is attacker-controlled text: a rogue certificate
/// named "Microsoft Update Root CA" is exactly the certificate an assurance agent has to
/// report, and a collection that silently drops it still reads as complete, so the
/// server would also prune any stored row for it. Recognising well-known platform
/// certificates is classification, and it belongs server-side where it can use
/// thumbprints and issuer chains rather than display text.
/// </summary>
internal static class CertInventoryMapper
{
    private const string BasicConstraintsOid = "2.5.29.19";
    private const string ExtKeyUsageOid      = "2.5.29.37";

    /// <summary>
    /// Reads one certificate. An exception means this certificate could not be read;
    /// <see cref="CertCollectionLogic.Collect"/> counts it as skipped. A
    /// <see cref="CertSkippedException"/> names the reason (PAT-1739). Does not dispose
    /// <paramref name="cert"/>. <paramref name="store"/> (PAT-1738) is the
    /// <see cref="CertStoreNames"/> value the row is tagged with; defaults to
    /// <see cref="CertStoreNames.My"/> for callers that read a single store.
    /// </summary>
    public static InventoryCert FromX509(X509Certificate2 cert, DateTimeOffset now, string store = CertStoreNames.My)
    {
        ArgumentNullException.ThrowIfNull(cert);
        ArgumentException.ThrowIfNullOrEmpty(store);

        var extensions = FindClassifiedExtensions(cert);

        // X509Certificate2.NotAfter is local time (DateTimeKind.Local). Pairing it with a
        // zero offset throws whenever the local offset at that date is not zero (every
        // non-UTC zone, and UK certificates expiring during BST), which skipped the
        // certificate and marked the whole collection partial. Convert first.
        var notAfter = new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero);

        return new InventoryCert
        {
            Store              = store,
            SubjectCn          = ParseCn(cert.Subject),
            IssuerCn           = ParseCn(cert.Issuer),
            Sha1               = cert.Thumbprint.ToLowerInvariant(),
            NotAfter           = notAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            DaysUntilExpiry    = (int)Math.Round((notAfter - now).TotalDays),
            ExtKeyUsage        = GetExtKeyUsage(extensions),
            BasicConstraintsCa = IsCA(extensions),
            IsSelfSigned       = string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase),
        };
    }

    internal static string ParseCn(string distinguishedName)
    {
        const string cnPrefix = "CN=";
        var span = distinguishedName.AsSpan();
        var idx  = span.IndexOf(cnPrefix, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
            return distinguishedName;

        var rest  = span[(idx + cnPrefix.Length)..];
        var comma = rest.IndexOf(',');
        return (comma >= 0 ? rest[..comma] : rest).Trim().ToString();
    }

    /// <summary>
    /// PAT-1739: finds the basicConstraints and extKeyUsage extensions and validates each
    /// value as DER, walking the extensions in certificate order the way
    /// macos/lib/certs.sh walks them. The collection indexer returns the first match
    /// and .NET's decoders are lenient, so a second basicConstraints (for example CA:FALSE
    /// then a critical CA:TRUE) or a BER-encoded value would otherwise be classified from
    /// whichever copy or reading .NET happened to pick. A repeat is
    /// <see cref="CertSkipReason.ExtensionsAmbiguous"/>; a value that is not strict DER in
    /// the shape X.509 requires is <see cref="CertSkipReason.DerUnparseable"/>. Either
    /// skips the certificate; neither is ever read as "not a CA" or "no EKU".
    /// </summary>
    private static ClassifiedExtensions FindClassifiedExtensions(X509Certificate2 cert)
    {
        var found = new ClassifiedExtensions();

        foreach (var ext in cert.Extensions)
        {
            switch (ext.Oid?.Value)
            {
                case BasicConstraintsOid:
                    if (found.BasicConstraints is not null)
                        throw Ambiguous("basicConstraints");
                    found.BasicConstraintsCa = ReadBasicConstraintsDer(ext.RawData);
                    found.BasicConstraints   = ext;
                    break;

                case ExtKeyUsageOid:
                    if (found.ExtKeyUsage is not null)
                        throw Ambiguous("extKeyUsage");
                    found.ExtKeyUsageOids = ReadExtKeyUsageDer(ext.RawData);
                    found.ExtKeyUsage     = ext;
                    break;
            }
        }

        return found;
    }

    private sealed class ClassifiedExtensions
    {
        public X509Extension?        BasicConstraints;
        public bool                  BasicConstraintsCa;
        public X509Extension?        ExtKeyUsage;
        public IReadOnlyList<string> ExtKeyUsageOids = Array.Empty<string>();
    }

    /// <summary>
    /// <c>BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }</c>,
    /// strict DER with nothing trailing. DER mode rejects a cA byte other than 0x00 or
    /// 0xFF, non-minimal lengths and integers, and indefinite lengths. Returns cA.
    /// </summary>
    internal static bool ReadBasicConstraintsDer(byte[] extnValue)
    {
        try
        {
            var reader = new AsnReader(extnValue, AsnEncodingRules.DER);
            var seq    = reader.ReadSequence();
            reader.ThrowIfNotEmpty();

            var ca = false;
            if (seq.HasData && seq.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                ca = seq.ReadBoolean();

            if (seq.HasData && seq.PeekTag().HasSameClassAndValue(Asn1Tag.Integer)
                && seq.ReadInteger() < BigInteger.Zero)
            {
                throw new AsnContentException("basicConstraints pathLenConstraint is negative");
            }

            seq.ThrowIfNotEmpty();
            return ca;
        }
        catch (AsnContentException ex)
        {
            throw Unparseable("basicConstraints", ex);
        }
    }

    /// <summary>
    /// <c>ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId</c> (OBJECT
    /// IDENTIFIER), strict DER with nothing trailing. Returns the dotted OIDs in order.
    /// </summary>
    internal static IReadOnlyList<string> ReadExtKeyUsageDer(byte[] extnValue)
    {
        try
        {
            var reader = new AsnReader(extnValue, AsnEncodingRules.DER);
            var seq    = reader.ReadSequence();
            reader.ThrowIfNotEmpty();

            var oids = new List<string>();
            while (seq.HasData)
                oids.Add(seq.ReadObjectIdentifier());

            if (oids.Count == 0)
                throw new AsnContentException("extKeyUsage holds no key purpose");

            return oids;
        }
        catch (AsnContentException ex)
        {
            throw Unparseable("extKeyUsage", ex);
        }
    }

    private static CertSkippedException Ambiguous(string extension) =>
        new(CertSkipReason.ExtensionsAmbiguous, $"certificate has more than one {extension} extension");

    private static CertSkippedException Unparseable(string extension, Exception? inner = null) =>
        new(CertSkipReason.DerUnparseable, $"certificate {extension} extension is not valid DER", inner);

    /// <summary>
    /// The emitted values are unchanged from before PAT-1739 (friendly name where .NET
    /// has one, else the dotted OID). The DER reading only confirms them: .NET's decoder
    /// must yield the same OIDs in the same order, or the certificate is skipped.
    /// </summary>
    private static string[] GetExtKeyUsage(ClassifiedExtensions found)
    {
        var ext = found.ExtKeyUsage;
        if (ext is null)
            return Array.Empty<string>();

        Oid[] decoded;
        try
        {
            var eku = ext as X509EnhancedKeyUsageExtension
                ?? new X509EnhancedKeyUsageExtension(new AsnEncodedData(ext.Oid!, ext.RawData), ext.Critical);
            decoded = eku.EnhancedKeyUsages.Cast<Oid>().ToArray();
        }
        catch (CryptographicException ex)
        {
            throw Unparseable("extKeyUsage", ex);
        }

        if (!decoded.Select(o => o.Value).SequenceEqual(found.ExtKeyUsageOids, StringComparer.Ordinal))
            throw Unparseable("extKeyUsage");

        return decoded
            .Select(o => o.FriendlyName ?? o.Value ?? "")
            .Where(s => s.Length > 0)
            .ToArray();
    }

    /// <summary>
    /// Same is_ca meaning as before PAT-1739 (cA TRUE, absent extension false), confirmed
    /// against the DER reading.
    /// </summary>
    private static bool IsCA(ClassifiedExtensions found)
    {
        var ext = found.BasicConstraints;
        if (ext is null)
            return false;

        bool decoded;
        try
        {
            var bc = ext as X509BasicConstraintsExtension
                ?? new X509BasicConstraintsExtension(new AsnEncodedData(ext.Oid!, ext.RawData), ext.Critical);
            decoded = bc.CertificateAuthority;
        }
        catch (CryptographicException ex)
        {
            throw Unparseable("basicConstraints", ex);
        }

        if (decoded != found.BasicConstraintsCa)
            throw Unparseable("basicConstraints");

        return decoded;
    }
}
