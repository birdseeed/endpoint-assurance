namespace Patched.Shared.Certificates;

/// <summary>
/// PAT-1739: why a certificate was left out of a collection. The values are the
/// <c>reason=</c> vocabulary macos/lib/certs.sh logs on its PATCHED_COLLECTION_WARNING
/// line, so a skip reads the same on both agents.
/// </summary>
internal static class CertSkipReason
{
    /// <summary>basicConstraints or extKeyUsage appears more than once.</summary>
    public const string ExtensionsAmbiguous = "extensions_ambiguous";

    /// <summary>A basicConstraints or extKeyUsage value is not in the DER shape X.509 requires.</summary>
    public const string DerUnparseable = "der_unparseable";

    /// <summary>The certificate could not be read for any other reason.</summary>
    public const string CertificateUnparseable = "certificate_unparseable";

    /// <summary>The reason carried by <paramref name="ex"/>, or <see cref="CertificateUnparseable"/>.</summary>
    public static string Of(Exception ex) =>
        ex is CertSkippedException skipped ? skipped.Reason : CertificateUnparseable;
}

/// <summary>
/// PAT-1739: thrown by <see cref="CertInventoryMapper"/> when a certificate must not be
/// classified. <see cref="CertCollectionLogic.Collect"/> counts it as skipped, so the
/// collection is partial and the server prunes nothing. There is no fallback
/// classification: a certificate whose CA flag or EKU cannot be read with certainty is
/// never reported as a non-CA with no EKU.
/// </summary>
internal sealed class CertSkippedException : Exception
{
    public CertSkippedException(string reason, string message, Exception? inner = null)
        : base(message, inner)
    {
        Reason = reason;
    }

    /// <summary>One of the <see cref="CertSkipReason"/> values.</summary>
    public string Reason { get; }
}
