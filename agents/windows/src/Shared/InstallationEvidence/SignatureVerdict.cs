using System.Collections.Frozen;

namespace Patched.Shared.InstallationEvidence;

internal static class SignatureStates
{
    internal const string Valid = "valid";
    internal const string Invalid = "invalid";
    // PAT-2116. Only ever from SignatureVerdictLogic.Decide's unsigned rule below.
    internal const string Unsigned = "unsigned";
    internal const string Unknown = "unknown";
}

internal static class RootKinds
{
    internal const string Microsoft = "microsoft";
    internal const string Public = "public";
    internal const string Enterprise = "enterprise";
}

// One file's Authenticode observation. The publisher fields are meaningful only with
// "valid"; AppInstallationEvidence.WithSignature drops them for every other state.
internal sealed record SignatureObservation(string State, string? Signer = null, string? SignerThumbprint = null,
    string? Issuer = null, string? RootThumbprint = null, string? RootKind = null, string? Error = null)
{
    internal static SignatureObservation Unknown(string error = "signature_unavailable") =>
        new(SignatureStates.Unknown, Error: error);
}

// Outcome of the SHA-256 catalog lookup that follows an embedded "no signature".
internal enum CatalogLookupOutcome
{
    // A catalog containing the file's SHA-256 member hash verified under WinVerifyTrust.
    Verified,
    // The lookup ran to completion and the catalog database holds no catalog with this
    // hash: the first CryptCATAdminEnumCatalogFromHash returned NULL with ERROR_NOT_FOUND.
    NoCatalog,
    // At least one catalog lists the hash, but none of them verified.
    MemberUnverified,
    // Anything else: no admin context, no hash, an enumeration error other than
    // ERROR_NOT_FOUND, an exception. Never evidence of absence.
    Failed,
}

// Whether any SHA-1 catalog lists the file. Used only to withhold "unsigned" from a file
// whose only catalog membership is SHA-1; it never grants "valid" (PAT-1981: a SHA-1
// membership is collidable, so it is not honoured as a signature).
internal enum CatalogPresence { Absent, Present, Failed }

internal enum SignatureDecision { ValidEmbedded, ValidCatalog, Invalid, Unsigned, Unknown }

// PAT-2116: the pure verdict rule. WindowsInstallationEvidence supplies the Win32 results;
// everything that decides a state lives here so it is covered on macOS CI.
internal static class SignatureVerdictLogic
{
    internal const uint TrustSuccess = 0;
    internal const uint TrustSubjectFormUnknown = 0x800B0003;
    internal const uint TrustNoSignature = 0x800B0100;
    internal const uint TrustBadDigest = 0x80096010;
    // winerror.h ERROR_NOT_FOUND. What CryptCATAdminEnumCatalogFromHash leaves in
    // GetLastError when the catalog database has no catalog for the hash.
    internal const int ErrorNotFound = 1168;

    // THE UNSIGNED RULE (conservative by design; also in AGENTS.md and
    // docs/windows-installation-evidence.md). "unsigned" is reported only when ALL hold:
    //   1. the embedded check returned TRUST_E_NOSIGNATURE exactly. TRUST_E_SUBJECT_FORM_UNKNOWN
    //      (a file wintrust cannot parse) still consults the catalog for "valid" but can never
    //      be "unsigned": an unparseable file is not proof there is no signature;
    //   2. the SHA-256 catalog lookup ran successfully and found no catalog listing the file
    //      (CatalogLookupOutcome.NoCatalog). Any catalog-API failure stays "unknown";
    //   3. no SHA-1 catalog lists the file either (CatalogPresence.Absent), so a file whose
    //      only catalog entry is SHA-1 stays "unknown" rather than being called unsigned;
    //   4. the catalog database answered a known catalog-signed OS file as a member in this
    //      helper run (catalogDatabaseHealthy), so an empty or broken database cannot turn
    //      every unsigned-looking file into "unsigned".
    // Everything else that is not valid or invalid is "unknown". Absence requires authority.
    // The lookups are lazy: a verdict that does not need one never runs it.
    internal static SignatureDecision Decide(uint embeddedCode, Func<CatalogLookupOutcome> sha256Catalog,
        Func<CatalogPresence> sha1Catalog, Func<bool> catalogDatabaseHealthy)
    {
        if (embeddedCode == TrustSuccess) return SignatureDecision.ValidEmbedded;
        // A digest mismatch is an answer, not a gap: never re-asked as a catalog lookup.
        if (embeddedCode == TrustBadDigest) return SignatureDecision.Invalid;
        if (embeddedCode is not (TrustNoSignature or TrustSubjectFormUnknown)) return SignatureDecision.Unknown;

        var catalog = sha256Catalog();
        if (catalog == CatalogLookupOutcome.Verified) return SignatureDecision.ValidCatalog;
        if (embeddedCode != TrustNoSignature || catalog != CatalogLookupOutcome.NoCatalog)
            return SignatureDecision.Unknown;
        if (sha1Catalog() != CatalogPresence.Absent) return SignatureDecision.Unknown;
        return catalogDatabaseHealthy() ? SignatureDecision.Unsigned : SignatureDecision.Unknown;
    }

    // The first CryptCATAdminEnumCatalogFromHash call: a catalog handle means the hash is
    // listed; NULL is "no catalog" only with ERROR_NOT_FOUND, and any other error a failure.
    internal static CatalogLookupOutcome? ClassifyFirstEnumeration(bool returnedCatalog, int lastError) =>
        returnedCatalog ? null : lastError == ErrorNotFound ? CatalogLookupOutcome.NoCatalog : CatalogLookupOutcome.Failed;

    internal static CatalogPresence ClassifyPresence(bool returnedCatalog, int lastError) =>
        returnedCatalog ? CatalogPresence.Present : lastError == ErrorNotFound ? CatalogPresence.Absent : CatalogPresence.Failed;

    // Per-row collection status. "complete" is a whole observation: a valid signature with
    // its signer read, or an authoritative unsigned. Anything else read a file but not a
    // full verdict, which is "partial" (the file-level caller sets "unavailable").
    internal static string CollectionStatusFor(SignatureObservation observation) =>
        (observation.State == SignatureStates.Valid && observation.Signer is not null) ||
        observation.State == SignatureStates.Unsigned ? "complete" : "partial";
}

// PAT-2116: which trust anchor a valid signature chains to.
//   microsoft  the root is one of Microsoft's own product-signing roots, hard-coded here by
//              SHA-256 thumbprint of the DER certificate (fetched from Microsoft's PKI
//              repository, www.microsoft.com/pki/certs, and cross-checked against the
//              published SHA-1 thumbprints).
//   public     the root is self-issued and present in the machine's registry "AuthRoot"
//              store (certlm "Third-Party Root Certification Authorities"), which is where
//              Windows' automatic root update places Microsoft Trusted Root Program roots.
//              Microsoft Identity Verification Root CA 2020 (Trusted Signing for third-party
//              publishers) is deliberately NOT in the Microsoft set: it vouches for other
//              publishers, so it is classified like any other public root.
//   enterprise everything else, including a root the chain could not name, a root that is
//              only in LocalMachine\Root or a Group Policy store, and a non-self-issued anchor.
// Conservative by construction: every uncertainty lands on enterprise, which is never
// eligible for the platform's Low urgency.
internal static class AuthenticodeRootClassifier
{
    internal static readonly FrozenSet<string> MicrosoftRootThumbprints = new[]
    {
        // CN=Microsoft Root Certificate Authority 2010 (SHA-1 3b1efd3a66ea28b16697394703a72ca340a05bd5)
        "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e",
        // CN=Microsoft Root Certificate Authority 2011 (SHA-1 8f43288ad272f3103b6fb1428485ea3014c0bcfe)
        "847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61",
        // CN=Microsoft Root Certificate Authority, DC=microsoft (2001; SHA-1 cdd4eeae6000ac7f40c3802c171e30148030c072)
        "885de64c340e3ea70658f01e1145f957fcda27abbeea1ab9faa9fdb0102d4077",
        // CN=Microsoft Root Authority (1997; SHA-1 a43489159a520f0d93d032ccaf37e7fe20a8b419)
        "f38406e540d7a9d90cb4a9479299640ffb6df9e224ecc7a01c0d9558d8dad77d",
    }.ToFrozenSet(StringComparer.Ordinal);

    internal static string Classify(string? rootSha256, bool selfIssued, bool inThirdPartyRootStore)
    {
        if (rootSha256 is null || !InstallationEvidenceCatalogue.IsHash(rootSha256)) return RootKinds.Enterprise;
        if (MicrosoftRootThumbprints.Contains(rootSha256)) return RootKinds.Microsoft;
        return selfIssued && inThirdPartyRootStore ? RootKinds.Public : RootKinds.Enterprise;
    }
}
