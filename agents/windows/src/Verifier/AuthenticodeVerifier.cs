using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace Patched.Verifier;

/// <summary>
/// Fail-closed Authenticode verification (PAT-305).
///
/// Before ANY installer is executed, this class must validate:
///   1. The file has a valid Authenticode signature (WinVerifyTrust).
///   2. The signature chains to a trusted root (Microsoft's trusted store).
///   3. The signing certificate's Subject CN / Organization matches the
///      expected publisher from the allowlist.
///
/// On any failure → VerificationResult with the correct failure_reason code.
/// There is NO bypass path. If this method is not called, the install MUST NOT proceed.
///
/// Maps exit codes to failure_reason (mirroring macOS exit 60/61/62):
///   missing_expected_signer → file has no signature
///   signature_untrusted     → signature present but chain untrusted
///   signer_mismatch         → chain trusted but publisher != expected
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AuthenticodeVerifier
{
    private readonly ILogger<AuthenticodeVerifier> _log;

    public AuthenticodeVerifier(ILogger<AuthenticodeVerifier> log) => _log = log;

    /// <summary>
    /// Verify the Authenticode signature of <paramref name="filePath"/> (a PE file —
    /// .exe/.msi) and check that the signing certificate's publisher matches
    /// <paramref name="expectedPublisher"/>.
    /// </summary>
    public VerificationResult Verify(string filePath, string expectedPublisher)
    {
        // Steps 1: existence + WinVerifyTrust (signature validity + chain trust).
        var trustFailure = CheckFileAndTrust(filePath);
        if (trustFailure is not null)
            return trustFailure;

        // Step 2: extract the signing certificate and read the publisher name.
        // PE-only path: X509Certificate2.CreateFromSignedFile reads the embedded
        // Authenticode cert from the PE image.
        string? actualPublisher = ExtractPublisher(filePath);

        // Step 3: publisher match — case-insensitive, exact.
        return MatchPublisher(filePath, actualPublisher, expectedPublisher);
    }

    /// <summary>
    /// MSIX/AppX variant of <see cref="Verify"/> (PAT-844). An .msix is a signed
    /// ZIP container, NOT a PE image, so <see cref="Verify"/>'s
    /// <c>X509Certificate2.CreateFromSignedFile</c> extraction cannot read its
    /// signer. This runs the SAME <see cref="WinVerifyTrust"/> trust check (on
    /// Windows 10+ the AppX SIP is registered, so WinVerifyTrust validates the
    /// .msix signature + chain), then extracts the publisher from the package's
    /// <c>AppxSignature.p7x</c> (a PKCS#7 blob), and applies the identical
    /// publisher O/CN exact-match. Every failure maps to the same
    /// <see cref="VerificationResult"/> code as <see cref="Verify"/>, fail-closed.
    /// </summary>
    public VerificationResult VerifyMsix(string filePath, string expectedPublisher)
    {
        // Step 1: existence + WinVerifyTrust (identical to Verify — the AppX SIP
        // makes WinVerifyTrust validate .msix signatures + chain on Windows 10+).
        var trustFailure = CheckFileAndTrust(filePath);
        if (trustFailure is not null)
            return trustFailure;

        // Step 2: extract the signer from AppxSignature.p7x (ZIP + PKCS#7), NOT
        // from a PE image. Null on any failure → Blocked_MissingExpectedSigner.
        string? actualPublisher = ExtractPublisherFromMsix(filePath);

        // Step 3: identical publisher O/CN exact-match as the PE path.
        return MatchPublisher(filePath, actualPublisher, expectedPublisher);
    }

    /// <summary>
    /// Shared step 1 for <see cref="Verify"/> and <see cref="VerifyMsix"/>: confirm
    /// the file exists and passes <see cref="WinVerifyTrust"/> (signature present +
    /// chain trusted). Returns a fail-closed <see cref="VerificationResult"/> on any
    /// problem, or null when trust is established and the caller should proceed to
    /// publisher extraction.
    /// </summary>
    private VerificationResult? CheckFileAndTrust(string filePath)
    {
        if (!File.Exists(filePath))
        {
            _log.LogError("Verification target not found: {Path}", filePath);
            return VerificationResult.Blocked_MissingExpectedSigner with
            {
                Detail = $"File not found: {filePath}"
            };
        }

        var trustResult = WinVerifyTrust(filePath);
        if (trustResult == TrustError.FileHasNoSignature)
        {
            _log.LogError("No Authenticode signature on {Path}", filePath);
            return VerificationResult.Blocked_MissingExpectedSigner with
            {
                Detail = "File has no Authenticode signature"
            };
        }
        if (trustResult != TrustError.Success)
        {
            _log.LogError("Signature untrusted for {Path}: {Error}", filePath, trustResult);
            return VerificationResult.Blocked_SignatureUntrusted with
            {
                Detail = $"WinVerifyTrust returned 0x{(uint)trustResult:X8}"
            };
        }
        return null;
    }

    /// <summary>
    /// Shared step 3 for <see cref="Verify"/> and <see cref="VerifyMsix"/>: given the
    /// extracted <paramref name="actualPublisher"/> (null if extraction failed),
    /// apply the case-insensitive exact publisher match against
    /// <paramref name="expectedPublisher"/> and return the corresponding
    /// <see cref="VerificationResult"/>.
    /// </summary>
    private VerificationResult MatchPublisher(string filePath, string? actualPublisher, string expectedPublisher)
    {
        if (actualPublisher is null)
        {
            _log.LogError("Could not extract signer from {Path}", filePath);
            return VerificationResult.Blocked_MissingExpectedSigner with
            {
                Detail = "Could not extract signing certificate"
            };
        }

        if (!string.Equals(actualPublisher, expectedPublisher, StringComparison.OrdinalIgnoreCase))
        {
            _log.LogError(
                "Signer mismatch on {Path}: expected='{Expected}' actual='{Actual}'",
                filePath, expectedPublisher, actualPublisher);
            return VerificationResult.Blocked_SignerMismatch(actualPublisher) with
            {
                Detail = $"Expected '{expectedPublisher}', got '{actualPublisher}'"
            };
        }

        _log.LogInformation("Authenticode OK: {Path} signed by '{Publisher}'",
            filePath, actualPublisher);
        return VerificationResult.Passed(actualPublisher);
    }

    // -------------------------------------------------------------------------
    // WinVerifyTrust P/Invoke
    // -------------------------------------------------------------------------

    private enum TrustError : uint
    {
        Success                    = 0x00000000,
        FileHasNoSignature         = 0x800B0100,   // TRUST_E_NOSIGNATURE
        SubjectNotTrusted          = 0x800B0004,   // TRUST_E_SUBJECT_NOT_TRUSTED
        ExplicitDistrust           = 0x800B0111,   // CERT_E_UNTRUSTEDROOT / explicit distrust
        CertExpired                = 0x800B0101,   // CERT_E_EXPIRED
        UntrustedRoot              = 0x800B0109,   // CERT_E_UNTRUSTEDROOT
        SubjectFormUnknown         = 0x800B0003,   // TRUST_E_SUBJECT_FORM_UNKNOWN
        ProviderUnknown            = 0x800B0001,   // TRUST_E_PROVIDER_UNKNOWN
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint   cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint   cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint   dwUIChoice;       // 2 = WTD_UI_NONE
        public uint   fdwRevocationChecks; // 1 = WTD_REVOKE_WHOLECHAIN
        public uint   dwUnionChoice;    // 1 = WTD_CHOICE_FILE
        public IntPtr pFile;
        public uint   dwStateAction;    // 1 = WTD_STATEACTION_VERIFY
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint   dwProvFlags;      // 0x00001040 = cache+safe flag
        public uint   dwUIContext;
    }

    // GUID: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE} (WINTRUST_ACTION_GENERIC_VERIFY_V2)
    private static readonly Guid GenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID,
        ref WinTrustData pWVTData);

    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE  = 2;

    private static TrustError WinVerifyTrust(string filePath)
    {
        var fileInfo = new WinTrustFileInfo
        {
            cbStruct      = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            pcwszFilePath = filePath,
            hFile         = IntPtr.Zero,
            pgKnownSubject= IntPtr.Zero,
        };

        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        var actionGuid  = GenericVerifyV2;
        var trustData = new WinTrustData
        {
            cbStruct           = (uint)Marshal.SizeOf<WinTrustData>(),
            dwUIChoice         = 2,     // WTD_UI_NONE
            fdwRevocationChecks= 1,     // WTD_REVOKE_WHOLECHAIN
            dwUnionChoice      = 1,     // WTD_CHOICE_FILE
            pFile              = fileInfoPtr,
            dwStateAction      = WTD_STATEACTION_VERIFY,
            dwProvFlags        = 0x00001040,
        };

        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);
            return (TrustError)WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref trustData);
        }
        finally
        {
            // WTD_STATEACTION_VERIFY allocates hWVTStateData; it is only released by
            // re-invoking WinVerifyTrust with WTD_STATEACTION_CLOSE against the SAME
            // WinTrustData (WinVerifyTrust writes the handle back into trustData via
            // the ref parameter above, so this reuses it). Without this, every call
            // leaks the state handle.
            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref trustData);
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    // -------------------------------------------------------------------------
    // Certificate extraction — reads the Authenticode signing cert Subject.
    // -------------------------------------------------------------------------

    private string? ExtractPublisher(string filePath)
    {
        try
        {
            using var cert = (X509Certificate2)X509Certificate2.CreateFromSignedFile(filePath);
            // Parse the Subject CN or O field for the publisher name.
            return ExtractOrganization(cert.SubjectName)
                ?? ExtractCommonName(cert.SubjectName)
                ?? cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch (CryptographicException ex)
        {
            _log.LogDebug(ex, "Could not read certificate from {Path}", filePath);
            return null;
        }
    }

    /// <summary>
    /// PAT-844: extract the publisher name from an MSIX package's Authenticode
    /// signature. An .msix is a signed OPC/ZIP container — its signature lives in a
    /// package-root <c>AppxSignature.p7x</c> entry (a PKCS#7 SignedData blob), NOT
    /// in a PE header, so <see cref="ExtractPublisher"/>'s
    /// <c>CreateFromSignedFile</c> cannot read it.
    ///
    /// The <c>.p7x</c> payload is prefixed with a 4-byte magic <c>0x50 0x4B 0x43
    /// 0x58</c> ("PKCX") that is NOT part of the PKCS#7 encoding and must be stripped
    /// before <see cref="SignedCms.Decode"/>. We return the signer's O (else CN, else
    /// simple name) via the SAME RDN helpers the PE path uses, so the exact-match
    /// publisher check in <see cref="VerifyMsix"/> compares like with like. Returns
    /// null on any failure so the caller fails closed as Blocked_MissingExpectedSigner.
    ///
    /// Hardening (GitHub-Non-Author-Review):
    ///  - <b>Exactly one</b> AppxSignature.p7x must be present. Zero → unsigned. More
    ///    than one (duplicate/ambiguous ZIP entries) → reject: WinVerifyTrust's AppX
    ///    SIP and this reader could otherwise resolve DIFFERENT entries, letting a
    ///    package validly signed by publisher X carry a planted copy of publisher Y's
    ///    blob past the publisher match.
    ///  - The signature entry is <b>size-capped before buffering</b> (declared size
    ///    checked up front AND enforced while streaming, in case the header lies) so a
    ///    crafted MSIX cannot force unbounded decompression/allocation (zip bomb).
    ///  - The decoded PKCS#7 is <b>cryptographically validated</b>
    ///    (<see cref="SignedCms.CheckSignature(bool)"/>, signature-only — trust/chain
    ///    is WinVerifyTrust's job) so the signer certificate we read is the actual
    ///    signer of a valid signature, not a planted certificate.
    ///
    /// <see cref="ZipFile"/> and <see cref="SignedCms"/> are in-box and cross-platform
    /// for net8.0 (no P/Invoke), so this extraction — unlike WinVerifyTrust — can run
    /// and be unit-tested off Windows.
    ///
    /// <c>internal</c> (not <c>private</c>) so Verifier.Tests (see Verifier.csproj's
    /// <c>InternalsVisibleTo</c>) can exercise this directly with in-memory ZIP +
    /// PKCS#7 fixtures (PAT-849), without widening the public surface.
    /// </summary>
    internal string? ExtractPublisherFromMsix(string filePath)
    {
        try
        {
            using var zip = ZipFile.OpenRead(filePath);

            // Exactly one AppxSignature.p7x — reject duplicates/ambiguity (see remarks).
            var sigEntries = zip.Entries.Where(e =>
                string.Equals(e.FullName, "AppxSignature.p7x", StringComparison.OrdinalIgnoreCase)).ToList();
            if (sigEntries.Count != 1)
            {
                _log.LogDebug("MSIX {Path}: expected exactly one AppxSignature.p7x, found {Count}",
                    filePath, sigEntries.Count);
                return null;
            }
            var sigEntry = sigEntries[0];

            // Size cap BEFORE buffering — an AppxSignature.p7x is a few KB in practice;
            // MaxMsixSignatureBytes is a generous ceiling. Reject an over-large declared
            // size up front, then re-enforce while reading in case the header lies.
            var payload = ReadZipEntryBounded(sigEntry, MaxMsixSignatureBytes);
            if (payload is null)
            {
                _log.LogDebug("MSIX {Path}: AppxSignature.p7x exceeds the {Cap}-byte cap — refusing",
                    filePath, MaxMsixSignatureBytes);
                return null;
            }

            // Strip the 4-byte "PKCX" (0x50 0x4B 0x43 0x58) magic prefix if present —
            // it wraps, but is not part of, the PKCS#7 blob.
            int offset = 0;
            if (payload.Length >= 4 &&
                payload[0] == 0x50 && payload[1] == 0x4B &&
                payload[2] == 0x43 && payload[3] == 0x58)
            {
                offset = 4;
            }

            var cms = new SignedCms();
            cms.Decode(offset == 0 ? payload : payload[offset..]);

            if (cms.SignerInfos.Count == 0)
            {
                _log.LogDebug("MSIX signature in {Path} has no signer infos", filePath);
                return null;
            }

            // Bind the extracted signer to a valid signature: verify the PKCS#7
            // signature itself (not the chain — WinVerifyTrust already established
            // trust). A planted certificate that did not actually sign the content
            // fails here, so the publisher we read is the real signer.
            try
            {
                cms.CheckSignature(verifySignatureOnly: true);
            }
            catch (CryptographicException ex)
            {
                _log.LogDebug(ex, "MSIX PKCS#7 signature in {Path} failed validation", filePath);
                return null;
            }

            var cert = cms.SignerInfos[0].Certificate;
            if (cert is null)
            {
                _log.LogDebug("MSIX signer in {Path} carries no certificate", filePath);
                return null;
            }

            return ExtractOrganization(cert.SubjectName)
                ?? ExtractCommonName(cert.SubjectName)
                ?? cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Could not read MSIX signature from {Path}", filePath);
            return null;
        }
    }

    /// <summary>
    /// Upper bound on the AppxSignature.p7x blob we will buffer (GitHub-Non-Author-Review abuse
    /// resistance). A real MSIX signature is a few KB; 4 MB is a generous ceiling
    /// that still bounds a hostile/zip-bomb entry.
    /// </summary>
    private const long MaxMsixSignatureBytes = 4L * 1024 * 1024;

    /// <summary>
    /// Read a ZIP entry into memory with a hard byte cap. Rejects (returns null) an
    /// entry whose declared uncompressed size exceeds <paramref name="cap"/> up front,
    /// AND aborts if the actual decompressed stream exceeds the cap while reading (in
    /// case the central-directory size is understated). Never allocates more than the
    /// cap, so a decompression-amplification ("zip bomb") entry cannot exhaust memory.
    /// </summary>
    private static byte[]? ReadZipEntryBounded(ZipArchiveEntry entry, long cap)
    {
        if (entry.Length > cap)
            return null;

        using var entryStream = entry.Open();
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        long total = 0;
        int read;
        while ((read = entryStream.Read(chunk, 0, chunk.Length)) > 0)
        {
            total += read;
            if (total > cap)
                return null;
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }

    // X.509 attribute type OIDs (RFC 5280 §4.1.2.4).
    private const string OidOrganization = "2.5.4.10"; // O
    private const string OidCommonName   = "2.5.4.3";  // CN

    /// <summary>
    /// Extract the Organization (O) RDN component from a certificate Subject DN.
    ///
    /// This deliberately does NOT split <c>subject.Name</c> (or the legacy <c>subject</c>
    /// string) on ',' — real code-signing certs routinely embed commas inside the O value
    /// itself (e.g. <c>O="Zoom Video Communications, Inc."</c>, <c>O="Slack Technologies,
    /// LLC"</c>), quoted precisely because they contain the RDN separator. A naive
    /// <c>Split(',')</c> truncates at the first embedded comma and never strips the
    /// surrounding quotes, silently producing a different string than the real publisher
    /// name.
    ///
    /// Parsing via <see cref="X500DistinguishedName.EnumerateRelativeDistinguishedNames"/>
    /// instead decodes the underlying ASN.1 RDN sequence directly, so the value returned
    /// here is the exact, unescaped, unquoted attribute value — never a fragment of it.
    /// This is also the canonical form CI's <c>_extract_publisher</c>
    /// (ci/mirror_pipeline_windows.py) recovers via its quote-aware regex followed by
    /// <c>.strip('"')</c> on the same certificate's Subject string, so the two sides agree
    /// exactly and the exact-equality publisher check in <see cref="Verify"/> is comparing
    /// like with like.
    /// </summary>
    internal static string? ExtractOrganization(X500DistinguishedName subjectName) =>
        ExtractRdnValue(subjectName, OidOrganization);

    /// <summary>Extract the Common Name (CN) RDN component. See <see cref="ExtractOrganization"/>.</summary>
    internal static string? ExtractCommonName(X500DistinguishedName subjectName) =>
        ExtractRdnValue(subjectName, OidCommonName);

    private static string? ExtractRdnValue(X500DistinguishedName name, string oidValue)
    {
        foreach (var rdn in name.EnumerateRelativeDistinguishedNames())
        {
            // Multi-valued RDNs (e.g. "OU=x+O=y") are vanishingly rare for O/CN on
            // code-signing certs; skip rather than guess which value applies.
            if (rdn.HasMultipleElements)
                continue;

            var oid = rdn.GetSingleElementType();
            if (oid.Value == oidValue)
                return rdn.GetSingleElementValue();
        }
        return null;
    }
}
