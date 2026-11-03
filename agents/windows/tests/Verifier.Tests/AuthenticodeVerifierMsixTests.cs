using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Patched.Verifier.Tests;

/// <summary>
/// Direct unit coverage for <see cref="AuthenticodeVerifier.ExtractPublisherFromMsix"/>
/// (PAT-849). The method is <c>internal</c> (see Verifier.csproj's
/// <c>InternalsVisibleTo</c>) so these tests call it directly rather than only through
/// <see cref="AuthenticodeVerifier.VerifyMsix"/>, which also requires a real
/// WinVerifyTrust-validated signature and so cannot run off Windows.
///
/// Every fixture here is built in-code at test run time — an ephemeral self-signed
/// cert, a real PKCS#7 SignedCms over arbitrary content, and a ZIP written to a temp
/// file with that blob as a root-level "AppxSignature.p7x" entry. No binary fixtures
/// are committed. <see cref="ZipFile"/> and <see cref="SignedCms"/> are in-box and
/// cross-platform, so this runs on macOS (this dev machine) and windows-latest (CI)
/// alike — unlike <see cref="AuthenticodeVerifierTests"/>, which needs real WinTrust.
///
/// PAT-849 finding: the 4-byte "PKCX" magic strip in ExtractPublisherFromMsix IS
/// conditional (checked before stripping — see AuthenticodeVerifier.cs's offset-only-
/// set-if-magic-matches logic), so a p7x payload without the magic still decodes
/// correctly. <see cref="NoPkcxMagic_StillDecodes_ReturnsOrganization"/> asserts that
/// actual (correct) behavior directly.
/// </summary>
public sealed class AuthenticodeVerifierMsixTests
{
    private readonly AuthenticodeVerifier _verifier =
        new(NullLogger<AuthenticodeVerifier>.Instance);

    private const string OrgSubject = "CN=Contoso Updater, O=\"Contoso Software, Inc.\", C=US";
    private const string CnOnlySubject = "CN=Contoso CN Only, C=US";

    // ----------------------------------------------------------------------
    // Fixture builders
    // ----------------------------------------------------------------------

    /// <summary>Ephemeral self-signed code-signing-shaped cert for the given subject.</summary>
    private static X509Certificate2 CreateSelfSignedCert(string subjectName)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subjectName),
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
    }

    /// <summary>
    /// Build a real PKCS#7/CMS SignedCms over arbitrary content, signed by an ephemeral
    /// self-signed cert for <paramref name="subjectName"/>. The signing cert is embedded
    /// (EndCertOnly) so the decoded SignerInfo carries a Certificate even though the cert
    /// is self-signed (ExcludeRoot would otherwise drop it, since a self-signed cert IS
    /// its own root).
    /// </summary>
    private static byte[] BuildSignedCms(string subjectName)
    {
        using var cert = CreateSelfSignedCert(subjectName);
        var content = new ContentInfo(Encoding.UTF8.GetBytes("arbitrary AppxSignature content"));
        var cms = new SignedCms(content, detached: false);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert)
        {
            IncludeOption = X509IncludeOption.EndCertOnly,
        };
        cms.ComputeSignature(signer, silent: true);
        return cms.Encode();
    }

    private static readonly byte[] PkcxMagic = { 0x50, 0x4B, 0x43, 0x58 }; // "PKCX"

    /// <summary>Write a ZIP to a fresh temp file containing the given entries, return the path.</summary>
    private static string WriteZip(params (string Name, byte[] Content)[] entries)
    {
        var path = Path.Combine(Path.GetTempPath(), $"msix-fixture-{Guid.NewGuid():N}.msix");
        using (var fileStream = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (var archive = new ZipArchive(fileStream, ZipArchiveMode.Create))
        {
            foreach (var (name, content) in entries)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
                using var entryStream = entry.Open();
                entryStream.Write(content, 0, content.Length);
            }
        }
        return path;
    }

    private static void DeleteQuietly(string path)
    {
        try { File.Delete(path); } catch { /* best-effort cleanup */ }
    }

    /// <summary>
    /// Locate <paramref name="needle"/> inside <paramref name="haystack"/> and return a
    /// copy of <paramref name="haystack"/> with that region overwritten by
    /// <paramref name="needle"/> XORed against 0xFF. Used to corrupt the embedded
    /// content of an encoded SignedCms in place, byte-for-byte, so the surrounding
    /// ASN.1/DER structure (lengths, tags) is untouched and only the signed content
    /// changes — this keeps <see cref="SignedCms.Decode"/> succeeding while making the
    /// stored signature (computed over the original content) invalid.
    /// </summary>
    private static byte[] TamperEmbeddedContent(byte[] haystack, byte[] needle)
    {
        int index = -1;
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) { index = i; break; }
        }
        Assert.True(index >= 0, "Could not locate content bytes in encoded CMS to tamper.");

        var tampered = (byte[])haystack.Clone();
        for (int j = 0; j < needle.Length; j++)
            tampered[index + j] = (byte)(needle[j] ^ 0xFF);
        return tampered;
    }

    // ----------------------------------------------------------------------
    // Case 1: valid signer with O → returns the O value.
    // ----------------------------------------------------------------------

    [Fact]
    public void ValidSigner_WithOrganization_ReturnsOrganization()
    {
        var p7x = BuildSignedCms(OrgSubject);
        var payload = PkcxMagic.Concat(p7x).ToArray();
        var path = WriteZip(("AppxSignature.p7x", payload));
        try
        {
            var publisher = _verifier.ExtractPublisherFromMsix(path);
            Assert.Equal("Contoso Software, Inc.", publisher);
        }
        finally
        {
            DeleteQuietly(path);
        }
    }

    // ----------------------------------------------------------------------
    // Case 2: zip with no AppxSignature.p7x entry → null.
    // ----------------------------------------------------------------------

    [Fact]
    public void MissingSignatureEntry_ReturnsNull()
    {
        var path = WriteZip(("AppxManifest.xml", Encoding.UTF8.GetBytes("<Package/>")));
        try
        {
            var publisher = _verifier.ExtractPublisherFromMsix(path);
            Assert.Null(publisher);
        }
        finally
        {
            DeleteQuietly(path);
        }
    }

    // ----------------------------------------------------------------------
    // Case 3: p7x payload WITHOUT the PKCX magic → still decodes.
    //
    // The implementation's magic-strip is conditional: it checks the first 4 bytes
    // against "PKCX" and only advances the offset when they match, so a payload that
    // is already a raw PKCS#7 blob (no magic prefix) falls through with offset=0 and
    // decodes unchanged. This test asserts that actual current behavior.
    // ----------------------------------------------------------------------

    [Fact]
    public void NoPkcxMagic_StillDecodes_ReturnsOrganization()
    {
        var p7x = BuildSignedCms(OrgSubject);
        // Deliberately NOT prepending the PKCX magic.
        var path = WriteZip(("AppxSignature.p7x", p7x));
        try
        {
            var publisher = _verifier.ExtractPublisherFromMsix(path);
            Assert.Equal("Contoso Software, Inc.", publisher);
        }
        finally
        {
            DeleteQuietly(path);
        }
    }

    // ----------------------------------------------------------------------
    // Case 4: garbage bytes in AppxSignature.p7x → null, no exception.
    // ----------------------------------------------------------------------

    [Fact]
    public void GarbageBytes_ReturnsNull_DoesNotThrow()
    {
        var garbage = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A };
        var path = WriteZip(("AppxSignature.p7x", garbage));
        try
        {
            string? publisher = null;
            var ex = Record.Exception(() => publisher = _verifier.ExtractPublisherFromMsix(path));
            Assert.Null(ex);
            Assert.Null(publisher);
        }
        finally
        {
            DeleteQuietly(path);
        }
    }

    [Fact]
    public void GarbageBytes_WithPkcxMagicPrefix_ReturnsNull_DoesNotThrow()
    {
        var garbage = PkcxMagic.Concat(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }).ToArray();
        var path = WriteZip(("AppxSignature.p7x", garbage));
        try
        {
            string? publisher = null;
            var ex = Record.Exception(() => publisher = _verifier.ExtractPublisherFromMsix(path));
            Assert.Null(ex);
            Assert.Null(publisher);
        }
        finally
        {
            DeleteQuietly(path);
        }
    }

    // ----------------------------------------------------------------------
    // Case 5: cert with CN but no O → returns CN fallback.
    // ----------------------------------------------------------------------

    [Fact]
    public void ValidSigner_CnOnly_ReturnsCommonNameFallback()
    {
        var p7x = BuildSignedCms(CnOnlySubject);
        var payload = PkcxMagic.Concat(p7x).ToArray();
        var path = WriteZip(("AppxSignature.p7x", payload));
        try
        {
            var publisher = _verifier.ExtractPublisherFromMsix(path);
            Assert.Equal("Contoso CN Only", publisher);
        }
        finally
        {
            DeleteQuietly(path);
        }
    }

    // ----------------------------------------------------------------------
    // Case 6 (PAT-958 hardening): TWO AppxSignature.p7x entries → null.
    //
    // Exercises the `sigEntries.Count != 1` guard in ExtractPublisherFromMsix. Both
    // entries here are byte-identical valid signatures — the point isn't that either
    // one is bad, it's that ambiguity itself (WinVerifyTrust's AppX SIP and this
    // reader could resolve DIFFERENT entries of the same name) must be rejected
    // rather than silently resolved by picking "the" entry.
    // ----------------------------------------------------------------------

    [Fact]
    public void DuplicateSignatureEntries_ReturnsNull()
    {
        var p7x = BuildSignedCms(OrgSubject);
        var payload = PkcxMagic.Concat(p7x).ToArray();
        var path = WriteZip(
            ("AppxSignature.p7x", payload),
            ("AppxSignature.p7x", payload));
        try
        {
            var publisher = _verifier.ExtractPublisherFromMsix(path);
            Assert.Null(publisher);
        }
        finally
        {
            DeleteQuietly(path);
        }
    }

    // ----------------------------------------------------------------------
    // Case 7 (PAT-958 hardening): structurally valid PKCS#7 whose signature does NOT
    // validate → null.
    //
    // Exercises the `cms.CheckSignature(verifySignatureOnly: true)` guard. Builds a
    // real, self-consistent SignedCms (same helper as the happy-path tests), then
    // overwrites the embedded content bytes in place — same offset, same length — so
    // the DER structure (tags/lengths) is untouched and SignedCms.Decode succeeds, but
    // the stored signature (computed over the ORIGINAL content) no longer matches.
    //
    // Failure mode triggered: this specifically reaches and fails CheckSignature (a
    // content-hash mismatch), NOT SignedCms.Decode — proving the crypto check, not
    // just parsing, is what rejects a mis-signed blob. A cert that validly signed
    // attacker content would sail through structural checks alone; this is the test
    // that proves that doesn't happen.
    // ----------------------------------------------------------------------

    [Fact]
    public void TamperedContent_SignatureCheckFails_ReturnsNull()
    {
        var originalContent = Encoding.UTF8.GetBytes("arbitrary AppxSignature content");
        var p7x = BuildSignedCms(OrgSubject);
        var tamperedP7x = TamperEmbeddedContent(p7x, originalContent);
        var payload = PkcxMagic.Concat(tamperedP7x).ToArray();
        var path = WriteZip(("AppxSignature.p7x", payload));
        try
        {
            var publisher = _verifier.ExtractPublisherFromMsix(path);
            Assert.Null(publisher);
        }
        finally
        {
            DeleteQuietly(path);
        }
    }

    // ----------------------------------------------------------------------
    // Case 8 (PAT-958 hardening): AppxSignature.p7x entry larger than
    // MaxMsixSignatureBytes (4 MiB) → null, without buffering the whole thing.
    //
    // Exercises the size cap in ReadZipEntryBounded / ExtractPublisherFromMsix — a
    // crafted MSIX cannot force unbounded decompression/allocation (zip bomb) via an
    // oversized signature entry.
    // ----------------------------------------------------------------------

    [Fact]
    public void OversizedSignatureEntry_ExceedsCap_ReturnsNull()
    {
        const int oneMiB = 1024 * 1024;
        // AuthenticodeVerifier's MaxMsixSignatureBytes cap is 4 MiB; go comfortably
        // over so the assertion isn't sensitive to the exact boundary value.
        var oversized = new byte[(5 * oneMiB)];
        var path = WriteZip(("AppxSignature.p7x", oversized));
        try
        {
            var publisher = _verifier.ExtractPublisherFromMsix(path);
            Assert.Null(publisher);
        }
        finally
        {
            DeleteQuietly(path);
        }
    }
}
