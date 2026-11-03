using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Patched.Shared.Certificates;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1739: the Windows mapper classifies basicConstraints and extKeyUsage only from a
/// single, strict-DER extension, matching macos/lib/certs.sh (PAT-1735). The collection
/// indexer returns the first match and .NET's decoders are lenient, so before this a
/// certificate carrying basicConstraints CA:FALSE followed by a critical CA:TRUE was
/// reported as not a CA, and a BER cA byte was read as whatever .NET chose. Each such
/// certificate is now skipped with the macOS reason, and the collection is partial.
/// </summary>
public sealed class CertExtensionDerTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 14, 12, 0, 0, TimeSpan.Zero);

    private const string BcOid  = "2.5.29.19";
    private const string EkuOid = "2.5.29.37";

    // 2.5.29.90 and up encode as 06 03 55 1D xx, the same length as 2.5.29.19 / 2.5.29.37.
    private const string PlaceholderOidPrefix = "2.5.29.";

    private static byte[] Hex(string hex) => Convert.FromHexString(hex.Replace(" ", ""));

    private static X509Extension Ext(string oid, string hex, bool critical = false) =>
        new(oid, Hex(hex), critical);

    private static X509Certificate2 SelfSigned(string subject, params X509Extension[] extensions)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        foreach (var ext in extensions)
            req.CertificateExtensions.Add(ext);
        return req.CreateSelfSigned(Now.AddYears(-1), Now.AddYears(5));
    }

    /// <summary>
    /// Builds certificate DER holding extensions CertificateRequest will not produce: each
    /// <paramref name="patched"/> extension is added under a placeholder OID of the same
    /// encoded length, then the placeholder bytes are patched to the real OID and the
    /// certificate is re-signed, so its signature still verifies. This is how a repeated
    /// extension is made (CertificateRequest refuses duplicate OIDs) and how a malformed
    /// basicConstraints is made (CreateSelfSigned on macOS reloads the certificate through
    /// Apple's parser, which refuses it).
    /// </summary>
    private static byte[] BuildDer(X509Extension[] plain, params (string Oid, string Hex, bool Critical)[] patched)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Patched Test Extension Fixture", key, HashAlgorithmName.SHA256);
        foreach (var ext in plain)
            req.CertificateExtensions.Add(ext);
        for (var i = 0; i < patched.Length; i++)
            req.CertificateExtensions.Add(Ext(PlaceholderOidPrefix + (90 + i), patched[i].Hex, patched[i].Critical));
        using var draft = req.CreateSelfSigned(Now.AddYears(-1), Now.AddYears(5));

        var outer  = new AsnReader(draft.RawData, AsnEncodingRules.DER).ReadSequence();
        var tbs    = outer.ReadEncodedValue().ToArray();
        var sigAlg = outer.ReadEncodedValue().ToArray();

        for (var i = 0; i < patched.Length; i++)
        {
            var placeholder = OidBytes(PlaceholderOidPrefix + (90 + i));
            var real        = OidBytes(patched[i].Oid);
            Assert.Equal(placeholder.Length, real.Length);
            var at = tbs.AsSpan().IndexOf(placeholder);
            Assert.True(at >= 0 && tbs.AsSpan(at + 1).IndexOf(placeholder) < 0, "placeholder OID must appear exactly once");
            real.CopyTo(tbs, at);
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteEncodedValue(tbs);
            writer.WriteEncodedValue(sigAlg);
            writer.WriteBitString(key.SignData(tbs, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        }
        return writer.Encode();
    }

    private static byte[] OidBytes(string oid)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteObjectIdentifier(oid);
        return w.Encode();
    }

    /// <summary>
    /// Loads fixture DER. Windows must accept it, because LocalMachine\My can hold such a
    /// certificate and the mapper is what has to catch it there. Apple's certificate
    /// parser refuses a malformed basicConstraints before .NET sees it, so on another OS a
    /// refusal returns null and the caller stops: the mapper cannot be reached with that
    /// certificate on that platform. windows-build.yml runs these on windows-latest.
    /// </summary>
    private static X509Certificate2? LoadOnPlatformsThatAccept(Func<X509Certificate2> load)
    {
        try
        {
            return load();
        }
        catch (CryptographicException) when (!OperatingSystem.IsWindows())
        {
            return null;
        }
    }

    private static X509Certificate2 WithDuplicate(string oid, X509Extension first, string secondHex, bool secondCritical)
    {
        var cert = X509CertificateLoader.LoadCertificate(
            BuildDer([first], (oid, secondHex, secondCritical)));
        Assert.Equal(2, cert.Extensions.Cast<X509Extension>().Count(e => e.Oid?.Value == oid));
        return cert;
    }

    private static CertSkippedException AssertSkipped(X509Certificate2 cert, string reason)
    {
        var ex = Assert.Throws<CertSkippedException>(() => CertInventoryMapper.FromX509(cert, Now));
        Assert.Equal(reason, ex.Reason);
        Assert.Equal(reason, CertSkipReason.Of(ex));
        return ex;
    }

    // ---- repeated extensions -------------------------------------------------------

    [Fact]
    public void DuplicateBasicConstraints_FalseThenCriticalTrue_IsSkipped_ExtensionsAmbiguous()
    {
        using var cert = WithDuplicate(BcOid, Ext(BcOid, "30 00"), "30 03 01 01 FF", secondCritical: true);

        // Before PAT-1739 the indexer took the first copy and reported "not a CA".
        Assert.False(LegacyMapper.FromX509(cert, Now).BasicConstraintsCa);
        AssertSkipped(cert, CertSkipReason.ExtensionsAmbiguous);
    }

    [Fact]
    public void DuplicateBasicConstraints_Identical_IsStillSkipped()
    {
        using var cert = WithDuplicate(BcOid, Ext(BcOid, "30 03 01 01 FF"), "30 03 01 01 FF", secondCritical: false);

        AssertSkipped(cert, CertSkipReason.ExtensionsAmbiguous);
    }

    [Fact]
    public void DuplicateExtKeyUsage_IsSkipped_ExtensionsAmbiguous()
    {
        // serverAuth, then codeSigning.
        using var cert = WithDuplicate(EkuOid,
            Ext(EkuOid, "30 0A 06 08 2B 06 01 05 05 07 03 01"),
            "30 0A 06 08 2B 06 01 05 05 07 03 03", secondCritical: false);

        AssertSkipped(cert, CertSkipReason.ExtensionsAmbiguous);
    }

    // ---- basicConstraints DER ------------------------------------------------------

    [Theory]
    [InlineData("30 03 01 01 01", "cA BOOLEAN content 0x01 (BER true, not DER 0xFF)")]
    [InlineData("30 03 01 01 7F", "cA BOOLEAN content 0x7F")]
    [InlineData("30 03 01 01 FF 00", "a byte after the SEQUENCE")]
    [InlineData("30 05 01 01 FF 05 00", "a NULL inside the SEQUENCE after cA")]
    [InlineData("30 06 02 01 00 01 01 FF", "pathLenConstraint before cA")]
    [InlineData("30 04 01 02 00 FF", "cA BOOLEAN two bytes long")]
    [InlineData("30 81 03 01 01 FF", "non-minimal length")]
    [InlineData("30 80 01 01 FF 00 00", "indefinite length")]
    [InlineData("30 07 01 01 FF 02 02 00 01", "non-minimal pathLenConstraint")]
    [InlineData("30 06 01 01 FF 02 01 FF", "negative pathLenConstraint")]
    [InlineData("30 06 01 01 FF 02 00", "empty pathLenConstraint")]
    [InlineData("30 03 01 01", "truncated")]
    [InlineData("31 03 01 01 FF", "a SET, not a SEQUENCE")]
    [InlineData("", "empty value")]
    public void BasicConstraints_NotDer_IsSkipped_DerUnparseable(string hex, string what)
    {
        var value = Assert.Throws<CertSkippedException>(() => CertInventoryMapper.ReadBasicConstraintsDer(Hex(hex)));
        Assert.Equal(CertSkipReason.DerUnparseable, value.Reason);

        var der = BuildDer([], (BcOid, hex, true));
        using var cert = LoadOnPlatformsThatAccept(() => X509CertificateLoader.LoadCertificate(der));
        if (cert is null)
            return;
        AssertSkipped(cert, CertSkipReason.DerUnparseable);
        Assert.False(string.IsNullOrEmpty(what));
    }

    // ---- extKeyUsage DER -----------------------------------------------------------

    [Theory]
    [InlineData("30 00", "empty SEQUENCE")]
    [InlineData("30 0A 06 08 2B 06 01 05 05 07 03 01 00", "a byte after the SEQUENCE")]
    [InlineData("30 0C 06 08 2B 06 01 05 05 07 03 01 05 00", "a NULL among the key purposes")]
    [InlineData("30 03 06 01 80", "OID arc with a leading 0x80")]
    [InlineData("30 02 06 00", "empty OID")]
    [InlineData("30 81 0A 06 08 2B 06 01 05 05 07 03 01", "non-minimal length")]
    [InlineData("31 0A 06 08 2B 06 01 05 05 07 03 01", "a SET, not a SEQUENCE")]
    [InlineData("06 08 2B 06 01 05 05 07 03 01", "a bare OID")]
    [InlineData("", "empty value")]
    public void ExtKeyUsage_NotDer_IsSkipped_DerUnparseable(string hex, string what)
    {
        var value = Assert.Throws<CertSkippedException>(() => CertInventoryMapper.ReadExtKeyUsageDer(Hex(hex)));
        Assert.Equal(CertSkipReason.DerUnparseable, value.Reason);

        var der = BuildDer([], (EkuOid, hex, false));
        using var cert = LoadOnPlatformsThatAccept(() => X509CertificateLoader.LoadCertificate(der));
        if (cert is null)
            return;
        AssertSkipped(cert, CertSkipReason.DerUnparseable);
        Assert.False(string.IsNullOrEmpty(what));
    }

    // ---- unchanged output ----------------------------------------------------------

    public static TheoryData<string, X509Extension[]> WellFormed() => new()
    {
        { "CA, critical, no pathLen",        [new X509BasicConstraintsExtension(true, false, 0, true)] },
        { "CA with pathLen 0 and code signing EKU",
            [new X509BasicConstraintsExtension(true, true, 0, true),
             new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }, false)] },
        { "CA with pathLen 300",             [Ext(BcOid, "30 07 01 01 FF 02 02 01 2C", critical: true)] },
        { "leaf, BC empty SEQUENCE",         [Ext(BcOid, "30 00")] },
        { "leaf, explicit cA FALSE",         [Ext(BcOid, "30 03 01 01 00")] },
        { "no BC, serverAuth clientAuth private and UUID OIDs",
            [Ext(EkuOid, "30 36 06 08 2B 06 01 05 05 07 03 01 06 08 2B 06 01 05 05 07 03 02 " +
                         "06 0A 2B 06 01 04 01 83 B2 03 07 01 06 14 69 83 F0 9D A7 EB CF DE E0 C7 A1 A7 B2 C0 94 8C C8 F9 D7 76")] },
        { "anyExtendedKeyUsage, critical EKU", [Ext(EkuOid, "30 06 06 04 55 1D 25 00", critical: true)] },
        { "no extensions at all",            [] },
        { "only unrelated extensions",       [Ext("2.5.29.15", "03 02 07 80", critical: true), Ext("1.3.6.1.4.1.55555.1", "04 03 41 42 43")] },
    };

    [Theory]
    [MemberData(nameof(WellFormed))]
    public void WellFormedCertificate_MapsExactlyAsBeforePat1739(string name, X509Extension[] extensions)
    {
        using var cert = SelfSigned("CN=Patched Test Well Formed", extensions);
        Assert.False(string.IsNullOrEmpty(name));

        AssertSameRow(LegacyMapper.FromX509(cert, Now), CertInventoryMapper.FromX509(cert, Now));
    }

    [Fact]
    public void IssuedLeaf_MapsExactlyAsBeforePat1739()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caReq = new CertificateRequest("CN=Internal CA", caKey, HashAlgorithmName.SHA256);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = caReq.CreateSelfSigned(Now.AddYears(-1), Now.AddYears(10));

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest("CN=host.example", leafKey, HashAlgorithmName.SHA256);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2") }, false));
        using var leaf = leafReq.Create(ca, Now.AddDays(-1), Now.AddDays(30), new byte[] { 1, 2, 3, 4 });

        var row = CertInventoryMapper.FromX509(leaf, Now);

        AssertSameRow(LegacyMapper.FromX509(leaf, Now), row);
        Assert.False(row.BasicConstraintsCa);
        Assert.Equal(2, row.ExtKeyUsage.Length);
    }

    private static void AssertSameRow(InventoryCert expected, InventoryCert actual)
    {
        Assert.Equal(expected.SubjectCn, actual.SubjectCn);
        Assert.Equal(expected.IssuerCn, actual.IssuerCn);
        Assert.Equal(expected.Sha1, actual.Sha1);
        Assert.Equal(expected.NotAfter, actual.NotAfter);
        Assert.Equal(expected.DaysUntilExpiry, actual.DaysUntilExpiry);
        Assert.Equal(expected.ExtKeyUsage, actual.ExtKeyUsage);
        Assert.Equal(expected.BasicConstraintsCa, actual.BasicConstraintsCa);
        Assert.Equal(expected.IsSelfSigned, actual.IsSelfSigned);
    }

    // ---- collection routing --------------------------------------------------------

    [Fact]
    public void SkippedCertificate_MakesCollectionPartial_OthersSent_ReasonReported()
    {
        using var good     = SelfSigned("CN=Patched Test Valid", new X509BasicConstraintsExtension(true, false, 0, true));
        using var dupBc    = WithDuplicate(BcOid, Ext(BcOid, "30 00"), "30 03 01 01 FF", secondCritical: true);
        using var emptyEku = SelfSigned("CN=Patched Test Empty EKU", Ext(EkuOid, "30 00"));
        using var trailing = SelfSigned("CN=Patched Test EKU Trailing", Ext(EkuOid, "30 0A 06 08 2B 06 01 05 05 07 03 01 00"));

        var reasons = new List<string>();
        var result = CertCollectionLogic.Collect(
            () => new[] { good, dupBc, emptyEku, trailing },
            c => CertInventoryMapper.FromX509(c, Now),
            onSkipped: ex => reasons.Add(CertSkipReason.Of(ex)));

        Assert.Equal(CertCollectionStatus.Partial, result.Status);
        Assert.Equal(3, result.Skipped);
        Assert.Equal(new[] { "Patched Test Valid" }, result.Certificates!.Select(c => c.SubjectCn).ToArray());
        Assert.Equal(
            new[] { CertSkipReason.ExtensionsAmbiguous, CertSkipReason.DerUnparseable, CertSkipReason.DerUnparseable },
            reasons.ToArray());
    }

    [Fact]
    public void OnlyUnclassifiableCertificates_ArePartial_WithCertificatesOmitted()
    {
        using var dupEku = WithDuplicate(EkuOid,
            Ext(EkuOid, "30 0A 06 08 2B 06 01 05 05 07 03 01"),
            "30 0A 06 08 2B 06 01 05 05 07 03 01", secondCritical: false);

        var result = CertCollectionLogic.Collect(() => new[] { dupEku }, c => CertInventoryMapper.FromX509(c, Now));

        Assert.Equal(CertCollectionStatus.Partial, result.Status);
        Assert.Equal(1, result.Skipped);
        Assert.Null(result.Certificates);
    }

    [Fact]
    public void ReasonOf_AnyOtherException_IsCertificateUnparseable()
    {
        Assert.Equal("certificate_unparseable", CertSkipReason.Of(new CryptographicException()));
        Assert.Equal("extensions_ambiguous", CertSkipReason.ExtensionsAmbiguous);
        Assert.Equal("der_unparseable", CertSkipReason.DerUnparseable);
    }

    // ---- parity with the macOS PAT-1735 fixtures ------------------------------------
    // PEMs copied verbatim from macos/lib/test-certs.zsh (public, keyless, self-signed
    // test certificates). Expected outcomes are the macOS ones.

    private const string MacDupBc = """
        -----BEGIN CERTIFICATE-----
        MIIBrDCCAVGgAwIBAgIIfqPMgNTO2KQwCgYIKoZIzj0EAwIwOzEVMBMGA1UECgwM
        UGF0Y2hlZCBUZXN0MSIwIAYDVQQDDBlQYXRjaGVkIFRlc3QgRHVwbGljYXRlIEJD
        MCAXDTI2MDkxNDAwNTEwMFoYDzIxMjYwODIxMDA1MTAwWjA7MRUwEwYDVQQKDAxQ
        YXRjaGVkIFRlc3QxIjAgBgNVBAMMGVBhdGNoZWQgVGVzdCBEdXBsaWNhdGUgQkMw
        WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ644qiKO7E97pcj35ZWlGh2nQEkaAp
        LHCHVwGRONgGca3/KBn73XKicRfU6YoEgvwofJyeFr0uS8dnI7PZ6LQ7oz0wOzAJ
        BgNVHRMEAjAAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFKM8IXxuzaNcIR51
        kD3vUlF+y0rDMAoGCCqGSM49BAMCA0kAMEYCIQDNrHqSTg3f9c8XvfzPBO8JIXq8
        nXl/iKivfCO/gFvsawIhAOoojx+VCsL5wmW+MCCaM+FLQnXbSDKJk6etaekOPYrn
        -----END CERTIFICATE-----
        """;

    private const string MacBerBool = """
        -----BEGIN CERTIFICATE-----
        MIIBnjCCAUSgAwIBAgIIMrMZPNyXQaMwCgYIKoZIzj0EAwIwOjEVMBMGA1UECgwM
        UGF0Y2hlZCBUZXN0MSEwHwYDVQQDDBhQYXRjaGVkIFRlc3QgQkVSIEJvb2xlYW4w
        IBcNMjYwOTE0MDA1MDA4WhgPMjEyNjA4MjEwMDUwMDhaMDoxFTATBgNVBAoMDFBh
        dGNoZWQgVGVzdDEhMB8GA1UEAwwYUGF0Y2hlZCBUZXN0IEJFUiBCb29sZWFuMFkw
        EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOuOKoijuxPe6XI9+WVpRodp0BJGgKSxw
        h1cBkTjYBnGt/ygZ+91yonEX1OmKBIL8KHycnha9LkvHZyOz2ei0O6MyMDAwDwYD
        VR0TAQH/BAUwAwEBATAdBgNVHQ4EFgQUozwhfG7No1whHnWQPe9SUX7LSsMwCgYI
        KoZIzj0EAwIDSAAwRQIgTT2lH0LCh7QRqmPADem88lA0YpUDzBe97TMAQYtttAcC
        IQDe0F4TJ8nKLDljQW7s+OaubmncmeEFnHxMArKG2BeEMw==
        -----END CERTIFICATE-----
        """;

    private const string MacEmptyEku = """
        -----BEGIN CERTIFICATE-----
        MIIBoDCCAUagAwIBAgIJAIjj4/o3XR65MAoGCCqGSM49BAMCMDgxFTATBgNVBAoM
        DFBhdGNoZWQgVGVzdDEfMB0GA1UEAwwWUGF0Y2hlZCBUZXN0IEVtcHR5IEVLVTAg
        Fw0yNjA5MTQwMDUwMDhaGA8yMTI2MDgyMTAwNTAwOFowODEVMBMGA1UECgwMUGF0
        Y2hlZCBUZXN0MR8wHQYDVQQDDBZQYXRjaGVkIFRlc3QgRW1wdHkgRUtVMFkwEwYH
        KoZIzj0CAQYIKoZIzj0DAQcDQgAEOuOKoijuxPe6XI9+WVpRodp0BJGgKSxwh1cB
        kTjYBnGt/ygZ+91yonEX1OmKBIL8KHycnha9LkvHZyOz2ei0O6M3MDUwCQYDVR0T
        BAIwADAJBgNVHSUEAjAAMB0GA1UdDgQWBBSjPCF8bs2jXCEedZA971JRfstKwzAK
        BggqhkjOPQQDAgNIADBFAiEA+Ev5U5E96hWDkza2rdGmuJF6zDvdnvkjO+A3lrH+
        cfYCIE4uc05oZ5dkv5o5vEmVLkpP909vQIe7qCW38CBszhmJ
        -----END CERTIFICATE-----
        """;

    // Classified on macOS: critical basicConstraints CA:TRUE behind a Netscape Comment
    // whose text forges "CA:FALSE".
    private const string MacHiddenCa = """
        -----BEGIN CERTIFICATE-----
        MIIB+jCCAaCgAwIBAgIUSAxq8Ynz0+j9cv8IH3p96/R+rxgwCgYIKoZIzj0EAwIw
        ODEVMBMGA1UECgwMUGF0Y2hlZCBUZXN0MR8wHQYDVQQDDBZQYXRjaGVkIFRlc3Qg
        SGlkZGVuIENBMCAXDTIwMDEwMTAwMDAwMFoYDzIwOTkxMjMxMjM1OTU5WjA4MRUw
        EwYDVQQKDAxQYXRjaGVkIFRlc3QxHzAdBgNVBAMMFlBhdGNoZWQgVGVzdCBIaWRk
        ZW4gQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQKwSFGg0IlFPrK/DY8byl5
        jh5viZ/fXkcssno4Gq26x7eRsw8VUOEGwCcJzHwNQo9umtOKJL/uhwykkQbESd7x
        o4GFMIGCMFAGCWCGSAGG+EIBDQRDFkF4CiAgICAgICAgICAgIFg1MDl2MyBCYXNp
        YyBDb25zdHJhaW50czogCiAgICAgICAgICAgICAgICBDQTpGQUxTRTAPBgNVHRMB
        Af8EBTADAQH/MB0GA1UdDgQWBBTvhD5MVs6AKuCfc/CsqzB+LQ24IzAKBggqhkjO
        PQQDAgNIADBFAiEArGWLtEmhM0KJ0AucrLAfDDL8exPw1TFK30cS2A1GKC0CIEHH
        PY3Wkmfc1RuFdZ9YN2ErEFLTxkhC8JYWJYelkHuu
        -----END CERTIFICATE-----
        """;

    // Classified on macOS: CA:FALSE, EKU serverAuth, clientAuth, a private OID and a UUID OID.
    private const string MacLeafUnknownEku = """
        -----BEGIN CERTIFICATE-----
        MIIB5TCCAYqgAwIBAgIJAK95o8dIPTFuMAoGCCqGSM49BAMCMD8xFTATBgNVBAoM
        DFBhdGNoZWQgVGVzdDEmMCQGA1UEAwwdUGF0Y2hlZCBUZXN0IExlYWYgVW5rbm93
        biBFS1UwIBcNMjYwOTE0MDA1MDA4WhgPMjEyNjA4MjEwMDUwMDhaMD8xFTATBgNV
        BAoMDFBhdGNoZWQgVGVzdDEmMCQGA1UEAwwdUGF0Y2hlZCBUZXN0IExlYWYgVW5r
        bm93biBFS1UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ644qiKO7E97pcj35Z
        WlGh2nQEkaApLHCHVwGRONgGca3/KBn73XKicRfU6YoEgvwofJyeFr0uS8dnI7PZ
        6LQ7o20wazAJBgNVHRMEAjAAMD8GA1UdJQQ4MDYGCCsGAQUFBwMBBggrBgEFBQcD
        AgYKKwYBBAGDsgMHAQYUaYPwnafrz97gx6GnssCUjMj513YwHQYDVR0OBBYEFKM8
        IXxuzaNcIR51kD3vUlF+y0rDMAoGCCqGSM49BAMCA0kAMEYCIQDUj/4gfS1ScXaV
        23bg16bdCrjQ1q9HpuYJtb/1bbAc1AIhALiUnfgmo3W6HjVZG4ozboLQwbxRHtzk
        rT8OuaHlIr0a
        -----END CERTIFICATE-----
        """;

    [Theory]
    [InlineData("dup-bc", CertSkipReason.ExtensionsAmbiguous)]
    [InlineData("ber-bool", CertSkipReason.DerUnparseable)]
    [InlineData("empty-eku", CertSkipReason.DerUnparseable)]
    public void MacOsFixture_IsSkippedWithTheMacOsReason(string fixture, string reason)
    {
        var pem = fixture switch
        {
            "dup-bc"    => MacDupBc,
            "ber-bool"  => MacBerBool,
            "empty-eku" => MacEmptyEku,
            _           => throw new ArgumentOutOfRangeException(nameof(fixture)),
        };

        using var cert = LoadOnPlatformsThatAccept(() => X509Certificate2.CreateFromPem(pem));
        if (cert is null)
            return;
        AssertSkipped(cert, reason);
    }

    [Fact]
    public void MacOsFixture_HiddenCa_IsClassifiedAsCa_LikeMacOs()
    {
        using var cert = X509Certificate2.CreateFromPem(MacHiddenCa);

        var row = CertInventoryMapper.FromX509(cert, Now);

        Assert.True(row.BasicConstraintsCa);
        Assert.Empty(row.ExtKeyUsage);
    }

    [Fact]
    public void MacOsFixture_LeafUnknownEku_IsClassified_LikeMacOs_WithWindowsEkuNames()
    {
        using var cert = X509Certificate2.CreateFromPem(MacLeafUnknownEku);

        var row = CertInventoryMapper.FromX509(cert, Now);

        Assert.False(row.BasicConstraintsCa);
        Assert.Equal(4, row.ExtKeyUsage.Length);
        AssertSameRow(LegacyMapper.FromX509(cert, Now), row);
    }

    /// <summary>
    /// The mapper exactly as it was before PAT-1739 (origin/main 210971c0), kept only to
    /// prove well-formed certificates map to the same row.
    /// </summary>
    private static class LegacyMapper
    {
        public static InventoryCert FromX509(X509Certificate2 cert, DateTimeOffset now)
        {
            var notAfter = new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero);
            var eku = cert.Extensions["2.5.29.37"] as X509EnhancedKeyUsageExtension;
            var bc  = cert.Extensions["2.5.29.19"] as X509BasicConstraintsExtension;

            return new InventoryCert
            {
                Store              = CertStoreNames.My,
                SubjectCn          = CertInventoryMapper.ParseCn(cert.Subject),
                IssuerCn           = CertInventoryMapper.ParseCn(cert.Issuer),
                Sha1               = cert.Thumbprint.ToLowerInvariant(),
                NotAfter           = notAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                DaysUntilExpiry    = (int)Math.Round((notAfter - now).TotalDays),
                ExtKeyUsage        = eku is null
                    ? Array.Empty<string>()
                    : eku.EnhancedKeyUsages.Cast<Oid>()
                        .Select(o => o.FriendlyName ?? o.Value ?? "")
                        .Where(s => s.Length > 0)
                        .ToArray(),
                BasicConstraintsCa = bc?.CertificateAuthority ?? false,
                IsSelfSigned       = string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase),
            };
        }
    }
}
