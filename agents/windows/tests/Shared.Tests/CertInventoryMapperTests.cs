using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Patched.Shared.Certificates;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1737: <see cref="CertInventoryMapper"/> against real, freshly generated
/// certificates. The Windows collector used to drop any certificate whose subject
/// contained "Microsoft" or "Windows" while still reporting the collection complete, so
/// a rogue root with a Microsoft-looking name never reached the platform and any stored
/// row for it was pruned.
/// </summary>
public sealed class CertInventoryMapperTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 14, 12, 0, 0, TimeSpan.Zero);

    private static X509Certificate2 SelfSignedCa(string subject, DateTimeOffset notAfter)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }, false));
        return req.CreateSelfSigned(Now.AddYears(-1), notAfter);
    }

    private static CertCollectionResult CollectThroughRealMapper(params X509Certificate2[] store) =>
        CertCollectionLogic.Collect(() => store, c => CertInventoryMapper.FromX509(c, Now));

    [Theory]
    [InlineData("CN=Microsoft Update Root CA")]
    [InlineData("CN=Windows Production PCA 2011, O=Microsoft Corporation, C=US")]
    [InlineData("CN=Rogue, O=microsoft windows")]
    public void PlatformLookingSubject_WithUnknownThumbprint_IsReported(string subject)
    {
        using var rogue = SelfSignedCa(subject, Now.AddYears(5));
        using var vpn   = SelfSignedCa("CN=Contoso VPN", Now.AddYears(1));

        var result = CollectThroughRealMapper(rogue, vpn);

        Assert.Equal(CertCollectionStatus.Complete, result.Status);
        Assert.Equal(0, result.Skipped);
        Assert.Equal(
            new[] { rogue.Thumbprint.ToLowerInvariant(), vpn.Thumbprint.ToLowerInvariant() },
            result.Certificates!.Select(c => c.Sha1).ToArray());
    }

    [Fact]
    public void FromX509_MapsEveryField()
    {
        var notAfter = new DateTimeOffset(2027, 3, 1, 8, 30, 0, TimeSpan.Zero);
        using var cert = SelfSignedCa("CN=Microsoft Update Root CA, O=Example", notAfter);

        var row = CertInventoryMapper.FromX509(cert, Now);

        Assert.Equal("Microsoft Update Root CA", row.SubjectCn);
        Assert.Equal("Microsoft Update Root CA", row.IssuerCn);
        Assert.Equal(cert.Thumbprint.ToLowerInvariant(), row.Sha1);
        Assert.Equal("2027-03-01T08:30:00Z", row.NotAfter);
        Assert.Equal((int)Math.Round((notAfter - Now).TotalDays), row.DaysUntilExpiry);
        Assert.True(row.BasicConstraintsCa);
        Assert.True(row.IsSelfSigned);
        Assert.Single(row.ExtKeyUsage);
    }

    /// <summary>PAT-1738: no explicit store defaults to My, the store CertCollector used before this ticket.</summary>
    [Fact]
    public void FromX509_NoStoreArgument_DefaultsToMy()
    {
        using var cert = SelfSignedCa("CN=Default Store", Now.AddYears(1));

        var row = CertInventoryMapper.FromX509(cert, Now);

        Assert.Equal(CertStoreNames.My, row.Store);
    }

    /// <summary>PAT-1738: each of the three Windows stores tags its rows with its own name.</summary>
    [Theory]
    [InlineData(CertStoreNames.My)]
    [InlineData(CertStoreNames.Root)]
    [InlineData(CertStoreNames.CA)]
    public void FromX509_TagsRowWithGivenStore(string store)
    {
        using var cert = SelfSignedCa($"CN=Tagged {store}", Now.AddYears(1));

        var row = CertInventoryMapper.FromX509(cert, Now, store);

        Assert.Equal(store, row.Store);
    }

    [Fact]
    public void FromX509_RejectsNullOrEmptyStore()
    {
        using var cert = SelfSignedCa("CN=Bad Store", Now.AddYears(1));

        Assert.Throws<ArgumentException>(() => CertInventoryMapper.FromX509(cert, Now, ""));
        Assert.Throws<ArgumentNullException>(() => CertInventoryMapper.FromX509(cert, Now, null!));
    }

    /// <summary>
    /// NotAfter is local time. An expiry that falls in a non-zero local offset (any
    /// non-UTC zone, or UK summer time) used to throw and skip the certificate. Only
    /// reproduces on a host whose zone is not UTC at that date; on a UTC host it still
    /// pins the value.
    /// </summary>
    [Theory]
    [InlineData(2027, 7, 1)]
    [InlineData(2027, 1, 15)]
    public void FromX509_NotAfter_IsUtc_WhateverTheLocalOffset(int year, int month, int day)
    {
        var notAfter = new DateTimeOffset(year, month, day, 23, 30, 0, TimeSpan.Zero);
        using var cert = SelfSignedCa("CN=Summer Expiry", notAfter);

        var row = CertInventoryMapper.FromX509(cert, Now);

        Assert.Equal(notAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"), row.NotAfter);
        Assert.Equal((int)Math.Round((notAfter - Now).TotalDays), row.DaysUntilExpiry);
    }

    [Fact]
    public void FromX509_IssuedCertificate_IsNotSelfSignedOrCa()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caReq = new CertificateRequest("CN=Internal CA", caKey, HashAlgorithmName.SHA256);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = caReq.CreateSelfSigned(Now.AddYears(-1), Now.AddYears(10));

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest("CN=host.example, O=Example", leafKey, HashAlgorithmName.SHA256);
        using var leaf = leafReq.Create(ca, Now.AddDays(-1), Now.AddDays(30), new byte[] { 1, 2, 3, 4 });

        var row = CertInventoryMapper.FromX509(leaf, Now);

        Assert.Equal("host.example", row.SubjectCn);
        Assert.Equal("Internal CA", row.IssuerCn);
        Assert.False(row.BasicConstraintsCa);
        Assert.False(row.IsSelfSigned);
        Assert.Empty(row.ExtKeyUsage);
    }

    [Theory]
    [InlineData("CN=Example, O=Org", "Example")]
    [InlineData("O=Org, CN=Last", "Last")]
    [InlineData("O=No Common Name", "O=No Common Name")]
    public void ParseCn_ExtractsCommonName(string dn, string expected)
    {
        Assert.Equal(expected, CertInventoryMapper.ParseCn(dn));
    }
}
