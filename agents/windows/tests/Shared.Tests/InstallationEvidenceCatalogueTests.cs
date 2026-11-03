using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Patched.Shared.InstallationEvidence;
using Patched.Shared.Removal;
using Xunit;

namespace Patched.Shared.Tests;

public sealed class InstallationEvidenceCatalogueTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-09-20T12:00:00Z");
    private static readonly ReviewedInstallationTarget Target = new("windows_msi_product_code",
        "{00112233-4455-6677-8899-AABBCCDDEEFF}", "CN=Fixture & Co", @"C:\Program Files\Fixture", @"C:\Program Files\Fixture\Fixture.exe");

    private static JsonObject Payload(params ReviewedInstallationTarget[] targets) => new()
    {
        ["tenant_id"] = "tenant-a",
        ["config_version"] = 2,
        ["windows_installation_evidence"] = new JsonObject
        {
            ["schema_version"] = 1,
            ["catalogue_version"] = "2026.09.20.1",
            ["delivery_version"] = 1,
            ["content_hash"] = InstallationEvidenceCatalogue.ContentDigest("2026.09.20.1", targets),
            ["published_at"] = "2026-09-20T00:00:00Z",
            ["expires_at"] = "2026-12-19T00:00:00Z",
            ["targets"] = new JsonArray(targets.Select(t => (JsonNode)new JsonObject
            {
                ["authenticode_subject"] = t.AuthenticodeSubject,
                ["executable_path"] = t.ExecutablePath,
                ["identity_kind"] = t.IdentityKind,
                ["identity_value"] = t.IdentityValue,
                ["install_path"] = t.InstallPath,
            }).ToArray()),
        },
    };

    private static InstallationEvidenceCatalogue? Parse(JsonNode payload) =>
        InstallationEvidenceCatalogue.ParseVerifiedPayload(Encoding.UTF8.GetBytes(payload.ToJsonString()), Now);

    [Fact]
    public async Task PublishedEmptyEnvelopeMatchesExactCrossLanguageHashAndNeverProbes()
    {
        var catalogue = Parse(Payload());
        Assert.NotNull(catalogue);
        Assert.Empty(catalogue.Targets);
        Assert.Equal("a3ea6bba02d8766c4f8432a04caf26154929651cb4722909b7f04df44922df5c", catalogue.ContentHash);
        var calls = 0;
        var app = new InventoryApp { Name = "Fixture", Version = "1", Identifier = Target.IdentityValue };
        var result = await InstallationEvidenceCollector.CollectVerifiedAsync([app], catalogue, (_, _) =>
        { calls++; return Task.FromResult(new AppInstallationEvidence()); }, new CatalogueClock(Now));
        Assert.Equal(0, calls);
        Assert.Same(app, result.Apps[0]);
        Assert.Null(result.Apps[0].InstallationEvidence);
        Assert.Equal("unavailable", result.Summary.CollectionStatus);
        Assert.Equal("2026.09.20.1", result.Summary.CatalogueVersion);
        Assert.Equal(1, result.Summary.DeliveryVersion);
    }

    [Fact]
    public void HashUsesGoEscapingAndAlphabeticKeys()
    {
        const string expected = "{\"catalogue_version\":\"2026.09.20.1\",\"schema_version\":1,\"targets\":[{\"authenticode_subject\":\"CN=Fixture \\u0026 Co\",\"executable_path\":\"C:\\\\Program Files\\\\Fixture\\\\Fixture.exe\",\"identity_kind\":\"windows_msi_product_code\",\"identity_value\":\"{00112233-4455-6677-8899-AABBCCDDEEFF}\",\"install_path\":\"C:\\\\Program Files\\\\Fixture\"}]}";
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(expected))).ToLowerInvariant(),
            InstallationEvidenceCatalogue.ContentDigest("2026.09.20.1", [Target]));
        Assert.NotNull(Parse(Payload(Target)));
    }

    // Independently produced by Go encoding/json.Marshal(map[string]any{...})
    // and crypto/sha256, with the same fixed target paths/ProductCode as Target.
    [Theory]
    [InlineData("CN=Crème 東京 🚀", "75ea4e567c73f0252034b0f8f84f335fb48c48cdace862454658baf5162bc5ce")]
    [InlineData("CN=<Publisher>& \"Quoted\" \\ Vendor", "1efaf5756bb5a1a610e003a1f8808cf3779b7e3834d7117d4255ab6fe57cbfaf")]
    [InlineData("CN=Line\u2028Paragraph\u2029Space\u3000Publisher", "254d69f456acd080ef90bd564fec971c5e47fc54e9464e1583563a7cbc34e045")]
    [InlineData("CN=Cafe\u0301", "6d5614fd83fa82c11ca74d7ac141eee813628233cbada7436ee79e601f806713")]
    public void UnicodeContentDigestMatchesIndependentGoVectors(string subject, string expected)
    {
        var target = Target with { AuthenticodeSubject = subject };
        Assert.Equal(expected, InstallationEvidenceCatalogue.ContentDigest("2026.09.20.1", [target]));
        Assert.NotNull(Parse(Payload(target)));
    }

    [Theory]
    [InlineData(0xd800)]
    [InlineData(0xdc00)]
    public void UnpairedUtf16CannotBeSilentlyReplacedDuringHashing(int scalar)
    {
        var invalid = "CN=Fixture" + (char)scalar;
        var target = Target with { AuthenticodeSubject = invalid };
        Assert.False(InstallationEvidenceCatalogue.ValidTarget(target));
        Assert.False(InstallationEvidenceCatalogue.SafePath("C:\\" + invalid + "\\app.exe"));
        Assert.Throws<ArgumentException>(() => InstallationEvidenceCatalogue.ContentDigest("2026.09.20.1", [target]));
        Assert.Throws<ArgumentException>(() => InstallationEvidenceCatalogue.ContentDigest(invalid, []));
    }

    [Theory]
    [InlineData("\\ud800")]
    [InlineData("\\udc00")]
    [InlineData("\\ud800text")]
    [InlineData("\\udc00\\ud800")]
    public void SignedJsonWithInvalidUnicodeEscapeIsUnavailable(string escape)
    {
        var json = Payload().ToJsonString().Replace("2026.09.20.1", escape);
        Assert.Null(InstallationEvidenceCatalogue.ParseVerifiedPayload(Encoding.UTF8.GetBytes(json), Now));
    }

    [Fact]
    public async Task ParentRejectsAnExpiredSnapshotWithoutInvokingProbe()
    {
        var clock = new CatalogueClock(Now);
        var catalogue = Parse(Payload(Target))! with { ExpiresAt = Now };
        var result = await InstallationEvidenceCollector.CollectVerifiedAsync(
            [new InventoryApp { Name = "Fixture", Version = "1", Identifier = Target.IdentityValue }], catalogue,
            (_, _) => throw new Exception("must not probe"), clock);
        Assert.Equal("unavailable", result.Summary.CollectionStatus);
        Assert.Equal(["catalogue_not_current"], result.Summary.Errors);
    }

    [Fact]
    public async Task ParentRechecksExpiryBetweenTargetsAndAfterProbeCompletion()
    {
        var clock = new CatalogueClock(Now);
        var later = Target with { IdentityValue = "{10112233-4455-6677-8899-AABBCCDDEEFF}" };
        var catalogue = Parse(Payload(Target, later))! with { ExpiresAt = Now.AddSeconds(1) };
        var calls = 0;
        var result = await InstallationEvidenceCollector.CollectVerifiedAsync(
            [new InventoryApp { Name = "Fixture", Version = "1", Identifier = Target.IdentityValue },
                new InventoryApp { Name = "Fixture 2", Version = "1", Identifier = later.IdentityValue }], catalogue,
            (_, _) => { calls++; clock.Now = Now.AddSeconds(1); return Task.FromResult(new AppInstallationEvidence { CollectionStatus = "complete" }); }, clock);
        Assert.Equal(1, calls);
        Assert.Equal("unavailable", result.Summary.CollectionStatus);
        Assert.All(result.Apps, app => Assert.Equal(["catalogue_not_current"], app.InstallationEvidence!.Errors));
    }

    private sealed class CatalogueClock(DateTimeOffset now) : TimeProvider
    {
        internal DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Theory]
    [InlineData("schema_version", "2")]
    [InlineData("schema_version", "\"1\"")]
    [InlineData("catalogue_version", "null")]
    [InlineData("delivery_version", "0")]
    [InlineData("delivery_version", "-1")]
    [InlineData("delivery_version", "9223372036854775808")]
    [InlineData("delivery_version", "1.1")]
    [InlineData("content_hash", "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"")]
    [InlineData("content_hash", "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"")]
    [InlineData("expires_at", "\"2026-09-20T12:00:00Z\"")]
    [InlineData("expires_at", "\"2026-09-19T00:00:00Z\"")]
    [InlineData("expires_at", "\"2026-12-19\"")]
    [InlineData("published_at", "\"2026-09-21T00:00:00Z\"")]
    [InlineData("targets", "null")]
    [InlineData("targets", "{}")]
    public async Task InvalidEnvelopesNeverProbe(string member, string json)
    {
        var payload = Payload(Target);
        payload["windows_installation_evidence"]![member] = JsonNode.Parse(json);
        var catalogue = Parse(payload);
        Assert.Null(catalogue);
        var result = await InstallationEvidenceCollector.CollectVerifiedAsync([], catalogue,
            (_, _) => throw new Exception("must not probe"));
        Assert.Equal("unavailable", result.Summary.CollectionStatus);
    }

    [Theory]
    [InlineData("identity_kind", "msi_upgrade_code")]
    [InlineData("identity_kind", "winget_id")]
    [InlineData("identity_value", "Fixture.App")]
    [InlineData("identity_value", "00112233-4455-6677-8899-AABBCCDDEEFF")]
    [InlineData("install_path", "\\\\host\\share")]
    [InlineData("install_path", "C:\\Fixture\\..\\Windows")]
    [InlineData("executable_path", "C:\\elsewhere\\file.exe")]
    [InlineData("executable_path", "C:\\Program Files\\Fixture\\NUL.exe")]
    [InlineData("executable_path", "C:\\Program Files\\Fixture\\file.exe:stream")]
    [InlineData("authenticode_subject", "")]
    public void HostileTargetInvalidatesWholeCatalogue(string member, string value)
    {
        var payload = Payload(Target);
        payload["windows_installation_evidence"]!["targets"]![0]![member] = value;
        Assert.Null(Parse(payload));
    }

    [Theory]
    [InlineData("{00112233-4455-6677-8899-aabbccddeeff}")]
    [InlineData("{00112233-4455-6677-8899-AABBccddeeFF}")]
    [InlineData("00112233-4455-6677-8899-AABBCCDDEEFF")]
    [InlineData(" {00112233-4455-6677-8899-AABBCCDDEEFF}")]
    public void NonCanonicalProductCodeIsRejectedEvenWithMatchingContentHash(string productCode)
    {
        var target = Target with { IdentityValue = productCode };
        Assert.False(InstallationEvidenceCatalogue.ValidTarget(target));
        // Payload recomputes the hash over the hostile value: rejection must come
        // from canonical identity validation, not a stale content-hash mismatch.
        Assert.Null(Parse(Payload(target)));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"windows_installation_evidence\":null}")]
    [InlineData("{\"windows_installation_evidence\":[]}")]
    [InlineData("{\"windows_installation_evidence\":true}")]
    public void OlderAndMalformedConfigsAreUnavailable(string value) =>
        Assert.Null(InstallationEvidenceCatalogue.ParseVerifiedPayload(Encoding.UTF8.GetBytes(value), Now));

    [Fact]
    public void DuplicateUnknownMembersAndCaseVariantsAreRejected()
    {
        var payload = Payload(Target);
        payload["windows_installation_evidence"]!["tenant_path"] = "C:\\evil.exe";
        Assert.Null(Parse(payload));
        var json = Payload().ToJsonString().Replace("\"schema_version\":1", "\"schema_version\":1,\"Schema_Version\":1");
        Assert.Null(InstallationEvidenceCatalogue.ParseVerifiedPayload(Encoding.UTF8.GetBytes(json), Now));
        json = Payload().ToJsonString().Replace("windows_installation_evidence", "Windows_Installation_Evidence");
        Assert.Null(InstallationEvidenceCatalogue.ParseVerifiedPayload(Encoding.UTF8.GetBytes(json), Now));
    }

    [Fact]
    public void DuplicateAndUnsortedTargetsAreRejected()
    {
        Assert.Null(Parse(Payload(Target, Target with { IdentityValue = Target.IdentityValue.ToLowerInvariant() })));
        var later = Target with { IdentityValue = "{10112233-4455-6677-8899-AABBCCDDEEFF}" };
        Assert.Null(Parse(Payload(later, Target)));
        Assert.NotNull(Parse(Payload(Target, later)));
    }

    [Fact]
    public async Task ProvenanceIsAdditiveAndInventoryMetadataSurvives()
    {
        var catalogue = Parse(Payload(Target))!;
        var app = new InventoryApp { Name = "Fixture", Identifier = Target.IdentityValue, Publisher = "Registry publisher", Architecture = "x86", Version = "1" };
        var result = await InstallationEvidenceCollector.CollectVerifiedAsync([app], catalogue,
            (_, _) => Task.FromResult(new AppInstallationEvidence { CollectionStatus = "complete" }), new CatalogueClock(Now));
        Assert.Equal(app, result.Apps[0] with { InstallationEvidence = null });
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(result.Apps[0].InstallationEvidence));
        Assert.Equal(catalogue.ContentHash, document.RootElement.GetProperty("content_hash").GetString());
        Assert.Equal(catalogue.DeliveryVersion, document.RootElement.GetProperty("delivery_version").GetInt64());
        Assert.Equal(catalogue.CatalogueVersion, document.RootElement.GetProperty("catalogue_version").GetString());
        Assert.DoesNotContain("catalogue_version", JsonSerializer.Serialize(new AppInstallationEvidence()));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MsiArpKeyContractPreservesBracesAndMatchesCanonicalTarget(bool lowercaseObservation)
    {
        var key = lowercaseObservation ? Target.IdentityValue.ToLowerInvariant() : Target.IdentityValue;
        var program = new InstalledProgram { Name = "Fixture", RegistryKeyName = key };
        // Existing GuidKey/MsiProductCode contract recognises braced ARP keys;
        // InstalledAppScanner.ScanHive copies keyName verbatim to Identifier.
        Assert.True(UninstallPlanner.IsMsi(program));
        Assert.Equal(key, UninstallPlanner.MsiProductCode(program));
        var bare = program with { RegistryKeyName = key.Trim('{', '}') };
        Assert.False(UninstallPlanner.IsMsi(bare));
        Assert.Null(UninstallPlanner.MsiProductCode(bare));

        var app = new InventoryApp { Name = program.Name, Version = "1", Identifier = program.RegistryKeyName };
        var catalogue = Parse(Payload(Target))!;
        var probes = 0;
        var result = await InstallationEvidenceCollector.CollectVerifiedAsync([app], catalogue,
            (_, _) => { probes++; return Task.FromResult(new AppInstallationEvidence { CollectionStatus = "complete" }); },
            new CatalogueClock(Now));
        Assert.Equal(1, probes);
        Assert.Equal(key, result.Apps[0].Identifier);
        Assert.Equal("complete", result.Apps[0].InstallationEvidence!.CollectionStatus);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("{\"signed_payload\":{},\"signature\":null,\"key_id\":1}")]
    public void UntrustedEnvelopesCannotReachParsing(string envelope) =>
        Assert.False(Ed25519Verifier.TryVerifyEnvelope(Encoding.UTF8.GetBytes(envelope), out _));

    [Fact]
    public void UnsignedAndWrongKeyPayloadCannotGrantEvidence()
    {
        var envelope = new JsonObject
        {
            ["key_id"] = Ed25519Verifier.PinnedKeyId,
            ["signed_payload"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(Payload(Target).ToJsonString())),
            ["signature"] = Convert.ToBase64String(new byte[64]),
        };
        Assert.False(Ed25519Verifier.TryVerifyEnvelope(Encoding.UTF8.GetBytes(envelope.ToJsonString()), out _));
        envelope["key_id"] = "another-key";
        Assert.False(Ed25519Verifier.TryVerifyEnvelope(Encoding.UTF8.GetBytes(envelope.ToJsonString()), out _));
    }
}
