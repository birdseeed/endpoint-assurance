using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Patched.Shared.Config;
using Patched.Shared.InstallationEvidence;
using Xunit;

namespace Patched.Service.Tests;

public sealed class InstallationEvidenceStoreTests
{
    private static readonly DateTimeOffset Published = DateTimeOffset.Parse("2026-09-20T00:00:00Z");
    private static readonly DateTimeOffset Now = Published.AddHours(12);
    private static InstallationEvidenceCatalogue Catalogue(long version = 2, string? hash = null) =>
        new("2026.09.20.1", version, hash ?? InstallationEvidenceCatalogue.ContentDigest("2026.09.20.1", []),
            Published, Published.AddDays(90), []);

    private static byte[] Payload(long delivery = 2, int config = 100, string tenant = "tenant-a") =>
        Encoding.UTF8.GetBytes($$$"""
        {"tenant_id":"{{{tenant}}}","config_version":{{{config}}},"windows_installation_evidence":{
          "schema_version":1,"catalogue_version":"2026.09.20.1","delivery_version":{{{delivery}}},
          "content_hash":"a3ea6bba02d8766c4f8432a04caf26154929651cb4722909b7f04df44922df5c",
          "published_at":"2026-09-20T00:00:00Z","expires_at":"2026-12-19T00:00:00Z","targets":[]}}
        """);

    [Fact]
    public void DeliveryFloorSurvivesSerializationAndIsIndependentOfTenantConfigVersion()
    {
        var floor = InstallationEvidenceStore.ParseFloor(JsonSerializer.SerializeToUtf8Bytes(InstallationEvidenceStore.Floor.From(Catalogue())));
        Assert.False(InstallationEvidenceStore.Accepts(floor, Catalogue(1)));
        Assert.True(InstallationEvidenceStore.Accepts(floor, Catalogue(2)));
        Assert.True(InstallationEvidenceStore.Accepts(floor, Catalogue(3)));
        var payload = Payload(delivery: 1, config: int.MaxValue, tenant: "new-tenant");
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(payload, payload, floor,
            new AgentConfig { TenantId = "new-tenant", ConfigVersion = int.MaxValue }, Now));
    }

    [Fact]
    public void SameDeliveryCannotMutateContentOrExtendExpiry()
    {
        var floor = InstallationEvidenceStore.Floor.From(Catalogue());
        Assert.False(InstallationEvidenceStore.Accepts(floor, Catalogue(hash: new string('b', 64))));
        Assert.False(InstallationEvidenceStore.Accepts(floor, Catalogue() with { ExpiresAt = Published.AddDays(91) }));
        Assert.False(InstallationEvidenceStore.Accepts(floor, Catalogue() with { PublishedAt = Published.AddHours(1) }));
        Assert.True(InstallationEvidenceStore.Accepts(floor, Catalogue(3) with { ExpiresAt = Published.AddDays(91) }));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("null")]
    [InlineData("1")]
    [InlineData("{\"DeliveryVersion\":1,\"ContentHash\":\"bad\"}")]
    public void CorruptFloorIsNeverTreatedAsAbsent(string json) =>
        Assert.ThrowsAny<Exception>(() => InstallationEvidenceStore.ParseFloor(Encoding.UTF8.GetBytes(json)));

    [Fact]
    public void CacheRequiresExactCurrentConfigAndMatchingPersistedFloor()
    {
        var payload = Payload();
        var floor = InstallationEvidenceStore.Floor.From(Catalogue());
        var current = new AgentConfig { TenantId = "tenant-a", ConfigVersion = 100 };
        Assert.NotNull(InstallationEvidenceStore.MatchVerifiedPayload(payload, payload, floor, current, Now));
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(payload, payload, null, current, Now));
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(payload, Payload(3), floor, current, Now));
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(payload, Encoding.UTF8.GetBytes("{}"), floor, current, Now));
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(payload, payload, floor, current with { TenantId = "tenant-b" }, Now));
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(payload, payload, floor, current with { ConfigVersion = 101 }, Now));
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(payload, payload, floor, current, Published.AddDays(90)));
    }

    [Fact]
    public void ParentRequiresCurrentWhileHelperStillRequiresExactAcceptedPayload()
    {
        Assert.Null(InstallationEvidenceStore.LoadForInventory(null!));
        var payload = Payload();
        var floor = InstallationEvidenceStore.Floor.From(Catalogue());
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(payload, payload, floor, AgentConfig.Defaults, Now));
        // Helper has no typed manager, but null cannot bypass payload-cache binding.
        Assert.NotNull(InstallationEvidenceStore.MatchVerifiedPayload(payload, payload, floor, null, Now));
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(payload, Payload(config: 101), floor, null, Now));
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(payload, Payload(tenant: "other"), floor, null, Now));
    }

    [Fact]
    public void UnreadableFloorDoesNotPublishAnEnvelopeOrResetTheFloor()
    {
        var writes = 0;
        Assert.Throws<IOException>(() => InstallationEvidenceStore.PersistVerifiedEnvelope(Payload(), Payload(), Now,
            () => throw new IOException("unreadable"), _ => writes++, _ => writes++));
        Assert.Equal(0, writes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PersistedSameVersionMutationRetainsFloorAndMakesSnapshotUnavailable(bool expiryOnly)
    {
        var floor = InstallationEvidenceStore.Floor.From(Catalogue());
        var retained = floor;
        var payload = JsonNode.Parse(Payload())!;
        if (expiryOnly)
            payload["windows_installation_evidence"]!["expires_at"] = "2026-12-20T00:00:00Z";
        else
        {
            payload["windows_installation_evidence"]!["catalogue_version"] = "2026.09.20.2";
            payload["windows_installation_evidence"]!["content_hash"] = InstallationEvidenceCatalogue.ContentDigest("2026.09.20.2", []);
        }
        var bytes = Encoding.UTF8.GetBytes(payload.ToJsonString());
        Assert.NotNull(InstallationEvidenceCatalogue.ParseVerifiedPayload(bytes, Now));
        byte[]? cached = null;
        InstallationEvidenceStore.PersistVerifiedEnvelope(bytes, bytes, Now, () => floor,
            next => floor = next, next => cached = next);
        Assert.Equal(retained, floor);
        Assert.Equal(bytes, cached);
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(cached!, cached!, floor, null, Now));
    }

    [Fact]
    public void FloorWrittenBeforeEnvelopeMakesInterruptedUpdateUnavailable()
    {
        var oldPayload = Payload(1);
        var nextPayload = Payload(2);
        var oldFloor = InstallationEvidenceStore.Floor.From(Catalogue(1));
        var nextFloor = InstallationEvidenceStore.Floor.From(Catalogue(2));
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(oldPayload, oldPayload, nextFloor, null, Now));
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(nextPayload, nextPayload, oldFloor, null, Now));
        Assert.NotNull(InstallationEvidenceStore.MatchVerifiedPayload(nextPayload, nextPayload, nextFloor, null, Now));
    }

    [Fact]
    public void PersistedFloorSurvivesMissingMalformedAndOlderDeliveriesAndRestart()
    {
        var directory = Directory.CreateTempSubdirectory("evidence-floor-test-").FullName;
        var floorFile = Path.Combine(directory, "floor.json");
        var envelopeFile = Path.Combine(directory, "envelope.json");
        try
        {
            InstallationEvidenceStore.Floor? Read() => File.Exists(floorFile)
                ? InstallationEvidenceStore.ParseFloor(File.ReadAllBytes(floorFile)) : null;
            void Commit(byte[] payload) => InstallationEvidenceStore.PersistVerifiedEnvelope(payload, payload, Now, Read,
                floor => File.WriteAllBytes(floorFile, JsonSerializer.SerializeToUtf8Bytes(floor)),
                bytes => File.WriteAllBytes(envelopeFile, bytes));
            Commit(Payload(2));
            var retained = File.ReadAllBytes(floorFile);
            foreach (var rejected in new[] { Encoding.UTF8.GetBytes("{}"), Encoding.UTF8.GetBytes("{\"windows_installation_evidence\":null}"),
                Encoding.UTF8.GetBytes("{\"windows_installation_evidence\":true}"), Payload(1) })
            {
                Commit(rejected);
                Assert.Equal(retained, File.ReadAllBytes(floorFile));
                Assert.Equal(rejected, File.ReadAllBytes(envelopeFile));
                Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(rejected, rejected, Read(), null, Now));
            }
            Commit(Payload(3));
            Assert.Equal(3, Read()!.DeliveryVersion);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void WriteFailuresCannotPublishAnEnvelopeBeforeTheFloor()
    {
        var writes = new List<string>();
        var floor = InstallationEvidenceStore.Floor.From(Catalogue(1));
        Assert.Throws<IOException>(() => InstallationEvidenceStore.PersistVerifiedEnvelope(Payload(), Payload(), Now,
            () => floor, _ => throw new IOException(), _ => writes.Add("envelope")));
        Assert.Empty(writes);
        Assert.Throws<IOException>(() => InstallationEvidenceStore.PersistVerifiedEnvelope(Payload(), Payload(), Now,
            () => floor, next => { floor = next; writes.Add("floor"); }, _ => throw new IOException()));
        Assert.Equal(["floor"], writes);
        Assert.Equal(2, floor.DeliveryVersion);
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(Payload(1), Payload(1), floor, null, Now));
    }

    [Fact]
    public void AcceptanceReportsFailureWithoutRelaxingCacheOrFloorBinding()
    {
        var floor = InstallationEvidenceStore.Floor.From(Catalogue(1));
        var cached = Payload(1);
        var next = Payload(2);
        var accepted = InstallationEvidenceStore.AcceptVerifiedEnvelope(() =>
            InstallationEvidenceStore.PersistVerifiedEnvelope(next, next, Now, () => floor,
                value => floor = value, _ => throw new IOException("cache write failed")));
        Assert.False(accepted); // The fetcher can emit a warning without exception text.
        Assert.Equal(2, floor.DeliveryVersion);
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(cached, next, floor, null, Now));
        Assert.Null(InstallationEvidenceStore.MatchVerifiedPayload(cached, cached, floor, null, Now));

        accepted = InstallationEvidenceStore.AcceptVerifiedEnvelope(() =>
            InstallationEvidenceStore.PersistVerifiedEnvelope(next, next, Now, () => floor,
                value => floor = value, value => cached = value));
        Assert.True(accepted);
        Assert.NotNull(InstallationEvidenceStore.MatchVerifiedPayload(cached, next, floor, null, Now));
    }

    [Fact]
    public void AcceptanceReportsTrustFailureWithoutPublishingState()
    {
        Assert.False(InstallationEvidenceStore.AcceptVerifiedEnvelope(() => throw new UnauthorizedAccessException()));
    }

    [Fact]
    public void HelperBindsIndexVersionHashAndExpiryWithoutAcceptingPaths()
    {
        var target = new ReviewedInstallationTarget("windows_msi_product_code", "{00112233-4455-6677-8899-AABBCCDDEEFF}",
            "CN=Fixture", @"C:\Fixture", @"C:\Fixture\app.exe");
        var snapshot = Catalogue() with { Targets = new[] { target }, ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10) };
        Assert.True(InstallationEvidenceProbe.MatchesBinding(snapshot, 0, 2, snapshot.ContentHash));
        Assert.False(InstallationEvidenceProbe.MatchesBinding(snapshot, 1, 2, snapshot.ContentHash));
        Assert.False(InstallationEvidenceProbe.MatchesBinding(snapshot, -1, 2, snapshot.ContentHash));
        Assert.False(InstallationEvidenceProbe.MatchesBinding(snapshot, 0, 3, snapshot.ContentHash));
        Assert.False(InstallationEvidenceProbe.MatchesBinding(snapshot, 0, 2, new string('c', 64)));
        Assert.False(InstallationEvidenceProbe.MatchesBinding(snapshot with { ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) }, 0, 2, snapshot.ContentHash));
        Assert.False(InstallationEvidenceProbe.MatchesBinding(null, 0, 2, snapshot.ContentHash));
        Assert.Equal(2, InstallationEvidenceProbe.RunCommand([InstallationEvidenceProbe.Command, @"C:\secret.exe", "2", snapshot.ContentHash]));
    }
}
