using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2422: a health reason whose recorder has been removed can never be cleared by
/// a success, so a store written by an older release reports a healthy device as
/// degraded for good. The store drops retired (kind, subject) pairs when it loads.
///
/// Every fixture below is the PascalCase shape read from an installed device's
/// %ProgramData%\Patched\agent-health.json, not a shape built through the store's own
/// API, so the test holds for a file this build did not write.
/// </summary>
public sealed class RetiredHealthReasonsTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));

    public RetiredHealthReasonsTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    private string StorePath => Path.Combine(_directory, "agent-health.json");

    private AgentHealthStore NewStore() => new(NullLogger<AgentHealthStore>.Instance, StorePath);

    private JsonElement OnDisk() => JsonDocument.Parse(File.ReadAllText(StorePath)).RootElement.Clone();

    private static bool Has(JsonElement root, string section, string kind, string subject) =>
        root.GetProperty(section).TryGetProperty(kind, out var subjects)
        && subjects.TryGetProperty(subject, out _);

    // The device observed on 2026-10-05: both stale reasons, one real reason, and the
    // update-channel report the store also owns.
    private const string DeviceStore = """
        {
          "Active": {
            "sync_never_succeeded": {
              "catalogue": { "Reason": "fetch_failed", "FirstSeen": "2026-09-27T08:00:00+00:00", "LastSeen": "2026-10-01T09:14:02+00:00", "Count": 19 },
              "posture":   { "Reason": "fetch_failed", "FirstSeen": "2026-10-04T08:00:00+00:00", "LastSeen": "2026-10-05T08:00:00+00:00", "Count": 3 }
            },
            "capability_missing": {
              "package_engine": { "Reason": "not_shipped", "FirstSeen": "2026-09-28T08:00:00+00:00", "LastSeen": "2026-10-05T08:00:00+00:00", "Count": 1042 }
            },
            "self_update": {
              "apply": { "Reason": "marker_not_newer", "FirstSeen": "2026-10-02T10:00:00+00:00", "LastSeen": "2026-10-05T07:30:00+00:00", "Count": 7 }
            }
          },
          "EverSucceeded": {
            "sync_never_succeeded": { "catalogue": true, "posture": true },
            "capability_missing": { "package_engine": true },
            "self_update": { "artifact": true }
          },
          "LastSuccess": {
            "sync_never_succeeded": { "catalogue": "2026-09-26T08:00:00+00:00", "posture": "2026-10-03T08:00:00+00:00" },
            "self_update": { "artifact": "2026-10-05T07:30:00+00:00" }
          },
          "UpdateChannel": { "effective_channel": "stable", "source": "tenant", "config_version": 4, "observed_at": "2026-10-05T07:30:00+00:00" },
          "UpdateChannelTenantId": "tenant-1",
          "UpdateChannelDeviceId": "device-1"
        }
        """;

    [Fact]
    public void Load_RemovesRetiredReasonsFromTheFile_AndLeavesEveryOtherReasonAlone()
    {
        File.WriteAllText(StorePath, DeviceStore);
        var before = OnDisk();

        var section = NewStore().BuildPayloadSection();

        var after = OnDisk();
        Assert.False(Has(after, "Active", "sync_never_succeeded", "catalogue"));
        Assert.False(Has(after, "EverSucceeded", "sync_never_succeeded", "catalogue"));
        Assert.False(Has(after, "LastSuccess", "sync_never_succeeded", "catalogue"));
        Assert.False(Has(after, "Active", "capability_missing", "package_engine"));
        Assert.False(Has(after, "EverSucceeded", "capability_missing", "package_engine"));
        // A kind left with no subjects is removed, not left behind as an empty object.
        Assert.False(after.GetProperty("Active").TryGetProperty("capability_missing", out _));
        Assert.False(after.GetProperty("EverSucceeded").TryGetProperty("capability_missing", out _));

        // The unrelated reason keeps its reason, both timestamps and its count.
        var apply = after.GetProperty("Active").GetProperty("self_update").GetProperty("apply");
        var applyBefore = before.GetProperty("Active").GetProperty("self_update").GetProperty("apply");
        Assert.Equal("marker_not_newer", apply.GetProperty("Reason").GetString());
        Assert.Equal(7, apply.GetProperty("Count").GetInt32());
        Assert.Equal(applyBefore.GetProperty("FirstSeen").GetDateTimeOffset(), apply.GetProperty("FirstSeen").GetDateTimeOffset());
        Assert.Equal(applyBefore.GetProperty("LastSeen").GetDateTimeOffset(), apply.GetProperty("LastSeen").GetDateTimeOffset());

        // A live subject under the same kind as a retired one survives with its ledger.
        Assert.Equal(3, after.GetProperty("Active").GetProperty("sync_never_succeeded").GetProperty("posture").GetProperty("Count").GetInt32());
        Assert.True(Has(after, "EverSucceeded", "sync_never_succeeded", "posture"));
        Assert.True(Has(after, "LastSuccess", "sync_never_succeeded", "posture"));
        Assert.True(Has(after, "EverSucceeded", "self_update", "artifact"));
        Assert.True(Has(after, "LastSuccess", "self_update", "artifact"));
        Assert.Equal("tenant-1", after.GetProperty("UpdateChannelTenantId").GetString());
        Assert.Equal("device-1", after.GetProperty("UpdateChannelDeviceId").GetString());
        Assert.Equal("stable", after.GetProperty("UpdateChannel").GetProperty("effective_channel").GetString());

        // The same load reports exactly the two real reasons upstream.
        Assert.NotNull(section);
        Assert.Equal(
            new[] { "self_update/apply=marker_not_newer", "sync_never_succeeded/posture=fetch_failed" },
            section!.Degraded.Select(e => $"{e.Kind}/{e.Subject}={e.Reason}").OrderBy(s => s, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public void Load_IsIdempotent_ASecondLoadLeavesTheFileByteForByteUnchanged()
    {
        File.WriteAllText(StorePath, DeviceStore);

        NewStore().BuildPayloadSection();
        var afterFirst = File.ReadAllBytes(StorePath);
        Assert.False(Has(OnDisk(), "Active", "sync_never_succeeded", "catalogue"));

        NewStore().BuildPayloadSection();
        NewStore().GetLastSuccess("self_update", "artifact");

        Assert.Equal(afterFirst, File.ReadAllBytes(StorePath));
    }

    [Fact]
    public void Load_WithNothingRetired_DoesNotRewriteTheFile()
    {
        // Hand-formatted, so any rewrite by the store's own serializer changes the bytes.
        const string clean =
            "{\"Active\":{\"self_update\":{\"apply\":{\"Reason\":\"marker_not_newer\"," +
            "\"FirstSeen\":\"2026-10-02T10:00:00+00:00\",\"LastSeen\":\"2026-10-05T07:30:00+00:00\",\"Count\":7}}}," +
            "\"EverSucceeded\":{},\"LastSuccess\":{}}";
        File.WriteAllText(StorePath, clean);

        var section = NewStore().BuildPayloadSection();

        Assert.Equal(clean, File.ReadAllText(StorePath));
        Assert.Single(section!.Degraded);
    }

    [Fact]
    public void Load_MissingFile_DoesNotThrowAndDoesNotCreateOne()
    {
        var ex = Record.Exception(() => NewStore().BuildPayloadSection());

        Assert.Null(ex);
        Assert.False(File.Exists(StorePath));
    }

    [Theory]
    [InlineData("{ this is not json")]
    [InlineData("")]
    [InlineData("{\"Active\":null,\"EverSucceeded\":{},\"LastSuccess\":{}}")]
    [InlineData("{\"Active\":{\"sync_never_succeeded\":null},\"EverSucceeded\":{},\"LastSuccess\":{}}")]
    [InlineData("{\"Active\":{\"sync_never_succeeded\":{\"catalogue\":null}},\"EverSucceeded\":{},\"LastSuccess\":{}}")]
    public void Load_MalformedFile_DoesNotThrowAndLeavesItUntouched(string malformed)
    {
        File.WriteAllText(StorePath, malformed);

        object? section = "unset";
        var ex = Record.Exception(() => section = NewStore().BuildPayloadSection());

        Assert.Null(ex);
        Assert.Null(section); // corrupt stays "no opinion", never an all-clear
        Assert.Equal(malformed, File.ReadAllText(StorePath));
    }

    [Fact]
    public void AssuranceBuild_DoesNotReportTheAbsentPackageEngineAsDegraded()
    {
        var health = NewStore();
        var reporter = new AssuranceCapabilityHealth(
            NullLogger<AssuranceCapabilityHealth>.Instance, health, Path.Combine(_directory, "posture.json"));

        reporter.Record();
        reporter.Record();

        Assert.False(Has(OnDisk(), "Active", "capability_missing", "package_engine"));
        var degraded = health.BuildPayloadSection()!.Degraded;
        Assert.DoesNotContain(degraded, e => e.Subject == "package_engine");
        // Control: the cycle still records the condition that is real on this device.
        var real = Assert.Single(degraded);
        Assert.Equal("directive_skipped/device_removal=no_device_id", $"{real.Kind}/{real.Subject}={real.Reason}");
        Assert.Equal(2, real.Count);
    }

    [Theory]
    [InlineData("not_shipped")]          // every assurance build before this change
    [InlineData("no_engine_available")]  // the pre-PAT-1531 engine probe
    public void AssuranceBuild_ClearsAPackageEngineReasonAnOlderReleaseLeft_WithoutClaimingSuccess(string reason)
    {
        File.WriteAllText(StorePath,
            "{\"Active\":{\"capability_missing\":{\"package_engine\":{\"Reason\":\"" + reason + "\"," +
            "\"FirstSeen\":\"2026-09-28T08:00:00+00:00\",\"LastSeen\":\"2026-10-05T08:00:00+00:00\",\"Count\":1042}}}," +
            "\"EverSucceeded\":{},\"LastSuccess\":{}}");
        var health = NewStore();

        new AssuranceCapabilityHealth(
            NullLogger<AssuranceCapabilityHealth>.Instance, health, Path.Combine(_directory, "posture.json")).Record();

        var after = OnDisk();
        Assert.False(Has(after, "Active", "capability_missing", "package_engine"));
        // Removing a retired reason is not a success: no ledger entry may appear for it.
        Assert.False(Has(after, "EverSucceeded", "capability_missing", "package_engine"));
        Assert.False(Has(after, "LastSuccess", "capability_missing", "package_engine"));
        Assert.Null(health.GetLastSuccess("capability_missing", "package_engine"));
    }
}
