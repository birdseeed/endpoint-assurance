using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1016: install/update provenance (ProvenancePoster.PostAsync / BuildPayload)
/// carried no per-device identifier, unlike the uninstall path (RemovalRunner ->
/// UninstallProvenanceDevice), unlike the macOS emitter (patched-update.sh
/// emit_provenance's 'device': {'hw_uuid':..., 'computer_name':...}), and unlike
/// server-side expectations (go-service rings/advance.go queryFailureRate and
/// report/report.go fetchProvenancePatchHistory both join on
/// lower(pr.body->'device'->>'hw_uuid')). These tests pin BuildPayload's device
/// object to the exact same DeviceCollector.CollectDevice() source the uninstall
/// path already uses, so a future change that drifts the two apart (e.g. one path
/// switching to a different device-id source, or a key rename) fails here.
/// </summary>
public sealed class ProvenancePosterTests
{
    private sealed class ThrowingHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            throw new InvalidOperationException("BuildPayload tests must not perform HTTP calls.");
    }

    private static ProvenancePoster NewPoster(out DeviceCollector device)
    {
        device = new DeviceCollector(NullLogger<DeviceCollector>.Instance);
        var creds = CredentialStore.ForTesting("tenant-1", "bearer-1", "hmac-secret-1");
        var httpFactory = new ThrowingHttpClientFactory();

        // BuildPayload never touches the queue/health path, so a throwaway
        // AgentHealthStore pointed at a temp file (never written in these
        // tests) is enough — mirrors the storePathOverride seam other tests
        // in this suite use (e.g. AgentHealthStoreTests).
        var agentHealth = new AgentHealthStore(
            NullLogger<AgentHealthStore>.Instance,
            Path.Combine(Path.GetTempPath(), $"patched-provenance-poster-test-{Guid.NewGuid():N}.json"));

        // PAT-1249 non-author review (P3): without pumpOverride, ProvenancePoster
        // would build its own ProvenanceQueuePump pointed at the real
        // PathConstants.ProvenanceQueueDir (%ProgramData%\Patched\provenance-queue
        // on a real device). These tests only exercise BuildPayload, which never
        // touches the pump, so nothing here has ever actually written to that
        // directory — but a suite that leaves the door open to the live queue,
        // even via an unused field, is one accidental refactor away from writing
        // into it. That location is also this ticket's operating evidence (the
        // WIN-STAGING backlog), so it must never be touched by a test run.
        // Point the pump at a throwaway temp directory instead — the same
        // isolation ProvenanceQueuePumpTests gives every pump it builds directly.
        var pump = new ProvenanceQueuePump(
            NullLogger<ProvenancePoster>.Instance,
            httpFactory,
            creds,
            Path.Combine(Path.GetTempPath(), $"patched-provenance-poster-test-queue-{Guid.NewGuid():N}"));

        return new ProvenancePoster(
            NullLogger<ProvenancePoster>.Instance,
            httpFactory,
            creds,
            device,
            agentHealth,
            pumpOverride: pump);
    }

    private static AppEntry NewAppEntry() => new()
    {
        Label            = "test-label",
        Name             = "Test App",
        InstalledVersion = "1.0.0",
        AvailableVersion = "1.1.0",
        State            = AppState.Installed,
        LastAction       = "installed",
        LastActionAt     = DateTimeOffset.UtcNow,
        WingetId         = "Vendor.TestApp",
    };

    [Fact]
    public void BuildPayload_InstallAction_IncludesDeviceObjectSourcedFromDeviceCollector()
    {
        var poster = NewPoster(out var device);
        var payload = poster.BuildPayload(NewAppEntry());

        Assert.True(payload.ContainsKey("device"),
            "install/update provenance must carry a device object (PAT-1016) — the server-side " +
            "join on pr.body->'device'->>'hw_uuid' otherwise sees zero Windows observations.");
        var deviceObj = Assert.IsType<Dictionary<string, object?>>(payload["device"]);

        // Same source as the uninstall path (RemovalRunner.RunAsync calls
        // _device.CollectDevice() once and threads device.HwUuid /
        // (device.Hostname ?? MachineName) into UninstallProvenanceDevice).
        // Calling the same collector independently here must yield identical
        // values — if BuildPayload ever invents its own hw_uuid source instead
        // of reusing DeviceCollector, this assertion is what catches the drift.
        var expected = device.CollectDevice();
        var expectedComputerName = string.IsNullOrWhiteSpace(expected.Hostname)
            ? Environment.MachineName
            : expected.Hostname;

        Assert.False(string.IsNullOrWhiteSpace(expected.HwUuid));
        Assert.Equal(expected.HwUuid, deviceObj["hw_uuid"]);
        Assert.Equal(expectedComputerName, deviceObj["computer_name"]);
    }

    [Fact]
    public void BuildPayload_DeviceObject_HasExactlyHwUuidAndComputerNameKeys()
    {
        var poster = NewPoster(out _);
        var payload = poster.BuildPayload(NewAppEntry());

        var deviceObj = Assert.IsType<Dictionary<string, object?>>(payload["device"]);

        // Matches macOS emit_provenance's 'device': {'hw_uuid':..., 'computer_name':...}
        // and Windows' own UninstallProvenanceDevice {hw_uuid, computer_name} exactly.
        Assert.Equal(2, deviceObj.Count);
        Assert.Contains("hw_uuid", deviceObj.Keys);
        Assert.Contains("computer_name", deviceObj.Keys);
    }

    [Fact]
    public void BuildPayload_SerializedJson_CarriesDeviceHwUuidAtExpectedPath()
    {
        var poster = NewPoster(out _);
        var payload = poster.BuildPayload(NewAppEntry());

        // Mirrors ProvenancePoster.PostAsync's own serialization call exactly, so this
        // test exercises the actual bytes that would hit /v1/provenance.
        var json = JsonSerializer.Serialize(payload,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });

        using var doc = JsonDocument.Parse(json);
        var deviceEl = doc.RootElement.GetProperty("device");
        var hwUuid = deviceEl.GetProperty("hw_uuid").GetString();

        Assert.False(string.IsNullOrWhiteSpace(hwUuid));
    }
}
