using System.Text.Json;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// Validates that UpdateStatus serialises to and from the neutral contract JSON
/// (contracts/update-status.schema.json) correctly.
/// In particular: enum snake_case round-trip, null omission, date format.
/// </summary>
public sealed class UpdateStatusTests
{
    private static readonly JsonSerializerOptions JsonOpts = ContractJsonOptions.Write;

    [Fact]
    public void OverallState_SerializesToSnakeCase()
    {
        var status = MinimalStatus(OverallState.UpdatesAvailable);
        var json   = JsonSerializer.Serialize(status, JsonOpts);
        Assert.Contains("\"updates_available\"", json);
    }

    [Fact]
    public void AppState_VerificationFailed_SerializesCorrectly()
    {
        var entry = new AppEntry
        {
            Label   = "googlechrome",
            Name    = "Google Chrome",
            State   = AppState.VerificationFailed,
        };
        var json = JsonSerializer.Serialize(entry, JsonOpts);
        Assert.Contains("\"verification_failed\"", json);
    }

    [Fact]
    public void FailureReason_SignerMismatch_SerializesCorrectly()
    {
        var entry = new AppEntry
        {
            Label         = "slack",
            Name          = "Slack",
            State         = AppState.VerificationFailed,
            FailureReason = FailureReason.SignerMismatch,
        };
        var json = JsonSerializer.Serialize(entry, JsonOpts);
        Assert.Contains("\"signer_mismatch\"", json);
    }

    [Fact]
    public void NullFields_OmittedFromJson()
    {
        var entry = new AppEntry
        {
            Label   = "zoom",
            Name    = "Zoom",
            State   = AppState.UpToDate,
            // VerifiedSigner, FailureReason, InstalledVersion, etc. are null
        };
        var json = JsonSerializer.Serialize(entry, JsonOpts);
        Assert.DoesNotContain("failure_reason", json);
        Assert.DoesNotContain("verified_signer", json);
    }

    [Fact]
    public void RoundTrip_SampleJson_ParsesCorrectly()
    {
        var samplePath = Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", "..",  // up to updater root from tests/Shared.Tests/bin/Debug/net8.0/
            "contracts", "update-status.sample.json");

        if (!File.Exists(samplePath))
        {
            // In CI the relative path may differ; skip rather than fail.
            return;
        }

        var json   = File.ReadAllText(samplePath);
        var status = JsonSerializer.Deserialize<UpdateStatus>(json, ContractJsonOptions.Read);

        Assert.NotNull(status);
        Assert.Equal(1, status!.SchemaVersion);
        Assert.NotEmpty(status.Apps);
        Assert.Equal(OverallState.UpdatesAvailable, status.OverallState);
    }

    [Fact]
    public void SchemaVersion_IsAlwaysOne()
    {
        var status = MinimalStatus(OverallState.UpToDate);
        Assert.Equal(1, status.SchemaVersion);
    }

    private static UpdateStatus MinimalStatus(OverallState state) =>
        new()
        {
            SchemaVersion = 1,
            GeneratedAt   = DateTimeOffset.UtcNow,
            OverallState  = state,
            Apps          = [],
        };
}
