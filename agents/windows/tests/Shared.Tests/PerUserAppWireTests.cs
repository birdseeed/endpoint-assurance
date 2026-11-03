using System.Text.Json;
using System.Text.Json.Serialization;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Shared.Tests;

// PAT-2075: exercise the shipping DTOs against the already-deployed platform
// contract. These tests deliberately compile before the optional fields exist;
// silently dropping scope is the defect, not a missing test-only API. Collector
// behaviour and InventoryPoster wiring require separate tests after the reader seam.
public sealed class PerUserAppWireTests
{
    private static readonly JsonSerializerOptions WireOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    private static JsonElement RoundTrip<T>(string json)
    {
        var value = JsonSerializer.Deserialize<T>(json, WireOptions);
        return JsonSerializer.SerializeToElement(value, WireOptions);
    }

    [Theory]
    [InlineData("LAB\\alice")]
    [InlineData("S-1-5-21-100-200-300-1001")]
    public void AppRowRetainsExactUserAccountAndUnchangedInstallationIdentifier(string account)
    {
        var input = JsonSerializer.Serialize(new
        {
            name = "Synthetic Editor", version = "1.2.3", identifier = "SyntheticEditor_is1",
            publisher = "Synthetic Publisher", architecture = "x86_64", user_account = account,
        });
        var row = RoundTrip<InventoryApp>(input);
        Assert.Equal("SyntheticEditor_is1", row.GetProperty("identifier").GetString());
        Assert.Equal("1.2.3", row.GetProperty("version").GetString());
        Assert.True(row.TryGetProperty("user_account", out var owner),
            "Shipping InventoryApp dropped user_account, turning a per-user install into a machine-wide assertion.");
        Assert.Equal(account, owner.GetString());
    }

    [Theory]
    [InlineData("complete")]
    [InlineData("partial")]
    [InlineData("unavailable")]
    public void PerUserAuthoritySurvivesSerializationWithoutChangingMachineAuthority(string state)
    {
        var input = JsonSerializer.Serialize(new
        {
            certificates = "unavailable", apps = "complete",
            apps_users = new[] { new { user_account = "LAB\\alice", collection_status = state } },
        });
        var status = RoundTrip<InventoryCollectionStatus>(input);
        Assert.Equal("complete", status.GetProperty("apps").GetString());
        Assert.True(status.TryGetProperty("apps_users", out var users),
            "Shipping InventoryCollectionStatus dropped apps_users, so no same-user report can authoritatively prune.");
        var user = Assert.Single(users.EnumerateArray());
        Assert.Equal(new[] { "collection_status", "user_account" },
            user.EnumerateObject().Select(p => p.Name).OrderBy(n => n).ToArray());
        Assert.Equal("LAB\\alice", user.GetProperty("user_account").GetString());
        Assert.Equal(state, user.GetProperty("collection_status").GetString());
    }

    [Fact]
    public void LegacyMachineRowDoesNotAcquireAnOwner()
    {
        var row = RoundTrip<InventoryApp>("""
            {"name":"Synthetic Editor","version":"1.2.3","identifier":"SyntheticEditor_is1"}
            """);
        Assert.False(row.TryGetProperty("user_account", out var owner) &&
                     owner.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(owner.GetString()));
    }

    [Fact]
    public void LoggedOffUserIsNotInventedBySerialization()
    {
        var status = RoundTrip<InventoryCollectionStatus>("""
            {"certificates":"unavailable","apps":"complete"}
            """);
        Assert.False(status.TryGetProperty("apps_users", out var users) &&
                     users.ValueKind == JsonValueKind.Array && users.GetArrayLength() != 0);
    }
}
