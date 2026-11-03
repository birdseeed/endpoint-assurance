using System.Text.Json;
using System.Text.Json.Serialization;

namespace Patched.Shared.Contract;

/// <summary>
/// Canonical JSON serializer options for the update-status.json contract.
/// Used by the service (writer), the tray (reader), and tests.
/// Enums are serialized as snake_case strings (e.g. UpdatesAvailable → "updates_available").
/// </summary>
public static class ContractJsonOptions
{
    public static readonly JsonSerializerOptions Write = new()
    {
        WriteIndented          = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters             = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    public static readonly JsonSerializerOptions Read = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition      = JsonIgnoreCondition.WhenWritingNull,
        Converters                  = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };
}
