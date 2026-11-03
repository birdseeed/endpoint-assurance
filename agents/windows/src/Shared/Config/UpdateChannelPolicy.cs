using System.Text.Json;

namespace Patched.Shared.Config;

/// <summary>Only the verified config path supplies authority; hardware UUIDs are never map keys.</summary>
public sealed record UpdateChannelPolicy(string Channel, string? Source, string? PinnedVersion, int? ConfigVersion)
{
    public static readonly UpdateChannelPolicy SafeDefault = new("stable", null, null, null);

    // Only a successfully resolved verified policy carries its config version.
    // SafeDefault is a reporting fallback, not permission to install stable.
    public bool HasAuthority => ConfigVersion.HasValue;

    public static UpdateChannelPolicy Resolve(AgentConfig config, string tenantId, string? canonicalDeviceId)
    {
        if (!config.UpdateAuthorityVerified || config.UpdateAuthorityShapeInvalid ||
            string.IsNullOrEmpty(tenantId) || config.TenantId != tenantId)
            return SafeDefault;
        string channel = config.UpdateChannel is "stable" or "beta" ? config.UpdateChannel : "stable";
        string? source = "tenant";
        bool ownId = Guid.TryParseExact(canonicalDeviceId, "D", out var own) && own != Guid.Empty;
        if (config.DeviceId is not null)
        {
            // A device-scoped response already projects P0 and override policy.
            // Missing source is unknown, never guessed from a beta channel.
            if (!ownId || !Guid.TryParseExact(config.DeviceId, "D", out var bound) || bound != own)
                return SafeDefault;
            source = config.UpdateChannelSource is "tenant" or "device_override" ? config.UpdateChannelSource : null;
            if (source == "device_override" && channel != "beta")
                return SafeDefault;
        }
        else if (ownId && config.DeviceChannelOverrides.ValueKind == JsonValueKind.Object)
        {
            // UUID case is not identity. Ambiguous duplicate own entries fail closed.
            var ownEntries = config.DeviceChannelOverrides.EnumerateObject().Where(p =>
                Guid.TryParseExact(p.Name, "D", out var candidate) && candidate == own).ToArray();
            if (ownEntries.Length == 1 && ownEntries[0].Value.ValueKind == JsonValueKind.String &&
                ownEntries[0].Value.GetString() == "beta")
            {
                channel = "beta";
                source = "device_override";
            }
        }
        string? pin = config.PinnedVersion is { Length: > 0 and <= 100 } value && !value.Contains('\0') ? value : null;
        return new(channel, source, pin, config.ConfigVersion);
    }
}
