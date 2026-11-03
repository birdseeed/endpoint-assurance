using System.Text.Json.Serialization;

namespace Patched.Shared.Config;

/// <summary>
/// Proxy configuration block (PAT-278 parity).
/// Field order in the signed canonical payload is alphabetical — see
/// <see cref="Ed25519Verifier.CanonicalBytes"/>.
/// </summary>
public sealed record ProxyConfig
{
    /// <summary>"system" | "manual" | "off".</summary>
    [JsonPropertyName("mode")]
    public string Mode { get; init; } = "system";

    /// <summary>"http" | "socks5" | "https".</summary>
    [JsonPropertyName("type")]
    public string Type { get; init; } = "http";

    [JsonPropertyName("host")]
    public string Host { get; init; } = "";

    /// <summary>
    /// PAT-737: nullable — the platform sends "port": null when no manual proxy
    /// is configured (mode "system"/"off"); a non-nullable int made the whole
    /// agent-config document fail deserialization, silently rejecting every
    /// config update (including blocked_versions kill-switch entries).
    /// </summary>
    [JsonPropertyName("port")]
    public int? Port { get; init; }

    /// <summary>Credential Manager target name for proxy credentials, if any.</summary>
    [JsonPropertyName("auth_ref")]
    public string? AuthRef { get; init; }

    [JsonPropertyName("bypass_when_off_corp")]
    public bool BypassWhenOffCorp { get; init; }

    [JsonPropertyName("pac_url")]
    public string? PacUrl { get; init; }

    [JsonPropertyName("probe_url")]
    public string? ProbeUrl { get; init; }

    [JsonPropertyName("no_proxy")]
    public string[]? NoProxy { get; init; }
}
