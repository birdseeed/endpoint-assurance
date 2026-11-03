using System.Text.Json.Serialization;

namespace Patched.Shared.Contract;

/// <summary>
/// PAT-2020: the <c>mcp_servers</c> block. The MCP servers configured in the AI clients'
/// own config files for every local user (Claude Desktop, Cursor, VS Code, Windsurf, Claude
/// Code), reduced on the device to a server's name, transport, executable basename, package
/// and URL host. Same shape, field for field, as the macOS collector
/// (macos/lib/mcp_servers.sh) so the platform ingest (PAT-2021) needs one contract for both.
///
/// SECRETS NEVER ENTER THIS TYPE (Andy's decision, 2026-09-22). There is no field here for an
/// argument list, an env block, a header, a token or a URL path or query, and nothing in the
/// scan copies one: <see cref="McpServerRow"/> is the whole of what is kept for a server.
/// PAT-2021's server-side guard rejects an entry with any other field.
///
/// Not on the wire yet: <see cref="InventoryPayload.McpServers"/> is <c>[JsonIgnore]</c>
/// until PAT-2021 defines and consumes the block.
///
/// ABSENCE REQUIRES AUTHORITY (PAT-1710). <see cref="CollectionStatus"/>, each client's, each
/// user's and each config file's status are one of <see cref="PackageCollectionStatus"/>'s
/// four values. A failed block omits <see cref="Servers"/> rather than sending <c>[]</c>.
/// Nullable scalars are written as explicit JSON nulls so both agents send the same keys.
/// </summary>
internal sealed record InventoryMcpServers
{
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    [JsonPropertyName("truncated")]
    public bool Truncated { get; init; }

    /// <summary>time_limit, server_limit or user_limit; null unless truncated.</summary>
    [JsonPropertyName("truncation_reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? TruncationReason { get; init; }

    /// <summary>Always the five keys of <see cref="McpClient.All"/>.</summary>
    [JsonPropertyName("clients")]
    public IReadOnlyDictionary<string, McpClientSummary> Clients { get; init; } =
        new Dictionary<string, McpClientSummary>();

    [JsonPropertyName("totals")]
    public McpServerTotals Totals { get; init; } = new();

    [JsonPropertyName("users")]
    public IReadOnlyList<McpServerUserRow> Users { get; init; } = Array.Empty<McpServerUserRow>();

    [JsonPropertyName("configs")]
    public IReadOnlyList<McpConfigRow> Configs { get; init; } = Array.Empty<McpConfigRow>();

    /// <summary>Code and config file path, never a value from the file. Capped at 50.</summary>
    [JsonPropertyName("issues")]
    public IReadOnlyList<PackageIssue> Issues { get; init; } = Array.Empty<PackageIssue>();

    /// <summary>Null (omitted) when <see cref="CollectionStatus"/> is failed.</summary>
    [JsonPropertyName("servers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<McpServerRow>? Servers { get; init; }
}

/// <summary>PAT-2020: the five clients, in wire order.</summary>
internal static class McpClient
{
    public const string ClaudeDesktop = "claude_desktop";
    public const string Cursor        = "cursor";
    public const string VsCode        = "vscode";
    public const string Windsurf      = "windsurf";
    public const string ClaudeCode    = "claude_code";

    public static readonly string[] All = [ClaudeDesktop, Cursor, VsCode, Windsurf, ClaudeCode];
}

internal sealed record McpClientSummary
{
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    [JsonPropertyName("config_count")]
    public int ConfigCount { get; init; }

    [JsonPropertyName("server_count")]
    public int ServerCount { get; init; }
}

internal sealed record McpServerTotals
{
    [JsonPropertyName("config_count")]
    public int ConfigCount { get; init; }

    [JsonPropertyName("server_count")]
    public int ServerCount { get; init; }
}

/// <summary>One local user profile that was looked at.</summary>
internal sealed record McpServerUserRow
{
    /// <summary>Windows: DOMAIN\user (the SID when it cannot be resolved). macOS: the home directory name.</summary>
    [JsonPropertyName("user")]
    public required string User { get; init; }

    /// <summary>Windows: the profile SID. macOS: the home directory owner's uid, as a string.</summary>
    [JsonPropertyName("user_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? UserId { get; init; }

    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    /// <summary>This user's status for each of the five clients.</summary>
    [JsonPropertyName("clients")]
    public IReadOnlyDictionary<string, string> Clients { get; init; } = new Dictionary<string, string>();
}

/// <summary>One config file that exists and was opened (or failed to open).</summary>
internal sealed record McpConfigRow
{
    [JsonPropertyName("client")]
    public required string Client { get; init; }

    [JsonPropertyName("user")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? User { get; init; }

    [JsonPropertyName("user_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? UserId { get; init; }

    [JsonPropertyName("path")]
    public required string Path { get; init; }

    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    [JsonPropertyName("server_count")]
    public int ServerCount { get; init; }
}

/// <summary>
/// One configured MCP server: identity and shape only. Never its arguments, env, headers or
/// URL beyond the host.
/// </summary>
internal sealed record McpServerRow
{
    [JsonPropertyName("client")]
    public required string Client { get; init; }

    [JsonPropertyName("user")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? User { get; init; }

    [JsonPropertyName("user_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? UserId { get; init; }

    [JsonPropertyName("config_path")]
    public required string ConfigPath { get; init; }

    /// <summary>user, or project for a Claude Code local-scope server (the project directory is not sent).</summary>
    [JsonPropertyName("scope")]
    public required string Scope { get; init; }

    /// <summary>The server's key in the config; null when it is not safe text or is secret-shaped.</summary>
    [JsonPropertyName("name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Name { get; init; }

    /// <summary>stdio, http, sse or unknown.</summary>
    [JsonPropertyName("transport")]
    public required string Transport { get; init; }

    /// <summary>declared (the config's own type) or inferred (a command is stdio, a URL is http).</summary>
    [JsonPropertyName("transport_source")]
    public required string TransportSource { get; init; }

    /// <summary>The command's basename only (npx, uvx, npx.cmd, docker); null when not a plain name.</summary>
    [JsonPropertyName("executable")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Executable { get; init; }

    /// <summary>The package runner the command names (npx, npm, bunx, pnpx, pnpm, yarn, uvx, uv, pipx, docker, podman), or null.</summary>
    [JsonPropertyName("runner")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Runner { get; init; }

    /// <summary>The runner's package, only when it matched the strict npm, PyPI or public Docker image pattern.</summary>
    [JsonPropertyName("package")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Package { get; init; }

    /// <summary>extracted, unrecognised (a candidate was dropped), missing (no candidate) or not_applicable.</summary>
    [JsonPropertyName("package_status")]
    public required string PackageStatus { get; init; }

    /// <summary>An http, sse or other URL's host only: no scheme, userinfo, port, path or query.</summary>
    [JsonPropertyName("host")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Host { get; init; }
}
