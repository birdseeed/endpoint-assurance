using System.Text.Json.Serialization;

namespace Patched.Shared.Contract;

/// <summary>
/// PAT-2017: the <c>ide_extensions</c> block. Every VS Code, VS Code Insiders, Cursor and
/// Windsurf extension and every JetBrains plugin installed in any local user profile, read
/// from disk. Same shape, field for field, as the macOS collector (macos/lib/ide_extensions.sh)
/// so the platform ingest (PAT-2021) needs one contract for both.
///
/// Not on the wire yet: <see cref="InventoryPayload.IdeExtensions"/> is <c>[JsonIgnore]</c>
/// until PAT-2021 defines and consumes the block.
///
/// ABSENCE REQUIRES AUTHORITY (PAT-1710). <see cref="CollectionStatus"/> is one of
/// <see cref="IdeCollectionStatus"/>'s four values. A failed block omits
/// <see cref="Extensions"/> rather than sending <c>[]</c>, so a failed read can never look
/// like "no extensions". Nullable scalars are written as explicit JSON nulls
/// (<see cref="JsonIgnoreCondition.Never"/>) so both agents send the same keys.
/// </summary>
internal sealed record InventoryIdeExtensions
{
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    [JsonPropertyName("truncated")]
    public bool Truncated { get; init; }

    [JsonPropertyName("truncation_reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? TruncationReason { get; init; }

    [JsonPropertyName("users")]
    public IReadOnlyList<IdeUserRow> Users { get; init; } = Array.Empty<IdeUserRow>();

    [JsonPropertyName("profiles")]
    public IReadOnlyList<IdeProfileRow> Profiles { get; init; } = Array.Empty<IdeProfileRow>();

    [JsonPropertyName("issues")]
    public IReadOnlyList<IdeIssue> Issues { get; init; } = Array.Empty<IdeIssue>();

    /// <summary>Null (omitted) when <see cref="CollectionStatus"/> is failed.</summary>
    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<InventoryIdeExtension>? Extensions { get; init; }
}

/// <summary>PAT-2017: collection_status values, identical on both agents.</summary>
internal static class IdeCollectionStatus
{
    public const string Complete   = "complete";
    public const string Partial    = "partial";
    public const string NotPresent = "not_present";
    public const string Failed     = "failed";
}

/// <summary>One local user profile that was looked at.</summary>
internal sealed record IdeUserRow
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

    /// <summary>How many editor profiles were found for this user.</summary>
    [JsonPropertyName("profiles")]
    public int Profiles { get; init; }
}

/// <summary>One editor installation's extension store for one user.</summary>
internal sealed record IdeProfileRow
{
    [JsonPropertyName("user")]
    public required string User { get; init; }

    [JsonPropertyName("user_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? UserId { get; init; }

    /// <summary>"vscode" (VS Code and its forks) or "jetbrains".</summary>
    [JsonPropertyName("family")]
    public required string Family { get; init; }

    /// <summary>vscode, vscode_insiders, cursor, windsurf, or the JetBrains product directory prefix (IntelliJIdea, PyCharm, ...).</summary>
    [JsonPropertyName("editor")]
    public required string Editor { get; init; }

    /// <summary>JetBrains product version from the directory name (2025.2); null for the VS Code family.</summary>
    [JsonPropertyName("editor_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? EditorVersion { get; init; }

    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    /// <summary>extensions_json, package_json or plugin_xml; null when nothing was read.</summary>
    [JsonPropertyName("manifest_source")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? ManifestSource { get; init; }

    [JsonPropertyName("extension_count")]
    public int ExtensionCount { get; init; }
}

/// <summary>Why something was not read in full. Capped at 50 per block.</summary>
internal sealed record IdeIssue
{
    [JsonPropertyName("code")]
    public required string Code { get; init; }

    [JsonPropertyName("path")]
    public required string Path { get; init; }
}

/// <summary>One installed extension or plugin.</summary>
internal sealed record InventoryIdeExtension
{
    [JsonPropertyName("user")]
    public required string User { get; init; }

    [JsonPropertyName("user_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? UserId { get; init; }

    [JsonPropertyName("family")]
    public required string Family { get; init; }

    [JsonPropertyName("editor")]
    public required string Editor { get; init; }

    [JsonPropertyName("editor_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? EditorVersion { get; init; }

    /// <summary>
    /// VS Code family: publisher.name, lowercased (the marketplace id is case-insensitive).
    /// JetBrains: the plugin.xml &lt;id&gt;, or &lt;name&gt; when there is no &lt;id&gt;, as
    /// JetBrains itself does. Null when the manifest could not be read.
    /// </summary>
    [JsonPropertyName("id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Id { get; init; }

    [JsonPropertyName("name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Name { get; init; }

    /// <summary>VS Code family: the publisher id. JetBrains: the &lt;vendor&gt; text.</summary>
    [JsonPropertyName("publisher")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Publisher { get; init; }

    [JsonPropertyName("publisher_display_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? PublisherDisplayName { get; init; }

    [JsonPropertyName("version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Version { get; init; }

    /// <summary>UTC, second precision, from the editor's own install timestamp. VS Code family only.</summary>
    [JsonPropertyName("installed_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? InstalledAt { get; init; }

    /// <summary>VS Code family: gallery, vsix or resource, as the editor recorded it.</summary>
    [JsonPropertyName("source")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Source { get; init; }

    [JsonPropertyName("pre_release")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public bool? PreRelease { get; init; }

    [JsonPropertyName("target_platform")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? TargetPlatform { get; init; }

    /// <summary>JetBrains: listed in disabled_plugins.txt. Null when that could not be read, and for the VS Code family.</summary>
    [JsonPropertyName("disabled")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public bool? Disabled { get; init; }

    /// <summary>The extension folder or plugin folder/jar name, relative to the extensions or plugins directory.</summary>
    [JsonPropertyName("directory")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Directory { get; init; }

    /// <summary>extensions_json, package_json, plugin_xml_jar, plugin_xml_unpacked or directory_name.</summary>
    [JsonPropertyName("manifest_source")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? ManifestSource { get; init; }

    /// <summary>read, missing, unreadable or unparseable.</summary>
    [JsonPropertyName("manifest_status")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? ManifestStatus { get; init; }
}
