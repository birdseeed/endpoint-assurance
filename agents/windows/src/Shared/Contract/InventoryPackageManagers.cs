using System.Text.Json.Serialization;

namespace Patched.Shared.Contract;

/// <summary>
/// PAT-2018: the <c>package_managers</c> block. Every npm global package, pip user-site
/// package and pipx venv package installed for any local user profile, plus the npm global
/// packages in the machine-wide Node install, read from disk. Same shape, field for field,
/// as the macOS collector (macos/lib/package_managers.sh) so the platform ingest (PAT-2021)
/// needs one contract for both.
///
/// Not on the wire yet: <see cref="InventoryPayload.PackageManagers"/> is <c>[JsonIgnore]</c>
/// until PAT-2021 defines and consumes the block.
///
/// ABSENCE REQUIRES AUTHORITY (PAT-1710). <see cref="CollectionStatus"/>, each source's
/// status, each user's and each location's are one of <see cref="PackageCollectionStatus"/>'s
/// four values. A failed block omits <see cref="Packages"/> rather than sending <c>[]</c>. A
/// failed source inside a block that is not failed contributes no rows, and its own status
/// says so: a consumer reads "none" for a source only when that source is complete or
/// not_present. Nullable scalars are written as explicit JSON nulls
/// (<see cref="JsonIgnoreCondition.Never"/>) so both agents send the same keys.
/// </summary>
internal sealed record InventoryPackageManagers
{
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    [JsonPropertyName("truncated")]
    public bool Truncated { get; init; }

    /// <summary>time_limit, package_limit or user_limit; null unless truncated.</summary>
    [JsonPropertyName("truncation_reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? TruncationReason { get; init; }

    /// <summary>Always the three keys npm_global, pip_user and pipx.</summary>
    [JsonPropertyName("sources")]
    public IReadOnlyDictionary<string, PackageSourceSummary> Sources { get; init; } =
        new Dictionary<string, PackageSourceSummary>();

    [JsonPropertyName("users")]
    public IReadOnlyList<PackageUserRow> Users { get; init; } = Array.Empty<PackageUserRow>();

    [JsonPropertyName("locations")]
    public IReadOnlyList<PackageLocationRow> Locations { get; init; } = Array.Empty<PackageLocationRow>();

    [JsonPropertyName("issues")]
    public IReadOnlyList<PackageIssue> Issues { get; init; } = Array.Empty<PackageIssue>();

    /// <summary>Null (omitted) when <see cref="CollectionStatus"/> is failed.</summary>
    [JsonPropertyName("packages")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<InventoryPackage>? Packages { get; init; }
}

/// <summary>PAT-2018: collection_status values, identical on both agents.</summary>
internal static class PackageCollectionStatus
{
    public const string Complete   = "complete";
    public const string Partial    = "partial";
    public const string NotPresent = "not_present";
    public const string Failed     = "failed";
}

/// <summary>PAT-2018: the three sources, in wire order.</summary>
internal static class PackageSource
{
    public const string NpmGlobal = "npm_global";
    public const string PipUser   = "pip_user";
    public const string Pipx      = "pipx";

    public static readonly string[] All = [NpmGlobal, PipUser, Pipx];
}

internal sealed record PackageSourceSummary
{
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    [JsonPropertyName("truncated")]
    public bool Truncated { get; init; }

    [JsonPropertyName("package_count")]
    public int PackageCount { get; init; }

    [JsonPropertyName("location_count")]
    public int LocationCount { get; init; }
}

/// <summary>One local user profile that was looked at.</summary>
internal sealed record PackageUserRow
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

    /// <summary>This user's status for each of the three sources.</summary>
    [JsonPropertyName("sources")]
    public IReadOnlyDictionary<string, string> Sources { get; init; } = new Dictionary<string, string>();
}

/// <summary>One npm prefix, user site-packages directory or pipx venv that was read.</summary>
internal sealed record PackageLocationRow
{
    [JsonPropertyName("source")]
    public required string Source { get; init; }

    /// <summary>
    /// npm_global: system, homebrew (macOS), appdata (Windows), nvm, fnm or volta.
    /// pip_user: library_python or local_lib (macOS), appdata_python or microsoft_store (Windows).
    /// pipx: pipx.
    /// </summary>
    [JsonPropertyName("manager")]
    public required string Manager { get; init; }

    /// <summary>user, or system for a machine-wide prefix (which then has no user).</summary>
    [JsonPropertyName("scope")]
    public required string Scope { get; init; }

    [JsonPropertyName("user")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? User { get; init; }

    [JsonPropertyName("user_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? UserId { get; init; }

    /// <summary>The npm prefix, the site-packages directory, or the pipx venv.</summary>
    [JsonPropertyName("path")]
    public required string Path { get; init; }

    /// <summary>Node version (nvm, fnm, volta), Python X.Y (pip_user) or the venv's Python version (pipx).</summary>
    [JsonPropertyName("runtime_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? RuntimeVersion { get; init; }

    /// <summary>
    /// pip_user: every interpreter found on disk that would use this site (it is not recorded
    /// anywhere, so it is inferred). pipx: the venv's own interpreter from pyvenv.cfg, when it
    /// names one. npm_global: empty.
    /// </summary>
    [JsonPropertyName("interpreters")]
    public IReadOnlyList<string> Interpreters { get; init; } = Array.Empty<string>();

    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    [JsonPropertyName("package_count")]
    public int PackageCount { get; init; }
}

/// <summary>Why something was not read in full, or a link deliberately not followed. Capped at 50 per block.</summary>
internal sealed record PackageIssue
{
    [JsonPropertyName("code")]
    public required string Code { get; init; }

    [JsonPropertyName("path")]
    public required string Path { get; init; }
}

/// <summary>One installed package.</summary>
internal sealed record InventoryPackage
{
    [JsonPropertyName("source")]
    public required string Source { get; init; }

    [JsonPropertyName("manager")]
    public required string Manager { get; init; }

    [JsonPropertyName("scope")]
    public required string Scope { get; init; }

    [JsonPropertyName("user")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? User { get; init; }

    [JsonPropertyName("user_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? UserId { get; init; }

    /// <summary>
    /// npm: the package.json "name" (scoped packages as @scope/name). pip and pipx: the
    /// METADATA Name header. Null when the manifest could not be read.
    /// </summary>
    [JsonPropertyName("name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Name { get; init; }

    [JsonPropertyName("version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Version { get; init; }

    /// <summary>The location's path: npm prefix, site-packages directory or pipx venv.</summary>
    [JsonPropertyName("prefix")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Prefix { get; init; }

    [JsonPropertyName("runtime_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? RuntimeVersion { get; init; }

    /// <summary>The interpreter, only when exactly one is known for the location; else null.</summary>
    [JsonPropertyName("interpreter")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Interpreter { get; init; }

    /// <summary>npm: name or @scope/name under node_modules. pip and pipx: the .dist-info or .egg-info name.</summary>
    [JsonPropertyName("directory")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Directory { get; init; }

    /// <summary>read, missing, unreadable or unparseable.</summary>
    [JsonPropertyName("metadata_status")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? MetadataStatus { get; init; }

    /// <summary>pipx: the venv (application) name. Null for npm and pip_user.</summary>
    [JsonPropertyName("pipx_app")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? PipxApp { get; init; }

    /// <summary>pipx: true for the application's own package, false for a dependency. Null otherwise.</summary>
    [JsonPropertyName("pipx_main")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public bool? PipxMain { get; init; }
}
