using System.Text.Json.Serialization;

namespace Patched.Shared.Contract;

/// <summary>
/// PAT-2019: the <c>local_models</c> block. Local model runtimes (Ollama, LM Studio,
/// llama.cpp) found in their default install locations, and the models in their default
/// stores for every local user: names, tags and sizes only. Same shape, field for field, as
/// the macOS collector (macos/lib/local_models.sh) so the platform ingest (PAT-2021) needs one
/// contract for both.
///
/// Not on the wire yet: <see cref="InventoryPayload.LocalModels"/> is <c>[JsonIgnore]</c>
/// until PAT-2021 defines and consumes the block.
///
/// ABSENCE REQUIRES AUTHORITY (PAT-1710). <see cref="CollectionStatus"/>, each runtime's,
/// each user's and each store's status are one of <see cref="PackageCollectionStatus"/>'s four
/// values. A failed block omits <see cref="Models"/> rather than sending <c>[]</c>. Nullable
/// scalars are written as explicit JSON nulls so both agents send the same keys.
/// </summary>
internal sealed record InventoryLocalModels
{
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    [JsonPropertyName("truncated")]
    public bool Truncated { get; init; }

    /// <summary>time_limit, model_limit or user_limit; null unless truncated.</summary>
    [JsonPropertyName("truncation_reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? TruncationReason { get; init; }

    /// <summary>Always the three keys ollama, lm_studio and llama_cpp.</summary>
    [JsonPropertyName("runtimes")]
    public IReadOnlyDictionary<string, LocalRuntimeSummary> Runtimes { get; init; } =
        new Dictionary<string, LocalRuntimeSummary>();

    [JsonPropertyName("totals")]
    public LocalModelTotals Totals { get; init; } = new();

    [JsonPropertyName("users")]
    public IReadOnlyList<LocalModelUserRow> Users { get; init; } = Array.Empty<LocalModelUserRow>();

    [JsonPropertyName("installations")]
    public IReadOnlyList<LocalRuntimeInstallation> Installations { get; init; } = Array.Empty<LocalRuntimeInstallation>();

    [JsonPropertyName("stores")]
    public IReadOnlyList<LocalModelStore> Stores { get; init; } = Array.Empty<LocalModelStore>();

    /// <summary>Same shape as the package_managers issues: code and path. Capped at 50.</summary>
    [JsonPropertyName("issues")]
    public IReadOnlyList<PackageIssue> Issues { get; init; } = Array.Empty<PackageIssue>();

    /// <summary>Null (omitted) when <see cref="CollectionStatus"/> is failed.</summary>
    [JsonPropertyName("models")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<InventoryLocalModel>? Models { get; init; }
}

/// <summary>PAT-2019: the three runtimes, in wire order.</summary>
internal static class LocalModelRuntime
{
    public const string Ollama   = "ollama";
    public const string LmStudio = "lm_studio";
    public const string LlamaCpp = "llama_cpp";

    public static readonly string[] All = [Ollama, LmStudio, LlamaCpp];
}

internal sealed record LocalRuntimeSummary
{
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    [JsonPropertyName("installation_count")]
    public int InstallationCount { get; init; }

    [JsonPropertyName("store_count")]
    public int StoreCount { get; init; }

    [JsonPropertyName("model_count")]
    public int ModelCount { get; init; }

    [JsonPropertyName("total_bytes")]
    public long TotalBytes { get; init; }
}

internal sealed record LocalModelTotals
{
    [JsonPropertyName("model_count")]
    public int ModelCount { get; init; }

    /// <summary>Sum of every store's total_bytes: what the models occupy on disk.</summary>
    [JsonPropertyName("total_bytes")]
    public long TotalBytes { get; init; }
}

/// <summary>One local user profile that was looked at.</summary>
internal sealed record LocalModelUserRow
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

    /// <summary>This user's status for each of the three runtimes.</summary>
    [JsonPropertyName("runtimes")]
    public IReadOnlyDictionary<string, string> Runtimes { get; init; } = new Dictionary<string, string>();
}

/// <summary>One runtime installation found on disk.</summary>
internal sealed record LocalRuntimeInstallation
{
    [JsonPropertyName("runtime")]
    public required string Runtime { get; init; }

    /// <summary>system (machine-wide) or user.</summary>
    [JsonPropertyName("scope")]
    public required string Scope { get; init; }

    [JsonPropertyName("user")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? User { get; init; }

    [JsonPropertyName("user_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? UserId { get; init; }

    /// <summary>
    /// macOS: app_bundle, homebrew_formula or binary. Windows: program_files (Program Files),
    /// local_programs (AppData\Local\Programs), winget_portable or scoop.
    /// </summary>
    [JsonPropertyName("kind")]
    public required string Kind { get; init; }

    [JsonPropertyName("path")]
    public required string Path { get; init; }

    [JsonPropertyName("version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Version { get; init; }

    /// <summary>
    /// Where the version came from: info_plist, homebrew_keg, pe_version_resource,
    /// scoop_version_dir, or none (no version could be read without running the binary).
    /// </summary>
    [JsonPropertyName("version_source")]
    public required string VersionSource { get; init; }

    /// <summary>macOS: CFBundleIdentifier of an app bundle. Null otherwise.</summary>
    [JsonPropertyName("identifier")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Identifier { get; init; }
}

/// <summary>One model store directory that was read.</summary>
internal sealed record LocalModelStore
{
    [JsonPropertyName("runtime")]
    public required string Runtime { get; init; }

    [JsonPropertyName("scope")]
    public required string Scope { get; init; }

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

    [JsonPropertyName("model_count")]
    public int ModelCount { get; init; }

    /// <summary>
    /// Bytes on disk: Ollama, the blobs present that the manifests reference, each once;
    /// LM Studio, the sizes of the model files. From a stat, never a read.
    /// </summary>
    [JsonPropertyName("total_bytes")]
    public long TotalBytes { get; init; }
}

/// <summary>One model: its name, tag and size. Nothing of its content.</summary>
internal sealed record InventoryLocalModel
{
    [JsonPropertyName("runtime")]
    public required string Runtime { get; init; }

    [JsonPropertyName("user")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? User { get; init; }

    [JsonPropertyName("user_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? UserId { get; init; }

    [JsonPropertyName("store_path")]
    public required string StorePath { get; init; }

    /// <summary>
    /// Ollama: the model (library models bare, e.g. qwen3; other namespaces ns/model; other
    /// registries host/ns/model). LM Studio: publisher/repo.
    /// </summary>
    [JsonPropertyName("name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Name { get; init; }

    /// <summary>Ollama: the tag. LM Studio: the GGUF file name without .gguf; null for a whole-repo model.</summary>
    [JsonPropertyName("tag")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Tag { get; init; }

    /// <summary>LM Studio: gguf, safetensors or other. Ollama: null (the blob is never opened).</summary>
    [JsonPropertyName("format")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Format { get; init; }

    /// <summary>Ollama: the manifest's declared size. LM Studio: the file sizes. Null when unknown.</summary>
    [JsonPropertyName("size_bytes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public long? SizeBytes { get; init; }

    [JsonPropertyName("file_count")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public int? FileCount { get; init; }

    /// <summary>manifest or stat; null when no size was read.</summary>
    [JsonPropertyName("size_source")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? SizeSource { get; init; }

    /// <summary>Ollama: referenced blobs not on disk (null when the blobs were not looked at). LM Studio: null.</summary>
    [JsonPropertyName("missing_blobs")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public int? MissingBlobs { get; init; }

    /// <summary>Ollama: read, missing, unreadable or unparseable for the manifest. LM Studio: null.</summary>
    [JsonPropertyName("metadata_status")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? MetadataStatus { get; init; }
}
