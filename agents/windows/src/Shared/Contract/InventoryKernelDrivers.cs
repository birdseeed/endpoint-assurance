using System.Text.Json.Serialization;

namespace Patched.Shared.Contract;

/// <summary>
/// PAT-2263: the <c>kernel_drivers</c> block. Which kernel and file-system driver files are
/// installed or loaded on the device, identified by hash, and whether Windows is enforcing
/// the Microsoft vulnerable driver blocklist. It answers the evidence half of "is a known
/// vulnerable driver present, and is Windows blocking it" (bring your own vulnerable driver
/// attacks). The agent makes no vulnerability claim: the platform matches the hashes sent
/// here against Microsoft's recommended driver block rules and loldrivers.io, by hash only.
///
/// ABSENCE REQUIRES AUTHORITY. <see cref="CollectionStatus"/> describes the driver list
/// only. It is <see cref="KernelDriverCollectionStatus.Complete"/> only when every source
/// was read, every driver file found was hashed or is genuinely missing, and nothing was cut
/// by a bound. A file that could not be read is sent as an unhashed row with a reason, never
/// left out, and makes the list partial. An unavailable block carries no driver list at all.
///
/// <see cref="Enforcement"/> is always present: its values are independent reads with their
/// own "unknown", so an unreadable driver list does not hide the blocklist state.
///
/// Not collected in this slice: the Authenticode signer (WinVerifyTrust runs only inside the
/// killable helper boundary, which does not cover drivers) and WDAC page hashes (the
/// Microsoft list carries them, loldrivers.io does not, and the platform matches on the
/// whole-image Authenticode hashes both lists share).
/// </summary>
internal sealed record InventoryKernelDrivers
{
    /// <summary>The block's own contract version. Bumped only with the platform.</summary>
    public const int CurrentSchemaVersion = 1;

    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    /// <summary>One of the <see cref="KernelDriverCollectionStatus"/> values; describes <see cref="Drivers"/>.</summary>
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    /// <summary>
    /// Why the list is not complete: fixed codes from <see cref="KernelDriverErrorCode"/>, never
    /// exception text or a path. Empty when complete; at most
    /// <see cref="KernelDriverErrorCode.MaxErrors"/> entries.
    /// </summary>
    [JsonPropertyName("errors")]
    public IReadOnlyList<string> Errors { get; init; } = [];

    [JsonPropertyName("enforcement")]
    public required InventoryDriverEnforcement Enforcement { get; init; }

    /// <summary>Sorted by path. Null (omitted) only when the block is unavailable.</summary>
    [JsonPropertyName("drivers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<InventoryKernelDriver>? Drivers { get; init; }
}

/// <summary>
/// PAT-2263: what Windows is enforcing against vulnerable drivers. Each value is the reading
/// of one source; "unknown" is a read that failed or a value of the wrong type, never "off".
/// </summary>
internal sealed record InventoryDriverEnforcement
{
    /// <summary>
    /// HKLM\SYSTEM\CurrentControlSet\Control\CI\Config VulnerableDriverBlocklistEnable:
    /// 1 <c>enabled</c>, 0 <c>disabled</c>, key or value absent <c>not_set</c>, anything else
    /// or a failed read <c>unknown</c>. <c>not_set</c> is reported as read: this agent does
    /// not infer the Windows default from the build number.
    /// </summary>
    [JsonPropertyName("vulnerable_driver_blocklist")]
    public required string VulnerableDriverBlocklist { get; init; }

    /// <summary>
    /// Win32_DeviceGuard HypervisorEnforcedCodeIntegrityStatus, read once per cycle by the
    /// compliance collector: 2 <c>running</c>, 1 <c>configured</c> (enabled, not running),
    /// 0 <c>off</c>, else <c>unknown</c>.
    /// </summary>
    [JsonPropertyName("hvci")]
    public required string Hvci { get; init; }

    /// <summary>
    /// HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy VerifiedAndReputablePolicyState:
    /// 1 <c>on</c>, 2 <c>evaluation</c>, 0 <c>off</c>, absent <c>not_present</c> (a Windows
    /// build without Smart App Control), else <c>unknown</c>.
    /// </summary>
    [JsonPropertyName("smart_app_control")]
    public required string SmartAppControl { get; init; }

    /// <summary>
    /// Win32_DeviceGuard CodeIntegrityPolicyEnforcementStatus (kernel-mode code integrity
    /// policy, which covers App Control for Business / WDAC): 2 <c>enforced</c>, 1
    /// <c>audit</c>, 0 <c>off</c>, else <c>unknown</c>.
    /// </summary>
    [JsonPropertyName("code_integrity_policy")]
    public required string CodeIntegrityPolicy { get; init; }

    /// <summary>
    /// Whether the vulnerable driver blocklist is being enforced, from the values above only:
    /// <c>yes</c> when the blocklist is enabled, HVCI is running or Smart App Control is on
    /// (each of which forces it); <c>no</c> when the blocklist is disabled, HVCI is off or only
    /// configured, and Smart App Control is off or not present; otherwise <c>unknown</c>
    /// (including <c>not_set</c>, whose effect depends on the Windows build and is not
    /// inferred here, and Smart App Control in evaluation mode).
    /// </summary>
    [JsonPropertyName("blocklist_enforced")]
    public required string BlocklistEnforced { get; init; }
}

/// <summary>
/// PAT-2263: one driver file, deduplicated by path across the three sources. A row is never
/// dropped because its file could not be read: it is sent unhashed with the reason.
/// </summary>
internal sealed record InventoryKernelDriver
{
    /// <summary>
    /// The resolved absolute path. Null (omitted) only when a service's ImagePath could not
    /// be resolved to a local path (<see cref="KernelDriverUnhashedReason.PathUnsupported"/>);
    /// the row then carries its <see cref="ServiceName"/>.
    /// </summary>
    [JsonPropertyName("path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Path { get; init; }

    /// <summary>Where the row was seen: <see cref="KernelDriverSource"/> values, in that order.</summary>
    [JsonPropertyName("sources")]
    public required IReadOnlyList<string> Sources { get; init; }

    /// <summary>The Services subkey name, when a kernel or file-system driver service points here.</summary>
    [JsonPropertyName("service_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ServiceName { get; init; }

    /// <summary><c>kernel</c> (Type 1) or <c>file_system</c> (Type 2); set with <see cref="ServiceName"/>.</summary>
    [JsonPropertyName("service_type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ServiceType { get; init; }

    /// <summary><c>boot</c>, <c>system</c>, <c>auto</c>, <c>demand</c> or <c>disabled</c>; omitted when unreadable.</summary>
    [JsonPropertyName("start_type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? StartType { get; init; }

    /// <summary>
    /// True when the module list shows it loaded, false when the list was read and it is
    /// not there; omitted when the loaded-module list could not be read.
    /// </summary>
    [JsonPropertyName("loaded")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Loaded { get; init; }

    /// <summary><see cref="KernelDriverHashStatus"/>.</summary>
    [JsonPropertyName("hash_status")]
    public required string HashStatus { get; init; }

    /// <summary>Set only when unhashed: a <see cref="KernelDriverUnhashedReason"/> value.</summary>
    [JsonPropertyName("unhashed_reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UnhashedReason { get; init; }

    [JsonPropertyName("size_bytes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? SizeBytes { get; init; }

    /// <summary>Flat SHA-256 of the whole file, lowercase hex.</summary>
    [JsonPropertyName("sha256")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Sha256 { get; init; }

    /// <summary>Flat SHA-1 of the whole file, lowercase hex (for list entries that only carry SHA-1).</summary>
    [JsonPropertyName("sha1")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Sha1 { get; init; }

    /// <summary>
    /// Authenticode (PE image) SHA-256: the file with the checksum, the certificate table
    /// directory entry and the certificate table left out. Omitted when the file is not a PE
    /// whose headers hold together; the flat hashes are still sent.
    /// </summary>
    [JsonPropertyName("authenticode_sha256")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AuthenticodeSha256 { get; init; }

    [JsonPropertyName("authenticode_sha1")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AuthenticodeSha1 { get; init; }

    /// <summary>VS_FIXEDFILEINFO file version, a.b.c.d; omitted when the file has none.</summary>
    [JsonPropertyName("version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Version { get; init; }
}

/// <summary>PAT-2263: collection_status values, lowercase on the wire.</summary>
internal static class KernelDriverCollectionStatus
{
    public const string Complete    = "complete";
    public const string Partial     = "partial";
    public const string Unavailable = "unavailable";
}

/// <summary>PAT-2263: <see cref="InventoryKernelDriver.Sources"/> values, in wire order.</summary>
internal static class KernelDriverSource
{
    public const string DriversDirectory = "drivers_directory";
    public const string Service          = "service";
    public const string Loaded           = "loaded";
}

internal static class KernelDriverHashStatus
{
    public const string Hashed   = "hashed";
    public const string Unhashed = "unhashed";
}

/// <summary>PAT-2263: why a row carries no hashes. Fixed tokens.</summary>
internal static class KernelDriverUnhashedReason
{
    /// <summary>The file does not exist (a stale service entry). A fact, not a failure.</summary>
    public const string FileMissing     = "file_missing";
    /// <summary>The path or one of its directories is a reparse point; it was not followed.</summary>
    public const string ReparsePoint    = "reparse_point";
    /// <summary>A directory, device or other non-regular file.</summary>
    public const string NotRegularFile  = "not_regular_file";
    /// <summary>Opening or reading the file failed.</summary>
    public const string ReadFailed      = "read_failed";
    /// <summary>The file is larger than the per-file hashing cap.</summary>
    public const string SizeLimit       = "size_limit";
    /// <summary>The cycle's hashing time budget ran out first.</summary>
    public const string TimeBudget      = "time_budget";
    /// <summary>The cycle's hashing byte budget ran out first.</summary>
    public const string ByteBudget      = "byte_budget";
    /// <summary>The ImagePath is not a local drive-letter path this agent will open.</summary>
    public const string PathUnsupported = "path_unsupported";
}

/// <summary>PAT-2263: the closed set of <see cref="InventoryKernelDrivers.Errors"/> codes.</summary>
internal static class KernelDriverErrorCode
{
    public const int MaxErrors = 16;

    public const string DriversDirectoryUnreadable = "drivers_directory_unreadable";
    public const string DriversDirectoryEntryUnusable = "drivers_directory_entry_unusable";
    public const string ServicesUnreadable         = "services_unreadable";
    public const string ServiceEntryUnreadable     = "service_entry_unreadable";
    public const string ServiceValueUnusable       = "service_value_unusable";
    public const string LoadedModulesUnreadable    = "loaded_modules_unreadable";
    public const string LoadedPathUnresolved       = "loaded_path_unresolved";
    public const string DriverUnhashed             = "driver_unhashed";
    public const string DriverCountLimit           = "driver_count_limit";
    public const string BlockOverBudget            = "block_over_budget";
    public const string CollectionFailed           = "collection_failed";
}

/// <summary>
/// PAT-2263: the bounds on the block. Parity with <see cref="ToolingBlockBudget"/>: one
/// oversized block must not cost the device all of its inventory (the server truncates the
/// body at 6 MiB and the HMAC then fails).
/// </summary>
internal static class KernelDriverBudget
{
    /// <summary>Rows sent. A real Windows 11 device has 400 to 700; past this the list is partial.</summary>
    public const int MaxDrivers = 1500;

    /// <summary>About 1,500 rows at the ~600 bytes a hashed row takes.</summary>
    public const int MaxBlockBytes = 1024 * 1024;

    /// <summary>Per file. The largest inbox driver (a GPU driver) is about 100 MB.</summary>
    public const long MaxFileBytes = 160L * 1024 * 1024;

    /// <summary>Across the cycle.</summary>
    public const long MaxTotalBytes = 3L * 1024 * 1024 * 1024;

    /// <summary>Across the cycle. A device with 700 drivers hashes in a few seconds.</summary>
    public static readonly TimeSpan HashingTimeBudget = TimeSpan.FromSeconds(90);

    public const int MaxPathLength        = 512;
    public const int MaxServiceNameLength = 256;
}
