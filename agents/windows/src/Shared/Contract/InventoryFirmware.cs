using System.Text.Json.Serialization;

namespace Patched.Shared.Contract;

/// <summary>
/// PAT-2262 (first slice of PAT-1863): the <c>firmware</c> block. What the device's own
/// firmware says it is: BIOS vendor, version, SMBIOS version and release date, plus the
/// system and baseboard identity strings SMBIOS carries beside them. Observation only.
/// Nothing here, and nothing on the platform built on it in this slice, says whether a
/// firmware version is current, outdated or vulnerable, so no field name implies it.
///
/// Platform-neutral in shape: <c>bios</c>, <c>system</c> and <c>baseboard</c> are the
/// SMBIOS structure names (types 0, 1 and 2), not Windows class names. macOS sends no
/// block in this slice; an agent older than PAT-2262 sends none either, and the platform
/// reports both as "not reported", which is a different claim from
/// <see cref="FirmwareCollectionStatus.Unavailable"/> (this agent tried and could not read).
///
/// ABSENCE REQUIRES AUTHORITY. <see cref="CollectionStatus"/> is
/// <see cref="FirmwareCollectionStatus.Unavailable"/> whenever no usable value was read,
/// including when every query succeeded and returned nothing, so an empty or failed
/// collection can never be stored as a complete, empty reading. An unavailable block
/// carries no sections at all. See <c>Patched.Shared.Firmware.FirmwareInventoryLogic</c>.
/// </summary>
internal sealed record InventoryFirmware
{
    /// <summary>The block's own contract version. Bumped only with the platform.</summary>
    public const int CurrentSchemaVersion = 1;

    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    /// <summary>One of the <see cref="FirmwareCollectionStatus"/> values.</summary>
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    /// <summary>
    /// Why the block is not complete: fixed codes from <see cref="FirmwareErrorCode"/>,
    /// never exception text or a firmware value. Empty when complete; at most
    /// <see cref="FirmwareErrorCode.MaxErrors"/> entries.
    /// </summary>
    [JsonPropertyName("errors")]
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>SMBIOS type 0. Null (omitted) only when the block is unavailable.</summary>
    [JsonPropertyName("bios")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public InventoryFirmwareBios? Bios { get; init; }

    /// <summary>SMBIOS type 1. Null (omitted) only when the block is unavailable.</summary>
    [JsonPropertyName("system")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public InventoryFirmwareSystem? System { get; init; }

    /// <summary>SMBIOS type 2. Null (omitted) only when the block is unavailable.</summary>
    [JsonPropertyName("baseboard")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public InventoryFirmwareBaseboard? Baseboard { get; init; }
}

/// <summary>
/// PAT-2262: the BIOS (SMBIOS type 0) section. Every value is optional: null means the
/// read succeeded and the firmware does not populate it, unless <see cref="CollectionStatus"/>
/// says the section is partial or unavailable, in which case a null may also be a value
/// that could not be read or was unusable. An unavailable section carries no values.
/// </summary>
internal sealed record InventoryFirmwareBios
{
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    /// <summary>Win32_BIOS.Manufacturer, the firmware vendor.</summary>
    [JsonPropertyName("manufacturer")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Manufacturer { get; init; }

    /// <summary>
    /// Win32_BIOS.SMBIOSBIOSVersion: the version string the firmware reports for itself
    /// (SMBIOS type 0 "BIOS Version"). Not Win32_BIOS.Version, which is the ACPI OEM
    /// table id and revision rather than the firmware version.
    /// </summary>
    [JsonPropertyName("version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Version { get; init; }

    /// <summary>"major.minor" from Win32_BIOS.SMBIOSMajorVersion and SMBIOSMinorVersion.</summary>
    [JsonPropertyName("smbios_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SmbiosVersion { get; init; }

    /// <summary>
    /// Win32_BIOS.ReleaseDate as a calendar date, <c>YYYY-MM-DD</c>: the date part of the
    /// CIM datetime as the firmware states it, with no time-zone conversion.
    /// </summary>
    [JsonPropertyName("release_date")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ReleaseDate { get; init; }

    /// <summary>
    /// The raw ReleaseDate string, sent only when it could not be parsed into
    /// <see cref="ReleaseDate"/> (the section is then partial), and only when it is
    /// itself a bounded, printable string.
    /// </summary>
    [JsonPropertyName("release_date_raw")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ReleaseDateRaw { get; init; }
}

/// <summary>PAT-2262: the system (SMBIOS type 1) section, from Win32_ComputerSystem.</summary>
internal sealed record InventoryFirmwareSystem
{
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    [JsonPropertyName("manufacturer")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Manufacturer { get; init; }

    [JsonPropertyName("model")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Model { get; init; }
}

/// <summary>PAT-2262: the baseboard (SMBIOS type 2) section, from Win32_BaseBoard.</summary>
internal sealed record InventoryFirmwareBaseboard
{
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    [JsonPropertyName("manufacturer")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Manufacturer { get; init; }

    [JsonPropertyName("product")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Product { get; init; }
}

/// <summary>
/// PAT-2262: firmware collection_status values, lowercase on the wire, for the block and
/// for each section. <see cref="Complete"/>: every property was read and every value
/// present was usable. <see cref="Partial"/>: at least one property could not be read,
/// or a value was unusable or unparseable; the values sent were read and are usable.
/// <see cref="Unavailable"/>: nothing usable was read (for the block, this includes
/// every query succeeding with no values).
/// </summary>
internal static class FirmwareCollectionStatus
{
    public const string Complete    = "complete";
    public const string Partial     = "partial";
    public const string Unavailable = "unavailable";
}

/// <summary>
/// PAT-2262: the closed set of <see cref="InventoryFirmware.Errors"/> codes. Fixed tokens
/// only, so the block can never carry exception text, a path or a firmware string.
/// </summary>
internal static class FirmwareErrorCode
{
    /// <summary>Wire bound on the errors array. The codes below number fewer than this.</summary>
    public const int MaxErrors = 16;

    /// <summary>Every property read of the section's WMI class failed.</summary>
    public const string BiosQueryFailed      = "bios_query_failed";
    public const string SystemQueryFailed    = "system_query_failed";
    public const string BaseboardQueryFailed = "baseboard_query_failed";

    /// <summary>At least one property read of the section failed, but not all.</summary>
    public const string BiosPropertyFailed      = "bios_property_failed";
    public const string SystemPropertyFailed    = "system_property_failed";
    public const string BaseboardPropertyFailed = "baseboard_property_failed";

    /// <summary>A value was read but was not usable: wrong type, too long or not printable.</summary>
    public const string BiosValueUnusable      = "bios_value_unusable";
    public const string SystemValueUnusable    = "system_value_unusable";
    public const string BaseboardValueUnusable = "baseboard_value_unusable";

    /// <summary>ReleaseDate was read but is not a CIM datetime with a real calendar date.</summary>
    public const string BiosReleaseDateUnparseable = "bios_release_date_unparseable";

    /// <summary>Every read succeeded or failed without yielding a single usable value.</summary>
    public const string NoFirmwareValues = "no_firmware_values";
}
