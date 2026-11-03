using System.Text.Json.Serialization;

namespace Patched.Shared.Contract;

/// <summary>
/// Schema v3 inventory payload for POST /v1/inventory.
/// Cross-platform envelope documented in go-service/docs/PAYLOAD_SCHEMA.md.
/// macOS-only sections (system_extensions, background_items, icloud) are omitted for Windows.
/// </summary>
internal sealed record InventoryPayload
{
    [JsonPropertyName("installation_evidence")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public InstallationEvidenceSummary? InstallationEvidence { get; init; }
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; } = 3;

    [JsonPropertyName("platform")]
    public string Platform { get; init; } = "windows";

    [JsonPropertyName("agent")]
    public required string Agent { get; init; }

    [JsonPropertyName("agent_version")]
    public required string AgentVersion { get; init; }

    [JsonPropertyName("tenant_id")]
    public required string TenantId { get; init; }

    [JsonPropertyName("collected_at")]
    public required string CollectedAt { get; init; }

    [JsonPropertyName("device")]
    public required InventoryDevice Device { get; init; }

    [JsonPropertyName("hardware")]
    public required InventoryHardware Hardware { get; init; }

    [JsonPropertyName("os")]
    public required InventoryOs Os { get; init; }

    /// <summary>
    /// PAT-1833: the OS-update verdict already computed once per worker cycle by
    /// OsUpdateChecker/OsUpdateStateEngine. Null means no verdict was available
    /// and omits the whole key; no inventory path invents a replacement.
    /// </summary>
    [JsonPropertyName("os_update")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OsUpdateInfo? OsUpdate { get; init; }

    /// <summary>
    /// PAT-1959: what class of machine this is — "workstation", "server",
    /// "domain_controller" or "unknown" (Patched.Shared.DeviceClassification.
    /// DeviceClassValue). Additive and optional, so schema_version stays 3, the same
    /// precedent as browser_extensions (PAT-827) and compliance_assessments (PAT-913);
    /// agent_version carries the version signal. An agent older than 0.15.0 omits the
    /// key, macOS omits it too, and both read server-side exactly as "unknown": score
    /// the device the way it was scored before device class existed.
    ///
    /// Platform-neutral by construction. Nothing about the field is Windows-shaped: it
    /// is a flat device attribute with a closed vocabulary, not a Windows object, and a
    /// macOS or Linux agent that gains a way to tell a server from a laptop can fill the
    /// same key with the same four words.
    ///
    /// Never a guess. A source that is missing, unreadable or says something
    /// unrecognised produces "unknown" here; see DeviceClassResolver for each rule and
    /// why refusing beats inferring when the server treats "unknown" as "score it the
    /// old way".
    /// </summary>
    [JsonPropertyName("device_class")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DeviceClass { get; init; }

    /// <summary>
    /// PAT-1959: the OS installation type as the platform reports it — on Windows one of
    /// "Client", "Server" or "Server Core", read from
    /// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallationType. Omitted
    /// entirely when the read was absent or failed, or when the value is not one of the
    /// documented three; an undocumented string is never mapped onto one of them, and an
    /// absent reading never becomes "Client".
    /// </summary>
    [JsonPropertyName("installation_type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? InstallationType { get; init; }

    /// <summary>
    /// PAT-1959: the operating system's own product caption, for an operator to read
    /// alongside the class — e.g. "Microsoft Windows Server 2022 Standard". Free text,
    /// localised, and deliberately never parsed into a class: build numbers and captions
    /// both fail to separate a server from a workstation (Server 2019 and Windows 10
    /// 1809 LTSC are both build 17763). Omitted when unreadable or unusable.
    /// </summary>
    [JsonPropertyName("os_caption")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? OsCaption { get; init; }

    [JsonPropertyName("compliance")]
    public required Dictionary<string, object> Compliance { get; init; }

    /// <summary>
    /// PAT-743: configuration/CIS advisory findings — same shape as the local
    /// tray contract's ComplianceFinding/ComplianceFindingVolume (UpdateStatus.cs).
    /// Violations only: an element is present ONLY when a control is genuinely
    /// violated, so this carries Fail state, never Pass. A clean control is
    /// reported by its ABSENCE here. Always present as an empty array (never
    /// omitted/null) when clean.
    /// </summary>
    [JsonPropertyName("compliance_findings")]
    public required IReadOnlyList<ComplianceFinding> ComplianceFindings { get; init; }

    /// <summary>
    /// PAT-913 (Option B): positive per-control attestation. controls_assessed
    /// lists the finding-controls this run actually ran a determination for and is
    /// the sole source of a Pass server-side (Pass iff a control is in
    /// controls_assessed AND absent from compliance_findings). An erroring
    /// sub-check drops its control from the list, so the server scores it Unknown,
    /// which for the critical disk-encryption rule fails (go-service migration
    /// 0083, treat_unknown_as='fail'). Always present for platform parity with the
    /// macOS collector; an empty controls_assessed attests nothing (same score as
    /// the section being absent, as on pre-PAT-913 agents).
    /// </summary>
    [JsonPropertyName("compliance_assessments")]
    public required ComplianceAssessments ComplianceAssessments { get; init; }

    [JsonPropertyName("security_tools")]
    public required IReadOnlyList<InventorySecurityTool> SecurityTools { get; init; }

    [JsonPropertyName("apps")]
    public required IReadOnlyList<InventoryApp> Apps { get; init; }

    /// <summary>
    /// Software-metering provenance (PAT-380): "ok" | "no_user_session" |
    /// "userassist_unavailable". Describes the source, never proves an app is unused.
    /// </summary>
    [JsonPropertyName("metering_status")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? MeteringStatus { get; init; }

    [JsonPropertyName("metering_user_hive_count")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? MeteringUserHiveCount { get; init; }

    [JsonPropertyName("metering_record_count")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? MeteringRecordCount { get; init; }

    /// <summary>
    /// PAT-641: machine-level x509 certificates from LocalMachine\My.
    /// Mirrors the macOS shape (PAT-216/220); ingested into device_certificates server-side.
    /// PAT-1732: null (key omitted) when the store could not be read, or when it was read
    /// but no certificate in it could be; an empty array only when the store was read
    /// and holds no customer-installed certs. Qualified by
    /// <see cref="CollectionStatus"/>.Certificates. Set both from one
    /// <c>CertCollectionResult</c>.
    /// </summary>
    [JsonPropertyName("certificates")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public required IReadOnlyList<InventoryCert>? Certificates { get; init; }

    /// <summary>
    /// PAT-1732: top-level collection_status. Required so no code path can omit it: an
    /// absent object reads as "complete" server-side. Mirrors the macOS payload.
    /// </summary>
    [JsonPropertyName("collection_status")]
    public required InventoryCollectionStatus CollectionStatus { get; init; }

    /// <summary>
    /// PAT-1974: the standing local administrator roster behind the
    /// <c>local_admin_count</c> compliance signal. The count stays a scalar in the flat
    /// compliance bag; the account names are structured data, so they live here with
    /// their own collection status, exactly as certificates and hardware_health do.
    /// Required so no code path can omit it, and always present on both platforms —
    /// macOS emits the identical object from <c>local_admins_payload</c> in
    /// macos/lib/auth.sh.
    /// </summary>
    [JsonPropertyName("local_admins")]
    public required InventoryLocalAdmins LocalAdmins { get; init; }

    /// <summary>
    /// PAT-685: hardware health — battery, storage volumes, physical-disk SMART status.
    /// Mirrors the macOS hardware_health section; absent when collection fails entirely
    /// (non-fatal — does not break the wider inventory run).
    /// </summary>
    [JsonPropertyName("hardware_health")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public InventoryHardwareHealth? HardwareHealth { get; init; }

    /// <summary>
    /// PAT-2262: BIOS, system and baseboard identity as the firmware reports it. See
    /// <see cref="InventoryFirmware"/>. Additive and optional on the wire, so
    /// schema_version stays 3; InventoryPoster always sets it, sending an unavailable
    /// block rather than omitting it when nothing could be read, because the platform
    /// reads an absent key as "not reported" (an agent that predates the block).
    /// </summary>
    [JsonPropertyName("firmware")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public InventoryFirmware? Firmware { get; init; }

    /// <summary>
    /// PAT-2263: installed and loaded kernel and file-system drivers, identified by hash, and
    /// the vulnerable driver blocklist enforcement state. See <see cref="InventoryKernelDrivers"/>.
    /// Additive and optional on the wire, so schema_version stays 3; InventoryPoster always
    /// sets it, sending an unavailable block rather than omitting it when the driver list
    /// could not be read, because the platform reads an absent key as "not reported".
    /// </summary>
    [JsonPropertyName("kernel_drivers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public InventoryKernelDrivers? KernelDrivers { get; init; }

    /// <summary>
    /// PAT-680: backup status — File History, OneDrive sync, and third-party tools
    /// (Acronis/Veeam/Backup Exec). Mirrors the macOS backup_status shape (PAT-679);
    /// always present, same as macOS, rather than optional like hardware_health.
    /// </summary>
    [JsonPropertyName("backup_status")]
    public required InventoryBackupStatus BackupStatus { get; init; }

    /// <summary>
    /// PAT-827: per-user, per-profile browser extension inventory for Chrome, Edge,
    /// and Firefox. Mirrors the macOS shape emitted by macos/lib/browser_extensions.sh
    /// (PAT-125); always present (empty array, never omitted), same as macOS. Field
    /// names must match exactly — the go-service extractor ingests both platforms into
    /// device_browser_extensions (migration 0018) with no server change.
    /// </summary>
    [JsonPropertyName("browser_extensions")]
    public required IReadOnlyList<InventoryBrowserExtension> BrowserExtensions { get; init; }

    /// <summary>
    /// PAT-2065 (agent half of PAT-2055): whether <see cref="BrowserExtensions"/> is complete,
    /// per user and browser, and whether the collector reached its row cap. A sibling key: the
    /// array above is unchanged. Required, so every run sends it; a collector that could not
    /// read sends {"collection_status":"failed"}, which grants the platform no absence authority.
    /// macOS sends the same block (macos/lib/browser_extensions.sh).
    /// </summary>
    [JsonPropertyName("browser_extensions_status")]
    public required InventoryBrowserExtensionsStatus BrowserExtensionsStatus { get; init; }

    /// <summary>
    /// PAT-2017: IDE extensions and plugins (VS Code, VS Code Insiders, Cursor, Windsurf,
    /// JetBrains) for every local user profile. See <see cref="InventoryIdeExtensions"/>.
    /// </summary>
    // ON THE WIRE since PAT-2225 (2026-09-28): the platform (PAT-2021) validates and ingests
    // the block. InventoryPoster sends it only within ToolingBlockBudget.IdeExtensionsMaxBytes
    // and sends the failed block past it. Payload_IdeExtensions_IsOnTheWire pins this; macOS
    // holds the same line with _IDE_EXTENSIONS_PAYLOAD_ON_WIRE=1 in
    // macos/lib/ide_extensions.sh.
    [JsonPropertyName("ide_extensions")]
    public InventoryIdeExtensions? IdeExtensions { get; init; }

    /// <summary>
    /// PAT-2018: npm global, pip user-site and pipx packages for every local user profile, plus
    /// the machine-wide Node install's globals. See <see cref="InventoryPackageManagers"/>.
    /// </summary>
    // ON THE WIRE since PAT-2225 (2026-09-28): the platform (PAT-2021) validates and ingests
    // the block. InventoryPoster sends it only within ToolingBlockBudget.PackageManagersMaxBytes
    // and sends the failed block past it. Payload_PackageManagers_IsOnTheWire pins this; macOS
    // holds the same line with _PACKAGE_MANAGERS_PAYLOAD_ON_WIRE=1 in macos/lib/package_managers.sh.
    [JsonPropertyName("package_managers")]
    public InventoryPackageManagers? PackageManagers { get; init; }

    /// <summary>
    /// PAT-2019: local model runtimes (Ollama, LM Studio, llama.cpp) and the models in their
    /// default stores, names and sizes only. See <see cref="InventoryLocalModels"/>.
    /// </summary>
    // ON THE WIRE since PAT-2225 (2026-09-28): the platform (PAT-2021) validates and ingests
    // the block. InventoryPoster sends it only within ToolingBlockBudget.LocalModelsMaxBytes
    // and sends the failed block past it. Payload_LocalModels_IsOnTheWire pins this; macOS
    // holds the same line with _LOCAL_MODELS_PAYLOAD_ON_WIRE=1 in macos/lib/local_models.sh.
    [JsonPropertyName("local_models")]
    public InventoryLocalModels? LocalModels { get; init; }

    /// <summary>
    /// PAT-2020: MCP servers configured in the AI clients' config files, reduced on the device
    /// to name, transport, executable, package and URL host. See <see cref="InventoryMcpServers"/>.
    /// </summary>
    // ON THE WIRE since PAT-2225 (2026-09-28): the platform (PAT-2021) validates and ingests
    // the block. InventoryPoster sends it only within ToolingBlockBudget.McpServersMaxBytes
    // and sends the failed block past it. Payload_McpServers_IsOnTheWire pins this; macOS
    // holds the same line with _MCP_SERVERS_PAYLOAD_ON_WIRE=1 in macos/lib/mcp_servers.sh.
    [JsonPropertyName("mcp_servers")]
    public InventoryMcpServers? McpServers { get; init; }

    /// <summary>
    /// PAT-1066: degraded-capability channel — the agent's own admission that it was
    /// handed a directive or expected to run a capability it could not carry out.
    /// Mirrors the macOS agent_health emission (PAT-1065); server ingestion is
    /// PAT-1064. Optional/nullable like <see cref="HardwareHealth"/>, NOT always-present
    /// like <see cref="BackupStatus"/>/<see cref="BrowserExtensions"/> — the
    /// absent-vs-present-empty distinction is load-bearing (go-service/docs/PAYLOAD_SCHEMA.md):
    /// absent means "no opinion" (agent could not trust its own on-disk store this
    /// cycle); present with an empty Degraded list means an explicit all-clear.
    /// </summary>
    [JsonPropertyName("agent_health")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public InventoryAgentHealth? AgentHealth { get; init; }
}

internal sealed record InventoryDevice
{
    [JsonPropertyName("serial")]
    public required string Serial { get; init; }

    [JsonPropertyName("hw_uuid")]
    public required string HwUuid { get; init; }

    [JsonPropertyName("hostname")]
    public required string Hostname { get; init; }

    [JsonPropertyName("hw_model")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? HwModel { get; init; }

    [JsonPropertyName("arch")]
    public required string Arch { get; init; }

    [JsonPropertyName("last_boot")]
    public required string LastBoot { get; init; }

    /// <summary>
    /// Primary user attribution (PAT-116): last-logged-on user account from the
    /// Windows registry (LogonUI\LastLoggedOnUser). Null when the key is missing,
    /// empty, or the value is a service account. PII — see PAT-112 DPA.
    /// </summary>
    [JsonPropertyName("primary_user_account")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PrimaryUserAccount { get; init; }

    [JsonPropertyName("primary_user_source")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PrimaryUserSource { get; init; }
}

internal sealed record InventoryHardware
{
    [JsonPropertyName("cpu_model")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CpuModel { get; init; }

    [JsonPropertyName("cpu_cores")]
    public int CpuCores { get; init; }

    [JsonPropertyName("ram_gb")]
    public int RamGb { get; init; }

    [JsonPropertyName("disk_total_gb")]
    public double DiskTotalGb { get; init; }

    [JsonPropertyName("disk_free_gb")]
    public double DiskFreeGb { get; init; }
}

internal sealed record InventoryOs
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = "Windows";

    [JsonPropertyName("version")]
    public required string Version { get; init; }

    [JsonPropertyName("build")]
    public required string Build { get; init; }
}

internal sealed record InventorySecurityTool
{
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    [JsonPropertyName("name")]
    public required string Name { get; init; }
}

/// <summary>
/// PAT-913 (Option B): positive per-control attestation object. Platform-neutral
/// contract shared with the macOS collector's compliance_assessments emission.
/// </summary>
internal sealed record ComplianceAssessments
{
    /// <summary>
    /// Finding-control IDs the agent actually ran a determination for this run.
    /// Same ID space as ComplianceFinding.Id. A control belongs here only when its
    /// detection ran to a clean determination; an erroring sub-check drops it.
    /// </summary>
    [JsonPropertyName("controls_assessed")]
    public required IReadOnlyList<string> ControlsAssessed { get; init; }
}

internal sealed record InventoryApp
{
    [JsonPropertyName("user_account")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UserAccount { get; init; }

    [JsonPropertyName("installation_evidence")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AppInstallationEvidence? InstallationEvidence { get; init; }
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("version")]
    public required string Version { get; init; }

    [JsonPropertyName("identifier")]
    public required string Identifier { get; init; }

    [JsonPropertyName("publisher")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Publisher { get; init; }

    [JsonPropertyName("architecture")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Architecture { get; init; }

    /// <summary>
    /// Software metering (PAT-380): last-run time from UserAssist, ISO 8601 UTC.
    /// Omitted when unknown — the extractor preserves the prior value (COALESCE).
    /// Same neutral column as macOS (device_apps.last_used_at).
    /// </summary>
    [JsonPropertyName("last_used_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LastUsedAt { get; init; }

    /// <summary>Software metering (PAT-380): lifetime cumulative launch count (UserAssist run count).</summary>
    [JsonPropertyName("launch_count")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? LaunchCount { get; init; }

    /// <summary>recorded, no_record, unmapped or unavailable; omission is not reported.</summary>
    [JsonPropertyName("usage_evidence")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UsageEvidence { get; init; }
}

/// <summary>
/// PAT-685: hardware health section — battery, storage volumes, and physical disks.
/// Mirrors the macOS hardware_health shape so the go-service extractor can ingest
/// both platforms from the same schema.  Field names must match the extractor's
/// hardwareHealthPart exactly — unknown shapes are silently dropped server-side.
/// </summary>
internal sealed record InventoryHardwareHealth
{
    [JsonPropertyName("battery")]
    public required InventoryBattery Battery { get; init; }

    [JsonPropertyName("storage")]
    public required IReadOnlyList<InventoryStorageVolume> Storage { get; init; }

    [JsonPropertyName("disks")]
    public required IReadOnlyList<InventoryDisk> Disks { get; init; }

    /// <summary>
    /// PAT-1720: how much of each section was actually read. Required so no code path
    /// can omit it: an absent object reads as "complete" server-side, which would let a
    /// failed WMI query prune stored rows. Mirrors macOS hardware_health.collection_status.
    /// </summary>
    [JsonPropertyName("collection_status")]
    public required InventoryHardwareCollectionStatus CollectionStatus { get; init; }
}

/// <summary>
/// PAT-1720: per-section collection status for hardware_health. Each value is one of
/// <see cref="HardwareCollectionStatus.Complete"/> (every row read; the server replaces
/// stored rows), <see cref="HardwareCollectionStatus.Partial"/> (rows sent are upserted,
/// none deleted) or <see cref="HardwareCollectionStatus.Unavailable"/> (the source query
/// failed; the server writes nothing for that section).
/// </summary>
internal sealed record InventoryHardwareCollectionStatus
{
    [JsonPropertyName("battery")]
    public required string Battery { get; init; }

    [JsonPropertyName("storage")]
    public required string Storage { get; init; }

    [JsonPropertyName("disks")]
    public required string Disks { get; init; }
}

/// <summary>PAT-1720: the three hardware_health.collection_status values, lowercase on the wire.</summary>
internal static class HardwareCollectionStatus
{
    public const string Complete    = "complete";
    public const string Partial     = "partial";
    public const string Unavailable = "unavailable";
}

/// <summary>
/// PAT-1732: top-level collection_status. Each value is one of
/// <see cref="CertCollectionStatus.Complete"/> (every row read; the server replaces
/// stored rows), <see cref="CertCollectionStatus.Partial"/> (rows sent are upserted,
/// none deleted) or <see cref="CertCollectionStatus.Unavailable"/> (the source could
/// not be read; the server writes nothing for that section).
/// </summary>
internal sealed record InventoryAppUserStatus
{
    [JsonPropertyName("user_account")]
    public required string UserAccount { get; init; }
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }
    // The user's profile directory as the OS records it. Sent only when it is
    // unambiguous for the account; omitted from the wire when null. The platform
    // must accept this field before an agent that sends it is released.
    [JsonPropertyName("home")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Home { get; init; }
}

internal sealed record InventoryCollectionStatus
{
    [JsonPropertyName("apps_users")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<InventoryAppUserStatus>? AppsUsers { get; init; }

    [JsonPropertyName("certificates")]
    public required string Certificates { get; init; }

    /// <summary>
    /// PAT-2066 (agent half of PAT-2063): whether the apps array is the whole installed
    /// inventory. One of the <see cref="AppCollectionStatus"/> values. Required so no code
    /// path can omit it: the platform reads an absent key as "no signal", not as complete.
    /// Built only from an <c>AppCollectionResult</c> alongside the apps it describes.
    /// </summary>
    [JsonPropertyName("apps")]
    public required string Apps { get; init; }
}

/// <summary>
/// PAT-2066: collection_status.apps values, lowercase on the wire, identical on macOS
/// (macos/lib/apps.sh). <see cref="Complete"/>: every source was enumerated and every
/// entry read, so the server prunes stored apps not listed, even when the list is empty.
/// <see cref="Partial"/>: a source, key or value could not be read; the rows sent are
/// upserted and nothing is pruned. <see cref="Unavailable"/>: the scan failed outright;
/// apps is sent as [] and nothing is written.
/// </summary>
internal static class AppCollectionStatus
{
    public const string Complete    = "complete";
    public const string Partial     = "partial";
    public const string Unavailable = "unavailable";
}

/// <summary>PAT-1732: collection_status.certificates values, lowercase on the wire.</summary>
internal static class CertCollectionStatus
{
    public const string Complete    = "complete";
    public const string Partial     = "partial";
    public const string Unavailable = "unavailable";
}

/// <summary>
/// PAT-1974: the standing local administrator roster, platform-neutral between the
/// Windows and macOS agents.
///
/// ABSENCE REQUIRES AUTHORITY. <see cref="Accounts"/> is null — the key omitted — exactly
/// when this run cannot vouch for the roster. An empty array is a positive claim that the
/// device has no standing local administrators, so it is only ever sent under
/// <see cref="LocalAdminCollectionStatus.Complete"/>. Same rule the certificates key
/// follows, for the same reason: under a non-complete status an older server that ignores
/// collection_status would read <c>[]</c> as "prune every stored row".
/// </summary>
internal sealed record InventoryLocalAdmins
{
    /// <summary>One of the <see cref="LocalAdminCollectionStatus"/> values.</summary>
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    [JsonPropertyName("accounts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<InventoryLocalAdmin>? Accounts { get; init; }
}

/// <summary>PAT-1974: one principal holding local administrator rights on the device.</summary>
internal sealed record InventoryLocalAdmin
{
    /// <summary>
    /// The principal as the OS names it — <c>MACHINE\alice</c> or <c>CONTOSO\Domain Admins</c>
    /// on Windows, the account short name on macOS. For an
    /// <see cref="LocalAdminPrincipalType.Unresolved"/> entry this is the raw SID string,
    /// because that is the only name the device has for it.
    /// </summary>
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    /// <summary>One of the <see cref="LocalAdminPrincipalType"/> values.</summary>
    [JsonPropertyName("principal_type")]
    public required string PrincipalType { get; init; }

    /// <summary>
    /// True for the platform's built-in administrator identity — the Windows account
    /// whose RID is 500. macOS filters its equivalent (<c>root</c>) out of the roster
    /// entirely, so every macOS entry is false.
    /// </summary>
    [JsonPropertyName("builtin")]
    public required bool Builtin { get; init; }

    /// <summary>
    /// Windows only: the string-form SID, the one stable key for a principal whose name
    /// can change or fail to resolve. macOS has no equivalent and omits it.
    /// </summary>
    [JsonPropertyName("sid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Sid { get; init; }

    /// <summary>
    /// PAT-1988: whether the account itself is enabled — one of the
    /// <see cref="LocalAdminAccountState"/> values. Read for the built-in Administrator
    /// (RID 500) only, because that is the entry whose enabled state is the risk signal:
    /// <see cref="Builtin"/> alone cannot tell a disabled built-in Administrator, the
    /// common hardened-image state, from an enabled one, which is a real finding. Null on
    /// every other entry, and on a run that was given no reader, meaning the state was
    /// never looked for rather than looked for and not found.
    /// <para>
    /// ABSENCE REQUIRES AUTHORITY. <see cref="LocalAdminAccountState.Unknown"/> means the
    /// read was attempted and could not establish the state. It never stands in for
    /// "disabled", so a built-in Administrator this run could not read cannot be the thing
    /// that lets a server rule conclude the device is low risk.
    /// </para>
    /// </summary>
    //
    // On the wire since PAT-1992 shipped server-side: patched.im's payload.schema.json and
    // validate.go accept account_state with enum enabled|disabled|unknown and treat an
    // explicit null as absent. The per-property WhenWritingNull below keeps a null (every
    // non-built-in entry, and a run given no reader) off the wire whatever serializer
    // options are in use, the same way Sid does. The serialisation tests
    // Payload_LocalAdmins_BuiltinAccountState_* pin the key name, the lowercase values and
    // the null omission. See PAT-1988.
    [JsonPropertyName("account_state")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AccountState { get; init; }
}

/// <summary>
/// PAT-1988: local_admins.accounts[].account_state values, lowercase on the wire to match
/// principal_type and collection_status, and matching the server enum exactly (PAT-1992).
/// See <see cref="InventoryLocalAdmin.AccountState"/>.
/// </summary>
internal static class LocalAdminAccountState
{
    /// <summary>The account exists on this device and is not disabled.</summary>
    public const string Enabled = "enabled";

    /// <summary>The account exists on this device and is disabled.</summary>
    public const string Disabled = "disabled";

    /// <summary>
    /// The read was attempted and could not establish the state: it failed, returned a
    /// value of an unusable type, or found no local account with that SID. Never a stand-in
    /// for <see cref="Disabled"/>.
    /// </summary>
    public const string Unknown = "unknown";
}

/// <summary>
/// PAT-1974: what kind of principal a local_admins entry is, lowercase on the wire.
/// A group's own membership is not visible from the device, so it is a different risk
/// shape from an individually provisioned admin and is reported apart from one.
/// </summary>
internal static class LocalAdminPrincipalType
{
    /// <summary>An individual principal: a user or computer account, local or directory-sourced.</summary>
    public const string User = "user";

    /// <summary>A group principal. Its membership is opaque to the device, so it is never counted as one admin.</summary>
    public const string Group = "group";

    /// <summary>The SID could not be resolved to a name or a kind on this device.</summary>
    public const string Unresolved = "unresolved";
}

/// <summary>PAT-1974: local_admins.collection_status values, lowercase on the wire.</summary>
internal static class LocalAdminCollectionStatus
{
    public const string Complete    = "complete";
    public const string Partial     = "partial";
    public const string Unavailable = "unavailable";
}

/// <summary>
/// Battery health sub-record.  When the device has no battery, <see cref="Present"/>
/// is false and all remaining fields are null — this is a normal desktop condition,
/// not an error.
/// </summary>
internal sealed record InventoryBattery
{
    [JsonPropertyName("present")]
    public required bool Present { get; init; }

    [JsonPropertyName("cycle_count")]
    public int? CycleCount { get; init; }

    [JsonPropertyName("condition")]
    public string? Condition { get; init; }

    [JsonPropertyName("max_capacity_pct")]
    public int? MaxCapacityPct { get; init; }
}

/// <summary>One fixed storage volume from DriveInfo.GetDrives().</summary>
internal sealed record InventoryStorageVolume
{
    [JsonPropertyName("mount")]
    public required string Mount { get; init; }

    [JsonPropertyName("total_bytes")]
    public required long TotalBytes { get; init; }

    [JsonPropertyName("free_bytes")]
    public required long FreeBytes { get; init; }

    /// <summary>Integer 0–100; computed as (used / total) * 100.</summary>
    [JsonPropertyName("used_pct")]
    public required int UsedPct { get; init; }
}

/// <summary>
/// One physical disk from MSFT_PhysicalDisk (primary) or
/// MSStorageDriver_FailurePredictStatus (fallback).
/// </summary>
internal sealed record InventoryDisk
{
    [JsonPropertyName("device")]
    public required string Device { get; init; }

    /// <summary>
    /// "Verified" when healthy; "Failing" for a warning or unhealthy state; "Undetermined"
    /// when the health value could not be read or is not one Windows defines as a verdict.
    /// </summary>
    [JsonPropertyName("smart_status")]
    public required string SmartStatus { get; init; }

    /// <summary>False when BusType is USB (7); true for all other bus types.</summary>
    [JsonPropertyName("internal")]
    public required bool Internal { get; init; }

    /// <summary>True when MediaType is 4 (SSD/NVMe).</summary>
    [JsonPropertyName("solid_state")]
    public required bool SolidState { get; init; }
}

/// <summary>
/// PAT-680: backup status — File History, OneDrive sync, and third-party tools.
/// Mirrors the macOS backup_status shape emitted by macos/lib/backup.sh (PAT-679).
/// Field names must match exactly so the go-service extractor ingests both
/// platforms from the same schema with no server change.
/// </summary>
internal sealed record InventoryBackupStatus
{
    [JsonPropertyName("has_backup")]
    public required bool HasBackup { get; init; }

    [JsonPropertyName("backup_type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BackupType { get; init; }

    [JsonPropertyName("last_backup_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LastBackupAt { get; init; }

    [JsonPropertyName("last_backup_days_ago")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? LastBackupDaysAgo { get; init; }

    [JsonPropertyName("stale")]
    public bool Stale { get; init; }

    /// <summary>True for sync-only mechanisms (OneDrive) — sync is not a substitute for backup.</summary>
    [JsonPropertyName("sync_only")]
    public bool SyncOnly { get; init; }

    [JsonPropertyName("notes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Notes { get; init; }
}

/// <summary>
/// PAT-1066: agent_health.degraded wrapper object. See <see cref="InventoryPayload.AgentHealth"/>
/// for why this is nullable rather than always-present.
/// </summary>
internal sealed record InventoryAgentHealth
{
    [JsonPropertyName("degraded")]
    public required IReadOnlyList<InventoryAgentHealthEntry> Degraded { get; init; }

    [JsonPropertyName("update_channel")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public InventoryUpdateChannel? UpdateChannel { get; init; }
}

internal sealed record InventoryUpdateChannel
{
    [JsonPropertyName("effective_channel")]
    public required string EffectiveChannel { get; init; }
    [JsonPropertyName("source")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Source { get; init; }
    [JsonPropertyName("config_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public int? ConfigVersion { get; init; }
    [JsonPropertyName("observed_at")]
    public required DateTimeOffset ObservedAt { get; init; }
}

/// <summary>
/// PAT-1066: one degraded-capability fault entry. Field names must match exactly —
/// go-service/docs/PAYLOAD_SCHEMA.md's "degraded array" table is the authoritative
/// contract; kind/subject/reason are documented vocabulary, not an enum, and must
/// never be validated/rejected against a fixed list here or server-side.
/// </summary>
internal sealed record InventoryAgentHealthEntry
{
    [JsonPropertyName("kind")]
    public required string Kind { get; init; }

    [JsonPropertyName("subject")]
    public required string Subject { get; init; }

    [JsonPropertyName("reason")]
    public required string Reason { get; init; }

    [JsonPropertyName("first_seen")]
    public required string FirstSeen { get; init; }

    [JsonPropertyName("last_seen")]
    public required string LastSeen { get; init; }

    [JsonPropertyName("count")]
    public required int Count { get; init; }

    [JsonPropertyName("ever_succeeded")]
    public required bool EverSucceeded { get; init; }
}

/// <summary>
/// PAT-827: one entry in the browser_extensions[] payload array — one
/// (browser, user, profile, extension) tuple. Mirrors the macOS shape emitted by
/// macos/lib/browser_extensions.sh (PAT-125). Field names must match exactly so
/// the go-service extractor ingests both platforms into the same
/// device_browser_extensions schema (migration 0018) with no server change.
/// </summary>
internal sealed record InventoryBrowserExtension
{
    /// <summary>"chrome" | "edge" | "firefox".</summary>
    [JsonPropertyName("browser")]
    public required string Browser { get; init; }

    /// <summary>Browser profile directory name (e.g. "Default", "Profile 1").</summary>
    [JsonPropertyName("profile")]
    public required string Profile { get; init; }

    /// <summary>
    /// Windows account name (DOMAIN\user or MACHINE\user) resolved from the profile's
    /// SID via LSA translation; falls back to the raw SID string when translation
    /// fails (e.g. an orphaned profile for a deleted account). Same neutral column as
    /// macOS's OS login name (device_browser_extensions.user_account).
    /// </summary>
    [JsonPropertyName("user_account")]
    public required string UserAccount { get; init; }

    [JsonPropertyName("extension_id")]
    public required string ExtensionId { get; init; }

    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("version")]
    public required string Version { get; init; }

    [JsonPropertyName("enabled")]
    public required bool Enabled { get; init; }

    [JsonPropertyName("permissions")]
    public required IReadOnlyList<string> Permissions { get; init; }

    [JsonPropertyName("host_permissions")]
    public required IReadOnlyList<string> HostPermissions { get; init; }

    [JsonPropertyName("from_webstore")]
    public required bool FromWebstore { get; init; }

    [JsonPropertyName("update_url")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UpdateUrl { get; init; }
}

/// <summary>
/// PAT-2065: the browser_extensions_status block (patched.im PAYLOAD_SCHEMA.md, "Browser
/// extensions status object"). A failed block carries only collection_status; every other
/// status carries cap_reached and users.
/// </summary>
internal sealed record InventoryBrowserExtensionsStatus
{
    /// <summary>"complete" | "partial" | "not_present" | "failed".</summary>
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    [JsonPropertyName("cap_reached")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? CapReached { get; init; }

    [JsonPropertyName("users")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<InventoryBrowserExtensionsStatusUser>? Users { get; init; }
}

/// <summary>PAT-2065: one user in browser_extensions_status.users[].</summary>
internal sealed record InventoryBrowserExtensionsStatusUser
{
    /// <summary>Exactly the user_account on this user's browser_extensions rows.</summary>
    [JsonPropertyName("user")]
    public required string User { get; init; }

    /// <summary>The profile's SID. Required by the contract even when null, so never omitted.</summary>
    [JsonPropertyName("user_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? UserId { get; init; }

    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }

    [JsonPropertyName("browsers")]
    public required InventoryBrowserExtensionsStatusBrowsers Browsers { get; init; }
}

/// <summary>PAT-2065: per-browser status. Safari is outside the block (its rows carry no user).</summary>
internal sealed record InventoryBrowserExtensionsStatusBrowsers
{
    [JsonPropertyName("chrome")]
    public required string Chrome { get; init; }

    [JsonPropertyName("edge")]
    public required string Edge { get; init; }

    [JsonPropertyName("firefox")]
    public required string Firefox { get; init; }
}

/// <summary>
/// PAT-641: one entry in the certificates[] payload array.
/// Mirrors the macOS shape emitted by macos/lib/certs.sh (PAT-216/220).
/// Field names must match exactly — the go-service ingests both platforms
/// from the same device_certificates schema with no server change.
/// </summary>
internal sealed record InventoryCert
{
    /// <summary>
    /// PAT-1738: which machine store this row was enumerated from. Windows sends
    /// "My", "Root" or "CA"; macOS sends the fixed value "System" (its only read
    /// keychain). Classification (which of these are platform roots) is server-side.
    /// </summary>
    [JsonPropertyName("store")]
    public required string Store { get; init; }

    [JsonPropertyName("subject_cn")]
    public required string SubjectCn { get; init; }

    [JsonPropertyName("issuer_cn")]
    public required string IssuerCn { get; init; }

    [JsonPropertyName("sha1")]
    public required string Sha1 { get; init; }

    [JsonPropertyName("not_after")]
    public required string NotAfter { get; init; }

    [JsonPropertyName("days_until_expiry")]
    public required int DaysUntilExpiry { get; init; }

    /// <summary>Extended key usages, e.g. ["Code Signing", "Client Authentication"].</summary>
    [JsonPropertyName("ext_key_usage")]
    public required string[] ExtKeyUsage { get; init; }

    /// <summary>True when the BasicConstraints extension marks this cert as a CA.</summary>
    [JsonPropertyName("basic_constraints_ca")]
    public required bool BasicConstraintsCa { get; init; }

    [JsonPropertyName("is_self_signed")]
    public required bool IsSelfSigned { get; init; }
}
