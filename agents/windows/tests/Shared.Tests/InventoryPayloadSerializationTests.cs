using System.Text.Json;
using System.Text.Json.Serialization;
using Patched.Shared.Apps;
using Patched.Shared.Certificates;
using Patched.Shared.Compliance;
using Patched.Shared.Contract;
using Patched.Shared.DeviceClassification;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// Validates that InventoryPayload serializes to the schema v3 shape
/// required by POST /v1/inventory (go-service/docs/PAYLOAD_SCHEMA.md).
/// </summary>
public sealed class InventoryPayloadSerializationTests
{
    private static readonly JsonSerializerOptions Opts = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        // Mirrors InventoryPoster.JsonOpts (PAT-743) so this test suite actually
        // exercises the same wire format production sends.
        Converters             = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    private static InventoryPayload MakePayload(
        Dictionary<string, object>?        compliance    = null,
        IReadOnlyList<InventorySecurityTool>? tools       = null,
        IReadOnlyList<InventoryApp>?        apps          = null,
        IReadOnlyList<InventoryCert>?       certs         = null,
        InventoryCollectionStatus?          collectionStatus = null,
        IReadOnlyList<ComplianceFinding>?   complianceFindings = null,
        IReadOnlyList<string>?              controlsAssessed = null,
        InventoryBackupStatus?              backupStatus  = null,
        IReadOnlyList<InventoryBrowserExtension>? browserExtensions = null,
        InventoryBrowserExtensionsStatus?         browserExtensionsStatus = null,
        InventoryAgentHealth?                agentHealth   = null,
        InventoryLocalAdmins?                localAdmins   = null,
        OsUpdateInfo?                        osUpdate      = null,
        string?                              deviceClass      = null,
        string?                              installationType = null,
        string?                              osCaption        = null) =>
        new()
        {
            DeviceClass      = deviceClass,
            InstallationType = installationType,
            OsCaption        = osCaption,
            Agent         = "patched-agent-win",
            AgentVersion  = "0.2.0",
            TenantId      = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            CollectedAt   = "2026-12-12T10:00:00Z",
            Device        = new InventoryDevice
            {
                Serial   = "SER-001",
                HwUuid   = "00000000-0000-0000-0000-000000000001",
                Hostname = "DESKTOP-TEST",
                HwModel  = "Dell OptiPlex 7090",
                Arch     = "x86_64",
                LastBoot = "2026-12-12T08:00:00Z",
            },
            Hardware = new InventoryHardware
            {
                CpuModel    = "Intel Core i7-10700",
                CpuCores    = 8,
                RamGb       = 16,
                DiskTotalGb = 476.9,
                DiskFreeGb  = 200.1,
            },
            Os = new InventoryOs
            {
                Version = "10.0.22631.3880",
                Build   = "22631",
            },
            OsUpdate           = osUpdate,
            Compliance         = compliance ?? new Dictionary<string, object> { ["bitlocker_os_drive"] = "On" },
            ComplianceFindings = complianceFindings ?? [],
            ComplianceAssessments = new ComplianceAssessments { ControlsAssessed = controlsAssessed ?? [] },
            SecurityTools      = tools ?? [],
            Apps               = apps  ?? [],
            Certificates       = certs ?? [],
            CollectionStatus   = collectionStatus ?? new InventoryCollectionStatus { Certificates = CertCollectionStatus.Complete, Apps = AppCollectionStatus.Complete },
            LocalAdmins        = localAdmins ?? new InventoryLocalAdmins
            {
                CollectionStatus = LocalAdminCollectionStatus.Complete,
                Accounts         = [],
            },
            BackupStatus       = backupStatus ?? new InventoryBackupStatus { HasBackup = false },
            BrowserExtensions  = browserExtensions ?? [],
            BrowserExtensionsStatus = browserExtensionsStatus ?? new InventoryBrowserExtensionsStatus { CollectionStatus = "failed" },
            AgentHealth        = agentHealth,
        };

    [Fact]
    public void Payload_SchemaVersion_Is3()
    {
        var doc = Parse(MakePayload());
        Assert.Equal(3, doc.RootElement.GetProperty("schema_version").GetInt32());
    }

    [Fact]
    public void Payload_Platform_IsWindows()
    {
        var doc = Parse(MakePayload());
        Assert.Equal("windows", doc.RootElement.GetProperty("platform").GetString());
    }

    [Fact]
    public void Payload_Agent_Fields_Present()
    {
        var doc  = Parse(MakePayload());
        var root = doc.RootElement;
        Assert.Equal("patched-agent-win", root.GetProperty("agent").GetString());
        Assert.Equal("0.2.0",             root.GetProperty("agent_version").GetString());
        Assert.Equal("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                     root.GetProperty("tenant_id").GetString());
        Assert.Equal("2026-12-12T10:00:00Z", root.GetProperty("collected_at").GetString());
    }

    [Fact]
    public void Payload_Device_Fields_Present()
    {
        var dev = Parse(MakePayload()).RootElement.GetProperty("device");
        Assert.Equal("SER-001",         dev.GetProperty("serial").GetString());
        Assert.Equal("DESKTOP-TEST",    dev.GetProperty("hostname").GetString());
        Assert.Equal("x86_64",          dev.GetProperty("arch").GetString());
        Assert.Equal("Dell OptiPlex 7090", dev.GetProperty("hw_model").GetString());
    }

    [Fact]
    public void Payload_Hardware_Fields_Present()
    {
        var hw = Parse(MakePayload()).RootElement.GetProperty("hardware");
        Assert.Equal("Intel Core i7-10700", hw.GetProperty("cpu_model").GetString());
        Assert.Equal(8,    hw.GetProperty("cpu_cores").GetInt32());
        Assert.Equal(16,   hw.GetProperty("ram_gb").GetInt32());
        Assert.Equal(476.9, hw.GetProperty("disk_total_gb").GetDouble(), precision: 1);
    }

    [Fact]
    public void Payload_Os_Fields_Present()
    {
        var os = Parse(MakePayload()).RootElement.GetProperty("os");
        Assert.Equal("Windows",          os.GetProperty("name").GetString());
        Assert.Equal("10.0.22631.3880",  os.GetProperty("version").GetString());
        Assert.Equal("22631",            os.GetProperty("build").GetString());
    }

    [Fact]
    public void Payload_OsUpdate_ComputedVerdict_SerialisesWithServerContractNamesAndTypes()
    {
        var checkedAt = new DateTimeOffset(2026, 9, 18, 12, 34, 56, TimeSpan.Zero);
        var payload = MakePayload(osUpdate: new OsUpdateInfo
        {
            InstalledOs        = "10.0.26100.6584",
            LatestOs           = "10.0.26100.7000",
            TargetOs           = "10.0.26100.7000",
            State              = OsUpdateState.UpdateRequired,
            Severity           = OsUpdateSeverity.High,
            SecurityRelevant   = true,
            ActivelyExploited  = false,
            Deadline           = new DateTimeOffset(2026, 9, 25, 3, 0, 0, TimeSpan.Zero),
            DeferralsRemaining = 4,
            ReleaseAgeDays     = 10,
            CheckedAt          = checkedAt,
        });

        var osUpdate = Parse(payload).RootElement.GetProperty("os_update");
        Assert.Equal("10.0.26100.6584", osUpdate.GetProperty("installed_os").GetString());
        Assert.Equal("10.0.26100.7000", osUpdate.GetProperty("latest_os").GetString());
        Assert.Equal("10.0.26100.7000", osUpdate.GetProperty("target_os").GetString());
        Assert.Equal("update_required", osUpdate.GetProperty("state").GetString());
        Assert.Equal("high", osUpdate.GetProperty("severity").GetString());
        Assert.True(osUpdate.GetProperty("security_relevant").GetBoolean());
        Assert.False(osUpdate.GetProperty("actively_exploited").GetBoolean());
        Assert.Equal(JsonValueKind.String, osUpdate.GetProperty("deadline").ValueKind);
        Assert.Equal(JsonValueKind.Number, osUpdate.GetProperty("deferrals_remaining").ValueKind);
        Assert.Equal(4, osUpdate.GetProperty("deferrals_remaining").GetInt32());
        Assert.Equal(10, osUpdate.GetProperty("release_age_days").GetInt32());
        Assert.Equal(checkedAt, osUpdate.GetProperty("checked_at").GetDateTimeOffset());
    }

    [Fact]
    public void Payload_OsUpdate_NullableMembers_DoNotBecomeFabricatedDefaults()
    {
        var payload = MakePayload(osUpdate: new OsUpdateInfo
        {
            InstalledOs        = "10.0.26100.6584",
            LatestOs           = null,
            TargetOs           = "10.0.26100.6584",
            State              = OsUpdateState.Unknown,
            Severity           = OsUpdateSeverity.None,
            SecurityRelevant   = false,
            ActivelyExploited  = false,
            Deadline           = null,
            DeferralsRemaining = 4,
            ReleaseAgeDays     = null,
            CheckedAt          = new DateTimeOffset(2026, 9, 18, 12, 34, 56, TimeSpan.Zero),
        });

        var osUpdate = Parse(payload).RootElement.GetProperty("os_update");
        Assert.False(osUpdate.TryGetProperty("latest_os", out _));
        Assert.False(osUpdate.TryGetProperty("deadline", out _));
        Assert.False(osUpdate.TryGetProperty("release_age_days", out _));
    }

    [Fact]
    public void Payload_OsUpdate_Unavailable_OmitsWholeBlock()
    {
        var root = Parse(MakePayload(osUpdate: null)).RootElement;
        Assert.False(root.TryGetProperty("os_update", out _));
    }

    /// <summary>
    /// PAT-2123: a pending update with no version info from WUA (common for
    /// cumulative updates) must send target_os as absent/null on the wire, never
    /// fabricate installed_os as the target. installed_os and state still go out
    /// unchanged.
    /// </summary>
    [Fact]
    public void Payload_OsUpdate_TargetOsNull_IsOmittedFromWire_StateAndInstalledOsUnaffected()
    {
        var payload = MakePayload(osUpdate: new OsUpdateInfo
        {
            InstalledOs        = "10.0.26200.8655",
            LatestOs           = null,
            TargetOs           = null,
            State              = OsUpdateState.UpdateRequired,
            Severity           = OsUpdateSeverity.High,
            SecurityRelevant   = true,
            ActivelyExploited  = false,
            Deadline           = new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero),
            DeferralsRemaining = 4,
            ReleaseAgeDays     = 12,
            CheckedAt          = new DateTimeOffset(2026, 9, 25, 12, 0, 0, TimeSpan.Zero),
        });

        var osUpdate = Parse(payload).RootElement.GetProperty("os_update");
        Assert.False(osUpdate.TryGetProperty("target_os", out _));
        Assert.Equal("10.0.26200.8655", osUpdate.GetProperty("installed_os").GetString());
        Assert.Equal("update_required", osUpdate.GetProperty("state").GetString());
    }

    [Fact]
    public void Payload_Compliance_StringValues_SerialiseAsJsonStrings()
    {
        var signals = new Dictionary<string, object>
        {
            ["bitlocker_os_drive"]  = "On",
            ["uac_enabled"]         = "Yes",
            ["defender_realtime"]   = "enabled",
        };
        var comp = Parse(MakePayload(compliance: signals)).RootElement.GetProperty("compliance");
        Assert.Equal("On",      comp.GetProperty("bitlocker_os_drive").GetString());
        Assert.Equal("Yes",     comp.GetProperty("uac_enabled").GetString());
        Assert.Equal("enabled", comp.GetProperty("defender_realtime").GetString());
    }

    [Fact]
    public void Payload_Compliance_IntValues_SerialiseAsJsonNumbers()
    {
        var signals = new Dictionary<string, object>
        {
            ["screensaver_timeout_seconds"] = 300,
        };
        var comp = Parse(MakePayload(compliance: signals)).RootElement.GetProperty("compliance");
        Assert.Equal(300, comp.GetProperty("screensaver_timeout_seconds").GetInt32());
    }

    [Fact]
    public void Payload_ComplianceFindings_EmptyByDefault()
    {
        var arr = Parse(MakePayload()).RootElement.GetProperty("compliance_findings");
        Assert.Equal(0, arr.GetArrayLength());
    }

    [Fact]
    public void Payload_ComplianceFindings_DiskEncryptionOff_Serialised()
    {
        var findings = new List<ComplianceFinding>
        {
            new() { Id = "disk_encryption_off", Severity = ComplianceSeverity.Critical },
        };
        var arr = Parse(MakePayload(complianceFindings: findings)).RootElement.GetProperty("compliance_findings");
        Assert.Equal(1, arr.GetArrayLength());
        Assert.Equal("disk_encryption_off", arr[0].GetProperty("id").GetString());
        // PAT-743 regression: Severity is a C# enum — without a string-enum converter
        // this serializes as a raw int (3), which the go-service extractor's
        // complianceFinding.Severity (a plain Go string) cannot unmarshal.
        Assert.Equal("critical", arr[0].GetProperty("severity").GetString());
        Assert.False(arr[0].TryGetProperty("volumes", out _));
    }

    [Fact]
    public void Payload_ComplianceFindings_RemovableStorageUnencrypted_WithVolumes_Serialised()
    {
        var findings = new List<ComplianceFinding>
        {
            new()
            {
                Id       = "removable_storage_unencrypted",
                Severity = ComplianceSeverity.Medium,
                Volumes  =
                [
                    new ComplianceFindingVolume
                    {
                        MountPoint       = "E:\\",
                        Filesystem       = "exFAT",
                        EncryptionState  = "plaintext",
                        ProvenanceSource = "wmi",
                    },
                ],
            },
        };
        var arr = Parse(MakePayload(complianceFindings: findings)).RootElement.GetProperty("compliance_findings");
        Assert.Equal(1, arr.GetArrayLength());
        Assert.Equal("removable_storage_unencrypted", arr[0].GetProperty("id").GetString());
        Assert.Equal("medium", arr[0].GetProperty("severity").GetString());
        var vols = arr[0].GetProperty("volumes");
        Assert.Equal(1, vols.GetArrayLength());
        Assert.Equal("E:\\", vols[0].GetProperty("mount_point").GetString());
    }

    // -------------------------------------------------------------------------
    // PAT-913: compliance_assessments (positive per-control attestation) — the
    // shape InventoryPoster.BuildPayload emits from its controls_assessed list.
    // -------------------------------------------------------------------------

    /// <summary>
    /// compliance_assessments is always present (parity with the macOS collector),
    /// with controls_assessed serialising as an empty array when nothing was
    /// attested — equivalent server-side to the section being absent.
    /// </summary>
    [Fact]
    public void Payload_ComplianceAssessments_AlwaysPresent_EmptyByDefault()
    {
        var root = Parse(MakePayload()).RootElement;
        Assert.True(root.TryGetProperty("compliance_assessments", out var obj));
        Assert.True(obj.TryGetProperty("controls_assessed", out var arr));
        Assert.Equal(JsonValueKind.Array, arr.ValueKind);
        Assert.Equal(0, arr.GetArrayLength());
    }

    [Fact]
    public void Payload_ComplianceAssessments_ControlsAssessed_Serialised()
    {
        var controls = new List<string> { "disk_encryption_off", "removable_storage_unencrypted" };
        var arr = Parse(MakePayload(controlsAssessed: controls)).RootElement
            .GetProperty("compliance_assessments")
            .GetProperty("controls_assessed");
        Assert.Equal(2, arr.GetArrayLength());
        Assert.Equal("disk_encryption_off",           arr[0].GetString());
        Assert.Equal("removable_storage_unencrypted", arr[1].GetString());
    }

    /// <summary>
    /// A finding and an attestation can coexist for the same control (the server
    /// resolves it: a finding is always a Fail, so the attestation does not fake a
    /// Pass). This asserts BuildPayload's output carries both independently.
    /// </summary>
    [Fact]
    public void Payload_ComplianceAssessments_And_Findings_Coexist()
    {
        var findings = new List<ComplianceFinding>
        {
            new() { Id = "disk_encryption_off", Severity = ComplianceSeverity.Critical },
        };
        var controls = new List<string> { "disk_encryption_off", "removable_storage_unencrypted" };
        var root = Parse(MakePayload(complianceFindings: findings, controlsAssessed: controls)).RootElement;

        Assert.Equal("disk_encryption_off",
            root.GetProperty("compliance_findings")[0].GetProperty("id").GetString());
        var assessed = root.GetProperty("compliance_assessments").GetProperty("controls_assessed");
        Assert.Equal(2, assessed.GetArrayLength());
    }

    [Fact]
    public void Payload_SecurityTools_Serialised()
    {
        var tools = new List<InventorySecurityTool>
        {
            new() { Id = "defender-for-endpoint", Name = "Microsoft Defender for Endpoint" },
        };
        var arr = Parse(MakePayload(tools: tools)).RootElement.GetProperty("security_tools");
        Assert.Equal(1, arr.GetArrayLength());
        Assert.Equal("defender-for-endpoint",          arr[0].GetProperty("id").GetString());
        Assert.Equal("Microsoft Defender for Endpoint", arr[0].GetProperty("name").GetString());
    }

    [Fact]
    public void Payload_App_WithPublisher_Serialised()
    {
        var apps = new List<InventoryApp>
        {
            new()
            {
                Name         = "Microsoft Edge",
                Version      = "124.0.0.0",
                Identifier   = "Microsoft Edge",
                Publisher    = "Microsoft Corporation",
                Architecture = "x86_64",
            },
        };
        var arr = Parse(MakePayload(apps: apps)).RootElement.GetProperty("apps");
        var app = arr[0];
        Assert.Equal("Microsoft Edge",      app.GetProperty("name").GetString());
        Assert.Equal("124.0.0.0",           app.GetProperty("version").GetString());
        Assert.Equal("Microsoft Edge",      app.GetProperty("identifier").GetString());
        Assert.Equal("Microsoft Corporation", app.GetProperty("publisher").GetString());
        Assert.Equal("x86_64",              app.GetProperty("architecture").GetString());
    }

    [Fact]
    public void Payload_App_NullPublisher_OmittedFromJson()
    {
        var apps = new List<InventoryApp>
        {
            new() { Name = "App", Version = "1.0", Identifier = "App" },
        };
        var app = Parse(MakePayload(apps: apps)).RootElement.GetProperty("apps")[0];
        Assert.False(app.TryGetProperty("publisher", out _));
    }

    [Fact]
    public void Payload_AuthoritativeMetering_RemainsInAppsWithoutLegacyDuplicate()
    {
        var payload = MakePayload(apps:
        [
            new InventoryApp
            {
                Name         = "Metered App",
                Version      = "1.0",
                Identifier   = "Metered.App",
                LastUsedAt   = "2026-08-14T09:30:00Z",
                LaunchCount  = 17,
                UsageEvidence = "recorded",
            },
        ]) with { MeteringStatus = "ok", MeteringUserHiveCount = 2, MeteringRecordCount = 3 };

        var root = Parse(payload).RootElement;
        var app = root.GetProperty("apps")[0];
        Assert.Equal("2026-08-14T09:30:00Z", app.GetProperty("last_used_at").GetString());
        Assert.Equal(17, app.GetProperty("launch_count").GetInt32());
        Assert.Equal("ok", root.GetProperty("metering_status").GetString());
        Assert.Equal("recorded", app.GetProperty("usage_evidence").GetString());
        Assert.Equal(2, root.GetProperty("metering_user_hive_count").GetInt32());
        Assert.Equal(3, root.GetProperty("metering_record_count").GetInt32());
        Assert.False(root.TryGetProperty("app_usage", out _));
    }

    [Theory]
    [InlineData("no_record")]
    [InlineData("unmapped")]
    [InlineData("unavailable")]
    public void Payload_UsageEvidence_AllStatesSurviveWithoutInventingUsage(string evidence)
    {
        var root = Parse(MakePayload(apps: [new InventoryApp
        {
            Name = "App", Version = "1.0", Identifier = "App", UsageEvidence = evidence,
        }])).RootElement;
        var app = root.GetProperty("apps")[0];
        Assert.Equal(evidence, app.GetProperty("usage_evidence").GetString());
        Assert.False(app.TryGetProperty("last_used_at", out _));
        Assert.False(app.TryGetProperty("launch_count", out _));
        Assert.False(root.TryGetProperty("metering_user_hive_count", out _));
        Assert.False(root.TryGetProperty("metering_record_count", out _));
    }

    [Fact]
    public void Payload_OlderUsageEvidence_IsOmittedRatherThanGuessed()
    {
        var root = Parse(MakePayload(apps: [new InventoryApp { Name = "App", Version = "1.0", Identifier = "App" }])).RootElement;
        Assert.False(root.GetProperty("apps")[0].TryGetProperty("usage_evidence", out _));
    }

    [Fact]
    public void Payload_MacOsOnly_Sections_Absent()
    {
        var root = Parse(MakePayload()).RootElement;
        Assert.False(root.TryGetProperty("system_extensions", out _));
        Assert.False(root.TryGetProperty("background_items", out _));
        Assert.False(root.TryGetProperty("icloud", out _));
    }

    /// <summary>PAT-649 / PAT-641: certificates[] is always present, empty by default.</summary>
    [Fact]
    public void Payload_Certificates_Empty_Serialised_AsEmptyArray()
    {
        var root = Parse(MakePayload()).RootElement;
        Assert.True(root.TryGetProperty("certificates", out var arr));
        Assert.Equal(JsonValueKind.Array, arr.ValueKind);
        Assert.Equal(0, arr.GetArrayLength());
    }

    [Fact]
    public void Payload_Certificates_SingleEntry_Serialised()
    {
        var certs = new List<InventoryCert>
        {
            new()
            {
                Store              = "My",
                SubjectCn          = "DESKTOP-TEST",
                IssuerCn           = "DESKTOP-TEST",
                Sha1               = "aabbccdd",
                NotAfter           = "2027-01-01T00:00:00Z",
                DaysUntilExpiry    = 365,
                ExtKeyUsage        = ["Client Authentication"],
                BasicConstraintsCa = false,
                IsSelfSigned       = true,
            },
        };
        var arr = Parse(MakePayload(certs: certs)).RootElement.GetProperty("certificates");
        Assert.Equal(1, arr.GetArrayLength());
        Assert.Equal("DESKTOP-TEST",           arr[0].GetProperty("subject_cn").GetString());
        Assert.Equal("My",                     arr[0].GetProperty("store").GetString());
        Assert.Equal("aabbccdd",               arr[0].GetProperty("sha1").GetString());
        Assert.Equal(365,                      arr[0].GetProperty("days_until_expiry").GetInt32());
        Assert.False(arr[0].GetProperty("basic_constraints_ca").GetBoolean());
        Assert.True(arr[0].GetProperty("is_self_signed").GetBoolean());
    }

    // -------------------------------------------------------------------------
    // PAT-1732: top-level collection_status.certificates
    // -------------------------------------------------------------------------

    private static InventoryPayload PayloadFrom(CertCollectionResult result) =>
        MakePayload() with
        {
            Certificates     = result.Certificates,
            CollectionStatus = new InventoryCollectionStatus { Certificates = result.Status, Apps = AppCollectionStatus.Complete },
        };

    private static InventoryCert Cert(string cn) => new()
    {
        Store              = "My",
        SubjectCn          = cn,
        IssuerCn           = cn,
        Sha1               = "aabbccdd",
        NotAfter           = "2027-01-01T00:00:00Z",
        DaysUntilExpiry    = 365,
        ExtKeyUsage        = [],
        BasicConstraintsCa = false,
        IsSelfSigned       = true,
    };

    [Fact]
    public void Payload_CollectionStatus_TopLevel_ExactKeyNames()
    {
        var root = Parse(MakePayload()).RootElement;
        Assert.True(root.TryGetProperty("collection_status", out var status));
        Assert.Equal(JsonValueKind.Object, status.ValueKind);
        // PAT-2066 added apps beside certificates.
        Assert.Equal(new[] { "certificates", "apps" }, status.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal("complete", status.GetProperty("certificates").GetString());
        Assert.Equal("complete", status.GetProperty("apps").GetString());
    }

    // -------------------------------------------------------------------------
    // PAT-2066: collection_status.apps travels with the apps it describes
    // -------------------------------------------------------------------------

    private static InventoryPayload PayloadFrom(AppCollectionResult result) =>
        MakePayload() with
        {
            Apps             = result.Apps,
            CollectionStatus = new InventoryCollectionStatus
            {
                Certificates = CertCollectionStatus.Complete,
                Apps         = result.Status,
            },
        };

    private static InventoryApp App(string id) => new() { Name = id, Version = "1.0", Identifier = id };

    private static AppSourceResult Source(string name, IEnumerable<string> ids, int throwingEntries = 0) =>
        AppCollectionLogic.ReadSource<string>(
            name,
            () => ids.Concat(Enumerable.Repeat("bad", throwingEntries)).ToArray(),
            id => id == "bad" ? throw new UnauthorizedAccessException("denied") : App(id));

    [Fact]
    public void Payload_AppsUnavailable_SendsEmptyArray_AndSaysUnavailable()
    {
        var root = Parse(PayloadFrom(AppCollectionLogic.Run(() => throw new InvalidOperationException("scan failed")))).RootElement;

        Assert.Equal(0, root.GetProperty("apps").GetArrayLength());
        Assert.Equal("unavailable", root.GetProperty("collection_status").GetProperty("apps").GetString());
    }

    [Fact]
    public void Payload_AppsPartial_SendsReadableApps_AndSaysPartial()
    {
        var root = Parse(PayloadFrom(AppCollectionLogic.Combine([Source("a", ["App1"], throwingEntries: 1)]))).RootElement;

        Assert.Equal(1, root.GetProperty("apps").GetArrayLength());
        Assert.Equal("partial", root.GetProperty("collection_status").GetProperty("apps").GetString());
    }

    [Fact]
    public void Payload_AppsComplete_Empty_SendsEmptyArray_AndSaysComplete()
    {
        var root = Parse(PayloadFrom(AppCollectionLogic.Combine([Source("a", []), Source("b", [])]))).RootElement;

        Assert.Equal(0, root.GetProperty("apps").GetArrayLength());
        Assert.Equal("complete", root.GetProperty("collection_status").GetProperty("apps").GetString());
    }

    [Fact]
    public void Payload_CertsUnavailable_OmitsCertificatesKey_AndSaysUnavailable()
    {
        var json = JsonSerializer.Serialize(PayloadFrom(CertCollectionLogic.Unavailable()), Opts);
        var root = JsonDocument.Parse(json).RootElement;

        Assert.False(root.TryGetProperty("certificates", out _));
        Assert.DoesNotContain("\"certificates\":[", json);
        Assert.Equal("unavailable", root.GetProperty("collection_status").GetProperty("certificates").GetString());
    }

    /// <summary>
    /// The omission must hold even without the serializer-wide WhenWritingNull default,
    /// so a future options change cannot turn "unavailable" into "certificates": null.
    /// </summary>
    [Fact]
    public void Payload_CertsUnavailable_OmitsCertificatesKey_WithDefaultSerializerOptions()
    {
        var root = JsonDocument.Parse(JsonSerializer.Serialize(PayloadFrom(CertCollectionLogic.Unavailable()))).RootElement;
        Assert.False(root.TryGetProperty("certificates", out _));
        Assert.Equal("unavailable", root.GetProperty("collection_status").GetProperty("certificates").GetString());
    }

    [Fact]
    public void Payload_CertsPartial_SendsReadableCertificates_AndSaysPartial()
    {
        var root = Parse(PayloadFrom(CertCollectionLogic.FromStore([Cert("VPN")], skipped: 1))).RootElement;

        var arr = root.GetProperty("certificates");
        Assert.Equal(1, arr.GetArrayLength());
        Assert.Equal("VPN", arr[0].GetProperty("subject_cn").GetString());
        Assert.Equal("partial", root.GetProperty("collection_status").GetProperty("certificates").GetString());
    }

    [Fact]
    public void Payload_CertsPartial_NothingReadable_OmitsCertificatesKey()
    {
        var root = Parse(PayloadFrom(CertCollectionLogic.FromStore([], skipped: 2))).RootElement;

        Assert.False(root.TryGetProperty("certificates", out _));
        Assert.Equal("partial", root.GetProperty("collection_status").GetProperty("certificates").GetString());
    }

    [Fact]
    public void Payload_CertsComplete_EmptyStore_SendsEmptyArray()
    {
        var root = Parse(PayloadFrom(CertCollectionLogic.FromStore([], skipped: 0))).RootElement;

        Assert.Equal(0, root.GetProperty("certificates").GetArrayLength());
        Assert.Equal("complete", root.GetProperty("collection_status").GetProperty("certificates").GetString());
    }

    [Fact]
    public void Payload_Device_NullHwModel_OmittedFromJson()
    {
        var payload = MakePayload() with
        {
            Device = new InventoryDevice
            {
                Serial   = "S",
                HwUuid   = "U",
                Hostname = "H",
                HwModel  = null,
                Arch     = "x86_64",
                LastBoot = "2026-07-01T00:00:00Z",
            },
        };
        var dev = Parse(payload).RootElement.GetProperty("device");
        Assert.False(dev.TryGetProperty("hw_model", out _));
    }

    // -------------------------------------------------------------------------
    // PAT-685: hardware_health section
    // -------------------------------------------------------------------------

    /// <summary>
    /// hardware_health is absent when null (WhenWritingNull), matching the server
    /// contract that treats the field as optional for backwards compat.
    /// </summary>
    [Fact]
    public void Payload_HardwareHealth_Null_OmittedFromJson()
    {
        var root = Parse(MakePayload()).RootElement;
        // MakePayload() does not set HardwareHealth → field must be absent.
        Assert.False(root.TryGetProperty("hardware_health", out _));
    }

    private static readonly InventoryHardwareCollectionStatus AllComplete = new()
    {
        Battery = HardwareCollectionStatus.Complete,
        Storage = HardwareCollectionStatus.Complete,
        Disks   = HardwareCollectionStatus.Complete,
    };

    /// <summary>
    /// PAT-1720: collection_status is always written with exactly the three lowercase
    /// section keys and lowercase values the platform contract defines.
    /// </summary>
    [Fact]
    public void Payload_HardwareHealth_CollectionStatus_KeyNamesAndValues_Match()
    {
        var payload = MakePayload() with
        {
            HardwareHealth = new InventoryHardwareHealth
            {
                Battery = new InventoryBattery { Present = false },
                Storage = [],
                Disks   = [],
                CollectionStatus = new InventoryHardwareCollectionStatus
                {
                    Battery = HardwareCollectionStatus.Unavailable,
                    Storage = HardwareCollectionStatus.Complete,
                    Disks   = HardwareCollectionStatus.Partial,
                },
            },
        };
        var health = Parse(payload).RootElement.GetProperty("hardware_health");

        Assert.Equal(
            new[] { "battery", "collection_status", "disks", "storage" },
            health.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray());

        var status = health.GetProperty("collection_status");
        Assert.Equal(
            new[] { "battery", "disks", "storage" },
            status.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray());
        Assert.Equal("unavailable", status.GetProperty("battery").GetString());
        Assert.Equal("complete",    status.GetProperty("storage").GetString());
        Assert.Equal("partial",     status.GetProperty("disks").GetString());
    }

    [Fact]
    public void Payload_HardwareHealth_NoBattery_SerialisesPresentFalse()
    {
        var payload = MakePayload() with
        {
            HardwareHealth = new InventoryHardwareHealth
            {
                Battery = new InventoryBattery { Present = false },
                Storage = [],
                Disks   = [],
                CollectionStatus = AllComplete,
            },
        };
        var root    = Parse(payload).RootElement;
        var health  = root.GetProperty("hardware_health");
        var battery = health.GetProperty("battery");

        Assert.False(battery.GetProperty("present").GetBoolean());
        // Null fields are omitted by WhenWritingNull — extractor treats absent == null.
        Assert.False(battery.TryGetProperty("cycle_count",     out _));
        Assert.False(battery.TryGetProperty("condition",       out _));
        Assert.False(battery.TryGetProperty("max_capacity_pct", out _));
    }

    [Fact]
    public void Payload_HardwareHealth_WithBattery_SerialisesAllFields()
    {
        var payload = MakePayload() with
        {
            HardwareHealth = new InventoryHardwareHealth
            {
                Battery = new InventoryBattery
                {
                    Present        = true,
                    CycleCount     = 187,
                    Condition      = "Normal",
                    MaxCapacityPct = 88,
                },
                Storage = [],
                Disks   = [],
                CollectionStatus = AllComplete,
            },
        };
        var battery = Parse(payload).RootElement
            .GetProperty("hardware_health")
            .GetProperty("battery");

        Assert.True(battery.GetProperty("present").GetBoolean());
        Assert.Equal(187,      battery.GetProperty("cycle_count").GetInt32());
        Assert.Equal("Normal", battery.GetProperty("condition").GetString());
        Assert.Equal(88,       battery.GetProperty("max_capacity_pct").GetInt32());
    }

    [Fact]
    public void Payload_HardwareHealth_StorageVolume_KeyNames_Match()
    {
        var payload = MakePayload() with
        {
            HardwareHealth = new InventoryHardwareHealth
            {
                Battery = new InventoryBattery { Present = false },
                Storage =
                [
                    new InventoryStorageVolume
                    {
                        Mount      = @"C:\",
                        TotalBytes = 512_110_190_592L,
                        FreeBytes  = 214_748_364_800L,
                        UsedPct    = 58,
                    },
                ],
                Disks = [],
                CollectionStatus = AllComplete,
            },
        };
        var vol = Parse(payload).RootElement
            .GetProperty("hardware_health")
            .GetProperty("storage")[0];

        Assert.Equal(@"C:\",             vol.GetProperty("mount").GetString());
        Assert.Equal(512_110_190_592L,   vol.GetProperty("total_bytes").GetInt64());
        Assert.Equal(214_748_364_800L,   vol.GetProperty("free_bytes").GetInt64());
        Assert.Equal(58,                 vol.GetProperty("used_pct").GetInt32());
    }

    [Fact]
    public void Payload_HardwareHealth_Disk_KeyNames_Match()
    {
        var payload = MakePayload() with
        {
            HardwareHealth = new InventoryHardwareHealth
            {
                Battery = new InventoryBattery { Present = false },
                Storage = [],
                Disks   =
                [
                    new InventoryDisk
                    {
                        Device      = "Samsung SSD 990 PRO 1TB",
                        SmartStatus = "Verified",
                        Internal    = true,
                        SolidState  = true,
                    },
                ],
                CollectionStatus = AllComplete,
            },
        };
        var disk = Parse(payload).RootElement
            .GetProperty("hardware_health")
            .GetProperty("disks")[0];

        Assert.Equal("Samsung SSD 990 PRO 1TB", disk.GetProperty("device").GetString());
        Assert.Equal("Verified",                disk.GetProperty("smart_status").GetString());
        Assert.True(disk.GetProperty("internal").GetBoolean());
        Assert.True(disk.GetProperty("solid_state").GetBoolean());
    }

    [Fact]
    public void Payload_HardwareHealth_ExternalHdd_InternalFalse_SolidStateFalse()
    {
        var payload = MakePayload() with
        {
            HardwareHealth = new InventoryHardwareHealth
            {
                Battery = new InventoryBattery { Present = false },
                Storage = [],
                Disks   =
                [
                    new InventoryDisk
                    {
                        Device      = "Seagate Expansion",
                        SmartStatus = "Failing",
                        Internal    = false,
                        SolidState  = false,
                    },
                ],
                CollectionStatus = AllComplete,
            },
        };
        var disk = Parse(payload).RootElement
            .GetProperty("hardware_health")
            .GetProperty("disks")[0];

        Assert.Equal("Failing", disk.GetProperty("smart_status").GetString());
        Assert.False(disk.GetProperty("internal").GetBoolean());
        Assert.False(disk.GetProperty("solid_state").GetBoolean());
    }

    // -------------------------------------------------------------------------
    // PAT-680: backup_status section
    // -------------------------------------------------------------------------

    /// <summary>backup_status is always present, unlike the optional hardware_health.</summary>
    [Fact]
    public void Payload_BackupStatus_DefaultsToNoBackup_ButFieldIsPresent()
    {
        var root = Parse(MakePayload()).RootElement;
        Assert.True(root.TryGetProperty("backup_status", out var status));
        Assert.False(status.GetProperty("has_backup").GetBoolean());
        Assert.False(status.GetProperty("stale").GetBoolean());
        Assert.False(status.GetProperty("sync_only").GetBoolean());
        Assert.False(status.TryGetProperty("backup_type", out _));
        Assert.False(status.TryGetProperty("last_backup_at", out _));
    }

    [Fact]
    public void Payload_BackupStatus_FileHistory_SerialisesAllFields()
    {
        var payload = MakePayload(backupStatus: new InventoryBackupStatus
        {
            HasBackup         = true,
            BackupType        = "file_history",
            LastBackupAt      = "2026-07-08T09:00:00Z",
            LastBackupDaysAgo = 2,
            Stale             = false,
            SyncOnly          = false,
        });
        var status = Parse(payload).RootElement.GetProperty("backup_status");

        Assert.True(status.GetProperty("has_backup").GetBoolean());
        Assert.Equal("file_history", status.GetProperty("backup_type").GetString());
        Assert.Equal("2026-07-08T09:00:00Z", status.GetProperty("last_backup_at").GetString());
        Assert.Equal(2, status.GetProperty("last_backup_days_ago").GetInt32());
        Assert.False(status.GetProperty("stale").GetBoolean());
        Assert.False(status.GetProperty("sync_only").GetBoolean());
    }

    [Fact]
    public void Payload_BackupStatus_StaleFileHistory_SerialisesStaleTrue()
    {
        var payload = MakePayload(backupStatus: new InventoryBackupStatus
        {
            HasBackup         = true,
            BackupType        = "file_history",
            LastBackupAt      = "2026-12-01T09:00:00Z",
            LastBackupDaysAgo = 39,
            Stale             = true,
            SyncOnly          = false,
        });
        var status = Parse(payload).RootElement.GetProperty("backup_status");
        Assert.True(status.GetProperty("stale").GetBoolean());
    }

    /// <summary>OneDrive is sync, not backup — has_backup stays false while sync_only is true.</summary>
    [Fact]
    public void Payload_BackupStatus_OneDrive_SyncOnlyTrue_HasBackupFalse()
    {
        var payload = MakePayload(backupStatus: new InventoryBackupStatus
        {
            HasBackup  = false,
            BackupType = "onedrive_sync",
            SyncOnly   = true,
            Notes      = "OneDrive sync detected; sync is not a substitute for backup",
        });
        var status = Parse(payload).RootElement.GetProperty("backup_status");

        Assert.False(status.GetProperty("has_backup").GetBoolean());
        Assert.Equal("onedrive_sync", status.GetProperty("backup_type").GetString());
        Assert.True(status.GetProperty("sync_only").GetBoolean());
        Assert.False(status.TryGetProperty("last_backup_at", out _));
        Assert.False(status.TryGetProperty("last_backup_days_ago", out _));
    }

    [Fact]
    public void Payload_BackupStatus_ThirdParty_NoTimestamp_NotesPresent()
    {
        var payload = MakePayload(backupStatus: new InventoryBackupStatus
        {
            HasBackup  = true,
            BackupType = "acronis",
            Notes      = "acronis detected; last backup timestamp not available",
        });
        var status = Parse(payload).RootElement.GetProperty("backup_status");

        Assert.True(status.GetProperty("has_backup").GetBoolean());
        Assert.Equal("acronis", status.GetProperty("backup_type").GetString());
        Assert.False(status.TryGetProperty("last_backup_at", out _));
        Assert.Equal("acronis detected; last backup timestamp not available",
            status.GetProperty("notes").GetString());
    }

    // -------------------------------------------------------------------------
    // PAT-827: browser_extensions[] section
    // -------------------------------------------------------------------------

    /// <summary>browser_extensions[] is always present, unlike the optional hardware_health.</summary>
    [Fact]
    public void Payload_BrowserExtensions_Empty_Serialised_AsEmptyArray()
    {
        var root = Parse(MakePayload()).RootElement;
        Assert.True(root.TryGetProperty("browser_extensions", out var arr));
        Assert.Equal(JsonValueKind.Array, arr.ValueKind);
        Assert.Equal(0, arr.GetArrayLength());
    }

    [Fact]
    public void Payload_BrowserExtensions_SingleEntry_KeyNames_Match()
    {
        var exts = new List<InventoryBrowserExtension>
        {
            new()
            {
                Browser         = "chrome",
                Profile         = "Default",
                UserAccount     = "DESKTOP-TEST\\alice",
                ExtensionId     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                Name            = "uBlock Origin",
                Version         = "1.55.0",
                Enabled         = true,
                Permissions     = ["storage", "webRequest"],
                HostPermissions = ["<all_urls>"],
                FromWebstore    = true,
                UpdateUrl       = "https://clients2.google.com/service/update2/crx",
            },
        };
        var arr = Parse(MakePayload(browserExtensions: exts)).RootElement.GetProperty("browser_extensions");
        Assert.Equal(1, arr.GetArrayLength());
        var ext = arr[0];
        Assert.Equal("chrome",        ext.GetProperty("browser").GetString());
        Assert.Equal("Default",       ext.GetProperty("profile").GetString());
        Assert.Equal("DESKTOP-TEST\\alice", ext.GetProperty("user_account").GetString());
        Assert.Equal("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ext.GetProperty("extension_id").GetString());
        Assert.Equal("uBlock Origin", ext.GetProperty("name").GetString());
        Assert.Equal("1.55.0",       ext.GetProperty("version").GetString());
        Assert.True(ext.GetProperty("enabled").GetBoolean());
        Assert.Equal(2, ext.GetProperty("permissions").GetArrayLength());
        Assert.Equal(1, ext.GetProperty("host_permissions").GetArrayLength());
        Assert.True(ext.GetProperty("from_webstore").GetBoolean());
        Assert.Equal("https://clients2.google.com/service/update2/crx", ext.GetProperty("update_url").GetString());
    }

    [Fact]
    public void Payload_BrowserExtensions_NullUpdateUrl_OmittedFromJson()
    {
        var exts = new List<InventoryBrowserExtension>
        {
            new()
            {
                Browser         = "firefox",
                Profile         = "abc123.default-release",
                UserAccount     = "S-1-5-21-1-2-3-1001",
                ExtensionId     = "{addon-guid}",
                Name            = "Bitwarden",
                Version         = "2024.6.2",
                Enabled         = false,
                Permissions     = [],
                HostPermissions = [],
                FromWebstore    = false,
            },
        };
        var ext = Parse(MakePayload(browserExtensions: exts)).RootElement
            .GetProperty("browser_extensions")[0];
        Assert.False(ext.TryGetProperty("update_url", out _));
        Assert.False(ext.GetProperty("enabled").GetBoolean());
        Assert.False(ext.GetProperty("from_webstore").GetBoolean());
        // SID fallback (account translation failed) still lands in user_account.
        Assert.Equal("S-1-5-21-1-2-3-1001", ext.GetProperty("user_account").GetString());
    }

    // -------------------------------------------------------------------------
    // PAT-1066: agent_health section — the absent-vs-present-empty distinction
    // is load-bearing (go-service/docs/PAYLOAD_SCHEMA.md): absent means "no
    // opinion" (server leaves existing device_agent_health rows untouched);
    // present with degraded: [] means an explicit all-clear (server deletes
    // every existing row for the device). AgentHealth follows the same
    // nullable + JsonIgnore(WhenWritingNull) convention as HardwareHealth, NOT
    // the always-present convention BackupStatus/BrowserExtensions use.
    // -------------------------------------------------------------------------

    [Fact]
    public void Payload_AgentHealth_Null_OmittedFromJson()
    {
        var root = Parse(MakePayload()).RootElement;
        // MakePayload() does not set AgentHealth -> the key must be entirely
        // absent, not present with a null value.
        Assert.False(root.TryGetProperty("agent_health", out _));
    }

    [Fact]
    public void Payload_AgentHealth_PresentWithEmptyDegraded_SerialisesAsExplicitAllClear()
    {
        var payload = MakePayload(agentHealth: new InventoryAgentHealth { Degraded = [] });
        var root    = Parse(payload).RootElement;

        Assert.True(root.TryGetProperty("agent_health", out var health));
        Assert.True(health.TryGetProperty("degraded", out var degraded));
        Assert.Equal(JsonValueKind.Array, degraded.ValueKind);
        Assert.Equal(0, degraded.GetArrayLength());
    }

    [Fact]
    public void Payload_AgentHealth_DegradedEntry_KeyNames_And_Values_Match()
    {
        var entry = new InventoryAgentHealthEntry
        {
            Kind          = "capability_missing",
            Subject       = "package_engine",
            Reason        = "no_engine_available",
            FirstSeen     = "2026-07-01T09:00:00Z",
            LastSeen      = "2026-07-28T09:00:00Z",
            Count         = 42,
            EverSucceeded = false,
        };
        var payload = MakePayload(agentHealth: new InventoryAgentHealth { Degraded = [entry] });
        var root    = Parse(payload).RootElement;

        var degraded = root.GetProperty("agent_health").GetProperty("degraded");
        Assert.Equal(1, degraded.GetArrayLength());
        var e = degraded[0];
        Assert.Equal("capability_missing",    e.GetProperty("kind").GetString());
        Assert.Equal("package_engine",        e.GetProperty("subject").GetString());
        Assert.Equal("no_engine_available",   e.GetProperty("reason").GetString());
        Assert.Equal("2026-07-01T09:00:00Z",  e.GetProperty("first_seen").GetString());
        Assert.Equal("2026-07-28T09:00:00Z",  e.GetProperty("last_seen").GetString());
        Assert.Equal(42,                      e.GetProperty("count").GetInt32());
        Assert.False(e.GetProperty("ever_succeeded").GetBoolean());
    }

    [Fact]
    public void Payload_AgentHealth_MultipleDegradedEntries_AllSerialised()
    {
        var entries = new List<InventoryAgentHealthEntry>
        {
            new()
            {
                Kind = "capability_missing", Subject = "package_engine",
                Reason = "no_engine_available",
                FirstSeen = "2026-07-01T09:00:00Z", LastSeen = "2026-07-28T09:00:00Z",
                Count = 3, EverSucceeded = false,
            },
            new()
            {
                Kind = "directive_skipped", Subject = "device_removal",
                Reason = "no_device_id",
                FirstSeen = "2026-07-02T09:00:00Z", LastSeen = "2026-07-27T09:00:00Z",
                Count = 1, EverSucceeded = true,
            },
        };
        var payload = MakePayload(agentHealth: new InventoryAgentHealth { Degraded = entries });
        var degraded = Parse(payload).RootElement.GetProperty("agent_health").GetProperty("degraded");

        Assert.Equal(2, degraded.GetArrayLength());
        Assert.Equal("capability_missing", degraded[0].GetProperty("kind").GetString());
        Assert.Equal("directive_skipped",  degraded[1].GetProperty("kind").GetString());
        Assert.True(degraded[1].GetProperty("ever_succeeded").GetBoolean());
    }

    // ------------------------------------------------------------------ PAT-1959
    //
    // The platform side is being written against these three names in parallel, so they
    // are asserted here byte for byte, at the top level of the payload, in the exact
    // wire format InventoryPoster sends. A rename anywhere in the record would leave the
    // agent reporting into a key the server never reads, and the symptom of that is a
    // whole estate quietly classed unknown rather than an error anyone sees.

    [Fact]
    public void Payload_DeviceClassFields_UseTheExactContractNames()
    {
        var root = Parse(MakePayload(
            deviceClass:      DeviceClassValue.Server,
            installationType: InstallationTypeValue.ServerCore,
            osCaption:        "Microsoft Windows Server 2022 Standard")).RootElement;

        Assert.Equal("server",      root.GetProperty("device_class").GetString());
        Assert.Equal("Server Core", root.GetProperty("installation_type").GetString());
        Assert.Equal("Microsoft Windows Server 2022 Standard",
                     root.GetProperty("os_caption").GetString());
    }

    [Theory]
    [InlineData(DeviceClassValue.Workstation,      "workstation")]
    [InlineData(DeviceClassValue.Server,           "server")]
    [InlineData(DeviceClassValue.DomainController, "domain_controller")]
    [InlineData(DeviceClassValue.Unknown,          "unknown")]
    public void Payload_DeviceClass_SerialisesLowercaseOnTheWire(string value, string expected)
    {
        var root = Parse(MakePayload(deviceClass: value)).RootElement;
        Assert.Equal(JsonValueKind.String, root.GetProperty("device_class").ValueKind);
        Assert.Equal(expected, root.GetProperty("device_class").GetString());
    }

    /// <summary>
    /// "unknown" is a real reading that has to reach the server, not a stand-in for a
    /// field the agent chose to leave out.
    /// </summary>
    [Fact]
    public void Payload_UnknownDeviceClass_IsSentRatherThanOmitted()
    {
        var root = Parse(MakePayload(deviceClass: DeviceClassValue.Unknown)).RootElement;
        Assert.True(root.TryGetProperty("device_class", out var deviceClass));
        Assert.Equal("unknown", deviceClass.GetString());
    }

    /// <summary>
    /// Additive and optional, both ways round: an agent with nothing to say omits the
    /// keys, which is exactly what an agent older than 0.15.0 and the macOS collector
    /// both send. Neither may serialise as null or as an empty string, because the
    /// server reads absence as "class unknown" and an empty string is not one of the
    /// four values.
    /// </summary>
    [Fact]
    public void Payload_DeviceClassFields_AreOmittedWhenThereIsNothingToSay()
    {
        var root = Parse(MakePayload()).RootElement;
        Assert.False(root.TryGetProperty("device_class",      out _));
        Assert.False(root.TryGetProperty("installation_type", out _));
        Assert.False(root.TryGetProperty("os_caption",        out _));
    }

    /// <summary>
    /// The two evidence strings are independent of the class: a machine can report a
    /// class with no caption, or a caption with no installation type.
    /// </summary>
    [Fact]
    public void Payload_DeviceClassFields_AreIndependentlyOmittable()
    {
        var root = Parse(MakePayload(
            deviceClass: DeviceClassValue.Workstation,
            osCaption:   "Microsoft Windows 11 Pro")).RootElement;

        Assert.Equal("workstation", root.GetProperty("device_class").GetString());
        Assert.False(root.TryGetProperty("installation_type", out _));
        Assert.Equal("Microsoft Windows 11 Pro", root.GetProperty("os_caption").GetString());
    }

    /// <summary>
    /// The fields sit flat on the payload, not inside the os object, and adding them
    /// changes nothing else about the schema v3 shape.
    /// </summary>
    [Fact]
    public void Payload_DeviceClassFields_AreTopLevelAndLeaveTheOsObjectUntouched()
    {
        var root = Parse(MakePayload(
            deviceClass:      DeviceClassValue.Workstation,
            installationType: InstallationTypeValue.Client,
            osCaption:        "Microsoft Windows 11 Pro")).RootElement;

        var os = root.GetProperty("os");
        Assert.False(os.TryGetProperty("device_class",      out _));
        Assert.False(os.TryGetProperty("installation_type", out _));
        Assert.False(os.TryGetProperty("os_caption",        out _));
        Assert.False(os.TryGetProperty("caption",           out _));

        Assert.Equal("Windows",         os.GetProperty("name").GetString());
        Assert.Equal("10.0.22631.3880", os.GetProperty("version").GetString());
        Assert.Equal("22631",           os.GetProperty("build").GetString());
        Assert.Equal(3, root.GetProperty("schema_version").GetInt32());
    }

    // -------------------------------------------------------------------------
    // PAT-1974: top-level local_admins
    // -------------------------------------------------------------------------

    private static InventoryPayload PayloadFrom(LocalAdminCollectionResult result) =>
        MakePayload() with
        {
            LocalAdmins = result.Payload,
            Compliance  = new Dictionary<string, object> { ["local_admin_count"] = result.CountSignal },
        };

    private static LocalAdminMemberReading Admin(string name, string sid, int usage) =>
        new() { Name = name, Sid = sid, SidUsage = usage };

    [Fact]
    public void Payload_LocalAdmins_Complete_ExactKeyNamesAndValues()
    {
        var result = LocalAdminLogic.Collect(() => new[]
        {
            Admin(@"WIN-TEST\alice",         "S-1-5-21-1-2-3-1001", 1),
            Admin(@"CONTOSO\Domain Admins",  "S-1-5-21-9-9-9-512",  2),
        });

        var root = Parse(PayloadFrom(result)).RootElement;
        var admins = root.GetProperty("local_admins");

        Assert.Equal(
            new[] { "collection_status", "accounts" },
            admins.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal("complete", admins.GetProperty("collection_status").GetString());

        var accounts = admins.GetProperty("accounts").EnumerateArray().ToArray();
        Assert.Equal(2, accounts.Length);
        Assert.Equal(
            new[] { "name", "principal_type", "builtin", "sid" },
            accounts[0].EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal(@"WIN-TEST\alice", accounts[0].GetProperty("name").GetString());
        Assert.Equal("user",            accounts[0].GetProperty("principal_type").GetString());
        Assert.False(accounts[0].GetProperty("builtin").GetBoolean());
        Assert.Equal("group",           accounts[1].GetProperty("principal_type").GetString());

        // The count stays a scalar in the flat compliance bag, and excludes the group.
        Assert.Equal(1, root.GetProperty("compliance").GetProperty("local_admin_count").GetInt32());
    }

    /// <summary>
    /// A failed enumeration must never reach the wire as "accounts": [] with a 0 count —
    /// that is a claim the device has no standing admins, not an admission it could not
    /// look.
    /// </summary>
    [Fact]
    public void Payload_LocalAdminsUnavailable_OmitsAccountsKey_AndCountIsUnknown()
    {
        var json = JsonSerializer.Serialize(PayloadFrom(LocalAdminLogic.Unavailable()), Opts);
        var root = JsonDocument.Parse(json).RootElement;

        var admins = root.GetProperty("local_admins");
        Assert.Equal("unavailable", admins.GetProperty("collection_status").GetString());
        Assert.False(admins.TryGetProperty("accounts", out _));
        Assert.DoesNotContain("\"accounts\":[", json);

        var count = root.GetProperty("compliance").GetProperty("local_admin_count");
        Assert.Equal(JsonValueKind.String, count.ValueKind);
        Assert.Equal("Unknown", count.GetString());
    }

    /// <summary>
    /// PAT-1988 / PAT-1992: the built-in Administrator's enabled state is on the wire as
    /// local_admins.accounts[].account_state. The server validates the key name exactly and
    /// enum-checks the value against enabled|disabled|unknown, so both are pinned here as
    /// literals rather than via the constants they are meant to match.
    /// </summary>
    [Theory]
    [InlineData(false, false, "enabled")]
    [InlineData(true,  false, "disabled")]
    [InlineData(false, true,  "unknown")]
    public void Payload_LocalAdmins_BuiltinAccountState_IsOnTheWire(
        bool disabled, bool readFails, string expected)
    {
        var result = LocalAdminLogic.Collect(
            () => new[] { Admin(@"WIN-TEST\Administrator", "S-1-5-21-1-2-3-500", 1) },
            readAccountState: _ => readFails
                ? LocalAccountStateRead.Failed
                : LocalAccountStateRead.Present(disabled: disabled));

        var json  = JsonSerializer.Serialize(PayloadFrom(result), Opts);
        var entry = JsonDocument.Parse(json).RootElement
            .GetProperty("local_admins").GetProperty("accounts")[0];

        Assert.Equal(
            new[] { "name", "principal_type", "builtin", "sid", "account_state" },
            entry.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal(expected, entry.GetProperty("account_state").GetString());
        Assert.Contains($"\"account_state\":\"{expected}\"", json);
        Assert.DoesNotContain("AccountState", json);
    }

    /// <summary>
    /// The three values are exactly the server's enum, lowercase. A casing or spelling drift
    /// here would have every built-in entry rejected by validate.go.
    /// </summary>
    [Fact]
    public void LocalAdminAccountState_Values_MatchServerEnumExactly()
    {
        Assert.Equal("enabled",  LocalAdminAccountState.Enabled);
        Assert.Equal("disabled", LocalAdminAccountState.Disabled);
        Assert.Equal("unknown",  LocalAdminAccountState.Unknown);
    }

    /// <summary>
    /// A null AccountState (every non-built-in entry, and a run given no reader) is omitted
    /// rather than written as "account_state": null, under the production options.
    /// </summary>
    [Fact]
    public void Payload_LocalAdmins_NullAccountState_IsOmitted()
    {
        var result = LocalAdminLogic.Collect(() => new[]
        {
            Admin(@"WIN-TEST\Administrator", "S-1-5-21-1-2-3-500",  1),
            Admin(@"WIN-TEST\alice",         "S-1-5-21-1-2-3-1001", 1),
        });
        Assert.All(result.Payload.Accounts!, a => Assert.Null(a.AccountState));

        var json = JsonSerializer.Serialize(PayloadFrom(result), Opts);

        Assert.DoesNotContain("account_state", json);
    }

    /// <summary>
    /// The null omission must hold without the serializer-wide WhenWritingNull default,
    /// which is why AccountState carries its own per-property condition: with default
    /// options a bare string? writes "account_state": null. This is the guard on that
    /// attribute; removing the condition turns it red.
    /// </summary>
    [Fact]
    public void Payload_LocalAdmins_NullAccountState_IsOmitted_WithDefaultSerializerOptions()
    {
        var result = LocalAdminLogic.Collect(
            () => new[]
            {
                Admin(@"WIN-TEST\Administrator", "S-1-5-21-1-2-3-500",  1),
                Admin(@"WIN-TEST\alice",         "S-1-5-21-1-2-3-1001", 1),
            },
            readAccountState: _ => LocalAccountStateRead.Present(disabled: true));

        var json    = JsonSerializer.Serialize(PayloadFrom(result));
        var entries = JsonDocument.Parse(json).RootElement
            .GetProperty("local_admins").GetProperty("accounts").EnumerateArray().ToArray();

        Assert.Equal("disabled", entries[0].GetProperty("account_state").GetString());
        Assert.False(entries[1].TryGetProperty("account_state", out _));
        Assert.DoesNotContain("\"account_state\":null", json);
        Assert.DoesNotContain("AccountState", json);
    }

    [Fact]
    public void Payload_LocalAdminsUnavailable_OmitsAccountsKey_WithDefaultSerializerOptions()
    {
        var json = JsonSerializer.Serialize(PayloadFrom(LocalAdminLogic.Unavailable()));
        Assert.DoesNotContain("\"accounts\"", json);
    }

    [Fact]
    public void Payload_LocalAdmins_UnresolvedSid_IsNamedByItsSid()
    {
        var result = LocalAdminLogic.Collect(() => new[]
        {
            new LocalAdminMemberReading { Name = null, Sid = "S-1-5-21-1-2-3-1777", SidUsage = 8 },
        });

        var admins = Parse(PayloadFrom(result)).RootElement.GetProperty("local_admins");
        var entry  = admins.GetProperty("accounts").EnumerateArray().Single();

        Assert.Equal("unresolved",          entry.GetProperty("principal_type").GetString());
        Assert.Equal("S-1-5-21-1-2-3-1777", entry.GetProperty("name").GetString());
        Assert.Equal("S-1-5-21-1-2-3-1777", entry.GetProperty("sid").GetString());
    }

    private JsonDocument Parse(InventoryPayload payload) =>
        JsonDocument.Parse(JsonSerializer.Serialize(payload, Opts));

    private static InventoryIdeExtensions PopulatedIdeExtensions() => new()
    {
        CollectionStatus = IdeCollectionStatus.Complete,
        Users = [new IdeUserRow { User = @"WIN-TEST\alice", UserId = "S-1-5-21-1-2-3-1001", CollectionStatus = IdeCollectionStatus.Complete, Profiles = 1 }],
        Profiles = [new IdeProfileRow { User = @"WIN-TEST\alice", Family = "vscode", Editor = "vscode", CollectionStatus = IdeCollectionStatus.Complete, ExtensionCount = 1 }],
        Extensions = [new InventoryIdeExtension { User = @"WIN-TEST\alice", Family = "vscode", Editor = "vscode", Id = "github.copilot", Version = "1.250.0" }],
    };

    /// <summary>
    /// PAT-2225: the ide_extensions block is on the wire, because the platform (PAT-2021)
    /// validates and ingests it. The payload carries the block exactly as it serialises on its
    /// own, so restoring [JsonIgnore] on InventoryPayload.IdeExtensions turns this red; that
    /// change must update this test in the same change. macOS pins the same line in
    /// test-ide-extensions.zsh.
    /// </summary>
    [Fact]
    public void Payload_IdeExtensions_IsOnTheWire()
    {
        var block = PopulatedIdeExtensions();
        var doc = Parse(MakePayload() with { IdeExtensions = block });

        Assert.True(doc.RootElement.TryGetProperty("ide_extensions", out var sent));
        Assert.Equal(JsonSerializer.Serialize(block, Opts), sent.GetRawText());
        Assert.Equal("github.copilot", sent.GetProperty("extensions")[0].GetProperty("id").GetString());
    }

    /// <summary>A payload built without the block (an agent path that never collected it) omits the key, which the platform reads as a no-op.</summary>
    [Fact]
    public void Payload_IdeExtensions_NullIsOmitted()
    {
        Assert.False(Parse(MakePayload()).RootElement.TryGetProperty("ide_extensions", out _));
    }

    /// <summary>
    /// The block itself serialises to the shape proposed to PAT-2021, so turning it on is
    /// only the [JsonIgnore] deletion: top-level keys in order, and a failed block omits
    /// extensions rather than sending [].
    /// </summary>
    [Fact]
    public void IdeExtensionsBlock_SerialisesToTheProposedShape()
    {
        var block = JsonDocument.Parse(JsonSerializer.Serialize(PopulatedIdeExtensions(), Opts)).RootElement;
        Assert.Equal(
            new[] { "collection_status", "truncated", "truncation_reason", "users", "profiles", "issues", "extensions" },
            block.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal(JsonValueKind.Null, block.GetProperty("truncation_reason").ValueKind);
        Assert.Equal(JsonValueKind.Null, block.GetProperty("profiles")[0].GetProperty("editor_version").ValueKind);

        var failed = JsonDocument.Parse(JsonSerializer.Serialize(
            new InventoryIdeExtensions { CollectionStatus = IdeCollectionStatus.Failed }, Opts)).RootElement;
        Assert.Equal("failed", failed.GetProperty("collection_status").GetString());
        Assert.False(failed.TryGetProperty("extensions", out _));
    }

    private static InventoryPackageManagers PopulatedPackageManagers() => new()
    {
        CollectionStatus = PackageCollectionStatus.Complete,
        Sources = PackageSource.All.ToDictionary(s => s, s => new PackageSourceSummary
        {
            CollectionStatus = s == PackageSource.NpmGlobal ? PackageCollectionStatus.Complete : PackageCollectionStatus.NotPresent,
            PackageCount = s == PackageSource.NpmGlobal ? 1 : 0,
            LocationCount = s == PackageSource.NpmGlobal ? 1 : 0,
        }),
        Users =
        [
            new PackageUserRow
            {
                User = @"WIN-TEST\alice", UserId = "S-1-5-21-1-2-3-1001", CollectionStatus = PackageCollectionStatus.Complete,
                Sources = new Dictionary<string, string> { ["npm_global"] = "complete", ["pip_user"] = "not_present", ["pipx"] = "not_present" },
            },
        ],
        Locations =
        [
            new PackageLocationRow
            {
                Source = PackageSource.NpmGlobal, Manager = "appdata", Scope = "user", User = @"WIN-TEST\alice",
                Path = @"C:\Users\alice\AppData\Roaming\npm", CollectionStatus = PackageCollectionStatus.Complete, PackageCount = 1,
            },
        ],
        Packages =
        [
            new InventoryPackage
            {
                Source = PackageSource.NpmGlobal, Manager = "appdata", Scope = "user", User = @"WIN-TEST\alice",
                Name = "@anthropic-ai/claude-code", Version = "2.0.1", MetadataStatus = "read",
            },
        ],
    };

    /// <summary>
    /// PAT-2225: the package_managers block is on the wire, because the platform (PAT-2021)
    /// validates and ingests it. The payload carries the block exactly as it serialises on its
    /// own, so restoring [JsonIgnore] on InventoryPayload.PackageManagers turns this red; that
    /// change must update this test in the same change. macOS pins the same line in
    /// test-package-managers.zsh.
    /// </summary>
    [Fact]
    public void Payload_PackageManagers_IsOnTheWire()
    {
        var block = PopulatedPackageManagers();
        var doc = Parse(MakePayload() with { PackageManagers = block });

        Assert.True(doc.RootElement.TryGetProperty("package_managers", out var sent));
        Assert.Equal(JsonSerializer.Serialize(block, Opts), sent.GetRawText());
        Assert.Contains("claude-code", sent.GetRawText());
    }

    /// <summary>A payload built without the block (an agent path that never collected it) omits the key, which the platform reads as a no-op.</summary>
    [Fact]
    public void Payload_PackageManagers_NullIsOmitted()
    {
        Assert.False(Parse(MakePayload()).RootElement.TryGetProperty("package_managers", out _));
    }

    /// <summary>
    /// The block itself serialises to the shape proposed to PAT-2021, key for key the same as
    /// macos/lib/package_managers.sh, so turning it on is only the [JsonIgnore] deletion. A
    /// failed block omits packages rather than sending [].
    /// </summary>
    [Fact]
    public void PackageManagersBlock_SerialisesToTheProposedShape()
    {
        var block = JsonDocument.Parse(JsonSerializer.Serialize(PopulatedPackageManagers(), Opts)).RootElement;
        Assert.Equal(
            new[] { "collection_status", "truncated", "truncation_reason", "sources", "users", "locations", "issues", "packages" },
            block.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal(new[] { "npm_global", "pip_user", "pipx" }, block.GetProperty("sources").EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal(
            new[] { "collection_status", "truncated", "package_count", "location_count" },
            block.GetProperty("sources").GetProperty("npm_global").EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal(
            new[] { "user", "user_id", "collection_status", "sources" },
            block.GetProperty("users")[0].EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal(
            new[] { "source", "manager", "scope", "user", "user_id", "path", "runtime_version", "interpreters", "collection_status", "package_count" },
            block.GetProperty("locations")[0].EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal(
            new[]
            {
                "source", "manager", "scope", "user", "user_id", "name", "version", "prefix", "runtime_version",
                "interpreter", "directory", "metadata_status", "pipx_app", "pipx_main",
            },
            block.GetProperty("packages")[0].EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal(JsonValueKind.Null, block.GetProperty("truncation_reason").ValueKind);
        Assert.Equal(JsonValueKind.Null, block.GetProperty("packages")[0].GetProperty("pipx_main").ValueKind);

        var failed = JsonDocument.Parse(JsonSerializer.Serialize(
            new InventoryPackageManagers { CollectionStatus = PackageCollectionStatus.Failed }, Opts)).RootElement;
        Assert.Equal("failed", failed.GetProperty("collection_status").GetString());
        Assert.False(failed.TryGetProperty("packages", out _));
    }

    private static InventoryLocalModels PopulatedLocalModels() => new()
    {
        CollectionStatus = PackageCollectionStatus.Complete,
        Runtimes = LocalModelRuntime.All.ToDictionary(r => r, r => new LocalRuntimeSummary
        {
            CollectionStatus = r == LocalModelRuntime.Ollama ? PackageCollectionStatus.Complete : PackageCollectionStatus.NotPresent,
            InstallationCount = r == LocalModelRuntime.Ollama ? 1 : 0,
            StoreCount = r == LocalModelRuntime.Ollama ? 1 : 0,
            ModelCount = r == LocalModelRuntime.Ollama ? 1 : 0,
            TotalBytes = r == LocalModelRuntime.Ollama ? 4_920_000_000 : 0,
        }),
        Totals = new LocalModelTotals { ModelCount = 1, TotalBytes = 4_920_000_000 },
        Users =
        [
            new LocalModelUserRow
            {
                User = @"WIN-TEST\alice", UserId = "S-1-5-21-1-2-3-1001", CollectionStatus = PackageCollectionStatus.Complete,
                Runtimes = new Dictionary<string, string> { ["ollama"] = "complete", ["lm_studio"] = "not_present", ["llama_cpp"] = "not_present" },
            },
        ],
        Installations =
        [
            new LocalRuntimeInstallation
            {
                Runtime = LocalModelRuntime.Ollama, Scope = "user", User = @"WIN-TEST\alice", Kind = "local_programs",
                Path = @"C:\Users\alice\AppData\Local\Programs\Ollama", Version = "0.12.3.0", VersionSource = "pe_version_resource",
            },
        ],
        Stores =
        [
            new LocalModelStore
            {
                Runtime = LocalModelRuntime.Ollama, Scope = "user", User = @"WIN-TEST\alice", Path = @"C:\Users\alice\.ollama\models",
                CollectionStatus = PackageCollectionStatus.Complete, ModelCount = 1, TotalBytes = 4_920_000_000,
            },
        ],
        Models =
        [
            new InventoryLocalModel
            {
                Runtime = LocalModelRuntime.Ollama, User = @"WIN-TEST\alice", StorePath = @"C:\Users\alice\.ollama\models",
                Name = "qwen3-privacy-marker", Tag = "8b", SizeBytes = 4_920_000_000, FileCount = 5, SizeSource = "manifest",
                MissingBlobs = 0, MetadataStatus = "read",
            },
        ],
    };

    /// <summary>
    /// PAT-2225: the local_models block is on the wire, because the platform (PAT-2021)
    /// validates and ingests it. The payload carries the block exactly as it serialises on its
    /// own, so restoring [JsonIgnore] on InventoryPayload.LocalModels turns this red; that
    /// change must update this test in the same change. macOS pins the same line in
    /// test-local-models.zsh.
    /// </summary>
    [Fact]
    public void Payload_LocalModels_IsOnTheWire()
    {
        var block = PopulatedLocalModels();
        var doc = Parse(MakePayload() with { LocalModels = block });

        Assert.True(doc.RootElement.TryGetProperty("local_models", out var sent));
        Assert.Equal(JsonSerializer.Serialize(block, Opts), sent.GetRawText());
        Assert.Contains("qwen3-privacy-marker", sent.GetRawText());
    }

    /// <summary>A payload built without the block (an agent path that never collected it) omits the key, which the platform reads as a no-op.</summary>
    [Fact]
    public void Payload_LocalModels_NullIsOmitted()
    {
        Assert.False(Parse(MakePayload()).RootElement.TryGetProperty("local_models", out _));
    }

    /// <summary>
    /// The block itself serialises to the shape proposed to PAT-2021, key for key the same as
    /// macos/lib/local_models.sh, so turning it on is only the [JsonIgnore] deletion. A failed
    /// block omits models rather than sending [].
    /// </summary>
    [Fact]
    public void LocalModelsBlock_SerialisesToTheProposedShape()
    {
        var block = JsonDocument.Parse(JsonSerializer.Serialize(PopulatedLocalModels(), Opts)).RootElement;
        string[] Keys(JsonElement e) => e.EnumerateObject().Select(p => p.Name).ToArray();
        Assert.Equal(
            new[] { "collection_status", "truncated", "truncation_reason", "runtimes", "totals", "users", "installations", "stores", "issues", "models" },
            Keys(block));
        Assert.Equal(new[] { "ollama", "lm_studio", "llama_cpp" }, Keys(block.GetProperty("runtimes")));
        Assert.Equal(
            new[] { "collection_status", "installation_count", "store_count", "model_count", "total_bytes" },
            Keys(block.GetProperty("runtimes").GetProperty("ollama")));
        Assert.Equal(new[] { "model_count", "total_bytes" }, Keys(block.GetProperty("totals")));
        Assert.Equal(new[] { "user", "user_id", "collection_status", "runtimes" }, Keys(block.GetProperty("users")[0]));
        Assert.Equal(
            new[] { "runtime", "scope", "user", "user_id", "kind", "path", "version", "version_source", "identifier" },
            Keys(block.GetProperty("installations")[0]));
        Assert.Equal(
            new[] { "runtime", "scope", "user", "user_id", "path", "collection_status", "model_count", "total_bytes" },
            Keys(block.GetProperty("stores")[0]));
        Assert.Equal(
            new[]
            {
                "runtime", "user", "user_id", "store_path", "name", "tag", "format", "size_bytes", "file_count",
                "size_source", "missing_blobs", "metadata_status",
            },
            Keys(block.GetProperty("models")[0]));
        Assert.Equal(JsonValueKind.Null, block.GetProperty("truncation_reason").ValueKind);
        Assert.Equal(JsonValueKind.Null, block.GetProperty("installations")[0].GetProperty("identifier").ValueKind);
        Assert.Equal(JsonValueKind.Null, block.GetProperty("models")[0].GetProperty("format").ValueKind);
        Assert.Equal(4_920_000_000, block.GetProperty("models")[0].GetProperty("size_bytes").GetInt64());

        var failed = JsonDocument.Parse(JsonSerializer.Serialize(
            new InventoryLocalModels { CollectionStatus = PackageCollectionStatus.Failed }, Opts)).RootElement;
        Assert.Equal("failed", failed.GetProperty("collection_status").GetString());
        Assert.False(failed.TryGetProperty("models", out _));
    }

    private static InventoryMcpServers PopulatedMcpServers() => new()
    {
        CollectionStatus = PackageCollectionStatus.Complete,
        Clients = McpClient.All.ToDictionary(c => c, c => new McpClientSummary
        {
            CollectionStatus = c == McpClient.Cursor ? PackageCollectionStatus.Complete : PackageCollectionStatus.NotPresent,
            ConfigCount = c == McpClient.Cursor ? 1 : 0,
            ServerCount = c == McpClient.Cursor ? 1 : 0,
        }),
        Totals = new McpServerTotals { ConfigCount = 1, ServerCount = 1 },
        Users =
        [
            new McpServerUserRow
            {
                User = @"WIN-TEST\alice", UserId = "S-1-5-21-1-2-3-1001", CollectionStatus = PackageCollectionStatus.Complete,
                Clients = McpClient.All.ToDictionary(c => c, c => c == McpClient.Cursor ? "complete" : "not_present"),
            },
        ],
        Configs =
        [
            new McpConfigRow
            {
                Client = McpClient.Cursor, User = @"WIN-TEST\alice", UserId = "S-1-5-21-1-2-3-1001",
                Path = @"C:\Users\alice\.cursor\mcp.json", CollectionStatus = PackageCollectionStatus.Complete, ServerCount = 1,
            },
        ],
        Servers =
        [
            new McpServerRow
            {
                Client = McpClient.Cursor, User = @"WIN-TEST\alice", UserId = "S-1-5-21-1-2-3-1001",
                ConfigPath = @"C:\Users\alice\.cursor\mcp.json", Scope = "user", Name = "mcp-privacy-marker",
                Transport = "stdio", TransportSource = "inferred", Executable = "npx", Runner = "npx",
                Package = "@modelcontextprotocol/server-filesystem", PackageStatus = "extracted", Host = null,
            },
        ],
    };

    /// <summary>
    /// PAT-2225: the mcp_servers block is on the wire, because the platform (PAT-2021)
    /// validates and ingests it. The payload carries the block exactly as it serialises on its
    /// own, so restoring [JsonIgnore] on InventoryPayload.McpServers turns this red; that
    /// change must update this test in the same change. macOS pins the same line in
    /// test-mcp-servers.zsh.
    /// </summary>
    [Fact]
    public void Payload_McpServers_IsOnTheWire()
    {
        var block = PopulatedMcpServers();
        var doc = Parse(MakePayload() with { McpServers = block });

        Assert.True(doc.RootElement.TryGetProperty("mcp_servers", out var sent));
        Assert.Equal(JsonSerializer.Serialize(block, Opts), sent.GetRawText());
        Assert.Contains("mcp-privacy-marker", sent.GetRawText());
    }

    /// <summary>A payload built without the block (an agent path that never collected it) omits the key, which the platform reads as a no-op.</summary>
    [Fact]
    public void Payload_McpServers_NullIsOmitted()
    {
        Assert.False(Parse(MakePayload()).RootElement.TryGetProperty("mcp_servers", out _));
    }

    /// <summary>
    /// The block serialises to the shape proposed to PAT-2021, key for key the same as
    /// macos/lib/mcp_servers.sh. A server row has exactly the allowed keys (PAT-2021's
    /// server-side guard rejects any other, such as args or env). A failed block omits servers
    /// rather than sending [].
    /// </summary>
    [Fact]
    public void McpServersBlock_SerialisesToTheProposedShape()
    {
        var block = JsonDocument.Parse(JsonSerializer.Serialize(PopulatedMcpServers(), Opts)).RootElement;
        string[] Keys(JsonElement e) => e.EnumerateObject().Select(p => p.Name).ToArray();
        Assert.Equal(
            new[] { "collection_status", "truncated", "truncation_reason", "clients", "totals", "users", "configs", "issues", "servers" },
            Keys(block));
        Assert.Equal(new[] { "claude_desktop", "cursor", "vscode", "windsurf", "claude_code" }, Keys(block.GetProperty("clients")));
        Assert.Equal(new[] { "collection_status", "config_count", "server_count" }, Keys(block.GetProperty("clients").GetProperty("cursor")));
        Assert.Equal(new[] { "config_count", "server_count" }, Keys(block.GetProperty("totals")));
        Assert.Equal(new[] { "user", "user_id", "collection_status", "clients" }, Keys(block.GetProperty("users")[0]));
        Assert.Equal(new[] { "client", "user", "user_id", "path", "collection_status", "server_count" }, Keys(block.GetProperty("configs")[0]));
        Assert.Equal(
            new[]
            {
                "client", "user", "user_id", "config_path", "scope", "name", "transport", "transport_source",
                "executable", "runner", "package", "package_status", "host",
            },
            Keys(block.GetProperty("servers")[0]));
        Assert.Equal(JsonValueKind.Null, block.GetProperty("truncation_reason").ValueKind);
        Assert.Equal(JsonValueKind.Null, block.GetProperty("servers")[0].GetProperty("host").ValueKind);

        var failed = JsonDocument.Parse(JsonSerializer.Serialize(
            new InventoryMcpServers { CollectionStatus = PackageCollectionStatus.Failed }, Opts)).RootElement;
        Assert.Equal("failed", failed.GetProperty("collection_status").GetString());
        Assert.False(failed.TryGetProperty("servers", out _));
    }
}
