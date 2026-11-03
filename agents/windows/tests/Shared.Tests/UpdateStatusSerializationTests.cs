using System.Text.Json;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// Verifies that the UpdateStatus contract serialises to the exact snake_case JSON
/// shape defined in contracts/update-status.schema.json and that round-trips preserve
/// all values.
/// </summary>
public sealed class UpdateStatusSerializationTests
{
    [Theory]
    [InlineData(OverallState.UpToDate,         "up_to_date")]
    [InlineData(OverallState.UpdatesAvailable, "updates_available")]
    [InlineData(OverallState.Updating,         "updating")]
    [InlineData(OverallState.Error,            "error")]
    [InlineData(OverallState.Unknown,          "unknown")]
    public void OverallState_SerializesAsSnakeCase(OverallState state, string expected)
    {
        var json = JsonSerializer.Serialize(state, ContractJsonOptions.Write);
        Assert.Equal($"\"{expected}\"", json);
    }

    [Theory]
    [InlineData(AppState.UpToDate,           "up_to_date")]
    [InlineData(AppState.UpdateAvailable,    "update_available")]
    [InlineData(AppState.Updating,           "updating")]
    [InlineData(AppState.Installed,          "installed")]
    [InlineData(AppState.VerificationFailed, "verification_failed")]
    [InlineData(AppState.Error,              "error")]
    [InlineData(AppState.NotInstalled,       "not_installed")]
    [InlineData(AppState.Unknown,            "unknown")]
    public void AppState_SerializesAsSnakeCase(AppState state, string expected)
    {
        var json = JsonSerializer.Serialize(state, ContractJsonOptions.Write);
        Assert.Equal($"\"{expected}\"", json);
    }

    [Theory]
    [InlineData(FailureReason.MissingExpectedSigner, "missing_expected_signer")]
    [InlineData(FailureReason.SignatureUntrusted,    "signature_untrusted")]
    [InlineData(FailureReason.SignerMismatch,        "signer_mismatch")]
    [InlineData(FailureReason.BlockedVersion,        "blocked_version")]
    [InlineData(FailureReason.BlockedVersionResolutionFailed, "blocked_version_resolution_failed")]
    [InlineData(FailureReason.Sha256Mismatch,        "sha256_mismatch")]
    public void FailureReason_SerializesAsSnakeCase(FailureReason reason, string expected)
    {
        var json = JsonSerializer.Serialize(reason, ContractJsonOptions.Write);
        Assert.Equal($"\"{expected}\"", json);
    }

    [Theory]
    [InlineData("installed",           AuditEventTypes.InstallCompleted)]
    [InlineData("already_current",     AuditEventTypes.VerificationPassed)]
    [InlineData("verification_failed", AuditEventTypes.VerificationFailed)]
    [InlineData("version_blocked",     AuditEventTypes.VersionBlocked)]
    [InlineData("error",               AuditEventTypes.InstallFailed)]
    [InlineData("update_available",    null)]
    public void AuditEventType_MapsEverySecurityRelevantUpdateAction(string lastAction, string? expected)
    {
        Assert.Equal(expected, AuditEventTypes.ForUpdateLastAction(lastAction));
    }

    [Fact]
    public void VersionBlockedAuditEvent_UsesTheRefusedCandidateVersion()
    {
        Assert.Equal("126.0.0", AuditEventTypes.VersionForUpdateLastAction(
            AuditEventTypes.VersionBlocked, "125.0.0", "126.0.0"));
        Assert.Equal("125.0.0", AuditEventTypes.VersionForUpdateLastAction(
            "installed", "125.0.0", "126.0.0"));
    }

    [Fact]
    public void VersionBlockedAuditEvent_QueuesTheFullWireContract()
    {
        var auditEvent = AuditEventTypes.ForUpdateEntry(new AppEntry
        {
            Label            = "googlechrome",
            Name             = "Google Chrome",
            InstalledVersion = "125.0.0",
            AvailableVersion = "126.0.0",
            State            = AppState.VerificationFailed,
            LastAction       = "version_blocked",
            FailureReason    = FailureReason.BlockedVersionResolutionFailed,
            VerifiedSigner   = "Google LLC",
        });

        Assert.NotNull(auditEvent);
        Assert.Equal(AuditEventTypes.VersionBlocked, auditEvent!.EventType);
        Assert.Equal("googlechrome", auditEvent.Label);
        Assert.Equal("126.0.0", auditEvent.Version);
        Assert.Equal("Google LLC", auditEvent.VerifiedSigner);
        Assert.Equal("blocked_version_resolution_failed", auditEvent.Reason);
        Assert.Equal("windows", auditEvent.Platform);

        var json = JsonSerializer.Serialize(auditEvent, ContractJsonOptions.Write);
        Assert.Contains("\"event_type\": \"version_blocked\"", json);
        Assert.Contains("\"reason\": \"blocked_version_resolution_failed\"", json);
    }

    [Fact]
    public void OverallState_DeserializesFromSnakeCase()
    {
        Assert.Equal(OverallState.UpdatesAvailable,
            JsonSerializer.Deserialize<OverallState>("\"updates_available\"", ContractJsonOptions.Read));
        Assert.Equal(OverallState.UpToDate,
            JsonSerializer.Deserialize<OverallState>("\"up_to_date\"", ContractJsonOptions.Read));
    }

    [Fact]
    public void AppState_DeserializesFromSnakeCase()
    {
        Assert.Equal(AppState.VerificationFailed,
            JsonSerializer.Deserialize<AppState>("\"verification_failed\"", ContractJsonOptions.Read));
        Assert.Equal(AppState.NotInstalled,
            JsonSerializer.Deserialize<AppState>("\"not_installed\"", ContractJsonOptions.Read));
    }

    [Fact]
    public void UpdateStatus_RoundTrips()
    {
        var status = new UpdateStatus
        {
            SchemaVersion = 1,
            GeneratedAt   = new DateTimeOffset(2026, 12, 11, 9, 0, 0, TimeSpan.Zero),
            OverallState  = OverallState.UpdatesAvailable,
            Apps          =
            [
                new AppEntry
                {
                    Label            = "googlechrome",
                    Name             = "Google Chrome",
                    State            = AppState.UpdateAvailable,
                    InstalledVersion = "125.0.0",
                    AvailableVersion = "126.0.0",
                    VerifiedSigner   = "Google LLC",
                },
            ],
        };

        var json  = JsonSerializer.Serialize(status, ContractJsonOptions.Write);
        var back  = JsonSerializer.Deserialize<UpdateStatus>(json, ContractJsonOptions.Read)!;

        Assert.Equal(1, back.SchemaVersion);
        Assert.Equal(OverallState.UpdatesAvailable, back.OverallState);
        Assert.Single(back.Apps);
        Assert.Equal("googlechrome",     back.Apps[0].Label);
        Assert.Equal(AppState.UpdateAvailable, back.Apps[0].State);
        Assert.Equal("Google LLC",       back.Apps[0].VerifiedSigner);
    }

    [Fact]
    public void UpdateStatus_NullFieldsOmittedInOutput()
    {
        var status = new UpdateStatus
        {
            SchemaVersion = 1,
            GeneratedAt   = DateTimeOffset.UtcNow,
            OverallState  = OverallState.UpToDate,
            Apps          = [],
        };

        var json = JsonSerializer.Serialize(status, ContractJsonOptions.Write);

        // Null-value fields (Device, LastRun, OsUpdate, Counts) must be absent.
        Assert.DoesNotContain("\"device\"", json);
        Assert.DoesNotContain("\"last_run\"", json);
        Assert.DoesNotContain("\"os_update\"", json);
    }

    [Fact]
    public void VerificationFailed_AppEntry_PreservesFailureReason()
    {
        var app = new AppEntry
        {
            Label         = "slack",
            Name          = "Slack",
            State         = AppState.VerificationFailed,
            FailureReason = FailureReason.SignerMismatch,
        };

        var json = JsonSerializer.Serialize(app, ContractJsonOptions.Write);
        var back = JsonSerializer.Deserialize<AppEntry>(json, ContractJsonOptions.Read)!;

        Assert.Equal(AppState.VerificationFailed,     back.State);
        Assert.Equal(FailureReason.SignerMismatch,     back.FailureReason);
    }

    // PAT-508/PAT-898: blocked-version kill switch. A refused blocked version is
    // reported with the shared verification_failed state (the representation the
    // macOS daemon uses), carrying failure_reason: blocked_version and
    // last_action: version_blocked. There is no separate version_blocked state:
    // the contract keeps one state for a refused install, platform-neutral.
    [Fact]
    public void BlockedVersion_AppEntry_UsesVerificationFailedState()
    {
        var app = new AppEntry
        {
            Label         = "riskyapp",
            Name          = "Risky App",
            State         = AppState.VerificationFailed,
            LastAction    = "version_blocked",
            FailureReason = FailureReason.BlockedVersion,
        };

        var json = JsonSerializer.Serialize(app, ContractJsonOptions.Write);
        var back = JsonSerializer.Deserialize<AppEntry>(json, ContractJsonOptions.Read)!;

        Assert.Contains("\"verification_failed\"", json);
        Assert.Contains("\"version_blocked\"",     json);
        Assert.Contains("\"blocked_version\"",      json);
        Assert.Equal(AppState.VerificationFailed,   back.State);
        Assert.Equal(FailureReason.BlockedVersion,  back.FailureReason);
        Assert.Equal("version_blocked",             back.LastAction);
    }

    [Fact]
    public void Sha256Mismatch_AppEntry_PreservesFailureReason()
    {
        var app = new AppEntry
        {
            Label         = "otherapp",
            Name          = "Other App",
            State         = AppState.VerificationFailed,
            FailureReason = FailureReason.Sha256Mismatch,
        };

        var json = JsonSerializer.Serialize(app, ContractJsonOptions.Write);
        var back = JsonSerializer.Deserialize<AppEntry>(json, ContractJsonOptions.Read)!;

        Assert.Equal(AppState.VerificationFailed, back.State);
        Assert.Equal(FailureReason.Sha256Mismatch, back.FailureReason);
    }

    // PAT-481: removable_storage_unencrypted finding contract tests

    [Fact]
    public void ComplianceFinding_RemovableStorage_RoundTrips()
    {
        var finding = new ComplianceFinding
        {
            Id       = "removable_storage_unencrypted",
            Severity = ComplianceSeverity.Medium,
            Volumes  =
            [
                new ComplianceFindingVolume
                {
                    MountPoint       = "E:",
                    Filesystem       = "FAT32",
                    EncryptionState  = "plaintext",
                    ProvenanceSource = "Win32_DiskDrive",
                },
            ],
        };

        var json = JsonSerializer.Serialize(finding, ContractJsonOptions.Write);
        var back = JsonSerializer.Deserialize<ComplianceFinding>(json, ContractJsonOptions.Read)!;

        Assert.Equal("removable_storage_unencrypted", back.Id);
        Assert.Equal(ComplianceSeverity.Medium, back.Severity);
        Assert.NotNull(back.Volumes);
        Assert.Single(back.Volumes);
        Assert.Equal("E:",             back.Volumes[0].MountPoint);
        Assert.Equal("FAT32",          back.Volumes[0].Filesystem);
        Assert.Equal("plaintext",      back.Volumes[0].EncryptionState);
        Assert.Equal("Win32_DiskDrive", back.Volumes[0].ProvenanceSource);
    }

    [Fact]
    public void ComplianceFinding_RemovableStorage_JsonShape()
    {
        var finding = new ComplianceFinding
        {
            Id       = "removable_storage_unencrypted",
            Severity = ComplianceSeverity.Medium,
            Volumes  =
            [
                new ComplianceFindingVolume
                {
                    MountPoint       = "F:",
                    Filesystem       = "exFAT",
                    EncryptionState  = "plaintext",
                    ProvenanceSource = "Win32_DiskDrive",
                },
            ],
        };

        // Serialise then normalise whitespace for portable key presence checks.
        var json = JsonSerializer.Serialize(finding, ContractJsonOptions.Write)
                                 .Replace(" ", "").Replace("\n", "").Replace("\r", "");

        Assert.Contains("\"id\":\"removable_storage_unencrypted\"", json);
        Assert.Contains("\"severity\":\"medium\"",                  json);
        Assert.Contains("\"mount_point\":\"F:\"",                   json);
        Assert.Contains("\"filesystem\":\"exFAT\"",                 json);
        Assert.Contains("\"encryption_state\":\"plaintext\"",       json);
        Assert.Contains("\"provenance_source\":\"Win32_DiskDrive\"", json);
    }

    [Fact]
    public void ComplianceFinding_DiskEncryptionOff_VolumesNull()
    {
        // disk_encryption_off finding must not have a volumes array.
        var finding = new ComplianceFinding
        {
            Id       = "disk_encryption_off",
            Severity = ComplianceSeverity.Critical,
        };

        var json = JsonSerializer.Serialize(finding, ContractJsonOptions.Write);
        var back = JsonSerializer.Deserialize<ComplianceFinding>(json, ContractJsonOptions.Read)!;

        Assert.Null(back.Volumes);
        Assert.DoesNotContain("\"volumes\"", json);
    }

    [Fact]
    public void UpdateStatus_WithRemovableStorageFinding_RoundTrips()
    {
        var status = new UpdateStatus
        {
            SchemaVersion      = 1,
            GeneratedAt        = new DateTimeOffset(2026, 12, 17, 10, 0, 0, TimeSpan.Zero),
            OverallState       = OverallState.UpToDate,
            Apps               = [],
            ComplianceFindings =
            [
                new ComplianceFinding
                {
                    Id       = "removable_storage_unencrypted",
                    Severity = ComplianceSeverity.Medium,
                    Volumes  =
                    [
                        new ComplianceFindingVolume
                        {
                            MountPoint       = "/Volumes/BACKUP",
                            Filesystem       = "msdos",
                            EncryptionState  = "plaintext",
                            ProvenanceSource = "diskutil",
                        },
                    ],
                },
            ],
        };

        var json = JsonSerializer.Serialize(status, ContractJsonOptions.Write);
        var back = JsonSerializer.Deserialize<UpdateStatus>(json, ContractJsonOptions.Read)!;

        Assert.NotNull(back.ComplianceFindings);
        Assert.Single(back.ComplianceFindings);
        var f = back.ComplianceFindings[0];
        Assert.Equal("removable_storage_unencrypted", f.Id);
        Assert.Equal(ComplianceSeverity.Medium,        f.Severity);
        Assert.NotNull(f.Volumes);
        Assert.Single(f.Volumes);
        Assert.Equal("/Volumes/BACKUP", f.Volumes[0].MountPoint);
        Assert.Equal("msdos",           f.Volumes[0].Filesystem);
        Assert.Equal("diskutil",        f.Volumes[0].ProvenanceSource);
    }
}
