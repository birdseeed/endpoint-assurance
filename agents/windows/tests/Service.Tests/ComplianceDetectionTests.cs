using Patched.Service;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-913 (Option B): unit tests for the pure compliance-detection classifiers
/// that feed StatusWriter.DetectComplianceFindings() — the controls_assessed list
/// InventoryPoster.BuildPayload emits.
///
/// The WMI probes themselves are Windows-only and untestable off-box, so the
/// decision logic is split out into ClassifyDiskEncryption / ClassifyRemovableStorage
/// which take the probe's raw result (null = the sub-check errored / could not
/// determine). The critical assertion mirrors the macOS harness: an erroring
/// sub-check DROPS its control from controls_assessed, so the server scores it
/// Unknown (fail-unknown on the critical disk rule) rather than a fabricated pass
/// or a fabricated violation. Control IDs match the macOS collector exactly
/// (disk_encryption_off, removable_storage_unencrypted) for platform parity.
/// </summary>
public sealed class ComplianceDetectionTests
{
    // ---- disk_encryption_off (BitLocker OS drive) ----

    [Fact]
    public void DiskEncryption_Protected_AssessedCleanNoFinding()
    {
        var (assessed, finding) = StatusWriter.ClassifyDiskEncryption(1); // ProtectionStatus 1 = Protected
        Assert.True(assessed);
        Assert.Null(finding);
    }

    [Fact]
    public void DiskEncryption_Unprotected_AssessedWithCriticalFinding()
    {
        var (assessed, finding) = StatusWriter.ClassifyDiskEncryption(0); // 0 = Unprotected
        Assert.True(assessed);
        Assert.NotNull(finding);
        Assert.Equal("disk_encryption_off", finding!.Id);
        Assert.Equal(ComplianceSeverity.Critical, finding.Severity);
    }

    [Fact]
    public void DiskEncryption_UnknownStatus_NotAssessedNoFinding()
    {
        // ProtectionStatus 2 = Unknown — not a determination, so drop the control
        // (matches the macOS "never fire on Unknown" rule).
        var (assessed, finding) = StatusWriter.ClassifyDiskEncryption(2);
        Assert.False(assessed);
        Assert.Null(finding);
    }

    [Fact]
    public void DiskEncryption_ProbeErrored_NotAssessedNoFinding()
    {
        // null = WMI unavailable / no C: EncryptableVolume row — sub-check errored.
        var (assessed, finding) = StatusWriter.ClassifyDiskEncryption(null);
        Assert.False(assessed);
        Assert.Null(finding);
    }

    // ---- removable_storage_unencrypted ----

    [Fact]
    public void RemovableStorage_RanNoVolumes_AssessedCleanNoFinding()
    {
        var (assessed, finding) = StatusWriter.ClassifyRemovableStorage(new List<ComplianceFindingVolume>());
        Assert.True(assessed);
        Assert.Null(finding);
    }

    [Fact]
    public void RemovableStorage_PlaintextVolume_AssessedWithMediumFinding()
    {
        var volumes = new List<ComplianceFindingVolume>
        {
            new()
            {
                MountPoint       = "E:\\",
                Filesystem       = "exFAT",
                EncryptionState  = "plaintext",
                ProvenanceSource = "Win32_DiskDrive",
            },
        };
        var (assessed, finding) = StatusWriter.ClassifyRemovableStorage(volumes);
        Assert.True(assessed);
        Assert.NotNull(finding);
        Assert.Equal("removable_storage_unencrypted", finding!.Id);
        Assert.Equal(ComplianceSeverity.Medium, finding.Severity);
        Assert.Equal(1, finding.Volumes!.Count);
    }

    [Fact]
    public void RemovableStorage_ProbeErrored_NotAssessedNoFinding()
    {
        // null = WMI enumeration threw — sub-check errored, drop the control.
        var (assessed, finding) = StatusWriter.ClassifyRemovableStorage(null);
        Assert.False(assessed);
        Assert.Null(finding);
    }

    // ---- end-to-end assembly of DetectComplianceFindings' two lists ----

    [Fact]
    public void ErroringSubCheck_DropsOnlyThatControl()
    {
        // Disk errored (null), removable ran clean ([]): only removable is attested,
        // no findings. Server then scores disk_encryption_off Unknown -> fail.
        var (diskAssessed, diskFinding)   = StatusWriter.ClassifyDiskEncryption(null);
        var (remAssessed,  remFinding)    = StatusWriter.ClassifyRemovableStorage(new List<ComplianceFindingVolume>());

        var assessed = new List<string>();
        if (diskAssessed) assessed.Add("disk_encryption_off");
        if (remAssessed)  assessed.Add("removable_storage_unencrypted");

        Assert.Equal(new[] { "removable_storage_unencrypted" }, assessed);
        Assert.Null(diskFinding);
        Assert.Null(remFinding);
    }
}
