using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Security;
using Xunit;
using Xunit.Abstractions;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2400: the order in which an untrusted staged object is taken off its path.
/// The decision tests script the file-system operations and run everywhere. The last
/// test builds the hostile case found on the Windows 11 proof machine (foreign owner,
/// protected DACL denying SYSTEM, Administrators and the caller) and needs Windows
/// and a token that holds SeTakeOwnership/SeBackup/SeRestore.
/// </summary>
public sealed class StagedObjectRemoverTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"patched-pat2400-remover-{Guid.NewGuid():N}");

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private sealed class ScriptedOps : IStagedObjectOps
    {
        public FileAttributes Kind = FileAttributes.Directory;
        public bool UnlinkDenied, RenameDeniedUntilReclaimed, RenameAlwaysDenied, ReclaimSucceeds;
        public int Quarantined;
        public List<string> Calls { get; } = [];
        private bool _gone, _reclaimed;

        public FileAttributes? Attributes(string path) => _gone ? null : Kind;

        public void Unlink(string path, bool isDirectory)
        {
            Calls.Add("unlink");
            if (UnlinkDenied && !_reclaimed) throw new UnauthorizedAccessException("denied");
            if (isDirectory && (Kind & FileAttributes.ReparsePoint) == 0 && !Empty) throw new IOException("not empty");
            _gone = true;
        }

        public bool Empty;

        public void Rename(string path, string destination)
        {
            Calls.Add("rename");
            // The proof machine reported a denied directory rename as IOException.
            if (RenameAlwaysDenied || (RenameDeniedUntilReclaimed && !_reclaimed)) throw new IOException("Access to the path is denied.");
            _gone = true;
        }

        public bool TakeOwnershipAndProtect(string path, bool isDirectory)
        {
            Calls.Add("reclaim");
            _reclaimed = ReclaimSucceeds;
            return ReclaimSucceeds;
        }

        public int CountQuarantined(string quarantineParent) => Quarantined;
    }

    private static string? Remove(ScriptedOps ops) =>
        new StagedObjectRemover(ops, NullLogger.Instance).Remove("/state/updates", "/state");

    [Fact]
    public void EmptyDirectoryOrLink_IsUnlinkedAndNothingElseIsTried()
    {
        var ops = new ScriptedOps { Empty = true };
        Assert.Null(Remove(ops));
        Assert.Equal(["unlink"], ops.Calls);
    }

    [Fact]
    public void DirectoryWithContents_IsRenamedAsideWithoutEscalating()
    {
        var ops = new ScriptedOps();
        Assert.Null(Remove(ops));
        Assert.Equal(["unlink", "rename"], ops.Calls);
    }

    [Fact]
    public void DeniedRename_EscalatesToTakeOwnershipThenRenames()
    {
        var ops = new ScriptedOps { UnlinkDenied = true, RenameDeniedUntilReclaimed = true, ReclaimSucceeds = true };
        Assert.Null(Remove(ops));
        Assert.Equal(["unlink", "rename", "reclaim", "rename"], ops.Calls);
    }

    [Fact]
    public void FailedEscalation_StaysClosedWithoutASecondRename()
    {
        var ops = new ScriptedOps { UnlinkDenied = true, RenameDeniedUntilReclaimed = true, ReclaimSucceeds = false };
        Assert.Equal("removal_failed", Remove(ops));
        Assert.Equal(["unlink", "rename", "reclaim"], ops.Calls);
    }

    [Fact]
    public void RenameStillDeniedAfterEscalation_StaysClosed()
    {
        var ops = new ScriptedOps { RenameAlwaysDenied = true, ReclaimSucceeds = true };
        Assert.Equal("removal_failed", Remove(ops));
        Assert.Equal(["unlink", "rename", "reclaim", "rename"], ops.Calls);
    }

    [Fact]
    public void ReparsePoint_IsOnlyEverUnlinked_NeverReAcledOrRenamed()
    {
        var ops = new ScriptedOps { Kind = FileAttributes.Directory | FileAttributes.ReparsePoint, UnlinkDenied = true, ReclaimSucceeds = true };
        Assert.Equal("removal_failed", Remove(ops));
        Assert.Equal(["unlink"], ops.Calls);
    }

    [Fact]
    public void DeniedFile_EscalatesThenIsDeleted()
    {
        var ops = new ScriptedOps { Kind = FileAttributes.Normal, UnlinkDenied = true, ReclaimSucceeds = true };
        Assert.Null(Remove(ops));
        Assert.Equal(["unlink", "reclaim", "unlink"], ops.Calls);
    }

    [Fact]
    public void QuarantineAtItsCap_RefusesAnotherWithADistinctReason()
    {
        var ops = new ScriptedOps { Quarantined = StagedObjectRemover.MaxQuarantined, ReclaimSucceeds = true };
        Assert.Equal("quarantine_full", Remove(ops));
        Assert.Equal(["unlink"], ops.Calls);

        var belowCap = new ScriptedOps { Quarantined = StagedObjectRemover.MaxQuarantined - 1 };
        Assert.Null(Remove(belowCap));
    }

    [Fact]
    public void RealOps_CountOnlyQuarantinedEntriesDirectlyUnderTheParent()
    {
        Directory.CreateDirectory(Path.Combine(_dir, StagedObjectRemover.QuarantinePrefix + "a", StagedObjectRemover.QuarantinePrefix + "nested"));
        Directory.CreateDirectory(Path.Combine(_dir, StagedObjectRemover.QuarantinePrefix + "b"));
        Directory.CreateDirectory(Path.Combine(_dir, "updates"));

        Assert.Equal(2, new WindowsStagedUpdateTrustVerifier(NullLogger.Instance).CountQuarantined(_dir));
    }

    // -------------------------------------------------------------------------
    // The privilege helper
    // -------------------------------------------------------------------------

    [Fact]
    public void OffWindows_PrivilegeHelperDoesNothingAndSaysSo()
    {
        if (OperatingSystem.IsWindows()) return;

        bool ran = false;
        Assert.False(PrivilegedReclaim.TryWithPrivileges([PrivilegedReclaim.TakeOwnership], () => ran = true));
        Assert.False(ran);
        Assert.False(PrivilegedReclaim.TryTakeOwnershipAndProtect(_dir, isDirectory: true, out string failure));
        Assert.Equal("not_windows", failure);
        Assert.False(new WindowsStagedUpdateTrustVerifier(NullLogger.Instance).TakeOwnershipAndProtect(_dir, isDirectory: true));
    }

    [Fact]
    public void Windows_HostileOwnerAndDenyDacl_IsReclaimedAndMovedAsideWithoutDescending()
    {
        if (!OperatingSystem.IsWindows()) return;

        string state = Path.Combine(_dir, "state");
        string updates = Path.Combine(state, "updates");
        string child = Path.Combine(updates, "planted");
        Directory.CreateDirectory(child);
        File.WriteAllText(Path.Combine(updates, "planted.txt"), "planted");

        // Case C from the installed proof: owner is a standard user, inheritance is cut,
        // and SYSTEM is denied everything. This process is not SYSTEM, so Administrators
        // and its own SID are denied too, or it would not be locked out the way the
        // service was.
        const string planter = "S-1-5-21-1004336348-1177238915-682003330-1001";
        string me = WindowsIdentity.GetCurrent().User!.Value;
        var hostile = new DirectorySecurity();
        hostile.SetSecurityDescriptorSddlForm(
            $"O:{planter}G:BAD:P(D;OICI;FA;;;SY)(D;OICI;FA;;;BA)(D;OICI;FA;;;{me})(A;OICI;FA;;;{planter})");
        bool built = PrivilegedReclaim.TryWithPrivileges(
            [PrivilegedReclaim.TakeOwnership, PrivilegedReclaim.Backup, PrivilegedReclaim.Restore],
            () => new DirectoryInfo(updates).SetAccessControl(hostile));
        if (!built)
        {
            output.WriteLine("SKIPPED: this token does not hold SeTakeOwnership/SeBackup/SeRestore (not elevated), " +
                             "so the hostile directory cannot be built. Nothing was asserted.");
            return;
        }

        try
        {
            var real = new WindowsStagedUpdateTrustVerifier(NullLogger.Instance);

            Assert.Equal("acl_unreadable", real.WhyUntrusted(updates, isDirectory: true));
            // The round-one failure: a plain rename is refused.
            var cheap = Record.Exception(() => Directory.Move(updates, updates + "-cheap-path"));
            Assert.True(cheap is IOException or UnauthorizedAccessException, "plain rename was not refused: " + cheap);

            Assert.Null(real.Remove(updates, state));

            Assert.False(Directory.Exists(updates));
            string quarantine = Assert.Single(Directory.GetDirectories(state));
            Assert.StartsWith(StagedObjectRemover.QuarantinePrefix, Path.GetFileName(quarantine));
            var owner = new DirectoryInfo(quarantine).GetAccessControl(AccessControlSections.Owner)
                .GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            Assert.True(owner!.IsWellKnown(WellKnownSidType.LocalSystemSid), "owner after reclaim: " + owner.Value);
            Assert.Null(SecureStagingDirectory.DescribeUntrusted(quarantine, isDirectory: true));
            // Both planted entries are still there: moved whole, not walked.
            Assert.Equal(2, Directory.GetFileSystemEntries(quarantine).Length);
        }
        finally
        {
            // The children still carry the inherited deny; reclaim each so the temp tree can go.
            foreach (string top in Directory.GetDirectories(state))
            {
                PrivilegedReclaim.TryTakeOwnershipAndProtect(top, isDirectory: true, out _);
                foreach (string entry in Directory.GetFileSystemEntries(top))
                    PrivilegedReclaim.TryTakeOwnershipAndProtect(entry, Directory.Exists(entry), out _);
            }
        }
    }
}
