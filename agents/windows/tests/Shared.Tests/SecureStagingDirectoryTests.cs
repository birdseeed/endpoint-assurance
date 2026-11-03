using System.Security.AccessControl;
using System.Security.Principal;
using Patched.Shared.Paths;
using Patched.Shared.Security;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// Tests for SecureStagingDirectory (PAT-857) — the ACL/reparse-point/ownership guard
/// that WingetCliEngine and ChocolateyEngine now stage downloads through instead of a
/// predictable path under Path.GetTempPath().
///
/// The ACL/reparse-point tests below do real Windows filesystem-security work and only
/// run meaningfully on Windows (the project's actual CI gate, windows-build.yml, is
/// windows-latest only); they no-op on other platforms so `dotnet test` still succeeds
/// if ever run locally on macOS/Linux. <see cref="StagingDir_IsNotUnderTempPath"/> is
/// plain string comparison and runs everywhere.
/// </summary>
public sealed class SecureStagingDirectoryTests : IDisposable
{
    private readonly string _root;

    public SecureStagingDirectoryTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"patched-securestaging-test-{Guid.NewGuid():N}");
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
                Directory.Delete(_root, recursive: true);
        }
        catch
        {
            // Best-effort cleanup; a leftover temp dir from a test run isn't worth failing over.
        }
    }

    // PAT-857 verification requirement: the resolved staging root must not live under
    // Path.GetTempPath() — that predictable, standard-user-writable location was the
    // whole root cause. Plain string comparison; runs on any OS.
    [Fact]
    public void StagingDir_IsNotUnderTempPath()
    {
        var tempRoot = Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        Assert.DoesNotContain(tempRoot, PathConstants.StagingDir, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateRandomSubdirectory_ReturnsDistinctHardenedDirectoriesUnderRoot()
    {
        if (!OperatingSystem.IsWindows()) return;

        var dir1 = SecureStagingDirectory.CreateRandomSubdirectory(_root);
        var dir2 = SecureStagingDirectory.CreateRandomSubdirectory(_root);

        Assert.True(Directory.Exists(dir1));
        Assert.True(Directory.Exists(dir2));
        Assert.NotEqual(dir1, dir2);
        Assert.StartsWith(_root, dir1, StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith(_root, dir2, StringComparison.OrdinalIgnoreCase);

        // A freshly created, hardened directory must pass its own trust check.
        SecureStagingDirectory.VerifyTrusted(dir1);
    }

    [Fact]
    public void EnsureHardened_NewDirectory_CreatesAndPassesVerification()
    {
        if (!OperatingSystem.IsWindows()) return;

        var dir = Path.Combine(_root, "fresh");
        SecureStagingDirectory.EnsureHardened(dir);

        Assert.True(Directory.Exists(dir));
        SecureStagingDirectory.VerifyTrusted(dir); // must not throw
    }

    // PAT-1223: assurance-tier devices (PAT-1599: formerly report_deploy) do not
    // necessarily reach package-download staging before a signed decommission
    // directive. The service therefore performs
    // this tier-independent bootstrap as its first state-directory operation. A fresh
    // install/missing state root must be created with the same trust boundary that
    // decommission staging later relies on.
    [Fact]
    public void StateDirectoryBootstrap_FreshStateDirectory_CreatesAndVerifiesProtectedRoot()
    {
        if (!OperatingSystem.IsWindows()) return;

        var stateDir = Path.Combine(_root, "Patched");
        Assert.False(StateDirectoryBootstrap.EnsureHardened(stateDir));

        Assert.True(Directory.Exists(stateDir));
        SecureStagingDirectory.VerifyTrusted(stateDir);

        // This is the operation the assurance tier must be able to reach: after the
        // tier-independent startup bootstrap, the decommission-specific chain can
        // create and harden its own child rather than relying on package staging.
        var decommissionDir = Path.Combine(stateDir, "decommission");
        SecureStagingDirectory.EnsureHardenedChain(decommissionDir, stateDir);
        SecureStagingDirectory.VerifyTrusted(decommissionDir);
    }

    // The MSI owns the normal pre-existing StateDir but can leave inherited ACEs in
    // place. A trusted owner does not make the existing writable contents safe.
    // Startup must refuse that legacy root and preserve its ACL for investigation.
    [Fact]
    public void StateDirectoryBootstrap_MsiOwnedRootWithInheritedWritableAce_RefusesWithoutMutation()
    {
        if (!OperatingSystem.IsWindows()) return;

        // Model %ProgramData% passing its write-capable ACE down into the MSI-created
        // Patched directory. The state root is then explicitly owned by Administrators,
        // a trusted owner whose writable legacy contents must still be refused.
        Directory.CreateDirectory(_root);
        var parentInfo = new DirectoryInfo(_root);
        var parentAcl = new DirectorySecurity();
        parentAcl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        parentAcl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        parentAcl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        parentAcl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        parentAcl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        parentInfo.SetAccessControl(parentAcl);

        var stateDir = Path.Combine(_root, "msi-created-state");
        Directory.CreateDirectory(stateDir);

        var info = new DirectoryInfo(stateDir);
        var stateOwner = info.GetAccessControl(AccessControlSections.Owner);
        stateOwner.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        info.SetAccessControl(stateOwner);

        var rules = info.GetAccessControl(AccessControlSections.Access).GetAccessRules(
            includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        Assert.Contains(rules.Cast<FileSystemAccessRule>(), rule =>
            rule.IsInherited &&
            ((SecurityIdentifier)rule.IdentityReference).IsWellKnown(WellKnownSidType.AuthenticatedUserSid) &&
            (rule.FileSystemRights & FileSystemRights.Modify) != 0);

        var before = info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
        Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(() =>
            StateDirectoryBootstrap.EnsureHardened(stateDir));
        Assert.Equal(before, info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
    }

    // DACL repair is intentionally unavailable to a credential ancestor or a directory
    // planted by a non-admin user: its untrusted owner is checked before any DACL is
    // changed, so service startup cannot upgrade that directory into a trusted root.
    [Fact]
    public void StateDirectoryBootstrap_AttackerOwnedRoot_ThrowsWithoutRepairingIt()
    {
        if (!OperatingSystem.IsWindows()) return;

        var stateDir = Path.Combine(_root, "attacker-controlled-state");
        Directory.CreateDirectory(stateDir);
        var info = new DirectoryInfo(stateDir);
        const AccessControlSections protectedState =
            AccessControlSections.Owner | AccessControlSections.Access;

        // windows-latest creates this directory as an Administrators-owned object, which
        // exercises the trusted-installer repair path rather than the planted-directory
        // rejection path. Model the attacker explicitly with the runner's user SID.
        var attackerSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Unable to determine the current Windows user SID.");
        Assert.False(attackerSid.IsWellKnown(WellKnownSidType.LocalSystemSid));
        Assert.False(attackerSid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));
        var ownerSecurity = info.GetAccessControl(AccessControlSections.Owner);
        ownerSecurity.SetOwner(attackerSid);
        info.SetAccessControl(ownerSecurity);

        string before = info.GetAccessControl(protectedState).GetSecurityDescriptorSddlForm(protectedState);

        Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(
            () => StateDirectoryBootstrap.EnsureHardened(stateDir));

        string after = info.GetAccessControl(protectedState).GetSecurityDescriptorSddlForm(protectedState);
        Assert.Equal(before, after);
    }

    [Fact]
    public void StateDirectoryBootstrap_PreExistingReparsePoint_ThrowsAndDoesNotTouchIt()
    {
        if (!OperatingSystem.IsWindows()) return;

        var target = Path.Combine(_root, "real-state-target");
        Directory.CreateDirectory(target);

        var stateDir = Path.Combine(_root, "planted-state-root");
        try
        {
            Directory.CreateSymbolicLink(stateDir, target);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return;
        }

        Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(
            () => StateDirectoryBootstrap.EnsureHardened(stateDir));
        Assert.True((File.GetAttributes(stateDir) & FileAttributes.ReparsePoint) != 0);
    }

    // PAT-1223: Program establishes the fixed installer log directory before the
    // Host and RollingFileLogger can use it. A junction planted during the old
    // inherited-write window must therefore stop startup rather than redirecting a
    // LocalSystem log write.
    [Fact]
    public void StateDirectoryBootstrap_PrePlantedLogsReparsePoint_IsRejectedBeforeLoggerSetup()
    {
        if (!OperatingSystem.IsWindows()) return;

        var stateDir = Path.Combine(_root, "Patched");
        StateDirectoryBootstrap.EnsureHardened(stateDir);
        var target = Path.Combine(_root, "real-log-target");
        Directory.CreateDirectory(target);
        var logsDir = Path.Combine(stateDir, "logs");
        try
        {
            Directory.CreateSymbolicLink(logsDir, target);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return;
        }

        Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(() =>
            SecureStagingDirectory.EnsureHardenedTrustedInstallerDirectory(logsDir));
        Assert.True((File.GetAttributes(logsDir) & FileAttributes.ReparsePoint) != 0);
    }

    // NOTE: a directory created via plain Directory.CreateDirectory (inheriting whatever
    // ACL its parent grants — e.g. broader access under a typical Temp folder) is
    // deliberately NOT the "pre-existing directory" shape this test wants: since the
    // non-author-review fix to VerifyTrusted (checking the effective DACL, not just
    // owner), such a directory correctly FAILS trust unless every inherited Allow ACE
    // already belongs to SYSTEM/Administrators. So "pre-existing" here means a
    // directory EnsureHardened already fully hardened on a prior call — this test
    // verifies calling it again on that already-trusted directory is idempotent, not
    // that any arbitrary pre-existing directory is waved through.
    [Fact]
    public void EnsureHardened_AlreadyHardenedDirectory_IsIdempotent()
    {
        if (!OperatingSystem.IsWindows()) return;

        var dir = Path.Combine(_root, "pre-existing");

        // First call creates + hardens it (the "doesn't exist yet" branch).
        SecureStagingDirectory.EnsureHardened(dir);

        // Second call must not throw: it already exists, so this exercises the
        // "pre-existing, verify without touching the ACL" branch against a directory
        // that's genuinely SYSTEM/Administrators-only.
        SecureStagingDirectory.EnsureHardened(dir);
    }

    // PAT-857 verification requirement: reject a staging path that already exists as a
    // reparse point/junction — the TOCTOU this whole fix exists to close. Uses a
    // symbolic link as the reparse-point vehicle (junctions and symlinks share the
    // FILE_ATTRIBUTE_REPARSE_POINT flag that IsReparsePoint checks). Creating a
    // directory symlink on Windows needs either Developer Mode or an elevated token;
    // if this environment has neither, skip rather than fail the run.
    [Fact]
    public void EnsureHardened_ExistingReparsePoint_ThrowsAndDoesNotTouchIt()
    {
        if (!OperatingSystem.IsWindows()) return;

        var target = Path.Combine(_root, "real-target");
        Directory.CreateDirectory(target);

        var link = Path.Combine(_root, "planted-link");
        try
        {
            Directory.CreateSymbolicLink(link, target);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            // Can't create symlinks without Developer Mode/elevation in this
            // environment — the reparse-point check itself is exercised on CI
            // (windows-latest, which permits this), so skip rather than fail here.
            return;
        }

        Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(
            () => SecureStagingDirectory.EnsureHardened(link));

        // Must not have been "fixed" in place: still a reparse point, still points
        // at the original target.
        Assert.True((File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0);
    }

    [Fact]
    public void VerifyTrusted_ExistingReparsePoint_Throws()
    {
        if (!OperatingSystem.IsWindows()) return;

        var target = Path.Combine(_root, "real-target-2");
        Directory.CreateDirectory(target);

        var link = Path.Combine(_root, "planted-link-2");
        try
        {
            Directory.CreateSymbolicLink(link, target);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return;
        }

        Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(
            () => SecureStagingDirectory.VerifyTrusted(link));
    }

    // PAT-857 code review finding: hardening only the leaf directory and trusting
    // inherited ACLs for everything above it leaves intermediate segments (e.g.
    // StagingDir/chocolatey) unhardened. EnsureHardenedChain must harden every level
    // from root down to the leaf, not just the leaf itself.
    [Fact]
    public void EnsureHardenedChain_HardensEveryIntermediateLevel()
    {
        if (!OperatingSystem.IsWindows()) return;

        var leaf = Path.Combine(_root, "a", "b", "c");
        SecureStagingDirectory.EnsureHardenedChain(leaf, _root);

        // Every level from _root down to the leaf must exist and independently pass
        // VerifyTrusted (i.e. each got its own explicit DACL, not just the leaf).
        SecureStagingDirectory.VerifyTrusted(_root);
        SecureStagingDirectory.VerifyTrusted(Path.Combine(_root, "a"));
        SecureStagingDirectory.VerifyTrusted(Path.Combine(_root, "a", "b"));
        SecureStagingDirectory.VerifyTrusted(leaf);
    }

    [Fact]
    public void EnsureHardenedChain_RootItself_HardensJustRoot()
    {
        if (!OperatingSystem.IsWindows()) return;

        SecureStagingDirectory.EnsureHardenedChain(_root, _root);
        SecureStagingDirectory.VerifyTrusted(_root);
    }

    [Fact]
    public void EnsureHardenedChain_DirOutsideRoot_Throws()
    {
        if (!OperatingSystem.IsWindows()) return;

        var outside = Path.Combine(Path.GetTempPath(), $"patched-outside-{Guid.NewGuid():N}");
        Assert.Throws<ArgumentException>(
            () => SecureStagingDirectory.EnsureHardenedChain(outside, _root));
    }

    // PAT-857 code review finding: CreateRandomSubdirectory makes a fresh GUID folder
    // on every call and nothing ever reclaimed it, growing %ProgramData% unbounded over
    // the service's lifetime (unlike the old %TEMP% path, which reused one folder per
    // package). A later call must purge stale siblings left by earlier ones.
    [Fact]
    public void CreateRandomSubdirectory_PurgesStaleSiblingsFromEarlierCalls()
    {
        if (!OperatingSystem.IsWindows()) return;

        var stale = SecureStagingDirectory.CreateRandomSubdirectory(_root);
        File.WriteAllText(Path.Combine(stale, "installer.exe"), "stale");

        // Back-date the stale directory so it looks old enough to purge.
        var oldTime = DateTime.UtcNow - TimeSpan.FromHours(2);
        Directory.SetLastWriteTimeUtc(stale, oldTime);

        var fresh = SecureStagingDirectory.CreateRandomSubdirectory(_root);

        Assert.False(Directory.Exists(stale));
        Assert.True(Directory.Exists(fresh));
    }

    [Fact]
    public void CreateRandomSubdirectory_KeepsRecentSiblings()
    {
        if (!OperatingSystem.IsWindows()) return;

        var recent = SecureStagingDirectory.CreateRandomSubdirectory(_root);
        var fresh  = SecureStagingDirectory.CreateRandomSubdirectory(_root);

        Assert.True(Directory.Exists(recent));
        Assert.True(Directory.Exists(fresh));
    }

    // Non-author security review finding (PAT-857 PR #295): a pre-existing directory
    // can be *owned* by SYSTEM/Administrators while still carrying an ACE that grants
    // some other principal (e.g. Authenticated Users) write access — inherited from a
    // permissive ancestor, or added by another process/admin after the fact. Checking
    // ownership alone would let VerifyTrusted wave through a directory a standard user
    // can still write into. This reproduces exactly that shape and asserts it's rejected.
    [Fact]
    public void VerifyTrusted_OwnedByAdminsButGrantsOtherPrincipalAccess_Throws()
    {
        if (!OperatingSystem.IsWindows()) return;

        var dir = Path.Combine(_root, "looks-trusted-but-isnt");
        Directory.CreateDirectory(dir);

        var info = new DirectoryInfo(dir);
        var acl  = new DirectorySecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));

        // Owner is Administrators (would pass the owner-only check), but Authenticated
        // Users still gets a real write grant via an extra ACE alongside it.
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            FileSystemRights.Modify,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow));
        info.SetAccessControl(acl);

        var ex = Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(
            () => SecureStagingDirectory.VerifyTrusted(dir));
        Assert.Contains("not SYSTEM or Administrators", ex.Message);
    }

    // PAT-857 non-author-review follow-up: once EnsureHardenedChain's anchor moved to
    // PathConstants.StateDir (%ProgramData%\Patched itself, not just its "staging"
    // child), the chain now includes a directory that — under %ProgramData%'s own
    // default Windows ACL — typically carries a benign inherited "Users: Read & Execute"
    // grant. A read-only Allow ACE for a non-admin principal is not a TOCTOU risk (it
    // can't be used to plant or swap a file) and must not fail-close an otherwise
    // correctly hardened directory.
    [Fact]
    public void VerifyTrusted_OwnedByAdminsWithReadOnlyGrantToOtherPrincipal_DoesNotThrow()
    {
        if (!OperatingSystem.IsWindows()) return;

        var dir = Path.Combine(_root, "read-only-grant-is-fine");
        Directory.CreateDirectory(dir);

        var info = new DirectoryInfo(dir);
        var acl  = new DirectorySecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));

        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        // BUILTIN\Users, read-only — no write-capable right at all.
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        info.SetAccessControl(acl);

        SecureStagingDirectory.VerifyTrusted(dir); // must not throw
    }

    // PAT-857 non-author-review finding (2nd round): a write-capable check built only
    // from named FileSystemRights members misses raw Windows GENERIC_WRITE/GENERIC_ALL
    // access-mask bits, which a stored on-disk ACE can carry directly. Production
    // VerifyTrusted reads rule.FileSystemRights from GetAccessRules, whose internal
    // AccessRuleFactory surfaces the raw access mask verbatim — unlike the PUBLIC
    // FileSystemAccessRule constructor, which validates and throws
    // ArgumentOutOfRangeException on generic bits. So the threat is genuinely reachable
    // by production, and the fix (generic bits added to WriteCapableRights) is
    // load-bearing.
    //
    // The ACE therefore MUST be planted via a raw path (SDDL here, whose GW/GA tokens
    // aren't validated), NOT via FileSystemAccessRule — an earlier version of this test
    // cast the raw bits into a FileSystemAccessRule and the SETUP threw on windows-latest
    // (this Mac can't target net8.0-windows, so only CI runs it). Whether Windows
    // persists the generic bit verbatim or maps it to FILE_ALL_ACCESS on write, the
    // resulting DACL still grants BUILTIN\Users a write-capable right, so VerifyTrusted
    // must reject either way — that's the security invariant this asserts.
    [Theory]
    [InlineData("GW")] // GENERIC_WRITE
    [InlineData("GA")] // GENERIC_ALL
    public void VerifyTrusted_OwnedByAdminsButGrantsGenericWriteOrAllToOtherPrincipal_Throws(string sddlRightToken)
    {
        if (!OperatingSystem.IsWindows()) return;

        var dir = Path.Combine(_root, $"generic-rights-{sddlRightToken}");
        Directory.CreateDirectory(dir);

        var info = new DirectoryInfo(dir);
        var acl  = new DirectorySecurity();

        // Owner Administrators (passes the owner check, so we reach the ACE loop), a
        // protected DACL granting SYSTEM/Administrators full control, plus BUILTIN\Users
        // (BU) the raw generic right. SDDL accepts GW/GA as first-class tokens and writes
        // the raw access-mask bits without the managed FileSystemAccessRule validation.
        acl.SetSecurityDescriptorSddlForm(
            "O:BAG:BA" +
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;" + sddlRightToken + ";;;BU)");
        info.SetAccessControl(acl);

        var ex = Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(
            () => SecureStagingDirectory.VerifyTrusted(dir));
        // "write-capable" pins the ACE-rejection branch specifically (the owner-check
        // branch's message says "owned by ... not SYSTEM or Administrators" but never
        // "write-capable"), proving we rejected on the Users ACE, not on ownership.
        Assert.Contains("write-capable", ex.Message);
        Assert.Contains("not SYSTEM or Administrators", ex.Message);
    }

    // Sanity check for the fix above: a directory whose DACL genuinely contains only
    // SYSTEM/Administrators Allow ACEs (what ApplyDacl itself produces) must still pass.
    [Fact]
    public void VerifyTrusted_OnlySystemAndAdministratorsGranted_DoesNotThrow()
    {
        if (!OperatingSystem.IsWindows()) return;

        var dir = Path.Combine(_root, "genuinely-hardened");
        SecureStagingDirectory.EnsureHardened(dir);

        SecureStagingDirectory.VerifyTrusted(dir); // must not throw
    }

    // -------------------------------------------------------------------------
    // PAT-2400: DescribeUntrusted is what the pending-update applier's real verifier
    // asks about the updates root, the version directory, the installer and the
    // marker. Real ACLs, so Windows only; the applier's handling of each verdict is
    // covered portably in Service.Tests (PendingUpdateStagedTrustTests).
    // -------------------------------------------------------------------------

    private const string NamedNonAdmin = "S-1-5-21-1004336348-1177238915-682003330-1001";

    private string NewStagedObject(bool isDirectory)
    {
        Directory.CreateDirectory(_root);
        string path = Path.Combine(_root, "staged-" + Guid.NewGuid().ToString("N"));
        if (isDirectory) Directory.CreateDirectory(path);
        else File.WriteAllText(path, "installer stand-in");
        return path;
    }

    private static void Persist(string path, FileSystemSecurity acl)
    {
        if (acl is DirectorySecurity directory) new DirectoryInfo(path).SetAccessControl(directory);
        else new FileInfo(path).SetAccessControl((FileSecurity)acl);
    }

    [Theory]
    [InlineData(true, "", null)]
    [InlineData(false, "", null)]
    [InlineData(true, "(A;;FR;;;BU)", null)]                        // read-only grant is harmless
    [InlineData(false, "(A;;FR;;;BU)", null)]
    [InlineData(true, "(A;;FW;;;BU)", "untrusted_acl")]             // Users
    [InlineData(false, "(A;;FW;;;BU)", "untrusted_acl")]
    [InlineData(true, "(A;;FW;;;WD)", "untrusted_acl")]             // Everyone
    [InlineData(false, "(A;;FW;;;WD)", "untrusted_acl")]
    [InlineData(true, "(A;;FW;;;" + NamedNonAdmin + ")", "untrusted_acl")]
    [InlineData(false, "(A;;FW;;;" + NamedNonAdmin + ")", "untrusted_acl")]
    [InlineData(false, "(A;;GA;;;BU)", "untrusted_acl")]            // raw generic bit
    public void DescribeUntrusted_AllowsWriteAccessToSystemAndAdministratorsOnly(
        bool isDirectory, string extraAce, string? expected)
    {
        if (!OperatingSystem.IsWindows()) return;

        string path = NewStagedObject(isDirectory);
        FileSystemSecurity acl = isDirectory ? new DirectorySecurity() : new FileSecurity();
        acl.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)" + extraAce);
        Persist(path, acl);

        Assert.Equal(expected, SecureStagingDirectory.DescribeUntrusted(path, isDirectory));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void DescribeUntrusted_OwnerOtherThanSystemOrAdministrators_IsUntrustedOwner(bool isDirectory)
    {
        if (!OperatingSystem.IsWindows()) return;

        // Same attacker model as StateDirectoryBootstrap_AttackerOwnedRoot: the runner's own SID.
        string path = NewStagedObject(isDirectory);
        var attackerSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Unable to determine the current Windows user SID.");
        FileSystemSecurity acl = isDirectory ? new DirectorySecurity() : new FileSecurity();
        acl.SetSecurityDescriptorSddlForm("O:" + attackerSid.Value + "G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)");
        Persist(path, acl);

        Assert.Equal("untrusted_owner", SecureStagingDirectory.DescribeUntrusted(path, isDirectory));
    }

    [Fact]
    public void DescribeUntrusted_AbsentWrongTypeAndReparsePoint_AreNeverTrusted()
    {
        if (!OperatingSystem.IsWindows()) return;

        string file = NewStagedObject(isDirectory: false);
        Assert.Equal("absent", SecureStagingDirectory.DescribeUntrusted(Path.Combine(_root, "missing"), isDirectory: true));
        Assert.Equal("wrong_type", SecureStagingDirectory.DescribeUntrusted(file, isDirectory: true));

        string link = Path.Combine(_root, "planted-link-2400");
        try { Directory.CreateSymbolicLink(link, NewStagedObject(isDirectory: true)); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { return; }

        Assert.Equal("reparse_point", SecureStagingDirectory.DescribeUntrusted(link, isDirectory: true));
    }
}
