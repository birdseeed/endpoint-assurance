using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Patched.Shared.Auth;
using Patched.Shared.Security;
using Xunit;

namespace Patched.Shared.Tests;

public sealed class CredentialWindowsFactAttribute : FactAttribute
{
    public CredentialWindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Requires native Windows ACL and file identity APIs on an isolated elevated fixture host.";
    }
}

/// <summary>All fixtures are random temp trees; none call host credential factories,
/// Credential Manager, registry, services or the real ProgramData state directory.</summary>
public sealed class CredentialFileTrustRegressionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "credential-trust-" + Guid.NewGuid().ToString("N"));
    private string Creds => Path.Combine(_root, "creds");
    private string Token => Path.Combine(Creds, "token");
    private CredentialFileTrust Reader => CredentialFileTrust.CreateWindows(_root, Creds);

    private void CreateTrusted()
    {
        Directory.CreateDirectory(_root);
        SetDirectoryAcl(_root);
        Directory.CreateDirectory(Creds);
        SetDirectoryAcl(Creds);
    }

    private static void SetDirectoryAcl(string path)
    {
        var acl = new DirectorySecurity();
        acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        acl.SetAccessRuleProtection(true, false);
        foreach (var type in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(type, null),
                FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(acl);
    }

    private void WriteToken(string contents = "fixture-token")
    {
        File.WriteAllText(Token, contents);
        var info = new FileInfo(Token);
        var acl = info.GetAccessControl();
        acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        info.SetAccessControl(acl);
    }

    [CredentialWindowsFact]
    public void TrustedMissingEmptyAndSuspensionLifecycle()
    {
        CreateTrusted();
        Assert.Null(Reader.ReadOptional("token"));
        WriteToken(" \r\n");
        Assert.Equal("", Reader.ReadOptional("token"));
        WriteToken("  fixture-token\n");
        Assert.Equal("fixture-token", Reader.ReadOptional("token"));
        Assert.False(Reader.IsPresentOrUnsafe("suspended"));
        Reader.MarkSuspended();
        Reader.MarkSuspended();
        Assert.True(Reader.IsPresentOrUnsafe("suspended"));
        Reader.DeleteIfTrusted("suspended");
        Reader.DeleteIfTrusted("suspended");
        Assert.False(Reader.IsPresentOrUnsafe("suspended"));
    }

    [CredentialWindowsFact]
    public void TrustedOwnerWithWritableLegacyRootIsNeverRepairedOrRead()
    {
        CreateTrusted(); WriteToken();
        var info = new DirectoryInfo(_root);
        var acl = info.GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.Modify, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(acl);
        var before = info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
        Assert.Null(Reader.ReadOptional("token"));
        Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(() => StateDirectoryBootstrap.EnsureHardened(_root));
        Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(() => Reader.MarkSuspended());
        Assert.Throws<IOException>(() => Reader.DeleteIfTrusted("token"));
        Assert.Equal(before, info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
        Assert.Equal("fixture-token", File.ReadAllText(Token));
    }

    [CredentialWindowsFact]
    public void EmptyWritableCredentialDirectoryIsNotRepaired()
    {
        CreateTrusted();
        var info = new DirectoryInfo(Creds);
        var acl = info.GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.Modify, AccessControlType.Allow));
        info.SetAccessControl(acl);
        var before = info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
        Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(() =>
            CredentialDirectoryPrivacy.EnsureWindows(Creds));
        Assert.Equal(before, info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
        Assert.Empty(Directory.EnumerateFileSystemEntries(Creds));
    }

    [CredentialWindowsFact]
    public void ExistingTrustedCredentialAncestorsAreNotRewritten()
    {
        CreateTrusted();
        var info = new DirectoryInfo(Creds);
        var before = info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
        CredentialDirectoryPrivacy.EnsureWindows(Creds);
        Assert.Equal(before, info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
    }

    [CredentialWindowsFact]
    public void InheritedWritableCredentialAncestryIsRejected()
    {
        CreateTrusted(); WriteToken();
        var acl = new DirectoryInfo(Creds).GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            FileSystemRights.Modify, InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly, AccessControlType.Allow));
        new DirectoryInfo(Creds).SetAccessControl(acl);
        var leaf = new FileInfo(Token).GetAccessControl();
        Assert.Contains(leaf.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(), r => r.IsInherited &&
            ((SecurityIdentifier)r.IdentityReference).IsWellKnown(WellKnownSidType.AuthenticatedUserSid));
        Assert.Null(Reader.ReadOptional("token"));
    }

    [CredentialWindowsFact]
    public void UntrustedLeafOwnerIsRejected()
    {
        CreateTrusted(); WriteToken();
        var acl = new FileInfo(Token).GetAccessControl();
        acl.SetOwner(WindowsIdentity.GetCurrent().User!);
        new FileInfo(Token).SetAccessControl(acl);
        Assert.Null(Reader.ReadOptional("token"));
    }

    [CredentialWindowsFact]
    public void RawGenericWriteLeafAceIsRejected()
    {
        CreateTrusted(); WriteToken();
        var acl = new FileSecurity();
        acl.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GW;;;BU)");
        new FileInfo(Token).SetAccessControl(acl);
        Assert.Null(Reader.ReadOptional("token"));
    }

    [CredentialWindowsFact]
    public void HardLinkAndSymbolicLinkLeavesAreRejectedWithoutReadingTarget()
    {
        CreateTrusted(); WriteToken();
        var target = Path.Combine(Creds, "target");
        File.Move(Token, target);
        Assert.True(CreateHardLink(Token, target, IntPtr.Zero), "Native fixture hard link creation failed.");
        Assert.Null(Reader.ReadOptional("token"));
        File.Delete(Token);
        File.CreateSymbolicLink(Token, target);
        Assert.Null(Reader.ReadOptional("token"));
        Assert.Throws<IOException>(() => Reader.DeleteIfTrusted("token"));
        Assert.Equal("fixture-token", File.ReadAllText(target));
    }

    [CredentialWindowsFact]
    public void ReparseCredentialDirectoryIsRejected()
    {
        CreateTrusted(); WriteToken();
        var target = Path.Combine(_root, "moved-creds");
        Directory.Move(Creds, target);
        Directory.CreateSymbolicLink(Creds, target);
        Assert.Null(Reader.ReadOptional("token"));
        Assert.True(Reader.IsPresentOrUnsafe("suspended"));
        Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(() => Reader.MarkSuspended());
    }

    private static void AddUsersRead(string directory, bool inheritable)
    {
        var info = new DirectoryInfo(directory);
        var acl = info.GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.ReadAndExecute,
            inheritable ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None,
            PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(acl);
    }

    private EnrollmentTokenProvisioner ScratchProvisioner() => new(_root, Creds,
        (path, root) =>
        {
            if (root) SecureStagingDirectory.EnsureHardenedTrustedInstallerDirectory(
                path, allowStandardUserRead: true, repairExisting: false);
            else CredentialDirectoryPrivacy.EnsureWindows(path);
        }, PathSafety.HasReparsePointInChain,
        (path, contents) =>
        {
            Reader.DeleteIfTrusted(EnrollmentTokenProvisioner.FileName);
            return EnrollmentTokenProvisioner.WriteFileReporting(path, contents);
        });

    [CredentialWindowsFact]
    public void ExplicitAndInheritedReadGrantsOnCredentialDirectoryAreRejected()
    {
        CreateTrusted(); WriteToken();
        AddUsersRead(Creds, true);
        Assert.Null(Reader.ReadOptional("token"));
        Assert.True(Reader.IsPresentOrUnsafe("suspended"));
        Assert.Equal("exposed_acl", SecureStagingDirectory.DescribeUntrusted(Creds, true, requirePrivate: true));
        SetDirectoryAcl(Creds);
        AddUsersRead(_root, true);
        var info = new DirectoryInfo(Creds);
        var acl = info.GetAccessControl();
        acl.SetAccessRuleProtection(false, true);
        info.SetAccessControl(acl);
        Assert.Contains(info.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
            rule => rule.IsInherited && ((SecurityIdentifier)rule.IdentityReference).IsWellKnown(WellKnownSidType.BuiltinUsersSid));
        Assert.Null(Reader.ReadOptional("token"));
    }

    [CredentialWindowsFact]
    public void ExplicitLeafReadWithPrivateAncestorsAndInheritedLeafReadAreRejected()
    {
        CreateTrusted(); WriteToken();
        Assert.Null(SecureStagingDirectory.DescribeUntrusted(Creds, true, requirePrivate: true));
        var acl = new FileSecurity();
        acl.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)");
        new FileInfo(Token).SetAccessControl(acl);
        var actual = new FileInfo(Token).GetAccessControl();
        Assert.Contains(actual.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
            rule => !rule.IsInherited &&
                ((SecurityIdentifier)rule.IdentityReference).IsWellKnown(WellKnownSidType.BuiltinUsersSid));
        Assert.Equal("exposed_acl", SecureStagingDirectory.DescribeUntrusted(Token, false, requirePrivate: true));
        Assert.Null(Reader.ReadOptional("token"));
        Assert.Throws<IOException>(() => Reader.DeleteIfTrusted("token"));
        Assert.Equal("fixture-token", File.ReadAllText(Token));

        // A real inherited ACE requires an unprotected child and an inheritable parent grant.
        // The parent is exposed in this case, so also classify the leaf directly.
        File.Delete(Token);
        WriteToken();
        Assert.False(new FileInfo(Token).GetAccessControl().AreAccessRulesProtected);
        AddUsersRead(Creds, true);
        actual = new FileInfo(Token).GetAccessControl();
        Assert.Contains(actual.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
            rule => rule.IsInherited &&
                ((SecurityIdentifier)rule.IdentityReference).IsWellKnown(WellKnownSidType.BuiltinUsersSid));
        Assert.Equal("exposed_acl", SecureStagingDirectory.DescribeUntrusted(Token, false, requirePrivate: true));
        Assert.Null(Reader.ReadOptional("token"));
        Assert.Throws<IOException>(() => Reader.DeleteIfTrusted("token"));
        Assert.Equal("fixture-token", File.ReadAllText(Token));
    }

    [CredentialWindowsFact]
    public void WritableLeafIsRejectedWithPrivateAncestors()
    {
        CreateTrusted(); WriteToken();
        var acl = new FileInfo(Token).GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.Modify, AccessControlType.Allow));
        new FileInfo(Token).SetAccessControl(acl);
        Assert.Null(SecureStagingDirectory.DescribeUntrusted(Creds, true, requirePrivate: true));
        Assert.Equal("untrusted_acl", SecureStagingDirectory.DescribeUntrusted(Token, false, requirePrivate: true));
        Assert.Null(Reader.ReadOptional("token"));
    }

    [CredentialWindowsFact]
    public void EmptyMsiReadBaselineIsMadePrivateBeforeTokenProvisioning()
    {
        CreateTrusted();
        AddUsersRead(_root, true);
        AddUsersRead(Creds, true);
        var rootBefore = new DirectoryInfo(_root).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
        Assert.True(ScratchProvisioner().Provision("fresh-fixture-token").Succeeded);
        Assert.Equal("fresh-fixture-token", Reader.ReadOptional(EnrollmentTokenProvisioner.FileName));
        Assert.Null(SecureStagingDirectory.DescribeUntrusted(Creds, true, requirePrivate: true));
        Assert.Null(SecureStagingDirectory.DescribeUntrusted(Path.Combine(Creds, EnrollmentTokenProvisioner.FileName), false, requirePrivate: true));
        Assert.Equal(rootBefore, new DirectoryInfo(_root).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
    }

    [CredentialWindowsFact]
    public void ExposedNonemptyStoreIsNotRepairedByProvisioningOrSuspension()
    {
        CreateTrusted(); WriteToken();
        AddUsersRead(Creds, true);
        var info = new DirectoryInfo(Creds);
        var before = info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
        Assert.False(ScratchProvisioner().Provision("fresh-fixture-token").Succeeded);
        Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(() => Reader.MarkSuspended());
        Assert.Equal(before, info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
        Assert.Equal("fixture-token", File.ReadAllText(Token));
        Assert.False(File.Exists(Path.Combine(Creds, EnrollmentTokenProvisioner.FileName)));
    }

    [CredentialWindowsFact]
    public void FreshBootstrapPreservesRootUiReadsWithoutExposingCredentialChildren()
    {
        Assert.False(StateDirectoryBootstrap.EnsureHardened(_root));
        var publicFile = Path.Combine(_root, "posture.json");
        File.WriteAllText(publicFile, "{}");
        var rootRules = new DirectoryInfo(_root).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier));
        var read = Assert.Single(rootRules.Cast<FileSystemAccessRule>(), rule =>
            ((SecurityIdentifier)rule.IdentityReference).IsWellKnown(WellKnownSidType.BuiltinUsersSid));
        Assert.Equal(InheritanceFlags.ObjectInherit, read.InheritanceFlags);
        Assert.Equal(PropagationFlags.NoPropagateInherit, read.PropagationFlags);
        Assert.Contains(new FileInfo(publicFile).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
            rule => rule.IsInherited && ((SecurityIdentifier)rule.IdentityReference).IsWellKnown(WellKnownSidType.BuiltinUsersSid));
        Assert.True(ScratchProvisioner().Provision("fresh-fixture-token").Succeeded);
        Assert.Null(SecureStagingDirectory.DescribeUntrusted(Creds, true, requirePrivate: true));
        Assert.Null(SecureStagingDirectory.DescribeUntrusted(Path.Combine(Creds, EnrollmentTokenProvisioner.FileName), false, requirePrivate: true));
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string name, string existing, IntPtr attributes);

    public void Dispose()
    {
        try
        {
            // Remove only fixture links, never recurse through their target.
            if (Directory.Exists(Creds) && (File.GetAttributes(Creds) & FileAttributes.ReparsePoint) != 0)
                Directory.Delete(Creds);
            if (Directory.Exists(_root)) Directory.Delete(_root, true);
        }
        catch { }
    }
}
