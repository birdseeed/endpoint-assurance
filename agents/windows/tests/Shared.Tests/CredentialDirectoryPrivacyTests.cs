using Patched.Shared.Auth;
using Patched.Shared.Security;
using Xunit;

namespace Patched.Shared.Tests;

public sealed class CredentialDirectoryPrivacyTests
{
    [Fact]
    public void IntegrityFailureNeverInspectsOrMutatesContents()
    {
        Assert.Throws<IOException>(() => CredentialDirectoryPrivacy.Ensure("creds",
            _ => throw new IOException("unsafe writes"),
            _ => throw new Exception("privacy must not be inspected"),
            _ => throw new Exception("contents must not be inspected"),
            _ => throw new Exception("ACL must not be changed")));
    }

    [Fact]
    public void PrivateStoreIsPreservedRegardlessOfContents()
    {
        CredentialDirectoryPrivacy.Ensure("creds", _ => { }, _ => true,
            _ => throw new Exception("contents must not be inspected"),
            _ => throw new Exception("ACL must not be changed"));
    }

    [Theory]
    [InlineData("enrollment-token")]
    [InlineData("suspended")]
    [InlineData("unknown-entry")]
    public void AnyExistingEntryPreventsExposedStoreRepair(string entry)
    {
        var repaired = false;
        Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(() =>
            CredentialDirectoryPrivacy.Ensure("creds", _ => { }, _ => false,
                _ => string.IsNullOrEmpty(entry), _ => repaired = true));
        Assert.False(repaired);
    }

    [Fact]
    public void EmptyReadOnlyBaselineBecomesPrivateBeforeUse()
    {
        var calls = new List<string>();
        var privateAcl = false;
        CredentialDirectoryPrivacy.Ensure("creds", _ => calls.Add("integrity"),
            _ => { calls.Add("privacy"); return privateAcl; },
            _ => { calls.Add("empty"); return true; },
            _ => { calls.Add("harden"); privateAcl = true; });
        Assert.Equal(new[] { "integrity", "privacy", "empty", "harden", "privacy" }, calls);
        Assert.True(privateAcl);
    }

    [Fact]
    public void FailedPrivacyRepairCannotBeReportedAsSuccess()
    {
        Assert.Throws<SecureStagingDirectory.UntrustedDirectoryException>(() =>
            CredentialDirectoryPrivacy.Ensure("creds", _ => { }, _ => false, _ => true, _ => { }));
    }
}
