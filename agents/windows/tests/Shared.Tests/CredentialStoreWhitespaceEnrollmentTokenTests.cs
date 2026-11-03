using Microsoft.Extensions.Logging.Abstractions;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1765: a whitespace-only enrolment token is no token. Every enrolment-token
/// check uses CredentialStore.IsUsableEnrollmentToken (IsNullOrWhiteSpace), so a blank
/// value is never loaded, never signals a retry, and never hides a real token in a
/// lower-priority source. LoadForStartup is driven through its StartupSources seam, so
/// nothing reads or changes Credential Manager, %ProgramData%\Patched or HKLM.
/// </summary>
public sealed class CredentialStoreWhitespaceEnrollmentTokenTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _suspendedFile;

    public CredentialStoreWhitespaceEnrollmentTokenTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-creds-ws-token-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _suspendedFile = Path.Combine(_tempDir, "suspended");
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("\t\r\n", false)]
    [InlineData("token", true)]
    public void IsUsableEnrollmentToken_RequiresNonWhitespace(string? token, bool expected) =>
        Assert.Equal(expected, CredentialStore.IsUsableEnrollmentToken(token));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    public void RefreshEnrollmentToken_BlankFreshValue_ReturnsFalse_AndKeepsTheCurrentToken(string blank)
    {
        var store = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", enrollmentTokenSource: () => blank, enrollmentToken: "rejected-token");

        Assert.False(store.RefreshEnrollmentToken());
        Assert.Equal("rejected-token", store.EnrollmentToken);
    }

    private static CredentialStore.StartupSources Sources(
        string suspendedFile, string? credentialManagerToken, string? fileToken, string? registryToken) => new(
            ReadCredential: t => t == CredentialStore.TargetEnrollmentToken ? credentialManagerToken : null,
            ReadEnvironment: _ => null,
            ReadCredsFile: n => n == EnrollmentTokenProvisioner.FileName ? fileToken : null,
            ReadRegistry: n => n == CredentialStore.RegistryEnrollmentTokenValue ? registryToken : null,
            WriteCredential: (_, _) => throw new InvalidOperationException("must not write"),
            DeleteRegistryKey: () => throw new InvalidOperationException("must not delete"),
            IgnoredEnrollmentTokenPresent: () => registryToken != null || fileToken != null,
            DeleteIgnoredEnrollmentToken: () => throw new InvalidOperationException("must not delete"),
            SuspendedFile: suspendedFile,
            ReadEnrollmentTokenSource: () => null,
            CredentialWriter: new InMemoryAgentCredentialWriter());

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void LoadForStartup_BlankHigherPriorityToken_DoesNotHideARealLowerPriorityToken(string blank)
    {
        var store = CredentialStore.LoadForStartup(
            NullLogger.Instance, Sources(_suspendedFile, credentialManagerToken: blank, fileToken: "  ", registryToken: "installer-token"));

        Assert.Equal("installer-token", store.EnrollmentToken);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public void LoadForStartup_OnlyBlankTokens_NothingStored_IsNoIdentity(string blank)
    {
        // Before PAT-1765 a whitespace token produced an enrolment-pending store that
        // could never enrol and ran silently. It is now the same as no token, which
        // since PAT-1766 means the store loads awaiting provisioning rather than
        // throwing, so the service stays up and reports it.
        var store = CredentialStore.LoadForStartup(
            NullLogger.Instance, Sources(_suspendedFile, credentialManagerToken: blank, fileToken: blank, registryToken: blank));

        Assert.True(store.AwaitingProvisioning);
        Assert.False(CredentialStore.IsUsableEnrollmentToken(store.EnrollmentToken));
    }

    [Fact]
    public void FirstUsableEnrollmentToken_StopsReadingAtTheFirstUsableSource()
    {
        var token = CredentialStore.FirstUsableEnrollmentToken(
            () => " ",
            () => "real-token",
            () => throw new InvalidOperationException("must not be read"));

        Assert.Equal("real-token", token);
    }
}
