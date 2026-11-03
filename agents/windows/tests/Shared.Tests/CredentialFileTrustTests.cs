using System.Text;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Shared.Tests;

public sealed class CredentialFileTrustTests
{
    [Theory]
    [InlineData("state", "untrusted_acl")]
    [InlineData("creds", "untrusted_owner")]
    [InlineData("creds", "exposed_acl")]
    [InlineData("token", "exposed_acl")]
    [InlineData("token", "reparse_point")]
    [InlineData("token", "wrong_type")]
    [InlineData("token", "absent")]
    public void UnsafeOrMissingComponentNeverOpensSecret(string component, string reason)
    {
        var root = Path.GetFullPath("state");
        var creds = Path.Combine(root, "creds");
        var blocked = component == "state" ? root : component == "creds" ? creds : Path.Combine(creds, "token");
        var opened = false;
        var reader = new CredentialFileTrust(root, creds,
            (path, _) => path == blocked ? reason : null,
            _ => { opened = true; return new MemoryStream(); }, (_, _) => true);
        Assert.Null(reader.ReadOptional("token"));
        Assert.False(opened);
    }

    [Fact]
    public void RejectedOpenIdentityNeverReadsAnySecretBytes()
    {
        var secret = new UnreadableStream();
        var reader = new CredentialFileTrust("state", "creds", (_, _) => null,
            _ => secret, (_, _) => false);
        Assert.Null(reader.ReadOptional("token"));
        Assert.True(secret.Disposed);
    }

    [Theory]
    [InlineData("  token\n", "token")]
    [InlineData(" \r\n", "")]
    public void TrustedValuesPreserveTrimAndEmptySemantics(string contents, string expected)
    {
        var reader = new CredentialFileTrust("state", "creds", (_, _) => null,
            _ => new MemoryStream(Encoding.UTF8.GetBytes(contents)), (_, _) => true);
        Assert.Equal(expected, reader.ReadOptional("token"));
    }

    [Fact]
    public void TrustIsRecheckedAfterOpening()
    {
        var calls = 0;
        var reader = new CredentialFileTrust("state", "creds",
            (_, _) => ++calls > 3 ? "untrusted_acl" : null,
            _ => new UnreadableStream(), (_, _) => true);
        Assert.Null(reader.ReadOptional("token"));
        Assert.True(reader.IsPresentOrUnsafe("suspended"));
    }

    [Fact]
    public void OptionalIoFailureAllowsLaterSource()
    {
        var reader = new CredentialFileTrust("state", "creds", (_, _) => null,
            _ => throw new IOException("fixture"), (_, _) => true);
        Assert.Null(reader.ReadOptional("token"));
        Assert.Equal("registry", reader.ReadOptional("token") ?? "registry");
    }

    [Theory]
    [InlineData("cm")]
    [InlineData("env")]
    [InlineData("registry")]
    public void UntrustedOptionalFilesPreserveStartupSourcePrecedence(string selected)
    {
        var fileReads = 0;
        var reader = new CredentialFileTrust("state", "creds", (_, _) => "untrusted_acl",
            _ => throw new Exception("Unsafe file opened"), (_, _) => true);
        var sources = new CredentialStore.StartupSources(
            ReadCredential: name => selected == "cm" && name != CredentialStore.TargetDeviceId ? "cm-value" : null,
            ReadEnvironment: _ => selected == "env" ? "env-value" : null,
            ReadCredsFile: name => { fileReads++; return reader.ReadOptional(name); },
            ReadRegistry: name => selected == "registry" && name != "EnrollmentToken" ? "registry-value" : null,
            WriteCredential: (_, _) => { }, DeleteRegistryKey: () => { },
            IgnoredEnrollmentTokenPresent: () => false, DeleteIgnoredEnrollmentToken: () => { },
            SuspendedFile: Path.Combine(Path.GetTempPath(), "unused-" + Guid.NewGuid().ToString("N")),
            ReadEnrollmentTokenSource: () => null, CredentialWriter: new InMemoryAgentCredentialWriter());
        var store = CredentialStore.LoadForStartup(null, sources);
        Assert.Equal(selected + "-value", store.TenantId);
        Assert.Equal(selected + "-value", store.BearerToken);
        Assert.False(store.WritesHostCredentialStorage);
        if (selected == "registry") Assert.True(fileReads >= 3);
    }

    [Fact]
    public void UnsafeEnrollmentFileFallsThroughToRegistryAtStartupAndRefresh()
    {
        var reader = new CredentialFileTrust("state", "creds", (_, _) => "untrusted_acl",
            _ => throw new Exception("Unsafe file opened"), (_, _) => true);
        string? Token() => CredentialStore.FirstUsableEnrollmentToken(
            () => null, () => reader.ReadOptional("enrollment-token"), () => "registry-token");
        var sources = new CredentialStore.StartupSources(
            _ => null, _ => null, reader.ReadOptional, name => name == "EnrollmentToken" ? "registry-token" : null,
            (_, _) => { }, () => { }, () => false, () => { },
            Path.Combine(Path.GetTempPath(), "unused-" + Guid.NewGuid().ToString("N")), Token,
            new InMemoryAgentCredentialWriter());
        var store = CredentialStore.LoadForStartup(null, sources);
        Assert.Equal("registry-token", store.EnrollmentToken);
        var refresh = CredentialStore.CreateForTests(sources.SuspendedFile, bearerToken: "", hmacSecret: "",
            enrollmentTokenSource: Token);
        Assert.True(refresh.RefreshEnrollmentToken());
        Assert.Equal("registry-token", refresh.EnrollmentToken);
    }

    private sealed class UnreadableStream : MemoryStream
    {
        internal bool Disposed;
        public override int Read(byte[] buffer, int offset, int count) => throw new Exception("Secret read before trust!");
        public override int Read(Span<byte> buffer) => throw new Exception("Secret read before trust!");
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
}
