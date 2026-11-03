using Patched.Shared.Auth;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1755: the installer provisions the enrolment token by writing
/// %ProgramData%\Patched\creds\enrollment-token as LocalSystem, before the service has
/// ever run and therefore before anything has hardened that directory. A SYSTEM write
/// into a path an unprivileged user can influence is an arbitrary-file-write primitive,
/// so the order is: harden the state root, harden creds, refuse a reparse point, then
/// write. Nothing may be written when any of that fails, and a failure must be reported
/// rather than swallowed: the custom action is Return="check" and the install depends on
/// the exit code.
///
/// The trust checks and the write are fakes here; the last group covers the real
/// file-write helper against a scratch directory, which works on any OS.
/// </summary>
public sealed class EnrollmentTokenProvisionerTests
{
    private const string Token = "tok_live_4f9a1c2b7e";
    private static readonly string StateDir = Path.Combine("fake", "ProgramData", "Patched");
    private static readonly string CredsDir = Path.Combine(StateDir, "creds");
    private static readonly string TokenFile = Path.Combine(CredsDir, "enrollment-token");

    private sealed class Fake
    {
        public List<(string Directory, bool AllowStandardUserRead)> Hardened { get; } = [];
        public HashSet<string> UntrustedDirs { get; } = new(StringComparer.Ordinal);
        public HashSet<string> ReparsePaths { get; } = new(StringComparer.Ordinal);
        public List<(string Path, string Contents)> Written { get; } = [];
        public Func<string, string, EnrollmentTokenProvisionResult>? WriteOverride { get; set; }

        public EnrollmentTokenProvisioner Provisioner() => new(
            StateDir, CredsDir,
            (directory, allowStandardUserRead) =>
            {
                Hardened.Add((directory, allowStandardUserRead));
                if (UntrustedDirs.Contains(directory))
                    throw new UnauthorizedAccessException("untrusted owner");
            },
            (root, target) =>
            {
                Assert.Equal(StateDir, root);
                return ReparsePaths.Contains(target);
            },
            (path, contents) =>
            {
                if (WriteOverride is not null)
                    return WriteOverride(path, contents);
                Written.Add((path, contents));
                return EnrollmentTokenProvisionResult.Provisioned;
            });
    }

    // ── the happy path ──

    [Fact]
    public void TrustedStore_HardensRootThenCreds_WritesTheTokenWithATrailingNewline()
    {
        var fake = new Fake();

        var result = fake.Provisioner().Provision(Token);

        Assert.True(result.Succeeded);
        Assert.Null(result.Error);
        Assert.Equal(
            new[] { (StateDir, true), (CredsDir, false) },
            fake.Hardened);
        var file = Assert.Single(fake.Written);
        Assert.Equal(TokenFile, file.Path);
        Assert.Equal(Token + "\n", file.Contents);
    }

    [Fact]
    public void CredsDirectoryIsHardenedWithNoStandardUserRead()
    {
        // The state root grants BUILTIN\Users read for the Tray's root-level status files.
        // creds must not, and the root's ACE is NoPropagateInherit so it cannot reach here.
        var fake = new Fake();

        fake.Provisioner().Provision(Token);

        Assert.False(fake.Hardened.Single(h => h.Directory == CredsDir).AllowStandardUserRead);
    }

    [Fact]
    public void SurroundingWhitespaceIsTrimmed_NotWrittenThrough()
    {
        var fake = new Fake();

        Assert.True(fake.Provisioner().Provision($"  {Token}\r\n").Succeeded);

        Assert.Equal(Token + "\n", Assert.Single(fake.Written).Contents);
    }

    [Fact]
    public void TokenFilePathIsTheOneTheServiceReadsAndTheUninstallPurges()
    {
        Assert.Equal("enrollment-token", EnrollmentTokenProvisioner.FileName);
        Assert.Contains(EnrollmentTokenProvisioner.FileName, CredentialStore.AgentCredentialFileNames);
        Assert.Equal(TokenFile, new Fake().Provisioner().TokenFilePath);
    }

    // ── nothing is written when the token is not a token ──

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\r\n")]
    public void NoUsableToken_WritesNothing_ReportsNoToken(string? supplied)
    {
        var fake = new Fake();

        var result = fake.Provisioner().Provision(supplied);

        Assert.False(result.Succeeded);
        Assert.Equal(EnrollmentTokenProvisioner.NoTokenError, result.Error);
        Assert.Empty(fake.Written);
        // Not even the directory hardening runs: an install with no token to place must
        // touch nothing.
        Assert.Empty(fake.Hardened);
    }

    [Theory]
    [InlineData("tok with a space")]
    [InlineData("tok\twith\ttabs")]
    [InlineData("tok\nwith\nlines")]
    [InlineData("tok\u0000with\u0000nul")]
    [InlineData("tok\u007fwith\u007fdelete")]
    [InlineData("tok\u00e9with\u00e9accents")]
    public void MalformedToken_WritesNothing_ReportsTheShape(string supplied)
    {
        var fake = new Fake();

        var result = fake.Provisioner().Provision(supplied);

        Assert.False(result.Succeeded);
        Assert.Equal(EnrollmentTokenProvisioner.ShapeError, result.Error);
        Assert.Empty(fake.Written);
    }

    [Fact]
    public void OverlongToken_WritesNothing()
    {
        var fake = new Fake();

        var result = fake.Provisioner().Provision(new string('a', EnrollmentTokenProvisioner.MaxTokenLength + 1));

        Assert.False(result.Succeeded);
        Assert.Equal(EnrollmentTokenProvisioner.ShapeError, result.Error);
        Assert.Empty(fake.Written);
    }

    [Fact]
    public void TokenAtTheLengthLimit_IsAccepted()
    {
        var fake = new Fake();

        Assert.True(fake.Provisioner()
            .Provision(new string('a', EnrollmentTokenProvisioner.MaxTokenLength)).Succeeded);
    }

    [Fact]
    public void ShapeErrorNamesTheLimit()
    {
        // The message is the only place the number appears to an operator, so keep it
        // tied to the constant.
        Assert.Contains(
            EnrollmentTokenProvisioner.MaxTokenLength.ToString(), EnrollmentTokenProvisioner.ShapeError);
    }

    [Theory]
    [InlineData("tok_live_4f9a")]
    [InlineData("eyJhbGciOiJFZDI1NTE5In0.eyJzdWIiOiJkZXYifQ.c2ln")]
    [InlineData("abcDEF-_0123456789=")]
    public void RealisticTokenShapesAreAccepted(string supplied)
    {
        Assert.True(EnrollmentTokenProvisioner.TryNormalise(supplied, out var token, out var error));
        Assert.Equal(supplied, token);
        Assert.Equal("", error);
    }

    // ── nothing is written when the store cannot be trusted ──

    [Fact]
    public void UntrustedStateRoot_WritesNothing_NeverReachesCreds()
    {
        var fake = new Fake();
        fake.UntrustedDirs.Add(StateDir);

        var result = fake.Provisioner().Provision(Token);

        Assert.False(result.Succeeded);
        Assert.Contains(EnrollmentTokenProvisioner.UntrustedStoreError, result.Error);
        Assert.Contains("UnauthorizedAccessException", result.Error);
        Assert.Empty(fake.Written);
        Assert.Equal(new[] { StateDir }, fake.Hardened.Select(h => h.Directory));
    }

    [Fact]
    public void UntrustedCredsDirectory_WritesNothing()
    {
        var fake = new Fake();
        fake.UntrustedDirs.Add(CredsDir);

        var result = fake.Provisioner().Provision(Token);

        Assert.False(result.Succeeded);
        Assert.Contains(EnrollmentTokenProvisioner.UntrustedStoreError, result.Error);
        Assert.Empty(fake.Written);
    }

    [Fact]
    public void ReparsePointInTheTokenFileChain_WritesNothing()
    {
        var fake = new Fake();
        fake.ReparsePaths.Add(TokenFile);

        var result = fake.Provisioner().Provision(Token);

        Assert.False(result.Succeeded);
        Assert.Equal(EnrollmentTokenProvisioner.UntrustedStoreError, result.Error);
        Assert.Empty(fake.Written);
    }

    [Fact]
    public void ReparseCheckThrows_WritesNothing_FailsClosed()
    {
        var provisioner = new EnrollmentTokenProvisioner(
            StateDir, CredsDir, (_, _) => { },
            (_, _) => throw new IOException("boom"),
            (_, _) => throw new InvalidOperationException("must not be reached"));

        var result = provisioner.Provision(Token);

        Assert.False(result.Succeeded);
        Assert.Contains("IOException", result.Error);
    }

    // ── a failed write is reported, never swallowed ──

    [Fact]
    public void WriteReportsFailure_IsPassedThroughUnchanged()
    {
        var fake = new Fake { WriteOverride = (_, _) => EnrollmentTokenProvisionResult.Failed("disk full") };

        var result = fake.Provisioner().Provision(Token);

        Assert.False(result.Succeeded);
        Assert.Equal("disk full", result.Error);
    }

    [Fact]
    public void WriteThrows_IsReportedAsTheExceptionTypeOnly_NeverTheToken()
    {
        var fake = new Fake { WriteOverride = (_, _) => throw new UnauthorizedAccessException($"denied {Token}") };

        var result = fake.Provisioner().Provision(Token);

        Assert.False(result.Succeeded);
        Assert.Contains(EnrollmentTokenProvisioner.WriteError, result.Error);
        Assert.Contains("UnauthorizedAccessException", result.Error);
        Assert.DoesNotContain(Token, result.Error);
    }

    // ── the real write helper ──

    public sealed class WriteFileReportingTests : IDisposable
    {
        private readonly string _dir =
            Path.Combine(Path.GetTempPath(), $"patched-token-write-{Guid.NewGuid():N}");

        public WriteFileReportingTests() => Directory.CreateDirectory(_dir);

        public void Dispose()
        {
            try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
        }

        private string Path_(string name) => Path.Combine(_dir, name);

        [Fact]
        public void WritesTheContentsExactly_NoBom()
        {
            string path = Path_("enrollment-token");

            Assert.True(EnrollmentTokenProvisioner.WriteFileReporting(path, Token + "\n").Succeeded);

            Assert.Equal(Token + "\n", File.ReadAllText(path));
            Assert.Equal((byte)'t', File.ReadAllBytes(path)[0]);
            // What CredentialStore.ReadCredsFile does with it.
            Assert.Equal(Token, File.ReadAllText(path).Trim());
        }

        [Fact]
        public void ReplacesAnExistingFile_LeavingOnlyTheNewToken()
        {
            string path = Path_("enrollment-token");
            File.WriteAllText(path, "a-much-longer-previous-token-value\n");

            Assert.True(EnrollmentTokenProvisioner.WriteFileReporting(path, Token + "\n").Succeeded);

            Assert.Equal(Token + "\n", File.ReadAllText(path));
        }

        [Fact]
        public void MissingDirectory_ReportsTheFailure_DoesNotThrow()
        {
            var result = EnrollmentTokenProvisioner.WriteFileReporting(
                Path.Combine(_dir, "absent", "enrollment-token"), Token);

            Assert.False(result.Succeeded);
            Assert.Contains(EnrollmentTokenProvisioner.WriteError, result.Error);
            Assert.DoesNotContain(Token, result.Error);
        }

        [Fact]
        public void SymlinkAtTheFinalComponent_IsUnlinked_NotWrittenThrough()
        {
            string outside = Path_("outside-target");
            File.WriteAllText(outside, "do not touch\n");
            string path = Path_("enrollment-token");
            try
            {
                File.CreateSymbolicLink(path, outside);
            }
            catch (Exception)
            {
                // Creating a symlink needs privilege or developer mode on Windows; the
                // guarantee is still covered by the unlink-then-CreateNew sequence.
                return;
            }

            Assert.True(EnrollmentTokenProvisioner.WriteFileReporting(path, Token + "\n").Succeeded);

            Assert.Equal("do not touch\n", File.ReadAllText(outside));
            Assert.Equal(Token + "\n", File.ReadAllText(path));
            Assert.Null(new FileInfo(path).LinkTarget);
        }
    }
}
