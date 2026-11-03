using Microsoft.Extensions.Logging.Abstractions;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1760 review round 2: a device holds credentials only when its bearer token
/// and HMAC secret are both non-whitespace (CredentialStore.IsUsablePair). These
/// cover the two places in Patched.Shared that decide it: RefreshEnrollmentToken's
/// short-circuit and LoadForStartup, driven through its StartupSources seam so no
/// test reads or changes Credential Manager, %ProgramData%\Patched or HKLM.
/// </summary>
public sealed class CredentialStoreUsablePairTests : IDisposable
{
    private const string Secret = "dGVzdC1obWFjLXNlY3JldC0zMi1ieXRlcy1sb25nIQ==";

    private readonly string _tempDir;
    private readonly string _suspendedFile;

    public CredentialStoreUsablePairTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-creds-usable-pair-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _suspendedFile = Path.Combine(_tempDir, "suspended");
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Theory]
    [InlineData("bearer", Secret, true)]
    [InlineData("", Secret, false)]
    [InlineData("   ", Secret, false)]
    [InlineData(null, Secret, false)]
    [InlineData("bearer", "", false)]
    [InlineData("bearer", "   ", false)]
    [InlineData("bearer", "\t", false)]
    [InlineData("bearer", null, false)]
    public void IsUsablePair_RequiresBothNonWhitespace(string? bearer, string? secret, bool expected) =>
        Assert.Equal(expected, CredentialStore.IsUsablePair(bearer, secret));

    [Theory]
    [InlineData("   ")]
    [InlineData("\t")]
    [InlineData("")]
    public void RefreshEnrollmentToken_BearerWithUnusableSecret_ReadsTheSourceAndPicksUpAToken(string secret)
    {
        var store = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "stored-bearer", hmacSecret: secret, enrollmentTokenSource: () => "fresh-token");

        Assert.True(store.RefreshEnrollmentToken());
        Assert.Equal("fresh-token", store.EnrollmentToken);
    }

    [Fact]
    public void RefreshEnrollmentToken_UsablePair_NeverReadsTheSource()
    {
        var store = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "stored-bearer", hmacSecret: Secret,
            enrollmentTokenSource: () => throw new InvalidOperationException("must not be read"));

        Assert.False(store.RefreshEnrollmentToken());
    }

    // ---------------------------------------------------------------------
    // LoadForStartup
    // ---------------------------------------------------------------------

    private sealed class FakeSources
    {
        public Dictionary<string, string> Credentials { get; } = new();
        public Dictionary<string, string> Registry { get; } = new();
        /// <summary>PAT-1755: the credential file store, where the installer now puts the token.</summary>
        public Dictionary<string, string> CredsFiles { get; } = new();

        public int IgnoredTokenDeletes { get; private set; }
        public int RegistryKeyDeletes { get; private set; }
        public List<string> Writes { get; } = new();

        public CredentialStore.StartupSources Build(string suspendedFile) => new(
            ReadCredential: t => Credentials.TryGetValue(t, out var v) ? v : null,
            ReadEnvironment: _ => null,
            ReadCredsFile: n => CredsFiles.TryGetValue(n, out var v2) ? v2 : null,
            ReadRegistry: n => Registry.TryGetValue(n, out var v) ? v : null,
            WriteCredential: (t, _) => Writes.Add(t),
            DeleteRegistryKey: () => RegistryKeyDeletes++,
            // PAT-1755: an ignored token is looked for, and cleared, in both provisioning
            // locations: the credential file store and the legacy registry key.
            IgnoredEnrollmentTokenPresent: () =>
                CredsFiles.ContainsKey(EnrollmentTokenProvisioner.FileName)
                || Registry.ContainsKey(CredentialStore.RegistryEnrollmentTokenValue),
            DeleteIgnoredEnrollmentToken: () =>
            {
                IgnoredTokenDeletes++;
                CredsFiles.Remove(EnrollmentTokenProvisioner.FileName);
                Registry.Remove(CredentialStore.RegistryEnrollmentTokenValue);
            },
            SuspendedFile: suspendedFile,
            ReadEnrollmentTokenSource: () => null,
            // PAT-1763: stores built from these sources never write the host either.
            CredentialWriter: new InMemoryAgentCredentialWriter());
    }

    private FakeSources StoredPair(string bearer, string secret)
    {
        var src = new FakeSources();
        src.Credentials[CredentialStore.TargetTenantId] = "stored-tenant";
        src.Credentials[CredentialStore.TargetBearerToken] = bearer;
        src.Credentials[CredentialStore.TargetHmacSecret] = secret;
        return src;
    }

    [Theory]
    [InlineData("   ")]
    [InlineData("\t")]
    [InlineData("")]
    public void LoadForStartup_UnusableStoredSecret_WithRegistryToken_LoadsTheTokenAndDoesNotDiscardIt(string secret)
    {
        var src = StoredPair("stored-bearer", secret);
        src.Registry[CredentialStore.RegistryEnrollmentTokenValue] = "installer-token";

        var store = CredentialStore.LoadForStartup(NullLogger.Instance, src.Build(_suspendedFile));

        Assert.Equal("installer-token", store.EnrollmentToken);
        Assert.Equal("", store.BearerToken);
        Assert.Equal("", store.HmacSecret);
        Assert.Equal(0, src.IgnoredTokenDeletes);
        Assert.Empty(src.Writes);
    }

    [Fact]
    public void LoadForStartup_UsableStoredPair_WithRegistryToken_KeepsThePairAndDiscardsTheToken()
    {
        // PAT-1764 behaviour, unchanged for a device that really holds credentials.
        var src = StoredPair("stored-bearer", Secret);
        src.Registry[CredentialStore.RegistryEnrollmentTokenValue] = "installer-token";

        var store = CredentialStore.LoadForStartup(NullLogger.Instance, src.Build(_suspendedFile));

        Assert.Equal("stored-bearer", store.BearerToken);
        Assert.Equal(Secret, store.HmacSecret);
        Assert.Null(store.EnrollmentToken);
        Assert.Equal(1, src.IgnoredTokenDeletes);
    }

    [Fact]
    public void LoadForStartup_UsableStoredPair_WithFileStoreToken_KeepsThePairAndDiscardsTheToken()
    {
        // PAT-1755: the installer now writes the token to the credential file store, so the
        // PAT-1764 rule that an ignored token is never left sitting as a live single-use
        // secret has to cover that location too.
        var src = StoredPair("stored-bearer", Secret);
        src.CredsFiles[EnrollmentTokenProvisioner.FileName] = "installer-token";

        var store = CredentialStore.LoadForStartup(NullLogger.Instance, src.Build(_suspendedFile));

        Assert.Equal("stored-bearer", store.BearerToken);
        Assert.Null(store.EnrollmentToken);
        Assert.Equal(1, src.IgnoredTokenDeletes);
        Assert.DoesNotContain(EnrollmentTokenProvisioner.FileName, src.CredsFiles.Keys);
    }

    [Fact]
    public void LoadForStartup_UnusableStoredSecret_WithFileStoreToken_LoadsTheTokenAndDoesNotDiscardIt()
    {
        var src = StoredPair("stored-bearer", "   ");
        src.CredsFiles[EnrollmentTokenProvisioner.FileName] = "installer-token";

        var store = CredentialStore.LoadForStartup(NullLogger.Instance, src.Build(_suspendedFile));

        Assert.Equal("installer-token", store.EnrollmentToken);
        Assert.Equal(0, src.IgnoredTokenDeletes);
    }

    [Fact]
    public void LoadForStartup_UnusableStoredSecret_NoToken_StartsWithTheUnusablePair_NotAnIdentityException()
    {
        var src = StoredPair("stored-bearer", "   ");

        var store = CredentialStore.LoadForStartup(NullLogger.Instance, src.Build(_suspendedFile));

        Assert.Equal("stored-bearer", store.BearerToken);
        Assert.False(CredentialStore.IsUsablePair(store.BearerToken, store.HmacSecret));
        Assert.True(store.StoredCredentialPairPresent);
        Assert.Null(store.EnrollmentToken);
        Assert.Equal(0, src.RegistryKeyDeletes);
    }

    [Fact]
    public void LoadForStartup_UnusableStoredSecret_DoesNotMigrateRegistryRawCredentialsOverIt()
    {
        var src = StoredPair("stored-bearer", "   ");
        src.Registry["TenantId"] = "reg-tenant";
        src.Registry["BearerToken"] = "reg-bearer";
        src.Registry["HmacSecret"] = Secret;

        CredentialStore.LoadForStartup(NullLogger.Instance, src.Build(_suspendedFile));

        Assert.Empty(src.Writes);
        Assert.Equal(0, src.RegistryKeyDeletes);
    }

    // ---------------------------------------------------------------------
    // PAT-1766: not provisioned is a running state, not an exception
    // ---------------------------------------------------------------------

    [Fact]
    public void LoadForStartup_NothingStored_NoToken_ReturnsStoreAwaitingProvisioning_ChangesNothing()
    {
        var src = new FakeSources();

        var store = CredentialStore.LoadForStartup(NullLogger.Instance, src.Build(_suspendedFile));

        Assert.True(store.AwaitingProvisioning);
        Assert.Equal("", store.TenantId);
        Assert.Equal("", store.BearerToken);
        Assert.Equal("", store.HmacSecret);
        Assert.Null(store.EnrollmentToken);
        Assert.False(store.StoredCredentialPairPresent);
        Assert.Empty(src.Writes);
        Assert.Equal(0, src.RegistryKeyDeletes);
        Assert.Equal(0, src.IgnoredTokenDeletes);
        Assert.False(store.WritesHostCredentialStorage);
    }

    [Fact]
    public void LoadForStartup_UnusableStoredSecret_NoToken_IsAwaitingProvisioning()
    {
        var store = CredentialStore.LoadForStartup(NullLogger.Instance, StoredPair("stored-bearer", "   ").Build(_suspendedFile));

        Assert.True(store.AwaitingProvisioning);
        Assert.True(store.StoredCredentialPairPresent);
    }

    [Fact]
    public void LoadForStartup_TokenOnly_IsNotAwaitingProvisioning()
    {
        var src = new FakeSources();
        src.Registry[CredentialStore.RegistryEnrollmentTokenValue] = "installer-token";

        var store = CredentialStore.LoadForStartup(NullLogger.Instance, src.Build(_suspendedFile));

        Assert.False(store.AwaitingProvisioning);
        Assert.Equal("installer-token", store.EnrollmentToken);
    }

    [Fact]
    public void LoadForStartup_UsablePair_IsNotAwaitingProvisioning()
    {
        var store = CredentialStore.LoadForStartup(NullLogger.Instance, StoredPair("stored-bearer", Secret).Build(_suspendedFile));

        Assert.False(store.AwaitingProvisioning);
    }

    [Fact]
    public void RefreshProvisioning_NothingAppears_ReturnsFalse_StoreUnchanged()
    {
        var src = new FakeSources();
        var store = CredentialStore.LoadForStartup(NullLogger.Instance, src.Build(_suspendedFile));

        Assert.False(store.RefreshProvisioning());
        Assert.False(store.RefreshProvisioning());

        Assert.True(store.AwaitingProvisioning);
        Assert.Null(store.EnrollmentToken);
        Assert.Empty(src.Writes);
    }

    [Fact]
    public void RefreshProvisioning_RegistryTokenAppears_AdoptsTheTokenInPlace_WritesNothing()
    {
        var src = new FakeSources();
        var store = CredentialStore.LoadForStartup(NullLogger.Instance, src.Build(_suspendedFile));

        src.Registry[CredentialStore.RegistryEnrollmentTokenValue] = "dropped-token";

        Assert.True(store.RefreshProvisioning());
        Assert.False(store.AwaitingProvisioning);
        Assert.Equal("dropped-token", store.EnrollmentToken);
        Assert.Equal("", store.BearerToken);
        Assert.Equal("", store.HmacSecret);
        Assert.Empty(src.Writes);
        Assert.Equal(0, src.IgnoredTokenDeletes);
    }

    [Fact]
    public void RefreshProvisioning_CredentialsAppear_AdoptsThePairInPlace()
    {
        var src = new FakeSources();
        var store = CredentialStore.LoadForStartup(NullLogger.Instance, src.Build(_suspendedFile));

        src.Credentials[CredentialStore.TargetTenantId] = "added-tenant";
        src.Credentials[CredentialStore.TargetBearerToken] = "added-bearer";
        src.Credentials[CredentialStore.TargetHmacSecret] = Secret;

        Assert.True(store.RefreshProvisioning());
        Assert.False(store.AwaitingProvisioning);
        Assert.Equal("added-tenant", store.TenantId);
        Assert.Equal("added-bearer", store.BearerToken);
        Assert.Equal(Secret, store.HmacSecret);
        Assert.Null(store.EnrollmentToken);
    }

    [Fact]
    public void RefreshProvisioning_RegistryRawCredentialsAppear_MigratesThemLikeStartup()
    {
        var src = new FakeSources();
        var store = CredentialStore.LoadForStartup(NullLogger.Instance, src.Build(_suspendedFile));

        src.Registry["TenantId"] = "reg-tenant";
        src.Registry["BearerToken"] = "reg-bearer";
        src.Registry["HmacSecret"] = Secret;

        Assert.True(store.RefreshProvisioning());
        Assert.Equal("reg-bearer", store.BearerToken);
        Assert.Equal(
            new[] { CredentialStore.TargetTenantId, CredentialStore.TargetBearerToken, CredentialStore.TargetHmacSecret },
            src.Writes);
        Assert.Equal(1, src.RegistryKeyDeletes);
    }

    [Fact]
    public void RefreshProvisioning_UnusableStoredPair_TokenAppears_AdoptsTokenAndBlanksThePair()
    {
        var src = StoredPair("stored-bearer", "   ");
        var store = CredentialStore.LoadForStartup(NullLogger.Instance, src.Build(_suspendedFile));

        src.Registry[CredentialStore.RegistryEnrollmentTokenValue] = "dropped-token";

        Assert.True(store.RefreshProvisioning());
        Assert.Equal("dropped-token", store.EnrollmentToken);
        Assert.Equal("", store.BearerToken);
        Assert.Equal("", store.HmacSecret);
        Assert.Equal(0, src.IgnoredTokenDeletes);
    }

    [Fact]
    public void RefreshProvisioning_UsablePair_NeverReloads()
    {
        var store = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "stored-bearer", hmacSecret: Secret,
            provisioningSource: () => throw new InvalidOperationException("must not reload"));

        Assert.False(store.RefreshProvisioning());
    }

    [Fact]
    public void RefreshProvisioning_TokenPresent_NeverReloads()
    {
        // A device suspended by a rejected token still holds that token: it is not
        // waiting to be provisioned, WaitForRecoveryAsync owns it.
        var store = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", enrollmentToken: "rejected-token",
            provisioningSource: () => throw new InvalidOperationException("must not reload"));

        Assert.False(store.AwaitingProvisioning);
        Assert.False(store.RefreshProvisioning());
    }

    [Fact]
    public void RefreshProvisioning_SourceThrows_Propagates_StoreUnchanged()
    {
        var store = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", hmacSecret: "",
            provisioningSource: () => throw new IOException("creds file locked"));

        Assert.Throws<IOException>(() => store.RefreshProvisioning());
        Assert.True(store.AwaitingProvisioning);
    }

    [Fact]
    public void RefreshProvisioning_ReloadStillUnprovisioned_ReturnsFalse()
    {
        var store = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", hmacSecret: "",
            provisioningSource: () => CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", hmacSecret: ""));

        Assert.False(store.RefreshProvisioning());
        Assert.True(store.AwaitingProvisioning);
    }

    [Fact]
    public void RefreshProvisioning_StoredBlankPairAppears_RetainsPresenceEvidence()
    {
        var fresh = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", hmacSecret: "", tenantId: "",
            storedCredentialPairPresent: true);
        var store = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", hmacSecret: "", tenantId: "",
            provisioningSource: () => fresh);

        Assert.False(store.StoredCredentialPairPresent);
        Assert.False(store.RefreshProvisioning());
        Assert.True(store.AwaitingProvisioning);
        Assert.True(store.StoredCredentialPairPresent);
    }

    [Fact]
    public void TestFactoryDefault_HasNothingToProvisionFrom()
    {
        // Test factories default to "nothing provisioned yet" and never touch the host.
        var store = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", hmacSecret: "");

        Assert.True(store.AwaitingProvisioning);
        Assert.False(store.RefreshProvisioning());
    }
}
