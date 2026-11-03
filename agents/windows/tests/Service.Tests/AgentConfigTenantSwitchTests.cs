using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1763: tenant-scoped agent-config state on Windows.
///
///   - AgentConfigManager never applies a cached or in-memory config that
///     belongs to a tenant other than the enrolled one, or that names no tenant:
///     after a device is moved to another tenant it runs on defaults until that
///     tenant's first signed config is accepted.
///   - AgentConfigFetcher's post-signature step validates everything, including
///     the typed deserialization, before it writes agent-config.json or advances
///     the anti-rollback floor, so a verified payload it cannot apply leaves both
///     untouched.
///
/// Every path is a scratch path and every store comes from
/// CredentialStore.CreateForTests / ForTesting, so nothing here touches
/// %ProgramData%\Patched or the Windows Credential Manager.
/// </summary>
public sealed class AgentConfigTenantSwitchTests : IDisposable
{
    private const string EnrolledTenant = "test-tenant"; // CredentialStore.CreateForTests' tenant
    private const string PreviousTenant = "previous-tenant";

    private readonly string _tempDir;
    private readonly string _suspendedFile;
    private readonly string _configFile;
    private readonly string _floorFile;

    public AgentConfigTenantSwitchTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-acf-tenant-switch-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _suspendedFile = Path.Combine(_tempDir, "creds", "suspended");
        _configFile    = Path.Combine(_tempDir, "agent-config.json");
        _floorFile     = Path.Combine(_tempDir, "agent-config.version");
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }

    private static byte[] ConfigBytes(string? tenantId, int version, string tier = "managed")
    {
        var fields = new Dictionary<string, object> { ["config_version"] = version, ["tier"] = tier };
        if (tenantId is not null)
            fields["tenant_id"] = tenantId;
        return JsonSerializer.SerializeToUtf8Bytes(fields);
    }

    private AgentConfigFetcher NewFetcher(CredentialStore creds, Func<byte[], AgentConfig?>? deserialize = null) =>
        deserialize is null
            ? new AgentConfigFetcher(NullLogger<AgentConfigFetcher>.Instance, new NoNetworkFactory(), creds, _configFile, _floorFile)
            : new AgentConfigFetcher(NullLogger<AgentConfigFetcher>.Instance, new NoNetworkFactory(), creds, _configFile, _floorFile, deserialize);

    private AgentConfigManager NewManager(CredentialStore creds, ILogger<AgentConfigManager> log) =>
        new(log, NewFetcher(creds), TimeSpan.FromHours(1), TimeSpan.FromHours(1), () => false);

    // ---------------------------------------------------------------------
    // AgentConfigManager: the cached config is judged against the enrolled tenant
    // ---------------------------------------------------------------------

    [Fact]
    public void CachedConfigForAnotherTenant_IsNotUsed_StartsFromDefaults_AndSaysWhy()
    {
        File.WriteAllBytes(_configFile, ConfigBytes(PreviousTenant, 40));
        var log = new CapturingLogger<AgentConfigManager>();

        using var manager = NewManager(CredentialStore.CreateForTests(_suspendedFile), log);

        Assert.Same(AgentConfig.Defaults, manager.Current);
        Assert.Contains(log.Warnings, m =>
            m.Contains("belongs to tenant previous-tenant, not enrolled tenant test-tenant") &&
            m.Contains("Starting from defaults"));
        Assert.True(File.Exists(_configFile), "the cache is left for the enrolled tenant's first accepted config to replace");
    }

    [Fact]
    public void CachedConfigWithNoTenant_IsTreatedAsAMismatch_StartsFromDefaults_AndSaysSo()
    {
        File.WriteAllBytes(_configFile, ConfigBytes(tenantId: null, 40));
        var log = new CapturingLogger<AgentConfigManager>();

        using var manager = NewManager(CredentialStore.CreateForTests(_suspendedFile), log);

        Assert.Same(AgentConfig.Defaults, manager.Current);
        Assert.Contains(log.Warnings, m =>
            m.Contains("has no tenant_id") && m.Contains("treated as another tenant's config and not used"));
    }

    [Fact]
    public void CachedConfigWithEmptyTenant_IsTreatedAsAMismatch()
    {
        File.WriteAllBytes(_configFile, ConfigBytes(tenantId: "", 40));

        using var manager = NewManager(CredentialStore.CreateForTests(_suspendedFile), NullLogger<AgentConfigManager>.Instance);

        Assert.Same(AgentConfig.Defaults, manager.Current);
    }

    [Fact]
    public void CachedConfigForTheEnrolledTenant_IsUsed()
    {
        File.WriteAllBytes(_configFile, ConfigBytes(EnrolledTenant, 40));
        var log = new CapturingLogger<AgentConfigManager>();

        using var manager = NewManager(CredentialStore.CreateForTests(_suspendedFile), log);

        Assert.Equal(40, manager.Current.ConfigVersion);
        Assert.Equal(EnrolledTenant, manager.Current.TenantId);
        Assert.Equal("managed", manager.Current.Tier);
        Assert.Empty(log.Warnings);
    }

    [Fact]
    public void CachedConfigWhileEnrolmentIsPending_IsNotUsed()
    {
        // LoadForStartup returns an empty tenant while only an enrolment token is
        // present: the cached config cannot be shown to belong to the tenant the
        // device is about to join.
        File.WriteAllBytes(_configFile, ConfigBytes(PreviousTenant, 40));
        var log = new CapturingLogger<AgentConfigManager>();

        using var manager = NewManager(CredentialStore.ForTesting("", "", ""), log);

        Assert.Same(AgentConfig.Defaults, manager.Current);
        Assert.Contains(log.Warnings, m => m.Contains("not enrolled tenant (none)"));
    }

    [Fact]
    public void CaseDifferingTenant_IsAnotherTenant()
    {
        File.WriteAllBytes(_configFile, ConfigBytes("TEST-TENANT", 40));

        using var manager = NewManager(CredentialStore.CreateForTests(_suspendedFile), NullLogger<AgentConfigManager>.Instance);

        Assert.Same(AgentConfig.Defaults, manager.Current);
    }

    [Fact]
    public void ReEnrolmentIntoAnotherTenantWhileRunning_StopsApplyingTheOldConfig_LoggedOnce()
    {
        File.WriteAllBytes(_configFile, ConfigBytes(EnrolledTenant, 40));
        var writer = new InMemoryAgentCredentialWriter();
        var creds = CredentialStore.CreateForTests(_suspendedFile, credentialWriter: writer);
        var log = new CapturingLogger<AgentConfigManager>();
        using var manager = NewManager(creds, log);
        Assert.Equal(40, manager.Current.ConfigVersion);

        // What AgentEnroller does after a successful /v1/enrol into another tenant.
        creds.UpdateFromEnrolment("new-tenant", "new-bearer", "aGVsbG8td29ybGQtaG1hYy1zZWNyZXQhISE=");

        Assert.Same(AgentConfig.Defaults, manager.Current);
        Assert.Same(AgentConfig.Defaults, manager.Current);
        Assert.Single(log.Warnings, m => m.Contains("belongs to tenant test-tenant, not enrolled tenant new-tenant"));
        Assert.Equal(new[] { "new-tenant" }, writer.PersistedTenants);
    }

    [Theory]
    [InlineData("test-tenant", "test-tenant", true)]
    [InlineData("test-tenant", "previous-tenant", false)]
    [InlineData("", "test-tenant", false)]
    [InlineData("test-tenant", "", false)]
    [InlineData("", "", false)]
    [InlineData("Test-Tenant", "test-tenant", false)]
    public void BelongsToTenant_RequiresAnExactNonEmptyMatch(string configTenant, string enrolledTenant, bool expected)
    {
        var config = new AgentConfig { TenantId = configTenant };
        Assert.Equal(expected, AgentConfigManager.BelongsToTenant(config, enrolledTenant));
    }

    // ---------------------------------------------------------------------
    // AgentConfigFetcher: validate everything before writing anything
    // ---------------------------------------------------------------------

    private static AgentConfig? CommitVerified(AgentConfigFetcher fetcher, byte[] signedPayload)
    {
        var method = typeof(AgentConfigFetcher).GetMethod(
            "CommitSignatureVerifiedPayload", BindingFlags.NonPublic | BindingFlags.Instance)!;
        return (AgentConfig?)method.Invoke(fetcher, new object[] { signedPayload, "test-key-id" });
    }

    private const string PreviousCache = "{\"tenant_id\":\"test-tenant\",\"config_version\":5}";

    private void SeedLastGood()
    {
        File.WriteAllText(_configFile, PreviousCache);
        AgentConfigRollbackFloor.Write(_floorFile, EnrolledTenant, 5);
    }

    private void AssertCacheAndFloorUntouched()
    {
        Assert.Equal(PreviousCache, File.ReadAllText(_configFile));
        Assert.False(File.Exists(_configFile + ".tmp"));
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 5), AgentConfigRollbackFloor.Read(_floorFile));
    }

    public static IEnumerable<object[]> UndeserializableOutcomes() => new[]
    {
        new object[] { "returns null" },
        new object[] { "throws" },
        new object[] { "binds another tenant" },
        new object[] { "binds another version" },
    };

    [Theory]
    [MemberData(nameof(UndeserializableOutcomes))]
    public void VerifiedPayloadThatDoesNotDeserialize_LeavesCacheAndFloorUntouched(string outcome)
    {
        SeedLastGood();
        var creds = CredentialStore.CreateForTests(_suspendedFile);
        creds.MarkSuspended();
        var log = new CapturingLogger<AgentConfigFetcher>();
        Func<byte[], AgentConfig?> deserialize = outcome switch
        {
            "returns null" => _ => null,
            "throws" => _ => throw new NotSupportedException("typed field this build cannot read"),
            "binds another tenant" => _ => new AgentConfig { TenantId = PreviousTenant, ConfigVersion = 9 },
            _ => _ => new AgentConfig { TenantId = EnrolledTenant, ConfigVersion = 10 },
        };
        var fetcher = new AgentConfigFetcher(log, new NoNetworkFactory(), creds, _configFile, _floorFile, deserialize);

        var result = CommitVerified(fetcher, ConfigBytes(EnrolledTenant, 9));

        Assert.Null(result);
        AssertCacheAndFloorUntouched();
        Assert.Contains(log.Messages, m => m.Contains("rejected:") && m.Contains("cache and floor left unchanged"));
        Assert.DoesNotContain(log.Messages, m => m.Contains("accepted version="));
        Assert.True(creds.IsSuspended, "a config that was not applied is not proof the device is reinstated");
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("42")]
    [InlineData("\"text\"")]
    [InlineData("{\"tenant_id\":7,\"config_version\":9}")]
    [InlineData("{\"tenant_id\":null,\"config_version\":9}")]
    public void VerifiedPayloadThatIsNotAConfigObject_IsRejected_LeavingCacheAndFloorUntouched(string payload)
    {
        SeedLastGood();

        var result = CommitVerified(NewFetcher(CredentialStore.CreateForTests(_suspendedFile)), Encoding.UTF8.GetBytes(payload));

        Assert.Null(result);
        AssertCacheAndFloorUntouched();
    }

    [Fact]
    public void VerifiedPayloadThatDeserializes_IsCommitted_AfterValidation()
    {
        SeedLastGood();
        var creds = CredentialStore.CreateForTests(_suspendedFile);
        creds.MarkSuspended();

        var result = CommitVerified(NewFetcher(creds), ConfigBytes(EnrolledTenant, 9));

        Assert.NotNull(result);
        Assert.Equal(9, result!.ConfigVersion);
        Assert.Equal(ConfigBytes(EnrolledTenant, 9), File.ReadAllBytes(_configFile));
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 9), AgentConfigRollbackFloor.Read(_floorFile));
        Assert.False(creds.IsSuspended);
    }

    // ---------------------------------------------------------------------
    // PAT-1773: a signed revocation is committed, so the floor keeps it denied
    // across restarts and cache loss without a separate denial marker
    // ---------------------------------------------------------------------

    private const string GrantingV5 =
        "{\"tenant_id\":\"test-tenant\",\"config_version\":5,\"app_control_authority\":\"enforce\",\"legacy_app_execution_enabled\":true}";

    public static IEnumerable<object[]> RevokingV6Payloads() => new[]
    {
        // The macOS exit-42 shape: unique top-level members that revoke, with a
        // nested duplicate that fails the macOS verifier's strict parse.
        new object[] { "{\"tenant_id\":\"test-tenant\",\"config_version\":6,\"app_control_authority\":\"report\",\"legacy_app_execution_enabled\":false,\"nested\":{\"key\":1,\"key\":2}}" },
        // Still granting at top level, but ambiguous: the duplicate denies.
        new object[] { "{\"tenant_id\":\"test-tenant\",\"config_version\":6,\"app_control_authority\":\"enforce\",\"legacy_app_execution_enabled\":true,\"nested\":{\"key\":1,\"KEY\":2}}" },
        // A typed field this build cannot bind.
        new object[] { "{\"tenant_id\":\"test-tenant\",\"config_version\":6,\"app_control_authority\":\"report\",\"legacy_app_execution_enabled\":false,\"scan_cadence\":{\"not\":\"a string\"}}" },
    };

    [Theory]
    [MemberData(nameof(RevokingV6Payloads))]
    public void NewerSignedRevocation_IsCommittedAsDeny_AndStaysDeniedAfterRestartAndCacheLoss(string revokingV6)
    {
        File.WriteAllText(_configFile, GrantingV5);
        AgentConfigRollbackFloor.Write(_floorFile, EnrolledTenant, 5);
        var creds = CredentialStore.CreateForTests(_suspendedFile);
        using (var before = NewManager(creds, NullLogger<AgentConfigManager>.Instance))
        {
            Assert.Equal(AppControlAuthority.Enforce, before.Current.AppControlAuthority);
            Assert.True(before.Current.LegacyAppExecutionEnabled);
        }

        var fetcher = NewFetcher(creds);
        var committed = CommitVerified(fetcher, Encoding.UTF8.GetBytes(revokingV6));

        Assert.NotNull(committed);
        Assert.Equal(6, committed!.ConfigVersion);
        Assert.Equal(AppControlAuthority.Report, committed.AppControlAuthority);
        Assert.False(committed.LegacyAppExecutionEnabled);
        Assert.Equal(revokingV6, File.ReadAllText(_configFile));
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 6), AgentConfigRollbackFloor.Read(_floorFile));

        // A replay of the older granting config is refused by the floor.
        Assert.Null(CommitVerified(fetcher, Encoding.UTF8.GetBytes(GrantingV5)));
        Assert.Equal(revokingV6, File.ReadAllText(_configFile));

        // Restart: the cached revocation deserializes to the same deny values.
        using (var restarted = NewManager(creds, NullLogger<AgentConfigManager>.Instance))
        {
            Assert.Equal(6, restarted.Current.ConfigVersion);
            Assert.Equal(AppControlAuthority.Report, restarted.Current.AppControlAuthority);
            Assert.False(restarted.Current.LegacyAppExecutionEnabled);
        }

        // Cache loss: defaults deny, and the floor still refuses the old grant.
        File.Delete(_configFile);
        using (var wiped = NewManager(creds, NullLogger<AgentConfigManager>.Instance))
        {
            Assert.Same(AgentConfig.Defaults, wiped.Current);
            Assert.Equal(AppControlAuthority.Report, wiped.Current.AppControlAuthority);
            Assert.False(wiped.Current.LegacyAppExecutionEnabled);
        }
        Assert.Null(CommitVerified(NewFetcher(creds), Encoding.UTF8.GetBytes(GrantingV5)));
        Assert.False(File.Exists(_configFile));
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 6), AgentConfigRollbackFloor.Read(_floorFile));
    }

    // ---------------------------------------------------------------------
    // Test doubles
    // ---------------------------------------------------------------------

    private sealed class NoNetworkFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            throw new InvalidOperationException("no request is expected in these tests");
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        private readonly object _gate = new();
        public List<string> Messages { get; } = [];
        public List<string> Warnings { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var message = formatter(state, exception);
            lock (_gate)
            {
                Messages.Add(message);
                if (logLevel == LogLevel.Warning) Warnings.Add(message);
            }
        }
    }
}
