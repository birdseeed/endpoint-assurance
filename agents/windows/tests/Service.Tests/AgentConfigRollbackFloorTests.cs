using System.Net;
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
/// PAT-1756: the agent-config anti-rollback floor is keyed by tenant.
///
/// WIN-STAGING (2026-09-14) held a bare floor of 12 written under one tenant,
/// re-enrolled into a tenant whose config_version was 3, and rejected every
/// signature-verified config for that tenant, so it could not leave suspension.
///
/// Three layers are covered:
///   - <see cref="AgentConfigRollbackFloor"/> itself: format, legacy migration,
///     corrupt handling, the comparison and the If-None-Match choice.
///   - AgentConfigFetcher's post-signature step (tenant binding, then the floor,
///     then the commit), reached by reflection because it is private on purpose
///     and the Ed25519 key is pinned with no test seam. Every path is a scratch
///     path through the internal constructor, never %ProgramData%\Patched.
///   - AgentEnroller's reset on a successful enrolment, with credentials stored in
///     the test store's in-memory writer so the real Windows Credential Manager is
///     never touched (PAT-1763).
/// </summary>
public sealed class AgentConfigRollbackFloorTests : IDisposable
{
    private const string EnrolledTenant = "test-tenant"; // CredentialStore.CreateForTests' tenant
    private const string PreviousTenant = "previous-tenant";

    private readonly string _tempDir;
    private readonly string _suspendedFile;
    private readonly string _floorFile;
    private readonly string _configFile;

    public AgentConfigRollbackFloorTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-acf-floor-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _suspendedFile = Path.Combine(_tempDir, "creds", "suspended");
        _floorFile     = Path.Combine(_tempDir, "agent-config.version");
        _configFile    = Path.Combine(_tempDir, "agent-config.json");
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

    // ---------------------------------------------------------------------
    // Format
    // ---------------------------------------------------------------------

    [Fact]
    public void Read_MissingFile_IsAbsent()
    {
        var floor = AgentConfigRollbackFloor.Read(_floorFile);
        Assert.Equal(AgentConfigRollbackFloor.FloorState.Absent, floor.State);
    }

    [Fact]
    public void Write_ThenRead_RoundTripsKeyedFloor_WithNoTempFileLeft()
    {
        AgentConfigRollbackFloor.Write(_floorFile, EnrolledTenant, 12);

        Assert.Equal("{\"tenant_id\":\"test-tenant\",\"config_version\":12}", File.ReadAllText(_floorFile));
        Assert.False(File.Exists(_floorFile + ".tmp"));
        var floor = AgentConfigRollbackFloor.Read(_floorFile);
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 12), floor);
        Assert.False(floor.IsLegacy);
    }

    [Theory]
    [InlineData("12", 12)]
    [InlineData("12\n", 12)]
    [InlineData("  0  ", 0)]
    public void Parse_BareInteger_IsLegacyFloor(string content, int expected)
    {
        var floor = AgentConfigRollbackFloor.Parse(Encoding.UTF8.GetBytes(content));
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Legacy(expected), floor);
        Assert.True(floor.IsLegacy);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   \n")]
    [InlineData("-1")]
    [InlineData("12abc")]
    [InlineData("99999999999")]
    [InlineData("[12]")]
    [InlineData("{\"tenant_id\":\"t\"}")]
    [InlineData("{\"config_version\":3}")]
    [InlineData("{\"tenant_id\":\"\",\"config_version\":3}")]
    [InlineData("{\"tenant_id\":\"t\",\"config_version\":-3}")]
    [InlineData("{\"tenant_id\":\"t\",\"config_version\":3.5}")]
    [InlineData("{\"tenant_id\":\"t\",\"config_version\":\"3\"}")]
    [InlineData("{\"tenant_id\":7,\"config_version\":3}")]
    [InlineData("{\"tenant_id\":\"t\",\"config_version\":3,\"extra\":1}")]
    [InlineData("{\"tenant_id\":\"t\",\"tenant_id\":\"u\",\"config_version\":3}")]
    [InlineData("{\"tenant_id\":\"t\",\"config_version\":3,\"config_version\":1}")]
    [InlineData("{\"tenant_id\":\"t\",\"config_version\":3")]
    public void Parse_MalformedContent_IsCorrupt(string content)
    {
        var floor = AgentConfigRollbackFloor.Parse(Encoding.UTF8.GetBytes(content));
        Assert.Equal(AgentConfigRollbackFloor.FloorState.Corrupt, floor.State);
        Assert.False(string.IsNullOrEmpty(floor.Problem));
    }

    [Fact]
    public void Parse_InvalidUtf8_IsCorrupt()
    {
        var floor = AgentConfigRollbackFloor.Parse(new byte[] { 0x31, 0xFF, 0x32 });
        Assert.Equal(AgentConfigRollbackFloor.FloorState.Corrupt, floor.State);
    }

    [Fact]
    public void Read_OversizedFile_IsCorrupt()
    {
        File.WriteAllText(_floorFile, new string(' ', AgentConfigRollbackFloor.MaxFileBytes) + "12");
        Assert.Equal(AgentConfigRollbackFloor.FloorState.Corrupt, AgentConfigRollbackFloor.Read(_floorFile).State);
    }

    // ---------------------------------------------------------------------
    // Comparison
    // ---------------------------------------------------------------------

    [Fact]
    public void Evaluate_SameTenantLowerVersion_IsRejected_NamingTheTenant()
    {
        var decision = AgentConfigRollbackFloor.Evaluate(
            AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 12), EnrolledTenant, 3);

        Assert.False(decision.Accept);
        Assert.Contains("new version 3 < last accepted 12 for tenant test-tenant", decision.Message);
    }

    [Theory]
    [InlineData(12)]
    [InlineData(13)]
    public void Evaluate_SameTenantEqualOrHigherVersion_IsAccepted(int newVersion)
    {
        var decision = AgentConfigRollbackFloor.Evaluate(
            AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 12), EnrolledTenant, newVersion);

        Assert.True(decision.Accept);
        Assert.Contains("for tenant test-tenant", decision.Message);
    }

    [Fact]
    public void Evaluate_DifferentTenantLowerVersion_IsAcceptedAsFreshFloor_NamingBothTenants()
    {
        var decision = AgentConfigRollbackFloor.Evaluate(
            AgentConfigRollbackFloor.StoredFloor.Keyed(PreviousTenant, 12), EnrolledTenant, 3);

        Assert.True(decision.Accept);
        Assert.Contains("tenant previous-tenant (version 12)", decision.Message);
        Assert.Contains("tenant test-tenant starts a fresh floor at version 3", decision.Message);
    }

    [Fact]
    public void Evaluate_LegacyFloorLowerVersion_IsRejected()
    {
        var decision = AgentConfigRollbackFloor.Evaluate(
            AgentConfigRollbackFloor.StoredFloor.Legacy(12), EnrolledTenant, 3);

        Assert.False(decision.Accept);
        Assert.Contains("new version 3 < last accepted 12 for tenant test-tenant (legacy floor", decision.Message);
    }

    [Fact]
    public void Evaluate_LegacyFloorHigherVersion_IsAccepted()
    {
        Assert.True(AgentConfigRollbackFloor.Evaluate(
            AgentConfigRollbackFloor.StoredFloor.Legacy(5), EnrolledTenant, 7).Accept);
    }

    [Fact]
    public void Evaluate_NoFloor_IsAccepted()
    {
        Assert.True(AgentConfigRollbackFloor.Evaluate(
            AgentConfigRollbackFloor.StoredFloor.Absent(), EnrolledTenant, 1).Accept);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(int.MaxValue)]
    public void Evaluate_CorruptFloor_RejectsEveryVersion(int newVersion)
    {
        var decision = AgentConfigRollbackFloor.Evaluate(
            AgentConfigRollbackFloor.StoredFloor.Corrupt("file is empty"), EnrolledTenant, newVersion);

        Assert.False(decision.Accept);
        Assert.Contains("for tenant test-tenant", decision.Message);
    }

    [Fact]
    public void Messages_ContainNoEmDashes()
    {
        var messages = new[]
        {
            AgentConfigRollbackFloor.Evaluate(AgentConfigRollbackFloor.StoredFloor.Absent(), EnrolledTenant, 1).Message,
            AgentConfigRollbackFloor.Evaluate(AgentConfigRollbackFloor.StoredFloor.Corrupt("x"), EnrolledTenant, 1).Message,
            AgentConfigRollbackFloor.Evaluate(AgentConfigRollbackFloor.StoredFloor.Keyed(PreviousTenant, 9), EnrolledTenant, 1).Message,
            AgentConfigRollbackFloor.Evaluate(AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 9), EnrolledTenant, 1).Message,
            AgentConfigRollbackFloor.Evaluate(AgentConfigRollbackFloor.StoredFloor.Legacy(9), EnrolledTenant, 10).Message,
        };
        Assert.All(messages, m => Assert.DoesNotContain("—", m));
    }

    [Fact]
    public void ConditionalGetVersion_OnlyForAFloorKeyedToTheEnrolledTenant()
    {
        Assert.Equal(12, AgentConfigRollbackFloor.ConditionalGetVersion(
            AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 12), EnrolledTenant));
        // A legacy floor carries no tenant and may be another tenant's: no validator.
        Assert.Null(AgentConfigRollbackFloor.ConditionalGetVersion(
            AgentConfigRollbackFloor.StoredFloor.Legacy(12), EnrolledTenant));
        Assert.Null(AgentConfigRollbackFloor.ConditionalGetVersion(
            AgentConfigRollbackFloor.StoredFloor.Keyed(PreviousTenant, 12), EnrolledTenant));
        Assert.Null(AgentConfigRollbackFloor.ConditionalGetVersion(
            AgentConfigRollbackFloor.StoredFloor.Corrupt("x"), EnrolledTenant));
        Assert.Null(AgentConfigRollbackFloor.ConditionalGetVersion(
            AgentConfigRollbackFloor.StoredFloor.Absent(), EnrolledTenant));
    }

    // ---------------------------------------------------------------------
    // AgentConfigFetcher: tenant binding, then floor, then commit
    // ---------------------------------------------------------------------

    private AgentConfigFetcher NewFetcher(ILogger<AgentConfigFetcher>? log = null, HttpMessageHandler? handler = null) =>
        new(log ?? NullLogger<AgentConfigFetcher>.Instance,
            new FakeHttpClientFactory(handler ?? new RecordingHandler()),
            CredentialStore.CreateForTests(_suspendedFile),
            _configFile, _floorFile);

    private static byte[] Payload(string tenantId, int version) =>
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { tenant_id = tenantId, config_version = version, tier = "report" }));

    /// <summary>
    /// Invokes the private post-signature step. Only reachable in production
    /// after the Ed25519 signature has verified (see the file header).
    /// </summary>
    private static AgentConfig? CommitVerified(AgentConfigFetcher fetcher, byte[] signedPayload)
    {
        var method = typeof(AgentConfigFetcher).GetMethod(
            "CommitSignatureVerifiedPayload", BindingFlags.NonPublic | BindingFlags.Instance)!;
        return (AgentConfig?)method.Invoke(fetcher, new object[] { signedPayload, "test-key-id" });
    }

    [Fact]
    public void Commit_SameTenantLowerVersion_IsRejected_CacheAndFloorUntouched()
    {
        AgentConfigRollbackFloor.Write(_floorFile, EnrolledTenant, 12);
        var log = new CapturingLogger<AgentConfigFetcher>();

        var result = CommitVerified(NewFetcher(log), Payload(EnrolledTenant, 3));

        Assert.Null(result);
        Assert.False(File.Exists(_configFile));
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 12), AgentConfigRollbackFloor.Read(_floorFile));
        Assert.Contains(log.Messages, m => m.Contains("rejected: anti-rollback: new version 3 < last accepted 12 for tenant test-tenant"));
    }

    [Fact]
    public void Commit_SameTenantHigherVersion_IsAccepted_FloorAdvances()
    {
        AgentConfigRollbackFloor.Write(_floorFile, EnrolledTenant, 12);

        var result = CommitVerified(NewFetcher(), Payload(EnrolledTenant, 13));

        Assert.NotNull(result);
        Assert.Equal(13, result!.ConfigVersion);
        Assert.True(File.Exists(_configFile));
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 13), AgentConfigRollbackFloor.Read(_floorFile));
    }

    [Fact]
    public void Commit_DifferentTenantFloorLowerVersion_IsAccepted_FloorReKeysToVerifiedTenant()
    {
        AgentConfigRollbackFloor.Write(_floorFile, PreviousTenant, 12);
        var log = new CapturingLogger<AgentConfigFetcher>();

        var result = CommitVerified(NewFetcher(log), Payload(EnrolledTenant, 3));

        Assert.NotNull(result);
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 3), AgentConfigRollbackFloor.Read(_floorFile));
        Assert.Contains(log.Messages, m => m.Contains("stored floor belongs to tenant previous-tenant (version 12)"));
    }

    [Fact]
    public void Commit_PayloadForAnotherTenant_IsRejectedByTenantBinding_EvenWhenAFloorForThatTenantIsLower()
    {
        // A signed config for a tenant the device is not enrolled in must never
        // reach the fresh-floor rule.
        AgentConfigRollbackFloor.Write(_floorFile, PreviousTenant, 1);
        var log = new CapturingLogger<AgentConfigFetcher>();

        var result = CommitVerified(NewFetcher(log), Payload(PreviousTenant, 50));

        Assert.Null(result);
        Assert.False(File.Exists(_configFile));
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed(PreviousTenant, 1), AgentConfigRollbackFloor.Read(_floorFile));
        Assert.Contains(log.Messages, m => m.Contains("tenant_id in signed_payload does not match local tenant-id credential"));
        Assert.DoesNotContain(log.Messages, m => m.Contains("anti-rollback"));
    }

    [Fact]
    public void Commit_TenantBindingRunsBeforeTheFloor_WrongTenantWithCorruptFloorNamesTheTenantMismatch()
    {
        File.WriteAllText(_floorFile, "not a floor");
        var log = new CapturingLogger<AgentConfigFetcher>();

        Assert.Null(CommitVerified(NewFetcher(log), Payload(PreviousTenant, 5)));

        Assert.Contains(log.Messages, m => m.Contains("tenant_id in signed_payload does not match local tenant-id credential"));
        Assert.DoesNotContain(log.Messages, m => m.Contains("anti-rollback"));
    }

    [Fact]
    public void Commit_LegacyBareIntegerSameTenantLowerVersion_IsRejected()
    {
        File.WriteAllText(_floorFile, "12");

        Assert.Null(CommitVerified(NewFetcher(), Payload(EnrolledTenant, 3)));

        Assert.Equal("12", File.ReadAllText(_floorFile));
        Assert.False(File.Exists(_configFile));
    }

    [Fact]
    public void Commit_LegacyBareIntegerSameTenantHigherVersion_IsAccepted_AndMigratesToKeyedFormat()
    {
        File.WriteAllText(_floorFile, "5\n");

        Assert.NotNull(CommitVerified(NewFetcher(), Payload(EnrolledTenant, 7)));

        Assert.Equal("{\"tenant_id\":\"test-tenant\",\"config_version\":7}", File.ReadAllText(_floorFile));
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("{\"tenant_id\":\"test-tenant\",\"config_version\":\"12\"}")]
    public void Commit_CorruptFloorSameTenant_RejectsEvenAHighVersion_AndLeavesFloorForAnOperator(string corrupt)
    {
        File.WriteAllText(_floorFile, corrupt);
        var log = new CapturingLogger<AgentConfigFetcher>();

        Assert.Null(CommitVerified(NewFetcher(log), Payload(EnrolledTenant, 1000)));

        Assert.False(File.Exists(_configFile));
        Assert.Equal(corrupt, File.ReadAllText(_floorFile));
        Assert.Contains(log.Messages, m => m.Contains("stored floor is unusable") && m.Contains("tenant test-tenant"));
    }

    [Theory]
    [InlineData("{\"tenant_id\":\"test-tenant\",\"config_version\":12}", null)]
    [InlineData("12", null)]
    [InlineData("{\"tenant_id\":\"previous-tenant\",\"config_version\":12}", null)]
    [InlineData("corrupt", null)]
    public async Task FetchAsync_MissingVerifiedEnvelopeRefetchesEvenWithATenantKeyedFloor(string floorContent, string? expectedEtag)
    {
        File.WriteAllText(_floorFile, floorContent);
        var handler = new RecordingHandler { ResponseStatus = HttpStatusCode.NotModified };

        Assert.Null(await NewFetcher(handler: handler).FetchAsync(CancellationToken.None));

        Assert.NotNull(handler.LastRequest);
        var tags = handler.LastRequest!.Headers.IfNoneMatch.Select(t => t.Tag).ToList();
        if (expectedEtag is null)
            Assert.Empty(tags);
        else
            Assert.Equal(expectedEtag, Assert.Single(tags));
    }

    // ---------------------------------------------------------------------
    // AgentEnroller: reset on successful enrolment only
    // ---------------------------------------------------------------------

    private static string EnrolSuccessBody(string tenantId) =>
        JsonSerializer.Serialize(new { tenant_id = tenantId, bearer_token = "new-bearer", hmac_secret = "aGVsbG8td29ybGQtaG1hYy1zZWNyZXQhISE=" });

    [Theory]
    [InlineData("00000000-0000-0000-0000-000000002005", "00000000-0000-0000-0000-000000002005")]
    [InlineData("hardware-serial", null)]
    [InlineData("00000000-0000-0000-0000-000000000000", null)]
    public async Task EnrolmentPersistsOnlyCanonicalServerDeviceId(string deviceId, string? expected)
    {
        string body = JsonSerializer.Serialize(new
        {
            tenant_id = EnrolledTenant,
            bearer_token = "new-bearer",
            hmac_secret = "aGVsbG8td29ybGQtaG1hYy1zZWNyZXQhISE=",
            device_id = deviceId
        });
        var (enroller, creds, _) = NewPendingEnroller(HttpStatusCode.OK, body);
        Assert.True(await enroller.TryEnrolAsync(CancellationToken.None));
        Assert.Equal(expected, creds.CanonicalDeviceId);
    }

    /// <summary>
    /// PAT-1763: credentials are stored through the store's in-memory writer
    /// (<paramref name="writer"/>, or a fresh one), never the host Credential Manager.
    /// </summary>
    private (AgentEnroller Enroller, CredentialStore Creds, RecordingHandler Handler) NewPendingEnroller(
        HttpStatusCode status, string body, InMemoryAgentCredentialWriter? writer = null)
    {
        var creds = CredentialStore.CreateForTests(
            _suspendedFile, bearerToken: "", enrollmentTokenSource: () => "fresh-token", credentialWriter: writer);
        Assert.True(creds.RefreshEnrollmentToken());
        var handler = new RecordingHandler { ResponseStatus = status, ResponseBody = body };
        var enroller = new AgentEnroller(
            NullLogger<AgentEnroller>.Instance, new FakeHttpClientFactory(handler), creds, _floorFile);
        return (enroller, creds, handler);
    }

    [Fact]
    public async Task Enrol_Success_ResetsTheFloor()
    {
        AgentConfigRollbackFloor.Write(_floorFile, PreviousTenant, 12);
        var writer = new InMemoryAgentCredentialWriter();
        var (enroller, _, handler) = NewPendingEnroller(
            HttpStatusCode.OK, EnrolSuccessBody(EnrolledTenant), writer);

        Assert.True(await enroller.TryEnrolAsync(CancellationToken.None));

        Assert.Equal(1, handler.RequestCount);
        Assert.Equal(new[] { EnrolledTenant }, writer.PersistedTenants);
        Assert.False(File.Exists(_floorFile));
    }

    [Fact]
    public async Task Enrol_SameTenantReenrolment_KeepsKeyedFloor_SoAnOlderSignedConfigIsStillRejected()
    {
        AgentConfigRollbackFloor.Write(_floorFile, EnrolledTenant, 12);
        var (enroller, _, _) = NewPendingEnroller(HttpStatusCode.OK, EnrolSuccessBody(EnrolledTenant));

        Assert.True(await enroller.TryEnrolAsync(CancellationToken.None));

        Assert.Equal("{\"tenant_id\":\"test-tenant\",\"config_version\":12}", File.ReadAllText(_floorFile));
        Assert.Null(CommitVerified(NewFetcher(), Payload(EnrolledTenant, 3)));
        Assert.False(File.Exists(_configFile));
    }

    [Theory]
    [InlineData("12")]
    [InlineData("not a floor")]
    [InlineData("{\"tenant_id\":\"previous-tenant\",\"config_version\":12}")]
    public async Task Enrol_LegacyCorruptOrOtherTenantFloor_IsRemoved(string floorContent)
    {
        File.WriteAllText(_floorFile, floorContent);
        var (enroller, _, _) = NewPendingEnroller(HttpStatusCode.OK, EnrolSuccessBody(EnrolledTenant));

        Assert.True(await enroller.TryEnrolAsync(CancellationToken.None));

        Assert.False(File.Exists(_floorFile));
    }

    [Fact]
    public async Task Enrol_FloorWrittenForEnrolledTenantAfterCredentialWrite_SurvivesTheReset()
    {
        // Models AgentConfigManager accepting a config for the new tenant in the
        // gap between the credential write and the reset: once the last credential
        // is stored, a verified commit writes {test-tenant,3} over the legacy floor
        // the old tenant left.
        File.WriteAllText(_floorFile, "12");
        var (enroller, _, _) = NewPendingEnroller(
            HttpStatusCode.OK, EnrolSuccessBody(EnrolledTenant),
            new InMemoryAgentCredentialWriter
            {
                OnWrite = (target, _) =>
                {
                    if (target == CredentialStore.TargetHmacSecret)
                        AgentConfigRollbackFloor.Write(_floorFile, EnrolledTenant, 3);
                },
            });

        Assert.True(await enroller.TryEnrolAsync(CancellationToken.None));

        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 3), AgentConfigRollbackFloor.Read(_floorFile));
    }

    [Fact]
    public void Read_FileThatCannotBeOpened_IsUnreadable_NotCorrupt()
    {
        Directory.CreateDirectory(_floorFile); // opening a directory as a file fails on every platform

        var floor = AgentConfigRollbackFloor.Read(_floorFile);

        Assert.Equal(AgentConfigRollbackFloor.FloorState.Unreadable, floor.State);
        Assert.False(AgentConfigRollbackFloor.Evaluate(floor, EnrolledTenant, 1000).Accept);
        Assert.Null(AgentConfigRollbackFloor.ConditionalGetVersion(floor, EnrolledTenant));
    }

    [Theory]
    [InlineData("{\"tenant_id\":\"test-tenant\",\"config_version\":12}")]
    [InlineData("12")]
    public void Reset_UnreadableFloor_IsKept_AndALowerVersionIsStillRejected(string onDisk)
    {
        // The service could not read the file (for example a standard user holds
        // it open with FileShare.Delete only). Whatever it holds, it must not be
        // deleted: that would strip a same-tenant floor and reopen replay.
        File.WriteAllText(_floorFile, onDisk);

        var outcome = AgentConfigRollbackFloor.ResetForEnrolment(
            _floorFile, EnrolledTenant, out var floor, out _,
            _ => AgentConfigRollbackFloor.StoredFloor.Unreadable("file could not be opened or read (IOException)"));

        Assert.Equal(AgentConfigRollbackFloor.EnrolmentResetOutcome.KeptUnreadable, outcome);
        Assert.Equal(AgentConfigRollbackFloor.FloorState.Unreadable, floor.State);
        Assert.Equal(onDisk, File.ReadAllText(_floorFile));
        Assert.Null(CommitVerified(NewFetcher(), Payload(EnrolledTenant, 3)));
    }

    [Fact]
    public async Task Enrol_FloorHeldOpenWithDeleteOnlyShare_IsKept_AndALowerVersionIsStillRejected()
    {
        // The real sharing-violation shape. On Windows the service's read fails
        // (unreadable) while a delete would succeed. POSIX does not enforce
        // FileShare, so elsewhere the read succeeds and the same-tenant rule keeps
        // it. Either way the floor must survive.
        AgentConfigRollbackFloor.Write(_floorFile, EnrolledTenant, 12);
        var expected = OperatingSystem.IsWindows()
            ? AgentConfigRollbackFloor.EnrolmentResetOutcome.KeptUnreadable
            : AgentConfigRollbackFloor.EnrolmentResetOutcome.KeptSameTenant;

        using (new FileStream(_floorFile, FileMode.Open, FileAccess.Read, FileShare.Delete))
        {
            Assert.Equal(expected, AgentConfigRollbackFloor.ResetForEnrolment(_floorFile, EnrolledTenant, out _, out _));

            var (enroller, _, _) = NewPendingEnroller(HttpStatusCode.OK, EnrolSuccessBody(EnrolledTenant));
            Assert.True(await enroller.TryEnrolAsync(CancellationToken.None));
            Assert.True(File.Exists(_floorFile));
        }

        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 12), AgentConfigRollbackFloor.Read(_floorFile));
        Assert.Null(CommitVerified(NewFetcher(), Payload(EnrolledTenant, 3)));
    }

    [Fact]
    public void Reset_ReadsChangeFromLegacyToCorruptToSameTenant_FloorIsKept()
    {
        File.WriteAllText(_floorFile, "12");
        var sequence = new Queue<AgentConfigRollbackFloor.StoredFloor>(new[]
        {
            AgentConfigRollbackFloor.StoredFloor.Legacy(12),
            AgentConfigRollbackFloor.StoredFloor.Corrupt("file is empty"),
            AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 3),
        });
        var last = sequence.Last();

        var outcome = AgentConfigRollbackFloor.ResetForEnrolment(
            _floorFile, EnrolledTenant, out var floor, out _,
            _ => sequence.Count > 0 ? sequence.Dequeue() : last);

        Assert.Equal(AgentConfigRollbackFloor.EnrolmentResetOutcome.KeptSameTenant, outcome);
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 3), floor);
        Assert.True(File.Exists(_floorFile));
    }

    [Fact]
    public void Reset_ReadsNeverAgree_FloorIsKept()
    {
        File.WriteAllText(_floorFile, "12");
        int reads = 0;

        var outcome = AgentConfigRollbackFloor.ResetForEnrolment(
            _floorFile, EnrolledTenant, out _, out _,
            _ => ++reads % 2 == 1
                ? AgentConfigRollbackFloor.StoredFloor.Legacy(12)
                : AgentConfigRollbackFloor.StoredFloor.Corrupt("file is empty"));

        Assert.Equal(AgentConfigRollbackFloor.EnrolmentResetOutcome.KeptUnstable, outcome);
        Assert.Equal(AgentConfigRollbackFloor.EnrolmentResetMaxReads, reads);
        Assert.Equal("12", File.ReadAllText(_floorFile));
    }

    [Fact]
    public void Reset_TwoAgreeingReadsOfARemovableFloor_Removes()
    {
        File.WriteAllText(_floorFile, "12");

        Assert.Equal(AgentConfigRollbackFloor.EnrolmentResetOutcome.Removed,
            AgentConfigRollbackFloor.ResetForEnrolment(_floorFile, EnrolledTenant, out _, out _));
        Assert.False(File.Exists(_floorFile));
    }

    [Fact]
    public async Task Enrol_CredentialWriteFails_DoesNotResetTheFloor()
    {
        AgentConfigRollbackFloor.Write(_floorFile, PreviousTenant, 12);
        var (enroller, _, handler) = NewPendingEnroller(
            HttpStatusCode.OK, EnrolSuccessBody(EnrolledTenant),
            new InMemoryAgentCredentialWriter { FailWith = new InvalidOperationException("credential store unavailable") });

        // PAT-1760: not enrolled (the token is consumed, nothing was stored), so
        // not a transient true any more. See EnrolmentRecoveryGapsTests.
        Assert.False(await enroller.TryEnrolAsync(CancellationToken.None));

        Assert.Equal(1, handler.RequestCount);
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed(PreviousTenant, 12), AgentConfigRollbackFloor.Read(_floorFile));
    }

    [Theory]
    [InlineData(HttpStatusCode.Gone)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task Enrol_NotSuccessful_DoesNotResetTheFloor(HttpStatusCode status)
    {
        File.WriteAllText(_floorFile, "12");
        var writer = new InMemoryAgentCredentialWriter { FailWith = new InvalidOperationException("must not persist") };
        var (enroller, _, _) = NewPendingEnroller(status, "", writer);

        await enroller.TryEnrolAsync(CancellationToken.None);

        Assert.Equal("12", File.ReadAllText(_floorFile));
        Assert.Empty(writer.Written);
    }

    /// <summary>
    /// The WIN-STAGING scenario end to end: a bare legacy floor of 12 left by the
    /// previous tenant, then enrolment into a new tenant whose config_version is
    /// 3. The first signature-verified config for the new tenant is accepted and
    /// becomes a keyed floor.
    /// </summary>
    [Fact]
    public async Task WinStaging_LegacyFloorFromPreviousTenant_ThenEnrolment_AcceptsNewTenantsFirstConfig()
    {
        File.WriteAllText(_floorFile, "12");

        // Without the enrolment reset this is exactly the defect: rejected.
        Assert.Null(CommitVerified(NewFetcher(), Payload(EnrolledTenant, 3)));

        var (enroller, _, _) = NewPendingEnroller(HttpStatusCode.OK, EnrolSuccessBody(EnrolledTenant));
        Assert.True(await enroller.TryEnrolAsync(CancellationToken.None));

        var accepted = CommitVerified(NewFetcher(), Payload(EnrolledTenant, 3));

        Assert.NotNull(accepted);
        Assert.Equal(3, accepted!.ConfigVersion);
        Assert.Equal(AgentConfigRollbackFloor.StoredFloor.Keyed(EnrolledTenant, 3), AgentConfigRollbackFloor.Read(_floorFile));
    }

    // ---------------------------------------------------------------------
    // Test doubles
    // ---------------------------------------------------------------------

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }
        public int RequestCount { get; private set; }
        public HttpStatusCode ResponseStatus { get; set; } = HttpStatusCode.NotModified;
        public string ResponseBody { get; set; } = "";

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            LastRequest = request;
            RequestCount++;
            return Task.FromResult(new HttpResponseMessage(ResponseStatus) { Content = new StringContent(ResponseBody) });
        }
    }

    private sealed class FakeHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false) { BaseAddress = new Uri("https://patched-1756-test.invalid") };
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Messages.Add(formatter(state, exception));
    }
}
