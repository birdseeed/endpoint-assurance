using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Compliance;
using Patched.Shared.Contract;
using Patched.Shared.DeviceClassification;
using Patched.Shared.KernelDrivers;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1266 / PAT-1270: integration coverage for InventoryPoster's queue pump
/// wiring and agent_health reporting — the two things that can't be exercised
/// by InventoryQueuePumpTests alone, since those construct the pump directly.
/// Uses the <c>pumpOverride</c> test seam on InventoryPoster's constructor
/// (mirrors ProvenancePoster's own pumpOverride, added by PAT-1249) to hand it
/// a pump pointed at a temp queue directory with a fake HTTP handler, exactly
/// as ProvenancePosterQueueHealthTests fakes the HTTP layer for the
/// provenance sibling.
///
/// Deliberately exercised through <see cref="InventoryPoster.DrainQueueAsync"/>
/// rather than <see cref="InventoryPoster.PostAsync"/>: PostAsync's BuildPayloadAsync
/// step drives real WMI/registry/process collectors (DeviceCollector,
/// InstalledAppScanner, SecurityToolDetector, ...) that are fail-safe by
/// design but not the thing this ticket is about, and standing this
/// process's queue up as `%ProgramData%\Patched` on the box PostAsync would
/// need is out of scope here. DrainQueueAsync exercises the exact same
/// pump call + ReportQueueHealth() pairing PostAsync does, just without
/// requiring a real collected payload — so it proves the health-signal wiring
/// this ticket adds without depending on those collectors.
///
/// Covers the acceptance-criteria flow end to end:
///   • DrainQueueAsync (the method PatchedWorker wires into its tick loop)
///     retains a file that hits 401/403 and reports it as a distinct
///     kind="auth_failure" signal, independent of queue depth.
///   • The signal clears once a later attempt succeeds.
///   • A non-auth failure (e.g. 503) leaves the auth_failure signal clear but
///     leaves the record queued, and PAT-1270's kind="queue_backlog" signal
///     appears with the depth while it does, then clears once the queue
///     drains back to empty.
///   • The two signals are independent and can be active at the same time —
///     an auth failure with an existing on-disk backlog reports both
///     kind="queue_backlog" and kind="auth_failure" simultaneously.
/// </summary>
public sealed class InventoryPosterQueueHealthTests : IDisposable
{
    private readonly string _queueDir;
    private readonly string _healthFile;
    private readonly CredentialStore _creds;
    private readonly AgentHealthStore _agentHealth;

    public InventoryPosterQueueHealthTests()
    {
        var root = Path.Combine(Path.GetTempPath(), $"patched-inventory-poster-health-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        _queueDir   = Path.Combine(root, "inventory-queue");
        _healthFile = Path.Combine(root, "agent-health.json");

        var hmacKey = Convert.ToBase64String(new byte[32]);
        _creds       = CredentialStore.ForTesting("test-tenant", "test-bearer", hmacKey);
        _agentHealth = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, _healthFile);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path.GetDirectoryName(_queueDir)!, recursive: true);
        }
        catch { /* ignore */ }
    }

    private string CreateQueueFile(string name)
    {
        Directory.CreateDirectory(_queueDir);
        var path = Path.Combine(_queueDir, name);
        File.WriteAllText(path, "{\"queued\":true}");
        return path;
    }

    private InventoryPoster NewPoster(
        HttpMessageHandler handler,
        CredentialStore?   credsOverride           = null,
        DeviceCollector?   deviceCollectorOverride = null)
    {
        var creds   = credsOverride ?? _creds;
        var client  = new HttpClient(handler) { BaseAddress = new Uri("https://test.local") };
        var factory = new NamedClientFactory(client);
        var pump = new InventoryQueuePump(NullLogger.Instance, factory, creds, _queueDir);

        return new InventoryPoster(
            NullLogger<InventoryPoster>.Instance,
            factory,
            creds,
            deviceCollectorOverride ?? new DeviceCollector(NullLogger<DeviceCollector>.Instance),
            new ComplianceCollector(NullLogger<ComplianceCollector>.Instance),
            new InstalledAppScanner(NullLogger<InstalledAppScanner>.Instance),
            new SecurityToolDetector(NullLogger<SecurityToolDetector>.Instance, _agentHealth),
            new MeteringCollector(NullLogger<MeteringCollector>.Instance, new UserAssistReader(NullLogger<UserAssistReader>.Instance)),
            new AgentConfigManager(NullLogger<AgentConfigManager>.Instance, new AgentConfigFetcher(NullLogger<AgentConfigFetcher>.Instance, factory, creds,
                Path.Combine(Path.GetDirectoryName(_queueDir)!, "agent-config.json"), Path.Combine(Path.GetDirectoryName(_queueDir)!, "agent-config.version"))),
            new CertCollector(NullLogger<CertCollector>.Instance),
            new LocalAdminCollector(NullLogger<LocalAdminCollector>.Instance),
            new HardwareHealthCollector(NullLogger<HardwareHealthCollector>.Instance),
            new BackupCollector(NullLogger<BackupCollector>.Instance),
            new BrowserExtensionScanner(NullLogger<BrowserExtensionScanner>.Instance, _agentHealth),
            new IdeExtensionScanner(NullLogger<IdeExtensionScanner>.Instance),
            new PackageManagerScanner(NullLogger<PackageManagerScanner>.Instance),
            new LocalModelScanner(NullLogger<LocalModelScanner>.Instance),
            new McpServerScanner(NullLogger<McpServerScanner>.Instance),
            NoKernelDrivers(),
            _agentHealth,
            pumpOverride: pump);
    }

    /// <summary>
    /// PAT-2309: the kernel-driver collector with every source faked, so no test here reads or
    /// hashes the runner's own drivers. The real collector hashes all of
    /// %SystemRoot%\System32\drivers on the Windows runner (up to its 90-second budget), and
    /// KernelDriverInventoryLogic runs at most one hashing worker per process: while that
    /// worker is alive, any other collect reports every row <c>time_budget</c> without opening
    /// anything. xUnit runs test classes in parallel, so KernelDriverCollectorTests failed
    /// intermittently on CI with every row <c>time_budget</c> within milliseconds.
    ///
    /// All three driver sources read as failed, so the block is unavailable on every OS and
    /// the logic returns before it starts a hashing worker at all. The opener says every file
    /// is missing in case it is ever reached.
    /// </summary>
    private static KernelDriverCollector NoKernelDrivers() => new(
        NullLogger<KernelDriverCollector>.Instance,
        systemRoot: () => @"C:\Windows",
        listDirectory: _ => DriverDirectoryListing.Unreadable,
        services: () => DriverServiceEnumeration.Unreadable,
        loaded: () => LoadedModuleList.Unreadable,
        hklm: (_, _) => RegistryRead.Absent,
        codeIntegrityPolicy: () => SourceRead.Absent,
        open: _ => new DriverFileOpen(DriverOpenOutcome.Missing));

    [Fact]
    public async Task BuildPayloadAsync_ComputedOsUpdate_UsesTheSameCycleObject()
    {
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.OK));
        var computed = new OsUpdateInfo
        {
            InstalledOs        = "10.0.26100.6584",
            LatestOs           = "10.0.26100.6584",
            TargetOs           = "10.0.26100.6584",
            State              = OsUpdateState.UpToDate,
            Severity           = OsUpdateSeverity.None,
            SecurityRelevant   = false,
            ActivelyExploited  = false,
            Deadline           = null,
            DeferralsRemaining = 4,
            ReleaseAgeDays     = null,
            CheckedAt          = new DateTimeOffset(2026, 9, 18, 12, 34, 56, TimeSpan.Zero),
        };

        var payload = await poster.BuildPayloadAsync([], [], computed);

        Assert.Same(computed, payload.OsUpdate);
    }

    /// <summary>
    /// PAT-2263: the kernel_drivers block is always on the payload. Every driver source reads
    /// as failed (<see cref="NoKernelDrivers"/>), so it is unavailable, never omitted (which
    /// the platform reads as an agent that predates the block) and never an empty complete
    /// list. The sources are faked (PAT-2309), so this now holds on the Windows runner too
    /// rather than only off Windows; the real reads are covered by
    /// KernelDriverCollectorTests.Collect_WithTheRealReads_NeverThrows.
    /// </summary>
    [Fact]
    public async Task BuildPayloadAsync_AlwaysCarriesAKernelDriversBlock()
    {
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.OK));

        var payload = await poster.BuildPayloadAsync([], [], osUpdate: null);

        Assert.NotNull(payload.KernelDrivers);
        Assert.NotNull(payload.KernelDrivers!.Enforcement);
        Assert.Equal(KernelDriverCollectionStatus.Unavailable, payload.KernelDrivers.CollectionStatus);
        Assert.Null(payload.KernelDrivers.Drivers);
    }

    [Fact]
    public async Task BuildPayloadAsync_UnavailableOsUpdate_LeavesSectionNullForOmission()
    {
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.OK));

        var payload = await poster.BuildPayloadAsync([], [], osUpdate: null);

        Assert.Null(payload.OsUpdate);
    }

    /// <summary>
    /// PAT-1959: the wiring from DeviceCollector into the payload. Without this the
    /// resolver could be perfect and every device would still report no class at all.
    /// device_class is always one of the four values; it is never left null on Windows,
    /// because an omitted key and "unknown" mean the same thing to the server and the
    /// agent should say which of the two it actually is.
    /// </summary>
    [Fact]
    public async Task BuildPayloadAsync_CarriesADeviceClassFromTheCollector()
    {
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.OK));

        var payload = await poster.BuildPayloadAsync([], [], osUpdate: null);

        Assert.Contains(payload.DeviceClass, new[]
        {
            DeviceClassValue.Workstation,
            DeviceClassValue.Server,
            DeviceClassValue.DomainController,
            DeviceClassValue.Unknown,
        });
    }

    /// <summary>
    /// PAT-1959: the honest-gap path, end to end, on every platform.
    ///
    /// The sources are failed deliberately through DeviceCollector's injection seam
    /// rather than by relying on the host lacking WMI and a registry. An earlier version
    /// of this test returned early on Windows, which meant it asserted nothing on
    /// windows-latest, the only platform this agent ships to and the platform CI runs on
    /// (.github/workflows/windows-build.yml). A test that no-ops reads exactly like a
    /// test that passes, which is the failure shape the root AGENTS.md names.
    ///
    /// This is the shape of a locked-down or damaged Windows box: the payload must come
    /// back "unknown" with both optional strings omitted, and the cycle must still build
    /// a full payload rather than throwing.
    /// </summary>
    [Fact]
    public async Task BuildPayloadAsync_WithNoReadableSources_ReportsUnknownRatherThanGuessing()
    {
        var everySourceFails = new DeviceCollector(
            NullLogger<DeviceCollector>.Instance,
            (_, _) => SourceRead.Failed,
            () => SourceRead.Failed);

        var poster = NewPoster(
            new CountingFakeHttpHandler(HttpStatusCode.OK),
            deviceCollectorOverride: everySourceFails);

        var payload = await poster.BuildPayloadAsync([], [], osUpdate: null);

        Assert.Equal(DeviceClassValue.Unknown, payload.DeviceClass);
        Assert.Null(payload.InstallationType);
        Assert.Null(payload.OsCaption);
    }

    /// <summary>
    /// PAT-1959: the same seam proves the other direction, so the test above cannot pass
    /// merely because the wiring drops the fields on the floor. A server that reads
    /// cleanly reaches the payload as a server, with both evidence strings intact.
    /// </summary>
    [Fact]
    public async Task BuildPayloadAsync_WithReadableSources_CarriesTheResolvedClassThrough()
    {
        var aDomainController = new DeviceCollector(
            NullLogger<DeviceCollector>.Instance,
            (_, property) => property == "ProductType"
                ? SourceRead.Present(2u)
                : SourceRead.Present("Microsoft Windows Server 2022 Datacenter"),
            () => SourceRead.Present("Server Core"));

        var poster = NewPoster(
            new CountingFakeHttpHandler(HttpStatusCode.OK),
            deviceCollectorOverride: aDomainController);

        var payload = await poster.BuildPayloadAsync([], [], osUpdate: null);

        Assert.Equal(DeviceClassValue.DomainController, payload.DeviceClass);
        Assert.Equal(InstallationTypeValue.ServerCore, payload.InstallationType);
        Assert.Equal("Microsoft Windows Server 2022 Datacenter", payload.OsCaption);
    }

    [Fact]
    public async Task DrainQueueAsync_OnAuthFailure_RetainsFile_AndReportsDistinctAuthFailureHealth()
    {
        var file = CreateQueueFile("inv-100-1.json");
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.Unauthorized));

        await poster.DrainQueueAsync(CancellationToken.None);

        Assert.True(File.Exists(file), "An already-queued record is retained, not deleted, on an auth failure");

        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        var authEntry = Assert.Single(health!.Degraded, e => e.Kind == "auth_failure" && e.Subject == "inventory");
        Assert.Contains("401", authEntry.Reason);
    }

    [Fact]
    public async Task DrainQueueAsync_On403_ReportsDistinctAuthFailureHealth()
    {
        CreateQueueFile("inv-100-1.json");
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.Forbidden));

        await poster.DrainQueueAsync(CancellationToken.None);

        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        Assert.Contains(health!.Degraded, e => e.Kind == "auth_failure" && e.Subject == "inventory");
    }

    [Fact]
    public async Task DrainQueueAsync_AuthFailureThenSuccess_ClearsAuthFailureHealth()
    {
        CreateQueueFile("inv-100-1.json");
        var handler = new SequencedFakeHttpHandler(HttpStatusCode.Unauthorized, HttpStatusCode.OK);
        var poster = NewPoster(handler);

        // First tick: the queued file hits 401 — retained, flagged degraded.
        await poster.DrainQueueAsync(CancellationToken.None);
        Assert.Contains(_agentHealth.BuildPayloadSection()!.Degraded, e => e.Kind == "auth_failure" && e.Subject == "inventory");

        // Simulates the credential being fixed (e.g. re-enrollment) before
        // the next tick's retry, which now succeeds.
        await poster.DrainQueueAsync(CancellationToken.None);

        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        Assert.DoesNotContain(health!.Degraded, e => e.Kind == "auth_failure" && e.Subject == "inventory");
        Assert.Empty(Directory.GetFiles(_queueDir, "inv-*.json"));
    }

    [Fact]
    public async Task DrainQueueAsync_NonAuthFailure_NeverReportsAuthFailureHealth()
    {
        CreateQueueFile("inv-100-1.json");
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.ServiceUnavailable));

        await poster.DrainQueueAsync(CancellationToken.None);

        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        Assert.DoesNotContain(health!.Degraded, e => e.Kind == "auth_failure" && e.Subject == "inventory");
    }

    [Fact]
    public async Task DrainQueueAsync_EmptyQueue_Success_LeavesAuthFailureHealthClear()
    {
        // No queued files at all — DrainQueueAsync makes no HTTP attempt, so
        // LastAttemptWasAuthFailure stays at its default (false) and the
        // health signal stays clear (RecordSuccess is idempotent here).
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.OK));

        await poster.DrainQueueAsync(CancellationToken.None);

        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        Assert.DoesNotContain(health!.Degraded, e => e.Kind == "auth_failure" && e.Subject == "inventory");
    }

    // ------------------------------------------------------------------ //
    // queue_backlog (PAT-1270)                                             //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task DrainQueueAsync_QueuedFileRetained_ReportsQueueBacklogHealth_WithDepth()
    {
        CreateQueueFile("inv-100-1.json");
        CreateQueueFile("inv-200-1.json");
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.ServiceUnavailable));

        // One-per-tick drain fails to send the rotated file, so it stays
        // queued and the depth (still 2 — nothing drained) must be visible.
        await poster.DrainQueueAsync(CancellationToken.None);

        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        var entry = Assert.Single(health!.Degraded, e => e.Kind == "queue_backlog" && e.Subject == "inventory");
        Assert.Contains("2 record", entry.Reason);
    }

    [Fact]
    public async Task DrainQueueAsync_QueueDrainsToEmpty_ClearsQueueBacklogHealth()
    {
        CreateQueueFile("inv-100-1.json");
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.OK));

        // Depth starts at 1; the queued file is retried and, on 2xx, deleted
        // — the health signal must clear along with the on-disk queue.
        await poster.DrainQueueAsync(CancellationToken.None);

        Assert.Empty(Directory.GetFiles(_queueDir, "inv-*.json"));
        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        Assert.DoesNotContain(health!.Degraded, e => e.Kind == "queue_backlog" && e.Subject == "inventory");
    }

    [Fact]
    public async Task DrainQueueAsync_BacklogThenDrains_QueueBacklogHealthTracksBothDirections()
    {
        CreateQueueFile("inv-100-1.json");
        var handler = new SequencedFakeHttpHandler(HttpStatusCode.ServiceUnavailable, HttpStatusCode.OK);
        var poster = NewPoster(handler);

        // First tick: 503 — file retained, backlog signal appears.
        await poster.DrainQueueAsync(CancellationToken.None);
        Assert.Contains(_agentHealth.BuildPayloadSection()!.Degraded, e => e.Kind == "queue_backlog" && e.Subject == "inventory");

        // Second tick: succeeds — file deleted, backlog signal clears.
        await poster.DrainQueueAsync(CancellationToken.None);
        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        Assert.DoesNotContain(health!.Degraded, e => e.Kind == "queue_backlog" && e.Subject == "inventory");
        Assert.Empty(Directory.GetFiles(_queueDir, "inv-*.json"));
    }

    [Fact]
    public async Task DrainQueueAsync_EmptyQueue_LeavesQueueBacklogHealthClear()
    {
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.OK));

        await poster.DrainQueueAsync(CancellationToken.None);

        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        Assert.DoesNotContain(health!.Degraded, e => e.Kind == "queue_backlog" && e.Subject == "inventory");
    }

    [Fact]
    public async Task DrainQueueAsync_AuthFailureWithExistingBacklog_ReportsBothSignalsSimultaneously()
    {
        // PAT-1270: queue_backlog and auth_failure are independent signals —
        // they are not mutually exclusive. An existing on-disk backlog (from
        // earlier transient failures) plus a now-broken credential must
        // surface both degraded kinds at once, not just the most recent one.
        CreateQueueFile("inv-100-1.json");
        CreateQueueFile("inv-200-1.json");
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.Unauthorized));

        await poster.DrainQueueAsync(CancellationToken.None);

        // Neither file is deleted on an auth failure — depth stays at 2.
        Assert.Equal(2, Directory.GetFiles(_queueDir, "inv-*.json").Length);

        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        var backlogEntry = Assert.Single(health!.Degraded, e => e.Kind == "queue_backlog" && e.Subject == "inventory");
        Assert.Contains("2 record", backlogEntry.Reason);
        var authEntry = Assert.Single(health.Degraded, e => e.Kind == "auth_failure" && e.Subject == "inventory");
        Assert.Contains("401", authEntry.Reason);
    }

    // ------------------------------------------------------------------ //
    // Test doubles                                                         //
    // ------------------------------------------------------------------ //

    private sealed class NamedClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public NamedClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class CountingFakeHttpHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        public int CallCount { get; private set; }

        public CountingFakeHttpHandler(HttpStatusCode status) => _status = status;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(new HttpResponseMessage(_status));
        }
    }

    private sealed class SequencedFakeHttpHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode[] _codes;
        private int _index;
        public int CallCount { get; private set; }

        public SequencedFakeHttpHandler(params HttpStatusCode[] codes) => _codes = codes;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            var code = _codes[Math.Min(_index++, _codes.Length - 1)];
            return Task.FromResult(new HttpResponseMessage(code));
        }
    }

    // PAT-1765: the sender checks the credential pair itself, so nothing is
    // collected, sent or queued without one, whichever caller reaches it.
    [Theory]
    [InlineData("", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("test-bearer", "   ")]
    public async Task PostAndDrain_NoUsableCredentialPair_SendNothing_AndKeepTheQueue(string bearer, string secret)
    {
        var queued = CreateQueueFile("inv-100-1.json");
        var handler = new CountingFakeHttpHandler(HttpStatusCode.OK);
        var poster = NewPoster(handler, CredentialStore.ForTesting("test-tenant", bearer, secret));

        // PostAsync returns before BuildPayloadAsync, so no collector runs either.
        await poster.PostAsync([], [], osUpdate: null, ct: CancellationToken.None);
        await poster.DrainQueueAsync(CancellationToken.None);

        Assert.Equal(0, handler.CallCount);
        Assert.True(File.Exists(queued));
        Assert.Single(Directory.GetFiles(_queueDir));
    }
}
