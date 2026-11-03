using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1249: integration coverage for ProvenancePoster's queue pump wiring and
/// agent_health reporting — the two things that can't be exercised by
/// ProvenanceQueuePumpTests alone, since those construct the pump directly.
/// Uses the <c>pumpOverride</c> test seam on ProvenancePoster's constructor
/// (mirrors AgentHealthStore's storePathOverride) to hand it a pump pointed at
/// a temp queue directory with a fake HTTP handler and a no-op pacing delay,
/// exactly as InventoryQueuePumpTests fakes the HTTP layer for the inventory
/// sibling.
///
/// Covers the acceptance-criteria flow end to end:
///   • A 429 on PostAsync queues the record rather than dropping it.
///   • DrainQueueAsync (the method PatchedWorker wires into its tick loop,
///     the same way it wires InventoryPoster.DrainQueueAsync) drains and
///     clears it once the server accepts the retry.
///   • The agent_health degraded signal (kind="queue_backlog",
///     subject="provenance") reflects a non-zero depth while records are
///     queued, and clears once the queue is empty again.
/// </summary>
public sealed class ProvenancePosterQueueHealthTests : IDisposable
{
    private readonly string _queueDir;
    private readonly string _healthFile;
    private readonly CredentialStore _creds;
    private readonly DeviceCollector _device;
    private readonly AgentHealthStore _agentHealth;

    public ProvenancePosterQueueHealthTests()
    {
        var root = Path.Combine(Path.GetTempPath(), $"patched-provenance-poster-health-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        _queueDir   = Path.Combine(root, "provenance-queue");
        _healthFile = Path.Combine(root, "agent-health.json");

        var hmacKey = Convert.ToBase64String(new byte[32]);
        _creds       = CredentialStore.ForTesting("test-tenant", "test-bearer", hmacKey);
        _device      = new DeviceCollector(NullLogger<DeviceCollector>.Instance);
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

    private static AppEntry NewAppEntry() => new()
    {
        Label            = "test-label",
        Name             = "Test App",
        InstalledVersion = "1.0.0",
        AvailableVersion = "1.1.0",
        State            = AppState.Installed,
        LastAction       = "installed",
        LastActionAt     = DateTimeOffset.UtcNow,
        WingetId         = "Vendor.TestApp",
    };

    private ProvenancePoster NewPoster(HttpMessageHandler handler, Func<DateTimeOffset>? utcNow = null)
    {
        var client  = new HttpClient(handler) { BaseAddress = new Uri("https://test.local") };
        var factory = new NamedClientFactory(client);
        var pump = new ProvenanceQueuePump(
            NullLogger.Instance, factory, _creds, _queueDir,
            readFileAsync: null,
            utcNow: utcNow,
            delay: (ts, ct) => Task.CompletedTask); // no-op: these tests assert behaviour, not timing

        return new ProvenancePoster(
            NullLogger<ProvenancePoster>.Instance,
            factory,
            _creds,
            _device,
            _agentHealth,
            pumpOverride: pump);
    }

    [Fact]
    public async Task PostAsync_On429_QueuesRecord_AndReportsDegradedHealth()
    {
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.TooManyRequests));

        await poster.PostAsync(NewAppEntry(), CancellationToken.None);

        Assert.Single(Directory.GetFiles(_queueDir, "prov-*.json"));

        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        var entry = Assert.Single(health!.Degraded, e => e.Kind == "queue_backlog" && e.Subject == "provenance");
        Assert.Contains("1 record", entry.Reason);
    }

    [Fact]
    public async Task PostAsync_On429_ThenDrainQueueAsync_AfterBackoffElapses_ClearsQueueAndHealth()
    {
        var now = new DateTimeOffset(2026, 8, 12, 9, 0, 0, TimeSpan.Zero);
        var handler = new SequencedFakeHttpHandler(HttpStatusCode.TooManyRequests, HttpStatusCode.OK);
        var poster = NewPoster(handler, utcNow: () => now);

        await poster.PostAsync(NewAppEntry(), CancellationToken.None);
        Assert.Single(Directory.GetFiles(_queueDir, "prov-*.json"));
        Assert.NotNull(_agentHealth.BuildPayloadSection());
        Assert.Contains(_agentHealth.BuildPayloadSection()!.Degraded, e => e.Subject == "provenance");

        // Same method PatchedWorker calls on every ~15s tick.
        // Still inside the 429 backoff window: no request, still degraded.
        await poster.DrainQueueAsync(CancellationToken.None);
        Assert.Equal(1, handler.CallCount);
        Assert.Contains(_agentHealth.BuildPayloadSection()!.Degraded, e => e.Subject == "provenance");

        now = now.AddSeconds(60);
        await poster.DrainQueueAsync(CancellationToken.None);

        Assert.Equal(2, handler.CallCount);
        Assert.Empty(Directory.GetFiles(_queueDir, "prov-*.json"));

        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        Assert.DoesNotContain(health!.Degraded, e => e.Subject == "provenance");
    }

    [Fact]
    public async Task PostAsync_On401_DoesNotQueue_ButReportsDistinctAuthFailureHealth()
    {
        // PAT-1249 non-author review (P1): an invalid/rotated credential must
        // not fill the bounded queue with doomed records, but it must still
        // be visible — as its own signal, since queue_backlog stays clear
        // (empty) throughout.
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.Unauthorized));

        await poster.PostAsync(NewAppEntry(), CancellationToken.None);

        Assert.False(Directory.Exists(_queueDir) && Directory.GetFiles(_queueDir, "prov-*.json").Length > 0);

        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        Assert.DoesNotContain(health!.Degraded, e => e.Kind == "queue_backlog" && e.Subject == "provenance");
        var authEntry = Assert.Single(health!.Degraded, e => e.Kind == "auth_failure" && e.Subject == "provenance");
        Assert.Contains("401", authEntry.Reason);
    }

    [Fact]
    public async Task PostAsync_On403_DoesNotQueue_ButReportsDistinctAuthFailureHealth()
    {
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.Forbidden));

        await poster.PostAsync(NewAppEntry(), CancellationToken.None);

        Assert.False(Directory.Exists(_queueDir) && Directory.GetFiles(_queueDir, "prov-*.json").Length > 0);
        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        Assert.Contains(health!.Degraded, e => e.Kind == "auth_failure" && e.Subject == "provenance");
    }

    [Fact]
    public async Task PostAsync_AuthFailureThenSuccess_ClearsAuthFailureHealth()
    {
        var handler = new SequencedFakeHttpHandler(HttpStatusCode.Unauthorized, HttpStatusCode.OK);
        var poster = NewPoster(handler);

        await poster.PostAsync(NewAppEntry(), CancellationToken.None);
        Assert.Contains(_agentHealth.BuildPayloadSection()!.Degraded, e => e.Kind == "auth_failure");

        // Simulates the credential being fixed (e.g. re-enrollment) before
        // the next cycle's send.
        await poster.PostAsync(NewAppEntry(), CancellationToken.None);

        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        Assert.DoesNotContain(health!.Degraded, e => e.Kind == "auth_failure");
        Assert.False(Directory.Exists(_queueDir) && Directory.GetFiles(_queueDir, "prov-*.json").Length > 0);
    }

    [Fact]
    public async Task PostAsync_Success_NeverQueuesOrDegrades()
    {
        var poster = NewPoster(new CountingFakeHttpHandler(HttpStatusCode.OK));

        await poster.PostAsync(NewAppEntry(), CancellationToken.None);

        Assert.False(Directory.Exists(_queueDir) && Directory.GetFiles(_queueDir, "prov-*.json").Length > 0);
        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        Assert.DoesNotContain(health!.Degraded, e => e.Subject == "provenance");
    }

    [Fact]
    public async Task DrainQueueAsync_MultipleStrandedRecords_DrainsThemAcrossRepeatedTicks()
    {
        // Simulates PAT-1249's actual bug scenario: records stranded by a
        // previous version of the agent that had no pump at all. A fresh
        // ProvenancePoster (this cycle's, with no in-memory backoff state)
        // must still drain files it never wrote itself.
        Directory.CreateDirectory(_queueDir);
        for (int i = 0; i < 5; i++)
        {
            File.WriteAllText(Path.Combine(_queueDir, $"prov-{1000 + i}-0.json"), "{\"stranded\":true}");
        }

        var handler = new CountingFakeHttpHandler(HttpStatusCode.OK);
        var poster = NewPoster(handler);

        // One file drained per DrainQueueAsync call, mirroring PatchedWorker's
        // one-per-tick cadence.
        for (int i = 0; i < 5; i++)
        {
            await poster.DrainQueueAsync(CancellationToken.None);
        }

        Assert.Equal(5, handler.CallCount);
        Assert.Empty(Directory.GetFiles(_queueDir, "prov-*.json"));
        var health = _agentHealth.BuildPayloadSection();
        Assert.NotNull(health);
        Assert.DoesNotContain(health!.Degraded, e => e.Subject == "provenance");
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
}
