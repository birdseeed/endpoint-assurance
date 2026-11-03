using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1077: Unit tests for AuditEventShipper.PostEnforcementAuditAsync's durable
/// pending-batch behaviour — the Windows twin of the macOS PAT-1037 fix
/// (macos/lib/browser_extension_removal.sh). Covers the fail -> persist -> retry ->
/// confirm -> clear cycle and the in-process concurrency guard.
///
/// Strategy: PendingEnforcementAuditFilePath is virtual (like PostEnforcementAuditAsync
/// itself), so TestAuditEventShipper below redirects it to a scratch temp file, matching
/// the existing "virtual seam + subclass redirect" convention used by
/// BrowserExtensionBlocklistEnforcerStateIoTests / AgentHealthStoreTests. HTTP is faked
/// via a HttpMessageHandler + IHttpClientFactory test double, matching the convention in
/// InventoryQueuePumpTests.
/// </summary>
public sealed class AuditEventShipperEnforcementAuditDurabilityTests : IDisposable
{
    private readonly string _pendingPath;
    private readonly CredentialStore _creds;
    private readonly List<string> _blockerFiles = [];

    public AuditEventShipperEnforcementAuditDurabilityTests()
    {
        _pendingPath = Path.Combine(
            Path.GetTempPath(), $"patched-pending-audit-test-{Guid.NewGuid():N}.json");

        var hmacKey = Convert.ToBase64String(new byte[32]);
        _creds = CredentialStore.ForTesting("test-tenant", "test-bearer", hmacKey);
    }

    public void Dispose()
    {
        try { File.Delete(_pendingPath); } catch { /* ignore */ }
        try { File.Delete(_pendingPath + ".tmp"); } catch { /* ignore */ }
        foreach (var f in _blockerFiles)
        {
            try { File.Delete(f); } catch { /* ignore */ }
        }
    }

    /// <summary>
    /// Returns a pending-file path whose containing "directory" is actually a plain file, so
    /// Directory.CreateDirectory reliably throws and WritePendingEnforcementAuditAtomic fails —
    /// used to exercise the gap-2 (durable-write-failure) best-effort-POST paths without
    /// relying on real filesystem permissions, which don't fail predictably for the owning
    /// user in a CI sandbox.
    /// </summary>
    private string MakeUnwritablePendingPath()
    {
        var blockerFile = Path.Combine(
            Path.GetTempPath(), $"patched-pending-audit-blocker-{Guid.NewGuid():N}");
        File.WriteAllText(blockerFile, "not a directory");
        _blockerFiles.Add(blockerFile);
        return Path.Combine(blockerFile, "pending.json");
    }

    private static EnforcementAuditEvent MakeEvent(string subject) => new()
    {
        EventType  = EnforcementAuditEventTypes.ExtensionRemoved,
        Subject    = subject,
        Details    = new { browser = "chrome" },
        OccurredAt = "2026-08-10T00:00:00Z",
    };

    private AuditEventShipper MakeShipper(HttpMessageHandler handler) =>
        new TestAuditEventShipper(
            new NamedClientFactory(new HttpClient(handler) { BaseAddress = new Uri("https://test.local") }),
            _creds,
            _pendingPath);

    // ------------------------------------------------------------------ //
    // Fail -> persist                                                      //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task PostEnforcementAuditAsync_NetworkFailure_PersistsPendingFile()
    {
        var shipper = MakeShipper(new ThrowingFakeHttpHandler());

        await shipper.PostEnforcementAuditAsync([MakeEvent("ext-a")], CancellationToken.None);

        Assert.True(File.Exists(_pendingPath), "a failed POST must durably persist the events");
        var persisted = ReadPending();
        Assert.Single(persisted);
        Assert.Equal("ext-a", persisted[0].Subject);
    }

    [Fact]
    public async Task PostEnforcementAuditAsync_NonSuccessStatus_PersistsPendingFile()
    {
        var shipper = MakeShipper(new EchoIngestedCountHandler(HttpStatusCode.InternalServerError));

        await shipper.PostEnforcementAuditAsync([MakeEvent("ext-a")], CancellationToken.None);

        Assert.True(File.Exists(_pendingPath));
        Assert.Single(ReadPending());
    }

    [Fact]
    public async Task PostEnforcementAuditAsync_2xxWithMismatchedIngestedCount_PersistsPendingFile()
    {
        // Server returns 200 but claims fewer rows ingested than were sent — must NOT be
        // treated as confirmed (go-service's insert is all-or-nothing per PAT-1037's
        // exact-match reasoning).
        var handler = new FixedBodyHandler(HttpStatusCode.OK, "{\"ingested\":0}");
        var shipper = MakeShipper(handler);

        await shipper.PostEnforcementAuditAsync([MakeEvent("ext-a"), MakeEvent("ext-b")], CancellationToken.None);

        Assert.True(File.Exists(_pendingPath));
        Assert.Equal(2, ReadPending().Count);
    }

    [Fact]
    public async Task PostEnforcementAuditAsync_2xxWithUnparseableBody_PersistsPendingFile()
    {
        var handler = new FixedBodyHandler(HttpStatusCode.OK, "not json");
        var shipper = MakeShipper(handler);

        await shipper.PostEnforcementAuditAsync([MakeEvent("ext-a")], CancellationToken.None);

        Assert.True(File.Exists(_pendingPath));
        Assert.Single(ReadPending());
    }

    // ------------------------------------------------------------------ //
    // Retry -> confirm -> clear                                            //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task PostEnforcementAuditAsync_SubsequentSuccess_ClearsPendingFile()
    {
        var failing = MakeShipper(new ThrowingFakeHttpHandler());
        await failing.PostEnforcementAuditAsync([MakeEvent("ext-a")], CancellationToken.None);
        Assert.True(File.Exists(_pendingPath));

        // A later invocation (same durable file, endpoint now reachable) must merge the
        // leftover batch with any new events, send the union, and clear only on confirmed
        // ingestion of the FULL combined count.
        var handler = new EchoIngestedCountHandler(HttpStatusCode.OK);
        var succeeding = MakeShipper(handler);
        await succeeding.PostEnforcementAuditAsync([MakeEvent("ext-b")], CancellationToken.None);

        Assert.False(File.Exists(_pendingPath), "confirmed ingestion must clear the pending file");
        Assert.Equal(1, handler.CallCount);
        Assert.Equal(2, handler.LastSentEventCount);
        Assert.Contains("ext-a", handler.LastSentSubjects);
        Assert.Contains("ext-b", handler.LastSentSubjects);
    }

    [Fact]
    public async Task PostEnforcementAuditAsync_LeftoverPendingBatch_RetriedEvenWithNoNewEvents()
    {
        var failing = MakeShipper(new ThrowingFakeHttpHandler());
        await failing.PostEnforcementAuditAsync([MakeEvent("ext-a")], CancellationToken.None);
        Assert.True(File.Exists(_pendingPath));

        // Called again with an EMPTY new-events list (e.g. a cycle where nothing new was
        // removed) — the leftover pending batch must still get a fresh drain attempt.
        var handler = new EchoIngestedCountHandler(HttpStatusCode.OK);
        var succeeding = MakeShipper(handler);
        await succeeding.PostEnforcementAuditAsync([], CancellationToken.None);

        Assert.Equal(1, handler.CallCount);
        Assert.False(File.Exists(_pendingPath));
    }

    [Fact]
    public async Task PostEnforcementAuditAsync_EmptyEventsAndNoPendingFile_MakesNoHttpCall()
    {
        var handler = new EchoIngestedCountHandler(HttpStatusCode.OK);
        var shipper = MakeShipper(handler);

        await shipper.PostEnforcementAuditAsync([], CancellationToken.None);

        Assert.Equal(0, handler.CallCount);
        Assert.False(File.Exists(_pendingPath));
    }

    // ------------------------------------------------------------------ //
    // Corrupted pending file                                               //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task PostEnforcementAuditAsync_CorruptedPendingFile_SuccessfulBestEffortPost_EventsSentAndFileCleaned()
    {
        // PAT-1077 gap-1 fix: a corrupt pending file must not drop this cycle's brand-new
        // events without even trying the network. When the best-effort direct POST succeeds
        // and is confirmed, the events ARE sent and the now-stale corrupt file is cleaned up.
        await File.WriteAllTextAsync(_pendingPath, "{not valid json");

        var handler = new EchoIngestedCountHandler(HttpStatusCode.OK);
        var shipper = MakeShipper(handler);

        var ex = await Record.ExceptionAsync(() =>
            shipper.PostEnforcementAuditAsync([MakeEvent("ext-a")], CancellationToken.None));

        Assert.Null(ex);
        Assert.Equal(1, handler.CallCount);
        Assert.Equal(1, handler.LastSentEventCount);
        Assert.Contains("ext-a", handler.LastSentSubjects);
        Assert.False(File.Exists(_pendingPath),
            "a confirmed best-effort POST proves this cycle is caught up, so the stale corrupt file is removed");
    }

    [Fact]
    public async Task PostEnforcementAuditAsync_CorruptedPendingFile_FailedBestEffortPost_EventsLoggedAndFileLeftInPlace()
    {
        // When the best-effort POST also fails, the events must not be silently lost — the
        // dropped-events log message must carry the actual event data, not just a count, and
        // the corrupt file (nothing new to prove it's safe to clear) stays in place.
        await File.WriteAllTextAsync(_pendingPath, "{not valid json");

        var logger = new CapturingLogger<AuditEventShipper>();
        var handler = new ThrowingFakeHttpHandler();
        var shipper = new TestAuditEventShipper(
            new NamedClientFactory(new HttpClient(handler) { BaseAddress = new Uri("https://test.local") }),
            _creds, _pendingPath, logger);

        var ex = await Record.ExceptionAsync(() =>
            shipper.PostEnforcementAuditAsync([MakeEvent("ext-a")], CancellationToken.None));

        Assert.Null(ex);
        Assert.Equal("{not valid json", await File.ReadAllTextAsync(_pendingPath));
        Assert.Contains(logger.Messages, m => m.Contains("ext-a", StringComparison.Ordinal));
    }

    // ------------------------------------------------------------------ //
    // Durable-write failure                                                //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task PostEnforcementAuditAsync_WriteFailure_SuccessfulBestEffortPost_EventsSentDespiteDiskIssue()
    {
        // PAT-1077 gap-2 fix: when the durable write itself fails (disk full, permissions,
        // AV lock, ...), the events must still get a best-effort network attempt rather than
        // being dropped outright. A successful, confirmed POST here means no data lost — only
        // a warning about the disk issue, not an error.
        var poisonedPath = MakeUnwritablePendingPath();
        var logger = new CapturingLogger<AuditEventShipper>();
        var handler = new EchoIngestedCountHandler(HttpStatusCode.OK);
        var shipper = new TestAuditEventShipper(
            new NamedClientFactory(new HttpClient(handler) { BaseAddress = new Uri("https://test.local") }),
            _creds, poisonedPath, logger);

        await shipper.PostEnforcementAuditAsync([MakeEvent("ext-a")], CancellationToken.None);

        Assert.Equal(1, handler.CallCount);
        Assert.Equal(1, handler.LastSentEventCount);
        Assert.Contains("ext-a", handler.LastSentSubjects);
        Assert.False(File.Exists(poisonedPath), "the write was made to fail, so no pending file should exist");
        Assert.Contains(logger.Warnings, m => m.Contains("disk issue", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(logger.Errors, m => m.Contains("ext-a", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PostEnforcementAuditAsync_WriteFailure_FailedBestEffortPost_EventsLoggedNotSilentlyDropped()
    {
        // Both the durable write AND the best-effort network attempt fail — the worst case.
        // The events must still not vanish silently: the dropped-events log message must carry
        // the actual event data.
        var poisonedPath = MakeUnwritablePendingPath();
        var logger = new CapturingLogger<AuditEventShipper>();
        var handler = new ThrowingFakeHttpHandler();
        var shipper = new TestAuditEventShipper(
            new NamedClientFactory(new HttpClient(handler) { BaseAddress = new Uri("https://test.local") }),
            _creds, poisonedPath, logger);

        var ex = await Record.ExceptionAsync(() =>
            shipper.PostEnforcementAuditAsync([MakeEvent("ext-a")], CancellationToken.None));

        Assert.Null(ex);
        Assert.False(File.Exists(poisonedPath));
        Assert.Contains(logger.Errors, m => m.Contains("ext-a", StringComparison.Ordinal));
    }

    // ------------------------------------------------------------------ //
    // Concurrency guard                                                    //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task PostEnforcementAuditAsync_ConcurrentCalls_SecondBlocksUntilFirstReleasesGate()
    {
        // Both calls MUST go through the same shipper instance — the SemaphoreSlim guard
        // (_pendingAuditGate) is a per-instance field, matching the real singleton lifetime
        // (AddSingleton<AuditEventShipper>() in Program.cs): exactly one instance exists in
        // production, so that is what makes the guard meaningful here too.
        var handler = new GatedHandler();
        var shipper = MakeShipper(handler);

        var taskA = shipper.PostEnforcementAuditAsync([MakeEvent("ext-a")], CancellationToken.None);
        await handler.FirstEntered; // A is now inside the gate, mid-HTTP-call

        var taskB = shipper.PostEnforcementAuditAsync([MakeEvent("ext-b")], CancellationToken.None);
        await Task.Delay(75);
        Assert.Equal(1, handler.CallCount); // B must still be blocked behind the semaphore

        handler.ReleaseFirst();
        await Task.WhenAll(taskA, taskB);

        Assert.Equal(2, handler.CallCount);
        // A's request carried only its own event (failed); B's request, once unblocked,
        // read A's persisted leftover and merged — union of both, no duplicate.
        Assert.Equal([1, 2], handler.SentEventCounts);
        Assert.False(File.Exists(_pendingPath), "confirmed batch should be cleared");
    }

    [Fact]
    public async Task PostEnforcementAuditAsync_ConcurrentCallsBothFail_PendingFileStaysValidNotCorrupted()
    {
        var handler = new ThrowingFakeHttpHandler();
        var shipper = MakeShipper(handler); // single instance — see guard-scope note above

        await Task.WhenAll(
            shipper.PostEnforcementAuditAsync([MakeEvent("ext-a")], CancellationToken.None),
            shipper.PostEnforcementAuditAsync([MakeEvent("ext-b")], CancellationToken.None));

        Assert.True(File.Exists(_pendingPath));
        var persisted = ReadPending();
        // The semaphore serializes the two invocations, so the second one's read-merge-write
        // sees the first one's already-persisted event — union of both, never lost or
        // duplicated, and always valid JSON (never a torn/corrupt write).
        Assert.Equal(2, persisted.Count);
        Assert.Contains(persisted, e => e.Subject == "ext-a");
        Assert.Contains(persisted, e => e.Subject == "ext-b");
    }

    // ------------------------------------------------------------------ //
    // Helpers                                                              //
    // ------------------------------------------------------------------ //

    private List<EnforcementAuditEvent> ReadPending()
    {
        var json = File.ReadAllText(_pendingPath);
        return JsonSerializer.Deserialize<List<EnforcementAuditEvent>>(json,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower })
            ?? [];
    }

    // ------------------------------------------------------------------ //
    // Test double: shipper with a redirected pending-file path             //
    // ------------------------------------------------------------------ //

    private sealed class TestAuditEventShipper : AuditEventShipper
    {
        private readonly string _pendingPath;

        public TestAuditEventShipper(
            IHttpClientFactory httpFactory, CredentialStore creds, string pendingPath,
            ILogger<AuditEventShipper>? logger = null)
            : base(logger ?? NullLogger<AuditEventShipper>.Instance, httpFactory, creds)
        {
            _pendingPath = pendingPath;
        }

        internal override string PendingEnforcementAuditFilePath => _pendingPath;
    }

    /// <summary>
    /// Captures every logged message (by level) so tests can assert on log CONTENT — used by
    /// the gap-1/gap-2 "events dropped" cases to prove the dropped batch is serialized into the
    /// log message itself, not just a count, matching the "fail loud, never fail silent"
    /// convention under test.
    /// </summary>
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];
        public List<string> Warnings { get; } = [];
        public List<string> Errors { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var message = formatter(state, exception);
            Messages.Add(message);
            if (logLevel == LogLevel.Warning) Warnings.Add(message);
            if (logLevel == LogLevel.Error) Errors.Add(message);
        }
    }

    // ------------------------------------------------------------------ //
    // Test doubles: HTTP                                                   //
    // ------------------------------------------------------------------ //

    private sealed class NamedClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public NamedClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class ThrowingFakeHttpHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromException<HttpResponseMessage>(
                new HttpRequestException("simulated network failure"));
    }

    private sealed class FixedBodyHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string _body;
        public int CallCount { get; private set; }

        public FixedBodyHandler(HttpStatusCode status, string body)
        {
            _status = status;
            _body = body;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            var resp = new HttpResponseMessage(_status)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json"),
            };
            return Task.FromResult(resp);
        }
    }

    /// <summary>Reads the submitted "events" array and echoes its length back as "ingested" —
    /// simulates a server that always fully ingests whatever batch it is sent.</summary>
    private sealed class EchoIngestedCountHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        public int CallCount { get; private set; }
        public int LastSentEventCount { get; private set; }
        public List<string> LastSentSubjects { get; private set; } = [];

        public EchoIngestedCountHandler(HttpStatusCode status) => _status = status;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            var bodyText = request.Content is null
                ? "{}"
                : await request.Content.ReadAsStringAsync(cancellationToken);
            var (count, subjects) = ParseEvents(bodyText);
            LastSentEventCount = count;
            LastSentSubjects = subjects;

            if (_status != HttpStatusCode.OK)
                return new HttpResponseMessage(_status);

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($"{{\"ingested\":{count}}}", Encoding.UTF8, "application/json"),
            };
        }

        internal static (int Count, List<string> Subjects) ParseEvents(string bodyJson)
        {
            using var doc = JsonDocument.Parse(bodyJson);
            var arr = doc.RootElement.GetProperty("events");
            var subjects = new List<string>();
            foreach (var el in arr.EnumerateArray())
                subjects.Add(el.GetProperty("subject").GetString() ?? "");
            return (arr.GetArrayLength(), subjects);
        }
    }

    /// <summary>
    /// The first request received blocks (holding the SemaphoreSlim gate for the whole
    /// duration) until the test explicitly releases it, then fails with a network error —
    /// simulating an in-flight POST for a first invocation while a second, truly concurrent
    /// invocation is attempted. Every subsequent request succeeds, echoing its event count
    /// as "ingested" (see EchoIngestedCountHandler).
    /// </summary>
    private sealed class GatedHandler : HttpMessageHandler
    {
        private readonly TaskCompletionSource _firstEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseFirst  = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _callCount;

        public int CallCount => _callCount;
        public List<int> SentEventCounts { get; } = [];
        public Task FirstEntered => _firstEntered.Task;
        public void ReleaseFirst() => _releaseFirst.TrySetResult();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var n = Interlocked.Increment(ref _callCount);
            var bodyText = request.Content is null
                ? "{}"
                : await request.Content.ReadAsStringAsync(cancellationToken);
            var (count, _) = EchoIngestedCountHandler.ParseEvents(bodyText);
            lock (SentEventCounts) SentEventCounts.Add(count);

            if (n == 1)
            {
                _firstEntered.TrySetResult();
                await _releaseFirst.Task;
                throw new HttpRequestException("simulated network failure for first call");
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($"{{\"ingested\":{count}}}", Encoding.UTF8, "application/json"),
            };
        }
    }

    // -------------------------------------------------------------------
    // PAT-1765: no request without a usable credential pair; events kept
    // -------------------------------------------------------------------

    [Theory]
    [InlineData("", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("test-bearer", "   ")]
    public async Task PostEnforcementAuditAsync_NoUsableCredentialPair_SendsNothing_AndKeepsTheEventsPending(string bearer, string secret)
    {
        var handler = new EchoIngestedCountHandler(HttpStatusCode.OK);
        var shipper = new TestAuditEventShipper(
            new NamedClientFactory(new HttpClient(handler) { BaseAddress = new Uri("https://test.local") }),
            CredentialStore.ForTesting("test-tenant", bearer, secret),
            _pendingPath);

        await shipper.PostEnforcementAuditAsync([MakeEvent("ext-a")], CancellationToken.None);

        Assert.Equal(0, handler.CallCount);
        Assert.Equal("ext-a", Assert.Single(ReadPending()).Subject);

        // Once the pair is usable the pending batch is delivered and cleared.
        var enrolled = MakeShipper(handler);
        await enrolled.PostEnforcementAuditAsync([], CancellationToken.None);
        Assert.Equal(1, handler.CallCount);
        Assert.False(File.Exists(_pendingPath));
    }

    [Fact]
    public async Task FlushAsync_NoUsableCredentialPair_SendsNothing()
    {
        var handler = new EchoIngestedCountHandler(HttpStatusCode.OK);
        var shipper = new TestAuditEventShipper(
            new NamedClientFactory(new HttpClient(handler) { BaseAddress = new Uri("https://test.local") }),
            CredentialStore.ForTesting("test-tenant", "", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            _pendingPath);

        await shipper.FlushAsync(CancellationToken.None);

        Assert.Equal(0, handler.CallCount);
    }
}
