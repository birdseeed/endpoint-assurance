using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// Unit tests for <see cref="ProvenanceQueuePump"/>, modeled directly on
/// <see cref="InventoryQueuePumpTests"/> — same fixture shape, same fake HTTP
/// handlers — plus coverage for the two things this pump adds beyond its
/// inventory sibling (PAT-1249):
///   • Every send/drain attempt is paced at least MinPostInterval apart, so a
///     tight loop of per-label sends can never reproduce the original burst
///     that got 9 of a single cycle's POSTs rejected with HTTP 429 in one
///     second.
///   • The on-disk queue is bounded (MaxQueuedRecords) with oldest-first
///     eviction, so an extended outage cannot grow it without limit the way
///     the write-only queue this pump replaces did (55 stranded records,
///     unbounded, on WIN-STAGING).
///
/// These tests cover:
///   • SendOrEnqueueAsync: payload enqueued on non-2xx / NOT enqueued on 2xx.
///   • DrainAsync / DrainOneAsync: delete-on-2xx, retain-on-failure, 429
///     Retry-After deferral, fair rotation across files.
///   • An unreadable queue file is skipped without wedging the pump —
///     the remaining file(s) still get a fair shot on the next call.
///   • Pacing: a second send within MinPostInterval of the first waits
///     before the request goes out; a send after the interval has already
///     elapsed does not wait at all.
///   • Bound: enqueuing past MaxQueuedRecords evicts the oldest file(s)
///     first and never exceeds the cap.
/// </summary>
public sealed class ProvenanceQueuePumpTests : IDisposable
{
    // ------------------------------------------------------------------ //
    // Fixtures                                                             //
    // ------------------------------------------------------------------ //

    private readonly string          _tmpDir;
    private readonly CredentialStore _creds;

    public ProvenanceQueuePumpTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), $"patched-provenance-pump-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tmpDir);

        // The test factory avoids Credential Manager P/Invoke, so these queue
        // mechanics run on the macOS CI host as well as Windows. A 32-byte zero
        // key is valid base64 for the real HMAC signing path.
        var hmacKey = Convert.ToBase64String(new byte[32]);
        _creds = CredentialStore.ForTesting("test-tenant", "test-bearer", hmacKey);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    // ------------------------------------------------------------------ //
    // SendOrEnqueueAsync                                                   //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task SendOrEnqueueAsync_OnSuccess_DoesNotCreateQueueFile()
    {
        var pump = MakePump(HttpStatusCode.OK);
        await pump.SendOrEnqueueAsync(new byte[] { 1, 2, 3 }, CancellationToken.None);

        Assert.Empty(Directory.GetFiles(_tmpDir, "prov-*.json"));
    }

    [Fact]
    public async Task SendOrEnqueueAsync_OnHttpFailure_WritesQueueFile()
    {
        var pump = MakePump(HttpStatusCode.BadGateway);
        await pump.SendOrEnqueueAsync(new byte[] { 4, 5, 6 }, CancellationToken.None);

        Assert.Single(Directory.GetFiles(_tmpDir, "prov-*.json"));
    }

    [Fact]
    public async Task SendOrEnqueueAsync_On429_WritesQueueFile()
    {
        var pump = MakePump(HttpStatusCode.TooManyRequests);
        await pump.SendOrEnqueueAsync(new byte[] { 7, 8, 9 }, CancellationToken.None);

        Assert.Single(Directory.GetFiles(_tmpDir, "prov-*.json"));
    }

    [Fact]
    public async Task SendOrEnqueueAsync_OnNetworkException_WritesQueueFile()
    {
        var pump = MakePump(throwNetworkError: true);
        await pump.SendOrEnqueueAsync(new byte[] { 1, 1, 1 }, CancellationToken.None);

        Assert.Single(Directory.GetFiles(_tmpDir, "prov-*.json"));
    }

    [Fact]
    public async Task SendOrEnqueueAsync_QueuedFile_ContainsOriginalBody()
    {
        var body = System.Text.Encoding.UTF8.GetBytes("{\"test\":true}");
        var pump = MakePump(HttpStatusCode.BadRequest);

        await pump.SendOrEnqueueAsync(body, CancellationToken.None);

        var files     = Directory.GetFiles(_tmpDir, "prov-*.json");
        var persisted = await File.ReadAllBytesAsync(files[0]);
        Assert.Equal(body, persisted);
    }

    // ------------------------------------------------------------------ //
    // Auth failure (401/403) — PAT-1249 non-author review (P1)             //
    // ------------------------------------------------------------------ //

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task SendOrEnqueueAsync_OnAuthFailure_DoesNotEnqueue_AndFlagsLastAttempt(HttpStatusCode status)
    {
        var pump = MakePump(status, noOpDelay: true);

        await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes("doomed"), CancellationToken.None);

        Assert.Empty(Directory.GetFiles(_tmpDir, "prov-*.json"));
        Assert.True(pump.LastAttemptWasAuthFailure);
    }

    [Fact]
    public async Task SendOrEnqueueAsync_OnHttpFailure_LastAttemptWasAuthFailureIsFalse()
    {
        var pump = MakePump(HttpStatusCode.ServiceUnavailable, noOpDelay: true);

        await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes("retryable"), CancellationToken.None);

        Assert.Single(Directory.GetFiles(_tmpDir, "prov-*.json"));
        Assert.False(pump.LastAttemptWasAuthFailure);
    }

    [Fact]
    public async Task SendOrEnqueueAsync_RepeatedAuthFailures_NeverFillTheQueue()
    {
        var pump = MakePump(HttpStatusCode.Unauthorized, noOpDelay: true);

        // A rotated/invalid credential means every subsequent cycle's send
        // fails the same way — the queue must stay empty throughout rather
        // than filling with doomed records and evicting retryable ones.
        for (int i = 0; i < 50; i++)
        {
            await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes($"record-{i}"), CancellationToken.None);
        }

        Assert.Empty(Directory.GetFiles(_tmpDir, "prov-*.json"));
        Assert.True(pump.LastAttemptWasAuthFailure);
    }

    [Fact]
    public async Task SendOrEnqueueAsync_SuccessAfterAuthFailure_ClearsTheFlag()
    {
        var handler = new SequencedFakeHttpHandler(HttpStatusCode.Unauthorized, HttpStatusCode.OK);
        var pump = MakePump(handler, noOpDelay: true);

        await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes("first"), CancellationToken.None);
        Assert.True(pump.LastAttemptWasAuthFailure);

        // Simulates the credential being fixed (e.g. re-enrollment) before
        // the next cycle's send.
        await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes("second"), CancellationToken.None);
        Assert.False(pump.LastAttemptWasAuthFailure);
        Assert.Empty(Directory.GetFiles(_tmpDir, "prov-*.json"));
    }

    [Fact]
    public async Task DrainOneAsync_OnAuthFailure_RetainsFile_AndFlagsLastAttempt()
    {
        var file = CreateQueueFile("prov-100-1.json");
        var pump = MakePump(HttpStatusCode.Forbidden, noOpDelay: true);

        await pump.DrainOneAsync(CancellationToken.None);

        Assert.True(File.Exists(file), "An already-queued record is retained, not deleted, on an auth failure");
        Assert.True(pump.LastAttemptWasAuthFailure);
    }

    [Fact]
    public async Task DrainAsync_OnAuthFailure_StopsThisPass_LeavingLaterFilesUnattempted()
    {
        var first  = CreateQueueFile("prov-100-1.json");
        var second = CreateQueueFile("prov-200-1.json");
        var handler = new CountingFakeHttpHandler(HttpStatusCode.Unauthorized);
        var pump = MakePump(handler, noOpDelay: true);

        // Full (non-tick-limited) drain: an auth failure on the first file
        // must not burn through the rest of the backlog on equally-doomed
        // attempts — same "stop this pass" treatment as a 429.
        await pump.DrainAsync(CancellationToken.None);

        Assert.Equal(1, handler.CallCount);
        Assert.True(File.Exists(first));
        Assert.True(File.Exists(second));
        Assert.True(pump.LastAttemptWasAuthFailure);
    }

    [Fact]
    public void LastAttemptWasAuthFailure_DefaultsFalse_BeforeAnyAttempt()
    {
        var pump = MakePump(HttpStatusCode.OK);
        Assert.False(pump.LastAttemptWasAuthFailure);
    }

    [Fact]
    public async Task DrainOneAsync_EmptyQueue_LeavesAuthFailureFlagUntouched()
    {
        var handler = new CountingFakeHttpHandler(HttpStatusCode.Unauthorized);
        var pump = MakePump(handler, noOpDelay: true);

        await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes("x"), CancellationToken.None);
        Assert.True(pump.LastAttemptWasAuthFailure);

        // Draining an empty queue makes no HTTP attempt at all, so it must
        // not silently reset the flag to a false all-clear — the credential
        // is still broken even though there's nothing queued to prove it
        // against right now.
        await pump.DrainOneAsync(CancellationToken.None);
        Assert.True(pump.LastAttemptWasAuthFailure);
    }

    // ------------------------------------------------------------------ //
    // Full 429 -> queued -> drained -> cleared cycle                       //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task Post429_WithoutRetryAfterHeader_FallsBackToDefaultBackoffThenClearsTheQueue()
    {
        var body = System.Text.Encoding.UTF8.GetBytes("{\"test\":\"retry\"}");
        var now = new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero);
        // No Retry-After header on this 429 — the pump must fall back to its
        // own Default429Backoff (60s). Asserted at the boundary (59s: still
        // deferred; 60s: retries) so this proves that specific fallback
        // value rather than merely "eventually, after some wait" (PAT-1249
        // non-author review: the previous version of this test used a bare
        // 429 but advanced the clock by exactly 60s, which only proved the
        // fallback path by coincidence with whatever Default429Backoff
        // happened to be set to).
        var handler = new SequencedFakeHttpHandler(
            HttpStatusCode.TooManyRequests,
            HttpStatusCode.OK);
        var pump = MakePump(handler, utcNow: () => now, noOpDelay: true);

        // A fresh send that hits 429 is queued rather than dropped silently.
        await pump.SendOrEnqueueAsync(body, CancellationToken.None);
        var queued = Directory.GetFiles(_tmpDir, "prov-*.json");
        Assert.Single(queued);
        Assert.Equal(1, handler.CallCount);

        now = now.AddSeconds(59);
        await pump.DrainOneAsync(CancellationToken.None);
        Assert.Equal(1, handler.CallCount);
        Assert.True(File.Exists(queued[0]), "59s is short of the 60s default backoff — must still be deferred");

        now = now.AddSeconds(1);
        await pump.DrainOneAsync(CancellationToken.None);

        Assert.Equal(2, handler.CallCount);
        Assert.False(File.Exists(queued[0]), "Queued payload must be deleted once the deferred retry succeeds");
        Assert.Empty(Directory.GetFiles(_tmpDir, "prov-*.json"));
    }

    [Fact]
    public async Task Post429_WithRetryAfterHeader_DrainHonoursThatValueThenClearsTheQueue()
    {
        var body = System.Text.Encoding.UTF8.GetBytes("{\"test\":\"retry\"}");
        var now = new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero);
        // Deliberately NOT 60s (Default429Backoff) — proves the pump reads
        // and honours the server's actual Retry-After value rather than
        // coincidentally matching its own fallback default (PAT-1249
        // non-author review).
        var retryAfter = TimeSpan.FromSeconds(10);
        var handler = new RetryAfterThenOkHandler(retryAfter);
        var pump = MakePump(handler, utcNow: () => now, noOpDelay: true);

        // A fresh send that hits 429 (with a Retry-After header) is queued
        // rather than dropped silently.
        await pump.SendOrEnqueueAsync(body, CancellationToken.None);
        var queued = Directory.GetFiles(_tmpDir, "prov-*.json");
        Assert.Single(queued);
        Assert.Equal(1, handler.CallCount);

        now = now.AddSeconds(9);
        await pump.DrainOneAsync(CancellationToken.None);
        Assert.Equal(1, handler.CallCount);
        Assert.True(File.Exists(queued[0]), "9s is short of the server's 10s Retry-After — must still be deferred");

        // Once exactly the server's advertised Retry-After has elapsed, the
        // drain retries and the queue is cleared on the resulting 2xx.
        now = now.AddSeconds(1);
        await pump.DrainOneAsync(CancellationToken.None);

        Assert.Equal(2, handler.CallCount);
        Assert.False(File.Exists(queued[0]), "Queued payload must be deleted once the deferred retry succeeds");
        Assert.Empty(Directory.GetFiles(_tmpDir, "prov-*.json"));
    }

    [Fact]
    public async Task DrainOneAsync_On429WithRetryAfter_MakesNoRequestUntilTheSpecifiedTime()
    {
        var first  = CreateQueueFile("prov-100-1.json");
        var second = CreateQueueFile("prov-200-1.json");
        var now = new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero);
        var handler = new RetryAfterThenOkHandler(TimeSpan.FromSeconds(120));
        var pump = MakePump(handler, utcNow: () => now, noOpDelay: true);

        await pump.DrainOneAsync(CancellationToken.None);
        Assert.Equal(1, handler.CallCount);
        Assert.True(File.Exists(first));
        Assert.True(File.Exists(second));

        now = now.AddSeconds(119);
        await pump.DrainOneAsync(CancellationToken.None);
        Assert.Equal(1, handler.CallCount);

        now = now.AddSeconds(1);
        await pump.DrainOneAsync(CancellationToken.None);
        Assert.Equal(2, handler.CallCount);
        Assert.True(File.Exists(first));
        Assert.False(File.Exists(second));
    }

    [Fact]
    public async Task DrainOneAsync_MultipleQueuedFiles_OnSuccess_RetriesAndDeletesOnlyFirstFile()
    {
        var first  = CreateQueueFile("prov-100-1.json");
        var second = CreateQueueFile("prov-200-1.json");
        var handler = new CountingFakeHttpHandler(HttpStatusCode.OK);
        var pump = MakePump(handler, noOpDelay: true);

        await pump.DrainOneAsync(CancellationToken.None);

        Assert.Equal(1, handler.CallCount);
        Assert.False(File.Exists(first));
        Assert.True(File.Exists(second));
    }

    // ------------------------------------------------------------------ //
    // Corrupt/unreadable queue file does not wedge the pump                //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task DrainOneAsync_AfterUnreadableFirstFile_RotatesToReadableFileOnNextTick()
    {
        var first  = CreateQueueFile("prov-100-1.json");
        var second = CreateQueueFile("prov-200-1.json");
        var handler = new CountingFakeHttpHandler(HttpStatusCode.OK);
        var pump = MakePump(handler, (path, ct) =>
            Path.GetFileName(path) == Path.GetFileName(first)
                ? Task.FromException<byte[]>(new IOException("simulated unreadable/corrupt queue file"))
                : File.ReadAllBytesAsync(path, ct),
            noOpDelay: true);

        // The unreadable file is skipped, not thrown — the pump keeps running
        // and simply has nothing left to try this tick (maximumFiles=1 landed
        // on the corrupt file).
        await pump.DrainOneAsync(CancellationToken.None);
        Assert.Equal(0, handler.CallCount);
        Assert.True(File.Exists(first), "Unreadable file is retained, not deleted, on a read failure");
        Assert.True(File.Exists(second));

        // Next tick rotates past the still-unreadable file to the readable one.
        await pump.DrainOneAsync(CancellationToken.None);

        Assert.Equal(1, handler.CallCount);
        Assert.True(File.Exists(first));
        Assert.False(File.Exists(second));
    }

    [Fact]
    public async Task DrainAsync_UnreadableFile_DoesNotPreventRemainingFilesFromBeingAttempted()
    {
        var unreadable = CreateQueueFile("prov-050-1.json");
        var readable   = CreateQueueFile("prov-150-1.json");
        var handler = new CountingFakeHttpHandler(HttpStatusCode.OK);
        var pump = MakePump(handler, (path, ct) =>
            Path.GetFileName(path) == Path.GetFileName(unreadable)
                ? Task.FromException<byte[]>(new IOException("simulated unreadable queue file"))
                : File.ReadAllBytesAsync(path, ct),
            noOpDelay: true);

        // Full (non-tick-limited) drain: the corrupt file is skipped but does
        // not abort the loop — the readable file still gets attempted and
        // cleared in the same call.
        await pump.DrainAsync(CancellationToken.None);

        Assert.Equal(1, handler.CallCount);
        Assert.True(File.Exists(unreadable));
        Assert.False(File.Exists(readable));
    }

    // ------------------------------------------------------------------ //
    // Pacing (PAT-1249)                                                    //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task SendOrEnqueueAsync_SecondCallWithinWindow_WaitsForRemainingInterval()
    {
        var now = new DateTimeOffset(2026, 8, 12, 9, 0, 0, TimeSpan.Zero);
        var handler = new CountingFakeHttpHandler(HttpStatusCode.OK);
        var recordedDelays = new List<TimeSpan>();
        var pump = MakePump(
            handler,
            utcNow: () => now,
            delay: (ts, ct) => { recordedDelays.Add(ts); return Task.CompletedTask; });

        // First send in this pump's lifetime never waits — nothing to pace
        // against yet.
        await pump.SendOrEnqueueAsync(new byte[] { 1 }, CancellationToken.None);
        Assert.Empty(recordedDelays);

        // The clock has not advanced, so the second send must wait out the
        // full pacing interval before its request goes out.
        await pump.SendOrEnqueueAsync(new byte[] { 2 }, CancellationToken.None);
        Assert.Single(recordedDelays);
        Assert.True(recordedDelays[0] > TimeSpan.Zero);
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task SendOrEnqueueAsync_SecondCallAfterIntervalElapsed_DoesNotWait()
    {
        var now = new DateTimeOffset(2026, 8, 12, 9, 0, 0, TimeSpan.Zero);
        var handler = new CountingFakeHttpHandler(HttpStatusCode.OK);
        var recordedDelays = new List<TimeSpan>();
        var pump = MakePump(
            handler,
            utcNow: () => now,
            delay: (ts, ct) => { recordedDelays.Add(ts); return Task.CompletedTask; });

        await pump.SendOrEnqueueAsync(new byte[] { 1 }, CancellationToken.None);

        // Simulate real elapsed time (e.g. the HTTP round trip / caller work)
        // exceeding the pacing interval before the next send is attempted.
        now = now.AddSeconds(5);
        await pump.SendOrEnqueueAsync(new byte[] { 2 }, CancellationToken.None);

        Assert.Empty(recordedDelays);
        Assert.Equal(2, handler.CallCount);
    }

    // ------------------------------------------------------------------ //
    // Bound + oldest-first eviction (PAT-1249)                             //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task SendOrEnqueueAsync_AtCap_EvictsOldestFileBeforeWritingNewOne()
    {
        // Pre-fill the queue to exactly the cap with distinguishably-ordered
        // filenames (ascending timestamp prefix), then enqueue one more.
        for (int i = 0; i < ProvenanceQueuePump.MaxQueuedRecords; i++)
        {
            CreateQueueFile($"prov-{1000 + i:D6}-0.json");
        }

        var pump = MakePump(HttpStatusCode.ServiceUnavailable, noOpDelay: true);
        await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes("newest"), CancellationToken.None);

        var files = Directory.GetFiles(_tmpDir, "prov-*.json");
        Assert.Equal(ProvenanceQueuePump.MaxQueuedRecords, files.Length);

        // The very oldest pre-existing file (smallest timestamp prefix) must
        // have been evicted to make room.
        Assert.DoesNotContain(files, f => Path.GetFileName(f).StartsWith("prov-001000-"));

        // The newest pre-existing file, and the one just enqueued, both survive.
        Assert.Contains(files, f => Path.GetFileName(f).StartsWith($"prov-{1000 + ProvenanceQueuePump.MaxQueuedRecords - 1:D6}-"));
    }

    [Fact]
    public async Task SendOrEnqueueAsync_RepeatedFailuresPastCap_NeverExceedsBound()
    {
        var pump = MakePump(HttpStatusCode.ServiceUnavailable, noOpDelay: true);

        // Enqueue well past the cap; the directory must never grow beyond it.
        for (int i = 0; i < ProvenanceQueuePump.MaxQueuedRecords + 25; i++)
        {
            await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes($"record-{i}"), CancellationToken.None);
            var count = Directory.GetFiles(_tmpDir, "prov-*.json").Length;
            Assert.True(count <= ProvenanceQueuePump.MaxQueuedRecords,
                $"Queue depth {count} exceeded the {ProvenanceQueuePump.MaxQueuedRecords}-record bound after enqueue #{i}");
        }

        Assert.Equal(ProvenanceQueuePump.MaxQueuedRecords, Directory.GetFiles(_tmpDir, "prov-*.json").Length);
    }

    // ------------------------------------------------------------------ //
    // QueueDepth                                                            //
    // ------------------------------------------------------------------ //

    [Fact]
    public void QueueDepth_EmptyDirectory_ReturnsZero()
    {
        var pump = MakePump(HttpStatusCode.OK);
        Assert.Equal(0, pump.QueueDepth());
    }

    [Fact]
    public void QueueDepth_MissingDirectory_ReturnsZeroNotThrow()
    {
        var missingDir = Path.Combine(_tmpDir, "does-not-exist");
        var client  = new HttpClient(new CountingFakeHttpHandler(HttpStatusCode.OK)) { BaseAddress = new Uri("https://test.local") };
        var factory = new NamedClientFactory(client);
        var pump = new ProvenanceQueuePump(NullLogger.Instance, factory, _creds, missingDir);

        Assert.Equal(0, pump.QueueDepth());
    }

    [Fact]
    public void QueueDepth_ReflectsQueuedFileCount()
    {
        CreateQueueFile("prov-100-1.json");
        CreateQueueFile("prov-200-1.json");
        var pump = MakePump(HttpStatusCode.OK);

        Assert.Equal(2, pump.QueueDepth());
    }

    // ------------------------------------------------------------------ //
    // Helpers                                                              //
    // ------------------------------------------------------------------ //

    private string CreateQueueFile(string name)
    {
        var path = Path.Combine(_tmpDir, name);
        File.WriteAllText(path, "{\"queued\":true}");
        return path;
    }

    private ProvenanceQueuePump MakePump(HttpStatusCode status, bool noOpDelay = false) =>
        MakePump(new CountingFakeHttpHandler(status), noOpDelay: noOpDelay);

    private ProvenanceQueuePump MakePump(bool throwNetworkError = false, bool noOpDelay = false) =>
        throwNetworkError
            ? MakePump(new ThrowingFakeHttpHandler(), noOpDelay: noOpDelay)
            : MakePump(HttpStatusCode.OK, noOpDelay: noOpDelay);

    private ProvenanceQueuePump MakePump(
        HttpMessageHandler handler,
        Func<string, CancellationToken, Task<byte[]>>? readFileAsync = null,
        Func<DateTimeOffset>? utcNow = null,
        bool noOpDelay = false,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        var client  = new HttpClient(handler) { BaseAddress = new Uri("https://test.local") };
        var factory = new NamedClientFactory(client);

        // Tests that don't care about pacing (queue-mechanics-only tests) pass
        // noOpDelay so MinPostInterval waits complete instantly instead of
        // slowing down the suite; pacing itself gets its own dedicated tests.
        var effectiveDelay = delay ?? (noOpDelay ? (ts, ct) => Task.CompletedTask : null);

        return new ProvenanceQueuePump(NullLogger.Instance, factory, _creds, _tmpDir, readFileAsync, utcNow, effectiveDelay);
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

    /// <summary>Returns status codes from a predefined sequence; last code repeated thereafter.</summary>
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

    /// <summary>Simulates a network-level failure (TCP timeout, DNS failure, etc.).</summary>
    private sealed class ThrowingFakeHttpHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromException<HttpResponseMessage>(
                new HttpRequestException("simulated network failure"));
    }

    private sealed class RetryAfterThenOkHandler : HttpMessageHandler
    {
        private readonly TimeSpan _retryAfter;
        public int CallCount { get; private set; }

        public RetryAfterThenOkHandler(TimeSpan retryAfter) => _retryAfter = retryAfter;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            if (CallCount > 1)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));

            var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
            response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(_retryAfter);
            return Task.FromResult(response);
        }
    }
}
