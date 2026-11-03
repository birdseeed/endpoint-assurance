using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// Unit tests for <see cref="InventoryQueuePump"/>.
///
/// PAT-705: the queue-drain path was silently broken — no file logger meant no
/// visible errors, and the HMAC computation sat outside the try-catch so any
/// exception crashed the BackgroundService instead of logging and continuing.
///
/// These tests cover:
///   • DrainAsync: files are deleted on 2xx.
///   • DrainAsync: files are retained on non-2xx.
///   • DrainAsync: files are retained on network exception.
///   • DrainAsync: empty queue returns without error.
///   • DrainAsync: unreadable file is skipped, remainder still attempted.
///   • SendOrEnqueueAsync: payload is enqueued on non-2xx.
///   • SendOrEnqueueAsync: payload is NOT enqueued on 2xx.
/// </summary>
public sealed class InventoryQueuePumpTests : IDisposable
{
    // ------------------------------------------------------------------ //
    // Fixtures                                                             //
    // ------------------------------------------------------------------ //

    private readonly string        _tmpDir;
    private readonly CredentialStore _creds;

    public InventoryQueuePumpTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), $"patched-pump-test-{Guid.NewGuid():N}");
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
    // DrainAsync                                                           //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task DrainAsync_EmptyQueue_ReturnsWithoutMakingHttpRequest()
    {
        var handler = new CountingFakeHttpHandler(HttpStatusCode.OK);
        var pump = MakePump(handler);
        // No files in _tmpDir — should complete immediately.
        await pump.DrainAsync(CancellationToken.None);
        Assert.Empty(Directory.GetFiles(_tmpDir, "inv-*.json"));
        Assert.Equal(0, handler.CallCount);
    }

    [Fact]
    public async Task DrainAsync_OnSuccess_DeletesFile()
    {
        var file = CreateQueueFile("inv-111-1.json");
        var pump = MakePump(HttpStatusCode.OK);

        await pump.DrainAsync(CancellationToken.None);

        Assert.False(File.Exists(file), "File should be deleted after a 2xx response");
    }

    [Fact]
    public async Task DrainAsync_OnHttpFailure_RetainsFile()
    {
        var file = CreateQueueFile("inv-222-2.json");
        var pump = MakePump(HttpStatusCode.InternalServerError);

        await pump.DrainAsync(CancellationToken.None);

        Assert.True(File.Exists(file), "File should be retained after a non-2xx response");
    }

    [Fact]
    public async Task DrainAsync_OnNetworkException_RetainsFile()
    {
        var file = CreateQueueFile("inv-333-3.json");
        var pump = MakePump(throwNetworkError: true);

        await pump.DrainAsync(CancellationToken.None);

        Assert.True(File.Exists(file), "File should be retained after a network exception");
    }

    [Fact]
    public async Task DrainAsync_MultipleFiles_DeletesOnlySuccessful()
    {
        var ok   = CreateQueueFile("inv-400-1.json");
        var fail = CreateQueueFile("inv-400-2.json");

        // First call succeeds, second fails.
        var handler = new SequencedFakeHttpHandler(
            HttpStatusCode.OK,
            HttpStatusCode.ServiceUnavailable);
        var pump = MakePump(handler);

        await pump.DrainAsync(CancellationToken.None);

        Assert.False(File.Exists(ok),   "Successful file should be deleted");
        Assert.True( File.Exists(fail), "Failed file should be retained");
    }

    [Fact]
    public async Task DrainAsync_MakesOneRequestPerFile()
    {
        CreateQueueFile("inv-500-1.json");
        CreateQueueFile("inv-500-2.json");

        var handler = new CountingFakeHttpHandler(HttpStatusCode.OK);
        var pump    = MakePump(handler);

        await pump.DrainAsync(CancellationToken.None);

        Assert.Equal(2, handler.CallCount);
    }

    // ------------------------------------------------------------------ //
    // SendOrEnqueueAsync                                                   //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task SendOrEnqueueAsync_OnSuccess_DoesNotCreateQueueFile()
    {
        var pump = MakePump(HttpStatusCode.OK);
        await pump.SendOrEnqueueAsync(new byte[] { 1, 2, 3 }, CancellationToken.None);

        Assert.Empty(Directory.GetFiles(_tmpDir, "inv-*.json"));
    }

    [Fact]
    public async Task SendOrEnqueueAsync_OnHttpFailure_WritesQueueFile()
    {
        var pump = MakePump(HttpStatusCode.BadGateway);
        await pump.SendOrEnqueueAsync(new byte[] { 4, 5, 6 }, CancellationToken.None);

        Assert.Single(Directory.GetFiles(_tmpDir, "inv-*.json"));
    }

    [Fact]
    public async Task SendOrEnqueueAsync_OnNetworkException_WritesQueueFile()
    {
        var pump = MakePump(throwNetworkError: true);
        await pump.SendOrEnqueueAsync(new byte[] { 7, 8, 9 }, CancellationToken.None);

        Assert.Single(Directory.GetFiles(_tmpDir, "inv-*.json"));
    }

    [Fact]
    public async Task SendOrEnqueueAsync_QueuedFile_ContainsOriginalBody()
    {
        var body = System.Text.Encoding.UTF8.GetBytes("{\"test\":true}");
        var pump = MakePump(HttpStatusCode.BadRequest);

        await pump.SendOrEnqueueAsync(body, CancellationToken.None);

        var files    = Directory.GetFiles(_tmpDir, "inv-*.json");
        var persisted = await File.ReadAllBytesAsync(files[0]);
        Assert.Equal(body, persisted);
    }

    [Fact]
    public async Task QueueOnlyRetry_AfterStartup429_UsesDefaultBackoffThenFlushesWithoutFreshPost()
    {
        var body = System.Text.Encoding.UTF8.GetBytes("{\"test\":\"retry\"}");
        var now = new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero);
        var handler = new SequencedFakeHttpHandler(
            HttpStatusCode.TooManyRequests,
            HttpStatusCode.OK);
        var pump = MakePump(handler, utcNow: () => now);

        // The startup inventory post is rate-limited and persists exactly one
        // retry payload. The lightweight tick path respects the safe default
        // 60-second backoff, then makes one retry request only.
        await pump.SendOrEnqueueAsync(body, CancellationToken.None);
        var queued = Directory.GetFiles(_tmpDir, "inv-*.json");
        Assert.Single(queued);
        Assert.Equal(1, handler.CallCount);

        await pump.DrainOneAsync(CancellationToken.None);
        Assert.Equal(1, handler.CallCount);

        now = now.AddSeconds(60);
        await pump.DrainOneAsync(CancellationToken.None);

        Assert.Equal(2, handler.CallCount);
        Assert.False(File.Exists(queued[0]), "A queued payload is deleted only after the later 2xx retry");
    }

    [Fact]
    public async Task DrainOneAsync_On429WithRetryAfter_MakesNoRequestUntilTheSpecifiedTime()
    {
        var first  = CreateQueueFile("inv-100-1.json");
        var second = CreateQueueFile("inv-200-1.json");
        var now = new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero);
        var handler = new RetryAfterThenOkHandler(TimeSpan.FromSeconds(120));
        var pump = MakePump(handler, utcNow: () => now);

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
    public async Task DrainOneAsync_Non429Attempt_ClearsPriorBackoff()
    {
        var first = CreateQueueFile("inv-100-1.json");
        var now = new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero);
        var handler = new SequencedFakeHttpHandler(
            HttpStatusCode.TooManyRequests,
            HttpStatusCode.OK,
            HttpStatusCode.OK);
        var pump = MakePump(handler, utcNow: () => now);

        await pump.DrainOneAsync(CancellationToken.None);
        Assert.Equal(1, handler.CallCount);
        Assert.True(File.Exists(first));

        now = now.AddSeconds(60);
        await pump.DrainOneAsync(CancellationToken.None);
        Assert.Equal(2, handler.CallCount);
        Assert.False(File.Exists(first));

        var later = CreateQueueFile("inv-200-1.json");
        await pump.DrainOneAsync(CancellationToken.None);

        Assert.Equal(3, handler.CallCount);
        Assert.False(File.Exists(later));
    }

    [Fact]
    public async Task DrainOneAsync_MultipleQueuedFiles_OnSuccess_RetriesAndDeletesOnlyFirstFile()
    {
        var first  = CreateQueueFile("inv-100-1.json");
        var second = CreateQueueFile("inv-200-1.json");
        var handler = new CountingFakeHttpHandler(HttpStatusCode.OK);
        var pump = MakePump(handler);

        await pump.DrainOneAsync(CancellationToken.None);

        Assert.Equal(1, handler.CallCount);
        Assert.False(File.Exists(first));
        Assert.True(File.Exists(second));
    }

    [Fact]
    public async Task DrainOneAsync_MultipleQueuedFiles_On429_RetainsEveryFile()
    {
        var first  = CreateQueueFile("inv-100-1.json");
        var second = CreateQueueFile("inv-200-1.json");
        var handler = new CountingFakeHttpHandler(HttpStatusCode.TooManyRequests);
        var pump = MakePump(handler);

        await pump.DrainOneAsync(CancellationToken.None);

        Assert.Equal(1, handler.CallCount);
        Assert.True(File.Exists(first));
        Assert.True(File.Exists(second));
    }

    [Fact]
    public async Task DrainOneAsync_AfterFailedFirstFile_RotatesToLaterFileOnNextTick()
    {
        var first  = CreateQueueFile("inv-100-1.json");
        var second = CreateQueueFile("inv-200-1.json");
        var handler = new SequencedFakeHttpHandler(
            HttpStatusCode.BadRequest,
            HttpStatusCode.OK);
        var pump = MakePump(handler);

        await pump.DrainOneAsync(CancellationToken.None);
        Assert.Equal(1, handler.CallCount);
        Assert.True(File.Exists(first));
        Assert.True(File.Exists(second));

        await pump.DrainOneAsync(CancellationToken.None);

        Assert.Equal(2, handler.CallCount);
        Assert.True(File.Exists(first));
        Assert.False(File.Exists(second));
    }

    [Fact]
    public async Task DrainOneAsync_AfterUnreadableFirstFile_RotatesToReadableFileOnNextTick()
    {
        var first  = CreateQueueFile("inv-100-1.json");
        var second = CreateQueueFile("inv-200-1.json");
        var handler = new CountingFakeHttpHandler(HttpStatusCode.OK);
        var pump = MakePump(handler, (path, ct) =>
            Path.GetFileName(path) == Path.GetFileName(first)
                ? Task.FromException<byte[]>(new IOException("simulated unreadable queue file"))
                : File.ReadAllBytesAsync(path, ct));

        await pump.DrainOneAsync(CancellationToken.None);
        Assert.Equal(0, handler.CallCount);
        Assert.True(File.Exists(first));
        Assert.True(File.Exists(second));

        await pump.DrainOneAsync(CancellationToken.None);

        Assert.Equal(1, handler.CallCount);
        Assert.True(File.Exists(first));
        Assert.False(File.Exists(second));
    }

    // ------------------------------------------------------------------ //
    // Auth failure (401/403) — PAT-1266 (mirrors ProvenanceQueuePumpTests,   //
    // PAT-1249)                                                             //
    // ------------------------------------------------------------------ //

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task SendOrEnqueueAsync_OnAuthFailure_DoesNotEnqueue_AndFlagsLastAttempt(HttpStatusCode status)
    {
        var pump = MakePump(status);

        await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes("doomed"), CancellationToken.None);

        Assert.Empty(Directory.GetFiles(_tmpDir, "inv-*.json"));
        Assert.True(pump.LastAttemptWasAuthFailure);
    }

    [Fact]
    public async Task SendOrEnqueueAsync_OnHttpFailure_LastAttemptWasAuthFailureIsFalse()
    {
        var pump = MakePump(HttpStatusCode.ServiceUnavailable);

        await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes("retryable"), CancellationToken.None);

        Assert.Single(Directory.GetFiles(_tmpDir, "inv-*.json"));
        Assert.False(pump.LastAttemptWasAuthFailure);
    }

    [Fact]
    public async Task SendOrEnqueueAsync_RepeatedAuthFailures_NeverFillTheQueue()
    {
        var pump = MakePump(HttpStatusCode.Unauthorized);

        // A rotated/invalid credential means every subsequent cycle's send
        // fails the same way — the queue must stay empty throughout rather
        // than filling with doomed records and evicting retryable ones.
        for (int i = 0; i < 50; i++)
        {
            await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes($"record-{i}"), CancellationToken.None);
        }

        Assert.Empty(Directory.GetFiles(_tmpDir, "inv-*.json"));
        Assert.True(pump.LastAttemptWasAuthFailure);
    }

    [Fact]
    public async Task SendOrEnqueueAsync_SuccessAfterAuthFailure_ClearsTheFlag()
    {
        var handler = new SequencedFakeHttpHandler(HttpStatusCode.Unauthorized, HttpStatusCode.OK);
        var pump = MakePump(handler);

        await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes("first"), CancellationToken.None);
        Assert.True(pump.LastAttemptWasAuthFailure);

        // Simulates the credential being fixed (e.g. re-enrollment) before
        // the next cycle's send.
        await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes("second"), CancellationToken.None);
        Assert.False(pump.LastAttemptWasAuthFailure);
        Assert.Empty(Directory.GetFiles(_tmpDir, "inv-*.json"));
    }

    [Fact]
    public async Task DrainOneAsync_OnAuthFailure_RetainsFile_AndFlagsLastAttempt()
    {
        var file = CreateQueueFile("inv-100-1.json");
        var pump = MakePump(HttpStatusCode.Forbidden);

        await pump.DrainOneAsync(CancellationToken.None);

        Assert.True(File.Exists(file), "An already-queued record is retained, not deleted, on an auth failure");
        Assert.True(pump.LastAttemptWasAuthFailure);
    }

    [Fact]
    public async Task DrainAsync_OnAuthFailure_StopsThisPass_LeavingLaterFilesUnattempted()
    {
        var first  = CreateQueueFile("inv-100-1.json");
        var second = CreateQueueFile("inv-200-1.json");
        var handler = new CountingFakeHttpHandler(HttpStatusCode.Unauthorized);
        var pump = MakePump(handler);

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
        var pump = MakePump(handler);

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
    // Bound + oldest-first eviction (PAT-1270, mirrors                    //
    // ProvenanceQueuePumpTests, PAT-1249)                                  //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task SendOrEnqueueAsync_AtCap_EvictsOldestFileBeforeWritingNewOne()
    {
        // Pre-fill the queue to exactly the cap with distinguishably-ordered
        // filenames (ascending timestamp prefix), then enqueue one more.
        for (int i = 0; i < InventoryQueuePump.MaxQueuedRecords; i++)
        {
            CreateQueueFile($"inv-{1000 + i:D6}-0.json");
        }

        var pump = MakePump(HttpStatusCode.ServiceUnavailable);
        await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes("newest"), CancellationToken.None);

        var files = Directory.GetFiles(_tmpDir, "inv-*.json");
        Assert.Equal(InventoryQueuePump.MaxQueuedRecords, files.Length);

        // The very oldest pre-existing file (smallest timestamp prefix) must
        // have been evicted to make room.
        Assert.DoesNotContain(files, f => Path.GetFileName(f).StartsWith("inv-001000-"));

        // The newest pre-existing file, and the one just enqueued, both survive.
        Assert.Contains(files, f => Path.GetFileName(f).StartsWith($"inv-{1000 + InventoryQueuePump.MaxQueuedRecords - 1:D6}-"));
    }

    [Fact]
    public async Task SendOrEnqueueAsync_RepeatedFailuresPastCap_NeverExceedsBound()
    {
        var pump = MakePump(HttpStatusCode.ServiceUnavailable);

        // Enqueue well past the cap; the directory must never grow beyond it.
        for (int i = 0; i < InventoryQueuePump.MaxQueuedRecords + 25; i++)
        {
            await pump.SendOrEnqueueAsync(System.Text.Encoding.UTF8.GetBytes($"record-{i}"), CancellationToken.None);
            var count = Directory.GetFiles(_tmpDir, "inv-*.json").Length;
            Assert.True(count <= InventoryQueuePump.MaxQueuedRecords,
                $"Queue depth {count} exceeded the {InventoryQueuePump.MaxQueuedRecords}-record bound after enqueue #{i}");
        }

        Assert.Equal(InventoryQueuePump.MaxQueuedRecords, Directory.GetFiles(_tmpDir, "inv-*.json").Length);
    }

    // ------------------------------------------------------------------ //
    // QueueDepth (PAT-1270)                                                //
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
        var pump = new InventoryQueuePump(NullLogger.Instance, factory, _creds, missingDir);

        Assert.Equal(0, pump.QueueDepth());
    }

    [Fact]
    public void QueueDepth_ReflectsQueuedFileCount()
    {
        CreateQueueFile("inv-100-1.json");
        CreateQueueFile("inv-200-1.json");
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

    private InventoryQueuePump MakePump(HttpStatusCode status) =>
        MakePump(new CountingFakeHttpHandler(status));

    private InventoryQueuePump MakePump(bool throwNetworkError) =>
        throwNetworkError
            ? MakePump(new ThrowingFakeHttpHandler())
            : MakePump(HttpStatusCode.OK);

    private InventoryQueuePump MakePump(
        HttpMessageHandler handler,
        Func<string, CancellationToken, Task<byte[]>>? readFileAsync = null,
        Func<DateTimeOffset>? utcNow = null)
    {
        var client  = new HttpClient(handler) { BaseAddress = new Uri("https://test.local") };
        var factory = new NamedClientFactory(client);
        return new InventoryQueuePump(NullLogger.Instance, factory, _creds, _tmpDir, readFileAsync, utcNow);
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
