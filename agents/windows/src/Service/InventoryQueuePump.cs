using System.Net.Http.Headers;
using Patched.Shared.Auth;

namespace Patched.Service;

/// <summary>
/// Drains the on-disk inventory retry queue: reads each <c>inv-*.json</c> file,
/// POSTs it to <c>POST /v1/inventory</c> with the device's HMAC + Bearer
/// credentials, and deletes the file only on a 2xx response.
///
/// Extracted from <see cref="InventoryPoster"/> so the queue-drain logic can be
/// unit-tested independently of all the collector singletons
/// (DeviceCollector, ComplianceCollector, …) that make <see cref="InventoryPoster"/>
/// impractical to construct in tests.
///
/// Also handles <see cref="SendOrEnqueueAsync"/>: tries a direct POST for the
/// current payload and enqueues to disk on any failure so the next cycle can retry.
///
/// Both <see cref="SendOrEnqueueAsync"/> and <see cref="DrainAsync"/> fully log
/// every attempt, HTTP status, and exception (including stack trace) so failures
/// are visible in the rolling file log even when the service cannot reach the
/// platform.
///
/// PAT-1266 (mirrors PAT-1249's fix on the sibling <c>ProvenanceQueuePump</c>):
/// HTTP 401/403 is a distinct, non-transient failure — the credential itself is
/// bad, so retrying can never succeed. <see cref="SendOrEnqueueAsync"/> does not
/// enqueue a fresh payload on an auth failure the way it would a 5xx or a
/// network exception (queuing it would just leave a record that can never
/// send), and <see cref="DrainAsync"/> stops the current drain pass on an auth
/// failure — same treatment as HTTP 429 — rather than burning through the rest
/// of the backlog on equally-doomed attempts. See
/// <see cref="LastAttemptWasAuthFailure"/> for the resulting health signal.
///
/// PAT-1270 (mirrors PAT-1249's fix on <c>ProvenanceQueuePump</c> again): the
/// on-disk queue is bounded (<see cref="MaxQueuedRecords"/>) with oldest-first
/// eviction, and the current depth is reported as a degraded agent_health
/// signal by <c>InventoryPoster.ReportQueueHealth</c> — see
/// <see cref="MaxQueuedRecords"/>'s doc comment for the bounded-vs-unbounded
/// decision and <see cref="QueueDepth"/> for the health-signal source.
/// </summary>
internal sealed class InventoryQueuePump
{
    private static readonly TimeSpan Default429Backoff = TimeSpan.FromSeconds(60);

    /// <summary>
    /// PAT-1270: bounds the on-disk inventory retry queue so a persistent
    /// rate limit or an extended outage cannot grow it without limit. Before
    /// this fix the queue had no cap at all -- unlike ProvenanceQueuePump's
    /// MaxQueuedRecords (added under PAT-1249 after 55 stranded provenance
    /// records were found on WIN-STAGING with nothing bounding that queue
    /// either), this pump never got the same treatment, and it was never a
    /// recorded decision to leave it that way -- just an omission that PAT-1270
    /// closes.
    ///
    /// Decision (PAT-1270): bound it the same way as provenance, for
    /// consistency and because an unbounded queue on a long-running endpoint
    /// is itself a resource-exhaustion risk. Inventory payloads are larger
    /// per record, but the loss on eviction is bounded and recoverable --
    /// the next successful inventory cycle produces a fresh full payload
    /// that supersedes any stale queued one, whereas provenance records
    /// (one per app action) are not superseded by later cycles the same way.
    /// If anything that argues for a *shorter* worst case here, not an
    /// unbounded one. Same oldest-first eviction as ProvenanceQueuePump (see
    /// <see cref="EnforceBound"/>) so the newest, most actionable failures are
    /// the ones kept when the cap is hit.
    /// </summary>
    internal const int MaxQueuedRecords = 1_000;

    private readonly ILogger          _log;
    private readonly IHttpClientFactory _httpFactory;
    private readonly CredentialStore  _creds;
    private readonly string           _queueDir;
    private readonly Func<string, CancellationToken, Task<byte[]>> _readFileAsync;
    private readonly Func<DateTimeOffset> _utcNow;
    private string? _lastTickFileName;
    private DateTimeOffset? _retryAfterUntil;

    /// <summary>
    /// PAT-1266 (mirrors ProvenanceQueuePump.LastAttemptWasAuthFailure, added by
    /// PAT-1249): true if the most recently completed send attempt (fresh or
    /// drained) ended in HTTP 401/403. Unlike every other failure this pump
    /// treats as transient (5xx, a network exception), an auth failure means
    /// the credential itself is bad — retrying, or queuing for a later retry
    /// with the same credential, can never succeed. Before this fix a
    /// rotated/invalid credential would queue every subsequent inventory
    /// payload forever.
    ///
    /// Reset to false at the start of every real HTTP attempt and set true
    /// only on an actual 401/403 response, so a later successful send (e.g.
    /// after re-enrollment refreshes the credential) clears it on its own.
    /// Left untouched — not reset — on a call that makes no HTTP attempt at
    /// all (empty queue, an unreadable file that gets skipped): callers read
    /// this after every pump call, and a no-attempt call resetting it to
    /// false would report a false all-clear while the credential is still
    /// broken.
    /// </summary>
    internal bool LastAttemptWasAuthFailure { get; private set; }

    internal InventoryQueuePump(
        ILogger             log,
        IHttpClientFactory  httpFactory,
        CredentialStore     creds,
        string              queueDir,
        Func<string, CancellationToken, Task<byte[]>>? readFileAsync = null,
        Func<DateTimeOffset>? utcNow = null)
    {
        _log         = log;
        _httpFactory = httpFactory;
        _creds       = creds;
        _queueDir    = queueDir;
        _readFileAsync = readFileAsync ?? File.ReadAllBytesAsync;
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    // ------------------------------------------------------------------ //
    // Send the fresh payload; enqueue on any failure                      //
    // ------------------------------------------------------------------ //

    /// <summary>
    /// Tries to POST <paramref name="body"/> directly to <c>/v1/inventory</c>.
    /// On any failure (network, non-2xx, or unexpected exception) the body is
    /// written to the on-disk queue for retry by <see cref="DrainAsync"/>.
    /// </summary>
    internal async Task SendOrEnqueueAsync(byte[] body, CancellationToken ct)
    {
        // PAT-1779: the pair is read once through DeviceCredentials.TryRead and that
        // snapshot is both the check and what signs and authorises the request, as in
        // PostureFetcher and AuditEventShipper (PAT-1765). The store used to be read
        // twice, the secret for the signature and the token for the header with the
        // client factory call in between, so a pair replaced in that window sent one
        // pair's token with the other pair's signature. InventoryPoster gates on the
        // pair before it builds a payload; if the pair is unusable by the time it gets
        // here nothing is sent and the payload is queued for the first drain with one.
        // No attempt is made, so LastAttemptWasAuthFailure is left as it was.
        if (!DeviceCredentials.TryRead(_creds, out var bearerToken, out var hmacSecret))
        {
            _log.LogWarning("Inventory POST not sent: device credentials not present (no usable bearer token and HMAC secret); queuing for retry");
            await EnqueueAsync(body).ConfigureAwait(false);
            return;
        }

        bool ok = false;
        bool authFailure = false;
        try
        {
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            var nonce     = Guid.NewGuid().ToString("N");
            var sig       = HmacSigner.ComputeSignature(hmacSecret, "POST", HmacSigner.EndpointInventory, timestamp, nonce, body);

            using var content = new ByteArrayContent(body);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var client = _httpFactory.CreateClient("patched");
            using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/inventory")
                { Content = content };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
            req.Headers.Add(HmacSigner.SignatureHeader, sig);
            req.Headers.Add("X-Patched-Timestamp", timestamp);
            req.Headers.Add("X-Patched-Nonce", nonce);

            var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
            ok = resp.IsSuccessStatusCode;
            authFailure = !ok && IsAuthFailure(resp.StatusCode);
            UpdateRetryBackoff(resp);

            if (ok)
                _log.LogInformation("Inventory POST OK ({Bytes} bytes)", body.Length);
            else if (authFailure)
                _log.LogWarning(
                    "Inventory POST returned HTTP {Status} ({Bytes} bytes) — credential appears " +
                    "invalid or rotated; discarding this payload instead of queuing it, since retrying " +
                    "with the same credential can never succeed",
                    (int)resp.StatusCode, body.Length);
            else
                _log.LogWarning("Inventory POST returned HTTP {Status} ({Bytes} bytes) — queuing for retry",
                    (int)resp.StatusCode, body.Length);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _retryAfterUntil = null;
            _log.LogWarning(ex, "Inventory POST failed — queuing for retry");
        }

        LastAttemptWasAuthFailure = authFailure;

        // PAT-1266 (mirrors PAT-1249 non-author review, P1): never enqueue an
        // auth failure — see LastAttemptWasAuthFailure's doc comment for why
        // queuing it would just leave a record that can never send.
        if (!ok && !authFailure)
            await EnqueueAsync(body).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ //
    // Drain the on-disk queue                                              //
    // ------------------------------------------------------------------ //

    /// <summary>
    /// Reads all <c>inv-*.json</c> files from the queue directory and attempts
    /// to POST each one. Files are deleted only on a 2xx response; failures
    /// are logged and the file is retained for the next cycle.
    /// </summary>
    internal Task DrainAsync(CancellationToken ct) => DrainAsync(ct, maximumFiles: null);

    /// <summary>
    /// Attempts one persisted payload, rotating fairly across retained files.
    /// Used by PatchedWorker's lightweight poll tick so a queue backlog cannot
    /// burst every payload and repeatedly exhaust the shared platform rate limit.
    /// </summary>
    internal Task DrainOneAsync(CancellationToken ct) => DrainAsync(ct, maximumFiles: 1);

    private async Task DrainAsync(CancellationToken ct, int? maximumFiles)
    {
        // PAT-1779: one TryRead snapshot is the check and signs every request of this
        // pass (see SendOrEnqueueAsync). Without a usable pair the queue is kept.
        if (!DeviceCredentials.TryRead(_creds, out var bearerToken, out var hmacSecret))
            return;

        if (_retryAfterUntil is { } retryAfterUntil && _utcNow() < retryAfterUntil)
        {
            _log.LogInformation("Inventory queue retry deferred until {RetryAfterUntil:O} after HTTP 429", retryAfterUntil);
            return;
        }

        if (!Directory.Exists(_queueDir)) return;

        string[] files;
        try
        {
            files = Directory.GetFiles(_queueDir, "inv-*.json");
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Inventory queue: failed to list queue directory — skipping drain");
            return;
        }

        if (files.Length == 0) return;

        // Make ordering independent of filesystem enumeration. The bounded
        // retry path rotates from the last selected file on subsequent ticks.
        Array.Sort(files, StringComparer.Ordinal);

        if (maximumFiles.HasValue)
            files = [SelectNextTickFile(files)];

        _log.LogInformation("Inventory queue: draining {Count} queued file(s)", files.Length);

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) break;
            if (maximumFiles.HasValue)
                _lastTickFileName = Path.GetFileName(file);

            byte[] body;
            try
            {
                body = await _readFileAsync(file, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Inventory queue: cannot read {File} — skipping",
                    Path.GetFileName(file));
                continue;
            }

            bool ok = false;
            bool authFailure = false;
            try
            {
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
                var nonce     = Guid.NewGuid().ToString("N");
                var sig       = HmacSigner.ComputeSignature(hmacSecret, "POST", HmacSigner.EndpointInventory, timestamp, nonce, body);

                using var content = new ByteArrayContent(body);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

                var client = _httpFactory.CreateClient("patched");
                using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/inventory")
                    { Content = content };
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
                req.Headers.Add(HmacSigner.SignatureHeader, sig);
                req.Headers.Add("X-Patched-Timestamp", timestamp);
                req.Headers.Add("X-Patched-Nonce", nonce);

                var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
                ok = resp.IsSuccessStatusCode;
                var rateLimited = resp.StatusCode == System.Net.HttpStatusCode.TooManyRequests;
                authFailure = !ok && IsAuthFailure(resp.StatusCode);
                // Set before the possible `break` below — `break` exits the
                // foreach immediately and would otherwise skip the
                // LastAttemptWasAuthFailure assignment that would otherwise
                // sit after this try/catch, silently leaving it at its
                // previous value.
                LastAttemptWasAuthFailure = authFailure;
                UpdateRetryBackoff(resp);

                if (ok)
                    _log.LogInformation("Inventory queue flush OK: {File}", Path.GetFileName(file));
                else if (authFailure)
                    _log.LogWarning(
                        "Inventory queue flush HTTP {Status}: {File} — credential appears invalid or " +
                        "rotated; leaving the file queued (not deleting it — a later re-enrollment may " +
                        "still be able to send it) but pausing further retries this pass",
                        (int)resp.StatusCode, Path.GetFileName(file));
                else
                    _log.LogWarning("Inventory queue flush HTTP {Status}: {File}",
                        (int)resp.StatusCode, Path.GetFileName(file));

                // PAT-1266 (mirrors PAT-1249 non-author review, P1): a 401/403
                // will not clear on the next queued file either — it's the
                // shared credential that's bad, not this particular record —
                // so stop this pass the same way a 429 does, rather than
                // burning through the rest of the backlog on doomed attempts.
                if (rateLimited || authFailure)
                    break;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                _retryAfterUntil = null;
                // A network/unexpected exception is a completed attempt too,
                // just not one that produced an HTTP status — never an auth
                // failure specifically, so this must not leave a stale `true`
                // from an earlier iteration in place.
                LastAttemptWasAuthFailure = false;
                _log.LogWarning(ex, "Inventory queue flush failed: {File}", Path.GetFileName(file));
            }

            if (ok)
            {
                try { File.Delete(file); }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Inventory queue: could not delete flushed file {File}",
                        Path.GetFileName(file));
                }
            }
        }
    }

    private string SelectNextTickFile(string[] sortedFiles)
    {
        if (_lastTickFileName == null)
            return sortedFiles[0];

        foreach (var file in sortedFiles)
        {
            if (StringComparer.Ordinal.Compare(Path.GetFileName(file), _lastTickFileName) > 0)
                return file;
        }

        return sortedFiles[0];
    }

    /// <summary>
    /// PAT-1266 (mirrors ProvenanceQueuePump.IsAuthFailure, added by PAT-1249
    /// non-author review): 401 (bad/expired bearer token) and 403 (HMAC/
    /// signature rejected) are the only two statuses this pump treats as "the
    /// credential itself is wrong" rather than transient — see
    /// <see cref="LastAttemptWasAuthFailure"/>.
    /// </summary>
    private static bool IsAuthFailure(System.Net.HttpStatusCode status) =>
        status == System.Net.HttpStatusCode.Unauthorized || status == System.Net.HttpStatusCode.Forbidden;

    private void UpdateRetryBackoff(HttpResponseMessage response)
    {
        if (response.StatusCode != System.Net.HttpStatusCode.TooManyRequests)
        {
            _retryAfterUntil = null;
            return;
        }

        var now = _utcNow();
        var retryAfter = response.Headers.RetryAfter;
        TimeSpan? delay = retryAfter?.Delta;
        if (delay == null && retryAfter?.Date is { } retryAfterDate)
            delay = retryAfterDate - now;
        delay ??= Default429Backoff;

        // A past Retry-After date is not a useful retry instruction. Keep the
        // conservative local default rather than immediately re-consuming the
        // shared limiter.
        if (delay.Value <= TimeSpan.Zero)
            delay = Default429Backoff;

        _retryAfterUntil = now.Add(delay.Value);
        _log.LogWarning("Inventory queue received HTTP 429; retry deferred until {RetryAfterUntil:O}", _retryAfterUntil.Value);
    }

    // ------------------------------------------------------------------ //
    // Private helpers                                                      //
    // ------------------------------------------------------------------ //

    private async Task EnqueueAsync(byte[] body)
    {
        try
        {
            Directory.CreateDirectory(_queueDir);
            EnforceBound();
            var epoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            // Use Abs() so the filename is never negative even on improbable int overflow.
            var rand = Math.Abs(Random.Shared.Next());
            var path = Path.Combine(_queueDir, $"inv-{epoch}-{rand}.json");
            await File.WriteAllBytesAsync(path, body).ConfigureAwait(false);
            _log.LogInformation("Inventory payload queued for retry: {File}", Path.GetFileName(path));
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Inventory queue: failed to write retry payload — payload lost for this cycle");
        }
    }

    /// <summary>
    /// PAT-1270 (mirrors ProvenanceQueuePump.EnforceBound, added by PAT-1249):
    /// caps the on-disk queue at <see cref="MaxQueuedRecords"/>, evicting the
    /// oldest file(s) first when a new enqueue would exceed it -- see that
    /// constant's doc comment for why oldest-first. Runs before the new file
    /// is written so it can never evict the record about to be added.
    /// Best-effort throughout: a failure to list or delete leaves the queue
    /// over-cap for this cycle rather than throwing into
    /// <see cref="EnqueueAsync"/>'s caller.
    /// </summary>
    private void EnforceBound()
    {
        try
        {
            var files = Directory.GetFiles(_queueDir, "inv-*.json");
            if (files.Length < MaxQueuedRecords) return;

            // Drop oldest (smallest timestamp prefix) until under the cap.
            Array.Sort(files, StringComparer.Ordinal);
            int excess = files.Length - MaxQueuedRecords + 1;
            for (int i = 0; i < excess; i++)
            {
                try
                {
                    File.Delete(files[i]);
                    _log.LogWarning("Inventory queue: bound of {Cap} exceeded — evicted oldest queued record {File}",
                        MaxQueuedRecords, Path.GetFileName(files[i]));
                }
                catch { /* best-effort */ }
            }
        }
        catch { /* best-effort */ }
    }

    // ------------------------------------------------------------------ //
    // Queue depth (agent_health signal)                                   //
    // ------------------------------------------------------------------ //

    /// <summary>
    /// Current on-disk queue depth (count of queued <c>inv-*.json</c> files).
    /// PAT-1270: InventoryPoster reports this as a degraded agent_health
    /// signal whenever it is non-zero, and clears it once the pump has
    /// drained the queue back to empty -- see InventoryPoster.ReportQueueHealth,
    /// mirroring ProvenancePoster.ReportQueueHealth's queue_backlog signal
    /// (PAT-1249). Fail-safe: returns 0 (never throws) if the directory
    /// cannot be listed, matching every other best-effort queue read in this
    /// class.
    /// </summary>
    internal int QueueDepth()
    {
        try
        {
            return Directory.Exists(_queueDir)
                ? Directory.GetFiles(_queueDir, "inv-*.json").Length
                : 0;
        }
        catch
        {
            return 0;
        }
    }
}
