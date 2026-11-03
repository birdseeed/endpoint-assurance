using System.Net.Http.Headers;
using Patched.Shared.Auth;

namespace Patched.Service;

/// <summary>
/// Sends/queues/drains provenance records for <see cref="ProvenancePoster"/>,
/// modeled directly on <see cref="InventoryQueuePump"/> (same send-or-enqueue,
/// fair-rotation single-file drain, and 429 Retry-After backoff shape).
///
/// PAT-1249: two things this pump does that <see cref="InventoryQueuePump"/>
/// does not need, because provenance — unlike inventory's single payload per
/// cycle — fires one record per allowlist label per cycle:
///   - Every send attempt (fresh or drained) is paced at least
///     <see cref="MinPostInterval"/> apart (<see cref="PaceBeforeSendAsync"/>).
///     ProvenancePoster used to fire one POST per label back to back with no
///     pacing at all; the platform's per-tenant rate limiter (RATE_LIMIT_RPM=60
///     sustained after a burst of 10 — see go-service's
///     cmd/patched-api/main.go) rejected 9 of one cycle's POSTs with HTTP 429
///     inside the same second. POST /v1/provenance (see go-service's
///     internal/handlers/provenance.go) accepts exactly one record per
///     request — no batch/array envelope — so pacing sends is the fix, not
///     batching them.
///   - The on-disk queue is bounded with oldest-first eviction
///     (<see cref="MaxQueuedRecords"/>/<see cref="EnforceBound"/>). Before
///     this pump existed nothing ever read <c>provenance-queue</c> back, so
///     it grew without limit — 55 records had silently accumulated on
///     WIN-STAGING, oldest from days earlier, by the time this was noticed.
///
/// Extracted from <see cref="ProvenancePoster"/> for the same reason
/// <see cref="InventoryQueuePump"/> was extracted from <c>InventoryPoster</c>:
/// the queue-drain/send/pace mechanics can be unit-tested with a fake HTTP
/// handler and an injectable clock, independent of DeviceCollector and the
/// other collaborators that make constructing a full <see cref="ProvenancePoster"/>
/// (or <c>InventoryPoster</c>) impractical in a unit test.
///
/// CONCURRENCY: like <see cref="InventoryQueuePump"/>, every call site
/// (PatchedWorker's provenance-posting loop, RemovalRunner's uninstall loop,
/// and PatchedWorker's queue-drain tick) runs sequentially, awaited one after
/// another, inside the single PatchedWorker BackgroundService's own async
/// loop — there is no concurrent caller, so <see cref="_lastSendAttemptAt"/>,
/// <see cref="_retryAfterUntil"/>, and <see cref="_lastTickFileName"/> need no
/// locking.
/// </summary>
internal sealed class ProvenanceQueuePump
{
    private static readonly TimeSpan Default429Backoff = TimeSpan.FromSeconds(60);

    /// <summary>
    /// PAT-1249: minimum spacing enforced between successive provenance send
    /// attempts (fresh sends and queue-drain retries alike). Chosen to sit
    /// just under the platform's sustained 1 request/sec (RATE_LIMIT_RPM=60)
    /// tenant rate limit once its burst allowance (RATE_LIMIT_BURST=10) is
    /// exhausted, so a full-allowlist cycle's worth of per-label POSTs never
    /// re-creates the original burst even though every request still goes
    /// out on its own (no batch envelope on the server side to use instead —
    /// see this class's own doc comment).
    /// </summary>
    private static readonly TimeSpan MinPostInterval = TimeSpan.FromMilliseconds(1100);

    /// <summary>
    /// PAT-1249: bounds the on-disk provenance retry queue so an extended
    /// outage or a persistent rate limit cannot grow it without limit — the
    /// write-only queue this pump replaces had already accumulated 55
    /// stranded records with no cap at all. Oldest-first eviction (see
    /// <see cref="EnforceBound"/>) mirrors the established ring-buffer
    /// precedent already in this service (AuditEventShipper's
    /// MaxQueuedEvents, PAT-499): the newest failures are the ones most
    /// likely to still be actionable against the currently-running
    /// allowlist, so when the cap is hit the stalest records are the ones
    /// dropped, not the freshest.
    /// </summary>
    internal const int MaxQueuedRecords = 1_000;

    private readonly ILogger            _log;
    private readonly IHttpClientFactory _httpFactory;
    private readonly CredentialStore    _creds;
    private readonly string             _queueDir;
    private readonly Func<string, CancellationToken, Task<byte[]>> _readFileAsync;
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private string? _lastTickFileName;
    private DateTimeOffset? _retryAfterUntil;
    private DateTimeOffset? _lastSendAttemptAt;

    /// <summary>
    /// PAT-1249 non-author review (P1): true if the most recently completed
    /// send attempt (fresh or drained) ended in HTTP 401/403. Unlike every
    /// other failure this pump treats as transient (429, 5xx, a network
    /// exception), an auth failure means the credential itself is bad —
    /// retrying, or queuing for a later retry with the same credential, can
    /// never succeed. Before this fix a rotated/invalid credential would
    /// queue every subsequent record forever, and because the queue is
    /// bounded (<see cref="MaxQueuedRecords"/>), that would fill it with
    /// doomed records and evict genuinely retryable ones.
    ///
    /// Reset to false at the start of every real HTTP attempt and set true
    /// only on an actual 401/403 response, so a later successful send (e.g.
    /// after re-enrollment refreshes the credential) clears it on its own.
    /// Left untouched — not reset — on a call that makes no HTTP attempt at
    /// all (empty queue, still inside a 429 backoff window, an unreadable
    /// file that gets skipped): <see cref="ProvenancePoster.ReportQueueHealth"/>
    /// reads this after every call, and a no-attempt call resetting it to
    /// false would report a false all-clear while the credential is still
    /// broken.
    /// </summary>
    internal bool LastAttemptWasAuthFailure { get; private set; }

    /// <summary>
    /// <paramref name="readFileAsync"/>, <paramref name="utcNow"/>, and
    /// <paramref name="delay"/> exist purely for test isolation — real
    /// callers (ProvenancePoster) never pass them, so production always uses
    /// the real file I/O, wall clock, and <see cref="Task.Delay(TimeSpan,CancellationToken)"/>.
    /// </summary>
    internal ProvenanceQueuePump(
        ILogger             log,
        IHttpClientFactory  httpFactory,
        CredentialStore     creds,
        string              queueDir,
        Func<string, CancellationToken, Task<byte[]>>? readFileAsync = null,
        Func<DateTimeOffset>? utcNow = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _log           = log;
        _httpFactory   = httpFactory;
        _creds         = creds;
        _queueDir      = queueDir;
        _readFileAsync = readFileAsync ?? File.ReadAllBytesAsync;
        _utcNow        = utcNow ?? (() => DateTimeOffset.UtcNow);
        _delay         = delay ?? Task.Delay;
    }

    // ------------------------------------------------------------------ //
    // Pacing                                                               //
    // ------------------------------------------------------------------ //

    /// <summary>
    /// Waits out whatever is left of <see cref="MinPostInterval"/> since the
    /// last send attempt (fresh or drained) before letting the caller
    /// proceed. A no-op on the very first call in this pump's lifetime (no
    /// prior attempt to pace against).
    /// </summary>
    private async Task PaceBeforeSendAsync(CancellationToken ct)
    {
        if (_lastSendAttemptAt is { } last)
        {
            var elapsed = _utcNow() - last;
            if (elapsed < MinPostInterval)
                await _delay(MinPostInterval - elapsed, ct).ConfigureAwait(false);
        }

        _lastSendAttemptAt = _utcNow();
    }

    // ------------------------------------------------------------------ //
    // Send the fresh payload; enqueue on any failure                      //
    // ------------------------------------------------------------------ //

    /// <summary>
    /// Paces, then tries to POST <paramref name="body"/> directly to
    /// <c>/v1/provenance</c>. On any failure (network, non-2xx, or
    /// unexpected exception) the body is written to the on-disk queue
    /// (bounded — see <see cref="MaxQueuedRecords"/>) for retry by
    /// <see cref="DrainAsync(CancellationToken)"/>.
    /// </summary>
    internal async Task SendOrEnqueueAsync(byte[] body, CancellationToken ct)
    {
        // PAT-1779: the pair is read once through DeviceCredentials.TryRead and that
        // snapshot is both the check and what signs and authorises the request, as in
        // PostureFetcher and AuditEventShipper (PAT-1765). The store used to be read
        // twice, the secret for the signature and the token for the header with the
        // client factory call in between, so a pair replaced in that window sent one
        // pair's token with the other pair's signature. Without a usable pair nothing
        // is sent (an unauthenticated request could only be rejected) and the record is
        // queued, like any other unsent record, for the first drain with credentials.
        // No attempt is made, so there is no pacing and LastAttemptWasAuthFailure is
        // left as it was.
        if (!DeviceCredentials.TryRead(_creds, out var bearerToken, out var hmacSecret))
        {
            _log.LogWarning("Provenance POST not sent: device credentials not present (no usable bearer token and HMAC secret); queuing for retry");
            await EnqueueAsync(body).ConfigureAwait(false);
            return;
        }

        await PaceBeforeSendAsync(ct).ConfigureAwait(false);

        bool ok = false;
        bool authFailure = false;
        try
        {
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            var nonce     = Guid.NewGuid().ToString("N");
            var sig       = HmacSigner.ComputeSignature(hmacSecret, "POST", HmacSigner.EndpointProvenance, timestamp, nonce, body);

            using var content = new ByteArrayContent(body);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var client = _httpFactory.CreateClient("patched");
            using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/provenance")
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
                _log.LogInformation("Provenance POST OK ({Bytes} bytes)", body.Length);
            else if (authFailure)
                _log.LogWarning(
                    "Provenance POST returned HTTP {Status} ({Bytes} bytes) — credential appears " +
                    "invalid or rotated; discarding this record instead of queuing it, since retrying " +
                    "with the same credential can never succeed",
                    (int)resp.StatusCode, body.Length);
            else
                _log.LogWarning("Provenance POST returned HTTP {Status} ({Bytes} bytes) — queuing for retry",
                    (int)resp.StatusCode, body.Length);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _retryAfterUntil = null;
            _log.LogWarning(ex, "Provenance POST failed — queuing for retry");
        }

        LastAttemptWasAuthFailure = authFailure;

        // PAT-1249 non-author review (P1): never enqueue an auth failure — see
        // LastAttemptWasAuthFailure's doc comment for why queuing it would
        // just fill the bounded queue with a record that can never send.
        if (!ok && !authFailure)
            await EnqueueAsync(body).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ //
    // Drain the on-disk queue                                              //
    // ------------------------------------------------------------------ //

    /// <summary>
    /// Reads all <c>prov-*.json</c> files from the queue directory and
    /// attempts to POST each one, paced the same as
    /// <see cref="SendOrEnqueueAsync"/>. Files are deleted only on a 2xx
    /// response; failures are logged and the file is retained for the next
    /// cycle.
    /// </summary>
    internal Task DrainAsync(CancellationToken ct) => DrainAsync(ct, maximumFiles: null);

    /// <summary>
    /// Attempts one persisted payload, rotating fairly across retained
    /// files. Used by PatchedWorker's lightweight poll tick — the same
    /// "one file per tick" pattern <see cref="InventoryQueuePump.DrainOneAsync"/>
    /// uses for inventory — so a queue backlog (including the 55 records
    /// already stranded on WIN-STAGING before this pump existed) drains
    /// steadily instead of bursting straight back into the rate limiter that
    /// produced it.
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
            _log.LogInformation("Provenance queue retry deferred until {RetryAfterUntil:O} after HTTP 429", retryAfterUntil);
            return;
        }

        if (!Directory.Exists(_queueDir)) return;

        string[] files;
        try
        {
            files = Directory.GetFiles(_queueDir, "prov-*.json");
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Provenance queue: failed to list queue directory — skipping drain");
            return;
        }

        if (files.Length == 0) return;

        // Make ordering independent of filesystem enumeration. The bounded
        // retry path rotates from the last selected file on subsequent ticks.
        Array.Sort(files, StringComparer.Ordinal);

        if (maximumFiles.HasValue)
            files = [SelectNextTickFile(files)];

        _log.LogInformation("Provenance queue: draining {Count} queued file(s)", files.Length);

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
                _log.LogWarning(ex, "Provenance queue: cannot read {File} — skipping",
                    Path.GetFileName(file));
                continue;
            }

            await PaceBeforeSendAsync(ct).ConfigureAwait(false);

            bool ok = false;
            bool authFailure = false;
            try
            {
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
                var nonce     = Guid.NewGuid().ToString("N");
                var sig       = HmacSigner.ComputeSignature(hmacSecret, "POST", HmacSigner.EndpointProvenance, timestamp, nonce, body);

                using var content = new ByteArrayContent(body);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

                var client = _httpFactory.CreateClient("patched");
                using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/provenance")
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
                // LastAttemptWasAuthFailure assignment that used to sit after
                // this try/catch, silently leaving it at its previous value.
                LastAttemptWasAuthFailure = authFailure;
                UpdateRetryBackoff(resp);

                if (ok)
                    _log.LogInformation("Provenance queue flush OK: {File}", Path.GetFileName(file));
                else if (authFailure)
                    _log.LogWarning(
                        "Provenance queue flush HTTP {Status}: {File} — credential appears invalid or " +
                        "rotated; leaving the file queued (not deleting it — a later re-enrollment may " +
                        "still be able to send it) but pausing further retries this pass",
                        (int)resp.StatusCode, Path.GetFileName(file));
                else
                    _log.LogWarning("Provenance queue flush HTTP {Status}: {File}",
                        (int)resp.StatusCode, Path.GetFileName(file));

                // PAT-1249 non-author review (P1): a 401/403 will not clear on
                // the next queued file either — it's the shared credential
                // that's bad, not this particular record — so stop this pass
                // the same way a 429 does, rather than burning through the
                // rest of the backlog on doomed attempts.
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
                _log.LogWarning(ex, "Provenance queue flush failed: {File}", Path.GetFileName(file));
            }

            if (ok)
            {
                try { File.Delete(file); }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Provenance queue: could not delete flushed file {File}",
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
    /// PAT-1249 non-author review (P1): 401 (bad/expired bearer token) and
    /// 403 (HMAC/signature rejected) are the only two statuses this pump
    /// treats as "the credential itself is wrong" rather than transient —
    /// see <see cref="LastAttemptWasAuthFailure"/>.
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
        _log.LogWarning("Provenance queue received HTTP 429; retry deferred until {RetryAfterUntil:O}", _retryAfterUntil.Value);
    }

    // ------------------------------------------------------------------ //
    // Queue depth (agent_health signal)                                   //
    // ------------------------------------------------------------------ //

    /// <summary>
    /// Current on-disk queue depth (count of queued <c>prov-*.json</c>
    /// files). PAT-1249: ProvenancePoster reports this as a degraded
    /// agent_health signal whenever it is non-zero, and clears it once the
    /// pump has drained the queue back to empty — see
    /// ProvenancePoster.ReportQueueHealth. Fail-safe: returns 0 (never
    /// throws) if the directory cannot be listed, matching every other
    /// best-effort queue read in this class.
    /// </summary>
    internal int QueueDepth()
    {
        try
        {
            return Directory.Exists(_queueDir)
                ? Directory.GetFiles(_queueDir, "prov-*.json").Length
                : 0;
        }
        catch
        {
            return 0;
        }
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
            var path = Path.Combine(_queueDir, $"prov-{epoch}-{rand}.json");
            await File.WriteAllBytesAsync(path, body).ConfigureAwait(false);
            _log.LogInformation("Provenance payload queued for retry: {File}", Path.GetFileName(path));
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Provenance queue: failed to write retry payload — payload lost for this cycle");
        }
    }

    /// <summary>
    /// PAT-1249: caps the on-disk queue at <see cref="MaxQueuedRecords"/>,
    /// evicting the oldest file(s) first when a new enqueue would exceed it
    /// — see that constant's doc comment for why oldest-first. Runs before
    /// the new file is written so it can never evict the record about to be
    /// added. Best-effort throughout: a failure to list or delete leaves the
    /// queue over-cap for this cycle rather than throwing into
    /// <see cref="EnqueueAsync"/>'s caller.
    /// </summary>
    private void EnforceBound()
    {
        try
        {
            var files = Directory.GetFiles(_queueDir, "prov-*.json");
            if (files.Length < MaxQueuedRecords) return;

            // Drop oldest (smallest timestamp prefix) until under the cap.
            Array.Sort(files, StringComparer.Ordinal);
            int excess = files.Length - MaxQueuedRecords + 1;
            for (int i = 0; i < excess; i++)
            {
                try
                {
                    File.Delete(files[i]);
                    _log.LogWarning("Provenance queue: bound of {Cap} exceeded — evicted oldest queued record {File}",
                        MaxQueuedRecords, Path.GetFileName(files[i]));
                }
                catch { /* best-effort */ }
            }
        }
        catch { /* best-effort */ }
    }
}
