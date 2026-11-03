using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Patched.Shared.Auth;
using Patched.Shared.Contract;
using Patched.Shared.Paths;

namespace Patched.Service;

/// <summary>
/// Ships structured security audit events to POST /v1/events (PAT-499).
/// Mirrors the InventoryPoster / ProvenancePoster send+queue+drain pattern.
///
/// Key differences vs provenance:
///   - Ship() is synchronous and non-blocking (writes to disk only).
///   - Queue is a ring-buffer capped at MaxQueuedEvents; oldest dropped on overflow.
///   - FlushAsync() drains the disk queue on each worker cycle (fail-safe: never throws).
/// </summary>
public class AuditEventShipper
{
    private const int MaxQueuedEvents = 1_000;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    private readonly ILogger<AuditEventShipper> _log;
    private readonly IHttpClientFactory         _httpFactory;
    private readonly CredentialStore            _creds;

    /// <summary>
    /// PAT-1077: guards the read-merge-write-POST-confirm-clear critical section in
    /// <see cref="PostEnforcementAuditAsync"/> around <see cref="PendingEnforcementAuditFilePath"/>.
    /// CONCURRENCY: today's only caller (PatchedWorker.RunCycleAsync, via
    /// RunFailSafeEnforcementAsync/RunTierGatedEnforcementAsync) awaits each run cycle to
    /// completion before starting the next, inside a single sequential BackgroundService
    /// loop, and the Windows Service host (AddWindowsService in Program.cs) guarantees one
    /// running instance of this service — so no two invocations can actually race on that
    /// file today. This is therefore a cheap correctness guard against a future change to
    /// that call graph, same reasoning as AgentHealthStore's in-process `_lock`, not a
    /// requirement of today's call graph. A SemaphoreSlim (not a plain `lock`) because this
    /// method awaits the network POST inside the guarded section, and `lock` cannot wrap an
    /// `await`.
    /// </summary>
    private readonly SemaphoreSlim _pendingAuditGate = new(1, 1);

    public AuditEventShipper(
        ILogger<AuditEventShipper> log,
        IHttpClientFactory         httpFactory,
        CredentialStore            creds)
    {
        _log         = log;
        _httpFactory = httpFactory;
        _creds       = creds;
    }

    /// <summary>
    /// Enqueue an event to the ring-buffer disk queue. Non-blocking.
    /// Never throws — audit event shipping must not affect agent behaviour.
    /// TenantId and DeviceId are filled from CredentialStore if not set by the caller.
    /// Virtual to allow test doubles (e.g. AdminEnforcerTests).
    /// </summary>
    public virtual void Ship(AuditEvent evt)
    {
        try
        {
            // Fill in identity fields the caller doesn't need to know about.
            if (string.IsNullOrEmpty(evt.TenantId) || string.IsNullOrEmpty(evt.DeviceId))
                evt = evt with
                {
                    TenantId = string.IsNullOrEmpty(evt.TenantId) ? _creds.TenantId : evt.TenantId,
                    DeviceId = string.IsNullOrEmpty(evt.DeviceId) ? Environment.MachineName : evt.DeviceId,
                };

            var body = JsonSerializer.Serialize(evt, JsonOpts);
            Directory.CreateDirectory(EventsQueueDirPath);
            EnforceRingBuffer();
            var path = Path.Combine(
                EventsQueueDirPath,
                $"evt-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}-{Guid.NewGuid():N}.json");
            File.WriteAllText(path, body, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "AuditEventShipper: failed to queue event type={Type} label={Label}",
                evt.EventType, evt.Label);
        }
    }

    /// <summary>
    /// Drain all queued events, posting them to /v1/events. Called on each worker cycle.
    /// Fail-safe: any individual POST failure leaves the file in place for the next cycle.
    /// </summary>
    public async Task FlushAsync(CancellationToken ct)
    {
        // PAT-1765: nothing is sent without the credential pair; queued events stay on
        // disk for the first flush after enrolment.
        if (!DeviceCredentials.TryRead(_creds, out var bearerToken, out var hmacSecret))
        {
            _log.LogDebug("Audit events: device credentials not present; queued events kept, nothing sent");
            return;
        }

        if (!Directory.Exists(EventsQueueDirPath)) return;

        string[] files;
        try { files = Directory.GetFiles(EventsQueueDirPath, "evt-*.json"); }
        catch { return; }

        if (files.Length == 0) return;

        Array.Sort(files);   // chronological order (timestamp prefix)
        int sent = 0, failed = 0;

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            byte[] body;
            try { body = File.ReadAllBytes(file); }
            catch { continue; }

            if (await TrySendAsync(body, bearerToken, hmacSecret, ct))
            {
                File.Delete(file);
                sent++;
            }
            else
            {
                failed++;
            }
        }

        if (sent > 0 || failed > 0)
            _log.LogInformation("Audit events: sent={Sent} queued={Failed}", sent, failed);
    }

    private async Task<bool> TrySendAsync(byte[] body, string bearerToken, string hmacSecret, CancellationToken ct)
    {
        try
        {
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            var nonce     = Guid.NewGuid().ToString("N");
            var sig       = HmacSigner.ComputeSignature(hmacSecret, "POST", HmacSigner.EndpointEvents, timestamp, nonce, body);

            using var content = new ByteArrayContent(body);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var client = _httpFactory.CreateClient("patched");
            using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/events") { Content = content };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
            req.Headers.Add(HmacSigner.SignatureHeader, sig);
            req.Headers.Add("X-Patched-Timestamp", timestamp);
            req.Headers.Add("X-Patched-Nonce", nonce);

            var resp = await client.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode) return true;

            _log.LogWarning("Audit event POST /v1/events returned {Status}", (int)resp.StatusCode);
            return false;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Audit event POST /v1/events failed (network)");
            return false;
        }
    }

    /// <summary>
    /// Path to the durable pending-enforcement-audit-events file. Virtual (like
    /// <see cref="PostEnforcementAuditAsync"/> itself) so a test subclass can redirect real
    /// file I/O to a scratch path — <see cref="PathConstants.PendingEnforcementAuditFile"/> is
    /// a fixed <c>static readonly</c> under %ProgramData% with no constructor/env seam of its
    /// own (same reasoning as BrowserExtensionBlocklistEnforcer.StateFilePath).
    /// </summary>
    internal virtual string PendingEnforcementAuditFilePath => PathConstants.PendingEnforcementAuditFile;

    /// <summary>
    /// PAT-1774: the ring-buffer disk queue directory <see cref="Ship"/>, <see cref="FlushAsync"/>
    /// and <see cref="EnforceRingBuffer"/> read and write. Virtual for the same reason as
    /// <see cref="PendingEnforcementAuditFilePath"/> above — <see cref="PathConstants.EventsQueueDir"/>
    /// is a fixed <c>static readonly</c> under %ProgramData% with no constructor/env seam of its
    /// own, so a test subclass overrides this to redirect real file I/O to a scratch directory
    /// instead of the real %ProgramData%\Patched\events-queue.
    /// </summary>
    internal virtual string EventsQueueDirPath => PathConstants.EventsQueueDir;

    /// <summary>
    /// POST enforcement audit events durably to /v1/inventory/enforcement-audit (PAT-603).
    /// Uses the same device bearer + HMAC-SHA256 scheme as /v1/events.
    ///
    /// PAT-1077: the artifact-level action this audit trail records (an admin removed, a
    /// browser extension deleted from disk, ...) has ALREADY happened and is unrecoverable/
    /// idempotent by the time this is called — a later run just finds nothing left to act on,
    /// so it never re-reports. A failed POST must therefore never mean a lost record, only a
    /// delayed one. Mirrors the macOS PAT-1037 shape (macos/lib/browser_extension_removal.sh):
    /// every new batch is merged onto any leftover batch from a prior failed attempt and
    /// committed atomically to <see cref="PendingEnforcementAuditFilePath"/> BEFORE the POST is
    /// even attempted, so a network failure can only delay delivery, never discard the record.
    /// A prior run's leftover pending batch is given a fresh drain attempt on every
    /// invocation, not only on calls that also carry new events — so <paramref name="events"/>
    /// may legitimately be empty and this method still makes a POST if a pending batch exists.
    ///
    /// "Confirmed" success is a 2xx response with a parseable <c>{"ingested": n}</c> body where
    /// n EXACTLY equals the combined batch size — go-service's dbIngestEnforcementAudit
    /// (enforcement_audit.go) wraps the whole batch in one Postgres transaction, so a genuine
    /// success is always all-rows-ingested, never a smaller count. A mismatched count, an
    /// unparseable body, a non-2xx status, or a network error are all treated the same way:
    /// NOT confirmed, so the pending file is left in place for the next invocation to retry.
    ///
    /// Known, currently-unclosable gap (same as macOS PAT-1037): the server has no idempotency
    /// key at the DB layer, only a per-request nonce that rejects a reused nonce with a bare
    /// 401 — indistinguishable from a genuine auth failure purely from the HTTP response. A
    /// 401 therefore falls into the same leave-pending branch as any other failure, so a real
    /// auth failure can never silently drop an audit event; the cost is a possible duplicate
    /// POST/insert on the next run if a 401 really was a replay of an already-ingested batch.
    ///
    /// Fail-safe: logs errors without throwing. Virtual to allow test doubles.
    /// </summary>
    public virtual async Task PostEnforcementAuditAsync(
        IReadOnlyList<EnforcementAuditEvent> events,
        CancellationToken ct = default)
    {
        await _pendingAuditGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var (outcome, prior) = TryReadPendingEnforcementAudit();
            if (outcome == PendingReadOutcome.Corrupt)
            {
                if (events.Count == 0)
                {
                    _log.LogError(
                        "Enforcement audit: {File} exists but is not valid JSON (corrupted or " +
                        "truncated), and there are no new events this cycle to attempt a " +
                        "best-effort POST with. NOT deleting it — left in place for manual " +
                        "inspection.",
                        PendingEnforcementAuditFilePath);
                    return;
                }

                // The prior contents are unrecoverable regardless, but this cycle's new
                // `events` are still sitting in memory — a corrupt local file is no reason to
                // give up on the network before even trying. Best-effort POST just `events`
                // (not `prior`, which is gone) directly, bypassing the durable-write step.
                var (corruptStatus, corruptConfirmed) =
                    await PostAndConfirmAsync(events, ct).ConfigureAwait(false);

                if (corruptConfirmed)
                {
                    _log.LogInformation(
                        "Enforcement audit: {File} was corrupted, but a best-effort direct POST " +
                        "of this cycle's {Count} new event(s) succeeded and was confirmed " +
                        "ingested (status {Status}) — removing the corrupt pending file now that " +
                        "this cycle is caught up; its own unrecoverable contents are gone " +
                        "regardless of whether the file is kept around.",
                        PendingEnforcementAuditFilePath, events.Count, (int)corruptStatus!.Value);
                    TryDeletePendingEnforcementAuditFile();
                }
                else
                {
                    _log.LogError(
                        "Enforcement audit: {File} exists but is not valid JSON (corrupted or " +
                        "truncated). NOT deleting it — left in place for manual inspection. A " +
                        "best-effort direct POST of this cycle's new event(s) also failed; they " +
                        "could not be durably recorded and are dropped: {Events}",
                        PendingEnforcementAuditFilePath, SerializeEventsForLog(events));
                }
                return;
            }

            var combined = new List<EnforcementAuditEvent>(prior.Count + events.Count);
            combined.AddRange(prior);
            combined.AddRange(events);

            if (combined.Count == 0) return; // nothing new this cycle, nothing pending either

            if (!WritePendingEnforcementAuditAtomic(combined))
            {
                // The durable write is what failed, not the network — a disk hiccup shouldn't
                // also cost us the network attempt. Best-effort POST the in-memory `combined`
                // list directly (skip the durable-write step, since it just failed).
                var (writeFailStatus, writeFailConfirmed) =
                    await PostAndConfirmAsync(combined, ct).ConfigureAwait(false);

                if (writeFailConfirmed)
                {
                    _log.LogWarning(
                        "Enforcement audit: could not durably commit merged pending batch " +
                        "({Count} event(s)) to {File} (disk issue — investigate), but a " +
                        "best-effort direct POST succeeded and was confirmed ingested (status " +
                        "{Status}); no data lost.",
                        combined.Count, PendingEnforcementAuditFilePath, (int)writeFailStatus!.Value);
                }
                else
                {
                    _log.LogError(
                        "Enforcement audit: could not durably commit merged pending batch " +
                        "({Count} event(s)) to {File}; this cycle's {NewCount} new event(s) " +
                        "could not be durably recorded (any pre-existing pending file is " +
                        "untouched). A best-effort direct POST also failed; the full merged " +
                        "batch could not be durably recorded and is dropped: {Events}",
                        combined.Count, PendingEnforcementAuditFilePath, events.Count,
                        SerializeEventsForLog(combined));
                }
                return;
            }

            var (statusCode, ingestedConfirmed) =
                await PostAndConfirmAsync(combined, ct).ConfigureAwait(false);

            if (ingestedConfirmed)
            {
                _log.LogInformation(
                    "Enforcement audit POST -> {Status}, ingested confirmed ({Count} event(s)) " +
                    "— clearing pending batch",
                    (int)statusCode!.Value, combined.Count);
                TryDeletePendingEnforcementAuditFile();
            }
            else if (statusCode is not null)
            {
                _log.LogWarning(
                    "Enforcement audit POST -> {Status} but response did not confirm ingestion " +
                    "of all {Count} event(s); pending batch left at {File} for next run",
                    (int)statusCode.Value, combined.Count, PendingEnforcementAuditFilePath);
            }
            // else: network-error branch already logged inside PostAndConfirmAsync.
        }
        finally
        {
            _pendingAuditGate.Release();
        }
    }

    /// <summary>
    /// POSTs <paramref name="batch"/> to /v1/inventory/enforcement-audit and reports whether
    /// ingestion of the FULL batch was confirmed. Shared by all three call sites in
    /// <see cref="PostEnforcementAuditAsync"/>: the normal durably-persisted-then-send path,
    /// and the two best-effort direct-send paths (corrupt pending file, durable-write
    /// failure) that skip persistence but must not skip the network attempt. Never throws
    /// (network/HTTP failures are logged here and reported back as an unconfirmed, null-status
    /// result); a genuine cancellation still propagates.
    /// </summary>
    private async Task<(System.Net.HttpStatusCode? StatusCode, bool Confirmed)> PostAndConfirmAsync(
        IReadOnlyList<EnforcementAuditEvent> batch, CancellationToken ct)
    {
        // PAT-1765: no POST without the credential pair. Reported as unconfirmed with no
        // status, the same as a network failure, so the caller keeps the durable pending
        // batch for the first run after enrolment.
        if (!DeviceCredentials.TryRead(_creds, out var bearerToken, out var hmacSecret))
        {
            _log.LogWarning(
                "Enforcement audit: device credentials not present (no usable bearer token and HMAC secret); {Count} event(s) not sent",
                batch.Count);
            return (null, false);
        }

        var body = JsonSerializer.SerializeToUtf8Bytes(new { events = batch }, JsonOpts);

        System.Net.HttpStatusCode? statusCode = null;
        bool confirmed = false;
        try
        {
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            var nonce     = Guid.NewGuid().ToString("N");
            var sig       = HmacSigner.ComputeSignature(hmacSecret, "POST", HmacSigner.EndpointEnforcementAudit, timestamp, nonce, body);

            using var content = new ByteArrayContent(body);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var client = _httpFactory.CreateClient("patched");
            using var req = new HttpRequestMessage(
                HttpMethod.Post, "/v1/inventory/enforcement-audit") { Content = content };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
            req.Headers.Add(HmacSigner.SignatureHeader, sig);
            req.Headers.Add("X-Patched-Timestamp", timestamp);
            req.Headers.Add("X-Patched-Nonce", nonce);

            using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
            statusCode = resp.StatusCode;

            if (resp.IsSuccessStatusCode)
            {
                var respBody = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                try
                {
                    using var doc = JsonDocument.Parse(respBody);
                    if (doc.RootElement.TryGetProperty("ingested", out var ingestedEl)
                        && ingestedEl.ValueKind == JsonValueKind.Number
                        && ingestedEl.TryGetInt32(out var ingested)
                        && ingested == batch.Count)
                    {
                        confirmed = true;
                    }
                }
                catch (JsonException)
                {
                    // Unparseable body — not confirmed; falls through to the leave-pending
                    // branch below exactly like a mismatched count would.
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogWarning(ex,
                "Enforcement audit POST /v1/inventory/enforcement-audit failed (network) for a " +
                "batch of {Count} event(s)",
                batch.Count);
        }

        return (statusCode, confirmed);
    }

    /// <summary>
    /// Best-effort JSON serialization of a batch of events for inclusion directly in a log
    /// message, used only on the fail-loud paths where the events are about to be dropped from
    /// durable storage entirely — matches this codebase's "fail loud, never fail silent"
    /// convention by keeping a trace of the actual dropped data in the event log, not just a
    /// count. Never throws: a serialization failure here must not prevent the ERROR log line
    /// itself from being emitted.
    /// </summary>
    private string SerializeEventsForLog(IReadOnlyList<EnforcementAuditEvent> events)
    {
        try
        {
            return JsonSerializer.Serialize(events, JsonOpts);
        }
        catch (Exception ex)
        {
            return $"<failed to serialize {events.Count} event(s) for logging: {ex.Message}>";
        }
    }

    private enum PendingReadOutcome { Empty, Loaded, Corrupt }

    /// <summary>
    /// Reads <see cref="PendingEnforcementAuditFilePath"/>. "Doesn't exist" (Empty, normal —
    /// nothing has ever been pending) is NOT the same outcome as "exists but fails to parse"
    /// (Corrupt — a loud failure the caller must not silently treat as empty, mirroring the
    /// macOS PAT-1037 merge helper's exit-code-3 distinction). A reparse point at the file or
    /// its containing directory is treated as Empty (refuse to read through it, per the same
    /// symlink-attack posture as BrowserExtensionBlocklistEnforcer.LoadState) rather than
    /// Corrupt, since WritePendingEnforcementAuditAtomic independently refuses to write through
    /// the same reparse point and reports that refusal on its own.
    /// </summary>
    private (PendingReadOutcome Outcome, List<EnforcementAuditEvent> Events) TryReadPendingEnforcementAudit()
    {
        var path = PendingEnforcementAuditFilePath;
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && IsReparsePoint(dir))
            {
                _log.LogWarning(
                    "Enforcement audit: refusing to read pending batch — containing directory " +
                    "'{Dir}' is a reparse point/junction, not a plain directory (possible " +
                    "symlink attack); treating as empty",
                    dir);
                return (PendingReadOutcome.Empty, new List<EnforcementAuditEvent>());
            }

            if (!File.Exists(path)) return (PendingReadOutcome.Empty, new List<EnforcementAuditEvent>());

            if (IsReparsePoint(path))
            {
                _log.LogWarning(
                    "Enforcement audit: refusing to read pending batch at '{Path}' — it is a " +
                    "reparse point/junction, not a plain file (possible symlink attack); " +
                    "treating as empty",
                    path);
                return (PendingReadOutcome.Empty, new List<EnforcementAuditEvent>());
            }

            var json = File.ReadAllText(path);
            var loaded = JsonSerializer.Deserialize<List<EnforcementAuditEvent>>(json, JsonOpts);
            return loaded is null
                ? (PendingReadOutcome.Corrupt, new List<EnforcementAuditEvent>())
                : (PendingReadOutcome.Loaded, loaded);
        }
        catch (Exception)
        {
            return (PendingReadOutcome.Corrupt, new List<EnforcementAuditEvent>());
        }
    }

    /// <summary>
    /// Persists the merged pending batch via write-to-temp-then-rename, guarding against a
    /// pre-planted NTFS reparse point (symlink/junction) at the containing directory, the temp
    /// path, or the final path — same hardening shape as
    /// BrowserExtensionBlocklistEnforcer.SaveState (PAT-1044) and AgentHealthStore.WriteAtomic.
    /// Returns false (and leaves any prior file untouched) on any failure; never throws.
    /// </summary>
    private bool WritePendingEnforcementAuditAtomic(List<EnforcementAuditEvent> combined)
    {
        var path = PendingEnforcementAuditFilePath;
        string? tmp = null;
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && IsReparsePoint(dir))
            {
                _log.LogWarning(
                    "Enforcement audit: refusing to persist pending batch — containing " +
                    "directory '{Dir}' is a reparse point/junction, not a plain directory " +
                    "(possible symlink attack); not creating or writing anything under it",
                    dir);
                return false;
            }

            Directory.CreateDirectory(dir!);
            var candidateTmp = path + ".tmp";

            if (IsReparsePoint(candidateTmp))
            {
                _log.LogWarning(
                    "Enforcement audit: refusing to persist pending batch — temp path '{Path}' " +
                    "is already a reparse point/junction, not a plain file (possible symlink " +
                    "attack); leaving it untouched and not writing",
                    candidateTmp);
                return false;
            }

            // Only track tmp for cleanup once confirmed safe to create/delete — a reparse point
            // caught above must never be deleted by the finally block below.
            tmp = candidateTmp;

            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write))
            {
                JsonSerializer.Serialize(fs, combined, JsonOpts);
            }

            if (IsReparsePoint(path))
            {
                _log.LogWarning(
                    "Enforcement audit: refusing to persist pending batch — destination " +
                    "'{Path}' is a reparse point/junction, not a plain file (possible symlink " +
                    "attack); not moving the freshly-written batch through it",
                    path);
                return false; // finally below deletes the freshly-written tmp
            }

            File.Move(tmp, path, overwrite: true);
            tmp = null; // moved successfully; nothing left to clean up
            return true;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Enforcement audit: could not persist pending batch to {File}", path);
            return false;
        }
        finally
        {
            if (tmp is not null)
            {
                try { File.Delete(tmp); }
                catch { /* best-effort cleanup; a failed save must not throw further */ }
            }
        }
    }

    private void TryDeletePendingEnforcementAuditFile()
    {
        try { File.Delete(PendingEnforcementAuditFilePath); }
        catch (Exception ex)
        {
            _log.LogWarning(ex,
                "Enforcement audit: could not delete cleared pending batch file {File}",
                PendingEnforcementAuditFilePath);
        }
    }

    /// <summary>
    /// True if a filesystem object already exists at <paramref name="path"/> and is a reparse
    /// point (NTFS symlink OR junction), checked without following it. Matches
    /// BrowserExtensionBlocklistEnforcer.IsReparsePoint / AgentHealthStore's identical helper —
    /// each durable-state class in this repo carries its own copy rather than sharing one.
    /// </summary>
    private static bool IsReparsePoint(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }

    private void EnforceRingBuffer()
    {
        try
        {
            var files = Directory.GetFiles(EventsQueueDirPath, "evt-*.json");
            if (files.Length < MaxQueuedEvents) return;

            // Drop oldest (smallest timestamp prefix) until under the cap.
            Array.Sort(files);
            int excess = files.Length - MaxQueuedEvents + 1;
            for (int i = 0; i < excess; i++)
            {
                try { File.Delete(files[i]); }
                catch { /* best-effort */ }
            }
        }
        catch { /* best-effort */ }
    }
}
