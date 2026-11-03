using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Patched.Shared.Auth;
using Patched.Shared.Contract;
using Patched.Shared.Paths;
using Patched.Shared.Removal;

namespace Patched.Service;

/// <summary>
/// POSTs one authenticated provenance record to /v1/provenance per app action.
/// Mirrors patched-update.sh emit_provenance():
///   Authorization: Bearer &lt;token&gt;
///   X-Patched-Signature: &lt;hmac-sha256 hex&gt;
///
/// PAT-1249: POST /v1/provenance only accepts one record per request — no
/// batch/array envelope (checked against go-service's own
/// internal/handlers/provenance.go handler) — so the fix for the platform's
/// per-tenant rate limiter rejecting a cycle's back-to-back per-label POSTs
/// with HTTP 429 is pacing sends, not batching them. All the send/queue/pace/
/// 429-backoff mechanics live in <see cref="ProvenanceQueuePump"/> (modeled
/// directly on <see cref="InventoryQueuePump"/>); on any send failure the
/// payload is queued to disk (bounded, oldest-first eviction — see
/// ProvenanceQueuePump.MaxQueuedRecords) for retry by the pump, and the
/// current queue depth is reported as a degraded agent_health signal (see
/// <see cref="ReportQueueHealth"/>) so a stranded backlog is never invisible
/// again — 55 records had silently accumulated on WIN-STAGING because
/// nothing ever read this queue back before this pump existed.
/// </summary>
internal sealed class ProvenancePoster
{
    private readonly ILogger<ProvenancePoster> _log;
    private readonly IHttpClientFactory        _httpFactory;
    private readonly CredentialStore           _creds;
    private readonly DeviceCollector           _device;
    private readonly AgentHealthStore          _agentHealth;
    private readonly ProvenanceQueuePump       _pump;

    /// <summary>
    /// <paramref name="pumpOverride"/> exists purely for test isolation — a
    /// unit test can hand this a <see cref="ProvenanceQueuePump"/> already
    /// pointed at a temp queue directory (with a fake HTTP handler and
    /// injectable clock, via that pump's own constructor) instead of the
    /// real %ProgramData%\Patched\provenance-queue pump this class builds by
    /// default. Production DI resolves this constructor with no registered
    /// ProvenanceQueuePump service, so the container falls back to the
    /// default (null) and every real instance builds its own pump against
    /// <see cref="PathConstants.ProvenanceQueueDir"/> — the same seam
    /// AgentHealthStore's storePathOverride provides for its own store file.
    /// </summary>
    public ProvenancePoster(
        ILogger<ProvenancePoster> log,
        IHttpClientFactory        httpFactory,
        CredentialStore           creds,
        DeviceCollector           device,
        AgentHealthStore          agentHealth,
        ProvenanceQueuePump?      pumpOverride = null)
    {
        _log         = log;
        _httpFactory = httpFactory;
        _creds       = creds;
        _device      = device;
        _agentHealth = agentHealth;
        _pump        = pumpOverride ?? new ProvenanceQueuePump(log, httpFactory, creds, PathConstants.ProvenanceQueueDir);
    }

    private static readonly JsonSerializerOptions UninstallJsonOpts = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters             = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    public async Task PostAsync(AppEntry app, CancellationToken ct)
    {
        var payload = BuildPayload(app);
        var bodyBytes = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(payload,
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower }));

        await SendOrQueueAsync(bodyBytes, ct);
    }

    /// <summary>
    /// PAT-379: post one app_uninstall provenance record. Enums serialize snake_case
    /// and the property names come from [JsonPropertyName], so the body is identical
    /// in shape to the macOS engine's emit_uninstall_provenance.
    /// </summary>
    public async Task PostUninstallAsync(UninstallProvenance record, CancellationToken ct)
    {
        var bodyBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record, UninstallJsonOpts));
        await SendOrQueueAsync(bodyBytes, ct);
    }

    // PAT-1016: install/update provenance carried no per-device identifier, so the
    // server-side `lower(pr.body->'device'->>'hw_uuid')` join in advance.go/report.go
    // (queryFailureRate / fetchProvenancePatchHistory) had zero Windows observations.
    // Sourced from the same DeviceCollector.CollectDevice() the uninstall path
    // (RemovalRunner.RunAsync) already uses for UninstallProvenanceDevice, so the
    // shape here — {"device":{"hw_uuid":..., "computer_name":...}} — matches both
    // that path and the macOS emitter's body.device.{hw_uuid,computer_name}.
    internal Dictionary<string, object?> BuildPayload(AppEntry app)
    {
        var device = _device.CollectDevice();
        var computerName = string.IsNullOrWhiteSpace(device.Hostname) ? Environment.MachineName : device.Hostname;

        return new()
        {
            ["tenant_id"]        = _creds.TenantId,
            ["label"]            = app.Label,
            ["name"]             = app.Name,
            ["identifier"]       = app.WingetId,
            // PAT-381: a policy-suppressed app reports action "skipped_policy"
            // (parity with the macOS patched-update.sh provenance) so the
            // dashboard sees the toggle actuate on Windows the same as on macOS.
            ["action"]           = app.PolicyDisabled ? "skipped_policy" : app.LastAction,
            ["policy_source"]    = app.PolicySource,
            ["action_at"]        = app.LastActionAt?.ToString("O"),
            ["installed_version"]= app.InstalledVersion,
            ["available_version"]= app.AvailableVersion,
            ["state"]            = app.State.ToString().ToLowerInvariant(),
            ["failure_reason"]   = app.FailureReason?.ToString(),
            ["verified_signer"]  = app.VerifiedSigner,
            ["platform"]         = "windows",
            ["computer_name"]    = Environment.MachineName,
            ["device"]           = new Dictionary<string, object?>
            {
                ["hw_uuid"]       = device.HwUuid,
                ["computer_name"] = computerName,
            },
        };
    }

    private async Task SendOrQueueAsync(byte[] bodyBytes, CancellationToken ct)
    {
        await _pump.SendOrEnqueueAsync(bodyBytes, ct).ConfigureAwait(false);
        ReportQueueHealth();
    }

    /// <summary>
    /// PAT-1249: drains one persisted provenance payload per call, fairly
    /// rotating across retained files — the same "one file per Worker tick"
    /// pattern InventoryPoster.DrainQueueAsync uses via
    /// InventoryQueuePump.DrainOneAsync, wired into PatchedWorker's tick loop
    /// the same way. This is what actually drains the backlog the queue used
    /// to silently accumulate (55 records stranded on WIN-STAGING before this
    /// pump existed) — steadily, one file every ~15s tick, so recovery itself
    /// cannot re-trigger the rate limiter that produced the backlog.
    /// </summary>
    public async Task DrainQueueAsync(CancellationToken ct)
    {
        await _pump.DrainOneAsync(ct).ConfigureAwait(false);
        ReportQueueHealth();
    }

    /// <summary>
    /// PAT-1249: mirrors InstallRunner.RecordPackageEngineAvailability /
    /// DeviceRemovalRunner.RecordDeviceIdentityHealth's shape. Reports two
    /// independent degraded signals:
    ///
    ///   - kind="queue_backlog": the pump's current on-disk queue depth,
    ///     whenever it is non-zero — cleared once the depth reaches zero
    ///     again. This is the fix for the failure mode that let 55 records
    ///     accumulate with nothing anywhere reporting it: a write-only queue
    ///     that no one reads back is indistinguishable from a healthy one.
    ///
    ///   - kind="auth_failure" (non-author review, P1): whether the most
    ///     recently completed send hit HTTP 401/403 — see
    ///     ProvenanceQueuePump.LastAttemptWasAuthFailure. Deliberately a
    ///     separate signal rather than folded into queue_backlog: an auth
    ///     failure is never enqueued (see that same doc comment for why), so
    ///     a broken credential can produce a SMALL or EMPTY queue while still
    ///     being actively degraded — the opposite shape of queue_backlog, so
    ///     it needs its own kind or it would be invisible exactly when the
    ///     queue looks healthiest.
    ///
    /// Called after every send/enqueue attempt and after every drain attempt
    /// so both signals track the pump's real state from both directions.
    /// </summary>
    private void ReportQueueHealth()
    {
        var depth = _pump.QueueDepth();
        if (depth > 0)
        {
            _agentHealth.RecordFailure("queue_backlog", "provenance",
                $"{depth} record(s) queued for retry (cap {ProvenanceQueuePump.MaxQueuedRecords})");
        }
        else
        {
            _agentHealth.RecordSuccess("queue_backlog", "provenance");
        }

        if (_pump.LastAttemptWasAuthFailure)
        {
            _agentHealth.RecordFailure("auth_failure", "provenance",
                "provenance POST rejected with HTTP 401/403 — credential appears invalid or rotated");
        }
        else
        {
            _agentHealth.RecordSuccess("auth_failure", "provenance");
        }
    }
}
