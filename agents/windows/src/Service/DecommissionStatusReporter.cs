using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Patched.Shared.Auth;
using Patched.Shared.Config;

namespace Patched.Service;

/// <summary>
/// Outcome of <see cref="DecommissionStatusReporter.ReportAcknowledgedAsync"/>. Third
/// contract round (2026-08, final wording): the platform's answer is BODY-FIRST — the
/// JSON <c>decommission</c> field ("proceed" | "superseded") is authoritative; the
/// HTTP status code (200 vs 409) is a secondary signal only, per
/// contracts/agent-config-schema.md. A response the agent cannot confidently read as
/// "proceed" — missing, unparseable, or an unrecognised <c>decommission</c> value —
/// is treated as <see cref="Aborted"/>, not as a green light: "an unreadable answer to
/// 'may I destroy this machine's agent' is not a yes."
/// </summary>
public enum DecommissionReportOutcome
{
    /// <summary>
    /// The response body's "decommission" field says "proceed" — the directive is
    /// still the tenant's current effective one. Safe to proceed.
    /// </summary>
    Proceed,

    /// <summary>
    /// The directive this report is about has been superseded or cancelled
    /// (mode="none") server-side since the agent last verified it — either because
    /// the body's "decommission" field explicitly said "superseded", OR because the
    /// platform WAS reachable but answered with something the agent cannot
    /// confidently read as "proceed" (missing/unparseable body, unrecognised
    /// decommission value, or a 409 with no parseable body). MUST NOT proceed with
    /// removal. Definitive: never retried — a reachable platform giving an
    /// unreadable answer is not a transient failure to retry past.
    /// </summary>
    Aborted,

    /// <summary>
    /// The retry budget was exhausted without ever getting a response at all
    /// (network/transport failure — the platform was UNREACHABLE, not merely
    /// unclear). The caller proceeds with removal anyway — network reachability
    /// must never be a way to indefinitely block an operator-issued decommission —
    /// but records that the outcome went unreported. Deliberately distinct from
    /// <see cref="Aborted"/>: reachable-but-unreadable fails closed; unreachable
    /// fails open (proceeds) after exhausting the bounded retry budget.
    /// </summary>
    Unreported,
}

/// <summary>
/// PAT-1110 (second contract round): reports the two-phase decommission status to
/// POST /v1/agent-decommission-status. Same auth chain as
/// <see cref="DeviceRemovalTasksClient"/>: Bearer + HMAC-SHA256 over the body +
/// X-Patched-Timestamp + X-Patched-Nonce.
///
/// Phase 1 (this class): a non-terminal "acknowledged" report sent BEFORE removal
/// begins — the last moment removal can still be called off. The platform's response
/// is the sole cancellation signal (see <see cref="DecommissionReportOutcome"/>).
///
/// Phase 2 (NOT this class): the genuine terminal outcome ("removed") is reported by
/// the detached removal script itself, AFTER it has verified removal actually
/// completed — see DecommissionHandoffScript. The .NET service is stopped by that same
/// script partway through, so it can never observe or report a verified terminal
/// outcome; posting one here, before removal has even started, would violate "never
/// post a terminal status you have not verified".
///
/// Bounded retry for genuine transport failure only (no response received at all) —
/// once ANY response comes back, the body's <c>decommission</c> field is decisive and
/// final, never retried (see <see cref="DecommissionReportOutcome"/>).
/// </summary>
/// <summary>
/// Seam so <c>DecommissionRunner</c> is unit-testable against every
/// <see cref="DecommissionReportOutcome"/> branch (Proceed / Aborted / Unreported)
/// without needing a real Windows Credential Manager or a real HTTP round trip —
/// mirrors <see cref="IDecommissionHandoff"/>'s reason for existing. Production DI
/// binds this to <see cref="DecommissionStatusReporter"/>.
/// </summary>
public interface IDecommissionStatusReporter
{
    Task<DecommissionReportOutcome> ReportAcknowledgedAsync(
        DecommissionPolicy policy, int directiveVersion, CancellationToken ct);
}

public class DecommissionStatusReporter : IDecommissionStatusReporter
{
    private readonly ILogger<DecommissionStatusReporter> _log;
    private readonly IHttpClientFactory                  _httpFactory;
    private readonly CredentialStore                     _creds;
    private readonly int                                 _maxAttempts;
    private readonly TimeSpan                             _retryDelay;

    public DecommissionStatusReporter(
        ILogger<DecommissionStatusReporter> log,
        IHttpClientFactory                  httpFactory,
        CredentialStore                     creds,
        int      maxAttempts = 3,
        TimeSpan? retryDelay = null)
    {
        _log         = log;
        _httpFactory = httpFactory;
        _creds       = creds;
        _maxAttempts = maxAttempts;
        _retryDelay  = retryDelay ?? TimeSpan.FromSeconds(5);
    }

    /// <summary>
    /// Reports the non-terminal "acknowledged" status for a decommission directive
    /// that is about to be actuated, BEFORE any removal step runs. This is the last
    /// point removal can be called off, and the platform's response is the sole
    /// mechanism for doing so (see <see cref="DecommissionReportOutcome"/>).
    /// </summary>
    /// <param name="policy">The verified decommission block that was acted on.</param>
    /// <param name="directiveVersion">
    /// The <c>config_version</c> of the signed agent-config whose <paramref name="policy"/>
    /// was actually acted on — captured by the caller at the point it decided to act
    /// (<see cref="DecommissionRunner"/>), NOT re-read here or afterwards from cached
    /// config, since the detached removal may already have deleted that cache by the
    /// time any retry runs. A missing/default value is treated server-side as
    /// untrusted and will not be attributed — so this is always sent, never omitted.
    /// </param>
    public async Task<DecommissionReportOutcome> ReportAcknowledgedAsync(
        DecommissionPolicy policy, int directiveVersion, CancellationToken ct)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(new DecommissionStatusRequest
        {
            Status          = "acknowledged",
            Purge           = policy.Purge,
            // Reason is forwarded for operator/audit visibility only — see
            // DecommissionPolicy's own doc comment. Never inspected here.
            Reason           = policy.Reason,
            ReportedAt       = DateTimeOffset.UtcNow,
            DirectiveVersion = directiveVersion,
        });

        for (int attempt = 1; attempt <= _maxAttempts; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var client = _httpFactory.CreateClient("patched");

                string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
                string nonce     = Guid.NewGuid().ToString("N");
                string sig       = HmacSigner.ComputeSignature(_creds.HmacSecret, "POST", HmacSigner.EndpointAgentDecommissionStatus, timestamp, nonce, body);

                using var content = new ByteArrayContent(body);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

                using var req = new HttpRequestMessage(
                    HttpMethod.Post, "/v1/agent-decommission-status") { Content = content };
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _creds.BearerToken);
                req.Headers.TryAddWithoutValidation(HmacSigner.SignatureHeader, sig);
                req.Headers.TryAddWithoutValidation("X-Patched-Timestamp", timestamp);
                req.Headers.TryAddWithoutValidation("X-Patched-Nonce", nonce);

                using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
                byte[] respBody = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);

                // We HAVE a response — the platform is reachable. From this point on
                // the body's "decommission" field decides, final, no retry: contract
                // final wording is body-first (contracts/agent-config-schema.md), the
                // HTTP status code is logged only as a secondary signal. This is
                // deliberately different from the catch block below, which retries —
                // there we never got a response at all.
                return ClassifyResponseBody(respBody, resp.StatusCode, attempt, directiveVersion);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                _log.LogWarning(ex, "decommission-status: attempt {Attempt}/{Max} failed (no response — platform unreachable)",
                    attempt, _maxAttempts);
            }

            if (attempt < _maxAttempts)
                await Task.Delay(_retryDelay, ct).ConfigureAwait(false);
        }

        return DecommissionReportOutcome.Unreported;
    }

    /// <summary>
    /// Decides Proceed/Aborted from a response the platform actually sent — status
    /// code is logged only, never decisive. Body shape (contracts/agent-config-schema.md,
    /// final wording):
    ///   200 → {"decommission":"proceed", "device_id":..., "recorded_status":...}
    ///   409 → {"decommission":"superseded", "device_id":...}
    ///
    /// Fails closed to <see cref="DecommissionReportOutcome.Aborted"/> for anything
    /// short of an explicit, recognised "proceed" — a missing/unparseable body, an
    /// unrecognised decommission value, or a 409 with no parseable body all abort,
    /// exactly as they would if the body had explicitly said "superseded". An
    /// unreadable answer to "may I destroy this machine's agent" is not a yes.
    /// </summary>
    /// <summary>internal (not private): directly unit tested — see DecommissionStatusReporterTests.</summary>
    internal DecommissionReportOutcome ClassifyResponseBody(
        byte[] body, HttpStatusCode statusCode, int attempt, int directiveVersion)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("decommission", out var d) &&
                d.ValueKind == JsonValueKind.String)
            {
                switch (d.GetString())
                {
                    case "proceed":
                        _log.LogInformation(
                            "decommission-status: body says proceed (http {Code}, attempt {Attempt}/{Max}) — proceeding",
                            (int)statusCode, attempt, _maxAttempts);
                        return DecommissionReportOutcome.Proceed;

                    case "superseded":
                        _log.LogWarning(
                            "decommission-status: directive_version={Version} superseded (body says so; http {Code}) " +
                            "— aborting, will NOT proceed with removal", directiveVersion, (int)statusCode);
                        return DecommissionReportOutcome.Aborted;

                    default:
                        _log.LogWarning(
                            "decommission-status: unrecognised decommission value '{Value}' (http {Code}) — " +
                            "failing closed, will NOT proceed with removal", d.GetString(), (int)statusCode);
                        return DecommissionReportOutcome.Aborted;
                }
            }

            _log.LogWarning(
                "decommission-status: response body missing a string 'decommission' field (http {Code}) — " +
                "failing closed, will NOT proceed with removal", (int)statusCode);
            return DecommissionReportOutcome.Aborted;
        }
        catch (JsonException ex)
        {
            _log.LogWarning(ex,
                "decommission-status: response body unparseable (http {Code}) — failing closed, " +
                "will NOT proceed with removal", (int)statusCode);
            return DecommissionReportOutcome.Aborted;
        }
    }
}

internal sealed record DecommissionStatusRequest
{
    [JsonPropertyName("status")]
    public string Status { get; init; } = "acknowledged";

    [JsonPropertyName("purge")]
    public bool Purge { get; init; }

    [JsonPropertyName("reason")]
    public string? Reason { get; init; }

    [JsonPropertyName("reported_at")]
    public DateTimeOffset ReportedAt { get; init; }

    /// <summary>
    /// The config_version of the signed agent-config whose decommission directive
    /// this report is about — see the doc comment on
    /// <see cref="DecommissionStatusReporter.ReportAcknowledgedAsync"/>. Field name
    /// and semantics must stay byte-identical to the macOS agent's report (ADR-0007
    /// parity; a divergence here is a parity failure, not a detail).
    /// </summary>
    [JsonPropertyName("directive_version")]
    public int DirectiveVersion { get; init; }
}
