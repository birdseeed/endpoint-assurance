using System.Management;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Patched.Shared.Auth;
using Patched.Shared.Paths;

namespace Patched.Service;

/// <summary>
/// Exchanges a single-use enrollment token for per-device credentials via
/// POST /v1/enrol. Invoked by PatchedWorker at startup when an enrollment
/// token is present but no bearer-token exists (fresh install / enrollment path).
///
/// Return semantics:
///   true  — enrolled (or no enrollment needed — caller proceeds normally).
///   false — terminal failure (410 consumed/expired, 401 rejected); the device
///           has been moved to suspended state; caller should halt all cycles.
///           PAT-1760: also returned when a 200 consumed the token but the
///           credentials it returned could not be stored, since that token can
///           never be used again either. PAT-1765: likewise for a 200 whose body
///           could not be read or parsed, or carried no tenant_id.
/// Transient failures (network, 5xx) return true — the worker retries on the
/// next TriggerPollInterval tick rather than halting.
/// </summary>
internal sealed class AgentEnroller
{
    private readonly ILogger<AgentEnroller> _log;
    private readonly IHttpClientFactory     _httpFactory;
    private readonly CredentialStore        _creds;
    private readonly AgentHealthStore?      _agentHealth;
    private readonly string                 _rollbackFloorFile;

    // PAT-1765: the enrolment token this process last saw the server consume or
    // reject. The suspended marker is what normally stops that token being sent
    // again, but the marker write can fail (an unwritable creds directory). This
    // keeps the token from being resent for the life of the process in that case;
    // a service restart tries it once more, the same documented cost as a stale
    // marker (PAT-1760). Read and written only from the worker's own loop.
    private string? _spentEnrollmentToken;

    // PAT-1765: exponential backoff for /v1/enrol answers that repeating every
    // 15-second poll cannot fix (see IsBackoffStatus). Worker-loop only, like
    // _spentEnrollmentToken above.
    internal static readonly TimeSpan EnrolBackoffBase = TimeSpan.FromSeconds(30);
    internal static readonly TimeSpan EnrolBackoffCap  = TimeSpan.FromHours(1);
    private readonly Func<DateTimeOffset> _utcNow;
    private int _backoffStep;
    private DateTimeOffset _backoffUntil = DateTimeOffset.MinValue;
    private string? _backoffToken; // the token that drew the backoff; a different token starts fresh

    public AgentEnroller(
        ILogger<AgentEnroller> log,
        IHttpClientFactory     httpFactory,
        CredentialStore        creds,
        AgentHealthStore       agentHealth)
        : this(log, httpFactory, creds, PathConstants.AgentConfigVersionFile, agentHealth)
    {
    }

    internal AgentEnroller(
        ILogger<AgentEnroller> log,
        IHttpClientFactory     httpFactory,
        CredentialStore        creds,
        string                 rollbackFloorFile,
        AgentHealthStore       agentHealth)
        : this(log, httpFactory, creds, rollbackFloorFile, utcNow: null, agentHealth)
    {
    }

    /// <summary>
    /// Test seam (PAT-1756): the same enroller with the agent-config
    /// anti-rollback floor redirected to a scratch path, so tests never touch
    /// %ProgramData%\Patched. PAT-1763: credentials are always stored through
    /// <see cref="CredentialStore.UpdateFromEnrolment"/>; a store from
    /// <see cref="CredentialStore.CreateForTests"/> writes them to an in-memory
    /// fake, never the host Credential Manager. Production always uses the
    /// public constructor.
    /// </summary>
    internal AgentEnroller(
        ILogger<AgentEnroller> log,
        IHttpClientFactory     httpFactory,
        CredentialStore        creds,
        string                 rollbackFloorFile,
        Func<DateTimeOffset>?  utcNow = null,
        AgentHealthStore?      agentHealth = null)
    {
        _log               = log;
        _httpFactory       = httpFactory;
        _creds             = creds;
        _agentHealth       = agentHealth;
        _rollbackFloorFile = rollbackFloorFile;
        _utcNow            = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    public async Task<bool> TryEnrolAsync(CancellationToken ct)
    {
        // Already enrolled, nothing to do. PAT-1760 review: "enrolled" is a usable
        // bearer token AND HMAC secret (DeviceCredentials.Present), the same rule every
        // authenticated caller applies. A bearer token with an unusable secret is not
        // enrolled, so an enrolment token present on the device is used to recover it.
        if (DeviceCredentials.Present(_creds))
            return true;

        // PAT-1765: a whitespace-only token is no token (DeviceCredentials.HasEnrollmentToken),
        // so it is never sent.
        var token = _creds.EnrollmentToken;
        if (!CredentialStore.IsUsableEnrollmentToken(token))
            return true;  // No token present (bare install or MDM raw-credential path)

        // PAT-1765: a token this process already saw consumed or rejected is never
        // resent, even when the suspended marker recording that could not be written.
        if (token == _spentEnrollmentToken)
        {
            _log.LogWarning("enrol: this enrolment token was already consumed or rejected and is not sent again; waiting for a fresh token");
            return false;
        }

        // PAT-1765: inside a backoff window nothing is sent; the backoff was logged
        // when it was set, so the worker's 15-second retry stays quiet here.
        if (token == _backoffToken && _utcNow() < _backoffUntil)
            return true;
        if (token != _backoffToken)
            ResetBackoff();

        _log.LogInformation("enrol: enrollment token present — calling /v1/enrol");

        var deviceId = ReadDeviceUuid();

        var payload = JsonSerializer.Serialize(new
        {
            enrollment_token = token,
            device_id        = deviceId,
        });

        HttpResponseMessage resp;
        try
        {
            var client = _httpFactory.CreateClient("patched");
            var req    = new HttpRequestMessage(HttpMethod.Post, "/v1/enrol");
            req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            resp = await client.SendAsync(req, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (
            ex is HttpRequestException or TaskCanceledException or OperationCanceledException
            && !ct.IsCancellationRequested)
        {
            _log.LogWarning(ex, "enrol: network error — will retry next poll");
            return true;
        }

        using (resp)
        {
            return (int)resp.StatusCode switch
            {
                200 => await HandleSuccessAsync(resp, token, ct).ConfigureAwait(false),
                410 => Suspend("410 Gone — enrollment token already consumed or expired", token),
                401 => Suspend("401 Unauthorized — enrollment token invalid", token),
                var code when IsBackoffStatus(code) => BackOff(code, token, resp.Headers.RetryAfter),
                _   => LogTransient((int)resp.StatusCode),
            };
        }
    }

    private async Task<bool> HandleSuccessAsync(HttpResponseMessage resp, string token, CancellationToken ct)
    {
        // PAT-1765: a 200 means the server has consumed the single-use token, whatever
        // the body turns out to hold. An unreadable body, an unparseable one, or one
        // with no tenant_id used to return "will retry", which resent the consumed token
        // every poll and drew a 410 that suspended the device with the real cause lost.
        // Each is now the same as an unusable pair below: logged, nothing stored, marker
        // written, token never resent.
        byte[] body;
        try
        {
            body = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw; // shutdown, not a response problem
        }
        catch (Exception ex)
        {
            _log.LogError(ex, ConsumedTokenUnusableResponse("the response body could not be read"));
            return SpendTokenAndSuspend(token);
        }

        string tenantId, bearerToken, hmacSecret;
        string? canonicalDeviceId;
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root  = doc.RootElement;
            tenantId    = root.GetProperty("tenant_id").GetString()    ?? "";
            bearerToken = root.GetProperty("bearer_token").GetString() ?? "";
            hmacSecret  = root.GetProperty("hmac_secret").GetString()  ?? "";
            canonicalDeviceId = root.TryGetProperty("device_id", out var id) && id.ValueKind == JsonValueKind.String ? id.GetString() : null;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, ConsumedTokenUnusableResponse("the response body is not JSON with string tenant_id, bearer_token and hmac_secret fields"));
            return SpendTokenAndSuspend(token);
        }

        // PAT-1760 review: a 200 has consumed the single-use token, so a response whose
        // bearer_token or hmac_secret is null, empty or whitespace cannot be retried into
        // an enrolment either. Storing it would leave the device holding credentials
        // that every caller treats as absent. Nothing is stored, and it fails the same
        // way as a failed credential write: not enrolled, device suspended, and the
        // consumed token is never sent again.
        if (!CredentialStore.IsUsablePair(bearerToken, hmacSecret))
        {
            _log.LogError(
                "enrol: the enrolment token was consumed by the server but the response carried an empty or whitespace bearer_token or hmac_secret. " +
                "Nothing was stored. The device is not enrolled and the consumed token cannot be used again. Re-provision the device with a fresh enrolment token");
            return SpendTokenAndSuspend(token);
        }

        if (string.IsNullOrWhiteSpace(tenantId))
        {
            _log.LogError(ConsumedTokenUnusableResponse("the response carried an empty or whitespace tenant_id"));
            return SpendTokenAndSuspend(token);
        }

        try
        {
            _creds.UpdateFromEnrolment(tenantId, bearerToken, hmacSecret, canonicalDeviceId);
        }
        catch (Exception ex)
        {
            // PAT-1760: this used to return true ("will retry"), which callers read
            // as enrolled: WaitForRecoveryAsync cleared the suspended marker and the
            // main loop retried /v1/enrol with a token the server had already
            // consumed. The 200 above means the single-use token is spent, so no
            // retry with it can succeed. Treat it like a rejected token: not
            // enrolled, device suspended (MarkSuspended writes the marker, never clears
            // it), and WaitForRecoveryAsync only retries once a different token is
            // provisioned. The floor is deliberately left alone: nothing was stored.
            // The exception carries no credential values (CredWrite reports only the
            // target name and a Win32 error code).
            _log.LogError(ex,
                "enrol: the enrolment token was consumed by the server but the credentials it returned could not be stored. " +
                "The device is not enrolled and the consumed token cannot be used again. Re-provision the device with a fresh enrolment token");
            return SpendTokenAndSuspend(token);
        }

        ResetAgentConfigRollbackFloor(tenantId);
        ClearMarkerThatPredatesTheseCredentials();
        ObserveRecoveryCredentialHealth();
        ResetBackoff();

        _log.LogInformation("enrol: enrolled successfully — tenant_id={TenantId}", tenantId);
        return true;
    }

    /// <summary>
    /// PAT-1760: enrolment runs only on a device with no bearer token, so any
    /// suspended marker on disk was written before the credentials just stored
    /// and cannot describe them (see PatchedWorker.WaitOutSuspensionAsync, which
    /// lets enrolment run past such a marker). Cleared once the new credentials
    /// are stored, so the device does not wait up to one agent-config poll with
    /// working credentials. A failure to clear is logged and left to the normal
    /// path: the worker's suspension gate waits, and the next signature-verified
    /// agent-config 200 clears the marker.
    /// </summary>
    private void ClearMarkerThatPredatesTheseCredentials()
    {
        try
        {
            if (!_creds.IsSuspended)
                return;
            _creds.ClearSuspended();
            _log.LogInformation("enrol: cleared a suspended marker written before these credentials were stored");
        }
        catch (Exception ex)
        {
            _log.LogError(ex,
                "enrol: could not clear the suspended marker after storing new credentials; collection stays paused until the next signature-verified agent-config response clears it");
        }
    }

    /// <summary>
    /// PAT-1756: a successful /v1/enrol is an admin-authorised act (a single-use
    /// token), and the device may now belong to a tenant whose config_version
    /// sequence is behind whatever floor is on disk. Once the new credentials
    /// are stored, a floor that cannot be this tenant's own is removed: a legacy
    /// bare integer (which the agent otherwise has to treat as the enrolled
    /// tenant's, the WIN-STAGING shape), a corrupt file, or a floor keyed to
    /// another tenant. A floor keyed to the tenant just enrolled is kept, so
    /// re-enrolling into the same tenant does not let an older signed config
    /// for that tenant be replayed. Called only after the credential write
    /// succeeded.
    /// </summary>
    private void ResetAgentConfigRollbackFloor(string tenantId)
    {
        var outcome = AgentConfigRollbackFloor.ResetForEnrolment(
            _rollbackFloorFile, tenantId, out var floor, out Exception? error);
        switch (outcome)
        {
            case AgentConfigRollbackFloor.EnrolmentResetOutcome.NoFloor:
                _log.LogInformation(
                    "enrol: no agent-config anti-rollback floor on disk; the first signed config for tenant {TenantId} sets it",
                    tenantId);
                break;
            case AgentConfigRollbackFloor.EnrolmentResetOutcome.KeptSameTenant:
                _log.LogInformation(
                    "enrol: agent-config anti-rollback floor kept at version {Version}; it already belongs to enrolled tenant {TenantId}",
                    floor.Version, tenantId);
                break;
            case AgentConfigRollbackFloor.EnrolmentResetOutcome.KeptUnreadable:
                _log.LogError(
                    "enrol: agent-config anti-rollback floor at {FloorFile} kept after enrolling into tenant {TenantId}: it could not be read ({Problem}), " +
                    "so it is not removed. Configs are refused until it can be read or an operator removes it",
                    _rollbackFloorFile, tenantId, floor.Problem);
                break;
            case AgentConfigRollbackFloor.EnrolmentResetOutcome.KeptUnstable:
                _log.LogError(
                    "enrol: agent-config anti-rollback floor at {FloorFile} kept after enrolling into tenant {TenantId}: it changed on every read, last seen as {FloorKind}. " +
                    "It is not removed; a config below that floor will be rejected until the file is removed",
                    _rollbackFloorFile, tenantId, DescribeFloor(floor));
                break;
            case AgentConfigRollbackFloor.EnrolmentResetOutcome.Removed:
                _log.LogInformation(
                    "enrol: agent-config anti-rollback floor removed ({FloorKind}); the first signed config for enrolled tenant {TenantId} sets the new floor",
                    DescribeFloor(floor), tenantId);
                break;
            default:
                _log.LogError(error,
                    "enrol: could not remove the agent-config anti-rollback floor ({FloorKind}) at {FloorFile} after enrolling into tenant {TenantId}. " +
                    "A config for this tenant below the old floor will be rejected until the file is removed",
                    DescribeFloor(floor), _rollbackFloorFile, tenantId);
                break;
        }
    }

    private static string DescribeFloor(AgentConfigRollbackFloor.StoredFloor floor) => floor switch
    {
        { State: AgentConfigRollbackFloor.FloorState.Corrupt } => $"corrupt: {floor.Problem}",
        { State: AgentConfigRollbackFloor.FloorState.Unreadable } => $"unreadable: {floor.Problem}",
        { IsLegacy: true } => $"legacy floor {floor.Version}",
        _ => $"floor {floor.Version} for tenant {floor.TenantId}",
    };

    private static string ConsumedTokenUnusableResponse(string problem) =>
        $"enrol: the enrolment token was consumed by the server (HTTP 200) but {problem}. " +
        "Nothing was stored. The device is not enrolled and the consumed token cannot be used again. Re-provision the device with a fresh enrolment token";

    private bool Suspend(string reason, string token)
    {
        _log.LogError("PATCHED_ENROL_REJECTED: {Reason} — device suspended", reason);
        return SpendTokenAndSuspend(token);
    }

    /// <summary>
    /// PAT-1765: records that <paramref name="token"/> is spent (consumed or rejected
    /// by the server) and writes the suspended marker. Always returns false (not
    /// enrolled). The marker write used to be unguarded: with an unwritable creds
    /// directory the exception escaped TryEnrolAsync, then PatchedWorker.ExecuteAsync,
    /// and the Generic Host stopped the service, which Product.wxs restarts only twice.
    /// A failed write is now logged and the device still behaves as suspended for this
    /// process: the token is not resent and <see cref="WaitForRecoveryAsync"/> waits for
    /// a fresh one.
    /// </summary>
    private bool SpendTokenAndSuspend(string token)
    {
        _spentEnrollmentToken = token;
        try
        {
            _creds.MarkSuspended();
        }
        catch (Exception ex)
        {
            _log.LogError(ex,
                "enrol: could not write the suspended marker. The service keeps running and this process will not send the spent enrolment token again, " +
                "but a service restart will try it once more. Check that the agent can write its credentials directory");
        }
        return false;
    }

    /// <summary>
    /// PAT-1765: true while the device holds no usable credentials and its current
    /// enrolment token is the one this process saw spent, which is the suspended state
    /// even when the marker for it could not be written.
    /// </summary>
    private bool WaitingOnSpentToken() =>
        _spentEnrollmentToken is not null
        && !DeviceCredentials.Present(_creds)
        && _creds.EnrollmentToken == _spentEnrollmentToken;

    /// <summary>
    /// PAT-1765: answers that the same request cannot fix by being repeated every
    /// 15 seconds. 400 (the device_id is not a UUID, as with the MachineName fallback
    /// when WMI has no UUID), 402 (the tenant's trial device cap), 409 (the tenant is
    /// decommissioned, PAT-1757) and 429 (rate limited). None of them consumes the
    /// token, so it is kept and retried, but on an exponential backoff.
    /// </summary>
    internal static bool IsBackoffStatus(int statusCode) => statusCode is 400 or 402 or 409 or 429;

    /// <summary>
    /// PAT-1765: the backoff for step <paramref name="step"/> (1-based):
    /// <see cref="EnrolBackoffBase"/> doubling each step, capped at <see cref="EnrolBackoffCap"/>.
    /// </summary>
    internal static TimeSpan BackoffDelay(int step)
    {
        // 2^20 is far past the cap and keeps the multiplication inside a long.
        var doublings = Math.Clamp(step - 1, 0, 20);
        var ticks = EnrolBackoffBase.Ticks * (1L << doublings);
        return ticks >= EnrolBackoffCap.Ticks ? EnrolBackoffCap : TimeSpan.FromTicks(ticks);
    }

    /// <summary>PAT-1765: the current backoff step (0 when not backing off), for tests.</summary>
    internal int BackoffStep => _backoffStep;

    private void ResetBackoff()
    {
        _backoffStep  = 0;
        _backoffUntil = DateTimeOffset.MinValue;
        _backoffToken = null;
    }

    /// <summary>
    /// PAT-1779: the delay before the next attempt for backoff step <paramref name="step"/>.
    /// For a 429 the server's Retry-After (delta seconds, or an HTTP-date read against
    /// <paramref name="now"/>) is honoured when it asks for longer than the computed
    /// backoff: max(<see cref="BackoffDelay"/>, Retry-After), still capped at
    /// <see cref="EnrolBackoffCap"/> so a hostile or mistaken header cannot park the
    /// device for longer than the existing cap. A Retry-After that is absent, zero, in
    /// the past, or on any other status is ignored. Also returns the Retry-After that
    /// was honoured (null when none was), for the log line.
    /// </summary>
    internal static (TimeSpan Delay, TimeSpan? RetryAfter) BackoffDelayHonouringRetryAfter(
        int step, int statusCode, RetryConditionHeaderValue? retryAfter, DateTimeOffset now)
    {
        var computed = BackoffDelay(step);
        if (statusCode != 429 || retryAfter is null)
            return (computed, null);

        TimeSpan? requested = retryAfter.Delta ?? (retryAfter.Date is { } date ? date - now : null);
        if (requested is not { } wait || wait <= computed)
            return (computed, null);

        return (wait >= EnrolBackoffCap ? EnrolBackoffCap : wait, wait);
    }

    private bool BackOff(int statusCode, string token, RetryConditionHeaderValue? retryAfter)
    {
        _backoffToken = token;
        _backoffStep++;
        var now = _utcNow();
        var (delay, honouredRetryAfter) = BackoffDelayHonouringRetryAfter(_backoffStep, statusCode, retryAfter, now);
        _backoffUntil = now.Add(delay);
        if (honouredRetryAfter is { } requested)
        {
            _log.LogWarning(
                "enrol: HTTP {Code} from /v1/enrol ({Meaning}); the enrolment token is kept, next attempt in {Delay} as the server's Retry-After of {RetryAfter} asks (backoff step {Step}, capped at {Cap})",
                statusCode, DescribeBackoffStatus(statusCode), delay, requested, _backoffStep, EnrolBackoffCap);
        }
        else
        {
            _log.LogWarning(
                "enrol: HTTP {Code} from /v1/enrol ({Meaning}); the enrolment token is kept, next attempt in {Delay} (backoff step {Step}, capped at {Cap})",
                statusCode, DescribeBackoffStatus(statusCode), delay, _backoffStep, EnrolBackoffCap);
        }
        return true;
    }

    private static string DescribeBackoffStatus(int statusCode) => statusCode switch
    {
        400 => "request rejected, for example a device_id that is not a UUID",
        402 => "the tenant's device limit is reached",
        409 => "the tenant is decommissioned",
        429 => "rate limited",
        _   => "not retryable at the poll interval",
    };

    private bool LogTransient(int statusCode)
    {
        _log.LogWarning("enrol: HTTP {Code} from /v1/enrol — will retry next poll", statusCode);
        return true;
    }

    /// <summary>
    /// PAT-1203: blocks while the device is suspended (<see
    /// cref="CredentialStore.IsSuspended"/>), polling at
    /// <paramref name="pollInterval"/> — the same cadence PatchedWorker uses
    /// for its trigger-file poll and PAT-1042's original revocation-wait loop.
    /// Called from PatchedWorker wherever it previously parked forever on a
    /// suspended device (startup, in-loop retry, and — since IsSuspended is
    /// checked at the top of every ExecuteAsync entry — after a full service
    /// restart too).
    ///
    /// Two independent causes share the single IsSuspended flag/sentinel, and
    /// this method resolves both without the caller needing to know which
    /// applies:
    ///
    ///  - Revocation (401 from /v1/agent-config): the device already has a
    ///    bearer token, and AgentConfigManager's own unconditional 15-minute
    ///    agent-config poll (a separate BackgroundService, not driven by this
    ///    method) already calls CredentialStore.ClearSuspended() the moment a
    ///    signature-verified 200 arrives. This method contributes nothing to
    ///    that path beyond noticing IsSuspended went false — same as
    ///    PatchedWorker's pre-PAT-1203 top-of-loop wait.
    ///
    ///  - Terminal enrollment rejection (410/401 from /v1/enrol): the device
    ///    has no bearer token, so AgentConfigFetcher's Authorization header is
    ///    empty and can never authenticate — the marker can never clear via
    ///    that path for this cause. Recovery instead requires an admin
    ///    dropping a FRESH single-use enrollment token. CredentialStore only
    ///    ever reads its EnrollmentToken sources once, at process start, so
    ///    this loop re-reads them itself (CredentialStore.RefreshEnrollmentToken)
    ///    every <paramref name="enrollmentRecheckInterval"/> and retries
    ///    TryEnrolAsync only when a token DIFFERENT from the one already
    ///    rejected shows up — RefreshEnrollmentToken itself refuses to signal
    ///    a retry for a repeat of the same still-bad token, so this loop can't
    ///    hammer /v1/enrol with a stale token the way macOS's
    ///    patched-enroll.sh did before PAT-1203 (see that script's 410/401
    ///    handling). A longer interval than the poll cadence is deliberate: a
    ///    token drop is a rare, deliberate admin action with no benefit from
    ///    sub-minute responsiveness, and every successful refresh costs one
    ///    real HTTP call to /v1/enrol.
    ///
    /// On a successful retry, clears the suspended marker itself — nothing
    /// else clears an enrollment-caused suspension — logs the recovery, and
    /// returns, leaving the caller to resume normal operation. Never runs any
    /// enforcement/collection cycle itself.
    /// </summary>
    public async Task WaitForRecoveryAsync(
        TimeSpan pollInterval, TimeSpan enrollmentRecheckInterval, CancellationToken ct)
    {
        var nextEnrollmentCheck = DateTimeOffset.UtcNow;
        ObserveRecoveryCredentialHealth();
        // PAT-1765: also waits when the marker for a spent token could not be written.
        while (_creds.IsSuspended || WaitingOnSpentToken())
        {
            await Task.Delay(pollInterval, ct).ConfigureAwait(false);

            ObserveRecoveryCredentialHealth();

            if (DateTimeOffset.UtcNow < nextEnrollmentCheck)
                continue;
            nextEnrollmentCheck = DateTimeOffset.UtcNow.Add(enrollmentRecheckInterval);

            if (!_creds.RefreshEnrollmentToken())
                continue;

            _log.LogInformation("enrol: new enrollment token detected while suspended — retrying enrollment");
            if (await TryEnrolAsync(ct).ConfigureAwait(false))
            {
                try
                {
                    _creds.ClearSuspended();
                    _log.LogInformation("enrol: retry with fresh token succeeded — suspended marker cleared");
                }
                catch (Exception ex)
                {
                    // PAT-1765: same reasoning as SpendTokenAndSuspend; a failure here must
                    // not stop the service. If the marker is still there the loop keeps
                    // waiting until the next signature-verified agent-config 200 clears it.
                    _log.LogError(ex, "enrol: retry with fresh token succeeded but the suspended marker could not be cleared");
                }
            }
            else
            {
                _log.LogError("enrol: retry with fresh token failed terminally — still suspended");
            }

            ObserveRecoveryCredentialHealth();
        }

        ObserveRecoveryCredentialHealth();
    }

    /// <summary>
    /// PAT-1781: a token this process has seen consumed or rejected is an unusable
    /// credential state until a usable bearer/HMAC pair appears. The persisted
    /// active row is the transition latch, so the recovery poll does not increment
    /// the same failure every tick.
    /// </summary>
    private void ObserveRecoveryCredentialHealth()
    {
        if (_agentHealth is null)
            return;

        if (DeviceCredentials.Present(_creds))
        {
            DeviceCredentialHealth.ClearIfActive(_agentHealth);
        }
        else if (WaitingOnSpentToken())
        {
            DeviceCredentialHealth.RecordFailureIfChanged(
                _agentHealth, DeviceCredentialHealth.EnrollmentTokenSpentReason);
        }
    }

    private string ReadDeviceUuid()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct");
            foreach (ManagementObject obj in searcher.Get())
            {
                var uuid = obj["UUID"]?.ToString();
                if (!string.IsNullOrEmpty(uuid))
                    return uuid;
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "enrol: WMI UUID unavailable — using machine name as device_id");
        }
        return Environment.MachineName;
    }
}
