using System.Net;
// DEPRECATED — PAT-1531: legacy removal source retained for reference only;
// excluded from the Windows assurance-only Service build.
using System.Net.Http.Headers;
using System.Text.Json;
using Patched.Shared.Auth;
using Patched.Shared.Posture;
using Patched.Shared.Removal;

namespace Patched.Service;

/// <summary>
/// Talks to the per-device removal-task endpoints (PAT-781):
///   GET  /v1/devices/{deviceID}/removal-tasks/pending
///   POST /v1/devices/{deviceID}/removal-tasks/report
///
/// Same auth chain as <see cref="PendingRemovalsFetcher"/> / <see cref="ProvenancePoster"/>:
/// Bearer + HMAC-SHA256 over the body + X-Patched-Timestamp + X-Patched-Nonce.
/// The {deviceID} segment is the server-assigned device UUID (devices.id), which the
/// agent learns from the cached posture (device.id) — distinct from the WMI hardware
/// UUID and refreshed on every posture poll, so no enrolment change is required.
///
/// Fail-safe: fetch errors return an empty list and report errors return false, so a
/// bad cycle is a no-op that retries next time — nothing throws into the worker.
/// </summary>
public sealed class DeviceRemovalTasksClient
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    private readonly ILogger<DeviceRemovalTasksClient> _log;
    private readonly IHttpClientFactory                _httpFactory;
    private readonly CredentialStore                   _creds;
    private readonly string?                            _postureCachePathOverride;

    /// <param name="postureCachePathOverride">
    /// Test-only seam mirroring <see cref="PostureReader"/>'s own cachePath override
    /// (same reason it exists there): lets a unit test point ReadDeviceId() at a temp
    /// posture.json instead of the real PathConstants.PostureStatusFile, which on some
    /// hosts (e.g. macOS's SIP-protected /usr/share) a non-privileged process cannot
    /// write to at all. Production code never supplies this — DI resolves the
    /// constructor with no registered string service and falls back to the default.
    /// </param>
    public DeviceRemovalTasksClient(
        ILogger<DeviceRemovalTasksClient> log,
        IHttpClientFactory                httpFactory,
        CredentialStore                   creds,
        string?                           postureCachePathOverride = null)
    {
        _log                      = log;
        _httpFactory              = httpFactory;
        _creds                    = creds;
        _postureCachePathOverride = postureCachePathOverride;
    }

    /// <summary>
    /// The server-assigned device UUID from the cached posture (device.id), or null
    /// when posture has not been fetched yet or the cache is unreadable. Without it the
    /// device-scoped endpoints cannot be addressed, so the caller skips the run. Reuses
    /// the same last-known-good reader the tray/Self-Service surfaces use.
    /// </summary>
    public string? ReadDeviceId()
    {
        var id = new PostureReader(_postureCachePathOverride).Read().Posture?.Device.Id;
        return string.IsNullOrWhiteSpace(id) ? null : id;
    }

    public async Task<IReadOnlyList<DeviceRemovalTask>> FetchPendingAsync(string deviceId, CancellationToken ct)
    {
        try
        {
            var client = _httpFactory.CreateClient("patched");

            string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            string nonce     = Guid.NewGuid().ToString("N");
            string sig       = HmacSigner.ComputeSignature(_creds.HmacSecret, "GET", HmacSigner.EndpointDeviceRemovalTasksPending, timestamp, nonce, ReadOnlySpan<byte>.Empty);

            using var req = new HttpRequestMessage(
                HttpMethod.Get, $"/v1/devices/{deviceId}/removal-tasks/pending");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _creds.BearerToken);
            req.Headers.TryAddWithoutValidation(HmacSigner.SignatureHeader, sig);
            req.Headers.Add("X-Patched-Timestamp", timestamp);
            req.Headers.Add("X-Patched-Nonce", nonce);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
            if (resp.StatusCode != HttpStatusCode.OK)
            {
                _log.LogWarning("removal-tasks/pending returned HTTP {Code} — skipping run", (int)resp.StatusCode);
                return [];
            }

            byte[] body = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            var parsed = JsonSerializer.Deserialize<DeviceRemovalTasksResponse>(body, JsonOpts);
            return parsed?.Tasks ?? [];
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _log.LogWarning(ex, "removal-tasks/pending fetch failed — skipping run");
            return [];
        }
    }

    /// <summary>Reports task outcomes. Returns true on a 2xx acknowledgement.</summary>
    public async Task<bool> ReportAsync(
        string deviceId, IReadOnlyList<DeviceRemovalReport> reports, CancellationToken ct)
    {
        if (reports.Count == 0) return true;

        try
        {
            byte[] body = JsonSerializer.SerializeToUtf8Bytes(
                new DeviceRemovalReportRequest { Reports = reports });

            string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            string nonce     = Guid.NewGuid().ToString("N");
            string sig       = HmacSigner.ComputeSignature(_creds.HmacSecret, "POST", HmacSigner.EndpointDeviceRemovalTasksReport, timestamp, nonce, body);

            using var content = new ByteArrayContent(body);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var client = _httpFactory.CreateClient("patched");
            using var req = new HttpRequestMessage(
                HttpMethod.Post, $"/v1/devices/{deviceId}/removal-tasks/report") { Content = content };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _creds.BearerToken);
            req.Headers.TryAddWithoutValidation(HmacSigner.SignatureHeader, sig);
            req.Headers.Add("X-Patched-Timestamp", timestamp);
            req.Headers.Add("X-Patched-Nonce", nonce);

            using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                _log.LogWarning("removal-tasks/report returned HTTP {Code} — results will be re-reported next run",
                    (int)resp.StatusCode);
                return false;
            }
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _log.LogWarning(ex, "removal-tasks/report failed — results will be re-reported next run");
            return false;
        }
    }
}
