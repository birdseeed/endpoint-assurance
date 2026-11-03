using System.Net;
// DEPRECATED — PAT-1531: legacy installer source retained for reference only;
// excluded from the Windows assurance-only Service build.
using System.Net.Http.Headers;
using System.Text.Json;
using Patched.Shared.Auth;
using Patched.Shared.Installation;

namespace Patched.Service;

/// <summary>
/// Fetches the tenant's pending-install queue from GET /v1/allowlist/pending-installs
/// (PAT-661 / PAT-659). Same auth chain as PendingRemovalsFetcher: Bearer + HMAC over
/// the empty GET body + X-Patched-Timestamp + X-Patched-Nonce.
///
/// Fail-safe: any error returns an empty list so the run is a no-op and retries next
/// cycle — never throws into the worker.
/// </summary>
public class PendingInstallsFetcher
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    private readonly ILogger<PendingInstallsFetcher> _log;
    private readonly IHttpClientFactory              _httpFactory;
    private readonly CredentialStore                 _creds;

    public PendingInstallsFetcher(
        ILogger<PendingInstallsFetcher> log,
        IHttpClientFactory              httpFactory,
        CredentialStore                 creds)
    {
        _log         = log;
        _httpFactory = httpFactory;
        _creds       = creds;
    }

    public virtual async Task<IReadOnlyList<PendingInstall>> FetchAsync(CancellationToken ct)
    {
        try
        {
            var client = _httpFactory.CreateClient("patched");

            string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            string nonce     = Guid.NewGuid().ToString("N");
            string sig       = HmacSigner.ComputeSignature(_creds.HmacSecret, "GET", HmacSigner.EndpointPendingInstalls, timestamp, nonce, ReadOnlySpan<byte>.Empty);

            using var req = new HttpRequestMessage(HttpMethod.Get, "/v1/allowlist/pending-installs");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _creds.BearerToken);
            req.Headers.TryAddWithoutValidation(HmacSigner.SignatureHeader, sig);
            req.Headers.Add("X-Patched-Timestamp", timestamp);
            req.Headers.Add("X-Patched-Nonce", nonce);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
            if (resp.StatusCode != HttpStatusCode.OK)
            {
                _log.LogWarning("pending-installs fetch returned HTTP {Code} — skipping run", (int)resp.StatusCode);
                return [];
            }

            byte[] body = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            var parsed = JsonSerializer.Deserialize<PendingInstallsResponse>(body, JsonOpts);
            return parsed?.Installs ?? [];
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _log.LogWarning(ex, "pending-installs fetch failed — skipping run");
            return [];
        }
    }
}
