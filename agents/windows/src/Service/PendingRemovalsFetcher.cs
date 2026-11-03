using System.Net;
// DEPRECATED — PAT-1531: legacy removal source retained for reference only;
// excluded from the Windows assurance-only Service build.
using System.Net.Http.Headers;
using System.Text.Json;
using Patched.Shared.Auth;
using Patched.Shared.Removal;

namespace Patched.Service;

/// <summary>
/// Fetches the tenant's pending-removal queue from GET /v1/allowlist/pending-removals
/// (PAT-376 #83). Same auth chain as the macOS engine: Bearer + HMAC over the empty
/// GET body + X-Patched-Timestamp + X-Patched-Nonce. The 24 h hold is server-side;
/// the agent simply processes whatever is returned.
///
/// Fail-safe: any error returns an empty list so the run is a no-op and retries next
/// cycle — never throws into the worker.
/// </summary>
public sealed class PendingRemovalsFetcher
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    private readonly ILogger<PendingRemovalsFetcher> _log;
    private readonly IHttpClientFactory              _httpFactory;
    private readonly CredentialStore                 _creds;

    public PendingRemovalsFetcher(
        ILogger<PendingRemovalsFetcher> log,
        IHttpClientFactory              httpFactory,
        CredentialStore                 creds)
    {
        _log         = log;
        _httpFactory = httpFactory;
        _creds       = creds;
    }

    public async Task<IReadOnlyList<PendingRemoval>> FetchAsync(CancellationToken ct)
    {
        try
        {
            var client = _httpFactory.CreateClient("patched");

            string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            string nonce     = Guid.NewGuid().ToString("N");
            string sig       = HmacSigner.ComputeSignature(_creds.HmacSecret, "GET", HmacSigner.EndpointPendingRemovals, timestamp, nonce, ReadOnlySpan<byte>.Empty);

            using var req = new HttpRequestMessage(HttpMethod.Get, "/v1/allowlist/pending-removals");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _creds.BearerToken);
            req.Headers.TryAddWithoutValidation(HmacSigner.SignatureHeader, sig);
            req.Headers.Add("X-Patched-Timestamp", timestamp);
            req.Headers.Add("X-Patched-Nonce", nonce);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
            if (resp.StatusCode != HttpStatusCode.OK)
            {
                _log.LogWarning("pending-removals fetch returned HTTP {Code} — skipping run", (int)resp.StatusCode);
                return [];
            }

            byte[] body = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            var parsed = JsonSerializer.Deserialize<PendingRemovalsResponse>(body, JsonOpts);
            return parsed?.Items ?? [];
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _log.LogWarning(ex, "pending-removals fetch failed — skipping run");
            return [];
        }
    }
}
