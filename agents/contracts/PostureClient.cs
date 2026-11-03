// PostureClient.cs — C# client for GET /v1/posture.
//
// Reads bearer + HMAC credentials from %PROGRAMDATA%\Patched\ (Windows)
// — the SAME credential store used by the Windows collector agent.
// No second credential path is introduced.
//
// HMAC signing matches the shell scripts and PostureClient.swift:
//   secret = Convert.FromBase64String(hmac-secret file)
//   sig    = HMAC-SHA256(secret, body: empty) → lowercase hex
//   headers: Authorization: Bearer <token>
//             X-Patched-Signature: <hex>
//             X-Patched-Timestamp: <unix-epoch>
//             X-Patched-Nonce: <uuid-hex>
//
// Offline / last-known-good:
//   On network failure, returns the cached posture if one exists.
//   Never throws when offline and a cache is present.
//   Cache: %LOCALAPPDATA%\Patched\posture.cache.json
//
// Platform-neutral: no WinForms / WPF references — pure .NET Standard types.
//
// PAT-471 · U0 · Posture read-client + vendored contract.

using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Patched.Contracts
{
    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    public sealed class PostureClientException : Exception
    {
        public PostureClientException(string message) : base(message) { }
        public PostureClientException(string message, Exception inner) : base(message, inner) { }
    }

    // -------------------------------------------------------------------------
    // PostureClient
    // -------------------------------------------------------------------------

    /// <summary>
    /// Fetches device posture from GET /v1/posture, with offline last-known-good caching.
    /// </summary>
    public sealed class PostureClient : IDisposable
    {
        // -------------------------------------------------------------------------
        // Configuration

        /// <summary>
        /// Directory containing bearer-token and hmac-secret files.
        /// Defaults to %PROGRAMDATA%\Patched — same path as the Windows collector.
        /// </summary>
        private readonly string _credsDir;

        /// <summary>Base URL for the Patched API (e.g. https://api.patched.im).</summary>
        private readonly string _apiBaseUrl;

        /// <summary>Full path for the last-known-good cache file.</summary>
        private readonly string _cacheFilePath;

        private readonly HttpClient _httpClient;
        private readonly bool _ownsHttpClient;

        private static readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        };

        // -------------------------------------------------------------------------
        // Init

        /// <param name="credsDir">
        ///   Override credential directory; defaults to %PROGRAMDATA%\Patched.
        /// </param>
        /// <param name="apiBaseUrl">
        ///   Override API base URL; defaults to https://api.patched.im.
        /// </param>
        /// <param name="cacheFilePath">
        ///   Override cache path; defaults to %LOCALAPPDATA%\Patched\posture.cache.json.
        /// </param>
        /// <param name="httpClient">
        ///   Inject an HttpClient for testing; if null a new one is created and owned.
        /// </param>
        public PostureClient(
            string? credsDir = null,
            string? apiBaseUrl = null,
            string? cacheFilePath = null,
            HttpClient? httpClient = null)
        {
            _credsDir = credsDir
                ?? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Patched");

            _apiBaseUrl = (apiBaseUrl ?? "https://api.patched.im").TrimEnd('/');

            _cacheFilePath = cacheFilePath
                ?? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Patched",
                    "posture.cache.json");

            if (httpClient is not null)
            {
                _httpClient = httpClient;
                _ownsHttpClient = false;
            }
            else
            {
                _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
                _ownsHttpClient = true;
            }
        }

        // -------------------------------------------------------------------------
        // Public API

        /// <summary>
        /// Fetch the device posture.
        ///
        /// On success: writes the response to the cache and returns the decoded Posture.
        /// On network failure: if a cache exists, returns the cached Posture; otherwise
        ///   throws PostureClientException.
        /// On non-200 HTTP: throws PostureClientException.
        /// </summary>
        public async Task<Posture> FetchAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var posture = await FetchFromNetworkAsync(cancellationToken).ConfigureAwait(false);
                PersistCache(posture);
                return posture;
            }
            catch (PostureClientException)
            {
                // Credential / server / decode errors — propagate immediately.
                throw;
            }
            catch (Exception ex) when (ex is HttpRequestException || ex is TaskCanceledException || ex is IOException)
            {
                // Network-layer failure — try last-known-good.
                var cached = LoadCache();
                if (cached is not null) return cached;
                throw new PostureClientException("Network unavailable and no cached posture found.", ex);
            }
        }

        // -------------------------------------------------------------------------
        // Network fetch (private)

        private async Task<Posture> FetchFromNetworkAsync(CancellationToken cancellationToken)
        {
            var bearerToken = ReadCredential("bearer-token");
            var hmacSecretB64 = ReadCredential("hmac-secret");

            byte[] secretBytes;
            try
            {
                secretBytes = Convert.FromBase64String(hmacSecretB64.Trim());
            }
            catch (FormatException ex)
            {
                throw new PostureClientException("hmac-secret is not valid base64.", ex);
            }

            var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var nonce = Guid.NewGuid().ToString("N"); // lowercase hex, no hyphens
            var sig = HmacHex(secretBytes, "GET", "posture", ts.ToString(), nonce, Array.Empty<byte>());

            var url = $"{_apiBaseUrl}/v1/posture";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
            request.Headers.Add("X-Patched-Signature", sig);
            request.Headers.Add("X-Patched-Timestamp", ts.ToString());
            request.Headers.Add("X-Patched-Nonce", nonce);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            HttpResponseMessage response;
            try
            {
                response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpRequestException || ex is TaskCanceledException)
            {
                throw; // let FetchAsync catch it for offline fallback
            }

            using (response)
            {
                if (!response.IsSuccessStatusCode)
                    throw new PostureClientException($"HTTP {(int)response.StatusCode} from /v1/posture.");

                var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(json))
                    throw new PostureClientException("Empty response body from /v1/posture.");

                try
                {
                    return JsonSerializer.Deserialize<Posture>(json, _jsonOptions)
                        ?? throw new PostureClientException("Deserialized posture was null.");
                }
                catch (JsonException ex)
                {
                    throw new PostureClientException("Failed to decode posture response.", ex);
                }
            }
        }

        // -------------------------------------------------------------------------
        // Cache (private)

        private Posture? LoadCache()
        {
            if (!File.Exists(_cacheFilePath)) return null;
            try
            {
                var json = File.ReadAllText(_cacheFilePath, Encoding.UTF8);
                return JsonSerializer.Deserialize<Posture>(json, _jsonOptions);
            }
            catch
            {
                return null;
            }
        }

        private void PersistCache(Posture posture)
        {
            try
            {
                var dir = Path.GetDirectoryName(_cacheFilePath)!;
                Directory.CreateDirectory(dir);
                var json = JsonSerializer.Serialize(posture, _jsonOptions);
                // Write to a temp file then move — atomic on NTFS.
                var tmp = _cacheFilePath + ".tmp";
                File.WriteAllText(tmp, json, Encoding.UTF8);
                File.Move(tmp, _cacheFilePath, overwrite: true);
            }
            catch
            {
                // Best-effort; never crash on cache write failure.
            }
        }

        // -------------------------------------------------------------------------
        // Credentials (private)

        /// <summary>
        /// Read a single-line credential file from _credsDir, stripping whitespace.
        /// Throws PostureClientException if the file is missing or empty.
        /// </summary>
        private string ReadCredential(string filename)
        {
            var path = Path.Combine(_credsDir, filename);
            if (!File.Exists(path))
                throw new PostureClientException($"Credential file missing: {path}");

            var lines = File.ReadAllLines(path, Encoding.UTF8);
            var value = lines.Length > 0 ? lines[0].Trim() : string.Empty;
            if (string.IsNullOrEmpty(value))
                throw new PostureClientException($"Credential file is empty: {path}");

            return value;
        }

        // -------------------------------------------------------------------------
        // HMAC-SHA256 (private)
        //
        // Mirrors the shell script and PostureClient.swift logic:
        //   sig = HMAC-SHA256(secret, body) as lowercase hex
        //
        // GET /v1/posture has an empty body — callers pass Array.Empty<byte>().

        private static string HmacHex(byte[] secret, string method, string endpointId, string timestamp, string nonce, byte[] body)
        {
            using var hmac = new HMACSHA256(secret);
            var prefix = Encoding.ASCII.GetBytes($"patched-hmac-v3\n{method}\n{endpointId}\n{timestamp}\n{nonce}\n");
            var input = new byte[prefix.Length + body.Length];
            Buffer.BlockCopy(prefix, 0, input, 0, prefix.Length);
            Buffer.BlockCopy(body, 0, input, prefix.Length, body.Length);
            var hash = hmac.ComputeHash(input);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        // -------------------------------------------------------------------------
        // IDisposable

        public void Dispose()
        {
            if (_ownsHttpClient) _httpClient.Dispose();
        }
    }
}
