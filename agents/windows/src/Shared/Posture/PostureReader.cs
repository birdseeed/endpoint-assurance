using System.Text.Json;
using Patched.Shared.Config;
using Patched.Shared.Paths;

namespace Patched.Shared.Posture;

/// <summary>
/// Reads the world-readable posture.json the Service caches (desktop chain U0).
/// The tray + Self Service hold NO credentials and never hit the network — they
/// only read this last-known-good cache. Offline is the normal case: if the file
/// is present it renders, however old; <see cref="PostureSnapshot.Age"/> /
/// <see cref="PostureSnapshot.IsStale"/> let the UI surface staleness honestly.
///
/// GET /v1/posture is signed the same way as /v1/agent-config (PAT-910 parity):
/// the wire response is an envelope ({signed_payload, key_id, signature}).
/// PAT-1285: PostureFetcher now verifies that envelope and caches only the
/// decoded, verified inner payload, matching the macOS writer
/// (patched-fetch-posture.sh + verify-posture.py verify before ever writing the
/// cache) — so the on-disk cache is normally already the plain payload, and this
/// reader takes the "not envelope, decode directly" branch below on every
/// freshly-written file. The envelope-detecting branch stays for backward
/// compatibility: it is what verifies and decodes any envelope-shaped cache file
/// still on disk from before PAT-1285 shipped, so an in-place upgrade never
/// treats a pre-existing, perfectly valid cache as corrupt.
/// (PAT-1273: before that fix this reader deserialized the raw envelope bytes
/// directly. System.Text.Json tolerates the unrecognised top-level fields and
/// every Posture property silently falls back to its default, so the result
/// looked exactly like an honest "no posture yet" record instead of an error.)
///
/// Mirrors the macOS PostureStore (menubar/PatchedUpdater/PostureStore.swift).
/// </summary>
public sealed class PostureReader
{
    /// <summary>Posture older than this is flagged stale (the Service fetches daily).</summary>
    public static readonly TimeSpan StaleThreshold = TimeSpan.FromHours(36);

    private readonly string _cachePath;
    private readonly Func<DateTimeOffset> _now;
    private readonly string _pinnedKeyId;
    private readonly byte[] _pinnedPublicKey;

    /// <param name="cachePath">Override the cache path (tests). Defaults to PathConstants.PostureStatusFile.</param>
    /// <param name="now">Override the clock (tests).</param>
    /// <param name="pinnedKeyId">
    /// Override the expected envelope key_id (tests only). Defaults to
    /// <see cref="Ed25519Verifier.PinnedKeyId"/>; production code never supplies
    /// this, so the real trust anchor is never reachable from a caller's environment.
    /// </param>
    /// <param name="pinnedPublicKeyBase64">
    /// Override the Ed25519 public key used to verify the envelope signature
    /// (tests only, paired with <paramref name="pinnedKeyId"/>: tests have no way
    /// to produce a signature the real pinned key accepts, so they inject a test
    /// keypair here the same way verify-posture.py's tests patch its module
    /// constants). Defaults to <see cref="Ed25519Verifier.PinnedPubKeyBase64"/>.
    /// </param>
    public PostureReader(
        string? cachePath = null,
        Func<DateTimeOffset>? now = null,
        string? pinnedKeyId = null,
        string? pinnedPublicKeyBase64 = null)
    {
        _cachePath       = cachePath ?? PathConstants.PostureStatusFile;
        _now             = now ?? (() => DateTimeOffset.UtcNow);
        _pinnedKeyId     = pinnedKeyId ?? Ed25519Verifier.PinnedKeyId;
        _pinnedPublicKey = Convert.FromBase64String(pinnedPublicKeyBase64 ?? Ed25519Verifier.PinnedPubKeyBase64);
    }

    /// <summary>
    /// Read last-known-good posture. Returns a snapshot whose Posture is null when
    /// there is no cache yet (first run, pre-daemon) or the cache is unreadable,
    /// undecodable, or fails signature verification. Every one of those failure
    /// shapes is reported via <see cref="PostureSnapshot.Error"/>, distinguishable
    /// from the honest "no cache yet" case where Error is also null but so is the
    /// file itself. Never throws.
    /// </summary>
    public PostureSnapshot Read()
    {
        byte[] bytes;
        try
        {
            if (!File.Exists(_cachePath))
                return PostureSnapshot.None;
            bytes = File.ReadAllBytes(_cachePath);
        }
        catch (Exception ex)
        {
            return PostureSnapshot.Failed($"Could not read posture cache: {ex.Message}");
        }

        var (posture, error) = DecodeCache(bytes);
        if (posture is null)
            return PostureSnapshot.Failed(error ?? "Posture cache is present but could not be parsed.");

        var age = _now() - posture.GeneratedAt;
        return new PostureSnapshot(posture, age < TimeSpan.Zero ? TimeSpan.Zero : age, null);
    }

    /// <summary>
    /// Decode the on-disk cache into a verified <see cref="Posture"/>. Detects the
    /// signed-envelope shape ({signed_payload, key_id, signature}) and, when
    /// present, verifies the Ed25519 signature and base64-decodes signed_payload
    /// before parsing the inner posture, so an envelope is never handed to
    /// <see cref="Posture.Deserialize(System.ReadOnlySpan{byte})"/> as if it were
    /// the payload. Falls back to decoding the bytes directly when the envelope
    /// fields are absent. Never throws.
    /// </summary>
    private (Posture? posture, string? error) DecodeCache(byte[] bytes)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(bytes);
        }
        catch (JsonException ex)
        {
            return (null, $"Posture cache is present but could not be parsed: {ex.Message}");
        }

        using (doc)
        {
            var root = doc.RootElement;
            bool isEnvelope = root.ValueKind == JsonValueKind.Object
                && root.TryGetProperty("signed_payload", out _)
                && root.TryGetProperty("key_id", out _)
                && root.TryGetProperty("signature", out _);

            if (!isEnvelope)
            {
                var direct = Posture.Deserialize(bytes);
                return direct is null
                    ? (null, "Posture cache is present but could not be parsed.")
                    : (direct, null);
            }

            string keyId = root.GetProperty("key_id").GetString() ?? "";
            if (keyId != _pinnedKeyId)
                return (null, $"Posture cache rejected: key_id mismatch (got '{keyId}', expected '{_pinnedKeyId}').");

            byte[] signedPayload;
            try
            {
                signedPayload = Convert.FromBase64String(root.GetProperty("signed_payload").GetString() ?? "");
            }
            catch (FormatException)
            {
                return (null, "Posture cache rejected: signed_payload is not valid base64.");
            }

            byte[] signature;
            try
            {
                signature = Convert.FromBase64String(root.GetProperty("signature").GetString() ?? "");
            }
            catch (FormatException)
            {
                return (null, "Posture cache rejected: signature is not valid base64.");
            }

            if (!Ed25519Verifier.Verify(_pinnedPublicKey, signedPayload, signature))
                return (null, "Posture cache rejected: Ed25519 signature is invalid.");

            var inner = Posture.Deserialize(signedPayload);
            return inner is null
                ? (null, "Posture cache envelope verified but signed_payload is not valid posture JSON.")
                : (inner, null);
        }
    }
}

/// <summary>
/// Result of a cache read: the posture (or null), its age, and any read error.
/// A null Posture with a null Error means "no cache yet" (honest first-run state).
/// </summary>
public sealed record PostureSnapshot(Posture? Posture, TimeSpan? Age, string? Error)
{
    public static readonly PostureSnapshot None = new(null, null, null);
    public static PostureSnapshot Failed(string message) => new(null, null, message);

    public bool HasPosture => Posture is not null;

    /// <summary>True when the cache exists but is older than the stale threshold.</summary>
    public bool IsStale => Age is { } a && a > PostureReader.StaleThreshold;
}
