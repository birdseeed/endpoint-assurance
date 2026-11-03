using System.Security.Cryptography;
using System.Text;

namespace Patched.Shared.Auth;

/// <summary>
/// Computes the HMAC-SHA256 request signature used for /v1/inventory, /v1/provenance,
/// and every other signed endpoint.
///
/// PAT-1154 v3 canonical form binds method + stable endpoint ID + timestamp + nonce + body
/// so a captured signed request cannot be replayed or moved between operations. Exact port of the v3 compute_hmac()/hmac_empty() helpers
/// in patched-update.sh, patched-upload.sh, and the rest of the macOS signers:
///   secret        = base64_decode(stored_key)
///   signing_input = "patched-hmac-v3\n" + method + "\n" + endpointId + "\n" + timestamp + "\n" + nonce + "\n" + body
///   sig           = hmac_sha256(secret, signing_input)
///   header        = "X-Patched-Signature: " + to_lower_hex(sig)
///
/// <paramref name="timestamp"/> and <paramref name="nonce"/> passed to
/// <see cref="ComputeSignature"/> MUST be the exact strings the caller also sends in the
/// X-Patched-Timestamp / X-Patched-Nonce headers for that same request — a mismatch here
/// breaks auth silently. Callers generate timestamp+nonce first, then use them both here
/// and in the headers.
/// </summary>
public static class HmacSigner
{
    public const string SignatureHeader = "X-Patched-Signature";

    public const string EndpointInventory = "inventory";
    public const string EndpointProvenance = "provenance";
    public const string EndpointAgentConfig = "agent_config";
    public const string EndpointAgentDecommissionStatus = "agent_decommission_status";
    public const string EndpointPendingRemovals = "pending_removals";
    public const string EndpointPendingInstalls = "pending_installs";
    public const string EndpointPosture = "posture";
    public const string EndpointAgentLogs = "agent_logs";
    public const string EndpointAgentArtifact = "agent_artifact";
    public const string EndpointAgentArtifactDownload = "agent_artifact_download";
    public const string EndpointEnforcementAudit = "enforcement_audit";
    public const string EndpointDeviceRemovalTasksPending = "device_removal_tasks_pending";
    public const string EndpointDeviceRemovalTasksReport = "device_removal_tasks_report";
    public const string EndpointEvents = "events";

    private static readonly byte[] DomainPrefix = Encoding.ASCII.GetBytes("patched-hmac-v3\n");

    /// <param name="base64Secret">The raw base64-encoded HMAC key from Credential Manager.</param>
    /// <param name="method">The uppercase HTTP method sent for this request.</param>
    /// <param name="endpointId">The stable server-owned endpoint identifier, never a URL.</param>
    /// <param name="timestamp">The exact string sent in the X-Patched-Timestamp header for this request.</param>
    /// <param name="nonce">The exact string sent in the X-Patched-Nonce header for this request.</param>
    /// <param name="body">The raw request body bytes (empty for GET routes).</param>
    /// <returns>Lowercase hex HMAC-SHA256 digest.</returns>
    public static string ComputeSignature(string base64Secret, string method, string endpointId, string timestamp, string nonce, ReadOnlySpan<byte> body)
    {
        var secret = Convert.FromBase64String(base64Secret);
        var message = BuildSigningInput(method, endpointId, timestamp, nonce, body);
        var digest = HMACSHA256.HashData(secret, message);
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    /// <summary>
    /// Verify a v3 signature. Constant-time compare guards against timing side-channels.
    /// Not currently called from request-sending code (the agent only signs outbound
    /// requests; the platform verifies them) — kept symmetric with ComputeSignature for
    /// any future caller and exercised directly by HmacSignerTests.
    /// </summary>
    public static bool VerifySignature(string base64Secret, string method, string endpointId, string timestamp, string nonce, ReadOnlySpan<byte> body, string expectedHex)
    {
        var computed = ComputeSignature(base64Secret, method, endpointId, timestamp, nonce, body);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(computed),
            Encoding.ASCII.GetBytes(expectedHex));
    }

    private static byte[] BuildSigningInput(string method, string endpointId, string timestamp, string nonce, ReadOnlySpan<byte> body)
    {
        var methodBytes = Encoding.ASCII.GetBytes(method);
        var endpointBytes = Encoding.ASCII.GetBytes(endpointId);
        var tsBytes    = Encoding.ASCII.GetBytes(timestamp);
        var nonceBytes = Encoding.ASCII.GetBytes(nonce);

        var message = new byte[DomainPrefix.Length + methodBytes.Length + 1 + endpointBytes.Length + 1 + tsBytes.Length + 1 + nonceBytes.Length + 1 + body.Length];
        int offset = 0;
        DomainPrefix.CopyTo(message.AsSpan(offset)); offset += DomainPrefix.Length;
		methodBytes.CopyTo(message.AsSpan(offset)); offset += methodBytes.Length;
		message[offset++] = (byte)'\n';
		endpointBytes.CopyTo(message.AsSpan(offset)); offset += endpointBytes.Length;
		message[offset++] = (byte)'\n';
        tsBytes.CopyTo(message.AsSpan(offset));       offset += tsBytes.Length;
        message[offset++] = (byte)'\n';
        nonceBytes.CopyTo(message.AsSpan(offset));    offset += nonceBytes.Length;
        message[offset++] = (byte)'\n';
        body.CopyTo(message.AsSpan(offset));

        return message;
    }
}
