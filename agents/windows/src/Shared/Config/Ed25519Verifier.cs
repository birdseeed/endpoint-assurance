using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Patched.Shared.Config;

/// <summary>
/// Ed25519 signature verification for agent-config responses.
/// Pinned public key: ecd47f2c5b3d5705 (rotate by updating both constants + shipping new agent).
/// </summary>
internal static class Ed25519Verifier
{
    // Pinned Ed25519 public key (32 bytes, base64-encoded).
    // Safe to commit — only the private seed on the server can sign.
    // Rotate: update server AGENT_CONFIG_SIGNING_KEY, then update these constants in the next release.
    internal const string PinnedPubKeyBase64 = "a3voEh/OojvVNeRUrP6iE68bqFAfEUPFUDth77oevV0="; // gitleaks:allow
    internal const string PinnedKeyId        = "ecd47f2c5b3d5705";

    // Shared by network acceptance and the evidence helper's protected envelope cache.
    // The signature always covers the original decoded bytes, never reconstructed JSON.
    internal static bool TryVerifyEnvelope(byte[] envelope, out byte[] payload)
    {
        payload = [];
        try
        {
            using var document = JsonDocument.Parse(envelope);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Select(p => p.Name)
                    .Distinct(StringComparer.OrdinalIgnoreCase).Count() != root.EnumerateObject().Count() ||
                root.GetProperty("key_id").GetString() != PinnedKeyId)
                return false;
            var bytes = Convert.FromBase64String(root.GetProperty("signed_payload").GetString()!);
            var signature = Convert.FromBase64String(root.GetProperty("signature").GetString()!);
            if (!Verify(Convert.FromBase64String(PinnedPubKeyBase64), bytes, signature)) return false;
            payload = bytes;
            return true;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Verify an Ed25519 signature.
    /// Returns false (does NOT throw) on any error.
    /// </summary>
    public static bool Verify(byte[] publicKeyBytes, byte[] message, byte[] signature)
    {
        try
        {
            var pubKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
            var signer = new Ed25519Signer();
            signer.Init(forSigning: false, parameters: pubKey);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.VerifySignature(signature);
        }
        catch
        {
            return false;
        }
    }
}
