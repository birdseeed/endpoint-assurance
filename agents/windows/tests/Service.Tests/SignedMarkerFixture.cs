using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Patched.Shared.Verification;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2396: PendingUpdateApplier applies a marker only when it carries a signed
/// artifact-metadata envelope that verifies and names the marker's own version and
/// SHA-256. The applier suites that predate that write markers by hand, so they sign
/// them here with a throwaway Ed25519 key and hand the applier the matching
/// <see cref="Trust"/>. Nothing is switched off: an unsigned or mis-signed marker is
/// still refused under this key, which PendingUpdateEnvelopeTrustTests covers.
/// </summary>
internal static class SignedMarkerFixture
{
    private static readonly Ed25519PrivateKeyParameters PrivateKey = new(new SecureRandom());

    internal static ArtifactTrust Trust { get; } =
        new("test-marker-key", PrivateKey.GeneratePublicKey().GetEncoded());

    internal static byte[] Payload(string version, string sha256, string platform = "windows", string channel = "stable") =>
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            version,
            platform,
            channel,
            artifact_url = "https://api.patched.im/v1/agent/artifact-download/x.msi",
            artifact_sha256 = sha256,
        }));

    internal static byte[] Sign(byte[] payload) => Sign(payload, PrivateKey);

    internal static byte[] Sign(byte[] payload, Ed25519PrivateKeyParameters key)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, key);
        signer.BlockUpdate(payload, 0, payload.Length);
        return signer.GenerateSignature();
    }

    /// <summary>Adds the envelope BootstrapUpdater would have written for a release
    /// with this version and SHA-256, signed with <see cref="Trust"/>'s key.</summary>
    internal static void AddEnvelope(JsonObject marker, string version, string sha256) =>
        AddEnvelope(marker, Payload(version, sha256));

    internal static void AddEnvelope(JsonObject marker, byte[] payload, byte[]? signature = null, string? keyId = null)
    {
        marker["signed_payload"] = Convert.ToBase64String(payload);
        marker["signature"]      = Convert.ToBase64String(signature ?? Sign(payload));
        marker["key_id"]         = keyId ?? Trust.KeyId;
    }
}
