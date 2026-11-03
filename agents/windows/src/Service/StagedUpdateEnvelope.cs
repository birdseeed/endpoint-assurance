using System.Text.Json;
using Patched.Shared.Config;
using Patched.Shared.Verification;

namespace Patched.Service;

/// <summary>
/// PAT-2396: the signed artifact-metadata envelope as it is carried in the
/// pending-update marker, and the one routine that re-verifies it.
///
/// <see cref="BootstrapUpdater"/> verifies this envelope when it fetches it, then stages
/// an installer and writes a marker. <see cref="PendingUpdateApplier"/> executes that
/// installer as LocalSystem on a LATER service start, from files on disk. Until this
/// existed the marker carried only values derived from the envelope (version, path,
/// SHA-256), so every check the applier made was answerable by whoever wrote the marker:
/// a marker and installer planted under a state root that was writable before
/// StateDirectoryBootstrap repaired it were applied exactly like a staged update.
///
/// The marker now carries the envelope itself (<see cref="PayloadField"/>,
/// <see cref="SignatureField"/>, <see cref="KeyIdField"/>, verbatim from the server
/// response), and both the applier and BootstrapUpdater's "already staged" check verify
/// it against the pinned <see cref="ArtifactTrust"/> key before trusting anything else in
/// the marker. The signature is the trust anchor; the directory the files sit in is not.
///
/// PAT-2400: the applier also binds the envelope's signed channel to the device's
/// verified channel policy when one is available at apply time (see
/// <see cref="ChannelPermitted"/>), and checks ownership and DACLs of the staged files
/// separately (<see cref="IStagedUpdateTrustVerifier"/>). With no verified policy, a
/// validly signed envelope for a real, newer Patched release on any channel is still
/// accepted.
/// </summary>
internal static class StagedUpdateEnvelope
{
    internal const string PayloadField   = "signed_payload";
    internal const string SignatureField = "signature";
    internal const string KeyIdField     = "key_id";

    /// <summary>The signed fields the apply path binds the marker and installer to.</summary>
    internal readonly record struct Metadata(string Version, string Platform, string ArtifactSha256, string Channel);

    /// <summary>
    /// Verifies the envelope with <paramref name="trust"/> and returns the signed
    /// metadata. Fails closed with a short reason token on any missing field, key-id
    /// mismatch, undecodable value, bad signature or unreadable payload. Never throws.
    /// </summary>
    internal static bool TryVerify(
        ArtifactTrust trust,
        string?       keyId,
        string?       signedPayloadBase64,
        string?       signatureBase64,
        out Metadata  metadata,
        out string    reason)
    {
        metadata = default;

        if (string.IsNullOrEmpty(keyId) || string.IsNullOrEmpty(signedPayloadBase64) || string.IsNullOrEmpty(signatureBase64))
        {
            reason = "envelope_absent";
            return false;
        }

        // Same refusal BootstrapUpdater makes before it will stage anything: the shipped
        // placeholder key verifies nothing, so nothing can have been staged under it.
        if (!trust.IsKeyMaterialProvisioned)
        {
            reason = "envelope_trust_not_provisioned";
            return false;
        }

        if (!string.Equals(keyId, trust.KeyId, StringComparison.Ordinal))
        {
            reason = "envelope_key_id_mismatch";
            return false;
        }

        byte[] payload, signature;
        try
        {
            payload   = Convert.FromBase64String(signedPayloadBase64);
            signature = Convert.FromBase64String(signatureBase64);
        }
        catch (FormatException)
        {
            reason = "envelope_not_base64";
            return false;
        }

        if (!trust.Verify(payload, signature))
        {
            reason = "envelope_signature_invalid";
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(payload);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                reason = "envelope_metadata_invalid";
                return false;
            }

            metadata = new Metadata(
                GetString(root, "version"), GetString(root, "platform"), GetString(root, "artifact_sha256"),
                GetString(root, "channel"));
        }
        catch (JsonException)
        {
            reason = "envelope_metadata_invalid";
            return false;
        }

        if (string.IsNullOrEmpty(metadata.Version) || string.IsNullOrEmpty(metadata.ArtifactSha256))
        {
            reason = "envelope_metadata_invalid";
            return false;
        }

        reason = "";
        return true;
    }

    /// <summary>
    /// Whether verified <paramref name="metadata"/> describes exactly this staged
    /// update: a Windows artifact, this version (ordinal, since BootstrapUpdater names
    /// the stage directory and the marker from the signed value verbatim), this SHA-256.
    /// </summary>
    internal static bool Matches(Metadata metadata, string version, string sha256, out string reason)
    {
        if (!string.Equals(metadata.Platform, "windows", StringComparison.OrdinalIgnoreCase))
        {
            reason = "envelope_platform_mismatch";
            return false;
        }
        if (!string.Equals(metadata.Version, version, StringComparison.Ordinal))
        {
            reason = "envelope_version_mismatch";
            return false;
        }
        if (!string.Equals(metadata.ArtifactSha256, sha256, StringComparison.OrdinalIgnoreCase))
        {
            reason = "envelope_hash_mismatch";
            return false;
        }

        reason = "";
        return true;
    }

    /// <summary>
    /// PAT-2400: whether verified <paramref name="metadata"/> may be applied under
    /// <paramref name="policy"/>. Only a policy with authority (PAT-2351: resolved from
    /// the verified agent-config) binds; then the signed channel must be that policy's
    /// channel, as BootstrapUpdater required when it requested the artifact. The
    /// reporting default has no authority and binds nothing, so without verified policy
    /// this permits what PAT-2396 permitted.
    /// </summary>
    internal static bool ChannelPermitted(Metadata metadata, UpdateChannelPolicy? policy, out string reason)
    {
        if (policy is { HasAuthority: true } &&
            !string.Equals(metadata.Channel, policy.Channel, StringComparison.OrdinalIgnoreCase))
        {
            reason = "envelope_channel_mismatch";
            return false;
        }

        reason = "";
        return true;
    }

    private static string GetString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? ""
            : "";
}
