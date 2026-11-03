using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Patched.Shared.Verification;

/// <summary>
/// PAT-1248: the dedicated Ed25519 trust anchor for signed Windows agent
/// self-update artifact metadata (version / platform / channel / artifact_url /
/// artifact_sha256), verified by <see cref="Patched.Service.BootstrapUpdater"/>.
///
/// This replaces the never-working <c>ARTIFACT_SIGNING_KEY</c> HMAC design:
/// that symmetric secret is deliberately absent from every endpoint (it also
/// signs the release MSI itself, verified out-of-band by human operators via
/// tools/verify-agent-release.py) — shipping it to every device would let one
/// compromised endpoint forge artifacts estate-wide. An Ed25519 key pair lets
/// endpoints verify with a public key that carries no forging power.
///
/// Deliberately its own distinct key/type — not
/// <c>Patched.Shared.Config.Ed25519Verifier</c> (the agent-config key) —
/// matching the PAT-516 key-separation model: an artifact-metadata key
/// compromise must not authorize an agent-config response, and no other key
/// may authorize a self-update artifact. verifier/sign-artifact-metadata.py
/// enforces the same separation on the signing side by rejecting the other
/// production key ids at runtime.
/// See docs/signing-key-architecture.md.
///
/// *** PRODUCTION KEY NOT YET PROVISIONED ***
/// <see cref="ProductionKeyId"/> / <see cref="ProductionPublicKeyBase64"/> are
/// placeholders — see their own doc comments and
/// <see cref="ProductionKeyIsProvisioned"/>. Generating the real
/// ARTIFACT_METADATA_SIGNING_KEY pair is Andy's (see
/// docs/signing-key-runbook.md); until then, this placeholder can never
/// validate any real signature, and <c>BootstrapUpdater</c> refuses to trust
/// anything and reports degraded health rather than silently accepting (or
/// silently never checking) artifacts.
/// </summary>
public sealed class ArtifactTrust
{
    /// <summary>
    /// The literal sentinel placeholder key id shipped until Andy provisions
    /// the real production key. Deliberately NOT a plausible 16-char hex
    /// value (unlike the real pin in <c>Ed25519Verifier</c>) so it can never be mistaken for a real key id
    /// and can never match a real signed envelope. Kept as its own constant
    /// (rather than comparing <see cref="ProductionKeyId"/> to itself) so
    /// <see cref="ProductionKeyIsProvisioned"/> keeps working correctly the
    /// day <see cref="ProductionKeyId"/> is finally replaced.
    /// </summary>
    internal const string UnprovisionedPlaceholderKeyId = "UNPROVISIONED-PAT-1248-ARTIFACT-KEY-REPLACE-BEFORE-SHIP";

    /// <summary>
    /// The production artifact-metadata signing key id, provisioned 2026-08-11
    /// under PAT-1255. Distinct from the catalogue key (734eba29d9f804a0) and
    /// the agent-config key (ecd47f2c5b3d5705) per the PAT-516 key-separation
    /// rule; the signing script rejects either of those at sign time.
    ///
    /// Equal to the first 16 hex characters of SHA-256 over
    /// <see cref="ProductionPublicKeyBase64"/>'s raw bytes, so the pair is
    /// self-consistent and a mismatched edit to one of the two is detectable.
    /// </summary>
    public const string ProductionKeyId = "1c6ffd04c60dd94d";

    /// <summary>
    /// PLACEHOLDER — 32 zero bytes, base64-encoded. Not a real Ed25519 public
    /// key: it is well-formed (right length, decodes cleanly) so the type
    /// still constructs and the process doesn't crash, but it can never
    /// verify a signature produced by a real Ed25519 private key. Replace
    /// with the real production public key alongside <see cref="ProductionKeyId"/>.
    /// </summary>
    public const string UnprovisionedPlaceholderPublicKeyBase64 =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // gitleaks:allow

    /// <summary>
    /// The production artifact-metadata signing PUBLIC key, provisioned
    /// 2026-08-11 under PAT-1255. Public material: safe to commit, safe to
    /// ship to every endpoint, and useless for forging anything. That is the
    /// whole reason PAT-1248 moved this channel off the symmetric
    /// ARTIFACT_SIGNING_KEY, which could not be distributed without letting
    /// any one endpoint forge artifacts for the estate.
    ///
    /// The private half lives only in the ARTIFACT_METADATA_SIGNING_KEY
    /// GitHub Actions secret on Patched-LTD/updater. It is deliberately absent
    /// from patched-api-01, so a compromised API still cannot forge an
    /// artifact it is also able to serve.
    /// </summary>
    public const string ProductionPublicKeyBase64 =
        "yYFmWA8rvRsalWAMP2B/JnIEQ5FX1cql+MK7LS+SOd0="; // gitleaks:allow

    /// <summary>
    /// False until <see cref="ProductionKeyId"/> is replaced with the real
    /// provisioned value. <c>BootstrapUpdater</c> checks this before trusting
    /// anything, so an unprovisioned key degrades loudly with an explicit
    /// "not provisioned" reason instead of surfacing as a generic signature
    /// failure indistinguishable from a real attack.
    ///
    /// PAT-1248: also checked by windows-agent-release.yml's "Assert self-update
    /// artifact trust key is provisioned" step, which greps this source file for
    /// <see cref="UnprovisionedPlaceholderKeyId"/> and hard-fails the release on
    /// the canonical repo if it is still present — the property below can only
    /// be exercised inside `dotnet test`, so the release gate is what actually
    /// stops a real ship with an unprovisioned key.
    /// </summary>
    public static bool ProductionKeyIsProvisioned =>
        IsProvisioned(ProductionKeyId, ProductionPublicKeyBase64);

    /// <summary>
    /// True only when BOTH the key id and the public key have been replaced.
    /// Factored out from <see cref="ProductionKeyIsProvisioned"/> so every branch
    /// is unit-testable without mutating the compile-time constants themselves
    /// (see ArtifactTrustTests.cs).
    ///
    /// Both halves are checked deliberately (review finding, 2026-08-11). Checking
    /// only the key id leaves a half-provisioned state that is worse than either
    /// clean state: replace <see cref="ProductionKeyId"/> but forget
    /// <see cref="ProductionPublicKeyBase64"/>, and this would report provisioned
    /// while the pinned key is still 32 zero bytes. The release gate would pass too,
    /// since it greps for the placeholder key id. Every update would then fail
    /// signature verification for a reason indistinguishable from tampering — the
    /// exact silent-failure shape PAT-1248 exists to remove.
    /// </summary>
    internal static bool IsProvisioned(string keyId, string publicKeyBase64) =>
        !string.Equals(keyId, UnprovisionedPlaceholderKeyId, StringComparison.Ordinal)
        && !string.Equals(publicKeyBase64, UnprovisionedPlaceholderPublicKeyBase64, StringComparison.Ordinal);

    public static ArtifactTrust Production { get; } = new(
        ProductionKeyId, Convert.FromBase64String(ProductionPublicKeyBase64));

    public ArtifactTrust(string keyId, byte[] publicKey)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            throw new ArgumentException("Artifact key id is required.", nameof(keyId));
        if (publicKey.Length != 32)
            throw new ArgumentException("An Ed25519 public key must be 32 bytes.", nameof(publicKey));

        KeyId = keyId;
        PublicKey = publicKey.ToArray();
    }

    public string KeyId { get; }
    public byte[] PublicKey { get; }

    /// <summary>
    /// True when THIS trust anchor carries real key material rather than the
    /// unprovisioned placeholders.
    ///
    /// PAT-1255: <c>BootstrapUpdater</c> gates on this instance property rather
    /// than on the static <see cref="ProductionKeyIsProvisioned"/> plus an
    /// identity check against <see cref="Production"/>. Two reasons. It is more
    /// correct — what matters is whether the anchor actually in use can verify
    /// anything, not which singleton it happens to be. And it stays testable:
    /// once the production constants hold real values, a guard written against
    /// the singleton can no longer be exercised at all, so the "never touch the
    /// network without usable trust material" property would have gone
    /// permanently unasserted the moment the key was provisioned.
    /// </summary>
    public bool IsKeyMaterialProvisioned =>
        IsProvisioned(KeyId, Convert.ToBase64String(PublicKey));

    public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (signature.Length != 64) return false;
        try
        {
            var signer = new Ed25519Signer();
            signer.Init(false, new Ed25519PublicKeyParameters(PublicKey, 0));
            var bytes = message.ToArray();
            signer.BlockUpdate(bytes, 0, bytes.Length);
            return signer.VerifySignature(signature.ToArray());
        }
        catch
        {
            return false;
        }
    }
}
