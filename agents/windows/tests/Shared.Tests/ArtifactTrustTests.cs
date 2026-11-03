using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Patched.Shared.Verification;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>PAT-1248 coverage for the artifact-metadata Ed25519 trust anchor.</summary>
public class ArtifactTrustTests
{
    private static (Ed25519PrivateKeyParameters priv, Ed25519PublicKeyParameters pub) GenerateKeyPair()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.GenerateKeyPair();
        return ((Ed25519PrivateKeyParameters)kp.Private, (Ed25519PublicKeyParameters)kp.Public);
    }

    private static byte[] SignBytes(Ed25519PrivateKeyParameters priv, byte[] message)
    {
        var signer = new Ed25519Signer();
        signer.Init(forSigning: true, priv);
        signer.BlockUpdate(message, 0, message.Length);
        return signer.GenerateSignature();
    }

    [Fact]
    public void Verify_KnownValidSignature_ReturnsTrue()
    {
        var (priv, pub) = GenerateKeyPair();
        var trust = new ArtifactTrust("test-artifact-key", pub.GetEncoded());
        byte[] message = Encoding.UTF8.GetBytes(
            """{"version":"0.13.16","platform":"windows","channel":"stable","artifact_url":"https://api.patched.im/x.msi","artifact_sha256":"aa"}""");
        byte[] sig = SignBytes(priv, message);

        Assert.True(trust.Verify(message, sig));
    }

    [Fact]
    public void Verify_CorruptedSignature_ReturnsFalseNotThrow()
    {
        var (priv, pub) = GenerateKeyPair();
        var trust = new ArtifactTrust("test-artifact-key", pub.GetEncoded());
        byte[] message = Encoding.UTF8.GetBytes("artifact metadata");
        byte[] sig = SignBytes(priv, message);
        sig[0] ^= 0xFF;

        Assert.False(trust.Verify(message, sig));
    }

    [Fact]
    public void Verify_WrongKey_ReturnsFalse()
    {
        var (priv, _) = GenerateKeyPair();
        var (_, otherPub) = GenerateKeyPair();
        var trust = new ArtifactTrust("test-artifact-key", otherPub.GetEncoded());
        byte[] message = Encoding.UTF8.GetBytes("artifact metadata");
        byte[] sig = SignBytes(priv, message);

        Assert.False(trust.Verify(message, sig));
    }

    [Fact]
    public void Verify_GarbageSignatureLength_ReturnsFalseNotThrow()
    {
        var (_, pub) = GenerateKeyPair();
        var trust = new ArtifactTrust("test-artifact-key", pub.GetEncoded());
        Assert.False(trust.Verify(new byte[] { 1, 2, 3 }, new byte[10]));
    }

    [Fact]
    public void Constructor_RejectsEmptyKeyIdOrWrongLengthPublicKey()
    {
        Assert.Throws<ArgumentException>(() => new ArtifactTrust("", new byte[32]));
        Assert.Throws<ArgumentException>(() => new ArtifactTrust("k", new byte[31]));
    }

    [Fact]
    public void ProductionPin_IsDedicatedAndNotTheOtherTwoKeys()
    {
        // PAT-516 key separation, extended to the third purpose: the artifact-metadata
        // key must never collide with the catalogue key or the agent-config key.
        Assert.NotEqual("734eba29d9f804a0", ArtifactTrust.ProductionKeyId); // catalogue key id
        Assert.NotEqual("ecd47f2c5b3d5705", ArtifactTrust.ProductionKeyId); // agent-config key id
    }

    [Fact]
    public void ProductionPublicKey_IsWellFormedBase64OfThirtyTwoBytes()
    {
        // The placeholder must decode cleanly (so the static Production instance can
        // construct without crashing the process) even though it is not a real key.
        byte[] decoded = Convert.FromBase64String(ArtifactTrust.ProductionPublicKeyBase64);
        Assert.Equal(32, decoded.Length);
    }

    [Fact]
    public void Production_NeverVerifiesAnyRealSignature_WhileUnprovisioned()
    {
        // The placeholder public key (32 zero bytes) can never validate a signature
        // produced by a real Ed25519 private key — this is what makes it safe to ship
        // an inert placeholder rather than crash: it fails closed, not open.
        var (priv, _) = GenerateKeyPair();
        byte[] message = Encoding.UTF8.GetBytes("anything at all");
        byte[] sig = SignBytes(priv, message);

        Assert.False(ArtifactTrust.Production.Verify(message, sig));
    }

    // -------------------------------------------------------------------------
    // PAT-1248 review correction: a unit test that is *expected* to fail until
    // Andy provisions the real key is noise with a comment attached, not a
    // guard — it trains reviewers to ignore red, and a PR cannot even open on
    // a red suite. The unit-testable guarantee is that BOTH states (still the
    // placeholder / has been replaced) are handled coherently, which is what
    // the two tests below prove. The actual "must not ship unprovisioned"
    // guarantee now lives at the only moment it can bite: the release, via
    // windows-agent-release.yml's "Assert self-update artifact trust key is
    // provisioned" step, which greps this file for the literal placeholder
    // marker and hard-fails the canonical repo's release if it is still
    // present. See BootstrapUpdaterTests for proof that the unprovisioned
    // state itself degrades safely (no network call, nothing staged) rather
    // than crashing or silently accepting.
    // -------------------------------------------------------------------------

    // A real-shaped Ed25519 public key (32 non-zero bytes, base64) standing in
    // for a provisioned value. Never used to verify anything here; these tests
    // only exercise the provisioned/unprovisioned predicate.
    private const string RealShapedPublicKey = "MdZjJUY8YEIV1hEg64ALirZtL4fn1EkaVjOFhjX7RSM="; // gitleaks:allow

    [Fact]
    public void IsProvisioned_PlaceholderKeyId_ReturnsFalse()
    {
        Assert.False(ArtifactTrust.IsProvisioned(
            ArtifactTrust.UnprovisionedPlaceholderKeyId, RealShapedPublicKey));
    }

    [Fact]
    public void IsProvisioned_PlaceholderPublicKey_ReturnsFalse()
    {
        // The half-provisioned state a review round caught (2026-08-11): the key
        // id was replaced but the public key was left as the placeholder. Checking
        // only the id would report provisioned while the pinned key is 32 zero
        // bytes, and every update would then fail verification for a reason
        // indistinguishable from tampering.
        Assert.False(ArtifactTrust.IsProvisioned(
            "734eba29d9f804a0", ArtifactTrust.UnprovisionedPlaceholderPublicKeyBase64));
    }

    [Fact]
    public void IsProvisioned_BothReplaced_ReturnsTrue()
    {
        // Simulates the post-provisioning state without mutating the
        // compile-time constants: both halves replaced counts as provisioned.
        Assert.True(ArtifactTrust.IsProvisioned("734eba29d9f804a0", RealShapedPublicKey));
        Assert.True(ArtifactTrust.IsProvisioned("some-future-real-artifact-key-id", RealShapedPublicKey));
    }

    [Fact]
    public void Production_KeyIdIsDerivedFromProductionPublicKey()
    {
        // PAT-1255: the key id is the first 16 hex chars of SHA-256 over the
        // public key's raw bytes, which is how generate-signing-key.py derives
        // it. Asserting the relationship catches the half-edit that
        // IsProvisioned cannot: replacing both constants but pasting a key id
        // and a public key from two DIFFERENT generated pairs. That would look
        // provisioned, pass the release gate, and then fail every signature
        // check in the estate for a reason indistinguishable from tampering.
        var pub = Convert.FromBase64String(ArtifactTrust.ProductionPublicKeyBase64);
        var expected = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(pub))
            .ToLowerInvariant()[..16];

        Assert.Equal(expected, ArtifactTrust.ProductionKeyId);
    }

    [Fact]
    public void Production_KeyIdDoesNotCollideWithTheOtherSigningPurposes()
    {
        // PAT-516 key separation: catalogue and agent-config must each keep
        // their own key. The signing script rejects these ids at sign time;
        // this catches a bad pin at build time instead.
        Assert.NotEqual("734eba29d9f804a0", ArtifactTrust.ProductionKeyId);
        Assert.NotEqual("ecd47f2c5b3d5705", ArtifactTrust.ProductionKeyId);
    }

    [Fact]
    public void ProductionKeyIsProvisioned_IsCoherentWithProductionKeyId()
    {
        // Ties the static property to the same IsProvisioned logic proven
        // above, so this test passes whether ProductionKeyId is currently the
        // placeholder (today) or has been replaced with a real value (after
        // Andy provisions it) — it asserts the relationship, not a fixed
        // outcome, so it never needs to go red for the placeholder to be
        // caught (that is the release gate's job).
        Assert.Equal(
            ArtifactTrust.IsProvisioned(ArtifactTrust.ProductionKeyId, ArtifactTrust.ProductionPublicKeyBase64),
            ArtifactTrust.ProductionKeyIsProvisioned);
    }
}
