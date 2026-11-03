using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Patched.Shared.Config;
using Xunit;

namespace Patched.Shared.Tests;

public class Ed25519VerifierTests
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
        byte[] message = Encoding.UTF8.GetBytes("the quick brown fox");
        byte[] sig = SignBytes(priv, message);

        Assert.True(Ed25519Verifier.Verify(pub.GetEncoded(), message, sig));
    }

    [Fact]
    public void Verify_CorruptedSignature_ReturnsFalseNotThrow()
    {
        var (priv, pub) = GenerateKeyPair();
        byte[] message = Encoding.UTF8.GetBytes("the quick brown fox");
        byte[] sig = SignBytes(priv, message);
        sig[0] ^= 0xFF; // flip a byte

        Assert.False(Ed25519Verifier.Verify(pub.GetEncoded(), message, sig));
    }

    [Fact]
    public void Verify_WrongKey_ReturnsFalse()
    {
        var (priv, _) = GenerateKeyPair();
        var (_, otherPub) = GenerateKeyPair();
        byte[] message = Encoding.UTF8.GetBytes("the quick brown fox");
        byte[] sig = SignBytes(priv, message);

        Assert.False(Ed25519Verifier.Verify(otherPub.GetEncoded(), message, sig));
    }

    [Fact]
    public void Verify_GarbageInputs_ReturnsFalseNotThrow()
    {
        // Wrong-length public key / signature must be rejected, not throw.
        Assert.False(Ed25519Verifier.Verify(new byte[5], new byte[] { 1, 2, 3 }, new byte[10]));
    }

    [Fact]
    public void Verify_ArbitraryBytes_RoundTrips()
    {
        // Simulate the new scheme: server signs arbitrary bytes; client verifies those
        // exact bytes without any reconstruction.
        var (priv, pub) = GenerateKeyPair();
        byte[] signedPayload = Encoding.UTF8.GetBytes(
            "{\"tier\":\"patch\",\"tenant_id\":\"t\",\"config_version\":3}");
        byte[] sig = SignBytes(priv, signedPayload);

        Assert.True(Ed25519Verifier.Verify(pub.GetEncoded(), signedPayload, sig));
    }

    [Fact]
    public void Verify_SpecialCharsInPayload_RoundTrips()
    {
        // HTML special chars and non-ASCII in the signed bytes — no re-encoding on
        // the client, so these verify correctly regardless of encoding.
        var (priv, pub) = GenerateKeyPair();
        byte[] signedPayload = Encoding.UTF8.GetBytes(
            "{\"pac_url\":\"http://a\\u0026b\\u003cc\\u003ed/\",\"host\":\"\\u30d7\\u30ed\\u30ad\\u30b7\"}");
        byte[] sig = SignBytes(priv, signedPayload);

        Assert.True(Ed25519Verifier.Verify(pub.GetEncoded(), signedPayload, sig));
    }
}
