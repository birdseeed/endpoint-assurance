namespace Patched.Shared.Config;

/// <summary>
/// Ed25519 signature verification for the on-disk windows-allowlist.json (PAT-511).
/// Uses the same pinned key as agent-config so both chains share a trust anchor.
/// </summary>
public static class AllowlistSignatureVerifier
{
    public static bool Verify(byte[] content, byte[] signature)
    {
        byte[] key = Convert.FromBase64String(Ed25519Verifier.PinnedPubKeyBase64);
        return Ed25519Verifier.Verify(key, content, signature);
    }
}
