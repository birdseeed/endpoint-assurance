namespace Patched.Shared.Certificates;

/// <summary>
/// PAT-1738: the LocalMachine store names a certificate row was enumerated from.
/// Windows sends one of these three (<see cref="CertCollectionLogic"/> reads all
/// three and tags each row through <see cref="CertInventoryMapper.FromX509"/>); macOS
/// sends the fixed value "System" (its only read keychain, macos/lib/certs.sh).
/// Classifying which of these are platform roots is server-side work.
/// </summary>
internal static class CertStoreNames
{
    /// <summary>The machine's personal store: device, VPN, 802.1X, MDM and internally issued certificates.</summary>
    public const string My = "My";

    /// <summary>The trusted root certification authorities store.</summary>
    public const string Root = "Root";

    /// <summary>The intermediate certification authorities store.</summary>
    public const string CA = "CA";
}
