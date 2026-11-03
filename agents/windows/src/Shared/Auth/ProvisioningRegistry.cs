namespace Patched.Shared.Auth;

/// <summary>
/// PAT-1764: the installer's registry provisioning key path, relative to HKLM, in a
/// platform-neutral type so messages built outside the Windows-only
/// <see cref="CredentialStore"/> can name it. <see cref="CredentialStore.RegistryProvisioningKey"/>
/// is defined from this constant.
/// </summary>
public static class ProvisioningRegistry
{
    public const string KeyPath = @"SOFTWARE\Patched\Enrollment";
}
