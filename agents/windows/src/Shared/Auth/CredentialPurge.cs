namespace Patched.Shared.Auth;

/// <summary>Outcome of one purge step. <see cref="Error"/> never carries a credential value.</summary>
public readonly record struct CredentialPurgeStep(bool Succeeded, string? Error)
{
    public static CredentialPurgeStep Removed => new(true, null);
    public static CredentialPurgeStep Failed(string error) => new(false, error);
}

/// <summary>Result of <see cref="CredentialPurge.Run"/>: one failure line per step that did not complete.</summary>
public sealed record CredentialPurgeResult(IReadOnlyList<string> Failures)
{
    public bool Succeeded => Failures.Count == 0;
}

/// <summary>
/// PAT-1764: removes the agent's identity from the device on a full uninstall, so a
/// later install with a fresh ENROLLMENT_TOKEN enrols instead of silently carrying
/// on as the old device. Deletes every <see cref="CredentialStore.AgentCredentialTargets"/>
/// entry from Credential Manager, every <see cref="CredentialStore.AgentCredentialFileNames"/>
/// file from %ProgramData%\Patched\creds when that store passes the trust checks in
/// <see cref="CredentialFileStorePurge"/>, and the HKLM\SOFTWARE\Patched\Enrollment
/// provisioning key.
///
/// Runs only from the MSI's uninstall custom action (<c>Patched.Service.exe
/// --purge-credentials</c>), which Product.wxs conditions on a full uninstall that
/// is not part of a major upgrade: a self-update must never wipe the device's
/// identity.
///
/// The delete operations are injected so tests never touch the host's Credential
/// Manager or registry. Every step is attempted even when an earlier one fails.
/// </summary>
public sealed class CredentialPurge
{
    private readonly IReadOnlyList<string> _targets;
    private readonly Func<string, CredentialPurgeStep> _deleteCredential;
    private readonly CredentialFileStorePurge _fileStore;
    private readonly Func<CredentialPurgeStep> _deleteRegistryProvisioningKey;

    public CredentialPurge(
        IReadOnlyList<string> targets,
        Func<string, CredentialPurgeStep> deleteCredential,
        CredentialFileStorePurge fileStore,
        Func<CredentialPurgeStep> deleteRegistryProvisioningKey)
    {
        _targets = targets;
        _deleteCredential = deleteCredential;
        _fileStore = fileStore;
        _deleteRegistryProvisioningKey = deleteRegistryProvisioningKey;
    }

    public CredentialPurgeResult Run()
    {
        var failures = new List<string>();
        foreach (var target in _targets)
        {
            var step = Attempt(() => _deleteCredential(target));
            if (!step.Succeeded)
                failures.Add($"credential {target}: {step.Error}");
        }

        // The file store is a full credential source (CredentialStore.LoadForStartup
        // reads it before the registry), so a file-provisioned device must lose its
        // identity too, or a reinstall would keep it and discard the new token. It is
        // path-based and runs as SYSTEM, so it deletes nothing unless the store passes
        // the reparse-point and ownership checks (CredentialFileStorePurge).
        try { failures.AddRange(_fileStore.Run()); }
        catch (Exception) { failures.Add(CredentialFileStorePurge.UntrustedFailure); }

        var registry = Attempt(_deleteRegistryProvisioningKey);
        if (!registry.Succeeded)
            failures.Add($"registry key HKLM\\{ProvisioningRegistry.KeyPath}: {registry.Error}");

        return new CredentialPurgeResult(failures);
    }

    private static CredentialPurgeStep Attempt(Func<CredentialPurgeStep> step)
    {
        try { return step(); }
        catch (Exception ex) { return CredentialPurgeStep.Failed(ex.GetType().Name); }
    }
}
