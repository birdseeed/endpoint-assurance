namespace Patched.Shared.Auth;

/// <summary>
/// PAT-1766: what the service reports while <see cref="CredentialStore.AwaitingProvisioning"/>.
/// Replaces PAT-1764's AgentIdentityMissingException: a device with no identity no
/// longer stops the service (which failed StartServices and rolled back the MSI
/// install or upgrade), it keeps running, reports this and polls. Platform-neutral
/// so tests on any host can check the wording. The message names no secret value.
/// </summary>
public static class AgentProvisioning
{
    /// <summary>
    /// The not-provisioned report, with how often the agent checks again. Tells the
    /// operator both ways to provision a device whose MSI is already installed: a
    /// token file the running agent picks up, or an uninstall and reinstall with a
    /// token (an install over an installed product does not write ENROLLMENT_TOKEN).
    /// </summary>
    public static string NotProvisionedMessage(TimeSpan recheckInterval) =>
        "This device has no Patched agent identity: no usable agent credentials and no enrollment token were " +
        "found in Credential Manager, the credential file store or the registry. The agent is running but collects " +
        "and sends nothing until the device is provisioned. It checks again every " + Describe(recheckInterval) +
        ", so no restart is needed. To provision it, save a fresh enrollment token as " +
        "%ProgramData%\\Patched\\creds\\enrollment-token, or uninstall the agent and install it again with a fresh " +
        "enrollment token. An upgrade that lost an unused enrollment token, or an uninstall that removed the " +
        "credentials and was then rolled back, leaves a device in this state.";

    /// <summary>Logged once when a token or usable credentials appear.</summary>
    public const string ProvisionedMessage =
        "Agent identity found: an enrollment token or usable agent credentials are now present. Resuming startup.";

    private static string Describe(TimeSpan interval) =>
        interval.TotalMinutes >= 1 && interval.TotalMinutes == Math.Floor(interval.TotalMinutes)
            ? (interval.TotalMinutes == 1 ? "minute" : FormattableString.Invariant($"{interval.TotalMinutes:0} minutes"))
            : FormattableString.Invariant($"{interval.TotalSeconds:0.###} seconds");
}
