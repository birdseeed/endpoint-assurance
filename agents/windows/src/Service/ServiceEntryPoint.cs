using System.Diagnostics;
using System.Runtime.Versioning;
using Patched.Shared.Auth;

namespace Patched.Service;

/// <summary>
/// PAT-1764: decides, before anything else in Program.cs runs, whether this process
/// is the Windows service or a one-shot installer command. Each command must never
/// start the host: no state-directory bootstrap, no logging providers, no hosted
/// services, no network.
///
/// The commands are:
///   <see cref="PurgeCredentialsFlag"/>      run by the MSI's uninstall custom action.
///   <see cref="WriteEnrollmentTokenFlag"/>  run by the MSI's install custom action
///                                           (PAT-1755), taking the token as the next
///                                           argument.
/// </summary>
public static class ServiceEntryPoint
{
    public const string PurgeCredentialsFlag = "--purge-credentials";

    /// <summary>
    /// PAT-1755: provisions the installer-supplied enrolment token into the credential
    /// file store. The token is the argument immediately after this flag, passed on the
    /// custom action's command line so it never appears in a verbose MSI log (only
    /// HideTarget on a custom action suppresses the execute-script op's data; a
    /// property's Hidden flag does not).
    /// </summary>
    public const string WriteEnrollmentTokenFlag = "--write-enrollment-token";

    /// <param name="writeEnrollmentToken">
    /// Receives the argument after the flag, or null when the flag was last on the
    /// command line and carried no value. A null reaches the command as "no token
    /// supplied", which fails rather than silently succeeding.
    /// </param>
    public static int Run(
        string[] args,
        Func<int> purgeCredentials,
        Func<string?, int> writeEnrollmentToken,
        Func<int> runServiceHost)
    {
        // Purge first: an uninstall must never be diverted into provisioning.
        if (args.Contains(PurgeCredentialsFlag, StringComparer.Ordinal))
            return purgeCredentials();

        var flagAt = Array.IndexOf(args, WriteEnrollmentTokenFlag);
        if (flagAt >= 0)
            return writeEnrollmentToken(flagAt + 1 < args.Length ? args[flagAt + 1] : null);

        return runServiceHost();
    }
}

/// <summary>
/// PAT-1764: writes an installer-command report to the console (which the MSI log
/// records) and to the Application event log under the service's own source. Reporting
/// must never change a command's exit code, so every failure here is swallowed.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class InstallerCommandReport
{
    internal static void Write(string message, bool isError)
    {
        (isError ? Console.Error : Console.Out).WriteLine(message);
        try
        {
            // "Patched Agent" is the source the service registers for its own event
            // log entries; this runs as SYSTEM, which may create it if absent.
            EventLog.WriteEntry("Patched Agent", message,
                isError ? EventLogEntryType.Warning : EventLogEntryType.Information);
        }
        catch
        {
            // Event log unavailable: the exit code still reaches the MSI log.
        }
    }
}

/// <summary>
/// PAT-1764: the <c>--purge-credentials</c> command. Runs <see cref="CredentialPurge"/>,
/// reports each failure (target names and error codes only, never values) and
/// returns a process exit code: 0 when everything was removed, 1 otherwise. The MSI
/// custom action is Return="ignore", so a failure is recorded in the verbose MSI log
/// as the exit code and in the Application event log, and never blocks uninstall.
/// </summary>
public static class CredentialPurgeCommand
{
    public const int ExitSucceeded = 0;
    public const int ExitFailed = 1;

    internal const string SucceededMessage =
        "Uninstall removed the agent credentials from Credential Manager, the credential file store and HKLM\\" +
        CredentialStore.RegistryProvisioningKey + ".";

    public static int Run(CredentialPurge purge, Action<string, bool> report)
    {
        CredentialPurgeResult result;
        try
        {
            result = purge.Run();
        }
        catch (Exception ex)
        {
            Report(report, $"Uninstall could not remove the agent credentials ({ex.GetType().Name}).", isError: true);
            return ExitFailed;
        }

        if (result.Succeeded)
        {
            Report(report, SucceededMessage, isError: false);
            return ExitSucceeded;
        }

        Report(report,
            "Uninstall could not remove every agent credential. A later install may keep the old device " +
            "identity until these are removed: " + string.Join("; ", result.Failures),
            isError: true);
        return ExitFailed;
    }

    private static void Report(Action<string, bool> report, string message, bool isError)
    {
        try { report(message, isError); } catch { /* reporting must never change the exit code */ }
    }

    [SupportedOSPlatform("windows")]
    public static int RunProduction() =>
        Run(
            new CredentialPurge(
                CredentialStore.AgentCredentialTargets,
                CredentialStore.DeleteCredentialReporting,
                CredentialStore.CreateFileStorePurge(),
                CredentialStore.DeleteRegistryProvisioningKeyReporting),
            InstallerCommandReport.Write);
}

/// <summary>
/// PAT-1755: the <c>--write-enrollment-token</c> command. Writes the installer-supplied
/// token into the credential file store and returns 0, or reports why it could not and
/// returns 1.
///
/// The MSI custom action is Return="check", the opposite of the uninstall purge: an
/// install that was handed an enrolment token and could not provision it would leave a
/// device that can never enrol and never collect anything, which must fail loudly rather
/// than complete and look healthy. Windows Installer rolls the install back and the
/// verbose log records this action's exit code; the reason is in the Application event
/// log under the source "Patched Agent". No message ever contains the token.
/// </summary>
public static class EnrollmentTokenProvisionCommand
{
    public const int ExitSucceeded = 0;
    public const int ExitFailed = 1;

    internal const string SucceededMessage =
        "Install provisioned the enrollment token into the agent credential file store. " +
        "The service exchanges it for per-device credentials on its first run cycle.";

    internal const string FailedMessagePrefix =
        "Install could not provision the enrollment token, so this device has no way to enrol: ";

    public static int Run(EnrollmentTokenProvisioner provisioner, string? suppliedToken, Action<string, bool> report)
    {
        EnrollmentTokenProvisionResult result;
        try
        {
            result = provisioner.Provision(suppliedToken);
        }
        catch (Exception ex)
        {
            Report(report, $"{FailedMessagePrefix}{ex.GetType().Name}.", isError: true);
            return ExitFailed;
        }

        if (result.Succeeded)
        {
            Report(report, SucceededMessage, isError: false);
            return ExitSucceeded;
        }

        Report(report, $"{FailedMessagePrefix}{result.Error}.", isError: true);
        return ExitFailed;
    }

    private static void Report(Action<string, bool> report, string message, bool isError)
    {
        try { report(message, isError); } catch { /* reporting must never change the exit code */ }
    }

    [SupportedOSPlatform("windows")]
    public static int RunProduction(string? suppliedToken) =>
        Run(CredentialStore.CreateEnrollmentTokenProvisioner(), suppliedToken, InstallerCommandReport.Write);
}
