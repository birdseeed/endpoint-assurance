using Microsoft.Extensions.Logging;

namespace Patched.Shared.Auth;

/// <summary>
/// PAT-1764: an ENROLLMENT_TOKEN the installer writes onto a device that already
/// holds agent credentials is never used, because the service keeps the existing
/// identity rather than re-enrolling over it (re-enrolment is PAT-1760). Left in
/// place it is a live single-use secret in a provisioning store with nothing to
/// consume it, so it is deleted at startup and the operator is told why the device
/// did not re-enrol. An MDM that re-pushes an already consumed token lands here too,
/// and must never disturb working credentials, so this only ever deletes the token.
///
/// PAT-1755: the provisioning store is the credential file store
/// (%ProgramData%\Patched\creds\enrollment-token) for this installer and the
/// HKLM\SOFTWARE\Patched\Enrollment key for one that predates it. Both are
/// reached through the seams below, so this class names neither.
/// </summary>
public static class IgnoredEnrollmentToken
{
    internal const string IgnoredMessage =
        "Enrollment token ignored: this device already holds agent credentials (kept from a previous " +
        "install or a decommission without purge), so the token written by the installer was deleted " +
        "without being used. To enrol again, uninstall normally or decommission with purge, then install " +
        "with a fresh enrollment token.";

    /// <summary>
    /// Deletes the provisioned enrolment token when one is present. Call only once the
    /// caller has established that full credentials already exist. Returns true when
    /// a token was found and deleted. Never reads or logs the token value.
    /// </summary>
    public static bool Discard(Func<bool> tokenPresent, Action deleteToken, ILogger log)
    {
        bool present;
        try
        {
            present = tokenPresent();
        }
        catch (Exception ex)
        {
            log.LogWarning("Could not check for an ignored enrollment token ({Error}).", ex.GetType().Name);
            return false;
        }

        if (!present)
            return false;

        try
        {
            deleteToken();
        }
        catch (Exception ex)
        {
            log.LogWarning(
                "Enrollment token ignored: this device already holds agent credentials (kept from a previous " +
                "install or a decommission without purge). The token could not be deleted from the installer " +
                "provisioning store ({Error}). To enrol again, uninstall normally or decommission with purge, " +
                "then install with a fresh enrollment token.",
                ex.GetType().Name);
            return false;
        }

        log.LogWarning(IgnoredMessage);
        return true;
    }
}
