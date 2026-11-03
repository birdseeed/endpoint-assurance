using Patched.Shared.Auth;

namespace Patched.Service;

/// <summary>
/// The one check every authenticated caller in the service makes before it
/// sends a request: does this device hold its enrolled bearer token and HMAC
/// secret? Moved here from AgentConfigFetcher (PAT-1754) by PAT-1760 so the
/// fetchers, the startup decommission check and the self-update check all
/// use the same rule instead of each re-reading <see cref="CredentialStore"/>.
///
/// PAT-1760 review: "enrolled" means <see cref="Present"/> everywhere in the
/// service: the fetchers, the startup checks, AgentEnroller's early return, the
/// worker's pending-enrolment branch, first-run scan and queue drains, and the
/// suspension skip. The rule itself lives in CredentialStore (IsUsablePair) so
/// RefreshEnrollmentToken and LoadForStartup in Patched.Shared use it too.
/// </summary>
internal static class DeviceCredentials
{
    /// <summary>
    /// PAT-1754: true when <paramref name="bearerToken"/> is a usable bearer
    /// token. An empty or whitespace value means the device has not enrolled.
    /// </summary>
    internal static bool HasBearerToken(string? bearerToken) => CredentialStore.IsUsableBearerToken(bearerToken);

    /// <summary>
    /// PAT-1754: true when <paramref name="creds"/> holds an enrolled bearer token
    /// and HMAC secret. Each value is read from the store exactly once and handed
    /// back as <paramref name="bearerToken"/> and <paramref name="hmacSecret"/>;
    /// callers must use these snapshots for the request header and the signature,
    /// never re-read the store, because CredentialStore's properties are plain
    /// unsynchronised auto-properties.
    /// The token is read before the secret on purpose: UpdateFromEnrolment sets
    /// BearerToken before HmacSecret and neither changes afterwards, so a non-empty
    /// secret read after a non-empty token means both belong to the enrolled pair.
    /// Checking the token alone would allow a request signed with the empty
    /// pre-enrolment secret in the instant between those two assignments, and
    /// that request would carry a token and be rejected.
    ///
    /// PAT-1760 review: the secret must be non-whitespace too, not just non-empty.
    /// Convert.FromBase64String("   ") returns an empty key, so a whitespace
    /// secret signs a request that carries a real bearer token with an invalid
    /// signature; a due decommission check reads each resulting 401 as an abort
    /// and repeats it every poll. The macOS guard already rejects whitespace.
    /// </summary>
    internal static bool TryRead(CredentialStore creds, out string bearerToken, out string hmacSecret)
    {
        bearerToken = creds.BearerToken;
        hmacSecret  = creds.HmacSecret;
        return HasBearerToken(bearerToken) && HasHmacSecret(hmacSecret);
    }

    /// <summary>
    /// PAT-1760 review: true when <paramref name="hmacSecret"/> could be a usable
    /// HMAC secret. An empty or whitespace value means the device has none.
    /// </summary>
    internal static bool HasHmacSecret(string? hmacSecret) => CredentialStore.IsUsableHmacSecret(hmacSecret);

    /// <summary>
    /// PAT-1765: true when <paramref name="creds"/> holds a usable enrolment token.
    /// Empty or whitespace means there is nothing to send to /v1/enrol.
    /// </summary>
    internal static bool HasEnrollmentToken(CredentialStore creds) => CredentialStore.IsUsableEnrollmentToken(creds.EnrollmentToken);

    /// <summary>True when <paramref name="creds"/> holds the enrolled pair (see <see cref="TryRead"/>).</summary>
    internal static bool Present(CredentialStore creds) => TryRead(creds, out _, out _);
}

/// <summary>
/// PAT-1781: one transition-aware writer for the cross-platform
/// credentials_unusable|device_credentials health row. The persisted active row
/// is the state latch, so repeated service ticks and process restarts do not bump
/// its count unless the reason actually changes. Clearing still uses
/// <see cref="AgentHealthStore.RecordSuccess"/>, preserving the existing
/// ever_succeeded and last_success semantics.
/// </summary>
internal static class DeviceCredentialHealth
{
    internal const string Kind = "credentials_unusable";
    internal const string Subject = "device_credentials";
    internal const string CredentialsEmptyReason = "credentials_empty";
    internal const string EnrollmentTokenSpentReason = "enrolment_token_spent";

    internal static void RecordFailureIfChanged(AgentHealthStore health, string reason)
    {
        var activeReason = ActiveReason(health);
        if (activeReason is not null && string.Equals(activeReason, reason, StringComparison.Ordinal))
            return;

        health.RecordFailure(Kind, Subject, reason);
    }

    internal static void ClearIfActive(AgentHealthStore health)
    {
        if (ActiveReason(health) is not null)
            health.RecordSuccess(Kind, Subject);
    }

    private static string? ActiveReason(AgentHealthStore health) =>
        health.BuildPayloadSection()?.Degraded.FirstOrDefault(entry =>
            string.Equals(entry.Kind, Kind, StringComparison.Ordinal)
            && string.Equals(entry.Subject, Subject, StringComparison.Ordinal))?.Reason;
}
