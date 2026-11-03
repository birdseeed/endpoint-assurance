namespace Patched.Service;

/// <summary>
/// PAT-687: decides whether a trigger file's owner SID is an acceptable,
/// non-foreign principal, and derives the authoritative <c>requested_by</c>
/// value from the OS owner (rather than trusting the self-asserted JSON field,
/// which any local user could spoof).
///
/// Pure logic — no Windows API calls — so it is unit-testable on any platform.
/// </summary>
public static class TriggerOwnerPolicy
{
    // Well-known SIDs that must never own a trigger file: they are not a real
    // authenticated/interactive user, so a file owned by one is "foreign" and
    // is rejected outright.
    private static readonly HashSet<string> RejectedOwnerSids =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "S-1-0-0",  // Null SID
            "S-1-1-0",  // Everyone
            "S-1-2-0",  // Local
            "S-1-2-1",  // Console Logon
            "S-1-5-7",  // Anonymous Logon
        };

    /// <summary>
    /// True when <paramref name="sid"/> is a well-formed SID that is permitted to
    /// own a trigger file (a normal user, SYSTEM, or Administrators — anything
    /// except the rejected anonymous/world principals above).
    /// </summary>
    public static bool IsAcceptableOwnerSid(string? sid)
    {
        if (string.IsNullOrWhiteSpace(sid)) return false;
        if (!sid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)) return false;
        return !RejectedOwnerSids.Contains(sid);
    }

    /// <summary>
    /// The authoritative requested_by string: the translated account name when
    /// available (e.g. "CORP\alice"), otherwise the raw SID. Never the value the
    /// trigger author wrote into the file.
    /// </summary>
    public static string DeriveRequestedBy(string ownerSid, string? ownerAccount)
        => !string.IsNullOrWhiteSpace(ownerAccount) ? ownerAccount! : ownerSid;
}
