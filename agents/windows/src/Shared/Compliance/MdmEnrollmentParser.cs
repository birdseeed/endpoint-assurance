namespace Patched.Shared.Compliance;

/// <summary>
/// One subkey of <c>HKLM\SOFTWARE\Microsoft\Enrollments</c>, reduced to the values
/// the MDM enrollment decision reads. Null means the value was absent or not of a
/// usable type.
/// </summary>
public sealed record EnrollmentSubkey(
    string Name,
    string? ProviderId,
    int? EnrollmentState,
    string? DiscoveryServiceFullUrl);

/// <summary>
/// PAT-1751 — pure decision for the <c>mdm_enrolled</c> compliance signal
/// (server rule <c>patched_win_mdm_enrolled</c>). The Service reads the
/// Enrollments subkeys (Windows-only) and passes a snapshot here; this class is
/// API-free and unit-testable off-box.
///
/// Subkey presence is not evidence. Windows creates Enrollments subkeys on devices
/// that were never enrolled: an unenrolled Windows 11 VM (dsregcmd: AzureAdJoined,
/// DomainJoined and WorkplaceJoined all NO) carried 34 of them, around 30 GUID keys
/// with no ProviderID, a <c>Context</c> key, and the built-in local management
/// authorities <c>Local Authority</c>, <c>Deploy Authority</c> and
/// <c>Cloud Authority</c>, each with EnrollmentState 1.
///
/// A device is MDM-enrolled only when at least one subkey has all of:
/// <list type="bullet">
///   <item>EnrollmentState == 1 (enrolled);</item>
///   <item>a non-empty ProviderID that is not a built-in local authority
///         (case-insensitive);</item>
///   <item>a non-empty DiscoveryServiceFullURL, the MDM discovery endpoint the
///         enrollment client used.</item>
/// </list>
/// EnrollmentType is deliberately not used as evidence. Microsoft does not publish
/// the numeric EnrollmentType values for this registry key (checked against the
/// Windows client-management "Diagnose MDM enrollment failures" and "Mobile device
/// enrollment" pages); the tables that circulate come from community blogs. An
/// MDM enrollment with no DiscoveryServiceFullURL therefore reads "No", which fails
/// the rule closed rather than passing it on unverified evidence.
/// </summary>
public static class MdmEnrollmentParser
{
    private const int EnrollmentStateEnrolled = 1;

    private static readonly HashSet<string> BuiltInAuthorities = new(StringComparer.OrdinalIgnoreCase)
    {
        "Local Authority",
        "Deploy Authority",
        "Cloud Authority",
    };

    /// <summary>
    /// Returns "Yes" when the snapshot carries a real MDM enrollment, otherwise "No".
    /// "Unknown" (a failed registry read) is the collector's decision, not this one's.
    /// </summary>
    public static string Evaluate(IEnumerable<EnrollmentSubkey>? subkeys)
    {
        if (subkeys is null)
            return "No";

        foreach (var k in subkeys)
        {
            if (k is not null && IsMdmEnrollment(k))
                return "Yes";
        }
        return "No";
    }

    private static bool IsMdmEnrollment(EnrollmentSubkey k)
    {
        if (k.EnrollmentState != EnrollmentStateEnrolled)
            return false;

        var provider = k.ProviderId?.Trim();
        if (string.IsNullOrEmpty(provider) || BuiltInAuthorities.Contains(provider))
            return false;

        return !string.IsNullOrWhiteSpace(k.DiscoveryServiceFullUrl);
    }

    /// <summary>
    /// Converts a raw registry value (REG_DWORD arrives as int, REG_QWORD as long,
    /// REG_SZ as string) to an int, or null when absent or not an integer.
    /// </summary>
    public static int? ToInt(object? value) => value switch
    {
        int i => i,
        long l when l is >= int.MinValue and <= int.MaxValue => (int)l,
        string s when int.TryParse(s.Trim(), out var parsed) => parsed,
        _ => null,
    };

    /// <summary>Returns a REG_SZ / REG_EXPAND_SZ value as a string, or null for any other type.</summary>
    public static string? ToText(object? value) => value as string;
}
