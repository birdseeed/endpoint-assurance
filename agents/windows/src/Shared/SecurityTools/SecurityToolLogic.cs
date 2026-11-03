using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Patched.Shared.Contract;
using Patched.Shared.Compliance;
using Patched.Shared.DeviceClassification;

namespace Patched.Shared.SecurityTools;

/// <summary>PAT-2267: how one registry key or Defender status probe ended. Absent and failed never collapse.</summary>
internal enum SecurityToolProbe
{
    /// <summary>The key or instance exists.</summary>
    Present,

    /// <summary>The read succeeded and found nothing.</summary>
    Absent,

    /// <summary>The read threw. Nothing is known.</summary>
    Failed,
}

/// <summary>PAT-2267: how the <c>root\SecurityCenter2</c> <c>AntiVirusProduct</c> query ended.</summary>
internal enum SecurityCenterReadState
{
    /// <summary>The query ran; <see cref="SecurityCenterRead.Products"/> is every instance.</summary>
    Read,

    /// <summary>The namespace or class does not exist (WBEM_E_INVALID_NAMESPACE / _CLASS).</summary>
    Missing,

    /// <summary>The query threw for any other reason (access denied, RPC, timeout).</summary>
    Failed,
}

/// <summary>One <c>AntiVirusProduct</c> instance, raw: the logic decides what is usable.</summary>
internal sealed record SecurityCenterProduct(string? DisplayName, object? ProductState);

internal sealed record SecurityCenterRead(SecurityCenterReadState State, IReadOnlyList<SecurityCenterProduct> Products)
{
    public static SecurityCenterRead Failed { get; } = new(SecurityCenterReadState.Failed, []);
    public static SecurityCenterRead Missing { get; } = new(SecurityCenterReadState.Missing, []);
    public static SecurityCenterRead Of(params SecurityCenterProduct[] products) => new(SecurityCenterReadState.Read, products);
}

/// <summary>
/// PAT-2267: the readers <see cref="SecurityToolLogic.Detect"/> consults. Each is a delegate
/// so every failure route is testable off Windows. A reader that throws is treated exactly as
/// one that reported a failed read.
/// </summary>
internal sealed record SecurityToolSources(
    string? DeviceClass,
    Func<SecurityCenterRead> SecurityCenter,
    Func<SecurityToolProbe> DefenderStatus,
    Func<string, SecurityToolProbe> RegistryKey,
    Func<RegistryRead>? MdeOnboarding = null);

/// <summary>
/// PAT-2267: the tools this run proved present, and every source it could not read.
/// <see cref="Tools"/> is only ever positive evidence; it is an authoritative list only
/// when <see cref="Complete"/>. security_tools has no status field on the wire, so an
/// incomplete detection is reported through agent_health (see SecurityToolDetector).
/// </summary>
internal sealed record SecurityToolDetection(IReadOnlyList<InventorySecurityTool> Tools, IReadOnlyList<string> Undetermined)
{
    public bool Complete => Undetermined.Count == 0;

    /// <summary>The agent_health reason, or null when complete. Bounded: at most six fixed codes.</summary>
    public string? HealthReason => Complete ? null : string.Join(",", Undetermined);
}

/// <summary>
/// PAT-2267: Windows security-tool detection, platform-neutral so it runs on macOS CI.
///
/// Sources, in order of authority:
/// <list type="number">
/// <item>Windows Security Center (<c>root\SecurityCenter2</c> <c>AntiVirusProduct</c>) on
/// anything that is not a server. Registration there needs a Microsoft Virus Initiative
/// ELAM-signed product, so it sees any vendor, not only those on a list. Windows Server
/// has no SecurityCenter2; on a server or domain controller it is not applicable and not
/// asked.</item>
/// <item>The Defender status class (<c>MSFT_MpComputerStatus</c>) wherever Security Center
/// was not read, so Defender Antivirus is still seen on Server.</item>
/// <item>The fixed registry table, always, plus Defender for Endpoint's typed onboarding
/// value. EDR sensors need not register as antivirus. MDE key existence is not onboarding.</item>
/// </list>
/// Results merge by id: a known vendor's Security Center display name maps onto the
/// table's existing id and name (the platform's protected_software baseline matches by
/// name), anything else gets a deterministic slug id and its bounded display name.
///
/// ABSENCE REQUIRES AUTHORITY: a source that fails, a registry path that fails without a
/// sibling path proving the tool, and a Security Center entry that cannot be decoded each
/// add a reason to <see cref="SecurityToolDetection.Undetermined"/>. None is ever read as
/// "not installed".
/// </summary>
internal static class SecurityToolLogic
{
    /// <summary>
    /// Built-in Microsoft Defender Antivirus. Deliberately NOT <c>defender-for-endpoint</c>:
    /// Defender Antivirus ships on every Windows client and registers in Security Center
    /// whether or not the device is onboarded to Defender for Endpoint (the EDR). Reporting
    /// it under the MDE id or name would match the platform's "Microsoft Defender for
    /// Endpoint" baseline row and mark every Windows device EDR-covered.
    /// </summary>
    public const string DefenderAntivirusId = "microsoft-defender-antivirus";
    public const string DefenderAntivirusName = "Microsoft Defender Antivirus";
    public const string MdeId = "defender-for-endpoint";
    public const string MdeStatusPath = @"SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status";
    public const string MdeOnboardingValue = "OnboardingState";

    public const string ReasonSecurityCenterFailed = "security_center_failed";
    public const string ReasonSecurityCenterMissing = "security_center_missing";
    public const string ReasonSecurityCenterEntryUnusable = "security_center_entry_unusable";
    public const string ReasonDefenderStatusFailed = "defender_status_failed";
    public const string ReasonRegistryFailed = "registry_failed";
    public const string ReasonMdeOnboardingFailed = "mde_onboarding_failed";

    public const int MaxNameLength = 128;
    public const int MaxIdLength = 64;

    /// <summary>WSC_SECURITY_PROVIDER_ANTIVIRUS in productState's provider byte (bits 16-23).</summary>
    private const int ProviderAntivirus = 0x04;

    /// <summary>
    /// A known product. <see cref="SecurityCenterNames"/> match the whole display name;
    /// <see cref="SecurityCenterPrefixes"/> match a leading vendor word, ending at the end of
    /// the name or a space, so "Bitdefenderish" is not Bitdefender. Both case-insensitive.
    /// </summary>
    internal sealed record KnownTool(
        string Id,
        string Name,
        string[] RegistryPaths,
        string[] SecurityCenterNames,
        string[] SecurityCenterPrefixes);

    /// <summary>
    /// Ids and names are unchanged from the pre-PAT-2267 registry table, which mirrors the
    /// macOS path table (macos/lib/sectools.sh). Order here is output order.
    /// </summary>
    internal static readonly IReadOnlyList<KnownTool> KnownTools =
    [
        new(MdeId, "Microsoft Defender for Endpoint",
            [],
            [], []),
        new("crowdstrike-falcon", "CrowdStrike Falcon",
            [
                @"SYSTEM\CurrentControlSet\Services\CSFalconService",
                @"SOFTWARE\CrowdStrike\Windows Sensor",
            ],
            [], ["CrowdStrike Falcon"]),
        new("sentinelone", "SentinelOne",
            [
                @"SYSTEM\CurrentControlSet\Services\SentinelAgent",
                @"SOFTWARE\Sentinel Labs",
            ],
            [], ["Sentinel Agent", "SentinelOne"]),
        new("sophos-endpoint", "Sophos Endpoint",
            [
                @"SOFTWARE\Sophos\SAVService",
                @"SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense",
            ],
            [], ["Sophos"]),
        new("malwarebytes", "Malwarebytes",
            [
                @"SOFTWARE\Malwarebytes",
                @"SOFTWARE\WOW6432Node\Malwarebytes' Anti-Malware",
            ],
            [], ["Malwarebytes"]),
        new("carbon-black", "VMware Carbon Black",
            [
                @"SOFTWARE\VMware, Inc.\VMware Carbon Black Cloud",
                @"SYSTEM\CurrentControlSet\Services\CbDefense",
            ],
            [], ["VMware Carbon Black", "Carbon Black"]),
        new("bitdefender", "Bitdefender",
            [
                @"SOFTWARE\Bitdefender",
                @"SOFTWARE\WOW6432Node\Bitdefender",
            ],
            [], ["Bitdefender"]),
        new("huntress", "Huntress",
            [
                @"SOFTWARE\Huntress Labs\Huntress",
                @"SYSTEM\CurrentControlSet\Services\HuntressAgent",
            ],
            [], []),
        new(DefenderAntivirusId, DefenderAntivirusName,
            [],
            ["Windows Defender", "Microsoft Defender Antivirus"], []),
    ];

    private static readonly HashSet<string> KnownIds =
        new(KnownTools.Select(t => t.Id), StringComparer.Ordinal);

    public static SecurityToolDetection Detect(SecurityToolSources sources)
    {
        var undetermined = new SortedSet<string>(StringComparer.Ordinal);
        var knownFound = new HashSet<string>(StringComparer.Ordinal);
        var unknownFound = new SortedDictionary<string, string>(StringComparer.Ordinal);

        var isServer = sources.DeviceClass is DeviceClassValue.Server or DeviceClassValue.DomainController;
        var securityCenterRead = false;

        if (!isServer)
        {
            var read = Guard(sources.SecurityCenter, SecurityCenterRead.Failed);
            switch (read.State)
            {
                case SecurityCenterReadState.Read:
                    securityCenterRead = true;
                    foreach (var product in read.Products)
                        AddSecurityCenterProduct(product, knownFound, unknownFound, undetermined);
                    break;
                case SecurityCenterReadState.Missing:
                    // Not a server by class, so a missing SecurityCenter2 is not "not
                    // applicable": a client with it is broken WMI, and an unknown class
                    // cannot prove the device is a server.
                    undetermined.Add(ReasonSecurityCenterMissing);
                    break;
                default:
                    undetermined.Add(ReasonSecurityCenterFailed);
                    break;
            }
        }

        if (!securityCenterRead)
        {
            switch (Guard(sources.DefenderStatus, SecurityToolProbe.Failed))
            {
                case SecurityToolProbe.Present:
                    knownFound.Add(DefenderAntivirusId);
                    break;
                case SecurityToolProbe.Failed:
                    undetermined.Add(ReasonDefenderStatusFailed);
                    break;
            }
        }

        // MDE is built into Windows even when not onboarded: only its authoritative
        // REG_DWORD OnboardingState == 1 proves this product. Never infer it from keys.
        var onboarding = Guard(sources.MdeOnboarding ?? (() => RegistryRead.Absent), RegistryRead.Failed);
        switch (DecideMdeOnboarding(onboarding))
        {
            case SecurityToolProbe.Present:
                knownFound.Add(MdeId);
                break;
            case SecurityToolProbe.Failed:
                undetermined.Add(ReasonMdeOnboardingFailed);
                break;
        }

        foreach (var tool in KnownTools)
        {
            if (tool.RegistryPaths.Length == 0 || knownFound.Contains(tool.Id))
                continue;
            var anyFailed = false;
            foreach (var path in tool.RegistryPaths)
            {
                var probe = Guard(() => sources.RegistryKey(path), SecurityToolProbe.Failed);
                if (probe == SecurityToolProbe.Present)
                {
                    knownFound.Add(tool.Id);
                    anyFailed = false;
                    break;
                }
                anyFailed |= probe == SecurityToolProbe.Failed;
            }
            if (anyFailed)
                undetermined.Add(ReasonRegistryFailed);
        }

        var tools = KnownTools
            .Where(t => knownFound.Contains(t.Id))
            .Select(t => new InventorySecurityTool { Id = t.Id, Name = t.Name })
            .Concat(unknownFound.Select(kv => new InventorySecurityTool { Id = kv.Key, Name = kv.Value }))
            .ToList();

        return new SecurityToolDetection(tools, undetermined.ToList());
    }

    internal static SecurityToolProbe DecideMdeOnboarding(RegistryRead read)
    {
        if (read.State == RegistryReadState.Absent)
            return SecurityToolProbe.Absent;
        if (read.TryGetInt(out var state))
            return state == 1 ? SecurityToolProbe.Present : SecurityToolProbe.Absent;
        return SecurityToolProbe.Failed;
    }

    private static void AddSecurityCenterProduct(
        SecurityCenterProduct product,
        HashSet<string> knownFound,
        SortedDictionary<string, string> unknownFound,
        SortedSet<string> undetermined)
    {
        var name = product.DisplayName?.Trim();
        if (string.IsNullOrEmpty(name) || name.Any(char.IsControl))
        {
            undetermined.Add(ReasonSecurityCenterEntryUnusable);
            return;
        }

        // An instance we cannot decode, or one that does not say it is an antivirus
        // registration, is not reported, and the list is not complete without it.
        if (!TryDecodeProductState(product.ProductState, out var state)
            || ((state >> 16) & ProviderAntivirus) == 0)
        {
            undetermined.Add(ReasonSecurityCenterEntryUnusable);
            return;
        }

        if (MatchKnown(name) is { } known)
        {
            knownFound.Add(known.Id);
            return;
        }

        var id = SlugId(name);
        var bounded = Bound(name);
        // Two display names with one slug: keep the ordinal-first name, deterministically.
        if (!unknownFound.TryGetValue(id, out var existing) || string.CompareOrdinal(bounded, existing) < 0)
            unknownFound[id] = bounded;
    }

    private static KnownTool? MatchKnown(string name)
    {
        foreach (var tool in KnownTools)
        {
            if (tool.SecurityCenterNames.Any(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase)))
                return tool;
            foreach (var prefix in tool.SecurityCenterPrefixes)
            {
                if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                    && (name.Length == prefix.Length || name[prefix.Length] == ' '))
                    return tool;
            }
        }
        return null;
    }

    /// <summary>
    /// productState is a 24-bit value (provider flags, scanner state, definitions state).
    /// WMI returns a uint32; any integral shape or decimal string in range is accepted, and
    /// anything else is undecodable rather than guessed.
    /// </summary>
    internal static bool TryDecodeProductState(object? raw, out int state)
    {
        state = 0;
        long value;
        switch (raw)
        {
            case uint u: value = u; break;
            case int i: value = i; break;
            case long l: value = l; break;
            case ulong ul when ul <= int.MaxValue: value = (long)ul; break;
            case ushort us: value = us; break;
            case short s: value = s; break;
            case string str when long.TryParse(str, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed):
                value = parsed;
                break;
            default:
                return false;
        }
        if (value is < 0 or > 0xFFFFFF)
            return false;
        state = (int)value;
        return true;
    }

    /// <summary>
    /// A deterministic id for a vendor not in <see cref="KnownTools"/>: lowercase ASCII
    /// letters and digits, every other run of characters one hyphen, at most
    /// <see cref="MaxIdLength"/>. A name with no ASCII letter or digit gets
    /// <c>av-</c> plus 12 hex of its SHA-256. A slug equal to a known id is prefixed
    /// <c>wsc-</c> so an unknown product can never merge into a known one's row.
    /// </summary>
    public static string SlugId(string displayName)
    {
        var sb = new StringBuilder(MaxIdLength);
        var pendingHyphen = false;
        foreach (var c in displayName.ToLowerInvariant())
        {
            if (c is (>= 'a' and <= 'z') or (>= '0' and <= '9'))
            {
                if (pendingHyphen && sb.Length > 0)
                    sb.Append('-');
                pendingHyphen = false;
                sb.Append(c);
            }
            else
            {
                pendingHyphen = true;
            }
        }

        var slug = sb.ToString();
        if (slug.Length > MaxIdLength - 4)
            slug = slug[..(MaxIdLength - 4)].TrimEnd('-');
        if (slug.Length == 0)
        {
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(displayName));
            return "av-" + Convert.ToHexString(hash)[..12].ToLowerInvariant();
        }
        return KnownIds.Contains(slug) ? "wsc-" + slug : slug;
    }

    private static string Bound(string name)
    {
        if (name.Length <= MaxNameLength)
            return name;
        var cut = MaxNameLength;
        if (char.IsHighSurrogate(name[cut - 1]))
            cut--;
        return name[..cut].TrimEnd();
    }

    private static T Guard<T>(Func<T> read, T onThrow)
    {
        try { return read(); }
        catch { return onThrow; }
    }
}
