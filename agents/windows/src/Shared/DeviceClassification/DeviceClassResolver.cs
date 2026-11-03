namespace Patched.Shared.DeviceClassification;

/// <summary>
/// PAT-1959: the three raw source reads the device-class decision is made from. The
/// Service does the Windows-only reading (WMI and the registry) and hands a snapshot
/// here, so the decision itself is API-free and testable off-box.
/// </summary>
public readonly record struct DeviceClassSources(
    SourceRead ProductType,
    SourceRead InstallationType,
    SourceRead OsCaption);

/// <summary>
/// PAT-1959: the resolved values that go on the wire. <see cref="DeviceClass"/> is
/// always one of <see cref="DeviceClassValue"/>'s four strings. The two optional strings
/// are null when they are to be omitted from the payload entirely.
/// </summary>
public sealed record DeviceClassResult(
    string DeviceClass,
    string? InstallationType,
    string? OsCaption);

/// <summary>
/// PAT-1959 — pure decision for <c>device_class</c>, <c>installation_type</c> and
/// <c>os_caption</c>.
///
/// Every rule here follows from one constraint: absence requires authority. A missing,
/// unreadable or unrecognised source value produces <see cref="DeviceClassValue.Unknown"/>
/// or an omitted string, never a guess and never an inferred default. On the platform
/// side "unknown" is deliberately treated as "score it the old way", so a confident wrong
/// answer here does not surface as a gap the operator can see, it surfaces as a wrong
/// assessment nobody questions. That asymmetry is why the rules below refuse rather than
/// infer.
/// </summary>
public static class DeviceClassResolver
{
    /// <summary>
    /// Longest <c>os_caption</c> accepted. The real captions are short
    /// ("Microsoft Windows 11 Pro", "Microsoft Windows Server 2022 Standard"); anything
    /// far longer is not a caption and is dropped rather than truncated, because a
    /// truncated caption still reads as a real reading.
    /// </summary>
    public const int MaxOsCaptionLength = 256;

    public static DeviceClassResult Resolve(DeviceClassSources sources)
    {
        var installationType = ResolveInstallationType(sources.InstallationType);
        return new DeviceClassResult(
            ResolveDeviceClass(sources.ProductType, installationType),
            installationType,
            ResolveOsCaption(sources.OsCaption));
    }

    /// <summary>
    /// Maps the registry value to the closed <see cref="InstallationTypeValue"/>
    /// vocabulary, matched case-insensitively and emitted in its canonical casing.
    /// Returns null (omit the field) when the read was absent or failed, when the value
    /// is not a string, when it is empty, or when it is a string Windows does not
    /// document. An undocumented value is never mapped onto one of the three.
    /// </summary>
    public static string? ResolveInstallationType(SourceRead read)
    {
        if (read.State != SourceReadState.Present)
            return null;

        var text = (read.Value as string)?.Trim();
        if (string.IsNullOrEmpty(text))
            return null;

        if (string.Equals(text, InstallationTypeValue.Client, StringComparison.OrdinalIgnoreCase))
            return InstallationTypeValue.Client;
        if (string.Equals(text, InstallationTypeValue.Server, StringComparison.OrdinalIgnoreCase))
            return InstallationTypeValue.Server;
        if (string.Equals(text, InstallationTypeValue.ServerCore, StringComparison.OrdinalIgnoreCase))
            return InstallationTypeValue.ServerCore;

        return null;
    }

    /// <summary>
    /// Returns the trimmed OS caption, or null (omit the field) when the read was absent
    /// or failed, the value is not a string, it is empty or whitespace, it is longer than
    /// <see cref="MaxOsCaptionLength"/>, or it carries control characters. The caption is
    /// free text for an operator to read, so it is passed through verbatim once it passes
    /// those checks; it is never parsed into a class, since the caption is localised and
    /// the same caption text can belong to more than one product type.
    /// </summary>
    public static string? ResolveOsCaption(SourceRead read)
    {
        if (read.State != SourceReadState.Present)
            return null;

        var text = (read.Value as string)?.Trim();
        if (string.IsNullOrEmpty(text) || text.Length > MaxOsCaptionLength)
            return null;

        foreach (var c in text)
        {
            if (char.IsControl(c))
                return null;
        }

        return text;
    }

    /// <summary>
    /// ProductType alone decides the class. InstallationType is never used to fill in a
    /// class ProductType did not supply: it cannot tell a domain controller from a member
    /// server, so deriving "server" from it would be a guess that reads as a fact, and it
    /// would report every domain controller as an ordinary server.
    ///
    /// InstallationType is used in one direction only, to withdraw a class the two
    /// sources disagree about. ProductType 1 with InstallationType "Server" or
    /// "Server Core", or ProductType 2 or 3 with "Client", is a contradiction: on a real
    /// Windows install these always agree. Something about the reading is wrong, and
    /// which one is wrong is not knowable from here, so the class becomes
    /// <see cref="DeviceClassValue.Unknown"/>. That matters most in the direction this
    /// ticket exists for: a server reporting ProductType 1 would otherwise be assessed as
    /// a laptop, confidently.
    /// </summary>
    private static string ResolveDeviceClass(SourceRead productTypeRead, string? installationType)
    {
        var fromProductType = ToProductType(productTypeRead) switch
        {
            WindowsProductType.Workstation      => DeviceClassValue.Workstation,
            WindowsProductType.DomainController => DeviceClassValue.DomainController,
            WindowsProductType.Server           => DeviceClassValue.Server,
            _                                   => DeviceClassValue.Unknown,
        };

        if (fromProductType == DeviceClassValue.Unknown || installationType is null)
            return fromProductType;

        var installationSaysClient     = installationType == InstallationTypeValue.Client;
        var productTypeSaysWorkstation = fromProductType == DeviceClassValue.Workstation;

        return installationSaysClient == productTypeSaysWorkstation
            ? fromProductType
            : DeviceClassValue.Unknown;
    }

    /// <summary>
    /// ProductType is a WMI uint32, which arrives as <see cref="uint"/> through
    /// System.Management but can surface as another integral type or as text through a
    /// different reader. Converted explicitly rather than with Convert.ToInt32, which
    /// throws on values that are simply not numbers. A value that is not an integer, or
    /// that does not fit one, is null and therefore unknown.
    /// </summary>
    private static int? ToProductType(SourceRead read)
    {
        if (read.State != SourceReadState.Present)
            return null;

        return read.Value switch
        {
            int i                                                   => i,
            uint u when u <= int.MaxValue                           => (int)u,
            short s                                                 => s,
            ushort us                                               => us,
            byte b                                                  => b,
            sbyte sb                                                => sb,
            long l when l is >= int.MinValue and <= int.MaxValue     => (int)l,
            ulong ul when ul <= int.MaxValue                        => (int)ul,
            string s when int.TryParse(s.Trim(), out var parsed)    => parsed,
            _                                                       => null,
        };
    }
}
