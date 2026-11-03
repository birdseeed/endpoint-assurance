namespace Patched.Shared.DeviceClassification;

/// <summary>
/// PAT-1959: the four <c>device_class</c> values, lowercase on the wire.
///
/// The seam stays platform-neutral. macOS omits <c>device_class</c> entirely, an agent
/// older than this one omits it too, and the server treats both that absence and an
/// explicit <see cref="Unknown"/> the same way: score the device the way it was scored
/// before device class existed. That is why nothing here may ever guess. A wrong class
/// is silently scored as if it were right; an honest <see cref="Unknown"/> is scored as
/// a gap, which is the outcome the platform is built to handle.
/// </summary>
public static class DeviceClassValue
{
    public const string Workstation      = "workstation";
    public const string Server           = "server";
    public const string DomainController = "domain_controller";
    public const string Unknown          = "unknown";
}

/// <summary>
/// PAT-1959: the values Windows writes to
/// <c>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallationType</c>, emitted
/// verbatim as <c>installation_type</c>.
///
/// This is a closed vocabulary on the wire. A value that is not one of these three is
/// omitted rather than passed through, because the platform branches on the field and an
/// arbitrary registry string is not evidence of anything the platform can act on.
/// </summary>
public static class InstallationTypeValue
{
    public const string Client     = "Client";
    public const string Server     = "Server";
    public const string ServerCore = "Server Core";
}

/// <summary>
/// PAT-1959: <c>Win32_OperatingSystem.ProductType</c>.
///
/// The ordering is not intuitive and is worth stating plainly: 2 is the DOMAIN
/// CONTROLLER and 3 is the member server. Reading these the other way round would
/// report every domain controller as an ordinary server and vice versa.
///
/// Build numbers cannot stand in for this. Windows Server 2019 and Windows 10 1809
/// LTSC are both build 17763, so a build-number heuristic would assess a domain
/// controller as a laptop, which is exactly the failure this field exists to remove.
/// </summary>
public static class WindowsProductType
{
    public const int Workstation      = 1;
    public const int DomainController = 2;
    public const int Server           = 3;
}
