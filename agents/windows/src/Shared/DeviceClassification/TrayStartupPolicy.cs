namespace Patched.Shared.DeviceClassification;

/// <summary>
/// PAT-1959: whether the tray should start on this machine.
///
/// Server Core has no desktop, so a tray process there is a process that can never show
/// anything. The decision lives here, in a project that builds and is unit-tested
/// everywhere, rather than inside the Tray project, which only builds on Windows.
///
/// The rule is one-sided on purpose. Only a definite "Server Core" reading suppresses the
/// tray. An absent, unreadable or undocumented InstallationType starts it, because not
/// being able to read the value is not evidence that the machine has no desktop, and
/// suppressing on a failed read would silently remove the local surface from ordinary
/// workstations whose registry read happened to fail. The two mistakes are not equal: a
/// tray that starts on Server Core is a harmless process with nowhere to draw, while a
/// tray that refuses to start on a workstation removes the only thing the user can see.
///
/// This governs the tray only. The service runs normally on every machine class,
/// including Server Core, and nothing here touches it.
/// </summary>
public static class TrayStartupPolicy
{
    /// <summary>Decides from a raw InstallationType read.</summary>
    public static bool ShouldStart(SourceRead installationTypeRead) =>
        ShouldStart(DeviceClassResolver.ResolveInstallationType(installationTypeRead));

    /// <summary>
    /// Decides from an already-resolved InstallationType (null when absent, unreadable or
    /// undocumented).
    /// </summary>
    public static bool ShouldStart(string? resolvedInstallationType) =>
        !string.Equals(resolvedInstallationType, InstallationTypeValue.ServerCore, StringComparison.Ordinal);
}
