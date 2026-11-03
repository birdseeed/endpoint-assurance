using System.Text.RegularExpressions;

namespace Patched.Shared.Removal;

/// <summary>
/// A registry uninstall entry (HKLM\...\Uninstall\&lt;key&gt;), the raw material the
/// planner reasons over. Populated by the Service-side registry lookup.
/// </summary>
public sealed record InstalledProgram
{
    public required string Name { get; init; }
    public string? Publisher { get; init; }
    /// <summary>The Uninstall subkey name — an MSI ProductCode GUID for MSI installs.</summary>
    public string RegistryKeyName { get; init; } = "";
    public string? QuietUninstallString { get; init; }
    public string? UninstallString { get; init; }
    public string? InstallLocation { get; init; }
    public bool SystemComponent { get; init; }
    public bool WindowsInstaller { get; init; }
}

/// <summary>A resolved removal method plus the detail string the executor needs.</summary>
public readonly record struct ResolvedMethod(RemovalMethod Method, string Detail);

/// <summary>
/// Pure removal-decision logic (PAT-379), the testable core mirroring the macOS
/// engine's resolve_uninstall / classify_failure. No registry or process IO here.
/// </summary>
public static class UninstallPlanner
{
    private static readonly Regex GuidKey =
        new(@"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$",
            RegexOptions.Compiled);

    private static readonly Regex ProductCodeInString =
        new(@"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}",
            RegexOptions.Compiled);

    /// <summary>True if this entry is an MSI install (key is a ProductCode, or the
    /// uninstall string shells msiexec, or WindowsInstaller=1).</summary>
    public static bool IsMsi(InstalledProgram p)
    {
        if (p.WindowsInstaller) return true;
        if (GuidKey.IsMatch(p.RegistryKeyName)) return true;
        var u = p.UninstallString ?? "";
        return u.Contains("msiexec", StringComparison.OrdinalIgnoreCase)
               && ProductCodeInString.IsMatch(u);
    }

    /// <summary>The MSI ProductCode for an MSI entry, or null.</summary>
    public static string? MsiProductCode(InstalledProgram p)
    {
        if (GuidKey.IsMatch(p.RegistryKeyName)) return p.RegistryKeyName;
        var m = ProductCodeInString.Match(p.UninstallString ?? "");
        return m.Success ? m.Value : null;
    }

    /// <summary>
    /// Resolve the removal method. OS-native first (silent paths preferred), then a
    /// catalogue recipe fallback, then unresolvable → manual removal.
    /// Order: QuietUninstallString → MSI (/qn) → UninstallString → winget → catalogue.
    /// </summary>
    /// <param name="program">Registry entry, or null when nothing is installed.</param>
    /// <param name="wingetKnows">winget has a matching package (CLI fallback).</param>
    /// <param name="catalogueRecipe">A catalogue/allowlist uninstall recipe, or null.</param>
    public static ResolvedMethod Resolve(
        InstalledProgram? program, bool wingetKnows, string? catalogueRecipe)
    {
        if (program is not null)
        {
            if (!string.IsNullOrWhiteSpace(program.QuietUninstallString))
                return new(RemovalMethod.RegistryQuietUninstall, program.QuietUninstallString!.Trim());

            if (IsMsi(program) && MsiProductCode(program) is { } code)
                return new(RemovalMethod.Msi, code);

            if (!string.IsNullOrWhiteSpace(program.UninstallString))
                return new(RemovalMethod.RegistryUninstall, program.UninstallString!.Trim());
        }

        if (wingetKnows)
            return new(RemovalMethod.Winget, program?.Name ?? "");

        if (!string.IsNullOrWhiteSpace(catalogueRecipe))
            return new(RemovalMethod.Catalogue, catalogueRecipe!.Trim());

        return new(RemovalMethod.Unresolvable, "");
    }

    /// <summary>
    /// Classify a still-present-after-attempt failure. hard = OS/MDM/Store-protected
    /// (surface as a finding, no retry); transient = retry next cycle. Mirrors the
    /// macOS classify_failure (System-protected / non-writable → hard).
    /// </summary>
    public static RemovalOutcome ClassifyStillPresent(InstalledProgram? program)
    {
        // A system component, or a baseline app that slipped through, is OS-protected.
        if (program is not null &&
            (program.SystemComponent || BaselineProtection.IsProtected(program.Name, program.Publisher)))
            return RemovalOutcome.FailedHard;

        return RemovalOutcome.FailedTransient;
    }

    /// <summary>Map a clean verify result (gone/residual) to its outcome.</summary>
    public static RemovalOutcome OutcomeFor(VerifyResult verify) => verify switch
    {
        VerifyResult.Gone     => RemovalOutcome.Removed,
        VerifyResult.Residual => RemovalOutcome.RemovedResidual,
        _                     => RemovalOutcome.Unknown,
    };
}
