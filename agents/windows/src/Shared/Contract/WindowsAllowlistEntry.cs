using System.Text.Json.Serialization;

namespace Patched.Shared.Contract;

/// <summary>
/// One entry in windows-allowlist.json — the Windows analog of labels-allowlist.txt.
/// Maps a label (shared with macOS) to a winget package ID and expected Authenticode publisher.
/// </summary>
public sealed record WindowsAllowlistEntry
{
    [JsonPropertyName("label")]
    public required string Label { get; init; }

    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("winget_id")]
    public required string WingetId { get; init; }

    /// <summary>
    /// Expected Authenticode Subject CN / publisher name. Verification fails if mismatch.
    /// </summary>
    [JsonPropertyName("expected_publisher")]
    public required string ExpectedPublisher { get; init; }

    [JsonPropertyName("tier")]
    public string? Tier { get; init; }

    /// <summary>Hex SHA-256 of the pinned installer; when set, post-download verification is mandatory.</summary>
    [JsonPropertyName("pinned_sha256")]
    public string? PinnedSha256 { get; init; }

    // ---------------------------------------------------------------------
    // PAT-823: mirror fields — the Windows analog of the macOS label.schema.json
    // mirror block. When Mirror=true the agent fetches the installer from the
    // Patched-controlled CDN (MirrorUrl) over HTTPS and runs it directly, instead
    // of shelling out to winget/choco against the public vendor source. Non-mirror
    // entries keep today's winget-CLI behaviour unchanged.
    // ---------------------------------------------------------------------

    /// <summary>
    /// Installer packaging type. The mirror-execute path supports two families:
    /// msiexec-installable "msi" and "wix" (a WiX-toolset-built .msi — winget's
    /// InstallerType label for it, not a distinct package format) via the uniform
    /// `msiexec /i /quiet` switch; and, as of PAT-842, exe-family "exe"/"nullsoft"/
    /// "inno" via a silent invocation of the verified EXE itself (see
    /// <see cref="SilentArgs"/>). Any other type (msix, appx, burn, portable, zip, …)
    /// is refused fail-closed by the mirror-execute path.
    /// </summary>
    [JsonPropertyName("installer_type")]
    public string? InstallerType { get; init; }

    /// <summary>
    /// True if this app is served from the internal Patched mirror rather than
    /// the public winget/Chocolatey source. When true, <see cref="MirrorUrl"/>
    /// and <see cref="PinnedSha256"/> MUST both be set — the agent downloads from
    /// MirrorUrl and hard-verifies the bytes against PinnedSha256 before install.
    /// </summary>
    [JsonPropertyName("mirror")]
    public bool Mirror { get; init; }

    /// <summary>
    /// Public CDN URL of the pinned mirrored artifact. Written by the Windows
    /// mirror pipeline (ci/mirror_pipeline_windows.py) alongside pinned_sha256.
    /// Null until the first mirror run for this label completes.
    /// </summary>
    [JsonPropertyName("mirror_url")]
    public string? MirrorUrl { get; init; }

    /// <summary>
    /// Redistribution/licensing confirmed for the internal mirror of this app's
    /// *Windows* artifact. The mirror pipeline skips entries where this is false.
    /// The macOS EULA sign-off does not carry over — Windows is a separate pass.
    /// </summary>
    [JsonPropertyName("mirror_eula_approved")]
    public bool MirrorEulaApproved { get; init; }

    /// <summary>
    /// True if this label cannot be mirrored programmatically (auth-gated download,
    /// CDN hotlink protection, no public programmatic URL). The mirror pipeline
    /// skips vendor_only entries and they do not appear in the failure report.
    /// </summary>
    [JsonPropertyName("vendor_only")]
    public bool VendorOnly { get; init; }

    // ---------------------------------------------------------------------
    // PAT-840: pin-vendor mode — verify WITHOUT re-hosting. For
    // redistribution-restricted vendors (e.g. Google Chrome) we may not host the
    // installer, so the agent downloads directly from the vendor's own pinned
    // HTTPS URL, still hard-verifying PinnedSha256 + Authenticode publisher and
    // failing closed on any mismatch. winget/choco are never used for a pinned label.
    // ---------------------------------------------------------------------

    /// <summary>
    /// Install source mode: "mirror" (default when null — install from MirrorUrl on
    /// the Patched CDN) or "vendor_pinned" (install directly from PinnedUrl, the
    /// vendor's own HTTPS URL, without re-hosting). See <see cref="IsVendorPinned"/>.
    /// </summary>
    [JsonPropertyName("install_mode")]
    public string? InstallMode { get; init; }

    /// <summary>
    /// vendor_pinned mode — the first-party, vendor-owned HTTPS URL the agent
    /// downloads from (never mirror.patched.im). Written by the mirror pipeline
    /// alongside <see cref="PinnedSha256"/>. Null until the first pipeline run pins
    /// it; the agent fails closed on a vendor_pinned entry with no PinnedUrl.
    /// </summary>
    [JsonPropertyName("pinned_url")]
    public string? PinnedUrl { get; init; }

    /// <summary>
    /// vendor_pinned mode — the resolved vendor version PinnedSha256/PinnedUrl
    /// correspond to (provenance/audit). Null until the first pipeline run.
    /// </summary>
    [JsonPropertyName("pinned_version")]
    public string? PinnedVersion { get; init; }

    /// <summary>
    /// True when this entry is served in pin-vendor mode (install_mode=vendor_pinned):
    /// download from <see cref="PinnedUrl"/> directly, verify, install — never re-host,
    /// never winget/choco fallback.
    /// </summary>
    [JsonIgnore]
    public bool IsVendorPinned =>
        string.Equals(InstallMode, "vendor_pinned", System.StringComparison.OrdinalIgnoreCase);

    // ---------------------------------------------------------------------
    // PAT-842: EXE-family installer support (exe/nullsoft/inno) — mirror and
    // vendor_pinned entries whose installer_type is not msiexec-installable.
    // The verification chain (HTTPS + pinned_sha256 + Authenticode) is
    // identical to msi/wix; only the execute step differs (a silent-install
    // invocation instead of msiexec).
    // ---------------------------------------------------------------------

    /// <summary>
    /// Silent-install command-line flags for exe-family installers (exe, nullsoft,
    /// inno). Required (or resolvable via a framework default — nullsoft: "/S",
    /// inno: "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-") for exe-family
    /// installer_types. A generic "exe" with no override and no framework default
    /// fails closed rather than guessing flags. Ignored for msi/wix (msiexec's
    /// switches are fixed).
    /// </summary>
    [JsonPropertyName("silent_args")]
    public string? SilentArgs { get; init; }

    /// <summary>
    /// Optional list of process exit codes treated as success for an exe-family
    /// install, beyond the runner's default {0, 3010}. Some vendor installers
    /// return a benign non-zero code (e.g. "already installed"); listing it here
    /// avoids misreporting that as a failure. Ignored for msi/wix.
    /// </summary>
    [JsonPropertyName("success_exit_codes")]
    public int[]? SuccessExitCodes { get; init; }
}
