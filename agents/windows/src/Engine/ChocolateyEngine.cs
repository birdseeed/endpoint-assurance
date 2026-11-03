using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Patched.Shared.Paths;
using Patched.Shared.Security;

namespace Patched.Engine;

/// <summary>
/// Chocolatey fallback engine — used when winget.exe is not present on the host
/// (LTSC/Server images that lack the App Installer package). Implements the same
/// <see cref="IPackageEngine"/> interface as <see cref="WingetCliEngine"/>.
///
/// PAT-304: Chocolatey is a fallback only, selected by <see cref="FallbackPackageEngine"/>
/// (PAT-344) — <see cref="WingetCliEngine"/> is always tried first. Only packages in the
/// curated allowlist are ever touched.
///
/// NOTE: Chocolatey is invoked via its CLI because there is no stable managed API
/// analogous to winget's COM projection (and that projection is itself unusable for
/// unpackaged ARM64 .NET — PAT-344/PAT-352). The install path for verification is
/// resolved from Chocolatey's package download cache before execution.
/// </summary>
public sealed class ChocolateyEngine : IPackageEngine
{
    private const string ChocoExe = @"C:\ProgramData\chocolatey\bin\choco.exe";

    private readonly ILogger<ChocolateyEngine> _log;
    private readonly AllowlistLoader           _allowlist;

    public ChocolateyEngine(ILogger<ChocolateyEngine> log, AllowlistLoader allowlist)
    {
        _log       = log;
        _allowlist = allowlist;
    }

    public static bool IsAvailable() =>
        File.Exists(ChocoExe);

    public async Task<PackageCheckResult> CheckAsync(string packageId, CancellationToken ct)
    {
        AssertAllowlisted(packageId);

        // choco list <id> --local-only --exact
        var (installed, _) = await RunChocoAsync($"list {packageId} --local-only --exact --limit-output", ct);
        var installedVer = ParseChocoVersion(installed, packageId);

        // choco outdated <id>
        var (outdated, _) = await RunChocoAsync($"outdated --id {packageId} --limit-output", ct);
        var availableVer = ParseChocoOutdatedVersion(outdated, packageId);

        return new PackageCheckResult
        {
            PackageId        = packageId,
            IsInstalled      = installedVer is not null,
            InstalledVersion = installedVer,
            AvailableVersion = availableVer ?? installedVer,
        };
    }

    public async Task<string?> ResolveInstallPathAsync(string packageId, CancellationToken ct)
    {
        AssertAllowlisted(packageId);

        // PAT-857: Chocolatey's default download cache is %TEMP%\chocolatey\<pkg>\ — for
        // the LocalSystem service that's C:\Windows\Temp, a directory any authenticated
        // user can create subdirectories in. A predictable, packageId-derived path there
        // is the same class of TOCTOU as the winget staging bug: a standard user could
        // pre-plant a directory (or reparse point) before choco ever ran, and the
        // newest-mtime file selection below would then hash whatever they planted for
        // the SHA-256 check. InstallAsync now points choco's cache at a
        // SYSTEM/Administrators-only staging directory via --cache-location; this reads
        // back from that same hardened, verified directory instead of %TEMP%.
        var cache = GetStagingDir(packageId);
        try
        {
            SecureStagingDirectory.EnsureHardenedChain(cache, PathConstants.StateDir);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            // Fail closed on ANY staging-directory problem, not just an explicit
            // UntrustedDirectoryException — ACL/IO failures must block the SHA-256
            // check running against an unverifiable location, not crash the caller.
            _log.LogError(ex, "Refusing to resolve Chocolatey install path for {PackageId}: could not prepare a trusted staging directory", packageId);
            return null;
        }

        if (Directory.Exists(cache))
        {
            var installer = Directory
                .GetFiles(cache, "*.exe", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(cache, "*.msi", SearchOption.AllDirectories))
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault();
            if (installer is not null)
                return installer;
        }

        await Task.CompletedTask;
        return null;
    }

    /// <summary>
    /// Hardened, per-package staging directory that <see cref="InstallAsync"/> points
    /// Chocolatey's <c>--cache-location</c> at, and <see cref="ResolveInstallPathAsync"/>
    /// reads back from. Deterministic (keyed only by the sanitised packageId) is safe
    /// here because the parent root is SYSTEM/Administrators-only — a standard user
    /// cannot create anything under it to pre-plant, unlike the old %TEMP% location.
    /// </summary>
    private static string GetStagingDir(string packageId)
    {
        var sanitized = string.Concat(packageId.Where(c => char.IsLetterOrDigit(c) || c is '.' or '-'));
        return Path.Combine(PathConstants.StagingDir, "chocolatey", sanitized);
    }

    public async Task<PackageInstallResult> InstallAsync(
        string packageId,
        CancellationToken ct,
        Patched.Shared.Config.BlockingProcessAction blockingAction = Patched.Shared.Config.BlockingProcessAction.NotifyOnly,
        string? pinnedVersion = null)
    {
        AssertAllowlisted(packageId);

        // PAT-857: point choco's download cache at our hardened staging directory
        // instead of letting it fall back to %TEMP%\chocolatey (see GetStagingDir /
        // ResolveInstallPathAsync). Fails closed if the staging directory can't be
        // trusted — never installs against an unverifiable cache location.
        var cacheDir = GetStagingDir(packageId);
        try
        {
            SecureStagingDirectory.EnsureHardenedChain(cacheDir, PathConstants.StateDir);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            // Fail closed on ANY staging-directory problem, not just an explicit
            // UntrustedDirectoryException.
            _log.LogError(ex, "Refusing to install {PackageId} via Chocolatey: could not prepare a trusted staging directory", packageId);
            return new PackageInstallResult
            {
                PackageId    = packageId,
                Success      = false,
                ErrorMessage = $"Chocolatey staging directory could not be prepared: {ex.Message}",
            };
        }

        _log.LogInformation("Installing {PackageId} via Chocolatey", packageId);
        // H6: pin to the verified version so choco cannot install a different
        // artifact than the one that was resolved + verified.
        var versionArg = string.IsNullOrEmpty(pinnedVersion) ? "" : $" --version {pinnedVersion}";
        var (output, exitCode) = await RunChocoAsync(
            $"install {packageId}{versionArg} --yes --no-progress --limit-output --cache-location=\"{cacheDir}\"", ct);

        if (exitCode != 0)
        {
            return new PackageInstallResult
            {
                PackageId    = packageId,
                Success      = false,
                ErrorMessage = $"choco install exited {exitCode}: {output?.Trim()}",
            };
        }

        // PAT-493 Item 3 / PAT-496: SHA-256 verification of the downloaded artifact.
        // Graceful degradation: if no hash is pinned in the allowlist for this package,
        // log a warning and proceed — the allowlist author has not yet pinned a hash.
        // When a hash IS pinned, mismatch is a hard failure (the install is rejected).
        var entry = _allowlist.FindByWingetId(packageId);
        if (entry?.PinnedSha256 is null)
        {
            _log.LogWarning(
                "PATCHED_POSTURE_WARNING label={Label} packageId={PackageId} reason=no_pinned_sha256 " +
                "message=SHA-256_verification_skipped_no_hash_in_allowlist",
                entry?.Label ?? packageId, packageId);
        }
        if (entry?.PinnedSha256 is not null)
        {
            var installerPath = await ResolveInstallPathAsync(packageId, ct);
            if (installerPath is null)
            {
                _log.LogError(
                    "PATCHED_VERIFICATION_FAILED label={Label} packageId={PackageId} reason=installer_not_found_for_sha256_check",
                    entry.Label, packageId);
                return new PackageInstallResult
                {
                    PackageId    = packageId,
                    Success      = false,
                    ErrorMessage = $"SHA-256 verification failed: installer not found in Chocolatey cache for '{packageId}'",
                };
            }

            var actualHash = ComputeSha256(installerPath);
            if (!actualHash.Equals(entry.PinnedSha256, StringComparison.OrdinalIgnoreCase))
            {
                _log.LogError(
                    "PATCHED_VERIFICATION_FAILED label={Label} packageId={PackageId} expected={Expected} actual={Actual} reason=sha256_mismatch",
                    entry.Label, packageId, entry.PinnedSha256, actualHash);
                return new PackageInstallResult
                {
                    PackageId    = packageId,
                    Success      = false,
                    ErrorMessage = $"SHA-256 mismatch for '{packageId}': expected {entry.PinnedSha256}, got {actualHash}",
                };
            }

            _log.LogInformation("SHA-256 verified for {PackageId}: {Hash}", packageId, actualHash);
        }

        var check = await CheckAsync(packageId, ct);
        return new PackageInstallResult
        {
            PackageId        = packageId,
            Success          = true,
            InstalledVersion = check.InstalledVersion,
        };
    }

    private async Task<(string? Output, int ExitCode)> RunChocoAsync(
        string args, CancellationToken ct)
    {
        if (!File.Exists(ChocoExe))
            throw new InvalidOperationException("Chocolatey is not installed");

        using var proc = new System.Diagnostics.Process();
        proc.StartInfo = new System.Diagnostics.ProcessStartInfo
        {
            FileName               = ChocoExe,
            Arguments              = args,
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute        = false,
            CreateNoWindow         = true,
        };
        proc.Start();
        var output = await proc.StandardOutput.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct);
        return (output, proc.ExitCode);
    }

    private static string? ParseChocoVersion(string? output, string packageId)
    {
        // Format: "packageId|version"
        if (output is null) return null;
        foreach (var line in output.Split('\n'))
        {
            var parts = line.Trim().Split('|');
            if (parts.Length >= 2 &&
                string.Equals(parts[0], packageId, StringComparison.OrdinalIgnoreCase))
                return parts[1].Trim();
        }
        return null;
    }

    private static string? ParseChocoOutdatedVersion(string? output, string packageId)
    {
        // Format: "packageId|installedVersion|availableVersion|pinned"
        if (output is null) return null;
        foreach (var line in output.Split('\n'))
        {
            var parts = line.Trim().Split('|');
            if (parts.Length >= 3 &&
                string.Equals(parts[0], packageId, StringComparison.OrdinalIgnoreCase))
                return parts[2].Trim();
        }
        return null;
    }

    internal static string ComputeSha256(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private void AssertAllowlisted(string packageId)
    {
        if (!_allowlist.IsAllowlisted(packageId))
            throw new InvalidOperationException(
                $"Package '{packageId}' is not in the curated allowlist. Blocked.");
    }
}
