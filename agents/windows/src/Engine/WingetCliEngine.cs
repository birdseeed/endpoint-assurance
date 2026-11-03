using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Patched.Shared.Config;
using Patched.Shared.Paths;
using Patched.Shared.Security;

namespace Patched.Engine;

/// <summary>
/// IPackageEngine implementation using the winget CLI.
/// Replaces WingetComEngine for ARM64 unpackaged .NET apps where the WinRT
/// Microsoft.Management.Deployment COM projection is unresolvable. (PAT-352)
/// </summary>
public sealed class WingetCliEngine : IPackageEngine
{
    private readonly ILogger<WingetCliEngine> _logger;

    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    public WingetCliEngine(ILogger<WingetCliEngine> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// True if winget.exe can be located on this host (user-level App Installer
    /// alias or PATH). Used by <see cref="FallbackPackageEngine"/> to decide
    /// whether to route package operations through Chocolatey instead — winget
    /// is absent on some LTSC/Server images that lack the App Installer package.
    /// </summary>
    public static bool IsAvailable() => FindWinget() is not null;

    public async Task<PackageCheckResult> CheckAsync(string packageId, CancellationToken ct)
    {
        string? installedVersion = null;
        string? availableVersion = null;

        // winget list --output json returns an array of installed entries.
        var listJson = await RunAsync(
            ["list", "--id", packageId, "--exact", "--source", "winget",
             "--accept-source-agreements", "--disable-interactivity", "--output", "json"],
            ct);

        if (listJson is not null)
        {
            try
            {
                var entries = JsonSerializer.Deserialize<ListEntry[]>(listJson, JsonOpts);
                var match = entries?.FirstOrDefault(e =>
                    string.Equals(e.Id, packageId, StringComparison.OrdinalIgnoreCase));
                if (match is not null)
                {
                    installedVersion = match.Version;
                    availableVersion = match.Available;
                }
            }
            catch (JsonException ex)
            {
                _logger.LogWarning(ex, "Failed to parse winget list JSON for {PackageId}", packageId);
            }
        }

        // winget show gives the store-side available version (even when not installed).
        if (availableVersion is null)
        {
            var showText = await RunAsync(
                ["show", "--id", packageId, "--exact", "--source", "winget",
                 "--accept-source-agreements", "--disable-interactivity"],
                ct);

            if (showText is not null)
            {
                var versionLine = showText.Split('\n')
                    .FirstOrDefault(l => l.StartsWith("Version:", StringComparison.OrdinalIgnoreCase));
                availableVersion = versionLine?.Split(':', 2).ElementAtOrDefault(1)?.Trim();
            }
        }

        return new PackageCheckResult
        {
            PackageId        = packageId,
            IsInstalled      = installedVersion is not null,
            InstalledVersion = installedVersion,
            AvailableVersion = availableVersion,
        };
    }

    /// <summary>
    /// Downloads the package installer to a hardened staging directory so the caller can
    /// Authenticode-verify it before allowing <see cref="InstallAsync"/>.
    /// Returns null (blocking install) if winget cannot download or no installer
    /// file is found.
    ///
    /// PAT-857: this used to stage into a fully deterministic path under
    /// <c>Path.GetTempPath()</c> — for the LocalSystem service that's C:\Windows\Temp,
    /// which any authenticated user can create subdirectories in. A standard user could
    /// pre-create the (predictable, packageId-derived) directory or plant a reparse
    /// point there before the service ever ran, TOCTOU-ing the file we're about to trust.
    /// Staging now happens under a SYSTEM/Administrators-only root
    /// (<see cref="PathConstants.StagingDir"/>), in a freshly randomised subdirectory
    /// that's hardened and verified (not a reparse point, correctly owned) before winget
    /// is ever told to write into it. If either check fails the download is aborted —
    /// fail closed, never "fixed" in place.
    /// </summary>
    public async Task<string?> ResolveInstallPathAsync(string packageId, CancellationToken ct)
    {
        string tmpDir;
        try
        {
            var root = Path.Combine(PathConstants.StagingDir, "winget");
            SecureStagingDirectory.EnsureHardenedChain(root, PathConstants.StateDir);
            tmpDir = SecureStagingDirectory.CreateRandomSubdirectory(root);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            // Fail closed on ANY staging-directory problem, not just an explicit
            // UntrustedDirectoryException — ACL/IO failures (e.g. UnauthorizedAccessException,
            // IOException from a full disk) must block this install, not crash the caller.
            _logger.LogError(ex, "Refusing to stage winget download for {PackageId}: could not prepare a trusted staging directory", packageId);
            return null;
        }

        var output = await RunAsync(
            ["download", "--id", packageId, "--exact", "--source", "winget",
             "--download-directory", tmpDir,
             "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"],
            ct);

        if (output is null)
        {
            _logger.LogWarning("winget download failed for {PackageId}", packageId);
            return null;
        }

        var installer = Directory
            .EnumerateFiles(tmpDir, "*", SearchOption.AllDirectories)
            .FirstOrDefault(f => Path.GetExtension(f).ToLowerInvariant()
                is ".exe" or ".msi" or ".msix" or ".msixbundle");

        if (installer is null)
            _logger.LogWarning("winget download produced no installer for {PackageId}", packageId);

        return installer;
    }

    /// <summary>
    /// Install or update a package via winget CLI, respecting the tenant-configured
    /// blocking-process action (PAT-296).
    ///
    /// Blocking-process mapping to winget flags:
    ///   NotifyOnly      — winget runs non-interactively; if a blocking process is
    ///                     detected winget will exit with a non-zero code. The agent
    ///                     treats this as a deferred run and does NOT force-quit.
    ///   PromptThenQuit  — winget is invoked without --disable-interactivity so it
    ///                     can send a close-app notification via Windows toast if a
    ///                     blocking process is found. Still not a silent force-quit.
    ///   SkipRun         — install is not attempted; caller should have skipped before
    ///                     reaching this path, but the flag is honoured defensively.
    ///
    /// The agent MUST NEVER call Process.Kill on a user app — any "force quit" is
    /// winget-mediated and requires the user to have seen a notification first.
    /// </summary>
    public async Task<PackageInstallResult> InstallAsync(
        string                packageId,
        CancellationToken     ct,
        BlockingProcessAction blockingAction = BlockingProcessAction.NotifyOnly,
        string?               pinnedVersion  = null)
    {
        // SkipRun: caller should not reach here but honour defensively.
        if (blockingAction == BlockingProcessAction.SkipRun)
        {
            _logger.LogInformation(
                "BlockingProcess: {PackageId} action=SkipRun — not attempting install", packageId);
            return new PackageInstallResult
            {
                PackageId    = packageId,
                Success      = false,
                ErrorMessage = "blocking_process_action=skip_run — install deferred to next run",
            };
        }

        // H6: pin the install to the exact version that was resolved + verified
        // (Authenticode + SHA-256) by ResolveInstallPathAsync. Without --version,
        // `winget install` re-resolves the *latest* version from the live source,
        // which can be a different artifact than the one we verified. Pinning the
        // version makes winget resolve the same manifest, whose installer SHA-256
        // winget itself enforces on download — so the executed artifact matches
        // what was verified.
        var args = new List<string>
        {
            "install", "--id", packageId, "--exact", "--source", "winget",
            "--silent", "--accept-package-agreements", "--accept-source-agreements",
        };
        if (!string.IsNullOrEmpty(pinnedVersion))
        {
            args.Add("--version");
            args.Add(pinnedVersion);
        }
        // For NotifyOnly: keep --disable-interactivity so winget exits cleanly if
        // blocked; the agent records the deferred state without force-quitting.
        // For PromptThenQuit: drop --disable-interactivity to allow winget to send
        // the close-app toast notification; winget handles the escalation, not us.
        if (blockingAction != BlockingProcessAction.PromptThenQuit)
            args.Add("--disable-interactivity");

        var (exitCode, output) = await RunWithExitCodeAsync(args.ToArray(), ct);

        return new PackageInstallResult
        {
            PackageId    = packageId,
            Success      = exitCode == 0,
            ErrorMessage = exitCode == 0 ? null
                : $"winget install exited {exitCode}: {output?.Trim()}",
        };
    }

    private Task<string?> RunAsync(string[] args, CancellationToken ct) =>
        RunWithExitCodeAsync(args, ct).ContinueWith(t => t.Result.output, ct);

    private async Task<(int exitCode, string? output)> RunWithExitCodeAsync(
        string[] args, CancellationToken ct)
    {
        var winget = FindWinget();
        if (winget is null)
        {
            _logger.LogError("winget.exe not found on this system");
            return (-1, null);
        }

        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName               = winget,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };
            foreach (var arg in args)
                proc.StartInfo.ArgumentList.Add(arg);

            proc.Start();
            var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
            _ = proc.StandardError.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct);
            var stdout = await stdoutTask;

            if (proc.ExitCode != 0)
                _logger.LogDebug("winget {Args} exited {Code}", string.Join(' ', args), proc.ExitCode);

            return (proc.ExitCode, stdout);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to run winget {Args}", string.Join(' ', args));
            return (-1, null);
        }
    }

    private static string? FindWinget()
    {
        // User-level App Installer alias (works for interactive user accounts)
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrEmpty(localAppData))
        {
            var alias = Path.Combine(localAppData, @"Microsoft\WindowsApps\winget.exe");
            if (File.Exists(alias)) return alias;
        }

        // PATH fallback (covers service accounts with winget on PATH)
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "")
                             .Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(dir.Trim(), "winget.exe");
            if (File.Exists(candidate)) return candidate;
        }

        return null;
    }

    private sealed class ListEntry
    {
        public string? Id        { get; set; }
        public string? Version   { get; set; }
        public string? Available { get; set; }
    }
}
