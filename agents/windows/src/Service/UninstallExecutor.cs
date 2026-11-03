// DEPRECATED — PAT-1531: retained source for a separately reviewed future boundary;
// excluded from the Windows assurance-only Service build.
using System.Diagnostics;
using System.Runtime.Versioning;
using Patched.Shared.Removal;

namespace Patched.Service;

/// <summary>
/// Runs the resolved removal method under the privileged service account, with a
/// hard timeout (kill-on-expiry) so a UI-bound uninstaller can't wedge the run.
/// Also handles running-process detection + graceful close. Mirrors the macOS
/// engine's execute_uninstall / is_running / request_quit. The exit code is logged
/// only — success is judged by re-inspection (see <see cref="RemovalRunner"/>),
/// never by the exit code.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class UninstallExecutor
{
    private static readonly TimeSpan ExecTimeout      = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan QuitGrace        = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan QuitPollInterval = TimeSpan.FromSeconds(2);

    private readonly ILogger<UninstallExecutor> _log;

    public UninstallExecutor(ILogger<UninstallExecutor> log) => _log = log;

    /// <summary>True if a process backed by this app appears to be running.</summary>
    public bool IsRunning(string appName, string? installLocation)
    {
        foreach (var proc in Processes())
        {
            try
            {
                if (!string.IsNullOrEmpty(installLocation))
                {
                    var path = SafeModulePath(proc);
                    if (path is not null &&
                        path.StartsWith(installLocation.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                if (proc.ProcessName.Contains(appName, StringComparison.OrdinalIgnoreCase) ||
                    appName.Contains(proc.ProcessName, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch { /* process exited / access denied — ignore */ }
            finally { proc.Dispose(); }
        }
        return false;
    }

    /// <summary>
    /// Ask matching processes to close and wait up to the grace window.
    /// Returns true if everything closed (safe to proceed), false if still running
    /// (caller defers to next cycle). Never force-kills user apps — that's the
    /// macOS request_quit contract.
    /// </summary>
    public async Task<bool> RequestCloseAndWaitAsync(string appName, string? installLocation, CancellationToken ct)
    {
        foreach (var proc in MatchingProcesses(appName, installLocation))
        {
            try { proc.CloseMainWindow(); } catch { }
            proc.Dispose();
        }

        var waited = TimeSpan.Zero;
        while (waited < QuitGrace)
        {
            if (!IsRunning(appName, installLocation)) return true;
            await Task.Delay(QuitPollInterval, ct).ConfigureAwait(false);
            waited += QuitPollInterval;
        }
        return !IsRunning(appName, installLocation);
    }

    /// <summary>Does winget have a package matching this name? (CLI fallback gate.)</summary>
    public async Task<bool> WingetKnowsAsync(string appName, CancellationToken ct)
    {
        var winget = FindWinget();
        if (winget is null) return false;
        var (code, output) = await RunAsync(winget,
            ["list", "--name", appName, "--accept-source-agreements", "--disable-interactivity"],
            ct).ConfigureAwait(false);
        // winget exits non-zero / prints "No installed package found" when there's no match.
        return code == 0 && output is not null &&
               !output.Contains("No installed package", StringComparison.OrdinalIgnoreCase) &&
               !output.Contains("No package found", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Execute the resolved method. Returns the process exit code (logging only).</summary>
    public async Task<int> ExecuteAsync(ResolvedMethod resolved, string appName, CancellationToken ct)
    {
        switch (resolved.Method)
        {
            case RemovalMethod.Msi:
                return await RunWithTimeoutAsync("msiexec.exe",
                    ["/x", resolved.Detail, "/qn", "/norestart"], ct).ConfigureAwait(false);

            case RemovalMethod.Winget:
                var winget = FindWinget();
                if (winget is null) { _log.LogError("winget.exe not found for uninstall"); return -1; }
                return await RunWithTimeoutAsync(winget,
                    ["uninstall", "--name", appName, "--silent", "--disable-interactivity",
                     "--accept-source-agreements"], ct).ConfigureAwait(false);

            case RemovalMethod.RegistryQuietUninstall:
            case RemovalMethod.RegistryUninstall:
            case RemovalMethod.Catalogue:
                // The detail is a full command line. Parse it into an executable +
                // argument list and launch the executable DIRECTLY (no cmd.exe), so
                // shell metacharacters in a vendor-controlled UninstallString can't
                // execute under the SYSTEM service account (PAT-687).
                return await RunParsedCommandLineAsync(resolved.Detail, ct).ConfigureAwait(false);

            default:
                _log.LogWarning("ExecuteAsync called with non-executable method {Method}", resolved.Method);
                return -1;
        }
    }

    // ----- process helpers -------------------------------------------------

    private static IEnumerable<Process> Processes()
    {
        try { return Process.GetProcesses(); }
        catch { return []; }
    }

    private IEnumerable<Process> MatchingProcesses(string appName, string? installLocation)
    {
        var matches = new List<Process>();
        foreach (var proc in Processes())
        {
            bool keep = false;
            try
            {
                if (!string.IsNullOrEmpty(installLocation))
                {
                    var path = SafeModulePath(proc);
                    if (path is not null &&
                        path.StartsWith(installLocation.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                        keep = true;
                }
                if (!keep && proc.ProcessName.Contains(appName, StringComparison.OrdinalIgnoreCase))
                    keep = true;
            }
            catch { }
            if (keep) matches.Add(proc); else proc.Dispose();
        }
        return matches;
    }

    private static string? SafeModulePath(Process proc)
    {
        try { return proc.MainModule?.FileName; } catch { return null; }
    }

    // ----- process runners -------------------------------------------------

    private Task<int> RunParsedCommandLineAsync(string commandLine, CancellationToken ct)
    {
        var parsed = Patched.Shared.Removal.WindowsCommandLine.Parse(commandLine);
        if (parsed is not { } p || string.IsNullOrWhiteSpace(p.Executable))
        {
            _log.LogError("Uninstall command line was empty or unparseable");
            return Task.FromResult(-1);
        }

        // Launch the uninstaller executable directly with a discrete argument list.
        // No cmd.exe, no shell — metacharacters in the registry UninstallString are
        // inert (passed as literal argv entries, not interpreted).
        return RunWithTimeoutAsync(p.Executable, [.. p.Arguments], ct);
    }

    private Task<int> RunWithTimeoutAsync(string fileName, string[] args, CancellationToken ct) =>
        RunWithTimeoutAsync(fileName, rawArguments: null, args: args, ct);

    private async Task<int> RunWithTimeoutAsync(
        string fileName, string? rawArguments, string[]? args, CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(ExecTimeout);
        try
        {
            var (code, _) = await RunAsync(fileName, args, rawArguments, timeoutCts.Token)
                .ConfigureAwait(false);
            return code;
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            _log.LogWarning("Uninstall '{File}' exceeded {Timeout} — killed", fileName, ExecTimeout);
            return -2;   // timeout sentinel; verify step decides the real outcome
        }
    }

    private Task<(int code, string? output)> RunAsync(string fileName, string[] args, CancellationToken ct) =>
        RunAsync(fileName, args, null, ct);

    private async Task<(int code, string? output)> RunAsync(
        string fileName, string[]? args, string? rawArguments, CancellationToken ct)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName               = fileName,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };
            if (rawArguments is not null) proc.StartInfo.Arguments = rawArguments;
            if (args is not null)
                foreach (var a in args) proc.StartInfo.ArgumentList.Add(a);

            proc.Start();
            var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
            _ = proc.StandardError.ReadToEndAsync(ct);
            try
            {
                await proc.WaitForExitAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                throw;
            }
            var stdout = await stdoutTask.ConfigureAwait(false);
            return (proc.ExitCode, stdout);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to run {File}", fileName);
            return (-1, null);
        }
    }

    private static string? FindWinget()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrEmpty(localAppData))
        {
            var alias = Path.Combine(localAppData, @"Microsoft\WindowsApps\winget.exe");
            if (File.Exists(alias)) return alias;
        }
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "")
                             .Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(dir.Trim(), "winget.exe");
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }
}
