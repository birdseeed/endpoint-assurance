using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Win32;
using Patched.Shared.Contract;
using Patched.Shared.InstallationEvidence;

namespace Patched.Service;

// PAT-2116: the all-apps Authenticode coverage helper and its parent-side runner.
//
// The parent (the service) passes only row indexes, ARP subkey names and the registry view
// on stdin, plus its verdict cache. The helper reads DisplayIcon and InstallLocation from
// HKLM itself, resolves one executable per row with ExecutableResolver, and reads it through
// WindowsInstallationEvidence.ReadResolved: the same locked, reparse-refusing, offline path
// the reviewed-target helper uses. No path and no command line crosses argv, nothing
// observed is executed, and the helper writes nothing to disk. It prints one JSON line per
// step so the parent can bound each target and kill a helper that hangs.
[SupportedOSPlatform("windows")]
internal static class AppSignatureCoverageProbe
{
    internal const string Command = "--collect-app-signatures";
    private const int MaximumRequestChars = 4 * 1024 * 1024;

    private static readonly string[] UninstallPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];

    // Parent memory only (see SignatureVerdictCache).
    internal static readonly SignatureVerdictCache Cache = new();

    // ---- helper (child) side ----

    internal static int RunCommand(string[] args, TextReader input, TextWriter output)
    {
        if (args.Length != 1 || args[0] != Command) return 2;
        var request = ParseRequest(input);
        if (request is null) return 2;
        var context = SignatureProbeContext.Production(request.Cache);
        Run(request, ProductionRoots(), ReadUninstallLocation, WindowsInstallationEvidence.ListExecutables,
            (resolution, target) => WindowsInstallationEvidence.ReadResolved(resolution.InstallPath!,
                resolution.ExecutablePath!, resolution.Method!, context),
            line =>
            {
                output.Write(JsonSerializer.Serialize(line));
                output.Write('\n');
                output.Flush();
            },
            MsiComponentReader.ExecutableKeyPaths);
        return 0;
    }

    // The helper's whole run with every IO seam injected, so the ordering of step and result
    // lines (which is what makes a hang attributable) is covered off Windows.
    internal static void Run(CoverageRequest request, ResolutionRoots roots,
        Func<CoverageTarget, UninstallLocation> readLocation,
        Func<string, IReadOnlyList<string>?> listExecutables,
        Func<ExecutableResolution, CoverageTarget, WindowsInstallationEvidence.ResolvedEvidence> readEvidence,
        Action<CoverageLine> emit,
        Func<string, IReadOnlyList<string>?>? msiComponentExecutables = null)
    {
        var stuck = request.Stuck.ToHashSet();
        var completed = request.Completed.ToHashSet();
        var targets = request.Targets.Where(t => !stuck.Contains(t.Index)).ToArray();
        var byIndex = targets.ToDictionary(t => t.Index);
        var locations = new List<UninstallLocation>();
        var unreadable = new List<int>();
        foreach (var target in targets)
        {
            emit(new() { Kind = CoverageLine.Step, Index = target.Index });
            try
            {
                locations.Add(readLocation(target) with { Index = target.Index });
            }
            catch { unreadable.Add(target.Index); }
        }

        // Every listing and MSI package read happens inside ResolveAll, after the step line
        // for its entry, so a hang there is attributable too.
        var resolutions = ExecutableResolver.ResolveAll(locations, roots, listExecutables,
            index => emit(new() { Kind = CoverageLine.Step, Index = index }), msiComponentExecutables);

        foreach (var index in unreadable.Where(i => !completed.Contains(i)))
            emit(new() { Kind = CoverageLine.Result, Index = index, Evidence = AppInstallationEvidence.Unavailable("registry_read_unavailable")
                with { ExecutableResolution = ExecutableResolutions.RegistryUnavailable } });

        foreach (var resolution in resolutions.Where(r => !completed.Contains(r.Index)))
        {
            if (!resolution.Resolved)
            {
                emit(new() { Kind = CoverageLine.Result, Index = resolution.Index,
                    Evidence = AppInstallationEvidence.Unavailable(resolution.Error ?? "executable_unresolved")
                        with { ExecutableResolution = resolution.Code } });
                continue;
            }
            emit(new() { Kind = CoverageLine.Step, Index = resolution.Index });
            WindowsInstallationEvidence.ResolvedEvidence read;
            try { read = readEvidence(resolution, byIndex[resolution.Index]); }
            catch
            {
                read = new(AppInstallationEvidence.Unavailable("file_read_unavailable") with
                    { ExecutableResolution = resolution.Method });
            }
            emit(new()
            {
                Kind = CoverageLine.Result,
                Index = resolution.Index,
                Evidence = read.Evidence,
                CacheKey = read.CacheKey,
                CacheObservation = read.CacheObservation,
            });
        }
        emit(new() { Kind = CoverageLine.Done });
    }

    internal static CoverageRequest? ParseRequest(TextReader input)
    {
        try
        {
            var buffer = new char[MaximumRequestChars + 1];
            var count = 0;
            int read;
            while (count < buffer.Length && (read = input.Read(buffer, count, buffer.Length - count)) > 0) count += read;
            if (count > MaximumRequestChars) return null;
            var request = JsonSerializer.Deserialize<CoverageRequest>(new string(buffer, 0, count));
            if (request?.Targets is null || request.Completed is null || request.Stuck is null || request.Cache is null ||
                request.Targets.Count > ExecutableResolver.MaximumTargets ||
                request.Cache.Count > SignatureVerdictCache.Capacity ||
                request.Targets.Any(t => t is null || t.Index < 0 || !AppSignatureCoverage.ValidIdentifier(t.Identifier)) ||
                request.Targets.Select(t => t.Index).Distinct().Count() != request.Targets.Count)
                return null;
            return request;
        }
        catch { return null; }
    }

    internal static ResolutionRoots ProductionRoots()
    {
        var roots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetEnvironmentVariable("ProgramW6432") ?? "",
            }
            .Where(r => r.Length >= 4 && WindowsInstallationEvidence.IsSafePath(r))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return new(Environment.GetFolderPath(Environment.SpecialFolder.Windows), roots);
    }

    // Read-only HKLM values from the same Uninstall view the scanner read the row from.
    // A missing key or a non-string value is a hint that is not there, not a failure.
    private static UninstallLocation ReadUninstallLocation(CoverageTarget target)
    {
        using var key = Registry.LocalMachine.OpenSubKey(UninstallPaths[target.Wow6432 ? 1 : 0] + "\\" + target.Identifier)
            ?? throw new InvalidOperationException("uninstall_key_missing");
        return UninstallLocationFrom(target, name => key.GetValue(name));
    }

    // PAT-2129: the values ExecutableResolver reads, from one Uninstall key. The MSI product
    // code is the subkey name itself, used only when the entry says WindowsInstaller=1 and
    // the name is a braced GUID; it is never read from a value.
    internal static UninstallLocation UninstallLocationFrom(CoverageTarget target, Func<string, object?> value) =>
        new(target.Index, value("DisplayIcon") as string, value("InstallLocation") as string)
        {
            DisplayName = value("DisplayName") as string,
            Publisher = value("Publisher") as string,
            UninstallString = value("UninstallString") as string,
            BurnBundle = value("BundleProviderKey") is string provider && !string.IsNullOrWhiteSpace(provider),
            MsiProductCode = value("WindowsInstaller") is int installer && installer == 1 &&
                MsiComponentReader.IsProductCode(target.Identifier) ? target.Identifier : null,
        };

    // ---- parent side ----

    internal static async Task<CoverageSession> RunSessionAsync(CoverageRequest request, TimeSpan budget,
        Action<InstallationEvidenceProbe.HelperPreflightRefusal?>? onPreflight = null)
    {
        var start = InstallationEvidenceProbe.PrepareTrustedHelper(Command, out var lockedSelf, out var refusal);
        onPreflight?.Invoke(refusal);
        if (start is null) return new([], CoverageSessionEnd.PreflightRefused, null);
        using (lockedSelf)
        {
            start.RedirectStandardInput = true;
            Process? process = null;
            try
            {
                process = Process.Start(start);
                if (process is null) return new([], CoverageSessionEnd.Failed, null);
                var stderr = DrainAsync(process.StandardError);
                var payload = JsonSerializer.Serialize(request);
                var write = WriteRequestAsync(process.StandardInput, payload);
                if (await Task.WhenAny(write, Task.Delay(budget)).ConfigureAwait(false) != write)
                    return new([], CoverageSessionEnd.BudgetExhausted, null);
                await write.ConfigureAwait(false);
                var session = await AppSignatureCoverage.ReadSessionAsync(process.StandardOutput,
                    AppSignatureCoverage.StepTimeout, budget).ConfigureAwait(false);
                _ = stderr;
                return session;
            }
            catch { return new([], CoverageSessionEnd.Failed, null); }
            finally
            {
                if (process is not null)
                {
                    try
                    {
                        if (!process.HasExited)
                        {
                            process.Kill(entireProcessTree: true);
                            using var terminationDeadline = new CancellationTokenSource(InstallationEvidenceProbe.TerminationGrace);
                            await process.WaitForExitAsync(terminationDeadline.Token).ConfigureAwait(false);
                        }
                    }
                    catch { /* Results already read stand; never wait without a deadline. */ }
                    process.Dispose();
                }
            }
        }
    }

    private static async Task WriteRequestAsync(StreamWriter input, string payload)
    {
        await input.WriteAsync(payload).ConfigureAwait(false);
        await input.FlushAsync().ConfigureAwait(false);
        input.Close();
    }

    // stderr is drained so a chatty helper can never block on a full pipe; its content is
    // discarded unread (it may carry paths, which never leave the device).
    private static async Task DrainAsync(StreamReader reader)
    {
        try
        {
            var buffer = new char[1024];
            while (await reader.ReadAsync(buffer).ConfigureAwait(false) > 0) { }
        }
        catch { /* The process is being killed or has exited. */ }
    }
}
