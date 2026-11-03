using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Patched.Shared.Contract;
using Patched.Shared.InstallationEvidence;

namespace Patched.Service;

internal static class InstallationEvidenceProbe
{
    internal const string Command = "--collect-installation-evidence";
    private const int OutputLimit = 16384;
    internal static readonly TimeSpan TerminationGrace = TimeSpan.FromMilliseconds(250);

    // No file paths cross argv. Reverify the fixed protected signed cache, then bind
    // its delivery/hash to the parent's immutable snapshot before resolving an index.
    internal static int RunCommand(string[] args)
    {
        if (args.Length != 4 || args[0] != Command ||
            !int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out var index) ||
            !long.TryParse(args[2], NumberStyles.None, CultureInfo.InvariantCulture, out var version) ||
            index < 0 || index >= InstallationEvidenceCollector.MaximumTargets || version < 1 ||
            !InstallationEvidenceCatalogue.IsHash(args[3]))
            return 2;
        var catalogue = InstallationEvidenceStore.LoadForHelper();
        if (!MatchesBinding(catalogue, index, version, args[3])) return 2;
        var evidence = WindowsInstallationEvidence.Read(catalogue!.Targets[index]) with
        {
            CatalogueVersion = catalogue.CatalogueVersion,
            DeliveryVersion = catalogue.DeliveryVersion,
            ContentHash = catalogue.ContentHash,
        };
        Console.Out.Write(JsonSerializer.Serialize(evidence));
        return 0;
    }

    internal static bool MatchesBinding(InstallationEvidenceCatalogue? catalogue, int index, long version, string hash) =>
        catalogue is not null && index >= 0 && index < catalogue.Targets.Count &&
        catalogue.DeliveryVersion == version && catalogue.ContentHash == hash && catalogue.IsCurrent(DateTimeOffset.UtcNow);

    internal static async Task<AppInstallationEvidence> CollectAsync(InstallationEvidenceCatalogue catalogue,
        ReviewedInstallationTarget target, TimeSpan budget, Action<HelperPreflightRefusal?>? onPreflight = null)
    {
        var targets = catalogue.Targets;
        var index = Enumerable.Range(0, targets.Count).FirstOrDefault(i => targets[i] == target, -1);
        if (index < 0) return AppInstallationEvidence.Unavailable("reviewed_target_unavailable");
        if (!catalogue.IsCurrent(DateTimeOffset.UtcNow))
            return AppInstallationEvidence.Unavailable("catalogue_not_current");
        var start = PrepareTrustedHelper(Command, out var lockedSelf, out var refusal);
        onPreflight?.Invoke(refusal);
        if (start is null) return AppInstallationEvidence.Unavailable(PreflightRefused);
        using (lockedSelf)
        {
            try
            {
                start.ArgumentList.Add(index.ToString(CultureInfo.InvariantCulture));
                start.ArgumentList.Add(catalogue.DeliveryVersion.ToString(CultureInfo.InvariantCulture));
                start.ArgumentList.Add(catalogue.ContentHash);
                var result = await RunHelperAsync(start, budget).ConfigureAwait(false);
                return result.CollectionStatus == "unavailable" ||
                    (result.CatalogueVersion == catalogue.CatalogueVersion && result.DeliveryVersion == catalogue.DeliveryVersion &&
                        result.ContentHash == catalogue.ContentHash)
                    ? result : AppInstallationEvidence.Unavailable("helper_binding_mismatch");
            }
            catch { return AppInstallationEvidence.Unavailable("helper_failed"); }
        }
    }

    // PAT-2116: the helper was never started because a preflight check refused it. Distinct
    // from helper_failed (it started, then crashed or wrote garbage) and collection_timeout.
    internal const string PreflightRefused = "helper_preflight_refused";

    // Why a preflight refused. Reason is a fixed code (it goes to agent-health on the wire);
    // Detail (a principal and its rights, or a local path) goes to the local log only.
    internal sealed record HelperPreflightRefusal(string Reason, string? Detail);

    // The fixed, protected service executable as a helper: only its own Program Files path,
    // after read-only ACL/reparse checks, held open against replacement for the caller's
    // lifetime of lockedSelf. Null (and no lock) when any check fails, with the refusal;
    // never repairs an untrusted installation. Shared by both evidence helpers (PAT-2116).
    internal static ProcessStartInfo? PrepareTrustedHelper(string command, out IDisposable? lockedSelf,
        out HelperPreflightRefusal? refusal) =>
        PrepareTrustedHelper(command, Environment.ProcessPath, out lockedSelf, out refusal);

    internal static ProcessStartInfo? PrepareTrustedHelper(string command, string? processPath,
        out IDisposable? lockedSelf, out HelperPreflightRefusal? refusal)
    {
        lockedSelf = null;
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Patched", "Patched.Service.exe");
        if (!string.Equals(processPath, executable, StringComparison.OrdinalIgnoreCase))
        {
            refusal = new("location_untrusted", $"process_path={processPath ?? "unknown"}");
            return null;
        }
        WindowsInstallationEvidence.LockedFile? locked = null;
        try
        {
            // The locked walk refuses a reparse point at every component, the install
            // directory included, and holds them all while the ACLs are read. The
            // directory is judged by the install-directory policy, not
            // SecureStagingDirectory.VerifyTrusted, which rejects the DACL every real
            // install inherits from %ProgramFiles% (PAT-2116).
            locked = WindowsInstallationEvidence.OpenLocalFile(executable);
            WindowsInstallationEvidence.VerifyInstallDirectoryAcl(Path.GetDirectoryName(executable)!);
            WindowsInstallationEvidence.VerifyExecutableAcl(executable);
            var start = new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(executable)!,
            };
            start.ArgumentList.Add(command);
            lockedSelf = locked;
            refusal = null;
            return start;
        }
        catch (Exception e)
        {
            locked?.Dispose();
            refusal = RefusalFor(e);
            return null;
        }
    }

    internal static HelperPreflightRefusal RefusalFor(Exception e) => e switch
    {
        WindowsInstallationEvidence.AclRefusalException acl => new(acl.Refusal.Reason, acl.Refusal.Detail),
        // OpenLocalChain's own fixed codes: not a local fixed path, missing, or a reparse point.
        IOException { Message: "path_not_local_fixed" or "file_unavailable_or_reparse" } io =>
            new("install_path_unavailable", io.Message),
        _ => new("preflight_error", e.GetType().Name),
    };

    // Kept separate so timeout/pipe limits can be exercised without installing a
    // service or populating the intentionally empty production product set.
    internal static async Task<AppInstallationEvidence> RunHelperAsync(ProcessStartInfo start, TimeSpan budget,
        Action<Process>? onStartedForTests = null)
    {
        using var deadline = new CancellationTokenSource(budget);
        Process? process = null;
        try
        {
            process = Process.Start(start);
            if (process is null) return AppInstallationEvidence.Unavailable("helper_start_failed");
            onStartedForTests?.Invoke(process);
            var output = ReadBoundedAsync(process.StandardOutput, deadline.Token);
            var error = ReadBoundedAsync(process.StandardError, deadline.Token);
            await Task.WhenAll(output, error, process.WaitForExitAsync(deadline.Token)).ConfigureAwait(false);
            if (process.ExitCode != 0 || error.Result.Length != 0)
                return AppInstallationEvidence.Unavailable("helper_failed");
            return JsonSerializer.Deserialize<AppInstallationEvidence>(output.Result)
                ?? AppInstallationEvidence.Unavailable("helper_output_invalid");
        }
        catch (OperationCanceledException) { return AppInstallationEvidence.Unavailable("collection_timeout"); }
        catch { return AppInstallationEvidence.Unavailable("helper_failed"); }
        finally
        {
            if (process is not null)
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                        using var terminationDeadline = new CancellationTokenSource(TerminationGrace);
                        await process.WaitForExitAsync(terminationDeadline.Token).ConfigureAwait(false);
                    }
                }
                catch { /* The result remains unavailable; never wait without a deadline. */ }
                process.Dispose();
            }
        }
    }

    internal static async Task<string> ReadBoundedAsync(StreamReader reader, CancellationToken ct)
    {
        var buffer = new char[OutputLimit + 1];
        var count = 0;
        while (count < buffer.Length)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(count), ct).ConfigureAwait(false);
            if (read == 0) return new string(buffer, 0, count);
            count += read;
        }
        throw new InvalidDataException("helper_output_limit");
    }
}
