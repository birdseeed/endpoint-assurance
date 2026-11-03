using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Patched.Shared.Contract;

namespace Patched.Shared.InstallationEvidence;

// One app row the coverage helper is asked about: its position in the parent's apps list,
// its ARP subkey name and which HKLM Uninstall view it came from. No path crosses the
// process boundary: the helper reads DisplayIcon and InstallLocation from HKLM itself.
internal sealed record CoverageTarget(
    [property: JsonPropertyName("i")] int Index,
    [property: JsonPropertyName("id")] string Identifier,
    [property: JsonPropertyName("wow")] bool Wow6432);

// Parent to helper, on stdin. Completed targets are resolved again (so one executable
// claimed by two entries stays ambiguous across a restart) but not probed; stuck targets,
// the ones a previous helper hung on, are neither.
internal sealed record CoverageRequest(
    [property: JsonPropertyName("targets")] IReadOnlyList<CoverageTarget> Targets,
    [property: JsonPropertyName("completed")] IReadOnlyList<int> Completed,
    [property: JsonPropertyName("stuck")] IReadOnlyList<int> Stuck,
    [property: JsonPropertyName("cache")] IReadOnlyList<SignatureCacheEntry> Cache);

// Helper to parent, one JSON object per stdout line. "step" says which target the helper
// is about to do IO for, so a hang is attributable; "result" carries the row's evidence
// and, for a verdict the parent may cache, its key.
internal sealed record CoverageLine
{
    internal const string Step = "step";
    internal const string Result = "result";
    internal const string Done = "done";

    [JsonPropertyName("k")] public required string Kind { get; init; }
    [JsonPropertyName("i")] public int Index { get; init; }
    [JsonPropertyName("evidence")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AppInstallationEvidence? Evidence { get; init; }
    [JsonPropertyName("cache_key")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SignatureCacheKey? CacheKey { get; init; }
    [JsonPropertyName("cache_observation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SignatureObservation? CacheObservation { get; init; }
}

// PreflightRefused: the parent refused to start the helper at all (its install directory or
// executable failed a trust check), as opposed to Failed: it started and then crashed,
// exited early or wrote something unparseable (PAT-2116).
internal enum CoverageSessionEnd { Completed, StepTimeout, BudgetExhausted, Failed, PreflightRefused }

internal sealed record CoverageSession(IReadOnlyList<CoverageLine> Results, CoverageSessionEnd End, int? StuckIndex);

internal sealed record CoverageResult(IReadOnlyList<InventoryApp> Apps, InstallationEvidenceCoverageSummary Summary);

// PAT-2116: Authenticode evidence for every installed app the scanner reports, not only the
// reviewed targets. The parent owns the time bounds and the cache; the helper process
// (AppSignatureCoverageProbe) owns every registry, filesystem and WinVerifyTrust call.
//
// Time bounds, all enforced by the parent against a killable helper:
//   * per step: StepTimeout. The helper prints a line before each target's IO and after
//     each result; a gap longer than this kills the helper, reports that one target
//     collection_timeout, and starts a fresh helper after it.
//   * per scan: TotalBudget across every helper started this scan, and at most
//     MaximumSessions helpers. Targets not reached are collection_budget_exhausted.
// Rows keep the reviewed-target evidence when they already have it; coverage never
// overwrites it (the reviewed path is bound to a signed delivery and an expected subject).
internal static class AppSignatureCoverage
{
    internal static readonly TimeSpan StepTimeout = TimeSpan.FromSeconds(10);
    internal static readonly TimeSpan TotalBudget = TimeSpan.FromSeconds(45);
    internal const int MaximumSessions = 6;

    internal static readonly HashSet<string> CollectionErrors = new(StringComparer.Ordinal)
    {
        "collection_timeout", "collection_budget_exhausted", "helper_failed", "helper_preflight_refused",
        "helper_output_incomplete", "coverage_limit", "per_user_scope_unverified",
    };

    internal static bool ValidIdentifier(string? identifier) => identifier is { Length: > 0 and <= 255 } &&
        !identifier.Contains('\\') && !identifier.Any(char.IsControl) && identifier.Trim().Length == identifier.Length;

    internal static async Task<CoverageResult> CollectAsync(IReadOnlyList<InventoryApp> apps, SignatureVerdictCache cache,
        Func<CoverageRequest, TimeSpan, Task<CoverageSession>> runSession, TimeProvider? timeProvider = null)
    {
        var clock = timeProvider ?? TimeProvider.System;
        var started = clock.GetTimestamp();
        var result = apps.ToArray();
        var evidence = new Dictionary<int, AppInstallationEvidence>();
        foreach (var index in Enumerable.Range(0, apps.Count).Where(i => !string.IsNullOrEmpty(apps[i].UserAccount)))
            evidence[index] = AppInstallationEvidence.PerUserUnverified();

        var eligible = Enumerable.Range(0, apps.Count)
            .Where(i => string.IsNullOrEmpty(apps[i].UserAccount) && apps[i].InstallationEvidence is null && ValidIdentifier(apps[i].Identifier))
            .ToArray();
        foreach (var index in eligible.Skip(ExecutableResolver.MaximumTargets))
            evidence[index] = AppInstallationEvidence.Unavailable("coverage_limit");
        var targets = eligible.Take(ExecutableResolver.MaximumTargets)
            .Select(i => new CoverageTarget(i, apps[i].Identifier, apps[i].Architecture == "x86"))
            .ToArray();
        var byIndex = targets.ToDictionary(t => t.Index);
        var stuck = new List<int>();
        var pendingReason = "helper_output_incomplete";

        for (var session = 0; targets.Length > 0 && session < MaximumSessions; session++)
        {
            var pending = targets.Where(t => !evidence.ContainsKey(t.Index)).ToArray();
            if (pending.Length == 0) break;
            var remaining = TotalBudget - clock.GetElapsedTime(started);
            if (remaining <= TimeSpan.Zero) { pendingReason = "collection_budget_exhausted"; break; }

            var completed = targets.Where(t => evidence.ContainsKey(t.Index) && !stuck.Contains(t.Index))
                .Select(t => t.Index).ToArray();
            CoverageSession outcome;
            try
            {
                outcome = await runSession(new(targets.Where(t => !stuck.Contains(t.Index)).ToArray(), completed,
                    stuck.ToArray(), cache.Snapshot()), remaining).ConfigureAwait(false);
            }
            catch { outcome = new([], CoverageSessionEnd.Failed, null); }

            foreach (var line in outcome.Results)
            {
                if (line.Kind != CoverageLine.Result || line.Evidence is null || !byIndex.ContainsKey(line.Index) ||
                    evidence.ContainsKey(line.Index))
                    continue;
                // Coverage rows never carry the reviewed delivery's provenance.
                evidence[line.Index] = line.Evidence with { CatalogueVersion = null, DeliveryVersion = null, ContentHash = null };
                if (line.CacheKey is not null && line.CacheObservation is not null)
                    cache.Set(line.CacheKey, line.CacheObservation);
            }

            if (outcome.End == CoverageSessionEnd.StepTimeout && outcome.StuckIndex is int hung &&
                byIndex.ContainsKey(hung) && !evidence.ContainsKey(hung))
            {
                // The one target the helper hung on is reported and skipped; the rest get a
                // fresh helper within whatever budget is left.
                evidence[hung] = AppInstallationEvidence.Unavailable("collection_timeout");
                stuck.Add(hung);
                pendingReason = "collection_budget_exhausted";
                continue;
            }
            pendingReason = outcome.End switch
            {
                CoverageSessionEnd.Completed => "helper_output_incomplete",
                CoverageSessionEnd.BudgetExhausted => "collection_budget_exhausted",
                CoverageSessionEnd.StepTimeout => "collection_timeout",
                CoverageSessionEnd.PreflightRefused => "helper_preflight_refused",
                _ => "helper_failed",
            };
            break;
        }

        foreach (var target in targets.Where(t => !evidence.ContainsKey(t.Index)))
            evidence[target.Index] = AppInstallationEvidence.Unavailable(pendingReason);
        // PAT-2129: every row says how its executable was found or why none was. A row the
        // helper never resolved (a limit, a timeout, a helper that failed or was refused)
        // says so; its errors carry the specific cause.
        foreach (var (index, row) in evidence)
            result[index] = apps[index] with
            {
                InstallationEvidence = row.ExecutableResolution is null
                    ? row with { ExecutableResolution = ExecutableResolutions.NotAttempted } : row,
            };

        var errors = evidence.Values.SelectMany(e => e.Errors).Where(CollectionErrors.Contains).Distinct().Take(4).ToArray();
        var attempted = evidence.Count;
        return new(result, new()
        {
            CollectionStatus = attempted == 0 ? "complete"
                : evidence.Values.All(e => e.Errors.Any(CollectionErrors.Contains)) ? "unavailable"
                : errors.Length > 0 ? "partial" : "complete",
            Attempted = attempted,
            Resolved = evidence.Values.Count(e => e.ExecutablePath is not null),
            Errors = errors,
        });
    }

    // Parent side of one helper run: reads its stdout line by line, bounded in size, with
    // a per-line and a whole-session deadline. The caller kills the helper when this
    // returns anything but Completed. Pure over a TextReader so the timing is testable.
    internal static async Task<CoverageSession> ReadSessionAsync(TextReader output, TimeSpan stepTimeout, TimeSpan budget,
        TimeProvider? timeProvider = null)
    {
        var clock = timeProvider ?? TimeProvider.System;
        var started = clock.GetTimestamp();
        var reader = new BoundedLineReader(output);
        var results = new List<CoverageLine>();
        int? current = null;
        while (true)
        {
            var remaining = budget - clock.GetElapsedTime(started);
            if (remaining <= TimeSpan.Zero) return new(results, CoverageSessionEnd.BudgetExhausted, current);
            var wait = remaining < stepTimeout ? remaining : stepTimeout;
            var read = reader.ReadLineAsync();
            using var delay = new CancellationTokenSource();
            var timer = Task.Delay(wait, clock, delay.Token);
            if (await Task.WhenAny(read, timer).ConfigureAwait(false) != read)
            {
                // The pending read is abandoned; the caller's kill closes the pipe under it.
                _ = read.ContinueWith(t => _ = t.Exception, TaskScheduler.Default);
                return new(results, wait < stepTimeout ? CoverageSessionEnd.BudgetExhausted : CoverageSessionEnd.StepTimeout, current);
            }
            delay.Cancel();
            string? text;
            try { text = await read.ConfigureAwait(false); }
            catch { return new(results, CoverageSessionEnd.Failed, current); }
            if (text is null) return new(results, CoverageSessionEnd.Failed, current);
            CoverageLine? line;
            try { line = JsonSerializer.Deserialize<CoverageLine>(text); }
            catch (JsonException) { return new(results, CoverageSessionEnd.Failed, current); }
            if (line is null) return new(results, CoverageSessionEnd.Failed, current);
            switch (line.Kind)
            {
                case CoverageLine.Done:
                    return new(results, CoverageSessionEnd.Completed, null);
                case CoverageLine.Step:
                    current = line.Index;
                    break;
                case CoverageLine.Result:
                    results.Add(line);
                    current = null;
                    break;
                default:
                    return new(results, CoverageSessionEnd.Failed, current);
            }
        }
    }
}

// Reads '\n'-terminated lines with a per-line and a total character bound, so a garbled
// helper can never grow the parent's memory without limit.
internal sealed class BoundedLineReader(TextReader reader)
{
    internal const int MaximumLineChars = 16384;
    internal const int MaximumTotalChars = 8 * 1024 * 1024;
    private readonly char[] _buffer = new char[4096];
    private int _start;
    private int _end;
    private long _total;

    internal async Task<string?> ReadLineAsync()
    {
        var line = new StringBuilder();
        while (true)
        {
            if (_start == _end)
            {
                var read = await reader.ReadAsync(_buffer.AsMemory()).ConfigureAwait(false);
                if (read == 0) return null; // A partial trailing line is not a line.
                _start = 0;
                _end = read;
                _total += read;
                if (_total > MaximumTotalChars) throw new InvalidDataException("helper_output_limit");
            }
            var newline = Array.IndexOf(_buffer, '\n', _start, _end - _start);
            var stop = newline < 0 ? _end : newline;
            line.Append(_buffer, _start, stop - _start);
            if (line.Length > MaximumLineChars) throw new InvalidDataException("helper_line_limit");
            _start = newline < 0 ? _end : newline + 1;
            if (newline >= 0) return line.ToString().TrimEnd('\r');
        }
    }
}
