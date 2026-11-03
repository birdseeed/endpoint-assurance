using System.Text.Json;
using Patched.Shared.Contract;
using Patched.Shared.Paths;

namespace Patched.Service;

/// <summary>
/// PAT-1066: persisted degraded-capability store — the Windows twin of the macOS
/// .agent-health.json sidecar (PAT-1065). Server ingestion is PAT-1064; the wire
/// contract this feeds is go-service/docs/PAYLOAD_SCHEMA.md's "Agent health object".
///
/// Three-part persisted shape, mirroring the macOS store's design (the third part,
/// <c>last_success</c>, is PAT-1269, added alongside the other two rather than as a
/// separate file — see its own doc comment below):
///   - <c>active</c> — faults currently observed (kind -&gt; subject -&gt; fault detail).
///     Cleared per-(kind,subject) on <see cref="RecordSuccess"/>.
///   - <c>ever_succeeded</c> — a durable ledger (kind -&gt; subject -&gt; bool) that must
///     survive a fault clearing and later recurring. Only ever goes false -&gt; true,
///     never back, and is never removed once true. This is the single most
///     safety-critical property of the whole feature (see the critical invariant
///     below) — a design that derived ever_succeeded from active's own presence
///     would report false on a fault that resolved and later recurred, even though
///     it plainly worked in between.
///   - <c>last_success</c> — PAT-1269: (kind -&gt; subject -&gt; UTC timestamp) of the most
///     recent <see cref="RecordSuccess"/> call, updated every time regardless of
///     whether there was an active fault to clear. Unlike <c>ever_succeeded</c> this
///     DOES move forward on every success — the point is "when did this last check
///     in", not "has it ever worked". Added so a healthy-but-silent signal (e.g.
///     BootstrapUpdater's periodic self-update check, which RecordSuccess()es on
///     every clean check whether or not an update was actually available) leaves
///     visible evidence of the last time it actually ran — "has not checked in N
///     days" becomes a fact readable from this file instead of something inferred
///     from a version number nobody watches.
///
/// Nested by kind then subject (not a concatenated "kind|subject" string key)
/// because kind/subject are free-form per the wire contract and could in
/// principle collide if joined with a delimiter.
///
/// CRITICAL INVARIANT (the single most important thing PAT-1065's code review
/// caught, twice, on the macOS side — do not repeat that mistake here):
/// <see cref="RecordFailure"/>/<see cref="RecordSuccess"/> must never treat "the
/// existing store file is present but fails to parse" the same as "the store is
/// empty" and then write a fresh, mostly-empty store over it — that would
/// permanently destroy the ever_succeeded ledger and any currently-active faults
/// on nothing more than a transient read glitch. On an unparseable-but-present
/// file, both methods log the problem and return WITHOUT WRITING ANYTHING —
/// the on-disk file is left exactly as it was, and this one observation is
/// simply skipped for this cycle. Only a genuinely absent file (first run) is
/// treated as "start from an empty store".
///
/// <see cref="BuildPayloadSection"/> mirrors that same read outcome into the wire
/// shape: a missing-or-cleanly-read store (even when empty) produces a non-null
/// object (present, `degraded: []` when empty — the explicit all-clear case);
/// only an unparseable-but-present file produces null (absent from the wire —
/// "no opinion", so the server does not touch existing rows for this device).
///
/// CONCURRENCY: every call site (InstallRunner.RunAsync, DeviceRemovalRunner.RunAsync,
/// InventoryPoster.PostAsync via BuildPayloadSection) runs sequentially, awaited
/// one after another, inside the single PatchedWorker BackgroundService's own async
/// loop — there is no second process and no concurrent in-process caller, unlike the
/// macOS store (shared by two separate LaunchDaemon processes). No cross-process
/// locking is needed; the in-process <see cref="_lock"/> is a cheap correctness
/// guard against future changes, not a requirement of today's call graph.
/// </summary>
internal sealed class AgentHealthStore
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
    };

    private readonly ILogger<AgentHealthStore> _log;
    private readonly object                    _lock = new();
    private readonly string                    _storePath;

    /// <summary>
    /// <paramref name="storePathOverride"/> exists purely for test isolation — a
    /// unit test can redirect the store to a temp file instead of the real
    /// %ProgramData%\Patched\agent-health.json (<see cref="PathConstants.AgentHealthFile"/>).
    /// Production DI resolves this constructor with no registered string service,
    /// so the container falls back to the default (null) and every real instance
    /// uses the production path.
    /// </summary>
    public AgentHealthStore(ILogger<AgentHealthStore> log, string? storePathOverride = null)
    {
        _log       = log;
        _storePath = storePathOverride ?? PathConstants.AgentHealthFile;
    }

    // -------------------------------------------------------------------------
    // Persisted shape
    // -------------------------------------------------------------------------

    private sealed class StoreFile
    {
        public Dictionary<string, Dictionary<string, ActiveFault>> Active { get; set; } = new();
        public Dictionary<string, Dictionary<string, bool>> EverSucceeded { get; set; } = new();
        public Dictionary<string, Dictionary<string, DateTimeOffset>> LastSuccess { get; set; } = new();
        public InventoryUpdateChannel? UpdateChannel { get; set; }
        public string? UpdateChannelTenantId { get; set; }
        public string? UpdateChannelDeviceId { get; set; }
    }

    private sealed class ActiveFault
    {
        public string Reason { get; set; } = "";
        public DateTimeOffset FirstSeen { get; set; }
        public DateTimeOffset LastSeen { get; set; }
        public int Count { get; set; }
    }

    private enum ReadOutcome { FreshOrOk, Corrupt }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// <summary>
    /// Records an observed fault for (kind, subject). Creates the active entry with
    /// first_seen = last_seen = now, count = 1 on first observation; on a repeat,
    /// preserves first_seen and bumps count, refreshing last_seen/reason. No-ops
    /// (logs, does not write) if the on-disk store is present but unparseable.
    /// </summary>
    /// <summary>
    /// PAT-2245: (kind, subject) pairs for capabilities this agent no longer has. A store
    /// written by an older release can still hold an active fault for one of them, and
    /// nothing will ever record a success to clear it, so it is never put on the wire.
    /// The platform deletes every row a payload leaves out, so omitting the pair clears
    /// it server side. PAT-2422: the pairs live in <see cref="RetiredHealthReasons"/>,
    /// and <see cref="TryReadStore"/> also removes them from the file itself.
    /// </summary>
    internal static bool IsRetired(string kind, string subject) =>
        RetiredHealthReasons.IsRetired(kind, subject);

    public void RecordFailure(string kind, string subject, string reason)
    {
        lock (_lock)
        {
            if (TryReadStore(out var store) == ReadOutcome.Corrupt)
                return;

            var now = DateTimeOffset.UtcNow;

            if (!store.Active.TryGetValue(kind, out var subjects))
            {
                subjects = new Dictionary<string, ActiveFault>();
                store.Active[kind] = subjects;
            }

            if (subjects.TryGetValue(subject, out var existing))
            {
                existing.Reason   = reason;
                existing.LastSeen = now;
                existing.Count   += 1;
            }
            else
            {
                subjects[subject] = new ActiveFault
                {
                    Reason    = reason,
                    FirstSeen = now,
                    LastSeen  = now,
                    Count     = 1,
                };
            }

            WriteAtomic(store);
        }
    }

    /// <summary>
    /// Records that (kind, subject) is currently working: clears any active fault
    /// for that pair, sets the ever_succeeded ledger entry to true (never reset
    /// to false once set), and stamps last_success[kind][subject] with the current
    /// UTC time (PAT-1269) — unlike ever_succeeded, this timestamp is overwritten on
    /// every call, not just the first. No-ops (logs, does not write) if the on-disk
    /// store is present but unparseable.
    /// </summary>
    public void RecordSuccess(string kind, string subject)
    {
        lock (_lock)
        {
            if (TryReadStore(out var store) == ReadOutcome.Corrupt)
                return;

            if (store.Active.TryGetValue(kind, out var subjects))
            {
                subjects.Remove(subject);
                if (subjects.Count == 0)
                    store.Active.Remove(kind);
            }

            if (!store.EverSucceeded.TryGetValue(kind, out var ledger))
            {
                ledger = new Dictionary<string, bool>();
                store.EverSucceeded[kind] = ledger;
            }
            ledger[subject] = true;

            if (!store.LastSuccess.TryGetValue(kind, out var lastSuccessBySubject))
            {
                lastSuccessBySubject = new Dictionary<string, DateTimeOffset>();
                store.LastSuccess[kind] = lastSuccessBySubject;
            }
            lastSuccessBySubject[subject] = DateTimeOffset.UtcNow;

            WriteAtomic(store);
        }
    }

    /// <summary>
    /// PAT-2400: removes the active fault for (kind, subject) only when its reason
    /// starts with <paramref name="reasonPrefix"/>. A pair holds one reason at a time,
    /// so this is how a check that has stopped failing withdraws its own reason without
    /// wiping one recorded by a different check on the same pair. Unlike
    /// <see cref="RecordSuccess"/> it claims no success: ever_succeeded and
    /// last_success are untouched. True when a fault was cleared. Writes nothing
    /// otherwise.
    /// </summary>
    public bool ClearFailure(string kind, string subject, string reasonPrefix)
    {
        lock (_lock)
        {
            if (TryReadStore(out var store) == ReadOutcome.Corrupt)
                return false;
            if (!store.Active.TryGetValue(kind, out var subjects) ||
                !subjects.TryGetValue(subject, out var fault) ||
                !fault.Reason.StartsWith(reasonPrefix, StringComparison.Ordinal))
                return false;

            subjects.Remove(subject);
            if (subjects.Count == 0)
                store.Active.Remove(kind);
            WriteAtomic(store);
            return true;
        }
    }

    /// <summary>
    /// Builds the agent_health payload section. Returns a non-null object (with an
    /// empty Degraded list when there are no active faults) whenever the store is
    /// either absent (first run) or read back cleanly — including cleanly-empty,
    /// which is the explicit all-clear case. Returns null only when the store file
    /// exists but fails to parse, which the wire contract treats as "absent" / "no
    /// opinion" rather than a false all-clear.
    /// </summary>
    public void RecordUpdateChannel(Patched.Shared.Config.UpdateChannelPolicy policy, string tenantId, string? deviceId)
    {
        lock (_lock)
        {
            if (TryReadStore(out var store) == ReadOutcome.Corrupt) return;
            store.UpdateChannel = new InventoryUpdateChannel
            {
                EffectiveChannel = policy.Channel,
                Source = policy.Source,
                ConfigVersion = policy.ConfigVersion,
                ObservedAt = DateTimeOffset.UtcNow
            };
            store.UpdateChannelTenantId = tenantId;
            store.UpdateChannelDeviceId = deviceId;
            WriteAtomic(store);
        }
    }

    public InventoryAgentHealth? BuildPayloadSection(string? tenantId = null, string? deviceId = null)
    {
        lock (_lock)
        {
            if (TryReadStore(out var store) == ReadOutcome.Corrupt)
                return null;

            var degraded = new List<InventoryAgentHealthEntry>();
            foreach (var (kind, subjects) in store.Active)
            {
                foreach (var (subject, fault) in subjects)
                {
                    if (IsRetired(kind, subject))
                        continue;

                    var everSucceeded =
                        store.EverSucceeded.TryGetValue(kind, out var ledger) &&
                        ledger.TryGetValue(subject, out var v) && v;

                    degraded.Add(new InventoryAgentHealthEntry
                    {
                        Kind          = kind,
                        Subject       = subject,
                        Reason        = fault.Reason,
                        FirstSeen     = fault.FirstSeen.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                        LastSeen      = fault.LastSeen.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                        Count         = fault.Count,
                        EverSucceeded = everSucceeded,
                    });
                }
            }

            return new InventoryAgentHealth
            {
                Degraded = degraded,
                UpdateChannel =
                !string.IsNullOrEmpty(tenantId) && store.UpdateChannelTenantId == tenantId && store.UpdateChannelDeviceId == deviceId &&
                store.UpdateChannel?.EffectiveChannel is "stable" or "beta" && store.UpdateChannel.Source is null or "tenant" or "device_override" &&
                (store.UpdateChannel.Source != "device_override" || store.UpdateChannel.EffectiveChannel == "beta") &&
                (store.UpdateChannel.ConfigVersion is null or >= 0) && store.UpdateChannel.ObservedAt > DateTimeOffset.MinValue &&
                store.UpdateChannel.ObservedAt <= DateTimeOffset.UtcNow.AddMinutes(5)
                    ? store.UpdateChannel : null
            };
        }
    }

    /// <summary>
    /// PAT-1269: reads back the last_success timestamp for (kind, subject) — the UTC
    /// time of the most recent <see cref="RecordSuccess"/> call for that pair, or
    /// null if it has never succeeded (or the on-disk store is currently
    /// unparseable). Not part of the <see cref="InventoryAgentHealth"/> wire
    /// contract (that section only carries active faults) — this reads the local
    /// agent-health.json sidecar directly, for diagnostics and tests.
    /// </summary>
    public DateTimeOffset? GetLastSuccess(string kind, string subject)
    {
        lock (_lock)
        {
            if (TryReadStore(out var store) == ReadOutcome.Corrupt)
                return null;

            return store.LastSuccess.TryGetValue(kind, out var lastSuccessBySubject)
                && lastSuccessBySubject.TryGetValue(subject, out var timestamp)
                ? timestamp
                : null;
        }
    }

    // -------------------------------------------------------------------------
    // Persistence
    // -------------------------------------------------------------------------

    /// <summary>
    /// Reads the store. A missing file is treated as "start from empty" (first run
    /// ever — <see cref="ReadOutcome.FreshOrOk"/> with a fresh <see cref="StoreFile"/>).
    /// A present file that fails to deserialize (corrupt/garbage bytes, wrong shape,
    /// even zero-length), that deserializes with a null <c>Active</c>,
    /// <c>EverSucceeded</c> or <c>LastSuccess</c> (PAT-1269) top-level dictionary, or
    /// that contains a null value nested anywhere inside any of those (e.g.
    /// <c>{"Active":{"k":null}}</c>) is <see cref="ReadOutcome.Corrupt"/> — callers
    /// must not write anything in that case; the corrupt/garbage file is left
    /// byte-for-byte untouched on disk.
    ///
    /// PAT-1066 non-author-review (P0): this runs as LocalSystem against a
    /// predictable %ProgramData% path, so a lower-privileged local user could
    /// pre-plant an NTFS reparse point (symlink/junction) at the store path or its
    /// CONTAINING directory to redirect a SYSTEM-owned read onto attacker-controlled
    /// content. Mirrors the fixed PAT-1044 precedent
    /// (<see cref="BrowserExtensionBlocklistEnforcer.LoadState"/>): the containing
    /// directory is checked first (before <see cref="File.Exists(string)"/> ever
    /// runs), then the leaf path, using <see cref="IsReparsePoint"/> — never
    /// <see cref="File.ResolveLinkTarget(string, bool)"/>, whose junction coverage
    /// is less certain. Deliberately DIFFERENT from that precedent's outcome, though:
    /// LoadState returns an empty default state on a directory-level reparse point
    /// because a browser blocklist has no <c>ever_succeeded</c>-style ledger to
    /// protect. THIS store must map a reparse point to <see cref="ReadOutcome.Corrupt"/>,
    /// not "fresh empty" — "fresh empty" here means an explicit all-clear on the
    /// wire (<see cref="BuildPayloadSection"/> would return
    /// <c>degraded: []</c>), and a redirected read must never produce that.
    /// </summary>
    private ReadOutcome TryReadStore(out StoreFile store)
    {
        var path = _storePath;

        try
        {
            // Directory-level reparse-point check must run before anything else
            // touches the leaf path (including File.Exists) — a pre-planted junction
            // at the containing directory makes every leaf-path check below resolve
            // through whatever that directory actually points to.
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && IsReparsePoint(dir))
            {
                _log.LogWarning(
                    "AgentHealthStore: refusing to read — containing directory '{Dir}' is a " +
                    "reparse point/junction, not a plain directory (possible symlink attack); " +
                    "treating as corrupt and skipping this observation (never a false all-clear)",
                    dir);
                store = null!;
                return ReadOutcome.Corrupt;
            }

            if (!File.Exists(path))
            {
                store = new StoreFile();
                return ReadOutcome.FreshOrOk;
            }

            if (IsReparsePoint(path))
            {
                _log.LogWarning(
                    "AgentHealthStore: refusing to read {File} — it is a reparse point/junction, " +
                    "not a plain file (possible symlink attack); treating as corrupt and skipping " +
                    "this observation (never a false all-clear)", path);
                store = null!;
                return ReadOutcome.Corrupt;
            }

            var json   = File.ReadAllText(path);
            var parsed = JsonSerializer.Deserialize<StoreFile>(json, JsonOpts)
                         ?? throw new JsonException("agent-health.json deserialised to null");

            // P1 non-author-review findings: a top-level `{"Active":null}` (or
            // EverSucceeded) must not be silently coerced into a fresh empty
            // dictionary — that would report a false all-clear and let
            // RecordFailure/RecordSuccess overwrite the ledger. Same treatment for a
            // null value nested inside either dictionary (e.g.
            // `{"Active":{"k":null}}` or `{"Active":{"k":{"s":null}}}`), which
            // deserializes successfully at the top level but throws a
            // NullReferenceException the moment BuildPayloadSection/RecordFailure/
            // RecordSuccess dereference it — routing it through this same Corrupt
            // path here, at the single choke point every public method already goes
            // through, means callers never see that throw.
            if (parsed.Active is null)
                throw new JsonException("agent-health.json 'Active' deserialised to null");
            if (parsed.EverSucceeded is null)
                throw new JsonException("agent-health.json 'EverSucceeded' deserialised to null");
            if (parsed.LastSuccess is null)
                throw new JsonException("agent-health.json 'LastSuccess' deserialised to null");
            if (HasNestedNull(parsed))
                throw new JsonException(
                    "agent-health.json contains a null value nested inside Active/EverSucceeded");

            // PAT-2422: drop reasons whose recorder no longer exists, with their
            // ledger entries, so an upgraded device stops carrying them from its
            // first load. Only a cleanly parsed store reaches this line; a store
            // with nothing retired is not rewritten.
            if (RetiredHealthReasons.RemoveFrom(parsed.Active)
                | RetiredHealthReasons.RemoveFrom(parsed.EverSucceeded)
                | RetiredHealthReasons.RemoveFrom(parsed.LastSuccess))
            {
                _log.LogInformation(
                    "AgentHealthStore: removed retired health reason(s) from {File}", path);
                WriteAtomic(parsed);
            }

            store = parsed;
            return ReadOutcome.FreshOrOk;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex,
                "AgentHealthStore: {File} exists but failed to parse — leaving it untouched and " +
                "skipping this observation (never overwriting a possibly-corrupt store with an " +
                "empty one — that would destroy the ever_succeeded ledger)", path);
            store = null!;
            return ReadOutcome.Corrupt;
        }
    }

    /// <summary>
    /// True if any value nested inside <paramref name="store"/>'s <c>Active</c>,
    /// <c>EverSucceeded</c> or <c>LastSuccess</c> (PAT-1269) top-level dictionaries
    /// is itself null — e.g. the inner <c>Dictionary&lt;string, ActiveFault&gt;</c>
    /// for a kind, or an individual <see cref="ActiveFault"/>. Called only after
    /// confirming all three top-level dictionaries are non-null, so the outer
    /// iteration itself is safe.
    /// </summary>
    private static bool HasNestedNull(StoreFile store)
    {
        foreach (var (_, subjects) in store.Active)
        {
            if (subjects is null) return true;
            foreach (var (_, fault) in subjects)
            {
                if (fault is null) return true;
            }
        }

        foreach (var (_, ledger) in store.EverSucceeded)
        {
            if (ledger is null) return true;
        }

        foreach (var (_, lastSuccessBySubject) in store.LastSuccess)
        {
            if (lastSuccessBySubject is null) return true;
        }

        return false;
    }

    /// <summary>
    /// Atomically writes the store: temp file in the same directory, then
    /// File.Move with overwrite (same-volume atomic rename).
    ///
    /// PAT-1066 non-author-review (P0): mirrors the fixed PAT-1044 pattern
    /// (<see cref="BrowserExtensionBlocklistEnforcer.SaveState"/>) exactly, rather
    /// than the still-unfixed <c>StatusWriter.WriteAtomic</c> precedent this method
    /// used to cite — this service runs as LocalSystem against a predictable
    /// %ProgramData% path, so a lower-privileged local user could pre-plant an NTFS
    /// reparse point (symlink/junction) at the ".tmp" path, the final destination,
    /// or the CONTAINING directory itself, to redirect a SYSTEM-owned write. The
    /// containing directory is checked first — before <see cref="Directory.CreateDirectory(string)"/>
    /// ever runs against it, since a pre-planted junction makes CreateDirectory a
    /// no-op from its own perspective while everything underneath still resolves
    /// through the link — then the ".tmp" candidate path, then (after writing)
    /// the final destination before <see cref="File.Move(string, string, bool)"/>.
    /// <see cref="FileMode.CreateNew"/> is used for the temp-file write as
    /// defense-in-depth alongside — not instead of — the explicit checks. The tmp
    /// path is only tracked for cleanup once confirmed safe to create, and cleared
    /// once the move actually succeeds, so a refusal at any checkpoint still cleans
    /// up its own temp file via the <c>finally</c> block, exactly mirroring
    /// PAT-1044's tmp-tracking-and-finally-cleanup shape. Never throws into the
    /// caller: any failure (including a refusal) is logged and swallowed (fail-safe,
    /// same convention as every other Runner/Poster in this service).
    /// </summary>
    private void WriteAtomic(StoreFile store)
    {
        var dest = _storePath;
        string? tmp = null;

        try
        {
            var dir = Path.GetDirectoryName(dest);
            if (!string.IsNullOrEmpty(dir) && IsReparsePoint(dir))
            {
                _log.LogWarning(
                    "AgentHealthStore: refusing to write — containing directory '{Dir}' is a " +
                    "reparse point/junction, not a plain directory (possible symlink attack); " +
                    "not creating or writing anything under it", dir);
                return;
            }

            Directory.CreateDirectory(dir!);
            var candidateTmp = dest + ".tmp";

            if (IsReparsePoint(candidateTmp))
            {
                _log.LogWarning(
                    "AgentHealthStore: refusing to write — temp path '{Path}' is already a " +
                    "reparse point/junction, not a plain file (possible symlink attack); leaving " +
                    "it untouched and not writing", candidateTmp);
                return;
            }

            // Only track tmp for cleanup once confirmed safe — a reparse point
            // caught above must never be deleted by the finally block below.
            tmp = candidateTmp;

            // CreateNew: defense-in-depth alongside the explicit check above. Throws
            // if anything (reparse point or ordinary file) already exists at this
            // exact path.
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(fs, store, JsonOpts);
            }

            if (IsReparsePoint(dest))
            {
                _log.LogWarning(
                    "AgentHealthStore: refusing to write — destination '{Path}' is a reparse " +
                    "point/junction, not a plain file (possible symlink attack); not moving the " +
                    "freshly-written file through it", dest);
                return; // finally below deletes the freshly-written tmp
            }

            File.Move(tmp, dest, overwrite: true);
            tmp = null; // moved successfully; nothing left to clean up
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "AgentHealthStore: failed to write {File}", dest);
        }
        finally
        {
            if (tmp is not null)
            {
                try { File.Delete(tmp); }
                catch { /* best-effort cleanup; a failed write must not throw further */ }
            }
        }
    }

    /// <summary>
    /// True if a filesystem object already exists at <paramref name="path"/> and is
    /// a reparse point (NTFS symlink OR junction) — checked without following it.
    /// Exactly matches <c>BrowserExtensionBlocklistEnforcer.IsReparsePoint</c> (the
    /// established, audited PAT-1044 pattern in this repo): uses
    /// <see cref="File.GetAttributes(string)"/> and tests
    /// <see cref="FileAttributes.ReparsePoint"/>, NOT <see cref="File.ResolveLinkTarget(string, bool)"/>
    /// (junction coverage is uncertain on that API). False (not a reparse point)
    /// for both the ordinary-file case and the doesn't-exist-yet case.
    /// </summary>
    private static bool IsReparsePoint(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }
}
