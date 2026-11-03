using System.Runtime.Versioning;
using Patched.Shared.Contract;
using Patched.Shared.Paths;

namespace Patched.Service;

/// <summary>
/// Drains and validates trigger files from the ACL-hardened triggers directory (PAT-307).
/// Service is the ONLY consumer: reads, validates, then deletes each file.
/// Malformed, oversized, or foreign-owned triggers are rejected and deleted.
///
/// PAT-687: verifies each trigger file's OWNER SID (rejecting foreign / anonymous
/// owners), derives the authoritative <c>requested_by</c> from that owner instead
/// of trusting the self-asserted JSON field, and rate-limits accepted triggers
/// per owner so a local user cannot flood the run loop.
///
/// PAT-906 follow-up: a file that cannot even be opened (locked by another
/// handle) is neither validated nor deleted by <see cref="TryExamineFile"/>, so
/// it would otherwise sit in the directory forever, re-examined every pass. An
/// authenticated low-privilege user can plant many such decoys -- e.g. holding
/// each open with any share mode, which conflicts with this class's exclusive
/// <c>FileShare.None</c> read -- ahead of a legitimate trigger to try to hide it
/// from every drain. <see cref="_lockedFiles"/> tracks consecutive open
/// failures per filename across passes; a file that stays unopenable well past
/// how long a legitimate writer (<c>File.WriteAllText</c>, effectively
/// instantaneous) could ever hold it is force-deleted ("quarantined") so it
/// stops permanently occupying a slot.
///
/// On Windows, <c>File.Delete</c> raises a sharing violation while any handle
/// lacking <c>FILE_SHARE_DELETE</c> is open, so an attacker who keeps a decoy
/// open defeats the force-delete. That case is handled by transitioning the
/// entry to a Quarantined state instead of dropping it: a Quarantined name is
/// skipped on every later pass WITHOUT an open attempt, and we merely retry the
/// cheap delete once per pass -- which succeeds the instant the attacker's
/// handle drops or the name leaves the directory.
///
/// No fixed per-pass constant is consumable by quarantined names. Quarantined
/// skips cost ZERO against every budget, and once the open-attempt ceiling is
/// exhausted the pass keeps WALKING (skipping unopened names untouched) so
/// quarantined names later in the enumeration still get their delete retry and
/// their tracking stays alive. Every per-pass cost an attacker can impose is
/// bounded by resources the attacker must actively expend, never by a constant
/// the attacker can occupy:
///   - Directory enumeration is O(entries), streamed. Any consumer of the
///     directory must pay this; each entry costs the attacker a real on-disk
///     file, and invalid openable files are deleted on sight.
///   - Open attempts are hard-capped per pass
///     (<see cref="TriggerFileValidator.MaxFilesEnumeratedPerPass"/>) and only
///     consumable by NON-quarantined files. Occupying this budget means either
///     recreating fresh invalid files every pass (they are deleted on
///     rejection) or planting fresh held-open names (they are quarantined
///     within a bounded number of passes) -- both warn-logged every pass.
///   - Each quarantined name costs one dictionary lookup plus one delete-retry
///     syscall per pass, and requires the attacker to keep a live open handle
///     to a file that is warn-logged (aggregate count) on every pass.
///   - Tracking memory (<see cref="_lockedFiles"/>) is linear in the number of
///     unopenable files the attacker actively maintains in the directory --
///     one small entry per held-open file, pruned as soon as the file is gone.
///
/// The valid-trigger budget stays separate from all of the above -- it is
/// <see cref="TriggerRateLimiter"/>'s per-owner limit, reached only by files
/// that pass full validation.
///
/// <see cref="CountOsDeferrals()"/> lives here too (moved from OsUpdateChecker
/// in the same follow-up) so counting pending os_defer triggers runs the SAME
/// hardened walk -- quarantine skip and delete-retry, open-attempt
/// ceiling, invalid-file deletion, shared locked-file tracking -- instead of a
/// second parallel loop that can drift back into a starvable shape. The two
/// passes differ only in consumption: the drain deletes valid triggers (it owns
/// consumption), while the count leaves valid files in place for the drain and
/// merely counts the os_defer ones. Sharing the tracking also closes a count
/// inflation hole: a valid os_defer file held open by its author could never be
/// consumed by the drain, so it would otherwise re-inflate the count on every
/// cycle forever; with shared tracking the drain quarantines it and the count
/// then skips it.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TriggerWatcher
{
    // A locked/unopenable file is quarantined (force-deleted) as soon as
    // EITHER threshold below is crossed: enough separate passes (drain or count) have
    // seen it fail, or enough wall-clock time has passed since it was first
    // seen unopenable. Either bound alone is already far longer than any
    // legitimate client ever holds a trigger file open (File.WriteAllText
    // opens, writes, and closes in one call), so this never quarantines a
    // file that is genuinely mid-write -- only one that has been
    // deliberately held open well past that. Using "either" (not "both")
    // gives the tightest guaranteed bound on how long an attacker-held decoy
    // can occupy a slot: at most min(failure-count bound, age bound).
    private const int LockedFileQuarantineFailureThreshold = 5;
    private static readonly TimeSpan LockedFileQuarantineAge = TimeSpan.FromMinutes(2);

    // NOTE: there is deliberately NO per-pass bound on directory entries
    // walked. Any such constant is occupiable: an attacker holding that many
    // quarantined (skipped-for-free) names would exhaust it on skips before
    // the walk reached legitimate triggers. The walk is O(directory size) by
    // necessity -- see the class doc for why every per-pass cost is bounded by
    // attacker-expended resources instead of an occupiable constant.

    private readonly ILogger<TriggerWatcher> _log;
    private readonly TriggerRateLimiter _rateLimiter;
    private readonly Func<DateTimeOffset> _clock;

    // Effective per-pass open budget. Production uses
    // TriggerFileValidator.MaxFilesEnumeratedPerPass; the internal ctor lets
    // tests shrink it so the "flood exceeds the budget" path can be exercised
    // with a handful of files. Never overridden outside tests.
    private readonly int _maxOpenAttempts;

    // Owner read seam: production reads the real file owner via
    // TriggerFileValidator.ReadOwner; tests inject fake owners so the
    // foreign-owner rejection paths can be exercised without manipulating
    // real ACLs (which may need privilege the CI test process lacks).
    private readonly Func<string, TriggerFileValidator.OwnerInfo> _ownerReader;

    // Tracks *.trigger filenames that failed to open on the most recent
    // pass(es) they were seen on. Keyed by filename (the trigger dir is flat
    // and names are GUIDs, so this is unambiguous). Pruned at the end of every
    // fully-enumerated pass to entries whose file is still present. Entries
    // are only ever created by a failed open attempt (at most the open budget
    // per pass), so the dictionary grows only while an attacker actively
    // maintains unopenable files in the directory: memory is one small entry
    // per such file, each of which costs the attacker a live open handle, and
    // every entry disappears as soon as its file does.
    private readonly Dictionary<string, LockedFileState> _lockedFiles = new(StringComparer.OrdinalIgnoreCase);

    // Quarantined == true means the file crossed the quarantine threshold but
    // its force-delete failed (a handle without FILE_SHARE_DELETE is still
    // open). Such a name is skipped on later passes without an open attempt and
    // only retried for deletion, until the delete succeeds or the name leaves
    // the directory. ConsecutiveFailures stops advancing once Quarantined (we
    // no longer open it), which is fine -- the threshold has already been met.
    private readonly record struct LockedFileState(
        DateTimeOffset FirstSeen, int ConsecutiveFailures, bool Quarantined);

    public TriggerWatcher(ILogger<TriggerWatcher> log)
        : this(log, new TriggerRateLimiter(), () => DateTimeOffset.UtcNow)
    {
    }

    // Test/config seam. maxOpenAttempts defaults to the production bound; tests
    // override it to keep the flood cases small. ownerReader defaults to the
    // real ACL owner read; tests inject fake owners.
    internal TriggerWatcher(
        ILogger<TriggerWatcher> log,
        TriggerRateLimiter rateLimiter,
        Func<DateTimeOffset> clock,
        int? maxOpenAttempts = null,
        Func<string, TriggerFileValidator.OwnerInfo>? ownerReader = null)
    {
        _log             = log;
        _rateLimiter     = rateLimiter;
        _clock           = clock;
        _maxOpenAttempts = maxOpenAttempts ?? TriggerFileValidator.MaxFilesEnumeratedPerPass;
        _ownerReader     = ownerReader ?? (path => TriggerFileValidator.ReadOwner(
            path, ex => _log.LogDebug(ex, "Could not read owner of trigger {Path}", path)));
    }

    /// <summary>
    /// Returns all valid trigger requests found in the trigger directory and
    /// deletes each file after reading (consumed once).
    /// </summary>
    public IReadOnlyList<TriggerRequest> DrainTriggers() => DrainTriggers(PathConstants.TriggerDir);

    /// <summary>Test seam: takes the trigger directory as a parameter so tests can
    /// drive the real drain loop (open ceiling, owner checks, locked-file
    /// quarantine) against a temp directory instead of the production
    /// ACL-hardened path.</summary>
    internal IReadOnlyList<TriggerRequest> DrainTriggers(string triggerDir)
    {
        _rateLimiter.BeginDrain();
        return WalkPass(triggerDir, consume: true, _rateLimiter);
    }

    /// <summary>
    /// Counts pending os_defer triggers in the trigger directory without
    /// consuming them.
    ///
    /// PAT-906: this used to live on OsUpdateChecker as its own raw scan of the
    /// same directory, first without any validation (letting any local user
    /// inflate the deferral count feeding OsUpdateStateEngine's escalation
    /// policy) and then, once validated, with a rejected-decoy starvation hole:
    /// its per-pass ceiling was consumed BEFORE validation and rejected files
    /// were never deleted, so 2048+ planted foreign-owned or malformed files
    /// sorting ahead of a real os_defer trigger hid it from every call, forever.
    /// It now runs the identical hardened walk as <see cref="DrainTriggers()"/>
    /// (same validation, invalid-file deletion, quarantine tracking, and
    /// bounds), differing only in consumption semantics:
    ///
    ///   - Valid triggers are NOT deleted -- the drain owns consumption, and a
    ///     counted os_defer file must still be there for the drain to process
    ///     (<c>HandleOsDeferAsync</c>). Non-os_defer valid triggers are left
    ///     untouched and uncounted, without consuming any rate-limit budget.
    ///   - The count opens files non-exclusively (<c>FileShare.ReadWrite</c>)
    ///     since it never deletes what it reads, while the drain opens with
    ///     <c>FileShare.None</c> because it is about to delete.
    ///   - A fresh rate limiter is used per call: it caps how many deferrals one
    ///     owner can contribute to a single count, but must never charge the
    ///     drain's rolling per-owner window -- counted files are not consumed,
    ///     and charging the shared window would make the drain later DROP the
    ///     same legitimate triggers as rate-limit excess.
    /// </summary>
    public int CountOsDeferrals() => CountOsDeferrals(PathConstants.TriggerDir);

    /// <summary>Test seam, mirroring <see cref="DrainTriggers(string)"/>.</summary>
    internal int CountOsDeferrals(string triggerDir)
    {
        var limiter = new TriggerRateLimiter();
        limiter.BeginDrain();
        return WalkPass(triggerDir, consume: false, limiter).Count;
    }

    /// <summary>
    /// The single hardened walk over the trigger directory shared by the drain
    /// and the count so the two can never drift apart again (the original
    /// PAT-906 finding was the count re-implementing its own weaker scan).
    /// <paramref name="consume"/> selects the semantics: true = drain (valid
    /// triggers of every type are returned and their files deleted), false =
    /// count (only valid os_defer triggers are returned and NO valid file is
    /// deleted). Invalid files are deleted in both modes -- the drain would
    /// reject-and-delete them anyway, so removing them from the count path too
    /// is what stops rejected decoys from permanently consuming either pass's
    /// budget. Locked-file tracking is shared across both modes; see the
    /// tracking rules at the bottom of the loop.
    /// </summary>
    private List<TriggerRequest> WalkPass(string triggerDir, bool consume, TriggerRateLimiter limiter)
    {
        if (!Directory.Exists(triggerDir))
            return [];

        IEnumerable<string> files;
        try
        {
            // STREAM the enumeration (never Directory.GetFiles, which materialises
            // the whole array): any authenticated user can plant an arbitrary
            // number of files here, so the path list must not be an unbounded
            // allocation (PAT-906).
            files = Directory.EnumerateFiles(triggerDir, "*.trigger");
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Could not enumerate trigger directory");
            return [];
        }

        var valid = new List<TriggerRequest>();
        // Names of TRACKED files observed present this pass, used to prune
        // _lockedFiles afterwards. Only tracked names are recorded, so this set
        // is bounded by the tracking dictionary (plus new failures this pass),
        // never by directory size.
        var trackedSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var openAttempts = 0;
        var ceilingLogged = false;
        var heldQuarantined = 0;
        var enumerationCompleted = false;

        try
        {
            foreach (var file in files)
            {
                var filename = Path.GetFileName(file);

                if (_lockedFiles.TryGetValue(filename, out var tracked))
                {
                    // Mark every tracked name that is still present so pruning
                    // below cannot evict live tracking or quarantine state.
                    trackedSeen.Add(filename);

                    // A Quarantined decoy (proven unopenable AND undeletable
                    // while a handle is held) is skipped WITHOUT an open attempt
                    // and costs ZERO against every per-pass budget -- its whole
                    // per-pass footprint is the dictionary lookup above plus one
                    // cheap delete retry, which succeeds the moment the
                    // attacker's handle drops or the name leaves the directory.
                    if (tracked.Quarantined)
                    {
                        if (!RetryQuarantineDelete(filename, file))
                            heldQuarantined++;
                        continue;
                    }
                }

                // Hard ceiling on total files this pass will attempt to OPEN,
                // not on valid triggers accepted -- see
                // TriggerFileValidator.MaxFilesEnumeratedPerPass. Quarantined
                // skips above never reach this. When the budget is exhausted the
                // pass keeps WALKING rather than stopping: unopened names are
                // skipped untouched (deferred to the next pass), while
                // quarantined and tracked names later in the enumeration still
                // get their delete retry / stay marked seen. Stopping here
                // instead would let an early-sorting flood starve late-sorting
                // quarantine state of its retry and evict it via the prune,
                // re-arming those decoys.
                if (openAttempts >= _maxOpenAttempts)
                {
                    if (!ceilingLogged)
                    {
                        _log.LogWarning(
                            "Trigger pass exhausted the per-pass open-attempt ceiling ({Cap}); remaining unexamined " +
                            "files deferred to the next pass",
                            _maxOpenAttempts);
                        ceilingLogged = true;
                    }
                    continue;
                }
                openAttempts++;

                if (!TryExamineFile(file, consume, limiter, out var request, out var unopenable))
                {
                    // Locked-file tracking rules:
                    //  - An unopenable file feeds the shared tracking from BOTH
                    //    modes. The count's non-exclusive open is strictly more
                    //    permissive than the drain's exclusive one, so a file
                    //    unopenable to the count is certainly unopenable to the
                    //    drain -- counting its failure toward quarantine is safe.
                    //  - Only the DRAIN clears tracking on other outcomes: its
                    //    exclusive open succeeding (or its rejection paths
                    //    deleting the file) proves the file is genuinely free.
                    //    The count's open succeeding proves nothing about the
                    //    drain's -- an author can hold a file with a share mode
                    //    that admits readers but still blocks the exclusive
                    //    drain open -- so the count never clears tracking, or it
                    //    would reset the drain's quarantine progress every cycle.
                    if (unopenable)
                    {
                        TrackLockedFile(filename, file);
                        trackedSeen.Add(filename);
                    }
                    else if (consume)
                    {
                        _lockedFiles.Remove(filename);
                    }
                    continue;
                }

                if (consume)
                    _lockedFiles.Remove(filename);
                if (request is not null)
                    valid.Add(request);
            }

            enumerationCompleted = true;
        }
        catch (Exception ex)
        {
            // EnumerateFiles streams lazily and can throw mid-iteration (directory
            // removed, IO error) -- return what was gathered rather than propagate.
            _log.LogWarning(ex, "Trigger enumeration failed mid-pass; returning triggers gathered so far");
        }

        // One aggregate warning per pass for decoys still being held open, so a
        // parked attack stays loudly visible without emitting one log line per
        // decoy per pass (which would let the attacker drive log volume).
        if (heldQuarantined > 0)
        {
            _log.LogWarning(
                "{Count} quarantined trigger file(s) still held open in {Dir}; delete retried this pass, will keep " +
                "retrying every pass until the handle(s) drop",
                heldQuarantined, triggerDir);
        }

        // Prune only after a COMPLETE enumeration: a pass that died mid-iteration
        // has not observed every name, and pruning on that partial view could
        // evict live tracking or quarantine state for files that are still
        // present. Skipping the prune for one pass is safe -- entries persist
        // one extra pass and the next complete pass reconciles.
        if (enumerationCompleted)
            PruneLockedFileTracking(trackedSeen);

        return valid;
    }

    /// <summary>
    /// Records one more consecutive open failure for <paramref name="filename"/>
    /// and, once it has been unopenable for either long enough or across enough
    /// separate passes that it cannot plausibly still be a legitimate in-flight
    /// write, quarantines it. Quarantine first tries a force-delete; if the
    /// delete succeeds the entry is dropped, and if it fails (a handle without
    /// FILE_SHARE_DELETE is still open, so File.Delete raises a sharing
    /// violation) the entry is KEPT and flagged Quarantined so later passes skip
    /// the open attempt entirely and just retry the delete. Not dropping the
    /// entry on a failed delete is what prevents the decoy from re-earning a
    /// fresh failure budget and permanently re-consuming an open-attempt slot.
    /// Only called for files not already Quarantined (Quarantined names never
    /// reach an open attempt). See the threshold constants' doc for why the
    /// bounds are safe.
    /// </summary>
    private void TrackLockedFile(string filename, string path)
    {
        var now = _clock();
        var state = _lockedFiles.TryGetValue(filename, out var existing)
            ? existing with { ConsecutiveFailures = existing.ConsecutiveFailures + 1 }
            : new LockedFileState(now, 1, Quarantined: false);
        _lockedFiles[filename] = state;

        var age = now - state.FirstSeen;
        if (state.ConsecutiveFailures < LockedFileQuarantineFailureThreshold && age < LockedFileQuarantineAge)
            return;

        if (TryDelete(path))
        {
            _log.LogWarning(
                "Quarantining trigger {Filename}: unopenable for {Failures} consecutive passes over {Age}; " +
                "force-deleted (locked or otherwise inaccessible far longer than a legitimate write ever takes)",
                filename, state.ConsecutiveFailures, age);
            _lockedFiles.Remove(filename);
        }
        else
        {
            _log.LogWarning(
                "Quarantining trigger {Filename}: unopenable for {Failures} consecutive passes over {Age} and " +
                "could not be force-deleted (a handle without FILE_SHARE_DELETE is held open); will skip the open " +
                "attempt and retry deletion each pass until the handle drops",
                filename, state.ConsecutiveFailures, age);
            _lockedFiles[filename] = state with { Quarantined = true };
        }
    }

    /// <summary>
    /// One cheap delete retry for an already-Quarantined name: no open attempt,
    /// so it costs nothing against the per-pass open-attempt budget. Succeeds
    /// the instant the attacker's handle drops (or the file has already left the
    /// directory), at which point tracking is dropped and true is returned. If
    /// the handle is still held, File.Delete raises a sharing violation and the
    /// name stays Quarantined for the next pass; the failure is deliberately
    /// NOT logged per file here (the caller emits one aggregate warning per
    /// pass, so N parked decoys cannot drive N log lines every pass). A name
    /// that has left the directory some other way is pruned by
    /// <see cref="PruneLockedFileTracking"/> instead.
    /// </summary>
    private bool RetryQuarantineDelete(string filename, string path)
    {
        if (!TryDelete(path, logFailure: false))
            return false;

        _log.LogInformation("Quarantined trigger {Filename} deleted; handle released", filename);
        _lockedFiles.Remove(filename);
        return true;
    }

    /// <summary>
    /// Drops tracking for any filename whose file was not observed present
    /// during the (fully enumerated) pass that just finished -- it was either
    /// consumed, rejected-and-deleted, deleted via the quarantine retry, or has
    /// left the directory some other way. Keeps <see cref="_lockedFiles"/>
    /// scoped to files that actually exist: an entry lives exactly as long as
    /// the attacker keeps its file (and the handle making it unopenable) alive.
    /// </summary>
    private void PruneLockedFileTracking(HashSet<string> trackedSeen)
    {
        if (_lockedFiles.Count == 0)
            return;

        List<string>? stale = null;
        foreach (var filename in _lockedFiles.Keys)
        {
            if (!trackedSeen.Contains(filename))
                (stale ??= new List<string>()).Add(filename);
        }
        if (stale is null)
            return;
        foreach (var filename in stale)
            _lockedFiles.Remove(filename);
    }

    /// <summary>
    /// Examines one trigger file under the shared validation pipeline
    /// (size-capped read off the open handle, owner SID, filename shape,
    /// schema, per-owner rate limit). <paramref name="consume"/> selects the
    /// drain semantics (exclusive open; every reject deletes; a valid trigger
    /// of any type is returned and its file deleted) versus the count semantics
    /// (non-exclusive open; invalid rejects still delete, but a VALID file is
    /// never deleted, a valid non-os_defer file is ignored without touching the
    /// rate limiter, and only a valid os_defer sets <paramref name="request"/>).
    /// Returns true when <paramref name="request"/> may be non-null;
    /// <paramref name="unopenable"/> is set when the file could not even be
    /// opened, so the caller can feed locked-file tracking.
    /// </summary>
    private bool TryExamineFile(
        string path, bool consume, TriggerRateLimiter limiter,
        out TriggerRequest? request, out bool unopenable)
    {
        request = null;
        unopenable = false;
        var filename = Path.GetFileName(path);

        string json;
        long fileSize;
        bool oversized;
        try
        {
            // The drain is about to delete what it reads, so it opens
            // exclusively (FileShare.None). The count never deletes valid
            // files, so it opens non-exclusively and must not block the drain
            // or a concurrent legitimate reader.
            var share = consume ? FileShare.None : FileShare.ReadWrite;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, share);
            // Bound the read to the size cap off the OPEN handle (PAT-906): any
            // authenticated user can drop files here, so a planted oversized file
            // must never force an unbounded read/allocation, and a pre-read stat
            // would be racy (the file can be grown between stat and read).
            oversized = !TriggerFileValidator.TryReadCapped(fs, out json, out fileSize);
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Could not read trigger file {Path}; skipping", path);
            unopenable = true;
            return false;
        }

        if (oversized)
        {
            _log.LogWarning("Rejected oversized trigger {Filename} (exceeds {Cap} bytes)",
                filename, TriggerFileValidator.MaxFileSizeBytes);
            TryDelete(path);
            return false;
        }

        // Owner verification (PAT-687): reject files owned by a foreign/anonymous
        // principal, and derive requested_by from the real OS owner. Filename
        // shape, owner acceptability, and size/schema validation are all applied
        // by the shared TriggerFileValidator (PAT-906). Invalid files are deleted
        // in BOTH modes: the drain would reject-and-delete them anyway, and
        // leaving them behind on the count path is exactly how rejected decoys
        // used to consume the count's per-pass ceiling forever.
        var owner = _ownerReader(path);
        if (!TriggerFileValidator.TryValidate(filename, owner, json, fileSize, out request, out var error))
        {
            _log.LogWarning("Rejected trigger {Filename}: {Error}", filename, error);
            TryDelete(path);
            request = null;
            return false;
        }

        // Count mode ignores valid non-os_defer triggers entirely: they belong
        // to the drain, and they must not consume the count's rate-limit budget
        // (a backlog of pending deploy/scan triggers must never mask real
        // deferrals from the count).
        if (!consume && !request!.IsOsDefer)
        {
            request = null;
            return false;
        }

        // Rate-limit by owner so a single user cannot flood the run loop (drain)
        // or inflate the deferral count (count).
        var requestedBy = TriggerOwnerPolicy.DeriveRequestedBy(owner.Sid, owner.Account);
        if (!limiter.TryAccept(requestedBy, _clock()))
        {
            if (consume)
            {
                _log.LogWarning("Dropped trigger {Filename}: rate limit exceeded for owner {Owner}", filename, requestedBy);
                TryDelete(path);
            }
            // Count mode: rate-limit excess is simply not counted; the file is
            // valid and still belongs to the drain, so it is not deleted.
            request = null;
            return false;
        }

        // Overwrite the self-asserted requested_by with the authoritative OS owner.
        request = request! with { RequestedBy = requestedBy };

        // Only the drain consumes: the count must leave valid os_defer files in
        // place for the drain (Worker.HandleOsDeferAsync) to process.
        if (consume)
            TryDelete(path);
        return true;
    }

    /// <summary>
    /// Deletes a trigger file. Returns true when the file is gone afterwards
    /// (File.Delete is a no-op, not an error, on an already-absent file), and
    /// false when deletion failed -- most importantly a Windows sharing
    /// violation while a handle without FILE_SHARE_DELETE is held open. Callers
    /// use the result to decide whether to keep quarantine tracking.
    /// <paramref name="logFailure"/> is false only for the per-pass quarantine
    /// delete retry, whose failures are reported as one aggregate warning per
    /// pass instead of one line per held decoy.
    /// </summary>
    private bool TryDelete(string path, bool logFailure = true)
    {
        try { File.Delete(path); return true; }
        catch (Exception ex)
        {
            if (logFailure)
                _log.LogWarning(ex, "Could not delete trigger {Path}", path);
            return false;
        }
    }
}
