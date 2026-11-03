using Patched.Shared.Interruption;

namespace Patched.Shared.Removal;

/// <summary>One app currently blocking its own removal by staying open.</summary>
public sealed record PendingRemovalPrompt(long EntryId, string Name);

/// <summary>
/// PAT-1623: the removal notify/defer surface's presentation-decision logic,
/// content-equivalent with the macOS StatusStore's removal additions
/// (menubar/PatchedUpdater/StatusStore.swift). Platform-neutral and
/// deliberately decoupled from file I/O / WPF so it is fully testable from
/// Shared.Tests (which runs on any OS, including macOS CI) without needing a
/// real Windows box.
///
/// What this does NOT do: detect whether an app is running, retry removal, or
/// write uninstall-status.json. That backend detection/retry/report already
/// exists (RemovalRunner.cs / DeviceRemovalRunner.cs — outcome
/// RemovalOutcome.DeferredAppRunning). This class only decides whether, given
/// the daemon's already-written status, the person at the keyboard should be
/// shown something right now.
/// </summary>
public sealed class RemovalPromptEvaluator
{
    /// <summary>Distinct from the OS-update governor's surface — see
    /// PromptPresentationGovernor's own contract: one instance per
    /// user-facing surface, so a quiet OS-update prompt does not silence a
    /// removal prompt, or vice versa.</summary>
    public const string Surface = "removal";

    private readonly PromptPresentationGovernor _governor;
    private HashSet<long> _knownDeferredIds = new();
    private long _deferralCount;

    public RemovalPromptPolicy Policy { get; }

    /// <summary>PAT-1623: "Managed tier only, fail closed." Starts false and
    /// is only ever raised by <see cref="ApplyTier"/>.</summary>
    public bool IsManagedTier { get; private set; }

    public PendingRemovalPrompt? Pending { get; private set; }

    public RemovalPromptEvaluator(PromptPresentationGovernor governor, RemovalPromptPolicy? policy = null)
    {
        _governor = governor;
        Policy = policy ?? RemovalPromptPolicy.Defaults;
    }

    /// <summary>
    /// Managed tier only, fail closed: anything other than exactly "managed"
    /// (case-insensitive, matching InterruptionPolicy.Resolve's own rule) —
    /// report, patch, unknown, or no tier read yet — keeps this path entirely
    /// inert. Resets the dedup set too, so a later upgrade to managed tier
    /// treats every currently-deferred app as newly seen rather than
    /// silently swallowing its one notification.
    /// </summary>
    public void ApplyTier(string? tier)
    {
        IsManagedTier = string.Equals(tier?.Trim(), "managed", StringComparison.OrdinalIgnoreCase);
        if (!IsManagedTier)
        {
            Pending = null;
            _knownDeferredIds.Clear();
        }
    }

    /// <summary>
    /// Feed the latest uninstall-status.json read. Returns true when this
    /// call is a fresh attempt opportunity — a NEW app entered the
    /// deferred-running set, or this is the first sighting — false when the
    /// same already-known app is merely being re-confirmed. That is the
    /// "retry without re-notifying every cycle" requirement: reading an
    /// unchanged status file every 20 seconds must not request a new
    /// attempt every time.
    /// </summary>
    public bool ApplyStatus(UninstallStatus? status)
    {
        if (!IsManagedTier)
        {
            Pending = null;
            return false;
        }

        var deferred = (status?.Removals ?? Array.Empty<RemovalResult>())
            .Where(r => r.Outcome == RemovalOutcome.DeferredAppRunning)
            .ToList();
        var currentIds = deferred.Select(r => r.EntryId).ToHashSet();
        var newIds = currentIds.Except(_knownDeferredIds).ToHashSet();
        _knownDeferredIds = currentIds;

        var first = deferred.FirstOrDefault();
        Pending = first is null ? null : new PendingRemovalPrompt(first.EntryId, first.Name);

        return newIds.Count > 0 && Pending is not null;
    }

    /// <summary>
    /// The one call site every removal notify/defer prompt goes through.
    ///
    /// "Queue, do not stack" (PAT-1623 ruling): <paramref name="shouldShowOsUpdatePrompt"/>
    /// is whatever the OS-update surface currently says it wants the screen
    /// for — including a same-tick suppressed attempt, deliberately, since an
    /// OS-update attempt being suppressed this tick is still "the OS-update
    /// surface's turn", not an opening for removal to slip through underneath
    /// it. The OS update has a real deadline; removal costs nothing to wait.
    /// </summary>
    public PromptOutcome Evaluate(DateTimeOffset now, bool sessionActive, bool shouldShowOsUpdatePrompt)
    {
        if (!IsManagedTier || Pending is null) return PromptOutcome.Absent;
        if (shouldShowOsUpdatePrompt) return PromptOutcome.Absent;
        return _governor.Evaluate(now, sessionActive);
    }

    /// <summary>
    /// Records a user-triggered defer. Never gates anything — see
    /// RemovalPromptPolicy.CanAlwaysDefer — and never touches the daemon's
    /// own automatic DeferredAppRunning retry, which already runs next cycle
    /// regardless. Only clears the local prompt so it is not re-shown until
    /// the next state change (ApplyStatus's id-diffing).
    /// </summary>
    public void RecordDefer()
    {
        _deferralCount++;
        _ = Policy.CanAlwaysDefer(_deferralCount); // always true; see RemovalPromptPolicy
        Pending = null;
    }
}
