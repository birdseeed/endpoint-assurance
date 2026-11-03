namespace Patched.Service;

/// <summary>
/// PAT-687: service-side rate limiting for trigger consumption. A local user can
/// create trigger files at will (the directory ACL only lets them add-file), so
/// a runaway or malicious writer could otherwise drive an unbounded number of
/// run cycles. This caps accepted triggers per-owner over a rolling window and
/// per drain pass.
///
/// Pure logic with an injectable clock — unit-testable on any platform. Not
/// thread-safe: the owning <see cref="TriggerWatcher"/> is a singleton drained
/// from a single worker loop.
/// </summary>
public sealed class TriggerRateLimiter
{
    private readonly int _maxPerOwnerPerWindow;
    private readonly TimeSpan _window;
    private readonly int _maxPerDrain;
    private readonly Dictionary<string, Queue<DateTimeOffset>> _byOwner =
        new(StringComparer.OrdinalIgnoreCase);

    private int _acceptedThisDrain;

    public TriggerRateLimiter(
        int maxPerOwnerPerWindow = 10,
        TimeSpan? window = null,
        int maxPerDrain = 50)
    {
        _maxPerOwnerPerWindow = maxPerOwnerPerWindow;
        _window               = window ?? TimeSpan.FromMinutes(5);
        _maxPerDrain          = maxPerDrain;
    }

    /// <summary>Reset the per-drain counter at the start of each drain pass.</summary>
    public void BeginDrain() => _acceptedThisDrain = 0;

    /// <summary>
    /// Record and authorise one trigger from <paramref name="owner"/> at
    /// <paramref name="now"/>. Returns false when either the per-drain cap or the
    /// owner's rolling-window cap is exceeded (the caller drops the trigger).
    /// </summary>
    public bool TryAccept(string owner, DateTimeOffset now)
    {
        if (_acceptedThisDrain >= _maxPerDrain)
            return false;

        if (!_byOwner.TryGetValue(owner, out var q))
            q = _byOwner[owner] = new Queue<DateTimeOffset>();

        // Evict timestamps outside the rolling window.
        while (q.Count > 0 && now - q.Peek() > _window)
            q.Dequeue();

        if (q.Count >= _maxPerOwnerPerWindow)
            return false;

        q.Enqueue(now);
        _acceptedThisDrain++;
        return true;
    }
}
