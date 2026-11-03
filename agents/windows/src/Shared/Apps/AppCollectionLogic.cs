using Patched.Shared.Contract;

namespace Patched.Shared.Apps;

/// <summary>
/// PAT-2066: what one source of installed applications (one registry Uninstall key)
/// yielded. Built only by <see cref="AppCollectionLogic.ReadSource{T}"/>.
/// </summary>
internal sealed record AppSourceResult
{
    private AppSourceResult(string name, IReadOnlyList<InventoryApp> apps, bool readable, int skipped)
    {
        Name     = name;
        Apps     = apps;
        Readable = readable;
        Skipped  = skipped;
    }

    /// <summary>The source, for logs (for example <c>HKLM\SOFTWARE\...\Uninstall</c>).</summary>
    public string Name { get; }

    /// <summary>Rows read from the source, including any read before it failed.</summary>
    public IReadOnlyList<InventoryApp> Apps { get; }

    /// <summary>False when the source could not be opened or enumerated as a whole.</summary>
    public bool Readable { get; }

    /// <summary>Entries the source listed that could not be read and were left out.</summary>
    public int Skipped { get; }

    internal static AppSourceResult Create(string name, IReadOnlyList<InventoryApp> apps, bool readable, int skipped) =>
        new(name, apps, readable, skipped);
}

/// <summary>
/// PAT-2066: outcome of one installed-application collection. <see cref="Status"/> is the
/// collection_status.apps wire value describes the machine rows. RegistryAppCollection
/// additionally carries per-user rows and independent Users authority, including when
/// the machine scope is unavailable. AppCollectionLogic alone combines one scope.
/// </summary>
internal sealed record AppCollectionResult
{
    private AppCollectionResult(IReadOnlyList<InventoryApp> apps, string status, int skipped,
        IReadOnlyList<string> unreadableSources)
    {
        Apps              = apps;
        Status            = status;
        Skipped           = skipped;
        UnreadableSources = unreadableSources;
    }

    /// <summary>The apps array to send, including independently observed per-user rows.</summary>
    public IReadOnlyList<InventoryApp> Apps { get; }

    /// <summary>One of the <see cref="AppCollectionStatus"/> values.</summary>
    public string Status { get; }

    /// <summary>Entries that could not be read, across every source.</summary>
    public int Skipped { get; }

    /// <summary>Sources that could not be opened or enumerated.</summary>
    public IReadOnlyList<string> UnreadableSources { get; }

    public IReadOnlyList<InventoryAppUserStatus> Users { get; init; } = [];

    internal static AppCollectionResult Create(IReadOnlyList<InventoryApp> apps, string status, int skipped,
        IReadOnlyList<string> unreadableSources) =>
        new(apps, status, skipped, unreadableSources);
}

/// <summary>
/// PAT-2066 (agent half of PAT-2063): platform-neutral status routing for the installed
/// application scan, kept out of the Windows-only <c>InstalledAppScanner</c> so
/// Shared.Tests can cover it on macOS CI (same split as <c>CertCollectionLogic</c>).
///
/// ABSENCE REQUIRES AUTHORITY. Under collection_status.apps the platform reads the apps
/// array as: complete, upsert and prune every stored app not listed, even when the list is
/// empty; partial, upsert and prune nothing; unavailable, write nothing. So:
///   the scan throws outright, or no source can be read -> unavailable, apps []
///   a source cannot be opened or enumerated             -> partial, rows read are sent
///   an entry (key or value) cannot be read              -> partial, rows read are sent
///   every source enumerated and every entry read        -> complete ([] included)
/// An entry the reader deliberately excludes (returns null for: no display name or
/// version, a system component, a duplicate) is scope, not a failure. macos/lib/apps.sh
/// sends the same three values with the same meaning.
/// </summary>
internal static class AppCollectionLogic
{
    /// <summary>
    /// Reads one source. <paramref name="enumerate"/> opens the source and lists its
    /// entries, returning null when the source does not exist; an exception from the call
    /// or from iterating the sequence means the source was not read as a whole.
    /// <paramref name="read"/> turns one entry into a row, returns null to exclude it by
    /// design, and throws when the entry could not be read. A missing source is unreadable
    /// unless <paramref name="absentIsEmpty"/> says its absence is expected on this machine.
    /// </summary>
    public static AppSourceResult ReadSource<T>(
        string                  name,
        Func<IEnumerable<T>?>   enumerate,
        Func<T, InventoryApp?>  read,
        bool                    absentIsEmpty = false,
        Action<Exception>?      onUnreadable  = null,
        Action<T, Exception>?   onSkipped     = null)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(enumerate);
        ArgumentNullException.ThrowIfNull(read);

        var apps    = new List<InventoryApp>();
        var skipped = 0;
        try
        {
            var entries = enumerate();
            if (entries is null)
            {
                if (absentIsEmpty)
                    return AppSourceResult.Create(name, apps, readable: true, skipped: 0);
                Notify(onUnreadable, new InvalidOperationException($"application source {name} is missing"));
                return AppSourceResult.Create(name, apps, readable: false, skipped: 0);
            }

            foreach (var entry in entries)
            {
                InventoryApp? app;
                try
                {
                    app = read(entry);
                }
                catch (Exception ex)
                {
                    skipped++;
                    if (onSkipped is not null)
                    {
                        try { onSkipped(entry, ex); }
                        catch { /* a failing log callback must not change the outcome */ }
                    }
                    continue;
                }

                if (app is not null)
                    apps.Add(app);
            }
        }
        catch (Exception ex)
        {
            Notify(onUnreadable, ex);
            return AppSourceResult.Create(name, apps, readable: false, skipped: skipped);
        }

        return AppSourceResult.Create(name, apps, readable: true, skipped: skipped);
    }

    /// <summary>Combines every source's result into the apps array and its status.</summary>
    public static AppCollectionResult Combine(IReadOnlyList<AppSourceResult> sources)
    {
        ArgumentNullException.ThrowIfNull(sources);
        if (sources.Count == 0)
            throw new ArgumentException("at least one application source is required", nameof(sources));

        var unreadable = sources.Where(s => !s.Readable).Select(s => s.Name).ToArray();
        if (unreadable.Length == sources.Count)
            return AppCollectionResult.Create([], AppCollectionStatus.Unavailable, sources.Sum(s => s.Skipped), unreadable);

        var apps    = sources.SelectMany(s => s.Apps).ToArray();
        var skipped = sources.Sum(s => s.Skipped);
        var status  = unreadable.Length == 0 && skipped == 0
            ? AppCollectionStatus.Complete
            : AppCollectionStatus.Partial;
        return AppCollectionResult.Create(apps, status, skipped, unreadable);
    }

    /// <summary>
    /// Runs the whole scan. Any exception that escapes <paramref name="scan"/> makes the
    /// collection unavailable, so a crash part way through can never be read as complete.
    /// </summary>
    public static AppCollectionResult Run(
        Func<IReadOnlyList<AppSourceResult>> scan,
        Action<Exception>?                   onUnavailable = null)
    {
        ArgumentNullException.ThrowIfNull(scan);
        try
        {
            return Combine(scan());
        }
        catch (Exception ex)
        {
            Notify(onUnavailable, ex);
            return Unavailable();
        }
    }

    /// <summary>The scan failed outright: apps [], status unavailable.</summary>
    public static AppCollectionResult Unavailable() =>
        AppCollectionResult.Create([], AppCollectionStatus.Unavailable, 0, []);

    // A failing log callback must not turn a reading into an exception that breaks the
    // wider inventory run, nor change the collection outcome.
    private static void Notify(Action<Exception>? callback, Exception ex)
    {
        if (callback is null)
            return;
        try
        {
            callback(ex);
        }
        catch
        {
            // Swallowed on purpose; see above.
        }
    }
}
