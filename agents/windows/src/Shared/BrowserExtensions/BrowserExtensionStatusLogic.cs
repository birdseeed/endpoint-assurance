using Patched.Shared.Contract;

namespace Patched.Shared.BrowserExtensions;

/// <summary>PAT-2065: the four collection statuses of the browser_extensions_status block.</summary>
internal static class BrowserExtensionCollectionStatus
{
    public const string Complete   = "complete";
    public const string Partial    = "partial";
    public const string NotPresent = "not_present";
    public const string Failed     = "failed";
}

/// <summary>PAT-2065: one profile's status for each browser the block covers. Safari is not one of them.</summary>
internal sealed record BrowserExtensionBrowserStatuses(string Chrome, string Edge, string Firefox)
{
    public static BrowserExtensionBrowserStatuses All(string status) => new(status, status, status);

    public IEnumerable<string> Values => [Chrome, Edge, Firefox];
}

/// <summary>PAT-2065: one scanned Windows profile, as the status block needs it.</summary>
internal sealed record BrowserExtensionUserScan(
    string UserAccount, string? UserId, BrowserExtensionBrowserStatuses Browsers, bool UserFailed);

/// <summary>
/// PAT-2065, the agent half of PAT-2055: builds the browser_extensions_status block from the
/// per-profile scans. Platform-neutral so Shared.Tests runs it anywhere; the macOS collector
/// (macos/lib/browser_extensions.sh, run_users and run_status) applies the same rules.
///
/// The platform (patched.im go-service/internal/extractor/validate_browser_extensions_status.go)
/// grants absence authority from this block, so every rule here leans to partial:
///   - a user is not_present when all three browsers are, complete when all are complete or
///     not_present, failed when the profile could not be entered, and partial otherwise;
///   - the block is failed when the profile list itself could not be read, not_present when
///     every user is (no users at all included), complete when every user is complete or
///     not_present, and partial for anything else: the cap reached, a profile whose registry
///     entry could not be read, more than 500 users, or a user with no usable name;
///   - user is exactly the user_account on that user's rows. Two profiles that resolve to the
///     same account are merged, least authoritative status winning, so the block never lists
///     a user twice.
/// </summary>
internal static class BrowserExtensionStatusLogic
{
    /// <summary>The contract's bound on users[].</summary>
    internal const int MaxUsers = 500;

    public static InventoryBrowserExtensionsStatus Failed() =>
        new() { CollectionStatus = BrowserExtensionCollectionStatus.Failed };

    public static InventoryBrowserExtensionsStatus Build(
        IReadOnlyList<BrowserExtensionUserScan> scans, bool capReached, int unreadableProfiles)
    {
        var order = new List<string>();
        var merged = new Dictionary<string, (string? UserId, BrowserExtensionBrowserStatuses Browsers, bool Failed)>(StringComparer.Ordinal);
        var unnamed = false;
        foreach (var scan in scans)
        {
            if (string.IsNullOrEmpty(scan.UserAccount))
            {
                // The block requires a non-empty user, and the platform skips rows without one.
                unnamed = true;
                continue;
            }
            if (merged.TryGetValue(scan.UserAccount, out var seen))
            {
                merged[scan.UserAccount] = (
                    seen.UserId ?? scan.UserId,
                    new BrowserExtensionBrowserStatuses(
                        Merge(seen.Browsers.Chrome, scan.Browsers.Chrome),
                        Merge(seen.Browsers.Edge, scan.Browsers.Edge),
                        Merge(seen.Browsers.Firefox, scan.Browsers.Firefox)),
                    seen.Failed && scan.UserFailed);
                continue;
            }
            order.Add(scan.UserAccount);
            merged[scan.UserAccount] = (scan.UserId, scan.Browsers, scan.UserFailed);
        }

        var users = new List<InventoryBrowserExtensionsStatusUser>();
        foreach (var name in order)
        {
            var (userId, browsers, failed) = merged[name];
            users.Add(new InventoryBrowserExtensionsStatusUser
            {
                User             = name,
                UserId           = userId,
                CollectionStatus = failed ? BrowserExtensionCollectionStatus.Failed : UserStatus(browsers),
                Browsers         = new InventoryBrowserExtensionsStatusBrowsers
                {
                    Chrome  = browsers.Chrome,
                    Edge    = browsers.Edge,
                    Firefox = browsers.Firefox,
                },
            });
        }

        var over = users.Count > MaxUsers;
        if (over) users = users.Take(MaxUsers).ToList();

        string status;
        if (capReached || over || unnamed || unreadableProfiles > 0
            || users.Any(u => u.CollectionStatus is not (BrowserExtensionCollectionStatus.Complete or BrowserExtensionCollectionStatus.NotPresent)))
            status = BrowserExtensionCollectionStatus.Partial;
        else if (users.All(u => u.CollectionStatus == BrowserExtensionCollectionStatus.NotPresent))
            status = BrowserExtensionCollectionStatus.NotPresent;
        else
            status = BrowserExtensionCollectionStatus.Complete;

        return new InventoryBrowserExtensionsStatus
        {
            CollectionStatus = status,
            CapReached       = capReached,
            Users            = users,
        };
    }

    internal static string UserStatus(BrowserExtensionBrowserStatuses browsers)
    {
        if (browsers.Values.All(v => v == BrowserExtensionCollectionStatus.NotPresent))
            return BrowserExtensionCollectionStatus.NotPresent;
        if (browsers.Values.All(v => v is BrowserExtensionCollectionStatus.Complete or BrowserExtensionCollectionStatus.NotPresent))
            return BrowserExtensionCollectionStatus.Complete;
        return BrowserExtensionCollectionStatus.Partial;
    }

    /// <summary>Two profiles under one account: the pair is only as good as the weaker read.</summary>
    private static string Merge(string a, string b)
    {
        if (a == b) return a;
        if (a == BrowserExtensionCollectionStatus.Failed || b == BrowserExtensionCollectionStatus.Failed)
            return BrowserExtensionCollectionStatus.Failed;
        if (a == BrowserExtensionCollectionStatus.Partial || b == BrowserExtensionCollectionStatus.Partial)
            return BrowserExtensionCollectionStatus.Partial;
        // complete + not_present: the rows of the one that has the browser were all listed.
        return BrowserExtensionCollectionStatus.Complete;
    }
}
