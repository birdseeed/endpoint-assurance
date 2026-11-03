namespace Patched.Shared.Removal;

/// <summary>
/// Safety guard — the Windows analogue of the macOS engine's `_NEVER_REMOVE` Apple
/// baseline list. Blocks removal of OS-critical components, shared runtimes that
/// other apps depend on, the security stack, and the Patched agent itself, even if
/// an entry is (mistakenly) queued for removal. Matching is case-insensitive on the
/// DisplayName the allowlist match reported (substring, since redistributable names
/// carry version suffixes).
/// </summary>
public static class BaselineProtection
{
    // Substrings matched (lower-cased) against the app name. Conservative on purpose:
    // removing any of these can break the OS, dependent apps, or endpoint security.
    private static readonly string[] ProtectedFragments =
    [
        // The agent must never remove itself.
        "patched agent", "patched updater",
        // Browser/runtime the OS and many apps embed.
        "microsoft edge", "webview2",
        // Shared runtimes — uninstalling breaks every dependent app.
        "microsoft visual c++", "vc_redist",
        "microsoft .net", ".net runtime", ".net host", "windows desktop runtime",
        "directx",
        // Endpoint security stack.
        "microsoft defender", "windows defender", "windows security",
        // Core platform / servicing.
        "microsoft store", "app installer",
        "windows software development kit", "windows sdk",
        "update for windows", "security update for", "servicing stack",
    ];

    /// <summary>True if <paramref name="name"/> names an OS/runtime/security baseline app.</summary>
    public static bool IsProtected(string? name, string? publisher = null)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        string n = name.ToLowerInvariant();
        foreach (var frag in ProtectedFragments)
            if (n.Contains(frag, StringComparison.Ordinal))
                return true;
        return false;
    }
}
