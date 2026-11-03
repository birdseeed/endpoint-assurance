using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using Patched.Shared.Contract;
using Patched.Shared.IdeExtensions;
using Patched.Shared.UserTrees;

namespace Patched.Shared.BrowserExtensions;

/// <summary>
/// Platform-neutral browser-extension inventory scanning: manifest.json / Secure
/// Preferences / Preferences parsing for Chrome + Edge, extensions.json parsing
/// for Firefox. Lives in Shared (no Windows TFM) so BrowserExtensionScanLogicTests
/// can run on macOS CI without any registry/WMI dependency — mirrors the
/// HardwareHealthLogic/BackupStatusLogic split. BrowserExtensionScanner (Service,
/// Windows-only) resolves the real per-user profile roots and SID/account
/// attribution, then hands each one to <see cref="ScanUserProfile"/> here for the
/// actual file/JSON work.
///
/// Field set and directory layout mirror updater/macos/lib/browser_extensions.sh
/// exactly (modulo the OS-specific profile roots), so both platforms feed the same
/// device_browser_extensions schema (migration 0018) with no server change.
///
/// PAT-2052: the scan runs as SYSTEM over a tree the profile's user owns, so it reads through
/// <see cref="UserTreeReader"/> exactly as the PAT-2050 collectors do. The profile root is
/// registered with <see cref="UserTreeReader.AddRoot"/>; whether anything below it exists comes
/// only from verified-handle listings of its parent; every file is read with the reader's
/// post-open identity check. A directory swapped for a junction into another profile is
/// refused whatever it points at, so the output is the same whether or not that profile holds
/// what was looked for. browser_extensions[] itself has no partial or unreadable state: the
/// refused part contributes no rows, <see cref="BrowserExtensionProfileScan.Partial"/> records
/// it for the agent's own log, and (PAT-2065) <see cref="BrowserExtensionProfileScan.Browsers"/>
/// says per browser whether the read was complete, partial, not_present or failed, which
/// <see cref="BrowserExtensionStatusLogic"/> turns into the browser_extensions_status block.
/// </summary>
internal static class BrowserExtensionScanLogic
{
    private static readonly (string VendorPath, string Browser)[] ChromiumBrowsers =
    [
        (Path.Combine("Google", "Chrome"), "chrome"),
        (Path.Combine("Microsoft", "Edge"), "edge"),
    ];

    /// <summary>Secure Preferences / Preferences: a few MB for a heavy profile.</summary>
    internal const int PreferencesCap = 32 * 1024 * 1024;

    /// <summary>An extension's manifest.json or one locale's messages.json.</summary>
    internal const int ManifestCap = 4 * 1024 * 1024;

    /// <summary>Firefox's extensions.json: a few MB with many add-ons.</summary>
    internal const int FirefoxExtensionsCap = 32 * 1024 * 1024;

    /// <summary>
    /// Scans one user's Chrome, Edge, and Firefox extensions given their Windows
    /// profile root (e.g. <c>C:\Users\alice</c>) and the account name/SID to
    /// attribute the results to. Never throws — per-browser, per-profile, and
    /// per-extension failures are caught and skipped so one corrupt profile can't
    /// drop the rest of the device's inventory (mirrors browser_extensions.sh's
    /// "skip unreadable dirs, never abort the loop" contract).
    ///
    /// <paramref name="maxResults"/> bounds actual scan work, not just the
    /// returned list: enumeration stops (and the lazy per-extension parsing behind
    /// it never runs) as soon as the cap is hit, so a profile with a pathological
    /// number of Extensions/ subdirectories can't make a single scan run unbounded.
    /// </summary>
    public static IReadOnlyList<InventoryBrowserExtension> ScanUserProfile(
        string profileRoot, string userAccount, int maxResults = int.MaxValue, BrowserExtensionScanOptions? options = null) =>
        Scan(profileRoot, userAccount, maxResults, options).Extensions;

    /// <summary>
    /// <see cref="ScanUserProfile"/> plus whether any part of the profile was refused or could
    /// not be read (PAT-2052), and each browser's collection status (PAT-2065). One reader, and
    /// so one listing cache, per call: nothing cached outlives the scan of this profile.
    ///
    /// <paramref name="maxResults"/> is this profile's share of the row cap. The scan stops at
    /// the first row past it (<see cref="BrowserExtensionProfileScan.Capped"/>): the browser it
    /// was reading and every browser after it are partial, never complete.
    /// </summary>
    public static BrowserExtensionProfileScan Scan(
        string profileRoot, string userAccount, int maxResults = int.MaxValue, BrowserExtensionScanOptions? options = null)
    {
        var run = new Run(options ?? new BrowserExtensionScanOptions());
        var results = new List<InventoryBrowserExtension>();
        BrowserExtensionBrowserStatuses browsers;
        try
        {
            browsers = run.Execute(profileRoot, userAccount, maxResults, results);
        }
        catch (Exception)
        {
            run.Partial = true;
            run.UserFailed = true;
            browsers = BrowserExtensionBrowserStatuses.All(BrowserExtensionCollectionStatus.Failed);
        }
        return new BrowserExtensionProfileScan(results, run.Partial)
        {
            Browsers = browsers,
            Capped = run.Capped,
            UserFailed = run.UserFailed,
        };
    }

    private sealed class Run(BrowserExtensionScanOptions options)
    {
        private readonly UserTreeReader _reader =
            new(options.VerifyOpenedFile, options.ResolveRootFinalPath, options.ListOpenedDirectory);

        private bool _partial;

        // PAT-2065: the browser being read. Every refusal while it is read makes it partial;
        // a missing user-data directory makes it not_present.
        private bool _scopePartial;
        private bool _scopeNotPresent;

        /// <summary>Any part of the profile was refused or unreadable (PAT-2052's health signal).</summary>
        public bool Partial
        {
            get => _partial;
            set
            {
                if (!value) return;
                _partial = true;
                _scopePartial = true;
            }
        }

        public bool Capped { get; private set; }

        public bool UserFailed { get; set; }

        public BrowserExtensionBrowserStatuses Execute(
            string profileRoot, string userAccount, int maxResults, List<InventoryBrowserExtension> results)
        {
            // The profile root itself is registered only from a handle on it (PAT-2040): a
            // root that is, or is reached through, a junction is refused, never read through.
            var rootKind = UserTreeReader.KindOf(profileRoot);
            if (rootKind == FsKind.Absent)
            {
                // PAT-2065 review: the profile is registered, so a missing root is an unmounted
                // volume or a detached profile container, not a user without browsers. Nothing
                // was read: failed, never not_present. (macOS differs on purpose: a home missing
                // from /Users is a deleted user, and is never listed.) Not a health fault: no
                // part of a present profile was refused.
                UserFailed = true;
                return BrowserExtensionBrowserStatuses.All(BrowserExtensionCollectionStatus.Failed);
            }
            if (rootKind != FsKind.Dir || !_reader.AddRoot(profileRoot))
            {
                // A profile root that cannot be entered is never read: the user's read failed.
                Partial = true;
                UserFailed = true;
                return BrowserExtensionBrowserStatuses.All(BrowserExtensionCollectionStatus.Failed);
            }

            var statuses = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var (vendorPath, browser) in ChromiumBrowsers)
            {
                statuses[browser] = ReadBrowser(
                    () => ScanChromiumUserData(profileRoot, vendorPath, browser, userAccount), maxResults, results);
            }
            statuses["firefox"] = ReadBrowser(() => ScanFirefoxProfiles(profileRoot, userAccount), maxResults, results);
            return new BrowserExtensionBrowserStatuses(statuses["chrome"], statuses["edge"], statuses["firefox"]);
        }

        /// <summary>
        /// One browser's rows into <paramref name="results"/>, and that browser's status. The cap
        /// is met at the first row past it, so a browser whose rows exactly fill the share is
        /// still complete. Once capped, later browsers are not read and are partial.
        /// </summary>
        private string ReadBrowser(
            Func<IEnumerable<InventoryBrowserExtension>> source, int maxResults, List<InventoryBrowserExtension> results)
        {
            if (Capped) return BrowserExtensionCollectionStatus.Partial;
            _scopePartial = false;
            _scopeNotPresent = false;
            try
            {
                foreach (var entry in source())
                {
                    if (results.Count >= maxResults)
                    {
                        Capped = true;
                        return BrowserExtensionCollectionStatus.Partial;
                    }
                    results.Add(entry);
                }
            }
            catch (Exception)
            {
                Partial = true;
                return BrowserExtensionCollectionStatus.Failed;
            }
            if (_scopeNotPresent) return BrowserExtensionCollectionStatus.NotPresent;
            return _scopePartial ? BrowserExtensionCollectionStatus.Partial : BrowserExtensionCollectionStatus.Complete;
        }

        /// <summary>The sorted entries of <paramref name="dir"/>, or null (and partial) when it cannot be listed.</summary>
        private List<(string Name, FsKind Kind, long Length)>? List(string dir)
        {
            try
            {
                return _reader.ListDirWithLengths(dir);
            }
            catch (UnlistableDirectoryException)
            {
                Partial = true;
                return null;
            }
        }

        /// <summary>A file's text, decoded as File.ReadAllText would; null (and partial) when it cannot be read.</summary>
        private string? ReadText(string path, int cap)
        {
            var (_, data) = _reader.ReadFile(path, cap);
            if (data is null)
            {
                Partial = true;
                return null;
            }
            using var text = new StreamReader(new MemoryStream(data), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            return text.ReadToEnd();
        }

        // ---------------------------------------------------------------------
        // Chromium (Chrome / Edge)
        // ---------------------------------------------------------------------

        private IEnumerable<InventoryBrowserExtension> ScanChromiumUserData(
            string profileRoot, string vendorPath, string browser, string userAccount)
        {
            var (kind, userDataDir) = _reader.Walk(profileRoot, "AppData", "Local", vendorPath, "User Data");
            if (kind == FsKind.Absent)
            {
                _scopeNotPresent = true;
                yield break;
            }
            if (kind != FsKind.Dir)
            {
                Partial = true;
                yield break;
            }
            if (List(userDataDir) is not { } entries) yield break;

            // Chrome/Edge always name profile directories "Default" or "Profile N"
            // internally, regardless of any display name the user sets — same
            // assumption browser_extensions.sh makes. "Default" first, as before.
            var profileNames = new List<string>();
            var defaultKind = UserTreeReader.Find(entries, "Default");
            if (defaultKind == FsKind.Dir) profileNames.Add("Default");
            else if (defaultKind != FsKind.Absent) Partial = true;
            foreach (var (name, entryKind, _) in entries)
            {
                if (!name.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase)) continue;
                if (entryKind == FsKind.Dir) profileNames.Add(name);
                else Partial = true;
            }

            foreach (var profileName in profileNames)
            {
                var profileDir = Path.Combine(userDataDir, profileName);
                if (List(profileDir) is not { } profileEntries) continue;

                var extensionsKind = UserTreeReader.Find(profileEntries, "Extensions");
                if (extensionsKind == FsKind.Absent) continue;
                if (extensionsKind != FsKind.Dir)
                {
                    Partial = true;
                    continue;
                }
                var extensionsDir = Path.Combine(profileDir, "Extensions");

                var settings = ReadChromiumExtensionSettings(profileDir, profileEntries);

                if (List(extensionsDir) is not { } extensionEntries) continue;
                foreach (var (extId, extKind, _) in extensionEntries)
                {
                    if (extKind == FsKind.File) continue;
                    if (extKind != FsKind.Dir)
                    {
                        Partial = true;
                        continue;
                    }
                    var entry = TryBuildChromiumEntry(extensionsDir, extId, browser, profileName, userAccount, settings);
                    if (entry is not null) yield return entry;
                }
            }
        }

        /// <summary>
        /// Reads extensions.settings from Secure Preferences (preferred) or Preferences
        /// (fallback) for enabled/disabled state — same precedence as browser_extensions.sh.
        /// </summary>
        private IReadOnlyDictionary<string, JsonElement> ReadChromiumExtensionSettings(
            string profileDir, List<(string Name, FsKind Kind, long Length)> profileEntries)
        {
            foreach (var prefsName in new[] { "Secure Preferences", "Preferences" })
            {
                var kind = UserTreeReader.Find(profileEntries, prefsName);
                if (kind == FsKind.Absent) continue;
                if (kind != FsKind.File)
                {
                    Partial = true;
                    continue;
                }
                if (ReadText(Path.Combine(profileDir, prefsName), PreferencesCap) is not { } text) continue;

                try
                {
                    using var doc = JsonDocument.Parse(text);
                    if (doc.RootElement.TryGetProperty("extensions", out var ext) &&
                        ext.TryGetProperty("settings", out var settings) &&
                        settings.ValueKind == JsonValueKind.Object)
                    {
                        return settings.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone());
                    }
                    return new Dictionary<string, JsonElement>();
                }
                catch
                {
                    // Corrupt — fall through to the next candidate file.
                }
            }
            return new Dictionary<string, JsonElement>();
        }

        private InventoryBrowserExtension? TryBuildChromiumEntry(
            string extensionsDir, string extId, string browser, string profileName, string userAccount,
            IReadOnlyDictionary<string, JsonElement> settings)
        {
            try
            {
                var extPath = Path.Combine(extensionsDir, extId);
                if (List(extPath) is not { } versionEntries) return null;

                // Find the latest version directory (ordinal sort, take last) that has a
                // manifest.json — same tie-break as browser_extensions.sh.
                string? manifestPath = null;
                string? versionDir = null;
                var version = "";
                foreach (var (verName, verKind, _) in versionEntries)
                {
                    if (verKind == FsKind.File) continue;
                    if (verKind != FsKind.Dir)
                    {
                        Partial = true;
                        continue;
                    }
                    var candidateDir = Path.Combine(extPath, verName);
                    var candidate = Path.Combine(candidateDir, "manifest.json");
                    var manifestKind = _reader.KindAt(candidate);
                    if (manifestKind == FsKind.File)
                    {
                        manifestPath = candidate;
                        versionDir = candidateDir;
                        version = verName;
                    }
                    else if (manifestKind != FsKind.Absent)
                    {
                        Partial = true;
                    }
                }
                if (manifestPath is null || versionDir is null) return null;

                if (ReadText(manifestPath, ManifestCap) is not { } manifestText) return null;
                using var manifestDoc = JsonDocument.Parse(manifestText);
                var mf = manifestDoc.RootElement;

                var name = ResolveChromiumName(mf, versionDir, extId);

                var enabled = true;
                if (settings.TryGetValue(extId, out var extSetting) &&
                    extSetting.ValueKind == JsonValueKind.Object &&
                    extSetting.TryGetProperty("state", out var stateEl) &&
                    stateEl.ValueKind == JsonValueKind.Number)
                {
                    enabled = stateEl.GetInt32() == 1;
                }

                var manifestVersion = mf.TryGetProperty("manifest_version", out var mvEl) &&
                                       mvEl.ValueKind == JsonValueKind.Number
                    ? mvEl.GetInt32()
                    : 2;

                var rawPerms = ReadStringArray(mf, "permissions");
                var hostPerms = ReadStringArray(mf, "host_permissions");

                // MV2 bundles host patterns inside the permissions array; MV3 separates
                // them into host_permissions. Split MV2's permissions the same way
                // browser_extensions.sh does.
                if (manifestVersion == 2)
                {
                    var apiPerms = new List<string>();
                    var extraHosts = new List<string>();
                    foreach (var p in rawPerms)
                    {
                        if (p.StartsWith("http", StringComparison.OrdinalIgnoreCase) ||
                            p.StartsWith('*') || p == "<all_urls>")
                            extraHosts.Add(p);
                        else
                            apiPerms.Add(p);
                    }
                    rawPerms = apiPerms;
                    hostPerms = extraHosts.Concat(hostPerms).ToList();
                }

                var updateUrl = mf.TryGetProperty("update_url", out var uEl) ? uEl.GetString() ?? "" : "";
                var fromWebstore =
                    updateUrl.Contains("clients2.google.com", StringComparison.OrdinalIgnoreCase) ||
                    updateUrl.Contains("update.googleapis.com", StringComparison.OrdinalIgnoreCase);

                return new InventoryBrowserExtension
                {
                    Browser         = browser,
                    Profile         = profileName,
                    UserAccount     = userAccount,
                    ExtensionId     = extId,
                    Name            = name,
                    Version         = version,
                    Enabled         = enabled,
                    Permissions     = rawPerms,
                    HostPermissions = hostPerms,
                    FromWebstore    = fromWebstore,
                    UpdateUrl       = string.IsNullOrEmpty(updateUrl) ? null : updateUrl,
                };
            }
            catch
            {
                // PAT-2065: a manifest that exists but cannot be parsed lists nothing.
                Partial = true;
                return null;
            }
        }

        /// <summary>
        /// Resolves __MSG_ i18n names via the extension's default locale, same as
        /// browser_extensions.sh. PAT-2052: default_locale comes from a file the user writes,
        /// so it must be one plain path component (no separator, drive colon, wildcard or dot
        /// name) before it is looked up at all: "..\..\bob\x" would otherwise have SYSTEM
        /// read, and report as a name, a file in another profile.
        /// </summary>
        private string ResolveChromiumName(JsonElement mf, string versionDir, string extId)
        {
            var name = mf.TryGetProperty("name", out var nameEl) ? nameEl.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(name)) name = extId;

            if (name.StartsWith("__MSG_", StringComparison.Ordinal) &&
                mf.TryGetProperty("default_locale", out var localeEl) &&
                localeEl.ValueKind == JsonValueKind.String &&
                localeEl.GetString() is { Length: > 0 } unsafeLocale &&
                !IsPlainComponent(unsafeLocale))
            {
                // PAT-2065: refused, as the macOS collector refuses it (unsafe_default_locale).
                Partial = true;
            }
            else if (name.StartsWith("__MSG_", StringComparison.Ordinal) &&
                mf.TryGetProperty("default_locale", out localeEl) &&
                localeEl.ValueKind == JsonValueKind.String &&
                localeEl.GetString() is { Length: > 0 } locale)
            {
                var key = name[6..].TrimEnd('_').ToLowerInvariant();
                var (localeKind, localeDir) = _reader.Walk(versionDir, "_locales", locale);
                if (localeKind == FsKind.Dir)
                {
                    var msgsPath = Path.Combine(localeDir, "messages.json");
                    var msgsKind = _reader.KindAt(msgsPath);
                    if (msgsKind == FsKind.File && ReadText(msgsPath, ManifestCap) is { } msgsText)
                    {
                        try
                        {
                            using var msgsDoc = JsonDocument.Parse(msgsText);
                            foreach (var prop in msgsDoc.RootElement.EnumerateObject())
                            {
                                if (string.Equals(prop.Name, key, StringComparison.OrdinalIgnoreCase) &&
                                    prop.Value.TryGetProperty("message", out var msgEl))
                                {
                                    var resolved = msgEl.GetString();
                                    if (!string.IsNullOrEmpty(resolved)) name = resolved;
                                    break;
                                }
                            }
                        }
                        catch
                        {
                            // Keep the __MSG_ placeholder handling below.
                        }
                    }
                    else if (msgsKind is not (FsKind.File or FsKind.Absent))
                    {
                        Partial = true;
                    }
                }
                else if (localeKind != FsKind.Absent)
                {
                    Partial = true;
                }
            }

            if (string.IsNullOrEmpty(name) || name.StartsWith("__MSG_", StringComparison.Ordinal))
                name = extId;

            return name;
        }

        // ---------------------------------------------------------------------
        // Firefox
        // ---------------------------------------------------------------------

        private IEnumerable<InventoryBrowserExtension> ScanFirefoxProfiles(string profileRoot, string userAccount)
        {
            var (kind, profilesDir) = _reader.Walk(profileRoot, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles");
            if (kind == FsKind.Absent)
            {
                _scopeNotPresent = true;
                yield break;
            }
            if (kind != FsKind.Dir)
            {
                Partial = true;
                yield break;
            }
            if (List(profilesDir) is not { } profiles) yield break;

            foreach (var (profileName, profileKind, _) in profiles)
            {
                if (profileKind == FsKind.File) continue;
                if (profileKind != FsKind.Dir)
                {
                    Partial = true;
                    continue;
                }
                var extFile = Path.Combine(profilesDir, profileName, "extensions.json");
                var extKind = _reader.KindAt(extFile);
                if (extKind == FsKind.Absent) continue;
                if (extKind != FsKind.File)
                {
                    Partial = true;
                    continue;
                }
                if (ReadText(extFile, FirefoxExtensionsCap) is not { } text) continue;

                JsonDocument doc;
                try
                {
                    doc = JsonDocument.Parse(text);
                }
                catch
                {
                    // PAT-2065: an extensions.json that cannot be parsed lists nothing.
                    Partial = true;
                    continue;
                }
                using (doc)
                {
                    foreach (var entry in ScanFirefoxExtensionsFile(doc, profileName, userAccount))
                        yield return entry;
                }
            }
        }

        /// <summary>
        /// One extensions.json's rows. PAT-2068: the same shapes macOS marks partial
        /// (browser_extensions.sh, firefox_profile) mark this pair partial here: a top level
        /// that is not an object, an "addons" that is present but not a list, and an add-on
        /// entry that cannot be read. A missing "addons" is an empty list, as on macOS. Add-ons
        /// whose type is not "extension" (themes, dictionaries, locales) are out of scope and
        /// filtered, never partial.
        /// </summary>
        private IEnumerable<InventoryBrowserExtension> ScanFirefoxExtensionsFile(
            JsonDocument doc, string profileName, string userAccount)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                Partial = true;
                yield break;
            }
            if (!root.TryGetProperty("addons", out var addons)) yield break;
            if (addons.ValueKind != JsonValueKind.Array)
            {
                Partial = true;
                yield break;
            }

            foreach (var addon in addons.EnumerateArray())
            {
                var entry = TryBuildFirefoxEntry(addon, profileName, userAccount, out var malformed);
                // An add-on the agent could not read is never evidence it is absent.
                if (malformed) Partial = true;
                if (entry is not null) yield return entry;
            }
        }
    }

    /// <summary>A single plain path component: no separator, drive colon, wildcard, control character or dot name.</summary>
    internal static bool IsPlainComponent(string value) =>
        value.Length is > 0 and <= 64
        && value is not ("." or "..")
        && value.All(c => c >= 0x20 && c != 0x7F && c is not ('\\' or '/' or ':' or '*' or '?' or '"' or '<' or '>' or '|'));

    /// <summary>
    /// One add-on entry as a row, or null. <paramref name="malformed"/> is set when the entry
    /// was dropped because it could not be read (not an object, no usable id, or a read that
    /// threw), never when it was filtered as out of scope. A wrong-typed optional field
    /// (name, version, updateURL) is read as empty, as macOS's text() does, and keeps the row.
    /// </summary>
    private static InventoryBrowserExtension? TryBuildFirefoxEntry(
        JsonElement addon, string profileName, string userAccount, out bool malformed)
    {
        malformed = false;
        try
        {
            if (addon.ValueKind != JsonValueKind.Object)
            {
                malformed = true;
                return null;
            }

            // Out of scope, not malformed: any type other than the string "extension".
            if (!addon.TryGetProperty("type", out var typeEl) ||
                typeEl.ValueKind != JsonValueKind.String ||
                typeEl.GetString() != "extension")
                return null;

            var extId = JsonText(addon, "id");
            if (string.IsNullOrEmpty(extId))
            {
                malformed = true;
                return null;
            }

            var name = extId;
            if (addon.TryGetProperty("defaultLocale", out var localeEl) &&
                localeEl.ValueKind == JsonValueKind.Object &&
                JsonText(localeEl, "name") is { Length: > 0 } localName)
            {
                name = localName;
            }

            var version = JsonText(addon, "version");

            var active = GetBool(addon, "active", true);
            var userDisabled = GetBool(addon, "userDisabled", false);
            var enabled = active && !userDisabled;

            var permissions = ReadStringArray(addon, "permissions");
            var hostPermissions = new List<string>();

            if (addon.TryGetProperty("userPermissions", out var userPerms) &&
                userPerms.ValueKind == JsonValueKind.Object)
            {
                permissions = permissions.Concat(ReadStringArray(userPerms, "permissions")).ToList();
                // PAT-2073: current Firefox writes granted host permissions under
                // userPermissions.origins; "hosts" is the older key, still read for old
                // profiles. The union keeps first-seen order. Optional permissions
                // (optionalPermissions.origins) are not granted and are left out, as the
                // Chromium reader leaves out optional_host_permissions. A wrong type reads
                // as empty and keeps the row, never partial (PAT-2068).
                hostPermissions = UniqueInOrder(
                    ReadStringArray(userPerms, "origins").Concat(ReadStringArray(userPerms, "hosts")));
            }

            var updateUrl = JsonText(addon, "updateURL");
            var fromWebstore = updateUrl.Contains("addons.mozilla.org", StringComparison.OrdinalIgnoreCase);

            return new InventoryBrowserExtension
            {
                Browser         = "firefox",
                Profile         = profileName,
                UserAccount     = userAccount,
                ExtensionId     = extId,
                Name            = string.IsNullOrEmpty(name) ? extId : name,
                Version         = version,
                Enabled         = enabled,
                Permissions     = permissions,
                HostPermissions = hostPermissions,
                FromWebstore    = fromWebstore,
                UpdateUrl       = string.IsNullOrEmpty(updateUrl) ? null : updateUrl,
            };
        }
        catch
        {
            malformed = true;
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Shared JSON helpers
    // -------------------------------------------------------------------------

    private static List<string> ReadStringArray(JsonElement obj, string prop)
    {
        var list = new List<string>();
        if (obj.TryGetProperty(prop, out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in arr.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    var s = item.GetString();
                    if (s is not null) list.Add(s);
                }
            }
        }
        return list;
    }

    /// <summary>Items with repeats removed (ordinal), first-seen order kept, as macOS's unique().</summary>
    private static List<string> UniqueInOrder(IEnumerable<string> items)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var list = new List<string>();
        foreach (var item in items)
            if (seen.Add(item)) list.Add(item);
        return list;
    }

    /// <summary>The string value of <paramref name="prop"/>, or "" when it is missing or not a string.</summary>
    private static string JsonText(JsonElement obj, string prop) =>
        obj.TryGetProperty(prop, out var el) && el.ValueKind == JsonValueKind.String ? el.GetString() ?? "" : "";

    private static bool GetBool(JsonElement obj, string prop, bool defaultValue)
    {
        if (obj.TryGetProperty(prop, out var el))
        {
            if (el.ValueKind == JsonValueKind.True) return true;
            if (el.ValueKind == JsonValueKind.False) return false;
        }
        return defaultValue;
    }
}

/// <summary>PAT-2052: one profile's browser extensions, and whether any part of it was refused or unreadable.</summary>
internal sealed record BrowserExtensionProfileScan(IReadOnlyList<InventoryBrowserExtension> Extensions, bool Partial)
{
    /// <summary>PAT-2065: each browser's collection status for this profile.</summary>
    public BrowserExtensionBrowserStatuses Browsers { get; init; } =
        BrowserExtensionBrowserStatuses.All(BrowserExtensionCollectionStatus.Failed);

    /// <summary>PAT-2065: the scan stopped at its share of the row cap.</summary>
    public bool Capped { get; init; }

    /// <summary>PAT-2065: the profile could not be entered, or its scan threw outside any one browser.</summary>
    public bool UserFailed { get; init; }
}

/// <summary>PAT-2052: the file-safety hooks for <see cref="BrowserExtensionScanLogic.Scan"/>, as the other collectors have.</summary>
internal sealed class BrowserExtensionScanOptions
{
    /// <summary>
    /// Checks an opened handle against the path the scan meant to open (link count, final
    /// path). <see cref="WindowsFileIdentity.IsExpectedRegularFile"/> on Windows; nothing
    /// elsewhere, where the scan runs only under test.
    /// </summary>
    public Func<SafeFileHandle, string, bool>? VerifyOpenedFile { get; init; } =
        OperatingSystem.IsWindows() ? WindowsFileIdentity.IsExpectedRegularFile : null;

    /// <summary>Kernel-resolved final path of the profile root; null from it refuses the root.</summary>
    public Func<string, string?>? ResolveRootFinalPath { get; init; } =
        OperatingSystem.IsWindows() ? WindowsFileIdentity.FinalPathOfDirectory : null;

    /// <summary>
    /// For tests only: lists a directory given (path, expected final path). Null, the default,
    /// is the reader's own verified-handle lister (<see cref="UserTreeReader.DefaultLister"/>).
    /// </summary>
    internal Func<string, string, List<(string Name, FsKind Kind, long Length)>?>? ListOpenedDirectory { get; init; }
}
