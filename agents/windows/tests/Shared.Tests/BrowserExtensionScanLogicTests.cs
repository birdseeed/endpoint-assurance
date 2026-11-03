using System.Text.Json;
using System.Text.RegularExpressions;
using Patched.Shared.BrowserExtensions;
using Patched.Shared.UserTrees;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// Platform-neutral tests for <see cref="BrowserExtensionScanLogic"/> — pure
/// file/JSON parsing (Chrome/Edge manifest.json + Secure Preferences/Preferences,
/// Firefox extensions.json), no registry or WMI dependency, so these run on any
/// OS including macOS CI (mirrors HardwareHealthLogicTests/BackupStatusLogicTests).
///
/// Covers PAT-773's multi-user / multi-profile acceptance criterion: each test
/// builds a fake "user profile root" directory tree under a temp folder and
/// scans it directly with <see cref="BrowserExtensionScanLogic.ScanUserProfile"/>,
/// exactly as BrowserExtensionScanner (Service) does for each real Windows profile.
/// </summary>
public sealed class BrowserExtensionScanLogicTests : IDisposable
{
    private readonly string _tempRoot;

    public BrowserExtensionScanLogicTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), "patched-bx-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempRoot);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempRoot, recursive: true); } catch { /* best-effort cleanup */ }
    }

    private string NewProfileRoot(string name)
    {
        var root = Path.Combine(_tempRoot, name);
        Directory.CreateDirectory(root);
        return root;
    }

    // -------------------------------------------------------------------------
    // Chromium (Chrome/Edge) basics
    // -------------------------------------------------------------------------

    [Fact]
    public void ScanUserProfile_NoBrowsersInstalled_ReturnsEmpty()
    {
        var root = NewProfileRoot("alice");
        var result = BrowserExtensionScanLogic.ScanUserProfile(root, "alice");
        Assert.Empty(result);
    }

    [Fact]
    public void ScanUserProfile_ChromeSingleExtension_Enabled_FieldsMatch()
    {
        var root = NewProfileRoot("alice");
        WriteChromiumExtension(root, "Google", "Chrome", "Default", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3",
            manifest: """
            {
              "name": "uBlock Origin",
              "manifest_version": 3,
              "permissions": ["storage", "webRequest"],
              "host_permissions": ["<all_urls>"],
              "update_url": "https://clients2.google.com/service/update2/crx"
            }
            """,
            securePreferences: BuildSecurePreferences(("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", state: 1)));

        var result = BrowserExtensionScanLogic.ScanUserProfile(root, "alice");

        var ext = Assert.Single(result);
        Assert.Equal("chrome", ext.Browser);
        Assert.Equal("Default", ext.Profile);
        Assert.Equal("alice", ext.UserAccount);
        Assert.Equal("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ext.ExtensionId);
        Assert.Equal("uBlock Origin", ext.Name);
        Assert.Equal("1.2.3", ext.Version);
        Assert.True(ext.Enabled);
        Assert.Equal(["storage", "webRequest"], ext.Permissions);
        Assert.Equal(["<all_urls>"], ext.HostPermissions);
        Assert.True(ext.FromWebstore);
        Assert.Equal("https://clients2.google.com/service/update2/crx", ext.UpdateUrl);
    }

    [Fact]
    public void ScanUserProfile_ChromeExtension_DisabledInSecurePreferences_EnabledFalse()
    {
        var root = NewProfileRoot("alice");
        WriteChromiumExtension(root, "Google", "Chrome", "Default", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "4.0",
            manifest: """{ "name": "Some Extension", "manifest_version": 3 }""",
            securePreferences: BuildSecurePreferences(("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", state: 0)));

        var ext = Assert.Single(BrowserExtensionScanLogic.ScanUserProfile(root, "alice"));
        Assert.False(ext.Enabled);
    }

    [Fact]
    public void ScanUserProfile_ChromeExtension_AbsentFromSettings_DefaultsEnabledTrue()
    {
        var root = NewProfileRoot("alice");
        WriteChromiumExtension(root, "Google", "Chrome", "Default", "cccccccccccccccccccccccccccccccc", "1.0",
            manifest: """{ "name": "No Settings Entry", "manifest_version": 3 }""",
            securePreferences: null);

        var ext = Assert.Single(BrowserExtensionScanLogic.ScanUserProfile(root, "alice"));
        Assert.True(ext.Enabled);
    }

    [Fact]
    public void ScanUserProfile_Edge_UsesEdgeBrowserLabel()
    {
        var root = NewProfileRoot("alice");
        WriteChromiumExtension(root, "Microsoft", "Edge", "Default", "dddddddddddddddddddddddddddddddd", "1.0",
            manifest: """{ "name": "Edge Ext", "manifest_version": 3 }""",
            securePreferences: null);

        var ext = Assert.Single(BrowserExtensionScanLogic.ScanUserProfile(root, "alice"));
        Assert.Equal("edge", ext.Browser);
    }

    // -------------------------------------------------------------------------
    // Manifest version permission splitting
    // -------------------------------------------------------------------------

    [Fact]
    public void ScanUserProfile_ManifestV2_HostPatternsInPermissions_SplitIntoHostPermissions()
    {
        var root = NewProfileRoot("alice");
        WriteChromiumExtension(root, "Google", "Chrome", "Default", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "1.0",
            manifest: """
            {
              "name": "MV2 Extension",
              "manifest_version": 2,
              "permissions": ["storage", "https://*.example.com/*", "<all_urls>", "tabs"]
            }
            """,
            securePreferences: null);

        var ext = Assert.Single(BrowserExtensionScanLogic.ScanUserProfile(root, "alice"));
        Assert.Equal(["storage", "tabs"], ext.Permissions);
        Assert.Equal(["https://*.example.com/*", "<all_urls>"], ext.HostPermissions);
    }

    [Fact]
    public void ScanUserProfile_ManifestV3_HostPermissionsKeptSeparate()
    {
        var root = NewProfileRoot("alice");
        WriteChromiumExtension(root, "Google", "Chrome", "Default", "ffffffffffffffffffffffffffffffff", "1.0",
            manifest: """
            {
              "name": "MV3 Extension",
              "manifest_version": 3,
              "permissions": ["storage", "tabs"],
              "host_permissions": ["https://*.example.com/*"]
            }
            """,
            securePreferences: null);

        var ext = Assert.Single(BrowserExtensionScanLogic.ScanUserProfile(root, "alice"));
        Assert.Equal(["storage", "tabs"], ext.Permissions);
        Assert.Equal(["https://*.example.com/*"], ext.HostPermissions);
    }

    // -------------------------------------------------------------------------
    // __MSG_ i18n name resolution
    // -------------------------------------------------------------------------

    [Fact]
    public void ScanUserProfile_MsgPlaceholderName_ResolvedViaDefaultLocaleMessages()
    {
        var root = NewProfileRoot("alice");
        var extDir = WriteChromiumExtension(root, "Google", "Chrome", "Default",
            "10101010101010101010101010101010", "1.0",
            manifest: """
            {
              "name": "__MSG_extName__",
              "manifest_version": 3,
              "default_locale": "en"
            }
            """,
            securePreferences: null);

        var localeDir = Path.Combine(extDir, "_locales", "en");
        Directory.CreateDirectory(localeDir);
        File.WriteAllText(Path.Combine(localeDir, "messages.json"), """
            { "extName": { "message": "Resolved Extension Name" } }
            """);

        var ext = Assert.Single(BrowserExtensionScanLogic.ScanUserProfile(root, "alice"));
        Assert.Equal("Resolved Extension Name", ext.Name);
    }

    [Fact]
    public void ScanUserProfile_MsgPlaceholderName_NoMessagesFile_FallsBackToExtensionId()
    {
        var root = NewProfileRoot("alice");
        WriteChromiumExtension(root, "Google", "Chrome", "Default",
            "20202020202020202020202020202020", "1.0",
            manifest: """
            {
              "name": "__MSG_missing__",
              "manifest_version": 3,
              "default_locale": "en"
            }
            """,
            securePreferences: null);

        var ext = Assert.Single(BrowserExtensionScanLogic.ScanUserProfile(root, "alice"));
        Assert.Equal("20202020202020202020202020202020", ext.Name);
    }

    // -------------------------------------------------------------------------
    // Latest-version resolution
    // -------------------------------------------------------------------------

    [Fact]
    public void ScanUserProfile_MultipleVersionDirs_PicksLatestWithManifest()
    {
        var root = NewProfileRoot("alice");
        var extId = "30303030303030303030303030303030";
        var extensionsDir = Path.Combine(
            root, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Extensions", extId);
        Directory.CreateDirectory(Path.Combine(extensionsDir, "1.0"));
        Directory.CreateDirectory(Path.Combine(extensionsDir, "2.0"));
        File.WriteAllText(Path.Combine(extensionsDir, "1.0", "manifest.json"),
            """{ "name": "Old", "manifest_version": 3 }""");
        File.WriteAllText(Path.Combine(extensionsDir, "2.0", "manifest.json"),
            """{ "name": "New", "manifest_version": 3 }""");

        var ext = Assert.Single(BrowserExtensionScanLogic.ScanUserProfile(root, "alice"));
        Assert.Equal("2.0", ext.Version);
        Assert.Equal("New", ext.Name);
    }

    [Fact]
    public void ScanUserProfile_VersionDirWithoutManifest_Skipped_NoCrash()
    {
        var root = NewProfileRoot("alice");
        var extId = "40404040404040404040404040404040";
        var extensionsDir = Path.Combine(
            root, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Extensions", extId);
        Directory.CreateDirectory(Path.Combine(extensionsDir, "1.0"));

        var result = BrowserExtensionScanLogic.ScanUserProfile(root, "alice");
        Assert.Empty(result);
    }

    // -------------------------------------------------------------------------
    // Multi-profile (same user, multiple Chrome profiles)
    // -------------------------------------------------------------------------

    [Fact]
    public void ScanUserProfile_MultipleChromeProfiles_BothScanned_ProfileFieldDistinguishes()
    {
        var root = NewProfileRoot("alice");
        WriteChromiumExtension(root, "Google", "Chrome", "Default", "50505050505050505050505050505050", "1.0",
            manifest: """{ "name": "Default Profile Ext", "manifest_version": 3 }""", securePreferences: null);
        WriteChromiumExtension(root, "Google", "Chrome", "Profile 1", "60606060606060606060606060606060", "1.0",
            manifest: """{ "name": "Work Profile Ext", "manifest_version": 3 }""", securePreferences: null);

        var result = BrowserExtensionScanLogic.ScanUserProfile(root, "alice");

        Assert.Equal(2, result.Count);
        Assert.Contains(result, e => e.Profile == "Default" && e.Name == "Default Profile Ext");
        Assert.Contains(result, e => e.Profile == "Profile 1" && e.Name == "Work Profile Ext");
        Assert.All(result, e => Assert.Equal("alice", e.UserAccount));
    }

    // -------------------------------------------------------------------------
    // Multi-user (two separate profile roots, mirroring BrowserExtensionScanner
    // calling ScanUserProfile once per enumerated Windows profile)
    // -------------------------------------------------------------------------

    [Fact]
    public void ScanUserProfile_TwoUsers_SameExtensionId_AttributedToCorrectUser()
    {
        var aliceRoot = NewProfileRoot("alice");
        var bobRoot   = NewProfileRoot("bob");
        const string sharedExtId = "70707070707070707070707070707070";

        WriteChromiumExtension(aliceRoot, "Google", "Chrome", "Default", sharedExtId, "1.0",
            manifest: """{ "name": "Shared Ext", "manifest_version": 3 }""", securePreferences: null);
        WriteChromiumExtension(bobRoot, "Google", "Chrome", "Default", sharedExtId, "1.0",
            manifest: """{ "name": "Shared Ext", "manifest_version": 3 }""", securePreferences: null);

        var aliceResults = BrowserExtensionScanLogic.ScanUserProfile(aliceRoot, "CONTOSO\\alice");
        var bobResults   = BrowserExtensionScanLogic.ScanUserProfile(bobRoot, "CONTOSO\\bob");

        var aliceExt = Assert.Single(aliceResults);
        var bobExt   = Assert.Single(bobResults);
        Assert.Equal("CONTOSO\\alice", aliceExt.UserAccount);
        Assert.Equal("CONTOSO\\bob",   bobExt.UserAccount);
        Assert.Equal(sharedExtId, aliceExt.ExtensionId);
        Assert.Equal(sharedExtId, bobExt.ExtensionId);
    }

    [Fact]
    public void ScanUserProfile_OrphanedProfile_FallsBackToRawSidAsUserAccount()
    {
        // Mirrors BrowserExtensionScanner's fallback: when SID translation fails
        // (deleted account, profile left on disk), the raw SID string is passed
        // through as the userAccount attribution instead of a resolved name.
        var root = NewProfileRoot("orphan");
        WriteChromiumExtension(root, "Google", "Chrome", "Default", "80808080808080808080808080808080", "1.0",
            manifest: """{ "name": "Orphan Ext", "manifest_version": 3 }""", securePreferences: null);

        var ext = Assert.Single(BrowserExtensionScanLogic.ScanUserProfile(root, "S-1-5-21-1-2-3-9999"));
        Assert.Equal("S-1-5-21-1-2-3-9999", ext.UserAccount);
    }

    // -------------------------------------------------------------------------
    // Firefox
    // -------------------------------------------------------------------------

    [Fact]
    public void ScanUserProfile_Firefox_EnabledExtension_FieldsMatch()
    {
        var root = NewProfileRoot("alice");
        WriteFirefoxExtensionsJson(root, "abc123.default-release", """
            {
              "addons": [
                {
                  "id": "{ext-guid-1}",
                  "type": "extension",
                  "version": "2024.6.2",
                  "active": true,
                  "userDisabled": false,
                  "defaultLocale": { "name": "Bitwarden" },
                  "permissions": ["storage"],
                  "userPermissions": { "permissions": ["nativeMessaging"], "hosts": ["<all_urls>"] },
                  "updateURL": "https://addons.mozilla.org/firefox/downloads/latest/bitwarden"
                }
              ]
            }
            """);

        var ext = Assert.Single(BrowserExtensionScanLogic.ScanUserProfile(root, "alice"));
        Assert.Equal("firefox", ext.Browser);
        Assert.Equal("abc123.default-release", ext.Profile);
        Assert.Equal("{ext-guid-1}", ext.ExtensionId);
        Assert.Equal("Bitwarden", ext.Name);
        Assert.Equal("2024.6.2", ext.Version);
        Assert.True(ext.Enabled);
        Assert.Contains("storage", ext.Permissions);
        Assert.Contains("nativeMessaging", ext.Permissions);
        Assert.Equal(["<all_urls>"], ext.HostPermissions);
        Assert.True(ext.FromWebstore);
    }

    /// <summary>
    /// PAT-2073: current Firefox writes granted host permissions under userPermissions.origins,
    /// with "hosts" only on old profiles. Both are read, unioned in first-seen order.
    /// optionalPermissions.origins are not granted and are left out, as Chromium's
    /// optional_host_permissions are. Mirrors macOS test-browser-extensions.zsh [firefox-origins].
    /// </summary>
    [Fact]
    public void ScanUserProfile_Firefox_HostPermissionsFromOriginsAndLegacyHosts()
    {
        var root = NewProfileRoot("alice");
        WriteFirefoxExtensionsJson(root, "abc123.default-release", """
            {
              "schemaVersion": 36,
              "addons": [
                {
                  "id": "uBlock0@raymondhill.net",
                  "type": "extension",
                  "version": "1.60.0",
                  "active": true,
                  "userDisabled": false,
                  "defaultLocale": { "name": "uBlock Origin" },
                  "userPermissions": {
                    "permissions": ["dns", "storage", "tabs"],
                    "origins": ["<all_urls>", "http://*/*", "https://*/*"],
                    "data_collection": []
                  },
                  "optionalPermissions": { "permissions": [], "origins": ["file:///*"] },
                  "updateURL": null
                },
                {
                  "id": "legacy@example.com",
                  "type": "extension",
                  "version": "1.0",
                  "userPermissions": { "permissions": ["tabs"], "hosts": ["*://*/*"] }
                },
                {
                  "id": "both@example.com",
                  "type": "extension",
                  "version": "1.0",
                  "userPermissions": { "origins": ["https://a.example/*", "<all_urls>"],
                                       "hosts": ["<all_urls>", "https://b.example/*", "https://b.example/*"] }
                },
                {
                  "id": "optional-only@example.com",
                  "type": "extension",
                  "version": "1.0",
                  "userPermissions": { "permissions": [], "origins": [] },
                  "optionalPermissions": { "permissions": ["tabs"], "origins": ["<all_urls>"] }
                }
              ]
            }
            """);

        var scan = BrowserExtensionScanLogic.Scan(root, "alice");
        var byId = scan.Extensions.ToDictionary(e => e.ExtensionId);

        Assert.Equal(["<all_urls>", "http://*/*", "https://*/*"], byId["uBlock0@raymondhill.net"].HostPermissions);
        Assert.Equal(["dns", "storage", "tabs"], byId["uBlock0@raymondhill.net"].Permissions);
        Assert.Equal(["*://*/*"], byId["legacy@example.com"].HostPermissions);
        Assert.Equal(["https://a.example/*", "<all_urls>", "https://b.example/*"], byId["both@example.com"].HostPermissions);
        Assert.Empty(byId["optional-only@example.com"].HostPermissions);
        Assert.Empty(byId["optional-only@example.com"].Permissions);
        Assert.Equal("complete", scan.Browsers.Firefox);
        Assert.False(scan.Partial);
    }

    /// <summary>
    /// PAT-2073, the PAT-2068 rule for an optional field: a wrong-typed origins or hosts, or a
    /// non-string element, reads as empty (or is dropped) and keeps the row; never partial.
    /// </summary>
    [Fact]
    public void ScanUserProfile_Firefox_WrongTypedOrigins_KeepTheRow_StayComplete()
    {
        var root = NewProfileRoot("alice");
        WriteFirefoxExtensionsJson(root, "abc123.default-release", """
            {
              "addons": [
                { "id": "str@example.com", "type": "extension",
                  "userPermissions": { "origins": "<all_urls>", "hosts": ["https://h.example/*"] } },
                { "id": "mixed@example.com", "type": "extension",
                  "userPermissions": { "origins": [null, 7, "<all_urls>", {"o": 1}, ["x"]], "hosts": {"h": 1} } },
                { "id": "arr@example.com", "type": "extension", "userPermissions": ["<all_urls>"] }
              ]
            }
            """);

        var scan = BrowserExtensionScanLogic.Scan(root, "alice");
        var byId = scan.Extensions.ToDictionary(e => e.ExtensionId);

        Assert.Equal(3, byId.Count);
        Assert.Equal(["https://h.example/*"], byId["str@example.com"].HostPermissions);
        Assert.Equal(["<all_urls>"], byId["mixed@example.com"].HostPermissions);
        Assert.Empty(byId["arr@example.com"].HostPermissions);
        Assert.Equal("complete", scan.Browsers.Firefox);
        Assert.False(scan.Partial);
    }

    [Fact]
    public void ScanUserProfile_Firefox_UserDisabled_EnabledFalse()
    {
        var root = NewProfileRoot("alice");
        WriteFirefoxExtensionsJson(root, "abc123.default-release", """
            {
              "addons": [
                { "id": "{ext-guid-2}", "type": "extension", "version": "1.0",
                  "active": true, "userDisabled": true }
              ]
            }
            """);

        var ext = Assert.Single(BrowserExtensionScanLogic.ScanUserProfile(root, "alice"));
        Assert.False(ext.Enabled);
    }

    [Fact]
    public void ScanUserProfile_Firefox_InactiveAddon_EnabledFalse()
    {
        var root = NewProfileRoot("alice");
        WriteFirefoxExtensionsJson(root, "abc123.default-release", """
            {
              "addons": [
                { "id": "{ext-guid-3}", "type": "extension", "version": "1.0", "active": false }
              ]
            }
            """);

        var ext = Assert.Single(BrowserExtensionScanLogic.ScanUserProfile(root, "alice"));
        Assert.False(ext.Enabled);
    }

    [Fact]
    public void ScanUserProfile_Firefox_NonExtensionAddonType_Excluded()
    {
        var root = NewProfileRoot("alice");
        WriteFirefoxExtensionsJson(root, "abc123.default-release", """
            {
              "addons": [
                { "id": "{theme-guid}", "type": "theme", "version": "1.0" }
              ]
            }
            """);

        var result = BrowserExtensionScanLogic.ScanUserProfile(root, "alice");
        Assert.Empty(result);
    }

    [Fact]
    public void ScanUserProfile_Firefox_NoDefaultLocaleName_FallsBackToId()
    {
        var root = NewProfileRoot("alice");
        WriteFirefoxExtensionsJson(root, "abc123.default-release", """
            {
              "addons": [
                { "id": "{ext-guid-4}", "type": "extension", "version": "1.0" }
              ]
            }
            """);

        var ext = Assert.Single(BrowserExtensionScanLogic.ScanUserProfile(root, "alice"));
        Assert.Equal("{ext-guid-4}", ext.Name);
    }

    [Fact]
    public void ScanUserProfile_Firefox_MultipleProfiles_BothScanned()
    {
        var root = NewProfileRoot("alice");
        WriteFirefoxExtensionsJson(root, "profile1.default-release", """
            { "addons": [ { "id": "{p1-ext}", "type": "extension", "version": "1.0" } ] }
            """);
        WriteFirefoxExtensionsJson(root, "profile2.dev-edition-default", """
            { "addons": [ { "id": "{p2-ext}", "type": "extension", "version": "1.0" } ] }
            """);

        var result = BrowserExtensionScanLogic.ScanUserProfile(root, "alice");

        Assert.Equal(2, result.Count);
        Assert.Contains(result, e => e.Profile == "profile1.default-release" && e.ExtensionId == "{p1-ext}");
        Assert.Contains(result, e => e.Profile == "profile2.dev-edition-default" && e.ExtensionId == "{p2-ext}");
    }

    [Fact]
    public void ScanUserProfile_Firefox_CorruptExtensionsJson_SkippedNoCrash()
    {
        var root = NewProfileRoot("alice");
        var profileDir = Path.Combine(root, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "broken.default");
        Directory.CreateDirectory(profileDir);
        File.WriteAllText(Path.Combine(profileDir, "extensions.json"), "{ not valid json ");

        var result = BrowserExtensionScanLogic.ScanUserProfile(root, "alice");
        Assert.Empty(result);
    }

    // -------------------------------------------------------------------------
    // Mixed Chrome + Edge + Firefox on one profile root
    // -------------------------------------------------------------------------

    [Fact]
    public void ScanUserProfile_AllThreeBrowsers_AllReturned()
    {
        var root = NewProfileRoot("alice");
        WriteChromiumExtension(root, "Google", "Chrome", "Default", "90909090909090909090909090909090", "1.0",
            manifest: """{ "name": "Chrome Ext", "manifest_version": 3 }""", securePreferences: null);
        WriteChromiumExtension(root, "Microsoft", "Edge", "Default", "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", "1.0",
            manifest: """{ "name": "Edge Ext", "manifest_version": 3 }""", securePreferences: null);
        WriteFirefoxExtensionsJson(root, "abc.default-release", """
            { "addons": [ { "id": "{ff-ext}", "type": "extension", "version": "1.0" } ] }
            """);

        var result = BrowserExtensionScanLogic.ScanUserProfile(root, "alice");

        Assert.Equal(3, result.Count);
        Assert.Contains(result, e => e.Browser == "chrome");
        Assert.Contains(result, e => e.Browser == "edge");
        Assert.Contains(result, e => e.Browser == "firefox");
    }

    // -------------------------------------------------------------------------
    // maxResults work-bounding (not just result truncation)
    // -------------------------------------------------------------------------

    [Fact]
    public void ScanUserProfile_MaxResults_StopsAtCap_AcrossBrowsers()
    {
        var root = NewProfileRoot("alice");
        WriteChromiumExtension(root, "Google", "Chrome", "Default", "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0", "1.0",
            manifest: """{ "name": "Chrome Ext", "manifest_version": 3 }""", securePreferences: null);
        WriteChromiumExtension(root, "Microsoft", "Edge", "Default", "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0", "1.0",
            manifest: """{ "name": "Edge Ext", "manifest_version": 3 }""", securePreferences: null);
        WriteFirefoxExtensionsJson(root, "abc.default-release", """
            { "addons": [ { "id": "{ff-ext-2}", "type": "extension", "version": "1.0" } ] }
            """);

        var result = BrowserExtensionScanLogic.ScanUserProfile(root, "alice", maxResults: 2);

        Assert.Equal(2, result.Count);
    }

    [Fact]
    public void ScanUserProfile_MaxResultsZero_ReturnsEmpty_WithoutScanning()
    {
        var root = NewProfileRoot("alice");
        WriteChromiumExtension(root, "Google", "Chrome", "Default", "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0", "1.0",
            manifest: """{ "name": "Chrome Ext", "manifest_version": 3 }""", securePreferences: null);

        var result = BrowserExtensionScanLogic.ScanUserProfile(root, "alice", maxResults: 0);

        Assert.Empty(result);
    }

    // -------------------------------------------------------------------------
    // PAT-2052: existence from verified listings, reads through the verified reader
    // -------------------------------------------------------------------------

    private const string LeakedExtId = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    /// <summary>A user's profile that is not the one being scanned, with a Chrome and a Firefox extension.</summary>
    private static void PopulateOtherProfile(string other)
    {
        WriteChromiumExtension(other, "Google", "Chrome", "Default", LeakedExtId, "9.9",
            manifest: """{ "name": "leaked chrome extension", "manifest_version": 3 }""", securePreferences: null);
        WriteFirefoxExtensionsJson(other, "leaked.default", """
            { "addons": [ { "id": "{leaked}", "type": "extension", "version": "1.0" } ] }
            """);
    }

    private static string Serialise(BrowserExtensionProfileScan scan) =>
        JsonSerializer.Serialize(new { scan.Extensions, scan.Partial });

    /// <summary>
    /// PAT-2052, the profile root swapped after it is registered: alice's profile passes
    /// AddRoot as a real directory and is then swapped for a junction into another profile.
    /// Every existence answer below it comes from a verified listing of its parent, which
    /// refuses the swapped root whatever it points at, so the scan is the same, and partial,
    /// whether the other profile has no extensions or has some: nothing about it is reported
    /// and nothing of alice's is reported as absent-and-complete. Windows only: the refusal is
    /// the handle lister's.
    /// </summary>
    [DirectoryLinkFact]
    public void Scan_OnWindows_ProfileRootSwappedAfterItIsRegistered_IsPartialAndTheSameWhateverTheTargetHolds()
    {
        if (!OperatingSystem.IsWindows()) return;
        var alice = NewProfileRoot("alice");
        WriteChromiumExtension(alice, "Google", "Chrome", "Default", "abababababababababababababababab", "1.0",
            manifest: """{ "name": "Alice Ext", "manifest_version": 3 }""", securePreferences: null);
        var other = NewProfileRoot("other");

        BrowserExtensionProfileScan Run()
        {
            var swap = new RootSwap(alice, other);
            try
            {
                return BrowserExtensionScanLogic.Scan(alice, "alice", options: new BrowserExtensionScanOptions
                {
                    ResolveRootFinalPath = swap.Wrap(new BrowserExtensionScanOptions().ResolveRootFinalPath),
                });
            }
            finally
            {
                Assert.True(swap.Swapped, "the swap never happened");
                swap.Restore();
            }
        }

        var lacking = Run();
        PopulateOtherProfile(other);
        var having = Run();

        Assert.Equal(Serialise(lacking), Serialise(having));
        Assert.DoesNotContain("leaked", Serialise(having), StringComparison.OrdinalIgnoreCase);
        Assert.Empty(lacking.Extensions);
        Assert.True(lacking.Partial);

        // Restored, the same profile scans in full.
        var clean = BrowserExtensionScanLogic.Scan(alice, "alice");
        Assert.False(clean.Partial);
        Assert.Equal("Alice Ext", Assert.Single(clean.Extensions).Name);
    }

    /// <summary>
    /// PAT-2052, a directory below the root swapped after its parent was listed: the scan
    /// lists Chrome's Default profile, and the user then swaps its Extensions directory for a
    /// junction into another profile's. Extensions is listed only from a handle whose final
    /// path is checked, so it is refused whatever it points at: the Firefox half is still
    /// reported, the Chrome half is partial, and the result is the same whether or not the
    /// other profile holds extensions. Windows only.
    /// </summary>
    [DirectoryLinkFact]
    public void Scan_OnWindows_ExtensionsSwappedAfterTheProfileIsListed_IsPartialAndTheSameWhateverTheTargetHolds()
    {
        if (!OperatingSystem.IsWindows()) return;
        var alice = NewProfileRoot("alice");
        var aliceVersion = WriteChromiumExtension(alice, "Google", "Chrome", "Default", "abababababababababababababababab", "1.0",
            manifest: """{ "name": "Alice Ext", "manifest_version": 3 }""", securePreferences: null);
        WriteFirefoxExtensionsJson(alice, "a.default", """
            { "addons": [ { "id": "{alice-ff}", "type": "extension", "version": "1.0" } ] }
            """);
        var profileDir = Path.GetFullPath(Path.Combine(aliceVersion, "..", "..", ".."));
        var extensions = Path.Combine(profileDir, "Extensions");
        var other = NewProfileRoot("other");
        var otherExtensions = Path.Combine(other, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Extensions");
        Directory.CreateDirectory(otherExtensions);

        BrowserExtensionProfileScan Run()
        {
            var swapped = false;
            var real = UserTreeReader.DefaultLister();
            try
            {
                return BrowserExtensionScanLogic.Scan(alice, "alice", options: new BrowserExtensionScanOptions
                {
                    ListOpenedDirectory = (path, expected) =>
                    {
                        var rows = real(path, expected);
                        if (!swapped && string.Equals(Path.TrimEndingDirectorySeparator(path), profileDir, StringComparison.OrdinalIgnoreCase))
                        {
                            swapped = true;
                            Directory.Move(extensions, extensions + "-listed");
                            DirectoryLinks.Plant(extensions, otherExtensions);
                        }
                        return rows;
                    },
                });
            }
            finally
            {
                Assert.True(swapped, "the swap never happened");
                Directory.Delete(extensions);
                Directory.Move(extensions + "-listed", extensions);
            }
        }

        var lacking = Run();
        PopulateOtherProfile(other);
        var having = Run();

        Assert.Equal(Serialise(lacking), Serialise(having));
        Assert.DoesNotContain("leaked", Serialise(having), StringComparison.OrdinalIgnoreCase);
        Assert.Equal("{alice-ff}", Assert.Single(lacking.Extensions).ExtensionId);
        Assert.True(lacking.Partial);
    }

    /// <summary>
    /// PAT-2052: a directory the scan cannot list (here a lister that refuses it, standing in
    /// for the Windows handle check) makes the scan partial and contributes nothing, never
    /// "no extensions"; the rest of the profile is still reported. A readable profile is not
    /// partial.
    /// </summary>
    [Fact]
    public void Scan_ADirectoryThatCannotBeListed_IsPartial_AndTheRestIsStillReported()
    {
        var root = NewProfileRoot("alice");
        WriteChromiumExtension(root, "Google", "Chrome", "Default", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "1.0",
            manifest: """{ "name": "Chrome Ext", "manifest_version": 3 }""", securePreferences: null);
        WriteFirefoxExtensionsJson(root, "a.default", """
            { "addons": [ { "id": "{ff}", "type": "extension", "version": "1.0" } ] }
            """);
        var clean = BrowserExtensionScanLogic.Scan(root, "alice");
        Assert.False(clean.Partial);
        Assert.Equal(2, clean.Extensions.Count);

        var userData = Path.Combine(root, "AppData", "Local", "Google", "Chrome", "User Data");
        var real = UserTreeReader.DefaultLister();
        var refused = BrowserExtensionScanLogic.Scan(root, "alice", options: new BrowserExtensionScanOptions
        {
            ListOpenedDirectory = (path, expected) =>
                string.Equals(Path.TrimEndingDirectorySeparator(path), userData, StringComparison.Ordinal) ? null : real(path, expected),
        });
        Assert.True(refused.Partial);
        Assert.Equal("{ff}", Assert.Single(refused.Extensions).ExtensionId);
    }

    /// <summary>
    /// PAT-2052: a link where the scan expects a directory (User Data, a Firefox profile, an
    /// extension) is refused as partial and never followed, whatever it points at.
    /// </summary>
    [DirectoryLinkFact]
    public void Scan_LinksInsteadOfDirectories_AreRefusedAsPartial_NeverFollowed()
    {
        var other = NewProfileRoot("other");
        PopulateOtherProfile(other);
        var root = NewProfileRoot("alice");
        var chrome = Path.Combine(root, "AppData", "Local", "Google", "Chrome");
        Directory.CreateDirectory(chrome);
        DirectoryLinks.Plant(Path.Combine(chrome, "User Data"),
            Path.Combine(other, "AppData", "Local", "Google", "Chrome", "User Data"));
        var ffProfiles = Path.Combine(root, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles");
        Directory.CreateDirectory(ffProfiles);
        DirectoryLinks.Plant(Path.Combine(ffProfiles, "leaked.default"),
            Path.Combine(other, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "leaked.default"));

        var scan = BrowserExtensionScanLogic.Scan(root, "alice");
        Assert.Empty(scan.Extensions);
        Assert.True(scan.Partial);
    }

    /// <summary>
    /// PAT-2052: default_locale is written by the user, so a value that is not one plain path
    /// component is never looked up: "../../../../other/x" would otherwise have SYSTEM read a
    /// messages.json in another profile and report its text as the extension's name.
    /// </summary>
    [Theory]
    [InlineData("../../../../../../other")]
    [InlineData("..")]
    [InlineData("en/../../../../../../other")]
    [InlineData("C:")]
    public void Scan_DefaultLocaleThatIsNotOnePlainName_IsNeverLookedUp(string locale)
    {
        var root = NewProfileRoot("alice");
        var extDir = WriteChromiumExtension(root, "Google", "Chrome", "Default", "12121212121212121212121212121212", "1.0",
            manifest: JsonSerializer.Serialize(new { name = "__MSG_extName__", manifest_version = 3, default_locale = locale }),
            securePreferences: null);
        // Where a naive Path.Combine(extDir, "_locales", locale) lands for the traversal values.
        var landing = Path.GetFullPath(Path.Combine(extDir, "_locales", locale.Replace('/', Path.DirectorySeparatorChar)));
        if (landing.StartsWith(_tempRoot, StringComparison.Ordinal))
        {
            Directory.CreateDirectory(landing);
            File.WriteAllText(Path.Combine(landing, "messages.json"), """{ "extName": { "message": "leaked name" } }""");
        }

        var ext = Assert.Single(BrowserExtensionScanLogic.ScanUserProfile(root, "alice"));
        Assert.Equal("12121212121212121212121212121212", ext.Name);
        Assert.False(BrowserExtensionScanLogic.IsPlainComponent(locale));
        Assert.True(BrowserExtensionScanLogic.IsPlainComponent("en_US"));
    }

    /// <summary>
    /// PAT-2052: the scan decides nothing by path. No Directory or File call is left in its
    /// source (existence comes from the reader's verified listings, contents from its verified
    /// reads), and it executes nothing and opens no network.
    /// </summary>
    [Fact]
    public void ScanSource_DecidesNothingByPath_AndExecutesNothing()
    {
        var code = CollectorSourceGuard.Code(File.ReadAllText(
            CollectorSourceGuard.SourceFile(Path.Combine("Shared", "BrowserExtensions", "BrowserExtensionScanLogic.cs"))));
        Assert.Empty(CollectorSourceGuard.Hits(code, ByPath));
        Assert.NotEmpty(CollectorSourceGuard.Hits("if (!Directory.Exists(userDataDir)) yield break;", ByPath));
        Assert.NotEmpty(CollectorSourceGuard.Hits("var t = File.ReadAllText(prefsPath);", ByPath));
        Assert.NotEmpty(CollectorSourceGuard.Hits("foreach (var d in new DirectoryInfo(p).EnumerateDirectories())", ByPath));
        CollectorSourceGuard.AssertExecutesNothing(Path.Combine("Shared", "BrowserExtensions", "BrowserExtensionScanLogic.cs"),
            new HashSet<string>(StringComparer.Ordinal)
            {
                "System.Text", "System.Text.Json", "Microsoft.Win32.SafeHandles", "Patched.Shared.Contract",
                "Patched.Shared.IdeExtensions", "Patched.Shared.UserTrees",
            });
    }

    private static readonly Regex ByPath = new(
        @"(?<![\w.])(Directory|File|FileInfo|DirectoryInfo|FileStream|FileSystemInfo)\s*\.|new\s+(FileInfo|DirectoryInfo|FileStream)\b",
        RegexOptions.CultureInvariant);

    // -------------------------------------------------------------------------
    // Fixture helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Writes a Chrome/Edge extension fixture and returns the extension's version
    /// directory path (so callers can add extra files like _locales/&lt;locale&gt;/messages.json).
    /// </summary>
    private static string WriteChromiumExtension(
        string profileRoot, string vendor, string product, string profileName,
        string extensionId, string version, string manifest, string? securePreferences)
    {
        // vendor/product passed as separate segments (not a single "Vendor\Product"
        // string) so Path.Combine builds the same platform-native separator the
        // production code uses via Path.Combine("Google", "Chrome") — a hardcoded
        // backslash would be a literal character (not a separator) on macOS CI.
        var userDataDir = Path.Combine(profileRoot, "AppData", "Local", vendor, product, "User Data");
        var profileDir  = Path.Combine(userDataDir, profileName);
        var extDir      = Path.Combine(profileDir, "Extensions", extensionId, version);
        Directory.CreateDirectory(extDir);
        File.WriteAllText(Path.Combine(extDir, "manifest.json"), manifest);

        if (securePreferences is not null)
        {
            File.WriteAllText(Path.Combine(profileDir, "Secure Preferences"), securePreferences);
        }

        return extDir;
    }

    private static void WriteFirefoxExtensionsJson(string profileRoot, string profileName, string json)
    {
        var profileDir = Path.Combine(profileRoot, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", profileName);
        Directory.CreateDirectory(profileDir);
        File.WriteAllText(Path.Combine(profileDir, "extensions.json"), json);
    }

    private static string BuildSecurePreferences(params (string ExtId, int state)[] settings)
    {
        var entries = string.Join(",", settings.Select(s => $"\"{s.ExtId}\": {{ \"state\": {s.state} }}"));
        return $$"""
            { "extensions": { "settings": { {{entries}} } } }
            """;
    }
}
