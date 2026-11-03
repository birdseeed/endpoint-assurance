using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using Patched.Shared.Contract;
using Patched.Shared.IdeExtensions;
using Patched.Shared.UserTrees;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-2017: the Windows IDE extension scan against fixture profiles built in a temp
/// directory: several users, each with a different mix of VS Code, VS Code Insiders,
/// Cursor, Windsurf and JetBrains. The same cases as macos/lib/test-ide-extensions.zsh, so
/// the two agents are held to one contract.
///
/// Reparse points: on Windows the directory cases plant an NTFS junction (mklink /J, which
/// needs no privilege, so it is what an ordinary user would actually use) and the file cases
/// a hard link (mklink /H, likewise unprivileged); elsewhere they plant a POSIX symlink. A
/// failure to create the planted link is an assertion failure, never a silent skip, so the
/// test cannot pass without the guard having run. A machine that cannot plant a junction at
/// all skips the directory cases explicitly, with the reason (DirectoryLinkFact, PAT-2033).
/// </summary>
public sealed class IdeExtensionScanLogicTests : IDisposable
{
    private readonly string _root;
    private readonly string _secret;

    public IdeExtensionScanLogicTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"patched-ide-test-{Guid.NewGuid():N}");
        _secret = Path.Combine(_root, "root-only");
        Directory.CreateDirectory(_root);
        Directory.CreateDirectory(Path.Combine(_secret, "leaked.secret-9.9.9"));
        File.WriteAllText(Path.Combine(_secret, "extensions.json"), $"[{VsxEntry("leaked.secret", "9.9.9", 1, "Leaked")}]");
        Jar(Path.Combine(_secret, "secret.jar"), PluginXml("leaked.secret", "Leaked", "Leaked", "9"));
    }

    public void Dispose()
    {
        try
        {
            DeleteTree(_root);
        }
        catch
        {
            // best effort
        }
    }

    // -------------------------------------------------------------------------
    // Fixture builders
    // -------------------------------------------------------------------------

    private string Users => Path.Combine(_root, "Users");
    private string Home(string user) => Path.Combine(Users, user);
    private string Idea => Path.Combine(Home("bob"), "AppData", "Roaming", "JetBrains", "IntelliJIdea2025.2");

    private static string VsxEntry(string id, string version, long ms, string display) =>
        "{\"identifier\":{\"id\":\"" + id + "\",\"uuid\":\"00000000-0000-0000-0000-000000000000\"},\"version\":\"" + version +
        "\",\"location\":{\"$mid\":1,\"path\":\"/x/" + id + "\",\"scheme\":\"file\"},\"relativeLocation\":\"" + id + "-" + version +
        "\",\"metadata\":{\"installedTimestamp\":" + ms + ",\"source\":\"gallery\",\"publisherDisplayName\":\"" + display +
        "\",\"targetPlatform\":\"undefined\",\"isPreReleaseVersion\":false}}";

    private static void Write(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    private static void PackageJson(string dir, string publisher, string name, string version) =>
        Write(Path.Combine(dir, "package.json"),
            "{\"name\":\"" + name + "\",\"publisher\":\"" + publisher + "\",\"version\":\"" + version + "\"}");

    private static string PluginXml(string id, string name, string vendor, string version) =>
        $"<idea-plugin><id>{id}</id><name>{name}</name><vendor url=\"https://example.invalid\">{vendor}</vendor>" +
        $"<version>{version}</version><depends>com.intellij.modules.platform</depends></idea-plugin>";

    private static void Jar(string path, string? pluginXml)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        using (var s = zip.CreateEntry("com/example/Main.class").Open()) s.Write([0xCA, 0xFE, 0xBA, 0xBE]);
        if (pluginXml is not null)
        {
            using var s = zip.CreateEntry("META-INF/plugin.xml").Open();
            s.Write(Encoding.UTF8.GetBytes(pluginXml));
        }
    }

    private void BuildTree()
    {
        if (Directory.Exists(Users)) DeleteTree(Users);
        Directory.CreateDirectory(Path.Combine(Home("carol"), "Documents"));

        var vs = Path.Combine(Home("alice"), ".vscode", "extensions");
        Directory.CreateDirectory(Path.Combine(vs, "github.copilot-1.250.0"));
        Directory.CreateDirectory(Path.Combine(vs, "ms-python.python-2026.1.0"));
        Write(Path.Combine(vs, "extensions.json"),
            $"[{VsxEntry("github.copilot", "1.250.0", 1767225600000, "GitHub")},{VsxEntry("ms-python.python", "2026.1.0", 1767225700000, "Microsoft")}]");
        var cu = Path.Combine(Home("alice"), ".cursor", "extensions");
        PackageJson(Path.Combine(cu, "continue.continue-1.2.22"), "Continue", "continue", "1.2.22");
        PackageJson(Path.Combine(cu, "anysphere.remote-ssh-1.1.13"), "anysphere", "remote-ssh", "1.1.13");
        PackageJson(Path.Combine(cu, "anysphere.remote-ssh-1.1.7"), "anysphere", "remote-ssh", "1.1.7");
        Write(Path.Combine(cu, ".obsolete"), "{\"anysphere.remote-ssh-1.1.7\":true}");
        Write(Path.Combine(Home("alice"), ".windsurf", "extensions", "extensions.json"),
            $"[{VsxEntry("codeium.windsurf-pyright", "1.0.0", 1767225800000, "Codeium")}]");

        Write(Path.Combine(Home("bob"), ".vscode-insiders", "extensions", "extensions.json"),
            $"[{VsxEntry("rooveterinaryinc.roo-cline", "3.0.0", 1767225900000, "RooCode")}]");
        Jar(Path.Combine(Idea, "plugins", "github-copilot-intellij", "lib", "aaa-deps.jar"), null);
        Jar(Path.Combine(Idea, "plugins", "github-copilot-intellij", "lib", "github-copilot-intellij.jar"),
            PluginXml("com.github.copilot", "GitHub Copilot", "GitHub", "1.5.40-243"));
        Jar(Path.Combine(Idea, "plugins", "tabnine.jar"), PluginXml("com.tabnine.TabNine", "Tabnine", "Tabnine", "1.200.0"));
        Write(Path.Combine(Idea, "plugins", "unpacked", "META-INF", "plugin.xml"),
            "<idea-plugin><name>Unpacked Tool</name><vendor>Acme</vendor><version>0.9</version></idea-plugin>");
        Write(Path.Combine(Idea, "disabled_plugins.txt"), "com.tabnine.TabNine\r\n");
        var jb = Path.Combine(Home("bob"), "AppData", "Roaming", "JetBrains");
        Directory.CreateDirectory(Path.Combine(jb, "PyCharm2024.3", "options"));
        Directory.CreateDirectory(Path.Combine(jb, "consentOptions"));
    }

    /// <summary>
    /// Deletes a fixture tree without ever walking through a planted link: a reparse point
    /// is unlinked where it stands and never recursed into, so the secret it points at
    /// survives and nothing outside the tree is touched.
    /// </summary>
    private static void DeleteTree(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            Directory.Delete(path);
            return;
        }
        foreach (var dir in Directory.GetDirectories(path)) DeleteTree(dir);
        foreach (var file in Directory.GetFiles(path)) File.Delete(file);
        Directory.Delete(path);
    }

    private IEnumerable<IdeProfileSource> Profiles(params string[] users) =>
        (users.Length == 0 ? ["alice", "bob", "carol"] : users)
            .Select((u, i) => new IdeProfileSource($"TEST\\{u}", $"S-1-5-21-1-2-3-{1001 + i}", Home(u)));

    private InventoryIdeExtensions ScanAll(IdeExtensionScanOptions? options = null, params string[] users) =>
        IdeExtensionScanLogic.Scan(Profiles(users).ToList(), options);

    private static InventoryIdeExtension Ext(InventoryIdeExtensions r, string id) =>
        Assert.Single(r.Extensions!, e => e.Id == id);

    private static IdeProfileRow Profile(InventoryIdeExtensions r, string user, string editor) =>
        Assert.Single(r.Profiles, p => p.User == $"TEST\\{user}" && p.Editor == editor);

    private static string Serialise(InventoryIdeExtensions r) => JsonSerializer.Serialize(r);

    /// <summary>Plants a directory reparse point: an NTFS junction on Windows, a symlink elsewhere.</summary>
    private static void PlantDirectoryLink(string link, string target)
    {
        if (OperatingSystem.IsWindows())
        {
            RunCmd($"mklink /J \"{link}\" \"{target}\"");
        }
        else
        {
            Directory.CreateSymbolicLink(link, target);
        }
        Assert.True((File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0, $"failed to plant a reparse point at {link}");
    }

    /// <summary>
    /// Plants a file the user points at a file they should not be able to read: a symlink
    /// where one can be created, else (Windows without the symlink privilege) a hard link.
    /// </summary>
    private static void PlantFileLink(string link, string target)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                File.CreateSymbolicLink(link, target);
                return;
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            RunCmd($"mklink /H \"{link}\" \"{target}\"");
            Assert.True(File.Exists(link), $"failed to plant a hard link at {link}");
            return;
        }
        File.CreateSymbolicLink(link, target);
    }

    private static void RunCmd(string args)
    {
        var psi = new ProcessStartInfo("cmd.exe", "/c " + args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var p = Process.Start(psi)!;
        p.WaitForExit(30_000);
        Assert.True(p.ExitCode == 0, $"cmd /c {args} failed: {p.StandardError.ReadToEnd()}");
    }

    // -------------------------------------------------------------------------
    // Everything readable
    // -------------------------------------------------------------------------

    [Fact]
    public void Scan_SeveralUsersEveryFamily_IsComplete()
    {
        BuildTree();
        var r = ScanAll();

        Assert.Equal(IdeCollectionStatus.Complete, r.CollectionStatus);
        Assert.Equal(9, r.Extensions!.Count);
        Assert.Equal(
            new[] { ("TEST\\alice", "complete", 3), ("TEST\\bob", "complete", 3), ("TEST\\carol", "not_present", 0) },
            r.Users.Select(u => (u.User, u.CollectionStatus, u.Profiles)).ToArray());
        Assert.Equal("S-1-5-21-1-2-3-1001", r.Users[0].UserId);
        Assert.Equal(
            new[]
            {
                ("TEST\\alice", "cursor", (string?)null, "package_json", 2),
                ("TEST\\alice", "vscode", null, "extensions_json", 2),
                ("TEST\\alice", "windsurf", null, "extensions_json", 1),
                ("TEST\\bob", "IntelliJIdea", "2025.2", "plugin_xml", 3),
                ("TEST\\bob", "PyCharm", "2024.3", "plugin_xml", 0),
                ("TEST\\bob", "vscode_insiders", null, "extensions_json", 1),
            },
            r.Profiles.Select(p => (p.User, p.Editor, p.EditorVersion, p.ManifestSource!, p.ExtensionCount))
                .OrderBy(t => t.User, StringComparer.Ordinal).ThenBy(t => t.Editor, StringComparer.Ordinal).ToArray());
        Assert.False(r.Truncated);
        Assert.Null(r.TruncationReason);
        Assert.Empty(r.Issues);
    }

    [Fact]
    public void Scan_ExtensionsJsonEntry_CarriesIdentityVersionAndInstallTime()
    {
        BuildTree();
        var c = Ext(ScanAll(), "github.copilot");

        Assert.Equal(("github", "copilot", "1.250.0"), (c.Publisher, c.Name, c.Version));
        Assert.Equal("2026-07-01T00:00:00Z", c.InstalledAt);
        Assert.Equal("gallery", c.Source);
        Assert.Equal("GitHub", c.PublisherDisplayName);
        Assert.Equal(("vscode", "vscode", "TEST\\alice"), (c.Family, c.Editor, c.User));
        Assert.Null(c.TargetPlatform);
        Assert.False(c.PreRelease);
        Assert.Equal("extensions_json", c.ManifestSource);
    }

    [Fact]
    public void Scan_ManifestFallback_SkipsObsoleteAndLowercasesId()
    {
        BuildTree();
        var r = ScanAll();

        Assert.Equal(new[] { "1.1.13" }, r.Extensions!.Where(e => e.Id == "anysphere.remote-ssh").Select(e => e.Version).ToArray());
        var cont = Ext(r, "continue.continue");
        Assert.Equal(("Continue", "package_json"), (cont.Publisher, cont.ManifestSource));
        Assert.Superset(new HashSet<string> { "vscode", "cursor", "windsurf", "vscode_insiders" }.ToHashSet(),
            r.Extensions!.Select(e => e.Editor).ToHashSet());
    }

    [Fact]
    public void Scan_JetBrains_ReadsJarUnpackedAndDisabledState()
    {
        BuildTree();
        var r = ScanAll();

        var g = Ext(r, "com.github.copilot");
        Assert.Equal(("GitHub Copilot", "GitHub", "1.5.40-243"), (g.Name, g.Publisher, g.Version));
        Assert.Equal(("plugin_xml_jar", "2025.2", "jetbrains"), (g.ManifestSource!, g.EditorVersion!, g.Family));
        Assert.False(g.Disabled);
        Assert.True(Ext(r, "com.tabnine.TabNine").Disabled);
        var u = Ext(r, "Unpacked Tool");
        Assert.Equal(("plugin_xml_unpacked", "Acme"), (u.ManifestSource!, u.Publisher!));
    }

    [Fact]
    public void Scan_RowsCarryNoLocationPath_AndSerialiseExplicitNulls()
    {
        BuildTree();
        var r = ScanAll();
        var json = Serialise(r);

        Assert.DoesNotContain("/x/", json);
        var tabnine = JsonDocument.Parse(json).RootElement.GetProperty("extensions")
            .EnumerateArray().Single(e => e.GetProperty("id").GetString() == "com.tabnine.TabNine");
        // Same keys as the macOS collector, nulls written rather than dropped.
        Assert.Equal(JsonValueKind.Null, tabnine.GetProperty("installed_at").ValueKind);
        Assert.Equal(JsonValueKind.Null, tabnine.GetProperty("publisher_display_name").ValueKind);
        Assert.Equal(
            new[]
            {
                "user", "user_id", "family", "editor", "editor_version", "id", "name", "publisher",
                "publisher_display_name", "version", "installed_at", "source", "pre_release",
                "target_platform", "disabled", "directory", "manifest_source", "manifest_status",
            },
            tabnine.EnumerateObject().Select(p => p.Name).ToArray());
    }

    // -------------------------------------------------------------------------
    // Corrupt manifests: partial, never empty
    // -------------------------------------------------------------------------

    [Fact]
    public void Scan_CorruptExtensionsJson_ReadsFoldersInstead_AndIsPartial()
    {
        BuildTree();
        var vs = Path.Combine(Home("alice"), ".vscode", "extensions");
        File.WriteAllText(Path.Combine(vs, "extensions.json"), "[{\"identifier\":");
        PackageJson(Path.Combine(vs, "github.copilot-1.250.0"), "GitHub", "copilot", "1.250.0");
        File.WriteAllText(Path.Combine(vs, "ms-python.python-2026.1.0", "package.json"), "{not json");

        var r = ScanAll();

        Assert.Equal(IdeCollectionStatus.Partial, r.CollectionStatus);
        var p = Profile(r, "alice", "vscode");
        Assert.Equal(("package_json", "partial", 2), (p.ManifestSource!, p.CollectionStatus, p.ExtensionCount));
        var broken = Assert.Single(r.Extensions!, e => e.Directory == "ms-python.python-2026.1.0");
        Assert.Null(broken.Id);
        Assert.Equal("unparseable", broken.ManifestStatus);
        Assert.Contains(r.Extensions!, e => e.Id == "github.copilot" && e.ManifestSource == "package_json");
        Assert.Equal(
            new[] { ("TEST\\alice", "partial"), ("TEST\\bob", "complete"), ("TEST\\carol", "not_present") },
            r.Users.Select(u => (u.User, u.CollectionStatus)).ToArray());
        Assert.Equal(new[] { "extensions_json_unparseable", "manifest_unparseable" },
            r.Issues.Select(i => i.Code).Order(StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public void Scan_ExtensionsJsonOfTheWrongShape_IsPartial()
    {
        BuildTree();
        File.WriteAllText(Path.Combine(Home("alice"), ".windsurf", "extensions", "extensions.json"), "{\"not\":\"a list\"}");
        Assert.Equal(IdeCollectionStatus.Partial, Profile(ScanAll(), "alice", "windsurf").CollectionStatus);
    }

    [Fact]
    public void Scan_DeeplyNestedExtensionsJson_OnlyThatProfileIsPartial()
    {
        BuildTree();
        File.WriteAllText(Path.Combine(Home("alice"), ".windsurf", "extensions", "extensions.json"),
            new string('[', 100_000) + new string(']', 100_000));
        var r = ScanAll();
        Assert.Equal(IdeCollectionStatus.Partial, r.CollectionStatus);
        Assert.Equal(IdeCollectionStatus.Partial, Profile(r, "alice", "windsurf").CollectionStatus);
        Assert.Equal(8, r.Extensions!.Count);
    }

    [Fact]
    public void Scan_JetBrainsCorruptPluginXmlAndJars_ListedByDirectory_AndPartial()
    {
        BuildTree();
        File.WriteAllText(Path.Combine(Idea, "plugins", "unpacked", "META-INF", "plugin.xml"), "<idea-plugin><name>broken");
        Jar(Path.Combine(Idea, "plugins", "nometa.jar"), null);
        File.WriteAllText(Path.Combine(Idea, "plugins", "garbage.jar"), "PK not a zip");

        var r = ScanAll();

        Assert.Equal(IdeCollectionStatus.Partial, Profile(r, "bob", "IntelliJIdea").CollectionStatus);
        Assert.Equal(
            new[] { ("garbage.jar", "unparseable"), ("nometa.jar", "missing"), ("unpacked", "unparseable") },
            r.Extensions!.Where(e => e.Editor == "IntelliJIdea" && e.Id is null)
                .Select(e => (e.Directory!, e.ManifestStatus!)).OrderBy(t => t.Item1, StringComparer.Ordinal).ToArray());
    }

    // -------------------------------------------------------------------------
    // Planted reparse points and links are never followed
    // -------------------------------------------------------------------------

    [DirectoryLinkFact]
    public void Scan_ReparsePointExtensionsDir_IsNotFollowed_ProfileFailed()
    {
        BuildTree();
        var vs = Path.Combine(Home("alice"), ".vscode", "extensions");
        Directory.Delete(vs, recursive: true);
        PlantDirectoryLink(vs, _secret);

        var r = ScanAll();

        Assert.DoesNotContain("leaked", Serialise(r), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(IdeCollectionStatus.Failed, Profile(r, "alice", "vscode").CollectionStatus);
        Assert.Contains(r.Issues, i => i.Code == "symlink_not_followed" && i.Path.EndsWith("extensions", StringComparison.Ordinal));
        Assert.Equal(IdeCollectionStatus.Partial, r.CollectionStatus);
        Assert.Equal(3, r.Extensions!.Count(e => e.User == "TEST\\alice"));
    }

    [DirectoryLinkFact]
    public void Scan_ReparsePointEditorDir_IsNotFollowed()
    {
        BuildTree();
        var cursor = Path.Combine(Home("alice"), ".cursor");
        Directory.Delete(cursor, recursive: true);
        PlantDirectoryLink(cursor, _secret);

        var r = ScanAll();

        Assert.DoesNotContain("leaked", Serialise(r), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(IdeCollectionStatus.Failed, Profile(r, "alice", "cursor").CollectionStatus);
    }

    [Fact]
    public void Scan_PlantedExtensionsJsonLink_IsRefused_FoldersReadInstead()
    {
        BuildTree();
        var list = Path.Combine(Home("alice"), ".vscode", "extensions", "extensions.json");
        File.Delete(list);
        PlantFileLink(list, Path.Combine(_secret, "extensions.json"));

        var r = ScanAll();

        Assert.DoesNotContain("leaked", Serialise(r), StringComparison.OrdinalIgnoreCase);
        Assert.Contains(r.Issues, i => i.Code == "extensions_json_unreadable");
        Assert.Equal(IdeCollectionStatus.Partial, r.CollectionStatus);
    }

    [DirectoryLinkFact]
    public void Scan_PlantedExtensionFolderAndJetBrainsLinks_AreRecordedNotRead()
    {
        BuildTree();
        File.Delete(Path.Combine(Home("alice"), ".cursor", "extensions", ".obsolete"));
        PlantDirectoryLink(Path.Combine(Home("alice"), ".cursor", "extensions", "planted-1.0.0"),
            Path.Combine(_secret, "leaked.secret-9.9.9"));
        var metaInf = Path.Combine(Idea, "plugins", "unpacked", "META-INF");
        Directory.Delete(metaInf, recursive: true);
        PlantDirectoryLink(metaInf, _secret);

        var r = ScanAll();

        Assert.DoesNotContain("leaked", Serialise(r), StringComparison.OrdinalIgnoreCase);
        Assert.Contains(r.Issues, i => i.Code == "symlink_not_followed" && i.Path.EndsWith("planted-1.0.0", StringComparison.Ordinal));
        Assert.Contains(r.Issues, i => i.Code == "symlink_not_followed" && i.Path.EndsWith("META-INF", StringComparison.Ordinal));
        Assert.Equal(IdeCollectionStatus.Partial, Profile(r, "bob", "IntelliJIdea").CollectionStatus);
    }

    [DirectoryLinkFact]
    public void Scan_ReparsePointProfileRoot_UserFailed_NotReadThrough()
    {
        BuildTree();
        DeleteTree(Home("carol"));
        PlantDirectoryLink(Home("carol"), Home("alice"));

        var r = ScanAll();

        Assert.Equal(IdeCollectionStatus.Failed, Assert.Single(r.Users, u => u.User == "TEST\\carol").CollectionStatus);
        Assert.DoesNotContain(r.Extensions!, e => e.User == "TEST\\carol");
    }

    /// <summary>
    /// The post-open handle check (link count and final path on Windows) is wired: a handle
    /// the verifier rejects is treated as unreadable, never read.
    /// </summary>
    [Fact]
    public void Scan_HandleRejectedAfterOpen_IsUnreadable()
    {
        BuildTree();
        var seen = new List<string>();
        var r = ScanAll(new IdeExtensionScanOptions
        {
            VerifyOpenedFile = (_, expected) =>
            {
                seen.Add(expected);
                return !expected.EndsWith("extensions.json", StringComparison.Ordinal);
            },
        });

        Assert.Contains(seen, p => p.EndsWith(Path.Combine(".vscode", "extensions", "extensions.json"), StringComparison.Ordinal));
        Assert.Contains(r.Issues, i => i.Code == "extensions_json_unreadable");
        Assert.Equal(IdeCollectionStatus.Partial, r.CollectionStatus);
    }

    /// <summary>
    /// Windows only: the real handle check refuses a file reached through a junction swapped
    /// in after the pre-open check, and a hard link, and accepts an ordinary file.
    /// </summary>
    [DirectoryLinkFact]
    public void WindowsFileIdentity_RefusesJunctionedPathAndHardLink()
    {
        if (!OperatingSystem.IsWindows()) return;

        var real = Path.Combine(_root, "real");
        Directory.CreateDirectory(real);
        var plain = Path.Combine(real, "plain.json");
        File.WriteAllText(plain, "{}");
        var junction = Path.Combine(_root, "junction");
        PlantDirectoryLink(junction, _secret);
        var hard = Path.Combine(real, "hard.json");
        RunCmd($"mklink /H \"{hard}\" \"{Path.Combine(_secret, "extensions.json")}\"");

        var rootFinal = WindowsFileIdentity.FinalPathOfDirectory(_root);
        Assert.NotNull(rootFinal);
        // Compare against the kernel's spelling of the temp root (it may differ from GetTempPath's).
        bool CheckUnderRoot(string path)
        {
            using SafeFileHandle h = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return WindowsFileIdentity.IsExpectedRegularFile(h, rootFinal + path[_root.Length..]);
        }

        Assert.True(CheckUnderRoot(plain));
        Assert.False(CheckUnderRoot(Path.Combine(junction, "extensions.json")));
        Assert.False(CheckUnderRoot(hard));
    }

    // -------------------------------------------------------------------------
    // Safe parsing and credential-shaped text
    // -------------------------------------------------------------------------

    [Fact]
    public void Scan_PluginXmlWithDtd_IsRefused_NoEntityExpanded()
    {
        BuildTree();
        Jar(Path.Combine(Idea, "plugins", "entity.jar"),
            "<?xml version=\"1.0\"?>\n<!DOCTYPE idea-plugin [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">]>\n" +
            "<idea-plugin><id>entity</id><name>&b;</name></idea-plugin>");

        var r = ScanAll();

        Assert.Equal("unparseable", Assert.Single(r.Extensions!, e => e.Directory == "entity.jar").ManifestStatus);
        Assert.DoesNotContain("aaaa", Serialise(r));
    }

    [Fact]
    public void Scan_OversizedPluginXmlInJar_IsRefusedUnread()
    {
        BuildTree();
        Jar(Path.Combine(Idea, "plugins", "bomb.jar"),
            "<idea-plugin><id>x</id><name>" + new string('a', 3 * 1024 * 1024) + "</name></idea-plugin>");

        Assert.Equal("unreadable", Assert.Single(ScanAll().Extensions!, e => e.Directory == "bomb.jar").ManifestStatus);
    }

    [Fact]
    public void Scan_UserInfoInUrlShapedField_IsStripped_ControlCharactersDropped()
    {
        BuildTree();
        var list = Path.Combine(Home("alice"), ".windsurf", "extensions", "extensions.json");
        File.WriteAllText(list, $"[{VsxEntry("acme.tool", "1.0.0", 1767225800000, "https://placeholder:placeholder@gallery.example.invalid/acme")}]");
        var r = ScanAll();
        Assert.Equal("https://gallery.example.invalid/acme", Ext(r, "acme.tool").PublisherDisplayName);
        Assert.DoesNotContain("placeholder", Serialise(r));

        File.WriteAllText(list, "[{\"identifier\":{\"id\":\"acme.tool\"},\"version\":\"1.0\\u001b[31m\",\"metadata\":{}}]");
        Assert.Null(Ext(ScanAll(), "acme.tool").Version);
    }

    // -------------------------------------------------------------------------
    // not_present, failed and bounds
    // -------------------------------------------------------------------------

    [Fact]
    public void Scan_NoEditorAnywhere_IsNotPresent_WithEmptyList()
    {
        Directory.CreateDirectory(Path.Combine(Home("dave"), "Documents"));
        Directory.CreateDirectory(Path.Combine(Home("erin"), ".vscode"));

        var r = ScanAll(null, "dave", "erin");

        Assert.Equal(IdeCollectionStatus.NotPresent, r.CollectionStatus);
        Assert.NotNull(r.Extensions);
        Assert.Empty(r.Extensions!);
        Assert.Empty(r.Profiles);
        Assert.All(r.Users, u => Assert.Equal(IdeCollectionStatus.NotPresent, u.CollectionStatus));
    }

    [Fact]
    public void Scan_UnreadableProfileList_IsFailed_ExtensionsOmitted()
    {
        var r = IdeExtensionScanLogic.Scan(null);

        Assert.Equal(IdeCollectionStatus.Failed, r.CollectionStatus);
        Assert.Null(r.Extensions);
        var json = JsonDocument.Parse(Serialise(r)).RootElement;
        Assert.False(json.TryGetProperty("extensions", out _));
    }

    [DirectoryLinkFact]
    public void Scan_OnlyProfileUnreadable_IsFailed_NotNotPresent()
    {
        BuildTree();
        DeleteTree(Home("bob"));
        DeleteTree(Home("carol"));
        Directory.Delete(Path.Combine(Home("alice"), ".cursor"), recursive: true);
        Directory.Delete(Path.Combine(Home("alice"), ".windsurf"), recursive: true);
        var vs = Path.Combine(Home("alice"), ".vscode", "extensions");
        Directory.Delete(vs, recursive: true);
        PlantDirectoryLink(vs, _secret);

        var r = ScanAll(null, "alice");

        Assert.Equal(IdeCollectionStatus.Failed, r.CollectionStatus);
        Assert.Null(r.Extensions);
    }

    [Fact]
    public void Scan_UnreadableProfileEntries_MakeTheBlockPartialOrFailed()
    {
        BuildTree();
        var partial = IdeExtensionScanLogic.Scan(Profiles().ToList(), unreadableProfiles: 1);
        Assert.Equal(IdeCollectionStatus.Partial, partial.CollectionStatus);
        Assert.Contains(partial.Issues, i => i.Code == "profile_unreadable");

        var failed = IdeExtensionScanLogic.Scan(Array.Empty<IdeProfileSource>(), unreadableProfiles: 2);
        Assert.Equal(IdeCollectionStatus.Failed, failed.CollectionStatus);
    }

    [Fact]
    public void Scan_MissingProfileDirectory_IsSkipped_NotAUser()
    {
        BuildTree();
        var r = IdeExtensionScanLogic.Scan([.. Profiles(), new IdeProfileSource("TEST\\gone", "S-1-5-21-9", Path.Combine(Users, "gone"))]);
        Assert.Equal(IdeCollectionStatus.Complete, r.CollectionStatus);
        Assert.DoesNotContain(r.Users, u => u.User == "TEST\\gone");
    }

    [Fact]
    public void Scan_PastTheExtensionLimit_IsPartialAndTruncated()
    {
        BuildTree();
        var r = ScanAll(new IdeExtensionScanOptions { MaxExtensions = 2 });

        Assert.Equal(IdeCollectionStatus.Partial, r.CollectionStatus);
        Assert.True(r.Truncated);
        Assert.Equal("extension_limit", r.TruncationReason);
        Assert.Equal(2, r.Extensions!.Count);
    }

    [Fact]
    public void Scan_PastTheTimeBudget_IsPartialAndTruncated()
    {
        BuildTree();
        var r = ScanAll(new IdeExtensionScanOptions { TimeBudget = TimeSpan.Zero });

        Assert.Equal(IdeCollectionStatus.Partial, r.CollectionStatus);
        Assert.Equal("time_limit", r.TruncationReason);
    }

    /// <summary>
    /// The Service scanner cancels the token when its hard timeout abandons the scan: the scan
    /// stops at its next budget check, reads nothing further and never claims complete.
    /// </summary>
    [Fact]
    public void Scan_CancelledByTheHardTimeout_StopsAndIsNotComplete()
    {
        BuildTree();
        var r = ScanAll(new IdeExtensionScanOptions { Cancellation = new CancellationToken(canceled: true) });

        Assert.NotEqual(IdeCollectionStatus.Complete, r.CollectionStatus);
        Assert.True(r.Truncated);
        Assert.Empty(r.Extensions ?? []);
    }

    // -------------------------------------------------------------------------
    // Nothing is executed, and the file-safety primitives are the shared ones (PAT-2033)
    // -------------------------------------------------------------------------

    public static IEnumerable<object[]> CollectorSources() =>
    [
        [Path.Combine("Shared", "IdeExtensions", "IdeExtensionScanLogic.cs")],
        [Path.Combine("Shared", "UserTrees", "UserTreeReader.cs")],
        [Path.Combine("Service", "IdeExtensionScanner.cs")],
    ];

    /// <summary>
    /// The collector reads files and never runs anything: no editor, no process, no native
    /// call, no network and no URL. Comments are stripped first, and the using list is an
    /// allowlist, so a new namespace has to be reviewed here before it can be used.
    /// </summary>
    [Theory]
    [MemberData(nameof(CollectorSources))]
    public void CollectorSource_ExecutesNothing_AndOpensNoNetwork(string relative) =>
        CollectorSourceGuard.AssertExecutesNothing(relative, new HashSet<string>(StringComparer.Ordinal)
        {
            "System.Diagnostics", "System.IO.Compression", "System.Runtime.Versioning", "System.Text",
            "System.Text.Json", "System.Text.RegularExpressions", "System.Xml", "System.Xml.Linq",
            "Microsoft.Win32.SafeHandles", "Patched.Shared.Contract", "Patched.Shared.IdeExtensions",
            "Patched.Shared.UserTrees",
        });

    private static readonly Regex OwnFileAccess = new(
        @"File\.\w+\(|Directory\.\w+\(|\bDirectoryInfo\b|\bFileInfo\b|FileSystemInfo|FileAttributes\.|" +
        @"RandomAccess\.|StreamReader|MemoryMapped|\benum Kind\b|(?<!UserTreeReader\.)\bKindOf\(|" +
        @"new FileStream\((?!handle, FileAccess\.Read\))",
        RegexOptions.CultureInvariant);

    /// <summary>
    /// PAT-2033: the scan has one set of file-safety primitives, UserTreeReader's, and no copy
    /// of its own to drift from it. Any direct file or directory API, a private KindOf, or a
    /// stream over anything but a handle the reader verified turns this red.
    /// </summary>
    [Fact]
    public void CollectorSource_HasNoFileSystemPrimitivesOfItsOwn()
    {
        var code = CollectorSourceGuard.Code(File.ReadAllText(
            CollectorSourceGuard.SourceFile(Path.Combine("Shared", "IdeExtensions", "IdeExtensionScanLogic.cs"))));
        Assert.Empty(CollectorSourceGuard.Hits(code, OwnFileAccess));
        Assert.Contains("_reader.ReadFile(", code);
        Assert.Contains("_reader.OpenRegular(", code);
    }

    /// <summary>The guards above can fail: each goes red on a line that breaks its rule.</summary>
    [Fact]
    public void CollectorSourceGuards_CatchWhatTheyAreFor()
    {
        Assert.NotEmpty(CollectorSourceGuard.Hits("var p = Process.Start(\"code.cmd\");", CollectorSourceGuard.ExecOrNetwork));
        Assert.NotEmpty(CollectorSourceGuard.Hits("var u = \"https://marketplace.visualstudio.com/items\";", CollectorSourceGuard.ExecOrNetwork));
        Assert.NotEmpty(CollectorSourceGuard.Hits("var u = \"http://plugins.jetbrains.com/\";", CollectorSourceGuard.ExecOrNetwork));
        Assert.NotEmpty(CollectorSourceGuard.Hits("var u = \"ftp://mirror.example/x\";", CollectorSourceGuard.ExecOrNetwork));
        // The URL survives comment stripping when it is in code, and a URL in a comment does not
        // count: the stripper used to cut every string at its "//", so this rule never saw one.
        Assert.NotEmpty(CollectorSourceGuard.Hits(CollectorSourceGuard.Code("var u = \"https://x.example/\"; // note"), CollectorSourceGuard.ExecOrNetwork));
        Assert.NotEmpty(CollectorSourceGuard.Hits(CollectorSourceGuard.Code("var u = @\"http://x.example/\";"), CollectorSourceGuard.ExecOrNetwork));
        Assert.NotEmpty(CollectorSourceGuard.Hits(CollectorSourceGuard.Code("var q = '\"'; var u = \"https://x.example/\";"), CollectorSourceGuard.ExecOrNetwork));
        Assert.Empty(CollectorSourceGuard.Hits(CollectorSourceGuard.Code("// see https://docs.example/x\nvar a = 1; /* http://y.example */"), CollectorSourceGuard.ExecOrNetwork));
        // A scanner may still test text for a scheme separator; only a scheme spelled out is a URL.
        Assert.Empty(CollectorSourceGuard.Hits("if (candidate.Contains(\"://\", StringComparison.Ordinal)) return;", CollectorSourceGuard.ExecOrNetwork));
        Assert.NotEmpty(CollectorSourceGuard.Hits("var a = File.GetAttributes(path);", OwnFileAccess));
        Assert.NotEmpty(CollectorSourceGuard.Hits("private static Kind KindOf(string path)", OwnFileAccess));
        Assert.NotEmpty(CollectorSourceGuard.Hits("using var s = new FileStream(path, FileMode.Open);", OwnFileAccess));
        Assert.Empty(CollectorSourceGuard.Hits("var k = UserTreeReader.KindOf(p); using var s = new FileStream(handle, FileAccess.Read);", OwnFileAccess));
    }

    /// <summary>
    /// PAT-2050: a profile swapped for a junction into another profile after the scan
    /// registered it. Existence below it comes only from verified listings, which refuse the
    /// swapped root whatever it points at, so the result is the same, and partial, whether the
    /// other profile lacks or has every config the scan probes for: nothing is closed on the
    /// swap as absent, and nothing says what the other profile holds. Windows only: the
    /// refusal is the handle lister's.
    /// </summary>
    [DirectoryLinkFact]
    public void Scan_OnWindows_ProfileSwappedAfterItIsRegistered_IsPartialAndTheSameWhateverTheTargetHolds()
    {
        if (!OperatingSystem.IsWindows()) return;
        BuildTree();
        var other = Directory.CreateDirectory(Path.Combine(_root, "other-profile")).FullName;
        InventoryIdeExtensions Run()
        {
            var swap = new RootSwap(Home("carol"), other);
            var r = ScanAll(new IdeExtensionScanOptions
            {
                ResolveRootFinalPath = swap.Wrap(new IdeExtensionScanOptions().ResolveRootFinalPath),
            });
            Assert.True(swap.Swapped, "the swap never happened");
            swap.Restore();
            return r;
        }

        var lacking = Run();
        Write(Path.Combine(other, ".vscode", "extensions", "extensions.json"),
            $"[{VsxEntry("leaked.extension", "1.0.0", 1767225600000, "Leaked")}]");
        PackageJson(Path.Combine(other, ".cursor", "extensions", "leaked.cursor-1.0.0"), "leaked", "cursor", "1.0.0");
        Directory.CreateDirectory(Path.Combine(other, "AppData", "Roaming", "JetBrains", "IntelliJIdea2025.2", "plugins"));
        var having = Run();

        Assert.Equal(Serialise(lacking), Serialise(having));
        Assert.DoesNotContain("leaked", Serialise(having), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(IdeCollectionStatus.Partial, lacking.CollectionStatus);
        Assert.DoesNotContain(Assert.Single(lacking.Users, u => u.User == "TEST\\carol").CollectionStatus,
            new[] { IdeCollectionStatus.Complete, IdeCollectionStatus.NotPresent });
    }
}
