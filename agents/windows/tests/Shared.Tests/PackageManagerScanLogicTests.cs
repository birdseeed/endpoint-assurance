using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Patched.Shared.Contract;
using Patched.Shared.PackageManagers;
using Patched.Shared.UserTrees;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-2018: the Windows npm global, pip user and pipx scan against fixture profiles built in
/// a temp directory: several users, nvm-windows with two Node versions, fnm, volta, npm's
/// AppData prefix, scoped packages, a python.org user site, a Microsoft Store user site and a
/// pipx venv, plus a machine-wide Program Files\nodejs. The same cases as
/// macos/lib/test-package-managers.zsh, so the two agents are held to one contract.
///
/// Reparse points: on Windows the directory cases plant an NTFS junction (mklink /J, which
/// needs no privilege, so it is what an ordinary user would actually use) and the file cases
/// a symlink or, without that privilege, a hard link; elsewhere they plant a POSIX symlink. A
/// failure to create the planted link is an assertion failure, never a silent skip. A machine
/// that cannot plant a junction at all skips the directory cases explicitly, with the reason
/// (DirectoryLinkFact, PAT-2033).
/// </summary>
public sealed class PackageManagerScanLogicTests : IDisposable
{
    private readonly string _root;
    private readonly string _secret;

    public PackageManagerScanLogicTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"patched-pkg-test-{Guid.NewGuid():N}");
        _secret = Path.Combine(_root, "root-only");
        NpmPkg(Path.Combine(_secret, "node_modules"), "leaked-secret", "9.9.9");
        Write(Path.Combine(_secret, "package.json"), "{\"name\":\"leaked-secret\",\"version\":\"9.9.9\"}");
        Write(Path.Combine(_secret, "METADATA"), "Name: leaked-secret\nVersion: 9.9.9\n");
        Write(Path.Combine(_secret, "leaked_secret-9.9.9.dist-info", "METADATA"), "Name: leaked-secret\nVersion: 9.9.9\n");
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
    private string Sys => Path.Combine(_root, "sys");
    private string ProgramFiles => Path.Combine(Sys, "Program Files");
    private string Home(string user) => Path.Combine(Users, user);
    private string Nvm(string version) => Path.Combine(Home("alice"), "AppData", "Roaming", "nvm", version);
    private string AliceSite => Path.Combine(Home("alice"), "AppData", "Roaming", "Python", "Python312", "site-packages");
    private string BobVenv => Path.Combine(Home("bob"), "pipx", "venvs", "aider-chat");
    private string BobStoreSite => Path.Combine(Home("bob"), "AppData", "Local", "Packages",
        "PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0", "LocalCache", "local-packages", "Python311", "site-packages");

    private static void Write(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    private static void NpmPkg(string modules, string name, string version) =>
        Write(Path.Combine(modules, name.Replace('/', Path.DirectorySeparatorChar), "package.json"),
            "{\"name\":\"" + name + "\",\"version\":\"" + version + "\",\"bin\":{\"x\":\"cli.js\"}}");

    private static string DistInfo(string site, string name, string version)
    {
        var dir = Path.Combine(site, $"{name.Replace('-', '_')}-{version}.dist-info");
        Write(Path.Combine(dir, "METADATA"),
            $"Metadata-Version: 2.1\r\nName: {name}\r\nVersion: {version}\r\nSummary: fixture\r\n\r\n" +
            "Long description. Name: not-a-header\r\nVersion: 9.9.9\r\n");
        Write(Path.Combine(dir, "INSTALLER"), "pip");
        return Path.Combine(dir, "METADATA");
    }

    private void BuildTree()
    {
        if (Directory.Exists(Users)) DeleteTree(Users);
        if (Directory.Exists(Sys)) DeleteTree(Sys);
        Directory.CreateDirectory(Path.Combine(Home("carol"), "Documents"));

        NpmPkg(Path.Combine(ProgramFiles, "nodejs", "node_modules"), "npm", "10.2.4");
        NpmPkg(Path.Combine(ProgramFiles, "nodejs", "node_modules"), "corepack", "0.24.0");
        Directory.CreateDirectory(Path.Combine(ProgramFiles, "nodejs", "node_modules", ".bin"));

        // alice: nvm-windows with two Node versions (a scoped package in each), npm's own
        // AppData prefix, and a python.org 3.12 user site with a per-user interpreter.
        NpmPkg(Path.Combine(Nvm("v20.11.0"), "node_modules"), "npm", "10.2.4");
        NpmPkg(Path.Combine(Nvm("v20.11.0"), "node_modules"), "@anthropic-ai/claude-code", "2.0.1");
        NpmPkg(Path.Combine(Nvm("v22.3.0"), "node_modules"), "npm", "10.8.1");
        NpmPkg(Path.Combine(Nvm("v22.3.0"), "node_modules"), "@openai/codex", "0.40.0");
        Write(Path.Combine(Home("alice"), "AppData", "Roaming", "nvm", "settings.txt"), "root: x\r\npath: C:\\Program Files\\nodejs\r\n");
        NpmPkg(Path.Combine(Home("alice"), "AppData", "Roaming", "npm", "node_modules"), "@google/gemini-cli", "0.5.0");
        DistInfo(AliceSite, "llm", "0.19");
        Write(Path.Combine(AliceSite, "oldpkg-1.0-py3.12.egg-info", "PKG-INFO"), "Metadata-Version: 1.1\nName: oldpkg\nVersion: 1.0\n");
        Directory.CreateDirectory(Path.Combine(AliceSite, "llm"));
        Write(Path.Combine(Home("alice"), "AppData", "Local", "Programs", "Python", "Python312", "python.exe"), "");

        // bob: fnm, volta (a node image and a scoped package image), a pipx venv and a
        // Microsoft Store Python user site.
        NpmPkg(Path.Combine(Home("bob"), "AppData", "Roaming", "fnm", "node-versions", "v20.1.0", "installation", "node_modules"), "npm", "9.6.4");
        Directory.CreateDirectory(Path.Combine(Home("bob"), "AppData", "Roaming", "fnm", "aliases"));
        var volta = Path.Combine(Home("bob"), "AppData", "Local", "Volta", "tools", "image");
        NpmPkg(Path.Combine(volta, "node", "18.0.0", "node_modules"), "npm", "8.6.0");
        NpmPkg(Path.Combine(volta, "packages", "@google", "gemini-cli", "node_modules"), "@google/gemini-cli", "0.5.0");
        Write(Path.Combine(BobVenv, "pyvenv.cfg"),
            "home = C:\\Users\\bob\\AppData\\Local\\Programs\\Python\\Python312\r\ninclude-system-site-packages = false\r\n" +
            "version = 3.12.4\r\nexecutable = C:\\Users\\bob\\AppData\\Local\\Programs\\Python\\Python312\\python.exe\r\n");
        DistInfo(Path.Combine(BobVenv, "Lib", "site-packages"), "aider-chat", "0.80.0");
        DistInfo(Path.Combine(BobVenv, "Lib", "site-packages"), "requests", "2.32.0");
        DistInfo(BobStoreSite, "httpie", "3.2.2");
        Directory.CreateDirectory(Path.Combine(Home("bob"), "AppData", "Local", "Packages", "Microsoft.WindowsCalculator_8wekyb3d8bbwe"));
    }

    /// <summary>
    /// Deletes a fixture tree without ever walking through a planted link: a reparse point
    /// is unlinked where it stands and never recursed into.
    /// </summary>
    private static void DeleteTree(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            if ((attributes & FileAttributes.Directory) != 0) Directory.Delete(path);
            else File.Delete(path);
            return;
        }
        foreach (var dir in Directory.GetDirectories(path)) DeleteTree(dir);
        foreach (var file in Directory.GetFiles(path))
        {
            File.SetAttributes(file, FileAttributes.Normal);
            File.Delete(file);
        }
        Directory.Delete(path);
    }

    private PackageManagerScanOptions Options(int max = 5000, TimeSpan? budget = null) => new()
    {
        MaxPackagesPerSource = max,
        TimeBudget = budget ?? TimeSpan.FromSeconds(30),
        SystemNpmPrefixes = [new SystemNpmPrefix("system", ProgramFiles, ["nodejs"])],
        PythonInstallRoots = [ProgramFiles],
    };

    private IEnumerable<UserProfileSource> Profiles(params string[] users) =>
        (users.Length == 0 ? ["alice", "bob", "carol"] : users)
            .Select((u, i) => new UserProfileSource($"TEST\\{u}", $"S-1-5-21-1-2-3-{1001 + i}", Home(u)));

    private InventoryPackageManagers ScanAll(PackageManagerScanOptions? options = null, params string[] users) =>
        PackageManagerScanLogic.Scan(Profiles(users).ToList(), options ?? Options());

    private static string Serialise(InventoryPackageManagers r) => JsonSerializer.Serialize(r);

    private static void AssertNoLeak(InventoryPackageManagers r) =>
        Assert.DoesNotContain("leaked", Serialise(r), StringComparison.OrdinalIgnoreCase);

    private static string Src(InventoryPackageManagers r, string source) => r.Sources[source].CollectionStatus;

    private static IEnumerable<InventoryPackage> Pkgs(InventoryPackageManagers r, string source) =>
        r.Packages!.Where(p => p.Source == source);

    /// <summary>Plants a directory reparse point: an NTFS junction on Windows, a symlink elsewhere.</summary>
    private static void PlantDirectoryLink(string link, string target)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        if (OperatingSystem.IsWindows()) RunCmd($"mklink /J \"{link}\" \"{target}\"");
        else Directory.CreateSymbolicLink(link, target);
        Assert.True((File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0, $"failed to plant a reparse point at {link}");
    }

    /// <summary>A symlink where one can be created, else (Windows without the privilege) a hard link.</summary>
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

    /// <summary>
    /// A hard link on Windows, where the post-open identity check (link count) is what refuses
    /// it; elsewhere that check is not wired (the scan runs there only under test), so a
    /// symlink stands in.
    /// </summary>
    private static void PlantHardLinkOnWindows(string link, string target)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.CreateSymbolicLink(link, target);
            return;
        }
        RunCmd($"mklink /H \"{link}\" \"{target}\"");
        Assert.True(File.Exists(link), $"failed to plant a hard link at {link}");
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

    /// <summary>
    /// Denies reads of one file to the test's own account (chmod 000, or an Everyone read
    /// deny ACE on Windows), runs <paramref name="body"/>, and restores access. Returns false
    /// when the platform cannot make the file unreadable (running as root).
    /// </summary>
    private static bool WithUnreadable(string path, Action body)
    {
        if (OperatingSystem.IsWindows())
        {
            RunCmd($"icacls \"{path}\" /deny *S-1-1-0:(R)");
            try { body(); }
            finally { RunCmd($"icacls \"{path}\" /remove:d *S-1-1-0"); }
            return true;
        }
        File.SetUnixFileMode(path, UnixFileMode.None);
        try
        {
            try
            {
                using var probe = File.OpenRead(path);
                return false; // root: chmod 000 does not deny a read
            }
            catch (UnauthorizedAccessException) { }
            body();
            return true;
        }
        finally
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    // -------------------------------------------------------------------------
    // Everything readable
    // -------------------------------------------------------------------------

    [Fact]
    public void Scan_EverySourceSeveralUsers_IsComplete()
    {
        BuildTree();
        var r = ScanAll();

        Assert.Equal(PackageCollectionStatus.Complete, r.CollectionStatus);
        Assert.Equal(new[] { "complete", "complete", "complete" }, PackageSource.All.Select(s => Src(r, s)).ToArray());
        Assert.Equal((10, 3, 2), (Pkgs(r, "npm_global").Count(), Pkgs(r, "pip_user").Count(), Pkgs(r, "pipx").Count()));
        Assert.Equal(
            new[] { ("TEST\\alice", "complete"), ("TEST\\bob", "complete"), ("TEST\\carol", "not_present") },
            r.Users.Select(u => (u.User, u.CollectionStatus)).ToArray());
        Assert.Equal("S-1-5-21-1-2-3-1001", r.Users[0].UserId);
        Assert.Equal(
            new Dictionary<string, string> { ["npm_global"] = "complete", ["pip_user"] = "complete", ["pipx"] = "not_present" },
            r.Users[0].Sources);
        Assert.Equal(
            new[] { ("npm_global", 10, 7), ("pip_user", 3, 2), ("pipx", 2, 1) },
            PackageSource.All.Select(s => (s, r.Sources[s].PackageCount, r.Sources[s].LocationCount)).ToArray());
        Assert.False(r.Truncated);
        Assert.Null(r.TruncationReason);
        Assert.Empty(r.Issues);
    }

    [Fact]
    public void Scan_NvmTwoVersions_EachReadOnce_WithScopedPackages()
    {
        BuildTree();
        var r = ScanAll();

        Assert.Equal(
            new[] { ("20.11.0", 2), ("22.3.0", 2) },
            r.Locations.Where(l => l.Manager == "nvm").Select(l => (l.RuntimeVersion!, l.PackageCount)).OrderBy(t => t.Item1).ToArray());
        var claude = Assert.Single(r.Packages!, p => p.Name == "@anthropic-ai/claude-code");
        Assert.Equal(("2.0.1", "@anthropic-ai/claude-code", "TEST\\alice", "20.11.0"),
            (claude.Version!, claude.Directory!, claude.User!, claude.RuntimeVersion!));
        Assert.EndsWith(Path.Combine("nvm", "v20.11.0"), claude.Prefix);
        Assert.Equal(4, r.Packages!.Count(p => p.Manager == "nvm"));
    }

    /// <summary>
    /// PAT-2033: a Volta package image directory is entered only under a name an npm package
    /// can have. Any other is recorded as name_unsafe, not entered, and npm_global is partial.
    /// </summary>
    [Fact]
    public void Volta_PackageDirectory_IsEnteredOnlyUnderAnNpmName()
    {
        BuildTree();
        var vp = Path.Combine(Home("bob"), "AppData", "Local", "Volta", "tools", "image", "packages");
        NpmPkg(Path.Combine(vp, "JSONStream", "node_modules"), "JSONStream", "1.3.5");
        NpmPkg(Path.Combine(vp, "has space", "node_modules"), "leaked-volta-space", "1.0.0");
        NpmPkg(Path.Combine(vp, "semi;colon", "node_modules"), "leaked-volta-semi", "1.0.0");
        NpmPkg(Path.Combine(vp, "@bad scope", "child", "node_modules"), "leaked-volta-scope", "1.0.0");
        NpmPkg(Path.Combine(vp, "@google", "bad+child", "node_modules"), "leaked-volta-child", "1.0.0");
        var r = ScanAll();

        Assert.Equal(new[] { "@google/gemini-cli", "JSONStream", "npm" },
            r.Packages!.Where(p => p.Manager == "volta").Select(p => p.Name!).Order(StringComparer.Ordinal).ToArray());
        AssertNoLeak(r);
        Assert.Equal(new[] { "@bad scope", Path.Combine("@google", "bad+child"), "has space", "semi;colon" },
            r.Issues.Where(i => i.Code == "name_unsafe")
                .Select(i => Path.GetRelativePath(vp, i.Path)).Order(StringComparer.Ordinal).ToArray());
        Assert.Equal(PackageCollectionStatus.Partial, Src(r, "npm_global"));
    }

    [Fact]
    public void Scan_AppDataFnmVoltaAndSystemPrefixes_AreRead()
    {
        BuildTree();
        var r = ScanAll();

        Assert.Contains(r.Packages!, p => p.Manager == "appdata" && p.Name == "@google/gemini-cli" && p.User == "TEST\\alice");
        Assert.Contains(r.Packages!, p => p.Manager == "fnm" && p.Name == "npm" && p.RuntimeVersion == "20.1.0"
                                          && p.Prefix!.EndsWith(Path.Combine("v20.1.0", "installation"), StringComparison.Ordinal));
        Assert.Equal(new[] { "@google/gemini-cli", "npm" },
            r.Packages!.Where(p => p.Manager == "volta").Select(p => p.Name!).Order(StringComparer.Ordinal).ToArray());
        Assert.Equal(new[] { "corepack", "npm" },
            r.Packages!.Where(p => p.Scope == "system").Select(p => p.Name!).Order(StringComparer.Ordinal).ToArray());
        Assert.All(r.Packages!.Where(p => p.Scope == "system"), p => Assert.Null(p.User));
        Assert.DoesNotContain(r.Packages!, p => p.Directory!.StartsWith('.'));
    }

    [Fact]
    public void Scan_PipUserAndPipx_NameVersionInterpreterAndMain()
    {
        BuildTree();
        var r = ScanAll();

        var llm = Assert.Single(r.Packages!, p => p.Name == "llm");
        Assert.Equal(("0.19", "appdata_python", "3.12", "llm-0.19.dist-info", "read"),
            (llm.Version!, llm.Manager, llm.RuntimeVersion!, llm.Directory!, llm.MetadataStatus!));
        Assert.EndsWith(Path.Combine("Programs", "Python", "Python312", "python.exe"), llm.Interpreter);
        Assert.DoesNotContain(r.Packages!, p => p.Version == "9.9.9" || p.Name == "not-a-header");
        Assert.Contains(r.Packages!, p => p.Name == "oldpkg" && p.Version == "1.0");
        var httpie = Assert.Single(r.Packages!, p => p.Name == "httpie");
        Assert.Equal(("microsoft_store", "3.11"), (httpie.Manager, httpie.RuntimeVersion!));
        Assert.Null(httpie.Interpreter);
        Assert.Equal(
            new[] { ("aider-chat", "aider-chat", true), ("requests", "aider-chat", false) },
            Pkgs(r, "pipx").Select(p => (p.Name!, p.PipxApp!, p.PipxMain!.Value)).OrderBy(t => t.Item1, StringComparer.Ordinal).ToArray());
        Assert.All(Pkgs(r, "pipx"), p =>
        {
            Assert.EndsWith("python.exe", p.Interpreter);
            Assert.Equal("3.12.4", p.RuntimeVersion);
        });
        Assert.All(r.Packages!.Where(p => p.Source != "pipx"), p => Assert.True(p.PipxApp is null && p.PipxMain is null));
    }

    [Fact]
    public void Scan_RowsSerialiseTheSameKeysAsMacOS_WithExplicitNulls()
    {
        BuildTree();
        var json = JsonDocument.Parse(Serialise(ScanAll())).RootElement;
        Assert.Equal(
            new[] { "collection_status", "truncated", "truncation_reason", "sources", "users", "locations", "issues", "packages" },
            json.EnumerateObject().Select(p => p.Name).ToArray());
        var row = json.GetProperty("packages").EnumerateArray().First(p => p.GetProperty("scope").GetString() == "system");
        Assert.Equal(
            new[]
            {
                "source", "manager", "scope", "user", "user_id", "name", "version", "prefix", "runtime_version",
                "interpreter", "directory", "metadata_status", "pipx_app", "pipx_main",
            },
            row.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal(JsonValueKind.Null, row.GetProperty("user").ValueKind);
        Assert.Equal(JsonValueKind.Null, row.GetProperty("interpreter").ValueKind);
    }

    // -------------------------------------------------------------------------
    // Unreadable or corrupt manifests: partial, never empty
    // -------------------------------------------------------------------------

    [Fact]
    public void Scan_UnreadableMetadata_IsPartial_AndStillListed()
    {
        BuildTree();
        var metadata = Path.Combine(AliceSite, "llm-0.19.dist-info", "METADATA");
        InventoryPackageManagers? r = null;
        if (!WithUnreadable(metadata, () => r = ScanAll())) return;

        Assert.Equal(PackageCollectionStatus.Partial, r!.CollectionStatus);
        Assert.Equal(PackageCollectionStatus.Partial, Src(r, "pip_user"));
        var row = Assert.Single(r.Packages!, p => p.Directory == "llm-0.19.dist-info");
        Assert.Equal((null, null, "unreadable"), (row.Name, row.Version, row.MetadataStatus));
        Assert.Contains(r.Issues, i => i.Code == "metadata_unreadable");
        Assert.Equal(PackageCollectionStatus.Complete, Src(r, "npm_global"));
        Assert.Equal(PackageCollectionStatus.Complete, Src(r, "pipx"));
    }

    /// <summary>The post-open handle check is wired for METADATA: a rejected handle is unreadable, never read.</summary>
    [Fact]
    public void Scan_MetadataHandleRejectedAfterOpen_IsUnreadable()
    {
        BuildTree();
        var seen = new List<string>();
        var r = ScanAll(new PackageManagerScanOptions
        {
            SystemNpmPrefixes = [new SystemNpmPrefix("system", ProgramFiles, ["nodejs"])],
            PythonInstallRoots = [ProgramFiles],
            VerifyOpenedFile = (_, expected) =>
            {
                seen.Add(expected);
                return !expected.EndsWith(Path.Combine("llm-0.19.dist-info", "METADATA"), StringComparison.Ordinal);
            },
        });

        Assert.Contains(seen, p => p.EndsWith("package.json", StringComparison.Ordinal));
        Assert.Contains(seen, p => p.EndsWith("pyvenv.cfg", StringComparison.Ordinal));
        Assert.Equal("unreadable", Assert.Single(r.Packages!, p => p.Directory == "llm-0.19.dist-info").MetadataStatus);
        Assert.Equal(PackageCollectionStatus.Partial, Src(r, "pip_user"));
    }

    [Fact]
    public void Scan_MetadataWithoutName_OrMissing_IsPartial()
    {
        BuildTree();
        File.WriteAllText(Path.Combine(BobStoreSite, "httpie-3.2.2.dist-info", "METADATA"), "Metadata-Version: 2.1\nSummary: none\n");
        var r = ScanAll();
        Assert.Equal("unparseable", Assert.Single(r.Packages!, p => p.Directory == "httpie-3.2.2.dist-info").MetadataStatus);
        Assert.Equal(PackageCollectionStatus.Partial, Src(r, "pip_user"));

        File.Delete(Path.Combine(BobStoreSite, "httpie-3.2.2.dist-info", "METADATA"));
        r = ScanAll();
        Assert.Equal("missing", Assert.Single(r.Packages!, p => p.Directory == "httpie-3.2.2.dist-info").MetadataStatus);
    }

    [Fact]
    public void Scan_LargeMetadata_OnlyTheHeaderIsNeeded()
    {
        BuildTree();
        var metadata = Path.Combine(AliceSite, "llm-0.19.dist-info", "METADATA");
        File.AppendAllText(metadata, new string('x', 8 * 1024 * 1024));
        var r = ScanAll();
        Assert.Equal(PackageCollectionStatus.Complete, Src(r, "pip_user"));
        Assert.Equal("0.19", Assert.Single(r.Packages!, p => p.Name == "llm").Version);
    }

    [Fact]
    public void Scan_CorruptPackageJson_IsPartial_AndStillListed()
    {
        BuildTree();
        File.WriteAllText(Path.Combine(Nvm("v22.3.0"), "node_modules", "@openai", "codex", "package.json"), "{not json");
        var r = ScanAll();

        Assert.Equal(PackageCollectionStatus.Partial, r.CollectionStatus);
        Assert.Equal(PackageCollectionStatus.Partial, Src(r, "npm_global"));
        var row = Assert.Single(r.Packages!, p => p.Directory == "@openai/codex");
        Assert.Equal((null, "unparseable"), (row.Name, row.MetadataStatus!));
        Assert.Contains(r.Packages!, p => p.Name == "npm" && p.RuntimeVersion == "22.3.0");
        Assert.Equal(
            new[] { ("TEST\\alice", "partial"), ("TEST\\bob", "complete"), ("TEST\\carol", "not_present") },
            r.Users.Select(u => (u.User, u.CollectionStatus)).ToArray());
    }

    // -------------------------------------------------------------------------
    // Planted reparse points and links are never followed
    // -------------------------------------------------------------------------

    [DirectoryLinkFact]
    public void Scan_ReparsePointVersionDir_IsNotFollowed_AndPartial()
    {
        BuildTree();
        PlantDirectoryLink(Nvm("v99.0.0"), _secret);
        var r = ScanAll();

        AssertNoLeak(r);
        Assert.Contains(r.Issues, i => i.Code == "symlink_not_followed" && i.Path.EndsWith("v99.0.0", StringComparison.Ordinal));
        Assert.Equal(PackageCollectionStatus.Partial, Src(r, "npm_global"));
        Assert.Equal(4, r.Packages!.Count(p => p.Manager == "nvm"));
    }

    /// <summary>
    /// The version managers' own alias directories (fnm aliases, an nvm "current"-style link)
    /// are never looked at: nothing leaks and they cost nothing.
    /// </summary>
    [DirectoryLinkFact]
    public void Scan_VersionManagerAliasLinks_AreNeverFollowed()
    {
        BuildTree();
        PlantDirectoryLink(Path.Combine(Home("bob"), "AppData", "Roaming", "fnm", "aliases", "default"), _secret);
        PlantDirectoryLink(Path.Combine(Home("alice"), "AppData", "Roaming", "nvm", "current"), _secret);
        var r = ScanAll();

        AssertNoLeak(r);
        Assert.Equal(PackageCollectionStatus.Complete, r.CollectionStatus);
        Assert.Empty(r.Issues);
    }

    [DirectoryLinkFact]
    public void Scan_NpmLinkInNodeModules_AndScopeLink_AreRecordedNotRead()
    {
        BuildTree();
        PlantDirectoryLink(Path.Combine(Nvm("v20.11.0"), "node_modules", "linked-dev"), Path.Combine(_secret, "node_modules", "leaked-secret"));
        var scope = Path.Combine(Nvm("v22.3.0"), "node_modules", "@openai");
        DeleteTree(scope);
        PlantDirectoryLink(scope, Path.Combine(_secret, "node_modules"));
        var r = ScanAll();

        AssertNoLeak(r);
        Assert.Contains(r.Issues, i => i.Code == "symlink_not_followed" && i.Path.EndsWith("linked-dev", StringComparison.Ordinal));
        Assert.Contains(r.Issues, i => i.Code == "symlink_not_followed" && i.Path.EndsWith("@openai", StringComparison.Ordinal));
        Assert.Equal(PackageCollectionStatus.Partial, Src(r, "npm_global"));
    }

    [Fact]
    public void Scan_PlantedPackageJsonAndMetadataLinks_AreRefused()
    {
        BuildTree();
        var pkg = Path.Combine(Nvm("v20.11.0"), "node_modules", "npm", "package.json");
        File.Delete(pkg);
        PlantFileLink(pkg, Path.Combine(_secret, "package.json"));
        var metadata = Path.Combine(AliceSite, "llm-0.19.dist-info", "METADATA");
        File.Delete(metadata);
        PlantHardLinkOnWindows(metadata, Path.Combine(_secret, "METADATA"));
        var r = ScanAll();

        AssertNoLeak(r);
        Assert.Equal("unreadable", Assert.Single(r.Packages!, p => p.Prefix!.EndsWith("v20.11.0", StringComparison.Ordinal) && p.Directory == "npm").MetadataStatus);
        Assert.Equal("unreadable", Assert.Single(r.Packages!, p => p.Directory == "llm-0.19.dist-info").MetadataStatus);
        Assert.Equal(PackageCollectionStatus.Partial, Src(r, "npm_global"));
        Assert.Equal(PackageCollectionStatus.Partial, Src(r, "pip_user"));
    }

    [DirectoryLinkFact]
    public void Scan_ReparsePointDistInfoSiteAndVenv_AreNotEntered()
    {
        BuildTree();
        PlantDirectoryLink(Path.Combine(AliceSite, "planted-1.0.dist-info"), Path.Combine(_secret, "leaked_secret-9.9.9.dist-info"));
        DeleteTree(BobStoreSite);
        PlantDirectoryLink(BobStoreSite, _secret);
        PlantDirectoryLink(Path.Combine(Home("bob"), "pipx", "venvs", "planted"), _secret);
        var r = ScanAll();

        AssertNoLeak(r);
        Assert.Contains(r.Issues, i => i.Code == "symlink_not_followed" && i.Path.EndsWith("planted-1.0.dist-info", StringComparison.Ordinal));
        Assert.Contains(r.Issues, i => i.Code == "symlink_not_followed" && i.Path.EndsWith("site-packages", StringComparison.Ordinal));
        Assert.Contains(r.Issues, i => i.Code == "symlink_not_followed" && i.Path.EndsWith("planted", StringComparison.Ordinal));
        Assert.Equal(PackageCollectionStatus.Partial, Src(r, "pip_user"));
        Assert.Equal(PackageCollectionStatus.Partial, Src(r, "pipx"));
    }

    [DirectoryLinkFact]
    public void Scan_ReparsePointProfileRoot_UserFailed_NotReadThrough()
    {
        BuildTree();
        DeleteTree(Home("carol"));
        PlantDirectoryLink(Home("carol"), Home("alice"));
        var r = ScanAll();

        var carol = Assert.Single(r.Users, u => u.User == "TEST\\carol");
        Assert.Equal(PackageCollectionStatus.Failed, carol.CollectionStatus);
        Assert.DoesNotContain(r.Packages!, p => p.User == "TEST\\carol");
    }

    // -------------------------------------------------------------------------
    // A machine-wide prefix that is a link (nvm-windows' Program Files\nodejs)
    // -------------------------------------------------------------------------

    [DirectoryLinkFact]
    public void Scan_SystemPrefixLinkedIntoAVersionThisRunRead_IsCoveredAlias()
    {
        BuildTree();
        DeleteTree(Path.Combine(ProgramFiles, "nodejs"));
        PlantDirectoryLink(Path.Combine(ProgramFiles, "nodejs"), Nvm("v22.3.0"));
        var r = ScanAll();

        Assert.Equal(PackageCollectionStatus.Complete, Src(r, "npm_global"));
        Assert.Contains(r.Issues, i => i.Code == "alias_not_followed");
        Assert.DoesNotContain(r.Packages!, p => p.Scope == "system");
    }

    [DirectoryLinkFact]
    public void Scan_SystemPrefixLinkedAnywhereElse_IsNotFollowed_AndPartial()
    {
        BuildTree();
        DeleteTree(Path.Combine(ProgramFiles, "nodejs"));
        PlantDirectoryLink(Path.Combine(ProgramFiles, "nodejs"), _secret);
        var r = ScanAll();

        AssertNoLeak(r);
        Assert.Equal(PackageCollectionStatus.Partial, Src(r, "npm_global"));
        Assert.Contains(r.Issues, i => i.Code == "symlink_not_followed" && i.Path.EndsWith("nodejs", StringComparison.Ordinal));
    }

    // -------------------------------------------------------------------------
    // Credential-shaped text
    // -------------------------------------------------------------------------

    [Fact]
    public void Scan_UserInfoStripped_ControlCharactersDropped()
    {
        BuildTree();
        var pkg = Path.Combine(ProgramFiles, "nodejs", "node_modules", "corepack", "package.json");
        File.WriteAllText(pkg, "{\"name\":\"corepack\",\"version\":\"https://placeholder:placeholder@registry.example.invalid/1\"}");
        var r = ScanAll();
        Assert.Equal("https://registry.example.invalid/1", Assert.Single(r.Packages!, p => p.Name == "corepack").Version);
        Assert.DoesNotContain("placeholder", Serialise(r));

        File.WriteAllText(pkg, "{\"name\":\"corepack\",\"version\":\"1.0\\u001b[31m\"}");
        Assert.Null(Assert.Single(ScanAll().Packages!, p => p.Name == "corepack").Version);
    }

    // -------------------------------------------------------------------------
    // not_present, failed and bounds
    // -------------------------------------------------------------------------

    [Fact]
    public void Scan_NothingAnywhere_IsNotPresent_WithEmptyList()
    {
        Directory.CreateDirectory(Path.Combine(Home("dave"), "Documents"));
        Directory.CreateDirectory(Path.Combine(Home("erin"), "AppData", "Roaming"));
        Directory.CreateDirectory(ProgramFiles);

        var r = ScanAll(null, "dave", "erin");

        Assert.Equal(PackageCollectionStatus.NotPresent, r.CollectionStatus);
        Assert.All(PackageSource.All, s => Assert.Equal(PackageCollectionStatus.NotPresent, Src(r, s)));
        Assert.NotNull(r.Packages);
        Assert.Empty(r.Packages!);
        Assert.Empty(r.Locations);
    }

    [DirectoryLinkFact]
    public void Scan_UnreadableProfileList_PerUserHalfFailed_NeverEmpty()
    {
        BuildTree();
        var r = PackageManagerScanLogic.Scan(null, Options());
        Assert.Equal(PackageCollectionStatus.Partial, r.CollectionStatus);
        Assert.Equal(PackageCollectionStatus.Partial, Src(r, "npm_global"));
        Assert.Equal(PackageCollectionStatus.Failed, Src(r, "pip_user"));
        Assert.Equal(PackageCollectionStatus.Failed, Src(r, "pipx"));
        Assert.DoesNotContain(r.Packages!, p => p.Source != "npm_global");

        DeleteTree(Path.Combine(ProgramFiles, "nodejs"));
        PlantDirectoryLink(Path.Combine(ProgramFiles, "nodejs"), _secret);
        var failed = PackageManagerScanLogic.Scan(null, Options());
        Assert.Equal(PackageCollectionStatus.Failed, failed.CollectionStatus);
        Assert.Null(failed.Packages);
        Assert.False(JsonDocument.Parse(Serialise(failed)).RootElement.TryGetProperty("packages", out _));
        AssertNoLeak(failed);
    }

    [DirectoryLinkFact]
    public void Scan_OnlyNpmTreeRefused_UserSourceFailed_NotNotPresent()
    {
        BuildTree();
        DeleteTree(Home("bob"));
        DeleteTree(Home("carol"));
        DeleteTree(Path.Combine(Home("alice"), "AppData"));
        DeleteTree(Path.Combine(ProgramFiles, "nodejs"));
        PlantDirectoryLink(Path.Combine(Home("alice"), "AppData"), _secret);
        var r = ScanAll(null, "alice");

        AssertNoLeak(r);
        Assert.Equal(PackageCollectionStatus.Failed, r.Users[0].Sources["npm_global"]);
        Assert.Equal(PackageCollectionStatus.Failed, Src(r, "pip_user"));
        Assert.NotEqual(PackageCollectionStatus.NotPresent, Src(r, "npm_global"));
    }

    [Fact]
    public void Scan_UnreadableProfileEntries_MakeEverySourcePartial()
    {
        BuildTree();
        var r = PackageManagerScanLogic.Scan(Profiles().ToList(), Options(), unreadableProfiles: 1);
        Assert.Equal(PackageCollectionStatus.Partial, r.CollectionStatus);
        Assert.All(PackageSource.All, s => Assert.Equal(PackageCollectionStatus.Partial, Src(r, s)));
        Assert.Contains(r.Issues, i => i.Code == "profile_unreadable");
    }

    [Fact]
    public void Scan_PastThePackageLimit_EachSourceBoundedSeparately()
    {
        BuildTree();
        var r = ScanAll(Options(max: 2));

        Assert.Equal(PackageCollectionStatus.Partial, r.CollectionStatus);
        Assert.True(r.Truncated);
        Assert.Equal("package_limit", r.TruncationReason);
        Assert.Equal((2, 2), (r.Sources["npm_global"].PackageCount, r.Sources["pip_user"].PackageCount));
        Assert.True(r.Sources["npm_global"].Truncated);
        Assert.Equal(PackageCollectionStatus.Complete, Src(r, "pipx"));
    }

    [Fact]
    public void Scan_PastTheTimeBudget_IsPartialAndTruncated()
    {
        BuildTree();
        var r = ScanAll(Options(budget: TimeSpan.Zero));

        Assert.Equal(PackageCollectionStatus.Partial, r.CollectionStatus);
        Assert.Equal("time_limit", r.TruncationReason);
        Assert.All(PackageSource.All, s => Assert.NotEqual(PackageCollectionStatus.Complete, Src(r, s)));
    }

    /// <summary>
    /// The Service scanner cancels the token when its hard timeout abandons the scan: the scan
    /// stops at its next budget check, reads nothing further and never claims complete.
    /// </summary>
    [Fact]
    public void Scan_CancelledByTheHardTimeout_StopsAndIsNotComplete()
    {
        BuildTree();
        var r = PackageManagerScanLogic.Scan(Profiles().ToList(), new PackageManagerScanOptions
        {
            SystemNpmPrefixes = [new SystemNpmPrefix("system", ProgramFiles, ["nodejs"])],
            PythonInstallRoots = [ProgramFiles],
            Cancellation = new CancellationToken(canceled: true),
        });

        Assert.NotEqual(PackageCollectionStatus.Complete, r.CollectionStatus);
        Assert.True(r.Truncated);
        Assert.Empty(r.Packages ?? []);
    }

    [Fact]
    public void ParseMetadata_ReadsOnlyTheHeaderSection()
    {
        var (status, name, version) = PackageManagerScanLogic.ParseMetadata(
            Encoding.UTF8.GetBytes("Metadata-Version: 2.1\r\nName: Foo\r\nVersion: 1.2\r\nVersion: 3\r\n\r\nName: bar\r\n"));
        Assert.Equal(("read", "Foo", "1.2"), (status, name!, version!));
        Assert.Equal("unparseable", PackageManagerScanLogic.ParseMetadata(Encoding.UTF8.GetBytes("\r\nName: late\r\nVersion: 1\r\n")).Status);
    }

    // -------------------------------------------------------------------------
    // Nothing is executed: a source guard over every file on the collector's path
    // -------------------------------------------------------------------------

    public static IEnumerable<object[]> CollectorSources() =>
    [
        [Path.Combine("Shared", "PackageManagers", "PackageManagerScanLogic.cs")],
        [Path.Combine("Shared", "UserTrees", "UserTreeReader.cs")],
        [Path.Combine("Service", "PackageManagerScanner.cs")],
    ];

    /// <summary>
    /// PAT-2018: the collector reads files and never runs anything: no npm, pip, pipx, node or
    /// python, no shell, no process of any kind, and no network. Comments are stripped first,
    /// so the check is on code, and the using list is an allowlist, so a new namespace has to
    /// be reviewed here before it can be used.
    /// </summary>
    [Theory]
    [MemberData(nameof(CollectorSources))]
    public void CollectorSource_ExecutesNothing_AndOpensNoNetwork(string relative) =>
        // The guard itself is shared with the other Windows scanners (CollectorSourceGuard).
        CollectorSourceGuard.AssertExecutesNothing(relative, new HashSet<string>(StringComparer.Ordinal)
        {
            "System.Diagnostics", "System.Runtime.Versioning", "System.Text", "System.Text.Json",
            "System.Text.RegularExpressions", "Microsoft.Win32.SafeHandles", "Patched.Shared.Contract",
            "Patched.Shared.IdeExtensions", "Patched.Shared.PackageManagers", "Patched.Shared.UserTrees",
        });

    /// <summary>The guard above can fail: the same check over a line that launches a process goes red.</summary>
    [Fact]
    public void CollectorSourceGuard_CatchesAProcessLaunch()
    {
        var forbidden = new Regex(@"\bProcess\b|ProcessStartInfo|DllImport|\.(cmd|bat|ps1)""");
        Assert.Matches(forbidden, "var p = Process.Start(new ProcessStartInfo(\"npm.cmd\", \"ls -g\"));");
        Assert.Matches(forbidden, "[DllImport(\"kernel32.dll\")] static extern bool CreateProcessW();");
        Assert.Matches(forbidden, "Launch(\"npx.cmd\");");
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
        InventoryPackageManagers Run()
        {
            var swap = new RootSwap(Home("carol"), other);
            var options = Options();
            var r = ScanAll(new PackageManagerScanOptions
            {
                MaxPackagesPerSource = options.MaxPackagesPerSource,
                TimeBudget = options.TimeBudget,
                SystemNpmPrefixes = options.SystemNpmPrefixes,
                PythonInstallRoots = options.PythonInstallRoots,
                ResolveRootFinalPath = swap.Wrap(options.ResolveRootFinalPath),
            });
            Assert.True(swap.Swapped, "the swap never happened");
            swap.Restore();
            return r;
        }

        var lacking = Run();
        NpmPkg(Path.Combine(other, "AppData", "Roaming", "npm", "node_modules"), "leaked-npm", "1.0.0");
        NpmPkg(Path.Combine(other, "AppData", "Roaming", "nvm", "v20.0.0", "node_modules"), "leaked-nvm", "1.0.0");
        DistInfo(Path.Combine(other, "AppData", "Roaming", "Python", "Python312", "site-packages"), "leaked-pip", "1.0");
        Write(Path.Combine(other, "pipx", "venvs", "leaked-app", "pyvenv.cfg"), "version = 3.12.4\r\n");
        var having = Run();

        Assert.Equal(Serialise(lacking), Serialise(having));
        AssertNoLeak(having);
        Assert.Equal(PackageCollectionStatus.Partial, Src(lacking, PackageSource.NpmGlobal));
        Assert.Equal(PackageCollectionStatus.Partial, Src(lacking, PackageSource.PipUser));
        Assert.True(lacking.Issues.Any(i => i.Code == "unreadable" && i.Path.EndsWith(Path.Combine("Users", "carol"), StringComparison.Ordinal)));
    }
}
