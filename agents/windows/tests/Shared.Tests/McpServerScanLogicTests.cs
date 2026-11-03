using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Patched.Shared.Contract;
using Patched.Shared.IdeExtensions;
using Patched.Shared.McpServers;
using Patched.Shared.UserTrees;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-2020: the Windows MCP server configuration scan against fixture profiles built in a
/// temp directory, one config file per client format: Claude Desktop, Cursor, VS Code mcp.json
/// and settings.json (JSONC), Windsurf and Claude Code's .claude.json. The same cases as
/// macos/lib/test-mcp-servers.zsh, so the two agents are held to one contract.
///
/// Secrets: every value a config may carry that must never leave the device (env, arguments,
/// headers, URL userinfo, path and query, other keys in the file, files beside it) is planted
/// as a PLACEHOLDER or "leaked" marker, and every case asserts that neither appears anywhere in
/// the serialised block, issues included. The ticket's secret cases each have their own test:
/// S1 env, S2 arguments, S3 headers, S4 URL query and userinfo, S5 an internal hostname in an
/// argument against one in a URL, S6 an unrecognised package candidate.
///
/// Reparse points: on Windows the directory case plants an NTFS junction and the file case a
/// symlink or, without that privilege, a hard link; elsewhere a POSIX symlink.
/// </summary>
public sealed class McpServerScanLogicTests : IDisposable
{
    private readonly string _root;

    public McpServerScanLogicTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"patched-mcp-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { DeleteTree(_root); }
        catch { /* best effort */ }
    }

    // -------------------------------------------------------------------------
    // Fixture builders
    // -------------------------------------------------------------------------

    private static readonly string[] CdRel = ["AppData", "Roaming", "Claude", "claude_desktop_config.json"];
    private static readonly string[] CurRel = [".cursor", "mcp.json"];
    private static readonly string[] VsmRel = ["AppData", "Roaming", "Code", "User", "mcp.json"];
    private static readonly string[] VssRel = ["AppData", "Roaming", "Code", "User", "settings.json"];
    private static readonly string[] WsRel = [".codeium", "windsurf", "mcp_config.json"];
    private static readonly string[] CcRel = [".claude.json"];

    private string Users => Path.Combine(_root, "Users");
    private string Home(string user) => Path.Combine(Users, user);
    private string At(string user, string[] rel) => Path.Combine([Home(user), .. rel]);

    private static void Write(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    private void Plant(string user, string[] rel, string json) => Write(At(user, rel), json);

    private void BuildTree()
    {
        if (Directory.Exists(Users)) DeleteTree(Users);
        Directory.CreateDirectory(Path.Combine(Home("dave"), "Documents"));

        // alice: Claude Desktop (stdio: npx, docker, a uvx by full path) and Cursor (a remote
        // server whose headers carry a credential).
        Plant("alice", CdRel, """
            {
              "mcpServers": {
                "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\alice\\leaked-dir"]},
                "github": {"command": "docker", "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server:latest", "--leaked-flag"],
                           "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "PLACEHOLDER_DESKTOP_ENV"}},
                "git": {"command": "C:\\leaked-bin\\uvx.exe", "args": ["mcp-server-git@0.6.2", "--repository", "C:\\Users\\alice\\leaked-repo"]}
              },
              "globalShortcut": "leaked-other-key"
            }
            """);
        Plant("alice", CurRel, """{"mcpServers": {"remote": {"url": "https://mcp.example.com/sse", "headers": {"X-Leaked": "PLACEHOLDER_CURSOR_HEADER"}}}}""");

        // bob: VS Code mcp.json and settings.json, both JSONC, and Windsurf.
        Plant("bob", VsmRel, """
            // user-level MCP servers, leaked comment
            {
              "servers": {
                /* a block comment, leaked */
                "playwright": {"type": "stdio", "command": "npx", "args": ["@playwright/mcp@latest",],},
                "context7": {"type": "http", "url": "https://mcp.context7.com/mcp", "headers": {"leaked": "x"}},
              },
              "inputs": [{"id": "leaked-input", "type": "promptString", "password": true},],
            }
            """);
        Plant("bob", VssRel, """
            {
              // editor settings the collector never keeps
              "editor.fontSize": 14,
              "leaked.setting": "https://leaked.example.org/a//b",
              "mcp": {
                "servers": {
                  "legacy-sse": {"type": "sse", "url": "http://legacy.example.org:9000/sse"},
                },
              },
            }
            """);
        Plant("bob", WsRel, """
            {"mcpServers": {
              "brave-search": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-brave-search"], "env": {"BRAVE_API_KEY": "PLACEHOLDER_WINDSURF_ENV"}},
              "remote-w": {"serverUrl": "https://windsurf.example.net/mcp/leaked-path"}
            }}
            """);

        // carol: Claude Code's .claude.json, user scope and a project's local scope, beside
        // the account, history and other keys it must never keep, and .claude\settings.json,
        // which it must never open.
        Plant("carol", CcRel, """
            {
              "numStartups": 12,
              "oauthAccount": {"emailAddress": "leaked@example.com"},
              "mcpServers": {"sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp"}},
              "projects": {
                "C:\\Users\\carol\\leaked-project": {
                  "history": [{"display": "leaked prompt"}],
                  "mcpServers": {"time": {"type": "stdio", "command": "pipx", "args": ["run", "--spec", "mcp-server-time", "mcp-server-time"], "env": {}}}
                },
                "C:\\Users\\carol\\leaked-empty-project": {"allowedTools": []}
              }
            }
            """);
        Write(Path.Combine(Home("carol"), ".claude", "settings.json"),
            """{"mcpServers": {"leaked-never-read": {"command": "npx", "args": ["leaked"]}}}""");
    }

    /// <summary>Deletes a fixture tree without ever walking through a planted link.</summary>
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

    private static McpServerScanOptions Options(int max = 2000, TimeSpan? budget = null) => new()
    {
        MaxServers = max,
        TimeBudget = budget ?? TimeSpan.FromSeconds(30),
    };

    private IEnumerable<UserProfileSource> Profiles() =>
        new[] { "alice", "bob", "carol", "dave" }
            .Select((u, i) => new UserProfileSource($"TEST\\{u}", $"S-1-5-21-1-2-3-{1001 + i}", Home(u)));

    private InventoryMcpServers ScanAll(McpServerScanOptions? options = null) =>
        McpServerScanLogic.Scan(Profiles().ToList(), options ?? Options());

    private static string Serialise(InventoryMcpServers r) => JsonSerializer.Serialize(r);

    private static void AssertAbsent(InventoryMcpServers r, string text) =>
        Assert.DoesNotContain(text, Serialise(r), StringComparison.OrdinalIgnoreCase);

    private static void AssertNoLeak(InventoryMcpServers r)
    {
        AssertAbsent(r, "leaked");
        AssertAbsent(r, "PLACEHOLDER");
    }

    private static string Cl(InventoryMcpServers r, string client) => r.Clients[client].CollectionStatus;

    private static string Ucl(InventoryMcpServers r, string user, string client) =>
        r.Users.Single(u => u.User == $"TEST\\{user}").Clients[client];

    private static McpServerRow One(InventoryMcpServers r, string name) => Assert.Single(r.Servers!, s => s.Name == name);

    private static bool HasIssue(InventoryMcpServers r, string code, string suffix) =>
        r.Issues.Any(i => i.Code == code && i.Path.EndsWith(suffix, StringComparison.Ordinal));

    private static string Tail(params string[] rel) => Path.Combine(rel);

    private static void PlantDirectoryLink(string link, string target)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        if (OperatingSystem.IsWindows()) RunCmd($"mklink /J \"{link}\" \"{target}\"");
        else Directory.CreateSymbolicLink(link, target);
        Assert.True((File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0, $"failed to plant a reparse point at {link}");
    }

    private static void PlantFileSymlink(string link, string target)
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
            Assert.True(File.Exists(link), $"failed to plant a link at {link}");
            return;
        }
        File.CreateSymbolicLink(link, target);
    }

    private static void PlantHardLink(string link, string target)
    {
        if (OperatingSystem.IsWindows()) RunCmd($"mklink /H \"{link}\" \"{target}\"");
        else File.CreateSymbolicLink(link, target);
        Assert.True(File.Exists(link), $"failed to plant a hard link at {link}");
    }

    private static void RunCmd(string args) => RunProcess("cmd.exe", "/c " + args);

    private static void RunProcess(string file, params string[] args)
    {
        var psi = new ProcessStartInfo(file)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        if (file == "cmd.exe") psi.Arguments = args[0];
        else foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        p.WaitForExit(30_000);
        Assert.True(p.ExitCode == 0, $"{file} failed: {p.StandardError.ReadToEnd()}");
    }

    private static readonly string[] RowKeys =
    [
        "client", "user", "user_id", "config_path", "scope", "name", "transport", "transport_source",
        "executable", "runner", "package", "package_status", "host",
    ];

    // -------------------------------------------------------------------------
    // One config per client format
    // -------------------------------------------------------------------------

    [Fact]
    public void EveryClientFormat_IsReadForEveryUser()
    {
        BuildTree();
        var r = ScanAll();

        Assert.Equal(PackageCollectionStatus.Complete, r.CollectionStatus);
        Assert.All(McpClient.All, c => Assert.Equal(PackageCollectionStatus.Complete, Cl(r, c)));
        AssertNoLeak(r);
        Assert.Equal((11, 6, 4), (r.Totals.ServerCount, r.Totals.ConfigCount, r.Users.Count));
        Assert.Equal(PackageCollectionStatus.NotPresent, r.Users.Single(u => u.User == @"TEST\dave").CollectionStatus);
        Assert.Empty(r.Issues);

        var fs = One(r, "filesystem");
        Assert.Equal(
            (McpClient.ClaudeDesktop, "stdio", "inferred", "npx", "npx", "@modelcontextprotocol/server-filesystem", "extracted", (string?)null),
            (fs.Client, fs.Transport, fs.TransportSource, fs.Executable, fs.Runner, fs.Package, fs.PackageStatus, fs.Host));
        Assert.Equal(("docker", "ghcr.io/github/github-mcp-server"), (One(r, "github").Runner, One(r, "github").Package));
        Assert.Equal(("uvx.exe", "uvx", "mcp-server-git"), (One(r, "git").Executable, One(r, "git").Runner, One(r, "git").Package));

        var remote = One(r, "remote");
        Assert.Equal((McpClient.Cursor, "http", "inferred", "mcp.example.com", (string?)null, "not_applicable"),
            (remote.Client, remote.Transport, remote.TransportSource, remote.Host, remote.Executable, remote.PackageStatus));

        Assert.Equal((McpClient.VsCode, "declared", "@playwright/mcp"),
            (One(r, "playwright").Client, One(r, "playwright").TransportSource, One(r, "playwright").Package));
        Assert.Equal(("http", "mcp.context7.com"), (One(r, "context7").Transport, One(r, "context7").Host));
        Assert.Equal((McpClient.VsCode, "sse", "legacy.example.org"),
            (One(r, "legacy-sse").Client, One(r, "legacy-sse").Transport, One(r, "legacy-sse").Host));

        Assert.Equal("@modelcontextprotocol/server-brave-search", One(r, "brave-search").Package);
        Assert.Equal((McpClient.Windsurf, "windsurf.example.net"), (One(r, "remote-w").Client, One(r, "remote-w").Host));

        Assert.Equal((McpClient.ClaudeCode, "user", "mcp.sentry.dev"),
            (One(r, "sentry").Client, One(r, "sentry").Scope, One(r, "sentry").Host));
        Assert.Equal(("project", "pipx", "mcp-server-time"), (One(r, "time").Scope, One(r, "time").Runner, One(r, "time").Package));
        Assert.DoesNotContain(r.Servers!, s => s.Name == "leaked-never-read");
        Assert.DoesNotContain(r.Configs, c => c.Path.EndsWith(Tail(".claude", "settings.json"), StringComparison.Ordinal));

        Assert.Equal(
            new[] { (1, 3), (1, 1), (2, 3), (1, 2), (1, 2) },
            McpClient.All.Select(c => (r.Clients[c].ConfigCount, r.Clients[c].ServerCount)).ToArray());
        Assert.Equal("S-1-5-21-1-2-3-1001", r.Users[0].UserId);

        // Every server row serialises to exactly the allowed keys.
        var json = JsonDocument.Parse(Serialise(r)).RootElement;
        Assert.All(json.GetProperty("servers").EnumerateArray(),
            s => Assert.Equal(RowKeys, s.EnumerateObject().Select(p => p.Name).ToArray()));
    }

    // -------------------------------------------------------------------------
    // The ticket's secret cases, one test each
    // -------------------------------------------------------------------------

    [Fact]
    public void S1_ATokenInEnv_NeverLeavesTheDevice()
    {
        BuildTree();
        Plant("alice", CurRel, """{"mcpServers": {"envcase": {"command": "npx", "args": ["-y", "@acme/mcp"], "env": {"API_KEY": "PLACEHOLDER_ENV_SECRET", "OTHER": "PLACEHOLDER_ENV_SECRET_2"}}}}""");
        var r = ScanAll();
        AssertAbsent(r, "PLACEHOLDER_ENV_SECRET");
        AssertNoLeak(r);
        Assert.Equal(("@acme/mcp", "extracted"), (One(r, "envcase").Package, One(r, "envcase").PackageStatus));
        Assert.Equal(PackageCollectionStatus.Complete, Cl(r, McpClient.Cursor));
    }

    [Fact]
    public void S2_ATokenInAnArgument_NeverLeavesTheDevice()
    {
        BuildTree();
        Plant("alice", CurRel, """
            {"mcpServers": {
              "argeq": {"command": "npx", "args": ["-y", "@acme/mcp", "--api-key=PLACEHOLDER_ARG_EQ"]},
              "argsp": {"command": "npx", "args": ["-y", "@acme/mcp", "--token", "PLACEHOLDER_ARG_SPACE"]},
              "argfirst": {"command": "npx", "args": ["--token", "PLACEHOLDER_ARG_FIRST", "@acme/mcp"]},
              "argeqfirst": {"command": "npx", "args": ["--api-key=PLACEHOLDER_ARG_EQ_FIRST", "@acme/mcp"]},
              "pyword": {"command": "uvx", "args": ["--api-key", "placeholder-token-value", "mcp-x"]},
              "oneline": {"command": "npx -y @acme/mcp --token PLACEHOLDER_IN_COMMAND"}
            }}
            """);
        var r = ScanAll();
        AssertAbsent(r, "PLACEHOLDER_ARG_EQ");
        AssertAbsent(r, "PLACEHOLDER_ARG_SPACE");
        AssertAbsent(r, "PLACEHOLDER_ARG_FIRST");
        AssertAbsent(r, "placeholder-token-value");
        AssertAbsent(r, "PLACEHOLDER_IN_COMMAND");
        AssertNoLeak(r);
        Assert.Equal("@acme/mcp", One(r, "argeq").Package);
        Assert.Equal("@acme/mcp", One(r, "argsp").Package);
        Assert.Equal(((string?)null, "unrecognised"), (One(r, "argfirst").Package, One(r, "argfirst").PackageStatus));
        Assert.Equal("@acme/mcp", One(r, "argeqfirst").Package);
        Assert.Equal("unrecognised", One(r, "pyword").PackageStatus);
        Assert.Equal(((string?)null, (string?)null), (One(r, "oneline").Executable, One(r, "oneline").Package));
        Assert.True(HasIssue(r, "executable_unrecognised", Tail(CurRel)));
    }

    [Fact]
    public void S3_ATokenInHttpHeaders_NeverLeavesTheDevice()
    {
        BuildTree();
        Plant("alice", CurRel, """{"mcpServers": {"hdr": {"type": "http", "url": "https://api.example.com/mcp", "headers": {"Authorization": "Bearer PLACEHOLDER_HEADER_SECRET", "X-Api-Key": "PLACEHOLDER_HEADER_SECRET_2"}}}}""");
        var r = ScanAll();
        AssertAbsent(r, "PLACEHOLDER_HEADER_SECRET");
        AssertAbsent(r, "Authorization");
        AssertNoLeak(r);
        Assert.Equal("api.example.com", One(r, "hdr").Host);
    }

    [Fact]
    public void S4_ATokenInTheUrlQueryOrUserinfo_NeverLeavesTheDevice()
    {
        BuildTree();
        Plant("alice", CurRel, """
            {"mcpServers": {
              "query": {"url": "https://q.example.com/sse?token=PLACEHOLDER_QUERY_SECRET&x=1#PLACEHOLDER_FRAGMENT"},
              "userinfo": {"url": "https://PLACEHOLDER_USER:PLACEHOLDER_PASS@u.example.com:8443/leaked-path"},
              "atinpath": {"url": "https://p.example.com/PLACEHOLDER_PATH@q"},
              "atinpass": {"url": "https://user:PLACEHOLDER@SECRET@host.example/path?x=PLACEHOLDER_TOKEN_VALUE"}
            }}
            """);
        var r = ScanAll();
        AssertAbsent(r, "PLACEHOLDER_QUERY_SECRET");
        AssertAbsent(r, "PLACEHOLDER_FRAGMENT");
        AssertAbsent(r, "PLACEHOLDER_USER");
        AssertAbsent(r, "PLACEHOLDER_PASS");
        AssertAbsent(r, "8443");
        AssertNoLeak(r);
        Assert.Equal("q.example.com", One(r, "query").Host);
        Assert.Equal("u.example.com", One(r, "userinfo").Host);
        Assert.Equal("p.example.com", One(r, "atinpath").Host);
        Assert.Equal("host.example", One(r, "atinpass").Host);
        AssertAbsent(r, "SECRET@");
        AssertAbsent(r, "PLACEHOLDER_TOKEN_VALUE");
    }

    /// <summary>
    /// The shared CleanText cuts URL userinfo at the last @ before the host, so a password
    /// containing @ leaves nothing behind in any collector's text.
    /// </summary>
    [Fact]
    public void CleanText_StripsUserinfoUpToTheLastAt() =>
        Assert.Equal("see https://host.example/p and ftp://c.example",
            UserTreeReader.CleanText("see https://user:PLACEHOLDER@SECRET@host.example/p and ftp://a@b@c.example"));

    [Fact]
    public void S5_AnInternalHostnameInAnArgumentIsDropped_AUrlHostIsKept()
    {
        BuildTree();
        Plant("alice", CurRel, """
            {"mcpServers": {
              "bridge": {"command": "npx", "args": ["-y", "mcp-remote", "https://argonly.corp.example/sse", "--header", "Authorization: Bearer PLACEHOLDER_BRIDGE"]},
              "direct": {"url": "https://urlhost.corp.example/sse"},
              "private-image": {"command": "docker", "args": ["run", "-i", "--rm", "registry.argimage.corp.example/team/mcp:1.0"]}
            }}
            """);
        var r = ScanAll();
        AssertAbsent(r, "argonly.corp.example");
        AssertAbsent(r, "PLACEHOLDER_BRIDGE");
        AssertAbsent(r, "argimage.corp.example");
        Assert.Equal(("mcp-remote", (string?)null), (One(r, "bridge").Package, One(r, "bridge").Host));
        Assert.Equal("urlhost.corp.example", One(r, "direct").Host);
        Assert.Equal("unrecognised", One(r, "private-image").PackageStatus);
    }

    /// <summary>
    /// PAT-2033: a bracketed host with no colon is not an IPv6 literal. It is dropped, never
    /// sent as the host, and the block is not failed for it, so an agent never sends a value
    /// the server would reject the whole payload over.
    /// </summary>
    [Fact]
    public void BracketedHostWithoutAColon_IsDropped_AndTheBlockDoesNotFail()
    {
        BuildTree();
        Plant("alice", CurRel, """
            {"mcpServers": {
              "hexhost": {"url": "http://[0123456789abcdef0123456789abcdef01234567]/"},
              "v6": {"url": "http://[fe80::1]:8080/mcp"}
            }}
            """);
        var r = ScanAll();
        Assert.Null(One(r, "hexhost").Host);
        AssertAbsent(r, "0123456789abcdef0123456789abcdef01234567");
        Assert.Equal("fe80::1", One(r, "v6").Host);
        Assert.NotEqual(PackageCollectionStatus.Failed, r.CollectionStatus);
        Assert.Equal(PackageCollectionStatus.Complete, Cl(r, McpClient.Cursor));
    }

    [Fact]
    public void S6_AnUnrecognisedPackageCandidate_IsDroppedAndRecorded()
    {
        BuildTree();
        Plant("alice", CurRel, """
            {"mcpServers": {
              "path": {"command": "npx", "args": ["-y", "./leaked-local-dir/server"]},
              "url": {"command": "npx", "args": ["https://leaked.example.com/pkg.tgz"]},
              "upper": {"command": "npx", "args": ["-y", "LEAKED_UPPER"]},
              "eq": {"command": "uvx", "args": ["leaked-pkg==1.0"]},
              "shape": {"command": "npx", "args": ["sk-abcdefghijklmnopqrstuvwxyz0123456789"]},
              "jwt": {"command": "npx", "args": ["eyjhbg-x"]},
              "jwtshort": {"command": "npx", "args": ["eyJhbGc"]},
              "newline": {"command": "npx", "args": ["acme-pkg\n"]},
              "noarg": {"command": "npx", "args": ["-y"]},
              "notrunner": {"command": "node", "args": ["C:\\Users\\alice\\leaked-server.js"]},
              "compose": {"command": "docker", "args": ["compose", "up"]}
            }}
            """);
        var r = ScanAll();
        AssertNoLeak(r);
        AssertAbsent(r, "sk-abc");
        foreach (var n in new[] { "path", "url", "upper", "eq", "shape", "newline", "jwtshort" })
            Assert.Equal(((string?)null, "unrecognised"), (One(r, n).Package, One(r, n).PackageStatus));
        Assert.Equal("eyjhbg-x", One(r, "jwt").Package);
        Assert.Equal(7, r.Issues.Count(i => i.Code == "package_unrecognised" && i.Path.EndsWith(Tail(CurRel), StringComparison.Ordinal)));
        Assert.Equal("missing", One(r, "noarg").PackageStatus);
        Assert.Equal(("node", (string?)null, "not_applicable"),
            (One(r, "notrunner").Executable, One(r, "notrunner").Runner, One(r, "notrunner").PackageStatus));
        Assert.Equal("not_applicable", One(r, "compose").PackageStatus);
        Assert.Equal(PackageCollectionStatus.Complete, Cl(r, McpClient.Cursor));
    }

    // -------------------------------------------------------------------------
    // Runner forms and odd entries
    // -------------------------------------------------------------------------

    [Fact]
    public void RunnerForms_AreParsed()
    {
        BuildTree();
        Plant("alice", CurRel, """
            {"mcpServers": {
              "npmx": {"command": "npm", "args": ["exec", "--yes", "--package=@acme/tool", "--", "tool"]},
              "npmx2": {"command": "npm", "args": ["x", "--", "@acme/other@2"]},
              "bun": {"command": "bunx", "args": ["@acme/bun-mcp"]},
              "pnpm": {"command": "pnpm", "args": ["dlx", "acme-mcp"]},
              "uvtool": {"command": "uv", "args": ["tool", "run", "--python", "3.12", "acme-py"]},
              "uvfrom": {"command": "uvx", "args": ["--from", "acme-pkg", "acme-cmd"]},
              "uvrun": {"command": "uv", "args": ["run", "leaked-script.py"]},
              "win": {"command": "C:\\Program Files\\nodejs\\npx.cmd", "args": ["-y", "@acme/win"]},
              "wrapped": {"command": "cmd", "args": ["/c", "npx", "-y", "@acme/wrapped"]},
              "dock": {"command": "docker", "args": ["run", "-it", "--rm", "--name", "leaked-name", "-v", "C:\\leaked:/data", "--env=A=PLACEHOLDER_D", "mcp/fetch@sha256:0000000000000000000000000000000000000000000000000000000000000000"]},
              "weird": {"type": "ws", "url": "wss://ws.example.com/x"},
              "notobj": "leaked-string-entry"
            }}
            """);
        var r = ScanAll();
        Assert.Equal(("@acme/tool", "@acme/other"), (One(r, "npmx").Package, One(r, "npmx2").Package));
        Assert.Equal(("@acme/bun-mcp", "acme-mcp"), (One(r, "bun").Package, One(r, "pnpm").Package));
        Assert.Equal(("acme-py", "acme-pkg"), (One(r, "uvtool").Package, One(r, "uvfrom").Package));
        Assert.Equal("not_applicable", One(r, "uvrun").PackageStatus);
        Assert.Equal(("npx.cmd", "npx", "@acme/win"), (One(r, "win").Executable, One(r, "win").Runner, One(r, "win").Package));
        Assert.Equal(("cmd", "npx", "@acme/wrapped"), (One(r, "wrapped").Executable, One(r, "wrapped").Runner, One(r, "wrapped").Package));
        Assert.Equal("mcp/fetch", One(r, "dock").Package);
        Assert.Equal(("unknown", "declared", "ws.example.com"), (One(r, "weird").Transport, One(r, "weird").TransportSource, One(r, "weird").Host));
        Assert.Equal(("unknown", (string?)null), (One(r, "notobj").Transport, One(r, "notobj").Executable));
        Assert.True(HasIssue(r, "server_unparseable", Tail(CurRel)));
        Assert.Equal(PackageCollectionStatus.Partial, Cl(r, McpClient.Cursor));
        AssertNoLeak(r);
    }

    [Fact]
    public void SecretShapedOrUrlServerNames_AreDropped_AndTheServerStillCounted()
    {
        BuildTree();
        Plant("alice", CurRel, """{"mcpServers": {"sk-abcdefghijklmnopqrstuvwxyz0123456789": {"command": "npx"}, "https://leaked.example.com": {"command": "npx"}}}""");
        var r = ScanAll();
        AssertAbsent(r, "sk-abc");
        AssertNoLeak(r);
        Assert.Equal(12, r.Servers!.Count);
        Assert.Equal(2, r.Servers!.Count(s => s.Name is null));
        Assert.True(HasIssue(r, "name_unsafe", Tail(CurRel)));
    }

    [Fact]
    public void PastTheProjectLimit_TheRestAreNotRead_AndClaudeCodeIsPartial()
    {
        BuildTree();
        var projects = Enumerable.Range(0, 1000).ToDictionary(i => $"/leaked/p{i}", _ => (object)new { });
        projects["/leaked/last"] = new { mcpServers = new { beyond = new { command = "npx" } } };
        Plant("carol", CcRel, JsonSerializer.Serialize(new { mcpServers = new { top = new { command = "npx" } }, projects }));
        var r = ScanAll();
        Assert.DoesNotContain(r.Servers!, s => s.Name == "beyond");
        Assert.Single(r.Servers!, s => s.Name == "top");
        Assert.True(HasIssue(r, "project_limit", ".claude.json"));
        Assert.Equal(PackageCollectionStatus.Partial, Cl(r, McpClient.ClaudeCode));
        AssertNoLeak(r);
    }

    // -------------------------------------------------------------------------
    // Unparseable, unreadable, links, caps
    // -------------------------------------------------------------------------

    [Fact]
    public void TruncatedJson_IsUnparseable_NeverEmpty()
    {
        BuildTree();
        Plant("alice", CurRel, """{"mcpServers": {"x": {"command": "npx", "env": {"K": "PLACEHOLDER_BROKEN"}}""");
        var r = ScanAll();
        Assert.True(HasIssue(r, "unparseable", Tail(CurRel)));
        Assert.Equal(PackageCollectionStatus.Failed, Ucl(r, "alice", McpClient.Cursor));
        Assert.Equal(PackageCollectionStatus.Partial, Cl(r, McpClient.Cursor));
        Assert.Equal(PackageCollectionStatus.Partial, r.CollectionStatus);
        Assert.Equal(new[] { PackageCollectionStatus.Failed }, r.Configs.Where(c => c.Client == McpClient.Cursor).Select(c => c.CollectionStatus));
        AssertAbsent(r, "PLACEHOLDER_BROKEN");
    }

    [Theory]
    [InlineData("/* unterminated", "settings")]
    [InlineData("""{"mcp": "leaked"}""", "settings")]
    [InlineData("""{"mcpServers": ["leaked"]}""", "cursor")]
    public void AKeyThatShouldHoldServersButIsNotAnObject_OrBrokenJsonc_IsUnparseable(string content, string which)
    {
        BuildTree();
        if (which == "settings") Plant("bob", VssRel, content);
        else Plant("alice", CurRel, content);
        var r = ScanAll();
        Assert.True(HasIssue(r, "unparseable", which == "settings" ? Tail("User", "settings.json") : Tail(CurRel)));
        Assert.Equal(PackageCollectionStatus.Partial, r.CollectionStatus);
        AssertNoLeak(r);
    }

    [Fact]
    public void SettingsWithNoMcpKey_IsCompleteWithZeroServers()
    {
        BuildTree();
        Plant("bob", VssRel, """{"editor.fontSize": 12}""");
        var r = ScanAll();
        Assert.Equal(PackageCollectionStatus.Complete, Cl(r, McpClient.VsCode));
        Assert.Equal((PackageCollectionStatus.Complete, 0),
            r.Configs.Where(c => c.Path.EndsWith("settings.json", StringComparison.Ordinal)).Select(c => (c.CollectionStatus, c.ServerCount)).Single());
    }

    [Theory]
    [InlineData(65, false)]
    [InlineData(64, true)]
    public void NestingPastTheLimit_IsUnparseable_AtTheLimitParses(int depth, bool parses)
    {
        BuildTree();
        Plant("alice", CurRel, "{\"mcpServers\":{},\"x\":" + new string('[', depth - 1) + new string(']', depth - 1) + "}");
        var r = ScanAll();
        Assert.Equal(!parses, HasIssue(r, "unparseable", Tail(CurRel)));
        Assert.Equal(PackageCollectionStatus.Complete, Cl(r, McpClient.ClaudeDesktop));
    }

    [Fact]
    public void CommentMarkersInsideStrings_AreText()
    {
        BuildTree();
        Plant("alice", CurRel, """{"mcpServers": {"x": {"command": "npx", "args": ["// not a comment", "/* nor this */"]}}, "u": "http://a.example/b//c",}""");
        var r = ScanAll();
        Assert.Equal(PackageCollectionStatus.Complete, Cl(r, McpClient.Cursor));
        Assert.Equal("unrecognised", One(r, "x").PackageStatus);
    }

    [Fact]
    public void ALinkedConfigFile_IsNotRead()
    {
        BuildTree();
        var secret = Path.Combine(_root, "root-only", "mcp.json");
        Write(secret, """{"mcpServers": {"leaked-through-link": {"command": "npx", "env": {"K": "PLACEHOLDER_LINKED"}}}}""");
        File.Delete(At("alice", CurRel));
        PlantFileSymlink(At("alice", CurRel), secret);
        var r = ScanAll();
        AssertNoLeak(r);
        Assert.DoesNotContain(r.Servers!, s => s.Client == McpClient.Cursor && s.User == @"TEST\alice");
        Assert.True(HasIssue(r, "symlink_not_followed", Tail(CurRel)) || HasIssue(r, "unreadable", Tail(CurRel)));
        Assert.NotEqual(PackageCollectionStatus.Complete, Ucl(r, "alice", McpClient.Cursor));
    }

    [DirectoryLinkFact]
    public void ALinkedConfigDirectory_IsNotEntered()
    {
        BuildTree();
        var secretDir = Path.Combine(_root, "root-only", "cursor-dir");
        Write(Path.Combine(secretDir, "mcp.json"), """{"mcpServers": {"leaked-through-link": {"command": "npx"}}}""");
        DeleteTree(Path.Combine(Home("alice"), ".cursor"));
        PlantDirectoryLink(Path.Combine(Home("alice"), ".cursor"), secretDir);
        var r = ScanAll();
        AssertNoLeak(r);
        Assert.True(HasIssue(r, "symlink_not_followed", ".cursor"));
        Assert.Equal(PackageCollectionStatus.Partial, Ucl(r, "alice", McpClient.Cursor));
    }

    /// <summary>
    /// The single-link check is <see cref="WindowsFileIdentity.IsExpectedRegularFile"/> on the
    /// opened handle, which exists only on Windows (the shared reader has no link-count check
    /// elsewhere, where the scan runs only under test), so this case runs on Windows only. The
    /// macOS collector's own hard-link case is in test-mcp-servers.zsh.
    /// </summary>
    [Fact]
    public void AHardLinkedConfig_IsRefused()
    {
        if (!OperatingSystem.IsWindows()) return;
        BuildTree();
        var secret = Path.Combine(_root, "root-only", "hard.json");
        Write(secret, """{"mcpServers": {"leaked-through-link": {"command": "npx"}}}""");
        File.Delete(At("alice", CurRel));
        PlantHardLink(At("alice", CurRel), secret);
        var r = ScanAll();
        AssertNoLeak(r);
        Assert.True(HasIssue(r, "unreadable", Tail(CurRel)));
        Assert.Equal(PackageCollectionStatus.Failed, Ucl(r, "alice", McpClient.Cursor));
    }

    [Fact]
    public void AConfigOverItsCap_IsRefused()
    {
        BuildTree();
        Plant("alice", CurRel, "{\"mcpServers\":{}, \"pad\":\"" + new string('x', 1024 * 1024) + "\"}");
        var r = ScanAll();
        Assert.True(HasIssue(r, "unreadable", Tail(CurRel)));
        Assert.Equal(PackageCollectionStatus.Failed, Ucl(r, "alice", McpClient.Cursor));
    }

    // -------------------------------------------------------------------------
    // Absence requires authority, bounds
    // -------------------------------------------------------------------------

    [Fact]
    public void NoConfigAnywhere_IsNotPresent_WithAnEmptyList()
    {
        Directory.CreateDirectory(Path.Combine(Home("erin"), "Documents"));
        Directory.CreateDirectory(Path.Combine(Home("frank"), ".cursor"));
        var r = McpServerScanLogic.Scan(
            [new UserProfileSource(@"TEST\erin", "S-1", Home("erin")), new UserProfileSource(@"TEST\frank", "S-2", Home("frank"))], Options());
        Assert.Equal(PackageCollectionStatus.NotPresent, r.CollectionStatus);
        Assert.NotNull(r.Servers);
        Assert.Empty(r.Servers!);
        Assert.Empty(r.Configs);
    }

    [Fact]
    public void AnUnreadableProfileList_IsFailed_AndServersAreOmitted()
    {
        var r = McpServerScanLogic.Scan(null, Options());
        Assert.Equal(PackageCollectionStatus.Failed, r.CollectionStatus);
        Assert.Null(r.Servers);
        Assert.DoesNotContain("\"servers\"", JsonSerializer.Serialize(r));
    }

    [Fact]
    public void UnreadableProfiles_MakeEveryClientPartial_NotComplete()
    {
        BuildTree();
        var r = McpServerScanLogic.Scan(Profiles().ToList(), Options(), unreadableProfiles: 1);
        Assert.All(McpClient.All, c => Assert.Equal(PackageCollectionStatus.Partial, Cl(r, c)));
        Assert.True(HasIssue(r, "profile_unreadable", "ProfileList"));
    }

    [Fact]
    public void PastTheServerLimit_IsPartial()
    {
        BuildTree();
        var r = ScanAll(Options(max: 2));
        Assert.Equal(PackageCollectionStatus.Partial, r.CollectionStatus);
        Assert.Equal((true, "server_limit", 2), (r.Truncated, r.TruncationReason, r.Servers!.Count));
    }

    [Fact]
    public void PastTheTimeBudget_OrCancelled_IsPartial()
    {
        BuildTree();
        var r = ScanAll(Options(budget: TimeSpan.Zero));
        Assert.Equal((PackageCollectionStatus.Partial, "time_limit"), (r.CollectionStatus, r.TruncationReason));
        Assert.All(McpClient.All, c => Assert.NotEqual(PackageCollectionStatus.Complete, Cl(r, c)));

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var cancelled = ScanAll(new McpServerScanOptions { Cancellation = cts.Token });
        Assert.Equal((PackageCollectionStatus.Partial, "time_limit"), (cancelled.CollectionStatus, cancelled.TruncationReason));
    }

    // -------------------------------------------------------------------------
    // The minimal model, unit level
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("https://h.example.com", "h.example.com")]
    [InlineData("HTTPS://User:Pass@H.Example.COM.:443/p?q=1", "h.example.com")]
    [InlineData("http://[::1]:8080/x", "::1")]
    [InlineData("http://[fe80::1]:8080/mcp", "fe80::1")]
    [InlineData("http://[0123456789abcdef0123456789abcdef01234567]/", null)]
    [InlineData("http://[deadbeef]/", null)]
    [InlineData("wss://ws.example.com", "ws.example.com")]
    [InlineData("ftp://h.example.com", null)]
    [InlineData("https://${env:HOST}/mcp", null)]
    [InlineData("https://h.example.com\n", "h.example.com")]
    [InlineData("https://user:PLACEHOLDER@SECRET@host.example/path?x=PLACEHOLDER_TOKEN_VALUE", "host.example")]
    [InlineData("not a url", null)]
    public void UrlHost_KeepsTheHostOnly(string url, string? expected) =>
        Assert.Equal(expected, McpServerScanLogic.UrlHost(url));

    [Theory]
    [InlineData("npm", "@scope/pkg@1.2.3", "@scope/pkg")]
    [InlineData("npm", "pkg", "pkg")]
    [InlineData("npm", "Pkg", null)]
    [InlineData("npm", "pkg@^1", null)]
    [InlineData("npm", "pkg\n", null)]
    [InlineData("pypi", "Mcp_Server.Git", "Mcp_Server.Git")]
    [InlineData("pypi", "pkg==1", null)]
    [InlineData("pypi", "my-secret-tool", null)]
    [InlineData("docker", "mcp/fetch:latest", "mcp/fetch")]
    [InlineData("docker", "docker.io/library/alpine", "docker.io/library/alpine")]
    [InlineData("docker", "localhost:5000/x", null)]
    [InlineData("docker", "Upper/Case", null)]
    public void ValidPackage_IsStrict(string kind, string candidate, string? expected) =>
        Assert.Equal(expected, McpServerScanLogic.ValidPackage(kind, candidate));

    // -------------------------------------------------------------------------
    // Nothing is executed, nothing is networked, nothing but the six files is read
    // -------------------------------------------------------------------------

    public static IEnumerable<object[]> CollectorSources() =>
    [
        [Path.Combine("Shared", "McpServers", "McpServerScanLogic.cs")],
        [Path.Combine("Shared", "UserTrees", "UserTreeReader.cs")],
        [Path.Combine("Service", "McpServerScanner.cs")],
    ];

    [Theory]
    [MemberData(nameof(CollectorSources))]
    public void CollectorSource_ExecutesNothing_AndOpensNoNetwork(string relative) =>
        CollectorSourceGuard.AssertExecutesNothing(relative, new HashSet<string>(StringComparer.Ordinal)
        {
            "System.Diagnostics", "System.Runtime.Versioning", "System.Text.Json", "System.Text.RegularExpressions",
            "Microsoft.Win32.SafeHandles", "Patched.Shared.Contract", "Patched.Shared.IdeExtensions",
            "Patched.Shared.McpServers", "Patched.Shared.UserTrees",
        });

    private static string ScanCode() => CollectorSourceGuard.Code(
        File.ReadAllText(CollectorSourceGuard.SourceFile(Path.Combine("Shared", "McpServers", "McpServerScanLogic.cs"))));

    private static readonly Regex DirectFileAccess = new(
        @"File\.(Open|Read|OpenRead|OpenHandle|OpenText)|FileStream|StreamReader|MemoryMapped|RandomAccess\.",
        RegexOptions.CultureInvariant);

    /// <summary>
    /// PAT-2020 privacy rule: the scan opens files only through one ReadFile call over the
    /// Configs table, the table names exactly six files, .claude\settings.json is not among
    /// them, and the server model never reads env, headers or inputs.
    /// </summary>
    [Fact]
    public void CollectorSource_ReadsOnlyTheSixConfigs_AndNeverEnvOrHeaders()
    {
        var code = ScanCode();
        Assert.Single(Regex.Matches(code, @"_reader\.ReadFile\("));
        Assert.Single(Regex.Matches(code, @"_reader\.ReadFile\(path, cap\)"));
        Assert.Empty(CollectorSourceGuard.Hits(code, DirectFileAccess));
        Assert.Equal(6, Regex.Matches(code, @"^\s*\(McpClient\.\w+, \[", RegexOptions.Multiline).Count);
        Assert.DoesNotMatch(new Regex(@"""\.claude"",\s*""settings"), code);
        Assert.DoesNotMatch(new Regex(@"""(env|headers|envFile|inputs|oauthAccount|history)"""), code);
        // The server model reads exactly these keys of an entry.
        var entryKeys = Regex.Matches(code, @"Get\(entry, ""(\w+)""\)").Select(m => m.Groups[1].Value).Distinct().OrderBy(k => k, StringComparer.Ordinal);
        Assert.Equal(new[] { "args", "command", "serverUrl", "type", "url" }, entryKeys);
    }

    /// <summary>
    /// The Service scanner logs counts and statuses only: no server field in any template, and
    /// no exception message (a JSON parser message can quote config text).
    /// </summary>
    [Fact]
    public void ServiceScanner_LogsCountsOnly()
    {
        var code = CollectorSourceGuard.Code(File.ReadAllText(CollectorSourceGuard.SourceFile(Path.Combine("Service", "McpServerScanner.cs"))));
        Assert.DoesNotMatch(new Regex(@"\{(Name|Package|Host|Executable|Path|Message)\}"), code);
        Assert.DoesNotMatch(new Regex(@"Log\w+\(\s*ex\b|ex\.Message|ex\.ToString"), code);
    }

    /// <summary>The leak assertion itself goes red on a planted leak, so the absence checks above can fail.</summary>
    [Fact]
    public void AbsenceCheck_CatchesAPlantedLeak()
    {
        var leaky = new InventoryMcpServers
        {
            CollectionStatus = PackageCollectionStatus.Complete,
            Issues = [new PackageIssue { Code = "x", Path = "--token PLACEHOLDER_SELF_TEST" }],
        };
        Assert.ThrowsAny<Xunit.Sdk.XunitException>(() => AssertAbsent(leaky, "PLACEHOLDER_SELF_TEST"));
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
        InventoryMcpServers Run()
        {
            var swap = new RootSwap(Home("dave"), other);
            var options = Options();
            var r = ScanAll(new McpServerScanOptions
            {
                MaxServers = options.MaxServers,
                TimeBudget = options.TimeBudget,
                ResolveRootFinalPath = swap.Wrap(options.ResolveRootFinalPath),
            });
            Assert.True(swap.Swapped, "the swap never happened");
            swap.Restore();
            return r;
        }

        var lacking = Run();
        Write(Path.Combine([other, .. CdRel]), """{"mcpServers": {"leaked-cd": {"command": "npx", "args": ["leaked"]}}}""");
        Write(Path.Combine([other, .. CurRel]), """{"mcpServers": {"leaked-cursor": {"command": "npx", "args": ["leaked"]}}}""");
        Write(Path.Combine([other, .. VsmRel]), """{"servers": {"leaked-vs": {"type": "stdio", "command": "npx"}}}""");
        Write(Path.Combine([other, .. WsRel]), """{"mcpServers": {"leaked-ws": {"command": "npx"}}}""");
        Write(Path.Combine([other, .. CcRel]), """{"mcpServers": {"leaked-cc": {"type": "http", "url": "https://leaked.example.org/mcp"}}}""");
        var having = Run();

        Assert.Equal(Serialise(lacking), Serialise(having));
        AssertNoLeak(having);
        foreach (var client in McpClient.All)
        {
            Assert.Equal(PackageCollectionStatus.Partial, Cl(lacking, client));
            Assert.DoesNotContain(Ucl(lacking, "dave", client), new[] { PackageCollectionStatus.Complete, PackageCollectionStatus.NotPresent });
        }
        Assert.True(HasIssue(lacking, "unreadable", Path.Combine("Users", "dave")));
    }
}
