using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using Patched.Shared.Contract;
using Patched.Shared.IdeExtensions;
using Patched.Shared.UserTrees;

namespace Patched.Shared.McpServers;

/// <summary>Bounds and seams for <see cref="McpServerScanLogic.Scan"/>.</summary>
internal sealed class McpServerScanOptions
{
    public int MaxServers { get; init; } = 2000;
    public TimeSpan TimeBudget { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Cancelled by the Service scanner when its hard timeout abandons the scan, so a scan
    /// stuck behind a slow read stops at its next budget check instead of running on (and
    /// touching files) after its result has been thrown away. Checked wherever the time budget is.
    /// </summary>
    public CancellationToken Cancellation { get; init; }

    /// <summary>
    /// Checks an opened handle against the path the scan meant to open (link count, final
    /// path). <see cref="WindowsFileIdentity.IsExpectedRegularFile"/> on Windows; nothing
    /// elsewhere, where the scan runs only under test.
    /// </summary>
    public Func<SafeFileHandle, string, bool>? VerifyOpenedFile { get; init; } =
        OperatingSystem.IsWindows() ? WindowsFileIdentity.IsExpectedRegularFile : null;

    /// <summary>Kernel-resolved final path of a trusted root; null falls back to its full path.</summary>
    public Func<string, string?>? ResolveRootFinalPath { get; init; } =
        OperatingSystem.IsWindows() ? WindowsFileIdentity.FinalPathOfDirectory : null;
}

/// <summary>
/// What is kept of one configured server: the whole of it. Built by
/// <see cref="McpServerScanLogic.SummariseServer"/> from four inputs (type, command, args,
/// url or serverUrl); there is no field for anything else.
/// </summary>
internal sealed record McpServerSummary(
    string? Name, string Transport, string TransportSource, string? Executable, string? Runner,
    string? Package, string PackageStatus, string? Host);

/// <summary>
/// PAT-2020: MCP server configurations for every local user profile, read from the AI
/// clients' own config files and reduced on the device to name, transport, executable,
/// package and URL host. The Windows twin of macos/lib/mcp_servers.sh, producing the same
/// <see cref="InventoryMcpServers"/> shape field for field. Lives in Shared (no Windows TFM) so
/// its tests run on macOS as well as Windows; the Service's McpServerScanner resolves the real
/// profiles from HKLM ProfileList.
///
/// WHAT IS READ, AND ONLY THIS. Per profile:
///   claude_desktop  AppData\Roaming\Claude\claude_desktop_config.json      "mcpServers"
///   cursor          .cursor\mcp.json                                       "mcpServers"
///   vscode          AppData\Roaming\Code\User\mcp.json                     "servers"
///                   AppData\Roaming\Code\User\settings.json    "mcp": {"servers"}, "mcp.servers"
///   windsurf        .codeium\windsurf\mcp_config.json                      "mcpServers"
///   claude_code     .claude.json: top-level "mcpServers" (scope user) and each
///                   "projects".&lt;dir&gt;."mcpServers" (scope project, the directory not sent).
///                   .claude\settings.json holds no server definitions and is not read.
///   Every file is parsed as JSONC (comments skipped, trailing commas allowed) by
///   System.Text.Json with a depth limit of 64; nothing is evaluated.
///
/// SECRETS NEVER ENTER THE BLOCK (Andy's decision, 2026-09-22). <see cref="SummariseServer"/>
/// reads a server entry's type, command, args and url or serverUrl and returns a
/// <see cref="McpServerSummary"/>; env, headers, every other argument, the URL's path and query
/// and every other key are never copied anywhere. A package candidate is kept only when it
/// matches the strict npm, PyPI or public Docker image pattern and is not secret-shaped;
/// anything else is dropped and recorded as package_unrecognised. Issues carry a code and the
/// config file's path, never a value.
///
/// NOTHING IS EXECUTED AND NOTHING TOUCHES THE NETWORK. McpServerScanLogicTests carries a
/// source guard over this file, the shared reader and the Service scanner.
///
/// THE PROFILES ARE USER-OWNED AND THIS RUNS AS SYSTEM. Every read goes through
/// <see cref="UserTreeReader"/>: no reparse point is entered (a config junctioned or linked
/// from a dotfiles checkout is recorded as symlink_not_followed and the client is partial),
/// and every file opened is a single-link regular file under a cap whose handle is checked
/// against the path meant.
///
/// ABSENCE REQUIRES AUTHORITY (PAT-1710): see <see cref="InventoryMcpServers"/>.
/// </summary>
internal static class McpServerScanLogic
{
    private const int ConfigCap = 1024 * 1024;
    private const int SettingsCap = 4 * 1024 * 1024;
    private const int ClaudeJsonCap = 8 * 1024 * 1024;
    private const int MaxUsers = 500;
    private const int MaxIssues = 50;
    private const int MaxArgs = 256;
    private const int MaxProjects = 1000;
    private const int MaxCommandLength = 4096;

    private static readonly string[] AppDataRoaming = ["AppData", "Roaming"];

    /// <summary>(client, directory under the profile, file name, layout, size cap).</summary>
    private static readonly (string Client, string[] Parts, string File, string Layout, int Cap)[] Configs =
    [
        (McpClient.ClaudeDesktop, [.. AppDataRoaming, "Claude"], "claude_desktop_config.json", "mcpServers", ConfigCap),
        (McpClient.Cursor, [".cursor"], "mcp.json", "mcpServers", ConfigCap),
        (McpClient.VsCode, [.. AppDataRoaming, "Code", "User"], "mcp.json", "servers", ConfigCap),
        (McpClient.VsCode, [.. AppDataRoaming, "Code", "User"], "settings.json", "vscode_settings", SettingsCap),
        (McpClient.Windsurf, [".codeium", "windsurf"], "mcp_config.json", "mcpServers", ConfigCap),
        (McpClient.ClaudeCode, [], ".claude.json", "claude_code", ClaudeJsonCap),
    ];

    // Known credential shapes, and any unbroken run of 32 or more letters and digits (a key, a
    // hash, a token). Applied to every emitted string.
    private static readonly Regex SecretShape = new(
        @"(?:^|[^A-Za-z0-9])(?:sk|pk|rk)[-_]|gh[pousr]_|github_pat_|glpat-|xox[abposr]-|AKIA[0-9A-Z]{12}" +
        @"|AIza[0-9A-Za-z_-]{8}|eyJ[A-Za-z0-9_-]{4}|ya29\.|[A-Za-z0-9]{32}",
        RegexOptions.CultureInvariant);

    // Words that make a package candidate look like a credential rather than a package; a
    // candidate carrying one is dropped (a server name may keep them).
    private static readonly Regex SecretWord = new(
        @"token|secret|passw|bearer|api[-_]?key|credential|auth[-_]?key",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex NameRe = new(@"^[A-Za-z0-9@][A-Za-z0-9 ._@/+()\-]{0,127}\z", RegexOptions.CultureInvariant);
    private static readonly Regex ExecutableRe = new(@"^[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}\z", RegexOptions.CultureInvariant);
    private static readonly Regex NpmRe = new(@"^(?:@[a-z0-9][a-z0-9._\-]*/)?[a-z0-9][a-z0-9._\-]*\z", RegexOptions.CultureInvariant);
    private static readonly Regex PypiRe = new(@"^[A-Za-z0-9](?:[A-Za-z0-9._\-]{0,98}[A-Za-z0-9])?\z", RegexOptions.CultureInvariant);
    private static readonly Regex VersionRe = new(@"^[A-Za-z0-9._+\-]{1,64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex DockerPathRe = new(
        @"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*\z", RegexOptions.CultureInvariant);
    private static readonly Regex DockerTagRe = new(@"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}\z", RegexOptions.CultureInvariant);
    private static readonly Regex DockerDigestRe = new(@"^sha256:[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex UrlRe = new(@"^(?:[Hh][Tt][Tt][Pp][Ss]?|[Ww][Ss][Ss]?)://([^/?#]*)", RegexOptions.CultureInvariant);
    private static readonly Regex HostRe = new(
        @"^(?=.{1,253}\z)[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*\z",
        RegexOptions.CultureInvariant);
    private static readonly Regex Ipv6Re = new(@"^[0-9a-f:.]{2,45}\z", RegexOptions.CultureInvariant);

    // Only public registries are named; an image from any other registry carries that
    // registry's hostname, so it is dropped like any internal hostname.
    private static readonly HashSet<string> PublicRegistries = new(StringComparer.Ordinal)
    {
        "docker.io", "index.docker.io", "registry-1.docker.io", "ghcr.io", "quay.io",
        "mcr.microsoft.com", "public.ecr.aws", "gcr.io", "registry.gitlab.com",
    };

    private static readonly HashSet<string> NpxValue = new(StringComparer.Ordinal)
    {
        "-p", "--package", "--registry", "--cache", "--userconfig", "-w", "--workspace", "--prefix",
        "--node-options", "--shell", "--script-shell", "-c", "--call",
    };

    private static readonly HashSet<string> UvValue = new(StringComparer.Ordinal)
    {
        "--from", "--with", "--with-editable", "--with-requirements", "--python", "-p", "--index",
        "--index-url", "--extra-index-url", "--default-index", "--find-links", "-f", "--directory",
        "--project", "--cache-dir", "--config-file", "--constraints", "--overrides", "--build-constraints",
        "--index-strategy", "--keyring-provider", "--exclude-newer", "--refresh-package", "--reinstall-package",
        "--upgrade-package", "--color", "--python-preference", "--env-file",
    };

    private sealed record RunnerSpec(
        string[] Subcommands, HashSet<string>? ValueFlags, HashSet<string> PackageFlags, HashSet<string> TerminalFlags,
        string Kind, Dictionary<string, string>? Aliases = null);

    private static HashSet<string> Set(params string[] items) => new(items, StringComparer.Ordinal);

    // Package runners: subcommand tokens, flags that take a value (null: docker's rule), flags
    // whose value is the package, flags after which no package can be named, and kind.
    private static readonly Dictionary<string, RunnerSpec> Runners = new(StringComparer.Ordinal)
    {
        ["npx"] = new([], NpxValue, Set("-p", "--package"), Set("-c", "--call"), "npm"),
        ["npm"] = new(["exec"], NpxValue, Set("-p", "--package"), Set("-c", "--call"), "npm",
            new Dictionary<string, string>(StringComparer.Ordinal) { ["x"] = "exec" }),
        ["bunx"] = new([], Set("-p", "--package"), Set("-p", "--package"), Set(), "npm"),
        ["pnpx"] = new([], Set("--package"), Set("--package"), Set(), "npm"),
        ["pnpm"] = new(["dlx"], Set("--package"), Set("--package"), Set(), "npm"),
        ["yarn"] = new(["dlx"], Set("-p", "--package"), Set("-p", "--package"), Set(), "npm"),
        ["uvx"] = new([], UvValue, Set("--from"), Set(), "pypi"),
        ["uv"] = new(["tool", "run"], UvValue, Set("--from"), Set(), "pypi"),
        ["pipx"] = new(["run"], Set("--spec", "--python", "--index-url", "-i", "--pip-args"), Set("--spec"), Set(), "pypi"),
        ["docker"] = new(["run"], null, Set(), Set(), "docker"),
        ["podman"] = new(["run"], null, Set(), Set(), "docker"),
    };

    // docker run flags that take no value; every other flag is assumed to take one unless
    // written --flag=value, so a value is never mistaken for the image.
    private static readonly HashSet<string> DockerBoolLong = Set(
        "--rm", "--init", "--privileged", "--read-only", "--detach", "--interactive", "--tty",
        "--publish-all", "--no-healthcheck", "--oom-kill-disable", "--quiet", "--help", "--sig-proxy");
    private const string DockerBoolShort = "itdPq";

    private static readonly HashSet<string> RunnerExtensions = Set("exe", "cmd", "bat", "ps1");

    private static readonly Dictionary<string, string[]> Wrappers = new(StringComparer.Ordinal)
    {
        ["cmd"] = ["/c", "/k"],
    };

    private sealed class StopException : Exception;
    private sealed class FullException : Exception;

    private sealed class Unit
    {
        public int Problems;
        public int Ok;
        public bool Partial;
        public int Locations;

        public string Status =>
            Problems > 0 && Ok == 0 ? PackageCollectionStatus.Failed
            : Problems > 0 || Partial ? PackageCollectionStatus.Partial
            : Locations == 0 ? PackageCollectionStatus.NotPresent
            : PackageCollectionStatus.Complete;
    }

    private sealed class Ctx(string user, string? userId)
    {
        public string User { get; } = user;
        public string? UserId { get; } = userId;
        public Dictionary<string, Unit> Units { get; } = McpClient.All.ToDictionary(c => c, _ => new Unit());
    }

    private sealed class ConfigState
    {
        public required string Client;
        public required Ctx Ctx;
        public required string Path;
        public string Status = PackageCollectionStatus.Failed;
        public int Count;
    }

    /// <summary>
    /// Scans every profile. <paramref name="profiles"/> null means the profile list itself could
    /// not be read: every client is failed, never "no servers". <paramref name="unreadableProfiles"/>
    /// counts registered profiles whose location could not be read. Never throws.
    /// </summary>
    public static InventoryMcpServers Scan(
        IEnumerable<UserProfileSource>? profiles, McpServerScanOptions? options = null, int unreadableProfiles = 0)
    {
        var run = new Run(options ?? new McpServerScanOptions());
        try
        {
            return run.Execute(profiles, unreadableProfiles);
        }
        catch (Exception)
        {
            return new InventoryMcpServers { CollectionStatus = PackageCollectionStatus.Failed, Issues = run.Issues };
        }
    }

    internal static string Combine(IReadOnlyCollection<string> statuses, bool truncated = false)
    {
        if (statuses.Count > 0 && statuses.All(s => s == PackageCollectionStatus.Failed)) return PackageCollectionStatus.Failed;
        if (truncated || statuses.Any(s => s is PackageCollectionStatus.Partial or PackageCollectionStatus.Failed))
            return PackageCollectionStatus.Partial;
        if (statuses.Count == 0 || statuses.All(s => s == PackageCollectionStatus.NotPresent))
            return PackageCollectionStatus.NotPresent;
        return PackageCollectionStatus.Complete;
    }

    // -------------------------------------------------------------------------
    // JSONC
    // -------------------------------------------------------------------------

    /// <summary>
    /// The parsed document when <paramref name="data"/> is a JSON(C) object within the depth
    /// limit, else null. Comments are skipped and trailing commas allowed, as VS Code writes
    /// them; nothing is evaluated. The caller disposes the document.
    /// </summary>
    internal static JsonDocument? ParseJsonc(byte[] data)
    {
        ReadOnlyMemory<byte> bytes = data;
        if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) bytes = bytes[3..];
        try
        {
            var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
                MaxDepth = 64,
            });
            if (doc.RootElement.ValueKind == JsonValueKind.Object) return doc;
            doc.Dispose();
            return null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>The last property called <paramref name="name"/> (the macOS parser's rule for a repeated key), or null when absent or JSON null.</summary>
    private static JsonElement? Get(JsonElement obj, string name)
    {
        JsonElement? found = null;
        foreach (var p in obj.EnumerateObject())
            if (p.NameEquals(name)) found = p.Value;
        return found is { ValueKind: JsonValueKind.Null } ? null : found;
    }

    /// <summary>An object's properties with repeated names collapsed to the last value, in first-seen order.</summary>
    private static List<(string Name, JsonElement Value)> Entries(JsonElement obj)
    {
        var order = new List<string>();
        var values = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var p in obj.EnumerateObject())
        {
            if (!values.ContainsKey(p.Name)) order.Add(p.Name);
            values[p.Name] = p.Value;
        }
        return order.Select(n => (n, values[n])).ToList();
    }

    /// <summary>
    /// ([(scope, servers object)], capped) for one parsed file, or null when a key that should
    /// hold servers is there but is not an object. capped is true when Claude Code's projects
    /// ran past <see cref="MaxProjects"/> and the rest were not looked at.
    /// </summary>
    internal static (List<(string Scope, JsonElement Servers)> Maps, bool Capped)? ServerMaps(JsonElement root, string layout)
    {
        var found = new List<(string, JsonElement)>();
        bool One(JsonElement? value, string scope)
        {
            if (value is null) return true;
            if (value.Value.ValueKind != JsonValueKind.Object) return false;
            found.Add((scope, value.Value));
            return true;
        }

        if (layout is "mcpServers" or "servers")
            return One(Get(root, layout), "user") ? (found, false) : null;
        if (layout == "vscode_settings")
        {
            var mcp = Get(root, "mcp");
            var ok = One(Get(root, "mcp.servers"), "user");
            if (mcp is not null)
                ok = ok && mcp.Value.ValueKind == JsonValueKind.Object && One(Get(mcp.Value, "servers"), "user");
            return ok ? (found, false) : null;
        }
        // claude_code: user scope at the top, local scope under each project. A project entry
        // that is not an object holds no servers and is skipped.
        var fine = One(Get(root, "mcpServers"), "user");
        var projects = Get(root, "projects");
        var capped = false;
        if (projects is { ValueKind: JsonValueKind.Object })
        {
            var index = 0;
            foreach (var (_, project) in Entries(projects.Value))
            {
                if (index++ >= MaxProjects)
                {
                    capped = true;
                    break;
                }
                if (project.ValueKind == JsonValueKind.Object)
                    fine = One(Get(project, "mcpServers"), "project") && fine;
            }
        }
        else if (projects is not null)
        {
            fine = false;
        }
        return fine ? (found, capped) : null;
    }

    // -------------------------------------------------------------------------
    // The minimal server model. Everything below sees one server entry and returns only a
    // McpServerSummary. Nothing here stores an argument, an env value, a header or a URL; the
    // only strings that leave are ones that passed a strict pattern.
    // -------------------------------------------------------------------------

    internal static bool LooksSecret(string value) => SecretShape.IsMatch(value);

    internal static string? SafeName(string? value)
    {
        var v = UserTreeReader.CleanText(value, 128);
        return v is null || !NameRe.IsMatch(v) || LooksSecret(v) ? null : v;
    }

    /// <summary>
    /// The basename of a command, or null when it is not a plain executable name (a command
    /// line written into one string, a variable, anything secret-shaped).
    /// </summary>
    internal static string? ExecutableName(string? command)
    {
        if (command is null || command.Length > MaxCommandLength) return null;
        var trimmed = command.Trim();
        var cut = trimmed.LastIndexOfAny(['\\', '/']);
        var name = cut < 0 ? trimmed : trimmed[(cut + 1)..];
        return !ExecutableRe.IsMatch(name) || LooksSecret(name) ? null : name;
    }

    internal static string RunnerKey(string executable)
    {
        // The Windows launcher extensions, compared without their dot so the source guard's
        // script-launch pattern stays meaningful for this file.
        var low = executable.ToLowerInvariant();
        var dot = low.LastIndexOf('.');
        return dot > 0 && RunnerExtensions.Contains(low[(dot + 1)..]) ? low[..dot] : low;
    }

    private static string? StripVersion(string candidate, bool scoped)
    {
        var at = candidate.IndexOf('@', scoped ? 1 : 0);
        if (at <= 0) return candidate;
        return VersionRe.IsMatch(candidate[(at + 1)..]) ? candidate[..at] : null;
    }

    /// <summary>registry/path of a public image, without tag or digest, or null.</summary>
    internal static string? DockerImage(string candidate)
    {
        var reference = candidate;
        var at = reference.IndexOf('@');
        if (at >= 0)
        {
            if (!DockerDigestRe.IsMatch(reference[(at + 1)..])) return null;
            reference = reference[..at];
        }
        var slash = reference.LastIndexOf('/');
        var colon = reference.LastIndexOf(':');
        if (colon > slash)
        {
            if (!DockerTagRe.IsMatch(reference[(colon + 1)..])) return null;
            reference = reference[..colon];
        }
        var parts = reference.Split('/').ToList();
        string? registry = null;
        if (parts.Count > 1 && (parts[0].Contains('.') || parts[0].Contains(':')))
        {
            registry = parts[0].ToLowerInvariant();
            parts.RemoveAt(0);
            if (!PublicRegistries.Contains(registry)) return null;
        }
        var path = string.Join('/', parts);
        if (!DockerPathRe.IsMatch(path)) return null;
        return (registry is null ? "" : registry + "/") + path;
    }

    /// <summary>
    /// The package name <paramref name="candidate"/> names, or null when it fails the strict
    /// pattern for its kind. Never returns a path, a URL, anything with "=" or anything
    /// secret-shaped.
    /// </summary>
    internal static string? ValidPackage(string kind, string? candidate)
    {
        if (string.IsNullOrEmpty(candidate) || candidate.Length > 214) return null;
        // A docker digest is 64 hex characters by design; it is checked by its own pattern and
        // dropped, so only the rest of the reference is secret-checked.
        var cut = kind == "docker" ? candidate.IndexOf("@sha256:", StringComparison.Ordinal) : -1;
        var probe = cut >= 0 ? candidate[..cut] : candidate;
        if (candidate.Contains('=') || candidate.Contains("://", StringComparison.Ordinal) || candidate.Contains('\\')
            || "./~$%".Contains(candidate[0]) || LooksSecret(probe) || SecretWord.IsMatch(probe))
            return null;
        switch (kind)
        {
            case "npm":
            {
                var name = StripVersion(candidate, candidate.StartsWith('@'));
                return name is not null && NpmRe.IsMatch(name) ? name : null;
            }
            case "pypi":
            {
                var name = StripVersion(candidate, false);
                return name is not null && PypiRe.IsMatch(name) ? name : null;
            }
            case "docker":
                return DockerImage(candidate);
            default:
                return null;
        }
    }

    private static bool TakesValue(string flag, HashSet<string>? valueFlags)
    {
        if (valueFlags is not null) return valueFlags.Contains(flag);
        // docker: bundled short booleans (-it) take none; any other flag does.
        if (flag.StartsWith("--", StringComparison.Ordinal)) return !DockerBoolLong.Contains(flag);
        return !flag[1..].All(c => DockerBoolShort.Contains(c));
    }

    /// <summary>
    /// (package_status, package): extracted, unrecognised, missing or not_applicable.
    /// <paramref name="args"/> is walked only to find the one candidate; nothing else is kept.
    /// A null element is an argument that was not a string.
    /// </summary>
    internal static (string Status, string? Package) PackageOf(string runner, IReadOnlyList<string?> args)
    {
        var spec = Runners[runner];
        int i = 0, n = Math.Min(args.Count, MaxArgs), sub = 0;
        string? candidate = null;
        var ended = false;
        while (i < n)
        {
            var a = args[i];
            if (a is null) return ("unrecognised", null);
            if (sub < spec.Subcommands.Length)
            {
                if (a.StartsWith('-'))
                {
                    i++;
                    continue;
                }
                var word = spec.Aliases is not null && spec.Aliases.TryGetValue(a, out var alias) ? alias : a;
                if (word != spec.Subcommands[sub]) return ("not_applicable", null);
                sub++;
                i++;
                continue;
            }
            if (a == "--")
            {
                candidate = i + 1 < n ? args[i + 1] : null;
                ended = true;
                break;
            }
            if (a.StartsWith('-') && a.Length > 1)
            {
                var eq = a.IndexOf('=');
                var flag = eq >= 0 ? a[..eq] : a;
                if (spec.TerminalFlags.Contains(flag)) return ("unrecognised", null);
                if (spec.PackageFlags.Contains(flag))
                {
                    candidate = eq >= 0 ? a[(eq + 1)..] : i + 1 < n ? args[i + 1] : null;
                    ended = true;
                    break;
                }
                i += eq >= 0 || !TakesValue(flag, spec.ValueFlags) ? 1 : 2;
                continue;
            }
            candidate = a;
            ended = true;
            break;
        }
        if (!ended) return sub == spec.Subcommands.Length ? ("missing", null) : ("not_applicable", null);
        if (candidate is null) return ("missing", null);
        var name = ValidPackage(spec.Kind, candidate);
        return name is not null ? ("extracted", name) : ("unrecognised", null);
    }

    /// <summary>
    /// A URL's host, lower-cased, with no scheme, userinfo, port, path or query, or null when it
    /// is not an http(s)/ws(s) URL with a plain host.
    /// </summary>
    internal static string? UrlHost(string? url)
    {
        if (url is null || url.Length > MaxCommandLength) return null;
        var m = UrlRe.Match(url.Trim());
        if (!m.Success) return null;
        var authority = m.Groups[1].Value;
        var at = authority.LastIndexOf('@');
        if (at >= 0) authority = authority[(at + 1)..];
        if (authority.StartsWith('['))
        {
            var end = authority.IndexOf(']');
            var v6 = end > 0 ? authority[1..end].ToLowerInvariant() : "";
            // A bracketed value with no colon is not an IPv6 literal: a hex token would
            // otherwise go out as the host. The server rejects one, so it is dropped here
            // rather than fail the whole payload (PAT-2033).
            return v6.Contains(':') && Ipv6Re.IsMatch(v6) ? v6 : null;
        }
        var colon = authority.IndexOf(':');
        var host = (colon >= 0 ? authority[..colon] : authority).ToLowerInvariant().TrimEnd('.');
        return !HostRe.IsMatch(host) || LooksSecret(host) ? null : host;
    }

    private static (string Transport, string Source) TransportOf(JsonElement? declared, bool commandIsString, bool urlIsString)
    {
        if (declared is { ValueKind: JsonValueKind.String })
        {
            var t = declared.Value.GetString()!.Trim().ToLowerInvariant();
            return t switch
            {
                "stdio" => ("stdio", "declared"),
                "http" or "streamable-http" or "streamable_http" or "streamablehttp" => ("http", "declared"),
                "sse" => ("sse", "declared"),
                _ => ("unknown", "declared"),
            };
        }
        if (commandIsString) return ("stdio", "inferred");
        if (urlIsString) return ("http", "inferred");
        return ("unknown", "inferred");
    }

    /// <summary>
    /// The summary of one server entry, and the issue codes it raised. Reads the entry's type,
    /// command, args and url or serverUrl, and nothing else.
    /// </summary>
    internal static McpServerSummary SummariseServer(string name, JsonElement entry, List<string> codes)
    {
        var safeName = SafeName(name);
        if (safeName is null) codes.Add("name_unsafe");
        if (entry.ValueKind != JsonValueKind.Object)
        {
            codes.Add("server_unparseable");
            return new McpServerSummary(safeName, "unknown", "inferred", null, null, null, "not_applicable", null);
        }

        var command = Get(entry, "command");
        var url = Get(entry, "url");
        if (url is not { ValueKind: JsonValueKind.String }) url = Get(entry, "serverUrl");
        var (transport, source) = TransportOf(
            Get(entry, "type"), command is { ValueKind: JsonValueKind.String }, url is { ValueKind: JsonValueKind.String });

        string? executable = null, runner = null, package = null, host = null;
        var packageStatus = "not_applicable";
        if (command is not null)
        {
            executable = command.Value.ValueKind == JsonValueKind.String ? ExecutableName(command.Value.GetString()) : null;
            if (executable is null)
            {
                codes.Add("executable_unrecognised");
            }
            else
            {
                var args = new List<string?>();
                if (Get(entry, "args") is { ValueKind: JsonValueKind.Array } array)
                    foreach (var item in array.EnumerateArray().Take(MaxArgs + 2))
                        args.Add(item.ValueKind == JsonValueKind.String ? item.GetString() : null);
                string? key = RunnerKey(executable);
                if (Wrappers.TryGetValue(key, out var switches) && args.Count > 0 && args[0] is { } first
                    && switches.Contains(first.ToLowerInvariant()))
                {
                    var inner = args.Count > 1 ? ExecutableName(args[1]) : null;
                    key = inner is null ? null : RunnerKey(inner);
                    args = args.Skip(2).ToList();
                }
                if (key is not null && Runners.ContainsKey(key))
                {
                    runner = key;
                    (packageStatus, package) = PackageOf(key, args);
                    if (packageStatus == "unrecognised") codes.Add("package_unrecognised");
                }
            }
        }
        if (url is not null)
        {
            host = url.Value.ValueKind == JsonValueKind.String ? UrlHost(url.Value.GetString()) : null;
            if (host is null) codes.Add("url_unrecognised");
        }
        return new McpServerSummary(safeName, transport, source, executable, runner, package, packageStatus, host);
    }

    // -------------------------------------------------------------------------
    // The scan
    // -------------------------------------------------------------------------

    private sealed class Run(McpServerScanOptions options)
    {
        private readonly Stopwatch _clock = Stopwatch.StartNew();
        private readonly UserTreeReader _reader = new(options.VerifyOpenedFile, options.ResolveRootFinalPath);
        private readonly List<PackageIssue> _issues = [];
        private readonly List<ConfigState> _configs = [];
        private readonly List<McpServerRow> _servers = [];
        private int _serverCount;
        private bool _truncated;
        private string? _reason;

        public IReadOnlyList<PackageIssue> Issues => _issues;

        public InventoryMcpServers Execute(IEnumerable<UserProfileSource>? profiles, int unreadableProfiles)
        {
            var users = new List<Ctx>();
            var clientStatuses = McpClient.All.ToDictionary(c => c, _ => new List<string>());
            var stopped = false;

            if (profiles is null)
            {
                Issue("unreadable", "ProfileList");
                foreach (var c in McpClient.All) clientStatuses[c].Add(PackageCollectionStatus.Failed);
            }
            else
            {
                foreach (var source in profiles)
                {
                    if (stopped) break;
                    if (users.Count >= MaxUsers)
                    {
                        _truncated = true;
                        _reason ??= "user_limit";
                        break;
                    }
                    var user = UserTreeReader.CleanText(source.User, 255) ?? "<unprintable>";
                    var userId = UserTreeReader.CleanText(source.UserId, 255);
                    string root;
                    try { root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(source.ProfileRoot)); }
                    catch { root = source.ProfileRoot; }

                    var rootKind = UserTreeReader.KindOf(root);
                    // PAT-2040: a root is registered from a handle that must be the root itself; one
                    // swapped for a junction since KindOf, or reached through one, is refused like a link.
                    if (rootKind == FsKind.Dir && !_reader.AddRoot(root)) rootKind = FsKind.Symlink;
                    if (rootKind == FsKind.Absent) continue;
                    var ctx = new Ctx(user, userId);
                    users.Add(ctx);
                    if (rootKind != FsKind.Dir)
                    {
                        Issue(Code(rootKind), root);
                        foreach (var u in ctx.Units.Values) u.Problems++;
                        continue;
                    }
                    try
                    {
                        foreach (var (client, parts, file, layout, cap) in Configs)
                            ReadConfig(ctx, root, client, parts, file, layout, cap);
                    }
                    catch (StopException)
                    {
                        foreach (var u in ctx.Units.Values) u.Partial = true;
                        stopped = true;
                    }
                }
                if (unreadableProfiles > 0)
                {
                    Issue("profile_unreadable", "ProfileList");
                    foreach (var c in McpClient.All) clientStatuses[c].Add(PackageCollectionStatus.Failed);
                }
            }

            var userRows = new List<McpServerUserRow>();
            foreach (var ctx in users)
            {
                var statuses = McpClient.All.Select(c => ctx.Units[c].Status).ToList();
                for (var i = 0; i < McpClient.All.Length; i++) clientStatuses[McpClient.All[i]].Add(statuses[i]);
                userRows.Add(new McpServerUserRow
                {
                    User = ctx.User,
                    UserId = ctx.UserId,
                    CollectionStatus = Combine(statuses),
                    Clients = McpClient.All.Zip(statuses).ToDictionary(p => p.First, p => p.Second),
                });
            }

            var clients = new Dictionary<string, McpClientSummary>();
            foreach (var c in McpClient.All)
            {
                clients[c] = new McpClientSummary
                {
                    CollectionStatus = Combine(clientStatuses[c], stopped),
                    ConfigCount = _configs.Count(r => r.Client == c),
                    ServerCount = _servers.Count(s => s.Client == c),
                };
            }
            var status = Combine(clients.Values.Select(v => v.CollectionStatus).ToList(), _truncated);

            return new InventoryMcpServers
            {
                CollectionStatus = status,
                Truncated = _truncated,
                TruncationReason = _truncated ? _reason : null,
                Clients = clients,
                Totals = new McpServerTotals { ConfigCount = _configs.Count, ServerCount = _servers.Count },
                Users = userRows,
                Configs = _configs.Select(r => new McpConfigRow
                {
                    Client = r.Client,
                    User = r.Ctx.User,
                    UserId = r.Ctx.UserId,
                    Path = UserTreeReader.CleanPath(r.Path),
                    CollectionStatus = r.Status,
                    ServerCount = r.Count,
                }).ToList(),
                Issues = _issues,
                Servers = status == PackageCollectionStatus.Failed
                    ? null
                    : _servers
                        .OrderBy(s => s.Client, StringComparer.Ordinal)
                        .ThenBy(s => s.User ?? "", StringComparer.Ordinal)
                        .ThenBy(s => s.ConfigPath, StringComparer.Ordinal)
                        .ThenBy(s => s.Scope, StringComparer.Ordinal)
                        .ThenBy(s => s.Name ?? "", StringComparer.Ordinal)
                        .ToList(),
            };
        }

        private void Issue(string code, string path)
        {
            if (_issues.Count >= MaxIssues) return;
            _issues.Add(new PackageIssue { Code = code, Path = UserTreeReader.CleanPath(path) });
        }

        private static string Code(FsKind kind) => kind switch
        {
            FsKind.Symlink => "symlink_not_followed",
            FsKind.Other   => "not_regular",
            _              => "unreadable",
        };

        private void CheckTime()
        {
            if (_clock.Elapsed > options.TimeBudget || options.Cancellation.IsCancellationRequested)
            {
                _truncated = true;
                _reason ??= "time_limit";
                throw new StopException();
            }
        }

        private void ReadConfig(Ctx ctx, string home, string client, string[] parts, string file, string layout, int cap)
        {
            var unit = ctx.Units[client];
            CheckTime();
            var (k, where) = _reader.Walk(home, parts);
            if (k == FsKind.Absent) return;
            if (k != FsKind.Dir)
            {
                Issue(Code(k), where);
                if (k == FsKind.Symlink) unit.Partial = true;
                else unit.Problems++;
                return;
            }
            var path = Path.Combine(where, file);
            var fk = _reader.KindAt(path);
            if (fk == FsKind.Absent) return;
            if (fk != FsKind.File)
            {
                // A linked config (a dotfiles checkout) is recorded and not read through, and
                // not claimed as a config; anything else is a problem.
                Issue(Code(fk), path);
                if (fk == FsKind.Symlink) unit.Partial = true;
                else unit.Problems++;
                return;
            }
            var (status, data) = _reader.ReadFile(path, cap);
            if (status == "missing") return;
            unit.Locations++;
            var row = new ConfigState { Client = client, Ctx = ctx, Path = path };
            _configs.Add(row);
            if (status != "read" || data is null)
            {
                Issue("unreadable", path);
                unit.Problems++;
                return;
            }

            using var doc = ParseJsonc(data);
            var maps = doc is null ? null : ServerMaps(doc.RootElement, layout);
            if (maps is null)
            {
                Issue("unparseable", path);
                unit.Problems++;
                return;
            }
            var partial = maps.Value.Capped;
            if (partial) Issue("project_limit", path);
            try
            {
                foreach (var (scope, servers) in maps.Value.Maps)
                {
                    foreach (var (name, entry) in Entries(servers))
                    {
                        CheckTime();
                        if (_serverCount >= options.MaxServers)
                        {
                            _truncated = true;
                            _reason ??= "server_limit";
                            throw new FullException();
                        }
                        _serverCount++;
                        var codes = new List<string>();
                        var s = SummariseServer(name, entry, codes);
                        foreach (var code in codes) Issue(code, path);
                        if (codes.Contains("server_unparseable")) partial = true;
                        _servers.Add(new McpServerRow
                        {
                            Client = client,
                            User = ctx.User,
                            UserId = ctx.UserId,
                            ConfigPath = UserTreeReader.CleanPath(path),
                            Scope = scope,
                            Name = s.Name,
                            Transport = s.Transport,
                            TransportSource = s.TransportSource,
                            Executable = s.Executable,
                            Runner = s.Runner,
                            Package = s.Package,
                            PackageStatus = s.PackageStatus,
                            Host = s.Host,
                        });
                        row.Count++;
                    }
                }
            }
            catch (Exception ex) when (ex is FullException or StopException)
            {
                row.Status = PackageCollectionStatus.Partial;
                unit.Partial = true;
                unit.Ok++;
                if (ex is StopException) throw;
                return;
            }
            row.Status = partial ? PackageCollectionStatus.Partial : PackageCollectionStatus.Complete;
            unit.Ok++;
            if (partial) unit.Partial = true;
        }
    }
}
