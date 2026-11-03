using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using Patched.Shared.Contract;
using Patched.Shared.IdeExtensions;
using Patched.Shared.UserTrees;

namespace Patched.Shared.PackageManagers;

/// <summary>A machine-wide npm prefix: <paramref name="Anchor"/> is trusted, <paramref name="Parts"/> are checked.</summary>
internal sealed record SystemNpmPrefix(string Manager, string Anchor, string[] Parts);

/// <summary>Bounds and seams for <see cref="PackageManagerScanLogic.Scan"/>.</summary>
internal sealed class PackageManagerScanOptions
{
    /// <summary>Applies to each source separately.</summary>
    public int MaxPackagesPerSource { get; init; } = 5000;
    public TimeSpan TimeBudget { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Cancelled by the Service scanner when its hard timeout abandons the scan, so a scan
    /// stuck behind a slow read stops at its next budget check instead of running on (and
    /// touching files) after its result has been thrown away. Checked wherever the time budget is.
    /// </summary>
    public CancellationToken Cancellation { get; init; }

    /// <summary>Machine-wide Node installs: Program Files\nodejs (both bitnesses) by default.</summary>
    public IReadOnlyList<SystemNpmPrefix> SystemNpmPrefixes { get; init; } = DefaultSystemNpmPrefixes();

    /// <summary>
    /// Directories an all-users python.org install lives directly under (Program Files, Program
    /// Files (x86), the system drive root), for inferring a user site's interpreter.
    /// </summary>
    public IReadOnlyList<string> PythonInstallRoots { get; init; } = DefaultPythonInstallRoots();

    /// <summary>
    /// Checks an opened handle against the path the scan meant to open (link count, final
    /// path). Defaults to <see cref="WindowsFileIdentity.IsExpectedRegularFile"/> on Windows,
    /// and to nothing elsewhere, where the scan runs only under test.
    /// </summary>
    public Func<SafeFileHandle, string, bool>? VerifyOpenedFile { get; init; } =
        OperatingSystem.IsWindows() ? WindowsFileIdentity.IsExpectedRegularFile : null;

    /// <summary>Kernel-resolved final path of a trusted root; null falls back to its full path.</summary>
    public Func<string, string?>? ResolveRootFinalPath { get; init; } =
        OperatingSystem.IsWindows() ? WindowsFileIdentity.FinalPathOfDirectory : null;

    private static IReadOnlyList<SystemNpmPrefix> DefaultSystemNpmPrefixes()
    {
        if (!OperatingSystem.IsWindows()) return [];
        return ProgramFilesDirs().Select(d => new SystemNpmPrefix("system", d, ["nodejs"])).ToList();
    }

    private static IReadOnlyList<string> DefaultPythonInstallRoots()
    {
        if (!OperatingSystem.IsWindows()) return [];
        var roots = ProgramFilesDirs().ToList();
        var drive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        if (!string.IsNullOrEmpty(drive)) roots.Add(drive);
        return roots.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static IEnumerable<string> ProgramFilesDirs() =>
        new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        }
        .Where(d => !string.IsNullOrEmpty(d))
        .Distinct(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// PAT-2018: npm global, pip user-site and pipx packages for every local user profile, and
/// the npm globals of the machine-wide Node install, read from disk. The Windows twin of
/// macos/lib/package_managers.sh, producing the same <see cref="InventoryPackageManagers"/>
/// shape field for field. Lives in Shared (no Windows TFM) so its tests run on macOS as well
/// as Windows; the Service's PackageManagerScanner resolves the real profiles from HKLM
/// ProfileList and hands them here.
///
/// WHAT IS READ, AND ONLY THIS. Under each profile root:
///   npm_global  &lt;prefix&gt;\node_modules\&lt;name&gt;\package.json and
///               &lt;prefix&gt;\node_modules\@&lt;scope&gt;\&lt;name&gt;\package.json ("name" and
///               "version"), for each prefix:
///                 AppData\Roaming\npm                       (npm's default global prefix)
///                 AppData\Roaming\nvm\&lt;version&gt;, AppData\Local\nvm\&lt;version&gt; (nvm-windows)
///                 AppData\Roaming\fnm\node-versions\&lt;version&gt;\installation, and under .fnm
///                 AppData\Local\Volta\tools\image\node\&lt;version&gt; and
///                   ...\image\packages\&lt;name&gt; or ...\packages\@&lt;scope&gt;\&lt;name&gt;
///               and machine-wide, Program Files\nodejs.
///   pip_user    &lt;site-packages&gt;\*.dist-info\METADATA and *.egg-info (PKG-INFO, or the file
///               itself) in AppData\Roaming\Python\Python&lt;XY&gt;[-32|-arm64]\site-packages and
///               the Microsoft Store Python's
///               AppData\Local\Packages\PythonSoftwareFoundation.Python.&lt;X.Y&gt;_*\LocalCache\
///               local-packages\Python&lt;XY&gt;\site-packages.
///   pipx        every venv under pipx\venvs, .local\pipx\venvs and
///               AppData\Local\pipx\pipx\venvs: pyvenv.cfg and Lib\site-packages\*.dist-info.
/// Only the Name and Version headers of METADATA are used, and only its first 64 KiB is read.
///
/// READ ONLY, AND NOTHING IS EXECUTED: no package manager, no Node, no Python.
/// PackageManagerScanLogicTests carries a source guard that goes red if this file, the
/// shared reader or the Service scanner gains a process launch.
///
/// THE TREES ARE USER-OWNED AND THIS RUNS AS SYSTEM. Every read goes through
/// <see cref="UserTreeReader"/>: no reparse point is entered, every file is a single-link
/// regular file under a cap whose opened handle is checked against the path meant.
///
/// VERSION-MANAGER ALIASES ARE NEVER FOLLOWED, AND NEVER NEED TO BE. nvm-windows makes
/// Program Files\nodejs a link to the active version; fnm and volta keep alias and shim
/// directories. The scan lists the directory holding the real versions and reads each real
/// directory once. A machine-wide prefix that is a link is not entered: its target is read
/// from the link itself and, when it names a node_modules this run already read in full, it
/// is recorded as alias_not_followed and costs nothing; otherwise it is
/// symlink_not_followed and the source is partial.
///
/// ABSENCE REQUIRES AUTHORITY (PAT-1710): see <see cref="InventoryPackageManagers"/>.
/// </summary>
internal static class PackageManagerScanLogic
{
    private const int PackageJsonCap    = 1024 * 1024;
    private const long MetadataFileCap  = 64L * 1024 * 1024;
    private const int MetadataHeadCap   = 64 * 1024;
    private const int PyvenvCap         = 64 * 1024;
    private const int MaxUsers          = 500;
    private const int MaxIssues         = 50;

    private static readonly Regex NodeVersion = new(@"^v?\d+\.\d+\.\d+[0-9A-Za-z.+-]*$", RegexOptions.CultureInvariant);
    // An npm package name, or its @scope, as one directory name. Older packages may carry
    // capitals; nothing else outside npm's URL-safe set is accepted (PAT-2033).
    private static readonly Regex VoltaPackage = new(@"^[A-Za-z0-9~-][A-Za-z0-9._~-]{0,213}\z", RegexOptions.CultureInvariant);
    private static readonly Regex VoltaScope = new(@"^@[A-Za-z0-9~-][A-Za-z0-9._~-]{0,212}\z", RegexOptions.CultureInvariant);
    private static readonly Regex AppDataPython = new(@"^Python(\d)(\d+)(-32|-arm64)?$", RegexOptions.CultureInvariant);
    private static readonly Regex StorePython =
        new(@"^PythonSoftwareFoundation\.Python\.(\d+\.\d+)_[0-9a-z]+$", RegexOptions.CultureInvariant);
    private static readonly Regex Canon = new(@"[-_.]+", RegexOptions.CultureInvariant);

    private static readonly string[][] FnmBases = [["AppData", "Roaming", "fnm"], [".fnm"]];
    private static readonly string[][] NvmBases = [["AppData", "Roaming", "nvm"], ["AppData", "Local", "nvm"]];
    private static readonly string[][] PipxBases =
        [["pipx", "venvs"], [".local", "pipx", "venvs"], ["AppData", "Local", "pipx", "pipx", "venvs"]];
    private static readonly string[] Volta = ["AppData", "Local", "Volta", "tools", "image"];

    private sealed class StopException : Exception;
    private sealed class SourceFullException : Exception;

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

    private sealed class Ctx(string scope, string? user, string? userId)
    {
        public string Scope { get; } = scope;
        public string? User { get; } = user;
        public string? UserId { get; } = userId;
        public Dictionary<string, Unit> Units { get; } = PackageSource.All.ToDictionary(s => s, _ => new Unit());
    }

    private sealed class Loc
    {
        public required string Source;
        public required string Manager;
        public required Ctx Ctx;
        public required string Path;
        public string? RuntimeVersion;
        public List<string> Interpreters = [];
        public string Status = PackageCollectionStatus.Failed;
        public int Count;
        public bool Partial;
    }

    /// <summary>
    /// Scans every profile and the machine-wide prefixes. <paramref name="profiles"/> null
    /// means the profile list itself could not be read: the per-user half of every source is
    /// failed, never "no users". <paramref name="unreadableProfiles"/> counts registered
    /// profiles whose location could not be read; any makes every source partial at best.
    /// Never throws.
    /// </summary>
    public static InventoryPackageManagers Scan(
        IEnumerable<UserProfileSource>? profiles, PackageManagerScanOptions? options = null, int unreadableProfiles = 0)
    {
        var run = new Run(options ?? new PackageManagerScanOptions());
        try
        {
            return run.Execute(profiles, unreadableProfiles);
        }
        catch (Exception)
        {
            return new InventoryPackageManagers { CollectionStatus = PackageCollectionStatus.Failed, Issues = run.Issues };
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

    /// <summary>
    /// ("read", name, version) from the header section of METADATA or PKG-INFO: RFC 822
    /// style headers up to the first blank line, Name and Version taken the first time each
    /// appears; ("unparseable", ...) when either is missing.
    /// </summary>
    internal static (string Status, string? Name, string? Version) ParseMetadata(byte[] data)
    {
        var text = Encoding.UTF8.GetString(data);
        string? name = null, version = null;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Trim().Length == 0) break;
            if (line[0] is ' ' or '\t') continue;
            var colon = line.IndexOf(':');
            if (colon < 0) continue;
            var key = line[..colon].Trim().ToLowerInvariant();
            var value = line[(colon + 1)..];
            if (key == "name" && name is null) name = UserTreeReader.CleanText(value);
            else if (key == "version" && version is null) version = UserTreeReader.CleanText(value, 128);
        }
        return (name is null || version is null ? "unparseable" : "read", name, version);
    }

    private static string? Canonical(string? name) => name is null ? null : Canon.Replace(name, "-").ToLowerInvariant();

    private sealed class Run(PackageManagerScanOptions options)
    {
        private readonly Stopwatch _clock = Stopwatch.StartNew();
        private readonly UserTreeReader _reader = new(options.VerifyOpenedFile, options.ResolveRootFinalPath);
        private readonly List<PackageIssue> _issues = [];
        private readonly List<Loc> _locations = [];
        private readonly List<InventoryPackage> _packages = [];
        private readonly List<string> _readModules = [];
        private readonly Dictionary<string, int> _counts = PackageSource.All.ToDictionary(s => s, _ => 0);
        private readonly HashSet<string> _full = [];
        private bool _truncated;
        private string? _reason;

        public IReadOnlyList<PackageIssue> Issues => _issues;

        public InventoryPackageManagers Execute(IEnumerable<UserProfileSource>? profiles, int unreadableProfiles)
        {
            var users = new List<(Ctx Ctx, string User, string? UserId)>();
            var unitStatuses = PackageSource.All.ToDictionary(s => s, _ => new List<string>());
            var stopped = false;

            if (profiles is null)
            {
                Issue("unreadable", "ProfileList");
                foreach (var s in PackageSource.All) unitStatuses[s].Add(PackageCollectionStatus.Failed);
            }
            else
            {
                foreach (var source in profiles)
                {
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
                    var ctx = new Ctx("user", user, userId);
                    users.Add((ctx, user, userId));
                    if (rootKind != FsKind.Dir)
                    {
                        Issue(Code(rootKind), root);
                        foreach (var u in ctx.Units.Values) u.Problems++;
                        continue;
                    }
                    try
                    {
                        NpmForProfile(ctx, root);
                        PipForProfile(ctx, root);
                        PipxForProfile(ctx, root);
                    }
                    catch (StopException)
                    {
                        foreach (var u in ctx.Units.Values) u.Partial = true;
                        stopped = true;
                        break;
                    }
                }
                if (unreadableProfiles > 0)
                {
                    Issue("profile_unreadable", "ProfileList");
                    foreach (var s in PackageSource.All) unitStatuses[s].Add(PackageCollectionStatus.Failed);
                }
            }

            var system = new Ctx("system", null, null);
            if (!stopped)
            {
                try
                {
                    NpmSystem(system);
                }
                catch (StopException)
                {
                    system.Units[PackageSource.NpmGlobal].Partial = true;
                    stopped = true;
                }
            }

            var userRows = new List<PackageUserRow>();
            foreach (var (ctx, user, userId) in users)
            {
                var statuses = PackageSource.All.Select(s => ctx.Units[s].Status).ToList();
                for (var i = 0; i < PackageSource.All.Length; i++) unitStatuses[PackageSource.All[i]].Add(statuses[i]);
                userRows.Add(new PackageUserRow
                {
                    User = user,
                    UserId = userId,
                    CollectionStatus = Combine(statuses),
                    Sources = PackageSource.All.Zip(statuses).ToDictionary(p => p.First, p => p.Second),
                });
            }
            unitStatuses[PackageSource.NpmGlobal].Add(system.Units[PackageSource.NpmGlobal].Status);

            var sources = new Dictionary<string, PackageSourceSummary>();
            foreach (var s in PackageSource.All)
            {
                var truncated = stopped || _full.Contains(s);
                sources[s] = new PackageSourceSummary
                {
                    CollectionStatus = Combine(unitStatuses[s], truncated),
                    Truncated = truncated,
                    PackageCount = _packages.Count(p => p.Source == s),
                    LocationCount = _locations.Count(l => l.Source == s),
                };
            }
            var status = Combine(sources.Values.Select(v => v.CollectionStatus).ToList(), _truncated);

            return new InventoryPackageManagers
            {
                CollectionStatus = status,
                Truncated = _truncated,
                TruncationReason = _truncated ? _reason : null,
                Sources = sources,
                Users = userRows,
                Locations = _locations.Select(l => new PackageLocationRow
                {
                    Source = l.Source,
                    Manager = l.Manager,
                    Scope = l.Ctx.Scope,
                    User = l.Ctx.User,
                    UserId = l.Ctx.UserId,
                    Path = UserTreeReader.CleanPath(l.Path),
                    RuntimeVersion = l.RuntimeVersion,
                    Interpreters = l.Interpreters,
                    CollectionStatus = l.Status,
                    PackageCount = l.Count,
                }).ToList(),
                Issues = _issues,
                Packages = status == PackageCollectionStatus.Failed
                    ? null
                    : _packages
                        .OrderBy(p => p.Source, StringComparer.Ordinal)
                        .ThenBy(p => p.User ?? "", StringComparer.Ordinal)
                        .ThenBy(p => p.Prefix ?? "", StringComparer.Ordinal)
                        .ThenBy(p => p.Name ?? "", StringComparer.Ordinal)
                        .ThenBy(p => p.Directory ?? "", StringComparer.Ordinal)
                        .ToList(),
            };
        }

        // ---------------------------------------------------------------------
        // Primitives
        // ---------------------------------------------------------------------

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

        private void RefuseUnit(Unit unit, FsKind kind, string where)
        {
            unit.Problems++;
            Issue(Code(kind), where);
        }

        private void CheckTime()
        {
            if (_clock.Elapsed > options.TimeBudget || options.Cancellation.IsCancellationRequested)
            {
                _truncated = true;
                _reason ??= "time_limit";
                throw new StopException();
            }
        }

        private void TakeSlot(string source)
        {
            if (_counts[source] >= options.MaxPackagesPerSource)
            {
                _full.Add(source);
                _truncated = true;
                _reason ??= "package_limit";
                throw new SourceFullException();
            }
            _counts[source]++;
        }

        private Loc NewLocation(Ctx ctx, string source, string manager, string path, string? runtimeVersion,
            IEnumerable<string>? interpreters = null)
        {
            var loc = new Loc
            {
                Source = source,
                Manager = manager,
                Ctx = ctx,
                Path = path,
                RuntimeVersion = runtimeVersion is null ? null : UserTreeReader.CleanText(runtimeVersion, 64),
                Interpreters = (interpreters ?? []).Select(UserTreeReader.CleanPath).ToList(),
            };
            _locations.Add(loc);
            ctx.Units[source].Locations++;
            return loc;
        }

        private static void FinishLocation(Loc loc, bool failed = false)
        {
            var unit = loc.Ctx.Units[loc.Source];
            loc.Status = failed
                ? (loc.Count == 0 ? PackageCollectionStatus.Failed : PackageCollectionStatus.Partial)
                : (loc.Partial ? PackageCollectionStatus.Partial : PackageCollectionStatus.Complete);
            if (loc.Status == PackageCollectionStatus.Failed)
            {
                unit.Problems++;
            }
            else
            {
                unit.Ok++;
                if (loc.Status == PackageCollectionStatus.Partial) unit.Partial = true;
            }
        }

        private InventoryPackage Row(Loc loc) => new()
        {
            Source = loc.Source,
            Manager = loc.Manager,
            Scope = loc.Ctx.Scope,
            User = loc.Ctx.User,
            UserId = loc.Ctx.UserId,
            Prefix = UserTreeReader.CleanPath(loc.Path),
            RuntimeVersion = loc.RuntimeVersion,
            Interpreter = loc.Interpreters.Count == 1 ? loc.Interpreters[0] : null,
        };

        /// <summary>
        /// Real directories directly under anchor\parts whose names match. A reparse point where
        /// a real directory should be is recorded, never entered, and makes the unit partial.
        /// </summary>
        private List<(string Name, string Path)> RealDirs(Ctx ctx, string source, string anchor, string[] parts, Regex? pattern)
        {
            var unit = ctx.Units[source];
            var (k, dir) = _reader.Walk(anchor, parts);
            if (k == FsKind.Absent) return [];
            if (k != FsKind.Dir)
            {
                RefuseUnit(unit, k, dir);
                return [];
            }
            List<(string Name, FsKind Kind)> entries;
            try
            {
                entries = _reader.ListDir(dir);
            }
            catch (UnlistableDirectoryException)
            {
                RefuseUnit(unit, FsKind.Error, dir);
                return [];
            }
            var found = new List<(string, string)>();
            foreach (var (name, kind) in entries)
            {
                if (pattern is not null && !pattern.IsMatch(name)) continue;
                if (kind != FsKind.Dir)
                {
                    if (kind != FsKind.File)
                    {
                        unit.Partial = true;
                        Issue(Code(kind), Path.Combine(dir, name));
                    }
                    continue;
                }
                found.Add((name, Path.Combine(dir, name)));
            }
            return found;
        }

        // ---------------------------------------------------------------------
        // npm
        // ---------------------------------------------------------------------

        private void NpmPackage(Loc loc, string modules, string rel)
        {
            var directory = UserTreeReader.CleanText(rel, 255);
            if (directory is null)
            {
                loc.Partial = true;
                Issue("name_unsafe", modules);
                return;
            }
            TakeSlot(PackageSource.NpmGlobal);
            var where = Path.Combine(modules, rel.Replace('/', Path.DirectorySeparatorChar));
            var (status, data) = _reader.ReadFile(Path.Combine(where, "package.json"), PackageJsonCap);
            string? name = null, version = null;
            if (status == "read")
            {
                try
                {
                    var bytes = data!;
                    var span = bytes.AsMemory();
                    if (span.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) span = span[3..];
                    using var doc = JsonDocument.Parse(span, new JsonDocumentOptions { MaxDepth = 256 });
                    if (doc.RootElement.ValueKind != JsonValueKind.Object)
                    {
                        status = "unparseable";
                    }
                    else
                    {
                        name = Str(doc.RootElement, "name");
                        version = Str(doc.RootElement, "version");
                    }
                }
                catch (Exception)
                {
                    status = "unparseable";
                }
            }
            if (status == "read")
            {
                if (name is null || version is null)
                {
                    loc.Partial = true;
                    Issue("manifest_incomplete", where);
                }
            }
            else
            {
                // Still listed: present, just not identified.
                loc.Partial = true;
                Issue("manifest_" + status, where);
            }
            _packages.Add(Row(loc) with { Name = name, Version = version, Directory = directory, MetadataStatus = status });
            loc.Count++;
        }

        private static string? Str(JsonElement obj, string name) =>
            obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? UserTreeReader.CleanText(v.GetString()) : null;

        private void NpmLocation(Ctx ctx, string manager, string prefix, string? runtimeVersion)
        {
            if (_full.Contains(PackageSource.NpmGlobal))
            {
                ctx.Units[PackageSource.NpmGlobal].Partial = true;
                return;
            }
            var loc = NewLocation(ctx, PackageSource.NpmGlobal, manager, prefix, runtimeVersion);
            var (k, modules) = _reader.Walk(prefix, "node_modules");
            if (k == FsKind.Absent)
            {
                FinishLocation(loc);
                return;
            }
            if (k != FsKind.Dir)
            {
                Issue(Code(k), modules);
                FinishLocation(loc, failed: true);
                return;
            }
            List<(string Name, FsKind Kind)> entries;
            try
            {
                entries = _reader.ListDir(modules);
            }
            catch (UnlistableDirectoryException)
            {
                Issue("unreadable", modules);
                FinishLocation(loc, failed: true);
                return;
            }
            try
            {
                foreach (var (name, kind) in entries)
                {
                    CheckTime();
                    var where = Path.Combine(modules, name);
                    if (kind == FsKind.File) continue;
                    if (kind != FsKind.Dir)
                    {
                        // npm link leaves a link here; it is recorded, never entered.
                        loc.Partial = true;
                        Issue(Code(kind), where);
                        continue;
                    }
                    if (!name.StartsWith('@'))
                    {
                        NpmPackage(loc, modules, name);
                        continue;
                    }
                    List<(string Name, FsKind Kind)> scoped;
                    try
                    {
                        scoped = _reader.ListDir(where);
                    }
                    catch (UnlistableDirectoryException)
                    {
                        loc.Partial = true;
                        Issue("unreadable", where);
                        continue;
                    }
                    foreach (var (child, childKind) in scoped)
                    {
                        CheckTime();
                        if (childKind == FsKind.File) continue;
                        if (childKind != FsKind.Dir)
                        {
                            loc.Partial = true;
                            Issue(Code(childKind), Path.Combine(where, child));
                            continue;
                        }
                        NpmPackage(loc, modules, name + "/" + child);
                    }
                }
            }
            catch (SourceFullException)
            {
                loc.Partial = true;
            }
            catch (StopException)
            {
                loc.Partial = true;
                FinishLocation(loc);
                throw;
            }
            FinishLocation(loc);
            if (!loc.Partial) _readModules.Add(Path.TrimEndingDirectorySeparator(modules));
        }

        private void NpmForProfile(Ctx ctx, string home)
        {
            var src = PackageSource.NpmGlobal;
            var (appKind, appNpm) = _reader.Walk(home, "AppData", "Roaming", "npm");
            if (appKind == FsKind.Dir) NpmLocation(ctx, "appdata", appNpm, null);
            else if (appKind != FsKind.Absent) RefuseUnit(ctx.Units[src], appKind, appNpm);

            foreach (var bases in NvmBases)
                foreach (var (name, path) in RealDirs(ctx, src, home, bases, NodeVersion))
                    NpmLocation(ctx, "nvm", path, name.TrimStart('v'));
            foreach (var bases in FnmBases)
            {
                foreach (var (name, path) in RealDirs(ctx, src, home, [.. bases, "node-versions"], NodeVersion))
                {
                    var (k, inst) = _reader.Walk(path, "installation");
                    if (k == FsKind.Absent) continue;
                    if (k != FsKind.Dir)
                    {
                        RefuseUnit(ctx.Units[src], k, inst);
                        continue;
                    }
                    NpmLocation(ctx, "fnm", inst, name.TrimStart('v'));
                }
            }
            foreach (var (name, path) in RealDirs(ctx, src, home, [.. Volta, "node"], NodeVersion))
                NpmLocation(ctx, "volta", path, name.TrimStart('v'));
            // A volta-installed global package gets its own image directory, named for the
            // package (@scope\name for a scoped one). A directory whose name no npm package
            // could have is recorded and not entered (PAT-2033).
            var unit = ctx.Units[src];
            foreach (var (name, path) in RealDirs(ctx, src, home, [.. Volta, "packages"], null))
            {
                if (!(name.StartsWith('@') ? VoltaScope : VoltaPackage).IsMatch(name))
                {
                    unit.Partial = true;
                    Issue("name_unsafe", path);
                    continue;
                }
                if (!name.StartsWith('@'))
                {
                    NpmLocation(ctx, "volta", path, null);
                    continue;
                }
                foreach (var (child, childPath) in RealDirs(ctx, src, path, [], null))
                {
                    if (!VoltaPackage.IsMatch(child))
                    {
                        unit.Partial = true;
                        Issue("name_unsafe", childPath);
                        continue;
                    }
                    NpmLocation(ctx, "volta", childPath, null);
                }
            }
        }

        private void NpmSystem(Ctx ctx)
        {
            foreach (var prefix in options.SystemNpmPrefixes)
            {
                if (UserTreeReader.KindOf(prefix.Anchor) != FsKind.Dir) continue;
                if (!_reader.AddRoot(prefix.Anchor))
                {
                    // PAT-2040: swapped for, or reached through, a junction since KindOf.
                    ctx.Units[PackageSource.NpmGlobal].Partial = true;
                    Issue(Code(FsKind.Symlink), prefix.Anchor);
                    continue;
                }
                string[] full = [.. prefix.Parts, "node_modules"];
                var (k, where) = _reader.Walk(prefix.Anchor, full);
                if (k == FsKind.Absent) continue;
                if (k == FsKind.Dir)
                {
                    NpmLocation(ctx, prefix.Manager, Path.Combine([prefix.Anchor, .. prefix.Parts]), null);
                    continue;
                }
                if (k == FsKind.Symlink && _reader.LinkTarget(where) is { } target)
                {
                    // Which walked component is the link, and what is left below it.
                    var linkIndex = -1;
                    var p = prefix.Anchor;
                    for (var i = 0; i < full.Length && linkIndex < 0; i++)
                    {
                        p = Path.Combine(p, full[i]);
                        if (string.Equals(p, where, StringComparison.Ordinal)) linkIndex = i;
                    }
                    var covered = linkIndex < 0
                        ? null
                        : Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.Combine([target, .. full[(linkIndex + 1)..]])));
                    if (covered is not null && _readModules.Contains(covered, StringComparer.OrdinalIgnoreCase))
                    {
                        Issue("alias_not_followed", where);
                        continue;
                    }
                }
                RefuseUnit(ctx.Units[PackageSource.NpmGlobal], k, where);
            }
        }

        // ---------------------------------------------------------------------
        // pip and pipx
        // ---------------------------------------------------------------------

        private void DistRow(Loc loc, string site, string name, FsKind kind, string? pipxApp)
        {
            var where = Path.Combine(site, name);
            string meta;
            if (name.EndsWith(".dist-info", StringComparison.Ordinal))
            {
                if (kind != FsKind.Dir)
                {
                    loc.Partial = true;
                    Issue(Code(kind), where);
                    return;
                }
                meta = Path.Combine(where, "METADATA");
            }
            else if (name.EndsWith(".egg-info", StringComparison.Ordinal))
            {
                if (kind == FsKind.Dir) meta = Path.Combine(where, "PKG-INFO");
                else if (kind == FsKind.File) meta = where;
                else
                {
                    loc.Partial = true;
                    Issue(Code(kind), where);
                    return;
                }
            }
            else
            {
                return;
            }
            var directory = UserTreeReader.CleanText(name, 255);
            if (directory is null)
            {
                loc.Partial = true;
                Issue("name_unsafe", site);
                return;
            }
            TakeSlot(loc.Source);
            var (status, data) = _reader.ReadHead(meta, MetadataFileCap, MetadataHeadCap);
            string? pkgName = null, version = null;
            if (status == "read") (status, pkgName, version) = ParseMetadata(data!);
            if (status != "read")
            {
                loc.Partial = true;
                Issue("metadata_" + status, where);
            }
            _packages.Add(Row(loc) with
            {
                Name = pkgName,
                Version = version,
                Directory = directory,
                MetadataStatus = status,
                PipxApp = pipxApp,
                PipxMain = loc.Source == PackageSource.Pipx && pkgName is not null
                    ? Canonical(pkgName) == Canonical(pipxApp)
                    : null,
            });
            loc.Count++;
        }

        /// <summary>Every dist in one site-packages. Throws UnlistableDirectoryException when unlistable.</summary>
        private void ReadSite(Loc loc, string site, string? pipxApp)
        {
            foreach (var (name, kind) in _reader.ListDir(site))
            {
                CheckTime();
                DistRow(loc, site, name, kind, pipxApp);
            }
        }

        private void SiteLocation(Ctx ctx, string manager, string site, string runtimeVersion, List<string> interpreters)
        {
            var src = PackageSource.PipUser;
            if (_full.Contains(src))
            {
                ctx.Units[src].Partial = true;
                return;
            }
            var loc = NewLocation(ctx, src, manager, site, runtimeVersion, interpreters);
            try
            {
                ReadSite(loc, site, null);
            }
            catch (UnlistableDirectoryException)
            {
                Issue("unreadable", site);
                FinishLocation(loc, failed: true);
                return;
            }
            catch (SourceFullException)
            {
                loc.Partial = true;
            }
            catch (StopException)
            {
                loc.Partial = true;
                FinishLocation(loc);
                throw;
            }
            FinishLocation(loc);
        }

        private bool Present(string path) => _reader.KindAt(path) is FsKind.File or FsKind.Symlink;

        private List<string> AppDataInterpreters(string home, string dirName, string xy, bool plain)
        {
            var found = new List<string>();
            var perUser = Path.Combine(home, "AppData", "Local", "Programs", "Python", dirName, "python.exe");
            if (Present(perUser)) found.Add(perUser);
            foreach (var root in options.PythonInstallRoots)
            {
                var candidate = Path.Combine(root, dirName, "python.exe");
                if (Present(candidate)) found.Add(candidate);
            }
            if (plain)
            {
                var (k, versions) = _reader.Walk(home, ".pyenv", "pyenv-win", "versions");
                if (k == FsKind.Dir)
                {
                    try
                    {
                        var pattern = new Regex("^" + Regex.Escape(xy) + @"\.\d+$", RegexOptions.CultureInvariant);
                        foreach (var (name, kind) in _reader.ListDir(versions))
                        {
                            if (kind != FsKind.Dir || !pattern.IsMatch(name)) continue;
                            var candidate = Path.Combine(versions, name, "python.exe");
                            if (Present(candidate)) found.Add(candidate);
                        }
                    }
                    catch (UnlistableDirectoryException)
                    {
                        // An unlistable pyenv tree only means fewer interpreter candidates.
                    }
                }
            }
            return found;
        }

        private void PipForProfile(Ctx ctx, string home)
        {
            var src = PackageSource.PipUser;
            foreach (var (name, path) in RealDirs(ctx, src, home, ["AppData", "Roaming", "Python"], AppDataPython))
            {
                var m = AppDataPython.Match(name);
                var xy = $"{m.Groups[1].Value}.{m.Groups[2].Value}";
                var (k, site) = _reader.Walk(path, "site-packages");
                if (k == FsKind.Absent) continue;
                if (k != FsKind.Dir)
                {
                    RefuseUnit(ctx.Units[src], k, site);
                    continue;
                }
                SiteLocation(ctx, "appdata_python", site, xy,
                    AppDataInterpreters(home, name, xy, plain: !m.Groups[3].Success));
            }
            foreach (var (name, path) in RealDirs(ctx, src, home, ["AppData", "Local", "Packages"], StorePython))
            {
                var xy = StorePython.Match(name).Groups[1].Value;
                foreach (var (_, pyDir) in RealDirs(ctx, src, path, ["LocalCache", "local-packages"],
                             new Regex("^Python" + xy.Replace(".", "") + "$", RegexOptions.CultureInvariant)))
                {
                    var (k, site) = _reader.Walk(pyDir, "site-packages");
                    if (k == FsKind.Absent) continue;
                    if (k != FsKind.Dir)
                    {
                        RefuseUnit(ctx.Units[src], k, site);
                        continue;
                    }
                    SiteLocation(ctx, "microsoft_store", site, xy, []);
                }
            }
        }

        private static Dictionary<string, string> ParsePyvenv(byte[] data)
        {
            var cfg = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var raw in Encoding.UTF8.GetString(data).Split('\n'))
            {
                var eq = raw.IndexOf('=');
                if (eq < 0) continue;
                cfg[raw[..eq].Trim().ToLowerInvariant()] = raw[(eq + 1)..].Trim();
            }
            return cfg;
        }

        private void PipxVenv(Ctx ctx, string app, string venv)
        {
            var src = PackageSource.Pipx;
            if (_full.Contains(src))
            {
                ctx.Units[src].Partial = true;
                return;
            }
            var (status, data) = _reader.ReadFile(Path.Combine(venv, "pyvenv.cfg"), PyvenvCap);
            var cfg = status == "read" ? ParsePyvenv(data!) : new Dictionary<string, string>();
            var interpreter = UserTreeReader.CleanText(cfg.GetValueOrDefault("executable"), 1024);
            var version = cfg.GetValueOrDefault("version") ?? cfg.GetValueOrDefault("version_info");
            var loc = NewLocation(ctx, src, "pipx", venv, version, interpreter is null ? [] : [interpreter]);
            if (status != "read")
            {
                loc.Partial = true;
                Issue("pyvenv_cfg_" + status, venv);
            }
            var pipxApp = UserTreeReader.CleanText(app, 255);
            var (k, site) = _reader.Walk(venv, "Lib", "site-packages");
            if (k != FsKind.Dir)
            {
                Issue(k == FsKind.Absent ? "site_packages_missing" : Code(k), site);
                FinishLocation(loc, failed: true);
                return;
            }
            try
            {
                ReadSite(loc, site, pipxApp);
            }
            catch (UnlistableDirectoryException)
            {
                Issue("unreadable", site);
                FinishLocation(loc, failed: true);
                return;
            }
            catch (SourceFullException)
            {
                loc.Partial = true;
            }
            catch (StopException)
            {
                loc.Partial = true;
                FinishLocation(loc);
                throw;
            }
            FinishLocation(loc);
        }

        private void PipxForProfile(Ctx ctx, string home)
        {
            foreach (var bases in PipxBases)
                foreach (var (name, path) in RealDirs(ctx, PackageSource.Pipx, home, bases, null))
                    PipxVenv(ctx, name, path);
        }
    }
}
