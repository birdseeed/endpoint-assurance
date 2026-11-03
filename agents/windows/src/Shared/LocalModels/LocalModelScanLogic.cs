using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using Patched.Shared.Contract;
using Patched.Shared.IdeExtensions;
using Patched.Shared.UserTrees;

namespace Patched.Shared.LocalModels;

/// <summary>Bounds and seams for <see cref="LocalModelScanLogic.Scan"/>.</summary>
internal sealed class LocalModelScanOptions
{
    public int MaxModels { get; init; } = 5000;
    public TimeSpan TimeBudget { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Cancelled by the Service scanner when its hard timeout abandons the scan, so a scan
    /// stuck behind a slow read stops at its next budget check instead of running on (and
    /// touching files) after its result has been thrown away. Checked wherever the time budget is.
    /// </summary>
    public CancellationToken Cancellation { get; init; }

    /// <summary>Machine-wide install roots: Program Files (both bitnesses) by default.</summary>
    public IReadOnlyList<string> ProgramFilesRoots { get; init; } = DefaultProgramFiles();

    /// <summary>Scoop's global root (%ProgramData%\scoop) by default; null to skip.</summary>
    public string? ScoopGlobalRoot { get; init; } = DefaultScoopGlobal();

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

    /// <summary>
    /// PAT-2052, for tests only: lists a directory given (path, expected final path). Null,
    /// the default, is the reader's own verified-handle lister
    /// (<see cref="UserTreeReader.DefaultLister"/>). A test wraps that lister to count
    /// listings or to swap a directory the moment it has been listed.
    /// </summary>
    internal Func<string, string, List<(string Name, FsKind Kind, long Length)>?>? ListOpenedDirectory { get; init; }

    private static IReadOnlyList<string> DefaultProgramFiles()
    {
        if (!OperatingSystem.IsWindows()) return [];
        return new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            }
            .Where(d => !string.IsNullOrEmpty(d))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string? DefaultScoopGlobal()
    {
        if (!OperatingSystem.IsWindows()) return null;
        var data = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return string.IsNullOrEmpty(data) ? null : Path.Combine(data, "scoop");
    }
}

/// <summary>
/// PAT-2019: local model runtimes (Ollama, LM Studio, llama.cpp) and their model stores, for
/// the machine and every local user profile, read from disk. The Windows twin of
/// macos/lib/local_models.sh, producing the same <see cref="InventoryLocalModels"/> shape
/// field for field. Lives in Shared (no Windows TFM) so its tests run on macOS as well as
/// Windows; the Service's LocalModelScanner resolves the real profiles from HKLM ProfileList.
///
/// WHAT IS READ, AND ONLY THIS.
///   Runtimes (presence and version):
///     Program Files\Ollama and AppData\Local\Programs\Ollama     ollama app.exe, ollama.exe
///     Program Files\LM Studio and AppData\Local\Programs\LM Studio   LM Studio.exe
///     WinGet\Packages\ggml.llamacpp_* (Program Files, and per user under
///       AppData\Local\Microsoft)                                 llama-server.exe, llama-cli.exe
///     scoop\apps\ollama\&lt;version&gt; and scoop\apps\llama.cpp\&lt;version&gt;
///       (per user, and %ProgramData%\scoop)                      the directory name is the version
///     A version is read from the executable's VS_VERSIONINFO resource as bytes
///     (<see cref="PeVersionReader"/>); the executable is never loaded or run. An executable
///     with no version resource is recorded with version_source none.
///   Model stores (names and sizes only), per profile:
///     Ollama     .ollama\models\manifests\&lt;registry&gt;\&lt;namespace&gt;\&lt;model&gt;\&lt;tag&gt;, read as
///                JSON for digests and sizes; each blob (.ollama\models\blobs\sha256-&lt;hex&gt;)
///                is only stat'd. A digest that is not sha256:&lt;64 hex&gt; is refused before it
///                becomes a path.
///     LM Studio  .lmstudio\models\&lt;publisher&gt;\&lt;repo&gt; and .cache\lm-studio\models\...: file
///                names and sizes from the directory listing. No model file is opened.
///   Nothing else under .ollama or .lmstudio is looked at: not history, logs, keys,
///   conversations or settings.
///
/// NOTHING IS EXECUTED AND NOTHING TOUCHES THE NETWORK. No runtime is started, no local HTTP
/// API is called. LocalModelScanLogicTests carries a source guard over this file, the shared
/// reader, the PE reader and the Service scanner that goes red on a process launch, a network
/// client or a loopback address.
///
/// THE TREES ARE USER-OWNED AND THIS RUNS AS SYSTEM. Every read goes through
/// <see cref="UserTreeReader"/>: no reparse point is entered (a model store junctioned to
/// another disk is recorded as symlink_not_followed and the runtime is partial), every file
/// opened is a single-link regular file under a cap whose handle is checked against the path
/// meant, and sizes come from directory entries, never from opening the file.
///
/// ABSENCE REQUIRES AUTHORITY (PAT-1710): see <see cref="InventoryLocalModels"/>.
/// </summary>
internal static class LocalModelScanLogic
{
    private const int ManifestCap = 1024 * 1024;
    private const long ExecutableCap = 1024L * 1024 * 1024;
    private const int MaxLayers = 1000;
    private const int MaxUsers = 500;
    private const int MaxIssues = 50;
    private const string DefaultRegistry = "registry.ollama.ai";

    private static readonly Regex Digest = new(@"^sha256:([0-9a-f]{64})$", RegexOptions.CultureInvariant);
    private static readonly Regex WinGetLlamaCpp = new(@"^ggml\.llamacpp_", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    private static readonly string[] WeightExtensions = [".safetensors", ".bin", ".npz", ".onnx", ".pt", ".pth"];

    private static readonly (string Runtime, string[] Dir, string[] Exes)[] AppDirs =
    [
        (LocalModelRuntime.Ollama, ["Ollama"], ["ollama app.exe", "ollama.exe"]),
        (LocalModelRuntime.LmStudio, ["LM Studio"], ["LM Studio.exe"]),
    ];
    private static readonly string[] LlamaCppExes = ["llama-server.exe", "llama-cli.exe"];
    private static readonly (string Runtime, string App)[] ScoopApps =
        [(LocalModelRuntime.Ollama, "ollama"), (LocalModelRuntime.LlamaCpp, "llama.cpp")];
    private static readonly string[] OllamaStoreParts = [".ollama", "models"];
    private static readonly string[][] LmStudioStoreParts = [[".lmstudio", "models"], [".cache", "lm-studio", "models"]];

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

    private sealed class Ctx(string scope, string? user, string? userId)
    {
        public string Scope { get; } = scope;
        public string? User { get; } = user;
        public string? UserId { get; } = userId;
        public Dictionary<string, Unit> Units { get; } = LocalModelRuntime.All.ToDictionary(r => r, _ => new Unit());
    }

    private sealed class Store
    {
        public required string Runtime;
        public required Ctx Ctx;
        public required string Path;
        public int Count;
        public long Bytes;
        public bool Partial;
        public bool Failed;
        public string Status = PackageCollectionStatus.Failed;
    }

    /// <summary>
    /// Scans the machine and every profile. <paramref name="profiles"/> null means the profile
    /// list itself could not be read: the per-user half of every runtime is failed, never "no
    /// users". <paramref name="unreadableProfiles"/> counts registered profiles whose location
    /// could not be read. Never throws.
    /// </summary>
    public static InventoryLocalModels Scan(
        IEnumerable<UserProfileSource>? profiles, LocalModelScanOptions? options = null, int unreadableProfiles = 0)
    {
        var run = new Run(options ?? new LocalModelScanOptions());
        try
        {
            return run.Execute(profiles, unreadableProfiles);
        }
        catch (Exception)
        {
            return new InventoryLocalModels { CollectionStatus = PackageCollectionStatus.Failed, Issues = run.Issues };
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
    /// ("read", [(hex digest, size)]) for the config and every layer of an Ollama manifest, or
    /// ("unparseable", null). Nothing but digest and size is kept.
    /// </summary>
    internal static (string Status, List<(string Digest, long Size)>? Layers) ParseManifest(byte[] data)
    {
        try
        {
            using var doc = JsonDocument.Parse(data, new JsonDocumentOptions { MaxDepth = 64 });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("layers", out var layers)
                || layers.ValueKind != JsonValueKind.Array
                || layers.GetArrayLength() > MaxLayers)
                return ("unparseable", null);
            var items = layers.EnumerateArray().ToList();
            if (root.TryGetProperty("config", out var config) && config.ValueKind != JsonValueKind.Null) items.Add(config);
            var result = new List<(string, long)>();
            foreach (var item in items)
            {
                if (item.ValueKind != JsonValueKind.Object
                    || !item.TryGetProperty("digest", out var digest) || digest.ValueKind != JsonValueKind.String
                    || !item.TryGetProperty("size", out var size) || size.ValueKind != JsonValueKind.Number
                    || !size.TryGetInt64(out var bytes) || bytes < 0)
                    return ("unparseable", null);
                var m = Digest.Match(digest.GetString()!);
                if (!m.Success) return ("unparseable", null);
                result.Add((m.Groups[1].Value, bytes));
            }
            return ("read", result);
        }
        catch (Exception)
        {
            return ("unparseable", null);
        }
    }

    internal static string? OllamaName(string registry, string ns, string model) =>
        registry == DefaultRegistry && ns == "library" ? UserTreeReader.CleanText(model, 255)
        : registry == DefaultRegistry ? UserTreeReader.CleanText(ns + "/" + model)
        : UserTreeReader.CleanText(registry + "/" + ns + "/" + model);

    private sealed class Run(LocalModelScanOptions options)
    {
        private readonly Stopwatch _clock = Stopwatch.StartNew();
        private readonly UserTreeReader _reader = new(options.VerifyOpenedFile, options.ResolveRootFinalPath, options.ListOpenedDirectory);
        private readonly List<PackageIssue> _issues = [];
        private readonly List<LocalRuntimeInstallation> _installations = [];
        private readonly List<Store> _stores = [];
        private readonly List<InventoryLocalModel> _models = [];
        private int _modelCount;
        private bool _truncated;
        private string? _reason;

        public IReadOnlyList<PackageIssue> Issues => _issues;

        public InventoryLocalModels Execute(IEnumerable<UserProfileSource>? profiles, int unreadableProfiles)
        {
            var users = new List<(Ctx Ctx, string User, string? UserId)>();
            var runtimeStatuses = LocalModelRuntime.All.ToDictionary(r => r, _ => new List<string>());
            var stopped = false;

            var system = new Ctx("system", null, null);
            try
            {
                foreach (var root in options.ProgramFilesRoots)
                {
                    if (UserTreeReader.KindOf(root) != FsKind.Dir) continue;
                    if (!_reader.AddRoot(root))
                    {
                        // PAT-2040: swapped for, or reached through, a junction since KindOf.
                        Issue(Code(FsKind.Symlink), root);
                        foreach (var unit in system.Units.Values) unit.Partial = true;
                        continue;
                    }
                    foreach (var (runtime, dir, exes) in AppDirs)
                        AppDir(system, runtime, "program_files", root, dir, exes);
                    WinGetPackages(system, root, ["WinGet", "Packages"]);
                }
                if (options.ScoopGlobalRoot is { } scoop
                    && UserTreeReader.KindOf(scoop) is var scoopKind and not (FsKind.Absent or FsKind.File))
                {
                    // PAT-2040: any user can create %ProgramData%\scoop, so it may be swapped for
                    // a junction into another profile after KindOf; AddRoot refuses that.
                    // PAT-2050: one that is already a junction (or unreadable) is refused the
                    // same way, never skipped as if there were no global scoop.
                    if (scoopKind == FsKind.Dir && _reader.AddRoot(scoop)) Scoop(system, scoop);
                    else
                    {
                        Issue(Code(scoopKind == FsKind.Dir ? FsKind.Symlink : scoopKind), scoop);
                        foreach (var (runtime, _) in ScoopApps) system.Units[runtime].Partial = true;
                    }
                }
            }
            catch (StopException)
            {
                foreach (var u in system.Units.Values) u.Partial = true;
                stopped = true;
            }

            if (profiles is null)
            {
                Issue("unreadable", "ProfileList");
                foreach (var r in LocalModelRuntime.All) runtimeStatuses[r].Add(PackageCollectionStatus.Failed);
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
                        foreach (var (runtime, dir, exes) in AppDirs)
                            AppDir(ctx, runtime, "local_programs", root, ["AppData", "Local", "Programs", .. dir], exes);
                        WinGetPackages(ctx, root, ["AppData", "Local", "Microsoft", "WinGet", "Packages"]);
                        var (sk, scoop) = _reader.Walk(root, "scoop");
                        if (sk == FsKind.Dir) Scoop(ctx, scoop);
                        else if (sk != FsKind.Absent) Refuse(ctx.Units[LocalModelRuntime.LlamaCpp], sk, scoop);
                        OllamaStore(ctx, root);
                        LmStudioStores(ctx, root);
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
                    foreach (var r in LocalModelRuntime.All) runtimeStatuses[r].Add(PackageCollectionStatus.Failed);
                }
            }

            foreach (var r in LocalModelRuntime.All) runtimeStatuses[r].Add(system.Units[r].Status);
            var userRows = new List<LocalModelUserRow>();
            foreach (var (ctx, user, userId) in users)
            {
                var statuses = LocalModelRuntime.All.Select(r => ctx.Units[r].Status).ToList();
                for (var i = 0; i < LocalModelRuntime.All.Length; i++) runtimeStatuses[LocalModelRuntime.All[i]].Add(statuses[i]);
                userRows.Add(new LocalModelUserRow
                {
                    User = user,
                    UserId = userId,
                    CollectionStatus = Combine(statuses),
                    Runtimes = LocalModelRuntime.All.Zip(statuses).ToDictionary(p => p.First, p => p.Second),
                });
            }

            var runtimes = new Dictionary<string, LocalRuntimeSummary>();
            foreach (var r in LocalModelRuntime.All)
            {
                var stores = _stores.Where(s => s.Runtime == r).ToList();
                runtimes[r] = new LocalRuntimeSummary
                {
                    CollectionStatus = Combine(runtimeStatuses[r], stopped),
                    InstallationCount = _installations.Count(i => i.Runtime == r),
                    StoreCount = stores.Count,
                    ModelCount = stores.Sum(s => s.Count),
                    TotalBytes = stores.Sum(s => s.Bytes),
                };
            }
            var status = Combine(runtimes.Values.Select(v => v.CollectionStatus).ToList(), _truncated);

            return new InventoryLocalModels
            {
                CollectionStatus = status,
                Truncated = _truncated,
                TruncationReason = _truncated ? _reason : null,
                Runtimes = runtimes,
                Totals = new LocalModelTotals
                {
                    ModelCount = runtimes.Values.Sum(v => v.ModelCount),
                    TotalBytes = runtimes.Values.Sum(v => v.TotalBytes),
                },
                Users = userRows,
                Installations = _installations,
                Stores = _stores.Select(s => new LocalModelStore
                {
                    Runtime = s.Runtime,
                    Scope = s.Ctx.Scope,
                    User = s.Ctx.User,
                    UserId = s.Ctx.UserId,
                    Path = UserTreeReader.CleanPath(s.Path),
                    CollectionStatus = s.Status,
                    ModelCount = s.Count,
                    TotalBytes = s.Bytes,
                }).ToList(),
                Issues = _issues,
                Models = status == PackageCollectionStatus.Failed
                    ? null
                    : _models
                        .OrderBy(m => m.Runtime, StringComparer.Ordinal)
                        .ThenBy(m => m.User ?? "", StringComparer.Ordinal)
                        .ThenBy(m => m.StorePath, StringComparer.Ordinal)
                        .ThenBy(m => m.Name ?? "", StringComparer.Ordinal)
                        .ThenBy(m => m.Tag ?? "", StringComparer.Ordinal)
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

        /// <summary>
        /// Something where a directory or file was expected. A reparse point (a model disk linked
        /// in, very common) is recorded and not followed, and makes the unit partial; anything
        /// else unreadable counts against it.
        /// </summary>
        private void Refuse(Unit unit, FsKind kind, string where)
        {
            Issue(Code(kind), where);
            if (kind == FsKind.Symlink) unit.Partial = true;
            else unit.Problems++;
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

        /// <summary>True once the model bound is reached; a store skipped for it is truncated too.</summary>
        private bool LimitHit()
        {
            if (_modelCount < options.MaxModels) return false;
            _truncated = true;
            _reason ??= "model_limit";
            return true;
        }

        private void TakeSlot()
        {
            if (LimitHit()) throw new FullException();
            _modelCount++;
        }

        private void AddInstallation(Ctx ctx, string runtime, string kind, string path, string? version,
            string versionSource, bool partial = false)
        {
            _installations.Add(new LocalRuntimeInstallation
            {
                Runtime = runtime,
                Scope = ctx.Scope,
                User = ctx.User,
                UserId = ctx.UserId,
                Kind = kind,
                Path = UserTreeReader.CleanPath(path),
                Version = version,
                VersionSource = version is null ? "none" : versionSource,
            });
            var unit = ctx.Units[runtime];
            unit.Locations++;
            unit.Ok++;
            if (partial) unit.Partial = true;
        }

        // ---------------------------------------------------------------------
        // Runtimes
        // ---------------------------------------------------------------------

        private (string Status, string? Version) ExeVersion(string exe) =>
            _reader.ReadRanges(exe, ExecutableCap, read => PeVersionReader.Read(read));

        /// <summary>
        /// An install directory holding one of <paramref name="exes"/>. The first executable
        /// that carries a version resource gives the version; a directory with none of them is
        /// not an installation.
        /// </summary>
        private void AppDir(Ctx ctx, string runtime, string kind, string anchor, string[] parts, string[] exes)
        {
            CheckTime();
            var unit = ctx.Units[runtime];
            var (k, dir) = _reader.Walk(anchor, parts);
            if (k == FsKind.Absent) return;
            if (k != FsKind.Dir)
            {
                Refuse(unit, k, dir);
                return;
            }
            InstallFromExes(ctx, runtime, kind, dir, exes, unit);
        }

        private void InstallFromExes(Ctx ctx, string runtime, string kind, string dir, string[] exes, Unit unit)
        {
            var found = false;
            string? version = null;
            var partial = false;
            foreach (var exe in exes)
            {
                var path = Path.Combine(dir, exe);
                var ek = _reader.KindAt(path);
                if (ek == FsKind.Absent) continue;
                if (ek != FsKind.File)
                {
                    partial = true;
                    Issue(Code(ek), path);
                    continue;
                }
                found = true;
                var (status, v) = ExeVersion(path);
                if (status is "read")
                {
                    version = UserTreeReader.CleanText(v, 64);
                    if (version is not null) break;
                }
                else if (status is not "none")
                {
                    partial = true;
                    Issue("pe_" + status, path);
                }
            }
            if (found) AddInstallation(ctx, runtime, kind, dir, version, "pe_version_resource", partial);
            else if (partial) unit.Partial = true;
        }

        private void WinGetPackages(Ctx ctx, string anchor, string[] parts)
        {
            var unit = ctx.Units[LocalModelRuntime.LlamaCpp];
            var (k, dir) = _reader.Walk(anchor, parts);
            if (k == FsKind.Absent) return;
            if (k != FsKind.Dir)
            {
                Refuse(unit, k, dir);
                return;
            }
            List<(string Name, FsKind Kind)> entries;
            try
            {
                entries = _reader.ListDir(dir);
            }
            catch (UnlistableDirectoryException)
            {
                Refuse(unit, FsKind.Error, dir);
                return;
            }
            foreach (var (name, ek) in entries)
            {
                CheckTime();
                if (!WinGetLlamaCpp.IsMatch(name)) continue;
                var where = Path.Combine(dir, name);
                if (ek != FsKind.Dir)
                {
                    if (ek != FsKind.File) Refuse(unit, ek, where);
                    continue;
                }
                InstallFromExes(ctx, LocalModelRuntime.LlamaCpp, "winget_portable", where, LlamaCppExes, unit);
            }
        }

        /// <summary>
        /// scoop\apps\&lt;app&gt;\&lt;version&gt;: the directory name is the version. Scoop's
        /// "current" junction is never followed; when its target is a version directory listed
        /// here it is recorded as alias_not_followed and costs nothing. PAT-2052: the target is
        /// read from a handle on "current" itself whose final path is checked first
        /// (<see cref="UserTreeReader.LinkTarget"/>), so an app directory swapped for a
        /// junction after it was listed yields no target, and the link is refused as partial
        /// whatever the other profile's link points at.
        /// </summary>
        private void Scoop(Ctx ctx, string scoop)
        {
            foreach (var (runtime, app) in ScoopApps)
            {
                CheckTime();
                var unit = ctx.Units[runtime];
                var (k, appDir) = _reader.Walk(scoop, "apps", app);
                if (k == FsKind.Absent) continue;
                if (k != FsKind.Dir)
                {
                    Refuse(unit, k, appDir);
                    continue;
                }
                List<(string Name, FsKind Kind)> entries;
                try
                {
                    entries = _reader.ListDir(appDir);
                }
                catch (UnlistableDirectoryException)
                {
                    Refuse(unit, FsKind.Error, appDir);
                    continue;
                }
                var versions = entries.Where(e => e.Kind == FsKind.Dir && e.Name != "current")
                    .Select(e => Path.Combine(appDir, e.Name)).ToList();
                foreach (var (name, ek) in entries)
                {
                    var where = Path.Combine(appDir, name);
                    if (ek == FsKind.Dir && name != "current")
                    {
                        var version = UserTreeReader.CleanText(name, 64);
                        if (version is null) Issue("name_unsafe", appDir);
                        AddInstallation(ctx, runtime, "scoop", where, version, "scoop_version_dir", partial: version is null);
                    }
                    else if (ek == FsKind.Symlink && name == "current"
                             && _reader.LinkTarget(where) is { } target
                             && versions.Contains(target, StringComparer.OrdinalIgnoreCase))
                    {
                        Issue("alias_not_followed", where);
                    }
                    else if (ek != FsKind.File)
                    {
                        unit.Partial = true;
                        Issue(Code(ek), where);
                    }
                }
            }
        }

        // ---------------------------------------------------------------------
        // Model stores
        // ---------------------------------------------------------------------

        private Store NewStore(Ctx ctx, string runtime, string path)
        {
            var store = new Store { Runtime = runtime, Ctx = ctx, Path = path };
            _stores.Add(store);
            ctx.Units[runtime].Locations++;
            return store;
        }

        private static void FinishStore(Store store)
        {
            var unit = store.Ctx.Units[store.Runtime];
            store.Status = store.Failed
                ? (store.Count == 0 ? PackageCollectionStatus.Failed : PackageCollectionStatus.Partial)
                : (store.Partial ? PackageCollectionStatus.Partial : PackageCollectionStatus.Complete);
            if (store.Status == PackageCollectionStatus.Failed)
            {
                unit.Problems++;
            }
            else
            {
                unit.Ok++;
                if (store.Status == PackageCollectionStatus.Partial) unit.Partial = true;
            }
        }

        private void AddModel(Store store, InventoryLocalModel model)
        {
            _models.Add(model);
            store.Count++;
        }

        private InventoryLocalModel Model(Store store, string? name, string? tag) => new()
        {
            Runtime = store.Runtime,
            User = store.Ctx.User,
            UserId = store.Ctx.UserId,
            StorePath = UserTreeReader.CleanPath(store.Path),
            Name = name,
            Tag = tag,
        };

        /// <summary>The real directories directly under path; a reparse point is recorded, never entered.</summary>
        private List<(string Name, string Path)> SubDirs(Store store, string path)
        {
            List<(string Name, FsKind Kind)> entries;
            try
            {
                entries = _reader.ListDir(path);
            }
            catch (UnlistableDirectoryException)
            {
                store.Partial = true;
                Issue("unreadable", path);
                return [];
            }
            var found = new List<(string, string)>();
            foreach (var (name, k) in entries)
            {
                var where = Path.Combine(path, name);
                if (k == FsKind.Dir) found.Add((name, where));
                else if (k != FsKind.File)
                {
                    store.Partial = true;
                    Issue(Code(k), where);
                }
            }
            return found;
        }

        private void OllamaStore(Ctx ctx, string home)
        {
            var unit = ctx.Units[LocalModelRuntime.Ollama];
            var (k, baseDir) = _reader.Walk(home, OllamaStoreParts);
            if (k == FsKind.Absent) return;
            if (k != FsKind.Dir)
            {
                Refuse(unit, k, baseDir);
                return;
            }
            if (LimitHit())
            {
                unit.Partial = true;
                return;
            }
            var store = NewStore(ctx, LocalModelRuntime.Ollama, baseDir);
            var digests = new Dictionary<string, long>(StringComparer.Ordinal);
            var (blobsKind, blobs) = _reader.Walk(baseDir, "blobs");
            if (blobsKind is not (FsKind.Dir or FsKind.Absent))
            {
                store.Partial = true;
                Issue(Code(blobsKind), blobs);
            }
            // PAT-2040: the blobs directory is listed once, from a verified handle, and a blob is
            // missing only when that listing does not have it. Testing each blob by path would
            // follow a junction swapped in for the directory afterwards, and the missing versus
            // unreadable answer would then say whether another user has that blob.
            Dictionary<string, FsKind>? blobEntries = null;
            if (blobsKind == FsKind.Dir)
            {
                try
                {
                    blobEntries = new Dictionary<string, FsKind>(StringComparer.OrdinalIgnoreCase);
                    foreach (var (entry, entryKind, _) in _reader.ListDirWithLengths(blobs)) blobEntries[entry] = entryKind;
                }
                catch (UnlistableDirectoryException)
                {
                    store.Partial = true;
                    Issue("unreadable", blobs);
                    blobsKind = FsKind.Error;
                    blobEntries = null;
                }
            }
            var (mk, manifests) = _reader.Walk(baseDir, "manifests");
            try
            {
                if (mk == FsKind.Absent)
                {
                    // A models directory with nothing pulled yet.
                }
                else if (mk != FsKind.Dir)
                {
                    Issue(Code(mk), manifests);
                    if (mk == FsKind.Symlink) store.Partial = true;
                    else store.Failed = true;
                }
                else
                {
                    List<(string Name, FsKind Kind)> registries;
                    try
                    {
                        registries = _reader.ListDir(manifests);
                    }
                    catch (UnlistableDirectoryException)
                    {
                        Issue("unreadable", manifests);
                        store.Failed = true;
                        registries = [];
                    }
                    foreach (var (reg, rk) in registries)
                    {
                        CheckTime();
                        if (rk == FsKind.File) continue;
                        if (rk != FsKind.Dir)
                        {
                            store.Partial = true;
                            Issue(Code(rk), Path.Combine(manifests, reg));
                            continue;
                        }
                        foreach (var (ns, nsPath) in SubDirs(store, Path.Combine(manifests, reg)))
                        {
                            foreach (var (model, modelPath) in SubDirs(store, nsPath))
                            {
                                CheckTime();
                                List<(string Name, FsKind Kind)> tags;
                                try
                                {
                                    tags = _reader.ListDir(modelPath);
                                }
                                catch (UnlistableDirectoryException)
                                {
                                    store.Partial = true;
                                    Issue("unreadable", modelPath);
                                    continue;
                                }
                                foreach (var (tag, tk) in tags)
                                {
                                    CheckTime();
                                    var where = Path.Combine(modelPath, tag);
                                    if (tk == FsKind.Dir) continue;
                                    if (tk != FsKind.File)
                                    {
                                        store.Partial = true;
                                        Issue(Code(tk), where);
                                        continue;
                                    }
                                    OllamaModel(store, reg, ns, model, tag, where, blobs, blobsKind, blobEntries, digests);
                                }
                            }
                        }
                    }
                }
            }
            catch (FullException)
            {
                store.Partial = true;
            }
            catch (StopException)
            {
                store.Partial = true;
                store.Bytes = digests.Values.Sum();
                FinishStore(store);
                throw;
            }
            store.Bytes = digests.Values.Sum();
            FinishStore(store);
        }

        private void OllamaModel(Store store, string registry, string ns, string model, string tag, string path,
            string blobs, FsKind blobsKind, Dictionary<string, FsKind>? blobEntries, Dictionary<string, long> digests)
        {
            var name = OllamaName(registry, ns, model);
            var cleanTag = UserTreeReader.CleanText(tag, 255);
            if (name is null || cleanTag is null)
            {
                store.Partial = true;
                Issue("name_unsafe", Path.GetDirectoryName(path) ?? path);
                return;
            }
            TakeSlot();
            var (status, data) = _reader.ReadFile(path, ManifestCap);
            // PAT-2040: the manifest came from a listing, so it was there. "missing" now means
            // it went, or its directory was swapped for a junction since, and telling that apart
            // from unreadable would say whether another user has a file of that name.
            if (status == "missing") status = "unreadable";
            List<(string Digest, long Size)>? layers = null;
            if (status == "read") (status, layers) = ParseManifest(data!);
            if (status != "read" || layers is null)
            {
                // Still listed: a model whose manifest cannot be read is present, just not sized.
                store.Partial = true;
                Issue("manifest_" + status, path);
                AddModel(store, Model(store, name, cleanTag) with { MetadataStatus = status });
                return;
            }
            var unique = new Dictionary<string, long>(StringComparer.Ordinal);
            foreach (var (digest, size) in layers) unique[digest] = size;
            int? missing;
            if (blobsKind == FsKind.Dir && blobEntries is not null)
            {
                // Length only: a blob is opened for its length through the verified handle
                // (PAT-2033) and never read, and a reparse point is not a blob. The store
                // total counts what is on disk, once per blob. PAT-2040: a blob is missing only
                // when the listing of the blobs directory does not have it. One the listing has
                // but that is not a plain file, or is refused when opened (a hard link, locked,
                // failing the identity check, gone since), is unreadable: not counted as
                // missing, not sized, and the store is partial with a blob_unreadable issue.
                missing = 0;
                foreach (var digest in unique.Keys)
                {
                    var blobName = "sha256-" + digest;
                    if (!blobEntries.TryGetValue(blobName, out var listed))
                    {
                        missing++;
                        continue;
                    }
                    var blob = Path.Combine(blobs, blobName);
                    long? onDisk = listed == FsKind.File ? _reader.StatLength(blob, listed).Length : null;
                    if (onDisk is { } length) digests[digest] = length;
                    else
                    {
                        store.Partial = true;
                        Issue("blob_unreadable", blob);
                    }
                }
            }
            else if (blobsKind == FsKind.Absent)
            {
                missing = unique.Count;
            }
            else
            {
                // The blobs directory was not looked into: fall back to the declared sizes.
                missing = null;
                foreach (var (digest, size) in unique) digests[digest] = size;
            }
            AddModel(store, Model(store, name, cleanTag) with
            {
                SizeBytes = unique.Values.Sum(),
                FileCount = unique.Count,
                SizeSource = "manifest",
                MissingBlobs = missing,
                MetadataStatus = "read",
            });
        }

        private void LmStudioStores(Ctx ctx, string home)
        {
            var unit = ctx.Units[LocalModelRuntime.LmStudio];
            foreach (var parts in LmStudioStoreParts)
            {
                var (k, baseDir) = _reader.Walk(home, parts);
                if (k == FsKind.Absent) continue;
                if (k != FsKind.Dir)
                {
                    Refuse(unit, k, baseDir);
                    continue;
                }
                if (LimitHit())
                {
                    unit.Partial = true;
                    continue;
                }
                var store = NewStore(ctx, LocalModelRuntime.LmStudio, baseDir);
                try
                {
                    List<(string Name, FsKind Kind)> publishers;
                    try
                    {
                        publishers = _reader.ListDir(baseDir);
                    }
                    catch (UnlistableDirectoryException)
                    {
                        Issue("unreadable", baseDir);
                        store.Failed = true;
                        publishers = [];
                    }
                    foreach (var (publisher, pk) in publishers)
                    {
                        CheckTime();
                        if (pk == FsKind.File) continue;
                        if (pk != FsKind.Dir)
                        {
                            store.Partial = true;
                            Issue(Code(pk), Path.Combine(baseDir, publisher));
                            continue;
                        }
                        foreach (var (repo, repoPath) in SubDirs(store, Path.Combine(baseDir, publisher)))
                        {
                            CheckTime();
                            LmStudioRepo(store, publisher, repo, repoPath);
                        }
                    }
                }
                catch (FullException)
                {
                    store.Partial = true;
                }
                catch (StopException)
                {
                    store.Partial = true;
                    FinishStore(store);
                    throw;
                }
                FinishStore(store);
            }
        }

        private static bool IsWeight(string name, bool includeGguf) =>
            WeightExtensions.Any(e => name.EndsWith(e, StringComparison.OrdinalIgnoreCase))
            || (includeGguf && name.EndsWith(".gguf", StringComparison.OrdinalIgnoreCase));

        private void LmStudioRepo(Store store, string publisher, string repo, string path)
        {
            List<(string Name, FsKind Kind, long Length)> entries;
            try
            {
                entries = _reader.ListDirWithLengths(path);
            }
            catch (UnlistableDirectoryException)
            {
                store.Partial = true;
                Issue("unreadable", path);
                return;
            }
            var ggufs = new List<(string Name, long Length)>();
            long otherBytes = 0;
            var otherFiles = 0;
            var weights = new HashSet<string>(StringComparer.Ordinal);
            foreach (var (name, k, length) in entries)
            {
                CheckTime();
                var where = Path.Combine(path, name);
                if (k == FsKind.File)
                {
                    if (name.EndsWith(".gguf", StringComparison.OrdinalIgnoreCase))
                    {
                        ggufs.Add((name, length));
                        continue;
                    }
                    otherBytes += length;
                    otherFiles++;
                    if (IsWeight(name, false)) weights.Add(name.EndsWith(".safetensors", StringComparison.OrdinalIgnoreCase) ? "safetensors" : "other");
                }
                else if (k == FsKind.Dir)
                {
                    // One level down (an MLX repo keeps its shards here); no deeper.
                    List<(string Name, FsKind Kind, long Length)> inner;
                    try
                    {
                        inner = _reader.ListDirWithLengths(where);
                    }
                    catch (UnlistableDirectoryException)
                    {
                        store.Partial = true;
                        Issue("unreadable", where);
                        continue;
                    }
                    foreach (var (innerName, ik, innerLength) in inner)
                    {
                        if (ik == FsKind.File)
                        {
                            otherBytes += innerLength;
                            otherFiles++;
                            if (IsWeight(innerName, true))
                                weights.Add(innerName.EndsWith(".safetensors", StringComparison.OrdinalIgnoreCase) ? "safetensors" : "other");
                        }
                        else
                        {
                            store.Partial = true;
                            Issue(ik == FsKind.Dir ? "depth_limit" : Code(ik), Path.Combine(where, innerName));
                        }
                    }
                }
                else
                {
                    store.Partial = true;
                    Issue(Code(k), where);
                }
            }
            var modelName = UserTreeReader.CleanText(publisher + "/" + repo);
            if (modelName is null)
            {
                store.Partial = true;
                Issue("name_unsafe", Path.GetDirectoryName(path) ?? path);
                return;
            }
            foreach (var (file, length) in ggufs)
            {
                var tag = UserTreeReader.CleanText(file[..^5], 255);
                if (tag is null)
                {
                    store.Partial = true;
                    Issue("name_unsafe", path);
                    continue;
                }
                TakeSlot();
                store.Bytes += length;
                AddModel(store, Model(store, modelName, tag) with
                {
                    Format = "gguf",
                    SizeBytes = length,
                    FileCount = 1,
                    SizeSource = "stat",
                });
            }
            if (ggufs.Count == 0 && weights.Count > 0)
            {
                TakeSlot();
                store.Bytes += otherBytes;
                AddModel(store, Model(store, modelName, null) with
                {
                    Format = weights.Contains("safetensors") ? "safetensors" : "other",
                    SizeBytes = otherBytes,
                    FileCount = otherFiles,
                    SizeSource = "stat",
                });
            }
        }
    }
}
