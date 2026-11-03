using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32.SafeHandles;
using Patched.Shared.Contract;
using Patched.Shared.UserTrees;

namespace Patched.Shared.IdeExtensions;

/// <summary>One local user profile handed to the scan.</summary>
/// <param name="User">DOMAIN\user, or the SID when it cannot be resolved.</param>
/// <param name="UserId">The profile SID.</param>
/// <param name="ProfileRoot">The profile directory, e.g. C:\Users\alice.</param>
internal sealed record IdeProfileSource(string User, string? UserId, string ProfileRoot);

/// <summary>Bounds and seams for <see cref="IdeExtensionScanLogic.Scan"/>.</summary>
internal sealed class IdeExtensionScanOptions
{
    public int MaxExtensions { get; init; } = 5000;
    public TimeSpan TimeBudget { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Cancelled by the Service scanner when its hard timeout abandons the scan, so a scan
    /// stuck behind a slow read stops at its next budget check instead of running on (and
    /// touching files) after its result has been thrown away. Checked wherever the time budget is.
    /// </summary>
    public CancellationToken Cancellation { get; init; }

    /// <summary>Where JetBrains keeps per-product config and plugins, relative to the profile root.</summary>
    public string[] JetBrainsRelative { get; init; } = ["AppData", "Roaming", "JetBrains"];

    /// <summary>
    /// Checks an opened handle against the path the scan meant to open (link count, final
    /// path). Defaults to <see cref="WindowsFileIdentity.IsExpectedRegularFile"/> on Windows,
    /// and to nothing elsewhere, where the scan runs only under test.
    /// </summary>
    public Func<SafeFileHandle, string, bool>? VerifyOpenedFile { get; init; } =
        OperatingSystem.IsWindows() ? WindowsFileIdentity.IsExpectedRegularFile : null;

    /// <summary>Kernel-resolved final path of a profile root; null falls back to its full path.</summary>
    public Func<string, string?>? ResolveRootFinalPath { get; init; } =
        OperatingSystem.IsWindows() ? WindowsFileIdentity.FinalPathOfDirectory : null;
}

/// <summary>
/// PAT-2017: IDE extension and plugin inventory for every local user profile, read from
/// disk. The Windows twin of macos/lib/ide_extensions.sh, producing the same
/// <see cref="InventoryIdeExtensions"/> shape field for field. Lives in Shared (no Windows
/// TFM) so its tests run on macOS as well as Windows; the Service's IdeExtensionScanner
/// resolves the real profiles from HKLM ProfileList and hands them here.
///
/// WHAT IS READ, AND ONLY THIS, under each profile root:
///   .vscode\extensions, .vscode-insiders\extensions, .cursor\extensions,
///   .windsurf\extensions: extensions.json, or when that is missing, unreadable or does not
///   parse, each extension folder's package.json (skipping folders listed in .obsolete);
///   AppData\Roaming\JetBrains\&lt;Product&gt;&lt;YYYY.N&gt;\plugins: META-INF\plugin.xml,
///   unpacked or as a member of a jar in the plugin's lib\ (or of a single-jar plugin), read
///   through ZipArchive without extracting anything, and parsed with DTDs prohibited; and
///   &lt;Product&gt;&lt;YYYY.N&gt;\disabled_plugins.txt.
///
/// READ ONLY. No editor is launched and nothing is written.
///
/// THE TREES ARE USER-OWNED AND THIS RUNS AS SYSTEM. Every directory is checked for a
/// reparse point (junction or symlink) before it is entered and is never entered through
/// one; every file must be a non-reparse regular file under a size cap before it is
/// opened, and after it is opened the handle must be a single-link file whose final path is
/// the one the scan meant (<see cref="IdeExtensionScanOptions.VerifyOpenedFile"/>), which
/// closes the swap-after-check window. Every string sent has control characters refused
/// and URL userinfo removed.
///
/// ABSENCE REQUIRES AUTHORITY (PAT-1710): see <see cref="InventoryIdeExtensions"/>.
/// </summary>
internal static class IdeExtensionScanLogic
{
    private const int JsonCap         = 8 * 1024 * 1024;
    private const int ManifestCap     = 1024 * 1024;
    private const int PluginXmlCap    = 2 * 1024 * 1024;
    private const long JarCap         = 256L * 1024 * 1024;
    private const int DisabledCap     = 256 * 1024;
    private const int TextCap         = 512;
    private const int MaxUsers        = 500;
    private const int MaxJarsPerPlugin = 200;
    private const int MaxIssues       = 50;

    private static readonly (string Editor, string Dot)[] VsCodeEditors =
    [
        ("vscode", ".vscode"),
        ("vscode_insiders", ".vscode-insiders"),
        ("cursor", ".cursor"),
        ("windsurf", ".windsurf"),
    ];

    private static readonly Regex JetBrainsProduct =
        new(@"^([A-Za-z][A-Za-z-]*?)(\d{4}\.\d+)$", RegexOptions.CultureInvariant);

    private sealed class StopException : Exception;

    /// <summary>A directory could not be read. Recorded == true means the issue is already written.</summary>
    private sealed class AbortException(bool recorded = false) : Exception
    {
        public bool Recorded { get; } = recorded;
    }

    private sealed class ProfileState
    {
        public bool Partial;
        public int Count;
    }

    private sealed record ProfileContext(
        string User, string? UserId, string Family, string Editor, string? EditorVersion, string Dir)
    {
        public string? ManifestSource { get; set; }
    }

    /// <summary>
    /// Scans every profile. <paramref name="profiles"/> null means the profile list itself
    /// could not be read: the block is failed, never "no users".
    /// <paramref name="unreadableProfiles"/> counts registered profiles whose location could
    /// not be read; any makes the block partial at best, since those users were not looked
    /// at. Never throws.
    /// </summary>
    public static InventoryIdeExtensions Scan(
        IEnumerable<IdeProfileSource>? profiles, IdeExtensionScanOptions? options = null, int unreadableProfiles = 0)
    {
        var run = new Run(options ?? new IdeExtensionScanOptions());
        try
        {
            return run.Execute(profiles, unreadableProfiles);
        }
        catch (Exception)
        {
            return new InventoryIdeExtensions { CollectionStatus = IdeCollectionStatus.Failed, Issues = run.Issues };
        }
    }

    private sealed class Run(IdeExtensionScanOptions options)
    {
        private readonly Stopwatch _clock = Stopwatch.StartNew();
        private readonly List<IdeIssue> _issues = [];
        private int _count;
        private bool _truncated;
        private string? _reason;
        // PAT-2033: the one set of file-safety primitives, shared with the other user-tree
        // collectors, in place of the private copy this class carried.
        private readonly UserTreeReader _reader = new(options.VerifyOpenedFile, options.ResolveRootFinalPath);

        public IReadOnlyList<IdeIssue> Issues => _issues;

        public InventoryIdeExtensions Execute(IEnumerable<IdeProfileSource>? profiles, int unreadableProfiles)
        {
            var extensions = new List<InventoryIdeExtension>();
            var users = new List<IdeUserRow>();
            var profileRows = new List<IdeProfileRow>();
            if (profiles is null)
            {
                Issue("unreadable", "ProfileList");
                return Finish(IdeCollectionStatus.Failed, extensions, users, profileRows);
            }

            var stopped = false;
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
                if (rootKind != FsKind.Dir)
                {
                    if (rootKind == FsKind.Absent) continue;
                    Issue(Code(rootKind), root);
                    users.Add(new IdeUserRow { User = user, UserId = userId, CollectionStatus = IdeCollectionStatus.Failed });
                    continue;
                }

                List<(string Family, string Editor, string? Version, string Path, FsKind Kind)> found;
                (string Path, FsKind Kind)? jbProblem;
                try
                {
                    (found, jbProblem) = EditorProfiles(root);
                }
                catch (AbortException)
                {
                    Issue("unreadable", root);
                    users.Add(new IdeUserRow { User = user, UserId = userId, CollectionStatus = IdeCollectionStatus.Failed });
                    continue;
                }
                var userPartial = false;
                if (jbProblem is { } problem)
                {
                    userPartial = true;
                    Issue(Code(problem.Kind), problem.Path);
                }

                var statuses = new List<string>();
                foreach (var (family, editor, version, path, kind) in found)
                {
                    var ctx = new ProfileContext(user, userId, family, editor, version, path);
                    var ps = new ProfileState();
                    string? pStatus = null;
                    if (kind != FsKind.Dir)
                    {
                        // A reparse point is recorded, never entered: everything under it
                        // would be read through a path the user chose.
                        Issue(Code(kind), path);
                        pStatus = IdeCollectionStatus.Failed;
                    }
                    else
                    {
                        try
                        {
                            if (family == "vscode") CollectVsCode(ctx, path, ps, extensions);
                            else CollectJetBrains(ctx, path, ps, extensions);
                        }
                        catch (AbortException ex)
                        {
                            if (!ex.Recorded) Issue("unreadable", path);
                            pStatus = ps.Count == 0 ? IdeCollectionStatus.Failed : IdeCollectionStatus.Partial;
                        }
                        catch (StopException)
                        {
                            ps.Partial = true;
                            stopped = true;
                        }
                    }
                    pStatus ??= ps.Partial ? IdeCollectionStatus.Partial : IdeCollectionStatus.Complete;
                    statuses.Add(pStatus);
                    profileRows.Add(new IdeProfileRow
                    {
                        User = user, UserId = userId, Family = family, Editor = editor, EditorVersion = version,
                        CollectionStatus = pStatus, ManifestSource = ctx.ManifestSource, ExtensionCount = ps.Count,
                    });
                    if (stopped) break;
                }

                string uStatus;
                if (statuses.Count == 0)
                    uStatus = userPartial ? IdeCollectionStatus.Partial : IdeCollectionStatus.NotPresent;
                else if (statuses.All(s => s == IdeCollectionStatus.Failed) && !userPartial)
                    uStatus = IdeCollectionStatus.Failed;
                else if (userPartial || statuses.Any(s => s != IdeCollectionStatus.Complete))
                    uStatus = IdeCollectionStatus.Partial;
                else
                    uStatus = IdeCollectionStatus.Complete;
                users.Add(new IdeUserRow { User = user, UserId = userId, CollectionStatus = uStatus, Profiles = statuses.Count });
            }
            if (stopped) _truncated = true;
            if (unreadableProfiles > 0) Issue("profile_unreadable", "ProfileList");

            string status;
            if ((users.Count > 0 && users.All(u => u.CollectionStatus == IdeCollectionStatus.Failed))
                || (users.Count == 0 && unreadableProfiles > 0))
                status = IdeCollectionStatus.Failed;
            else if (_truncated || unreadableProfiles > 0
                     || users.Any(u => u.CollectionStatus is IdeCollectionStatus.Partial or IdeCollectionStatus.Failed))
                status = IdeCollectionStatus.Partial;
            else if (profileRows.Count == 0)
                status = IdeCollectionStatus.NotPresent;
            else
                status = IdeCollectionStatus.Complete;
            return Finish(status, extensions, users, profileRows);
        }

        private InventoryIdeExtensions Finish(
            string status, List<InventoryIdeExtension> extensions, List<IdeUserRow> users, List<IdeProfileRow> profiles)
        {
            IReadOnlyList<InventoryIdeExtension>? list = null;
            if (status != IdeCollectionStatus.Failed)
            {
                list = extensions
                    .OrderBy(e => e.User, StringComparer.Ordinal)
                    .ThenBy(e => e.Family, StringComparer.Ordinal)
                    .ThenBy(e => e.Editor, StringComparer.Ordinal)
                    .ThenBy(e => e.EditorVersion ?? "", StringComparer.Ordinal)
                    .ThenBy(e => e.Id ?? "", StringComparer.Ordinal)
                    .ThenBy(e => e.Directory ?? "", StringComparer.Ordinal)
                    .ToList();
            }
            return new InventoryIdeExtensions
            {
                CollectionStatus = status,
                Truncated = _truncated,
                TruncationReason = _truncated ? _reason : null,
                Users = users,
                Profiles = profiles,
                Issues = _issues,
                Extensions = list,
            };
        }

        // ---------------------------------------------------------------------
        // Primitives
        // ---------------------------------------------------------------------

        private void Issue(string code, string path)
        {
            if (_issues.Count >= MaxIssues) return;
            _issues.Add(new IdeIssue { Code = code, Path = UserTreeReader.CleanPath(path) });
        }

        private static string Code(FsKind kind) => kind switch
        {
            FsKind.Symlink => "symlink_not_followed",
            FsKind.Other   => "not_regular",
            _            => "unreadable",
        };

        private void Refused(FsKind kind, string where, ProfileState ps)
        {
            ps.Partial = true;
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

        private void TakeSlot()
        {
            if (_count >= options.MaxExtensions)
            {
                _truncated = true;
                _reason ??= "extension_limit";
                throw new StopException();
            }
            _count++;
        }

        /// <summary>
        /// <see cref="UserTreeReader.ListDir"/>, with an unlistable directory raised as this
        /// scan's <see cref="AbortException"/>.
        /// </summary>
        private List<(string Name, FsKind Kind)> ListDir(string path)
        {
            try
            {
                return _reader.ListDir(path);
            }
            catch (UnlistableDirectoryException)
            {
                throw new AbortException();
            }
        }

        private static (string Status, JsonDocument? Doc) ParseJson(string status, byte[]? data)
        {
            if (status != "read" || data is null) return (status, null);
            var span = data.AsMemory();
            if (span.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) span = span[3..];
            try
            {
                return ("read", JsonDocument.Parse(span, new JsonDocumentOptions { MaxDepth = 256 }));
            }
            catch (Exception)
            {
                return ("unparseable", null);
            }
        }

        private static string? Str(JsonElement obj, string name, int cap = TextCap) =>
            obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? UserTreeReader.CleanText(v.GetString(), cap)
                : null;

        private static bool? Bool(JsonElement obj, string name) =>
            obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var v)
                ? v.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null }
                : null;

        private static string? IsoFromMs(JsonElement obj, string name)
        {
            if (obj.ValueKind != JsonValueKind.Object || !obj.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.Number)
                return null;
            if (!v.TryGetDouble(out var ms) || double.IsNaN(ms) || ms <= 0) return null;
            try
            {
                return DateTimeOffset.FromUnixTimeMilliseconds((long)Math.Floor(ms))
                    .UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
            }
            catch
            {
                return null;
            }
        }

        private static JsonElement Obj(JsonElement parent, string name) =>
            parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Object
                ? v
                : default;

        private static InventoryIdeExtension Entry(ProfileContext p) => new()
        {
            User = p.User, UserId = p.UserId, Family = p.Family, Editor = p.Editor, EditorVersion = p.EditorVersion,
        };

        private static string? Platform(string? target) => target is null or "undefined" ? null : target;

        // ---------------------------------------------------------------------
        // VS Code family
        // ---------------------------------------------------------------------

        private bool FromExtensionsJson(ProfileContext p, JsonElement root, ProfileState ps, List<InventoryIdeExtension> sink)
        {
            if (root.ValueKind != JsonValueKind.Array) return false;
            foreach (var item in root.EnumerateArray())
            {
                CheckTime();
                var ident = Obj(item, "identifier");
                var id = item.ValueKind == JsonValueKind.Object ? Str(ident, "id") : null;
                if (id is null || !id.Contains('.'))
                {
                    ps.Partial = true;
                    Issue("entry_malformed", p.Dir);
                    continue;
                }
                TakeSlot();
                var meta = Obj(item, "metadata");
                var dot = id.IndexOf('.');
                sink.Add(Entry(p) with
                {
                    Id = id.ToLowerInvariant(),
                    Name = UserTreeReader.CleanText(id[(dot + 1)..]),
                    Publisher = UserTreeReader.CleanText(id[..dot]),
                    PublisherDisplayName = Str(meta, "publisherDisplayName"),
                    Version = Str(item, "version"),
                    InstalledAt = IsoFromMs(meta, "installedTimestamp"),
                    Source = Str(meta, "source"),
                    PreRelease = Bool(meta, "isPreReleaseVersion"),
                    TargetPlatform = Platform(Str(meta, "targetPlatform")),
                    Directory = Str(item, "relativeLocation"),
                    ManifestSource = "extensions_json",
                    ManifestStatus = "read",
                });
                ps.Count++;
            }
            return true;
        }

        private HashSet<string> ObsoleteDirs(string extDir, ProfileState ps)
        {
            var path = Path.Combine(extDir, ".obsolete");
            var (status, doc) = ReadJsonFile(path, ManifestCap);
            using (doc)
            {
                if (status == "read" && doc!.RootElement.ValueKind == JsonValueKind.Object)
                {
                    return doc.RootElement.EnumerateObject()
                        .Where(o => o.Value.ValueKind == JsonValueKind.True)
                        .Select(o => o.Name)
                        .ToHashSet(StringComparer.Ordinal);
                }
                if (status != "missing")
                {
                    ps.Partial = true;
                    Issue("obsolete_unreadable", path);
                }
                return [];
            }
        }

        private void FromPackageManifests(ProfileContext p, string extDir, ProfileState ps, List<InventoryIdeExtension> sink)
        {
            var obsolete = ObsoleteDirs(extDir, ps);
            foreach (var (name, kind) in ListDir(extDir))
            {
                CheckTime();
                var where = Path.Combine(extDir, name);
                if (kind == FsKind.File) continue;
                if (kind != FsKind.Dir)
                {
                    Refused(kind, where, ps);
                    continue;
                }
                if (obsolete.Contains(name)) continue;
                var directory = UserTreeReader.CleanText(name, 255);
                if (directory is null)
                {
                    ps.Partial = true;
                    Issue("name_unsafe", extDir);
                    continue;
                }
                TakeSlot();
                var (status, doc) = ReadJsonFile(Path.Combine(where, "package.json"), ManifestCap);
                using (doc)
                {
                    if (status == "read" && doc!.RootElement.ValueKind != JsonValueKind.Object) status = "unparseable";
                    if (status == "read")
                    {
                        var manifest = doc!.RootElement;
                        var publisher = Str(manifest, "publisher");
                        var extName = Str(manifest, "name");
                        var meta = Obj(manifest, "__metadata");
                        if (publisher is null || extName is null)
                        {
                            ps.Partial = true;
                            Issue("manifest_incomplete", where);
                        }
                        sink.Add(Entry(p) with
                        {
                            Id = publisher is not null && extName is not null ? $"{publisher}.{extName}".ToLowerInvariant() : null,
                            Name = extName,
                            Publisher = publisher,
                            PublisherDisplayName = Str(meta, "publisherDisplayName"),
                            Version = Str(manifest, "version"),
                            InstalledAt = IsoFromMs(meta, "installedTimestamp"),
                            Source = Str(meta, "source"),
                            PreRelease = Bool(meta, "isPreReleaseVersion"),
                            TargetPlatform = Platform(Str(meta, "targetPlatform")),
                            Directory = directory,
                            ManifestSource = "package_json",
                            ManifestStatus = "read",
                        });
                    }
                    else
                    {
                        // Still listed: present, just not identified.
                        ps.Partial = true;
                        Issue("manifest_" + status, where);
                        sink.Add(Entry(p) with { Directory = directory, ManifestSource = "package_json", ManifestStatus = status });
                    }
                }
                ps.Count++;
            }
        }

        private (string Status, JsonDocument? Doc) ReadJsonFile(string path, int cap)
        {
            var (status, data) = _reader.ReadFile(path, cap);
            return ParseJson(status, data);
        }

        private void CollectVsCode(ProfileContext p, string extDir, ProfileState ps, List<InventoryIdeExtension> sink)
        {
            var listPath = Path.Combine(extDir, "extensions.json");
            var (status, doc) = ReadJsonFile(listPath, JsonCap);
            using (doc)
            {
                if (status == "read")
                {
                    if (FromExtensionsJson(p, doc!.RootElement, ps, sink))
                    {
                        p.ManifestSource = "extensions_json";
                        return;
                    }
                    status = "unparseable";
                }
            }
            if (status != "missing")
            {
                // A corrupt list is never taken as "no extensions".
                ps.Partial = true;
                Issue("extensions_json_" + status, listPath);
            }
            p.ManifestSource = "package_json";
            FromPackageManifests(p, extDir, ps, sink);
        }

        // ---------------------------------------------------------------------
        // JetBrains
        // ---------------------------------------------------------------------

        private static readonly XmlReaderSettings XmlSettings = new()
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 0,
            MaxCharactersInDocument = PluginXmlCap,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
        };

        private sealed record PluginFields(string? Id, string? Name, string? Publisher, string? Version);

        /// <summary>A DTD is refused outright, so no entity is ever expanded or fetched.</summary>
        private static (string Status, PluginFields? Fields) ParsePluginXml(byte[] data)
        {
            try
            {
                using var reader = XmlReader.Create(new MemoryStream(data), XmlSettings);
                var root = XDocument.Load(reader).Root;
                if (root is null || root.Name != XName.Get("idea-plugin")) return ("unparseable", null);
                string? Child(string tag) => root.Element(tag) is { } e ? UserTreeReader.CleanText(e.Value) : null;
                var name = Child("name");
                // JetBrains uses <name> as the id when <id> is not given.
                return ("read", new PluginFields(Child("id") ?? name, name, Child("vendor"), Child("version")));
            }
            catch (Exception)
            {
                return ("unparseable", null);
            }
        }

        private (string Status, PluginFields? Fields) PluginXmlFromJar(string jarPath)
        {
            var (status, handle) = _reader.OpenRegular(jarPath, JarCap);
            if (handle is null) return (status, null);
            byte[] data;
            try
            {
                using var stream = new FileStream(handle, FileAccess.Read);
                using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
                var entry = zip.GetEntry("META-INF/plugin.xml");
                if (entry is null) return ("missing", null);
                if (entry.Length > PluginXmlCap) return ("unreadable", null);
                using var member = entry.Open();
                var buffer = new byte[PluginXmlCap + 1];
                var total = 0;
                int read;
                while (total < buffer.Length && (read = member.Read(buffer, total, buffer.Length - total)) > 0)
                    total += read;
                if (total > PluginXmlCap) return ("unreadable", null);
                data = buffer.AsSpan(0, total).ToArray();
            }
            catch (Exception)
            {
                return ("unparseable", null);
            }
            finally
            {
                handle.Dispose();
            }
            return ParsePluginXml(data);
        }

        private (string Source, string Status, PluginFields? Fields) JetBrainsPlugin(string pluginPath, string name, FsKind kind, ProfileState ps)
        {
            if (kind == FsKind.File)
            {
                var (s, f) = PluginXmlFromJar(pluginPath);
                return ("plugin_xml_jar", s, f);
            }
            var metaInf = Path.Combine(pluginPath, "META-INF");
            var metaKind = _reader.KindAt(metaInf);
            if (metaKind == FsKind.Dir)
            {
                var (s, data) = _reader.ReadFile(Path.Combine(metaInf, "plugin.xml"), PluginXmlCap);
                if (s == "read")
                {
                    var (ps2, f) = ParsePluginXml(data!);
                    return ("plugin_xml_unpacked", ps2, f);
                }
                if (s == "unreadable") return ("plugin_xml_unpacked", s, null);
            }
            else if (metaKind != FsKind.Absent)
            {
                Refused(metaKind, metaInf, ps);
            }
            var lib = Path.Combine(pluginPath, "lib");
            var libKind = _reader.KindAt(lib);
            if (libKind == FsKind.Absent) return ("directory_name", "missing", null);
            if (libKind != FsKind.Dir)
            {
                Refused(libKind, lib, ps);
                return ("directory_name", "unreadable", null);
            }
            List<(string Name, FsKind Kind)> jars;
            try
            {
                jars = ListDir(lib).Where(j => j.Name.EndsWith(".jar", StringComparison.Ordinal)).ToList();
            }
            catch (AbortException)
            {
                Issue("unreadable", lib);
                return ("directory_name", "unreadable", null);
            }
            // The jar named after the plugin folder usually carries plugin.xml.
            jars = jars
                .OrderBy(j => j.Name.StartsWith(name, StringComparison.OrdinalIgnoreCase) ? 0 : 1)
                .ThenBy(j => j.Name, StringComparer.Ordinal)
                .ToList();
            var worst = "missing";
            foreach (var (jar, jarKind) in jars.Take(MaxJarsPerPlugin))
            {
                CheckTime();
                if (jarKind != FsKind.File)
                {
                    Refused(jarKind, Path.Combine(lib, jar), ps);
                    worst = "unreadable";
                    continue;
                }
                var (s, f) = PluginXmlFromJar(Path.Combine(lib, jar));
                if (s == "read") return ("plugin_xml_jar", s, f);
                if (s != "missing") worst = s;
            }
            if (jars.Count > MaxJarsPerPlugin && worst == "missing") worst = "unreadable";
            return ("directory_name", worst, null);
        }

        private HashSet<string>? DisabledIds(string configDir, ProfileState ps)
        {
            var (status, data) = _reader.ReadFile(Path.Combine(configDir, "disabled_plugins.txt"), DisabledCap);
            if (status == "missing") return [];
            if (status != "read")
            {
                ps.Partial = true;
                Issue("disabled_plugins_unreadable", configDir);
                return null;
            }
            return Encoding.UTF8.GetString(data!)
                .Split('\n')
                .Select(l => l.Trim())
                .Where(l => l.Length > 0)
                .ToHashSet(StringComparer.Ordinal);
        }

        private void CollectJetBrains(ProfileContext p, string configDir, ProfileState ps, List<InventoryIdeExtension> sink)
        {
            p.ManifestSource = "plugin_xml";
            var plugins = Path.Combine(configDir, "plugins");
            var pluginsKind = _reader.KindAt(plugins);
            if (pluginsKind == FsKind.Absent) return;
            if (pluginsKind != FsKind.Dir)
            {
                Issue(Code(pluginsKind), plugins);
                throw new AbortException(recorded: true);
            }
            var disabled = DisabledIds(configDir, ps);
            foreach (var (name, kind) in ListDir(plugins))
            {
                CheckTime();
                var where = Path.Combine(plugins, name);
                if (kind == FsKind.File && !name.EndsWith(".jar", StringComparison.Ordinal)) continue;
                if (kind is not (FsKind.Dir or FsKind.File))
                {
                    Refused(kind, where, ps);
                    continue;
                }
                var directory = UserTreeReader.CleanText(name, 255);
                if (directory is null)
                {
                    ps.Partial = true;
                    Issue("name_unsafe", plugins);
                    continue;
                }
                TakeSlot();
                var (source, status, fields) = JetBrainsPlugin(where, name, kind, ps);
                if (status != "read" || fields?.Id is null)
                {
                    ps.Partial = true;
                    Issue("plugin_xml_" + (status != "read" ? status : "incomplete"), where);
                }
                var id = fields?.Id;
                sink.Add(Entry(p) with
                {
                    Id = id,
                    Name = fields?.Name,
                    Publisher = fields?.Publisher,
                    Version = fields?.Version,
                    Disabled = id is not null && disabled is not null ? disabled.Contains(id) : null,
                    Directory = directory,
                    ManifestSource = source,
                    ManifestStatus = status,
                });
                ps.Count++;
            }
        }

        // ---------------------------------------------------------------------
        // Editors present in one profile
        // ---------------------------------------------------------------------

        private (List<(string, string, string?, string, FsKind)> Found, (string, FsKind)? JetBrainsProblem) EditorProfiles(string home)
        {
            var found = new List<(string, string, string?, string, FsKind)>();
            foreach (var (editor, dot) in VsCodeEditors)
            {
                var baseDir = Path.Combine(home, dot);
                var baseKind = _reader.KindAt(baseDir);
                if (baseKind == FsKind.Absent) continue;
                if (baseKind != FsKind.Dir)
                {
                    found.Add(("vscode", editor, null, baseDir, baseKind));
                    continue;
                }
                var extDir = Path.Combine(baseDir, "extensions");
                var extKind = _reader.KindAt(extDir);
                if (extKind != FsKind.Absent) found.Add(("vscode", editor, null, extDir, extKind));
            }
            var jb = home;
            foreach (var part in options.JetBrainsRelative)
            {
                jb = Path.Combine(jb, part);
                var k = _reader.KindAt(jb);
                if (k == FsKind.Absent) return (found, null);
                if (k != FsKind.Dir) return (found, (jb, k));
            }
            List<(string Name, FsKind Kind)> products;
            try
            {
                products = ListDir(jb);
            }
            catch (AbortException)
            {
                return (found, (jb, FsKind.Error));
            }
            foreach (var (name, kind) in products)
            {
                var m = JetBrainsProduct.Match(name);
                if (!m.Success || kind == FsKind.File) continue;
                found.Add(("jetbrains", m.Groups[1].Value, m.Groups[2].Value, Path.Combine(jb, name), kind));
            }
            return (found, null);
        }
    }
}
