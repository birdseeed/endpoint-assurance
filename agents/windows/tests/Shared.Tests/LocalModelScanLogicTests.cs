using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Patched.Shared.Contract;
using Patched.Shared.LocalModels;
using Patched.Shared.UserTrees;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-2019: the Windows local model runtime and model store scan against fixture profiles
/// built in a temp directory: Program Files\Ollama with a versioned executable, LM Studio in a
/// profile's AppData\Local\Programs, a WinGet portable llama.cpp with no version resource, a
/// scoop llama.cpp with its "current" junction, an Ollama store with two models sharing a blob,
/// and LM Studio GGUF, MLX and older-cache stores. The same cases as
/// macos/lib/test-local-models.zsh, so the two agents are held to one contract.
///
/// Every fixture profile also carries the files the scan must never read (Ollama history, key
/// and logs; LM Studio conversations and settings), and a root-only tree the planted links
/// point at, each containing the marker "leaked"; the cases assert it never appears.
///
/// Reparse points: on Windows the directory cases plant an NTFS junction (mklink /J, which an
/// ordinary user can make) and the file cases a symlink or, without that privilege, a hard
/// link; elsewhere a POSIX symlink. A failure to plant is an assertion failure, not a skip,
/// except on a machine that cannot plant a junction at all: there every case that needs one
/// (the fixture tree plants the scoop "current" junction) is skipped explicitly, with the
/// reason (DirectoryLinkFact, PAT-2033).
/// </summary>
public sealed class LocalModelScanLogicTests : IDisposable
{
    private static readonly string A = new('a', 64), B = new('b', 64), L = new('c', 64), C1 = new('d', 64), C2 = new('e', 64);

    private readonly string _root;
    private readonly string _secret;

    public LocalModelScanLogicTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"patched-lm-test-{Guid.NewGuid():N}");
        _secret = Path.Combine(_root, "root-only");
        Sized(Path.Combine(_secret, "leaked-publisher", "leaked-repo", "leaked.gguf"), 123);
        Manifest(Path.Combine(_secret, "manifests", "registry.ollama.ai", "library", "leaked", "latest"), C1, 10, (A, 1000));
        Write(Path.Combine(_secret, "leaked-manifest"), "{\"layers\":[{\"digest\":\"sha256:" + A + "\",\"size\":1}],\"leaked\":1}");
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
    private string ProgramFiles => Path.Combine(_root, "sys", "Program Files");
    private string Home(string user) => Path.Combine(Users, user);
    private string OllamaModels => Path.Combine(Home("alice"), ".ollama", "models");
    private string Qwen => Path.Combine(OllamaModels, "manifests", "registry.ollama.ai", "library", "qwen3", "14b");
    private string LmModels => Path.Combine(Home("bob"), ".lmstudio", "models");

    private static void Write(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    private static void Sized(string path, int bytes)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, new byte[bytes]);
    }

    private static void Manifest(string path, string configDigest, long configSize, params (string Digest, long Size)[] layers) =>
        Write(path, JsonSerializer.Serialize(new
        {
            schemaVersion = 2,
            mediaType = "application/vnd.docker.distribution.manifest.v2+json",
            config = new { mediaType = "application/vnd.docker.container.image.v1+json", digest = "sha256:" + configDigest, size = configSize },
            layers = layers.Select(l => new { mediaType = "application/vnd.ollama.image.model", digest = "sha256:" + l.Digest, size = l.Size }),
        }));

    private void BuildTree()
    {
        if (Directory.Exists(Users)) DeleteTree(Users);
        if (Directory.Exists(Path.Combine(_root, "sys"))) DeleteTree(Path.Combine(_root, "sys"));
        Directory.CreateDirectory(Path.Combine(Home("carol"), "Documents"));

        // Machine-wide: Ollama with a versioned executable, and a WinGet portable llama.cpp
        // whose executable carries no version resource (a plain CMake build).
        File.WriteAllBytes(Path.Combine(Dir(ProgramFiles, "Ollama"), "ollama app.exe"), PeFixture.WithVersion(0, 12, 3, 0));
        File.WriteAllBytes(Path.Combine(Dir(ProgramFiles, "Ollama"), "ollama.exe"), PeFixture.WithVersion(9, 9, 9, 9));
        File.WriteAllBytes(
            Path.Combine(Dir(ProgramFiles, "WinGet", "Packages", "ggml.llamacpp_Microsoft.Winget.Source_8wekyb3d8bbwe"), "llama-server.exe"),
            PeFixture.WithoutVersion());

        // alice: an Ollama store with two models sharing a license blob, a scoop llama.cpp
        // with its "current" junction, and the files around the store that must never be read.
        Manifest(Path.Combine(OllamaModels, "manifests", "registry.ollama.ai", "library", "llama3.2", "latest"), C1, 10, (A, 1000), (L, 100));
        Manifest(Qwen, C2, 20, (B, 2000), (L, 100));
        foreach (var (digest, size) in new[] { (A, 1000), (B, 2000), (L, 100), (C1, 10), (C2, 20) })
            Sized(Path.Combine(OllamaModels, "blobs", "sha256-" + digest), size);
        Write(Path.Combine(Home("alice"), ".ollama", "history"), "leaked prompt: tell me the payroll");
        Write(Path.Combine(Home("alice"), ".ollama", "id_ed25519"), "leaked private key");
        Write(Path.Combine(Home("alice"), ".ollama", "logs", "server.log"), "leaked log line");
        var scoopApp = Dir(Home("alice"), "scoop", "apps", "llama.cpp");
        Sized(Path.Combine(scoopApp, "6230", "llama-server.exe"), 10);
        PlantDirectoryLink(Path.Combine(scoopApp, "current"), Path.Combine(scoopApp, "6230"));

        // bob: LM Studio in AppData\Local\Programs, a GGUF repo with two quantisations and a
        // README, an MLX repo, the older .cache store, conversations and settings.
        File.WriteAllBytes(Path.Combine(Dir(Home("bob"), "AppData", "Local", "Programs", "LM Studio"), "LM Studio.exe"),
            PeFixture.WithVersion(0, 3, 27, 0));
        Sized(Path.Combine(LmModels, "lmstudio-community", "Qwen3-8B-GGUF", "Qwen3-8B-Q4_K_M.gguf"), 3000);
        Sized(Path.Combine(LmModels, "lmstudio-community", "Qwen3-8B-GGUF", "Qwen3-8B-Q8_0.gguf"), 5000);
        Write(Path.Combine(LmModels, "lmstudio-community", "Qwen3-8B-GGUF", "README.md"), "leaked readme text");
        Sized(Path.Combine(LmModels, "mlx-community", "Llama-3.2-3B-Instruct-4bit", "model.safetensors"), 4000);
        Sized(Path.Combine(LmModels, "mlx-community", "Llama-3.2-3B-Instruct-4bit", "config.json"), 50);
        Sized(Path.Combine(LmModels, "mlx-community", "Llama-3.2-3B-Instruct-4bit", "tokenizer.json"), 60);
        Sized(Path.Combine(Home("bob"), ".cache", "lm-studio", "models", "TheBloke", "old-GGUF", "old.Q4_0.gguf"), 700);
        Write(Path.Combine(Home("bob"), ".lmstudio", "conversations", "1.conversation.json"), "leaked conversation");
        Write(Path.Combine(Home("bob"), ".lmstudio", "settings.json"), "leaked settings");
    }

    private static string Dir(string anchor, params string[] parts)
    {
        var path = Path.Combine([anchor, .. parts]);
        Directory.CreateDirectory(path);
        return path;
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

    private LocalModelScanOptions Options(int max = 5000, TimeSpan? budget = null) => new()
    {
        MaxModels = max,
        TimeBudget = budget ?? TimeSpan.FromSeconds(30),
        ProgramFilesRoots = [ProgramFiles],
        ScoopGlobalRoot = null,
    };

    private IEnumerable<UserProfileSource> Profiles(params string[] users) =>
        (users.Length == 0 ? ["alice", "bob", "carol"] : users)
            .Select((u, i) => new UserProfileSource($"TEST\\{u}", $"S-1-5-21-1-2-3-{1001 + i}", Home(u)));

    private InventoryLocalModels ScanAll(LocalModelScanOptions? options = null) =>
        LocalModelScanLogic.Scan(Profiles().ToList(), options ?? Options());

    private static string Serialise(InventoryLocalModels r) => JsonSerializer.Serialize(r);

    private static void AssertNoLeak(InventoryLocalModels r) =>
        Assert.DoesNotContain("leaked", Serialise(r), StringComparison.OrdinalIgnoreCase);

    private static string Rt(InventoryLocalModels r, string runtime) => r.Runtimes[runtime].CollectionStatus;

    private static bool HasIssue(InventoryLocalModels r, string code, string suffix) =>
        r.Issues.Any(i => i.Code == code && i.Path.EndsWith(suffix, StringComparison.Ordinal));

    private static void PlantDirectoryLink(string link, string target)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        if (OperatingSystem.IsWindows()) RunCmd($"mklink /J \"{link}\" \"{target}\"");
        else Directory.CreateSymbolicLink(link, target);
        Assert.True((File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0, $"failed to plant a reparse point at {link}");
    }

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

    /// <summary>
    /// Denies reads of one file to the test's own account (chmod 000, or an Everyone read deny
    /// ACE on Windows), runs <paramref name="body"/>, and restores access. False when the
    /// platform cannot make the file unreadable (running as root).
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
                return false;
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
    // An Ollama store with two models, LM Studio stores, runtimes
    // -------------------------------------------------------------------------

    [DirectoryLinkFact]
    public void Scan_EverythingReadable_IsComplete_AndReadsNothingPrivate()
    {
        BuildTree();
        var r = ScanAll();

        Assert.Equal(PackageCollectionStatus.Complete, r.CollectionStatus);
        Assert.Equal(new[] { "complete", "complete", "complete" }, LocalModelRuntime.All.Select(x => Rt(r, x)).ToArray());
        AssertNoLeak(r);
        Assert.Equal(
            new[]
            {
                ("TEST\\alice", "complete", "complete", "not_present", "complete"),
                ("TEST\\bob", "complete", "not_present", "complete", "not_present"),
                ("TEST\\carol", "not_present", "not_present", "not_present", "not_present"),
            },
            r.Users.Select(u => (u.User, u.CollectionStatus, u.Runtimes["ollama"], u.Runtimes["lm_studio"], u.Runtimes["llama_cpp"])).ToArray());
        Assert.Equal("S-1-5-21-1-2-3-1001", r.Users[0].UserId);
        Assert.False(r.Truncated);
        Assert.Null(r.TruncationReason);
        Assert.Equal(new[] { ("alias_not_followed", true) }, r.Issues.Select(i => (i.Code, i.Path.EndsWith("current"))).ToArray());
    }

    [DirectoryLinkFact]
    public void Scan_Runtimes_VersionsFromThePeResource_WithoutRunningAnything()
    {
        BuildTree();
        var r = ScanAll();

        var ollama = Assert.Single(r.Installations, i => i.Runtime == "ollama");
        Assert.Equal(("program_files", "system", (string?)null, "0.12.3.0", "pe_version_resource"),
            (ollama.Kind, ollama.Scope, ollama.User, ollama.Version, ollama.VersionSource));
        var lm = Assert.Single(r.Installations, i => i.Runtime == "lm_studio");
        Assert.Equal(("local_programs", "user", "TEST\\bob", "0.3.27.0"), (lm.Kind, lm.Scope, lm.User!, lm.Version!));
        Assert.Equal(
            new[] { ("scoop", "6230", "scoop_version_dir"), ("winget_portable", (string?)null, "none") },
            r.Installations.Where(i => i.Runtime == "llama_cpp").Select(i => (i.Kind, i.Version, i.VersionSource))
                .OrderBy(t => t.Kind).ToArray());
    }

    [DirectoryLinkFact]
    public void Scan_OllamaStore_TwoModels_NamesTagsAndSizes()
    {
        BuildTree();
        var r = ScanAll();

        var models = r.Models!.Where(m => m.Runtime == "ollama").OrderBy(m => m.Name).ToArray();
        Assert.Equal(
            new[] { ("llama3.2", "latest", 1110L, 3, 0), ("qwen3", "14b", 2120L, 3, 0) },
            models.Select(m => (m.Name!, m.Tag!, m.SizeBytes!.Value, m.FileCount!.Value, m.MissingBlobs!.Value)).ToArray());
        Assert.All(models, m => Assert.Equal(("manifest", "read"), (m.SizeSource, m.MetadataStatus)));
        var store = Assert.Single(r.Stores, s => s.Runtime == "ollama");
        // The shared license blob is on disk once and counted once.
        Assert.Equal(("TEST\\alice", 2, 3130L, "complete"), (store.User!, store.ModelCount, store.TotalBytes, store.CollectionStatus));
    }

    [DirectoryLinkFact]
    public void Scan_OllamaNames_KeepTheirNamespaceAndRegistry_AndAMissingBlobIsCounted()
    {
        BuildTree();
        Manifest(Path.Combine(OllamaModels, "manifests", "hf.co", "bartowski", "Llama-3.2-1B-Instruct-GGUF", "Q4_K_M"), C1, 10, (A, 1000));
        Manifest(Path.Combine(OllamaModels, "manifests", "registry.ollama.ai", "MFDoom", "deepseek-coder-v2-tool-calling", "16b"), C1, 10, (new string('f', 64), 5));
        var r = ScanAll();

        Assert.Equal(
            new[] { "MFDoom/deepseek-coder-v2-tool-calling", "hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF", "llama3.2", "qwen3" },
            r.Models!.Where(m => m.Runtime == "ollama").Select(m => m.Name!).OrderBy(n => n, StringComparer.Ordinal).ToArray());
        var gone = Assert.Single(r.Models!, m => m.Tag == "16b");
        Assert.Equal((1, 15L), (gone.MissingBlobs!.Value, gone.SizeBytes!.Value));
        Assert.Equal(3130L, Assert.Single(r.Stores, s => s.Runtime == "ollama").TotalBytes);
        Assert.Equal(PackageCollectionStatus.Complete, Rt(r, "ollama"));
    }

    /// <summary>
    /// PAT-2040: a blob that is on disk but refused is unreadable, never missing. It is not in
    /// missing_blobs and not in the store total, the store is partial, and the refusal is a
    /// blob_unreadable issue at the blob's path.
    /// </summary>
    private void AssertBlobUnreadable(InventoryLocalModels r, string digest, string model)
    {
        Assert.Equal(0, Assert.Single(r.Models!, m => m.Name == model).MissingBlobs);
        Assert.True(HasIssue(r, "blob_unreadable", "sha256-" + digest));
        Assert.DoesNotContain(r.Issues, i => i.Code == "blob_unreadable" && !i.Path.EndsWith("sha256-" + digest, StringComparison.Ordinal));
        var store = Assert.Single(r.Stores, s => s.Runtime == "ollama");
        Assert.Equal(PackageCollectionStatus.Partial, store.CollectionStatus);
        Assert.Equal(PackageCollectionStatus.Partial, Rt(r, "ollama"));
    }

    [DirectoryLinkFact]
    public void Scan_ALinkedBlob_IsUnreadable_NotMissing()
    {
        BuildTree();
        var blob = Path.Combine(OllamaModels, "blobs", "sha256-" + A);
        File.Delete(blob);
        Sized(Path.Combine(_secret, "leaked-blob"), 1000);
        PlantFileLink(blob, Path.Combine(_secret, "leaked-blob"));
        var r = ScanAll();

        AssertNoLeak(r);
        AssertBlobUnreadable(r, A, "llama3.2");
        Assert.Equal(2130L, Assert.Single(r.Stores, s => s.Runtime == "ollama").TotalBytes);
    }

    [DirectoryLinkFact]
    public void Scan_ABlobFailingTheIdentityCheck_IsUnreadable_NotMissing()
    {
        BuildTree();
        var options = Options();
        var refused = "sha256-" + B;
        var r = ScanAll(new LocalModelScanOptions
        {
            MaxModels = options.MaxModels,
            TimeBudget = options.TimeBudget,
            ProgramFilesRoots = options.ProgramFilesRoots,
            ScoopGlobalRoot = null,
            VerifyOpenedFile = (handle, expected) =>
                !expected.EndsWith(refused, StringComparison.Ordinal)
                && (options.VerifyOpenedFile is not { } real || real(handle, expected)),
        });

        AssertBlobUnreadable(r, B, "qwen3");
        Assert.Equal(1130L, Assert.Single(r.Stores, s => s.Runtime == "ollama").TotalBytes);
    }

    /// <summary>
    /// PAT-2040: whether a blob is missing comes from one listing of the blobs directory, taken
    /// before any blob is looked at, never from testing each blob by path. Here the blobs
    /// directory is swapped for a link into another user's blobs just after the listing (when
    /// the model's manifest is opened). A blob only the other user has must still read as
    /// missing, never as unreadable or sized, and alice's own listed blob, now unreachable, is
    /// unreadable rather than missing, so the answer never depends on what the other user has.
    /// </summary>
    [DirectoryLinkFact]
    public void Scan_BlobsSwappedAfterTheListing_NeverAnswersForTheOtherUser()
    {
        BuildTree();
        string X = new('1', 64), Y = new('2', 64), Z = new('3', 64);
        var probe = Path.Combine(OllamaModels, "manifests", "registry.ollama.ai", "library", "probe", "latest");
        Manifest(probe, X, 1, (Y, 2), (Z, 3));
        Sized(Path.Combine(OllamaModels, "blobs", "sha256-" + X), 1);
        var otherBlobs = Path.Combine(_secret, "blobs");
        Sized(Path.Combine(otherBlobs, "sha256-" + Y), 77777);

        var options = Options();
        var blobs = Path.Combine(OllamaModels, "blobs");
        var swapped = false;
        var r = ScanAll(new LocalModelScanOptions
        {
            MaxModels = options.MaxModels,
            TimeBudget = options.TimeBudget,
            ProgramFilesRoots = options.ProgramFilesRoots,
            ScoopGlobalRoot = null,
            VerifyOpenedFile = (handle, expected) =>
            {
                if (!swapped && expected.EndsWith(Path.Combine("probe", "latest"), StringComparison.OrdinalIgnoreCase))
                {
                    swapped = true;
                    Directory.Move(blobs, blobs + "-moved");
                    PlantDirectoryLink(blobs, otherBlobs);
                }
                return options.VerifyOpenedFile is not { } real || real(handle, expected);
            },
        });

        Assert.True(swapped, "the swap never happened");
        var model = Assert.Single(r.Models!, m => m.Name == "probe");
        Assert.Equal(2, model.MissingBlobs);
        Assert.True(HasIssue(r, "blob_unreadable", "sha256-" + X));
        Assert.False(HasIssue(r, "blob_unreadable", "sha256-" + Y));
        Assert.DoesNotContain(r.Stores, st => st.TotalBytes >= 77777);
    }

    /// <summary>
    /// PAT-2040, the Scoop root swap: any user can create %ProgramData%\scoop, so it can be a
    /// real directory when the scan checks it and a junction into another profile when the
    /// root is registered. The root is registered from a handle opened on the root itself
    /// (never through a reparse point) whose final path must be the root's own, so the swapped
    /// root is refused, reported, and nothing under it is read. Windows only: the root check is
    /// WindowsFileIdentity's, which exists nowhere else.
    /// </summary>
    [DirectoryLinkFact]
    public void Scan_OnWindows_ScoopRootSwappedForAJunctionBeforeItIsRegistered_IsRefused()
    {
        if (!OperatingSystem.IsWindows()) return;
        BuildTree();
        var scoop = Dir(_root, "sys", "ProgramData", "scoop");
        var other = Path.Combine(_secret, "scoop");
        Sized(Path.Combine(other, "apps", "llama.cpp", "9999", "llama-server.exe"), 10);

        var options = Options();
        var swapped = false;
        var r = ScanAll(new LocalModelScanOptions
        {
            MaxModels = options.MaxModels,
            TimeBudget = options.TimeBudget,
            ProgramFilesRoots = options.ProgramFilesRoots,
            ScoopGlobalRoot = scoop,
            ResolveRootFinalPath = root =>
            {
                if (!swapped && string.Equals(root, scoop, StringComparison.OrdinalIgnoreCase))
                {
                    // Between the scan's KindOf and the registration, exactly the reviewer's window.
                    swapped = true;
                    Directory.Delete(scoop);
                    PlantDirectoryLink(scoop, other);
                }
                return options.ResolveRootFinalPath!(root);
            },
        });

        Assert.True(swapped, "the swap never happened");
        Assert.DoesNotContain(r.Installations, i => i.Kind == "scoop" && i.Scope == "system");
        Assert.DoesNotContain(r.Installations, i => i.Version == "9999");
        Assert.True(HasIssue(r, "symlink_not_followed", Path.Combine("ProgramData", "scoop")));
        Assert.Equal(PackageCollectionStatus.Partial, Rt(r, "llama_cpp"));
    }

    [DirectoryLinkFact]
    public void Scan_ALockedBlob_IsUnreadable_NotMissing()
    {
        BuildTree();
        using (new FileStream(Path.Combine(OllamaModels, "blobs", "sha256-" + L), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var r = ScanAll();
            Assert.True(HasIssue(r, "blob_unreadable", "sha256-" + L));
            Assert.All(r.Models!.Where(m => m.Runtime == "ollama"), m => Assert.Equal(0, m.MissingBlobs));
            Assert.Equal(3030L, Assert.Single(r.Stores, s => s.Runtime == "ollama").TotalBytes);
            Assert.Equal(PackageCollectionStatus.Partial, Rt(r, "ollama"));
        }
    }

    [DirectoryLinkFact]
    public void Scan_LmStudioStores_EachGgufIsAModel_AndAnMlxRepoIsOne()
    {
        BuildTree();
        var r = ScanAll();

        Assert.Equal(
            new[]
            {
                ("TheBloke/old-GGUF", "old.Q4_0", "gguf", 700L, 1),
                ("lmstudio-community/Qwen3-8B-GGUF", "Qwen3-8B-Q4_K_M", "gguf", 3000L, 1),
                ("lmstudio-community/Qwen3-8B-GGUF", "Qwen3-8B-Q8_0", "gguf", 5000L, 1),
            },
            r.Models!.Where(m => m.Format == "gguf").Select(m => (m.Name!, m.Tag!, m.Format!, m.SizeBytes!.Value, m.FileCount!.Value))
                .OrderBy(t => t.Item1, StringComparer.Ordinal).ThenBy(t => t.Item2, StringComparer.Ordinal).ToArray());
        var mlx = Assert.Single(r.Models!, m => m.Format == "safetensors");
        Assert.Equal(("mlx-community/Llama-3.2-3B-Instruct-4bit", (string?)null, 4110L, 3), (mlx.Name!, mlx.Tag, mlx.SizeBytes!.Value, mlx.FileCount!.Value));
        Assert.All(r.Models!.Where(m => m.Runtime == "lm_studio"), m => Assert.Equal(("stat", (string?)null), (m.SizeSource, m.MetadataStatus)));
        Assert.Equal(
            new[] { (2, 12810L) },
            new[] { (r.Stores.Count(s => s.Runtime == "lm_studio"), r.Stores.Where(s => s.Runtime == "lm_studio").Sum(s => s.TotalBytes)) });
        Assert.Equal(
            new[] { ("ollama", 1, 1, 2, 3130L), ("lm_studio", 1, 2, 4, 12810L), ("llama_cpp", 2, 0, 0, 0L) },
            LocalModelRuntime.All.Select(x => (x, r.Runtimes[x].InstallationCount, r.Runtimes[x].StoreCount, r.Runtimes[x].ModelCount, r.Runtimes[x].TotalBytes)).ToArray());
        Assert.Equal((6, 15940L), (r.Totals.ModelCount, r.Totals.TotalBytes));
    }

    // -------------------------------------------------------------------------
    // Empty stores and missing runtimes
    // -------------------------------------------------------------------------

    [DirectoryLinkFact]
    public void Scan_EmptyStores_AreComplete_WithZeroModels()
    {
        BuildTree();
        DeleteTree(Path.Combine(OllamaModels, "manifests"));
        DeleteTree(Path.Combine(OllamaModels, "blobs"));
        Directory.CreateDirectory(Path.Combine(OllamaModels, "manifests"));
        DeleteTree(LmModels);
        Directory.CreateDirectory(LmModels);
        DeleteTree(Path.Combine(Home("bob"), ".cache"));
        var r = ScanAll();

        Assert.Equal(PackageCollectionStatus.Complete, r.CollectionStatus);
        Assert.NotNull(r.Models);
        Assert.Empty(r.Models!);
        Assert.Equal(
            new[] { ("lm_studio", "complete", 0), ("ollama", "complete", 0) },
            r.Stores.Select(s => (s.Runtime, s.CollectionStatus, s.ModelCount)).OrderBy(t => t.Runtime).ToArray());
        Assert.Contains("\"models\":[]", Serialise(r));
    }

    [Fact]
    public void Scan_MissingRuntime_IsNotPresent()
    {
        Directory.CreateDirectory(Path.Combine(Users, "dave", "Documents"));
        Directory.CreateDirectory(Path.Combine(Users, "erin", ".ollama"));
        Directory.CreateDirectory(ProgramFiles);
        var r = LocalModelScanLogic.Scan(Profiles("dave", "erin").ToList(), Options());

        Assert.Equal(PackageCollectionStatus.NotPresent, r.CollectionStatus);
        Assert.All(LocalModelRuntime.All, x => Assert.Equal(PackageCollectionStatus.NotPresent, Rt(r, x)));
        Assert.Empty(r.Models!);
        Assert.Empty(r.Installations);
        Assert.Empty(r.Stores);
    }

    [DirectoryLinkFact]
    public void Scan_OneRuntimeRemoved_IsNotPresent_OthersUnaffected()
    {
        BuildTree();
        DeleteTree(Path.Combine(ProgramFiles, "WinGet"));
        DeleteTree(Path.Combine(Home("alice"), "scoop"));
        var r = ScanAll();

        Assert.Equal(PackageCollectionStatus.NotPresent, Rt(r, "llama_cpp"));
        Assert.Equal(PackageCollectionStatus.Complete, Rt(r, "ollama"));
        Assert.Equal(PackageCollectionStatus.Complete, Rt(r, "lm_studio"));
    }

    // -------------------------------------------------------------------------
    // Links are never followed
    // -------------------------------------------------------------------------

    [DirectoryLinkFact]
    public void Scan_LinkedLmStudioModelsDir_IsNotFollowed_AndIsPartial()
    {
        BuildTree();
        DeleteTree(LmModels);
        PlantDirectoryLink(LmModels, _secret);
        var r = ScanAll();

        AssertNoLeak(r);
        Assert.True(HasIssue(r, "symlink_not_followed", Path.Combine(".lmstudio", "models")));
        Assert.Equal(PackageCollectionStatus.Partial, Rt(r, "lm_studio"));
        Assert.Equal(PackageCollectionStatus.Partial, r.CollectionStatus);
        Assert.Equal("partial", r.Users.Single(u => u.User == "TEST\\bob").Runtimes["lm_studio"]);
        // The linked store is neither read nor claimed; the older store still is.
        Assert.Equal(new[] { Path.Combine(".cache", "lm-studio", "models") },
            r.Stores.Where(s => s.Runtime == "lm_studio").Select(s => Path.GetRelativePath(Home("bob"), s.Path)).ToArray());
        Assert.Equal(PackageCollectionStatus.Complete, Rt(r, "ollama"));
    }

    [DirectoryLinkFact]
    public void Scan_LinkedOllamaModelsDir_IsNotFollowed_AndIsPartial()
    {
        BuildTree();
        DeleteTree(OllamaModels);
        PlantDirectoryLink(OllamaModels, _secret);
        var r = ScanAll();

        AssertNoLeak(r);
        Assert.True(HasIssue(r, "symlink_not_followed", Path.Combine(".ollama", "models")));
        Assert.Equal(PackageCollectionStatus.Partial, Rt(r, "ollama"));
    }

    [DirectoryLinkFact]
    public void Scan_LinkedBlobsDir_IsNotLookedInto_SizesFallBackToManifests()
    {
        BuildTree();
        DeleteTree(Path.Combine(OllamaModels, "blobs"));
        PlantDirectoryLink(Path.Combine(OllamaModels, "blobs"), _secret);
        var r = ScanAll();

        AssertNoLeak(r);
        Assert.Equal(PackageCollectionStatus.Partial, Rt(r, "ollama"));
        Assert.All(r.Models!.Where(m => m.Runtime == "ollama"), m => Assert.Null(m.MissingBlobs));
        Assert.Equal(3130L, Assert.Single(r.Stores, s => s.Runtime == "ollama").TotalBytes);
    }

    [DirectoryLinkFact]
    public void Scan_LinkedManifest_IsRefused_AndTheModelIsKeptUnsized()
    {
        BuildTree();
        File.Delete(Qwen);
        PlantFileLink(Qwen, Path.Combine(_secret, "leaked-manifest"));
        var r = ScanAll();

        AssertNoLeak(r);
        Assert.Equal(PackageCollectionStatus.Partial, Rt(r, "ollama"));
        Assert.DoesNotContain(r.Models!, m => m.Tag == "14b" && m.SizeBytes is not null);
    }

    [DirectoryLinkFact]
    public void Scan_LinkedGgufPublisherAndRepo_AreRecorded_NotStatted()
    {
        BuildTree();
        PlantFileLink(Path.Combine(LmModels, "lmstudio-community", "Qwen3-8B-GGUF", "planted.gguf"),
            Path.Combine(_secret, "leaked-publisher", "leaked-repo", "leaked.gguf"));
        PlantDirectoryLink(Path.Combine(LmModels, "planted-publisher"), Path.Combine(_secret, "leaked-publisher"));
        PlantDirectoryLink(Path.Combine(LmModels, "mlx-community", "planted-repo"), Path.Combine(_secret, "leaked-publisher", "leaked-repo"));
        var r = ScanAll();

        AssertNoLeak(r);
        Assert.True(HasIssue(r, "symlink_not_followed", "planted-publisher"));
        Assert.True(HasIssue(r, "symlink_not_followed", "planted-repo"));
        Assert.Equal(PackageCollectionStatus.Partial, Rt(r, "lm_studio"));
        Assert.Equal(4, r.Models!.Count(m => m.Runtime == "lm_studio"));
    }

    [DirectoryLinkFact]
    public void Scan_LinkedInstallDir_IsNotFollowed()
    {
        BuildTree();
        DeleteTree(Path.Combine(ProgramFiles, "Ollama"));
        PlantDirectoryLink(Path.Combine(ProgramFiles, "Ollama"), _secret);
        var r = ScanAll();

        AssertNoLeak(r);
        Assert.True(HasIssue(r, "symlink_not_followed", Path.Combine("Program Files", "Ollama")));
        Assert.Equal(PackageCollectionStatus.Partial, Rt(r, "ollama"));
        Assert.DoesNotContain(r.Installations, i => i.Runtime == "ollama");
    }

    [DirectoryLinkFact]
    public void Scan_ScoopCurrentPointingElsewhere_IsNotFollowed_AndIsPartial()
    {
        BuildTree();
        var current = Path.Combine(Home("alice"), "scoop", "apps", "llama.cpp", "current");
        Directory.Delete(current);
        PlantDirectoryLink(current, _secret);
        var r = ScanAll();

        Assert.True(HasIssue(r, "symlink_not_followed", "current"));
        Assert.Equal(PackageCollectionStatus.Partial, Rt(r, "llama_cpp"));
    }

    // -------------------------------------------------------------------------
    // An unreadable or corrupt manifest is partial, never empty
    // -------------------------------------------------------------------------

    [DirectoryLinkFact]
    public void Scan_UnreadableManifest_IsPartial_AndTheModelIsStillListed()
    {
        BuildTree();
        InventoryLocalModels? r = null;
        if (!WithUnreadable(Qwen, () => r = ScanAll())) return;

        Assert.Equal(PackageCollectionStatus.Partial, r!.CollectionStatus);
        Assert.Equal(PackageCollectionStatus.Partial, Rt(r, "ollama"));
        var row = Assert.Single(r.Models!, m => m.Tag == "14b");
        Assert.Equal(("qwen3", (long?)null, "unreadable"), (row.Name!, row.SizeBytes, row.MetadataStatus!));
        Assert.True(HasIssue(r, "manifest_unreadable", "14b"));
        Assert.Equal("partial", Assert.Single(r.Stores, s => s.Runtime == "ollama").CollectionStatus);
        Assert.Contains(r.Models!, m => m.Tag == "latest" && m.SizeBytes == 1110);
        Assert.Equal(PackageCollectionStatus.Complete, Rt(r, "lm_studio"));
    }

    [DirectoryLinkTheory]
    [InlineData("{not json")]
    [InlineData("{\"layers\":[{\"digest\":\"sha256:../../../root-only/leaked-manifest\",\"size\":1}]}")]
    [InlineData("{\"layers\":[{\"digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"size\":true}]}")]
    [InlineData("{\"layers\":[{\"digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"size\":-1}]}")]
    [InlineData("[]")]
    public void Scan_CorruptManifest_IsUnparseable_AndPartial(string content)
    {
        BuildTree();
        File.WriteAllText(Qwen, content);
        var r = ScanAll();

        AssertNoLeak(r);
        Assert.Equal(PackageCollectionStatus.Partial, Rt(r, "ollama"));
        Assert.Equal("unparseable", Assert.Single(r.Models!, m => m.Tag == "14b").MetadataStatus);
    }

    [DirectoryLinkFact]
    public void Scan_UnversionableExecutable_IsStillAnInstallation_AndCorruptOneIsPartial()
    {
        BuildTree();
        File.WriteAllBytes(Path.Combine(ProgramFiles, "Ollama", "ollama app.exe"), Encoding.ASCII.GetBytes("MZ not really a PE"));
        File.WriteAllBytes(Path.Combine(ProgramFiles, "Ollama", "ollama.exe"), PeFixture.WithoutVersion());
        var r = ScanAll();

        var ollama = Assert.Single(r.Installations, i => i.Runtime == "ollama");
        Assert.Equal(((string?)null, "none"), (ollama.Version, ollama.VersionSource));
        Assert.True(HasIssue(r, "pe_unparseable", "ollama app.exe"));
        Assert.Equal(PackageCollectionStatus.Partial, Rt(r, "ollama"));
    }

    // -------------------------------------------------------------------------
    // Failed, bounds
    // -------------------------------------------------------------------------

    [DirectoryLinkFact]
    public void Scan_NothingReadable_IsFailed_WithModelsOmitted()
    {
        BuildTree();
        DeleteTree(Path.Combine(_root, "sys"));
        Directory.CreateDirectory(ProgramFiles);
        File.WriteAllText(Path.Combine(ProgramFiles, "Ollama"), "");
        File.WriteAllText(Path.Combine(ProgramFiles, "LM Studio"), "");
        Directory.CreateDirectory(Path.Combine(ProgramFiles, "WinGet"));
        File.WriteAllText(Path.Combine(ProgramFiles, "WinGet", "Packages"), "");
        var r = LocalModelScanLogic.Scan(null, Options());

        Assert.Equal(PackageCollectionStatus.Failed, r.CollectionStatus);
        Assert.All(LocalModelRuntime.All, x => Assert.Equal(PackageCollectionStatus.Failed, Rt(r, x)));
        Assert.Null(r.Models);
        Assert.DoesNotContain("\"models\"", Serialise(r));
    }

    [DirectoryLinkFact]
    public void Scan_UnreadableProfileList_WithTheMachineRead_IsPartial_NeverNotPresent()
    {
        BuildTree();
        var r = LocalModelScanLogic.Scan(null, Options());

        Assert.Equal(PackageCollectionStatus.Partial, r.CollectionStatus);
        Assert.All(LocalModelRuntime.All, x => Assert.Equal(PackageCollectionStatus.Partial, Rt(r, x)));
    }

    [DirectoryLinkFact]
    public void Scan_PastTheModelLimit_IsPartial()
    {
        BuildTree();
        var r = ScanAll(Options(max: 2));

        Assert.Equal(PackageCollectionStatus.Partial, r.CollectionStatus);
        Assert.Equal(("model_limit", 2), (r.TruncationReason!, r.Models!.Count));
        Assert.Equal(PackageCollectionStatus.Partial, Rt(r, "lm_studio"));
    }

    [DirectoryLinkFact]
    public void Scan_PastTheTimeBudget_IsPartial_AndNothingClaimsComplete()
    {
        BuildTree();
        var r = ScanAll(Options(budget: TimeSpan.Zero));

        Assert.Equal(PackageCollectionStatus.Partial, r.CollectionStatus);
        Assert.Equal("time_limit", r.TruncationReason);
        Assert.All(LocalModelRuntime.All, x => Assert.NotEqual(PackageCollectionStatus.Complete, Rt(r, x)));
    }

    /// <summary>
    /// The Service scanner cancels the token when its hard timeout abandons the scan: the scan
    /// stops at its next budget check, reads nothing further and never claims complete.
    /// </summary>
    [DirectoryLinkFact]
    public void Scan_CancelledByTheHardTimeout_StopsAndIsNotComplete()
    {
        BuildTree();
        var options = Options();
        var r = ScanAll(new LocalModelScanOptions
        {
            ProgramFilesRoots = options.ProgramFilesRoots,
            ScoopGlobalRoot = null,
            Cancellation = new CancellationToken(canceled: true),
        });

        Assert.NotEqual(PackageCollectionStatus.Complete, r.CollectionStatus);
        Assert.True(r.Truncated);
        Assert.Empty(r.Models ?? []);
        Assert.Empty(r.Installations);
    }

    // -------------------------------------------------------------------------
    // PE version resource
    // -------------------------------------------------------------------------

    private static (string Status, string? Version) ReadPe(byte[] bytes) =>
        PeVersionReader.Read((offset, destination) =>
        {
            if (offset >= bytes.Length) return 0;
            var n = (int)Math.Min(destination.Length, bytes.Length - offset);
            bytes.AsSpan((int)offset, n).CopyTo(destination);
            return n;
        });

    [Fact]
    public void PeVersionReader_ReadsTheFixedProductVersion()
    {
        Assert.Equal(("read", "1.22.333.4444"), ReadPe(PeFixture.WithVersion(1, 22, 333, 4444)));
        Assert.Equal(("none", (string?)null), ReadPe(PeFixture.WithoutVersion()));
    }

    [Fact]
    public void PeVersionReader_RefusesMalformedInput()
    {
        Assert.Equal("unparseable", ReadPe(Encoding.ASCII.GetBytes("not a pe at all")).Status);
        Assert.Equal("unparseable", ReadPe(PeFixture.WithVersion(1, 2, 3, 4)[..0x220]).Status);
        var badSignature = PeFixture.WithVersion(1, 2, 3, 4);
        badSignature[0x80] = (byte)'X';
        Assert.Equal("unparseable", ReadPe(badSignature).Status);
        var hugeOffset = PeFixture.WithVersion(1, 2, 3, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(hugeOffset.AsSpan(0x3C), 0x7FFF_FFFF);
        Assert.Equal("unparseable", ReadPe(hugeOffset).Status);
    }

    /// <summary>On Windows, the reader agrees with the OS's own reading of a real system binary.</summary>
    [Fact]
    public void PeVersionReader_AgreesWithWindows_OnARealBinary()
    {
        if (!OperatingSystem.IsWindows()) return;
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var (status, version) = PeVersionReader.Read((offset, destination) => RandomAccess.Read(handle, destination, offset));
        var info = FileVersionInfo.GetVersionInfo(path);
        Assert.Equal("read", status);
        Assert.Equal($"{info.ProductMajorPart}.{info.ProductMinorPart}.{info.ProductBuildPart}.{info.ProductPrivatePart}", version);
    }

    // -------------------------------------------------------------------------
    // Nothing is executed, nothing is networked, nothing private is read
    // -------------------------------------------------------------------------

    public static IEnumerable<object[]> CollectorSources() =>
    [
        [Path.Combine("Shared", "LocalModels", "LocalModelScanLogic.cs")],
        [Path.Combine("Shared", "LocalModels", "PeVersionReader.cs")],
        [Path.Combine("Shared", "UserTrees", "UserTreeReader.cs")],
        [Path.Combine("Service", "LocalModelScanner.cs")],
    ];

    [Theory]
    [MemberData(nameof(CollectorSources))]
    public void CollectorSource_ExecutesNothing_AndOpensNoNetwork(string relative) =>
        CollectorSourceGuard.AssertExecutesNothing(relative, new HashSet<string>(StringComparer.Ordinal)
        {
            "System.Buffers.Binary", "System.Diagnostics", "System.Runtime.Versioning", "System.Text",
            "System.Text.Json", "System.Text.RegularExpressions", "Microsoft.Win32.SafeHandles",
            "Patched.Shared.Contract", "Patched.Shared.IdeExtensions", "Patched.Shared.LocalModels",
            "Patched.Shared.UserTrees",
        });

    private static string ScanCode() => CollectorSourceGuard.Code(
        File.ReadAllText(CollectorSourceGuard.SourceFile(Path.Combine("Shared", "LocalModels", "LocalModelScanLogic.cs"))));

    /// <summary>
    /// PAT-2019 privacy rule, names and sizes only: the scan reads exactly two kinds of file,
    /// an Ollama manifest (ReadFile) and an executable's headers (ReadRanges, into
    /// PeVersionReader), and nothing else; a blob is only opened for its length (StatLength,
    /// PAT-2033). A third read site, any direct file API, or a name
    /// for a history, conversation, prompt, key, log or settings file turns this red.
    /// </summary>
    [Fact]
    public void CollectorSource_ReadsOnlyManifestsAndExecutableHeaders()
    {
        var code = ScanCode();
        Assert.Single(Regex.Matches(code, @"_reader\.ReadFile\(path, ManifestCap\)"));
        Assert.Single(Regex.Matches(code, @"_reader\.ReadRanges\(exe, ExecutableCap, read => PeVersionReader\.Read\(read\)\)"));
        Assert.Equal(2, Regex.Matches(code, @"_reader\.Read\w*\(").Count);
        Assert.Empty(CollectorSourceGuard.Hits(code, PrivateFiles));
        Assert.Empty(CollectorSourceGuard.Hits(code, DirectFileAccess));
        Assert.Empty(CollectorSourceGuard.Hits(CollectorSourceGuard.Code(
            File.ReadAllText(CollectorSourceGuard.SourceFile(Path.Combine("Shared", "LocalModels", "PeVersionReader.cs")))), DirectFileAccess));
        // A blob path only ever reaches StatLength, and (PAT-2040) the issue that records a
        // refused blob by its path: it is built once and used nowhere else.
        Assert.Single(Regex.Matches(code, @"""sha256-"" \+ digest"));
        Assert.Single(Regex.Matches(code, @"var blobName = ""sha256-"" \+ digest;"));
        Assert.Single(Regex.Matches(code, @"var blob = Path\.Combine\(blobs, blobName\);"));
        Assert.Equal(
            new[] { "_reader.StatLength(blob, listed)", "Issue(\"blob_unreadable\", blob)" },
            Regex.Matches(code, @"[\w.]+\([^()]*\bblob\b[^()]*\)").Select(m => m.Value).ToArray());
        Assert.Equal(3, Regex.Matches(code, @"\bblob\b").Count);
    }

    private static readonly Regex PrivateFiles = new(
        @"history|conversation|\bchats?\b|prompt|id_ed25519|\.pub\b|\blogs?\b|settings|\.sqlite|\.db\b",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex DirectFileAccess = new(
        @"File\.(Open|Read|OpenRead|OpenHandle|OpenText)|FileStream|StreamReader|MemoryMapped|RandomAccess\.",
        RegexOptions.CultureInvariant);

    /// <summary>The guards above can fail: each goes red on a line that breaks its rule.</summary>
    [Fact]
    public void CollectorSourceGuards_CatchWhatTheyAreFor()
    {
        Assert.NotEmpty(CollectorSourceGuard.Hits("var p = Process.Start(\"ollama.exe\");", CollectorSourceGuard.ExecOrNetwork));
        Assert.NotEmpty(CollectorSourceGuard.Hits("await new HttpClient().GetAsync(\"http://localhost:11434/api/tags\");", CollectorSourceGuard.ExecOrNetwork));
        Assert.NotEmpty(CollectorSourceGuard.Hits("var u = \"http://127.0.0.1:1234/v1/models\";", CollectorSourceGuard.ExecOrNetwork));
        Assert.NotEmpty(CollectorSourceGuard.Hits("_reader.ReadFile(Path.Combine(home, \".ollama\", \"history\"), cap);", PrivateFiles));
        Assert.NotEmpty(CollectorSourceGuard.Hits("Walk(home, \".lmstudio\", \"conversations\");", PrivateFiles));
        Assert.NotEmpty(CollectorSourceGuard.Hits("using var s = File.OpenRead(blob);", DirectFileAccess));
    }

    /// <summary>
    /// PAT-2050, the Scoop root swapped after it is registered: %ProgramData%\scoop passes
    /// AddRoot as a real directory and is then swapped for a junction into another profile.
    /// Whether an app is there comes only from a verified listing of its parent, which refuses
    /// the swapped root whatever it points at, so the scan is the same, and partial, whether
    /// the other profile lacks or has scoop\apps\llama.cpp: never complete-and-empty, and
    /// never an answer about the other profile. Windows only: the refusal is the handle
    /// lister's.
    /// </summary>
    [DirectoryLinkFact]
    public void Scan_OnWindows_ScoopRootSwappedAfterItIsRegistered_IsPartialAndTheSameWhateverTheTargetHolds()
    {
        if (!OperatingSystem.IsWindows()) return;
        BuildTree();
        var scoop = Dir(_root, "sys", "ProgramData", "scoop");
        Sized(Path.Combine(scoop, "apps", "llama.cpp", "6000", "llama-server.exe"), 10);
        var other = Dir(_secret, "scoop");
        InventoryLocalModels Run()
        {
            var swap = new RootSwap(scoop, other);
            var options = Options();
            var r = ScanAll(new LocalModelScanOptions
            {
                MaxModels = options.MaxModels,
                TimeBudget = options.TimeBudget,
                ProgramFilesRoots = options.ProgramFilesRoots,
                ScoopGlobalRoot = scoop,
                ResolveRootFinalPath = swap.Wrap(options.ResolveRootFinalPath),
            });
            Assert.True(swap.Swapped, "the swap never happened");
            swap.Restore();
            return r;
        }

        var lacking = Run();
        Sized(Path.Combine(other, "apps", "llama.cpp", "9999", "llama-server.exe"), 10);
        Sized(Path.Combine(other, "apps", "ollama", "9998", "ollama.exe"), 10);
        var having = Run();

        Assert.Equal(Serialise(lacking), Serialise(having));
        AssertNoLeak(having);
        Assert.DoesNotContain(having.Installations, i => i.Kind == "scoop" && i.Scope == "system");
        Assert.Equal(PackageCollectionStatus.Partial, Rt(lacking, LocalModelRuntime.LlamaCpp));
        Assert.Equal(PackageCollectionStatus.Partial, Rt(lacking, LocalModelRuntime.Ollama));
        Assert.True(HasIssue(lacking, "unreadable", Path.Combine("ProgramData", "scoop")));
    }

    /// <summary>
    /// PAT-2052, Scoop's "current" link read after its app directory was swapped: the scan
    /// lists scoop\apps\llama.cpp (a real directory with 6000 and a "current" junction to it)
    /// and the user then swaps that directory for a junction into another profile. The link's
    /// target is read only from a handle on the link whose final path is checked, so it is
    /// refused (symlink_not_followed, partial) the same whether the other profile has no
    /// "current" or one pointing at the very version path the scan would accept as an alias:
    /// one bit about the other profile, and never a complete answer. Windows only: the check
    /// is the handle reader's.
    /// </summary>
    [DirectoryLinkFact]
    public void Scan_OnWindows_ScoopAppSwappedAfterItIsListed_CurrentIsRefused_TheSameWhateverTheTargetHolds()
    {
        if (!OperatingSystem.IsWindows()) return;
        BuildTree();
        var scoop = Dir(_root, "sys", "ProgramData", "scoop");
        var app = Dir(scoop, "apps", "llama.cpp");
        Sized(Path.Combine(app, "6000", "llama-server.exe"), 10);
        PlantDirectoryLink(Path.Combine(app, "current"), Path.Combine(app, "6000"));
        var other = Dir(_secret, "scoop", "apps", "llama.cpp");
        Dir(other, "6000");
        var parked = app + "-listed";

        InventoryLocalModels Run()
        {
            var swapped = false;
            var real = UserTreeReader.DefaultLister();
            var options = Options();
            try
            {
                return ScanAll(new LocalModelScanOptions
                {
                    MaxModels = options.MaxModels,
                    TimeBudget = options.TimeBudget,
                    ProgramFilesRoots = options.ProgramFilesRoots,
                    ScoopGlobalRoot = scoop,
                    ListOpenedDirectory = (path, expected) =>
                    {
                        var rows = real(path, expected);
                        if (!swapped && string.Equals(Path.TrimEndingDirectorySeparator(path), app, StringComparison.OrdinalIgnoreCase))
                        {
                            swapped = true;
                            Directory.Move(app, parked);
                            DirectoryLinks.Plant(app, other);
                        }
                        return rows;
                    },
                });
            }
            finally
            {
                Assert.True(swapped, "the swap never happened");
                Directory.Delete(app);
                Directory.Move(parked, app);
            }
        }

        var lacking = Run();
        PlantDirectoryLink(Path.Combine(other, "current"), Path.Combine(app, "6000"));
        var having = Run();

        Assert.Equal(Serialise(lacking), Serialise(having));
        AssertNoLeak(having);
        Assert.True(HasIssue(lacking, "symlink_not_followed", Path.Combine("ProgramData", "scoop", "apps", "llama.cpp", "current")));
        Assert.False(HasIssue(lacking, "alias_not_followed", Path.Combine("ProgramData", "scoop", "apps", "llama.cpp", "current")));
        Assert.Equal(PackageCollectionStatus.Partial, Rt(lacking, LocalModelRuntime.LlamaCpp));
    }

    /// <summary>
    /// PAT-2052: a scan lists each directory at most once, however many walks and kind checks
    /// land below it, and the next scan lists again: the listing cache belongs to one scan.
    /// </summary>
    [DirectoryLinkFact]
    public void Scan_ListsEachDirectoryOncePerScan_AndAgainInTheNextScan()
    {
        BuildTree();
        var calls = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var real = UserTreeReader.DefaultLister();
        var options = Options();
        LocalModelScanOptions Counting() => new()
        {
            MaxModels = options.MaxModels,
            TimeBudget = options.TimeBudget,
            ProgramFilesRoots = options.ProgramFilesRoots,
            ScoopGlobalRoot = null,
            ListOpenedDirectory = (path, expected) =>
            {
                calls[expected] = calls.GetValueOrDefault(expected) + 1;
                return real(path, expected);
            },
        };

        var first = ScanAll(Counting());
        Assert.Equal(PackageCollectionStatus.Complete, first.CollectionStatus);
        Assert.True(calls.Count > 10, $"only {calls.Count} directories listed");
        Assert.All(calls, c => Assert.True(c.Value == 1, $"{c.Key} listed {c.Value} times in one scan"));

        ScanAll(Counting());
        Assert.All(calls, c => Assert.True(c.Value == 2, $"{c.Key} listed {c.Value} times over two scans"));
    }

    /// <summary>
    /// PAT-2050: a %ProgramData%\scoop that is already a junction when the scan starts is
    /// refused and recorded, never skipped as though there were no global scoop.
    /// </summary>
    [DirectoryLinkFact]
    public void Scan_ScoopRootThatIsAlreadyALink_IsRefused_NotSkipped()
    {
        BuildTree();
        var other = Dir(_secret, "scoop");
        Sized(Path.Combine(other, "apps", "llama.cpp", "9999", "llama-server.exe"), 10);
        var scoop = Path.Combine(_root, "sys", "ProgramData", "scoop");
        PlantDirectoryLink(scoop, other);
        var options = Options();
        var r = ScanAll(new LocalModelScanOptions
        {
            MaxModels = options.MaxModels,
            TimeBudget = options.TimeBudget,
            ProgramFilesRoots = options.ProgramFilesRoots,
            ScoopGlobalRoot = scoop,
        });

        Assert.DoesNotContain(r.Installations, i => i.Version == "9999");
        Assert.True(HasIssue(r, "symlink_not_followed", Path.Combine("ProgramData", "scoop")));
        Assert.Equal(PackageCollectionStatus.Partial, Rt(r, LocalModelRuntime.LlamaCpp));
    }
}

/// <summary>
/// A minimal PE32+ image with one .rsrc section, built byte by byte, carrying an RT_VERSION
/// resource (VS_VERSIONINFO with VS_FIXEDFILEINFO) or none. It is never executed; it exists so
/// the version reader can be tested on every platform without a real Windows binary.
/// </summary>
internal static class PeFixture
{
    private const int PeOffset = 0x80;
    private const int RawOffset = 0x200;
    private const uint RsrcRva = 0x1000;

    public static byte[] WithVersion(ushort a, ushort b, ushort c, ushort d) => Build(((uint)a << 16) | b, ((uint)c << 16) | d);

    public static byte[] WithoutVersion() => Build(null, null);

    private static byte[] Build(uint? ms, uint? ls)
    {
        const int versionAt = 0x58;
        const int versionLength = 92;
        var rsrcLength = ms is null ? 0 : versionAt + versionLength;
        var image = new byte[RawOffset + Math.Max(rsrcLength, 16)];
        var s = image.AsSpan();
        s[0] = (byte)'M'; s[1] = (byte)'Z';
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x3C..], PeOffset);
        "PE\0\0"u8.CopyTo(s[PeOffset..]);
        BinaryPrimitives.WriteUInt16LittleEndian(s[(PeOffset + 4)..], 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(s[(PeOffset + 6)..], 1);
        BinaryPrimitives.WriteUInt16LittleEndian(s[(PeOffset + 20)..], 240);
        var opt = PeOffset + 24;
        BinaryPrimitives.WriteUInt16LittleEndian(s[opt..], 0x20B);
        BinaryPrimitives.WriteUInt32LittleEndian(s[(opt + 108)..], 16);
        if (ms is not null)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(s[(opt + 112 + 16)..], RsrcRva);
            BinaryPrimitives.WriteUInt32LittleEndian(s[(opt + 112 + 20)..], (uint)rsrcLength);
        }
        var section = opt + 240;
        ".rsrc"u8.CopyTo(s[section..]);
        BinaryPrimitives.WriteUInt32LittleEndian(s[(section + 8)..], (uint)Math.Max(rsrcLength, 16));
        BinaryPrimitives.WriteUInt32LittleEndian(s[(section + 12)..], RsrcRva);
        BinaryPrimitives.WriteUInt32LittleEndian(s[(section + 16)..], (uint)Math.Max(rsrcLength, 16));
        BinaryPrimitives.WriteUInt32LittleEndian(s[(section + 20)..], RawOffset);
        if (ms is null) return image;

        var r = s[RawOffset..];
        // Type directory -> RT_VERSION (16) -> name directory -> id 1 -> language directory -> 0x409 -> data entry.
        BinaryPrimitives.WriteUInt16LittleEndian(r[14..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(r[16..], 16);
        BinaryPrimitives.WriteUInt32LittleEndian(r[20..], 0x8000_0000 | 0x18);
        BinaryPrimitives.WriteUInt16LittleEndian(r[(0x18 + 14)..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(r[(0x18 + 16)..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(r[(0x18 + 20)..], 0x8000_0000 | 0x30);
        BinaryPrimitives.WriteUInt16LittleEndian(r[(0x30 + 14)..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(r[(0x30 + 16)..], 0x409);
        BinaryPrimitives.WriteUInt32LittleEndian(r[(0x30 + 20)..], 0x48);
        BinaryPrimitives.WriteUInt32LittleEndian(r[0x48..], RsrcRva + versionAt);
        BinaryPrimitives.WriteUInt32LittleEndian(r[(0x48 + 4)..], versionLength);
        var v = r[versionAt..];
        BinaryPrimitives.WriteUInt16LittleEndian(v, versionLength);
        BinaryPrimitives.WriteUInt16LittleEndian(v[2..], 52);
        Encoding.Unicode.GetBytes("VS_VERSION_INFO\0").CopyTo(v[6..]);
        BinaryPrimitives.WriteUInt32LittleEndian(v[40..], 0xFEEF04BD);
        BinaryPrimitives.WriteUInt32LittleEndian(v[44..], 0x0001_0000);
        BinaryPrimitives.WriteUInt32LittleEndian(v[48..], ms.Value);
        BinaryPrimitives.WriteUInt32LittleEndian(v[52..], ls!.Value);
        BinaryPrimitives.WriteUInt32LittleEndian(v[56..], ms.Value);
        BinaryPrimitives.WriteUInt32LittleEndian(v[60..], ls.Value);
        return image;
    }
}
