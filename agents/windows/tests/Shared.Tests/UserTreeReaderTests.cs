using System.Buffers.Binary;
using System.Text;
using Patched.Shared.IdeExtensions;
using Patched.Shared.UserTrees;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>PAT-2033: the shared file-safety primitives, where no collector test pins them.</summary>
public sealed class UserTreeReaderTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("patched-user-tree-").FullName;

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    /// <summary>
    /// A length is read from the handle OpenRegular returns, after the same post-open identity
    /// check a read gets, never from the path: a file the check refuses has no length.
    /// </summary>
    [Fact]
    public void StatLength_ComesThroughTheVerifiedHandle()
    {
        var file = Path.Combine(_root, "sha256-blob");
        File.WriteAllBytes(file, new byte[1234]);

        var checkedPaths = new List<string>();
        var trusting = new UserTreeReader((_, expected) => { checkedPaths.Add(expected); return true; }, null);
        Assert.Equal(("open", (long?)1234), trusting.StatLength(file));
        Assert.Equal(new[] { file }, checkedPaths);

        // PAT-2040: refused is unreadable, never missing: the file is there.
        var refusing = new UserTreeReader((_, _) => false, null);
        Assert.Equal(("unreadable", (long?)null), refusing.StatLength(file));
    }

    [Fact]
    public void StatLength_OfADirectoryIsUnreadable_AndOfNothingIsMissing()
    {
        var reader = new UserTreeReader(null, null);
        Assert.Equal(("unreadable", (long?)null), reader.StatLength(Directory.CreateDirectory(Path.Combine(_root, "dir")).FullName));
        Assert.Equal(("missing", (long?)null), reader.StatLength(Path.Combine(_root, "absent")));
        Assert.Equal(("missing", (long?)null), reader.StatLength(Path.Combine(_root, "absent-dir", "absent")));
    }

    /// <summary>
    /// PAT-2040: a directory the scan checked and then found swapped for a junction into
    /// another profile is never listed. The listing opens the directory itself (a junction is
    /// opened as a junction and refused), checks the handle's final path, and enumerates from
    /// that handle, so neither a junction at the directory nor one above it is listed through.
    /// Windows only: elsewhere the reader has no handle lister and the scan runs only under test.
    /// </summary>
    [DirectoryLinkFact]
    public void ListDir_OnWindows_RefusesACheckedDirectorySwappedForAJunction()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (reader, alice, bob, checkedDir) = SwapFixture();

        Assert.Equal(new[] { ("link", FsKind.Symlink, 0L), ("mine.gguf", FsKind.File, 3L), ("sub", FsKind.Dir, 0L) },
            reader.ListDirWithLengths(checkedDir));
        Assert.Equal(new[] { ("link", FsKind.Symlink), ("mine.gguf", FsKind.File), ("sub", FsKind.Dir) }, reader.ListDir(checkedDir));

        // The scan checks the directory, then the user swaps it for a junction into bob's profile.
        // PAT-2052: a reader lists each directory once and keeps it, so the swap is met by a
        // reader that has not listed it yet, as a scan meets it.
        Assert.Equal(FsKind.Dir, UserTreeReader.KindOf(checkedDir));
        reader = FreshReader(alice);
        Assert.Equal(FsKind.Dir, reader.KindAt(checkedDir));
        Directory.Move(checkedDir, checkedDir + "-moved");
        DirectoryLinks.Plant(checkedDir, bob);
        Assert.Throws<UnlistableDirectoryException>(() => reader.ListDir(checkedDir));
        Assert.Throws<UnlistableDirectoryException>(() => reader.ListDirWithLengths(checkedDir));

        // A junction higher up the path is refused by the final-path check.
        DirectoryLinks.Plant(Path.Combine(alice, "via"), Path.GetDirectoryName(bob)!);
        Assert.Throws<UnlistableDirectoryException>(() => reader.ListDir(Path.Combine(alice, "via", "private")));
    }

    /// <summary>
    /// PAT-2040: the same swap, raced. One thread flips the checked directory between itself
    /// and a junction into bob's profile while the scan lists it over and over; no listing may
    /// ever contain bob's file name. Windows only.
    /// </summary>
    [DirectoryLinkFact]
    public void ListDir_OnWindows_RacedJunctionSwap_NeverListsTheOtherProfile()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (_, alice, bob, checkedDir) = SwapFixture();
        var parked = checkedDir + "-parked";
        var (swaps, listed, refused) = Race(
            swapOnce: () =>
            {
                Directory.Move(checkedDir, parked);
                DirectoryLinks.Plant(checkedDir, bob);
                Directory.Delete(checkedDir);
                Directory.Move(parked, checkedDir);
            },
            // The scan held the directory (no FILE_SHARE_DELETE) or a step failed: put the
            // real directory back before the next round.
            restore: () =>
            {
                if (Directory.Exists(parked))
                {
                    if (Directory.Exists(checkedDir)) Directory.Delete(checkedDir);
                    Directory.Move(parked, checkedDir);
                }
            },
            readOnce: () =>
            {
                try
                {
                    // PAT-2052: a fresh reader each round, since a reader keeps what it listed.
                    var names = FreshReader(alice).ListDirWithLengths(checkedDir).Select(e => e.Name).ToList();
                    Assert.DoesNotContain("leaked-name.txt", names);
                    return true;
                }
                catch (UnlistableDirectoryException)
                {
                    return false;
                }
            });
        Assert.True(swaps > 0 && listed > 0 && refused > 0, $"the race never happened: swaps={swaps} listed={listed} refused={refused}");
    }

    // PAT-2077: a raced test is bounded on how much racing happened, not on wall time, so a
    // slow or busy runner races for longer instead of racing for less.
    private const int RaceMinSwaps = 200;
    private const int RaceMinReads = 200;
    private static readonly TimeSpan RaceSwapperStartTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan RaceSafetyTimeout = TimeSpan.FromSeconds(60);

    /// <summary>
    /// PAT-2077: runs <paramref name="swapOnce"/> on its own dedicated thread (never a pool
    /// thread, which a busy runner can starve for the whole test) against
    /// <paramref name="readOnce"/> on this one. The swapper must complete one swap before any
    /// read runs; if it cannot within <see cref="RaceSwapperStartTimeout"/>, the test fails as
    /// a harness failure, named as such, rather than as the race-never-happened guard. Reads
    /// then run until at least <see cref="RaceMinSwaps"/> swaps and <see cref="RaceMinReads"/>
    /// reads, including at least one accepted and one refused, have interleaved, or the safety
    /// timeout passes. <paramref name="readOnce"/> returns true for an accepted read, false for
    /// a refused one, and holds the test's own security assertion.
    /// </summary>
    private static (int Swaps, int Accepted, int Refused) Race(Action swapOnce, Action restore, Func<bool> readOnce)
    {
        using var stop = new CancellationTokenSource();
        using var firstSwap = new ManualResetEventSlim(false);
        var swaps = 0;
        Exception? lastSwapError = null;
        var swapper = Task.Factory.StartNew(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                try
                {
                    swapOnce();
                    Interlocked.Increment(ref swaps);
                    firstSwap.Set();
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    Volatile.Write(ref lastSwapError, e);
                    try { restore(); }
                    catch (Exception again) when (again is IOException or UnauthorizedAccessException) { }
                }
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        int accepted = 0, refused = 0;
        try
        {
            if (!firstSwap.Wait(RaceSwapperStartTimeout))
            {
                var why = swapper.IsFaulted ? swapper.Exception!.GetBaseException().Message
                    : Volatile.Read(ref lastSwapError)?.Message ?? "the swapper thread never ran";
                Assert.Fail($"harness, not product: the swapper completed no swap within {RaceSwapperStartTimeout.TotalSeconds}s, so there was no race to test ({why})");
            }
            var deadline = DateTime.UtcNow + RaceSafetyTimeout;
            while (DateTime.UtcNow < deadline && !swapper.IsCompleted)
            {
                if (readOnce()) accepted++; else refused++;
                if (Volatile.Read(ref swaps) >= RaceMinSwaps && accepted + refused >= RaceMinReads
                    && accepted > 0 && refused > 0) break;
            }
        }
        finally
        {
            stop.Cancel();
            swapper.Wait();
        }
        return (Volatile.Read(ref swaps), accepted, refused);
    }

    private (UserTreeReader Reader, string Alice, string Bob, string Checked) SwapFixture()
    {
        var alice = Directory.CreateDirectory(Path.Combine(_root, "alice")).FullName;
        var bob = Directory.CreateDirectory(Path.Combine(_root, "bob", "private")).FullName;
        File.WriteAllBytes(Path.Combine(bob, "leaked-name.txt"), new byte[77]);
        var checkedDir = Directory.CreateDirectory(Path.Combine(alice, "models")).FullName;
        File.WriteAllText(Path.Combine(checkedDir, "mine.gguf"), "abc");
        Directory.CreateDirectory(Path.Combine(checkedDir, "sub"));
        Directory.CreateDirectory(Path.Combine(checkedDir, ".hidden"));
        DirectoryLinks.Plant(Path.Combine(checkedDir, "link"), bob);
        return (FreshReader(alice), alice, bob, checkedDir);
    }

    private static UserTreeReader FreshReader(string root)
    {
        var reader = new UserTreeReader(null, OperatingSystem.IsWindows() ? WindowsFileIdentity.FinalPathOfDirectory : null);
        Assert.True(reader.AddRoot(root));
        return reader;
    }

    /// <summary>
    /// PAT-2040: a root is registered only from a handle on the root itself. A root that is a
    /// junction, or is reached through one, is refused (AddRoot is false and nothing is
    /// registered); a plain directory is accepted with its kernel spelling. Windows only.
    /// </summary>
    [DirectoryLinkFact]
    public void AddRoot_OnWindows_RefusesARootThatIsOrIsReachedThroughAJunction()
    {
        if (!OperatingSystem.IsWindows()) return;
        var bob = Directory.CreateDirectory(Path.Combine(_root, "bob", "private")).FullName;
        var plain = Directory.CreateDirectory(Path.Combine(_root, "scoop-real")).FullName;
        var junction = Path.Combine(_root, "scoop");
        DirectoryLinks.Plant(junction, bob);
        DirectoryLinks.Plant(Path.Combine(_root, "via"), Path.GetDirectoryName(bob)!);

        Assert.Null(WindowsFileIdentity.FinalPathOfDirectory(junction));
        Assert.Null(WindowsFileIdentity.FinalPathOfDirectory(Path.Combine(_root, "via", "private")));
        Assert.NotNull(WindowsFileIdentity.FinalPathOfDirectory(plain));

        var reader = new UserTreeReader(null, null);
        Assert.False(reader.AddRoot(junction));
        Assert.False(reader.AddRoot(Path.Combine(_root, "via", "private")));
        Assert.True(reader.AddRoot(plain));
    }

    /// <summary>
    /// PAT-2040: the same, raced. One thread flips a root between a real directory and a
    /// junction into bob's profile while roots are resolved over and over; a resolved root is
    /// only ever the real directory's final path, never bob's. Windows only.
    /// </summary>
    [DirectoryLinkFact]
    public void AddRoot_OnWindows_RacedRootSwap_NeverRecordsTheOtherProfile()
    {
        if (!OperatingSystem.IsWindows()) return;
        var bob = Directory.CreateDirectory(Path.Combine(_root, "bob", "private")).FullName;
        var root = Directory.CreateDirectory(Path.Combine(_root, "scoop")).FullName;
        var realFinal = WindowsFileIdentity.FinalPathOfDirectory(root);
        Assert.NotNull(realFinal);
        var (swaps, accepted, refused) = Race(
            swapOnce: () =>
            {
                Directory.Delete(root);
                DirectoryLinks.Plant(root, bob);
                Directory.Delete(root);
                Directory.CreateDirectory(root);
            },
            restore: () =>
            {
                if (!Directory.Exists(root)) Directory.CreateDirectory(root);
            },
            readOnce: () =>
            {
                // The analyser does not carry the test's OnWindows guard into a lambda.
                var final = OperatingSystem.IsWindows() ? WindowsFileIdentity.FinalPathOfDirectory(root) : null;
                if (final is null) return false;
                Assert.Equal(realFinal, final, StringComparer.OrdinalIgnoreCase);
                return true;
            });
        Assert.True(swaps > 0 && accepted > 0 && refused > 0, $"the race never happened: swaps={swaps} accepted={accepted} refused={refused}");
    }

    /// <summary>
    /// PAT-2050: existence below a root comes only from a verified listing of the parent,
    /// never a path test. Here a lister that refuses chosen directories stands in for the
    /// Windows handle check: below a refused directory nothing is ever Absent or "missing",
    /// only Error or "unreadable", while an unrefused tree walks normally (dot directories
    /// included) and a name under a parent that is itself absent is still Absent.
    /// </summary>
    [Fact]
    public void Existence_BelowADirectoryTheListerRefuses_IsNeverAbsent()
    {
        var home = Directory.CreateDirectory(Path.Combine(_root, "home")).FullName;
        var app = Directory.CreateDirectory(Path.Combine(home, ".config", "app")).FullName;
        File.WriteAllText(Path.Combine(app, "x.json"), "{}");
        var refused = new HashSet<string>(StringComparer.Ordinal);
        // PAT-2052: a reader keeps each listing for its scan, so each refusal set gets its own.
        UserTreeReader NewReader()
        {
            var r = new UserTreeReader(null, null, (path, _) =>
                refused.Contains(Path.TrimEndingDirectorySeparator(path)) ? null : Enumerate(path));
            Assert.True(r.AddRoot(home));
            return r;
        }
        var reader = NewReader();

        Assert.Equal((FsKind.Dir, app), reader.Walk(home, ".config", "app"));
        Assert.Equal((FsKind.Absent, Path.Combine(home, "absent")), reader.Walk(home, "absent", "deeper"));
        Assert.Equal(FsKind.File, reader.KindAt(Path.Combine(app, "x.json")));
        Assert.Equal(FsKind.Absent, reader.KindAt(Path.Combine(home, "absent", "deeper")));
        Assert.Equal(("missing", (long?)null), reader.StatLength(Path.Combine(home, "absent", "x.json")));
        Assert.Equal("read", reader.ReadFile(Path.Combine(app, "x.json"), 100).Status);

        refused.Add(home);
        reader = NewReader();
        Assert.Equal((FsKind.Error, home), reader.Walk(home, ".config", "app"));
        Assert.Equal((FsKind.Error, home), reader.Walk(home, "absent"));
        Assert.Equal(FsKind.Error, reader.KindAt(Path.Combine(home, "absent")));
        Assert.Equal(FsKind.Error, reader.KindAt(Path.Combine(home, "absent", "deeper")));
        Assert.Equal(("unreadable", (long?)null), reader.StatLength(Path.Combine(home, "absent")));
        Assert.Equal("read", reader.ReadFile(Path.Combine(app, "x.json"), 100).Status);

        refused.Add(app);
        reader = NewReader();
        Assert.Equal((FsKind.Error, app), reader.Walk(app, "absent"));
        Assert.Equal("unreadable", reader.ReadFile(Path.Combine(app, "x.json"), 100).Status);
        Assert.Equal("unreadable", reader.ReadFile(Path.Combine(app, "absent.json"), 100).Status);
    }

    /// <summary>A stand-in lister: null, as the Windows one is, for anything it cannot list.</summary>
    private static List<(string Name, FsKind Kind, long Length)>? Enumerate(string path)
    {
        try
        {
            return new DirectoryInfo(path).EnumerateFileSystemInfos().Select(i => (
                i.Name,
                i.LinkTarget is not null ? FsKind.Symlink : i is DirectoryInfo ? FsKind.Dir : FsKind.File,
                i is FileInfo f && i.LinkTarget is null ? f.Length : 0L)).ToList();
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>
    /// PAT-2050: a registered root swapped for a junction into another profile after
    /// AddRoot. Every existence answer below it is Error or "unreadable", and exactly the same
    /// whether the other profile lacks or has what is asked about, so nothing is closed on the
    /// swap and nothing about the other profile leaks. Windows only: the refusal is the
    /// handle lister's, which exists nowhere else.
    /// </summary>
    [DirectoryLinkFact]
    public void Existence_OnWindows_BelowARootSwappedAfterItIsRegistered_IsTheSameWhateverTheTargetHolds()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (first, alice, bob, _) = SwapFixture();
        // PAT-2052: a reader keeps what it listed, including a refusal, so the second set of
        // answers comes from its own reader, registered before the swap like the first.
        var second = FreshReader(alice);
        var reader = first;
        var other = Path.GetDirectoryName(bob)!;
        Directory.Move(alice, alice + "-moved");
        DirectoryLinks.Plant(alice, bob);

        object Answers() => new
        {
            Models = reader.Walk(alice, "models", "sub"),
            Leaked = reader.Walk(alice, "leaked-dir"),
            Kind = reader.KindAt(Path.Combine(alice, "models", "mine.gguf")),
            LeakedKind = reader.KindAt(Path.Combine(alice, "leaked-name.txt")),
            Stat = reader.StatLength(Path.Combine(alice, "leaked-name.txt")),
            Read = reader.ReadFile(Path.Combine(alice, "models", "mine.gguf"), 100).Status,
        };
        var lacking = Answers();
        Directory.CreateDirectory(Path.Combine(bob, "models", "sub"));
        Directory.CreateDirectory(Path.Combine(bob, "leaked-dir"));
        File.WriteAllText(Path.Combine(bob, "models", "mine.gguf"), "xyz");
        reader = second;
        var having = Answers();

        Assert.Equal(lacking, having);
        Assert.Equal((FsKind.Error, alice), reader.Walk(alice, "models", "sub"));
        Assert.Equal((FsKind.Error, alice), reader.Walk(alice, "leaked-dir"));
        Assert.Equal(FsKind.Error, reader.KindAt(Path.Combine(alice, "leaked-name.txt")));
        Assert.Equal(("unreadable", (long?)null), reader.StatLength(Path.Combine(alice, "leaked-name.txt")));
        Assert.True(Directory.Exists(other));
    }

    /// <summary>
    /// PAT-2052: a listing over the entry cap is unlistable, never a truncated list taken as
    /// complete. Below a directory over the cap nothing is Absent or "missing", only Error or
    /// "unreadable", exactly as for a directory the lister refuses; a directory at the cap is
    /// listed normally. The cap holds whatever the lister returns, so an injected lister that
    /// ignores it is refused too.
    /// </summary>
    [Fact]
    public void Listing_PastTheEntryCap_IsUnlistable_SoPartial_NeverComplete()
    {
        Assert.Equal(100_000, UserTreeReader.DefaultMaxEntriesPerListing);
        var home = Directory.CreateDirectory(Path.Combine(_root, "home")).FullName;
        var atCap = Directory.CreateDirectory(Path.Combine(home, "at-cap")).FullName;
        var overCap = Directory.CreateDirectory(Path.Combine(home, "over-cap")).FullName;
        for (var i = 0; i < 5; i++) File.WriteAllText(Path.Combine(atCap, $"f{i}.json"), "{}");
        for (var i = 0; i < 6; i++) File.WriteAllText(Path.Combine(overCap, $"f{i}.json"), "{}");

        foreach (var lister in new[] { null, UserTreeReader.DefaultLister(maxEntries: int.MaxValue) })
        {
            var reader = new UserTreeReader(null, null, lister, maxEntriesPerListing: 5);
            Assert.True(reader.AddRoot(home));

            Assert.Equal(5, reader.ListDir(atCap).Count);
            Assert.Equal(FsKind.Absent, reader.KindAt(Path.Combine(atCap, "absent.json")));
            Assert.Equal("read", reader.ReadFile(Path.Combine(atCap, "f0.json"), 100).Status);

            Assert.Throws<UnlistableDirectoryException>(() => reader.ListDir(overCap));
            Assert.Throws<UnlistableDirectoryException>(() => reader.ListDirWithLengths(overCap));
            Assert.Equal(FsKind.Error, reader.KindAt(Path.Combine(overCap, "f0.json")));
            Assert.Equal(FsKind.Error, reader.KindAt(Path.Combine(overCap, "absent.json")));
            Assert.Equal(FsKind.Error, reader.KindAt(Path.Combine(overCap, "absent", "deeper.json")));
            Assert.Equal((FsKind.Error, overCap), reader.Walk(home, "over-cap", "absent"));
            Assert.Equal("unreadable", reader.ReadFile(Path.Combine(overCap, "f0.json"), 100).Status);
            Assert.Equal(("unreadable", (long?)null), reader.StatLength(Path.Combine(overCap, "absent.json")));
        }
    }

    /// <summary>PAT-2052: the Windows handle lister itself stops at the cap and answers null. Windows only.</summary>
    [Fact]
    public void ListDirectory_OnWindows_PastTheEntryCap_IsNull()
    {
        if (!OperatingSystem.IsWindows()) return;
        var dir = Directory.CreateDirectory(Path.Combine(_root, "many")).FullName;
        for (var i = 0; i < 6; i++) File.WriteAllText(Path.Combine(dir, $"f{i}"), "x");
        var final = WindowsFileIdentity.FinalPathOfDirectory(dir);
        Assert.NotNull(final);
        Assert.Equal(6, WindowsFileIdentity.ListDirectory(dir, final, maxEntries: 6)!.Count);
        Assert.Null(WindowsFileIdentity.ListDirectory(dir, final, maxEntries: 5));
    }

    /// <summary>
    /// PAT-2052: a reader lists each directory once. However many walks, kind checks, stats
    /// and reads land below it, every directory (the root, each ancestor, a directory that
    /// cannot be listed) reaches the lister exactly once; a new reader, as the next scan
    /// makes, lists again, so nothing cached outlives the reader.
    /// </summary>
    [Fact]
    public void Listings_AreCachedPerReader_OnePerDirectory_AndNotAcrossReaders()
    {
        var home = Directory.CreateDirectory(Path.Combine(_root, "home")).FullName;
        var deep = Directory.CreateDirectory(Path.Combine(home, "AppData", "Local", "app", "data")).FullName;
        for (var i = 0; i < 3; i++) File.WriteAllText(Path.Combine(deep, $"f{i}.json"), "{}");
        var refused = deep;
        var calls = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var real = UserTreeReader.DefaultLister();
        UserTreeReader NewReader(bool refuse)
        {
            var reader = new UserTreeReader(null, null, (path, expected) =>
            {
                calls[expected] = calls.GetValueOrDefault(expected) + 1;
                return refuse && string.Equals(Path.TrimEndingDirectorySeparator(path), refused, StringComparison.Ordinal)
                    ? null
                    : real(path, expected);
            });
            Assert.True(reader.AddRoot(home));
            return reader;
        }

        void Ask(UserTreeReader reader)
        {
            for (var round = 0; round < 10; round++)
            {
                reader.Walk(home, "AppData", "Local", "app", "data");
                reader.Walk(home, "AppData", "Local", "absent");
                for (var i = 0; i < 4; i++)
                {
                    reader.KindAt(Path.Combine(deep, $"f{i}.json"));
                    reader.StatLength(Path.Combine(deep, $"f{i}.json"));
                    reader.ReadFile(Path.Combine(deep, $"f{i}.json"), 100);
                }
            }
        }

        Ask(NewReader(refuse: false));
        Assert.Equal(5, calls.Count);
        Assert.All(calls.Values, n => Assert.Equal(1, n));

        Ask(NewReader(refuse: false));
        Assert.All(calls.Values, n => Assert.Equal(2, n));

        // A refused directory is asked for once too, and the refusal holds for the reader.
        calls.Clear();
        var refusing = NewReader(refuse: true);
        Ask(refusing);
        Assert.Equal(1, calls[refused]);
        Assert.Equal(5, calls.Count);
        Assert.All(calls.Values, n => Assert.Equal(1, n));
        Assert.Equal(FsKind.Error, refusing.KindAt(Path.Combine(deep, "f0.json")));
    }

    /// <summary>
    /// PAT-2052 review: in a case-sensitive directory "foo" and "Foo" are two directories.
    /// The cache must never answer one with the other's listing: each is listed for itself,
    /// so a name only "Foo" holds is found there and not reported absent.
    /// </summary>
    [Fact]
    public void ListingCache_KeepsNamesThatDifferOnlyInCaseApart()
    {
        var home = Directory.CreateDirectory(Path.Combine(_root, "home")).FullName;
        var lower = Path.Combine(home, "foo");
        var upper = Path.Combine(home, "Foo");
        var reader = new UserTreeReader(null, null, (path, _) => Path.TrimEndingDirectorySeparator(path) switch
        {
            var p when string.Equals(p, home, StringComparison.Ordinal) => [("foo", FsKind.Dir, 0L), ("Foo", FsKind.Dir, 0L)],
            var p when string.Equals(p, lower, StringComparison.Ordinal) => [("lower.json", FsKind.File, 2L)],
            var p when string.Equals(p, upper, StringComparison.Ordinal) => [("upper.json", FsKind.File, 2L)],
            _ => null,
        });
        Assert.True(reader.AddRoot(home));

        Assert.Equal(new[] { ("lower.json", FsKind.File) }, reader.ListDir(lower));
        Assert.Equal(new[] { ("upper.json", FsKind.File) }, reader.ListDir(upper));
        Assert.Equal(FsKind.File, reader.KindAt(Path.Combine(upper, "upper.json")));
        Assert.Equal(FsKind.Absent, reader.KindAt(Path.Combine(upper, "lower.json")));
    }

    /// <summary>
    /// The same on a real case-sensitive NTFS directory (fsutil file setCaseSensitiveInfo),
    /// through the Windows handle lister. Skipped with the reason on a machine that cannot
    /// make a directory case-sensitive (and off Windows).
    /// </summary>
    [CaseSensitiveDirectoryFact]
    public void ListingCache_OnWindows_CaseSensitiveDirectory_ListsfooAndFooApart()
    {
        var home = Directory.CreateDirectory(Path.Combine(_root, "cs-home")).FullName;
        CaseSensitiveDirectories.Enable(home);
        var lower = Directory.CreateDirectory(Path.Combine(home, "foo")).FullName;
        var upper = Directory.CreateDirectory(Path.Combine(home, "Foo")).FullName;
        File.WriteAllText(Path.Combine(lower, "lower.json"), "{}");
        File.WriteAllText(Path.Combine(upper, "upper.json"), "{}");
        Assert.Equal(2, Directory.GetDirectories(home).Length);

        var reader = FreshReader(home);
        Assert.Equal(new[] { ("lower.json", FsKind.File) }, reader.ListDir(lower));
        Assert.Equal(new[] { ("upper.json", FsKind.File) }, reader.ListDir(upper));
        Assert.Equal(FsKind.File, reader.KindAt(Path.Combine(upper, "upper.json")));
        Assert.Equal(FsKind.Absent, reader.KindAt(Path.Combine(upper, "lower.json")));
    }

    /// <summary>
    /// PAT-2052: the cache holds at most its entry budget. Past it the oldest listing is
    /// dropped, and asked for again it is listed again, never answered from nothing.
    /// </summary>
    [Fact]
    public void ListingCache_KeepsToItsBudget_AndRelistsWhatItDropped()
    {
        var home = Directory.CreateDirectory(Path.Combine(_root, "home")).FullName;
        var a = Directory.CreateDirectory(Path.Combine(home, "a")).FullName;
        var b = Directory.CreateDirectory(Path.Combine(home, "b")).FullName;
        foreach (var d in new[] { a, b })
            for (var i = 0; i < 2; i++) File.WriteAllText(Path.Combine(d, $"f{i}"), "x");
        var calls = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var real = UserTreeReader.DefaultLister();
        var reader = new UserTreeReader(null, null, (path, expected) =>
        {
            calls[expected] = calls.GetValueOrDefault(expected) + 1;
            return real(path, expected);
        }, maxCachedEntries: 3);
        Assert.True(reader.AddRoot(home));

        Assert.Equal(2, reader.ListDir(a).Count);
        Assert.Equal(2, reader.ListDir(a).Count);
        Assert.Equal(1, calls[a]);
        Assert.Equal(2, reader.ListDir(b).Count);
        Assert.Equal(2, reader.ListDir(a).Count);
        Assert.Equal(2, calls[a]);
    }

    /// <summary>
    /// PAT-2052: a link's target is read from a handle on the link itself after its final
    /// path is checked. A junction read in place gives its target; the same link reached after
    /// its directory was swapped for a junction into another profile gives nothing, and the
    /// same nothing whether or not that profile holds a link there, or one pointing at the
    /// very path the scan would accept. Windows only: elsewhere the reader reads by path.
    /// </summary>
    [DirectoryLinkFact]
    public void LinkTarget_OnWindows_ReadsFromTheVerifiedLink_AndNothingAfterASwap()
    {
        if (!OperatingSystem.IsWindows()) return;
        var alice = Directory.CreateDirectory(Path.Combine(_root, "alice")).FullName;
        var app = Directory.CreateDirectory(Path.Combine(alice, "scoop", "apps", "llama.cpp")).FullName;
        var version = Directory.CreateDirectory(Path.Combine(app, "6000")).FullName;
        DirectoryLinks.Plant(Path.Combine(app, "current"), version);
        var bobApp = Directory.CreateDirectory(Path.Combine(_root, "bob", "llama.cpp")).FullName;
        Directory.CreateDirectory(Path.Combine(bobApp, "6000"));

        var reader = FreshReader(alice);
        Assert.Equal(version, reader.LinkTarget(Path.Combine(app, "current")), StringComparer.OrdinalIgnoreCase);
        Assert.Null(reader.LinkTarget(version));
        Assert.Null(reader.LinkTarget(Path.Combine(app, "absent")));

        Directory.Move(app, app + "-registered");
        DirectoryLinks.Plant(app, bobApp);
        try
        {
            var lacking = reader.LinkTarget(Path.Combine(app, "current"));
            DirectoryLinks.Plant(Path.Combine(bobApp, "current"), version);
            Assert.NotNull(new DirectoryInfo(Path.Combine(app, "current")).LinkTarget);
            var having = reader.LinkTarget(Path.Combine(app, "current"));
            Assert.Null(lacking);
            Assert.Null(having);
        }
        finally
        {
            Directory.Delete(app);
            Directory.Move(app + "-registered", app);
        }
    }

    /// <summary>
    /// PAT-2052: the REPARSE_DATA_BUFFER parser behind the link reader: a junction's and an
    /// absolute symlink's target lose their \??\ prefix (a UNC one becomes \\), a relative
    /// symlink's is kept as written, and any other tag, empty name, or name running past the
    /// data is refused. Pure parsing, so it runs everywhere.
    /// </summary>
    [Fact]
    public void ParseReparseTarget_ReadsJunctionsAndSymlinks_AndRefusesTheRest()
    {
        static byte[] Buffer(uint tag, string substitute, uint? flags, int? claimLength = null)
        {
            var name = Encoding.Unicode.GetBytes(substitute);
            var print = Encoding.Unicode.GetBytes("print");
            var head = flags is null ? 8 : 12;
            var dataLength = head + name.Length + print.Length;
            var b = new byte[8 + dataLength];
            BinaryPrimitives.WriteUInt32LittleEndian(b, tag);
            BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(4), (ushort)dataLength);
            BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(8), 0);
            BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(10), (ushort)(claimLength ?? name.Length));
            BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(12), (ushort)name.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(14), (ushort)print.Length);
            if (flags is { } f) BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(16), f);
            name.CopyTo(b, 8 + head);
            print.CopyTo(b, 8 + head + name.Length);
            return b;
        }
        const uint MountPoint = 0xA0000003, Symlink = 0xA000000C;
#pragma warning disable CA1416 // the parser is pure managed code; only the read around it is Windows-only
        Assert.Equal(@"C:\ProgramData\scoop\apps\x\6000", WindowsFileIdentity.ParseReparseTarget(Buffer(MountPoint, @"\??\C:\ProgramData\scoop\apps\x\6000", null)));
        Assert.Equal(@"C:\target", WindowsFileIdentity.ParseReparseTarget(Buffer(Symlink, @"\??\C:\target", 0)));
        Assert.Equal(@"\\server\share\x", WindowsFileIdentity.ParseReparseTarget(Buffer(Symlink, @"\??\UNC\server\share\x", 0)));
        Assert.Equal(@"..\6000", WindowsFileIdentity.ParseReparseTarget(Buffer(Symlink, @"..\6000", 1)));
        Assert.Null(WindowsFileIdentity.ParseReparseTarget(Buffer(0x80000017, @"\??\C:\x", null)));
        Assert.Null(WindowsFileIdentity.ParseReparseTarget(Buffer(MountPoint, "", null)));
        Assert.Null(WindowsFileIdentity.ParseReparseTarget(Buffer(MountPoint, @"\??\C:\x", null, claimLength: 400)));
        Assert.Null(WindowsFileIdentity.ParseReparseTarget(Buffer(MountPoint, @"\??\C:\x", null).AsSpan(0, 12)));
#pragma warning restore CA1416
    }

    /// <summary>
    /// PAT-2040: the FILE_FULL_DIR_INFO parser behind the Windows listing reads each record's
    /// name, attributes and length, skips "." and "..", and refuses a record that runs past
    /// the buffer rather than reading beyond it. Pure parsing, so it runs everywhere.
    /// </summary>
    [Fact]
    public void ParseFullDirectoryInfo_ReadsRecords_AndRefusesOneRunningPastTheBuffer()
    {
        static byte[] Record(string name, uint attributes, long length, bool last)
        {
            var nameBytes = Encoding.Unicode.GetBytes(name);
            var size = (68 + nameBytes.Length + 7) & ~7;
            var r = new byte[size];
            BinaryPrimitives.WriteUInt32LittleEndian(r, last ? 0u : (uint)size);
            BinaryPrimitives.WriteInt64LittleEndian(r.AsSpan(40), length);
            BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(56), attributes);
            BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(60), (uint)nameBytes.Length);
            nameBytes.CopyTo(r, 68);
            return r;
        }
        var buffer = Record(".", 0x10, 0, false).Concat(Record("..", 0x10, 0, false))
            .Concat(Record("a.gguf", 0x20, 1234, false)).Concat(Record("dir", 0x10, 0, false))
            .Concat(Record("junction", 0x410, 0, false)).Concat(Record("dev", 0x40, 5, true)).ToArray();
        var rows = new List<(string, FsKind, long)>();
#pragma warning disable CA1416 // the parser is pure managed code; only the listing around it is Windows-only
        Assert.True(WindowsFileIdentity.ParseFullDirectoryInfo(buffer, rows));
        Assert.Equal(new[] { ("a.gguf", FsKind.File, 1234L), ("dir", FsKind.Dir, 0L), ("junction", FsKind.Symlink, 0L), ("dev", FsKind.Other, 0L) }, rows);

        var truncated = Record("long-name.bin", 0x20, 1, true);
        Assert.False(WindowsFileIdentity.ParseFullDirectoryInfo(truncated.AsSpan(0, 80), []));
        var runaway = Record("a", 0x20, 1, false);
        BinaryPrimitives.WriteUInt32LittleEndian(runaway, 4096);
        Assert.False(WindowsFileIdentity.ParseFullDirectoryInfo(runaway, []));
#pragma warning restore CA1416
    }

    /// <summary>
    /// PAT-2056: a path call whose first 1,024-character buffer is too small reports the size
    /// it needs (terminator counted) and is called once more with exactly that, so a deep path
    /// is read in full. A size past 32,768, a second answer that still does not fit (the path
    /// grew in between) or a failure is null, never a truncated path. Pure, so it runs everywhere.
    /// </summary>
    [Fact]
    public void CallGrowingOnce_GrowsOnceToTheSizeAsked_AndRefusesPastTheCapOrASecondMiss()
    {
        var deep = @"C:\Users\alice\" + string.Join('\\', Enumerable.Repeat(new string('n', 200), 8)) + @"\a.json";
        Assert.True(deep.Length > WindowsFileIdentity.InitialPathChars);
        var sizes = new List<int>();
        uint Fake(char[] buffer, string path)
        {
            sizes.Add(buffer.Length);
            if (buffer.Length <= path.Length) return (uint)path.Length + 1;
            path.CopyTo(0, buffer, 0, path.Length);
            buffer[path.Length] = '\0';
            return (uint)path.Length;
        }

#pragma warning disable CA1416 // the retry is pure managed code; only the calls it wraps are Windows-only
        Assert.Equal(deep, WindowsFileIdentity.CallGrowingOnce(b => Fake(b, deep)));
        Assert.Equal(new[] { WindowsFileIdentity.InitialPathChars, deep.Length + 1 }, sizes);

        sizes.Clear();
        Assert.Equal(@"C:\short", WindowsFileIdentity.CallGrowingOnce(b => Fake(b, @"C:\short")));
        Assert.Equal(new[] { WindowsFileIdentity.InitialPathChars }, sizes);

        var atCap = @"C:\" + new string('x', WindowsFileIdentity.MaxPathChars - 4);
        Assert.Equal(atCap, WindowsFileIdentity.CallGrowingOnce(b => Fake(b, atCap)));
        var pastCap = atCap + "y";
        sizes.Clear();
        Assert.Null(WindowsFileIdentity.CallGrowingOnce(b => Fake(b, pastCap)));
        Assert.Equal(new[] { WindowsFileIdentity.InitialPathChars }, sizes);

        var growing = deep;
        sizes.Clear();
        Assert.Null(WindowsFileIdentity.CallGrowingOnce(b => { var r = Fake(b, growing); growing += @"\more"; return r; }));
        Assert.Equal(2, sizes.Count);

        Assert.Null(WindowsFileIdentity.CallGrowingOnce(_ => 0));
#pragma warning restore CA1416
    }

    /// <summary>
    /// PAT-2056: a file more than 1,024 characters deep (nested node_modules) is verified and
    /// read like any other: the root resolves, every directory on the way is listed from a
    /// verified handle, and the opened file's final path, longer than the first buffer, matches.
    /// The tree is made with \\?\ paths. Windows only.
    /// </summary>
    [Fact]
    public void ReadFile_OnWindows_FileDeeperThanTheFirstPathBuffer_IsVerifiedAndRead()
    {
        if (!OperatingSystem.IsWindows()) return;
        var root = Directory.CreateDirectory(Path.Combine(_root, "home")).FullName;
        var deepDir = Path.Combine(new[] { root }.Concat(Enumerable.Range(0, 12).Select(i => $"node_modules_{i:D2}_" + new string('m', 90))).ToArray());
        var file = Path.Combine(deepDir, "package.json");
        Assert.True(file.Length > WindowsFileIdentity.InitialPathChars, $"only {file.Length} characters");
        Directory.CreateDirectory(@"\\?\" + deepDir);
        File.WriteAllText(@"\\?\" + file, "{\"name\":\"deep\"}");

        Assert.Equal(@"\\?\" + file, WindowsFileIdentity.ExtendedLengthPath(file));
        Assert.Equal(@"\\?\UNC\server\share\" + new string('s', 300), WindowsFileIdentity.ExtendedLengthPath(@"\\server\share\" + new string('s', 300)));
        Assert.Equal(@"\\?\" + file, WindowsFileIdentity.ExtendedLengthPath(@"\\?\" + file));
        Assert.Equal(root, WindowsFileIdentity.ExtendedLengthPath(root));
        Assert.Equal(deepDir, WindowsFileIdentity.FinalPathOfDirectory(deepDir), StringComparer.OrdinalIgnoreCase);
        Assert.Equal(new[] { ("package.json", FsKind.File, 15L) }, WindowsFileIdentity.ListDirectory(deepDir, deepDir));
        var reader = new UserTreeReader(WindowsFileIdentity.IsExpectedRegularFile, null);
        Assert.True(reader.AddRoot(root));
        var (status, data) = reader.ReadFile(file, 1024);
        Assert.Equal("read", status);
        Assert.Equal("{\"name\":\"deep\"}", Encoding.UTF8.GetString(data!));
        Assert.Equal(("open", (long?)15), reader.StatLength(file));
    }
}
