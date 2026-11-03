using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using Patched.Shared.Compliance;
using Patched.Shared.Contract;
using Patched.Shared.DeviceClassification;
using Patched.Shared.KernelDrivers;
using Patched.Shared.LocalModels;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-2263: the kernel driver inventory rules, off Windows. Driver sources are fakes (a
/// directory listing, a Services enumeration and a loaded-module list) and files are served
/// from memory by a fake opener, so every rule about merging, bounding, hashing and
/// completeness runs here. Nothing in this file is, or contains, a real driver: the "PE"
/// files are synthetic headers built below, and every hash is computed from them.
/// </summary>
public sealed class KernelDriverInventoryTests
{
    private const string Root = @"C:\Windows";
    private const string Drivers = @"C:\Windows\System32\drivers";

    private static readonly InventoryDriverEnforcement Enforcement = DriverEnforcementLogic.Build(
        RegistryRead.Present(1), RegistryRead.Absent, SourceRead.Present(2u), SourceRead.Present(0u));

    private static DriverServiceEntry Service(string name, int? type, object? imagePath, int? start = 3) =>
        new(name,
            type is null ? RegistryRead.Absent : RegistryRead.Present(type.Value),
            imagePath is null ? RegistryRead.Absent : RegistryRead.Present(imagePath),
            start is null ? RegistryRead.Absent : RegistryRead.Present(start.Value));

    /// <summary>In-memory files keyed by Windows path; anything else is missing.</summary>
    private sealed class FakeFiles
    {
        public readonly Dictionary<string, Func<DriverFileOpen>> Files = new(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> Opened = new();

        public FakeFiles Add(string path, byte[] bytes)
        {
            Files[path] = () => new DriverFileOpen(DriverOpenOutcome.Opened, new MemoryStream(bytes, writable: false));
            return this;
        }

        public FakeFiles Outcome(string path, DriverOpenOutcome outcome)
        {
            Files[path] = () => new DriverFileOpen(outcome);
            return this;
        }

        public DriverFileOpen Open(string path)
        {
            lock (Opened) Opened.Add(path);
            return Files.TryGetValue(path, out var open) ? open() : new DriverFileOpen(DriverOpenOutcome.Missing);
        }
    }

    private static KernelDriverSources Sources(
        IEnumerable<string>? directory = null,
        IEnumerable<DriverServiceEntry>? services = null,
        IEnumerable<string>? loaded = null,
        bool directoryFailed = false,
        bool servicesFailed = false,
        bool loadedFailed = false,
        int unreadableServices = 0,
        string? systemRoot = Root) =>
        new(systemRoot,
            directoryFailed ? DriverDirectoryListing.Unreadable : new DriverDirectoryListing(false, (directory ?? []).ToList()),
            servicesFailed ? DriverServiceEnumeration.Unreadable : new DriverServiceEnumeration(false, (services ?? []).ToList(), unreadableServices),
            loadedFailed ? LoadedModuleList.Unreadable : new LoadedModuleList(false, (loaded ?? []).ToList()),
            Enforcement);

    private static KernelDriverLimits Limits(int maxDrivers = 1500, long maxFile = 1 << 20, long maxTotal = 1 << 30, TimeSpan? budget = null) =>
        new(maxDrivers, maxFile, maxTotal, budget ?? TimeSpan.FromSeconds(30));

    private static InventoryKernelDriver Row(InventoryKernelDrivers block, string path) =>
        Assert.Single(block.Drivers!, d => string.Equals(d.Path, path, StringComparison.OrdinalIgnoreCase));

    private static string Sha256(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();
    private static string Sha1(byte[] b) => Convert.ToHexString(SHA1.HashData(b)).ToLowerInvariant();

    private static byte[] Bytes(string s) => System.Text.Encoding.ASCII.GetBytes(s);

    // -------------------------------------------------------------------------
    // Enumeration: three sources, merged and deduplicated by path
    // -------------------------------------------------------------------------

    [Fact]
    public void Build_MergesTheThreeSources_DedupedByPathIgnoringCase()
    {
        var files = new FakeFiles()
            .Add($@"{Drivers}\alpha.sys", Bytes("alpha"))
            .Add($@"{Drivers}\beta.sys", Bytes("beta"))
            .Add(@"C:\Vendor\gamma.sys", Bytes("gamma"));
        var block = KernelDriverInventoryLogic.Build(Sources(
            directory: [$@"{Drivers}\alpha.sys", $@"{Drivers}\beta.sys"],
            services:
            [
                Service("alpha", 1, @"\SystemRoot\System32\DRIVERS\ALPHA.sys", start: 0),
                Service("gamma", 2, @"\??\C:\Vendor\gamma.sys", start: 2),
                Service("NotADriver", 16, @"C:\Program Files\x.exe"),
                Service("NoType", null, @"C:\y.sys"),
            ],
            loaded: [@"\SystemRoot\system32\drivers\alpha.sys", @"\??\C:\Vendor\gamma.sys"]),
            files.Open, Limits());

        Assert.Equal(KernelDriverCollectionStatus.Complete, block.CollectionStatus);
        Assert.Empty(block.Errors);
        // Sorted by path; the first spelling seen (the directory listing's) is the one sent.
        Assert.Equal([@"C:\Vendor\gamma.sys", $@"{Drivers}\alpha.sys", $@"{Drivers}\beta.sys"], block.Drivers!.Select(d => d.Path));

        var alpha = Row(block, $@"{Drivers}\alpha.sys");
        Assert.Equal([KernelDriverSource.DriversDirectory, KernelDriverSource.Service, KernelDriverSource.Loaded], alpha.Sources);
        Assert.Equal(("alpha", "kernel", "boot", true), (alpha.ServiceName, alpha.ServiceType, alpha.StartType, alpha.Loaded));
        Assert.Equal((KernelDriverHashStatus.Hashed, Sha256(Bytes("alpha")), Sha1(Bytes("alpha")), 5L),
            (alpha.HashStatus, alpha.Sha256, alpha.Sha1, alpha.SizeBytes));
        Assert.Null(alpha.AuthenticodeSha256); // not a PE

        var beta = Row(block, $@"{Drivers}\beta.sys");
        Assert.Equal([KernelDriverSource.DriversDirectory], beta.Sources);
        Assert.Equal((null, false), (beta.ServiceName, beta.Loaded));

        var gamma = Row(block, @"C:\Vendor\gamma.sys");
        Assert.Equal(("gamma", "file_system", "auto"), (gamma.ServiceName, gamma.ServiceType, gamma.StartType));
        Assert.Equal([KernelDriverSource.Service, KernelDriverSource.Loaded], gamma.Sources);

        // Each file was opened once, whatever the number of sources that named it.
        Assert.Equal(3, files.Opened.Count);
    }

    [Fact]
    public void Build_AServiceWithNoImagePath_IsTheIoManagersDefault()
    {
        var files = new FakeFiles().Add($@"{Drivers}\quiet.sys", Bytes("q"));
        var block = KernelDriverInventoryLogic.Build(Sources(services: [Service("quiet", 1, null)]), files.Open, Limits());

        var row = Assert.Single(block.Drivers!);
        Assert.Equal($@"{Drivers}\quiet.sys", row.Path);
        Assert.Equal(KernelDriverHashStatus.Hashed, row.HashStatus);
    }

    [Fact]
    public void Build_AnUnsupportedImagePath_IsKeptUnhashed_WithTheServiceName()
    {
        var block = KernelDriverInventoryLogic.Build(
            Sources(services: [Service("remote", 1, @"\\server\share\evil.sys")]), new FakeFiles().Open, Limits());

        var row = Assert.Single(block.Drivers!);
        Assert.Null(row.Path);
        Assert.Equal(("remote", KernelDriverHashStatus.Unhashed, KernelDriverUnhashedReason.PathUnsupported),
            (row.ServiceName, row.HashStatus, row.UnhashedReason));
        Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
        Assert.Contains(KernelDriverErrorCode.DriverUnhashed, block.Errors);
    }

    [Fact]
    public void Build_AServiceWhoseTypeCannotBeRead_IsPartial_NeverSilentlyNotADriver()
    {
        var entry = new DriverServiceEntry("odd", RegistryRead.Failed, RegistryRead.Absent, RegistryRead.Absent);
        var block = KernelDriverInventoryLogic.Build(Sources(services: [entry]), new FakeFiles().Open, Limits());

        Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
        Assert.Contains(KernelDriverErrorCode.ServiceEntryUnreadable, block.Errors);
    }

    [Fact]
    public void Build_UnreadableServiceSubkeys_ArePartial()
    {
        var block = KernelDriverInventoryLogic.Build(Sources(unreadableServices: 2), new FakeFiles().Open, Limits());
        Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
        Assert.Contains(KernelDriverErrorCode.ServiceEntryUnreadable, block.Errors);
    }

    [Fact]
    public void Build_ALoadedModuleWithNoRoot_IsNotGuessed()
    {
        var block = KernelDriverInventoryLogic.Build(Sources(loaded: ["ntoskrnl.exe"]), new FakeFiles().Open, Limits());
        Assert.Empty(block.Drivers!);
        Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
        Assert.Contains(KernelDriverErrorCode.LoadedPathUnresolved, block.Errors);
    }

    [Fact]
    public void Build_WhenTheLoadedListFailed_LoadedIsOmitted_NotFalse()
    {
        var files = new FakeFiles().Add($@"{Drivers}\a.sys", Bytes("a"));
        var block = KernelDriverInventoryLogic.Build(Sources(directory: [$@"{Drivers}\a.sys"], loadedFailed: true), files.Open, Limits());

        Assert.Null(Assert.Single(block.Drivers!).Loaded);
        Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
        Assert.Equal([KernelDriverErrorCode.LoadedModulesUnreadable], block.Errors);
    }

    // -------------------------------------------------------------------------
    // Nothing is dropped: unreadable, missing and refused files stay as rows
    // -------------------------------------------------------------------------

    [Fact]
    public void Build_AFileThatCannotBeRead_IsUnhashed_AndTheListIsPartial()
    {
        var files = new FakeFiles()
            .Add($@"{Drivers}\ok.sys", Bytes("ok"))
            .Outcome($@"{Drivers}\locked.sys", DriverOpenOutcome.Failed);
        var block = KernelDriverInventoryLogic.Build(
            Sources(directory: [$@"{Drivers}\ok.sys", $@"{Drivers}\locked.sys"]), files.Open, Limits());

        var locked = Row(block, $@"{Drivers}\locked.sys");
        Assert.Equal((KernelDriverHashStatus.Unhashed, KernelDriverUnhashedReason.ReadFailed), (locked.HashStatus, locked.UnhashedReason));
        Assert.Null(locked.Sha256);
        Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
        Assert.Equal([KernelDriverErrorCode.DriverUnhashed], block.Errors);
        Assert.Equal(KernelDriverHashStatus.Hashed, Row(block, $@"{Drivers}\ok.sys").HashStatus);
    }

    [Fact]
    public void Build_AReadThatThrows_IsUnhashed_NeverAnException()
    {
        var files = new FakeFiles();
        files.Files[$@"{Drivers}\bad.sys"] = () => new DriverFileOpen(DriverOpenOutcome.Opened, new ThrowingStream(10));
        var block = KernelDriverInventoryLogic.Build(Sources(directory: [$@"{Drivers}\bad.sys"]), files.Open, Limits());

        Assert.Equal(KernelDriverUnhashedReason.ReadFailed, Assert.Single(block.Drivers!).UnhashedReason);
        Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
    }

    [Fact]
    public void Build_AReparsePoint_IsRefused_AndRecordedUnhashed()
    {
        var files = new FakeFiles().Outcome(@"C:\Temp\planted.sys", DriverOpenOutcome.ReparsePoint);
        var block = KernelDriverInventoryLogic.Build(
            Sources(services: [Service("planted", 1, @"\??\C:\Temp\planted.sys")]), files.Open, Limits());

        var row = Assert.Single(block.Drivers!);
        Assert.Equal((KernelDriverHashStatus.Unhashed, KernelDriverUnhashedReason.ReparsePoint), (row.HashStatus, row.UnhashedReason));
        Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
    }

    [Fact]
    public void Build_AMissingFile_IsAFact_NotAFailure()
    {
        var block = KernelDriverInventoryLogic.Build(
            Sources(services: [Service("gone", 1, @"System32\drivers\gone.sys")]), new FakeFiles().Open, Limits());

        var row = Assert.Single(block.Drivers!);
        Assert.Equal((KernelDriverHashStatus.Unhashed, KernelDriverUnhashedReason.FileMissing), (row.HashStatus, row.UnhashedReason));
        Assert.Equal(KernelDriverCollectionStatus.Complete, block.CollectionStatus);
    }

    // -------------------------------------------------------------------------
    // Bounds
    // -------------------------------------------------------------------------

    [Fact]
    public void Build_AFileOverThePerFileCap_IsUnhashed_WithItsSize()
    {
        var files = new FakeFiles().Add($@"{Drivers}\big.sys", new byte[2048]);
        var block = KernelDriverInventoryLogic.Build(Sources(directory: [$@"{Drivers}\big.sys"]), files.Open, Limits(maxFile: 1024));

        var row = Assert.Single(block.Drivers!);
        Assert.Equal((KernelDriverUnhashedReason.SizeLimit, 2048L), (row.UnhashedReason, row.SizeBytes));
        Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
    }

    [Fact]
    public void Build_PastTheCycleByteBudget_TheRestAreUnhashed()
    {
        var files = new FakeFiles()
            .Add($@"{Drivers}\a.sys", new byte[600])
            .Add($@"{Drivers}\b.sys", new byte[600]);
        var block = KernelDriverInventoryLogic.Build(
            Sources(directory: [$@"{Drivers}\a.sys", $@"{Drivers}\b.sys"]), files.Open, Limits(maxTotal: 1000));

        Assert.Equal(KernelDriverHashStatus.Hashed, Row(block, $@"{Drivers}\a.sys").HashStatus);
        Assert.Equal(KernelDriverUnhashedReason.ByteBudget, Row(block, $@"{Drivers}\b.sys").UnhashedReason);
        Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
    }

    [Fact]
    public void Build_AReadThatNeverReturns_CostsTheBudgetAndNoMore()
    {
        using var release = new ManualResetEventSlim(false);
        var files = new FakeFiles().Add($@"{Drivers}\a.sys", Bytes("a"));
        files.Files[$@"{Drivers}\stuck.sys"] = () =>
        {
            release.Wait(TimeSpan.FromSeconds(30));
            return new DriverFileOpen(DriverOpenOutcome.Failed);
        };
        var clock = Stopwatch.StartNew();
        var block = KernelDriverInventoryLogic.Build(
            Sources(directory: [$@"{Drivers}\a.sys", $@"{Drivers}\stuck.sys", $@"{Drivers}\z.sys"]),
            files.Open, Limits(budget: TimeSpan.FromMilliseconds(300)));
        clock.Stop();
        release.Set();
        SpinWait.SpinUntil(() => !KernelDriverInventoryLogic.EarlierWorkerStillRunning, TimeSpan.FromSeconds(10));

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), $"took {clock.Elapsed}");
        Assert.Equal(KernelDriverHashStatus.Hashed, Row(block, $@"{Drivers}\a.sys").HashStatus);
        Assert.Equal(KernelDriverUnhashedReason.TimeBudget, Row(block, $@"{Drivers}\stuck.sys").UnhashedReason);
        Assert.Equal(KernelDriverUnhashedReason.TimeBudget, Row(block, $@"{Drivers}\z.sys").UnhashedReason);
        Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
    }

    /// <summary>
    /// A read that never returns leaves its worker thread blocked. The next cycle must not
    /// start another one behind it (a thread per cycle, forever): it reports every row
    /// time_budget at once and opens nothing until the stuck worker has gone.
    /// </summary>
    [Fact]
    public void Build_WhileAnEarlierWorkerIsStuck_StartsNoSecondWorker()
    {
        using var release = new ManualResetEventSlim(false);
        var stuck = new FakeFiles();
        stuck.Files[$@"{Drivers}\stuck.sys"] = () =>
        {
            release.Wait(TimeSpan.FromSeconds(30));
            return new DriverFileOpen(DriverOpenOutcome.Failed);
        };
        try
        {
            KernelDriverInventoryLogic.Build(Sources(directory: [$@"{Drivers}\stuck.sys"]), stuck.Open,
                Limits(budget: TimeSpan.FromMilliseconds(200)));
            Assert.True(KernelDriverInventoryLogic.EarlierWorkerStillRunning);

            var next = new FakeFiles().Add($@"{Drivers}\a.sys", Bytes("a"));
            var clock = Stopwatch.StartNew();
            var block = KernelDriverInventoryLogic.Build(Sources(directory: [$@"{Drivers}\a.sys"]), next.Open,
                Limits(budget: TimeSpan.FromSeconds(10)));

            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"took {clock.Elapsed}");
            Assert.Empty(next.Opened);
            Assert.Equal(KernelDriverUnhashedReason.TimeBudget, Assert.Single(block.Drivers!).UnhashedReason);
            Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
        }
        finally
        {
            release.Set();
            SpinWait.SpinUntil(() => !KernelDriverInventoryLogic.EarlierWorkerStillRunning, TimeSpan.FromSeconds(10));
        }
        var after = new FakeFiles().Add($@"{Drivers}\a.sys", Bytes("a"));
        Assert.Equal(KernelDriverHashStatus.Hashed, Assert.Single(KernelDriverInventoryLogic.Build(
            Sources(directory: [$@"{Drivers}\a.sys"]), after.Open, Limits()).Drivers!).HashStatus);
    }

    [Fact]
    public void Build_PastTheRowCap_KeepsLoadedAndServiceRowsFirst_AndIsPartial()
    {
        var files = new FakeFiles();
        var directory = Enumerable.Range(0, 5).Select(i => $@"{Drivers}\a{i}.sys").ToList();
        var block = KernelDriverInventoryLogic.Build(Sources(
                directory: directory,
                services: [Service("zsvc", 1, @"System32\drivers\zsvc.sys")],
                loaded: [@"\SystemRoot\System32\drivers\zload.sys"]),
            files.Open, Limits(maxDrivers: 3));

        Assert.Equal(3, block.Drivers!.Count);
        Assert.Contains(block.Drivers, d => d.Path!.EndsWith("zsvc.sys"));
        Assert.Contains(block.Drivers, d => d.Path!.EndsWith("zload.sys"));
        Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
        Assert.Contains(KernelDriverErrorCode.DriverCountLimit, block.Errors);
    }

    // -------------------------------------------------------------------------
    // Unavailable
    // -------------------------------------------------------------------------

    [Fact]
    public void Build_WhenEverySourceFailed_IsUnavailable_WithNoList_AndEnforcementStillSent()
    {
        var block = KernelDriverInventoryLogic.Build(
            Sources(directoryFailed: true, servicesFailed: true, loadedFailed: true), new FakeFiles().Open, Limits());

        Assert.Equal(KernelDriverCollectionStatus.Unavailable, block.CollectionStatus);
        Assert.Null(block.Drivers);
        Assert.Equal(
            [KernelDriverErrorCode.DriversDirectoryUnreadable, KernelDriverErrorCode.ServicesUnreadable, KernelDriverErrorCode.LoadedModulesUnreadable],
            block.Errors);
        Assert.Same(Enforcement, block.Enforcement);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("/usr/lib")]
    [InlineData(@"\\server\Windows")]
    public void Build_WithNoUsableSystemRoot_IsUnavailable(string? systemRoot)
    {
        var block = KernelDriverInventoryLogic.Build(
            Sources(directory: [$@"{Drivers}\a.sys"], systemRoot: systemRoot), new FakeFiles().Open, Limits());

        Assert.Equal(KernelDriverCollectionStatus.Unavailable, block.CollectionStatus);
        Assert.Equal([KernelDriverErrorCode.CollectionFailed], block.Errors);
    }

    [Fact]
    public void Build_OneSourceFailing_IsPartial_NotUnavailable()
    {
        var files = new FakeFiles().Add($@"{Drivers}\a.sys", Bytes("a"));
        var block = KernelDriverInventoryLogic.Build(
            Sources(directory: [$@"{Drivers}\a.sys"], servicesFailed: true), files.Open, Limits());

        Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
        Assert.Equal([KernelDriverErrorCode.ServicesUnreadable], block.Errors);
        Assert.Single(block.Drivers!);
    }

    // -------------------------------------------------------------------------
    // The drivers directory listing, on a real (temporary) directory
    // -------------------------------------------------------------------------

    [Fact]
    public void List_ReturnsTheSysFiles_IncludingLinks_AndSkipsDirectories()
    {
        var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "patched-drivers-" + Guid.NewGuid().ToString("N"))).FullName;
        try
        {
            File.WriteAllText(Path.Combine(dir, "a.sys"), "a");
            File.WriteAllText(Path.Combine(dir, "B.SYS"), "b");
            File.WriteAllText(Path.Combine(dir, "c.txt"), "c");
            File.WriteAllText(Path.Combine(dir, "d.sysx"), "d");
            Directory.CreateDirectory(Path.Combine(dir, "sub.sys"));
            var linked = OperatingSystem.IsWindows() ? null : Path.Combine(dir, "link.sys");
            if (linked is not null) File.CreateSymbolicLink(linked, Path.Combine(dir, "a.sys"));

            var listing = DriverDirectoryLister.List(dir);

            Assert.False(listing.Failed);
            var names = listing.Files.Select(Path.GetFileName).ToList();
            Assert.Equal(linked is null ? ["a.sys", "B.SYS"] : ["a.sys", "B.SYS", "link.sys"], names);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void List_AMissingDirectory_IsUnreadable_NotEmpty() =>
        Assert.True(DriverDirectoryLister.List(Path.Combine(Path.GetTempPath(), "patched-no-such-" + Guid.NewGuid().ToString("N"))).Failed);

    [Fact]
    public void List_PastTheEntryCap_IsUnreadable_NotTruncated()
    {
        var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "patched-drivers-" + Guid.NewGuid().ToString("N"))).FullName;
        try
        {
            for (var i = 0; i < 4; i++) File.WriteAllText(Path.Combine(dir, $"d{i}.sys"), "x");
            Assert.True(DriverDirectoryLister.List(dir, maxEntries: 3).Failed);
            Assert.Equal(4, DriverDirectoryLister.List(dir, maxEntries: 4).Files.Count);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // -------------------------------------------------------------------------
    // The kernel's loaded-module buffer (synthetic RTL_PROCESS_MODULES)
    // -------------------------------------------------------------------------

    private static byte[] ModuleBuffer(params byte[][] names)
    {
        var buffer = new byte[LoadedModuleParser.HeaderBytes + names.Length * LoadedModuleParser.EntryBytes];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, (uint)names.Length);
        for (var i = 0; i < names.Length; i++)
            names[i].CopyTo(buffer, LoadedModuleParser.HeaderBytes + i * LoadedModuleParser.EntryBytes + LoadedModuleParser.NameOffset);
        return buffer;
    }

    [Fact]
    public void LoadedModules_AreReadByName_AndAnUnprintableNameIsNotGuessed()
    {
        var list = LoadedModuleParser.Parse(ModuleBuffer(
            Bytes(@"\SystemRoot\system32\ntoskrnl.exe"),
            Bytes(@"\SystemRoot\System32\drivers\a.sys"),
            [0x5C, 0x3F, 0xE9, 0x2E, 0x73, 0x79, 0x73]));

        Assert.False(list.Failed);
        Assert.Equal([@"\SystemRoot\system32\ntoskrnl.exe", @"\SystemRoot\System32\drivers\a.sys", ""], list.Names);
    }

    [Fact]
    public void LoadedModules_AMalformedBuffer_IsUnreadable_NotEmpty()
    {
        Assert.True(LoadedModuleParser.Parse(new byte[4]).Failed);
        var truncated = ModuleBuffer(Bytes("x"), Bytes("y"));
        Assert.True(LoadedModuleParser.Parse(truncated.AsSpan(0, truncated.Length - 1)).Failed);
        Assert.True(LoadedModuleParser.Parse(ModuleBuffer()).Failed);
    }

    // -------------------------------------------------------------------------
    // ImagePath resolution
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(@"\SystemRoot\System32\drivers\x.sys", @"C:\Windows\System32\drivers\x.sys")]
    [InlineData(@"\systemroot\system32\DRIVERS\x.sys", @"C:\Windows\system32\DRIVERS\x.sys")]
    [InlineData(@"System32\drivers\x.sys", @"C:\Windows\System32\drivers\x.sys")]
    [InlineData(@"%SystemRoot%\System32\drivers\x.sys", @"C:\Windows\System32\drivers\x.sys")]
    [InlineData(@"%windir%\System32\drivers\x.sys", @"C:\Windows\System32\drivers\x.sys")]
    [InlineData(@"\??\D:\Vendor\x.sys", @"D:\Vendor\x.sys")]
    [InlineData(@"\\?\D:\Vendor\x.sys", @"D:\Vendor\x.sys")]
    [InlineData(@"\Program Files\V\x.sys", @"C:\Program Files\V\x.sys")]
    [InlineData(@"""C:\Program Files\V\x.sys""", @"C:\Program Files\V\x.sys")]
    [InlineData(@"C:\Vendor\x.sys", @"C:\Vendor\x.sys")]
    public void Resolve_KnownForms(string raw, string expected) =>
        Assert.Equal(expected, DriverPathResolver.Resolve(raw, Root));

    [Theory]
    [InlineData(@"\\server\share\x.sys")]
    [InlineData(@"\??\UNC\server\share\x.sys")]
    [InlineData(@"%TEMP%\x.sys")]
    [InlineData(@"..\..\x.sys")]
    [InlineData(@"C:\Vendor\..\x.sys")]
    [InlineData(@"C:\Vendor\x.sys:stream")]
    [InlineData("C:\\Vendor\\x\u0001.sys")]
    [InlineData(@"C:/Vendor/x.sys")]
    [InlineData("")]
    [InlineData(null)]
    public void Resolve_AnythingElse_IsUnsupported(string? raw) =>
        Assert.Null(DriverPathResolver.Resolve(raw, Root));

    [Fact]
    public void Resolve_AnOverlongPath_IsUnsupported() =>
        Assert.Null(DriverPathResolver.Resolve(@"C:\" + new string('a', 600) + ".sys", Root));

    // -------------------------------------------------------------------------
    // Hashing: flat and Authenticode, on synthetic PE headers
    // -------------------------------------------------------------------------

    /// <summary>
    /// A synthetic PE32+ image (the local-model test fixture), with a fake certificate table
    /// appended and pointed to by data directory 4 when <paramref name="certTable"/> is given.
    /// </summary>
    private static byte[] SyntheticPe(byte[]? certTable, ushort a = 1, ushort b = 2, ushort c = 3, ushort d = 4)
    {
        var image = PeFixture.WithVersion(a, b, c, d);
        // A checksum value, so leaving it out is observable.
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(PeCheckSumAt), 0xDEADBEEF);
        if (certTable is null) return image;
        var at = (image.Length + 7) & ~7;
        var withCert = new byte[at + certTable.Length];
        image.CopyTo(withCert, 0);
        certTable.CopyTo(withCert, at);
        BinaryPrimitives.WriteUInt32LittleEndian(withCert.AsSpan(PeCertDirectoryAt), (uint)at);
        BinaryPrimitives.WriteUInt32LittleEndian(withCert.AsSpan(PeCertDirectoryAt + 4), (uint)certTable.Length);
        return withCert;
    }

    // PeFixture puts the PE header at 0x80: the optional header starts at 0x98, its CheckSum
    // is at +64 and (PE32+) data directory 4 is at +112 + 4*8.
    private const int PeCheckSumAt = 0x98 + 64;
    private const int PeCertDirectoryAt = 0x98 + 112 + 32;

    /// <summary>The Authenticode digest computed the slow, obvious way: copy out the included bytes.</summary>
    private static byte[] ExpectedAuthenticodeInput(byte[] file)
    {
        var certAt = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(PeCertDirectoryAt));
        var certLength = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(PeCertDirectoryAt + 4));
        var included = new List<byte>();
        for (var i = 0; i < file.Length; i++)
        {
            if (i >= PeCheckSumAt && i < PeCheckSumAt + 4) continue;
            if (i >= PeCertDirectoryAt && i < PeCertDirectoryAt + 8) continue;
            if (certLength > 0 && i >= certAt && i < certAt + certLength) continue;
            included.Add(file[i]);
        }
        return included.ToArray();
    }

    [Fact]
    public void Hash_ASignedPe_GivesFlatAndAuthenticodeDigests()
    {
        var file = SyntheticPe(certTable: Enumerable.Range(0, 64).Select(i => (byte)i).ToArray());
        var hashes = DriverFileHasher.Hash(new MemoryStream(file), CancellationToken.None);

        Assert.Equal(Sha256(file), hashes.Sha256);
        Assert.Equal(Sha1(file), hashes.Sha1);
        var input = ExpectedAuthenticodeInput(file);
        Assert.Equal(Sha256(input), hashes.AuthenticodeSha256);
        Assert.Equal(Sha1(input), hashes.AuthenticodeSha1);
        Assert.NotEqual(hashes.Sha256, hashes.AuthenticodeSha256);
    }

    [Fact]
    public void Hash_TheAuthenticodeDigest_IgnoresTheCheckSumAndTheSignature()
    {
        var one = SyntheticPe(certTable: new byte[32]);
        var two = (byte[])one.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(two.AsSpan(PeCheckSumAt), 0x12345678);
        two[^1] ^= 0xFF; // inside the certificate table

        var a = DriverFileHasher.Hash(new MemoryStream(one), CancellationToken.None);
        var b = DriverFileHasher.Hash(new MemoryStream(two), CancellationToken.None);

        Assert.Equal(a.AuthenticodeSha256, b.AuthenticodeSha256);
        Assert.NotEqual(a.Sha256, b.Sha256);
    }

    [Fact]
    public void Hash_AnUnsignedPe_LeavesOutOnlyTheCheckSumAndDirectoryEntry()
    {
        var file = SyntheticPe(certTable: null);
        var hashes = DriverFileHasher.Hash(new MemoryStream(file), CancellationToken.None);
        Assert.Equal(Sha256(ExpectedAuthenticodeInput(file)), hashes.AuthenticodeSha256);
    }

    [Fact]
    public void Hash_ACertificateDirectoryPointingOutsideTheFile_GivesNoAuthenticodeDigest()
    {
        var file = SyntheticPe(certTable: new byte[16]);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(PeCertDirectoryAt + 4), 0x7FFF_0000);
        var hashes = DriverFileHasher.Hash(new MemoryStream(file), CancellationToken.None);

        Assert.Null(hashes.AuthenticodeSha256);
        Assert.Null(hashes.AuthenticodeSha1);
        Assert.Equal(Sha256(file), hashes.Sha256);
    }

    [Fact]
    public void Hash_ANonPe_GivesFlatDigestsOnly()
    {
        var hashes = DriverFileHasher.Hash(new MemoryStream(Bytes("MZ but nothing else")), CancellationToken.None);
        Assert.Null(hashes.AuthenticodeSha256);
        Assert.Equal(Sha256(Bytes("MZ but nothing else")), hashes.Sha256);
    }

    [Fact]
    public void Hash_AcrossManyChunks_MatchesTheOneShotDigest()
    {
        var cert = new byte[40];
        var file = SyntheticPe(cert);
        var big = new byte[file.Length + 700_000];
        file.AsSpan(0, file.Length - cert.Length - 0).CopyTo(big);
        // Move the certificate table to the end of the enlarged file.
        var certAt = big.Length - cert.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(big.AsSpan(PeCertDirectoryAt), (uint)certAt);
        RandomNumberGenerator.Fill(big.AsSpan(file.Length, 700_000 - 8));
        var hashes = DriverFileHasher.Hash(new MemoryStream(big), CancellationToken.None);

        Assert.Equal(Sha256(big), hashes.Sha256);
        Assert.Equal(Sha256(ExpectedAuthenticodeInput(big)), hashes.AuthenticodeSha256);
    }

    [Fact]
    public void Build_APeDriver_CarriesItsFileVersion_NotItsProductVersion()
    {
        var file = SyntheticPe(certTable: new byte[8], a: 10, b: 0, c: 22621, d: 1);
        // PeFixture writes the same file and product version; make the product version differ.
        var productVersionAt = 0x200 + 0x58 + 40 + 16;
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(productVersionAt), (9u << 16) | 9);
        var files = new FakeFiles().Add($@"{Drivers}\pe.sys", file);
        var block = KernelDriverInventoryLogic.Build(Sources(directory: [$@"{Drivers}\pe.sys"]), files.Open, Limits());

        var row = Assert.Single(block.Drivers!);
        Assert.Equal("10.0.22621.1", row.Version);
        Assert.NotNull(row.AuthenticodeSha256);
    }

    // -------------------------------------------------------------------------
    // Enforcement state
    // -------------------------------------------------------------------------

    public static IEnumerable<object[]> BlocklistCases() =>
    [
        [RegistryRead.Present(1), "enabled"],
        [RegistryRead.Present(0), "disabled"],
        [RegistryRead.Absent, "not_set"],
        [RegistryRead.Failed, "unknown"],
        [RegistryRead.Present("1"), "unknown"],
        [RegistryRead.Present(7), "unknown"],
    ];

    [Theory]
    [MemberData(nameof(BlocklistCases))]
    public void Enforcement_BlocklistValue(RegistryRead read, string expected) =>
        Assert.Equal(expected, DriverEnforcementLogic.Build(read, RegistryRead.Absent, SourceRead.Absent, SourceRead.Absent)
            .VulnerableDriverBlocklist);

    [Fact]
    public void Enforcement_BlocklistOn_IsEnforced()
    {
        var e = DriverEnforcementLogic.Build(RegistryRead.Present(1), RegistryRead.Failed, SourceRead.Failed, SourceRead.Failed);
        Assert.Equal(("enabled", "yes"), (e.VulnerableDriverBlocklist, e.BlocklistEnforced));
    }

    [Fact]
    public void Enforcement_BlocklistOff_WithHvciRunning_IsStillEnforced()
    {
        var e = DriverEnforcementLogic.Build(RegistryRead.Present(0), RegistryRead.Present(0), SourceRead.Present(2u), SourceRead.Present(0u));
        Assert.Equal(("disabled", "running", "yes"), (e.VulnerableDriverBlocklist, e.Hvci, e.BlocklistEnforced));
    }

    [Fact]
    public void Enforcement_BlocklistOff_WithSmartAppControlOn_IsStillEnforced()
    {
        var e = DriverEnforcementLogic.Build(RegistryRead.Present(0), RegistryRead.Present(1), SourceRead.Present(0u), SourceRead.Present(0u));
        Assert.Equal(("on", "yes"), (e.SmartAppControl, e.BlocklistEnforced));
    }

    [Fact]
    public void Enforcement_BlocklistOff_AndNothingForcingIt_IsNotEnforced()
    {
        var e = DriverEnforcementLogic.Build(RegistryRead.Present(0), RegistryRead.Absent, SourceRead.Present(1u), SourceRead.Present(2u));
        Assert.Equal(("disabled", "configured", "not_present", "enforced", "no"),
            (e.VulnerableDriverBlocklist, e.Hvci, e.SmartAppControl, e.CodeIntegrityPolicy, e.BlocklistEnforced));
    }

    [Fact]
    public void Enforcement_BlocklistOff_ButHvciUnreadable_IsUnknown_NeverNo()
    {
        var e = DriverEnforcementLogic.Build(RegistryRead.Present(0), RegistryRead.Present(0), SourceRead.Failed, SourceRead.Failed);
        Assert.Equal(("unknown", "unknown", "unknown"), (e.Hvci, e.CodeIntegrityPolicy, e.BlocklistEnforced));
    }

    [Fact]
    public void Enforcement_BlocklistUnreadable_IsUnknown()
    {
        var e = DriverEnforcementLogic.Build(RegistryRead.Failed, RegistryRead.Present(0), SourceRead.Present(0u), SourceRead.Present(0u));
        Assert.Equal(("unknown", "unknown"), (e.VulnerableDriverBlocklist, e.BlocklistEnforced));
    }

    [Fact]
    public void Enforcement_NotSet_IsNotInferredFromTheBuild()
    {
        var e = DriverEnforcementLogic.Build(RegistryRead.Absent, RegistryRead.Present(0), SourceRead.Present(0u), SourceRead.Present(0u));
        Assert.Equal(("not_set", "unknown"), (e.VulnerableDriverBlocklist, e.BlocklistEnforced));
    }

    [Fact]
    public void Enforcement_SmartAppControlEvaluation_LeavesItUnknown()
    {
        var e = DriverEnforcementLogic.Build(RegistryRead.Present(0), RegistryRead.Present(2), SourceRead.Present(0u), SourceRead.Present(0u));
        Assert.Equal(("evaluation", "unknown"), (e.SmartAppControl, e.BlocklistEnforced));
    }

    private sealed class ThrowingStream(long length) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get; set; }
        public override int Read(byte[] buffer, int offset, int count) => throw new IOException("device error");
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => Position = offset;
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
