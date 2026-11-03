using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Compliance;
using Patched.Shared.Contract;
using Patched.Shared.DeviceClassification;
using Patched.Shared.KernelDrivers;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2263: the Windows wiring behind the <c>kernel_drivers</c> block. The collector's
/// sources (system root, drivers directory, Services key, loaded-module list, CI registry
/// values, Win32_DeviceGuard) and its file opener are swapped for fakes so the wiring and the
/// wire bytes are checked off-box; the rules themselves are covered in Shared.Tests
/// (KernelDriverInventoryTests).
///
/// The wire tests serialise with the real <c>InventoryPoster.JsonOpts</c>, read by
/// reflection, and pin the exact bytes. The complete, partial and unavailable strings below
/// are copied verbatim into the platform repo's payload fixtures
/// (go-service/testdata/payload-fixtures/valid/with-kernel-drivers-*-windows.json) and its
/// ValidatePayload test, so agent and platform are checked against the same JSON. Every file
/// served here is synthetic: nothing is, or was derived from, a real driver.
/// </summary>
public sealed class KernelDriverCollectorTests
{
    private const string Root = @"C:\Windows";
    private const string Drivers = @"C:\Windows\System32\drivers";

    private static readonly byte[] FlatFile = Encoding.ASCII.GetBytes("patched synthetic driver: not a PE");
    private static readonly byte[] PeFile = SyntheticPe();

    /// <summary>
    /// PAT-2309: KernelDriverInventoryLogic runs at most one hashing worker per process. While
    /// an earlier worker is alive it opens nothing and reports every row <c>time_budget</c>,
    /// and xUnit runs test classes in parallel, so a test elsewhere in this assembly that
    /// hashes real files (InventoryPosterQueueHealthTests once hashed the Windows runner's own
    /// drivers) turned these tests into misleading <c>time_budget</c>/<c>partial</c> failures.
    /// Runs before each test: wait briefly for any such worker to finish, then fail naming the
    /// cause rather than as a wrong status further down. This catches a worker still alive
    /// when a test starts; it cannot stop one started while a test runs, so no test in this
    /// assembly may hash real files.
    /// </summary>
    public KernelDriverCollectorTests()
    {
        SpinWait.SpinUntil(() => !KernelDriverInventoryLogic.EarlierWorkerStillRunning, TimeSpan.FromSeconds(10));
        Assert.False(KernelDriverInventoryLogic.EarlierWorkerStillRunning,
            "PAT-2309: a kernel-driver hashing worker started elsewhere in this test assembly is still " +
            "running after 10s. KernelDriverInventoryLogic's static in-flight guard would report every " +
            "row here as time_budget. Build that test's KernelDriverCollector with faked sources and " +
            "opener instead of the real reads.");
    }

    private sealed record Fakes
    {
        public string? SystemRoot { get; init; } = Root;
        public DriverDirectoryListing Directory { get; init; } =
            new(false, [$@"{Drivers}\flat.sys", $@"{Drivers}\pe.sys"]);
        public DriverServiceEnumeration Services { get; init; } = new(false,
        [
            new DriverServiceEntry("pe", RegistryRead.Present(1), RegistryRead.Present(@"\SystemRoot\System32\drivers\pe.sys"), RegistryRead.Present(1)),
            new DriverServiceEntry("vendorfs", RegistryRead.Present(2), RegistryRead.Present(@"\??\C:\Vendor\vendorfs.sys"), RegistryRead.Present(3)),
            new DriverServiceEntry("Spooler", RegistryRead.Present(16), RegistryRead.Present(@"C:\Windows\System32\spoolsv.exe"), RegistryRead.Present(2)),
        ]);
        public LoadedModuleList Loaded { get; init; } = new(false, [@"\SystemRoot\System32\drivers\pe.sys"]);
        public RegistryRead Blocklist { get; init; } = RegistryRead.Present(1);
        public RegistryRead SmartAppControl { get; init; } = RegistryRead.Present(0);
        public SourceRead CodeIntegrity { get; init; } = SourceRead.Present(0u);
        public Dictionary<string, DriverOpenOutcome> Outcomes { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private static KernelDriverCollector Collector(Fakes f) => new(
        NullLogger<KernelDriverCollector>.Instance,
        systemRoot: () => f.SystemRoot,
        listDirectory: dir =>
        {
            Assert.Equal(Path.Combine(Root, "System32", "drivers"), dir);
            return f.Directory;
        },
        services: () => f.Services,
        loaded: () => f.Loaded,
        hklm: (key, value) => (key, value) switch
        {
            (KernelDriverCollector.CiConfigKey, KernelDriverCollector.BlocklistValue) => f.Blocklist,
            (KernelDriverCollector.CiPolicyKey, KernelDriverCollector.SmartAppControlValue) => f.SmartAppControl,
            _ => throw new InvalidOperationException($"unexpected registry read {key}\\{value}"),
        },
        codeIntegrityPolicy: () => f.CodeIntegrity,
        open: path =>
        {
            if (f.Outcomes.TryGetValue(path, out var outcome)) return new DriverFileOpen(outcome);
            if (path.Equals($@"{Drivers}\flat.sys", StringComparison.OrdinalIgnoreCase))
                return new DriverFileOpen(DriverOpenOutcome.Opened, new MemoryStream(FlatFile, writable: false));
            if (path.Equals($@"{Drivers}\pe.sys", StringComparison.OrdinalIgnoreCase))
                return new DriverFileOpen(DriverOpenOutcome.Opened, new MemoryStream(PeFile, writable: false));
            return new DriverFileOpen(DriverOpenOutcome.Missing);
        },
        limits: new KernelDriverLimits(1500, 1 << 20, 1 << 30, TimeSpan.FromSeconds(30)));

    private static JsonSerializerOptions PosterOpts()
    {
        var field = typeof(InventoryPoster).GetField("JsonOpts", BindingFlags.NonPublic | BindingFlags.Static);
        return (JsonSerializerOptions)field!.GetValue(null)!;
    }

    private static string Wire(InventoryKernelDrivers block) => JsonSerializer.Serialize(block, PosterOpts());

    // -------------------------------------------------------------------------
    // Wiring
    // -------------------------------------------------------------------------

    [Fact]
    public void Collect_ReadsEverySource_AndOnlyTheDriverServices()
    {
        var block = Collector(new Fakes()).Collect(SourceRead.Present(2u));

        Assert.Equal(KernelDriverCollectionStatus.Complete, block.CollectionStatus);
        Assert.Equal([@"C:\Vendor\vendorfs.sys", $@"{Drivers}\flat.sys", $@"{Drivers}\pe.sys"], block.Drivers!.Select(d => d.Path));
        Assert.DoesNotContain(block.Drivers!, d => d.ServiceName == "Spooler");
        var pe = block.Drivers!.Single(d => d.ServiceName == "pe");
        Assert.Equal((true, "system"), (pe.Loaded, pe.StartType));
        Assert.NotNull(pe.AuthenticodeSha256);
        Assert.Equal("10.0.22621.2506", pe.Version);
        Assert.Equal(KernelDriverUnhashedReason.FileMissing, block.Drivers!.Single(d => d.ServiceName == "vendorfs").UnhashedReason);
        Assert.Equal(("enabled", "running", "off", "off", "yes"),
            (block.Enforcement.VulnerableDriverBlocklist, block.Enforcement.Hvci, block.Enforcement.SmartAppControl,
             block.Enforcement.CodeIntegrityPolicy, block.Enforcement.BlocklistEnforced));
    }

    [Fact]
    public void Collect_BlocklistOff_NothingForcingIt_IsNotEnforced()
    {
        var block = Collector(new Fakes { Blocklist = RegistryRead.Present(0) }).Collect(SourceRead.Present(0u));
        Assert.Equal(("disabled", "no"), (block.Enforcement.VulnerableDriverBlocklist, block.Enforcement.BlocklistEnforced));
    }

    [Fact]
    public void Collect_BlocklistUnreadable_IsUnknown()
    {
        var block = Collector(new Fakes { Blocklist = RegistryRead.Failed }).Collect(SourceRead.Present(0u));
        Assert.Equal(("unknown", "unknown"), (block.Enforcement.VulnerableDriverBlocklist, block.Enforcement.BlocklistEnforced));
    }

    [Fact]
    public void Collect_AnUnreadableFile_IsUnhashed_AndPartial()
    {
        var fakes = new Fakes();
        fakes.Outcomes[$@"{Drivers}\flat.sys"] = DriverOpenOutcome.Failed;
        var block = Collector(fakes).Collect(SourceRead.Present(2u));

        Assert.Equal(KernelDriverCollectionStatus.Partial, block.CollectionStatus);
        Assert.Equal(KernelDriverUnhashedReason.ReadFailed, block.Drivers!.Single(d => d.Path!.EndsWith("flat.sys")).UnhashedReason);
    }

    [Fact]
    public void Collect_WithEverySourceFailing_IsUnavailable_AndKeepsEnforcement()
    {
        var block = Collector(new Fakes
        {
            Directory = DriverDirectoryListing.Unreadable,
            Services = DriverServiceEnumeration.Unreadable,
            Loaded = LoadedModuleList.Unreadable,
        }).Collect(SourceRead.Present(2u));

        Assert.Equal(KernelDriverCollectionStatus.Unavailable, block.CollectionStatus);
        Assert.Null(block.Drivers);
        Assert.Equal("yes", block.Enforcement.BlocklistEnforced);
    }

    [Fact]
    public void Collect_WhenASourceThrows_IsUnavailable_NeverAnException()
    {
        var collector = new KernelDriverCollector(
            NullLogger<KernelDriverCollector>.Instance,
            systemRoot: () => Root,
            listDirectory: _ => throw new InvalidOperationException("boom"),
            services: () => DriverServiceEnumeration.Unreadable,
            loaded: () => LoadedModuleList.Unreadable,
            hklm: (_, _) => throw new InvalidOperationException("boom"),
            codeIntegrityPolicy: () => SourceRead.Failed,
            open: _ => new DriverFileOpen(DriverOpenOutcome.Failed));

        var block = collector.Collect(SourceRead.Failed);

        Assert.Equal(KernelDriverCollectionStatus.Unavailable, block.CollectionStatus);
        Assert.Equal([KernelDriverErrorCode.CollectionFailed], block.Errors);
        Assert.Equal("unknown", block.Enforcement.VulnerableDriverBlocklist);
    }

    /// <summary>
    /// Off Windows every real read fails, and the block says so rather than throwing.
    ///
    /// PAT-2309: the file opener is the one seam still faked, and it reports every file
    /// missing. The real opener would hash every driver in the Windows runner's
    /// System32\drivers (up to the 90-second budget) on the process-wide hashing worker, and
    /// while that worker is alive any other collect in this assembly reports
    /// <c>time_budget</c>. The real opener is covered by the OpenDriverFile tests below.
    /// </summary>
    [Fact]
    public void Collect_WithTheRealReads_NeverThrows()
    {
        var block = new KernelDriverCollector(
            NullLogger<KernelDriverCollector>.Instance,
            systemRoot: null,
            open: _ => new DriverFileOpen(DriverOpenOutcome.Missing)).Collect(SourceRead.Failed);
        Assert.Contains(block.CollectionStatus, new[] { "complete", "partial", "unavailable" });
        if (!OperatingSystem.IsWindows()) Assert.Equal(KernelDriverCollectionStatus.Unavailable, block.CollectionStatus);
    }

    // -------------------------------------------------------------------------
    // The production opener (Windows only: it is the locked, reparse-refusing walk)
    // -------------------------------------------------------------------------

    [WindowsFact]
    public void OpenDriverFile_ARegularFile_Opens_AndAMissingOneIsMissing()
    {
        var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "patched-drv-" + Guid.NewGuid().ToString("N"))).FullName;
        try
        {
            var file = Path.Combine(dir, "plain.sys");
            File.WriteAllBytes(file, FlatFile);
            using (var open = KernelDriverCollector.OpenDriverFile(file))
            {
                Assert.Equal(DriverOpenOutcome.Opened, open.Outcome);
                Assert.Equal(FlatFile.Length, open.Stream!.Length);
            }
            using var missing = KernelDriverCollector.OpenDriverFile(Path.Combine(dir, "gone.sys"));
            Assert.Equal(DriverOpenOutcome.Missing, missing.Outcome);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [WindowsFact]
    public void OpenDriverFile_ThroughAJunction_IsRefused_AsAReparsePoint()
    {
        var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "patched-drv-" + Guid.NewGuid().ToString("N"))).FullName;
        try
        {
            var target = Directory.CreateDirectory(Path.Combine(dir, "real")).FullName;
            File.WriteAllBytes(Path.Combine(target, "x.sys"), FlatFile);
            var junction = Path.Combine(dir, "junction");
            var psi = new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{junction}\" \"{target}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            using (var p = Process.Start(psi)!)
            {
                Assert.True(p.WaitForExit(30_000));
                Assert.Equal(0, p.ExitCode);
            }

            using var open = KernelDriverCollector.OpenDriverFile(Path.Combine(junction, "x.sys"));
            Assert.Equal(DriverOpenOutcome.ReparsePoint, open.Outcome);
            Assert.Null(open.Stream);
        }
        finally
        {
            try { Directory.Delete(Path.Combine(dir, "junction")); } catch { }
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void OpenDriverFile_ANonLocalPath_IsUnsupported() =>
        Assert.Equal(DriverOpenOutcome.PathUnsupported, KernelDriverCollector.OpenDriverFile(@"\\server\share\x.sys").Outcome);

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows()) Skip = "Requires the Windows locked-open walk and NTFS junctions.";
        }
    }

    // -------------------------------------------------------------------------
    // Wire bytes, pinned (copied into the platform's payload fixtures)
    // -------------------------------------------------------------------------

    internal const string CompleteWire =
        """
        {"schema_version":1,"collection_status":"complete","errors":[],"enforcement":{"vulnerable_driver_blocklist":"enabled","hvci":"running","smart_app_control":"off","code_integrity_policy":"off","blocklist_enforced":"yes"},"drivers":[{"path":"C:\\Vendor\\vendorfs.sys","sources":["service"],"service_name":"vendorfs","service_type":"file_system","start_type":"demand","loaded":false,"hash_status":"unhashed","unhashed_reason":"file_missing"},{"path":"C:\\Windows\\System32\\drivers\\flat.sys","sources":["drivers_directory"],"loaded":false,"hash_status":"hashed","size_bytes":34,"sha256":"357c27a02e97161fc2fbb97dc21a8b3d60053a591a1f1d760d91159fcc507cf1","sha1":"d348d0ef0d72cf831c6cbfb9479ff27318bc8715"},{"path":"C:\\Windows\\System32\\drivers\\pe.sys","sources":["drivers_directory","service","loaded"],"service_name":"pe","service_type":"kernel","start_type":"system","loaded":true,"hash_status":"hashed","size_bytes":712,"sha256":"cd6ac90baf05f488c05f7ac2397bf0d2c40ed842bf4587f3f78c4af7f357857b","sha1":"7f7cd97c3162150aa4a205cc41efcad2f8c682bb","authenticode_sha256":"8812f0c849e0e9537b5060dd011057885eaf9047af11842840b97d8444eff841","authenticode_sha1":"49eb0bea78d9946ac607558732d912e74bb8dade","version":"10.0.22621.2506"}]}
        """;
    internal const string PartialWire =
        """
        {"schema_version":1,"collection_status":"partial","errors":["loaded_modules_unreadable","driver_unhashed"],"enforcement":{"vulnerable_driver_blocklist":"not_set","hvci":"configured","smart_app_control":"not_present","code_integrity_policy":"unknown","blocklist_enforced":"unknown"},"drivers":[{"path":"C:\\Windows\\System32\\drivers\\flat.sys","sources":["drivers_directory"],"hash_status":"unhashed","unhashed_reason":"reparse_point"},{"path":"C:\\Windows\\System32\\drivers\\pe.sys","sources":["drivers_directory","service"],"service_name":"pe","service_type":"kernel","start_type":"demand","hash_status":"hashed","size_bytes":712,"sha256":"cd6ac90baf05f488c05f7ac2397bf0d2c40ed842bf4587f3f78c4af7f357857b","sha1":"7f7cd97c3162150aa4a205cc41efcad2f8c682bb","authenticode_sha256":"8812f0c849e0e9537b5060dd011057885eaf9047af11842840b97d8444eff841","authenticode_sha1":"49eb0bea78d9946ac607558732d912e74bb8dade","version":"10.0.22621.2506"},{"sources":["service"],"service_name":"remote","service_type":"kernel","start_type":"disabled","hash_status":"unhashed","unhashed_reason":"path_unsupported"}]}
        """;
    internal const string UnavailableWire =
        """
        {"schema_version":1,"collection_status":"unavailable","errors":["drivers_directory_unreadable","services_unreadable","loaded_modules_unreadable"],"enforcement":{"vulnerable_driver_blocklist":"disabled","hvci":"off","smart_app_control":"off","code_integrity_policy":"off","blocklist_enforced":"no"}}
        """;

    [Fact]
    public void Wire_Complete_IsPinned() =>
        Assert.Equal(CompleteWire, Wire(Collector(new Fakes()).Collect(SourceRead.Present(2u))));

    [Fact]
    public void Wire_Partial_IsPinned()
    {
        var fakes = new Fakes
        {
            Blocklist = RegistryRead.Absent,
            SmartAppControl = RegistryRead.Absent,
            CodeIntegrity = SourceRead.Failed,
            Loaded = LoadedModuleList.Unreadable,
            Services = new DriverServiceEnumeration(false,
            [
                new DriverServiceEntry("pe", RegistryRead.Present(1), RegistryRead.Absent, RegistryRead.Present(3)),
                new DriverServiceEntry("remote", RegistryRead.Present(1), RegistryRead.Present(@"\\server\share\remote.sys"), RegistryRead.Present(4)),
            ]),
        };
        fakes.Outcomes[$@"{Drivers}\flat.sys"] = DriverOpenOutcome.ReparsePoint;
        Assert.Equal(PartialWire, Wire(Collector(fakes).Collect(SourceRead.Present(1u))));
    }

    [Fact]
    public void Wire_Unavailable_IsPinned() =>
        Assert.Equal(UnavailableWire, Wire(Collector(new Fakes
        {
            Directory = DriverDirectoryListing.Unreadable,
            Services = DriverServiceEnumeration.Unreadable,
            Loaded = LoadedModuleList.Unreadable,
            Blocklist = RegistryRead.Present(0),
        }).Collect(SourceRead.Present(0u))));

    // -------------------------------------------------------------------------
    // A synthetic PE32+ image: headers, one .rsrc section holding a version resource
    // (10.0.22621.2506), and a fake 16-byte certificate table. Not a driver.
    // -------------------------------------------------------------------------

    private static byte[] SyntheticPe()
    {
        const int peAt = 0x80, rawAt = 0x200, versionAt = 0x58, versionLength = 92;
        const uint rsrcRva = 0x1000;
        const uint ms = (10u << 16) | 0, ls = (22621u << 16) | 2506;
        var rsrcLength = versionAt + versionLength;
        var image = new byte[rawAt + rsrcLength];
        var s = image.AsSpan();
        s[0] = (byte)'M'; s[1] = (byte)'Z';
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x3C..], peAt);
        "PE\0\0"u8.CopyTo(s[peAt..]);
        BinaryPrimitives.WriteUInt16LittleEndian(s[(peAt + 4)..], 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(s[(peAt + 6)..], 1);
        BinaryPrimitives.WriteUInt16LittleEndian(s[(peAt + 20)..], 240);
        var opt = peAt + 24;
        BinaryPrimitives.WriteUInt16LittleEndian(s[opt..], 0x20B);
        BinaryPrimitives.WriteUInt32LittleEndian(s[(opt + 64)..], 0x0001_2345); // CheckSum
        BinaryPrimitives.WriteUInt32LittleEndian(s[(opt + 108)..], 16);
        BinaryPrimitives.WriteUInt32LittleEndian(s[(opt + 112 + 16)..], rsrcRva);
        BinaryPrimitives.WriteUInt32LittleEndian(s[(opt + 112 + 20)..], (uint)rsrcLength);
        var section = opt + 240;
        ".rsrc"u8.CopyTo(s[section..]);
        BinaryPrimitives.WriteUInt32LittleEndian(s[(section + 8)..], (uint)rsrcLength);
        BinaryPrimitives.WriteUInt32LittleEndian(s[(section + 12)..], rsrcRva);
        BinaryPrimitives.WriteUInt32LittleEndian(s[(section + 16)..], (uint)rsrcLength);
        BinaryPrimitives.WriteUInt32LittleEndian(s[(section + 20)..], rawAt);
        var r = s[rawAt..];
        BinaryPrimitives.WriteUInt16LittleEndian(r[14..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(r[16..], 16);
        BinaryPrimitives.WriteUInt32LittleEndian(r[20..], 0x8000_0000 | 0x18);
        BinaryPrimitives.WriteUInt16LittleEndian(r[(0x18 + 14)..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(r[(0x18 + 16)..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(r[(0x18 + 20)..], 0x8000_0000 | 0x30);
        BinaryPrimitives.WriteUInt16LittleEndian(r[(0x30 + 14)..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(r[(0x30 + 16)..], 0x409);
        BinaryPrimitives.WriteUInt32LittleEndian(r[(0x30 + 20)..], 0x48);
        BinaryPrimitives.WriteUInt32LittleEndian(r[0x48..], rsrcRva + versionAt);
        BinaryPrimitives.WriteUInt32LittleEndian(r[(0x48 + 4)..], versionLength);
        var v = r[versionAt..];
        BinaryPrimitives.WriteUInt16LittleEndian(v, versionLength);
        BinaryPrimitives.WriteUInt16LittleEndian(v[2..], 52);
        Encoding.Unicode.GetBytes("VS_VERSION_INFO\0").CopyTo(v[6..]);
        BinaryPrimitives.WriteUInt32LittleEndian(v[40..], 0xFEEF04BD);
        BinaryPrimitives.WriteUInt32LittleEndian(v[44..], 0x0001_0000);
        BinaryPrimitives.WriteUInt32LittleEndian(v[48..], ms);
        BinaryPrimitives.WriteUInt32LittleEndian(v[52..], ls);
        BinaryPrimitives.WriteUInt32LittleEndian(v[56..], ms);
        BinaryPrimitives.WriteUInt32LittleEndian(v[60..], ls);

        var certAt = (image.Length + 7) & ~7;
        var signed = new byte[certAt + 16];
        image.CopyTo(signed, 0);
        for (var i = 0; i < 16; i++) signed[certAt + i] = (byte)(0xA0 + i);
        BinaryPrimitives.WriteUInt32LittleEndian(signed.AsSpan(opt + 112 + 32), (uint)certAt);
        BinaryPrimitives.WriteUInt32LittleEndian(signed.AsSpan(opt + 112 + 36), 16);
        return signed;
    }
}
