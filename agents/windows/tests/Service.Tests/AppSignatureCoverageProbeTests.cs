using System.Text.Json;
using Patched.Shared.Contract;
using Patched.Shared.InstallationEvidence;
using Xunit;

namespace Patched.Service.Tests;

// PAT-2116: the coverage helper's own run, with every IO seam replaced. What matters is
// the line order: a step line precedes every piece of IO for a target, so the parent can
// name the target a hung helper was working on.
public sealed class AppSignatureCoverageProbeTests
{
    private static readonly ResolutionRoots Roots = new(@"C:\Windows", [@"C:\Program Files"]);

    private static CoverageRequest Request(int[]? completed = null, int[]? stuck = null) => new(
        [new(0, "{A}", false), new(1, "B", true), new(2, "C", false), new(3, "D", false)],
        completed ?? [], stuck ?? [], []);

    private static UninstallLocation Location(CoverageTarget target) => target.Index switch
    {
        0 => new(0, @"C:\Program Files\A\a.exe,0", null),
        1 => new(0, null, @"C:\Program Files (x86)\B"), // outside the roots given above
        2 => throw new UnauthorizedAccessException(),
        _ => new(0, null, @"C:\Program Files\D"),
    };

    [Fact]
    public void EveryIoStepIsAnnouncedBeforeItHappensAndEveryTargetGetsAResult()
    {
        var lines = new List<CoverageLine>();
        var io = new List<string>();
        AppSignatureCoverageProbe.Run(Request(), Roots,
            target => { io.Add("reg" + target.Index); Assert.Equal(target.Index, lines[^1].Index); return Location(target); },
            dir => { io.Add("list"); Assert.Equal(3, lines[^1].Index); return ["d.exe"]; },
            (resolution, _) =>
            {
                io.Add("read" + resolution.Index);
                Assert.Equal(CoverageLine.Step, lines[^1].Kind);
                Assert.Equal(resolution.Index, lines[^1].Index);
                return new(new AppInstallationEvidence { CollectionStatus = "complete", SignatureState = "unsigned",
                    ExecutablePath = resolution.ExecutablePath, ExecutableResolution = resolution.Method });
            },
            lines.Add);

        Assert.Equal(["reg0", "reg1", "reg2", "reg3", "list", "read0", "read3"], io);
        var results = lines.Where(l => l.Kind == CoverageLine.Result).ToDictionary(l => l.Index, l => l.Evidence!);
        Assert.Equal([0, 1, 2, 3], results.Keys.Order());
        Assert.Equal(@"C:\Program Files\A\a.exe", results[0].ExecutablePath);
        Assert.Equal(["executable_outside_supported_roots"], results[1].Errors);
        Assert.Equal(["registry_read_unavailable"], results[2].Errors);
        // PAT-2129: an unresolved row says why in executable_resolution too.
        Assert.Equal(ExecutableResolutions.OutsideRoots, results[1].ExecutableResolution);
        Assert.Equal(ExecutableResolutions.RegistryUnavailable, results[2].ExecutableResolution);
        Assert.Equal(ExecutableResolutions.InstallLocationSingleExe, results[3].ExecutableResolution);
        Assert.Equal(CoverageLine.Done, lines[^1].Kind);
    }

    [Fact]
    public void CompletedTargetsAreResolvedButNotReadAndStuckTargetsAreNotTouched()
    {
        var lines = new List<CoverageLine>();
        var io = new List<string>();
        AppSignatureCoverageProbe.Run(Request(completed: [0], stuck: [3]), Roots,
            target => { io.Add("reg" + target.Index); return Location(target); },
            _ => throw new Exception("stuck target must not be listed"),
            (resolution, _) => { io.Add("read" + resolution.Index); return new(new AppInstallationEvidence()); },
            lines.Add);
        Assert.Equal(["reg0", "reg1", "reg2"], io);
        Assert.Equal([1, 2], lines.Where(l => l.Kind == CoverageLine.Result).Select(l => l.Index).Order());
    }

    [Fact]
    public void AReadThatThrowsIsUnavailableNotAFailedRun()
    {
        var lines = new List<CoverageLine>();
        AppSignatureCoverageProbe.Run(new([new(0, "{A}", false)], [], [], []), Roots, Location, _ => [],
            (_, _) => throw new IOException(@"C:\Users\private"), lines.Add);
        var evidence = lines.Single(l => l.Kind == CoverageLine.Result).Evidence!;
        Assert.Equal(["file_read_unavailable"], evidence.Errors);
        Assert.Equal("unknown", evidence.SignatureState);
        Assert.Equal(CoverageLine.Done, lines[^1].Kind);
    }

    // PAT-2129: the MSI reader is asked only for an entry that is an MSI product, only after
    // that entry's step line, and a not_applicable bundle is reported as such.
    [Fact]
    public void TheMsiReaderRunsAfterItsStepLineAndEveryResultCarriesACode()
    {
        var lines = new List<CoverageLine>();
        var asked = new List<string>();
        var request = new CoverageRequest([new(0, "{9BF28BF1-237D-5239-A1E6-89A2A84B5AA7}", false), new(1, "{f4fca927}", true)],
            [], [], []);
        AppSignatureCoverageProbe.Run(request, Roots,
            target => target.Index == 0
                ? new(0, null, "") { DisplayName = "Tailscale", MsiProductCode = target.Identifier }
                : new(0, @"C:\ProgramData\Package Cache\{f4fca927}\VC_redist.arm64.exe,0", null)
                {
                    DisplayName = "Microsoft Visual C++ 2022 Redistributable (Arm64) - 14.42.34438",
                    Publisher = "Microsoft Corporation", BurnBundle = true,
                },
            _ => null,
            (resolution, _) => new(new AppInstallationEvidence { CollectionStatus = "complete", SignatureState = "valid",
                ExecutablePath = resolution.ExecutablePath, ExecutableResolution = resolution.Method }),
            lines.Add,
            code =>
            {
                asked.Add(code);
                Assert.Equal(CoverageLine.Step, lines[^1].Kind);
                Assert.Equal(0, lines[^1].Index);
                return [@"C:\Program Files\Tailscale\tailscale.exe", @"C:\Program Files\Tailscale\tailscaled.exe"];
            });
        Assert.Equal(["{9BF28BF1-237D-5239-A1E6-89A2A84B5AA7}"], asked);
        var results = lines.Where(l => l.Kind == CoverageLine.Result).ToDictionary(l => l.Index, l => l.Evidence!);
        Assert.Equal(@"C:\Program Files\Tailscale\tailscale.exe", results[0].ExecutablePath);
        Assert.Equal(ExecutableResolutions.MsiComponentNamedExe, results[0].ExecutableResolution);
        Assert.Equal(ExecutableResolutions.NotApplicable, results[1].ExecutableResolution);
        Assert.Equal(["executable_not_applicable"], results[1].Errors);
        Assert.Equal("unknown", results[1].SignatureState);
    }

    [Theory]
    [InlineData("{9BF28BF1-237D-5239-A1E6-89A2A84B5AA7}", 1, "{9BF28BF1-237D-5239-A1E6-89A2A84B5AA7}")]
    [InlineData("{9BF28BF1-237D-5239-A1E6-89A2A84B5AA7}", 0, null)]
    [InlineData("Git_is1", 1, null)]
    [InlineData("{9BF28BF1-237D-5239-A1E6-89A2A84B5AA7}.old", 1, null)]
    public void TheMsiProductCodeIsTheSubkeyNameOnlyForAWindowsInstallerEntry(string identifier, int windowsInstaller,
        string? expected)
    {
        var values = new Dictionary<string, object> { ["WindowsInstaller"] = windowsInstaller };
        var location = AppSignatureCoverageProbe.UninstallLocationFrom(new(3, identifier, false), n => values.GetValueOrDefault(n));
        Assert.Equal(expected, location.MsiProductCode);
        Assert.Equal(3, location.Index);
    }

    [Fact]
    public void UninstallValuesAreReadAsHintsAndWrongTypesAreAbsent()
    {
        var values = new Dictionary<string, object>
        {
            ["DisplayIcon"] = @"C:\Program Files\A\a.exe", ["InstallLocation"] = 7, ["DisplayName"] = "A",
            ["Publisher"] = "P", ["UninstallString"] = "\"C:\\Program Files\\A\\unins000.exe\"",
            ["BundleProviderKey"] = "VC,redist.arm64,arm64,14.42,bundle", ["WindowsInstaller"] = "1",
        };
        var location = AppSignatureCoverageProbe.UninstallLocationFrom(new(0, "{9BF28BF1-237D-5239-A1E6-89A2A84B5AA7}", false),
            n => values.GetValueOrDefault(n));
        Assert.Equal(@"C:\Program Files\A\a.exe", location.DisplayIcon);
        Assert.Null(location.InstallLocation);
        Assert.Equal("A", location.DisplayName);
        Assert.Equal("P", location.Publisher);
        Assert.True(location.BurnBundle);
        Assert.Null(location.MsiProductCode); // a REG_SZ "1" is not WindowsInstaller=1
        values["BundleProviderKey"] = " ";
        Assert.False(AppSignatureCoverageProbe.UninstallLocationFrom(new(0, "x", false), n => values.GetValueOrDefault(n)).BurnBundle);
    }

    [Theory]
    [InlineData(@"C:\WINDOWS\Installer\58f3e40.msi", true)]
    [InlineData(@"C:\Windows\Installer\22f7c3.MSI", true)]
    [InlineData(@"C:\Windows\Installer\{GUID}\x.msi", false)]
    [InlineData(@"C:\Windows\Installer\x.exe", false)]
    [InlineData(@"C:\Windows\Installer\", false)]
    [InlineData(@"C:\Windows\Installer\..\x.msi", false)]
    [InlineData(@"C:\ProgramData\Package Cache\x.msi", false)]
    [InlineData(@"\\server\share\Installer\x.msi", false)]
    public void OnlyAPackageDirectlyInTheInstallerCacheIsOpened(string path, bool expected) =>
        Assert.Equal(expected, MsiComponentReader.IsCachedPackagePath(path, @"C:\Windows"));

    [Theory]
    [InlineData("dvdneymt.exe|tailscale.exe", "tailscale.exe")]
    [InlineData("qemu-ga.exe", "qemu-ga.exe")]
    public void FileTableNamesUseTheLongName(string value, string expected) =>
        Assert.Equal(expected, MsiComponentReader.LongFileName(value));

    [Theory]
    [InlineData("{9BF28BF1-237D-5239-A1E6-89A2A84B5AA7}", true)]
    [InlineData("{9bf28bf1-237d-5239-a1e6-89a2a84b5aa7}", true)]
    [InlineData("9BF28BF1-237D-5239-A1E6-89A2A84B5AA7", false)]
    [InlineData("{9BF28BF1-237D-5239-A1E6-89A2A84B5AA7}\\..", false)]
    [InlineData("Git_is1", false)]
    public void OnlyABracedGuidIsAProductCode(string value, bool expected) =>
        Assert.Equal(expected, MsiComponentReader.IsProductCode(value));

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("{\"targets\":[{\"i\":0,\"id\":\"a\\\\b\",\"wow\":false}],\"completed\":[],\"stuck\":[],\"cache\":[]}")]
    [InlineData("{\"targets\":[{\"i\":-1,\"id\":\"a\",\"wow\":false}],\"completed\":[],\"stuck\":[],\"cache\":[]}")]
    [InlineData("{\"targets\":[{\"i\":0,\"id\":\"a\",\"wow\":false},{\"i\":0,\"id\":\"b\",\"wow\":false}],\"completed\":[],\"stuck\":[],\"cache\":[]}")]
    [InlineData("{\"targets\":[],\"completed\":[],\"stuck\":[]}")]
    public void MalformedRequestsAreRefused(string json) =>
        Assert.Null(AppSignatureCoverageProbe.ParseRequest(new StringReader(json)));

    [Fact]
    public void AWellFormedRequestParses()
    {
        var request = Request();
        var parsed = AppSignatureCoverageProbe.ParseRequest(new StringReader(JsonSerializer.Serialize(request)));
        Assert.Equal(request.Targets, parsed!.Targets);
    }

    [Fact]
    public void HelperTakesNoArgumentsAtAll()
    {
        Assert.Equal(2, AppSignatureCoverageProbe.RunCommand([AppSignatureCoverageProbe.Command, @"C:\secret"],
            new StringReader(""), TextWriter.Null));
        Assert.Equal(2, AppSignatureCoverageProbe.RunCommand([AppSignatureCoverageProbe.Command],
            new StringReader("not json"), TextWriter.Null));
    }
}
