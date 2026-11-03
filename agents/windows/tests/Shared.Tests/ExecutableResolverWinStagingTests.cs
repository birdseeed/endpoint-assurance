using System.Reflection;
using System.Text.RegularExpressions;
using Patched.Shared.Contract;
using Patched.Shared.InstallationEvidence;
using Xunit;

namespace Patched.Shared.Tests;

// PAT-2129: the resolver against the real Uninstall entries and install layouts read from
// WIN-STAGING (Windows 11 arm64, agent 0.14.3) on 2026-09-25. Before PAT-2129 only Microsoft
// Edge resolved there (1 of 10), and no unresolved row said why in executable_resolution.
// The fixtures below are the registry values and directory listings verbatim.
public sealed class ExecutableResolverWinStagingTests
{
    private static readonly ResolutionRoots Roots = new(@"C:\WINDOWS", [@"C:\Program Files", @"C:\Program Files (x86)"]);

    // What WindowsInstallationEvidence.ListExecutables returns for each directory on the box:
    // top-level .exe names only, null for a directory that does not exist (or is refused as
    // a reparse point by the locked walk).
    private static readonly Dictionary<string, string[]> Box = new(StringComparer.OrdinalIgnoreCase)
    {
        [@"C:\Program Files\Git"] = ["git-bash.exe", "git-cmd.exe", "unins000.exe"],
        [@"C:\Program Files\Git\cmd"] = ["git-gui.exe", "git-lfs.exe", "git-receive-pack.exe", "git-upload-pack.exe",
            "git.exe", "gitk.exe", "scalar.exe", "tig.exe"],
        [@"C:\Program Files\Git\bin"] = ["bash.exe", "git.exe", "sh.exe"],
        [@"C:\Program Files\PowerToys"] = ["FancyZonesCLI.exe", "FileLocksmithCLI.exe", "PowerToys.ActionRunner.exe",
            "PowerToys.AlwaysOnTop.exe", "PowerToys.Awake.exe", "PowerToys.BgcodePreviewHandler.exe",
            "PowerToys.BgcodeThumbnailProvider.exe", "PowerToys.ColorPickerUI.exe", "PowerToys.CropAndLock.exe",
            "PowerToys.DSC.exe", "PowerToys.exe", "PowerToys.FancyZones.exe", "PowerToys.FancyZonesEditor.exe",
            "PowerToys.GcodePreviewHandler.exe", "PowerToys.GcodeThumbnailProvider.exe", "PowerToys.GrabAndMove.exe",
            "PowerToys.MarkdownPreviewHandler.exe", "PowerToys.MonacoPreviewHandler.exe", "PowerToys.MouseJumpUI.exe",
            "PowerToys.MouseWithoutBorders.exe", "PowerToys.MouseWithoutBordersHelper.exe",
            "PowerToys.MouseWithoutBordersService.exe", "PowerToys.PdfPreviewHandler.exe",
            "PowerToys.PdfThumbnailProvider.exe", "PowerToys.PowerAccent.exe", "PowerToys.PowerLauncher.exe",
            "PowerToys.PowerOCR.exe", "PowerToys.QoiPreviewHandler.exe", "PowerToys.QoiThumbnailProvider.exe",
            "PowerToys.StlThumbnailProvider.exe", "PowerToys.SvgPreviewHandler.exe", "PowerToys.SvgThumbnailProvider.exe",
            "PowerToys.Update.exe", "PowerToys.WorkspacesEditor.exe", "PowerToys.WorkspacesLauncher.exe",
            "PowerToys.WorkspacesLauncherUI.exe", "PowerToys.WorkspacesSnapshotTool.exe",
            "PowerToys.WorkspacesWindowArranger.exe", "PowerToys.ZoomIt.exe", "RestartAgent.exe"],
        [@"C:\Program Files\Microsoft VS Code"] = ["Code.exe", "unins000.exe"],
        [@"C:\Program Files\Microsoft VS Code\bin"] = ["code-tunnel.exe"],
        [@"C:\Program Files (x86)\UTM Guest Tools"] = ["Uninstall utm-guest-tools.exe", "vc_redist.arm64.exe"],
    };

    private static IReadOnlyList<string>? List(string directory) => Box.TryGetValue(directory, out var names) ? names : null;

    // MsiComponentReader.ExecutableKeyPaths on the box: every component key path that is an
    // .exe, as MsiGetComponentPath reported it (read with the WindowsInstaller COM API).
    private static readonly Dictionary<string, string[]> MsiKeyPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        ["{9BF28BF1-237D-5239-A1E6-89A2A84B5AA7}"] = [@"C:\Program Files\Tailscale\tailscale.exe",
            @"C:\Program Files\Tailscale\tailscale-ipn.exe", @"C:\Program Files\Tailscale\tailscaled.exe"],
        ["{A86CF81E-C180-4F13-A14F-63743F285999}"] = [@"C:\Program Files\Qemu-ga\qemu-ga.exe",
            @"C:\Program Files\Qemu-ga\gspawn-win64-helper-console.exe", @"C:\Program Files\Qemu-ga\gspawn-win64-helper.exe"],
        ["{83DC0084-A872-4762-8878-57FBD3174A36}"] = [@"C:\Program Files\SPICE webdavd\spice-webdavd.exe"],
        ["{3CA4DE3F-3565-40A0-B268-0B822B7D3193}"] = [@"C:\Program Files\Patched\Patched.Service.exe",
            @"C:\Program Files\Patched\PatchedTray.exe"],
    };

    private static IReadOnlyList<string>? Msi(string productCode) =>
        MsiKeyPaths.TryGetValue(productCode, out var paths) ? paths : null;

    private static UninstallLocation Msi(string name, string code) =>
        new(0, null, "") { DisplayName = name, UninstallString = "MsiExec.exe /X" + code, MsiProductCode = code };

    private static UninstallLocation Bundle(string name, string cached) => new(0, cached + ",0", null)
    {
        DisplayName = name,
        Publisher = "Microsoft Corporation",
        UninstallString = "\"" + cached + "\"  /uninstall",
        BurnBundle = true,
    };

    internal static readonly UninstallLocation Git = new(0,
        @"C:\Program Files\Git\clangarm64\share\git\git-for-windows.ico", @"C:\Program Files\Git\")
    {
        DisplayName = "Git", UninstallString = "\"C:\\Program Files\\Git\\unins000.exe\"",
    };

    internal static readonly UninstallLocation PowerToysBundle = new(0,
        @"C:\ProgramData\Package Cache\{6D689563-C066-417A-A64D-96545CEF4490}\PowerToysSetup-0.100.0-ARM64.exe,0",
        @"C:\Program Files\PowerToys\")
    {
        DisplayName = "PowerToys (Preview) ARM64",
        Publisher = "Microsoft Corporation",
        UninstallString = "\"C:\\ProgramData\\Package Cache\\{6D689563-C066-417A-A64D-96545CEF4490}\\PowerToysSetup-0.100.0-ARM64.exe\"  /uninstall",
        BurnBundle = true,
    };

    // The PowerToys MSI entry is SystemComponent=1, so the scanner never reports it; were it
    // reported, its empty DisplayIcon would resolve the same file by name.
    internal static readonly UninstallLocation PowerToysMsi = new(0, "", @"C:\Program Files\PowerToys\")
    {
        DisplayName = "PowerToys (Preview)",
        Publisher = "Microsoft Corporation",
        UninstallString = "MsiExec.exe /X{D80EB085-CE76-46D2-8D1D-4D92D4F61281}",
        MsiProductCode = "{D80EB085-CE76-46D2-8D1D-4D92D4F61281}",
    };

    internal static readonly UninstallLocation VsCode = new(0, @"C:\Program Files\Microsoft VS Code\Code.exe",
        @"C:\Program Files\Microsoft VS Code\")
    {
        DisplayName = "Microsoft Visual Studio Code",
        Publisher = "Microsoft Corporation",
        UninstallString = "\"C:\\Program Files\\Microsoft VS Code\\unins000.exe\"",
    };

    internal static readonly UninstallLocation Edge = new(0,
        @"C:\Program Files (x86)\Microsoft\Edge\Application\153.0.4234.48\msedge.exe,0",
        @"C:\Program Files (x86)\Microsoft\Edge\Application")
    {
        DisplayName = "Microsoft Edge",
        UninstallString = "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\153.0.4234.48\\Installer\\setup.exe\" --uninstall --msedge --channel=stable --system-level --verbose-logging",
    };

    internal static readonly UninstallLocation UtmGuestTools = new(0, null, null)
    {
        DisplayName = "UTM Guest Tools 0.1.271",
        Publisher = "Turing Software, LLC",
        UninstallString = "\"C:\\Program Files (x86)\\UTM Guest Tools\\Uninstall utm-guest-tools\"",
    };

    internal static readonly UninstallLocation Tailscale = Msi("Tailscale", "{9BF28BF1-237D-5239-A1E6-89A2A84B5AA7}");
    internal static readonly UninstallLocation Qemu = Msi("QEMU guest agent", "{A86CF81E-C180-4F13-A14F-63743F285999}");
    internal static readonly UninstallLocation Spice = Msi("Spice webdavd 2.5 (ARM64)", "{83DC0084-A872-4762-8878-57FBD3174A36}");
    internal static readonly UninstallLocation PatchedAgent = Msi("Patched Agent", "{3CA4DE3F-3565-40A0-B268-0B822B7D3193}");

    internal static readonly UninstallLocation DotnetSdk10 = Bundle("Microsoft .NET SDK 10.0.301 (arm64)",
        @"C:\ProgramData\Package Cache\{37D0ACB0-A305-4AEB-A58B-3EE63D375FEE}\dotnet-sdk-10.0.301-win-arm64.exe");
    internal static readonly UninstallLocation DotnetSdk8 = Bundle("Microsoft .NET SDK 8.0.422 (arm64)",
        @"C:\ProgramData\Package Cache\{1f01007b-2617-4cc6-bc0a-6a74fc73b132}\dotnet-sdk-8.0.422-win-arm64.exe");
    internal static readonly UninstallLocation VcRedist = Bundle("Microsoft Visual C++ 2022 Redistributable (Arm64) - 14.42.34438",
        @"C:\ProgramData\Package Cache\{f4fca927-ceb7-4549-8782-5835bd91078c}\VC_redist.arm64.exe");

    private static ExecutableResolution Resolve(UninstallLocation entry) =>
        ExecutableResolver.Resolve(entry, Roots, List, Msi);

    public static TheoryData<string, string?, string> Expected => new()
    {
        // entry, expected executable (null = none), expected executable_resolution
        { nameof(Edge), @"C:\Program Files (x86)\Microsoft\Edge\Application\153.0.4234.48\msedge.exe", ExecutableResolutions.DisplayIcon },
        { nameof(VsCode), @"C:\Program Files\Microsoft VS Code\Code.exe", ExecutableResolutions.DisplayIcon },
        { nameof(Git), @"C:\Program Files\Git\cmd\git.exe", ExecutableResolutions.InstallLocationNamedExe },
        { nameof(PowerToysBundle), @"C:\Program Files\PowerToys\PowerToys.exe", ExecutableResolutions.InstallLocationNamedExe },
        { nameof(PowerToysMsi), @"C:\Program Files\PowerToys\PowerToys.exe", ExecutableResolutions.InstallLocationNamedExe },
        { nameof(Tailscale), @"C:\Program Files\Tailscale\tailscale.exe", ExecutableResolutions.MsiComponentNamedExe },
        { nameof(Spice), @"C:\Program Files\SPICE webdavd\spice-webdavd.exe", ExecutableResolutions.MsiComponentSingleExe },
        { nameof(Qemu), null, ExecutableResolutions.Ambiguous },
        { nameof(PatchedAgent), null, ExecutableResolutions.Ambiguous },
        { nameof(UtmGuestTools), null, ExecutableResolutions.NotFound },
        { nameof(DotnetSdk10), null, ExecutableResolutions.NotApplicable },
        { nameof(DotnetSdk8), null, ExecutableResolutions.NotApplicable },
        { nameof(VcRedist), null, ExecutableResolutions.NotApplicable },
    };

    private static UninstallLocation Fixture(string name) =>
        (UninstallLocation)typeof(ExecutableResolverWinStagingTests).GetField(name, BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;

    [Theory]
    [MemberData(nameof(Expected))]
    public void EachWinStagingEntryResolvesOrSaysWhyNot(string fixture, string? executable, string code)
    {
        var result = Resolve(Fixture(fixture));
        Assert.Equal(executable, result.ExecutablePath);
        Assert.Equal(code, result.Code);
        Assert.Equal(executable is not null, result.Resolved);
    }

    // The ten rows the 0.14.3 agent attempted (the PowerToys MSI and every SystemComponent
    // entry are not reported by the scanner). One resolved on origin/main; four now.
    [Fact]
    public void TheTenAttemptedRowsResolveFourAndGiveEveryOtherOneAReason()
    {
        var rows = new[] { Edge, Git, Tailscale, DotnetSdk10, DotnetSdk8, VcRedist, Qemu, Spice, UtmGuestTools, PatchedAgent }
            .Select((e, i) => e with { Index = i }).ToArray();
        var results = ExecutableResolver.ResolveAll(rows, Roots, List, msiComponentExecutables: Msi);
        Assert.Equal(4, results.Count(r => r.Resolved));
        Assert.All(results, r => Assert.True(ExecutableResolutions.IsValidCode(r.Code)));
        Assert.Equal(3, results.Count(r => r.Code == ExecutableResolutions.NotApplicable));
    }

    [Fact]
    public void ABundledRedistributableIsNeverTakenForTheApp()
    {
        // UTM Guest Tools: the uninstaller's directory holds exactly one other exe, and it is
        // Microsoft's vc_redist. Neither the named rule nor the single-exe rule may take it.
        var asInstallLocation = UtmGuestTools with { InstallLocation = @"C:\Program Files (x86)\UTM Guest Tools" };
        Assert.Equal(ExecutableResolutions.NotFound, Resolve(asInstallLocation).Code);
        Assert.Null(Resolve(UtmGuestTools).ExecutablePath);
    }

    [Fact]
    public void WithoutTheMsiReaderAnMsiProductWithNoHintSaysSo()
    {
        var result = ExecutableResolver.Resolve(Tailscale, Roots, List);
        Assert.Equal(ExecutableResolutions.NoHint, result.Code);
        Assert.Equal("executable_unresolved", result.Error);
    }

    [Fact]
    public void AnMsiReadThatFailsIsListingUnavailableNeverNoExecutable()
    {
        Assert.Equal(ExecutableResolutions.ListingUnavailable, ExecutableResolver.Resolve(Tailscale, Roots, List, _ => null).Code);
        Assert.Equal(ExecutableResolutions.ListingUnavailable,
            ExecutableResolver.Resolve(Tailscale, Roots, List, _ => throw new IOException()).Code);
    }
}

// PAT-2129: each new rule's refusals.
public sealed class ExecutableResolverWideningTests
{
    private static readonly ResolutionRoots Roots = new(@"C:\Windows", [@"C:\Program Files", @"C:\Program Files (x86)"]);

    private static Func<string, IReadOnlyList<string>?> Tree(Dictionary<string, string[]> tree) =>
        dir => tree.TryGetValue(dir, out var names) ? names : null;

    private static UninstallLocation Named(string name, string? location, string? uninstall = null) =>
        new(0, null, location) { DisplayName = name, UninstallString = uninstall };

    [Fact]
    public void TwoNameMatchesInOneFolderAreAmbiguous()
    {
        var result = ExecutableResolver.Resolve(Named("Tool", @"C:\Program Files\Tool"), Roots,
            Tree(new() { [@"C:\Program Files\Tool"] = ["Tool.exe", "T-ool.exe", "helper.exe"] }));
        Assert.Null(result.ExecutablePath);
        Assert.Equal(ExecutableResolutions.Ambiguous, result.Code);
    }

    [Fact]
    public void TheFirstConventionalFolderWithAMatchWinsAndItsSecondMatchStopsTheSearch()
    {
        var tree = new Dictionary<string, string[]>
        {
            [@"C:\Program Files\Tool"] = ["a.exe", "b.exe"],
            [@"C:\Program Files\Tool\cmd"] = ["tool.exe", "Tool_.exe"],
            [@"C:\Program Files\Tool\bin"] = ["tool.exe"],
        };
        var result = ExecutableResolver.Resolve(Named("Tool", @"C:\Program Files\Tool"), Roots, Tree(tree));
        Assert.Equal(ExecutableResolutions.Ambiguous, result.Code);
    }

    [Fact]
    public void AMissingOrRefusedSubfolderIsSkippedNotFatal()
    {
        // cmd\ lists as null (absent, or a reparse point the locked walk refused); bin\ is used.
        var result = ExecutableResolver.Resolve(Named("Tool", @"C:\Program Files\Tool"), Roots,
            Tree(new() { [@"C:\Program Files\Tool"] = [], [@"C:\Program Files\Tool\bin"] = ["tool.exe"] }));
        Assert.Equal(@"C:\Program Files\Tool\bin\tool.exe", result.ExecutablePath);
        Assert.Equal(ExecutableResolutions.InstallLocationNamedExe, result.Code);
    }

    [Fact]
    public void ARefusedInstallLocationIsListingUnavailableAndNothingIsGuessed()
    {
        // The top level itself is a reparse point: the locked walk refuses it (null).
        var result = ExecutableResolver.Resolve(Named("Tool", @"C:\Program Files\Tool"), Roots, _ => null);
        Assert.Null(result.ExecutablePath);
        Assert.Equal(ExecutableResolutions.ListingUnavailable, result.Code);
    }

    [Fact]
    public void AListingThatReachedTheBoundNeverClaimsAUniqueMatch()
    {
        var names = Enumerable.Range(0, ExecutableResolver.MaximumListedExecutables - 1).Select(i => $"x{i}.exe")
            .Append("tool.exe").ToArray();
        var result = ExecutableResolver.Resolve(Named("Tool", @"C:\Program Files\Tool"), Roots,
            Tree(new() { [@"C:\Program Files\Tool"] = names }));
        Assert.Equal(ExecutableResolutions.Ambiguous, result.Code);
        var single = ExecutableResolver.Resolve(new(0, null, @"C:\Program Files\Tool"), Roots,
            Tree(new() { [@"C:\Program Files\Tool"] = [.. Enumerable.Repeat("unins000.exe", 63), "tool.exe"] }));
        Assert.Equal(ExecutableResolutions.Ambiguous, single.Code);
    }

    [Theory]
    [InlineData(@"C:\Tools\Tool")]
    [InlineData(@"C:\Users\alice\AppData\Local\Tool")]
    [InlineData(@"C:\Windows\Tool")]
    public void ANamedMatchOutsideTheRootsIsNeverListed(string location)
    {
        var result = ExecutableResolver.Resolve(Named("Tool", location), Roots, _ => throw new Exception("must not list"));
        Assert.Equal(ExecutableResolutions.OutsideRoots, result.Code);
    }

    [Theory]
    [InlineData("\"C:\\Tools\\Tool\\uninstall.exe\"")]
    [InlineData("C:\\Users\\alice\\Tool\\uninst.exe /S")]
    [InlineData("\"C:\\Program Files\\uninstall.exe\"")] // its directory is the root itself
    public void AnUninstallDirectoryOutsideTheRootsIsNeverListed(string uninstall)
    {
        var result = ExecutableResolver.Resolve(Named("Tool", null, uninstall), Roots, _ => throw new Exception("must not list"));
        Assert.Equal(ExecutableResolutions.OutsideRoots, result.Code);
    }

    [Fact]
    public void TheUninstallDirectoryRuleIsNameMatchedOnly()
    {
        var tree = new Dictionary<string, string[]> { [@"C:\Program Files\Tool"] = ["uninst.exe", "helper.exe"] };
        Assert.Equal(ExecutableResolutions.NotFound, ExecutableResolver.Resolve(
            Named("Tool", null, "\"C:\\Program Files\\Tool\\uninst.exe\""), Roots, Tree(tree)).Code);
        tree[@"C:\Program Files\Tool"] = ["uninst.exe", "helper.exe", "tool.exe"];
        var result = ExecutableResolver.Resolve(Named("Tool", null, @"C:\Program Files\Tool\uninst.exe /S"), Roots, Tree(tree));
        Assert.Equal(@"C:\Program Files\Tool\tool.exe", result.ExecutablePath);
        Assert.Equal(ExecutableResolutions.UninstallDirectoryNamedExe, result.Code);
        Assert.Equal(@"C:\Program Files\Tool", result.InstallPath);
    }

    [Fact]
    public void TheUninstallDirectoryIsNotUsedWhenAnInstallLocationIsPresent()
    {
        // An InstallLocation outside the roots is not replaced by the uninstaller's directory.
        var result = ExecutableResolver.Resolve(Named("Tool", @"C:\Tools\Tool", @"C:\Program Files\Tool\uninst.exe"),
            Roots, _ => throw new Exception("must not list"));
        Assert.Equal(ExecutableResolutions.OutsideRoots, result.Code);
    }

    [Fact]
    public void AQualifierOutsideTheClosedListKeepsAPlugInOffItsHostsExe()
    {
        var result = ExecutableResolver.Resolve(Named("Foo (Plugin)", @"C:\Program Files\Foo"), Roots,
            Tree(new() { [@"C:\Program Files\Foo"] = ["foo.exe", "foo-helper.exe"] }));
        Assert.Null(result.ExecutablePath);
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\tool.exe")]
    [InlineData(@"C:\Users\alice\AppData\Local\Tool\tool.exe")]
    [InlineData(@"C:\ProgramData\Tool\tool.exe")]
    public void AnMsiKeyPathOutsideTheRootsIsNeverAccepted(string path)
    {
        var entry = new UninstallLocation(0, null, null) { DisplayName = "Tool", MsiProductCode = "{00000000-0000-0000-0000-000000000001}" };
        var alone = ExecutableResolver.Resolve(entry, Roots, _ => null, _ => [path]);
        Assert.Null(alone.ExecutablePath);
        Assert.Equal(ExecutableResolutions.NotFound, alone.Code);
        // With one usable exe beside it, the single rule still refuses: not every key path is inside.
        var mixed = ExecutableResolver.Resolve(entry with { DisplayName = "Other" }, Roots, _ => null,
            _ => [path, @"C:\Program Files\Tool\helper.exe"]);
        Assert.Null(mixed.ExecutablePath);
        Assert.Equal(ExecutableResolutions.Ambiguous, mixed.Code);
    }

    [Fact]
    public void AnMsiKeyPathOutsideAPresentInstallLocationIsNotTaken()
    {
        var entry = new UninstallLocation(0, null, @"C:\Program Files\Tool") { DisplayName = "Tool",
            MsiProductCode = "{00000000-0000-0000-0000-000000000001}" };
        var result = ExecutableResolver.Resolve(entry, Roots, Tree(new() { [@"C:\Program Files\Tool"] = [] }),
            _ => [@"C:\Program Files\Other\tool.exe"]);
        Assert.Null(result.ExecutablePath);
    }

    [Fact]
    public void AnMsiListThatReachedTheBoundIsAmbiguous()
    {
        var entry = new UninstallLocation(0, null, null) { DisplayName = "Tool", MsiProductCode = "{00000000-0000-0000-0000-000000000001}" };
        var paths = Enumerable.Range(0, ExecutableResolver.MaximumListedExecutables - 1)
            .Select(i => $@"C:\Program Files\Tool\x{i}.exe").Append(@"C:\Program Files\Tool\tool.exe").ToArray();
        Assert.Equal(ExecutableResolutions.Ambiguous, ExecutableResolver.Resolve(entry, Roots, _ => null, _ => paths).Code);
    }

    [Fact]
    public void OneExecutableClaimedByABundleAndItsMsiIsAmbiguousForBoth()
    {
        // Were both PowerToys entries reported, neither may keep PowerToys.exe to itself.
        var tree = new Dictionary<string, string[]> { [@"C:\Program Files\PowerToys"] = ["PowerToys.exe", "PowerToys.Awake.exe"] };
        var results = ExecutableResolver.ResolveAll([
            ExecutableResolverWinStagingTests.PowerToysBundle with { Index = 0 },
            ExecutableResolverWinStagingTests.PowerToysMsi with { Index = 1 },
        ], Roots, Tree(tree));
        Assert.All(results, r => Assert.Equal(ExecutableResolutions.Ambiguous, r.Code));
    }

    private static readonly Dictionary<string, UninstallLocation> NotNotApplicableCases = new()
    {
        // The bundle shape alone is not evidence: PowerToys is a Microsoft Burn bundle with a real app.
        ["powertoys bundle"] = ExecutableResolverWinStagingTests.PowerToysBundle with { InstallLocation = null },
        ["other publisher"] = ExecutableResolverWinStagingTests.VcRedist with { Publisher = "Contoso" },
        ["not a bundle"] = ExecutableResolverWinStagingTests.VcRedist with { BurnBundle = false },
        ["has install location"] = ExecutableResolverWinStagingTests.VcRedist with { InstallLocation = @"C:\Program Files\Redist" },
        ["other vc name"] = ExecutableResolverWinStagingTests.VcRedist with { DisplayName = "Microsoft Visual C++ 2022 Redistributable Helper" },
        ["other sdk name"] = ExecutableResolverWinStagingTests.DotnetSdk10 with { DisplayName = "Microsoft .NET SDK Tools" },
        ["no name"] = ExecutableResolverWinStagingTests.DotnetSdk10 with { DisplayName = null },
    };

    public static TheoryData<string> NotNotApplicable => new(NotNotApplicableCases.Keys);

    [Theory]
    [MemberData(nameof(NotNotApplicable))]
    public void NotApplicableNeedsTheWholeEvidencePattern(string name)
    {
        var result = ExecutableResolver.Resolve(NotNotApplicableCases[name], Roots, _ => null);
        Assert.NotEqual(ExecutableResolutions.NotApplicable, result.Code);
    }

    [Fact]
    public void NotApplicableNeverOverridesAResolution()
    {
        var entry = ExecutableResolverWinStagingTests.VcRedist with
        {
            DisplayIcon = @"C:\Program Files\Redist\redistui.exe",
        };
        Assert.Equal(ExecutableResolutions.DisplayIcon, ExecutableResolver.Resolve(entry, Roots, _ => null).Code);
    }

    [Theory]
    [InlineData("PowerToys (Preview) ARM64", "powertoys")]
    [InlineData("Spice webdavd 2.5 (ARM64)", "spicewebdavd")]
    [InlineData("7-Zip 24.08 (x64)", "7zip")]
    [InlineData("Tool v1.2.3 x86", "tool")]
    [InlineData("Foo (Plugin)", "fooplugin")]
    [InlineData("QEMU guest agent", "qemuguestagent")]
    [InlineData("Git", "git")]
    [InlineData("x64", "x64")]
    [InlineData("A", null)]
    [InlineData("  ", null)]
    [InlineData(null, null)]
    public void ProductNamesDropOnlyTrailingQualifiers(string? name, string? expected) =>
        Assert.Equal(expected, ExecutableResolver.NormaliseProductName(name));

    [Theory]
    [InlineData("\"C:\\Program Files (x86)\\UTM Guest Tools\\Uninstall utm-guest-tools\"", @"C:\Program Files (x86)\UTM Guest Tools")]
    [InlineData("\"C:\\Program Files\\Git\\unins000.exe\"", @"C:\Program Files\Git")]
    [InlineData(@"C:\Program Files\Tool\uninst.exe /S", @"C:\Program Files\Tool")]
    [InlineData(@"C:\Program Files\Tool\uninst.exe", @"C:\Program Files\Tool")]
    [InlineData("MsiExec.exe /X{83DC0084-A872-4762-8878-57FBD3174A36}", null)]
    [InlineData(@"C:\Program Files\Tool\uninst.exefoo", null)]
    [InlineData(@"C:\Program Files\..\Windows\uninst.exe", null)]
    [InlineData("\"C:\\Program Files\\Tool\\uninst.exe", null)]
    [InlineData(null, null)]
    public void UninstallStringsYieldTheirDirectoryOrNothing(string? raw, string? expected) =>
        Assert.Equal(expected, ExecutableResolver.UninstallDirectory(raw));

    // Every value executable_resolution can carry fits the platform's CHECK
    // (migration 0188: ^[a-z][a-z0-9_]{0,63}$), or the platform stores it as NULL.
    [Fact]
    public void EveryResolutionCodeFitsThePlatformCheck()
    {
        var check = new Regex("^[a-z][a-z0-9_]{0,63}$");
        var codes = typeof(ExecutableResolutions).GetFields(BindingFlags.NonPublic | BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string))
            .Select(f => (string)f.GetRawConstantValue()!)
            .ToArray();
        Assert.True(codes.Length >= 15);
        Assert.All(codes, code => Assert.Matches(check, code));
        Assert.Equal(codes.Length, codes.Distinct().Count());
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData(@"C:\Program Files\App\app.ico", null)]
    [InlineData(null, @"C:\Tools\App")]
    [InlineData(null, @"C:\Program Files\Empty")]
    [InlineData(null, @"C:\Program Files\Suite")]
    public void EveryUnresolvedRowCarriesAReason(string? icon, string? location)
    {
        var result = ExecutableResolver.Resolve(new(0, icon, location), Roots,
            Tree(new() { [@"C:\Program Files\Empty"] = [], [@"C:\Program Files\Suite"] = ["a.exe", "b.exe"] }));
        Assert.False(result.Resolved);
        Assert.NotNull(result.Reason);
        Assert.True(ExecutableResolutions.IsValidCode(result.Code));
        Assert.StartsWith("unresolved_", result.Code);
    }
}

// PAT-2129: every coverage row carries executable_resolution, including rows the helper
// never resolved.
public sealed class CoverageResolutionReasonTests
{
    private static InventoryApp App(string id) => new() { Name = "App " + id, Version = "1.0", Identifier = id, Architecture = "x86_64" };

    [Theory]
    [InlineData((int)CoverageSessionEnd.PreflightRefused)]
    [InlineData((int)CoverageSessionEnd.Failed)]
    [InlineData((int)CoverageSessionEnd.StepTimeout)]
    [InlineData((int)CoverageSessionEnd.BudgetExhausted)]
    public async Task RowsTheHelperNeverResolvedSayNotAttempted(int endValue)
    {
        var result = await AppSignatureCoverage.CollectAsync([App("A"), App("B")], new SignatureVerdictCache(new FakeTime()),
            (_, _) => Task.FromResult(new CoverageSession([], (CoverageSessionEnd)endValue, null)), new FakeTime());
        Assert.All(result.Apps, a => Assert.Equal(ExecutableResolutions.NotAttempted, a.InstallationEvidence!.ExecutableResolution));
    }

    [Fact]
    public async Task ARowPastTheCoverageLimitSaysNotAttempted()
    {
        var apps = Enumerable.Range(0, ExecutableResolver.MaximumTargets + 1).Select(i => App("A" + i)).ToArray();
        var result = await AppSignatureCoverage.CollectAsync(apps, new SignatureVerdictCache(new FakeTime()),
            (request, _) => Task.FromResult(new CoverageSession(request.Targets.Select(t => new CoverageLine
            {
                Kind = CoverageLine.Result, Index = t.Index,
                Evidence = AppInstallationEvidence.Unavailable("executable_not_found") with { ExecutableResolution = ExecutableResolutions.NotFound },
            }).ToArray(), CoverageSessionEnd.Completed, null)), new FakeTime());
        Assert.Equal(["coverage_limit"], result.Apps[^1].InstallationEvidence!.Errors);
        Assert.Equal(ExecutableResolutions.NotAttempted, result.Apps[^1].InstallationEvidence!.ExecutableResolution);
        // A reason the helper sent is kept, never overwritten.
        Assert.Equal(ExecutableResolutions.NotFound, result.Apps[0].InstallationEvidence!.ExecutableResolution);
    }

    [Fact]
    public async Task ReviewedTargetRowsThatNeverReachedTheFileSayNotAttempted()
    {
        var target = new ReviewedInstallationTarget(InstallationEvidenceCatalogue.SupportedIdentity,
            "{00000000-0000-0000-0000-000000000001}", "CN=Fixture", @"C:\Program Files\App", @"C:\Program Files\App\app.exe");
        var result = await InstallationEvidenceCollector.CollectAsync(
            [App("{00000000-0000-0000-0000-000000000001}")], [target],
            (_, _) => Task.FromResult(AppInstallationEvidence.Unavailable("probe_failed")), new FakeTime());
        Assert.Equal(ExecutableResolutions.NotAttempted, result.Apps[0].InstallationEvidence!.ExecutableResolution);
    }
}
