using Patched.Shared.Metering;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-380: the pure software-metering core — ROT13 decode, known-folder expansion,
/// and UserAssist→app correlation.
/// </summary>
public class MeteringTests
{
    private const string FixtureSid = "S-1-5-21-100-200-300-1001";
    private static readonly UserAssistUsage FixtureLaunch = new() { Path = @"C:\Apps\app.exe", RunCount = 1 };

    [Fact]
    public void SourceStatus_LoadedHiveWithoutUsableRecords_IsUnavailable()
    {
        var result = UserAssistCollection.Read(() => [FixtureSid], _ => new([]));
        Assert.Equal(MeteringStatus.Unavailable, result.Status);
        Assert.Equal(1, result.UserHiveCount);
        Assert.Equal(0, result.RecordCount);
    }

    [Fact]
    public void SourceStatus_ExplicitTrackingDisabled_DoesNotReportHistoricalRecordsAsCurrentCoverage()
    {
        var result = UserAssistCollection.Read(() => [FixtureSid], _ => new([FixtureLaunch], TrackingDisabled: true));
        Assert.Equal(MeteringStatus.Unavailable, result.Status);
        Assert.Empty(result.Usages);
        Assert.Equal(0, result.RecordCount);
    }

    [Fact]
    public void SourceStatus_EnumerationFailure_IsUnavailableWithUnknownCounts()
    {
        var result = UserAssistCollection.Read(() => throw new UnauthorizedAccessException(), _ => new([]));
        Assert.Equal(MeteringStatus.Unavailable, result.Status);
        Assert.Null(result.UserHiveCount);
        Assert.Null(result.RecordCount);
    }

    [Fact]
    public void SourceStatus_FailedHiveAlongsideReadableHive_DoesNotClaimCompleteCoverage()
    {
        var result = UserAssistCollection.Read(() => [FixtureSid, FixtureSid + "2"],
            sid => sid == FixtureSid ? new([FixtureLaunch]) : throw new UnauthorizedAccessException());
        Assert.Equal(MeteringStatus.Unavailable, result.Status);
        Assert.Equal(2, result.UserHiveCount);
        Assert.Equal(1, result.RecordCount);
        Assert.Single(result.Usages);
    }

    [Fact]
    public void SourceStatus_ZeroCountAndNoTimestamp_IsNotAUsableLaunchRecord()
    {
        var result = UserAssistCollection.Read(() => [FixtureSid],
            _ => new([new UserAssistUsage { Path = @"C:\Apps\app.exe", RunCount = 0 }]));
        Assert.Equal(MeteringStatus.Unavailable, result.Status);
        Assert.Equal(0, result.RecordCount);
    }

    [Fact]
    public void SourceStatus_UsableRecordsAreOkAndOnlyInteractiveHivesCount()
    {
        var result = UserAssistCollection.Read(() => [".DEFAULT", "S-1-5-18", FixtureSid + "_Classes", FixtureSid],
            sid => { Assert.Equal(FixtureSid, sid); return new([FixtureLaunch]); });
        Assert.Equal(MeteringStatus.Ok, result.Status);
        Assert.Equal(1, result.UserHiveCount);
        Assert.Equal(1, result.RecordCount);
    }

    [Fact]
    public void SourceStatus_NoInteractiveHive_IsNoUserSession()
    {
        var result = UserAssistCollection.Read(() => [], _ => throw new InvalidOperationException());
        Assert.Equal(MeteringStatus.NoUserSession, result.Status);
        Assert.Equal(0, result.UserHiveCount);
        Assert.Equal(0, result.RecordCount);
    }

    [Fact]
    public void Rot13_RoundTrips_AndLeavesNonLetters()
    {
        const string path = @"C:\Program Files\Acme\acme.exe";
        string encoded = Rot13.Decode(path);          // ROT13 is its own inverse
        Assert.NotEqual(path, encoded);
        Assert.Equal(path, Rot13.Decode(encoded));
        // digits / separators unchanged
        Assert.Equal(@"P:\1234\", Rot13.Decode(@"C:\1234\"));
    }

    [Fact]
    public void KnownFolders_ExpandsProgramFilesGuid()
    {
        string expanded = KnownFolders.Expand(
            @"{6D809377-6AF0-444B-8957-A3773F02200E}\Acme\acme.exe",
            f => f == Environment.SpecialFolder.ProgramFiles ? @"C:\Program Files" : "");

        Assert.Equal(@"C:\Program Files\Acme\acme.exe", expanded);
    }

    [Fact]
    public void KnownFolders_LeavesUnknownGuidAndPlainPaths()
    {
        Assert.Equal(@"{00000000-0000-0000-0000-000000000000}\x\y.exe",
            KnownFolders.Expand(@"{00000000-0000-0000-0000-000000000000}\x\y.exe", _ => "X"));
        Assert.Equal(@"C:\already\abs.exe",
            KnownFolders.Expand(@"C:\already\abs.exe", _ => "X"));
    }

    [Fact]
    public void UserAssistRecord_ParsesModernBlob()
    {
        var dt = new DateTime(2026, 12, 13, 9, 27, 44, DateTimeKind.Utc);
        var data = new byte[72];
        BitConverter.GetBytes(503).CopyTo(data, 4);              // run count
        BitConverter.GetBytes(dt.ToFileTimeUtc()).CopyTo(data, 60); // last run FILETIME

        string encodedName = Rot13.Decode(@"C:\Apps\foo.exe");  // encode the path
        var usage = UserAssistRecord.TryParse(encodedName, data);

        Assert.NotNull(usage);
        Assert.Equal(@"C:\Apps\foo.exe", usage!.Path);
        Assert.Equal(503, usage.RunCount);
        Assert.Equal(new DateTimeOffset(dt, TimeSpan.Zero), usage.LastUsed);
    }

    [Fact]
    public void UserAssistRecord_SkipsSessionRowsAndShortData()
    {
        Assert.Null(UserAssistRecord.TryParse(Rot13.Decode("UEME_CTLSESSION"), new byte[72]));
        Assert.Null(UserAssistRecord.TryParse(Rot13.Decode(@"C:\x.exe"), new byte[8]));   // too short
        Assert.Null(UserAssistRecord.TryParse("", new byte[72]));
    }

    [Fact]
    public void UserAssistRecord_ZeroFileTimeIsNull()
    {
        Assert.Null(UserAssistRecord.FileTimeToUtc(0));
        Assert.Null(UserAssistRecord.FileTimeToUtc(-5));
    }

    [Fact]
    public void Matcher_ExactExecutableDoesNotIncludeUnboundHelpers()
    {
        var t1 = new DateTimeOffset(2026, 12, 10, 0, 0, 0, TimeSpan.Zero);
        var t2 = new DateTimeOffset(2026, 12, 13, 0, 0, 0, TimeSpan.Zero);
        var usages = new[]
        {
            new UserAssistUsage { Path = @"C:\Program Files\Acme\acme.exe",     RunCount = 10, LastUsed = t1 },
            new UserAssistUsage { Path = @"C:\Program Files\Acme\helper.exe",   RunCount = 5,  LastUsed = t2 },
            new UserAssistUsage { Path = @"C:\Program Files\Other\other.exe",   RunCount = 99, LastUsed = t2 },
        };
        var apps = new[]
        {
            new MeteredApp { Identifier = "AcmeKey", InstallLocation = @"C:\Program Files\Acme", ExePath = @"C:\Program Files\Acme\acme.exe" },
        };

        var map = MeteringMatcher.Match(usages, apps);

        Assert.True(map.ContainsKey("AcmeKey"));
        Assert.Equal(10, map["AcmeKey"].LaunchCount);   // Only the explicitly bound acme.exe.
        Assert.Equal(t1, map["AcmeKey"].LastUsed);      // The unbound helper's newer date is not app usage.
    }

    [Fact]
    public void Matcher_MatchesByExePath_WhenNoInstallLocation()
    {
        var usages = new[]
        {
            new UserAssistUsage { Path = @"C:\tools\x\thing.exe", RunCount = 3,
                                  LastUsed = new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero) },
        };
        var apps = new[]
        {
            new MeteredApp { Identifier = "ThingKey", ExePath = @"C:\tools\x\thing.exe" },
        };

        var map = MeteringMatcher.Match(usages, apps);
        Assert.Equal(3, map["ThingKey"].LaunchCount);
    }

    [Fact]
    public void Matcher_DoesNotMatchSiblingPrefix()
    {
        // "C:\Program Files\App" must not swallow "C:\Program Files\AppOther".
        var usages = new[]
        {
            new UserAssistUsage { Path = @"C:\Program Files\AppOther\x.exe", RunCount = 7 },
        };
        var apps = new[]
        {
            new MeteredApp { Identifier = "AppKey", InstallLocation = @"C:\Program Files\App" },
        };

        var usage = MeteringMatcher.Match(usages, apps)["AppKey"];
        Assert.Equal("unmapped", usage.UsageEvidence);
        Assert.Null(usage.LaunchCount);
    }

    [Fact]
    public void Matcher_NoUsage_LeavesAppUnmapped()
    {
        var apps = new[] { new MeteredApp { Identifier = "Unused", InstallLocation = @"C:\Program Files\Unused" } };
        Assert.Equal("unmapped", MeteringMatcher.Match([], apps)["Unused"].UsageEvidence);
    }

    [Fact]
    public void UsageEvidence_KnownExecutableWithoutRecord_IsNoRecord()
    {
        var apps = new[] { new MeteredApp
        {
            Identifier = "DesktopApp", ExePath = @"C:\Program Files\DesktopApp\app.exe",
        } };
        var map = MeteringMatcher.Match([], apps);

        Assert.True(map.ContainsKey("DesktopApp"), "A meterable app without a record must retain its evidence state.");
        Assert.Equal("no_record", Evidence(map["DesktopApp"]));
        Assert.Null(map["DesktopApp"].LastUsed);
        Assert.Null(map["DesktopApp"].LaunchCount);
    }

    [Fact]
    public void UsageEvidence_NoExecutableOrLocation_IsUnmapped()
    {
        var map = MeteringMatcher.Match([], [new MeteredApp { Identifier = "Runtime" }]);

        Assert.True(map.ContainsKey("Runtime"), "An app without mapping hints must be explicitly unmapped.");
        Assert.Equal("unmapped", Evidence(map["Runtime"]));
        Assert.Null(map["Runtime"].LastUsed);
        Assert.Null(map["Runtime"].LaunchCount);
    }

    [Fact]
    public void UsageEvidence_MatchingLaunch_IsRecorded()
    {
        var last = new DateTimeOffset(2026, 9, 30, 12, 0, 0, TimeSpan.Zero);
        var map = MeteringMatcher.Match(
            [new UserAssistUsage { Path = @"C:\Apps\app.exe", RunCount = 8, LastUsed = last }],
            [new MeteredApp { Identifier = "DesktopApp", ExePath = @"C:\Apps\app.exe" }]);

        Assert.Equal(last, map["DesktopApp"].LastUsed);
        Assert.Equal(8, map["DesktopApp"].LaunchCount);
        Assert.Equal("recorded", Evidence(map["DesktopApp"]));
    }

    // AppIDs and counts captured from WINDOWS11 on 2026-10-01 (PAT-2328).
    // Executable targets are synthetic fixture paths, not inferred device data.
    [Theory]
    [InlineData("MSEdge", @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", 12)]
    [InlineData("Microsoft.Office.WINWORD.EXE.15", @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", 9)]
    [InlineData("Microsoft.Office.OUTLOOK.EXE.15", @"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", 1)]
    public void UsageEvidence_ObservedAppId_MapsToItsExecutable(string appId, string executable, int launches)
    {
        var map = MeteringMatcher.Match(
            [new UserAssistUsage { Path = appId, RunCount = launches }],
            [appId == "MSEdge"
                ? new MeteredApp { Identifier = "Microsoft Edge", ExePath = executable }
                : new MeteredApp { Identifier = "O365ProPlusRetail - en-us", InstallLocation = @"C:\Program Files\Microsoft Office", OfficeExePaths = [executable] }]);

        var usage = Assert.Single(map).Value;
        Assert.Equal(launches, usage.LaunchCount);
        Assert.Equal("recorded", Evidence(usage));
    }

    [Fact]
    public void UsageEvidence_EdgeAppIdAndShortcut_DoNotDoubleCount()
    {
        var map = MeteringMatcher.Match(
            [
                new UserAssistUsage { Path = "MSEdge", RunCount = 12 },
                new UserAssistUsage { Path = @"C:\Users\fixture\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk", RunCount = 11 },
                new UserAssistUsage { Path = @"C:\Users\Public\Desktop\Microsoft Edge.lnk", RunCount = 0 },
            ],
            [new MeteredApp { Identifier = "Microsoft Edge", ExePath = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" }]);

        Assert.True(map.ContainsKey("Microsoft Edge"));
        Assert.Equal(12, map["Microsoft Edge"].LaunchCount);
    }

    [Theory]
    [InlineData("MSEdgeBeta")]
    [InlineData("Fake.MSEdge")]
    [InlineData("Microsoft.Office.WINWORD.EXE.15.fake")]
    [InlineData("Microsoft.Office.rundll32.exe.15")]
    [InlineData(@"C:\Users\Public\Desktop\Microsoft Edge.lnk")]
    public void UsageEvidence_UnknownAppIdOrShortcut_IsNotGuessed(string record)
    {
        var map = MeteringMatcher.Match(
            [new UserAssistUsage { Path = record, RunCount = 10 }],
            [
                new MeteredApp { Identifier = "Microsoft Edge", ExePath = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" },
                new MeteredApp { Identifier = "Word", ExePath = @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" },
            ]);

        Assert.DoesNotContain(map.Values, u => u.LaunchCount > 0 || u.LastUsed is not null);
    }

    [Fact]
    public void UsageEvidence_CapturedOfficeSuite_UsesBoundWordAndOutlookNotServiceIcon()
    {
        var app = new MeteredApp
        {
            Identifier = "O365ProPlusRetail - en-us", InstallLocation = @"C:\Program Files\Microsoft Office",
            ExePath = @"C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe",
            OfficeExePaths = [@"C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE",
                @"C:\Program Files\Microsoft Office\Root\Office16\OUTLOOK.EXE"],
        };
        var map = MeteringMatcher.Match(
            [new() { Path = "Microsoft.Office.WINWORD.EXE.15", RunCount = 9 },
             new() { Path = "Microsoft.Office.OUTLOOK.EXE.15", RunCount = 1 },
             new() { Path = app.ExePath, RunCount = 100 }], [app]);
        Assert.Equal(10, map[app.Identifier].LaunchCount);
        Assert.Equal("recorded", map[app.Identifier].UsageEvidence);
    }

    [Fact]
    public void UsageEvidence_VersionedEdgeIcon_MapsExactAppId()
    {
        var map = MeteringMatcher.Match([new() { Path = "MSEdge", RunCount = 12 },
            new() { Path = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", RunCount = 11 }],
            [new() { Identifier = "Microsoft Edge", InstallLocation = @"C:\Program Files (x86)\Microsoft\Edge\Application",
                ExePath = @"C:\Program Files (x86)\Microsoft\Edge\Application\154.0.4258.48\msedge.exe" }]);
        Assert.Equal(12, map["Microsoft Edge"].LaunchCount);
    }

    [Theory]
    [InlineData("{90160000-008C-0000-1000-0000000FF1CE}", @"C:\Program Files\Microsoft Office")]
    [InlineData("O365ProPlusRetail - en-us", @"C:\Other\Microsoft Office")]
    [InlineData("Other", @"C:\Program Files\Microsoft Office")]
    public void UsageEvidence_OfficeBinding_RequiresReviewedProductAndRoot(string id, string root)
    {
        Assert.Empty(MeteringMatcher.BindOfficeExecutables(id, root,
            [@"C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE"]));
    }

    [Fact]
    public void UsageEvidence_OfficeAppPathsOutsideSuiteRoot_AreNotBound()
    {
        Assert.Empty(MeteringMatcher.BindOfficeExecutables("O365ProPlusRetail - en-us", @"C:\Program Files\Microsoft Office",
            [@"C:\Other\Office16\WINWORD.EXE", @"C:\Program Files\Microsoft Office\Root\Office16\..\WINWORD.EXE"]));
    }

    [Theory]
    [InlineData("OfficeClickToRun.exe")]
    [InlineData("OfficeC2RClient.exe")]
    [InlineData("msedgewebview2.exe")]
    [InlineData("Patched.Service.exe")]
    [InlineData("setup.exe")]
    [InlineData("uninstall.exe")]
    public void UsageEvidence_ClosedNonAppTargets_AreUnmapped(string name)
    {
        string exe = @"C:\Apps\" + name;
        var usage = MeteringMatcher.Match([new() { Path = exe, RunCount = 99 }],
            [new() { Identifier = name, InstallLocation = @"C:\Apps", ExePath = exe }])[name];
        Assert.Equal("unmapped", usage.UsageEvidence);
        Assert.Null(usage.LaunchCount);
    }

    [Fact]
    public void UsageEvidence_SimilarlyNamedApp_IsNotExcludedBySubstring()
    {
        const string exe = @"C:\Apps\MySetupEditor.exe";
        var usage = MeteringMatcher.Match([new() { Path = exe, RunCount = 9 }],
            [new() { Identifier = "Editor", ExePath = exe }])["Editor"];
        Assert.Equal("recorded", usage.UsageEvidence);
        Assert.Equal(9, usage.LaunchCount);
    }

    [Fact]
    public void UsageEvidence_AppIdAndExecutable_AreDeduplicatedWithinHiveButSummedAcrossHives()
    {
        const string exe = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
        var usage = MeteringMatcher.Match(
            [new() { Path = "MSEdge", RunCount = 12, UserHive = 1 },
             new() { Path = exe, RunCount = 11, UserHive = 1 },
             new() { Path = "MSEdge", RunCount = 3, UserHive = 2 }],
            [new() { Identifier = "Microsoft Edge", ExePath = exe }])["Microsoft Edge"];
        Assert.Equal(15, usage.LaunchCount);
    }

    [Fact]
    public void UsageEvidence_UnavailableSource_NeverClaimsNoRecordOrUnmapped()
    {
        var map = MeteringMatcher.Match([], [new() { Identifier = "App", ExePath = @"C:\Apps\app.exe" },
            new() { Identifier = "Runtime" }], sourceAvailable: false);
        Assert.All(map.Values, usage => Assert.Equal("unavailable", usage.UsageEvidence));
    }

    [Fact]
    public void UsageEvidence_PartialSource_PreservesPositiveLaunchEvidence()
    {
        var usage = MeteringMatcher.Match([FixtureLaunch],
            [new() { Identifier = "App", ExePath = FixtureLaunch.Path }], sourceAvailable: false)["App"];
        Assert.Equal("recorded", usage.UsageEvidence);
    }

    [Fact]
    public void UsageEvidence_ExecutableClaimedByTwoApps_IsUnmappedNotAnAbsenceClaim()
    {
        var map = MeteringMatcher.Match([FixtureLaunch],
            [new() { Identifier = "App1", ExePath = FixtureLaunch.Path },
             new() { Identifier = "App2", ExePath = FixtureLaunch.Path }]);
        Assert.All(map.Values, usage =>
        {
            Assert.Equal("unmapped", usage.UsageEvidence);
            Assert.Null(usage.LaunchCount);
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UsageEvidence_DuplicateIdentifier_RetainsExactHintFromEitherView(bool reverse)
    {
        MeteredApp[] apps = [new() { Identifier = "App" },
            new() { Identifier = "App", ExePath = FixtureLaunch.Path }];
        if (reverse) Array.Reverse(apps);

        var usage = Assert.Single(MeteringMatcher.Match([FixtureLaunch], apps)).Value;
        Assert.Equal("recorded", usage.UsageEvidence);
        Assert.Equal(1, usage.LaunchCount);
    }

    [Fact]
    public void UsageEvidence_DuplicateIdentifier_SameTargetCountsOncePerHive()
    {
        var usage = Assert.Single(MeteringMatcher.Match(
            [FixtureLaunch with { RunCount = 8, UserHive = 1 },
             FixtureLaunch with { RunCount = 3, UserHive = 2 }],
            [new() { Identifier = "App", ExePath = FixtureLaunch.Path, InstallLocation = @"C:\Apps" },
             new() { Identifier = "App", ExePath = FixtureLaunch.Path, InstallLocation = @"C:\Apps" }])).Value;

        Assert.Equal("recorded", usage.UsageEvidence);
        Assert.Equal(11, usage.LaunchCount);
    }

    [Fact]
    public void UsageEvidence_DuplicateIdentifier_DistinctExactTargetsRetainBothObservations()
    {
        const string other = @"C:\Other\app.exe";
        var usage = Assert.Single(MeteringMatcher.Match(
            [FixtureLaunch with { RunCount = 8, UserHive = 1 },
             new() { Path = other, RunCount = 3, UserHive = 1 }],
            [new() { Identifier = "App", ExePath = FixtureLaunch.Path },
             new() { Identifier = "App", ExePath = other }])).Value;

        Assert.Equal("recorded", usage.UsageEvidence);
        Assert.Equal(11, usage.LaunchCount);
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData(null, true)]
    [InlineData(@"C:\Other\app.exe", false)]
    [InlineData(@"C:\Other\app.exe", true)]
    public void UsageEvidence_DuplicateIdentifier_DisagreeingHintsCannotClaimNoRecord(string? other, bool reverse)
    {
        MeteredApp[] apps = [new() { Identifier = "App", ExePath = FixtureLaunch.Path },
            new() { Identifier = "App", ExePath = other }];
        if (reverse) Array.Reverse(apps);

        var usage = Assert.Single(MeteringMatcher.Match([], apps)).Value;
        Assert.Equal("unmapped", usage.UsageEvidence);
        Assert.Null(usage.LaunchCount);
        Assert.Null(usage.LastUsed);
        Assert.Equal("unavailable", Assert.Single(MeteringMatcher.Match([], apps, sourceAvailable: false)).Value.UsageEvidence);
    }

    [Fact]
    public void UsageEvidence_DuplicateIdentifier_AgreeingHintsCanReportNoRecord()
    {
        var usage = Assert.Single(MeteringMatcher.Match([],
            [new() { Identifier = "App", ExePath = FixtureLaunch.Path },
             new() { Identifier = "App", ExePath = @"c:\APPS\APP.EXE" }])).Value;
        Assert.Equal("no_record", usage.UsageEvidence);
    }

    [Fact]
    public void UsageEvidence_DuplicateIdentifier_CaseInsensitiveGroupingPreservesFirstIdentifier()
    {
        var map = MeteringMatcher.Match([FixtureLaunch],
            [new() { Identifier = "CanonicalApp", ExePath = FixtureLaunch.Path },
             new() { Identifier = "CANONICALAPP", ExePath = FixtureLaunch.Path }]);
        var entry = Assert.Single(map);
        Assert.Equal("CanonicalApp", entry.Key);
        Assert.Equal("recorded", entry.Value.UsageEvidence);
        Assert.Equal(1, entry.Value.LaunchCount);
    }

    // PAT-2362: folder proximity does not establish executable identity.
    // Existing captured AppID, Office binding, shortcut, ambiguity, source-status,
    // and duplicate-identifier tests remain part of the full verification gate.
    [Fact]
    public void UsageEvidence_BroadInstallLocationCannotAttributeForeignExecutable()
    {
        var foreignLast = new DateTimeOffset(2026, 7, 1, 12, 0, 0, TimeSpan.Zero);
        var usage = Assert.Single(MeteringMatcher.Match(
            [new() { Path = @"C:\Apps\Unrelated\other.exe", RunCount = 8, LastUsed = foreignLast }],
            [new() { Identifier = "Acme", InstallLocation = @"C:\Apps",
                ExePath = @"C:\Apps\Acme\acme.exe" }])).Value;

        Assert.Equal("no_record", usage.UsageEvidence);
        Assert.Null(usage.LastUsed);
        Assert.Null(usage.LaunchCount);
    }

    [Fact]
    public void UsageEvidence_BroadInstallLocationKeepsOnlyExactPositiveEvidence()
    {
        var actualLast = new DateTimeOffset(2026, 9, 1, 12, 0, 0, TimeSpan.Zero);
        var foreignLast = actualLast.AddDays(10);
        var usage = Assert.Single(MeteringMatcher.Match(
            [new() { Path = @"C:\Apps\Acme\acme.exe", RunCount = 3, LastUsed = actualLast },
             new() { Path = @"C:\Apps\Unrelated\other.exe", RunCount = 8, LastUsed = foreignLast }],
            [new() { Identifier = "Acme", InstallLocation = @"C:\Apps",
                ExePath = @"C:\Apps\Acme\acme.exe" }])).Value;

        Assert.Equal("recorded", usage.UsageEvidence);
        Assert.Equal(actualLast, usage.LastUsed);
        Assert.Equal(3, usage.LaunchCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UsageEvidence_EdgeVersionEquivalenceDoesNotDependOnAnAppIdRecord(bool versionedHint)
    {
        const string root = @"C:\Program Files (x86)\Microsoft\Edge\Application";
        string unversioned = root + @"\msedge.exe";
        string versioned = root + @"\154.0.4258.48\msedge.exe";
        var usage = Assert.Single(MeteringMatcher.Match(
            [new() { Path = versionedHint ? unversioned : versioned, RunCount = 11 }],
            [new() { Identifier = "Microsoft Edge", InstallLocation = root,
                ExePath = versionedHint ? versioned : unversioned }])).Value;

        Assert.Equal("recorded", usage.UsageEvidence);
        Assert.Equal(11, usage.LaunchCount);
    }

    [Fact]
    public void UsageEvidence_EdgeVersionAndAppIdCountsRemainDeduplicatedAcrossViewsAndHives()
    {
        const string root = @"C:\Program Files (x86)\Microsoft\Edge\Application";
        string unversioned = root + @"\msedge.exe";
        string versioned = root + @"\154.0.4258.48\msedge.exe";
        var usage = Assert.Single(MeteringMatcher.Match(
            [new() { Path = "MSEdge", RunCount = 12, UserHive = 1 },
             new() { Path = unversioned, RunCount = 11, UserHive = 1 },
             new() { Path = versioned, RunCount = 10, UserHive = 1 },
             new() { Path = unversioned, RunCount = 3, UserHive = 2 }],
            [new() { Identifier = "Microsoft Edge", InstallLocation = root, ExePath = versioned },
             new() { Identifier = "MICROSOFT EDGE", InstallLocation = root, ExePath = unversioned }])).Value;

        Assert.Equal("recorded", usage.UsageEvidence);
        Assert.Equal(15, usage.LaunchCount);
    }

    [Theory]
    [InlineData("Other Browser", @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")]
    [InlineData("Microsoft Edge", @"D:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")]
    [InlineData("Microsoft Edge", @"C:\Program Files\Microsoft\Edge\Application\msedge.exe")]
    [InlineData("Microsoft Edge", @"C:\Program Files (x86)\Microsoft\Edge\Application\not-a-version\msedge.exe")]
    public void UsageEvidence_EdgeVersionEquivalenceRequiresTheSameBoundIdentityAndRoot(string identifier, string record)
    {
        const string root = @"C:\Program Files (x86)\Microsoft\Edge\Application";
        var usage = Assert.Single(MeteringMatcher.Match(
            [new() { Path = record, RunCount = 11 }],
            [new() { Identifier = identifier, InstallLocation = root,
                ExePath = root + @"\154.0.4258.48\msedge.exe" }])).Value;

        Assert.Equal("no_record", usage.UsageEvidence);
        Assert.Null(usage.LaunchCount);
        Assert.Null(usage.LastUsed);
    }

    // Reflection keeps the regression runnable against the old contract: its
    // failure must be an assertion about missing evidence, not a compile error.
    private static string Evidence(AppUsage usage) =>
        Assert.IsType<string>(typeof(AppUsage).GetProperty("UsageEvidence")?.GetValue(usage));
}
