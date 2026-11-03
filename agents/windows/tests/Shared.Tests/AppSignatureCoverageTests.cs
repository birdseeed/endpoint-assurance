using System.Text.Json;
using Patched.Shared.Contract;
using Patched.Shared.InstallationEvidence;
using Xunit;

namespace Patched.Shared.Tests;

// PAT-2116: all-apps Authenticode coverage. Everything here is the pure decision logic;
// the Win32 calls that feed it are thin and covered by the Windows-only suite.
public sealed class ExecutableResolverTests
{
    private static readonly ResolutionRoots Roots = new(@"C:\Windows", [@"C:\Program Files", @"C:\Program Files (x86)"]);

    private static Func<string, IReadOnlyList<string>?> Listing(params string[] names) => _ => names;
    private static readonly Func<string, IReadOnlyList<string>?> NoListing = _ => throw new Exception("must not list");

    [Theory]
    [InlineData(@"C:\Program Files\Fixture\Fixture.exe")]
    [InlineData(@"C:\Program Files\Fixture\Fixture.exe,0")]
    [InlineData(@"C:\Program Files\Fixture\Fixture.exe, -101")]
    [InlineData("\"C:\\Program Files\\Fixture\\Fixture.exe\"")]
    [InlineData("\"C:\\Program Files\\Fixture\\Fixture.exe\",0")]
    [InlineData("  C:\\Program Files\\Fixture\\Fixture.exe,3  ")]
    public void DisplayIconNamingAnExeInsideProgramFilesResolves(string icon)
    {
        var result = ExecutableResolver.Resolve(new(0, icon, null), Roots, NoListing);
        Assert.Equal(@"C:\Program Files\Fixture\Fixture.exe", result.ExecutablePath);
        Assert.Equal(@"C:\Program Files\Fixture", result.InstallPath);
        Assert.Equal(ExecutableResolutions.DisplayIcon, result.Method);
        Assert.Null(result.Error);
    }

    [Fact]
    public void DisplayIconInsideInstallLocationResolvesWithThatInstallPath()
    {
        var result = ExecutableResolver.Resolve(new(0, @"C:\Program Files\Vendor\App\bin\app.exe,0",
            @"C:\Program Files\Vendor\App\"), Roots, NoListing);
        Assert.Equal(@"C:\Program Files\Vendor\App\bin\app.exe", result.ExecutablePath);
        Assert.Equal(@"C:\Program Files\Vendor\App", result.InstallPath);
    }

    [Fact]
    public void DisplayIconOutsideAPresentInstallLocationIsNotTrustedAndFallsThrough()
    {
        // A plug-in whose icon is its host's exe must not borrow the host's signer.
        var result = ExecutableResolver.Resolve(new(0, @"C:\Program Files\Host\host.exe",
            @"C:\Program Files\Plugin"), Roots, Listing("plugin.exe"));
        Assert.Equal(@"C:\Program Files\Plugin\plugin.exe", result.ExecutablePath);
        Assert.Equal(ExecutableResolutions.InstallLocationSingleExe, result.Method);
    }

    [Fact]
    public void InstallLocationWithExactlyOneExeResolves()
    {
        var result = ExecutableResolver.Resolve(new(3, null, "\"C:\\Program Files (x86)\\Tool\""), Roots,
            Listing("tool.exe", "unins000.exe", "Uninstall.exe"));
        Assert.Equal(3, result.Index);
        Assert.Equal(@"C:\Program Files (x86)\Tool\tool.exe", result.ExecutablePath);
        Assert.Equal(@"C:\Program Files (x86)\Tool", result.InstallPath);
        Assert.Equal(ExecutableResolutions.InstallLocationSingleExe, result.Method);
    }

    [Fact]
    public void InstallLocationWithTwoCandidatesIsAmbiguousNeverAGuess()
    {
        var result = ExecutableResolver.Resolve(new(0, null, @"C:\Program Files\Suite"), Roots,
            Listing("editor.exe", "viewer.exe"));
        Assert.False(result.Resolved);
        Assert.Equal("executable_ambiguous", result.Error);
    }

    [Theory]
    [InlineData]
    [InlineData("unins000.exe")]
    [InlineData("uninst.exe", "readme.txt")]
    public void InstallLocationWithNoCandidateIsMissing(params string[] names)
    {
        var result = ExecutableResolver.Resolve(new(0, null, @"C:\Program Files\Empty"), Roots, Listing(names));
        Assert.False(result.Resolved);
        Assert.Equal("executable_not_found", result.Error);
    }

    [Fact]
    public void ListingFailureIsReportedAndNeverReadAsNoExecutable()
    {
        Assert.Equal("executable_listing_unavailable",
            ExecutableResolver.Resolve(new(0, null, @"C:\Program Files\App"), Roots, _ => null).Error);
        Assert.Equal("executable_listing_unavailable",
            ExecutableResolver.Resolve(new(0, null, @"C:\Program Files\App"), Roots, _ => throw new IOException()).Error);
    }

    [Theory]
    [InlineData(@"C:\Windows\Installer\{00112233-4455-6677-8899-AABBCCDDEEFF}\icon.exe", null)]
    [InlineData(@"C:\Windows\System32\msiexec.exe", null)]
    [InlineData(@"C:\Users\alice\AppData\Local\App\app.exe", null)]
    [InlineData(@"D:\Apps\app.exe", null)]
    [InlineData(null, @"C:\Tools\App")]
    [InlineData(null, @"C:\Windows\App")]
    [InlineData(null, @"C:\Program Files")]
    public void HintsOutsideTheSupportedRootsAreRefused(string? icon, string? location)
    {
        var result = ExecutableResolver.Resolve(new(0, icon, location), Roots, NoListing);
        Assert.False(result.Resolved);
        Assert.Equal("executable_outside_supported_roots", result.Error);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", "  ")]
    [InlineData(@"C:\Program Files\App\app.ico", null)]
    [InlineData(@"%ProgramFiles%\App\app.exe", null)]
    [InlineData(@"\\server\share\app.exe", null)]
    [InlineData(@"C:\Program Files\App\..\Other\app.exe", null)]
    [InlineData("\"C:\\Program Files\\App\\app.exe\" --flag", null)]
    [InlineData(@"C:\Program Files\App\unins000.exe", null)]
    public void UnusableHintsAreUnresolved(string? icon, string? location)
    {
        var result = ExecutableResolver.Resolve(new(0, icon, location), Roots, NoListing);
        Assert.False(result.Resolved);
        Assert.Equal("executable_unresolved", result.Error);
    }

    [Fact]
    public void OneExecutableClaimedByTwoEntriesIsAmbiguousForBoth()
    {
        var results = ExecutableResolver.ResolveAll([
            new(0, @"C:\Program Files\Host\host.exe", null),
            new(1, @"C:\PROGRAM FILES\Host\HOST.EXE,0", null),
            new(2, @"C:\Program Files\Other\other.exe", null),
        ], Roots, NoListing);
        Assert.Equal("executable_ambiguous", results[0].Error);
        Assert.Equal("executable_ambiguous", results[1].Error);
        Assert.True(results[2].Resolved);
    }

    [Fact]
    public void ResolveAllReportsEachEntryBeforeItsIo()
    {
        var seen = new List<int>();
        ExecutableResolver.ResolveAll([new(4, null, @"C:\Program Files\A"), new(9, null, @"C:\Program Files\B")], Roots,
            dir => { Assert.Equal(dir.EndsWith('A') ? 4 : 9, seen[^1]); return ["x.exe"]; }, seen.Add);
        Assert.Equal([4, 9], seen);
    }
}

public sealed class SignatureVerdictLogicTests
{
    private const uint UntrustedRoot = 0x800B0109;
    private static Func<T> Never<T>() => () => throw new Exception("must not be asked");

    private static SignatureDecision Decide(uint code, CatalogLookupOutcome sha256, CatalogPresence sha1 = CatalogPresence.Absent,
        bool healthy = true) =>
        SignatureVerdictLogic.Decide(code, () => sha256, () => sha1, () => healthy);

    [Fact]
    public void EmbeddedSuccessIsValidWithoutAnyCatalogLookup() =>
        Assert.Equal(SignatureDecision.ValidEmbedded, SignatureVerdictLogic.Decide(0,
            Never<CatalogLookupOutcome>(), Never<CatalogPresence>(), Never<bool>()));

    [Fact]
    public void DigestMismatchIsInvalidAndNeverReAskedAsACatalogLookup() =>
        Assert.Equal(SignatureDecision.Invalid, SignatureVerdictLogic.Decide(SignatureVerdictLogic.TrustBadDigest,
            Never<CatalogLookupOutcome>(), Never<CatalogPresence>(), Never<bool>()));

    [Fact]
    public void AnyOtherTrustErrorIsUnknownWithoutAnyCatalogLookup() =>
        Assert.Equal(SignatureDecision.Unknown, SignatureVerdictLogic.Decide(UntrustedRoot,
            Never<CatalogLookupOutcome>(), Never<CatalogPresence>(), Never<bool>()));

    [Theory]
    [InlineData(SignatureVerdictLogic.TrustNoSignature)]
    [InlineData(SignatureVerdictLogic.TrustSubjectFormUnknown)]
    public void VerifiedCatalogMembershipIsValid(uint code) =>
        Assert.Equal(SignatureDecision.ValidCatalog, Decide(code, CatalogLookupOutcome.Verified));

    [Fact]
    public void UnsignedOnlyWithNoEmbeddedSignatureAndASuccessfulCatalogMiss() =>
        Assert.Equal(SignatureDecision.Unsigned, Decide(SignatureVerdictLogic.TrustNoSignature, CatalogLookupOutcome.NoCatalog));

    [Theory]
    [InlineData((int)CatalogLookupOutcome.Failed)]
    [InlineData((int)CatalogLookupOutcome.MemberUnverified)]
    public void CatalogFailureOrUnverifiedMembershipStaysUnknownAndSkipsTheSha1Check(int outcome) =>
        Assert.Equal(SignatureDecision.Unknown, SignatureVerdictLogic.Decide(SignatureVerdictLogic.TrustNoSignature,
            () => (CatalogLookupOutcome)outcome, Never<CatalogPresence>(), Never<bool>()));

    [Fact]
    public void UnparseableSubjectIsNeverUnsignedEvenWithACatalogMiss() =>
        Assert.Equal(SignatureDecision.Unknown, SignatureVerdictLogic.Decide(SignatureVerdictLogic.TrustSubjectFormUnknown,
            () => CatalogLookupOutcome.NoCatalog, Never<CatalogPresence>(), Never<bool>()));

    [Theory]
    [InlineData((int)CatalogPresence.Present)]
    [InlineData((int)CatalogPresence.Failed)]
    public void ASha1OnlyCatalogOrAFailedSha1CheckWithholdsUnsigned(int sha1) =>
        Assert.Equal(SignatureDecision.Unknown,
            Decide(SignatureVerdictLogic.TrustNoSignature, CatalogLookupOutcome.NoCatalog, (CatalogPresence)sha1));

    [Fact]
    public void AnUnhealthyCatalogDatabaseWithholdsUnsigned() =>
        Assert.Equal(SignatureDecision.Unknown,
            Decide(SignatureVerdictLogic.TrustNoSignature, CatalogLookupOutcome.NoCatalog, healthy: false));

    [Theory]
    [InlineData(1168, (int)CatalogLookupOutcome.NoCatalog)] // ERROR_NOT_FOUND
    [InlineData(0, (int)CatalogLookupOutcome.Failed)]
    [InlineData(1722, (int)CatalogLookupOutcome.Failed)] // RPC_S_SERVER_UNAVAILABLE (CryptSvc down)
    [InlineData(87, (int)CatalogLookupOutcome.Failed)]
    public void OnlyErrorNotFoundOnTheFirstEnumerationMeansNoCatalog(int lastError, int expected)
    {
        Assert.Equal((CatalogLookupOutcome)expected, SignatureVerdictLogic.ClassifyFirstEnumeration(false, lastError));
        Assert.Null(SignatureVerdictLogic.ClassifyFirstEnumeration(true, lastError));
    }

    [Theory]
    [InlineData(true, 0, (int)CatalogPresence.Present)]
    [InlineData(false, 1168, (int)CatalogPresence.Absent)]
    [InlineData(false, 5, (int)CatalogPresence.Failed)]
    public void PresenceIsAbsentOnlyOnErrorNotFound(bool returned, int lastError, int expected) =>
        Assert.Equal((CatalogPresence)expected, SignatureVerdictLogic.ClassifyPresence(returned, lastError));

    [Theory]
    [InlineData("valid", "CN=A", "complete")]
    [InlineData("valid", null, "partial")]
    [InlineData("unsigned", null, "complete")]
    [InlineData("invalid", null, "partial")]
    [InlineData("unknown", null, "partial")]
    public void RowStatusIsCompleteOnlyForAWholeVerdict(string state, string? signer, string expected) =>
        Assert.Equal(expected, SignatureVerdictLogic.CollectionStatusFor(new(state, signer)));
}

public sealed class AuthenticodeRootClassifierTests
{
    private const string PublicRoot = "0000000000000000000000000000000000000000000000000000000000000001";

    [Theory]
    [InlineData("df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e")] // MS Root CA 2010
    [InlineData("847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61")] // MS Root CA 2011
    [InlineData("885de64c340e3ea70658f01e1145f957fcda27abbeea1ab9faa9fdb0102d4077")] // MS Root CA (2001)
    [InlineData("f38406e540d7a9d90cb4a9479299640ffb6df9e224ecc7a01c0d9558d8dad77d")] // MS Root Authority (1997)
    public void MicrosoftProductRootsAreMicrosoft(string root) =>
        Assert.Equal(RootKinds.Microsoft, AuthenticodeRootClassifier.Classify(root, selfIssued: true, inThirdPartyRootStore: true));

    [Fact]
    public void TrustedSigningRootIsPublicNotMicrosoft() =>
        // Microsoft Identity Verification Root CA 2020 vouches for third-party publishers.
        Assert.Equal(RootKinds.Public, AuthenticodeRootClassifier.Classify(
            "5367f20c7ade0e2bca790915056d086b720c33c1fa2a2661acf787e3292e1270", true, true));

    [Fact]
    public void SelfIssuedRootInTheThirdPartyStoreIsPublic() =>
        Assert.Equal(RootKinds.Public, AuthenticodeRootClassifier.Classify(PublicRoot, true, true));

    [Theory]
    [InlineData(PublicRoot, true, false)]  // only in LocalMachine\Root or a policy store
    [InlineData(PublicRoot, false, true)]  // not self-issued: not a real root
    [InlineData(null, true, true)]         // the chain could not name a root
    [InlineData("DF545BF919A2439C36983B54CDFC903DFA4F37D3996D8D84B4C31EEC6F3C163E", true, true)] // not canonical
    [InlineData("not-a-hash", true, true)]
    public void EverythingUncertainIsEnterprise(string? root, bool selfIssued, bool inStore) =>
        Assert.Equal(RootKinds.Enterprise, AuthenticodeRootClassifier.Classify(root, selfIssued, inStore));
}

public sealed class SignatureVerdictCacheTests
{
    private static readonly SignatureCacheKey Key = new(new string('a', 64), 1024, 133_000_000_000_000_000);
    private static readonly SignatureObservation Valid = new("valid", "CN=Fixture", new string('b', 64), "CN=Issuer",
        new string('c', 64), RootKinds.Public);

    [Fact]
    public void HitOnlyForTheSameHashSizeAndMtime()
    {
        var cache = new SignatureVerdictCache(new FakeTime());
        cache.Set(Key, Valid);
        Assert.True(cache.TryGet(Key, out var hit));
        Assert.Equal(Valid, hit);
        Assert.False(cache.TryGet(Key with { Sha256 = new string('d', 64) }, out _));
        Assert.False(cache.TryGet(Key with { Size = 1025 }, out _));
        Assert.False(cache.TryGet(Key with { LastWriteUtcTicks = Key.LastWriteUtcTicks + 1 }, out _));
    }

    [Fact]
    public void VerdictsExpireAndUnknownExpiresSooner()
    {
        var clock = new FakeTime();
        var cache = new SignatureVerdictCache(clock);
        var unknownKey = Key with { Sha256 = new string('e', 64) };
        cache.Set(Key, Valid);
        cache.Set(unknownKey, SignatureObservation.Unknown());
        clock.Advance(SignatureVerdictCache.UnknownLifetime + TimeSpan.FromSeconds(1));
        Assert.True(cache.TryGet(Key, out _));
        Assert.False(cache.TryGet(unknownKey, out _));
        clock.Advance(SignatureVerdictCache.DefinitiveLifetime);
        Assert.False(cache.TryGet(Key, out _));
        Assert.Empty(cache.Snapshot());
    }

    [Fact]
    public void MalformedKeysAreNeverStored()
    {
        var cache = new SignatureVerdictCache(new FakeTime());
        cache.Set(Key with { Sha256 = "short" }, Valid);
        cache.Set(Key with { Size = 0 }, Valid);
        cache.Set(Key with { LastWriteUtcTicks = 0 }, Valid);
        cache.Set(Key, new SignatureObservation("made-up"));
        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public void CapacityIsBounded()
    {
        var cache = new SignatureVerdictCache(new FakeTime());
        for (var i = 0; i < SignatureVerdictCache.Capacity + 10; i++)
            cache.Set(Key with { Sha256 = i.ToString("x64") }, Valid);
        Assert.Equal(SignatureVerdictCache.Capacity, cache.Count);
    }
}

public sealed class AppSignatureCoverageTests
{
    private static InventoryApp App(string id, string? arch = "x86_64") => new()
    {
        Name = "App " + id, Version = "1.0", Identifier = id, Publisher = "Registry claim", Architecture = arch,
    };

    private static AppInstallationEvidence Unsigned(string path) => new()
    {
        CollectionStatus = "complete",
        InstallPath = @"C:\Program Files\App",
        ExecutablePath = path,
        ExecutableSha256 = new string('a', 64),
        SignatureState = "unsigned",
        ExecutableResolution = ExecutableResolutions.DisplayIcon,
    };

    private static CoverageLine Result(int index, AppInstallationEvidence evidence, SignatureCacheKey? key = null,
        SignatureObservation? observation = null) =>
        new() { Kind = CoverageLine.Result, Index = index, Evidence = evidence, CacheKey = key, CacheObservation = observation };

    // Coverage reaches every app row, not only the reviewed targets (which are empty in
    // production). On origin/main no non-target row ever carried installation_evidence.
    [Fact]
    public async Task EveryAppWithoutReviewedEvidenceIsAttemptedAndReviewedEvidenceIsKept()
    {
        var reviewed = new AppInstallationEvidence { CollectionStatus = "complete", SignatureState = "valid", Signer = "CN=R",
            ExecutableResolution = ExecutableResolutions.ReviewedTarget };
        var apps = new[] { App("{A}"), App("{B}", "x86") with { }, App("C") with { InstallationEvidence = reviewed } };
        CoverageRequest? seen = null;
        var result = await AppSignatureCoverage.CollectAsync(apps, new SignatureVerdictCache(new FakeTime()), (request, _) =>
        {
            seen = request;
            return Task.FromResult(new CoverageSession(
                request.Targets.Select(t => Result(t.Index, Unsigned(@"C:\Program Files\App\" + t.Index + ".exe"))).ToArray(),
                CoverageSessionEnd.Completed, null));
        }, new FakeTime());

        Assert.Equal([0, 1], seen!.Targets.Select(t => t.Index));
        Assert.Equal([false, true], seen.Targets.Select(t => t.Wow6432));
        Assert.Equal("unsigned", result.Apps[0].InstallationEvidence!.SignatureState);
        Assert.Equal("unsigned", result.Apps[1].InstallationEvidence!.SignatureState);
        Assert.Same(reviewed, result.Apps[2].InstallationEvidence);
        Assert.Equal("complete", result.Summary.CollectionStatus);
        Assert.Equal(2, result.Summary.Attempted);
        Assert.Equal(2, result.Summary.Resolved);
        // Everything else on the row is untouched.
        Assert.Equal(apps[0], result.Apps[0] with { InstallationEvidence = null });
    }

    [Fact]
    public async Task CoverageRowsNeverCarryReviewedDeliveryProvenance()
    {
        var forged = Unsigned(@"C:\Program Files\App\a.exe") with { CatalogueVersion = "x", DeliveryVersion = 9, ContentHash = new string('f', 64) };
        var result = await AppSignatureCoverage.CollectAsync([App("A")], new SignatureVerdictCache(new FakeTime()),
            (_, _) => Task.FromResult(new CoverageSession([Result(0, forged)], CoverageSessionEnd.Completed, null)), new FakeTime());
        var evidence = result.Apps[0].InstallationEvidence!;
        Assert.Null(evidence.CatalogueVersion);
        Assert.Null(evidence.DeliveryVersion);
        Assert.Null(evidence.ContentHash);
    }

    [Fact]
    public async Task NewVerdictsAreCachedAndTheSnapshotGoesToTheNextHelper()
    {
        var cache = new SignatureVerdictCache(new FakeTime());
        var key = new SignatureCacheKey(new string('a', 64), 10, 20);
        var observation = new SignatureObservation("unsigned");
        await AppSignatureCoverage.CollectAsync([App("A")], cache, (request, _) =>
        {
            Assert.Empty(request.Cache);
            return Task.FromResult(new CoverageSession([Result(0, Unsigned(@"C:\Program Files\App\a.exe"), key, observation)],
                CoverageSessionEnd.Completed, null));
        }, new FakeTime());
        Assert.True(cache.TryGet(key, out var cached));
        Assert.Equal(observation, cached);
        await AppSignatureCoverage.CollectAsync([App("A")], cache, (request, _) =>
        {
            Assert.Equal(key, Assert.Single(request.Cache).Key);
            return Task.FromResult(new CoverageSession([], CoverageSessionEnd.Completed, null));
        }, new FakeTime());
    }

    [Fact]
    public async Task EachHelperGetsOnlyTheRemainingBudgetAndExhaustionIsReported()
    {
        var clock = new FakeTime();
        var budgets = new List<TimeSpan>();
        var apps = Enumerable.Range(0, 4).Select(i => App("A" + i)).ToArray();
        var result = await AppSignatureCoverage.CollectAsync(apps, new SignatureVerdictCache(clock), (request, budget) =>
        {
            budgets.Add(budget);
            // Each helper hangs on its first pending target and eats 20 seconds doing it.
            clock.Advance(TimeSpan.FromSeconds(20));
            var first = request.Targets.First(t => !request.Completed.Contains(t.Index));
            return Task.FromResult(new CoverageSession([], CoverageSessionEnd.StepTimeout, first.Index));
        }, clock);

        Assert.Equal([AppSignatureCoverage.TotalBudget, AppSignatureCoverage.TotalBudget - TimeSpan.FromSeconds(20),
            AppSignatureCoverage.TotalBudget - TimeSpan.FromSeconds(40)], budgets);
        Assert.Equal(["collection_timeout"], result.Apps[0].InstallationEvidence!.Errors);
        Assert.Equal(["collection_timeout"], result.Apps[1].InstallationEvidence!.Errors);
        Assert.Equal(["collection_timeout"], result.Apps[2].InstallationEvidence!.Errors);
        Assert.Equal(["collection_budget_exhausted"], result.Apps[3].InstallationEvidence!.Errors);
        Assert.All(result.Apps, a => Assert.Equal("unknown", a.InstallationEvidence!.SignatureState));
        Assert.Equal("unavailable", result.Summary.CollectionStatus);
    }

    [Fact]
    public async Task AHungTargetIsSkippedAndTheRestFinishInAFreshHelper()
    {
        var requests = new List<CoverageRequest>();
        var result = await AppSignatureCoverage.CollectAsync([App("A"), App("B"), App("C")],
            new SignatureVerdictCache(new FakeTime()), (request, _) =>
            {
                requests.Add(request);
                return Task.FromResult(requests.Count == 1
                    ? new CoverageSession([Result(0, Unsigned(@"C:\Program Files\App\a.exe"))], CoverageSessionEnd.StepTimeout, 1)
                    : new CoverageSession([Result(2, Unsigned(@"C:\Program Files\App\c.exe"))], CoverageSessionEnd.Completed, null));
            }, new FakeTime());

        Assert.Equal(2, requests.Count);
        Assert.Equal([0, 2], requests[1].Targets.Select(t => t.Index));
        Assert.Equal([0], requests[1].Completed);
        Assert.Equal([1], requests[1].Stuck);
        Assert.Equal("unsigned", result.Apps[0].InstallationEvidence!.SignatureState);
        Assert.Equal(["collection_timeout"], result.Apps[1].InstallationEvidence!.Errors);
        Assert.Equal("unsigned", result.Apps[2].InstallationEvidence!.SignatureState);
        Assert.Equal("partial", result.Summary.CollectionStatus);
        Assert.Equal(["collection_timeout"], result.Summary.Errors);
    }

    [Fact]
    public async Task HelperStartsAreCapped()
    {
        var calls = 0;
        var apps = Enumerable.Range(0, 20).Select(i => App("A" + i)).ToArray();
        await AppSignatureCoverage.CollectAsync(apps, new SignatureVerdictCache(new FakeTime()), (request, _) =>
        {
            calls++;
            var first = request.Targets.First(t => !request.Completed.Contains(t.Index));
            return Task.FromResult(new CoverageSession([], CoverageSessionEnd.StepTimeout, first.Index));
        }, new FakeTime());
        Assert.Equal(AppSignatureCoverage.MaximumSessions, calls);
    }

    [Fact]
    public async Task AFailedHelperLeavesEveryRowUnknownNeverAbsent()
    {
        var result = await AppSignatureCoverage.CollectAsync([App("A")], new SignatureVerdictCache(new FakeTime()),
            (_, _) => throw new IOException("private path"), new FakeTime());
        var evidence = result.Apps[0].InstallationEvidence!;
        Assert.Equal("unknown", evidence.SignatureState);
        Assert.Equal(["helper_failed"], evidence.Errors);
        Assert.Null(evidence.ExecutablePath);
    }

    // PAT-2116: a helper that was never started is not a helper that crashed or hung.
    [Theory]
    [InlineData((int)CoverageSessionEnd.PreflightRefused, "helper_preflight_refused")]
    [InlineData((int)CoverageSessionEnd.Failed, "helper_failed")]
    [InlineData((int)CoverageSessionEnd.StepTimeout, "collection_timeout")]
    public async Task EachWayAHelperCanFailKeepsItsOwnCode(int endValue, string code)
    {
        var end = (CoverageSessionEnd)endValue;
        var calls = 0;
        var result = await AppSignatureCoverage.CollectAsync([App("A")], new SignatureVerdictCache(new FakeTime()),
            (_, _) => { calls++; return Task.FromResult(new CoverageSession([], end, null)); }, new FakeTime());
        Assert.Equal([code], result.Apps[0].InstallationEvidence!.Errors);
        Assert.Equal("unavailable", result.Summary.CollectionStatus);
        Assert.Equal([code], result.Summary.Errors);
        Assert.Equal(1, calls); // a refused preflight is not retried within the scan
    }

    [Fact]
    public async Task IdentifiersThatCannotBeARegistrySubkeyAreNotSent()
    {
        CoverageRequest? seen = null;
        await AppSignatureCoverage.CollectAsync([App(@"a\..\b"), App(" padded"), App("ok")],
            new SignatureVerdictCache(new FakeTime()), (request, _) =>
            {
                seen = request;
                return Task.FromResult(new CoverageSession([], CoverageSessionEnd.Completed, null));
            }, new FakeTime());
        Assert.Equal(["ok"], seen!.Targets.Select(t => t.Identifier));
    }

    [Fact]
    public async Task ReadSessionStopsAtTheStepTimeoutAndNamesTheHungTarget()
    {
        var pipe = new BlockingReader("{\"k\":\"step\",\"i\":7}\n");
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var session = await AppSignatureCoverage.ReadSessionAsync(pipe, TimeSpan.FromMilliseconds(150), TimeSpan.FromSeconds(30));
        Assert.Equal(CoverageSessionEnd.StepTimeout, session.End);
        Assert.Equal(7, session.StuckIndex);
        Assert.InRange(watch.Elapsed, TimeSpan.FromMilliseconds(100), TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task ReadSessionStopsAtTheBudgetWhenItIsShorterThanAStep()
    {
        var session = await AppSignatureCoverage.ReadSessionAsync(new BlockingReader(""),
            TimeSpan.FromSeconds(30), TimeSpan.FromMilliseconds(150));
        Assert.Equal(CoverageSessionEnd.BudgetExhausted, session.End);
    }

    [Fact]
    public async Task ReadSessionCollectsResultsUntilDone()
    {
        var evidence = JsonSerializer.Serialize(new CoverageLine { Kind = "result", Index = 2,
            Evidence = Unsigned(@"C:\Program Files\App\a.exe") });
        var session = await AppSignatureCoverage.ReadSessionAsync(
            new StringReader("{\"k\":\"step\",\"i\":2}\n" + evidence + "\n{\"k\":\"done\",\"i\":0}\n"),
            TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        Assert.Equal(CoverageSessionEnd.Completed, session.End);
        Assert.Equal("unsigned", Assert.Single(session.Results).Evidence!.SignatureState);
    }

    [Theory]
    [InlineData("not json\n")]
    [InlineData("{\"k\":\"surprise\",\"i\":0}\n")]
    [InlineData("{\"k\":\"step\",\"i\":0}\n")] // ends with no done line
    public async Task ReadSessionTreatsGarbageAndEarlyEndAsFailed(string output) =>
        Assert.Equal(CoverageSessionEnd.Failed, (await AppSignatureCoverage.ReadSessionAsync(new StringReader(output),
            TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5))).End);

    [Fact]
    public async Task ALineOverTheBoundFailsTheSession()
    {
        var session = await AppSignatureCoverage.ReadSessionAsync(
            new StringReader(new string('x', BoundedLineReader.MaximumLineChars + 1) + "\n"),
            TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        Assert.Equal(CoverageSessionEnd.Failed, session.End);
    }

    [Fact]
    public void WireShapeCarriesThePinnablePublisherOnlyBesideValid()
    {
        var observation = new SignatureObservation("valid", "CN=Vendor", new string('1', 64), "CN=Vendor CA",
            new string('2', 64), RootKinds.Public);
        var valid = new AppInstallationEvidence { CollectionStatus = "complete" }.WithSignature(observation);
        using (var json = JsonDocument.Parse(JsonSerializer.Serialize(App("A") with { InstallationEvidence = valid })))
        {
            var e = json.RootElement.GetProperty("installation_evidence");
            Assert.Equal("valid", e.GetProperty("signature_state").GetString());
            Assert.Equal("CN=Vendor", e.GetProperty("signer").GetString());
            Assert.Equal(new string('1', 64), e.GetProperty("signer_thumbprint").GetString());
            Assert.Equal("CN=Vendor CA", e.GetProperty("issuer").GetString());
            Assert.Equal(new string('2', 64), e.GetProperty("root_thumbprint").GetString());
            Assert.Equal("public", e.GetProperty("root_kind").GetString());
        }
        foreach (var state in new[] { "unsigned", "invalid", "unknown" })
        {
            var other = new AppInstallationEvidence().WithSignature(observation with { State = state });
            using var json = JsonDocument.Parse(JsonSerializer.Serialize(other));
            Assert.Equal(state, json.RootElement.GetProperty("signature_state").GetString());
            foreach (var field in new[] { "signer", "signer_thumbprint", "issuer", "root_thumbprint", "root_kind" })
                Assert.False(json.RootElement.TryGetProperty(field, out _), $"{state} must not carry {field}");
        }
    }

    [Fact]
    public void RequestAndLineRoundTrip()
    {
        var request = new CoverageRequest([new(1, "{X}", true)], [3], [4],
            [new(new(new string('a', 64), 1, 2), new SignatureObservation("valid", "CN=A", RootKind: "public"))]);
        var back = JsonSerializer.Deserialize<CoverageRequest>(JsonSerializer.Serialize(request))!;
        Assert.Equal(request.Targets, back.Targets);
        Assert.Equal(request.Cache[0].Key, back.Cache[0].Key);
        Assert.Equal(request.Cache[0].Observation, back.Cache[0].Observation);
    }

    // A reader that returns its text, then never completes: a hung helper.
    private sealed class BlockingReader(string text) : TextReader
    {
        private string _text = text;
        public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken cancellationToken = default)
        {
            if (_text.Length == 0) return new(new TaskCompletionSource<int>().Task);
            var count = Math.Min(buffer.Length, _text.Length);
            _text.AsSpan(0, count).CopyTo(buffer.Span);
            _text = _text[count..];
            return new(count);
        }
    }
}

internal sealed class FakeTime : TimeProvider
{
    private long _ticks;
    private DateTimeOffset _now = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public override long GetTimestamp() => _ticks;
    public override DateTimeOffset GetUtcNow() => _now;
    public void Advance(TimeSpan by)
    {
        _ticks += by.Ticks;
        _now += by;
    }
}
