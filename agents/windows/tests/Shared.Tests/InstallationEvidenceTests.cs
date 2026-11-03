using System.Text.Json;
using Patched.Shared.Contract;
using Patched.Shared.InstallationEvidence;
using Xunit;

namespace Patched.Shared.Tests;

public sealed class InstallationEvidenceTests
{
    private const string Product = "{00112233-4455-6677-8899-AABBCCDDEEFF}";
    private const string SecondProduct = "{10112233-4455-6677-8899-AABBCCDDEEFF}";
    private static readonly ReviewedInstallationTarget Target = new("windows_msi_product_code", Product,
        "CN=Fixture Publisher", @"C:\Program Files\Fixture", @"C:\Program Files\Fixture\Fixture.exe");
    private static InventoryApp App(string id = Product) => new()
    {
        Name = "Display name is not identity",
        Identifier = id,
        Publisher = "Fixture Publisher",
        Version = "1.2.3",
        Architecture = "x86_64",
        LastUsedAt = "2026-09-20T10:00:00Z",
        LaunchCount = 3,
    };
    private static AppInstallationEvidence Complete => new()
    {
        CollectionStatus = "complete",
        InstallPath = Target.InstallPath,
        ExecutablePath = Target.ExecutablePath,
        ExecutableSha256 = new string('a', 64),
        SignatureState = "valid",
        Signer = "CN=Fixture Publisher",
    };

    [Fact]
    public async Task MissingVerifiedSnapshotDoesNotProbe()
    {
        var result = await InstallationEvidenceCollector.CollectVerifiedAsync([App()],
            null, (_, _) => throw new Exception("must not probe"));
        Assert.Equal("unavailable", result.Summary.CollectionStatus);
        Assert.Equal(["reviewed_targets_unavailable"], result.Summary.Errors);
        Assert.Null(result.Apps[0].InstallationEvidence);
    }

    [Fact]
    public async Task MatchesStableIdentityAndPreservesEveryExistingField()
    {
        var original = App();
        var result = await InstallationEvidenceCollector.CollectAsync([original], [Target], (_, budget) =>
        {
            Assert.InRange(budget.TotalSeconds, 0.001, 3);
            return Task.FromResult(Complete);
        });
        Assert.Equal(original, result.Apps[0] with { InstallationEvidence = null });
        Assert.Equal("complete", result.Summary.CollectionStatus);
        Assert.Equal("valid", result.Apps[0].InstallationEvidence!.SignatureState);
    }

    [Fact]
    public async Task DuplicatedObservationsHashOnlyOnce()
    {
        var calls = 0;
        var result = await InstallationEvidenceCollector.CollectAsync([App(), App()], [Target], (_, _) =>
        { calls++; return Task.FromResult(Complete); });
        Assert.Equal(1, calls);
        Assert.Same(result.Apps[0].InstallationEvidence, result.Apps[1].InstallationEvidence);
    }

    [Fact]
    public async Task MixedCaseNativeIdentityMatchesWithoutChangingMetadataOrRepeatingProbe()
    {
        var original = App() with
        {
            Identifier = Target.IdentityValue.ToLowerInvariant(),
            Publisher = "Different registry observation",
            Architecture = "x86",
        };
        var calls = 0;
        var result = await InstallationEvidenceCollector.CollectAsync([original, App()], [Target], (_, _) =>
        {
            calls++;
            return Task.FromResult(Complete);
        });
        Assert.Equal(1, calls);
        Assert.Equal("complete", result.Summary.CollectionStatus);
        Assert.Equal(original, result.Apps[0] with { InstallationEvidence = null });
        Assert.Same(result.Apps[0].InstallationEvidence, result.Apps[1].InstallationEvidence);
    }

    [Fact]
    public async Task CaseOnlyDuplicateTargetsAreRejectedBeforeProbing()
    {
        var duplicate = Target with
        {
            IdentityValue = Target.IdentityValue.ToLowerInvariant(),
        };
        var calls = 0;
        var result = await InstallationEvidenceCollector.CollectAsync([App()], [Target, duplicate], (_, _) =>
        {
            calls++;
            return Task.FromResult(Complete);
        });
        Assert.Equal(0, calls);
        Assert.Equal("unavailable", result.Summary.CollectionStatus);
        Assert.Equal(["reviewed_targets_invalid"], result.Summary.Errors);
    }

    [Fact]
    public async Task NameOrPublisherAloneNeverSelectsAFile()
    {
        var apps = new[] { App("other"), App("winget.fixture"), App("Fixture") };
        var result = await InstallationEvidenceCollector.CollectAsync(apps, [Target], (_, _) => throw new Exception());
        Assert.Equal("unavailable", result.Summary.CollectionStatus);
        Assert.Equal(["no_reviewed_observations"], result.Summary.Errors);
        Assert.All(result.Apps, a => Assert.Null(a.InstallationEvidence));
    }

    [Theory]
    [InlineData("partial", "partial")]
    [InlineData("unavailable", "partial")]
    [InlineData("complete", "complete")]
    public async Task MixedStatusAggregatesWithoutInferringAbsence(string secondStatus, string expected)
    {
        var second = Target with { IdentityValue = SecondProduct };
        var result = await InstallationEvidenceCollector.CollectAsync([App(), App(SecondProduct)], [Target, second],
            (t, _) => Task.FromResult(t == Target ? Complete : new AppInstallationEvidence { CollectionStatus = secondStatus }));
        Assert.Equal(expected, result.Summary.CollectionStatus);
        Assert.Equal(2, result.Apps.Count);
    }

    [Fact]
    public async Task ProbeErrorsRemainUnknownWithNoSensitiveExceptionText()
    {
        var result = await InstallationEvidenceCollector.CollectAsync([App()], [Target],
            (_, _) => throw new IOException("private user and network path"));
        var evidence = result.Apps[0].InstallationEvidence!;
        Assert.Equal("unavailable", result.Summary.CollectionStatus);
        Assert.Equal("unknown", evidence.SignatureState);
        Assert.Null(evidence.InstallPath);
        Assert.Null(evidence.ExecutableSha256);
        Assert.Equal(["probe_failed"], evidence.Errors);
    }

    [Fact]
    public async Task InvalidOrExcessiveReviewedTargetsNeverProbe()
    {
        foreach (var targets in new[] { new[] { Target, Target },
            Enumerable.Range(0, 25).Select(i => Target with { IdentityValue = Guid.NewGuid().ToString("B") }).ToArray(),
            new[] { Target with { AuthenticodeSubject = "" } } })
        {
            var result = await InstallationEvidenceCollector.CollectAsync([App()], targets, (_, _) => throw new Exception());
            Assert.Equal(["reviewed_targets_invalid"], result.Summary.Errors);
        }
    }

    [Theory]
    [InlineData(null, @"C:\Program Files\Fixture\Fixture.exe")]
    [InlineData("", @"C:\Program Files\Fixture\Fixture.exe")]
    [InlineData(" \t", @"C:\Program Files\Fixture\Fixture.exe")]
    [InlineData(@"C:\Program Files\Fixture", null)]
    [InlineData(@"C:\Program Files\Fixture", "")]
    [InlineData(@"C:\Program Files\Fixture", " \t")]
    public async Task BlankReviewedPathsAreRejectedBeforeProbing(string? installPath, string? executablePath)
    {
        var calls = 0;
        var app = App();
        var target = Target with { InstallPath = installPath!, ExecutablePath = executablePath! };
        var result = await InstallationEvidenceCollector.CollectAsync([app], [target], (_, _) =>
        {
            calls++;
            return Task.FromResult(Complete);
        });
        Assert.Equal(0, calls);
        Assert.Equal("unavailable", result.Summary.CollectionStatus);
        Assert.Equal(["reviewed_targets_invalid"], result.Summary.Errors);
        Assert.Same(app, result.Apps[0]);
        Assert.Null(result.Apps[0].InstallationEvidence);
    }

    [Fact]
    public async Task OverallBudgetStopsFurtherProbesAndPreservesRemainingObservations()
    {
        var clock = new FixtureClock();
        var second = Target with { IdentityValue = SecondProduct };
        var calls = 0;
        var result = await InstallationEvidenceCollector.CollectAsync([App(), App(SecondProduct)], [Target, second],
            (_, _) => { calls++; clock.Advance(16); return Task.FromResult(Complete); }, clock);
        Assert.Equal(1, calls);
        Assert.Equal("partial", result.Summary.CollectionStatus);
        Assert.Equal(["collection_budget_exhausted"], result.Apps[1].InstallationEvidence!.Errors);
        Assert.Equal("unknown", result.Apps[1].InstallationEvidence!.SignatureState);
    }

    private sealed class FixtureClock : TimeProvider
    {
        private long _timestamp;
        public override long TimestampFrequency => 1;
        public override long GetTimestamp() => _timestamp;
        public void Advance(long seconds) => _timestamp += seconds;
    }

    [Fact]
    public void WireShapeIsAdditiveAndCanRepresentMacEvidence()
    {
        var oldApp = JsonSerializer.Serialize(App());
        Assert.DoesNotContain("installation_evidence", oldApp);
        var mac = App() with
        {
            Identifier = "im.example.fixture",
            InstallationEvidence = Complete with
            {
                Source = "macos_codesign",
                InstallPath = "/Applications/Fixture.app",
                ExecutablePath = "/Applications/Fixture.app/Contents/MacOS/Fixture",
            },
        };
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(mac));
        var evidence = json.RootElement.GetProperty("installation_evidence");
        Assert.Equal("macos_codesign", evidence.GetProperty("source").GetString());
        Assert.Equal(64, evidence.GetProperty("executable_sha256").GetString()!.Length);
        Assert.Equal("complete", evidence.GetProperty("collection_status").GetString());
        Assert.False(evidence.TryGetProperty("compliance", out _));
    }
}
