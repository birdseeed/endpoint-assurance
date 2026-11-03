using Patched.Shared.Apps;
using Patched.Shared.Contract;
using Patched.Shared.InstallationEvidence;
using Patched.Shared.Metering;
using Xunit;

namespace Patched.Shared.Tests;

public sealed class PerUserAppBehaviorTests
{
    private const string AliceSid = "S-1-5-21-100-200-300-1001";
    private const string BobSid = "S-1-5-21-100-200-300-1002";
    private const string Product = "{00112233-4455-6677-8899-AABBCCDDEEFF}";
    private const string Alice = "LAB\\alice";
    private const string Bob = "LAB\\bob";
    private static readonly ReviewedInstallationTarget Target = new("windows_msi_product_code", Product,
        "CN=Synthetic", @"C:\Program Files\Synthetic", @"C:\Program Files\Synthetic\app.exe");
    private static InventoryApp App(string? user = null) => new()
        { Name = "Synthetic", Version = "1.2.3", Identifier = Product, UserAccount = user };
    private static readonly AppInstallationEvidence ValidMachine = new()
        { CollectionStatus = "complete", SignatureState = "valid", InstallPath = Target.InstallPath,
          ExecutablePath = Target.ExecutablePath, Signer = Target.AuthenticodeSubject };

    private sealed class Key : IAppRegistryKey
    {
        internal readonly Dictionary<string, Key> Children = new(StringComparer.OrdinalIgnoreCase);
        internal readonly Dictionary<string, object> Values = new();
        internal readonly HashSet<string> Denied = new(StringComparer.OrdinalIgnoreCase);
        internal bool ListFails;
        internal bool ValuesFail;
        internal readonly List<string> Opened = [];
        internal Key Add(string name) { var key = new Key(); Children.Add(name, key); return key; }
        internal Key App(string id = Product)
        {
            var key = Add(id);
            key.Values["DisplayName"] = "Synthetic";
            key.Values["DisplayVersion"] = "1.2.3";
            return key;
        }
        public IEnumerable<string> GetSubKeyNames() => ListFails ? throw new IOException("synthetic listing failure") : Children.Keys.ToArray();
        public IAppRegistryKey? OpenSubKey(string path)
        {
            Opened.Add(path);
            if (Denied.Contains(path)) throw new UnauthorizedAccessException("synthetic denied key");
            return Children.GetValueOrDefault(path);
        }
        public object? GetValue(string name) => ValuesFail ? throw new IOException("synthetic unreadable value") : Values.GetValueOrDefault(name);
        public void Dispose() { }
    }
    private sealed class Reader : IAppRegistryReader
    {
        internal readonly Key Machine = new();
        internal readonly Key Users = new();
        internal readonly Dictionary<string, string?> Accounts = new() { [AliceSid] = Alice, [BobSid] = Bob };
        internal readonly List<string> Resolved = [];
        internal Reader() { Machine.Add(RegistryAppCollection.NativePath); Machine.Add(RegistryAppCollection.WowPath); }
        public bool Is64BitOperatingSystem => true;
        public IAppRegistryKey OpenMachine() => Machine;
        public IAppRegistryKey OpenUsers() => Users;
        public string? ResolveAccountName(string sid) { Resolved.Add(sid); return Accounts.GetValueOrDefault(sid); }
        internal Key User(string sid) => Users.Add(sid);
        internal AppCollectionResult Scan() => RegistryAppCollection.Scan(this, (_, _, version) => version);
    }
    private static void UserStatus(AppCollectionResult scan, string user, string state) =>
        Assert.Equal(state, Assert.Single(scan.Users, s => s.UserAccount == user).CollectionStatus);

    [Fact]
    public void LoadedRealUsersAreReadAndMachineAndUserIdentityNeverDeduplicateEachOther()
    {
        var r = new Reader();
        r.Machine.Children[RegistryAppCollection.NativePath].App();
        var alice = r.User(AliceSid);
        alice.Add(RegistryAppCollection.NativePath).App();
        alice.Add(RegistryAppCollection.WowPath).App();
        r.User(BobSid).Add(RegistryAppCollection.NativePath).App();
        foreach (var ignored in new[] { ".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20", AliceSid + "_Classes", "S-1-5-21-bad" })
            r.Users.Add(ignored).Add(RegistryAppCollection.NativePath).App();
        var scan = r.Scan();
        Assert.Equal("complete", scan.Status);
        Assert.Equal(new string?[] { null, Alice, Bob }, scan.Apps.Select(a => a.UserAccount).OrderBy(x => x).ToArray());
        Assert.All(scan.Apps, a => { Assert.Equal(Product, a.Identifier); Assert.Equal("1.2.3", a.Version); });
        Assert.Equal(new[] { AliceSid, BobSid }, r.Resolved.OrderBy(x => x).ToArray());
        Assert.Equal(new[] { AliceSid, BobSid }, r.Users.Opened.OrderBy(x => x).ToArray());
        UserStatus(scan, Alice, "complete"); UserStatus(scan, Bob, "complete");
    }

    [Fact]
    public void LoggedOffUserIsOmittedAndAuthoritativeEmptyUserIsExplicit()
    {
        var r = new Reader();
        r.User(AliceSid).Add(RegistryAppCollection.NativePath).App();
        Assert.Single(r.Scan().Apps);
        r.Users.Children.Remove(AliceSid);
        r.User(BobSid); // loaded, both uninstall keys absent: authoritative empty scope
        var scan = r.Scan();
        Assert.Empty(scan.Apps);
        Assert.DoesNotContain(scan.Users, u => u.UserAccount == Alice);
        UserStatus(scan, Bob, "complete");
    }

    [Theory]
    [InlineData("hive")]
    [InlineData("source")]
    [InlineData("entry")]
    [InlineData("value")]
    public void FailedUserCannotPruneAndDoesNotPoisonMachineOrOtherUser(string failure)
    {
        var r = new Reader();
        var hive = r.User(AliceSid);
        var source = hive.Add(RegistryAppCollection.NativePath);
        var app = source.App();
        if (failure == "hive") r.Users.Denied.Add(AliceSid);
        if (failure == "source") source.ListFails = true;
        if (failure == "entry") source.Denied.Add(Product);
        if (failure == "value") app.ValuesFail = true;
        r.User(BobSid).Add(RegistryAppCollection.NativePath).App();
        var scan = r.Scan();
        Assert.Equal("complete", scan.Status);
        UserStatus(scan, Alice, "partial"); UserStatus(scan, Bob, "complete");
        Assert.Contains(scan.Apps, a => a.UserAccount == Bob);
    }

    [Fact]
    public void PartialHivePreservesItsReadableRows()
    {
        var r = new Reader();
        var hive = r.User(AliceSid);
        hive.Add(RegistryAppCollection.NativePath).App();
        hive.Denied.Add(RegistryAppCollection.WowPath);
        var scan = r.Scan();
        UserStatus(scan, Alice, "partial");
        Assert.Equal(Alice, Assert.Single(scan.Apps).UserAccount);
    }

    [Fact]
    public void TwoSidsResolvingToOneAccountMergeConservatively()
    {
        var r = new Reader(); r.Accounts[BobSid] = Alice;
        r.User(AliceSid).Add(RegistryAppCollection.NativePath).App();
        r.User(BobSid); r.Users.Denied.Add(BobSid);
        var scan = r.Scan();
        Assert.Single(scan.Users); UserStatus(scan, Alice, "partial");
        Assert.Equal(Alice, Assert.Single(scan.Apps).UserAccount);
    }

    [Fact]
    public void MissingAccountUsesExactSidAndOverlongAccountIsNeverTruncated()
    {
        var r = new Reader(); r.Accounts[AliceSid] = null; r.Accounts[BobSid] = new string('a', 129);
        r.User(AliceSid).Add(RegistryAppCollection.NativePath).App();
        r.User(BobSid).Add(RegistryAppCollection.NativePath).App();
        var scan = r.Scan();
        Assert.Equal(AliceSid, Assert.Single(scan.Apps).UserAccount);
        Assert.Single(scan.Users); UserStatus(scan, AliceSid, "complete");
    }

    [Fact]
    public void MachineFailureDoesNotDiscardReadableUserRowsOrTheirAuthority()
    {
        var r = new Reader();
        r.Machine.Denied.UnionWith([RegistryAppCollection.NativePath, RegistryAppCollection.WowPath]);
        r.User(AliceSid).Add(RegistryAppCollection.NativePath).App();
        var scan = r.Scan();
        Assert.Equal("unavailable", scan.Status);
        Assert.Equal(Alice, Assert.Single(scan.Apps).UserAccount); UserStatus(scan, Alice, "complete");
    }

    [Fact]
    public void FailedUserEnumerationNeverInventsACompleteUser()
    {
        var r = new Reader(); r.Users.ListFails = true;
        var scan = r.Scan();
        Assert.Empty(scan.Users); Assert.Equal("complete", scan.Status);
    }

    [Fact]
    public void MeteringNeverCopiesMachineIdentifierEvidenceOntoUserRow()
    {
        var apps = AppMeteringEvidence.Apply([App(), App(Alice)], new Dictionary<string, AppUsage>
            { [Product] = new(DateTimeOffset.Parse("2026-07-01T00:00:00Z"), 42, "recorded") });
        Assert.Equal(42, apps[0].LaunchCount);
        Assert.Equal(Alice, apps[1].UserAccount);
        Assert.Equal("unavailable", apps[1].UsageEvidence);
        Assert.Null(apps[1].LaunchCount); Assert.Null(apps[1].LastUsedAt);
    }

    [Fact]
    public async Task ReviewedMachineProbeDoesNotLendEvidenceToMatchingUserIdentifier()
    {
        var calls = 0;
        var result = await InstallationEvidenceCollector.CollectAsync([App(), App(Alice)], [Target], (_, _) =>
        { calls++; return Task.FromResult(ValidMachine); });
        Assert.Equal(1, calls); Assert.Equal("valid", result.Apps[0].InstallationEvidence!.SignatureState);
        Assert.Equal(Alice, result.Apps[1].UserAccount);
        AssertUnknown(result.Apps[1]);
    }

    [Fact]
    public async Task UserOnlyReviewedTargetNeverStartsMachineProbe()
    {
        var calls = 0;
        var result = await InstallationEvidenceCollector.CollectAsync([App(Alice)], [Target], (_, _) =>
        { calls++; return Task.FromResult(ValidMachine); });
        Assert.Equal(0, calls); AssertUnknown(Assert.Single(result.Apps));
    }

    [Fact]
    public async Task SignatureCoverageOnlySendsMachineRowsToHelperAndPreservesOwners()
    {
        var sent = new List<int>();
        var result = await AppSignatureCoverage.CollectAsync([App(), App(Alice), App(Bob)], new SignatureVerdictCache(),
            (request, _) =>
            {
                sent.AddRange(request.Targets.Select(t => t.Index));
                return Task.FromResult(new CoverageSession(request.Targets.Select(t => new CoverageLine
                    { Kind = CoverageLine.Result, Index = t.Index, Evidence = ValidMachine }).ToArray(), CoverageSessionEnd.Completed, null));
            });
        Assert.Equal(new[] { 0 }, sent);
        Assert.Equal("valid", result.Apps[0].InstallationEvidence!.SignatureState);
        Assert.Equal(new[] { Alice, Bob }, result.Apps.Skip(1).Select(a => a.UserAccount));
        Assert.All(result.Apps.Skip(1), AssertUnknown);
    }

    private static void AssertUnknown(InventoryApp app)
    {
        Assert.NotNull(app.InstallationEvidence);
        Assert.Equal("unknown", app.InstallationEvidence.SignatureState);
        Assert.Equal("unavailable", app.InstallationEvidence.CollectionStatus);
        Assert.Null(app.InstallationEvidence.InstallPath); Assert.Null(app.InstallationEvidence.ExecutablePath);
        Assert.Null(app.InstallationEvidence.Signer); Assert.Null(app.InstallationEvidence.ExecutableSha256);
    }
}
