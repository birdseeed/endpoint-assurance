using Patched.Shared.Posture;
using Patched.Shared.Tray;
using Xunit;
using PostureDoc = Patched.Shared.Posture.Posture;

namespace Patched.Shared.Tests;

/// <summary>
/// Desktop chain U4: the glanceable tray-flyout presenter. Verifies the icon-state
/// precedence (attention > updates > ok), the glanceable lines, tier text, and the
/// no-data state.
/// </summary>
public class TrayFlyoutPresenterTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-12-17T08:20:00Z");

    private static PostureDoc Fixture()
    {
        var path = LocateContractsFile("posture.sample.windows.json");
        return PostureDoc.Deserialize(File.ReadAllText(path))!;
    }

    private static TrayFlyoutVm Build(PostureDoc p, bool stale = false) =>
        TrayFlyoutPresenter.Build(new PostureSnapshot(p, TimeSpan.FromMinutes(6), null), Now);

    [Fact]
    public void Fixture_HasUpdatesAndDrift_ShowsAttention()
    {
        // The windows fixture has an unapproved_present drift entry → attention wins.
        var vm = Build(Fixture());
        Assert.Equal(TrayIconState.Attention, vm.IconState);
        Assert.Equal("Needs attention", vm.Headline);
        Assert.Contains("CIS 87 of 134", vm.DetailLine);
        Assert.StartsWith("Endpoint Assurance:", vm.TierLine);
        Assert.True(vm.AttentionCount >= 1);
    }

    [Fact]
    public void UpdatesOnly_ShowsUpdateState()
    {
        // Drift-free posture (built via record `with`, not brittle text replacement):
        // no criticals + no drift → updates (2) drive the state.
        var p = Fixture();
        var noDrift = p with { AppPolicy = p.AppPolicy! with { Drift = [] } };
        var vm = Build(noDrift);
        Assert.Equal(TrayIconState.UpdatesAvailable, vm.IconState);
        Assert.Equal("2 updates available", vm.Headline);
    }

    [Fact]
    public void NoData_ShowsWaitingState()
    {
        var vm = TrayFlyoutPresenter.Build(PostureSnapshot.None, Now);
        Assert.Equal(TrayIconState.Unknown, vm.IconState);
        Assert.Equal("Waiting for Patched service", vm.Headline);

        var err = TrayFlyoutPresenter.Build(PostureSnapshot.Failed("x"), Now);
        Assert.Equal("Status unavailable", err.Headline);
    }

    [Fact]
    public void StaleFlagPropagates()
    {
        var vm = TrayFlyoutPresenter.Build(
            new PostureSnapshot(Fixture(), TimeSpan.FromHours(48), null), Now);
        Assert.True(vm.IsStale);
    }

    /// <summary>
    /// Walks up from the test binary looking for a sibling 'contracts/' directory
    /// (repo layout: 'contracts/' sits next to 'windows/', not inside it). Throws
    /// rather than returning null: every test in this file needs the fixture to test
    /// anything meaningful, so a missing file must fail loudly with a message that
    /// says why, not surface later as a bare ArgumentNullException out of
    /// File.ReadAllText. A vague failure here is exactly what produced PAT-1253's
    /// false "27 Windows-only failures" — the fixture wasn't found because the repro
    /// copied only the 'windows' subtree (e.g. 'git archive &lt;ref&gt; windows') and
    /// dropped the sibling 'contracts/' directory the search relies on.
    /// </summary>
    private static string LocateContractsFile(string fileName)
    {
        var start = AppContext.BaseDirectory;
        var dir = new DirectoryInfo(start);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "contracts", fileName);
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        throw new FileNotFoundException(
            $"Could not locate '{fileName}' under a 'contracts' directory walking up from " +
            $"'{start}'. 'contracts/' is a repo-root sibling of 'windows/' — if this test binary " +
            "was built from a copy that includes only the 'windows' subtree, copy 'contracts/' " +
            "alongside it too.");
    }
}
