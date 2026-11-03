using System.Reflection;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1260 non-author-review finding: HttpClient.Timeout bounds the WHOLE
/// operation including reading the response body, even under
/// HttpCompletionOption.ResponseHeadersRead - the "patched" client's 30s
/// budget (right for the small JSON envelope fetch) would demand >5.3 MB/s
/// sustained throughput to pull the ~160 MB artifact MSI, which fails on any
/// ordinary connection. The fix splits the artifact download onto its own
/// named client ("patched-artifact", Program.cs) with a longer, but still
/// bounded, Timeout.
///
/// This file proves two things directly against
/// <see cref="PatchedHttpClientTimeouts"/>, the actual typed source of truth
/// both AddHttpClient registrations in Program.cs read from:
///   1. The artifact timeout is genuinely different from (longer than) the
///      default - the whole download-times-out bug was that it silently
///      wasn't.
///   2. The artifact timeout is still BOUNDED to a defensible ceiling - an
///      unbounded/Infinite timeout would trade one failure mode (fails too
///      fast on a real connection) for a worse one (can hang forever on a
///      dead peer).
///
/// What this file deliberately does NOT do: wait out an actual 30-minute
/// HttpClient timeout, or stand up the full Windows-service DI host
/// (Host.CreateApplicationBuilder + AddWindowsService + the file-system
/// hardening Program.cs does at the top of Main) just to call
/// IHttpClientFactory.CreateClient("patched-artifact") and read .Timeout off
/// the result - that would mean either an excessively slow test or
/// reimplementing HttpClient's internal timeout enforcement. Asserting the
/// registration action's TimeSpan directly, that its value matches this
/// class's constant, is the practical proxy: the source check in
/// <see cref="ProgramCsWiring_BothAddHttpClientCallsUseTheseConstants_NotInlineLiterals"/>
/// below then closes the remaining gap by proving Program.cs's two
/// AddHttpClient blocks actually read from these same named constants rather
/// than inlining their own (possibly-drifted) literals.
/// </summary>
public sealed class PatchedHttpClientTimeoutsTests
{
    [Fact]
    public void Artifact_IsLongerThan_Default()
    {
        Assert.True(
            PatchedHttpClientTimeouts.Artifact > PatchedHttpClientTimeouts.Default,
            "the artifact download timeout must not collapse back to (or below) the small-JSON-call default");
    }

    [Fact]
    public void Default_Is30Seconds()
    {
        // Unchanged by this ticket - every other call on "patched" (envelope
        // fetch, inventory, provenance, agent-config, ...) still needs a short
        // budget so a stuck platform call doesn't stall the service.
        Assert.Equal(TimeSpan.FromSeconds(30), PatchedHttpClientTimeouts.Default);
    }

    [Fact]
    public void Artifact_IsBoundedToADefensibleCeiling()
    {
        // Long enough to tolerate a genuinely poor connection for a ~160 MB
        // transfer (30 minutes ≈ 89 KB/s sustained), short enough that a
        // truly dead peer can't hang the bootstrap-update check forever.
        // Lower bound guards against a future edit accidentally shrinking
        // this back toward the failure this ticket exists to fix; upper
        // bound guards against "fix a too-short timeout" being overcorrected
        // into an effectively-unbounded one.
        Assert.InRange(PatchedHttpClientTimeouts.Artifact, TimeSpan.FromMinutes(10), TimeSpan.FromHours(1));
    }

    [Fact]
    public void Artifact_IsNotInfinite()
    {
        // The download must still be BOUNDED - an unbounded hang on a dead
        // peer is not an acceptable trade for fixing a too-short timeout.
        Assert.NotEqual(Timeout.InfiniteTimeSpan, PatchedHttpClientTimeouts.Artifact);
    }

    [Fact]
    public void ProgramCsWiring_BothAddHttpClientCallsUseTheseConstants_NotInlineLiterals()
    {
        // Program.cs is a top-level-statements file (Host.CreateApplicationBuilder,
        // AddWindowsService, StateDirectoryBootstrap.EnsureHardened(), ...) with
        // no seam that lets a unit test instantiate just its two AddHttpClient
        // registrations in isolation. Reading the source is the practical
        // alternative to standing up the real Windows-service host in a test
        // run - but unlike a plain "does the file contain the number 30"
        // grep, this checks that Program.cs references the SAME typed
        // constants this file already tests the values of above, so a future
        // edit that inlines a different literal at either call site (the
        // exact class of drift PAT-1257 was raised over) fails loudly here
        // rather than silently reintroducing the too-short-for-160MB bug.
        string programCsPath = FindProgramCs();
        string text = File.ReadAllText(programCsPath);

        int patchedIdx = text.IndexOf("AddHttpClient(\"patched\",", StringComparison.Ordinal);
        int artifactIdx = text.IndexOf("AddHttpClient(\"patched-artifact\",", StringComparison.Ordinal);
        Assert.True(patchedIdx >= 0, "expected an AddHttpClient(\"patched\", ...) registration in Program.cs");
        Assert.True(artifactIdx >= 0, "expected an AddHttpClient(\"patched-artifact\", ...) registration in Program.cs");
        Assert.True(artifactIdx > patchedIdx, "\"patched-artifact\" should be registered after \"patched\"");

        string patchedBlock = text[patchedIdx..artifactIdx];
        string artifactBlock = text[artifactIdx..];

        Assert.Contains("PatchedHttpClientTimeouts.Default", patchedBlock);
        Assert.Contains("PatchedHttpClientTimeouts.Artifact", artifactBlock);
        // The whole point: "patched" must not also pick up the artifact value,
        // and vice versa.
        Assert.DoesNotContain("PatchedHttpClientTimeouts.Artifact", patchedBlock);
    }

    /// <summary>
    /// Locates windows/src/Service/Program.cs relative to this test assembly's
    /// output directory rather than a hardcoded absolute path, so the test
    /// works from any checkout location.
    /// </summary>
    private static string FindProgramCs()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, "src", "Service", "Program.cs");
            if (File.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
        throw new FileNotFoundException("could not locate windows/src/Service/Program.cs from the test output directory");
    }
}
