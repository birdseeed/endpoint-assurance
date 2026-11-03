using System.Diagnostics;
using Patched.Shared.Auth;
using Patched.Shared.Security;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1764 round 2: the file-store purge runs as SYSTEM, so a planted junction or an
/// attacker-owned state directory must make it delete nothing. The trust checks and the
/// delete are fakes here; the last test uses a real NTFS junction on Windows only.
/// </summary>
public sealed class CredentialFileStorePurgeTests
{
    private static readonly string StateDir = Path.Combine("fake", "ProgramData", "Patched");
    private static readonly string CredsDir = Path.Combine(StateDir, "creds");

    private sealed class Fake
    {
        public HashSet<string> Files { get; } = new(CredentialStore.AgentCredentialFileNames, StringComparer.Ordinal);
        public HashSet<string> ExistingDirs { get; } = new(StringComparer.Ordinal) { StateDir, CredsDir };
        public HashSet<string> UntrustedDirs { get; } = new(StringComparer.Ordinal);
        public HashSet<string> ReparsePaths { get; } = new(StringComparer.Ordinal);
        public List<string> Verified { get; } = [];
        public List<string> Deleted { get; } = [];
        public Func<string, CredentialPurgeStep>? DeleteOverride { get; set; }
        public Action<string>? AfterDelete { get; set; }

        public CredentialFileStorePurge Purge() => new(
            StateDir, CredsDir, CredentialStore.AgentCredentialFileNames,
            dir => ExistingDirs.Contains(dir),
            dir =>
            {
                Verified.Add(dir);
                if (UntrustedDirs.Contains(dir))
                    throw new UnauthorizedAccessException("untrusted owner");
            },
            (root, target) =>
            {
                Assert.Equal(StateDir, root);
                return ReparsePaths.Contains(target);
            },
            path =>
            {
                var name = Path.GetFileName(path);
                Assert.Equal(CredsDir, Path.GetDirectoryName(path));
                Deleted.Add(name);
                var step = DeleteOverride?.Invoke(name) ?? CredentialPurgeStep.Removed;
                if (step.Succeeded) Files.Remove(name);
                AfterDelete?.Invoke(name);
                return step;
            });
    }

    [Fact]
    public void TrustedStore_DeletesAllFiveFiles_AfterVerifyingBothDirectories()
    {
        var fake = new Fake();

        var failures = fake.Purge().Run();

        Assert.Empty(failures);
        Assert.Empty(fake.Files);
        Assert.Equal(CredentialStore.AgentCredentialFileNames, fake.Deleted);
        Assert.Equal(new[] { StateDir, CredsDir }, fake.Verified);
    }

    [Fact]
    public void UntrustedStateDir_DeletesNothing_ReportsUntrusted()
    {
        var fake = new Fake();
        fake.UntrustedDirs.Add(StateDir);

        var failures = fake.Purge().Run();

        Assert.Equal(new[] { CredentialFileStorePurge.UntrustedFailure }, failures);
        Assert.Empty(fake.Deleted);
        Assert.Equal(CredentialStore.AgentCredentialFileNames.Count, fake.Files.Count);
    }

    [Fact]
    public void UntrustedCredsDir_DeletesNothing_ReportsUntrusted()
    {
        var fake = new Fake();
        fake.UntrustedDirs.Add(CredsDir);

        var failures = fake.Purge().Run();

        Assert.Equal(new[] { CredentialFileStorePurge.UntrustedFailure }, failures);
        Assert.Empty(fake.Deleted);
    }

    [Fact]
    public void ReparsePointInChainForOneFile_SkipsWholeFileStorePurge()
    {
        var fake = new Fake();
        fake.ReparsePaths.Add(Path.Combine(CredsDir, "suspended"));

        var failures = fake.Purge().Run();

        Assert.Equal(new[] { CredentialFileStorePurge.UntrustedFailure }, failures);
        Assert.Empty(fake.Deleted); // not even the four files ahead of it
        Assert.Equal(CredentialStore.AgentCredentialFileNames.Count, fake.Files.Count);
    }

    [Fact]
    public void CredsDirJunctionReportingAsMissing_IsStillRefused()
    {
        var fake = new Fake();
        fake.ExistingDirs.Remove(CredsDir);
        fake.ReparsePaths.Add(CredsDir);

        var failures = fake.Purge().Run();

        Assert.Equal(new[] { CredentialFileStorePurge.UntrustedFailure }, failures);
        Assert.Empty(fake.Deleted);
    }

    [Fact]
    public void NoStateDirOrNoCredsDir_NothingToDelete_NoFailure()
    {
        var noState = new Fake();
        noState.ExistingDirs.Clear();
        Assert.Empty(noState.Purge().Run());
        Assert.Empty(noState.Deleted);

        var noCreds = new Fake();
        noCreds.ExistingDirs.Remove(CredsDir);
        Assert.Empty(noCreds.Purge().Run());
        Assert.Empty(noCreds.Deleted);
    }

    [Fact]
    public void ReparsePointPlantedMidPurge_StopsRemainingDeletes()
    {
        var fake = new Fake();
        fake.AfterDelete = name =>
        {
            if (name == "bearer-token") fake.ReparsePaths.Add(Path.Combine(CredsDir, "hmac-secret"));
        };

        var failures = fake.Purge().Run();

        Assert.Equal(new[] { CredentialFileStorePurge.UntrustedFailure }, failures);
        Assert.Equal(new[] { "tenant-id", "bearer-token" }, fake.Deleted);
    }

    [Fact]
    public void DeleteFailure_ReportedByName_OtherFilesStillDeleted()
    {
        var fake = new Fake { DeleteOverride = name => name == "hmac-secret" ? throw new IOException("contents") : CredentialPurgeStep.Removed };

        var failures = fake.Purge().Run();

        Assert.Equal(new[] { "credential file hmac-secret: IOException" }, failures);
        Assert.Equal(CredentialStore.AgentCredentialFileNames.Count, fake.Deleted.Count);
    }

    /// <summary>
    /// Windows only: a real NTFS junction (mklink /J, no elevation needed) in place of
    /// creds\ must be caught by PathSafety.HasReparsePointInChain, and the purge must
    /// delete nothing through it. Directory trust is faked because a scratch directory
    /// is owned by the test user, not SYSTEM or Administrators. The scratch root is
    /// PATCHED_JUNCTION_TEST_ROOT when set, else a temp directory. No-ops elsewhere.
    /// </summary>
    [Fact]
    public void RealJunctionAtCredsDir_IsDetected_AndNothingIsDeletedThroughIt()
    {
        if (!OperatingSystem.IsWindows()) return;

        var baseDir = Environment.GetEnvironmentVariable("PATCHED_JUNCTION_TEST_ROOT") ?? Path.GetTempPath();
        var root = Path.Combine(baseDir, $"pat1764-{Guid.NewGuid():N}");
        var state = Path.Combine(root, "Patched");
        var creds = Path.Combine(state, "creds");
        var victim = Path.Combine(root, "victim");
        Directory.CreateDirectory(state);
        Directory.CreateDirectory(victim);
        foreach (var name in CredentialStore.AgentCredentialFileNames)
            File.WriteAllText(Path.Combine(victim, name), "must survive");

        try
        {
            var psi = new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{creds}\" \"{victim}\"")
            { UseShellExecute = false, CreateNoWindow = true };
            using (var p = Process.Start(psi)!) p.WaitForExit();
            Assert.True((File.GetAttributes(creds) & FileAttributes.ReparsePoint) != 0);

            Assert.True(PathSafety.HasReparsePointInChain(state, creds));
            Assert.True(PathSafety.HasReparsePointInChain(state, Path.Combine(creds, "suspended")));

            var purge = new CredentialFileStorePurge(
                state, creds, CredentialStore.AgentCredentialFileNames,
                Directory.Exists, _ => { }, PathSafety.HasReparsePointInChain,
                CredentialFileStorePurge.DeleteFileReporting);

            Assert.Equal(new[] { CredentialFileStorePurge.UntrustedFailure }, purge.Run());
            foreach (var name in CredentialStore.AgentCredentialFileNames)
                Assert.True(File.Exists(Path.Combine(victim, name)), name);

            // Control: the same purge on a plain creds directory really deletes.
            Directory.Delete(creds); // removes the junction only
            Directory.CreateDirectory(creds);
            foreach (var name in CredentialStore.AgentCredentialFileNames)
                File.WriteAllText(Path.Combine(creds, name), "x");
            Assert.Empty(purge.Run());
            Assert.Empty(Directory.GetFiles(creds));
            foreach (var name in CredentialStore.AgentCredentialFileNames)
                Assert.True(File.Exists(Path.Combine(victim, name)), name);
        }
        finally
        {
            if ((File.GetAttributes(creds) & FileAttributes.ReparsePoint) != 0) Directory.Delete(creds);
            Directory.Delete(root, recursive: true);
        }
    }
}
