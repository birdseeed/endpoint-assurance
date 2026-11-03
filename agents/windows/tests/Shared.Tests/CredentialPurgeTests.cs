using Patched.Shared.Auth;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1764: the uninstall purge. Every delete goes through an injected seam, so
/// these tests never touch the host's Credential Manager or registry (PAT-1763).
/// </summary>
public sealed class CredentialPurgeTests
{
    private sealed class FakeStores
    {
        public HashSet<string> Credentials { get; } = new(StringComparer.Ordinal)
        {
            CredentialStore.TargetTenantId,
            CredentialStore.TargetBearerToken,
            CredentialStore.TargetHmacSecret,
            CredentialStore.TargetDeviceId,
        };
        // Stand-in for %ProgramData%\Patched\creds: never the host's real directory.
        public HashSet<string> Files { get; } = new(StringComparer.Ordinal)
        {
            "tenant-id", "bearer-token", "hmac-secret", "enrollment-token", "suspended", "canonical-device-identity",
        };
        public bool RegistryKeyPresent { get; set; } = true;
        public List<string> Attempts { get; } = [];
        public Func<string, CredentialPurgeStep>? CredentialOverride { get; set; }
        public Func<string, CredentialPurgeStep>? FileOverride { get; set; }
        public Func<CredentialPurgeStep>? RegistryOverride { get; set; }
        public bool FileStoreTrusted { get; set; } = true;

        public CredentialPurge Purge() => new(
            CredentialStore.AgentCredentialTargets,
            target =>
            {
                Attempts.Add(target);
                if (CredentialOverride is not null) return CredentialOverride(target);
                Credentials.Remove(target);
                return CredentialPurgeStep.Removed;
            },
            new CredentialFileStorePurge(
                "state", Path.Combine("state", "creds"),
                CredentialStore.AgentCredentialFileNames,
                _ => true,
                dir => { if (!FileStoreTrusted) throw new UnauthorizedAccessException(dir); },
                (_, _) => false,
                path =>
                {
                    var file = Path.GetFileName(path);
                    Attempts.Add("file:" + file);
                    if (FileOverride is not null) return FileOverride(file);
                    // A missing file is not an error: delete is idempotent.
                    Files.Remove(file);
                    return CredentialPurgeStep.Removed;
                }),
            () =>
            {
                Attempts.Add("registry");
                if (RegistryOverride is not null) return RegistryOverride();
                RegistryKeyPresent = false;
                return CredentialPurgeStep.Removed;
            });
    }

    private static int TotalSteps =>
        CredentialStore.AgentCredentialTargets.Count + CredentialStore.AgentCredentialFileNames.Count + 1;

    [Fact]
    public void AgentCredentialFileNames_CoverTheFileStoreAndSuspendedMarker()
    {
        Assert.Equal(
            new[] { "tenant-id", "bearer-token", "hmac-secret", "canonical-device-identity", "enrollment-token", "suspended" },
            CredentialStore.AgentCredentialFileNames);
    }

    [Fact]
    public void Run_FileProvisionedDevice_RemovesAllFiveFiles()
    {
        var stores = new FakeStores();

        var result = stores.Purge().Run();

        Assert.True(result.Succeeded);
        Assert.Empty(stores.Files);
        foreach (var file in CredentialStore.AgentCredentialFileNames)
            Assert.Contains("file:" + file, stores.Attempts);
    }

    [Fact]
    public void Run_MissingFiles_AreNotAnError()
    {
        var stores = new FakeStores();
        stores.Files.Clear();
        stores.Files.Add("bearer-token");

        var result = stores.Purge().Run();

        Assert.True(result.Succeeded);
        Assert.Empty(stores.Files);
    }

    [Fact]
    public void Run_FileDeleteFails_ReportedByNameAndErrorOnly_OtherStepsStillRun()
    {
        const string fileContents = "hmac-secret-value-do-not-log";
        var stores = new FakeStores
        {
            FileOverride = file => file == "hmac-secret"
                ? throw new IOException(fileContents)
                : CredentialPurgeStep.Removed,
        };

        var result = stores.Purge().Run();

        Assert.False(result.Succeeded);
        Assert.Equal(new[] { "credential file hmac-secret: IOException" }, result.Failures);
        Assert.DoesNotContain(result.Failures, f => f.Contains(fileContents));
        Assert.Equal(TotalSteps, stores.Attempts.Count);
        Assert.False(stores.RegistryKeyPresent);
    }

    [Fact]
    public void AgentCredentialTargets_CoverEveryAgentCredential()
    {
        Assert.Equal(
            new[]
            {
                "PatchedAgent/TenantId", "PatchedAgent/BearerToken",
                "PatchedAgent/HmacSecret", "PatchedAgent/CanonicalDeviceIdentity",
                "PatchedAgent/EnrollmentToken",
            },
            CredentialStore.AgentCredentialTargets);
    }

    [Fact]
    public void Run_DeletesTheThreeCredentialsAndTheRegistryKey()
    {
        var stores = new FakeStores();

        var result = stores.Purge().Run();

        Assert.True(result.Succeeded);
        Assert.Empty(stores.Credentials);
        Assert.False(stores.RegistryKeyPresent);
        Assert.Contains(CredentialStore.TargetEnrollmentToken, stores.Attempts);
    }

    [Fact]
    public void Run_CredentialDeleteFails_StillAttemptsEveryOtherStep_AndReportsFailure()
    {
        var stores = new FakeStores
        {
            CredentialOverride = target => target == CredentialStore.TargetBearerToken
                ? CredentialPurgeStep.Failed("CredDelete error 5")
                : CredentialPurgeStep.Removed,
        };

        var result = stores.Purge().Run();

        Assert.False(result.Succeeded);
        Assert.Equal(new[] { "credential PatchedAgent/BearerToken: CredDelete error 5" }, result.Failures);
        Assert.Equal(TotalSteps, stores.Attempts.Count);
        Assert.False(stores.RegistryKeyPresent);
    }

    [Fact]
    public void Run_ThrowingStep_IsReportedByTypeOnly_AndDoesNotStopThePurge()
    {
        var stores = new FakeStores
        {
            CredentialOverride = target => target == CredentialStore.TargetTenantId
                ? throw new InvalidOperationException("secret-looking-message")
                : CredentialPurgeStep.Removed,
            RegistryOverride = () => throw new UnauthorizedAccessException("denied"),
        };

        var result = stores.Purge().Run();

        Assert.False(result.Succeeded);
        Assert.Equal(2, result.Failures.Count);
        Assert.Contains("credential PatchedAgent/TenantId: InvalidOperationException", result.Failures);
        Assert.Contains(@"registry key HKLM\SOFTWARE\Patched\Enrollment: UnauthorizedAccessException", result.Failures);
        Assert.DoesNotContain(result.Failures, f => f.Contains("secret-looking-message"));
        Assert.Equal(TotalSteps, stores.Attempts.Count);
    }

    // PAT-1764 round 2: an untrusted file store deletes no files, but Credential
    // Manager and the registry key are not path-based and must still be purged.
    [Fact]
    public void Run_UntrustedFileStore_SkipsFilesOnly_CredentialManagerAndRegistryStillPurged()
    {
        var stores = new FakeStores { FileStoreTrusted = false };

        var result = stores.Purge().Run();

        Assert.False(result.Succeeded);
        Assert.Equal(new[] { CredentialFileStorePurge.UntrustedFailure }, result.Failures);
        Assert.Equal(CredentialStore.AgentCredentialFileNames.Count, stores.Files.Count);
        Assert.DoesNotContain(stores.Attempts, a => a.StartsWith("file:"));
        Assert.Empty(stores.Credentials);
        Assert.False(stores.RegistryKeyPresent);
    }
}
