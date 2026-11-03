using Patched.Service;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1764: the MSI uninstall custom action runs "Patched.Service.exe
/// --purge-credentials". That invocation must purge and exit without starting the
/// service host; any other invocation must start the host and never purge.
///
/// PAT-1755: the MSI install custom action runs "Patched.Service.exe
/// --write-enrollment-token &lt;token&gt;", which must provision that token and exit
/// the same way. A missing or malformed token must fail, never silently succeed: the
/// action is Return="check", so a false success would leave an installed agent with no
/// way to enrol and no error anywhere.
/// </summary>
public sealed class ServiceEntryPointTests
{
    [Fact]
    public void PurgeFlag_RunsPurge_ReturnsItsExitCode_NeverStartsHost()
    {
        var hostStarted = false;
        var purged = 0;

        var exit = ServiceEntryPoint.Run(
            new[] { "--purge-credentials" },
            () => { purged++; return 7; },
            _ => throw new InvalidOperationException("an uninstall must never provision a token"),
            () => { hostStarted = true; return 0; });

        Assert.Equal(7, exit);
        Assert.Equal(1, purged);
        Assert.False(hostStarted);
    }

    [Fact]
    public void PurgeFlagAmongOtherArgs_StillNeverStartsHost()
    {
        var hostStarted = false;

        ServiceEntryPoint.Run(
            new[] { "--contentRoot", "C:\\x", "--purge-credentials" },
            () => 0,
            _ => 0,
            () => { hostStarted = true; return 0; });

        Assert.False(hostStarted);
    }

    [Theory]
    [InlineData("")]
    [InlineData("--PURGE-CREDENTIALS")]
    [InlineData("--purge-credentials=1")]
    [InlineData("purge-credentials")]
    public void NoExactPurgeFlag_StartsHost_NeverPurges(string commandLine)
    {
        var args = commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var purged = false;
        var hostStarted = false;

        ServiceEntryPoint.Run(
            args,
            () => { purged = true; return 0; },
            _ => throw new InvalidOperationException("no provisioning flag was passed"),
            () => { hostStarted = true; return 0; });

        Assert.True(hostStarted);
        Assert.False(purged);
    }

    [Fact]
    public void Command_AllStepsSucceed_ExitsZero_ReportsInformation()
    {
        var reports = new List<(string Message, bool IsError)>();
        var purge = new CredentialPurge(
            CredentialStore.AgentCredentialTargets, _ => CredentialPurgeStep.Removed,
            EmptyFileStore(),
            () => CredentialPurgeStep.Removed);

        var exit = CredentialPurgeCommand.Run(purge, (m, e) => reports.Add((m, e)));

        Assert.Equal(CredentialPurgeCommand.ExitSucceeded, exit);
        var report = Assert.Single(reports);
        Assert.False(report.IsError);
    }

    [Fact]
    public void Command_StepFails_ExitsNonZero_ReportsTargetAndError()
    {
        var reports = new List<(string Message, bool IsError)>();
        var purge = new CredentialPurge(
            CredentialStore.AgentCredentialTargets,
            t => t == CredentialStore.TargetHmacSecret ? CredentialPurgeStep.Failed("CredDelete error 5") : CredentialPurgeStep.Removed,
            EmptyFileStore(),
            () => CredentialPurgeStep.Removed);

        var exit = CredentialPurgeCommand.Run(purge, (m, e) => reports.Add((m, e)));

        Assert.Equal(CredentialPurgeCommand.ExitFailed, exit);
        var report = Assert.Single(reports);
        Assert.True(report.IsError);
        Assert.Contains("PatchedAgent/HmacSecret: CredDelete error 5", report.Message);
    }

    [Fact]
    public void Command_ReporterThrows_ExitCodeUnchanged()
    {
        var purge = new CredentialPurge(
            CredentialStore.AgentCredentialTargets, _ => CredentialPurgeStep.Removed,
            EmptyFileStore(),
            () => CredentialPurgeStep.Removed);

        var exit = CredentialPurgeCommand.Run(purge, (_, _) => throw new InvalidOperationException());

        Assert.Equal(CredentialPurgeCommand.ExitSucceeded, exit);
    }

    [Fact]
    public void PurgeFlag_MatchesTheInstallerCustomAction()
    {
        // The installer guard (windows/installer/test_hidden_credentials.py) reads this
        // constant from source and requires it as the custom action's ExeCommand.
        Assert.Equal("--purge-credentials", ServiceEntryPoint.PurgeCredentialsFlag);
    }

    // -----------------------------------------------------------------------
    // PAT-1755: --write-enrollment-token
    // -----------------------------------------------------------------------

    [Fact]
    public void WriteEnrollmentTokenFlag_MatchesTheInstallerCustomAction()
    {
        Assert.Equal("--write-enrollment-token", ServiceEntryPoint.WriteEnrollmentTokenFlag);
    }

    [Fact]
    public void ProvisionFlag_PassesTheNextArgument_ReturnsItsExitCode_NeverStartsHost()
    {
        var hostStarted = false;
        string? received = null;

        var exit = ServiceEntryPoint.Run(
            new[] { "--write-enrollment-token", "tok_live_abc" },
            () => throw new InvalidOperationException("an install must never purge"),
            token => { received = token; return 5; },
            () => { hostStarted = true; return 0; });

        Assert.Equal(5, exit);
        Assert.Equal("tok_live_abc", received);
        Assert.False(hostStarted);
    }

    [Fact]
    public void ProvisionFlagAmongOtherArgs_TakesTheArgumentThatFollowsIt()
    {
        string? received = "unset";

        ServiceEntryPoint.Run(
            new[] { "--contentRoot", "C:\\x", "--write-enrollment-token", "tok_live_def" },
            () => 0,
            token => { received = token; return 0; },
            () => 0);

        Assert.Equal("tok_live_def", received);
    }

    [Fact]
    public void ProvisionFlagWithNoValue_PassesNull_SoTheCommandFailsRatherThanNoOps()
    {
        string? received = "unset";

        ServiceEntryPoint.Run(
            new[] { "--write-enrollment-token" },
            () => 0,
            token => { received = token; return 0; },
            () => 0);

        Assert.Null(received);
    }

    [Theory]
    [InlineData("--WRITE-ENROLLMENT-TOKEN tok")]
    [InlineData("--write-enrollment-token=tok")]
    [InlineData("write-enrollment-token tok")]
    public void NoExactProvisionFlag_StartsHost_NeverProvisions(string commandLine)
    {
        var args = commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var provisioned = false;
        var hostStarted = false;

        ServiceEntryPoint.Run(
            args, () => 0,
            _ => { provisioned = true; return 0; },
            () => { hostStarted = true; return 0; });

        Assert.True(hostStarted);
        Assert.False(provisioned);
    }

    [Fact]
    public void BothFlags_PurgeWins_SoAnUninstallIsNeverDivertedIntoProvisioning()
    {
        var provisioned = false;
        var purged = false;

        ServiceEntryPoint.Run(
            new[] { "--write-enrollment-token", "tok", "--purge-credentials" },
            () => { purged = true; return 0; },
            _ => { provisioned = true; return 0; },
            () => 0);

        Assert.True(purged);
        Assert.False(provisioned);
    }

    [Fact]
    public void ProvisionCommand_Succeeds_ExitsZero_ReportsInformation_WithoutTheToken()
    {
        var reports = new List<(string Message, bool IsError)>();
        var written = new List<(string Path, string Contents)>();

        var exit = EnrollmentTokenProvisionCommand.Run(
            Provisioner(written), "tok_live_ghi", (m, e) => reports.Add((m, e)));

        Assert.Equal(EnrollmentTokenProvisionCommand.ExitSucceeded, exit);
        var report = Assert.Single(reports);
        Assert.False(report.IsError);
        Assert.DoesNotContain("tok_live_ghi", report.Message);
        var file = Assert.Single(written);
        Assert.Equal("tok_live_ghi\n", file.Contents);
    }

    [Fact]
    public void ProvisionCommand_NoToken_ExitsNonZero_WritesNothing()
    {
        var reports = new List<(string Message, bool IsError)>();
        var written = new List<(string Path, string Contents)>();

        var exit = EnrollmentTokenProvisionCommand.Run(
            Provisioner(written), null, (m, e) => reports.Add((m, e)));

        Assert.Equal(EnrollmentTokenProvisionCommand.ExitFailed, exit);
        Assert.Empty(written);
        var report = Assert.Single(reports);
        Assert.True(report.IsError);
        Assert.Contains(EnrollmentTokenProvisioner.NoTokenError, report.Message);
    }

    [Fact]
    public void ProvisionCommand_WriteFails_ExitsNonZero_ReportsTheReasonWithoutTheToken()
    {
        var reports = new List<(string Message, bool IsError)>();
        var provisioner = new EnrollmentTokenProvisioner(
            "state", Path.Combine("state", "creds"), (_, _) => { }, (_, _) => false,
            (_, _) => EnrollmentTokenProvisionResult.Failed("ACCESS_DENIED"));

        var exit = EnrollmentTokenProvisionCommand.Run(provisioner, "tok_live_jkl", (m, e) => reports.Add((m, e)));

        Assert.Equal(EnrollmentTokenProvisionCommand.ExitFailed, exit);
        var report = Assert.Single(reports);
        Assert.True(report.IsError);
        Assert.Contains("ACCESS_DENIED", report.Message);
        Assert.DoesNotContain("tok_live_jkl", report.Message);
    }

    [Fact]
    public void ProvisionCommand_ProvisionerThrows_ExitsNonZero_NamesTheExceptionTypeOnly()
    {
        var reports = new List<(string Message, bool IsError)>();
        var provisioner = new EnrollmentTokenProvisioner(
            "state", Path.Combine("state", "creds"),
            (_, _) => { }, (_, _) => false,
            (_, _) => throw new OutOfMemoryException("tok_live_mno"));

        var exit = EnrollmentTokenProvisionCommand.Run(provisioner, "tok_live_mno", (m, e) => reports.Add((m, e)));

        Assert.Equal(EnrollmentTokenProvisionCommand.ExitFailed, exit);
        var report = Assert.Single(reports);
        Assert.Contains("OutOfMemoryException", report.Message);
        Assert.DoesNotContain("tok_live_mno", report.Message);
    }

    [Fact]
    public void ProvisionCommand_ReporterThrows_ExitCodeUnchanged()
    {
        var exit = EnrollmentTokenProvisionCommand.Run(
            Provisioner(new List<(string, string)>()), "tok_live_pqr",
            (_, _) => throw new InvalidOperationException());

        Assert.Equal(EnrollmentTokenProvisionCommand.ExitSucceeded, exit);
    }

    private static EnrollmentTokenProvisioner Provisioner(List<(string Path, string Contents)> written) => new(
        "state", Path.Combine("state", "creds"),
        (_, _) => { },
        (_, _) => false,
        (path, contents) =>
        {
            written.Add((path, contents));
            return EnrollmentTokenProvisionResult.Provisioned;
        });

    private static CredentialFileStorePurge EmptyFileStore() => new(
        "state", Path.Combine("state", "creds"), CredentialStore.AgentCredentialFileNames,
        _ => false, _ => { }, (_, _) => false, _ => CredentialPurgeStep.Removed);
}
