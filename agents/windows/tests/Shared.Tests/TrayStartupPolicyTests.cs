using Patched.Shared.DeviceClassification;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1959: the Server Core tray suppression. The decision lives in Shared precisely so
/// it can be tested here; the Tray project only builds on Windows, and its call site is
/// one line that calls straight into this predicate.
///
/// The rule is one-sided and these tests hold it that way. Only a definite "Server Core"
/// suppresses the tray. Absence is not evidence of a missing desktop, so a failed or
/// undocumented read must keep starting the tray rather than silently removing the local
/// surface from ordinary workstations.
/// </summary>
public sealed class TrayStartupPolicyTests
{
    [Fact]
    public void ServerCore_DoesNotStartTheTray()
    {
        Assert.False(TrayStartupPolicy.ShouldStart(SourceRead.Present("Server Core")));
        Assert.False(TrayStartupPolicy.ShouldStart(InstallationTypeValue.ServerCore));
    }

    [Theory]
    [InlineData("server core")]
    [InlineData("  Server Core  ")]
    public void ServerCore_IsRecognisedRegardlessOfCaseOrPadding(string raw)
    {
        Assert.False(TrayStartupPolicy.ShouldStart(SourceRead.Present(raw)));
    }

    [Theory]
    [InlineData("Client")]
    [InlineData("Server")]
    public void ClientAndFullServer_StartTheTray(string raw)
    {
        Assert.True(TrayStartupPolicy.ShouldStart(SourceRead.Present(raw)));
    }

    /// <summary>
    /// A read that found nothing or threw keeps the tray running. Suppressing here would
    /// be a behaviour change on every workstation whose registry read happened to fail,
    /// and not being able to read a value is not evidence the machine has no desktop.
    /// </summary>
    [Fact]
    public void AbsentOrFailedRead_StillStartsTheTray()
    {
        Assert.True(TrayStartupPolicy.ShouldStart(SourceRead.Absent));
        Assert.True(TrayStartupPolicy.ShouldStart(SourceRead.Failed));
        Assert.True(TrayStartupPolicy.ShouldStart((string?)null));
    }

    [Theory]
    [InlineData("Nano Server")]
    [InlineData("ServerCore")]
    [InlineData("")]
    public void UndocumentedValue_StillStartsTheTray(string raw)
    {
        Assert.True(TrayStartupPolicy.ShouldStart(SourceRead.Present(raw)));
    }

    [Fact]
    public void NonStringValue_StillStartsTheTray()
    {
        Assert.True(TrayStartupPolicy.ShouldStart(SourceRead.Present(3)));
    }
}
