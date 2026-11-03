using Microsoft.Extensions.Logging;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1764: an enrolment token written onto an already-enrolled device is deleted
/// and a warning explains why, without re-enrolling and without logging the value.
/// The registry is reached only through seams.
/// </summary>
public sealed class IgnoredEnrollmentTokenTests
{
    private const string TokenValue = "tok_live_4f9a1c2b7e";

    private sealed class CapturingLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception) + (exception?.ToString() ?? "")));
    }

    [Fact]
    public void TokenPresent_DeletesValue_LogsWarningWithoutTheValue()
    {
        string? registryValue = TokenValue;
        var log = new CapturingLogger();

        var discarded = IgnoredEnrollmentToken.Discard(
            () => registryValue is not null, () => registryValue = null, log);

        Assert.True(discarded);
        Assert.Null(registryValue);
        var entry = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("already holds agent credentials", entry.Message);
        // Credentials may be kept on purpose by a decommission without purge, so the
        // advice must cover that case, not only a leftover install (PAT-1764 review).
        Assert.Contains("decommission without purge", entry.Message);
        Assert.Contains("uninstall normally or decommission with purge, then install with a fresh enrollment token", entry.Message);
        Assert.DoesNotContain("Uninstall the agent first", entry.Message);
        Assert.DoesNotContain(TokenValue, entry.Message);
    }

    [Fact]
    public void NoToken_DeletesNothing_LogsNothing()
    {
        var deleted = false;
        var log = new CapturingLogger();

        var discarded = IgnoredEnrollmentToken.Discard(() => false, () => deleted = true, log);

        Assert.False(discarded);
        Assert.False(deleted);
        Assert.Empty(log.Entries);
    }

    [Fact]
    public void DeleteFails_LogsWarningWithErrorTypeOnly_NeverTheValueOrExceptionText()
    {
        var log = new CapturingLogger();

        var discarded = IgnoredEnrollmentToken.Discard(
            () => true, () => throw new UnauthorizedAccessException($"denied {TokenValue}"), log);

        Assert.False(discarded);
        var entry = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("UnauthorizedAccessException", entry.Message);
        Assert.Contains("decommission with purge", entry.Message);
        Assert.DoesNotContain(TokenValue, entry.Message);
    }

    [Fact]
    public void PresenceCheckFails_DeletesNothing_LogsWarningWithoutTheValue()
    {
        var deleted = false;
        var log = new CapturingLogger();

        var discarded = IgnoredEnrollmentToken.Discard(
            () => throw new IOException(TokenValue), () => deleted = true, log);

        Assert.False(discarded);
        Assert.False(deleted);
        var entry = Assert.Single(log.Entries);
        Assert.DoesNotContain(TokenValue, entry.Message);
    }

    [Fact]
    public void NotProvisionedMessage_SaysTheAgentKeepsRunning_TellsOperatorHowToProvision_NamesNoSecret()
    {
        // PAT-1766: replaces PAT-1764's AgentIdentityMissingException message.
        var message = AgentProvisioning.NotProvisionedMessage(TimeSpan.FromMinutes(5));

        Assert.Contains("no Patched agent identity", message);
        Assert.Contains("is running but collects and sends nothing", message);
        Assert.Contains("every 5 minutes", message);
        Assert.Contains(@"%ProgramData%\Patched\creds\enrollment-token", message);
        Assert.Contains("fresh enrollment token", message);
        Assert.DoesNotContain("PATCHED_BEARER_TOKEN", message);
        Assert.DoesNotContain("\u2014", message);
        Assert.DoesNotContain("\u2014", AgentProvisioning.ProvisionedMessage);
    }

    [Theory]
    [InlineData(300, "every 5 minutes")]
    [InlineData(60, "every minute")]
    [InlineData(0.05, "every 0.05 seconds")]
    public void NotProvisionedMessage_DescribesTheInterval(double seconds, string expected) =>
        Assert.Contains(expected, AgentProvisioning.NotProvisionedMessage(TimeSpan.FromSeconds(seconds)));
}
