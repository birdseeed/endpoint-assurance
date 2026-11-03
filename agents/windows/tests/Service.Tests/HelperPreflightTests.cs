using System.Security.AccessControl;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Shared.InstallationEvidence;
using Xunit;

namespace Patched.Service.Tests;

// PAT-2116: a refused evidence-helper preflight is reported as helper_preflight_refused (not
// helper_failed), logged once as a WARN naming the reason and the offending principal, and
// recorded in agent-health as helper_preflight/<subject>/<reason>.
public sealed class HelperPreflightTests
{
    private const string Users = "S-1-5-32-545";

    [Fact]
    public void AHelperOutsideProgramFilesIsRefusedWithAReasonAndNoLock()
    {
        var start = InstallationEvidenceProbe.PrepareTrustedHelper(AppSignatureCoverageProbe.Command,
            "/not/program/files/Patched.Service.exe", out var locked, out var refusal);
        Assert.Null(start);
        Assert.Null(locked);
        Assert.Equal("location_untrusted", refusal!.Reason);
        Assert.Contains("/not/program/files/Patched.Service.exe", refusal.Detail);
    }

    [Fact]
    public void RefusalsKeepTheCheckThatRefusedAndItsPrincipal()
    {
        var acl = InstallationEvidenceProbe.RefusalFor(new WindowsInstallationEvidence.AclRefusalException("x",
            new("install_dir_acl", Users, FileSystemRights.CreateFiles)));
        Assert.Equal(new("install_dir_acl", $"principal={Users} rights=0x00000002"), acl);
        Assert.Equal("install_path_unavailable",
            InstallationEvidenceProbe.RefusalFor(new IOException("file_unavailable_or_reparse")).Reason);
        // Anything unexpected is still a refusal, with no message (it may carry a path).
        Assert.Equal(new("preflight_error", "UnauthorizedAccessException"),
            InstallationEvidenceProbe.RefusalFor(new UnauthorizedAccessException(@"C:\secret")));
    }

    // The real parent path on a host that is not the installed service: the session ends
    // PreflightRefused, the observer hears why, and every row says helper_preflight_refused.
    [Fact]
    public async Task ARefusedCoverageSessionIsPreflightRefusedNotHelperFailed()
    {
        var seen = new List<InstallationEvidenceProbe.HelperPreflightRefusal?>();
        var request = new CoverageRequest([new(0, "App", false)], [], [], []);
        var session = await AppSignatureCoverageProbe.RunSessionAsync(request, TimeSpan.FromSeconds(5), seen.Add);
        Assert.Equal(CoverageSessionEnd.PreflightRefused, session.End);
        Assert.Equal("location_untrusted", Assert.Single(seen)!.Reason);

        var app = new Patched.Shared.Contract.InventoryApp { Name = "App", Version = "1", Identifier = "App" };
        var result = await AppSignatureCoverage.CollectAsync([app], new SignatureVerdictCache(),
            (r, b) => AppSignatureCoverageProbe.RunSessionAsync(r, b));
        Assert.Equal(["helper_preflight_refused"], result.Apps[0].InstallationEvidence!.Errors);
        Assert.Equal("unavailable", result.Summary.CollectionStatus);
        Assert.Equal(["helper_preflight_refused"], result.Summary.Errors);
    }

    [Fact]
    public void ARefusalLogsOneWarnAndRecordsAgentHealthUntilAPreflightPasses()
    {
        var dir = Directory.CreateTempSubdirectory("patched-preflight-").FullName;
        try
        {
            var health = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, Path.Combine(dir, "agent-health.json"));
            var log = new ListLogger();
            var refusal = new InstallationEvidenceProbe.HelperPreflightRefusal("install_dir_acl",
                $"principal={Users} rights=0x00000002");

            var reporter = new HelperPreflightReporter(log, health, HelperPreflightReporter.AppSignaturesSubject);
            reporter.Observe(refusal);
            reporter.Observe(refusal); // a retried helper in the same scan logs once

            var line = Assert.Single(log.Entries);
            Assert.Equal(LogLevel.Warning, line.Level);
            Assert.Contains("app_signatures", line.Message);
            Assert.Contains("install_dir_acl", line.Message);
            Assert.Contains($"principal={Users} rights=0x00000002", line.Message);
            Assert.Contains("helper_preflight_refused", line.Message);

            var degraded = Assert.Single(health.BuildPayloadSection()!.Degraded);
            Assert.Equal(("helper_preflight", "app_signatures", "install_dir_acl"),
                (degraded.Kind, degraded.Subject, degraded.Reason));
            // The principal stays in the local log, never on the wire.
            Assert.DoesNotContain(Users, JsonSerializer.Serialize(degraded));

            new HelperPreflightReporter(log, health, HelperPreflightReporter.AppSignaturesSubject).Observe(null);
            Assert.Empty(health.BuildPayloadSection()!.Degraded);
            Assert.Single(log.Entries); // passing is not logged
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    private sealed class ListLogger : ILogger
    {
        internal List<(LogLevel Level, string Message)> Entries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Entries.Add((logLevel, formatter(state, exception)));
    }
}
