using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Config;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1316: unit tests for the directive_skipped AgentHealthStore signal
/// BrowserExtensionRemover.Remove now records around NormalizeDirectives'
/// unknown-scope out param — mirrors DeviceRemovalRunnerTests' AgentHealthStore
/// coverage for the same (RecordFailure/RecordSuccess) shape (PAT-1066/PAT-1273).
///
/// WindowsUserProfiles.Enumerate (the per-profile glue this class calls after the
/// health check) opens HKLM\...\ProfileList via Microsoft.Win32.Registry, which
/// throws on non-Windows and is caught internally, yielding zero profiles — so
/// Remove() runs to completion safely on macOS/Linux CI in every case exercised
/// here (it never needs a real Windows profile to reach or clear the health
/// signal, only to differ in whether the config contained the two lines are
/// what changed).
/// </summary>
public sealed class BrowserExtensionRemoverTests
{
    private static AgentHealthStore MakeStore(string tmpDir) =>
        new(NullLogger<AgentHealthStore>.Instance, Path.Combine(tmpDir, "agent-health.json"));

    private static BrowserExtensionRemover MakeRemover(AgentHealthStore agentHealth) =>
        new(NullLogger<BrowserExtensionRemover>.Instance, agentHealth);

    private static AppControlPolicy PolicyWith(params ExtensionRemovalEntry[] entries) =>
        new() { Enabled = true, ExtensionRemovals = entries.ToList() };

    [Fact]
    public void Remove_UnknownScope_RecordsDirectiveSkippedFailure()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var agentHealth = MakeStore(tmpDir);
            var remover = MakeRemover(agentHealth);
            var policy = PolicyWith(new ExtensionRemovalEntry
            {
                Browser = "chrome", ExtensionId = "aaaa", Scope = "some_future_scope",
            });

            var events = remover.Remove(policy);

            Assert.Empty(events);
            var section = agentHealth.BuildPayloadSection();
            Assert.NotNull(section);
            var entry = Assert.Single(section!.Degraded);
            Assert.Equal("directive_skipped",   entry.Kind);
            Assert.Equal("extension_removal",   entry.Subject);
            Assert.Contains("some_future_scope", entry.Reason);
            Assert.Equal(1, entry.Count);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void Remove_AllKnownScopes_RecordsDirectiveSkippedSuccess_ClearingPriorFailure()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var agentHealth = MakeStore(tmpDir);
            var remover = MakeRemover(agentHealth);

            // First cycle: an unknown scope records a fault.
            remover.Remove(PolicyWith(new ExtensionRemovalEntry
            {
                Browser = "chrome", ExtensionId = "aaaa", Scope = "some_future_scope",
            }));
            Assert.Single(agentHealth.BuildPayloadSection()!.Degraded);

            // Second cycle: every directive uses a scope this build recognises —
            // the fault must clear, exactly like DeviceRemovalRunner's
            // directive_skipped/device_removal recovering once a device id
            // becomes available again.
            var events = remover.Remove(PolicyWith(new ExtensionRemovalEntry
            {
                Browser = "chrome", ExtensionId = "aaaa", Scope = "all_devices",
            }));

            Assert.Empty(events); // no real Windows profile on this CI host to act on
            Assert.Empty(agentHealth.BuildPayloadSection()!.Degraded);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void Remove_UnsafePathSegment_RecordsDirectiveSkippedFailure()
    {
        // PAT-1329: an ExtensionId that isn't a single plain path component
        // must be just as visible a drop as the PAT-1316 unknown-scope case
        // above — same directive_skipped kind/subject, distinguished only by
        // the invalid_segment: reason prefix.
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var agentHealth = MakeStore(tmpDir);
            var remover = MakeRemover(agentHealth);
            var policy = PolicyWith(new ExtensionRemovalEntry
            {
                Browser = "chrome", ExtensionId = @"C:\Windows\System32", Scope = "all_devices",
            });

            var events = remover.Remove(policy);

            Assert.Empty(events);
            var section = agentHealth.BuildPayloadSection();
            Assert.NotNull(section);
            var entry = Assert.Single(section!.Degraded);
            Assert.Equal("directive_skipped", entry.Kind);
            Assert.Equal("extension_removal", entry.Subject);
            Assert.Contains("invalid_segment:", entry.Reason);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void Remove_NoExtensionRemovalsConfigured_RecordsNothing()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var agentHealth = MakeStore(tmpDir);
            var remover = MakeRemover(agentHealth);

            // Empty ExtensionRemovals: nothing to evaluate, so this must be silent —
            // a tenant that never uses this feature should not accumulate a
            // permanent ever_succeeded=true ledger entry for a capability it has
            // never actually exercised.
            var events = remover.Remove(PolicyWith());

            Assert.Empty(events);
            var section = agentHealth.BuildPayloadSection();
            Assert.NotNull(section);
            Assert.Empty(section!.Degraded);
            Assert.Null(agentHealth.GetLastSuccess("directive_skipped", "extension_removal"));
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }
}
