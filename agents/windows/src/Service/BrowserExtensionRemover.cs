using System.Runtime.Versioning;
using Patched.Shared.BrowserExtensions;
using Patched.Shared.Config;
using Patched.Shared.Contract;

namespace Patched.Service;

/// <summary>
/// PAT-829: Browser Extension Control — profile-aware, audited extension removal
/// (Windows). Consumes app_control.extension_removals from the signed agent-config
/// and destructively removes each listed extension from the user profiles its scope
/// selects: for Chrome/Edge it deletes the profile's Extensions\&lt;id&gt; directory and
/// prunes the Secure Preferences / Preferences settings entry; for Firefox it drops
/// the addon from extensions.json and deletes the XPI.
///
/// This is deliberately NOT the UninstallPlanner/RemovalRunner path — extensions
/// have no Add/Remove-Programs registry entry. The decision + file logic is the
/// platform-neutral <see cref="ExtensionRemovalLogic"/> in Shared (unit-tested on
/// any OS); this class is the thin Windows glue: enumerate every on-disk user
/// profile (<see cref="WindowsUserProfiles"/>), run the in-scope directives against
/// each, and return one extension_removed enforcement_audit event per artifact
/// actually removed for POST /v1/inventory/enforcement-audit.
///
/// Scope semantics are realised by the enumeration + the logic's per-user filter:
/// one_profile / one_user match a specific user (and profile); all_profiles and
/// all_devices act across every user + profile on this device (all_devices is the
/// server-fanned form — locally identical, audited distinctly).
///
/// Fail-safe: never throws into the run cycle. Dry-run ($env:PATCHED_DRY_RUN='1')
/// computes + emits events but deletes nothing.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class BrowserExtensionRemover
{
    private readonly ILogger<BrowserExtensionRemover> _log;
    private readonly AgentHealthStore                  _agentHealth;

    public BrowserExtensionRemover(ILogger<BrowserExtensionRemover> log, AgentHealthStore agentHealth)
    {
        _log         = log;
        _agentHealth = agentHealth;
    }

    /// <summary>Runs the removal pass. Never throws.</summary>
    /// <returns>One event per (browser, user, profile, extension) artifact actually removed.</returns>
    public IReadOnlyList<EnforcementAuditEvent> Remove(AppControlPolicy policy)
    {
        var events = new List<EnforcementAuditEvent>();
        try
        {
            var directives = ExtensionRemovalLogic.NormalizeDirectives(
                policy, out var unknownScopes, out var invalidSegments);

            // PAT-1316: a scope this agent build does not recognise (e.g. the
            // server started emitting one_observation before this build shipped
            // it, or a still-newer scope after) is silently dropped by
            // NormalizeDirectives — correctly fail-safe (never widen a
            // destructive removal to a scope it didn't understand), but a
            // dropped directive must not be indistinguishable from one the
            // server never sent. CLAUDE.md's standing rule: anything able to
            // silently disable itself must report degraded, not stay silent.
            // Mirrors DeviceRemovalRunner.RecordDeviceIdentityHealth's
            // directive_skipped signal (PAT-1066/PAT-1273) exactly — same kind,
            // same RecordFailure/RecordSuccess shape — and the macOS remover's
            // adjacent `ext_removal: REJECT unrecognised scope` stderr line.
            //
            // PAT-1329: an ExtensionId/Profile that isn't a single plain path
            // component (invalidSegments) is the same class of "silently
            // dropped, must not look like it was never sent" event — logged
            // and recorded the same way, distinguished only by reason prefix.
            if (unknownScopes.Count > 0 || invalidSegments.Count > 0)
            {
                foreach (var scope in unknownScopes.Distinct(StringComparer.Ordinal))
                    _log.LogWarning(
                        "ext_removal: REJECT unrecognised scope (agent build does not support it): '{Scope}'",
                        scope);
                foreach (var segment in invalidSegments.Distinct(StringComparer.Ordinal))
                    _log.LogWarning(
                        "ext_removal: REJECT unsafe path segment (ExtensionId/Profile must be a single path component): '{Segment}'",
                        segment);

                var reasons = new List<string>();
                if (unknownScopes.Count > 0)
                    reasons.Add("unknown_scope:" + string.Join(",", unknownScopes.Distinct(StringComparer.Ordinal)));
                if (invalidSegments.Count > 0)
                    reasons.Add("invalid_segment:" + string.Join(",", invalidSegments.Distinct(StringComparer.Ordinal)));
                _agentHealth.RecordFailure("directive_skipped", "extension_removal", string.Join(";", reasons));
            }
            else if (policy is { Enabled: true, ExtensionRemovals.Count: > 0 })
            {
                // Every directive this cycle used a scope this build understands —
                // only recorded when there was something to evaluate, same as
                // the other content-driven health signals in this class (not a
                // channel-identity check like device_removal's, which has no
                // config-content precondition).
                _agentHealth.RecordSuccess("directive_skipped", "extension_removal");
            }

            if (directives.Count == 0) return events;

            var dryRun = string.Equals(
                Environment.GetEnvironmentVariable("PATCHED_DRY_RUN"), "1", StringComparison.Ordinal);
            var deviceId = Environment.MachineName;
            var occurredAt = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

            foreach (var profile in WindowsUserProfiles.Enumerate(_log))
            {
                var userEvents = ExtensionRemovalLogic.RemoveForUser(
                    profile.ProfilePath, profile.UserAccount, directives, deviceId, dryRun, occurredAt);
                events.AddRange(userEvents);
            }

            if (events.Count > 0)
                _log.LogInformation(
                    "ext_removal: {Verb} {Count} extension install(s) across in-scope profiles",
                    dryRun ? "would remove" : "removed", events.Count);
            else
                _log.LogDebug("ext_removal: nothing to remove");

            return events;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "ext_removal: unexpected error — skipping removal");
            return events;
        }
    }
}
