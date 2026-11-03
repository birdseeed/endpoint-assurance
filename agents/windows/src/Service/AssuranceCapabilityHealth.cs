using Patched.Shared.Posture;

namespace Patched.Service;

/// <summary>
/// PAT-1531 assurance-build health observations for legacy channels that are
/// deliberately not compiled into the shipped service.
///
/// This preserves PAT-1066's per-cycle agent_health semantics without restoring
/// an installer or removal runner: device-removal identity is still observable
/// from the signed posture cache. Package execution is absent by design and is
/// not reported as a health fault (PAT-2422). Decommission health remains owned
/// by <see cref="DecommissionRunner"/>.
/// </summary>
internal sealed class AssuranceCapabilityHealth
{
    private readonly ILogger<AssuranceCapabilityHealth> _log;
    private readonly AgentHealthStore                    _agentHealth;
    private readonly PostureReader                       _postureReader;

    public AssuranceCapabilityHealth(
        ILogger<AssuranceCapabilityHealth> log,
        AgentHealthStore                    agentHealth,
        string?                             postureCachePathOverride = null)
    {
        _log           = log;
        _agentHealth   = agentHealth;
        _postureReader = new PostureReader(postureCachePathOverride);
    }

    /// <summary>
    /// Records whether this device has the server-assigned identity needed for a
    /// device-scoped directive. This is observation only: it does not fetch,
    /// acknowledge, execute, or report a removal task.
    /// </summary>
    internal void RecordDeviceRemovalIdentity()
    {
        try
        {
            var deviceId = _postureReader.Read().Posture?.Device.Id;
            if (string.IsNullOrWhiteSpace(deviceId))
            {
                _agentHealth.RecordFailure("directive_skipped", "device_removal", "no_device_id");
                return;
            }

            // Preserve PAT-1066's resolve path: a current usable identity clears
            // a stale no_device_id fault even though this build cannot execute the
            // removed directive type.
            _agentHealth.RecordSuccess("directive_skipped", "device_removal");
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Assurance health: device-removal identity observation failed");
        }
    }

    /// <summary>
    /// Records the non-actuating assurance observation once per cycle.
    ///
    /// PAT-2422: this used to record a package-engine "not shipped" fault on every
    /// cycle as well. The engine is absent from the assurance agent by design, so
    /// that marked every healthy device as degraded and nothing could ever clear
    /// it. The absence is neither a fault nor a success, so nothing is recorded for
    /// it now; the pair is listed in <see cref="RetiredHealthReasons"/>, which removes
    /// what older releases left in the store.
    /// </summary>
    internal void Record() => RecordDeviceRemovalIdentity();
}
