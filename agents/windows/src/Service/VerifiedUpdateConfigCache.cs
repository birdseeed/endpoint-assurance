using Patched.Shared.Config;

namespace Patched.Service;

internal static class VerifiedUpdateConfigCache
{
    internal static AgentConfig? Match(byte[] envelope, byte[] canonical, string tenantId,
        AgentConfigRollbackFloor.StoredFloor floor, Func<byte[], byte[]?> verify)
    {
        var payload = verify(envelope);
        if (payload is null || !payload.AsSpan().SequenceEqual(canonical)) return null;
        var config = AgentConfig.Deserialize(payload);
        if (config is null || string.IsNullOrEmpty(tenantId) || config.TenantId != tenantId ||
            !AgentConfigRollbackFloor.Evaluate(floor, tenantId, config.ConfigVersion).Accept) return null;
        return config with { UpdateAuthorityVerified = true };
    }
}
