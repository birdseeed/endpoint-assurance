using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Config;
using Xunit;

namespace Service.Tests;

public class UpdateChannelAuthorityTests
{
    [Fact]
    public void RestartRequiresSignatureExactBytesScopeAndFloor()
    {
        byte[] payload = Encoding.UTF8.GetBytes("{\"tenant_id\":\"tenant\",\"config_version\":4,\"update_channel\":\"beta\"}");
        byte[] proof = [1];
        var floor = AgentConfigRollbackFloor.StoredFloor.Keyed("tenant", 4);
        var accepted = VerifiedUpdateConfigCache.Match(proof, payload, "tenant", floor, _ => payload);
        Assert.NotNull(accepted); Assert.True(accepted!.UpdateAuthorityVerified);
        Assert.Null(VerifiedUpdateConfigCache.Match(proof, payload, "tenant", floor, _ => null));
        Assert.Null(VerifiedUpdateConfigCache.Match(proof, [2], "tenant", floor, _ => payload));
        Assert.Null(VerifiedUpdateConfigCache.Match(proof, payload, "other", floor, _ => payload));
        Assert.Null(VerifiedUpdateConfigCache.Match(proof, payload, "tenant", AgentConfigRollbackFloor.StoredFloor.Keyed("tenant", 5), _ => payload));
        Assert.False(AgentConfig.Deserialize(payload)!.UpdateAuthorityVerified);
    }

    [Fact]
    public void HealthySelectionPersistsWithoutFaultAndIsScoped()
    {
        string directory = Path.Combine(Path.GetTempPath(), "patched-update-channel-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        try
        {
            string file = Path.Combine(directory, "health.json");
            var health = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, file);
            health.RecordUpdateChannel(new("beta", "device_override", "1.2.3", 4), "tenant", "device");
            var restarted = new AgentHealthStore(NullLogger<AgentHealthStore>.Instance, file);
            var section = restarted.BuildPayloadSection("tenant", "device");
            Assert.Empty(section!.Degraded); Assert.Equal("beta", section.UpdateChannel!.EffectiveChannel);
            Assert.Equal("device_override", section.UpdateChannel.Source); Assert.Equal(4, section.UpdateChannel.ConfigVersion);
            health.RecordUpdateChannel(Patched.Shared.Config.UpdateChannelPolicy.SafeDefault, "tenant", "device");
            string json = System.Text.Json.JsonSerializer.Serialize(health.BuildPayloadSection("tenant", "device"),
                new System.Text.Json.JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
            Assert.Contains("\"source\":null", json);
            Assert.Contains("\"config_version\":null", json);
            Assert.Null(restarted.BuildPayloadSection("other", "device")!.UpdateChannel);
            File.WriteAllText(file, "corrupt");
            restarted.RecordUpdateChannel(new("stable", "tenant", null, 5), "tenant", "device");
            Assert.Equal("corrupt", File.ReadAllText(file)); Assert.Null(restarted.BuildPayloadSection("tenant", "device"));
        }
        finally { Directory.Delete(directory, true); }
    }
}
