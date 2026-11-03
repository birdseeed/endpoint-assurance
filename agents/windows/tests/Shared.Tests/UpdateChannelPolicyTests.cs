using Patched.Shared.Config;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Shared.Tests;

public class UpdateChannelPolicyTests
{
    private const string Own = "00000000-0000-0000-0000-000000002005";
    private const string Other = "00000000-0000-0000-0000-000000002006";

    [Theory]
    [InlineData("beta", true, "beta", "device_override")]
    [InlineData("stable", true, "stable", "tenant")]
    [InlineData("preview", true, "stable", "tenant")]
    [InlineData("beta", false, "stable", null)]
    public void OnlyVerifiedOwnBetaOverrideApplies(string channel, bool verified, string expected, string? source)
    {
        var config = AgentConfig.Deserialize(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new { tenant_id = "tenant", config_version = 4, update_channel = "stable", pinned_version = "1.2.3", device_channel_overrides = new Dictionary<string, string> { [Own] = channel } }))! with { UpdateAuthorityVerified = verified };
        var policy = UpdateChannelPolicy.Resolve(config, "tenant", Own);
        Assert.Equal(expected, policy.Channel);
        Assert.Equal(verified, policy.HasAuthority);
        Assert.Equal(source, policy.Source);
        Assert.Equal(verified ? "1.2.3" : null, policy.PinnedVersion);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("42")]
    [InlineData("{\"00000000-0000-0000-0000-000000002006\":\"beta\"}")]
    public void AbsentForeignOrMalformedMapUsesTenant(string map)
    {
        var config = AgentConfig.Deserialize(System.Text.Encoding.UTF8.GetBytes($$"""{"tenant_id":"tenant","config_version":4,"update_channel":"beta","device_channel_overrides":{{map}}} """))! with { UpdateAuthorityVerified = true };
        Assert.Equal(new UpdateChannelPolicy("beta", "tenant", null, 4), UpdateChannelPolicy.Resolve(config, "tenant", Own));
        Assert.Equal(UpdateChannelPolicy.SafeDefault, UpdateChannelPolicy.Resolve(config, "foreign", Own));
    }

    [Theory]
    [InlineData("tenant", "stable", "stable", "tenant")]
    [InlineData("device_override", "beta", "beta", "device_override")]
    [InlineData("device_override", "stable", "stable", null)]
    [InlineData("unknown", "beta", "beta", null)]
    public void BoundDeviceSourceIsSignedNotInferred(string declaredSource, string channel, string expected, string? source)
    {
        var config = new AgentConfig { TenantId = "tenant", DeviceId = Own, UpdateChannel = channel, UpdateChannelSource = declaredSource, UpdateAuthorityVerified = true, PinnedVersion = "1.2.3" };
        config = config with { DeviceChannelOverrides = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>("{\"" + Own + "\":\"beta\"}") };
        var policy = UpdateChannelPolicy.Resolve(config, "tenant", Own);
        Assert.Equal(expected, policy.Channel); Assert.Equal(source, policy.Source);
        Assert.Equal(declaredSource != "device_override" || channel == "beta", policy.HasAuthority);
        Assert.Equal(UpdateChannelPolicy.SafeDefault, UpdateChannelPolicy.Resolve(config, "tenant", Other));
        Assert.Equal(UpdateChannelPolicy.SafeDefault, UpdateChannelPolicy.Resolve(config, "tenant", null));
    }

    [Theory]
    [InlineData("\"update_channel\":\"stable\",\"update_channel\":\"beta\"")]
    [InlineData("\"device_channel_overrides\":{},\"device_channel_overrides\":{\"00000000-0000-0000-0000-000000002005\":\"beta\"}")]
    [InlineData("\"device_id\":null,\"device_id\":\"00000000-0000-0000-0000-000000002005\"")]
    [InlineData("\"update_channel_source\":\"tenant\",\"update_channel_source\":\"device_override\"")]
    [InlineData("\"pinned_version\":\"1.2.3\",\"pinned_version\":\"0.0.1\"")]
    public void DuplicateSignedUpdateAuthorityFailsClosed(string authorityFields)
    {
        var config = AgentConfig.Deserialize(System.Text.Encoding.UTF8.GetBytes(
            "{\"tenant_id\":\"tenant\",\"config_version\":4," + authorityFields + "}"))! with
        { UpdateAuthorityVerified = true };

        Assert.Equal(UpdateChannelPolicy.SafeDefault, UpdateChannelPolicy.Resolve(config, "tenant", Own));
        Assert.False(UpdateChannelPolicy.Resolve(config, "tenant", Own).HasAuthority);
    }

    [Theory]
    [InlineData("{\"tenant_id\":\"tenant\",\"TENANT_ID\":\"tenant\",\"config_version\":4,\"update_channel\":\"beta\"}")]
    [InlineData("{\"tenant_id\":\"tenant\",\"config_version\":4,\"CONFIG_VERSION\":4,\"update_channel\":\"beta\"}")]
    [InlineData("{\"tenant_id\":\"tenant\",\"config_version\":4,\"update_channel\":\"beta\",\"UPDATE_CHANNEL\":\"beta\"}")]
    [InlineData("{\"tenant_id\":\"tenant\",\"config_version\":4,\"update_channel\":\"stable\",\"device_channel_overrides\":{\"00000000-0000-0000-0000-000000002005\":\"beta\"},\"DEVICE_CHANNEL_OVERRIDES\":{\"00000000-0000-0000-0000-000000002005\":\"beta\"}}")]
    [InlineData("{\"tenant_id\":\"tenant\",\"config_version\":4,\"update_channel\":\"beta\",\"device_id\":\"00000000-0000-0000-0000-000000002005\",\"DEVICE_ID\":\"00000000-0000-0000-0000-000000002005\",\"update_channel_source\":\"device_override\"}")]
    [InlineData("{\"tenant_id\":\"tenant\",\"config_version\":4,\"update_channel\":\"beta\",\"device_id\":\"00000000-0000-0000-0000-000000002005\",\"update_channel_source\":\"device_override\",\"UPDATE_CHANNEL_SOURCE\":\"device_override\"}")]
    [InlineData("{\"tenant_id\":\"tenant\",\"config_version\":4,\"update_channel\":\"beta\",\"pinned_version\":\"1.2.3\",\"PINNED_VERSION\":\"1.2.3\"}")]
    public void CaseCollidingSignedUpdateAuthorityFailsClosed(string json)
    {
        var config = AgentConfig.Deserialize(json)! with { UpdateAuthorityVerified = true };

        Assert.Equal(UpdateChannelPolicy.SafeDefault, UpdateChannelPolicy.Resolve(config, "tenant", Own));
    }

    [Theory]
    [InlineData("TENANT_ID", "\"tenant\"")]
    [InlineData("CONFIG_VERSION", "4")]
    [InlineData("UPDATE_CHANNEL", "\"beta\"")]
    [InlineData("DEVICE_CHANNEL_OVERRIDES", "{\"00000000-0000-0000-0000-000000002005\":\"beta\"}")]
    [InlineData("DEVICE_ID", "\"00000000-0000-0000-0000-000000002005\"")]
    [InlineData("UPDATE_CHANNEL_SOURCE", "\"device_override\"")]
    [InlineData("PINNED_VERSION", "\"1.2.3\"")]
    public void NonCanonicalSignedUpdateAuthorityNameFailsClosed(string field, string value)
    {
        string identity = field == "TENANT_ID" ? "" : "\"tenant_id\":\"tenant\",";
        string version = field == "CONFIG_VERSION" ? "" : "\"config_version\":4,";
        var config = AgentConfig.Deserialize(System.Text.Encoding.UTF8.GetBytes(
            "{" + identity + version + "\"" + field + "\":" + value + "}"))! with
        { UpdateAuthorityVerified = true };

        Assert.Equal(UpdateChannelPolicy.SafeDefault, UpdateChannelPolicy.Resolve(config, "tenant", Own));
    }

    [Fact]
    public void CanonicalIdentityIsPersistedBoundAndClearedOnReenrolment()
    {
        var writer = new InMemoryAgentCredentialWriter();
        var creds = CredentialStore.CreateForTests("unused", credentialWriter: writer);
        creds.UpdateFromEnrolment("tenant", "bearer", "hmac", Own);
        Assert.Equal(Own, creds.CanonicalDeviceId);
        Assert.Contains(CredentialStore.TargetDeviceId, CredentialStore.AgentCredentialTargets);
        Assert.Contains("canonical-device-identity", CredentialStore.AgentCredentialFileNames);
        creds.UpdateFromEnrolment("other", "different", "hmac");
        Assert.Null(creds.CanonicalDeviceId);
        Assert.Equal("", writer.Written[CredentialStore.TargetDeviceId]);
    }

    [Fact]
    public void RestartLoadsIdentityButMixedProvisioningCannotReuseIt()
    {
        var writer = new InMemoryAgentCredentialWriter();
        var creds = CredentialStore.CreateForTests("unused", credentialWriter: writer);
        creds.UpdateFromEnrolment("tenant", "bearer", "aGVsbG8td29ybGQtaG1hYy1zZWNyZXQhISE=", Own);
        var sources = new CredentialStore.StartupSources(
            t => writer.Written.TryGetValue(t, out var value) ? value : null,
            _ => null, _ => null, _ => null, (_, _) => { }, () => { },
            () => false, () => { }, "unused", () => null, writer);
        Assert.Equal(Own, CredentialStore.LoadForStartup(null, sources).CanonicalDeviceId);
        writer.WriteCredential(CredentialStore.TargetBearerToken, "different-bearer");
        Assert.Null(CredentialStore.LoadForStartup(null, sources).CanonicalDeviceId);
        writer.WriteCredential(CredentialStore.TargetTenantId, "different-tenant");
        Assert.Null(CredentialStore.LoadForStartup(null, sources).CanonicalDeviceId);
    }
}
