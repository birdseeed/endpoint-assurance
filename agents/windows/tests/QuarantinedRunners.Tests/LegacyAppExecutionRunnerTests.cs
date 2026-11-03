using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Config;
using Xunit;

namespace Patched.QuarantinedRunners.Tests;

/// <summary>
/// These tests deliberately compile the excluded runner source in a separate,
/// non-shipping test assembly. They prove the containment check is before any
/// queue access, while Service.csproj remains assurance-only.
/// </summary>
public sealed class LegacyAppExecutionRunnerTests
{
    private sealed class CountingInstallFetcher : PendingInstallsFetcher
    {
        public int Calls { get; private set; }

        public CountingInstallFetcher()
            : base(NullLogger<PendingInstallsFetcher>.Instance, null!, null!) { }

        public override Task<IReadOnlyList<Patched.Shared.Installation.PendingInstall>> FetchAsync(CancellationToken ct)
        {
            Calls++;
            return Task.FromResult<IReadOnlyList<Patched.Shared.Installation.PendingInstall>>([]);
        }
    }

    private sealed class CountingHttpClientFactory : IHttpClientFactory
    {
        public int Calls { get; private set; }
        public HttpClient CreateClient(string name)
        {
            Calls++;
            return new HttpClient();
        }
    }

    // This is a deserialisation/mechanical-containment fixture, not an
    // authenticated config-cache fixture. The production Windows Service does not
    // compile these runners, so this target must not imply it exercises runtime
    // freshness, hash or suspension enforcement.
    private static AgentConfig ExplicitExactTrueConfig() =>
        AgentConfig.Deserialize("{\"legacy_app_execution_enabled\":true}")!;

    [Fact]
    public async Task InstallRunner_DeniesBeforePendingInstallQueue()
    {
        var fetcher = new CountingInstallFetcher();
        var runner = new InstallRunner(NullLogger<InstallRunner>.Instance, fetcher,
            null!, null!, null!, null!, null!, null!);

        await runner.RunAsync(CancellationToken.None, AgentConfig.Defaults);

        Assert.Equal(0, fetcher.Calls);
    }

    [Fact]
    public async Task InstallRunner_ExactTrueReachesItsExistingQueueGate()
    {
        var fetcher = new CountingInstallFetcher();
        var runner = new InstallRunner(NullLogger<InstallRunner>.Instance, fetcher,
            null!, null!, null!, null!, null!, null!);

        await runner.RunAsync(CancellationToken.None, ExplicitExactTrueConfig());

        Assert.Equal(1, fetcher.Calls);
    }

    [Fact]
    public async Task RemovalRunner_DeniesBeforePendingRemovalQueue()
    {
        var factory = new CountingHttpClientFactory();
        var fetcher = new PendingRemovalsFetcher(NullLogger<PendingRemovalsFetcher>.Instance, factory, null!);
        var runner = new RemovalRunner(NullLogger<RemovalRunner>.Instance, fetcher,
            null!, null!, null!, null!, null!);

        await runner.RunAsync(null, CancellationToken.None, AgentConfig.Defaults);

        Assert.Equal(0, factory.Calls);
    }

    [Fact]
    public async Task DeviceRemovalRunner_DeniesBeforeDeviceTaskQueue()
    {
        var factory = new CountingHttpClientFactory();
        var client = new DeviceRemovalTasksClient(NullLogger<DeviceRemovalTasksClient>.Instance, factory, null!);
        var runner = new DeviceRemovalRunner(NullLogger<DeviceRemovalRunner>.Instance, client,
            null!, null!, null!);

        await runner.RunAsync(CancellationToken.None, AgentConfig.Defaults);

        Assert.Equal(0, factory.Calls);
    }

    [Fact]
    public void RunnerSignatures_RequireAnExplicitConfigArgument()
    {
        Assert.False(typeof(InstallRunner).GetMethod(nameof(InstallRunner.RunAsync))!
            .GetParameters().Last().HasDefaultValue);
        Assert.False(typeof(RemovalRunner).GetMethod(nameof(RemovalRunner.RunAsync))!
            .GetParameters().Last().HasDefaultValue);
        Assert.False(typeof(DeviceRemovalRunner).GetMethod(nameof(DeviceRemovalRunner.RunAsync))!
            .GetParameters().Last().HasDefaultValue);
        Assert.False(typeof(InventoryCollector).GetMethod(nameof(InventoryCollector.CollectAsync))!
            .GetParameters().First(p => p.ParameterType == typeof(AgentConfig)).HasDefaultValue);
    }
}
