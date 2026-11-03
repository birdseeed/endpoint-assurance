using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Shared.Tests;

public class DeviceIdentityHandlerTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
    }

    // Rebuilds the "patched" client's handler pipeline the same way
    // IHttpClientFactory does internally on every (re)build: resolve a fresh
    // HttpMessageHandlerBuilder and replay the configured builder actions
    // (ConfigurePrimaryHttpMessageHandler + AddHttpMessageHandler<T>), then
    // Build(). Calling this twice reproduces the post-HandlerLifetime pipeline
    // rebuild directly, so the PAT-736 invariant is exercised deterministically
    // instead of racing a real Task.Delay against the factory's background
    // expiry timer (which starves and flakes on loaded CI runners, PAT-831).
    private static HttpMessageHandler BuildPipeline(IServiceProvider sp, string name)
    {
        var builder = sp.GetRequiredService<HttpMessageHandlerBuilder>();
        builder.Name = name;
        var options = sp.GetRequiredService<IOptionsMonitor<HttpClientFactoryOptions>>().Get(name);
        foreach (var action in options.HttpMessageHandlerBuilderActions)
            action(builder);
        return builder.Build();
    }

    // PAT-736 regression: DeviceIdentityHandler was registered as a singleton, but
    // IHttpClientFactory rebuilds the handler pipeline after HandlerLifetime and
    // refuses DelegatingHandler instances whose InnerHandler is already set
    // ("The 'InnerHandler' property must be null"). Every CreateClient("patched")
    // more than ~2 minutes after service start then threw, killing config polls,
    // posture fetches and inventory uploads until the service restarted.
    // With the transient registration the rebuild resolves a fresh handler each
    // time, so a second pipeline builds cleanly and still functions.
    [Fact]
    public async Task Handler_registration_survives_pipeline_rebuild_after_expiry()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<DeviceIdProvider>();
        services.AddTransient<DeviceIdentityHandler>();
        services.AddHttpClient("patched")
            .ConfigurePrimaryHttpMessageHandler(() => new StubHandler())
            .AddHttpMessageHandler<DeviceIdentityHandler>();

        await using var sp = services.BuildServiceProvider();

        using (var first = BuildPipeline(sp, "patched"))
        using (var firstInvoker = new HttpMessageInvoker(first))
        {
            var r1 = await firstInvoker.SendAsync(
                new HttpRequestMessage(HttpMethod.Get, "http://localhost/ping"), default);
            Assert.True(r1.IsSuccessStatusCode);
        }

        // The pipeline rebuild that took down the singleton registration.
        using var second = BuildPipeline(sp, "patched");
        using var secondInvoker = new HttpMessageInvoker(second);
        var r2 = await secondInvoker.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "http://localhost/ping"), default);
        Assert.True(r2.IsSuccessStatusCode);
    }

    // Pins the framework behaviour that motivated PAT-736: a singleton
    // DelegatingHandler makes the factory throw on the first pipeline rebuild,
    // because the reused instance's InnerHandler is already set. If this test
    // ever stops throwing, the .NET constraint changed and the comment in
    // Program.cs can be revisited.
    [Fact]
    public void Singleton_handler_registration_throws_on_pipeline_rebuild()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<DeviceIdProvider>();
        services.AddSingleton<DeviceIdentityHandler>(); // the PAT-736 bug shape
        services.AddHttpClient("patched")
            .ConfigurePrimaryHttpMessageHandler(() => new StubHandler())
            .AddHttpMessageHandler<DeviceIdentityHandler>();

        using var sp = services.BuildServiceProvider();

        // First build sets the singleton handler's InnerHandler; keep it alive so
        // the second build sees the same reused, already-wired instance.
        using var first = BuildPipeline(sp, "patched");

        // The rebuild reuses the same singleton instance, whose InnerHandler is
        // now non-null — the exact failure that took down the Windows agent.
        var ex = Assert.Throws<InvalidOperationException>(() => BuildPipeline(sp, "patched"));
        Assert.Contains("InnerHandler", ex.Message);
    }
}
