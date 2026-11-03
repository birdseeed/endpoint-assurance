using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// Exercises the exact bounded queue-only helper PatchedWorker runs after local
/// triggers and scheduled work, without constructing the worker's full DI graph.
/// </summary>
public sealed class WorkerInventoryQueueRetryTests
{
    private const string Secret = "dGVzdC1obWFjLXNlY3JldC0zMi1ieXRlcy1sb25nIQ==";

    // PAT-1760 review: the helper takes the credential store and applies
    // DeviceCredentials.Present, so these build in-memory stores.
    private static CredentialStore Enrolled() => CredentialStore.ForTesting("test-tenant", "enrolled", Secret);

    [Fact]
    public async Task DrainInventoryQueueForTickAsync_WithoutBearer_DoesNotCallDrain()
    {
        var calls = 0;

        await PatchedWorker.DrainInventoryQueueForTickAsync(
            CredentialStore.ForTesting("test-tenant", "", Secret), _ => { calls++; return Task.CompletedTask; },
            NullLogger.Instance, CancellationToken.None);

        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData("   ")]
    [InlineData("\t")]
    [InlineData("")]
    public async Task DrainInventoryQueueForTickAsync_BearerWithUnusableSecret_DoesNotCallDrain(string hmacSecret)
    {
        var calls = 0;

        await PatchedWorker.DrainInventoryQueueForTickAsync(
            CredentialStore.ForTesting("test-tenant", "enrolled", hmacSecret), _ => { calls++; return Task.CompletedTask; },
            NullLogger.Instance, CancellationToken.None);

        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task DrainInventoryQueueForTickAsync_WithBearer_CallsDrainOnce()
    {
        var calls = 0;

        await PatchedWorker.DrainInventoryQueueForTickAsync(
            Enrolled(), _ => { calls++; return Task.CompletedTask; },
            NullLogger.Instance, CancellationToken.None);

        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task DrainInventoryQueueForTickAsync_FailureIsFailSafe()
    {
        var calls = 0;

        await PatchedWorker.DrainInventoryQueueForTickAsync(
            Enrolled(), _ =>
            {
                calls++;
                return Task.FromException(new HttpRequestException("simulated queue failure"));
            },
            NullLogger.Instance, CancellationToken.None);

        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task DrainInventoryQueueForTickAsync_TimeoutIsFailSafe()
    {
        var calls = 0;

        await PatchedWorker.DrainInventoryQueueForTickAsync(
            Enrolled(), async token =>
            {
                calls++;
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
            },
            NullLogger.Instance, CancellationToken.None,
            timeout: TimeSpan.FromMilliseconds(10));

        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task DrainInventoryQueueForTickAsync_ShutdownCancellationPropagates()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            PatchedWorker.DrainInventoryQueueForTickAsync(
                Enrolled(), token => Task.FromCanceled(token),
                NullLogger.Instance, cts.Token));
    }
}
