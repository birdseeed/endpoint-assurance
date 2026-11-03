using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1779: <see cref="InventoryQueuePump"/> and <see cref="ProvenanceQueuePump"/> sign
/// every request with one <see cref="DeviceCredentials.TryRead"/> snapshot, the same
/// snapshot that decides whether to send at all, as PostureFetcher and AuditEventShipper
/// do after PAT-1765.
///
/// Before PAT-1779 each request read the HMAC secret from the store for the signature,
/// then called the client factory, then read the bearer token for the header. The
/// factory here replaces the credential pair on that call, which is exactly the window
/// that let one request carry pair B's token with pair A's signature. Every request the
/// handler sees must verify against the secret of the pair whose token it carries.
///
/// Runs against CredentialStore.ForTesting (in-memory writer, scratch suspended path)
/// and scratch queue directories only.
/// </summary>
public sealed class QueuePumpCredentialSnapshotTests : IDisposable
{
    private const string BearerA = "bearer-pair-a";
    private const string BearerB = "bearer-pair-b";
    private static readonly string SecretA = Convert.ToBase64String(Enumerable.Repeat((byte)0x0A, 32).ToArray());
    private static readonly string SecretB = Convert.ToBase64String(Enumerable.Repeat((byte)0x0B, 32).ToArray());

    private readonly string _tmpDir;

    public QueuePumpCredentialSnapshotTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), $"patched-pump-snapshot-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tmpDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* best effort */ }
    }

    // ------------------------------------------------------------------ //
    // A pair replaced between the check and the send                       //
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task InventorySend_PairReplacedMidRequest_SignsWithOneConsistentPair()
    {
        var (creds, factory, handler) = SwappingFixture(HmacSigner.EndpointInventory);
        var pump = new InventoryQueuePump(NullLogger.Instance, factory, creds, _tmpDir);

        await pump.SendOrEnqueueAsync("{\"x\":1}"u8.ToArray(), CancellationToken.None);

        var sent = Assert.Single(handler.Requests);
        AssertSignedWithOnePair(sent);
        Assert.Equal(BearerA, sent.Bearer); // the snapshot taken before the swap
    }

    [Fact]
    public async Task InventoryDrain_PairReplacedMidPass_EveryRequestSignedWithOneConsistentPair()
    {
        WriteQueueFile("inv-100-1.json");
        WriteQueueFile("inv-100-2.json");
        var (creds, factory, handler) = SwappingFixture(HmacSigner.EndpointInventory);
        var pump = new InventoryQueuePump(NullLogger.Instance, factory, creds, _tmpDir);

        await pump.DrainAsync(CancellationToken.None);

        Assert.Equal(2, handler.Requests.Count);
        Assert.All(handler.Requests, AssertSignedWithOnePair);
    }

    [Fact]
    public async Task ProvenanceSend_PairReplacedMidRequest_SignsWithOneConsistentPair()
    {
        var (creds, factory, handler) = SwappingFixture(HmacSigner.EndpointProvenance);
        var pump = NewProvenancePump(factory, creds);

        await pump.SendOrEnqueueAsync("{\"x\":1}"u8.ToArray(), CancellationToken.None);

        var sent = Assert.Single(handler.Requests);
        AssertSignedWithOnePair(sent);
        Assert.Equal(BearerA, sent.Bearer);
    }

    [Fact]
    public async Task ProvenanceDrain_PairReplacedMidPass_EveryRequestSignedWithOneConsistentPair()
    {
        WriteQueueFile("prov-100-1.json");
        WriteQueueFile("prov-100-2.json");
        var (creds, factory, handler) = SwappingFixture(HmacSigner.EndpointProvenance);
        var pump = NewProvenancePump(factory, creds);

        await pump.DrainAsync(CancellationToken.None);

        Assert.Equal(2, handler.Requests.Count);
        Assert.All(handler.Requests, AssertSignedWithOnePair);
    }

    // ------------------------------------------------------------------ //
    // No usable pair: nothing sent, nothing lost                           //
    // ------------------------------------------------------------------ //

    public static IEnumerable<object[]> UnusablePairs() => new[]
    {
        new object[] { "", SecretA },
        new object[] { "   ", SecretA },
        new object[] { BearerA, "" },
        new object[] { BearerA, "   " },
    };

    [Theory]
    [MemberData(nameof(UnusablePairs))]
    public async Task InventoryPump_NoUsablePair_SendsNothing_QueuesTheFreshPayload_AndKeepsTheQueue(string bearer, string secret)
    {
        var queued = WriteQueueFile("inv-200-1.json");
        var handler = new RecordingHandler(HmacSigner.EndpointInventory);
        var pump = new InventoryQueuePump(
            NullLogger.Instance, new SwappingFactory(handler, onCreate: null), CredentialStore.ForTesting("tenant", bearer, secret), _tmpDir);

        await pump.SendOrEnqueueAsync("{\"fresh\":true}"u8.ToArray(), CancellationToken.None);
        await pump.DrainAsync(CancellationToken.None);
        await pump.DrainOneAsync(CancellationToken.None);

        Assert.Empty(handler.Requests);
        Assert.True(File.Exists(queued));
        Assert.Equal(2, Directory.GetFiles(_tmpDir, "inv-*.json").Length);
        Assert.False(pump.LastAttemptWasAuthFailure);
    }

    [Theory]
    [MemberData(nameof(UnusablePairs))]
    public async Task ProvenancePump_NoUsablePair_SendsNothing_QueuesTheFreshRecord_AndKeepsTheQueue(string bearer, string secret)
    {
        var queued = WriteQueueFile("prov-200-1.json");
        var handler = new RecordingHandler(HmacSigner.EndpointProvenance);
        var pump = NewProvenancePump(new SwappingFactory(handler, onCreate: null), CredentialStore.ForTesting("tenant", bearer, secret));

        await pump.SendOrEnqueueAsync("{\"fresh\":true}"u8.ToArray(), CancellationToken.None);
        await pump.DrainAsync(CancellationToken.None);
        await pump.DrainOneAsync(CancellationToken.None);

        Assert.Empty(handler.Requests);
        Assert.True(File.Exists(queued));
        Assert.Equal(2, Directory.GetFiles(_tmpDir, "prov-*.json").Length);
        Assert.False(pump.LastAttemptWasAuthFailure);
    }

    // ------------------------------------------------------------------ //
    // Helpers                                                              //
    // ------------------------------------------------------------------ //

    private ProvenanceQueuePump NewProvenancePump(IHttpClientFactory factory, CredentialStore creds) =>
        new(NullLogger.Instance, factory, creds, _tmpDir, delay: (_, _) => Task.CompletedTask);

    private string WriteQueueFile(string name)
    {
        var file = Path.Combine(_tmpDir, name);
        File.WriteAllText(file, "{\"queued\":\"" + name + "\"}");
        return file;
    }

    /// <summary>
    /// Pair A in the store; the first client the pump creates replaces it with pair B,
    /// between the signature and the header of the first request.
    /// </summary>
    private static (CredentialStore Creds, SwappingFactory Factory, RecordingHandler Handler) SwappingFixture(string endpointId)
    {
        var creds = CredentialStore.ForTesting("tenant-a", BearerA, SecretA);
        var handler = new RecordingHandler(endpointId);
        bool swapped = false;
        var factory = new SwappingFactory(handler, onCreate: () =>
        {
            if (swapped) return;
            swapped = true;
            creds.UpdateFromEnrolment("tenant-b", BearerB, SecretB);
        });
        return (creds, factory, handler);
    }

    private static void AssertSignedWithOnePair(SentRequest sent)
    {
        string secretForBearer = sent.Bearer switch
        {
            BearerA => SecretA,
            BearerB => SecretB,
            _ => throw new Xunit.Sdk.XunitException($"unexpected bearer token '{sent.Bearer}'"),
        };
        Assert.True(
            HmacSigner.VerifySignature(secretForBearer, "POST", sent.EndpointId, sent.Timestamp, sent.Nonce, sent.Body, sent.Signature),
            $"request carrying {sent.Bearer} was not signed with that pair's secret (mixed pair)");
    }

    private sealed record SentRequest(string Bearer, string Signature, string Timestamp, string Nonce, byte[] Body, string EndpointId);

    private sealed class RecordingHandler(string endpointId) : HttpMessageHandler
    {
        public List<SentRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(ct);
            Requests.Add(new SentRequest(
                request.Headers.Authorization?.Parameter ?? "",
                request.Headers.GetValues(HmacSigner.SignatureHeader).Single(),
                request.Headers.GetValues("X-Patched-Timestamp").Single(),
                request.Headers.GetValues("X-Patched-Nonce").Single(),
                body,
                endpointId));
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    private sealed class SwappingFactory(HttpMessageHandler handler, Action? onCreate) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name)
        {
            onCreate?.Invoke();
            return new HttpClient(handler, disposeHandler: false) { BaseAddress = new Uri("https://patched-1779-test.invalid") };
        }
    }
}
