using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Patched.Shared.Auth;
using Patched.Shared.Config;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1110. DecommissionStatusReporter's constructor takes the real
/// <c>Patched.Shared.Auth.CredentialStore</c> (same as DeviceRemovalTasksClient's
/// established pattern), whose only public factories (<c>Load</c>/<c>LoadForStartup</c>)
/// call into Windows Credential Manager via a raw <c>DllImport("advapi32.dll")</c>
/// P/Invoke with no try/catch around the call itself — so, exactly like
/// DeviceRemovalRunnerTests does for DeviceRemovalTasksClient, these tests pass
/// <c>null!</c> for it rather than constructing a real instance, which would throw
/// <c>DllNotFoundException</c> on this non-Windows CI host before ever reaching the
/// HTTP call. That means these tests exercise the METHOD'S retry/return-value
/// contract under a totally broken credentials dependency (a real failure mode: e.g.
/// Credential Manager unavailable) — always <see cref="DecommissionReportOutcome.Unreported"/>
/// for that specific setup, never Proceed/Aborted — not the happy-path HTTP body.
///
/// The Proceed/Aborted body-classification logic (third contract round, final
/// wording — body-first: the "decommission" field decides, status code is a
/// secondary signal only) is proven directly against
/// <see cref="DecommissionStatusReporter.ClassifyResponseBody"/> — deliberately
/// <c>internal</c>, not <c>private</c>, exactly so these tests can drive it with
/// literal response bytes without needing a real HTTP round trip through the
/// same unavailable CredentialStore. See PAT-1110's report for the real
/// end-to-end HTTP path as a named gap requiring real Windows hardware
/// (Credential Manager) to close.
///
/// The end-to-end abort behaviour this classification feeds into (service left
/// installed, scheduled task deregistered) is proven separately at the
/// DecommissionRunner level (DecommissionRunnerTests, via a fake
/// IDecommissionStatusReporter that returns a canned outcome) — that test does not
/// need to know HOW an outcome was decided, only that DecommissionRunner reacts
/// correctly to each one.
///
/// The wire-contract requirement that most needs direct proof — the post-PAT-1108
/// platform change requiring "directive_version" on every report, captured at
/// decide-to-act time rather than read back later — is instead proven by serializing
/// <see cref="DecommissionStatusRequest"/> directly (no HTTP, no CredentialStore
/// needed at all).
/// </summary>
public class DecommissionStatusReporterTests
{
    [Fact]
    public void DecommissionStatusRequest_SerializesAcknowledgedStatus_AndDirectiveVersion_ByExactFieldNames()
    {
        // Field names and semantics must stay byte-identical to the macOS agent
        // (ADR-0007 parity). "acknowledged" (not "removing" — the pre-second-round
        // status name, which the real server's agentReportableDecommissionStatuses
        // allowlist would have rejected with 400) is the non-terminal phase-1 status.
        var request = new DecommissionStatusRequest
        {
            Status           = "acknowledged",
            Purge            = true,
            Reason           = "offboarding",
            ReportedAt       = DateTimeOffset.Parse("2026-08-01T00:00:00Z"),
            DirectiveVersion = 42,
        };

        string json = JsonSerializer.Serialize(request);
        using var doc = JsonDocument.Parse(json);

        Assert.Equal(42, doc.RootElement.GetProperty("directive_version").GetInt32());
        Assert.Equal("acknowledged", doc.RootElement.GetProperty("status").GetString());
        Assert.True(doc.RootElement.GetProperty("purge").GetBoolean());
        Assert.Equal("offboarding", doc.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public void DecommissionStatusRequest_DirectiveVersion_IsNeverOmitted()
    {
        // The platform treats a missing directive_version as untrusted and will not
        // attribute the report — so even the zero-value default must still be
        // present on the wire (never conditionally omitted).
        var request = new DecommissionStatusRequest { DirectiveVersion = 0 };
        string json = JsonSerializer.Serialize(request);

        Assert.Contains("\"directive_version\":0", json);
    }

    private sealed class StubHandler(HttpStatusCode status) : HttpMessageHandler
    {
        public int CallCount { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            CallCount++;
            return Task.FromResult(new HttpResponseMessage(status));
        }
    }

    private sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler) { BaseAddress = new Uri("https://api.patched.test") };
    }

    [Fact]
    public async Task ReportAcknowledgedAsync_BrokenCredentials_ReturnsUnreported_NeverThrows_BoundedRetries()
    {
        // null! CredentialStore mirrors DeviceRemovalRunnerTests' established pattern
        // (see this class's doc comment) — _creds.HmacSecret throws a
        // NullReferenceException before any HTTP call is made, exercising the
        // method's own catch-and-retry contract under a real failure mode
        // (Credential Manager unavailable) rather than the HTTP path. This can never
        // produce Aborted (that requires a real 409 response) — only Unreported.
        var handler = new StubHandler(HttpStatusCode.OK);
        var reporter = new DecommissionStatusReporter(
            NullLogger<DecommissionStatusReporter>.Instance,
            new StubHttpClientFactory(handler),
            null!,
            maxAttempts: 3,
            retryDelay: TimeSpan.Zero);

        var outcome = await reporter.ReportAcknowledgedAsync(
            new DecommissionPolicy { ModeRaw = "immediate" }, directiveVersion: 1, CancellationToken.None);

        Assert.Equal(DecommissionReportOutcome.Unreported, outcome);
        Assert.Equal(0, handler.CallCount); // never reached the network — failed before SendAsync
    }

    [Fact]
    public async Task ReportAcknowledgedAsync_RespectsMaxAttemptsBound_EvenWhenRetriedIndefinitelyWouldBeWrong()
    {
        // A directive that IS due must proceed to removal even if the platform is
        // permanently unreachable — retries must be bounded, not indefinite. This is
        // exercised at the "maxAttempts=1" boundary to keep the test fast and
        // deterministic regardless of which failure path (network vs credentials)
        // trips first.
        var handler = new StubHandler(HttpStatusCode.OK);
        var reporter = new DecommissionStatusReporter(
            NullLogger<DecommissionStatusReporter>.Instance,
            new StubHttpClientFactory(handler),
            null!,
            maxAttempts: 1,
            retryDelay: TimeSpan.FromMinutes(10)); // would time out the test if ever awaited

        var outcome = await reporter.ReportAcknowledgedAsync(
            new DecommissionPolicy { ModeRaw = "immediate" }, directiveVersion: 1, CancellationToken.None);

        // Returned promptly — the 10-minute delay was never awaited past the single attempt.
        Assert.Equal(DecommissionReportOutcome.Unreported, outcome);
    }

    private sealed class CapturingHandler(HttpStatusCode status, string responseBody) : HttpMessageHandler
    {
        public HttpRequestMessage? CapturedRequest { get; private set; }
        public byte[] CapturedBody { get; private set; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            CapturedRequest = request;
            CapturedBody = request.Content is null
                ? []
                : await request.Content.ReadAsByteArrayAsync(ct);
            return new HttpResponseMessage(status)
            {
                Content = new StringContent(responseBody, Encoding.UTF8, "application/json"),
            };
        }
    }

    // -------------------------------------------------------------------------
    // Non-author review (P2): every test above either uses null! credentials (the
    // production CredentialStore factories touch Windows Credential Manager via a
    // raw P/Invoke this non-Windows CI host cannot run) or drives
    // ClassifyResponseBody directly, so none of them ever exercised the actual
    // outgoing HTTP request this method builds. CredentialStore.ForTesting
    // (test-only, InternalsVisibleTo — never touches Credential Manager) makes that
    // possible: a real CredentialStore instance, a real request, captured by a fake
    // handler, and the v2 HMAC signature independently recomputed and compared byte
    // for byte, so a regression in header names, timestamp/nonce reuse between the
    // signature and the headers, or the signing input itself would fail this test.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task ReportAcknowledgedAsync_RealCredentials_SignsRequestCorrectly_AndClassifiesResponse()
    {
        string secret = Convert.ToBase64String(Encoding.ASCII.GetBytes("test-hmac-secret-for-decommission"));
        var creds = CredentialStore.ForTesting("tenant-abc", "bearer-token-xyz", secret);
        var handler = new CapturingHandler(
            HttpStatusCode.OK,
            """{"decommission":"proceed","device_id":"dev-1","recorded_status":"acknowledged"}""");
        var reporter = new DecommissionStatusReporter(
            NullLogger<DecommissionStatusReporter>.Instance,
            new StubHttpClientFactory(handler),
            creds,
            maxAttempts: 1,
            retryDelay: TimeSpan.Zero);

        var outcome = await reporter.ReportAcknowledgedAsync(
            new DecommissionPolicy { ModeRaw = "immediate", Purge = true, Reason = "offboarding" },
            directiveVersion: 55, CancellationToken.None);

        Assert.Equal(DecommissionReportOutcome.Proceed, outcome);

        var req = handler.CapturedRequest;
        Assert.NotNull(req);
        Assert.Equal("Bearer", req!.Headers.Authorization!.Scheme);
        Assert.Equal("bearer-token-xyz", req.Headers.Authorization!.Parameter);

        Assert.True(req.Headers.TryGetValues("X-Patched-Timestamp", out var tsValues));
        string timestamp = tsValues!.Single();
        Assert.True(long.TryParse(timestamp, out _), "timestamp header must be the raw unix-seconds integer string");

        Assert.True(req.Headers.TryGetValues("X-Patched-Nonce", out var nonceValues));
        string nonce = nonceValues!.Single();
        Assert.Equal(32, nonce.Length); // Guid "N" format, as ReportAcknowledgedAsync generates it

        Assert.True(req.Headers.TryGetValues(HmacSigner.SignatureHeader, out var sigValues));
        string signature = sigValues!.Single();

        // Recompute the v3 signature independently over the exact target/ts/nonce/body
        // and assert it matches byte for byte. This proves the headers and stable
        // endpoint identity are the same values used by the request signer.
        string expectedSignature = HmacSigner.ComputeSignature(
            secret,
            "POST",
            HmacSigner.EndpointAgentDecommissionStatus,
            timestamp,
            nonce,
            handler.CapturedBody);
        Assert.Equal(expectedSignature, signature);

        using var bodyDoc = JsonDocument.Parse(handler.CapturedBody);
        Assert.Equal(55, bodyDoc.RootElement.GetProperty("directive_version").GetInt32());
        Assert.True(bodyDoc.RootElement.GetProperty("purge").GetBoolean());
    }

    // -------------------------------------------------------------------------
    // Third contract round (final wording): body-first classification.
    // contracts/agent-config-schema.md:
    //   200 -> {"decommission":"proceed","device_id":...,"recorded_status":...}
    //   409 -> {"decommission":"superseded","device_id":...}
    // The "decommission" field decides; HTTP status code is a secondary signal only.
    // -------------------------------------------------------------------------

    private static DecommissionStatusReporter MakeReporter() => new(
        NullLogger<DecommissionStatusReporter>.Instance,
        httpFactory: null!, // ClassifyResponseBody never touches the HTTP client
        creds: null!,       // ClassifyResponseBody never touches credentials
        maxAttempts: 1,
        retryDelay: TimeSpan.Zero);

    [Fact]
    public void ClassifyResponseBody_SupersededBody_ReturnsAborted_EvenWith200()
    {
        // Body is authoritative over status code: a 200 carrying "superseded" must
        // still abort, not proceed.
        var reporter = MakeReporter();
        byte[] body = """{"decommission":"superseded","device_id":"dev-1"}"""u8.ToArray();

        var outcome = reporter.ClassifyResponseBody(body, HttpStatusCode.OK, attempt: 1, directiveVersion: 7);

        Assert.Equal(DecommissionReportOutcome.Aborted, outcome);
    }

    [Fact]
    public void ClassifyResponseBody_ProceedBody_ReturnsProceed()
    {
        var reporter = MakeReporter();
        byte[] body = """{"decommission":"proceed","device_id":"dev-1","recorded_status":"acknowledged"}"""u8.ToArray();

        var outcome = reporter.ClassifyResponseBody(body, HttpStatusCode.OK, attempt: 1, directiveVersion: 7);

        Assert.Equal(DecommissionReportOutcome.Proceed, outcome);
    }

    [Fact]
    public void ClassifyResponseBody_SupersededBodyWith409_ReturnsAborted()
    {
        // The "normal" real-world case: status code and body agree.
        var reporter = MakeReporter();
        byte[] body = """{"decommission":"superseded","device_id":"dev-1"}"""u8.ToArray();

        var outcome = reporter.ClassifyResponseBody(body, HttpStatusCode.Conflict, attempt: 1, directiveVersion: 7);

        Assert.Equal(DecommissionReportOutcome.Aborted, outcome);
    }

    [Fact]
    public void ClassifyResponseBody_200WithGarbledBody_MustAbort_NotProceed()
    {
        // Reachable (we got a 200), but the body cannot be understood as a "proceed"
        // — an unreadable answer to "may I destroy this machine's agent" is not a
        // yes. Must NOT be treated the same as an actual "proceed".
        var reporter = MakeReporter();
        byte[] body = "{not valid json at all"u8.ToArray();

        var outcome = reporter.ClassifyResponseBody(body, HttpStatusCode.OK, attempt: 1, directiveVersion: 7);

        Assert.Equal(DecommissionReportOutcome.Aborted, outcome);
    }

    [Fact]
    public void ClassifyResponseBody_409WithEmptyBody_MustAbort()
    {
        var reporter = MakeReporter();
        byte[] body = [];

        var outcome = reporter.ClassifyResponseBody(body, HttpStatusCode.Conflict, attempt: 1, directiveVersion: 7);

        Assert.Equal(DecommissionReportOutcome.Aborted, outcome);
    }

    [Fact]
    public void ClassifyResponseBody_200WithEmptyBody_MustAbort_NotProceed()
    {
        // Same failure-closed rule regardless of which "success-looking" status code
        // carried the unreadable body.
        var reporter = MakeReporter();
        byte[] body = [];

        var outcome = reporter.ClassifyResponseBody(body, HttpStatusCode.OK, attempt: 1, directiveVersion: 7);

        Assert.Equal(DecommissionReportOutcome.Aborted, outcome);
    }

    [Fact]
    public void ClassifyResponseBody_MissingDecommissionField_MustAbort()
    {
        var reporter = MakeReporter();
        byte[] body = """{"device_id":"dev-1","recorded_status":"acknowledged"}"""u8.ToArray();

        var outcome = reporter.ClassifyResponseBody(body, HttpStatusCode.OK, attempt: 1, directiveVersion: 7);

        Assert.Equal(DecommissionReportOutcome.Aborted, outcome);
    }

    [Fact]
    public void ClassifyResponseBody_UnrecognisedDecommissionValue_MustAbort_NotProceed()
    {
        var reporter = MakeReporter();
        byte[] body = """{"decommission":"maybe_later","device_id":"dev-1"}"""u8.ToArray();

        var outcome = reporter.ClassifyResponseBody(body, HttpStatusCode.OK, attempt: 1, directiveVersion: 7);

        Assert.Equal(DecommissionReportOutcome.Aborted, outcome);
    }

    [Fact]
    public void ClassifyResponseBody_DecommissionFieldWrongJsonType_MustAbort()
    {
        // "decommission": true (not a string) — a wrong-shaped answer is exactly as
        // unreadable as no answer at all.
        var reporter = MakeReporter();
        byte[] body = """{"decommission":true}"""u8.ToArray();

        var outcome = reporter.ClassifyResponseBody(body, HttpStatusCode.OK, attempt: 1, directiveVersion: 7);

        Assert.Equal(DecommissionReportOutcome.Aborted, outcome);
    }
}
