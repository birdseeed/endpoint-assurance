using System.Runtime.Versioning;

namespace Patched.Shared.Auth;

/// <summary>
/// PAT-513: adds X-Patched-Device-Id to every outgoing "patched" client request.
/// The header value is the WMI UUID (Win32_ComputerSystemProduct.UUID) — the same
/// identifier sent in the inventory payload. The server can use this header to
/// enforce device-to-tenant binding once per-device tokens are issued.
/// Fail-open: if WMI is unavailable, the header is omitted and the request proceeds.
///
/// PAT-736: MUST be registered transient. IHttpClientFactory builds a fresh
/// handler pipeline after HandlerLifetime and refuses DelegatingHandler
/// instances whose InnerHandler is already set — a singleton here breaks every
/// CreateClient("patched") call ~2 minutes after service start
/// ("The 'InnerHandler' property must be null"). The WMI UUID cache lives in
/// the singleton DeviceIdProvider instead.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DeviceIdentityHandler : DelegatingHandler
{
    public const string DeviceIdHeader = "X-Patched-Device-Id";

    private readonly string? _deviceId;

    public DeviceIdentityHandler(DeviceIdProvider provider)
    {
        _deviceId = provider.DeviceId;
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        if (_deviceId is not null)
            request.Headers.TryAddWithoutValidation(DeviceIdHeader, _deviceId);
        return base.SendAsync(request, ct);
    }
}
