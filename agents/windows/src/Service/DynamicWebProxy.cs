using System.Net;
using System.Runtime.Versioning;
using Patched.Shared.Proxy;

namespace Patched.Service;

/// <summary>
/// An <see cref="IWebProxy"/> that resolves the egress proxy on every request
/// from the live agent-config (PAT-309). Because <see cref="ProxyResolver"/> is
/// re-run per request, a config-poll change (PAT-310) takes effect without a
/// service restart.
///
/// The credential-bearing proxy URL from <see cref="ProxyResolution.ProxyUrl"/>
/// is returned to the handler but is NEVER logged — only
/// <see cref="ProxyResolution.DisplayUrl"/> (credentials redacted) is logged,
/// and only once per distinct destination+resolution to avoid log spam.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class DynamicWebProxy : IWebProxy
{
    private readonly ProxyResolver           _resolver;
    private readonly AgentConfigManager      _config;
    private readonly ILogger<DynamicWebProxy> _log;

    // Dedupe advisory logging: log a given (display-url, warning) pair only once.
    private string? _lastLogged;

    public DynamicWebProxy(
        ProxyResolver            resolver,
        AgentConfigManager       config,
        ILogger<DynamicWebProxy> log)
    {
        _resolver = resolver;
        _config   = config;
        _log      = log;
    }

    public ICredentials? Credentials { get; set; }

    public Uri? GetProxy(Uri destination)
    {
        var resolution = Resolve(destination);
        if (resolution.IsDirect || string.IsNullOrEmpty(resolution.ProxyUrl))
            return null;
        return new Uri(resolution.ProxyUrl);
    }

    public bool IsBypassed(Uri host)
    {
        var resolution = Resolve(host);
        return resolution.IsDirect;
    }

    private ProxyResolution Resolve(Uri destination)
    {
        var resolution = _resolver.Resolve(destination.ToString(), _config.Current?.Proxy);
        LogOnce(resolution);
        return resolution;
    }

    private void LogOnce(ProxyResolution resolution)
    {
        // Build a log key from ONLY redacted/safe fields. ProxyUrl (with creds)
        // is never part of the key or the log message.
        string key = resolution.IsDirect
            ? "direct"
            : $"{resolution.DisplayUrl}|{resolution.Warning}";

        if (key == _lastLogged)
            return;
        _lastLogged = key;

        if (resolution.IsDirect)
        {
            _log.LogInformation("Proxy: connecting direct (no proxy)");
        }
        else
        {
            _log.LogInformation("Proxy: routing via {Proxy}{NoProxy}",
                resolution.DisplayUrl,
                resolution.NoProxy is null ? "" : $" (no_proxy: {resolution.NoProxy})");
        }

        if (!string.IsNullOrEmpty(resolution.Warning))
            _log.LogWarning("Proxy advisory: {Warning}", resolution.Warning);
    }
}
