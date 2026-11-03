using System.Net.Sockets;
using System.Runtime.Versioning;
using Patched.Shared.Auth;
using Patched.Shared.Config;

namespace Patched.Shared.Proxy;

/// <summary>
/// Resolves the egress proxy for a target URL from the verified agent-config
/// (PAT-309). This is the Windows parity of the macOS
/// <c>patched-proxy-resolve.py</c> and mirrors its logic exactly:
///
///   mode "off"     → direct.
///   mode "manual"  → host/port/type from config, probe reachability, read
///                    creds from Windows Credential Manager (never plaintext on
///                    disk), apply no_proxy, with the same advisory warnings.
///   mode "system"  → WinHTTP IE/WinINet settings, including in-process PAC
///                    evaluation for the target URL.
///
/// SECURITY MODEL:
///   * Proxy credentials (user:pass) appear ONLY in <see cref="ProxyResolution.ProxyUrl"/>.
///     They are never placed in <see cref="ProxyResolution.DisplayUrl"/>, never
///     logged, and never written to disk.
///   * <see cref="ProxyResolution.DisplayUrl"/> always substitutes "[redacted]"
///     for the credentials, so it is safe to log.
///   * Basic-auth over a cleartext "http" proxy is a non-fatal WARNING (operator
///     choice), not a hard error — prefer an "https" proxy.
///   * no_proxy CIDR ranges are a non-fatal WARNING: WinHTTP does not honour CIDR.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProxyResolver
{
    private const int ProbeTimeoutMs = 2000;

    private readonly Func<string, int, bool> _tcpProbe;
    private readonly Func<string, (string user, string pass)> _credReader;

    /// <summary>Production constructor: probes real TCP and reads Windows Credential Manager.</summary>
    public ProxyResolver()
        : this(TcpReachable, ReadProxyCredential)
    {
    }

    /// <summary>
    /// Testable constructor. Inject a reachability probe and credential reader so
    /// tests never touch the network or Credential Manager. Internal — visible to
    /// Patched.Shared.Tests via InternalsVisibleTo.
    /// </summary>
    internal ProxyResolver(
        Func<string, int, bool> tcpProbe,
        Func<string, (string user, string pass)>? credReader = null)
    {
        _tcpProbe = tcpProbe;
        _credReader = credReader ?? ((_) => ("", ""));
    }

    /// <summary>Resolve the proxy for <paramref name="targetUrl"/>. Never throws; fails open to direct.</summary>
    public ProxyResolution Resolve(string targetUrl, ProxyConfig? config)
    {
        try
        {
            var mode = config?.Mode ?? "system";

            if (mode == "off")
                return new ProxyResolution { IsDirect = true };

            if (mode == "manual")
                return ResolveManual(targetUrl, config!);

            return ResolveSystem(targetUrl);
        }
        catch
        {
            // Fail open: any unexpected error → direct, never block egress.
            return new ProxyResolution { IsDirect = true };
        }
    }

    // -------------------------------------------------------------------------
    // system mode
    // -------------------------------------------------------------------------

    private ProxyResolution ResolveSystem(string targetUrl)
    {
        var sys = WinHttpProxyInfo.GetSystemProxy(targetUrl);
        if (sys is null || string.IsNullOrWhiteSpace(sys.ProxyServer))
            return new ProxyResolution { IsDirect = true };

        // WinHTTP can return "host:port" or a scheme list
        // ("http=host:port;https=host:port"). Pick the entry for the target
        // scheme; fall back to the first/raw entry. System proxies carry no
        // credentials, so ProxyUrl == DisplayUrl here.
        string proxyServer = SelectProxyForTarget(sys.ProxyServer!, targetUrl);
        string url = EnsureScheme(proxyServer);

        return new ProxyResolution
        {
            IsDirect   = false,
            ProxyUrl   = url,
            DisplayUrl = url,
            NoProxy    = NullIfEmpty(sys.ProxyBypass),
        };
    }

    private static string SelectProxyForTarget(string winHttpProxy, string targetUrl)
    {
        // No scheme map → single proxy for everything.
        if (!winHttpProxy.Contains('='))
            return winHttpProxy.Trim();

        bool isHttps = targetUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        string wantScheme = isHttps ? "https" : "http";

        string? firstEntry = null;
        foreach (var part in winHttpProxy.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int eq = part.IndexOf('=');
            if (eq < 0)
            {
                firstEntry ??= part.Trim();
                continue;
            }
            string scheme = part[..eq].Trim();
            string value = part[(eq + 1)..].Trim();
            firstEntry ??= value;
            if (scheme.Equals(wantScheme, StringComparison.OrdinalIgnoreCase))
                return value;
        }
        return firstEntry ?? winHttpProxy.Trim();
    }

    // -------------------------------------------------------------------------
    // manual mode
    // -------------------------------------------------------------------------

    private ProxyResolution ResolveManual(string targetUrl, ProxyConfig config)
    {
        string host = config.Host ?? "";
        int port = config.Port is null or 0 ? 8080 : config.Port.Value;
        string type = string.IsNullOrWhiteSpace(config.Type) ? "http" : config.Type;

        if (string.IsNullOrWhiteSpace(host))
            return new ProxyResolution { IsDirect = true };

        var warnings = new List<string>();

        // Probe reachability before use. If unreachable:
        //   bypass_when_off_corp=true  → fall back to direct (roaming laptops).
        //   bypass_when_off_corp=false → keep the proxy (fail closed) but warn.
        bool reachable = _tcpProbe(host, port);
        if (!reachable && config.BypassWhenOffCorp)
            return new ProxyResolution { IsDirect = true };

        // Build base + credential-bearing URLs.
        string baseUrl = $"{type}://{host}:{port}";
        string proxyUrl = baseUrl;
        string displayUrl = baseUrl;

        if (!string.IsNullOrWhiteSpace(config.AuthRef))
        {
            var (user, pass) = _credReader(config.AuthRef!);
            if (!string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(pass))
            {
                string u = Uri.EscapeDataString(user);
                string p = Uri.EscapeDataString(pass);
                proxyUrl   = $"{type}://{u}:{p}@{host}:{port}";
                displayUrl = $"{type}://[redacted]@{host}:{port}";

                // Basic-auth over a cleartext HTTP proxy exposes the credentials
                // on the wire. Warn (don't refuse) — prefer an HTTPS proxy.
                if (type.Equals("http", StringComparison.OrdinalIgnoreCase))
                {
                    warnings.Add("proxy credentials are being sent over an unencrypted HTTP proxy; "
                               + "prefer an HTTPS proxy (set proxy.type to \"https\")");
                }
            }
        }

        // no_proxy: join the array; warn on CIDR (WinHTTP does not honour CIDR).
        string? noProxy = null;
        if (config.NoProxy is { Length: > 0 } entries)
        {
            noProxy = string.Join(",", entries);
            if (entries.Any(e => e is not null && e.Contains('/')))
            {
                warnings.Add("no_proxy contains a CIDR range, which WinHTTP does not honour; "
                           + "use exact hosts or domain suffixes (e.g. \"corp.example.com\") instead");
            }
        }

        if (!reachable)
        {
            warnings.Add($"manual proxy {host}:{port} is not reachable; egress will fail until it is "
                       + "(set proxy.bypass_when_off_corp=true to fall back to direct when off-network)");
        }

        return new ProxyResolution
        {
            IsDirect   = false,
            ProxyUrl   = proxyUrl,
            DisplayUrl = displayUrl,
            NoProxy    = noProxy,
            Warning    = warnings.Count > 0 ? string.Join("; ", warnings) : null,
        };
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    private static string EnsureScheme(string proxy)
    {
        if (proxy.Contains("://", StringComparison.Ordinal))
            return proxy;
        // WinHTTP static proxies are HTTP CONNECT proxies; default to http://.
        return $"http://{proxy}";
    }

    private static string? NullIfEmpty(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s;

    private static bool TcpReachable(string host, int port)
    {
        try
        {
            using var client = new TcpClient();
            var task = client.ConnectAsync(host, port);
            return task.Wait(ProbeTimeoutMs) && client.Connected;
        }
        catch
        {
            return false;
        }
    }

    [SupportedOSPlatform("windows")]
    private static (string user, string pass) ReadProxyCredential(string target)
    {
        var cred = CredentialStore.ReadGenericCredential(target);
        return cred ?? ("", "");
    }
}
