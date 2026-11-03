using System.Diagnostics.CodeAnalysis;
using Patched.Shared.Config;
using Patched.Shared.Proxy;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// Platform-neutral tests for <see cref="ProxyResolver"/> (PAT-309). These run on
/// macOS CI: they exercise the "off" and "manual" code paths only, which never
/// call into WinHTTP. The reachability probe and Credential Manager reads are
/// injected via the internal test constructor so no network or Windows API is hit.
///
/// CA1416 is suppressed at the class level: ProxyResolver is annotated
/// [SupportedOSPlatform("windows")] for production callers, but the manual/off
/// paths under test are pure managed code and run on any OS. The Windows-only
/// system path (WinHTTP P/Invoke) is never reached by these tests.
/// </summary>
[SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
    Justification = "Manual/off resolution paths are platform-neutral; WinHTTP is never invoked in tests.")]
public sealed class ProxyResolverTests
{
    // Probes that always return a fixed reachability, ignoring host/port.
    private static readonly Func<string, int, bool> AlwaysReachable   = (_, _) => true;
    private static readonly Func<string, int, bool> AlwaysUnreachable = (_, _) => false;

    private const string Target = "https://api.patched.im/v1/inventory";

    [Fact]
    public void OffMode_IsDirect()
    {
        var resolver = new ProxyResolver(AlwaysReachable);
        var cfg = new ProxyConfig { Mode = "off", Host = "proxy.corp", Port = 8080 };

        var result = resolver.Resolve(Target, cfg);

        Assert.True(result.IsDirect);
        Assert.Null(result.ProxyUrl);
    }

    [Fact]
    public void Manual_UnreachableWithBypass_FallsBackToDirect()
    {
        var resolver = new ProxyResolver(AlwaysUnreachable);
        var cfg = new ProxyConfig
        {
            Mode = "manual",
            Type = "http",
            Host = "proxy.corp.example.com",
            Port = 8080,
            BypassWhenOffCorp = true,
        };

        var result = resolver.Resolve(Target, cfg);

        Assert.True(result.IsDirect);
        Assert.Null(result.ProxyUrl);
    }

    [Fact]
    public void Manual_UnreachableNoBypass_KeepsProxyAndWarns()
    {
        var resolver = new ProxyResolver(AlwaysUnreachable);
        var cfg = new ProxyConfig
        {
            Mode = "manual",
            Type = "https",
            Host = "proxy.corp.example.com",
            Port = 8443,
            BypassWhenOffCorp = false,
        };

        var result = resolver.Resolve(Target, cfg);

        Assert.False(result.IsDirect);
        Assert.Equal("https://proxy.corp.example.com:8443", result.ProxyUrl);
        Assert.NotNull(result.Warning);
        Assert.Contains("not reachable", result.Warning);
    }

    [Fact]
    public void Manual_HttpProxyWithAuth_WarnsAboutUnencryptedAuth()
    {
        var resolver = new ProxyResolver(
            AlwaysReachable,
            credReader: _ => ("alice", "s3cr3t"));
        var cfg = new ProxyConfig
        {
            Mode = "manual",
            Type = "http",
            Host = "proxy.corp.example.com",
            Port = 8080,
            AuthRef = "PatchedAgent/ProxyCreds",
        };

        var result = resolver.Resolve(Target, cfg);

        Assert.False(result.IsDirect);
        Assert.NotNull(result.Warning);
        Assert.Contains("unencrypted HTTP proxy", result.Warning);
    }

    [Fact]
    public void Manual_NoProxyWithCidr_Warns()
    {
        var resolver = new ProxyResolver(AlwaysReachable);
        var cfg = new ProxyConfig
        {
            Mode = "manual",
            Type = "https",
            Host = "proxy.corp.example.com",
            Port = 8443,
            NoProxy = new[] { "localhost", "10.0.0.0/8", "corp.example.com" },
        };

        var result = resolver.Resolve(Target, cfg);

        Assert.False(result.IsDirect);
        Assert.NotNull(result.Warning);
        Assert.Contains("CIDR", result.Warning);
        Assert.Equal("localhost,10.0.0.0/8,corp.example.com", result.NoProxy);
    }

    [Fact]
    public void Manual_WithCredentials_RedactsDisplayUrlButEmbedsInProxyUrl()
    {
        var resolver = new ProxyResolver(
            AlwaysReachable,
            credReader: _ => ("alice", "s3cr3t"));
        var cfg = new ProxyConfig
        {
            Mode = "manual",
            Type = "https",
            Host = "proxy.corp.example.com",
            Port = 8443,
            AuthRef = "PatchedAgent/ProxyCreds",
        };

        var result = resolver.Resolve(Target, cfg);

        Assert.False(result.IsDirect);

        // DisplayUrl is safe to log: credentials replaced with [redacted].
        Assert.NotNull(result.DisplayUrl);
        Assert.Contains("[redacted]", result.DisplayUrl);
        Assert.DoesNotContain("alice", result.DisplayUrl);
        Assert.DoesNotContain("s3cr3t", result.DisplayUrl);

        // ProxyUrl carries the real credentials (used by the handler, never logged).
        Assert.NotNull(result.ProxyUrl);
        Assert.Contains("alice", result.ProxyUrl);
        Assert.Contains("s3cr3t", result.ProxyUrl);
        Assert.Equal("https://alice:s3cr3t@proxy.corp.example.com:8443", result.ProxyUrl);

        // An HTTPS proxy with auth produces no unencrypted-HTTP warning.
        Assert.True(result.Warning is null || !result.Warning.Contains("unencrypted"));
    }

    [Fact]
    public void Manual_EmptyHost_IsDirect()
    {
        var resolver = new ProxyResolver(AlwaysReachable);
        var cfg = new ProxyConfig { Mode = "manual", Host = "", Port = 8080 };

        var result = resolver.Resolve(Target, cfg);

        Assert.True(result.IsDirect);
    }

    [Fact]
    public void Manual_CredentialsWithSpecialChars_AreUrlEncoded()
    {
        var resolver = new ProxyResolver(
            AlwaysReachable,
            credReader: _ => ("user@domain", "p@ss:word/value"));
        var cfg = new ProxyConfig
        {
            Mode = "manual",
            Type = "https",
            Host = "proxy.corp.example.com",
            Port = 8443,
            AuthRef = "PatchedAgent/ProxyCreds",
        };

        var result = resolver.Resolve(Target, cfg);

        Assert.NotNull(result.ProxyUrl);
        // The raw characters must be percent-encoded so the URL stays parseable.
        var uri = new Uri(result.ProxyUrl!);
        Assert.Equal("proxy.corp.example.com", uri.Host);
        Assert.Equal(8443, uri.Port);
        // Display stays redacted regardless.
        Assert.Contains("[redacted]", result.DisplayUrl!);
    }
}
