namespace Patched.Shared.Proxy;

/// <summary>
/// Result of resolving the egress proxy for a single target URL (PAT-309,
/// parity with the macOS <c>patched-proxy-resolve.py</c>).
///
/// SECURITY: <see cref="ProxyUrl"/> may embed <c>user:pass</c> credentials and
/// MUST NOT be logged. Log <see cref="DisplayUrl"/> instead — it always has the
/// credentials replaced with the literal <c>[redacted]</c>.
/// </summary>
public sealed record ProxyResolution
{
    /// <summary>True when the agent should connect directly (no proxy).</summary>
    public bool IsDirect { get; init; }

    /// <summary>
    /// Full proxy URL including credentials if any (<c>type://user:pass@host:port</c>).
    /// NEVER log this. Null when <see cref="IsDirect"/> is true.
    /// </summary>
    public string? ProxyUrl { get; init; }

    /// <summary>
    /// Proxy URL with credentials redacted (<c>type://[redacted]@host:port</c>).
    /// Safe to log. Null when <see cref="IsDirect"/> is true.
    /// </summary>
    public string? DisplayUrl { get; init; }

    /// <summary>Comma-separated proxy bypass list, or null when none applies.</summary>
    public string? NoProxy { get; init; }

    /// <summary>
    /// Human-readable advisory warning (e.g. unencrypted-HTTP auth, unreachable
    /// proxy, CIDR no_proxy). Logged but never fatal. Null when no advisory.
    /// </summary>
    public string? Warning { get; init; }
}
