namespace Patched.Service;

/// <summary>
/// PAT-1260: the "patched" and "patched-artifact" named HttpClients registered in
/// Program.cs share every other setting (base address, user agent, proxy
/// resolution via DynamicWebProxy, the DeviceIdentityHandler) but MUST carry
/// different <see cref="HttpClient.Timeout"/> values.
///
/// HttpClient.Timeout bounds the WHOLE operation, including reading the
/// response body, even under HttpCompletionOption.ResponseHeadersRead — the
/// timeout's linked CancellationTokenSource stays attached to the response
/// stream for its entire lifetime. "patched" is deliberately short (right for
/// the envelope fetch, inventory, provenance, and every other small JSON call
/// on it), but reusing it for the artifact byte download demanded upload/
/// download rates no ordinary endpoint connection can sustain — the whole
/// point of PAT-1260 is that self-update actually works on a real endpoint,
/// so a client whose timeout guarantees it can't is the same "correct-looking
/// change that could never work" failure this ticket exists to fix.
///
/// Centralised as named constants — rather than inlined literals at each
/// AddHttpClient call site — so a unit test can assert the actual configured
/// values directly (BootstrapUpdaterTests / this class's own tests) without
/// standing up the full Windows-service DI host to do it.
/// </summary>
internal static class PatchedHttpClientTimeouts
{
    /// <summary>Small JSON calls: envelope fetch, inventory, provenance, agent-config, etc.</summary>
    public static readonly TimeSpan Default = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The artifact byte download only. The MSI is ~160 MB; 30 minutes tolerates
    /// a genuinely poor ~89 KB/s sustained transfer for the full file while still
    /// guaranteeing the service can never hang forever on a dead peer — bounded,
    /// just not so tight it fails on an ordinary connection.
    /// </summary>
    public static readonly TimeSpan Artifact = TimeSpan.FromMinutes(30);
}
