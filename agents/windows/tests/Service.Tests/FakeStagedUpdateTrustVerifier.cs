using Patched.Service;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2400: test double for the staged-update owner/DACL seam. The applier suites
/// stage into temp directories that carry the test user's own write ACE, which the
/// real verifier correctly refuses, so they hand the applier <see cref="Trusted"/>:
/// what a hardened staging tree looks like to the real verifier. It lives in the test
/// assembly only; PendingUpdateStagedTrustTests proves production never resolves it.
/// </summary>
internal sealed class FakeStagedUpdateTrustVerifier : IStagedUpdateTrustVerifier
{
    private readonly Dictionary<string, string> _untrusted = new(StringComparer.OrdinalIgnoreCase);

    internal static FakeStagedUpdateTrustVerifier Trusted() => new();

    /// <summary>Null: removal works. Otherwise the failure token removal reports.</summary>
    internal string? RemovalFailure { get; set; }
    internal List<string> Checked { get; } = [];
    internal List<string> Removed { get; } = [];

    internal FakeStagedUpdateTrustVerifier Untrusted(string path, string why)
    {
        _untrusted[Path.GetFullPath(path)] = why;
        return this;
    }

    internal void Trust(string path) => _untrusted.Remove(Path.GetFullPath(path));

    public string? WhyUntrusted(string path, bool isDirectory)
    {
        Checked.Add(Path.GetFullPath(path));
        if (_untrusted.TryGetValue(Path.GetFullPath(path), out var why)) return why;
        return (isDirectory ? Directory.Exists(path) : File.Exists(path)) ? null : "absent";
    }

    public string? Remove(string path, string quarantineParent)
    {
        Removed.Add(Path.GetFullPath(path));
        if (RemovalFailure is not null) return RemovalFailure;
        if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
        else File.Delete(path);
        _untrusted.Remove(Path.GetFullPath(path));
        return null;
    }
}
