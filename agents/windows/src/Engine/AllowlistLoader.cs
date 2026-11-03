using System.Text.Json;
using Microsoft.Extensions.Logging;
using Patched.Shared.Config;
using Patched.Shared.Contract;
using Patched.Shared.Paths;

namespace Patched.Engine;

/// <summary>
/// Loads and caches the curated Windows allowlist from
/// %ProgramData%\Patched\windows-allowlist.json.
/// Equivalent to reading labels-allowlist.txt on macOS, but JSON-structured.
/// The allowlist is the ONLY source of package IDs the engine will touch.
/// </summary>
public sealed class AllowlistLoader
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly ILogger<AllowlistLoader> _log;
    private readonly string                    _filePath;
    private IReadOnlyList<WindowsAllowlistEntry>? _entries;
    private HashSet<string>?                       _wingetIds;

    public AllowlistLoader(ILogger<AllowlistLoader> log)
        : this(log, PathConstants.AllowlistFile) { }

    /// <summary>Constructor for testing with an explicit file path.</summary>
    public AllowlistLoader(ILogger<AllowlistLoader> log, string filePath)
    {
        _log      = log;
        _filePath = filePath;
    }

    public IReadOnlyList<WindowsAllowlistEntry> Entries => _entries ??= Load();

    public bool IsAllowlisted(string wingetId) =>
        (_wingetIds ??= Entries
            .Select(e => e.WingetId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase))
        .Contains(wingetId);

    public WindowsAllowlistEntry? FindByWingetId(string wingetId) =>
        Entries.FirstOrDefault(e =>
            string.Equals(e.WingetId, wingetId, StringComparison.OrdinalIgnoreCase));

    public WindowsAllowlistEntry? FindByLabel(string label) =>
        Entries.FirstOrDefault(e =>
            string.Equals(e.Label, label, StringComparison.OrdinalIgnoreCase));

    private IReadOnlyList<WindowsAllowlistEntry> Load()
    {
        var path = _filePath;
        if (!File.Exists(path))
        {
            _log.LogWarning("Allowlist not found at {Path}; using empty list", path);
            return [];
        }

        try
        {
            var rawBytes = File.ReadAllBytes(path);
            if (!VerifySignature(path, rawBytes))
            {
                // Fail closed: with no valid signature we refuse to load any
                // package IDs, so the engine manages nothing rather than trusting
                // a potentially attacker-supplied allowlist.
                return [];
            }
            var list = JsonSerializer.Deserialize<List<WindowsAllowlistEntry>>(
                           (ReadOnlySpan<byte>)rawBytes, JsonOpts)
                       ?? throw new InvalidOperationException("Allowlist deserialised to null");
            _log.LogInformation("Loaded {Count} allowlisted packages from {Path}", list.Count, path);
            return list;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to load allowlist from {Path}", path);
            throw;
        }
    }

    // Returns true only if the allowlist carries a valid Ed25519 signature.
    // A MISSING .sig is fail-closed (returns false → empty allowlist) unless the
    // explicit dev opt-out PATCHED_ALLOW_UNSIGNED_ALLOWLIST=1 is set. A PRESENT
    // but invalid/tampered signature always throws (active-tamper signal).
    private bool VerifySignature(string path, byte[] rawBytes)
    {
        var sigPath = path + ".sig";
        if (!File.Exists(sigPath))
        {
            if (string.Equals(
                    Environment.GetEnvironmentVariable("PATCHED_ALLOW_UNSIGNED_ALLOWLIST"),
                    "1", StringComparison.Ordinal))
            {
                _log.LogWarning(
                    "PATCHED_POSTURE_WARNING reason=allowlist_unsigned_dev_optout path={Path}", path);
                return true;
            }
            _log.LogError(
                "PATCHED_ALLOWLIST_TAMPER_DETECTED path={Path} reason=missing_signature — " +
                "refusing to load (empty allowlist). Sign the allowlist or set " +
                "PATCHED_ALLOW_UNSIGNED_ALLOWLIST=1 for local dev.",
                path);
            return false;
        }

        byte[] sig;
        try
        {
            sig = Convert.FromBase64String(File.ReadAllText(sigPath).Trim());
        }
        catch (FormatException)
        {
            _log.LogError("PATCHED_ALLOWLIST_TAMPER_DETECTED path={Path} reason=sig_not_valid_base64", path);
            throw new InvalidOperationException($"Allowlist signature at '{sigPath}' is not valid base64");
        }

        if (!AllowlistSignatureVerifier.Verify(rawBytes, sig))
        {
            _log.LogError("PATCHED_ALLOWLIST_TAMPER_DETECTED path={Path} reason=sig_verification_failed", path);
            throw new InvalidOperationException(
                $"Allowlist Ed25519 signature verification failed — '{path}' may be tampered");
        }

        _log.LogInformation("Allowlist signature verified for {Path}", path);
        return true;
    }
}
