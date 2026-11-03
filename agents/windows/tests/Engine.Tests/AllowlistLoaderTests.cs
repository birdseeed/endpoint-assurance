using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Engine.Tests;

/// <summary>
/// Tests AllowlistLoader in isolation using a temp file.
/// Platform-neutral: no Windows APIs involved.
///
/// The fixtures here are UNSIGNED (no .sig). Since #188 the loader fails closed on
/// an unsigned allowlist, so parse/lookup tests trigger the (lazy) load inside an
/// <see cref="UnsignedAllowlistScope"/> that sets the documented dev opt-out and
/// restores it afterwards. This class joins <see cref="AllowlistTestCollection"/>
/// so it never runs in parallel with other env-mutating allowlist tests (PAT-687).
/// </summary>
[Collection(AllowlistTestCollection.Name)]
public sealed class AllowlistLoaderTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _allowlistPath;

    public AllowlistLoaderTests()
    {
        _tempDir       = Path.Combine(Path.GetTempPath(), $"patched-test-{Guid.NewGuid()}");
        _allowlistPath = Path.Combine(_tempDir, "windows-allowlist.json");
        Directory.CreateDirectory(_tempDir);
    }

    /// <summary>Writes an UNSIGNED allowlist fixture and returns a loader for it.</summary>
    private AllowlistLoader LoaderWith(WindowsAllowlistEntry[] entries)
    {
        File.WriteAllText(_allowlistPath, JsonSerializer.Serialize(entries));
        return new AllowlistLoader(NullLogger<AllowlistLoader>.Instance, _allowlistPath);
    }

    [Fact]
    public void Load_ValidAllowlist_ReturnsAllEntries()
    {
        var loader = LoaderWith(SampleEntries());
        using var _ = new UnsignedAllowlistScope();
        Assert.Equal(2, loader.Entries.Count);
    }

    [Fact]
    public void IsAllowlisted_KnownWingetId_ReturnsTrue()
    {
        var loader = LoaderWith(SampleEntries());
        using var _ = new UnsignedAllowlistScope();
        Assert.True(loader.IsAllowlisted("Google.Chrome"));
    }

    [Fact]
    public void IsAllowlisted_UnknownId_ReturnsFalse()
    {
        var loader = LoaderWith(SampleEntries());
        using var _ = new UnsignedAllowlistScope();
        Assert.False(loader.IsAllowlisted("SomeMalicious.Package"));
    }

    [Fact]
    public void IsAllowlisted_CaseInsensitive()
    {
        var loader = LoaderWith(SampleEntries());
        using var _ = new UnsignedAllowlistScope();
        Assert.True(loader.IsAllowlisted("google.chrome"));
        Assert.True(loader.IsAllowlisted("GOOGLE.CHROME"));
    }

    [Fact]
    public void FindByLabel_ReturnsCorrectEntry()
    {
        var loader = LoaderWith(SampleEntries());
        using var _ = new UnsignedAllowlistScope();
        var entry  = loader.FindByLabel("googlechrome");
        Assert.NotNull(entry);
        Assert.Equal("Google.Chrome", entry!.WingetId);
        Assert.Equal("Google LLC", entry.ExpectedPublisher);
    }

    [Fact]
    public void FindByLabel_MissingLabel_ReturnsNull()
    {
        var loader = LoaderWith(SampleEntries());
        using var _ = new UnsignedAllowlistScope();
        Assert.Null(loader.FindByLabel("nonexistent"));
    }

    [Fact]
    public void MissingFile_ReturnsEmptyList()
    {
        // A missing allowlist FILE returns empty before any signature check, so
        // this is independent of the opt-out.
        var loader = new AllowlistLoader(NullLogger<AllowlistLoader>.Instance,
            Path.Combine(_tempDir, "nonexistent.json"));
        Assert.Empty(loader.Entries);
    }

    [Fact]
    public void Load_EmptyArray_ReturnsEmpty()
    {
        // Empty-array JSON parses to an empty list. Load under the opt-out so this
        // exercises the parse path rather than the fail-closed path (which would
        // also return empty, for the wrong reason).
        File.WriteAllText(_allowlistPath, "[]");
        var loader = new AllowlistLoader(NullLogger<AllowlistLoader>.Instance, _allowlistPath);
        using var _ = new UnsignedAllowlistScope();
        Assert.Empty(loader.Entries);
    }

    [Fact]
    public void FindByWingetId_CaseInsensitive()
    {
        var loader = LoaderWith(SampleEntries());
        using var _ = new UnsignedAllowlistScope();
        var entry  = loader.FindByWingetId("slacktechnologies.slack");
        Assert.NotNull(entry);
        Assert.Equal("slack", entry!.Label);
    }

    // -------------------------------------------------------------------------
    // Fail-closed behaviour introduced by #188 (unsigned allowlist).
    // -------------------------------------------------------------------------

    [Fact]
    public void Load_NoSigFile_FailClosed_ReturnsEmpty()
    {
        // No .sig and NO dev opt-out → the loader refuses to load any entries.
        var loader = LoaderWith(SampleEntries());
        Assert.Empty(loader.Entries);
    }

    [Fact]
    public void Load_NoSigFile_DevOptOut_LoadsWithWarning()
    {
        // No .sig but the documented dev opt-out is set → entries load.
        var loader = LoaderWith(SampleEntries());
        using var _ = new UnsignedAllowlistScope();
        Assert.Equal(2, loader.Entries.Count);
    }

    [Fact]
    public void Load_InvalidBase64Sig_Throws()
    {
        // A PRESENT but malformed signature always throws, opt-out or not.
        File.WriteAllText(_allowlistPath, "[]");
        File.WriteAllText(_allowlistPath + ".sig", "this is not base64 !!!@#$");
        var loader = new AllowlistLoader(NullLogger<AllowlistLoader>.Instance, _allowlistPath);
        Assert.Throws<InvalidOperationException>(() => _ = loader.Entries);
    }

    [Fact]
    public void Load_AllZerosSig_Throws()
    {
        File.WriteAllText(_allowlistPath, "[]");
        File.WriteAllText(_allowlistPath + ".sig", Convert.ToBase64String(new byte[64]));
        var loader = new AllowlistLoader(NullLogger<AllowlistLoader>.Instance, _allowlistPath);
        Assert.Throws<InvalidOperationException>(() => _ = loader.Entries);
    }

    [Fact]
    public void Load_RandomSig_Throws()
    {
        File.WriteAllText(_allowlistPath, "[]");
        var rng = new byte[64];
        System.Security.Cryptography.RandomNumberGenerator.Fill(rng);
        File.WriteAllText(_allowlistPath + ".sig", Convert.ToBase64String(rng));
        var loader = new AllowlistLoader(NullLogger<AllowlistLoader>.Instance, _allowlistPath);
        Assert.Throws<InvalidOperationException>(() => _ = loader.Entries);
    }

    private static WindowsAllowlistEntry[] SampleEntries() =>
    [
        new() { Label = "googlechrome", Name = "Google Chrome",
                WingetId = "Google.Chrome", ExpectedPublisher = "Google LLC" },
        new() { Label = "slack",        Name = "Slack",
                WingetId = "SlackTechnologies.Slack", ExpectedPublisher = "Slack Technologies, LLC" },
    ];

    public void Dispose() => Directory.Delete(_tempDir, recursive: true);
}
