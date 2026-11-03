using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Engine.Tests;

/// <summary>
/// Platform-neutral tests for ChocolateyEngine helpers.
/// InstallAsync / CheckAsync are not tested here — they require choco.exe on Windows.
///
/// Joins <see cref="AllowlistTestCollection"/> because one test mutates the
/// process-global PATCHED_ALLOW_UNSIGNED_ALLOWLIST env var (PAT-687).
/// </summary>
[Collection(AllowlistTestCollection.Name)]
public sealed class ChocolateyEngineTests : IDisposable
{
    private readonly string _tempDir;

    public ChocolateyEngineTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-chocotest-{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public void ComputeSha256_KnownContent_ReturnsCorrectHash()
    {
        var file    = Path.Combine(_tempDir, "test.bin");
        var content = Encoding.UTF8.GetBytes("patched-sha256-test");
        File.WriteAllBytes(file, content);

        var expected = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
        var actual   = ChocolateyEngine.ComputeSha256(file);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ComputeSha256_EmptyFile_ReturnsEmptyFileHash()
    {
        var file = Path.Combine(_tempDir, "empty.bin");
        File.WriteAllBytes(file, []);

        var expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        Assert.Equal(expected, ChocolateyEngine.ComputeSha256(file));
    }

    [Fact]
    public void ComputeSha256_ResultIsLowercase()
    {
        var file = Path.Combine(_tempDir, "case.bin");
        File.WriteAllBytes(file, [0xDE, 0xAD, 0xBE, 0xEF]);

        var hash = ChocolateyEngine.ComputeSha256(file);
        Assert.Equal(hash, hash.ToLowerInvariant());
    }

    [Fact]
    public void WindowsAllowlistEntry_PinnedSha256_RoundTripsJson()
    {
        const string json = """
            [{
              "label": "zoom",
              "name": "Zoom",
              "winget_id": "Zoom.Zoom",
              "expected_publisher": "Zoom Video Communications, Inc.",
              "pinned_sha256": "abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef567890"
            }]
            """;

        var entries = JsonSerializer.Deserialize<WindowsAllowlistEntry[]>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        Assert.NotNull(entries);
        Assert.Single(entries!);
        Assert.Equal("abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef567890",
            entries![0].PinnedSha256);
    }

    [Fact]
    public void WindowsAllowlistEntry_NoPinnedSha256_DeserializesAsNull()
    {
        const string json = """
            [{
              "label": "slack",
              "name": "Slack",
              "winget_id": "SlackTechnologies.Slack",
              "expected_publisher": "Slack Technologies, LLC"
            }]
            """;

        var entries = JsonSerializer.Deserialize<WindowsAllowlistEntry[]>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        Assert.NotNull(entries);
        Assert.Null(entries![0].PinnedSha256);
    }

    [Fact]
    public void AllowlistLoader_EntryWithPinnedSha256_FindByWingetId_ReturnsPinnedSha256()
    {
        var path = Path.Combine(_tempDir, "allowlist.json");
        var entries = new[]
        {
            new WindowsAllowlistEntry
            {
                Label             = "zoom",
                Name              = "Zoom",
                WingetId          = "Zoom.Zoom",
                ExpectedPublisher = "Zoom Video Communications, Inc.",
                PinnedSha256      = "deadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233",
            },
        };
        File.WriteAllText(path, JsonSerializer.Serialize(entries));

        // Unsigned fixture: load under the documented dev opt-out (#188 fail-closed).
        var loader = new AllowlistLoader(NullLogger<AllowlistLoader>.Instance, path);
        using var _ = new UnsignedAllowlistScope();
        var found  = loader.FindByWingetId("Zoom.Zoom");

        Assert.NotNull(found);
        Assert.Equal("deadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233",
            found!.PinnedSha256);
    }

    public void Dispose() => Directory.Delete(_tempDir, recursive: true);
}
