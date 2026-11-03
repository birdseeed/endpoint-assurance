using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Xunit;

namespace Patched.Verifier.Tests;

/// <summary>
/// Regression tests for PAT-823: publisher DN parsing must not truncate comma-containing
/// Organization names, and must agree exactly with the CI-side parser
/// (ci/mirror_pipeline_windows.py:_extract_publisher) so the same certificate yields the
/// same canonical publisher string on both sides of the Windows mirror pipeline.
///
/// Real code-signing certs routinely embed a comma inside O/CN (Delaware/California
/// corporate suffixes), quoted precisely because the comma would otherwise be read as the
/// RDN separator, e.g.:
///   O="Zoom Video Communications, Inc."
///   O="Slack Technologies, LLC"
/// </summary>
public sealed class AuthenticodeVerifierDnParsingTests
{
    private const string ZoomSubject =
        "CN=\"Zoom Video Communications, Inc.\", O=\"Zoom Video Communications, Inc.\", " +
        "L=San Jose, S=California, C=US";

    private const string SlackSubject =
        "CN=\"Slack Technologies, LLC\", O=\"Slack Technologies, LLC\", " +
        "L=San Francisco, S=California, C=US";

    // A spoofed cert whose O merely contains the real publisher name as a substring.
    private const string SpoofSubject =
        "CN=\"Evil Zoom Video Communications, Inc.\", O=\"Evil Zoom Video Communications, Inc.\", C=US";

    [Fact]
    public void ExtractOrganization_PreservesEmbeddedComma_AndStripsQuotes()
    {
        var name = new X500DistinguishedName(ZoomSubject);
        var org = AuthenticodeVerifier.ExtractOrganization(name);
        Assert.Equal("Zoom Video Communications, Inc.", org);
    }

    [Fact]
    public void ExtractCommonName_PreservesEmbeddedComma_AndStripsQuotes()
    {
        var name = new X500DistinguishedName(SlackSubject);
        var cn = AuthenticodeVerifier.ExtractCommonName(name);
        Assert.Equal("Slack Technologies, LLC", cn);
    }

    [Fact]
    public void ExactEquality_MatchesGenuinePublisher()
    {
        var name = new X500DistinguishedName(ZoomSubject);
        var actual = AuthenticodeVerifier.ExtractOrganization(name);
        const string expectedPublisher = "Zoom Video Communications, Inc.";

        Assert.Equal(expectedPublisher, actual, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void ExactEquality_RejectsSpoofedPublisher_DespiteSharedSuffix()
    {
        // AuthenticodeVerifier.Verify compares with string.Equals(..., OrdinalIgnoreCase) —
        // exact equality, never Contains/StartsWith. A spoofed org name that merely contains
        // the real publisher as a substring must not be treated as a match.
        var name = new X500DistinguishedName(SpoofSubject);
        var actual = AuthenticodeVerifier.ExtractOrganization(name);
        const string expectedPublisher = "Zoom Video Communications, Inc.";

        Assert.NotNull(actual);
        Assert.Contains(expectedPublisher, actual); // substring relationship exists...
        Assert.False(
            string.Equals(actual, expectedPublisher, StringComparison.OrdinalIgnoreCase),
            "spoofed publisher must not exact-match the real publisher");
    }

    /// <summary>Replicates the pre-fix ExtractOrganization exactly, for regression comparison.</summary>
    private static string? OldNaiveExtractOrganization(string subject)
    {
        foreach (var part in subject.Split(','))
        {
            var kv = part.Trim().Split('=', 2);
            if (kv.Length == 2 && string.Equals(kv[0].Trim(), "O", StringComparison.OrdinalIgnoreCase))
                return kv[1].Trim();
        }
        return null;
    }

    [Fact]
    public void PreExistingBug_NaiveCommaSplit_TruncatesAndKeepsQuote()
    {
        var naive = OldNaiveExtractOrganization(ZoomSubject);
        Assert.NotNull(naive);
        Assert.DoesNotContain("Inc.", naive); // truncated before reaching "Inc."
        Assert.StartsWith("\"", naive);       // and never stripped the surrounding quote

        var name = new X500DistinguishedName(ZoomSubject);
        var fixedOrg = AuthenticodeVerifier.ExtractOrganization(name);

        Assert.Equal("Zoom Video Communications, Inc.", fixedOrg);
        Assert.NotEqual(naive, fixedOrg);
    }

    /// <summary>
    /// Re-implements ci/mirror_pipeline_windows.py:_extract_publisher's regex
    /// (<c>(?:^|,)\s*{key}=("(?:[^"]*)"|[^,]+)</c> for key in "O" then "CN", followed by
    /// <c>.strip('"')</c>) so parity with the .NET extraction can be asserted directly,
    /// rather than merely documented.
    /// </summary>
    private static string? CiStyleExtractPublisher(string subject)
    {
        foreach (var key in new[] { "O", "CN" })
        {
            var match = Regex.Match(subject, $@"(?:^|,)\s*{key}=(""(?:[^""]*)""|[^,]+)");
            if (match.Success)
                return match.Groups[1].Value.Trim().Trim('"');
        }
        return null;
    }

    [Theory]
    [InlineData(ZoomSubject)]
    [InlineData(SlackSubject)]
    [InlineData(SpoofSubject)]
    public void AgentExtraction_MatchesCiExtraction_ForSameSubject(string subject)
    {
        var name = new X500DistinguishedName(subject);
        var agentValue = AuthenticodeVerifier.ExtractOrganization(name)
            ?? AuthenticodeVerifier.ExtractCommonName(name);
        var ciValue = CiStyleExtractPublisher(subject);

        Assert.Equal(ciValue, agentValue);
    }
}
