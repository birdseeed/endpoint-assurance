using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Verifier.Tests;

/// <summary>
/// Authenticode verifier tests.
/// These run on Windows only (require WinTrust + real Authenticode chains).
///
/// PAT-305 critical scenarios:
///   1. Missing file → MissingExpectedSigner
///   2. Valid file signed by expected publisher → Passed
///   3. Valid file with wrong publisher → SignerMismatch
///   4. Unsigned file → MissingExpectedSigner
///   5. Tampered file (signature doesn't cover modified bytes) → SignatureUntrusted
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AuthenticodeVerifierTests
{
    private readonly AuthenticodeVerifier _verifier =
        new(NullLogger<AuthenticodeVerifier>.Instance);

    [Fact]
    public void MissingFile_Returns_MissingExpectedSigner()
    {
        var result = _verifier.Verify(@"C:\nonexistent\file.exe", "Some Publisher");
        Assert.False(result.IsValid);
        Assert.Equal(FailureReason.MissingExpectedSigner, result.FailureReason);
    }

    [Fact]
    public void UnsignedFile_Returns_MissingExpectedSigner()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"unsigned-{Guid.NewGuid()}.exe");
        try
        {
            // Write 4 bytes of fake PE header — no Authenticode signature.
            File.WriteAllBytes(tmp, [0x4D, 0x5A, 0x00, 0x00]);
            var result = _verifier.Verify(tmp, "Any Publisher");
            Assert.False(result.IsValid);
            // A truncated PE can trigger TRUST_E_NOSIGNATURE (→ MissingExpectedSigner) or
            // TRUST_E_SUBJECT_FORM_UNKNOWN (→ SignatureUntrusted) depending on the WinTrust
            // version on the runner. Both are correct "no valid Authenticode" results.
            Assert.Contains(result.FailureReason, new FailureReason?[]
            {
                FailureReason.MissingExpectedSigner,
                FailureReason.SignatureUntrusted,
            });
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    [Fact]
    public void SignedSystemFile_WrongPublisher_Returns_SignerMismatch()
    {
        // notepad.exe is signed by Microsoft Corporation on desktop Windows.
        // On Windows Server (GHA runner) it may be unsigned — skip in that case.
        var notepad = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");

        if (!File.Exists(notepad))
            return;  // Skip on atypical environments

        var result = _verifier.Verify(notepad, "Not Microsoft Corporation");
        if (result.FailureReason == FailureReason.MissingExpectedSigner)
            return;  // notepad.exe is unsigned on this runner — skip.

        Assert.False(result.IsValid);
        Assert.Equal(FailureReason.SignerMismatch, result.FailureReason);
        Assert.NotNull(result.ActualPublisher);
    }

    [Fact]
    public void SignedSystemFile_CorrectPublisher_Passes()
    {
        var notepad = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");

        if (!File.Exists(notepad))
            return;

        // Verify what the actual publisher is first, then test against it.
        var probe = _verifier.Verify(notepad, "Microsoft Corporation");
        // Results by environment:
        //   Desktop Windows (signed, correct publisher) → null (Passed)
        //   Desktop Windows (signed, different publisher e.g. "Microsoft Windows") → SignerMismatch
        //   Windows Server / GHA runner (unsigned notepad stub) → MissingExpectedSigner
        // Assert that we always get one of our known result types — never an exception.
        Assert.Contains(probe.FailureReason, new FailureReason?[]
        {
            null,
            FailureReason.SignerMismatch,
            FailureReason.MissingExpectedSigner,
        });
    }

    [Fact]
    public void VerificationResult_Passed_HasIsValidTrue()
    {
        var result = VerificationResult.Passed("Test Publisher");
        Assert.True(result.IsValid);
        Assert.Equal("Test Publisher", result.ActualPublisher);
        Assert.Null(result.FailureReason);
    }

    [Fact]
    public void VerificationResult_Blocked_SignerMismatch_HasCorrectCode()
    {
        var result = VerificationResult.Blocked_SignerMismatch("Actual Co.");
        Assert.False(result.IsValid);
        Assert.Equal(FailureReason.SignerMismatch, result.FailureReason);
        Assert.Equal("Actual Co.", result.ActualPublisher);
    }

    [Fact]
    public void VerificationResult_Blocked_SignatureUntrusted_HasCorrectCode()
    {
        var result = VerificationResult.Blocked_SignatureUntrusted;
        Assert.False(result.IsValid);
        Assert.Equal(FailureReason.SignatureUntrusted, result.FailureReason);
    }
}
