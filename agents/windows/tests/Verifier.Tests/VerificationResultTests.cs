using Patched.Shared.Contract;
using Patched.Verifier;
using Xunit;

namespace Patched.Verifier.Tests;

/// <summary>
/// Tests for VerificationResult factory methods and failure_reason mapping (PAT-305).
/// Does not invoke WinVerifyTrust — verifies the result shape only.
/// </summary>
public sealed class VerificationResultTests
{
    [Fact]
    public void Passed_IsValid_WithPublisher()
    {
        var result = VerificationResult.Passed("Google LLC");
        Assert.True(result.IsValid);
        Assert.Equal("Google LLC", result.ActualPublisher);
        Assert.Null(result.FailureReason);
    }

    [Fact]
    public void Blocked_MissingExpectedSigner_HasCorrectCode()
    {
        var result = VerificationResult.Blocked_MissingExpectedSigner;
        Assert.False(result.IsValid);
        Assert.Equal(FailureReason.MissingExpectedSigner, result.FailureReason);
        Assert.Null(result.ActualPublisher);
    }

    [Fact]
    public void Blocked_SignatureUntrusted_HasCorrectCode()
    {
        var result = VerificationResult.Blocked_SignatureUntrusted;
        Assert.False(result.IsValid);
        Assert.Equal(FailureReason.SignatureUntrusted, result.FailureReason);
    }

    [Fact]
    public void Blocked_SignerMismatch_IncludesActualPublisher()
    {
        var result = VerificationResult.Blocked_SignerMismatch("Evil Corp");
        Assert.False(result.IsValid);
        Assert.Equal(FailureReason.SignerMismatch, result.FailureReason);
        Assert.Equal("Evil Corp", result.ActualPublisher);
    }

    [Fact]
    public void WithDetail_PreservesOtherFields()
    {
        // Verify the 'with' expression on the immutable record works correctly.
        var base_ = VerificationResult.Blocked_MissingExpectedSigner;
        var result = base_ with { Detail = "File not found: C:\\foo.exe" };

        Assert.False(result.IsValid);
        Assert.Equal(FailureReason.MissingExpectedSigner, result.FailureReason);
        Assert.Equal("File not found: C:\\foo.exe", result.Detail);
    }

    [Fact]
    public void SignerMismatch_MapsToContractFailureReason()
    {
        // The FailureReason enum value must match the contract spec
        // (serialised as "signer_mismatch" by ContractJsonOptions).
        var result = VerificationResult.Blocked_SignerMismatch("Attacker Inc");
        Assert.Equal(FailureReason.SignerMismatch, result.FailureReason);
    }

    [Fact]
    public void AllThreeBlockedVariants_AreNotValid()
    {
        VerificationResult[] blocked =
        [
            VerificationResult.Blocked_MissingExpectedSigner,
            VerificationResult.Blocked_SignatureUntrusted,
            VerificationResult.Blocked_SignerMismatch("x"),
        ];
        Assert.All(blocked, r => Assert.False(r.IsValid));
    }
}
