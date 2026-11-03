using Patched.Shared.Contract;
using FR = Patched.Shared.Contract.FailureReason;

namespace Patched.Verifier;

/// <summary>
/// Result of an Authenticode verification.
/// Maps to the failure_reason codes in contracts/update-status.schema.json.
/// </summary>
public sealed record VerificationResult
{
    public bool           IsValid         { get; init; }
    public string?        ActualPublisher { get; init; }
    public FailureReason? FailureReason   { get; init; }
    public string?        Detail          { get; init; }

    public static readonly VerificationResult Blocked_MissingExpectedSigner =
        new() { IsValid = false, FailureReason = FR.MissingExpectedSigner };

    public static readonly VerificationResult Blocked_SignatureUntrusted =
        new() { IsValid = false, FailureReason = FR.SignatureUntrusted };

    public static VerificationResult Blocked_SignerMismatch(string actualPublisher) =>
        new() { IsValid = false, FailureReason = FR.SignerMismatch,
                ActualPublisher = actualPublisher };

    public static VerificationResult Passed(string publisher) =>
        new() { IsValid = true, ActualPublisher = publisher };
}
