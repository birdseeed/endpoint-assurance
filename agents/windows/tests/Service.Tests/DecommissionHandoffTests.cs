using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1110. <see cref="DecommissionHandoff"/> itself is NOT independently unit
/// testable — registering/querying/deleting a real Windows scheduled task requires
/// a live Task Scheduler service (Windows-only, admin-only); see its own class doc
/// comment. This covers the one piece of it that IS pure logic:
/// <see cref="DecommissionHandoff.ClassifyQueryResult"/>, split out specifically so
/// the exit-code/message classification could be proven here without a real
/// schtasks.exe process.
///
/// Non-author review round 2 (item 4): the regression this file exists to prevent —
/// treating every nonzero <c>schtasks /Query</c> exit as "task absent" would let
/// <see cref="DecommissionHandoff.EnsureDeregistered"/> delete the report-creds
/// snapshot while an ONSTART-triggered removal task might still be fully armed (an
/// access-denied or Task-Scheduler-service error is also a nonzero exit, and is NOT
/// the same fact as "no task with this name exists").
/// </summary>
public class DecommissionHandoffTests
{
    [Fact]
    public void ClassifyQueryResult_ExitZero_IsPresent()
    {
        var result = DecommissionHandoff.ClassifyQueryResult(0, "");
        Assert.Equal(DecommissionHandoff.TaskQueryResult.Present, result);
    }

    [Fact]
    public void ClassifyQueryResult_KnownNotFoundMessage_IsAbsent()
    {
        // schtasks' well-known English-locale "not found" message.
        var result = DecommissionHandoff.ClassifyQueryResult(
            1, "ERROR: The system cannot find the file specified.");
        Assert.Equal(DecommissionHandoff.TaskQueryResult.Absent, result);
    }

    [Fact]
    public void ClassifyQueryResult_KnownNotFoundMessage_IsCaseInsensitive()
    {
        var result = DecommissionHandoff.ClassifyQueryResult(
            1, "error: the system CANNOT FIND THE FILE SPECIFIED.");
        Assert.Equal(DecommissionHandoff.TaskQueryResult.Absent, result);
    }

    // -------------------------------------------------------------------------
    // THE regression this file exists to prove: a nonzero exit for any OTHER
    // reason must NOT be read as "absent" — round-2 non-author review item 4.
    // -------------------------------------------------------------------------
    [Theory]
    [InlineData("ERROR: Access is denied.")]
    [InlineData("ERROR: The Task Scheduler service is not running.")]
    [InlineData("")] // malformed/empty output alongside a nonzero exit
    [InlineData("some completely unrecognised message")]
    public void ClassifyQueryResult_NonzeroExitForAnyOtherReason_IsUnknown_NeverAbsent(string stderr)
    {
        var result = DecommissionHandoff.ClassifyQueryResult(1, stderr);
        Assert.Equal(DecommissionHandoff.TaskQueryResult.Unknown, result);
        Assert.NotEqual(DecommissionHandoff.TaskQueryResult.Absent, result);
    }

    [Fact]
    public void ClassifyQueryResult_NonzeroExitDifferentCode_StillClassifiedByMessageNotCode()
    {
        // The exit code itself beyond "zero vs nonzero" carries no meaning here —
        // only the message decides Absent vs Unknown for a nonzero exit.
        var absent = DecommissionHandoff.ClassifyQueryResult(1, "ERROR: The system cannot find the file specified.");
        var unknown = DecommissionHandoff.ClassifyQueryResult(87, "ERROR: Access is denied.");

        Assert.Equal(DecommissionHandoff.TaskQueryResult.Absent, absent);
        Assert.Equal(DecommissionHandoff.TaskQueryResult.Unknown, unknown);
    }

    // -------------------------------------------------------------------------
    // Non-author review (P0): WriteReportCredsSnapshot (private, and — like the
    // rest of this class — not independently unit-testable behind a live Windows
    // host) now DPAPI-protects the bearer token/HMAC secret snapshot at
    // DataProtectionScope.LocalMachine before writing it, matching the
    // protection level CredentialStore already gives these same secrets via
    // Windows Credential Manager, instead of relying on the decommission
    // directory's ACLs alone. This proves the underlying Protect/Unprotect
    // contract this class and DecommissionHandoffScript's generated PowerShell
    // both rely on actually round-trips under the SAME scope the detached
    // script uses (LocalMachine, not CurrentUser — the script runs as SYSTEM
    // via the scheduled task, not as whichever user was logged in when the
    // service staged the file). Only meaningful on a real Windows host — DPAPI
    // throws PlatformNotSupportedException elsewhere — so this no-ops on the
    // non-Windows dev/CI hosts this test project otherwise builds and runs on,
    // and actually executes on the windows-latest CI runner (windows-build.yml).
    // -------------------------------------------------------------------------
    [Fact]
    public void DpapiProtectUnprotect_LocalMachineScope_RoundTrips()
    {
        if (!OperatingSystem.IsWindows()) return;

        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes(
            "{\"api_url\":\"https://example.test\",\"bearer_token\":\"tok\",\"hmac_secret\":\"c2VjcmV0\"}");

        byte[] encrypted = System.Security.Cryptography.ProtectedData.Protect(
            plaintext, optionalEntropy: null, System.Security.Cryptography.DataProtectionScope.LocalMachine);

        // The encrypted form must not just be the plaintext bytes passed through —
        // proves this is actually going through DPAPI, not a no-op.
        Assert.NotEqual(plaintext, encrypted);

        byte[] decrypted = System.Security.Cryptography.ProtectedData.Unprotect(
            encrypted, optionalEntropy: null, System.Security.Cryptography.DataProtectionScope.LocalMachine);

        Assert.Equal(plaintext, decrypted);
    }
}
