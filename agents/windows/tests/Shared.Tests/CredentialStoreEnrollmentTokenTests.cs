using Patched.Shared.Auth;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1203: tests for RefreshEnrollmentToken() — the seam that lets a
/// running instance notice an admin dropping a FRESH single-use enrollment
/// token after a terminal 410/401 from /v1/enrol, without a full service
/// restart. EnrollmentToken is otherwise only ever read once, at
/// CredentialStore construction (LoadForStartup); nothing re-reads disk /
/// Credential Manager / registry afterward, so a device that hit terminal
/// enrollment failure could never see a corrected token land.
///
/// Instances are built via CredentialStore.CreateForTests(...), extended by
/// this ticket with a `bearerToken` override (defaults to the pre-existing
/// "test-bearer" placeholder so every prior call site is unaffected; these
/// tests pass "" to model an enrollment-pending device) and an
/// `enrollmentTokenSource` override — a closure the test controls directly,
/// so no real Windows Credential Manager / %ProgramData%\Patched\creds /
/// registry read ever happens here, same isolation rule
/// CredentialStoreSuspendedTests already follows.
/// </summary>
public sealed class CredentialStoreEnrollmentTokenTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _suspendedFile;

    public CredentialStoreEnrollmentTokenTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-creds-enroltoken-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _suspendedFile = Path.Combine(_tempDir, "suspended");
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup; a leftover temp dir from a test run isn't worth failing over.
        }
    }

    [Fact]
    public void RefreshEnrollmentToken_NoTokenAvailable_ReturnsFalse_LeavesEnrollmentTokenNull()
    {
        var store = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", enrollmentTokenSource: () => null);

        var changed = store.RefreshEnrollmentToken();

        Assert.False(changed);
        Assert.Null(store.EnrollmentToken);
    }

    [Fact]
    public void RefreshEnrollmentToken_NewTokenAvailable_ReturnsTrue_UpdatesEnrollmentToken()
    {
        var store = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", enrollmentTokenSource: () => "fresh-token-123");

        var changed = store.RefreshEnrollmentToken();

        Assert.True(changed);
        Assert.Equal("fresh-token-123", store.EnrollmentToken);
    }

    [Fact]
    public void RefreshEnrollmentToken_SameTokenAsBefore_ReturnsFalse_DoesNotSignalRetry()
    {
        // Simulates the exact failure mode this ticket exists to avoid: a
        // device rejected once for a token should not be told "there's
        // something new to try" on every subsequent recheck of the SAME
        // still-bad token — that would just repeat the identical 410/401
        // forever (the bug flagged in macOS's patched-enroll.sh, PAT-1203).
        var store = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", enrollmentTokenSource: () => "rejected-token");

        var first = store.RefreshEnrollmentToken();
        Assert.True(first);
        Assert.Equal("rejected-token", store.EnrollmentToken);

        var second = store.RefreshEnrollmentToken();

        Assert.False(second);
        Assert.Equal("rejected-token", store.EnrollmentToken); // unchanged
    }

    [Fact]
    public void RefreshEnrollmentToken_TokenChangesAfterRejection_ReturnsTrue_PicksUpNewValue()
    {
        // The real recovery scenario: the token that was rejected is still
        // sitting on disk on the first few rechecks, then an admin drops a
        // genuinely different one.
        var current = "rejected-token";
        var store = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", enrollmentTokenSource: () => current);

        Assert.True(store.RefreshEnrollmentToken());
        Assert.False(store.RefreshEnrollmentToken()); // still the same rejected token — no signal

        current = "brand-new-token-456";
        var changed = store.RefreshEnrollmentToken();

        Assert.True(changed);
        Assert.Equal("brand-new-token-456", store.EnrollmentToken);
    }

    [Fact]
    public void RefreshEnrollmentToken_EmptyStringSource_TreatedAsNoTokenAvailable()
    {
        var store = CredentialStore.CreateForTests(_suspendedFile, bearerToken: "", enrollmentTokenSource: () => "");

        var changed = store.RefreshEnrollmentToken();

        Assert.False(changed);
        Assert.Null(store.EnrollmentToken);
    }

    [Fact]
    public void RefreshEnrollmentToken_BearerTokenAlreadyPresent_NeverConsultsSource_ReturnsFalse()
    {
        // An already-enrolled device (including one suspended later by a
        // REVOCATION, which is unrelated to the enrollment token) has
        // nothing to refresh. Proven by making the source throw if it is
        // ever invoked — the bearer-token guard must short-circuit before
        // that call.
        var store = CredentialStore.CreateForTests(
            _suspendedFile,
            bearerToken: "already-enrolled-bearer-token",
            enrollmentTokenSource: () => throw new InvalidOperationException(
                "RefreshEnrollmentToken must not consult the token source once BearerToken is set"));

        var changed = store.RefreshEnrollmentToken();

        Assert.False(changed);
    }

    [Fact]
    public void RefreshEnrollmentToken_DefaultCreateForTestsOverload_StillHasTestBearerToken()
    {
        // Backward-compatibility guard: every pre-existing CreateForTests(path)
        // call site across the test suite must keep behaving exactly as
        // before this ticket's new optional parameters were added.
        var store = CredentialStore.CreateForTests(_suspendedFile);

        Assert.Equal("test-bearer", store.BearerToken);
        Assert.False(store.RefreshEnrollmentToken()); // bearer present -> no-op, as above
    }
}
