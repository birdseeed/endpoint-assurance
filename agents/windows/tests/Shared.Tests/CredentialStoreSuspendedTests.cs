using Patched.Shared.Auth;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-1042: tests for ClearSuspended() — the self-clearing counterpart to
/// MarkSuspended()/IsSuspended added so a device the platform revokes (401)
/// and later reinstates (a signature-verified 200) returns to normal
/// automatically instead of staying suspended until someone deletes the
/// sentinel by hand.
///
/// Instances are built via CredentialStore.CreateForTests(path) — an
/// internal, always-compiled (not #if DEBUG) test-only factory that points
/// the instance's suspended-marker path at a scratch temp directory instead
/// of the real %ProgramData%\Patched\creds, and bypasses
/// CredentialStore.Load()/LoadForStartup() entirely (those P/Invoke Windows
/// Credential Manager via advapi32.dll with no non-Windows fallback, so they
/// cannot run on this platform-neutral test project's macOS/Linux CI
/// target). Round-2 non-author review on this ticket flagged an earlier
/// version of this test file, which redirected `internal static` mutable
/// fields on CredentialStore itself — a compiler-unenforced immutability
/// hole on the field that defines the entire revocation control. Those
/// fields are back to `private static readonly` in production; the
/// suspended-marker path is now `readonly` per instance, set once by
/// CreateForTests for tests and by the real constructor for everything else,
/// same rule SecureStagingDirectoryTests already follows of never touching
/// real system paths in a test run.
/// </summary>
public sealed class CredentialStoreSuspendedTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _suspendedFile;
    private readonly CredentialStore _store;

    public CredentialStoreSuspendedTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"patched-creds-suspended-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _suspendedFile = Path.Combine(_tempDir, "suspended");
        _store = CredentialStore.CreateForTests(_suspendedFile);
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
    public void ClearSuspended_RemovesSentinel_WhenPresent()
    {
        File.WriteAllText(_suspendedFile, "");
        Assert.True(_store.IsSuspended);

        _store.ClearSuspended();

        Assert.False(_store.IsSuspended);
        Assert.False(File.Exists(_suspendedFile));
    }

    [Fact]
    public void ClearSuspended_IsIdempotent_WhenSentinelAlreadyAbsent()
    {
        Assert.False(File.Exists(_suspendedFile));
        Assert.False(_store.IsSuspended);

        var ex = Record.Exception(() => _store.ClearSuspended());

        Assert.Null(ex);
        Assert.False(_store.IsSuspended);
    }

    [Fact]
    public void ClearSuspended_CalledTwiceInARow_DoesNotThrow()
    {
        File.WriteAllText(_suspendedFile, "");

        _store.ClearSuspended();
        var ex = Record.Exception(() => _store.ClearSuspended());

        Assert.Null(ex);
        Assert.False(_store.IsSuspended);
    }

    // Symmetric round-trip: a device can be marked suspended, cleared, and
    // suspended again — mirrors the real lifecycle of a 401 (suspend) followed
    // by a verified 200 (clear) followed by a later revocation.
    [Fact]
    public void MarkSuspended_ThenClearSuspended_RoundTripsCleanly()
    {
        Assert.False(_store.IsSuspended);

        _store.MarkSuspended();
        Assert.True(_store.IsSuspended);

        _store.ClearSuspended();
        Assert.False(_store.IsSuspended);

        _store.MarkSuspended();
        Assert.True(_store.IsSuspended);

        _store.ClearSuspended();
        Assert.False(_store.IsSuspended);
    }
}
