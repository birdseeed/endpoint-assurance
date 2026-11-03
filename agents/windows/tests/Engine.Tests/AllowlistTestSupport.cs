using Xunit;

namespace Patched.Engine.Tests;

/// <summary>
/// PAT-687: shared support for the allowlist tests, which manipulate the
/// process-global PATCHED_ALLOW_UNSIGNED_ALLOWLIST environment variable.
///
/// #188 made AllowlistLoader fail closed: a missing .sig now yields an EMPTY
/// allowlist unless the documented dev opt-out (PATCHED_ALLOW_UNSIGNED_ALLOWLIST=1)
/// is set. Tests that exercise parse/lookup on an UNSIGNED fixture must set that
/// opt-out only for the duration of the load, and must not let the global env var
/// leak into env-sensitive tests running concurrently.
/// </summary>
///
/// <remarks>
/// Every test class that reads (or depends on the absence of) the opt-out env var
/// joins <see cref="AllowlistTestCollection"/> so xUnit serialises them relative to
/// one another — the two classes never run in parallel, closing the cross-class
/// race. Within a class, tests already run sequentially, and each opt-out is scoped
/// with try/finally via <see cref="UnsignedAllowlistScope"/> so the variable is
/// restored the instant the load completes.
/// </remarks>
[CollectionDefinition(Name)]
public sealed class AllowlistTestCollection
{
    public const string Name = "AllowlistEnv (serialised: mutates PATCHED_ALLOW_UNSIGNED_ALLOWLIST)";
}

/// <summary>
/// Sets PATCHED_ALLOW_UNSIGNED_ALLOWLIST=1 for the lifetime of the scope and
/// restores the previous value (usually unset) on dispose — even if the wrapped
/// code throws. Access the loader's <c>Entries</c>/lookups INSIDE the scope: the
/// load is lazy + cached, so triggering it here bakes in the opt-out result.
/// </summary>
public sealed class UnsignedAllowlistScope : IDisposable
{
    private const string Var = "PATCHED_ALLOW_UNSIGNED_ALLOWLIST";
    private readonly string? _previous;

    public UnsignedAllowlistScope()
    {
        _previous = Environment.GetEnvironmentVariable(Var);
        Environment.SetEnvironmentVariable(Var, "1");
    }

    public void Dispose() => Environment.SetEnvironmentVariable(Var, _previous);
}
