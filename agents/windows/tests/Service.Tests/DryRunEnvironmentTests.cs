using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// Tests that own the PATCHED_DRY_RUN environment variable.
/// </summary>
/// <remarks>
/// PAT-1129 moved every other test off the process-wide PATCHED_DRY_RUN global and
/// onto a per-instance IsDryRun() override, which closed a real cross-class race.
/// The side effect was that nothing exercised the production implementation any
/// more: a typo in the variable name, or a change to which value counts as "on",
/// would silently disable dry-run across every endpoint and no test would notice.
/// That is a worse failure than the race, because dry-run is the switch that stops
/// the enforcers actuating destructively.
///
/// So exactly one class still touches the real variable, and it is serialised
/// against everything else that does, following the AllowlistTestCollection pattern
/// already established in Engine.Tests. Every mutation is scoped and restored.
/// </remarks>
[CollectionDefinition(Name)]
public sealed class DryRunEnvCollection
{
    public const string Name = "DryRunEnv (serialised: mutates PATCHED_DRY_RUN)";
}

/// <summary>
/// Sets PATCHED_DRY_RUN for the lifetime of the scope and restores the previous
/// value (usually unset) on dispose, even if the assertion throws.
/// </summary>
internal sealed class DryRunScope : IDisposable
{
    private const string Var = "PATCHED_DRY_RUN";
    private readonly string? _previous;

    internal DryRunScope(string? value)
    {
        _previous = Environment.GetEnvironmentVariable(Var);
        Environment.SetEnvironmentVariable(Var, value);
    }

    public void Dispose() => Environment.SetEnvironmentVariable(Var, _previous);
}

[Collection(DryRunEnvCollection.Name)]
public class DryRunEnvironmentTests
{
    private static AdminEnforcer Admin() =>
        new(NullLogger<AdminEnforcer>.Instance);

    private static BrowserExtensionBlocklistEnforcer Blocklist() =>
        new(NullLogger<BrowserExtensionBlocklistEnforcer>.Instance);

    // The exact variable name is the thing most likely to rot silently, so it is
    // spelled out here as a literal rather than shared with production code.
    [Fact]
    public void AdminEnforcer_IsDryRun_TrueWhenVariableIsExactlyOne()
    {
        using var _ = new DryRunScope("1");
        Assert.True(Admin().IsDryRun());
    }

    [Fact]
    public void BlocklistEnforcer_IsDryRun_TrueWhenVariableIsExactlyOne()
    {
        using var _ = new DryRunScope("1");
        Assert.True(Blocklist().IsDryRun());
    }

    [Fact]
    public void AdminEnforcer_IsDryRun_FalseWhenVariableUnset()
    {
        using var _ = new DryRunScope(null);
        Assert.False(Admin().IsDryRun());
    }

    [Fact]
    public void BlocklistEnforcer_IsDryRun_FalseWhenVariableUnset()
    {
        using var _ = new DryRunScope(null);
        Assert.False(Blocklist().IsDryRun());
    }

    // Dry-run must fail CLOSED in the safe direction: anything that is not exactly
    // "1" leaves the enforcers actuating normally. A value like "true" or "0"
    // quietly enabling dry-run would suppress real enforcement estate-wide, which
    // is the silent-no-op failure shape CLAUDE.md calls out.
    [Theory]
    [InlineData("0")]
    [InlineData("true")]
    [InlineData("TRUE")]
    [InlineData("yes")]
    [InlineData("")]
    [InlineData(" 1")]
    [InlineData("1 ")]
    public void AdminEnforcer_IsDryRun_FalseForAnythingButExactlyOne(string value)
    {
        using var _ = new DryRunScope(value);
        Assert.False(Admin().IsDryRun());
    }

    [Theory]
    [InlineData("0")]
    [InlineData("true")]
    [InlineData("")]
    [InlineData(" 1")]
    public void BlocklistEnforcer_IsDryRun_FalseForAnythingButExactlyOne(string value)
    {
        using var _ = new DryRunScope(value);
        Assert.False(Blocklist().IsDryRun());
    }
}
