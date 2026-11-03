using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-687: platform-neutral tests for the trigger owner policy and the
/// service-side rate limiter (the pure logic added to TriggerWatcher). The ACL
/// owner read itself requires Windows and is not exercised here.
/// </summary>
public sealed class TriggerOwnerAndRateLimitTests
{
    [Theory]
    [InlineData("S-1-5-21-1004336348-1177238915-682003330-1001", true)] // normal user
    [InlineData("S-1-5-18", true)]   // SYSTEM
    [InlineData("S-1-5-32-544", true)] // Administrators
    [InlineData("S-1-1-0", false)]   // Everyone
    [InlineData("S-1-5-7", false)]   // Anonymous
    [InlineData("S-1-0-0", false)]   // Null
    [InlineData("", false)]
    [InlineData("not-a-sid", false)]
    [InlineData(null, false)]
    public void IsAcceptableOwnerSid(string? sid, bool expected)
    {
        Assert.Equal(expected, TriggerOwnerPolicy.IsAcceptableOwnerSid(sid));
    }

    [Fact]
    public void DeriveRequestedBy_PrefersAccountName_FallsBackToSid()
    {
        Assert.Equal("CORP\\alice", TriggerOwnerPolicy.DeriveRequestedBy("S-1-5-21-9-9-9-1001", "CORP\\alice"));
        Assert.Equal("S-1-5-21-9-9-9-1001", TriggerOwnerPolicy.DeriveRequestedBy("S-1-5-21-9-9-9-1001", null));
        Assert.Equal("S-1-5-21-9-9-9-1001", TriggerOwnerPolicy.DeriveRequestedBy("S-1-5-21-9-9-9-1001", "  "));
    }

    [Fact]
    public void RateLimiter_AllowsUpToPerOwnerWindowThenBlocks()
    {
        var limiter = new TriggerRateLimiter(maxPerOwnerPerWindow: 3, window: TimeSpan.FromMinutes(5), maxPerDrain: 100);
        var now = DateTimeOffset.UtcNow;
        limiter.BeginDrain();

        Assert.True(limiter.TryAccept("alice", now));
        Assert.True(limiter.TryAccept("alice", now));
        Assert.True(limiter.TryAccept("alice", now));
        Assert.False(limiter.TryAccept("alice", now)); // 4th within window blocked
        Assert.True(limiter.TryAccept("bob", now));     // other owner unaffected
    }

    [Fact]
    public void RateLimiter_WindowEviction_AllowsAgainAfterWindow()
    {
        var limiter = new TriggerRateLimiter(maxPerOwnerPerWindow: 1, window: TimeSpan.FromMinutes(5), maxPerDrain: 100);
        var t0 = DateTimeOffset.UtcNow;
        limiter.BeginDrain();

        Assert.True(limiter.TryAccept("alice", t0));
        Assert.False(limiter.TryAccept("alice", t0.AddMinutes(1)));
        Assert.True(limiter.TryAccept("alice", t0.AddMinutes(6))); // outside window
    }

    [Fact]
    public void RateLimiter_PerDrainCap_BlocksAcrossOwners()
    {
        var limiter = new TriggerRateLimiter(maxPerOwnerPerWindow: 100, window: TimeSpan.FromMinutes(5), maxPerDrain: 2);
        var now = DateTimeOffset.UtcNow;
        limiter.BeginDrain();

        Assert.True(limiter.TryAccept("alice", now));
        Assert.True(limiter.TryAccept("bob", now));
        Assert.False(limiter.TryAccept("carol", now)); // per-drain cap hit

        limiter.BeginDrain(); // new pass resets the per-drain counter
        Assert.True(limiter.TryAccept("carol", now));
    }
}
