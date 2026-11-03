using System.Reflection;
using System.Text.Json;
using Patched.Service;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1988: local_admins.accounts[].account_state serialised with the real
/// <c>InventoryPoster.JsonOpts</c>, not the Shared.Tests mirror of it, so a drift between
/// the two cannot hide a wire change. The options are private, so they are read by
/// reflection; a rename of the field fails the test loudly rather than skipping it.
/// </summary>
public sealed class InventoryPosterLocalAdminWireTests
{
    private static JsonSerializerOptions PosterOpts()
    {
        var field = typeof(InventoryPoster).GetField(
            "JsonOpts", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(field);
        return Assert.IsType<JsonSerializerOptions>(field!.GetValue(null));
    }

    private static InventoryLocalAdmins Admins(string? builtinState) => new()
    {
        CollectionStatus = "complete",
        Accounts = new[]
        {
            new InventoryLocalAdmin
            {
                Name = @"WIN-TEST\Administrator", PrincipalType = "user", Builtin = true,
                Sid = "S-1-5-21-1-2-3-500", AccountState = builtinState,
            },
            new InventoryLocalAdmin
            {
                Name = @"WIN-TEST\alice", PrincipalType = "user", Builtin = false,
                Sid = "S-1-5-21-1-2-3-1001", AccountState = null,
            },
        },
    };

    [Theory]
    [InlineData("enabled")]
    [InlineData("disabled")]
    [InlineData("unknown")]
    public void AccountState_IsWrittenAsSnakeCaseKey_WithPosterOptions(string state)
    {
        var json = JsonSerializer.Serialize(Admins(state), PosterOpts());

        Assert.Contains($"\"account_state\":\"{state}\"", json);
        Assert.DoesNotContain("AccountState", json);
    }

    [Fact]
    public void NullAccountState_IsOmitted_WithPosterOptions()
    {
        var json = JsonSerializer.Serialize(Admins(null), PosterOpts());

        Assert.DoesNotContain("account_state", json);
    }
}
