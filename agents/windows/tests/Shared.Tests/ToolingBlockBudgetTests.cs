using System.Text.Json;
using System.Text.Json.Serialization;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-2225: the byte budget a tooling block must fit before it goes into the inventory
/// payload. Parity with patched_block_within_budget (macos/lib/common.sh): within the budget
/// the block is sent unchanged, past it the failed block is sent instead, never a cut-down
/// block, because the platform's tooling contract has no size_limit truncation reason.
/// </summary>
public sealed class ToolingBlockBudgetTests
{
    // Mirrors InventoryPoster.JsonOpts; Service.Tests checks the budget with the real options.
    private static readonly JsonSerializerOptions Opts = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters             = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    private static InventoryIdeExtensions Ide() => new()
    {
        CollectionStatus = IdeCollectionStatus.Complete,
        Users = [new IdeUserRow { User = @"WIN-TEST\alice", UserId = "S-1-5-21-1-2-3-1001", CollectionStatus = IdeCollectionStatus.Complete, Profiles = 1 }],
        Profiles = [new IdeProfileRow { User = @"WIN-TEST\alice", Family = "vscode", Editor = "vscode", CollectionStatus = IdeCollectionStatus.Complete, ExtensionCount = 1 }],
        Extensions = [new InventoryIdeExtension { User = @"WIN-TEST\alice", Family = "vscode", Editor = "vscode", Id = "github.copilot", Version = "1.250.0" }],
    };

    private static InventoryIdeExtensions IdeFailed() => new() { CollectionStatus = IdeCollectionStatus.Failed };

    private static int Size<T>(T block) => JsonSerializer.SerializeToUtf8Bytes(block, Opts).Length;

    [Fact]
    public void ShippedBudgets_MatchTheMacOsCollectors()
    {
        Assert.Equal(512 * 1024, ToolingBlockBudget.IdeExtensionsMaxBytes);   // _IDE_MAX_BYTES
        Assert.Equal(256 * 1024, ToolingBlockBudget.McpServersMaxBytes);   // _MCP_MAX_BYTES
        Assert.Equal(256 * 1024, ToolingBlockBudget.LocalModelsMaxBytes);   // _LM_MAX_BYTES
        Assert.Equal(1024 * 1024, ToolingBlockBudget.PackageManagersMaxBytes);   // _PKG_MAX_BYTES
    }

    [Fact]
    public void WithinBudget_TheBlockIsSentUnchanged()
    {
        var block = Ide();
        var fit = ToolingBlockBudget.Fit(block, ToolingBlockBudget.IdeExtensionsMaxBytes, Opts, IdeFailed);

        Assert.False(fit.OverBudget);
        Assert.Same(block, fit.Block);
        Assert.Equal(Size(block), fit.Bytes);
    }

    [Fact]
    public void ExactlyAtTheBudget_IsWithinIt()
    {
        var block = Ide();
        var fit = ToolingBlockBudget.Fit(block, Size(block), Opts, IdeFailed);

        Assert.False(fit.OverBudget);
        Assert.Same(block, fit.Block);
    }

    [Fact]
    public void OneByteOver_TheFailedBlockIsSentInstead()
    {
        var block = Ide();
        var size = Size(block);
        var fit = ToolingBlockBudget.Fit(block, size - 1, Opts, IdeFailed);

        Assert.True(fit.OverBudget);
        Assert.Equal(size, fit.Bytes);
        Assert.Equal(IdeCollectionStatus.Failed, fit.Block.CollectionStatus);
        var sent = JsonDocument.Parse(JsonSerializer.Serialize(fit.Block, Opts)).RootElement;
        Assert.Equal("failed", sent.GetProperty("collection_status").GetString());
        Assert.False(sent.TryGetProperty("extensions", out _));
        Assert.DoesNotContain("github.copilot", sent.GetRawText());
    }

    private sealed class Unserialisable
    {
        public string Value => throw new InvalidOperationException("cannot be read");
    }

    [Fact]
    public void ABlockThatCannotBeMeasured_CountsAsOverTheBudget()
    {
        var failed = new Unserialisable();
        var fit = ToolingBlockBudget.Fit(new Unserialisable(), int.MaxValue, Opts, () => failed);

        Assert.True(fit.OverBudget);
        Assert.Equal(-1, fit.Bytes);
        Assert.Same(failed, fit.Block);
    }
}
