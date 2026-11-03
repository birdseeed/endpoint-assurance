using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using Patched.Service;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-2225: the tooling blocks go on the wire only through InventoryPoster.WithinBudget, and
/// the budget is measured with the real <c>InventoryPoster.JsonOpts</c> (read by reflection,
/// as InventoryPosterLocalAdminWireTests does), so what is measured is what is sent.
/// </summary>
public sealed class InventoryPosterToolingBudgetTests
{
    private static JsonSerializerOptions PosterOpts()
    {
        var field = typeof(InventoryPoster).GetField(
            "JsonOpts", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(field);
        return Assert.IsType<JsonSerializerOptions>(field!.GetValue(null));
    }

    private static string PosterSource([CallerFilePath] string thisFile = "")
    {
        var path = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(thisFile)!, "..", "..", "src", "Service", "InventoryPoster.cs"));
        Assert.True(File.Exists(path), $"InventoryPoster.cs not found at {path}; this test must run from a source checkout");
        // Whitespace collapsed, so line breaks and indentation cannot decide a check.
        return Regex.Replace(File.ReadAllText(path), @"\s+", " ");
    }

    private static int Count(string haystack, string needle)
    {
        var n = 0;
        for (var i = haystack.IndexOf(needle, StringComparison.Ordinal); i >= 0; i = haystack.IndexOf(needle, i + 1, StringComparison.Ordinal))
            n++;
        return n;
    }

    [Theory]
    [InlineData("ide_extensions", "_ideExtensions.Collect()", "ToolingBlockBudget.IdeExtensionsMaxBytes")]
    [InlineData("mcp_servers", "_mcpServers.Collect()", "ToolingBlockBudget.McpServersMaxBytes")]
    [InlineData("local_models", "_localModels.Collect()", "ToolingBlockBudget.LocalModelsMaxBytes")]
    [InlineData("package_managers", "_packageManagers.Collect()", "ToolingBlockBudget.PackageManagersMaxBytes")]
    public void EachToolingBlock_IsBuiltThroughItsBudget(string subject, string collect, string budget)
    {
        var source = PosterSource();

        Assert.Equal(1, Count(source, $"WithinBudget(\"{subject}\", {collect}, {budget},"));
        Assert.Equal(1, Count(source, collect));
    }

    [Fact]
    public void TheBudgetIsMeasuredWithThePosterOptions()
    {
        var block = new InventoryIdeExtensions
        {
            CollectionStatus = IdeCollectionStatus.Complete,
            Extensions = [new InventoryIdeExtension { User = "u", Family = "vscode", Editor = "vscode", Id = "github.copilot", Version = "1.0.0" }],
        };
        var size = JsonSerializer.SerializeToUtf8Bytes(block, PosterOpts()).Length;

        var kept = ToolingBlockBudget.Fit(block, size, PosterOpts(),
            () => new InventoryIdeExtensions { CollectionStatus = IdeCollectionStatus.Failed });
        var dropped = ToolingBlockBudget.Fit(block, size - 1, PosterOpts(),
            () => new InventoryIdeExtensions { CollectionStatus = IdeCollectionStatus.Failed });

        Assert.Same(block, kept.Block);
        Assert.Equal(IdeCollectionStatus.Failed, dropped.Block.CollectionStatus);
    }
}
