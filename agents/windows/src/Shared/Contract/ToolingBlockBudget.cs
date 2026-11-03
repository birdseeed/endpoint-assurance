using System.Text.Json;

namespace Patched.Shared.Contract;

/// <summary>
/// PAT-2225: the byte budget for a tooling block (ide_extensions, package_managers,
/// local_models, mcp_servers) before it goes into the inventory payload. Parity with
/// <c>patched_block_within_budget</c> in macos/lib/common.sh and the same budgets as the
/// macOS collectors.
///
/// The server truncates an inventory body at 6 MiB and the HMAC check then fails on every
/// check-in, so one oversized block would cost the device all of its inventory. The
/// platform's tooling contract has no size_limit truncation reason (homebrew's does), so an
/// oversized block cannot be cut down and sent partial: it is replaced by the failed block,
/// the one status the platform accepts that sends no item list and grants no absence
/// authority. A block that cannot be serialised to measure counts as over the budget.
///
/// The budgets keep the tooling blocks within 2 MiB together, the budget the macOS homebrew
/// block has on its own, so the two leave 2 MiB of the 6 MiB cap for everything else.
/// </summary>
public static class ToolingBlockBudget
{
    /// <summary>About 1,000 extensions at the ~500 bytes a real row takes.</summary>
    public const int IdeExtensionsMaxBytes = 512 * 1024;

    /// <summary>About 800 servers at the ~300 bytes a real row takes.</summary>
    public const int McpServersMaxBytes = 256 * 1024;

    /// <summary>About 900 models at the ~290 bytes a real row takes.</summary>
    public const int LocalModelsMaxBytes = 256 * 1024;

    /// <summary>About 2,400 packages at the ~430 bytes a real row takes.</summary>
    public const int PackageManagersMaxBytes = 1024 * 1024;

    /// <summary>The measured block, or the failed block that replaced it.</summary>
    /// <param name="Block">What goes into the payload.</param>
    /// <param name="Bytes">The measured UTF-8 size of the original block, or -1 when it could
    /// not be serialised.</param>
    /// <param name="OverBudget">True when <paramref name="Block"/> is the failed replacement.</param>
    public readonly record struct Result<T>(T Block, long Bytes, bool OverBudget);

    /// <summary>
    /// Returns <paramref name="block"/> when its serialised UTF-8 form, with the options the
    /// payload is sent with, is at most <paramref name="maxBytes"/> bytes; otherwise the block
    /// <paramref name="failed"/> builds.
    /// </summary>
    public static Result<T> Fit<T>(T block, int maxBytes, JsonSerializerOptions options, Func<T> failed)
    {
        long bytes;
        try
        {
            bytes = JsonSerializer.SerializeToUtf8Bytes(block, options).LongLength;
        }
        catch (Exception)
        {
            return new Result<T>(failed(), -1, true);
        }
        return bytes <= maxBytes
            ? new Result<T>(block, bytes, false)
            : new Result<T>(failed(), bytes, true);
    }
}
