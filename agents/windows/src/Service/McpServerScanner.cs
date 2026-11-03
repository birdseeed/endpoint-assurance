using System.Runtime.Versioning;
using Patched.Shared.Contract;
using Patched.Shared.McpServers;
using Patched.Shared.UserTrees;

namespace Patched.Service;

/// <summary>
/// PAT-2020: MCP server configurations (Claude Desktop, Cursor, VS Code, Windsurf, Claude
/// Code) for every profile in HKLM ProfileList, run with the daily inventory. Parity with
/// macos/lib/mcp_servers.sh; the file work, the secret-free server model and every hardening
/// rule live in <see cref="McpServerScanLogic"/> and <see cref="UserTreeReader"/>. Nothing is
/// executed and nothing touches the network. Only a server's name, transport, executable
/// basename, package and URL host are kept; arguments, env, headers and URL paths never leave
/// the scan.
///
/// An unreadable ProfileList fails every client rather than reporting it empty (absence
/// requires authority).
///
/// The scan checks its own 30-second budget between entries. A read that blocks inside one
/// call cannot be interrupted, so the scan runs on a worker task and is abandoned as failed
/// after <see cref="HardTimeout"/>, the same outer bound the macOS collector enforces by
/// killing its parser. Never throws. The exception is not logged with its message: a JSON
/// parser message can quote the text it choked on, and config text carries secrets.
///
/// On the wire since PAT-2225: <see cref="InventoryPoster"/> puts the block in the payload
/// within its byte budget (<see cref="ToolingBlockBudget"/>). The summary line logged here
/// (counts and statuses only, never a server name) is how the block is checked on real devices.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class McpServerScanner
{
    internal static readonly TimeSpan HardTimeout = TimeSpan.FromSeconds(45);

    private readonly ILogger<McpServerScanner> _log;

    public McpServerScanner(ILogger<McpServerScanner> log) => _log = log;

    public InventoryMcpServers Collect()
    {
        InventoryMcpServers result;
        try
        {
            // Cancelled when the hard timeout abandons the scan, so it stops at its next
            // budget check instead of running on, touching files, after its result is dropped.
            var abandon = new CancellationTokenSource();
            var scan = Task.Run(() =>
            {
                var snapshot = WindowsUserProfiles.Snapshot(_log);
                var profiles = snapshot?.Profiles
                    .Select(p => new UserProfileSource(p.UserAccount, p.Sid, p.ProfilePath))
                    .ToList();
                return McpServerScanLogic.Scan(profiles, new McpServerScanOptions { Cancellation = abandon.Token }, snapshot?.Unreadable ?? 0);
            });
            if (scan.Wait(HardTimeout))
            {
                result = scan.Result;
            }
            else
            {
                abandon.Cancel();
                _log.LogWarning("mcp_servers: scan still running after {Seconds}s, abandoned; block is failed",
                    HardTimeout.TotalSeconds);
                result = new InventoryMcpServers { CollectionStatus = PackageCollectionStatus.Failed };
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning("mcp_servers: scan failed ({Type}); block is failed", ex.GetType().Name);
            result = new InventoryMcpServers { CollectionStatus = PackageCollectionStatus.Failed };
        }

        string Client(string c) => result.Clients.TryGetValue(c, out var v) ? v.CollectionStatus : PackageCollectionStatus.Failed;
        _log.LogInformation(
            "mcp_servers: status={Status} claude_desktop={ClaudeDesktop} cursor={Cursor} vscode={VsCode} windsurf={Windsurf} claude_code={ClaudeCode} configs={Configs} servers={Servers} users={Users} (collected)",
            result.CollectionStatus, Client(McpClient.ClaudeDesktop), Client(McpClient.Cursor), Client(McpClient.VsCode),
            Client(McpClient.Windsurf), Client(McpClient.ClaudeCode), result.Totals.ConfigCount, result.Totals.ServerCount,
            result.Users.Count);
        return result;
    }
}
