using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Patched.Shared.Contract;
using Patched.Shared.Paths;

namespace Patched.Tray;

/// <summary>
/// Drops trigger files into the ACL-hardened triggers directory.
/// Mirrors StatusStore.swift requestUpdate().
/// The tray app ONLY creates new trigger files; it never reads or deletes them.
/// The service consumes and validates each file.
/// </summary>
public sealed class TriggerWriter
{
    private static readonly TimeSpan MinTriggerInterval = TimeSpan.FromSeconds(30);

    private readonly ILogger<TriggerWriter> _log;
    private DateTimeOffset _lastTriggerAt = DateTimeOffset.MinValue;

    public TriggerWriter(ILogger<TriggerWriter> log) => _log = log;

    public string? RequestScan(string source = "tray")
    {
        if (DateTimeOffset.Now - _lastTriggerAt < MinTriggerInterval)
            return "Please wait a moment before scanning again.";

        var request = new TriggerRequest
        {
            Type        = "scan",
            RequestedBy = Environment.UserName,
            RequestedAt = DateTimeOffset.UtcNow,
            Source      = source,
        };

        var err = WriteTrigger(request);
        if (err is null) _lastTriggerAt = DateTimeOffset.Now;
        return err;
    }

    public string? RequestOsDefer()
    {
        var request = new TriggerRequest
        {
            Type        = "os_defer",
            RequestedBy = Environment.UserName,
            DeferredAt  = DateTimeOffset.UtcNow,
            RequestedAt = DateTimeOffset.UtcNow,
        };
        return WriteTrigger(request);
    }

    /// <summary>
    /// PAT-1623: the removal notify/defer prompt's own Defer button. Mirrors
    /// RequestOsDefer's shape exactly except for the app identity (removal is
    /// per-app; the OS update is one global clock) — see
    /// TriggerRequest.IsRemovalDeferRequest for why this is a distinct type
    /// rather than a reused os_defer. Never touches the daemon's own
    /// automatic DeferredAppRunning retry (RemovalRunner/DeviceRemovalRunner):
    /// that already runs next cycle regardless of whether this is ever called.
    /// </summary>
    public string? RequestRemovalDefer(long entryId, string name)
    {
        var request = new TriggerRequest
        {
            Type        = "removal_defer",
            EntryId     = entryId,
            Name        = name,
            RequestedBy = Environment.UserName,
            DeferredAt  = DateTimeOffset.UtcNow,
            RequestedAt = DateTimeOffset.UtcNow,
        };
        return WriteTrigger(request);
    }

    private string? WriteTrigger(TriggerRequest request)
    {
        try
        {
            var dir = PathConstants.TriggerDir;
            if (!Directory.Exists(dir))
            {
                _log.LogWarning("Trigger directory not found; service may not be running");
                return "Patched service is not running. Please contact your IT admin.";
            }

            var payload  = JsonSerializer.Serialize(request,
                new JsonSerializerOptions { WriteIndented = false });
            var filename = $"{Guid.NewGuid()}.trigger";
            var path     = Path.Combine(dir, filename);

            // Write atomically: temp + rename within same directory.
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, payload, System.Text.Encoding.UTF8);
            File.Move(tmp, path, overwrite: false);

            _log.LogDebug("Dropped trigger {Filename}", filename);
            return null;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to write trigger");
            return $"Could not contact Patched service: {ex.Message}";
        }
    }
}
