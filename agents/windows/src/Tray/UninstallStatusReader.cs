using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Patched.Shared.Contract;
using Patched.Shared.Paths;
using Patched.Shared.Removal;

namespace Patched.Tray;

/// <summary>
/// PAT-1623: reads uninstall-status.json — the same file
/// RemovalRunner.cs/DeviceRemovalRunner.cs already write RemovalOutcome.DeferredAppRunning
/// into (see RemovalContracts.cs) — so the removal notify/defer surface can
/// tell the person at the keyboard what the backend already knows. Mirrors
/// StatusReader.cs exactly (same directory-watch + 20s poll pattern) but for
/// a separate file, since uninstall-status.json and update-status.json are
/// written by separate daemon components and one existing without the other
/// is a normal state. The tray app ONLY reads — it never writes this file.
/// </summary>
public sealed class UninstallStatusReader : IDisposable
{
    private readonly ILogger<UninstallStatusReader> _log;
    private FileSystemWatcher?                       _watcher;
    private System.Threading.Timer?                  _pollTimer;

    public UninstallStatus? Current { get; private set; }
    public event EventHandler<UninstallStatus?>? StatusChanged;

    public UninstallStatusReader(ILogger<UninstallStatusReader> log) => _log = log;

    public void Start()
    {
        Directory.CreateDirectory(PathConstants.StateDir);
        Reload();

        _watcher = new FileSystemWatcher(PathConstants.StateDir, "uninstall-status.json")
        {
            NotifyFilter        = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.CreationTime,
            EnableRaisingEvents = true,
        };
        _watcher.Changed += (_, _) => Reload();
        _watcher.Renamed += (_, _) => Reload();
        _watcher.Created += (_, _) => Reload();

        _pollTimer = new System.Threading.Timer(
            _ => Reload(),
            state: null,
            dueTime: TimeSpan.FromSeconds(20),
            period:  TimeSpan.FromSeconds(20));
    }

    private void Reload()
    {
        var path = PathConstants.UninstallStatusFile;
        if (!File.Exists(path))
        {
            Current = null;
            OnStatusChanged(null);
            return;
        }

        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var status = JsonSerializer.Deserialize<UninstallStatus>(fs, ContractJsonOptions.Read);
            Current = status;
            OnStatusChanged(status);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Could not read uninstall-status.json");
        }
    }

    private void OnStatusChanged(UninstallStatus? status) => StatusChanged?.Invoke(this, status);

    public void Dispose()
    {
        _watcher?.Dispose();
        _pollTimer?.Dispose();
    }
}
