using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Patched.Shared.Contract;
using Patched.Shared.Paths;

namespace Patched.Tray;

/// <summary>
/// Reads update-status.json from the state directory and raises a notification
/// on change. Mirrors StatusStore.swift: watches the directory for renames
/// (atomic writes) and polls every 20s as a backstop.
/// The tray app ONLY reads — it never writes the contract file.
/// </summary>
public sealed class StatusReader : IDisposable
{
    private static readonly JsonSerializerOptions JsonOpts = ContractJsonOptions.Read;

    private readonly ILogger<StatusReader> _log;
    private FileSystemWatcher?             _watcher;
    private System.Threading.Timer?        _pollTimer;

    public UpdateStatus? Current { get; private set; }
    public event EventHandler<UpdateStatus?>? StatusChanged;

    public StatusReader(ILogger<StatusReader> log) => _log = log;

    public void Start()
    {
        Directory.CreateDirectory(PathConstants.StateDir);
        Reload();

        // Watch the STATE directory for renames (atomic temp→dest write by the service).
        _watcher = new FileSystemWatcher(PathConstants.StateDir, "update-status.json")
        {
            NotifyFilter          = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.CreationTime,
            EnableRaisingEvents   = true,
        };
        _watcher.Changed += (_, _) => Reload();
        _watcher.Renamed += (_, _) => Reload();
        _watcher.Created += (_, _) => Reload();

        // 20-second poll backstop (mirrors macOS).
        _pollTimer = new System.Threading.Timer(
            _ => Reload(),
            state: null,
            dueTime:  TimeSpan.FromSeconds(20),
            period:   TimeSpan.FromSeconds(20));
    }

    private void Reload()
    {
        var path = PathConstants.UpdateStatusFile;
        if (!File.Exists(path))
        {
            Current = null;
            OnStatusChanged(null);
            return;
        }

        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var status = JsonSerializer.Deserialize<UpdateStatus>(fs, JsonOpts);
            Current = status;
            OnStatusChanged(status);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Could not read update-status.json");
        }
    }

    private void OnStatusChanged(UpdateStatus? status) =>
        StatusChanged?.Invoke(this, status);

    public void Dispose()
    {
        _watcher?.Dispose();
        _pollTimer?.Dispose();
    }
}
