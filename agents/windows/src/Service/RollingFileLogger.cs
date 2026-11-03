using System.Text;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace Patched.Service;

/// <summary>
/// Lightweight rolling daily file logger for the Patched Windows agent.
///
/// Written because Microsoft.Extensions.Logging has no built-in rolling file
/// provider; Serilog would work too but adds significant transitive dependencies.
///
/// Behaviour:
///   • Log file: %ProgramData%\Patched\logs\patched-agent-YYYY-MM-DD-&lt;session&gt;.log.
///     The process-randomised session component is permanent: an old predictable
///     daily filename might be a legacy hard link or reparse point.
///   • Rolling: one file per UTC calendar day and service process.
///   • Retention: safe, regular logs older than <see cref="MaxAgeDays"/> days are
///     purged at most once per UTC day. Reparse points and hard-linked files are
///     deliberately left alone.
///   • Minimum level: Information (Debug/Trace are suppressed to avoid log spam).
///   • Thread-safe: process-wide lock; writes via File.AppendAllText (atomic per line).
///   • Fail-open: any I/O error inside the logger is swallowed so the service
///     never crashes due to a logging failure.
/// </summary>
internal sealed class RollingFileLoggerProvider : ILoggerProvider
{
    /// <summary>Number of UTC calendar days of log files retained.</summary>
    internal const int MaxAgeDays = 30;

    private readonly string _logDir;
    private readonly string _sessionId = Guid.NewGuid().ToString("N");

    // Shared across all loggers created by this provider.
    private static readonly object _lock = new();
    private static string _lastPurgeDay = "";

    public RollingFileLoggerProvider(string logDir)
    {
        _logDir = logDir;
    }

    public ILogger CreateLogger(string categoryName) =>
        new RollingFileLogger(categoryName, _logDir, _sessionId);

    public void Dispose() { }

    // ------------------------------------------------------------------ //
    // Inner logger                                                         //
    // ------------------------------------------------------------------ //

    private sealed class RollingFileLogger : ILogger
    {
        private readonly string _category;
        private readonly string _logDir;
        private readonly string _sessionId;

        public RollingFileLogger(string category, string logDir, string sessionId)
        {
            _category  = category;
            _logDir    = logDir;
            _sessionId = sessionId;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(
            LogLevel                          logLevel,
            EventId                           eventId,
            TState                            state,
            Exception?                        exception,
            Func<TState, Exception?, string>  formatter)
        {
            if (!IsEnabled(logLevel)) return;

            var message = formatter(state, exception);
            var level   = logLevel switch
            {
                LogLevel.Information => "INF",
                LogLevel.Warning     => "WRN",
                LogLevel.Error       => "ERR",
                LogLevel.Critical    => "CRT",
                _                    => "INF",
            };

            var now = DateTimeOffset.UtcNow;
            var sb  = new StringBuilder();
            sb.Append(now.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            sb.Append(' ');
            sb.Append('[');
            sb.Append(level);
            sb.Append(']');
            sb.Append(' ');
            sb.Append(_category);
            sb.Append(": ");
            sb.AppendLine(message);

            if (exception is not null)
            {
                sb.Append("  Exception: ");
                sb.AppendLine(exception.ToString());
            }

            var line  = sb.ToString();
            var today = now.ToString("yyyy-MM-dd");

            lock (_lock)
            {
                try
                {
                    Directory.CreateDirectory(_logDir);
                    var path = Path.Combine(_logDir, $"patched-agent-{today}-{_sessionId}.log");
                    File.AppendAllText(path, line, Encoding.UTF8);

                    if (today != _lastPurgeDay)
                    {
                        _lastPurgeDay = today;
                        PurgeOldLogs(_logDir);
                    }
                }
                catch
                {
                    // File logger must never crash the service.
                }
            }
        }

        private static void PurgeOldLogs(string logDir)
        {
            try
            {
                var cutoff = DateTime.UtcNow.AddDays(-MaxAgeDays);
                foreach (var file in Directory.GetFiles(logDir, "patched-agent-*.log"))
                {
                    // Establish that the object itself is an unlinked regular file
                    // before even consulting its timestamp. A reparse point or hard
                    // link is never a retention candidate.
                    if (IsSafeRegularLogFile(file) && File.GetLastWriteTimeUtc(file) < cutoff)
                        try { File.Delete(file); } catch { /* ignore */ }
                }
            }
            catch { /* purge failure is non-fatal */ }
        }

        private static bool IsSafeRegularLogFile(string path)
        {
            try
            {
                // GetFileAttributes identifies the link itself without resolving a
                // reparse target. Never delete a reparse point, even when it matches
                // the retention filename pattern.
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    return false;

                if (!OperatingSystem.IsWindows()) return false;

                // A directory DACL repair cannot establish the provenance of a file
                // retained from the previously writable window. More importantly,
                // deleting a hard link mutates its target's link count. Only purge
                // an NTFS file with exactly one link.
                using var stream = new FileStream(
                    path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                return GetFileInformationByHandle(stream.SafeFileHandle, out var info) &&
                    info.NumberOfLinks == 1;
            }
            catch
            {
                // Retention is best-effort. Anything unavailable or not provably a
                // regular unlinked file is suspicious and must be preserved.
                return false;
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation fileInformation);

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public FileAttributes FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }
    }
}
