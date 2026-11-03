using Microsoft.Extensions.Logging;
using System.Runtime.InteropServices;
using Xunit;

namespace Patched.Service.Tests;

public sealed class RollingFileLoggerTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"patched-rolling-log-{Guid.NewGuid():N}");

    public void Dispose()
    {
        try { if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true); }
        catch { }
    }

    // PAT-1223: a legacy StateDir with an inherited write ACE could contain a
    // predictable current-day log path hard-linked to another file. The session
    // filename is permanent, including after a second safe restart: no later process
    // may return to the attacker-prepared legacy name.
    [Fact]
    public void Logger_DoesNotAppendToLegacyPredictableHardLinkedDailyPath()
    {
        if (!OperatingSystem.IsWindows()) return;

        Directory.CreateDirectory(_root);
        var target = Path.Combine(_root, "hard-link-target.txt");
        File.WriteAllText(target, "original");
        var day = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd");
        var legacyPath = Path.Combine(_root, $"patched-agent-{day}.log");

        if (!CreateHardLink(legacyPath, target, IntPtr.Zero)) return;
        File.SetLastWriteTimeUtc(legacyPath, DateTime.UtcNow.AddDays(
            -RollingFileLoggerProvider.MaxAgeDays - 1));

        using (var firstStart = new RollingFileLoggerProvider(_root))
        {
            firstStart.CreateLogger("test").LogInformation("first start must not reach legacy hard link");
        }

        using (var secondStart = new RollingFileLoggerProvider(_root))
        {
            secondStart.CreateLogger("test").LogInformation("second start must not reach legacy hard link");
        }

        Assert.Equal("original", File.ReadAllText(target));
        Assert.True(File.Exists(legacyPath)); // retention must skip a hard-linked legacy path
        Assert.Equal(2, Directory.GetFiles(_root, $"patched-agent-{day}-*.log").Length);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLink(string fileName, string existingFileName, IntPtr securityAttributes);
}
