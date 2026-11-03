using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Patched.Service;

/// <summary>
/// PAT-2352: retire the old user-session UI without giving the headless service a
/// generic process-kill or registry-delete command. MSI owns removal of its old
/// binary. We remove only its exact Run value in loaded hives and stop its exact
/// installed image. Offline hives are never loaded: later logons are caught by the
/// next bounded pass. Failure cannot block collection, enrolment or self-update.
/// </summary>
internal sealed class RetiredTrayCleanup : BackgroundService
{
    internal const string RunValueName = "PatchedTray";
    internal const int PassLimit = 64;
    internal static readonly TimeSpan RetryInterval = TimeSpan.FromMinutes(15);
    private static readonly string[] RunPath = ["Software", "Microsoft", "Windows", "CurrentVersion", "Run"];
    private static int _aliasReported;
    private readonly Action _run;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    public RetiredTrayCleanup(ILogger<RetiredTrayCleanup> log, AgentHealthStore health)
        : this(() => RunProduction(log, health), Task.Delay) { }

    internal RetiredTrayCleanup(Action run, Func<TimeSpan, CancellationToken, Task> delay)
    {
        _run = run;
        _delay = delay;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Never hold up SCM's service-start acknowledgement with retirement work.
        await Task.Yield();
        while (!stoppingToken.IsCancellationRequested)
        {
            _run(); // Production callback contains and reports every failure.
            try { await _delay(RetryInterval, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }

    internal interface IRegistryKey : IDisposable
    {
        // Must open the link itself, never its target. Every component is checked.
        IRegistryKey? OpenChild(string name, bool writable);
        bool IsLink { get; }
        string[] GetSubKeyNames();
        (RegistryValueKind Kind, object? Value)? ReadRunValue();
        void DeleteRunValue();
    }

    internal interface ITrayProcess : IDisposable
    {
        // ImagePath and Terminate must use the SAME opened process handle.
        string ImagePath { get; }
        void Terminate();
    }

    internal static bool IsOurRunValue((RegistryValueKind Kind, object? Value)? value, string trayPath) =>
        value is { Kind: RegistryValueKind.String, Value: string text } &&
        (string.Equals(text, trayPath, StringComparison.OrdinalIgnoreCase) ||
         string.Equals(text, '"' + trayPath + '"', StringComparison.OrdinalIgnoreCase));

    internal static bool IsLoadedHiveName(string name) => name == ".DEFAULT" ||
        Regex.IsMatch(name, @"\AS-1-\d+(?:-\d+)+\z", RegexOptions.CultureInvariant);

    /// <summary>
    /// PAT-2416: <paramref name="alias"/> is true when the hive key itself, directly
    /// under HKEY_USERS, is a registry link. Windows publishes LocalSystem's hive
    /// twice: HKU\S-1-5-18 is a link to HKU\.DEFAULT. Refusing that link failed
    /// every pass, so the cleanup could never report complete. Skipping it is safe
    /// because nothing is read or written through it, and its target is a top-level
    /// hive that this same pass walks under its own name; following the link would
    /// only visit that key twice. Every non-link hive is still processed, and a link
    /// anywhere below a hive root is still refused as a failure.
    /// </summary>
    internal static IRegistryKey? OpenRunKey(IRegistryKey users, string hive, out bool alias)
    {
        alias = false;
        if (!IsLoadedHiveName(hive)) return null; // Excludes *_Classes and arbitrary paths.
        IRegistryKey? current = null;
        try
        {
            current = users.OpenChild(hive, writable: false);
            if (current is null) return null;
            if (current.IsLink) { alias = true; return null; }
            foreach (var component in RunPath)
            {
                var next = current.OpenChild(component, writable: component == "Run");
                current.Dispose();
                current = next;
                if (current is null) return null;
                if (current.IsLink) throw new IOException("registry_link_refused");
            }
            var result = current;
            current = null; // Caller owns the final opened key.
            return result;
        }
        finally { current?.Dispose(); }
    }

    internal static bool RunPass(ILogger log, string trayPath, Func<IDisposable> lockInstallation,
        IRegistryKey users, Func<IEnumerable<ITrayProcess>> processes)
    {
        using var installation = lockInstallation(); // Fail closed before any mutation.
        var success = true;
        var hives = users.GetSubKeyNames().Where(IsLoadedHiveName).Take(PassLimit + 1).ToArray();
        if (hives.Length > PassLimit)
        {
            log.LogWarning("Retired tray cleanup: loaded-hive limit reached; cleanup incomplete");
            success = false;
        }
        foreach (var hive in hives.Take(PassLimit))
        {
            try
            {
                using var run = OpenRunKey(users, hive, out var alias);
                if (alias)
                {
                    // Not a failure and not a warning: say so once per service run.
                    log.Log(Interlocked.Exchange(ref _aliasReported, 1) == 0 ? LogLevel.Information : LogLevel.Debug,
                        "Retired tray cleanup: {Hive} is a registry alias of another hive; skipped, its target is checked directly", hive);
                    continue;
                }
                if (run is null || !IsOurRunValue(run.ReadRunValue(), trayPath)) continue;
                // Read again on the same link-refusing handle immediately before delete.
                // Do not remove a differently configured same-name startup entry.
                if (!IsOurRunValue(run.ReadRunValue(), trayPath)) continue;
                run.DeleteRunValue();
                log.LogInformation("Retired tray cleanup: removed the installed tray's Run value from {Hive}", hive);
            }
            catch (Exception ex)
            {
                success = false;
                log.LogWarning("Retired tray cleanup: hive {Hive} refused or unavailable ({Error}); will retry", hive, ex.GetType().Name);
            }
        }
        var count = 0;
        foreach (var process in processes())
        {
            using (process)
            {
                if (++count > PassLimit)
                {
                    log.LogWarning("Retired tray cleanup: process limit reached; cleanup incomplete");
                    success = false;
                    break;
                }
                try
                {
                    if (!string.Equals(process.ImagePath, trayPath, StringComparison.OrdinalIgnoreCase)) continue;
                    process.Terminate();
                    log.LogInformation("Retired tray cleanup: stopped the installed tray process");
                }
                catch (Exception ex)
                {
                    success = false;
                    log.LogWarning("Retired tray cleanup: process refused or unavailable ({Error}); will retry", ex.GetType().Name);
                }
            }
        }
        return success;
    }

    private static void RunProduction(ILogger log, AgentHealthStore health)
    {
        var success = false;
        try
        {
            var install = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Patched");
            var service = Path.Combine(install, "Patched.Service.exe");
            var tray = Path.Combine(install, "PatchedTray.exe");
            using var users = new NativeRegistryKey(RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64));
            success = RunPass(log, tray, () =>
            {
                if (!string.Equals(Environment.ProcessPath, service, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("service_location_untrusted");
                // Holds the reparse-refusing ancestor walk throughout this pass.
                var locked = WindowsInstallationEvidence.OpenLocalFile(service);
                IDisposable? lockedTray = null;
                try
                {
                    WindowsInstallationEvidence.VerifyInstallDirectoryAcl(install);
                    WindowsInstallationEvidence.VerifyExecutableAcl(service);
                    // MSI normally removed the tray already. If it remains on disk
                    // (for example pending reboot), require its own ACL and locked
                    // path too: a protected directory alone cannot vouch for an
                    // individually writable executable inside it.
                    try
                    {
                        _ = File.GetAttributes(tray);
                        lockedTray = WindowsInstallationEvidence.OpenLocalFile(tray);
                        WindowsInstallationEvidence.VerifyExecutableAcl(tray);
                    }
                    catch (FileNotFoundException) { }
                    return new InstallationLease(locked, lockedTray);
                }
                catch { lockedTray?.Dispose(); locked.Dispose(); throw; }
            }, users, OpenTrayProcesses);
        }
        catch (Exception ex)
        {
            log.LogWarning("Retired tray cleanup: pass refused or unavailable ({Error}); will retry", ex.GetType().Name);
        }
        RecordOutcome(log, health, success);
    }

    // A complete pass clears a cleanup_incomplete reason an earlier pass (or an
    // earlier release) left in agent-health.json; an incomplete one records it.
    internal static void RecordOutcome(ILogger log, AgentHealthStore health, bool success)
    {
        try
        {
            if (success) health.RecordSuccess("retired_component_cleanup", "windows_tray");
            else health.RecordFailure("retired_component_cleanup", "windows_tray", "cleanup_incomplete");
        }
        catch (Exception ex)
        {
            log.LogWarning("Retired tray cleanup: could not record health ({Error})", ex.GetType().Name);
        }
    }

    private sealed class InstallationLease(IDisposable service, IDisposable? tray) : IDisposable
    {
        public void Dispose()
        {
            try { tray?.Dispose(); }
            finally { service.Dispose(); }
        }
    }

    private static IEnumerable<ITrayProcess> OpenTrayProcesses()
    {
        // Name is only an enumeration filter. Authority is the image path queried
        // from the opened handle, which is also the only handle we terminate.
        var candidates = Process.GetProcessesByName(RunValueName);
        try
        {
            foreach (var candidate in candidates.Take(PassLimit + 1))
                yield return new NativeTrayProcess(candidate.Id);
        }
        finally { foreach (var candidate in candidates) candidate.Dispose(); }
    }

    internal sealed class NativeTrayProcess : ITrayProcess
    {
        private readonly SafeProcessHandle _handle;
        private readonly int _openError;
        internal NativeTrayProcess(int pid)
        {
            _handle = OpenProcess(0x1000 | 0x0001, false, pid); // QUERY_LIMITED_INFORMATION | TERMINATE
            _openError = _handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        }
        public string ImagePath
        {
            get
            {
                if (_handle.IsInvalid) throw new Win32Exception(_openError);
                var path = new StringBuilder(32768);
                var length = path.Capacity;
                if (!QueryFullProcessImageName(_handle, 0, path, ref length))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return path.ToString();
            }
        }
        public void Terminate()
        {
            if (!TerminateProcess(_handle, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public void Dispose() => _handle.Dispose();
    }

    internal sealed class NativeRegistryKey(RegistryKey key) : IRegistryKey
    {
        public IRegistryKey? OpenChild(string name, bool writable)
        {
            // Microsoft specifies OPEN_LINK returns the source key itself:
            // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/d5ce9dcc-1f90-4f5a-b076-cc1d2c9b4195
            const int queryValue = 0x0001, enumerate = 0x0008, setValue = 0x0002, view64 = 0x0100;
            var error = RegOpenKeyEx(key.Handle, name, 0x0008 /* REG_OPTION_OPEN_LINK */,
                queryValue | enumerate | view64 | (writable ? setValue : 0), out var handle);
            if (error != 0)
            {
                handle.Dispose();
                if (error == 2) return null;
                throw new Win32Exception(error);
            }
            try { return new NativeRegistryKey(RegistryKey.FromHandle(handle, RegistryView.Registry64)); }
            catch { handle.Dispose(); throw; }
        }
        public bool IsLink
        {
            get
            {
                uint size = 0;
                var error = RegQueryValueEx(key.Handle, "SymbolicLinkValue", IntPtr.Zero, out var type, IntPtr.Zero, ref size);
                if (error == 2) return false;
                if (error != 0) throw new Win32Exception(error);
                return type == 6; // REG_LINK. Never follow the value to discover its target.
            }
        }
        public string[] GetSubKeyNames() => key.GetSubKeyNames();
        public (RegistryValueKind Kind, object? Value)? ReadRunValue()
        {
            var value = key.GetValue(RunValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            return value is null ? null : (key.GetValueKind(RunValueName), value);
        }
        public void DeleteRunValue() => key.DeleteValue(RunValueName, throwOnMissingValue: false);
        public void Dispose() => key.Dispose();
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegOpenKeyEx(SafeRegistryHandle key, string subKey, int options, int access, out SafeRegistryHandle result);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegQueryValueEx(SafeRegistryHandle key, string name, IntPtr reserved, out uint type, IntPtr data, ref uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(int access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process, int flags, StringBuilder path, ref int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
}
