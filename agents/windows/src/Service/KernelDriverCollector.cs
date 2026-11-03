using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Patched.Shared.Compliance;
using Patched.Shared.Contract;
using Patched.Shared.DeviceClassification;
using Patched.Shared.KernelDrivers;
using Patched.Shared.Security;

namespace Patched.Service;

/// <summary>
/// PAT-2263: the Windows reads behind the <c>kernel_drivers</c> block. Every rule about what
/// the reads mean (merging, bounds, hashing, completeness, enforcement) is in Shared
/// (<see cref="KernelDriverInventoryLogic"/>, <see cref="DriverEnforcementLogic"/>,
/// <see cref="DriverFileHasher"/>), covered off Windows by Shared.Tests. This class only
/// reads:
///
/// - the *.sys files directly in %SystemRoot%\System32\drivers (<see cref="DriverDirectoryLister"/>);
/// - HKLM\SYSTEM\CurrentControlSet\Services, each subkey's Type, ImagePath (unexpanded) and
///   Start, read-only in the 64-bit view;
/// - the kernel's loaded-module names (NtQuerySystemInformation SystemModuleInformation,
///   names only, parsed by <see cref="LoadedModuleParser"/>);
/// - CI\Config VulnerableDriverBlocklistEnable and CI\Policy VerifiedAndReputablePolicyState;
/// - Win32_DeviceGuard CodeIntegrityPolicyEnforcementStatus, in its own query so the
///   compliance collector's existing Win32_DeviceGuard query is unchanged. HVCI is not read
///   again: the compliance collector's read of the same cycle is passed in.
///
/// Files are opened through <see cref="WindowsInstallationEvidence.OpenLocalFile"/>: a local
/// fixed drive only, every component opened with FILE_FLAG_OPEN_REPARSE_POINT and refused if
/// it is a reparse point, each held without write sharing until hashing ends, so nothing on
/// the path can be swapped for a junction mid-read. The file is read as bytes and hashed; it
/// is never loaded, mapped as an image, run or verified with WinVerifyTrust in this process.
/// Nothing is written anywhere. Never throws.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class KernelDriverCollector
{
    internal const string ServicesKey          = @"SYSTEM\CurrentControlSet\Services";
    internal const string CiConfigKey          = @"SYSTEM\CurrentControlSet\Control\CI\Config";
    internal const string BlocklistValue       = "VulnerableDriverBlocklistEnable";
    internal const string CiPolicyKey          = @"SYSTEM\CurrentControlSet\Control\CI\Policy";
    internal const string SmartAppControlValue = "VerifiedAndReputablePolicyState";
    internal const string CodeIntegrityQuery   = "SELECT CodeIntegrityPolicyEnforcementStatus FROM Win32_DeviceGuard";
    internal const int MaxServiceSubkeys       = 20_000;

    private readonly ILogger<KernelDriverCollector> _log;
    private readonly Func<string?> _systemRoot;
    private readonly Func<string, DriverDirectoryListing> _listDirectory;
    private readonly Func<DriverServiceEnumeration> _services;
    private readonly Func<LoadedModuleList> _loaded;
    private readonly RegistryValueReader _hklm;
    private readonly Func<SourceRead> _codeIntegrityPolicy;
    private readonly DriverFileOpener _open;
    private readonly KernelDriverLimits _limits;

    public KernelDriverCollector(ILogger<KernelDriverCollector> log)
        : this(log, systemRoot: null)
    {
    }

    /// <summary>Test seams. Null uses the real Windows read.</summary>
    internal KernelDriverCollector(
        ILogger<KernelDriverCollector>          log,
        Func<string?>?                          systemRoot,
        Func<string, DriverDirectoryListing>?   listDirectory = null,
        Func<DriverServiceEnumeration>?         services = null,
        Func<LoadedModuleList>?                 loaded = null,
        RegistryValueReader?                    hklm = null,
        Func<SourceRead>?                       codeIntegrityPolicy = null,
        DriverFileOpener?                       open = null,
        KernelDriverLimits?                     limits = null)
    {
        _log                 = log;
        _systemRoot          = systemRoot ?? (() => Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        _listDirectory       = listDirectory ?? (dir => DriverDirectoryLister.List(dir));
        _services            = services ?? ReadServices;
        _loaded              = loaded ?? ReadLoadedModules;
        _hklm                = hklm ?? ((key, value) => ComplianceCollector.ReadValue(Registry.LocalMachine, key, value, _log));
        _codeIntegrityPolicy = codeIntegrityPolicy ?? ReadCodeIntegrityPolicy;
        _open                = open ?? OpenDriverFile;
        _limits              = limits ?? KernelDriverLimits.Default;
    }

    /// <param name="hvciStatus">
    /// Win32_DeviceGuard HypervisorEnforcedCodeIntegrityStatus as the compliance collector read
    /// it this cycle (<see cref="ComplianceCollector.LastHvciStatus"/>).
    /// </param>
    public InventoryKernelDrivers Collect(SourceRead hvciStatus)
    {
        InventoryDriverEnforcement enforcement;
        try
        {
            enforcement = DriverEnforcementLogic.Build(
                _hklm(CiConfigKey, BlocklistValue),
                _hklm(CiPolicyKey, SmartAppControlValue),
                hvciStatus,
                _codeIntegrityPolicy());
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "KernelDriverCollector: enforcement reads failed");
            enforcement = DriverEnforcementLogic.Build(RegistryRead.Failed, RegistryRead.Failed, SourceRead.Failed, SourceRead.Failed);
        }

        try
        {
            var root = _systemRoot();
            var directory = string.IsNullOrEmpty(root)
                ? DriverDirectoryListing.Unreadable
                : _listDirectory(Path.Combine(root, "System32", "drivers"));
            var block = KernelDriverInventoryLogic.Build(
                new KernelDriverSources(root, directory, _services(), _loaded(), enforcement), _open, _limits);

            if (block.CollectionStatus != KernelDriverCollectionStatus.Complete)
                _log.LogInformation("KernelDriverCollector: driver inventory {Status}: {Errors}",
                    block.CollectionStatus, string.Join(",", block.Errors));
            _log.LogInformation(
                "KernelDriverCollector: {Count} drivers ({Hashed} hashed), blocklist {Blocklist}, enforced {Enforced}",
                block.Drivers?.Count ?? 0,
                block.Drivers?.Count(d => d.HashStatus == KernelDriverHashStatus.Hashed) ?? 0,
                enforcement.VulnerableDriverBlocklist, enforcement.BlocklistEnforced);
            return block;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "KernelDriverCollector: driver inventory failed");
            return KernelDriverInventoryLogic.Unavailable(enforcement, KernelDriverErrorCode.CollectionFailed);
        }
    }

    // ---------------------------------------------------------------------
    // Services
    // ---------------------------------------------------------------------

    private DriverServiceEnumeration ReadServices()
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var services = hklm.OpenSubKey(ServicesKey, writable: false);
            if (services is null) return DriverServiceEnumeration.Unreadable;
            var names = services.GetSubKeyNames();
            if (names.Length > MaxServiceSubkeys) return DriverServiceEnumeration.Unreadable;

            var entries = new List<DriverServiceEntry>(names.Length);
            var unreadable = 0;
            foreach (var name in names)
            {
                try
                {
                    using var key = services.OpenSubKey(name, writable: false);
                    if (key is null)
                    {
                        unreadable++;
                        continue;
                    }
                    entries.Add(new DriverServiceEntry(
                        name,
                        RegistryRead.Capture(() => key.GetValue("Type")),
                        RegistryRead.Capture(() => key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames)),
                        RegistryRead.Capture(() => key.GetValue("Start"))));
                }
                catch (Exception ex)
                {
                    _log.LogDebug(ex, "KernelDriverCollector: service subkey unreadable");
                    unreadable++;
                }
            }
            return new DriverServiceEnumeration(false, entries, unreadable);
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "KernelDriverCollector: Services key unreadable");
            return DriverServiceEnumeration.Unreadable;
        }
    }

    // ---------------------------------------------------------------------
    // Loaded modules
    // ---------------------------------------------------------------------

    private const int SystemModuleInformation = 11;
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    private const int MaxModuleBufferBytes = 8 * 1024 * 1024;

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);

    private LoadedModuleList ReadLoadedModules()
    {
        if (IntPtr.Size != 8) return LoadedModuleList.Unreadable; // the parser's layout is 64-bit only
        var size = 256 * 1024;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var status = NtQuerySystemInformation(SystemModuleInformation, buffer, size, out var needed);
                if (status == StatusInfoLengthMismatch)
                {
                    size = Math.Max(size * 2, needed + 64 * 1024);
                    if (size > MaxModuleBufferBytes) return LoadedModuleList.Unreadable;
                    continue;
                }
                if (status < 0) return LoadedModuleList.Unreadable;
                var bytes = new byte[needed > 0 && needed <= size ? needed : size];
                Marshal.Copy(buffer, bytes, 0, bytes.Length);
                return LoadedModuleParser.Parse(bytes);
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "KernelDriverCollector: loaded-module list unreadable");
                return LoadedModuleList.Unreadable;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return LoadedModuleList.Unreadable;
    }

    // ---------------------------------------------------------------------
    // Code integrity policy
    // ---------------------------------------------------------------------

    private SourceRead ReadCodeIntegrityPolicy() =>
        SourceRead.Capture(() =>
        {
            var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\DeviceGuard");
            scope.Connect();
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(CodeIntegrityQuery));
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                using (obj) return obj["CodeIntegrityPolicyEnforcementStatus"];
            }
            return null;
        }, ex => _log.LogDebug(ex, "KernelDriverCollector: Win32_DeviceGuard code integrity read failed"));

    // ---------------------------------------------------------------------
    // Files
    // ---------------------------------------------------------------------

    /// <summary>
    /// Opens <paramref name="path"/> through the locked, reparse-refusing walk. When the open
    /// fails, the reason is classified from attributes read afterwards; that read only labels
    /// the failure and never leads to a second open.
    /// </summary>
    internal static DriverFileOpen OpenDriverFile(string path)
    {
        if (!WindowsInstallationEvidence.IsSafePath(path)) return new DriverFileOpen(DriverOpenOutcome.PathUnsupported);
        try
        {
            var locked = WindowsInstallationEvidence.OpenLocalFile(path);
            return new DriverFileOpen(DriverOpenOutcome.Opened, locked.Stream, locked);
        }
        catch (IOException ex) when (ex.Message == "path_not_local_fixed")
        {
            return new DriverFileOpen(DriverOpenOutcome.PathUnsupported);
        }
        catch (Exception)
        {
            return new DriverFileOpen(ClassifyFailedOpen(path));
        }
    }

    internal static DriverOpenOutcome ClassifyFailedOpen(string path)
    {
        try
        {
            if (PathSafety.HasReparsePointInChain(path[..3], path)) return DriverOpenOutcome.ReparsePoint;
            var attributes = File.GetAttributes(path);
            if ((attributes & (FileAttributes.Directory | FileAttributes.Device)) != 0) return DriverOpenOutcome.NotRegularFile;
            return DriverOpenOutcome.Failed;
        }
        catch (FileNotFoundException) { return DriverOpenOutcome.Missing; }
        catch (DirectoryNotFoundException) { return DriverOpenOutcome.Missing; }
        catch (Exception) { return DriverOpenOutcome.Failed; }
    }
}
