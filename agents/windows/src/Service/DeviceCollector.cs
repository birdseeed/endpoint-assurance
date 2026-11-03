using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Patched.Shared.Contract;
using Patched.Shared.DeviceClassification;
using Patched.Shared.Firmware;

namespace Patched.Service;

/// <summary>
/// Reads one property off the first instance a WMI query returns. Returns
/// <see cref="SourceReadState.Absent"/> when the query matched nothing or the property is
/// not set, and <see cref="SourceReadState.Failed"/> when the query threw; it never throws.
/// </summary>
internal delegate SourceRead WmiPropertyReader(string query, string property);

/// <summary>
/// PAT-2262: reads the named properties off the first instance a WMI query returns, with
/// one query. Every property is <see cref="SourceReadState.Failed"/> when the query or its
/// enumeration threw, every property is <see cref="SourceReadState.Absent"/> when it matched
/// no instance, and otherwise each property is read on its own, so one unreadable property
/// cannot take the others down with it. Never throws. The result has exactly one entry per
/// requested property.
/// </summary>
internal delegate IReadOnlyDictionary<string, SourceRead> WmiInstanceReader(string query, IReadOnlyList<string> properties);

/// <summary>
/// Collects device identity, hardware specs, and OS info for the schema v3 inventory payload.
/// All WMI queries are non-fatal: failures return safe fallback values.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class DeviceCollector
{
    /// <summary>PAT-1959: WMI sources for the device-class decision.</summary>
    private const string OsQuery              = "SELECT ProductType, Caption FROM Win32_OperatingSystem";
    private const string ProductTypeProperty  = "ProductType";
    private const string CaptionProperty      = "Caption";

    private readonly ILogger<DeviceCollector> _log;
    private readonly WmiPropertyReader        _wmi;
    private readonly WmiInstanceReader        _wmiInstance;
    private readonly Func<SourceRead>         _installationType;

    /// <summary>PAT-2262: WMI sources for the firmware block, one query per SMBIOS structure.</summary>
    internal const string BiosQuery =
        "SELECT Manufacturer, SMBIOSBIOSVersion, SMBIOSMajorVersion, SMBIOSMinorVersion, ReleaseDate FROM Win32_BIOS";
    internal const string SystemQuery    = "SELECT Manufacturer, Model FROM Win32_ComputerSystem";
    internal const string BaseboardQuery = "SELECT Manufacturer, Product FROM Win32_BaseBoard";

    private static readonly string[] BiosProperties =
        ["Manufacturer", "SMBIOSBIOSVersion", "SMBIOSMajorVersion", "SMBIOSMinorVersion", "ReleaseDate"];
    private static readonly string[] SystemProperties    = ["Manufacturer", "Model"];
    private static readonly string[] BaseboardProperties = ["Manufacturer", "Product"];

    public DeviceCollector(ILogger<DeviceCollector> log)
        : this(log, wmi: null, installationType: null)
    {
    }

    /// <summary>
    /// PAT-1959 test seam: <paramref name="wmi"/> replaces the WMI property reader and
    /// <paramref name="installationType"/> the HKLM InstallationType read, so the
    /// device-class wiring is exercised off-box where neither WMI nor the registry
    /// exists. Production uses the public constructor, which reads the real machine.
    /// </summary>
    internal DeviceCollector(
        ILogger<DeviceCollector> log,
        WmiPropertyReader?       wmi,
        Func<SourceRead>?        installationType,
        WmiInstanceReader?       wmiInstance = null)
    {
        _log              = log;
        _wmi              = wmi ?? ReadWmiProperty;
        _wmiInstance      = wmiInstance ?? ReadWmiInstance;
        _installationType = installationType
            ?? (() => InstallationTypeProbe.Read(
                    ex => _log.LogDebug(ex, "DeviceCollector: could not read InstallationType from the registry")));
    }

    /// <summary>
    /// PAT-1959: what class of machine this is, plus the two evidence strings that sit
    /// beside it. Every source is read independently and every failure is non-fatal: an
    /// unreadable source produces "unknown" or an omitted string, never a fallback that
    /// reads like a real answer. See
    /// <see cref="DeviceClassResolver"/> for the rules and their reasoning.
    /// </summary>
    public DeviceClassResult CollectDeviceClass() =>
        DeviceClassResolver.Resolve(new DeviceClassSources(
            ProductType:      _wmi(OsQuery, ProductTypeProperty),
            InstallationType: _installationType(),
            OsCaption:        _wmi(OsQuery, CaptionProperty)));

    /// <summary>
    /// Production WMI reader. One property per call so a property that cannot be read
    /// cannot take the other one down with it; the underlying query is the same cheap
    /// single-instance Win32_OperatingSystem read the collector already does elsewhere.
    /// </summary>
    private SourceRead ReadWmiProperty(string query, string property) =>
        SourceRead.Capture(
            () =>
            {
                using var mos = new ManagementObjectSearcher(query);
                foreach (ManagementObject obj in mos.Get())
                    return obj[property];
                return null;
            },
            ex => _log.LogDebug(ex, "DeviceCollector: WMI property read failed: {Query} [{Property}]", query, property));

    /// <summary>
    /// PAT-2262: the firmware block. One read of each of Win32_BIOS, Win32_ComputerSystem
    /// and Win32_BaseBoard per cycle; every rule about what the reads mean (failed versus
    /// absent, bounding, the release-date parse, completeness) is in
    /// <see cref="FirmwareInventoryLogic"/>. Never throws: a failed class becomes an
    /// unavailable section, and nothing read at all becomes an unavailable block.
    /// </summary>
    public InventoryFirmware CollectFirmware()
    {
        var bios      = _wmiInstance(BiosQuery, BiosProperties);
        var system    = _wmiInstance(SystemQuery, SystemProperties);
        var baseboard = _wmiInstance(BaseboardQuery, BaseboardProperties);

        static SourceRead Get(IReadOnlyDictionary<string, SourceRead> reads, string property) =>
            reads.TryGetValue(property, out var read) ? read : SourceRead.Failed;

        var firmware = FirmwareInventoryLogic.Build(new FirmwareSources(
            BiosManufacturer:      Get(bios, "Manufacturer"),
            BiosVersion:           Get(bios, "SMBIOSBIOSVersion"),
            SmbiosMajorVersion:    Get(bios, "SMBIOSMajorVersion"),
            SmbiosMinorVersion:    Get(bios, "SMBIOSMinorVersion"),
            BiosReleaseDate:       Get(bios, "ReleaseDate"),
            SystemManufacturer:    Get(system, "Manufacturer"),
            SystemModel:           Get(system, "Model"),
            BaseboardManufacturer: Get(baseboard, "Manufacturer"),
            BaseboardProduct:      Get(baseboard, "Product")));

        if (firmware.CollectionStatus != FirmwareCollectionStatus.Complete)
            _log.LogInformation("DeviceCollector: firmware collection {Status}: {Errors}",
                firmware.CollectionStatus, string.Join(",", firmware.Errors));
        return firmware;
    }

    /// <summary>Production <see cref="WmiInstanceReader"/>: one query, first instance only.</summary>
    private IReadOnlyDictionary<string, SourceRead> ReadWmiInstance(string query, IReadOnlyList<string> properties)
    {
        var result = new Dictionary<string, SourceRead>(StringComparer.Ordinal);
        try
        {
            using var mos = new ManagementObjectSearcher(query);
            using var results = mos.Get();
            foreach (ManagementObject obj in results)
            {
                using (obj)
                {
                    foreach (var property in properties)
                    {
                        result[property] = SourceRead.Capture(
                            () => obj[property],
                            ex => _log.LogDebug(ex, "DeviceCollector: WMI property read failed: {Query} [{Property}]", query, property));
                    }
                }
                return result;
            }
            foreach (var property in properties)
                result[property] = SourceRead.Absent;
            return result;
        }
        catch (Exception ex)
        {
            // The query or its enumeration threw: nothing about this class is known.
            _log.LogDebug(ex, "DeviceCollector: WMI query failed: {Query}", query);
            result.Clear();
            foreach (var property in properties)
                result[property] = SourceRead.Failed;
            return result;
        }
    }

    public InventoryDevice CollectDevice()
    {
        var (primaryUserAccount, primaryUserSource) = GetPrimaryUser();
        return new InventoryDevice
        {
            Serial              = WmiQuerySingle("SELECT SerialNumber FROM Win32_BIOS", "SerialNumber") ?? "Unknown",
            HwUuid              = WmiQuerySingle("SELECT UUID FROM Win32_ComputerSystemProduct", "UUID") ?? "Unknown",
            Hostname            = Environment.MachineName,
            HwModel             = WmiQuerySingle("SELECT Name FROM Win32_ComputerSystemProduct", "Name"),
            Arch                = RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "arm64" : "x86_64",
            LastBoot            = GetLastBoot(),
            PrimaryUserAccount  = primaryUserAccount,
            PrimaryUserSource   = primaryUserSource,
        };
    }

    /// <summary>
    /// Reads the last-logged-on user from
    /// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authentication\LogonUI\LastLoggedOnUser.
    /// Service accounts (containing '$', or named SYSTEM / LOCAL SERVICE / NETWORK SERVICE)
    /// are filtered out — they indicate a machine account or built-in service, not a
    /// human user. Returns (null, null) when the key is missing, empty, or filtered.
    /// Never throws — a missing registry key is a non-fatal condition.
    /// </summary>
    private (string? account, string? source) GetPrimaryUser()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authentication\LogonUI");
            if (key is null) return (null, null);

            var raw = key.GetValue("LastLoggedOnUser")?.ToString()?.Trim();
            if (string.IsNullOrEmpty(raw)) return (null, null);

            // Filter service accounts: machine accounts contain '$', and the
            // well-known NT built-ins are excluded by name.
            if (raw.Contains('$')) return (null, null);
            var namePart = raw.Contains('\\') ? raw.Split('\\', 2)[1] : raw;
            if (string.Equals(namePart, "SYSTEM",          StringComparison.OrdinalIgnoreCase) ||
                string.Equals(namePart, "LOCAL SERVICE",   StringComparison.OrdinalIgnoreCase) ||
                string.Equals(namePart, "NETWORK SERVICE", StringComparison.OrdinalIgnoreCase))
                return (null, null);

            return (raw, "registry");
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "DeviceCollector: could not read primary user from registry");
            return (null, null);
        }
    }

    public InventoryHardware CollectHardware()
    {
        var (cpuModel, cpuCores) = GetCpuInfo();
        var (diskTotal, diskFree) = GetDiskInfo();

        return new InventoryHardware
        {
            CpuModel    = cpuModel,
            CpuCores    = cpuCores,
            RamGb       = GetRamGb(),
            DiskTotalGb = diskTotal,
            DiskFreeGb  = diskFree,
        };
    }

    public InventoryOs CollectOs()
    {
        var (version, build) = GetOsVersion();
        return new InventoryOs { Version = version, Build = build };
    }

    private string GetLastBoot()
    {
        try
        {
            var raw = WmiQuerySingle("SELECT LastBootUpTime FROM Win32_OperatingSystem", "LastBootUpTime");
            if (raw is not null)
            {
                var dt = ManagementDateTimeConverter.ToDateTime(raw);
                return new DateTimeOffset(dt, TimeSpan.Zero).ToString("yyyy-MM-ddTHH:mm:ssZ");
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "DeviceCollector: could not get last boot time");
        }
        return "Unknown";
    }

    private (string? model, int cores) GetCpuInfo()
    {
        try
        {
            using var mos = new ManagementObjectSearcher(
                "SELECT Name, NumberOfLogicalProcessors FROM Win32_Processor");
            foreach (ManagementObject obj in mos.Get())
            {
                var name  = obj["Name"]?.ToString();
                var cores = Convert.ToInt32(obj["NumberOfLogicalProcessors"] ?? Environment.ProcessorCount);
                return (name, cores);
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "DeviceCollector: could not get CPU info");
        }
        return (null, Environment.ProcessorCount);
    }

    private int GetRamGb()
    {
        try
        {
            long total = 0;
            using var mos = new ManagementObjectSearcher("SELECT Capacity FROM Win32_PhysicalMemory");
            foreach (ManagementObject obj in mos.Get())
                total += Convert.ToInt64(obj["Capacity"] ?? 0L);
            return (int)(total / (1024L * 1024 * 1024));
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "DeviceCollector: could not get RAM info");
            return 0;
        }
    }

    private (double total, double free) GetDiskInfo()
    {
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType == DriveType.Fixed && drive.IsReady
                    && string.Equals(drive.RootDirectory.FullName, @"C:\",
                        StringComparison.OrdinalIgnoreCase))
                {
                    const double gb = 1024.0 * 1024 * 1024;
                    return (Math.Round(drive.TotalSize / gb, 1),
                            Math.Round(drive.AvailableFreeSpace / gb, 1));
                }
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "DeviceCollector: could not get disk info");
        }
        return (0, 0);
    }

    private static (string version, string build) GetOsVersion()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key is not null)
            {
                var currentBuild = key.GetValue("CurrentBuild")?.ToString() ?? "";
                var ubr          = key.GetValue("UBR") is int u ? u : 0;
                return ($"10.0.{currentBuild}.{ubr}", currentBuild);
            }
        }
        catch { }
        var ver = Environment.OSVersion.Version;
        return (ver.ToString(), ver.Build.ToString());
    }

    private string? WmiQuerySingle(string query, string property)
    {
        try
        {
            using var mos = new ManagementObjectSearcher(query);
            foreach (ManagementObject obj in mos.Get())
                return obj[property]?.ToString();
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "DeviceCollector: WMI query failed: {Query}", query);
        }
        return null;
    }
}
