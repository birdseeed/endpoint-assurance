using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;
using Patched.Shared.InstallationEvidence;

namespace Patched.Service;

// PAT-2129: the executables a Windows Installer product registered as component key paths,
// for ExecutableResolver's MSI rule. Runs only inside the --collect-app-signatures helper,
// after the step line for its entry, so a hang is bounded and attributable.
//
// Read-only throughout. The product's cached package (LocalPackage, which Windows Installer
// keeps in %WINDIR%\Installer, writable only by SYSTEM and administrators) is opened with
// MSIDBOPEN_READONLY while the same locked, reparse-refusing walk the file reads use holds
// every component of its path, so it cannot be swapped under the parse. Each component's
// installed path comes from MsiGetComponentPath, which reads the registration and never
// installs, repairs or provides anything (MsiProvideComponent would; it is not called).
// Only components whose key path is a File table row with an .exe name are asked about,
// and only a path reported INSTALLSTATE_LOCAL is returned. The resolver still applies the
// Program Files roots to every path it gets.
//
// Returns null when anything could not be read (the resolver reports listing_unavailable,
// never "no executable"), and at most ExecutableResolver.MaximumListedExecutables paths
// (a list that long is ambiguous to the resolver).
[SupportedOSPlatform("windows")]
internal static class MsiComponentReader
{
    // A product's Component table can be large (the .NET SDK toolset has about 3,800 rows
    // on WIN-STAGING); past this the package is not a single-application product anyway.
    internal const int MaximumRows = 20_000;
    private const int InstallStateLocal = 3;
    private const uint ErrorSuccess = 0;
    private const uint ErrorNoMoreItems = 259;

    private static readonly Regex ProductCodePattern = new(
        "^\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\\}$",
        RegexOptions.CultureInvariant);

    internal static bool IsProductCode(string? value) => value is not null && ProductCodePattern.IsMatch(value);

    // The key file of every component whose key path is a file, with the File table's
    // "SHORT~1.EXE|Long Name.exe" form reduced to its long name.
    private const string Query =
        "SELECT `Component`.`ComponentId`, `File`.`FileName` FROM `Component`, `File` " +
        "WHERE `Component`.`KeyPath` = `File`.`File`";

    internal static IReadOnlyList<string>? ExecutableKeyPaths(string productCode)
    {
        if (!IsProductCode(productCode)) return null;
        try
        {
            var package = ProductInfo(productCode, "LocalPackage");
            if (package is null || !IsCachedPackagePath(package, Environment.GetFolderPath(Environment.SpecialFolder.Windows)))
                return null;
            using var locked = WindowsInstallationEvidence.OpenLocalFile(package);
            var components = ExecutableComponents(package);
            if (components is null) return null;
            var paths = new List<string>();
            foreach (var component in components)
            {
                var path = ComponentPath(productCode, component);
                if (path is null) continue;
                paths.Add(path);
                if (paths.Count >= ExecutableResolver.MaximumListedExecutables) break;
            }
            return paths;
        }
        catch { return null; }
    }

    // %WINDIR%\Installer\<name>.msi, directly inside it and a safe local path.
    internal static bool IsCachedPackagePath(string path, string windowsDirectory)
    {
        var installer = windowsDirectory.TrimEnd('\\') + "\\Installer\\";
        return WindowsInstallationEvidence.IsSafePath(path) && windowsDirectory.Length >= 4 &&
            path.StartsWith(installer, StringComparison.OrdinalIgnoreCase) &&
            path.Length > installer.Length && path.IndexOf('\\', installer.Length) < 0 &&
            path.EndsWith(".msi", StringComparison.OrdinalIgnoreCase);
    }

    // The long name from a File table FileName ("SHORT~1.EXE|Long Name.exe" or "name.exe").
    internal static string LongFileName(string value)
    {
        var bar = value.IndexOf('|');
        return bar >= 0 ? value[(bar + 1)..] : value;
    }

    private static List<string>? ExecutableComponents(string package)
    {
        IntPtr database = IntPtr.Zero, view = IntPtr.Zero;
        try
        {
            if (MsiOpenDatabaseW(package, IntPtr.Zero, out database) != ErrorSuccess) return null;
            if (MsiDatabaseOpenViewW(database, Query, out view) != ErrorSuccess) return null;
            if (MsiViewExecute(view, IntPtr.Zero) != ErrorSuccess) return null;
            var components = new List<string>();
            for (var rows = 0; ; rows++)
            {
                var fetched = MsiViewFetch(view, out var record);
                if (fetched == ErrorNoMoreItems) break;
                if (fetched != ErrorSuccess || rows >= MaximumRows) { Close(record); return null; }
                try
                {
                    var componentId = RecordString(record, 1);
                    var fileName = RecordString(record, 2);
                    if (componentId is null || fileName is null) return null;
                    // A component with no ComponentId is not registered and has no path.
                    if (componentId.Length > 0 &&
                        LongFileName(fileName).EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        components.Add(componentId);
                }
                finally { Close(record); }
            }
            return components;
        }
        finally
        {
            Close(view);
            Close(database);
        }
    }

    // Every string read uses one fixed buffer: a value that does not fit is refused (the
    // resolver never accepts a path that long), never retried with a size msi.dll chose.
    private const int PathBuffer = 1025;
    private const int RecordBuffer = 4097;

    private static string? ComponentPath(string productCode, string componentId)
    {
        var buffer = new StringBuilder(PathBuffer);
        var length = (uint)PathBuffer;
        return MsiGetComponentPathW(productCode, componentId, buffer, ref length) == InstallStateLocal &&
            length is > 0 and < PathBuffer ? buffer.ToString(0, (int)length) : null;
    }

    private static string? ProductInfo(string productCode, string property)
    {
        var buffer = new StringBuilder(PathBuffer);
        var length = (uint)PathBuffer;
        return MsiGetProductInfoW(productCode, property, buffer, ref length) == ErrorSuccess &&
            length is > 0 and < PathBuffer ? buffer.ToString(0, (int)length) : null;
    }

    private static string? RecordString(IntPtr record, uint field)
    {
        var buffer = new StringBuilder(RecordBuffer);
        var length = (uint)RecordBuffer;
        return MsiRecordGetStringW(record, field, buffer, ref length) == ErrorSuccess && length < RecordBuffer
            ? buffer.ToString(0, (int)length) : null;
    }

    private static void Close(IntPtr handle)
    {
        if (handle != IntPtr.Zero) MsiCloseHandle(handle);
    }

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint MsiGetProductInfoW(string product, string property, StringBuilder value, ref uint length);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint MsiOpenDatabaseW(string path, IntPtr persist, out IntPtr database);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint MsiDatabaseOpenViewW(IntPtr database, string query, out IntPtr view);
    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiViewExecute(IntPtr view, IntPtr record);
    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiViewFetch(IntPtr view, out IntPtr record);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint MsiRecordGetStringW(IntPtr record, uint field, StringBuilder value, ref uint length);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int MsiGetComponentPathW(string product, string component, StringBuilder path, ref uint length);
    [DllImport("msi.dll", ExactSpelling = true)]
    private static extern uint MsiCloseHandle(IntPtr handle);
}
