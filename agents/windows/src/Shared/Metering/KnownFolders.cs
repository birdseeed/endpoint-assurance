namespace Patched.Shared.Metering;

/// <summary>
/// Expands the leading KNOWNFOLDERID GUID that UserAssist sometimes prefixes onto a
/// path (e.g. "{6D809377-...}\Acme\acme.exe") into an absolute path, so the matcher
/// can compare it against an app's InstallLocation. Unknown GUIDs are left as-is.
/// </summary>
public static class KnownFolders
{
    // FOLDERID GUIDs (upper-case, braced) → resolver key.
    private static readonly Dictionary<string, Environment.SpecialFolder> Map =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["{6D809377-6AF0-444B-8957-A3773F02200E}"] = Environment.SpecialFolder.ProgramFiles,     // ProgramFiles (x64)
            ["{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}"] = Environment.SpecialFolder.ProgramFilesX86,  // ProgramFilesX86
            ["{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}"] = Environment.SpecialFolder.LocalApplicationData, // Local
            ["{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"] = Environment.SpecialFolder.System,           // System32
            ["{5E6C858F-0E22-4760-9AFE-EA3317B67173}"] = Environment.SpecialFolder.UserProfile,      // UserProfile
            ["{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"] = Environment.SpecialFolder.DesktopDirectory, // Desktop
        };

    /// <summary>Expand a leading {GUID}\ prefix to an absolute path. Pure given a resolver.</summary>
    public static string Expand(string path, Func<Environment.SpecialFolder, string>? resolver = null)
    {
        if (string.IsNullOrEmpty(path) || path[0] != '{') return path;

        int brace = path.IndexOf('}');
        if (brace < 0) return path;

        string guid = path.Substring(0, brace + 1);
        if (!Map.TryGetValue(guid, out var folder)) return path;

        resolver ??= Environment.GetFolderPath;
        string root = resolver(folder);
        if (string.IsNullOrEmpty(root)) return path;

        string rest = path.Substring(brace + 1).TrimStart('\\');
        // Join with a literal backslash (Windows path semantics) rather than
        // Path.Combine, whose separator is host-OS-dependent.
        return rest.Length == 0 ? root : root.TrimEnd('\\') + "\\" + rest;
    }
}
