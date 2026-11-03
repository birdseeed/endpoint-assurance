using System.Diagnostics;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-2033: a test that plants a directory reparse point, an NTFS junction (mklink /J) on
/// Windows and a symlink elsewhere. A locked-down machine can refuse the junction without
/// elevation, so whether one can be planted is probed once per run: when it cannot, every test
/// marked with this attribute is skipped with the reason, rather than failed on the machine or
/// passed without its guard having run. A plant that fails after the probe succeeded is still
/// an assertion failure in the test's own helper.
/// </summary>
public sealed class DirectoryLinkFactAttribute : FactAttribute
{
    public DirectoryLinkFactAttribute()
    {
        if (DirectoryLinks.SkipReason is { } reason) Skip = reason;
    }
}

/// <summary>The <see cref="DirectoryLinkFactAttribute"/> rule for a theory.</summary>
public sealed class DirectoryLinkTheoryAttribute : TheoryAttribute
{
    public DirectoryLinkTheoryAttribute()
    {
        if (DirectoryLinks.SkipReason is { } reason) Skip = reason;
    }
}

internal static class DirectoryLinks
{
    private static readonly Lazy<string?> Probed = new(() => Probe(Plant));

    /// <summary>Null when a directory link can be planted on this machine, else why not.</summary>
    public static string? SkipReason => Probed.Value;

    /// <summary>Plants <paramref name="link"/> pointing at <paramref name="target"/>; throws when it cannot.</summary>
    public static void Plant(string link, string target)
    {
        if (!OperatingSystem.IsWindows())
        {
            Directory.CreateSymbolicLink(link, target);
            return;
        }
        var psi = new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var p = Process.Start(psi) ?? throw new IOException("cmd.exe did not start");
        if (!p.WaitForExit(30_000))
        {
            p.Kill();
            throw new IOException("mklink /J did not finish in 30 seconds");
        }
        if (p.ExitCode != 0)
            throw new IOException($"mklink /J exited {p.ExitCode}: {p.StandardError.ReadToEnd().Trim()}");
    }

    /// <summary>
    /// Plants one link in a scratch directory with <paramref name="plant"/> and checks a
    /// reparse point is really there. Null when it is, else the reason a test that needs one
    /// is skipped.
    /// </summary>
    internal static string? Probe(Action<string, string> plant)
    {
        const string Prefix = "skipped: this machine cannot plant a directory link (junction or symlink), so the reparse-point guard cannot be exercised here";
        var root = Path.Combine(Path.GetTempPath(), "patched-link-probe-" + Guid.NewGuid().ToString("N"));
        try
        {
            var target = Directory.CreateDirectory(Path.Combine(root, "target")).FullName;
            var link = Path.Combine(root, "link");
            try
            {
                plant(link, target);
            }
            catch (Exception ex)
            {
                return $"{Prefix}: {ex.Message}";
            }
            var attributes = File.Exists(link) || Directory.Exists(link) ? File.GetAttributes(link) : (FileAttributes?)null;
            return attributes is { } a && (a & FileAttributes.ReparsePoint) != 0
                ? null
                : $"{Prefix}: the plant reported success but left no reparse point";
        }
        catch (Exception ex)
        {
            return $"{Prefix}: {ex.Message}";
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }
}

/// <summary>PAT-2033: the probe behind <see cref="DirectoryLinkFactAttribute"/> can say no.</summary>
public sealed class DirectoryLinkFactTests
{
    [Fact]
    public void Probe_WhenThePlantIsRefused_GivesTheReason()
    {
        var reason = DirectoryLinks.Probe((_, _) => throw new UnauthorizedAccessException("mklink /J needs elevation here"));
        Assert.NotNull(reason);
        Assert.StartsWith("skipped: ", reason);
        Assert.EndsWith("mklink /J needs elevation here", reason);
    }

    [Fact]
    public void Probe_WhenThePlantLeavesNoReparsePoint_GivesTheReason()
    {
        var reason = DirectoryLinks.Probe((link, _) => Directory.CreateDirectory(link));
        Assert.NotNull(reason);
        Assert.EndsWith("left no reparse point", reason);
    }

    [Fact]
    public void Attribute_CarriesTheProbeResult_AsItsSkipReason() =>
        Assert.Equal(DirectoryLinks.SkipReason, new DirectoryLinkFactAttribute().Skip);
}

/// <summary>
/// PAT-2052 review: a test that needs a case-sensitive NTFS directory (fsutil file
/// setCaseSensitiveInfo). Probed once per run; where it cannot be made (off Windows, or
/// without the feature), the test is skipped with the reason rather than passed unexercised.
/// </summary>
public sealed class CaseSensitiveDirectoryFactAttribute : FactAttribute
{
    public CaseSensitiveDirectoryFactAttribute()
    {
        if (CaseSensitiveDirectories.SkipReason is { } reason) Skip = reason;
    }
}

internal static class CaseSensitiveDirectories
{
    private static readonly Lazy<string?> Probed = new(() =>
    {
        const string Prefix = "skipped: this machine cannot make a case-sensitive directory";
        if (!OperatingSystem.IsWindows()) return Prefix + ": not Windows";
        var root = Path.Combine(Path.GetTempPath(), "patched-cs-probe-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(root);
            Enable(root);
            Directory.CreateDirectory(Path.Combine(root, "a"));
            Directory.CreateDirectory(Path.Combine(root, "A"));
            return Directory.GetDirectories(root).Length == 2 ? null : Prefix + ": a and A were the same directory";
        }
        catch (Exception ex)
        {
            return $"{Prefix}: {ex.Message}";
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    });

    public static string? SkipReason => Probed.Value;

    /// <summary>Makes <paramref name="dir"/> case-sensitive; throws when it cannot.</summary>
    public static void Enable(string dir)
    {
        var psi = new ProcessStartInfo("fsutil.exe", $"file setCaseSensitiveInfo \"{dir}\" enable")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var p = Process.Start(psi) ?? throw new IOException("fsutil did not start");
        if (!p.WaitForExit(30_000))
        {
            p.Kill();
            throw new IOException("fsutil did not finish in 30 seconds");
        }
        if (p.ExitCode != 0)
            throw new IOException($"fsutil exited {p.ExitCode}: {p.StandardOutput.ReadToEnd().Trim()} {p.StandardError.ReadToEnd().Trim()}");
    }
}
