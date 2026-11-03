namespace Patched.Shared.Security;

/// <summary>
/// PAT-1329 (Defect B) belt-and-braces path-safety primitives, promoted out of
/// <c>ExtensionRemovalLogic</c> (PAT-1334) once <c>PendingUpdateApplier</c> became a
/// third privileged-recursive-delete consumer of the same pattern: a SYSTEM-privileged
/// process about to delete/move a path built (directly or indirectly) from data an
/// unprivileged local user can influence, needing to confirm the target is both
/// contained within a trusted root and reached via a chain with no reparse point
/// (NTFS junction/symlink) planted anywhere along it.
///
/// PAT-1334 empirical findings (Windows staging VM, 2026-08-13, dotnet SDK 10.0.301
/// host; repo targets net8.0-windows10.0.22621.0) that drive why the chain walk below
/// checks every ancestor component, not just the leaf:
///  - Junction AS the delete target itself (<c>Directory.Delete(&lt;junction&gt;, true)</c>):
///    SAFE — .NET detects the reparse point and unlinks the junction; the real
///    target's contents are untouched.
///  - Junction as an IMMEDIATE CHILD encountered while recursing: real data survives,
///    but the call throws <c>IOException</c> ("The parameter is incorrect.") and
///    aborts the delete part-way.
///  - Junction as an ANCESTOR (e.g. the enumerated root itself is a junction):
///    DESTRUCTIVE — <c>Directory.GetDirectories</c> on a junctioned root returns
///    paths THROUGH the link, and recursively deleting one of those wipes the real
///    target's contents. This is the case <see cref="HasReparsePointInChain"/> exists
///    to catch; a leaf-only reparse-point check does not.
/// </summary>
public static class PathSafety
{
    /// <summary>
    /// True when <paramref name="target"/> canonicalises to strictly inside
    /// <paramref name="root"/> (both via <see cref="Path.GetFullPath"/>), with
    /// an explicit directory-separator boundary between them — a naive
    /// <c>StartsWith</c> would wrongly let a sibling like "...\User Datax"
    /// pass a check meant for "...\User Data".
    /// </summary>
    public static bool IsContained(string root, string target)
    {
        string fullRoot, fullTarget;
        try
        {
            fullRoot   = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
            fullTarget = Path.TrimEndingDirectorySeparator(Path.GetFullPath(target));
        }
        catch { return false; }

        return fullTarget.StartsWith(
            fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// True when any path component from (but not including) <paramref name="trustedRoot"/>
    /// down to and including <paramref name="target"/> is a reparse point
    /// (PAT-1329, Defect B). Checking the leaf alone is not enough — see the class
    /// doc comment's three empirical cases; the ancestor case is the one this
    /// method exists to catch, since a leaf-only check would miss it entirely.
    ///
    /// .NET has no openat/O_NOFOLLOW equivalent, so unlike the macOS remover's
    /// fd-anchored descent (PAT-916), this is a check-then-act component walk,
    /// not a hold-open-throughout guarantee — a TOCTOU window remains between
    /// this call and the mutation that follows it. It closes the "never
    /// checked at all" gap, not the full POSIX-strength one; that's a
    /// deliberately honest limitation, not an oversight.
    ///
    /// <paramref name="target"/> is expected to be an already-canonicalised
    /// descendant of <paramref name="trustedRoot"/> (callers run this after
    /// <see cref="IsContained"/> has passed); if it somehow isn't, this fails
    /// closed (returns <see langword="true"/>, i.e. "treat as unsafe").
    /// </summary>
    public static bool HasReparsePointInChain(string trustedRoot, string target)
    {
        string fullRoot, fullTarget, relative;
        try
        {
            fullRoot   = Path.TrimEndingDirectorySeparator(Path.GetFullPath(trustedRoot));
            fullTarget = Path.TrimEndingDirectorySeparator(Path.GetFullPath(target));
            relative   = Path.GetRelativePath(fullRoot, fullTarget);
        }
        catch { return true; }

        if (relative.StartsWith("..") || Path.IsPathRooted(relative))
            return true; // target isn't actually under trustedRoot — refuse.

        var current = fullRoot;
        foreach (var segment in relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
        {
            if (segment.Length == 0 || segment == ".") continue;
            current = Path.Combine(current, segment);
            if (IsReparsePoint(current)) return true;
        }
        return false;
    }

    /// <summary>
    /// A path that doesn't exist is not (yet) a reparse point — nothing to
    /// refuse; the caller's own Exists check governs whether it proceeds.
    /// </summary>
    private static bool IsReparsePoint(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }
}
