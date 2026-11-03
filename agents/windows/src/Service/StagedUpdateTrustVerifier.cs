using System.Runtime.Versioning;
using Patched.Shared.Security;

namespace Patched.Service;

/// <summary>
/// PAT-2400: the owner, DACL and reparse-point check <see cref="PendingUpdateApplier"/>
/// makes on the staged update before it will launch an installer as LocalSystem, and
/// the removal of an object that fails it. A seam so the applier's decisions are
/// testable on every platform; the rules themselves need a real Windows ACL.
/// </summary>
internal interface IStagedUpdateTrustVerifier
{
    /// <summary>
    /// Null when <paramref name="path"/> is trusted. Otherwise one reason token:
    /// <c>absent</c>, <c>reparse_point</c>, <c>wrong_type</c>, <c>untrusted_owner</c>,
    /// <c>untrusted_acl</c>, <c>acl_unreadable</c> or <c>unverifiable</c>. Never throws.
    /// </summary>
    string? WhyUntrusted(string path, bool isDirectory);

    /// <summary>
    /// Takes an untrusted object off its path without descending into it, so the path
    /// can be recreated. Null when nothing is left at <paramref name="path"/>; otherwise
    /// why it is still there: <c>removal_failed</c> or <c>quarantine_full</c>. A
    /// directory that cannot simply be unlinked is moved under
    /// <paramref name="quarantineParent"/>. Never throws.
    /// </summary>
    string? Remove(string path, string quarantineParent);
}

/// <summary>
/// The file-system operations removal is built from, one object at a time. None of
/// them enumerates or descends into the object. A seam so the order of attempts in
/// <see cref="StagedObjectRemover"/> is testable without a hostile Windows ACL.
/// </summary>
internal interface IStagedObjectOps
{
    /// <summary>Attributes of the object itself (a link is not followed); null when absent.</summary>
    FileAttributes? Attributes(string path);

    /// <summary>Deletes a file, a link, or an empty directory. Throws when it cannot.</summary>
    void Unlink(string path, bool isDirectory);

    /// <summary>Renames the object itself. Throws when it cannot.</summary>
    void Rename(string path, string destination);

    /// <summary>
    /// Makes SYSTEM the owner of this one object and replaces its DACL with SYSTEM and
    /// Administrators full control, through a handle on the object that was checked to
    /// be a real file or directory. False when refused or failed.
    /// </summary>
    bool TakeOwnershipAndProtect(string path, bool isDirectory);

    /// <summary>How many quarantined objects already sit directly under the parent.</summary>
    int CountQuarantined(string quarantineParent);
}

/// <summary>
/// PAT-2400: takes one untrusted staged object off its path. It never enumerates or
/// recurses into the object: its contents may still be writable by whoever planted it,
/// and a recursive delete as LocalSystem through a directory swapped for a junction is
/// an arbitrary-delete primitive.
///
/// Cheapest first. A file, a link or an empty directory is unlinked. Any other
/// directory is renamed whole, in one call, to a random name under the hardened state
/// root, where nothing reads it. Only when that is refused (a planter-owned object
/// whose DACL denies SYSTEM) is the object itself reclaimed with
/// <see cref="IStagedObjectOps.TakeOwnershipAndProtect"/> and the same step retried. A
/// reparse point is only ever unlinked, never reclaimed or renamed.
///
/// Quarantine is capped at <see cref="MaxQuarantined"/>. A rename adds no bytes, and
/// after the state root's DACL is repaired a non-admin can plant nothing new, so the
/// count is bounded by what was planted beforehand; the cap makes that a guarantee
/// rather than an argument. At the cap removal is refused with its own reason and the
/// path stays failed closed until an operator clears the quarantine, because deleting
/// those trees here would mean descending into them.
///
/// Known and accepted: if reclaim succeeds but the rename is still refused (a handle
/// held open without delete sharing), the object stays in place owned by SYSTEM with a
/// SYSTEM/Administrators DACL and reads as trusted from then on. Its children do not:
/// every level is verified on its own before anything is staged into or run from it.
/// </summary>
internal sealed class StagedObjectRemover(IStagedObjectOps ops, ILogger log)
{
    internal const string QuarantinePrefix = "updates-untrusted-";
    internal const int MaxQuarantined = 8;

    /// <summary>Null when nothing is left at the path; else <c>removal_failed</c> or <c>quarantine_full</c>.</summary>
    internal string? Remove(string path, string quarantineParent)
    {
        try
        {
            if (ops.Attributes(path) is not { } attributes) return null;
            bool isDirectory = (attributes & FileAttributes.Directory) != 0;

            if (!Try(() => ops.Unlink(path, isDirectory)))
            {
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    return Failed(path, "a reparse point that could not be unlinked; it is never re-ACLed");

                if (!isDirectory)
                {
                    if (!ops.TakeOwnershipAndProtect(path, isDirectory: false) || !Try(() => ops.Unlink(path, false)))
                        return Failed(path, "file could not be deleted, also after taking ownership");
                }
                else
                {
                    if (ops.CountQuarantined(quarantineParent) >= MaxQuarantined)
                    {
                        log.LogError(
                            "staged-update-trust: {Count} quarantined directories ({Prefix}*) already exist under {Parent}; " +
                            "not moving {Path} aside until they are removed by an operator",
                            MaxQuarantined, QuarantinePrefix, quarantineParent, path);
                        return "quarantine_full";
                    }

                    string quarantine = Path.Combine(quarantineParent, QuarantinePrefix + Guid.NewGuid().ToString("N"));
                    if (!Try(() => ops.Rename(path, quarantine)) &&
                        (!ops.TakeOwnershipAndProtect(path, isDirectory: true) || !Try(() => ops.Rename(path, quarantine))))
                        return Failed(path, "directory could not be moved aside, also after taking ownership");

                    log.LogWarning(
                        "staged-update-trust: moved untrusted directory {Path} aside to {Quarantine}; its contents were not read or deleted",
                        path, quarantine);
                }
            }

            return ops.Attributes(path) is null ? null : Failed(path, "still present after removal");
        }
        catch (Exception ex)
        {
            log.LogError(ex, "staged-update-trust: could not remove untrusted {Path}", path);
            return "removal_failed";
        }
    }

    private string Failed(string path, string detail)
    {
        log.LogError("staged-update-trust: could not remove untrusted {Path}: {Detail}", path, detail);
        return "removal_failed";
    }

    private bool Try(Action operation)
    {
        try { operation(); return true; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log.LogInformation("staged-update-trust: {Message}", ex.Message);
            return false;
        }
    }
}

/// <summary>
/// Production <see cref="IStagedUpdateTrustVerifier"/> and <see cref="IStagedObjectOps"/>.
/// Trust is exactly <see cref="SecureStagingDirectory"/>'s rule: owned by SYSTEM or
/// Administrators, no write-capable Allow ACE for anyone else, not a reparse point. An
/// object whose owner or DACL cannot be read is untrusted (<c>acl_unreadable</c> when
/// access is denied, which is what a DACL denying SYSTEM produces). Off Windows there
/// is no ACL to read, so nothing is trusted; the shipping agent never takes that
/// branch. Removal is <see cref="StagedObjectRemover"/> over the operations below.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsStagedUpdateTrustVerifier(ILogger log) : IStagedUpdateTrustVerifier, IStagedObjectOps
{
    internal const string QuarantinePrefix = StagedObjectRemover.QuarantinePrefix;

    public string? WhyUntrusted(string path, bool isDirectory)
    {
        if (!OperatingSystem.IsWindows()) return "unverifiable";
        try
        {
            return SecureStagingDirectory.DescribeUntrusted(path, isDirectory);
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "staged-update-trust: could not read owner/DACL of {Path}; treating it as untrusted", path);
            return ex is UnauthorizedAccessException ? "acl_unreadable" : "unverifiable";
        }
    }

    public string? Remove(string path, string quarantineParent) =>
        new StagedObjectRemover(this, log).Remove(path, quarantineParent);

    public FileAttributes? Attributes(string path)
    {
        try { return File.GetAttributes(path); }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
    }

    public void Unlink(string path, bool isDirectory)
    {
        if (isDirectory) Directory.Delete(path, recursive: false);
        else File.Delete(path);
    }

    public void Rename(string path, string destination) => Directory.Move(path, destination);

    public bool TakeOwnershipAndProtect(string path, bool isDirectory)
    {
        bool reclaimed = PrivilegedReclaim.TryTakeOwnershipAndProtect(path, isDirectory, out string failure);
        if (reclaimed)
            log.LogWarning("staged-update-trust: took ownership of {Path} and reset its DACL to SYSTEM/Administrators (that object only)", path);
        else
            log.LogError("staged-update-trust: could not take ownership of {Path}: {Failure}", path, failure);
        return reclaimed;
    }

    public int CountQuarantined(string quarantineParent) =>
        Directory.GetFileSystemEntries(quarantineParent, StagedObjectRemover.QuarantinePrefix + "*", SearchOption.TopDirectoryOnly).Length;
}
