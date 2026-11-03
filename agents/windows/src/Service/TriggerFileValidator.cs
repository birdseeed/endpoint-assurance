using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Patched.Shared.Contract;

namespace Patched.Service;

/// <summary>
/// Shared trigger-file validation used by every consumer that trusts a file
/// dropped into the ACL-hardened trigger directory (PAT-307): filename shape,
/// owner-SID acceptability (PAT-687), and size/schema validation
/// (TriggerRequestValidator). Extracted under PAT-906 so TriggerWatcher's
/// destructive drain-and-delete path and OsUpdateChecker's read-only
/// deferral counter apply the identical checks -- neither re-implements (and
/// neither can silently under-implement) its own raw file scan.
/// </summary>
[SupportedOSPlatform("windows")]
public static class TriggerFileValidator
{
    /// <summary>
    /// Result of reading a trigger file's owner from the filesystem.
    /// <paramref name="Found"/> is false when the owner could not be
    /// determined at all (distinct from an owner that was read but rejected).
    /// </summary>
    public readonly record struct OwnerInfo(bool Found, string Sid, string? Account);

    /// <summary>The trigger file size cap in bytes (shared with the post-parse
    /// check in <see cref="TriggerRequestValidator"/>).</summary>
    public static int MaxFileSizeBytes => TriggerRequestValidator.MaxFileSizeBytes;

    /// <summary>
    /// Hard ceiling on how many *.trigger files a single drain/count pass will
    /// even attempt to open. The trigger directory is writable by any
    /// authenticated user (TriggerAcl grants FILE_ADD_FILE), so a low-privilege
    /// user can plant an arbitrary number of files -- including ones deliberately
    /// left unopenable (locked) or invalid so they are never consumed. This bound
    /// caps the open/validate work per pass (walking the directory itself is
    /// inherently O(entries) for any consumer and is not capped -- see
    /// TriggerWatcher's class doc for why every walk cost is bounded by
    /// attacker-expended resources); a failed/rejected file costs one cheap
    /// FileStream-open attempt, so the bound can sit far above any legitimate
    /// backlog (PAT-906, hardened for starvation resistance in the PAT-906
    /// follow-up).
    ///
    /// Deliberately NOT the cap on how many valid triggers get accepted in a
    /// pass -- that is <see cref="TriggerRateLimiter"/>'s per-drain limit, which
    /// only counts files that pass full validation. Decoupling the two means a
    /// planted flood of invalid/locked files (which never reach the rate
    /// limiter) cannot consume the same budget that gates real triggers, so it
    /// cannot hide a legitimate trigger enumerated after it within one pass as
    /// long as the flood stays under this ceiling.
    ///
    /// A flood that does exceed this ceiling does not achieve permanent
    /// starvation either: invalid-but-openable files are deleted the moment
    /// they're examined (self-cleaning across passes), and TriggerWatcher
    /// additionally quarantines (force-deletes) any file that stays unopenable
    /// across several passes -- see TriggerWatcher's locked-file tracking.
    /// This constant only has to be "comfortably larger than any real backlog,"
    /// not "large enough to survive an unbounded flood in one pass."
    /// </summary>
    public const int MaxFilesEnumeratedPerPass = 2048;

    /// <summary>
    /// Reads a trigger file's UTF-8 text from an already-open <paramref name="stream"/>,
    /// bounded to the size cap. Returns false (oversized -- caller rejects)
    /// when the stream holds more than the cap.
    ///
    /// PAT-906: reading off the OPEN handle -- never from a prior
    /// <see cref="FileInfo.Length"/> stat -- closes the TOCTOU window where an
    /// authenticated user (TriggerAcl grants FILE_ADD_FILE) grows or replaces
    /// the file between a stat and the read. At most cap+1 bytes are ever
    /// allocated regardless of the file's true on-disk size: cap+1 is enough
    /// to tell "over the cap" while never buffering the whole of a planted
    /// gigabyte file. A leading UTF-8 BOM is stripped -- the tray and Self
    /// Service write triggers via <c>File.WriteAllText(..., Encoding.UTF8)</c>
    /// which emits one, and the previous StreamReader-based read stripped it
    /// automatically (the JSON parser rejects a leading BOM).
    /// </summary>
    public static bool TryReadCapped(Stream stream, out string json, out long bytesRead)
    {
        json = "";
        var cap = TriggerRequestValidator.MaxFileSizeBytes;
        var buffer = new byte[cap + 1];
        var total = 0;
        int n;
        while (total < buffer.Length &&
               (n = stream.Read(buffer, total, buffer.Length - total)) > 0)
            total += n;

        bytesRead = total;
        if (total > cap)
            return false;

        var start = (total >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF) ? 3 : 0;
        json = System.Text.Encoding.UTF8.GetString(buffer, start, total - start);
        return true;
    }

    public static bool IsValidFilename(string filename)
    {
        // Accept only GUID.trigger or uuid-style names; reject path separators and null bytes.
        if (filename.Contains('/') || filename.Contains('\\') || filename.Contains('\0'))
            return false;
        if (!filename.EndsWith(".trigger", StringComparison.OrdinalIgnoreCase))
            return false;
        // Max filename length guard.
        return filename.Length <= 128;
    }

    /// <summary>
    /// Read the owner SID (and, best-effort, the translated account name) of a
    /// trigger file. <see cref="OwnerInfo.Found"/> is false if the owner
    /// cannot be determined. <paramref name="onError"/> is an optional hook
    /// so callers that have a logger (TriggerWatcher) can record the
    /// underlying exception for diagnostics; callers that don't (the
    /// read-only OsUpdateChecker count) can omit it and fail silently, same
    /// as before this method was extracted.
    /// </summary>
    public static OwnerInfo ReadOwner(string path, Action<Exception>? onError = null)
    {
        try
        {
            var security = new FileSecurity(path, AccessControlSections.Owner);
            if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier sid)
                return new OwnerInfo(false, "", null);

            string? account;
            try
            {
                account = ((NTAccount)sid.Translate(typeof(NTAccount))).Value;
            }
            catch
            {
                // Unresolvable SID (e.g. deleted account) -- keep the raw SID.
                account = null;
            }
            return new OwnerInfo(true, sid.Value, account);
        }
        catch (Exception ex)
        {
            onError?.Invoke(ex);
            return new OwnerInfo(false, "", null);
        }
    }

    /// <summary>
    /// Fully validates one trigger file's identity and content: filename
    /// shape, owner-SID acceptability, and size/schema (via
    /// <see cref="TriggerRequestValidator"/>). Takes the owner and file
    /// content as parameters (rather than reading them itself) so:
    ///   (a) callers keep control of their own file-locking mode (TriggerWatcher
    ///       reads exclusively because it is about to delete; OsUpdateChecker
    ///       reads non-exclusively because it only counts), and
    ///   (b) tests can inject a fake owner without manipulating real ACLs.
    /// Does not delete the file and does not rate-limit -- both are
    /// per-consumer concerns layered on top by the caller.
    /// </summary>
    public static bool TryValidate(
        string filename,
        OwnerInfo owner,
        string json,
        long fileSizeBytes,
        out TriggerRequest? request,
        out string? error)
    {
        request = null;
        error   = null;

        if (!IsValidFilename(filename))
        {
            error = "invalid filename";
            return false;
        }

        if (!owner.Found)
        {
            error = "owner could not be read";
            return false;
        }
        if (!TriggerOwnerPolicy.IsAcceptableOwnerSid(owner.Sid))
        {
            error = $"foreign-owned trigger (owner SID {owner.Sid})";
            return false;
        }

        if (!TriggerRequestValidator.TryValidate(json, fileSizeBytes, out request, out error))
        {
            request = null;
            return false;
        }

        return true;
    }
}
