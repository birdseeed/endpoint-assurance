using System.Runtime.Versioning;
using System.Security.AccessControl;
using Patched.Shared.IdeExtensions;
using Patched.Shared.Security;

namespace Patched.Shared.Auth;

/// <summary>
/// Read-only trust boundary for the optional plaintext credential source. Production
/// policy is immutable. Delegates let portable tests exercise refusal and source
/// fallback without touching ProgramData, Credential Manager or registry storage.
/// </summary>
internal sealed class CredentialFileTrust
{
    private readonly string _root;
    private readonly string _creds;
    private readonly Func<string, bool, string?> _describe;
    private readonly Func<string, Stream> _open;
    private readonly Func<Stream, string, bool> _verifyOpenFile;

    internal CredentialFileTrust(string root, string creds,
        Func<string, bool, string?> describe, Func<string, Stream> open,
        Func<Stream, string, bool> verifyOpenFile)
    {
        _root = root;
        _creds = creds;
        _describe = describe;
        _open = open;
        _verifyOpenFile = verifyOpenFile;
    }

    [SupportedOSPlatform("windows")]
    internal static CredentialFileTrust CreateWindows(string root, string creds) => new(
        root, creds, (path, isDirectory) => SecureStagingDirectory.DescribeUntrusted(
            path, isDirectory, requirePrivate: !path.Equals(root, StringComparison.OrdinalIgnoreCase)),
        path => new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read),
        (stream, path) =>
        {
            var file = (FileStream)stream;
            var parent = WindowsFileIdentity.FinalPathOfDirectory(Path.GetDirectoryName(path)!);
            if (parent is null || !WindowsFileIdentity.IsExpectedRegularFile(
                    file.SafeFileHandle, Path.Combine(parent, Path.GetFileName(path))))
                return false;
            // ACL retrieval is bound to the same open handle as the eventual read.
            var acl = file.GetAccessControl();
            SecureStagingDirectory.VerifyTrustedOwner(acl, path, "file");
            SecureStagingDirectory.VerifyTrustedAccessRules(acl, path, "file");
            SecureStagingDirectory.VerifyPrivateAccessRules(acl, path);
            return true;
        });

    private string FilePath(string name)
    {
        if (string.IsNullOrEmpty(name) || Path.GetFileName(name) != name || name is "." or "..")
            throw new ArgumentException("A credential file must have a fixed leaf name.", nameof(name));
        return Path.Combine(_creds, name);
    }

    private bool ValidatePath(string path)
    {
        foreach (var entry in new[] { (_root, true), (_creds, true), (path, false) })
        {
            var reason = _describe(entry.Item1, entry.Item2);
            if (reason == "absent") return false;
            if (reason is not null) throw new IOException("The credential file store is untrusted.");
        }
        return true;
    }

    private Stream? OpenTrusted(string name)
    {
        var path = FilePath(name);
        if (!ValidatePath(path)) return null;
        var stream = _open(path);
        try
        {
            if (!_verifyOpenFile(stream, path) || !ValidatePath(path))
                throw new IOException("The open credential file is untrusted.");
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    /// <summary>Unsafe, absent or unreadable optional files contribute no source value.
    /// A trusted empty file still contributes an empty string, preserving precedence.</summary>
    internal string? ReadOptional(string name)
    {
        try
        {
            using var stream = OpenTrusted(name);
            if (stream is null) return null;
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd().Trim();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
            System.Security.SecurityException or SecureStagingDirectory.UntrustedDirectoryException)
        { return null; }
    }

    /// <summary>An unsafe suspension path stops work rather than bypassing revocation.</summary>
    internal bool IsPresentOrUnsafe(string name)
    {
        try { using var stream = OpenTrusted(name); return stream is not null; }
        catch { return true; }
    }

    internal void DeleteIfTrusted(string name)
    {
        // Holding the read handle excludes writers/deleters during verification. The
        // verified ancestors exclude unprivileged replacement after it is released.
        using (var stream = OpenTrusted(name))
        {
            if (stream is null) return;
        }
        File.Delete(FilePath(name));
    }

    [SupportedOSPlatform("windows")]
    internal void MarkSuspended()
    {
        SecureStagingDirectory.EnsureHardenedTrustedInstallerDirectory(
            _root, allowStandardUserRead: true, repairExisting: false);
        CredentialDirectoryPrivacy.EnsureWindows(_creds);
        using (var existing = OpenTrusted("suspended"))
        {
            if (existing is not null) return;
        }
        // CreateNew cannot truncate or follow a newly planted final-component link.
        // Failures propagate; no caller may treat an unwritten marker as persisted.
        using var created = new FileStream(FilePath("suspended"), FileMode.CreateNew,
            FileAccess.Write, FileShare.None);
        created.Flush(flushToDisk: true);
    }
}
