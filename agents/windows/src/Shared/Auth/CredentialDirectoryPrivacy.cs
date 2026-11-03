using System.Runtime.Versioning;
using Patched.Shared.Security;

namespace Patched.Shared.Auth;

/// <summary>Only an empty, integrity-trusted credential directory may have its
/// read grants removed before a new secret is written. Existing exposed material
/// is never blessed by changing its ACL. Callers first verify the state root.</summary>
internal static class CredentialDirectoryPrivacy
{
    internal static void Ensure(string directory, Action<string> ensureIntegrity,
        Func<string, bool> isPrivate, Func<string, bool> isEmpty, Action<string> hardenPrivate)
    {
        ensureIntegrity(directory); // Refuse every unsafe write grant before any repair.
        if (isPrivate(directory)) return; // Preserve an existing private store verbatim.
        if (!isEmpty(directory))
            throw new SecureStagingDirectory.UntrustedDirectoryException(
                "The non-private credential directory contains existing material; administrator reprovisioning is required.");
        // A verified parent and directory exclude unprivileged entry creation races.
        hardenPrivate(directory);
        if (!isPrivate(directory))
            throw new SecureStagingDirectory.UntrustedDirectoryException("Credential privacy could not be established.");
    }

    [SupportedOSPlatform("windows")]
    internal static void EnsureWindows(string directory) => Ensure(directory,
        path => SecureStagingDirectory.EnsureHardenedTrustedInstallerDirectory(path, repairExisting: false),
        path => SecureStagingDirectory.DescribeUntrusted(path, isDirectory: true, requirePrivate: true) is null,
        path => !Directory.EnumerateFileSystemEntries(path).Any(),
        path => SecureStagingDirectory.EnsureHardenedTrustedInstallerDirectory(path));
}
