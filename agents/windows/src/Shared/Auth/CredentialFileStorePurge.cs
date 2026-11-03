namespace Patched.Shared.Auth;

/// <summary>
/// PAT-1764: deletes the agent's plaintext credential files (%ProgramData%\Patched\creds)
/// during the uninstall purge, which runs as SYSTEM.
///
/// A SYSTEM delete on a path under %ProgramData% is an arbitrary-file-delete primitive
/// if the path can be redirected: a standard user who pre-creates %ProgramData%\Patched
/// owns it, and can swap creds\ for a junction to \RPC Control with an object-manager
/// symlink named like one of these files pointing at any file on the system. So nothing
/// is deleted until the whole store passes the checks the agent already uses for its
/// privileged paths:
///   * the state root and the creds directory pass
///     <c>SecureStagingDirectory.VerifyTrusted</c> (not a reparse point, owned by SYSTEM
///     or Administrators, no write-capable ACE for anyone else), read-only, never
///     repaired, because repairing an attacker-planted directory would bless it;
///   * <c>PathSafety.HasReparsePointInChain(stateDir, path)</c> is false for the creds
///     directory and for every target file.
/// If any check fails or throws, the whole file-store purge is skipped and reported as
/// <see cref="UntrustedFailure"/>. Each file's chain is checked again immediately before
/// its delete, and a change mid-purge stops the remaining deletes. The Credential Manager
/// and registry steps are not path-based and still run.
///
/// Deletes use <see cref="File.Delete"/> (DeleteFileW), which removes a symlink at the
/// final component rather than its target. No helper in the codebase deletes with
/// no-follow semantics for intermediate components; the chain walk covers those, with
/// the check-then-act window PathSafety documents.
///
/// All checks and the delete are injected so tests use fakes.
/// </summary>
public sealed class CredentialFileStorePurge
{
    public const string UntrustedFailure =
        "credential file store: untrusted path (reparse point or untrusted owner)";

    private readonly string _stateDir;
    private readonly string _credsDir;
    private readonly IReadOnlyList<string> _fileNames;
    private readonly Func<string, bool> _directoryExists;
    private readonly Action<string> _verifyTrustedDirectory;
    private readonly Func<string, string, bool> _hasReparsePointInChain;
    private readonly Func<string, CredentialPurgeStep> _deleteFile;

    /// <param name="verifyTrustedDirectory">Throws when the directory is not trusted.</param>
    /// <param name="hasReparsePointInChain">(trusted root, target) as PathSafety.HasReparsePointInChain.</param>
    /// <param name="deleteFile">Deletes the file at a full path; a missing file is success.</param>
    public CredentialFileStorePurge(
        string stateDir,
        string credsDir,
        IReadOnlyList<string> fileNames,
        Func<string, bool> directoryExists,
        Action<string> verifyTrustedDirectory,
        Func<string, string, bool> hasReparsePointInChain,
        Func<string, CredentialPurgeStep> deleteFile)
    {
        _stateDir = stateDir;
        _credsDir = credsDir;
        _fileNames = fileNames;
        _directoryExists = directoryExists;
        _verifyTrustedDirectory = verifyTrustedDirectory;
        _hasReparsePointInChain = hasReparsePointInChain;
        _deleteFile = deleteFile;
    }

    public IReadOnlyList<string> Run()
    {
        List<string> paths;
        try
        {
            if (!_directoryExists(_stateDir))
                return [];
            _verifyTrustedDirectory(_stateDir);

            // Before the existence check: a junction to a non-directory target can
            // report as missing, and must still be refused rather than skipped quietly.
            if (_hasReparsePointInChain(_stateDir, _credsDir))
                return [UntrustedFailure];
            if (!_directoryExists(_credsDir))
                return [];
            _verifyTrustedDirectory(_credsDir);

            paths = _fileNames.Select(name => Path.Combine(_credsDir, name)).ToList();
            if (paths.Any(path => _hasReparsePointInChain(_stateDir, path)))
                return [UntrustedFailure];
        }
        catch (Exception)
        {
            return [UntrustedFailure];
        }

        var failures = new List<string>();
        for (var i = 0; i < paths.Count; i++)
        {
            bool unsafeNow;
            try { unsafeNow = _hasReparsePointInChain(_stateDir, paths[i]); }
            catch (Exception) { unsafeNow = true; }
            if (unsafeNow)
            {
                failures.Add(UntrustedFailure);
                break;
            }

            CredentialPurgeStep step;
            try { step = _deleteFile(paths[i]); }
            catch (Exception ex) { step = CredentialPurgeStep.Failed(ex.GetType().Name); }
            if (!step.Succeeded)
                failures.Add($"credential file {_fileNames[i]}: {step.Error}");
        }
        return failures;
    }

    /// <summary>
    /// Production delete: a missing file is success; the error names the exception type
    /// only, never the file contents.
    /// </summary>
    public static CredentialPurgeStep DeleteFileReporting(string path)
    {
        try
        {
            if (!File.Exists(path))
                return CredentialPurgeStep.Removed;
            File.Delete(path);
            return File.Exists(path)
                ? CredentialPurgeStep.Failed("file still present after delete")
                : CredentialPurgeStep.Removed;
        }
        catch (Exception ex)
        {
            return CredentialPurgeStep.Failed(ex.GetType().Name);
        }
    }
}
