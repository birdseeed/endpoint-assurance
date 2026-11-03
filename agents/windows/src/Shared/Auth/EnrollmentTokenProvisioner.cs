using System.Text;

namespace Patched.Shared.Auth;

/// <summary>
/// Outcome of provisioning the installer's enrolment token. <see cref="Error"/> never
/// carries the token value.
/// </summary>
public readonly record struct EnrollmentTokenProvisionResult(bool Succeeded, string? Error)
{
    public static EnrollmentTokenProvisionResult Provisioned => new(true, null);
    public static EnrollmentTokenProvisionResult Failed(string error) => new(false, error);
}

/// <summary>
/// Establishes a directory the agent is about to write a secret into: creates it with the
/// protected DACL, or verifies an existing path. A credential child with an
/// integrity-trusted read-only baseline may be made private only while entirely empty.
/// Existing exposed material and every unsafe write grant are refused without repair.
/// </summary>
public delegate void HardenDirectory(string directory, bool allowStandardUserRead);

/// <summary>
/// PAT-1755: writes the installer-supplied enrolment token into the agent's credential
/// file store (<c>%ProgramData%\Patched\creds\enrollment-token</c>), the source
/// <see cref="CredentialStore.LoadForStartup(Microsoft.Extensions.Logging.ILogger?)"/>
/// already reads and PAT-1764's uninstall purge already deletes.
///
/// Why a custom action rather than a WiX RegistryValue: <c>Hidden="yes"</c> on an MSI
/// property masks only the property-level log entries ("PROPERTY CHANGE", the closing
/// "Property(S)" dump and the "Command Line:" entry). The execute-script op that performs
/// the write is logged with its resolved data regardless, so a verbose (/l*v) log of a bare
/// upgrade contained
///   <c>Executing op: RegAddValue(Name=EnrollmentToken,Value=&lt;token&gt;,)</c>
/// (WIN-STAGING, 2026-09-15). Only msidbCustomActionTypeHideTarget, which WiX authors as
/// <c>HideTarget="yes"</c> on a custom action, suppresses that, so the write moved here.
///
/// This runs as LocalSystem from a deferred, non-impersonated custom action before the
/// service has ever started, so <c>%ProgramData%\Patched</c> and its <c>creds</c> child
/// still carry whatever DACL they inherited from <c>%ProgramData%</c> when the MSI created
/// them. A SYSTEM write into a path an unprivileged user can influence is an
/// arbitrary-file-write primitive, so nothing is written until:
///   * the state root and the creds directory have both been established through
///     <c>SecureStagingDirectory.EnsureHardenedTrustedInstallerDirectory</c>, which refuses
///     existing unsafe write DACLs, reparse points or untrusted owners without repair;
///     the credential-specific privacy helper removes read grants only from an entirely
///     empty integrity-trusted child, never blessing existing exposed contents; and
///   * <c>PathSafety.HasReparsePointInChain</c> is false for the token file itself.
/// The write then unlinks whatever is already at the path (<see cref="File.Delete"/>
/// removes a symlink at the final component rather than writing through it) and creates the
/// file with <see cref="FileMode.CreateNew"/>, so a link planted in the check-then-act
/// window fails the write instead of redirecting it. The file needs no ACL of its own: it
/// inherits the hardened directory's protected DACL, SYSTEM and Administrators full control
/// and nothing else.
///
/// Every host operation is injected, so the tests run on any OS.
/// </summary>
public sealed class EnrollmentTokenProvisioner
{
    /// <summary>
    /// The one file name the installer writes, the service reads
    /// (<c>CredentialStore.ReadCredsFile</c>) and the uninstall purge deletes
    /// (<see cref="CredentialStore.AgentCredentialFileNames"/>). Single source of truth, so
    /// the installer cannot write somewhere the service never reads or the uninstall never
    /// clears.
    /// </summary>
    public const string FileName = "enrollment-token";

    /// <summary>
    /// Server-minted tokens are base64url. A longer or non-printable value is not one, so it
    /// is refused rather than written: sending it could only draw a 401 and suspend the
    /// device for a token that was never real (the PAT-1765 reasoning, applied at the
    /// installer boundary).
    /// </summary>
    public const int MaxTokenLength = 4096;

    public const string NoTokenError = "no enrolment token was supplied";

    public const string ShapeError =
        "the enrolment token is not a single run of printable ASCII characters of at most 4096 characters";

    public const string UntrustedStoreError =
        "the credential file store cannot be trusted: a reparse point in its path, an owner that is not " +
        "SYSTEM or Administrators, or a DACL that grants write access to someone else";

    public const string WriteError = "the enrolment token file could not be written";

    private readonly string _stateDir;
    private readonly string _credsDir;
    private readonly HardenDirectory _hardenDirectory;
    private readonly Func<string, string, bool> _hasReparsePointInChain;
    private readonly Func<string, string, EnrollmentTokenProvisionResult> _writeFile;

    /// <param name="hardenDirectory">Throws when the directory cannot be trusted.</param>
    /// <param name="hasReparsePointInChain">(trusted root, target) as PathSafety.HasReparsePointInChain.</param>
    /// <param name="writeFile">(full path, file contents). Must not follow a link at the final component.</param>
    public EnrollmentTokenProvisioner(
        string stateDir,
        string credsDir,
        HardenDirectory hardenDirectory,
        Func<string, string, bool> hasReparsePointInChain,
        Func<string, string, EnrollmentTokenProvisionResult> writeFile)
    {
        _stateDir = stateDir;
        _credsDir = credsDir;
        _hardenDirectory = hardenDirectory;
        _hasReparsePointInChain = hasReparsePointInChain;
        _writeFile = writeFile;
    }

    /// <summary>Where the token is written. Not a secret; safe to name in a report.</summary>
    public string TokenFilePath => Path.Combine(_credsDir, FileName);

    /// <summary>
    /// Writes <paramref name="suppliedToken"/> to <see cref="TokenFilePath"/>. Returns a
    /// failure, having written nothing, when the token is absent or malformed or when the
    /// store cannot be trusted. The caller turns a failure into a non-zero exit code: an
    /// install that was given a token and did not provision it must fail loudly rather than
    /// leave a device that can never enrol.
    /// </summary>
    public EnrollmentTokenProvisionResult Provision(string? suppliedToken)
    {
        if (!TryNormalise(suppliedToken, out var token, out var shapeError))
            return EnrollmentTokenProvisionResult.Failed(shapeError);

        try
        {
            // Parent before child: the creds DACL means nothing until the root it sits under
            // has itself been established and verified. allowStandardUserRead on the root
            // matches StateDirectoryBootstrap (the Tray reads root-level status files); its
            // ObjectInherit + NoPropagateInherit ACE deliberately cannot reach a file in
            // creds, which is hardened with no standard-user access at all.
            _hardenDirectory(_stateDir, true);
            _hardenDirectory(_credsDir, false);

            if (_hasReparsePointInChain(_stateDir, TokenFilePath))
                return EnrollmentTokenProvisionResult.Failed(UntrustedStoreError);
        }
        catch (Exception ex)
        {
            return EnrollmentTokenProvisionResult.Failed($"{UntrustedStoreError} ({ex.GetType().Name})");
        }

        try
        {
            // Trailing newline matches how the macOS installer writes /etc/patched/* and how
            // a hand-provisioned file is normally created; CredentialStore trims on read.
            return _writeFile(TokenFilePath, token + "\n");
        }
        catch (Exception ex)
        {
            return EnrollmentTokenProvisionResult.Failed($"{WriteError} ({ex.GetType().Name})");
        }
    }

    /// <summary>
    /// Trims the supplied value and accepts it only as a single run of printable ASCII of at
    /// most <see cref="MaxTokenLength"/> characters. Interior whitespace is rejected by the
    /// printable check (space is below '!'), so a value carrying a newline can never become
    /// two lines in the token file.
    /// </summary>
    public static bool TryNormalise(string? suppliedToken, out string token, out string error)
    {
        token = (suppliedToken ?? string.Empty).Trim();

        if (token.Length == 0)
        {
            error = NoTokenError;
            return false;
        }

        if (token.Length > MaxTokenLength)
        {
            error = ShapeError;
            return false;
        }

        foreach (var character in token)
        {
            if (character < '!' || character > '~')
            {
                error = ShapeError;
                return false;
            }
        }

        error = "";
        return true;
    }

    /// <summary>
    /// Production write. Unlinks anything already at the path, then creates the file with
    /// <see cref="FileMode.CreateNew"/> and no sharing, so a symlink planted between the
    /// trust check and the write fails the call rather than redirecting a SYSTEM write. The
    /// error names the exception type only, never the token.
    ///
    /// PAT-1793 considered replacing this with a stage-then-rename (write to
    /// <c>enrollment-token.new</c> with the same CreateNew defence, then
    /// <c>File.Move(..., overwrite: true)</c> onto the final path) so an unconsumed token is
    /// not lost if the write fails partway through disk-full. That was not implemented: the
    /// staged rename's final step is a Win32 <c>MoveFileEx</c> with
    /// <c>MOVEFILE_REPLACE_EXISTING</c>, and Microsoft's own enumeration of how symbolic links
    /// change standard file-function behaviour ("Symbolic Link Effects on File Systems
    /// Functions") documents <c>CopyFile</c> following a destination-side symlink and
    /// overwriting its target rather than the link, but does not list <c>MoveFile</c> /
    /// <c>MoveFileEx</c> at all. With no authoritative confirmation that
    /// <c>MOVEFILE_REPLACE_EXISTING</c> replaces rather than follows a reparse point planted at
    /// the destination in the staging window, adopting it risks silently reintroducing the
    /// exact TOCTOU redirect the delete-then-<see cref="FileMode.CreateNew"/> sequence above
    /// exists to close, on a SYSTEM-privileged write path. The failure mode being traded away
    /// (losing an unconsumed token on disk-full, which fails the install closed via
    /// <c>Return="check"</c> and is cleared by a retry with a fresh token) is rare, low
    /// severity and self-recovering; a confirmed arbitrary-file-write primitive would not be.
    /// Left as-is until a Windows install can confirm <c>MoveFileEx</c>'s reparse-point
    /// behaviour on the destination side, not assumed from its source-side/`CopyFile` behaviour.
    /// </summary>
    public static EnrollmentTokenProvisionResult WriteFileReporting(string path, string contents)
    {
        try
        {
            File.Delete(path);

            var bytes = Encoding.UTF8.GetBytes(contents);
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(flushToDisk: true);
            }

            return File.Exists(path)
                ? EnrollmentTokenProvisionResult.Provisioned
                : EnrollmentTokenProvisionResult.Failed($"{WriteError}: it is not present after the write");
        }
        catch (Exception ex)
        {
            return EnrollmentTokenProvisionResult.Failed($"{WriteError} ({ex.GetType().Name})");
        }
    }
}
