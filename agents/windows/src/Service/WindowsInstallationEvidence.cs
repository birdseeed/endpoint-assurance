using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using Patched.Shared.Contract;
using Patched.Shared.IdeExtensions;
using Patched.Shared.InstallationEvidence;
using Patched.Shared.Security;

namespace Patched.Service;

// Only invoked in a killable helper. No execution of observed files, network trust
// retrieval, profile loading, registry changes or filesystem writes.
internal static class WindowsInstallationEvidence
{
    internal const long MaximumFileBytes = 256L * 1024 * 1024;

    // Winnt.h ACCESS_MASK generic bits, not object-specific FileSystemRights:
    // bit 28 = GENERIC_ALL; bit 30 = GENERIC_WRITE. Read/execute are bits 31/29.
    // An unmapped generic grant must not evade the mutation-access check.
    internal const FileSystemRights GenericAll = (FileSystemRights)0x10000000;
    internal const FileSystemRights GenericWrite = (FileSystemRights)0x40000000;
    private const FileSystemRights MutationRights = FileSystemRights.Write | FileSystemRights.Delete |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | GenericAll | GenericWrite;

    internal static bool GrantsMutation(FileSystemRights rights) => (rights & MutationRights) != 0;

    internal static AppInstallationEvidence Read(ReviewedInstallationTarget target) =>
        ReadResolved(target.InstallPath, target.ExecutablePath, ExecutableResolutions.ReviewedTarget,
            SignatureProbeContext.Uncached()).Evidence;

    // One executable's evidence. The reviewed-target helper and the PAT-2116 all-apps
    // coverage helper both come through here, so the path rules, the locked open and the
    // verdict are identical for both. CacheKey/CacheObservation are set only when the
    // verdict came from a completed verification the parent may reuse.
    internal static ResolvedEvidence ReadResolved(string installPath, string path, string resolution,
        SignatureProbeContext context)
    {
        try
        {
            if (!IsSafePath(path) || !IsSafePath(installPath) ||
                !path.StartsWith(installPath.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase) ||
                !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                return new(AppInstallationEvidence.Unavailable("path_not_supported") with { ExecutableResolution = resolution });
            using var file = OpenLocalFile(path);
            if (file.Stream.Length <= 0 || file.Stream.Length > MaximumFileBytes)
                return new(AppInstallationEvidence.Unavailable("file_size_limit") with { ExecutableResolution = resolution });
            var hash = Convert.ToHexString(SHA256.HashData(file.Stream)).ToLowerInvariant();
            file.Stream.Position = 0;
            var key = new SignatureCacheKey(hash, file.Stream.Length, file.LastWriteFileTime);
            SignatureObservation observation;
            var fresh = false;
            if (context.TryGetCached(key, out var cached)) observation = cached;
            else
            {
                try { observation = ReadSignature(path, file.Stream.SafeFileHandle, context); fresh = true; }
                catch { observation = SignatureObservation.Unknown(); }
            }
            var evidence = new AppInstallationEvidence
            {
                CollectionStatus = SignatureVerdictLogic.CollectionStatusFor(observation),
                InstallPath = installPath,
                ExecutablePath = path,
                ExecutableSha256 = hash,
                ExecutableResolution = resolution,
                Errors = observation.Error is null ? [] : [observation.Error],
            }.WithSignature(observation);
            return fresh && SignatureVerdictCache.Valid(key) ? new(evidence, key, observation) : new(evidence);
        }
        catch { return new(AppInstallationEvidence.Unavailable("file_read_unavailable") with { ExecutableResolution = resolution }); }
    }

    internal sealed record ResolvedEvidence(AppInstallationEvidence Evidence, SignatureCacheKey? CacheKey = null,
        SignatureObservation? CacheObservation = null);

    internal static bool IsSafePath(string path) => path.Length is >= 4 and <= 512 &&
        char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\' &&
        !path[2..].Contains(':') && !path.Contains('/') && !path.Any(char.IsControl) &&
        path[3..].Split('\\').All(p => p.Length > 0 && p is not "." and not ".." && !IsDeviceName(p) &&
            !p.EndsWith(' ') && !p.EndsWith('.') && p.IndexOfAny(['*', '?', '"', '<', '>', '|']) < 0);

    private static bool IsDeviceName(string part)
    {
        var name = part.Split('.')[0].ToUpperInvariant();
        return name is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" ||
            (name.Length == 4 && (name.StartsWith("COM") || name.StartsWith("LPT")) &&
                "123456789¹²³".Contains(name[3]));
    }

    // Lock each ancestor before opening its child, reject reparse points on the actual
    // handles, and retain the locks through hashing/WinVerifyTrust. Denying write
    // sharing also prevents converting an open directory into a reparse point.
    // A check-then-open
    // path walk alone would allow a junction swap and SYSTEM's network credentials.
    internal static LockedFile OpenLocalFile(string path) => OpenLocalChain(path, leafIsFile: true);

    // PAT-2116: the same locked walk ending at a directory, so an InstallLocation can be
    // listed without any component being a reparse point or swapped while it is read.
    internal static LockedFile OpenLocalDirectory(string path) => OpenLocalChain(path, leafIsFile: false);

    private static LockedFile OpenLocalChain(string path, bool leafIsFile)
    {
        if (!IsSafePath(path) || GetDriveType(path[..3]) != 3)
            throw new IOException("path_not_local_fixed");
        var handles = new List<SafeFileHandle>();
        try
        {
            var parts = path[3..].Split('\\');
            var current = path[..3];
            FileInformation leaf = default;
            for (var i = -1; i < parts.Length; i++)
            {
                if (i >= 0) current = Path.Combine(current, parts[i]);
                var isLeaf = i == parts.Length - 1;
                var isFile = isLeaf && leafIsFile;
                // PAT-2060: with LongPathsEnabled off (the Windows default) CreateFile refuses
                // any component from MAX_PATH up, so a deep install had no evidence at all.
                // current is built only from a path IsSafePath accepted (a drive-letter path
                // with no dot segments, device names, trailing dots or spaces), so it never
                // carries a prefix of its own and GetFullPath leaves it unchanged. The per-
                // handle reparse and type checks below still decide what is accepted.
                var handle = CreateFile(WindowsFileIdentity.ExtendedLengthPath(current), isFile ? 0x80000000u : 0x80u,
                    1u, IntPtr.Zero, 3, 0x00200000u | 0x02000000u, IntPtr.Zero);
                handles.Add(handle);
                if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var info) ||
                    (info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) == 0) != isFile)
                    throw new IOException("file_unavailable_or_reparse");
                if (isLeaf) leaf = info;
            }
            var stream = leafIsFile ? new FileStream(handles[^1], FileAccess.Read) : null;
            var written = ((long)leaf.Written.dwHighDateTime << 32) | (uint)leaf.Written.dwLowDateTime;
            return new(stream, handles, written);
        }
        catch
        {
            foreach (var handle in handles) handle.Dispose();
            throw;
        }
    }

    // PAT-2116: the top-level *.exe names of an InstallLocation, read while the whole path
    // is held by OpenLocalDirectory. Reparse points (including cloud placeholders, which
    // would otherwise be hydrated), offline files and directories are skipped. Returns at
    // most ExecutableResolver.MaximumListedExecutables names; null when the directory
    // could not be opened or listed, which the resolver reports, never as "no executable".
    internal static IReadOnlyList<string>? ListExecutables(string directory)
    {
        try
        {
            using var locked = OpenLocalDirectory(directory);
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = false,
                IgnoreInaccessible = false,
                ReturnSpecialDirectories = false,
                MatchType = MatchType.Simple,
                MatchCasing = MatchCasing.CaseInsensitive,
                AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Directory | FileAttributes.Offline |
                    FileAttributes.Device,
            };
            var names = new List<string>();
            foreach (var file in Directory.EnumerateFiles(WindowsFileIdentity.ExtendedLengthPath(directory), "*.exe", options))
            {
                names.Add(Path.GetFileName(file));
                if (names.Count >= ExecutableResolver.MaximumListedExecutables) break;
            }
            return names;
        }
        catch { return null; }
    }

    internal static void VerifyExecutableAcl(string path)
    {
        var acl = new FileInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        static bool Trusted(SecurityIdentifier sid) => sid.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
            sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
        var owner = acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !Trusted(owner))
            throw new AclRefusalException("helper_owner_untrusted", new("executable_owner", owner?.Value, 0));
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && GrantsMutation(rule.FileSystemRights) &&
                !Trusted((SecurityIdentifier)rule.IdentityReference))
                throw new AclRefusalException("helper_acl_untrusted",
                    new("executable_acl", ((SecurityIdentifier)rule.IdentityReference).Value, rule.FileSystemRights));
    }

    // PAT-2116: which check refused, and for an ACL refusal the one principal and the rights
    // it holds, so a refused helper is diagnosable from one log line. Reason is a fixed code
    // (safe for agent-health on the wire); Sid and Rights go to the local log only.
    internal readonly record struct AclRefusal(string Reason, string? Sid, FileSystemRights Rights)
    {
        internal string Detail => $"principal={Sid ?? "unresolved"} rights=0x{(uint)Rights:X8}";
    }

    // An IOException, with the historical message, so existing callers that only need
    // "refused" (InstallationEvidenceStore) behave exactly as before.
    internal sealed class AclRefusalException(string message, AclRefusal refusal) : IOException(message)
    {
        internal AclRefusal Refusal { get; } = refusal;
    }

    // PAT-2116: the helper's install directory, %ProgramFiles%\Patched, as the MSI really
    // leaves it. That directory inherits %ProgramFiles%' default DACL: TrustedInstaller
    // FullControl, plus inherit-only GENERIC_ALL for TrustedInstaller, SYSTEM,
    // Administrators and CREATOR OWNER. SecureStagingDirectory.VerifyTrusted is the policy
    // for directories the agent creates and hardens itself, and it rejects both, so every
    // helper spawn on a real install failed (helper_failed on every row, 0.14.2 on
    // WIN-STAGING). Here TrustedInstaller counts as a trusted writer (it outranks
    // Administrators). Every other write-capable grant still fails closed.
    // PAT-2399: the rule itself now lives in InstallDirectoryAclPolicy, shared with the
    // start-up check, and is stricter about inherit-only entries than PAT-2116 was: only
    // CREATOR OWNER's is accepted, because any other one hands write to every child.
    internal const string LocalSystemSid = InstallDirectoryAclPolicy.LocalSystemSid;
    internal const string AdministratorsSid = InstallDirectoryAclPolicy.AdministratorsSid;
    internal const string TrustedInstallerSid = InstallDirectoryAclPolicy.TrustedInstallerSid;

    internal readonly record struct AclEntry(string Sid, FileSystemRights Rights, bool Allow, bool InheritOnly);

    internal static InstallDirectoryAclPolicy.Ace ToPolicyAce(AclEntry entry) =>
        new(entry.Sid, unchecked((uint)entry.Rights), entry.Allow, entry.InheritOnly);

    // Null when only trusted principals can write, else the first offending owner or entry,
    // under the helper preflight's own reason codes.
    internal static AclRefusal? InstallDirectoryRefusal(string? ownerSid, IEnumerable<AclEntry> entries) =>
        InstallDirectoryAclPolicy.Evaluate(false, ownerSid, entries.Select(ToPolicyAce)) is { } finding
            ? new(finding.Reason == InstallDirectoryAclPolicy.UntrustedOwner ? "install_dir_owner" : "install_dir_acl",
                finding.Sid, (FileSystemRights)unchecked((int)finding.Mask))
            : null;

    internal static (string? Owner, IReadOnlyList<AclEntry> Entries) ReadAcl(FileSystemSecurity acl) =>
        ((acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value,
            acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                .Select(r => new AclEntry(((SecurityIdentifier)r.IdentityReference).Value, r.FileSystemRights,
                    r.AccessControlType == AccessControlType.Allow, r.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)))
                .ToArray());

    // Reparse points are refused by OpenLocalFile's locked walk, which the caller holds.
    internal static void VerifyInstallDirectoryAcl(string directory)
    {
        var (owner, entries) = ReadAcl(new DirectoryInfo(directory)
            .GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
        if (InstallDirectoryRefusal(owner, entries) is { } refusal)
            throw new AclRefusalException("helper_directory_untrusted", refusal);
    }

    internal sealed class LockedFile(FileStream? stream, List<SafeFileHandle> handles, long lastWriteFileTime) : IDisposable
    {
        // Only a file chain has a stream; OpenLocalDirectory returns the held handles only.
        internal FileStream Stream => stream ?? throw new InvalidOperationException("directory_has_no_stream");
        // The leaf's last-write time as a raw FILETIME, read from the held handle.
        internal long LastWriteFileTime { get; } = lastWriteFileTime;
        public void Dispose()
        {
            stream?.Dispose();
            foreach (var handle in handles) handle.Dispose();
        }
    }

    private static SignatureObservation ReadSignature(string path, SafeFileHandle handle, SignatureProbeContext context)
    {
        var retained = false;
        try
        {
            handle.DangerousAddRef(ref retained);
            // The retained reference spans verification, provider-chain extraction and
            // WTD_STATEACTION_CLOSE, regardless of managed/JIT lifetime analysis.
            return ReadSignatureWithRetainedHandle(path, handle.DangerousGetHandle(), context);
        }
        finally
        {
            if (retained) handle.DangerousRelease();
        }
    }

    // "valid" here means one thing whichever branch produced it: WinVerifyTrust accepted
    // the subject against this machine's trust store. Windows signs most of its own
    // shipped binaries into a catalog rather than embedding an Authenticode signature in
    // the PE, so a file-handle check alone reports every System32 binary as unsigned.
    // Both subject forms go through the same WinVerifyTrust call with the same flags, so
    // a catalog "valid" carries exactly the offline, no-revocation caveat documented for
    // the embedded one below, and neither is current revocation assurance.
    //
    // Which state is reported is decided by SignatureVerdictLogic.Decide (Shared, unit
    // tested): this method only supplies the Win32 answers. The catalog store is consulted
    // only when the embedded check found no signature to judge (TRUST_E_NOSIGNATURE or
    // TRUST_E_SUBJECT_FORM_UNKNOWN). A digest mismatch, an untrusted chain or any other
    // verdict has already answered the question, and asking a second provider afterwards
    // would be shopping for a better answer rather than collecting more evidence. Codes
    // measured on Windows 11 26100 arm64: an unsigned PE and every System32 binary return
    // TRUST_E_NOSIGNATURE, a truncated non-PE stub returns TRUST_E_SUBJECT_FORM_UNKNOWN,
    // and a byte-flipped signed binary returns TRUST_E_BAD_DIGEST. "unsigned" needs the
    // full rule documented on Decide: embedded TRUST_E_NOSIGNATURE, a SHA-256 catalog
    // lookup that ran and found nothing, no SHA-1 catalog listing either, and a catalog
    // database that answered for a known OS file. Any catalog-API failure stays "unknown".
    private static SignatureObservation ReadSignatureWithRetainedHandle(string path, IntPtr handle, SignatureProbeContext context)
    {
        var (code, embedded) = VerifyEmbedded(path, handle, context);
        SignatureObservation? catalogValid = null;
        var decision = SignatureVerdictLogic.Decide(code,
            () =>
            {
                try
                {
                    var (outcome, observation) = VerifyInCatalog(path, handle, context);
                    catalogValid = observation;
                    return outcome;
                }
                catch { return CatalogLookupOutcome.Failed; }
            },
            () =>
            {
                try { return CatalogPresenceFor(handle, "SHA1"); }
                catch { return CatalogPresence.Failed; }
            },
            context.CatalogDatabaseHealthy);
        return decision switch
        {
            SignatureDecision.ValidEmbedded when embedded is not null => embedded,
            SignatureDecision.ValidCatalog when catalogValid is not null => catalogValid,
            SignatureDecision.Invalid => new(SignatureStates.Invalid, Error: "signer_unavailable"),
            SignatureDecision.Unsigned => new(SignatureStates.Unsigned),
            _ => SignatureObservation.Unknown(),
        };
    }

    private static (uint Code, SignatureObservation? Valid) VerifyEmbedded(string path, IntPtr handle, SignatureProbeContext context)
    {
        var file = new TrustFile { Size = (uint)Marshal.SizeOf<TrustFile>(), Path = path, Handle = handle };
        var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<TrustFile>());
        Marshal.StructureToPtr(file, pointer, false);
        try
        {
            // Only an explicit digest mismatch is an invalid signature. Missing
            // signatures, unavailable chains/revocation and all other trust errors
            // are decided by SignatureVerdictLogic, never here.
            return Verify(ChoiceFile, pointer, context);
        }
        finally
        {
            Marshal.DestroyStructure<TrustFile>(pointer);
            Marshal.FreeHGlobal(pointer);
        }
    }

    // Verified: a catalog listing the SHA-256 member hash verified, with its observation.
    // NoCatalog: only when the first enumeration returned NULL with ERROR_NOT_FOUND.
    // MemberUnverified: some catalog lists the hash but none verified. Failed: all else.
    private static (CatalogLookupOutcome Outcome, SignatureObservation? Valid) VerifyInCatalog(string path, IntPtr handle,
        SignatureProbeContext context)
    {
        var admin = IntPtr.Zero;
        var hash = IntPtr.Zero;
        var catalog = IntPtr.Zero;
        try
        {
            // SHA-256 only, which is why this uses CryptCATAdminAcquireContext2 and
            // CalcHashFromFileHandle2: the original entry points hard-code SHA-1. A
            // catalog is a signed hash-to-file binding, so honouring a SHA-1 membership
            // would make a SHA-1 collision sufficient to earn "valid" and a Microsoft
            // signer. A file whose only catalog entry is SHA-1 stays unknown instead.
            if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0)) return (CatalogLookupOutcome.Failed, null);
            uint size = 0;
            CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, IntPtr.Zero, 0);
            if (size is 0 or > MaximumCatalogHashBytes) return (CatalogLookupOutcome.Failed, null);
            hash = Marshal.AllocHGlobal((int)size);
            if (!CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, hash, 0)) return (CatalogLookupOutcome.Failed, null);
            var bytes = new byte[size];
            Marshal.Copy(hash, bytes, 0, (int)size);
            var tag = Convert.ToHexString(bytes);
            for (var attempt = 0; attempt < MaximumCatalogCandidates; attempt++)
            {
                // One file's hash is commonly a member of several catalogs (up to 12 were
                // observed in System32), so a superseded or damaged first catalog must not
                // mask a signature a later one still carries. The enumeration releases the
                // context handed to it, so ownership is surrendered before the call and
                // retaken from its result, leaving exactly one context to release below.
                var previous = catalog;
                catalog = IntPtr.Zero;
                var next = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, ref previous);
                if (next == IntPtr.Zero)
                {
                    // Read the error before any other call can overwrite it. Only the first
                    // call can say "no catalog"; a later NULL is the end of the list.
                    var error = Marshal.GetLastPInvokeError();
                    return attempt == 0
                        ? (SignatureVerdictLogic.ClassifyFirstEnumeration(false, error)!.Value, null)
                        : (CatalogLookupOutcome.MemberUnverified, null);
                }
                catalog = next;
                var located = new CatalogLocation { Size = (uint)Marshal.SizeOf<CatalogLocation>() };
                if (!CryptCATCatalogInfoFromContext(catalog, ref located, 0)) continue;
                var member = new TrustCatalogMember
                {
                    Size = (uint)Marshal.SizeOf<TrustCatalogMember>(),
                    CatalogFilePath = located.CatalogFile,
                    MemberTag = tag,
                    MemberFilePath = path,
                    MemberFile = handle,
                    CalculatedFileHash = hash,
                    CalculatedFileHashSize = size,
                    CatalogContext = catalog,
                    CatalogAdmin = admin,
                };
                var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<TrustCatalogMember>());
                Marshal.StructureToPtr(member, pointer, false);
                try
                {
                    var (code, observation) = Verify(ChoiceCatalog, pointer, context);
                    if (code != 0 || observation is null) continue;
                    return (CatalogLookupOutcome.Verified, observation);
                }
                finally
                {
                    Marshal.DestroyStructure<TrustCatalogMember>(pointer);
                    Marshal.FreeHGlobal(pointer);
                }
            }
            return (CatalogLookupOutcome.MemberUnverified, null);
        }
        finally
        {
            // The catalog context is released before the admin context that issued it;
            // the reverse order can invalidate the catalog handle before it is freed.
            if (catalog != IntPtr.Zero && admin != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
            if (admin != IntPtr.Zero) CryptCATAdminReleaseContext(admin, 0);
            if (hash != IntPtr.Zero) Marshal.FreeHGlobal(hash);
        }
    }

    // PAT-2116: is any catalog listing this file's hash under the given algorithm? A
    // membership question only; nothing is verified and nothing here can produce "valid".
    // Used with SHA1 to withhold "unsigned", and with SHA256 for the database canary.
    internal static CatalogPresence CatalogPresenceFor(IntPtr handle, string algorithm)
    {
        var admin = IntPtr.Zero;
        var hash = IntPtr.Zero;
        var catalog = IntPtr.Zero;
        try
        {
            if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) return CatalogPresence.Failed;
            uint size = 0;
            CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, IntPtr.Zero, 0);
            if (size is 0 or > MaximumCatalogHashBytes) return CatalogPresence.Failed;
            hash = Marshal.AllocHGlobal((int)size);
            if (!CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, hash, 0)) return CatalogPresence.Failed;
            var previous = IntPtr.Zero;
            catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, ref previous);
            var error = catalog == IntPtr.Zero ? Marshal.GetLastPInvokeError() : 0;
            return SignatureVerdictLogic.ClassifyPresence(catalog != IntPtr.Zero, error);
        }
        finally
        {
            if (catalog != IntPtr.Zero && admin != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
            if (admin != IntPtr.Zero) CryptCATAdminReleaseContext(admin, 0);
            if (hash != IntPtr.Zero) Marshal.FreeHGlobal(hash);
        }
    }

    // One WinVerifyTrust call for either subject form, returning the raw status and, for
    // an accepted subject, the valid observation read from its provider chain. The trust
    // state is closed on every path, including the exception path, so neither form leaks it.
    private static (uint Code, SignatureObservation? Valid) Verify(uint choice, IntPtr subject, SignatureProbeContext context)
    {
        var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        var trust = new TrustData
        {
            Size = (uint)Marshal.SizeOf<TrustData>(),
            UI = 2,
            Union = choice,
            Subject = subject,
            StateAction = 1,
            // Cache-only URL retrieval; no revocation checks. This is an explicitly
            // offline OS signature observation, never current revocation assurance.
            Flags = 0x1000 | 0x10,
        };
        try
        {
            var code = WinVerifyTrust(new IntPtr(-1), ref action, ref trust);
            return (code, code == 0 ? ReadValidObservation(trust.State, context) : null);
        }
        finally
        {
            trust.StateAction = 2;
            WinVerifyTrust(new IntPtr(-1), ref action, ref trust);
        }
    }

    // WinVerifyTrust populates the same provider data for a catalog member as for an
    // embedded signature, so one extraction serves both (confirmed against catalog-signed
    // System32 binaries, which resolve to CN=Microsoft Windows through this exact path).
    // PAT-2116 adds the pinnable publisher from the same verified provider chain: the leaf's
    // SHA-256 thumbprint and Issuer, and the chain's last element (the trust anchor
    // WinVerifyTrust accepted) as root_thumbprint and root_kind. Nothing is fetched and no
    // second chain is built: these are exactly the certificates the verdict rests on.
    private static SignatureObservation ReadValidObservation(IntPtr state, SignatureProbeContext context)
    {
        string? subject = null, thumbprint = null, issuer = null, root = null;
        var selfIssued = false;
        try
        {
            var data = WTHelperProvDataFromStateData(state);
            var signer = data == IntPtr.Zero ? IntPtr.Zero : WTHelperGetProvSignerFromChain(data, 0, false, 0);
            if (signer != IntPtr.Zero)
            {
                using (var leaf = CertificateAt(signer, 0))
                {
                    if (leaf is not null)
                    {
                        subject = BoundedName(leaf.Subject);
                        issuer = BoundedName(leaf.Issuer);
                        thumbprint = leaf.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();
                    }
                }
                // CRYPT_PROVIDER_SGNR: cbStruct, sftVerifyAsOf (FILETIME), csCertChain, ...
                var header = Marshal.PtrToStructure<ProviderSignerHeader>(signer);
                if (header.Size >= Marshal.SizeOf<ProviderSignerHeader>() && header.CertChainCount is >= 1 and <= MaximumChainLength)
                {
                    using var anchor = CertificateAt(signer, header.CertChainCount - 1);
                    if (anchor is not null)
                    {
                        root = anchor.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();
                        selfIssued = anchor.SubjectName.RawData.AsSpan().SequenceEqual(anchor.IssuerName.RawData);
                    }
                }
            }
        }
        catch
        {
            // A chain that cannot be read leaves the fields it did not reach null; the
            // verdict itself is WinVerifyTrust's and stands.
        }
        var kind = AuthenticodeRootClassifier.Classify(root, selfIssued, root is not null && context.InThirdPartyRootStore(root));
        return new(SignatureStates.Valid, subject, thumbprint, issuer, root, kind, subject is null ? "signer_unavailable" : null);
    }

    private static X509Certificate2? CertificateAt(IntPtr signer, uint index)
    {
        var cert = WTHelperGetProvCertFromChain(signer, index);
        if (cert == IntPtr.Zero) return null;
        var providerCert = Marshal.PtrToStructure<ProviderCert>(cert);
        return providerCert.Certificate == IntPtr.Zero ? null : new X509Certificate2(providerCert.Certificate);
    }

    private static string? BoundedName(string name) =>
        name.Length is > 0 and <= 512 && !name.Any(char.IsControl) ? name : null;

    // PAT-2116: SHA-256 thumbprints of the registry "AuthRoot" physical store only
    // (HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot), which Windows' automatic root
    // update populates from the Microsoft Trusted Root Program. CERT_STORE_PROV_SYSTEM_REGISTRY
    // deliberately excludes the Group Policy and Enterprise physical stores that the logical
    // AuthRoot store also merges, so a root pushed by policy reads as enterprise. Read-only and
    // open-existing; any failure is an empty set, which classifies every root enterprise.
    internal static HashSet<string> ReadThirdPartyRootThumbprints()
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        var store = IntPtr.Zero;
        try
        {
            store = CertOpenStore(new IntPtr(CertStoreProvSystemRegistryW), 0, IntPtr.Zero,
                CertSystemStoreLocalMachine | CertStoreReadOnlyFlag | CertStoreOpenExistingFlag, "AuthRoot");
            if (store == IntPtr.Zero) return result;
            using var managed = new X509Store(store);
            foreach (var certificate in managed.Certificates)
            {
                using (certificate)
                {
                    if (certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData))
                        result.Add(certificate.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant());
                }
                if (result.Count >= MaximumThirdPartyRoots) break;
            }
            return result;
        }
        catch { return new HashSet<string>(StringComparer.Ordinal); }
        finally
        {
            if (store != IntPtr.Zero) CertCloseStore(store, 0);
        }
    }

    private const uint ChoiceFile = 1; // WTD_CHOICE_FILE
    private const uint ChoiceCatalog = 2; // WTD_CHOICE_CATALOG
    // A SHA-256 member hash is 32 bytes; the bound only stops an implausible length
    // from becoming an unbounded allocation in the evidence helper.
    private const uint MaximumCatalogHashBytes = 64;
    private const int MaximumCatalogCandidates = 16;
    private const uint MaximumChainLength = 16;
    private const int MaximumThirdPartyRoots = 4096;
    private const int CertStoreProvSystemRegistryW = 13; // CERT_STORE_PROV_SYSTEM_REGISTRY_W
    private const uint CertSystemStoreLocalMachine = 0x00020000;
    private const uint CertStoreReadOnlyFlag = 0x00008000;
    private const uint CertStoreOpenExistingFlag = 0x00004000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct TrustFile { public uint Size; [MarshalAs(UnmanagedType.LPWStr)] public string Path; public IntPtr Handle; public IntPtr Subject; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct TrustCatalogMember
    {
        public uint Size; public uint CatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string CatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string MemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string MemberFilePath;
        public IntPtr MemberFile; public IntPtr CalculatedFileHash; public uint CalculatedFileHashSize;
        public IntPtr CatalogContext; public IntPtr CatalogAdmin;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogLocation
    {
        public uint Size;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string CatalogFile;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct TrustData
    {
        public uint Size; public IntPtr Policy; public IntPtr Sip; public uint UI; public uint Revocation;
        public uint Union; public IntPtr Subject; public uint StateAction; public IntPtr State; public IntPtr Url;
        public uint Flags; public uint Context; public IntPtr SignatureSettings;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProviderCert { public uint Size; public IntPtr Certificate; }
    // The leading, fixed-layout members of CRYPT_PROVIDER_SGNR (wintrust.h); only these are read.
    [StructLayout(LayoutKind.Sequential)]
    private struct ProviderSignerHeader { public uint Size; public uint VerifyAsOfLow; public uint VerifyAsOfHigh; public uint CertChainCount; }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetDriveType(string root);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation info);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern uint WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr data, uint index, [MarshalAs(UnmanagedType.Bool)] bool counterSigner, uint counterIndex);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr signer, uint index);
    // Read-only catalog-database lookups. Nothing here installs, removes or edits a
    // catalog; a null subsystem GUID selects the machine's own catalog database.
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr subsystem,
        [MarshalAs(UnmanagedType.LPWStr)] string algorithm, IntPtr policy, uint flags);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, IntPtr file, ref uint size, IntPtr hash, uint flags);
    // SetLastError: the NULL-return error is what separates "no catalog" from a failure.
    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, IntPtr hash, uint size, uint flags, ref IntPtr previous);
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr catalog, ref CatalogLocation info, uint flags);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catalog, uint flags);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CertOpenStore(IntPtr provider, uint encoding, IntPtr cryptProv, uint flags,
        [MarshalAs(UnmanagedType.LPWStr)] string parameter);
    [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertCloseStore(IntPtr store, uint flags);
}
