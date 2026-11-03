using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using Patched.Shared.Paths;
using Patched.Shared.Security;

namespace Patched.Shared.Auth;

/// <summary>
/// Reads and writes Patched credentials in Windows Credential Manager.
/// DPAPI protects blobs at rest; CRED_PERSIST_LOCAL_MACHINE lets SYSTEM read them.
///
/// Credential Manager targets:
///   PatchedAgent/TenantId        — opaque tenant ID         (post-enrolment)
///   PatchedAgent/BearerToken     — Bearer token             (post-enrolment)
///   PatchedAgent/HmacSecret      — base64 HMAC-SHA256 key   (post-enrolment)
///   PatchedAgent/EnrollmentToken — single-use enrolment token (pre-enrolment)
///
/// Lifecycle:
///   Fresh install:  only EnrollmentToken is stored by the installer.
///                   The service calls AgentEnroller, which exchanges it for the
///                   three post-enrolment credentials and then clears the token.
///   Enrolled:       only TenantId / BearerToken / HmacSecret are present.
///   Suspended:      a sentinel file at %ProgramData%\Patched\creds\suspended
///                   exists; all run cycles are skipped until the device is
///                   re-enrolled.
///
/// Credential sources (in priority order, checked by LoadForStartup):
///   1. Windows Credential Manager (DPAPI-protected, CRED_PERSIST_LOCAL_MACHINE)
///   2. Environment variables (PATCHED_TENANT_ID / PATCHED_BEARER_TOKEN / PATCHED_HMAC_SECRET)
///   3. Plaintext file store at %ProgramData%\Patched\creds\ (ACL'd to SYSTEM + Admins).
///      PAT-1755: the MSI provisions the enrolment token here, from a deferred
///      HideTarget custom action, so no verbose install log ever records it.
///   4. Registry provisioning store at HKLM\SOFTWARE\Patched\Enrollment (PAT-599).
///      Written by an installer that predates PAT-1755; still read so a device
///      upgraded from one is migrated. LoadForStartup moves raw credentials found
///      there to Credential Manager on first service start and deletes the key.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CredentialStore
{
    // -------------------------------------------------------------------------
    // Credential Manager target names
    // -------------------------------------------------------------------------
    public const string TargetEnrollmentToken = "PatchedAgent/EnrollmentToken";

    /// <summary>
    /// Public (not private) so <c>DecommissionHandoffScript.Build</c> can generate
    /// the purge=true Credential Manager cleanup list FROM these constants rather
    /// than re-typing the target names — a single source of truth means a future
    /// credential added here cannot be silently missed by that cleanup (PAT-1110).
    /// </summary>
    public const string TargetTenantId    = "PatchedAgent/TenantId";
    public const string TargetBearerToken = "PatchedAgent/BearerToken";
    public const string TargetHmacSecret  = "PatchedAgent/HmacSecret";
    public const string TargetDeviceId = "PatchedAgent/CanonicalDeviceIdentity";

    /// <summary>
    /// PAT-1764: every Credential Manager target the agent owns, in one place, so
    /// the uninstall purge (<see cref="CredentialPurge"/>) cannot miss a credential
    /// added here later. Same set the decommission purge=true script clears.
    /// </summary>
    public static readonly IReadOnlyList<string> AgentCredentialTargets = new[]
    {
        TargetTenantId,
        TargetBearerToken,
        TargetHmacSecret,
        TargetDeviceId,
        TargetEnrollmentToken,
    };

    // -------------------------------------------------------------------------
    // Properties — private set so AgentEnroller can update them in-place after a
    // successful enrolment exchange without requiring a DI re-registration.
    // -------------------------------------------------------------------------
    public string  TenantId        { get; private set; }
    public string  BearerToken     { get; private set; }
    public string  HmacSecret      { get; private set; }
    public string? EnrollmentToken { get; private set; }
    private string? _canonicalDeviceIdentity;
    public string? CanonicalDeviceId
    {
        get
        {
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(_canonicalDeviceIdentity ?? "");
                var root = doc.RootElement;
                string hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(BearerToken)));
                string? id = root.GetProperty("device_id").GetString();
                return root.GetProperty("tenant_id").GetString() == TenantId && root.GetProperty("credential_hash").GetString() == hash &&
                    Guid.TryParseExact(id, "D", out var uuid) && uuid != Guid.Empty ? uuid.ToString("D") : null;
            }
            catch { return null; }
        }
    }

    /// <summary>
    /// PAT-1781: true when the most recent startup-source load found both the
    /// bearer-token and HMAC-secret entries, regardless of whether their values
    /// were usable. This is presence evidence only: it never exposes either value.
    /// The worker uses it to distinguish a stored-but-blank pair from a device that
    /// has never been provisioned at all.
    /// </summary>
    public bool StoredCredentialPairPresent { get; private set; }

    // -------------------------------------------------------------------------
    // Suspended-state sentinel
    // -------------------------------------------------------------------------
    // Production default: a true immutable static, exactly as before PAT-1042.
    // Non-author review (round 2) correctly flagged an earlier version of this
    // change that made this field `internal static` and mutable — a
    // compiler-unenforced immutability hole on the field that defines the
    // entire revocation control, reassignable at runtime by any in-assembly
    // code, and not thread-safe. Restored to `private static readonly` here;
    // see _suspendedFile below for how tests get their own path instead.
    private static readonly string DefaultSuspendedFile = Path.Combine(PathConstants.CredsDir, "suspended");

    // Per-instance, set exactly once in the constructor and never reassigned
    // afterward (readonly) — real immutability after construction, not just a
    // convention. Every production instance gets DefaultSuspendedFile; only the
    // internal test-only constructor overload below (used exclusively by
    // Patched.Shared.Tests) can point it elsewhere, so IsSuspended/
    // MarkSuspended/ClearSuspended never touch the real
    // %ProgramData%\Patched\creds on the machine running the tests. Mirrors the
    // spirit of macOS's env-overridable PATCHED_CREDS_DIR: test-only override,
    // production immutable.
    private readonly string _suspendedFile;

    /// <summary>
    /// True after the server rejected this device's authentication (a bare 401 from
    /// agent-config, whose cause the server does not disclose, PAT-1745) or rejected
    /// an enrolment token.
    /// </summary>
    public bool IsSuspended => WritesHostCredentialStorage
        ? CredentialFiles.IsPresentOrUnsafe("suspended")
        : File.Exists(_suspendedFile);

    // PAT-1203: how to re-read the enrollment-token sources on demand (see
    // RefreshEnrollmentToken below). Per-instance, readonly, same seam
    // philosophy as _suspendedFile — production always resolves to
    // ReadEnrollmentTokenFromRealSources (Credential Manager / file store /
    // registry, the same three LoadForStartup already checks once at process
    // start); only the test-only factory overload can point it elsewhere, so
    // tests never touch the real Windows Credential Manager or
    // %ProgramData%\Patched\creds.
    private readonly Func<string?> _readEnrollmentTokenSource;

    // PAT-1763: where UpdateFromEnrolment writes. Production stores always get
    // HostCredentialWriter (Credential Manager, the creds file store and the
    // registry provisioning key); the test factories below get an
    // InMemoryAgentCredentialWriter, so a test that enrols never writes the host.
    private readonly IAgentCredentialWriter _credentialWriter;

    // PAT-1766: how a store that is waiting to be provisioned re-runs the startup
    // load. Production stores built by LoadForStartup re-run it against the same
    // sources; every other store (Load, test factories unless given one) returns null.
    private readonly Func<CredentialStore?> _reloadForStartup;

    // -------------------------------------------------------------------------
    // Constructor (private — use Load / LoadForStartup)
    // -------------------------------------------------------------------------
    private CredentialStore(string tenantId, string bearer, string hmac, string? enrollToken)
        : this(tenantId, bearer, hmac, enrollToken, DefaultSuspendedFile, ReadEnrollmentTokenFromRealSources,
               HostCredentialWriter.Instance, static () => null, storedCredentialPairPresent: true)
    {
    }

    // PAT-1042 test-only constructor overload. Not gated behind #if DEBUG:
    // this repo's CI (windows-build.yml) builds AND tests the Windows agent in
    // Release configuration (`dotnet test windows/PatchedAgent.sln -c
    // Release`), so a DEBUG-only seam would vanish under the exact
    // configuration CI actually runs and silently break this test project's
    // build. A real, always-compiled constructor overload avoids that trap
    // while keeping every field it touches `readonly` — there is no runtime-
    // mutable state in either configuration.
    private CredentialStore(
        string tenantId, string bearer, string hmac, string? enrollToken,
        string suspendedFile, Func<string?> readEnrollmentTokenSource,
        IAgentCredentialWriter credentialWriter, Func<CredentialStore?> reloadForStartup,
        bool storedCredentialPairPresent)
    {
        TenantId        = tenantId;
        BearerToken     = bearer;
        HmacSecret      = hmac;
        EnrollmentToken = enrollToken;
        _suspendedFile  = suspendedFile;
        _readEnrollmentTokenSource = readEnrollmentTokenSource;
        _credentialWriter = credentialWriter;
        _reloadForStartup = reloadForStartup;
        StoredCredentialPairPresent = storedCredentialPairPresent;
    }

    /// <summary>
    /// PAT-1763: the production <see cref="IAgentCredentialWriter"/>. Nested so it
    /// can reach the private P/Invoke and file-store helpers; the only instance is
    /// handed to stores built by <see cref="Load"/> and <see cref="LoadForStartup(ILogger?)"/>.
    /// </summary>
    private sealed class HostCredentialWriter : IAgentCredentialWriter
    {
        internal static readonly HostCredentialWriter Instance = new();

        private HostCredentialWriter() { }

        public void WriteCredential(string target, string value) => Write(target, value);

        public void DiscardConsumedEnrollmentToken()
        {
            // Best-effort removal — the token is single-use on the server, so leaving
            // a stale file fallback here is harmless but messy.
            CredDelete(TargetEnrollmentToken, 1, 0);

            // PAT-1755: the installer provisions the token here, so this is the location
            // that normally holds the consumed value.
            try { DeleteCredsFileEnrollmentToken(); } catch { /* ignore */ }

            // Remove the registry provisioning key (PAT-599): written by an installer that
            // predates PAT-1755 when an ENROLLMENT_TOKEN was supplied; no longer needed
            // after successful enrol.
            DeleteRegistryProvisioningKey();
        }
    }

    /// <summary>
    /// PAT-1763: true when this store writes to host credential storage. Only
    /// stores built by the production factories do; guard tests assert every test
    /// factory returns false.
    /// </summary>
    internal bool WritesHostCredentialStorage => _credentialWriter is HostCredentialWriter;

    /// <summary>PAT-1763: the suspended-marker path this store reads and writes, for guard tests.</summary>
    internal string SuspendedMarkerPath => _suspendedFile;

    /// <summary>
    /// PAT-1203: the production enrollment-token source chain — identical to,
    /// and kept in sync with, the enrollment-token lookup in LoadForStartup
    /// below (Credential Manager, then the plaintext file fallback, then the
    /// WiX registry provisioning key). Extracted so RefreshEnrollmentToken can
    /// re-run the same lookup on a running instance instead of only once at
    /// process start.
    /// </summary>
    private static string? ReadEnrollmentTokenFromRealSources() =>
        FirstUsableEnrollmentToken(
            () => ReadCredential(TargetEnrollmentToken),
            () => ReadCredsFile(EnrollmentTokenProvisioner.FileName),
            () => ReadRegistryProvisioning("EnrollmentToken"));

    /// <summary>
    /// PAT-1042 test-only factory: builds an instance whose suspended-marker
    /// path is <paramref name="suspendedFile"/> instead of the real
    /// %ProgramData%\Patched\creds\suspended, so
    /// Patched.Shared.Tests / Service.Tests can exercise IsSuspended/
    /// MarkSuspended/ClearSuspended (and, via AgentConfigFetcherSuspendedTests,
    /// the HmacSecret-dependent request-signing path) against a scratch temp
    /// path. Bypasses Credential Manager and environment variables entirely.
    /// The placeholder HmacSecret is valid base64 (HmacSigner.ComputeSignature
    /// calls Convert.FromBase64String on it) — arbitrary bytes, never a real
    /// key, but must decode. Internal — visible only to Patched.Service,
    /// Patched.Shared.Tests, and Service.Tests via the existing
    /// InternalsVisibleTo grants below; production code always goes through
    /// Load()/LoadForStartup() instead.
    ///
    /// PAT-1203: <paramref name="bearerToken"/> defaults to the original
    /// "test-bearer" placeholder so every pre-existing call site is
    /// unaffected; AgentEnrollerRecoveryTests passes "" to model an
    /// enrollment-pending device (no bearer token yet). <paramref
    /// name="enrollmentTokenSource"/> defaults to "no token available"
    /// (matching a device with nothing enrollment-related present) and lets
    /// those same tests simulate an admin dropping a fresh single-use token
    /// without touching the real Credential Manager / file store / registry.
    ///
    /// PAT-1760: <paramref name="enrollmentToken"/> seeds the token loaded at
    /// process start (null by default, as before), so a test can model a device
    /// that holds an enrolment token alongside credentials, or a token that was
    /// already present at start rather than dropped in later.
    /// <paramref name="hmacSecret"/> (PAT-1760 review) lets a test model a stored
    /// pair whose secret is unusable.
    ///
    /// PAT-1763: <paramref name="credentialWriter"/> receives what
    /// <see cref="UpdateFromEnrolment"/> stores. It defaults to a fresh
    /// <see cref="InMemoryAgentCredentialWriter"/>; a test store never writes the
    /// host Credential Manager, file store or registry, whatever it is passed.
    ///
    /// PAT-1766: <paramref name="provisioningSource"/> stands in for re-running the
    /// startup load in <see cref="RefreshProvisioning"/>. It defaults to "nothing
    /// provisioned yet" (null).
    /// </summary>
    internal static CredentialStore CreateForTests(
        string suspendedFile, string bearerToken = "test-bearer", Func<string?>? enrollmentTokenSource = null,
        string? enrollmentToken = null, string hmacSecret = "dGVzdC1obWFjLXNlY3JldC0zMi1ieXRlcy1sb25nIQ==",
        InMemoryAgentCredentialWriter? credentialWriter = null, Func<CredentialStore?>? provisioningSource = null,
        string tenantId = "test-tenant", bool storedCredentialPairPresent = false) =>
        new(tenantId, bearerToken, hmacSecret,
            enrollToken: enrollmentToken, suspendedFile, enrollmentTokenSource ?? (() => null),
            credentialWriter ?? new InMemoryAgentCredentialWriter(), provisioningSource ?? (() => null),
            storedCredentialPairPresent);

    // -------------------------------------------------------------------------
    // Environment variable fallback names
    // -------------------------------------------------------------------------
    private const string EnvTenantId    = "PATCHED_TENANT_ID";
    private const string EnvBearerToken = "PATCHED_BEARER_TOKEN";
    private const string EnvHmacSecret  = "PATCHED_HMAC_SECRET";

    // -------------------------------------------------------------------------
    // File-based fallback — mirrors macOS /etc/patched/
    // -------------------------------------------------------------------------
    // True immutable static, as before PAT-1042. Only ReadCredsFile below uses
    // this directly, and that runs from the static Load()/LoadForStartup()
    // factories before any instance (and therefore before _suspendedFile)
    // exists, so it has no test-seam need of its own — this ticket's tests
    // exercise IsSuspended/MarkSuspended/ClearSuspended, not the credential
    // file-fallback lookup.
    private static readonly string CredsDir = PathConstants.CredsDir;

    /// <summary>
    /// PAT-1764: every file the agent keeps in the plaintext file store
    /// (%ProgramData%\Patched\creds), including the suspended marker, so the
    /// uninstall purge clears a file-provisioned identity as well as Credential
    /// Manager. Names match <see cref="ReadCredsFile"/> and <see cref="MarkSuspended"/>.
    /// </summary>
    public static readonly IReadOnlyList<string> AgentCredentialFileNames = new[]
    {
        "tenant-id",
        "bearer-token",
        "hmac-secret",
        "canonical-device-identity",
        EnrollmentTokenProvisioner.FileName,
        "suspended",
    };

    /// <summary>
    /// PAT-1764: the production file-store purge, wired to the same trust primitives
    /// the agent uses for its other privileged paths: <see cref="SecureStagingDirectory.VerifyTrusted"/>
    /// (read-only, never repairs) and <see cref="PathSafety.HasReparsePointInChain"/>,
    /// both anchored at <see cref="PathConstants.StateDir"/>.
    /// </summary>
    internal static CredentialFileStorePurge CreateFileStorePurge() => new(
        PathConstants.StateDir,
        CredsDir,
        AgentCredentialFileNames,
        Directory.Exists,
        SecureStagingDirectory.VerifyTrusted,
        PathSafety.HasReparsePointInChain,
        CredentialFileStorePurge.DeleteFileReporting);

    private static readonly CredentialFileTrust CredentialFiles =
        CredentialFileTrust.CreateWindows(PathConstants.StateDir, CredsDir);

    private static string? ReadCredsFile(string name) => CredentialFiles.ReadOptional(name);

    /// <summary>
    /// The production installer writer refuses existing unsafe credential ancestors.
    /// It never repairs a writable legacy root or blesses pre-existing secrets.
    /// </summary>
    internal static EnrollmentTokenProvisioner CreateEnrollmentTokenProvisioner() => new(
        PathConstants.StateDir,
        CredsDir,
        (directory, allowStandardUserRead) =>
        {
            if (allowStandardUserRead)
                SecureStagingDirectory.EnsureHardenedTrustedInstallerDirectory(
                    directory, allowStandardUserRead: true, repairExisting: false);
            else CredentialDirectoryPrivacy.EnsureWindows(directory);
        },
        PathSafety.HasReparsePointInChain,
        (path, contents) =>
        {
            CredentialFiles.DeleteIfTrusted(EnrollmentTokenProvisioner.FileName);
            return EnrollmentTokenProvisioner.WriteFileReporting(path, contents);
        });

    /// <summary>
    /// PAT-1755: whether the credential file store holds an unconsumed enrolment token.
    /// Presence only; the value is never returned.
    /// </summary>
    internal static bool CredsFileEnrollmentTokenPresent() =>
        IsUsableEnrollmentToken(ReadCredsFile(EnrollmentTokenProvisioner.FileName));

    /// <summary>
    /// PAT-1755: deletes only the enrolment-token file from the credential file store,
    /// leaving every other credential file in place. Runs as LocalSystem against a fixed
    /// %ProgramData% path, so it refuses to delete through a reparse point for the same
    /// reason <see cref="CredentialFileStorePurge"/> does, and throws rather than reporting
    /// a silent success so the caller can say the token is still there.
    /// </summary>
    internal static void DeleteCredsFileEnrollmentToken()
    {
        CredentialFiles.DeleteIfTrusted(EnrollmentTokenProvisioner.FileName);
    }

    // -------------------------------------------------------------------------
    // Registry provisioning store (PAT-599 — ARM64-safe installer path)
    // -------------------------------------------------------------------------
    // The WiX installer writes MSI properties to HKLM\SOFTWARE\Patched\Enrollment
    // via RegistryValue elements — no custom DLL required, works on x64 and ARM64.
    // LoadForStartup reads these on first service start, migrates to Credential
    // Manager, then deletes the key. Raw-credential values are migrated inline;
    // enrollment-token cleanup happens in UpdateFromEnrolment after a successful
    // /v1/enrol exchange.

    /// <summary>
    /// Public (not private) for the same reason as the Credential Manager targets
    /// above — <c>DecommissionHandoffScript.Build</c> reads this constant directly
    /// for the purge=true cleanup rather than duplicating the literal path
    /// (PAT-1110). Relative to HKLM (no hive prefix) to match
    /// <see cref="Registry.LocalMachine"/>.OpenSubKey's own usage below.
    /// </summary>
    public const string RegistryProvisioningKey = ProvisioningRegistry.KeyPath;

    private static string? ReadRegistryProvisioning(string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryProvisioningKey);
            return key?.GetValue(name)?.ToString();
        }
        catch { return null; }
    }

    private static void DeleteRegistryProvisioningKey()
    {
        try
        {
            Registry.LocalMachine.DeleteSubKeyTree(RegistryProvisioningKey,
                throwOnMissingSubKey: false);
        }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// PAT-1764: registry value name the installer writes the enrolment token to.
    /// </summary>
    public const string RegistryEnrollmentTokenValue = "EnrollmentToken";

    /// <summary>
    /// PAT-1764: deletes the registry provisioning key and reports the outcome
    /// (an absent key is success). Used by the uninstall purge, which must be able
    /// to say whether the key is really gone rather than swallow the failure.
    /// </summary>
    internal static CredentialPurgeStep DeleteRegistryProvisioningKeyReporting()
    {
        try
        {
            Registry.LocalMachine.DeleteSubKeyTree(RegistryProvisioningKey, throwOnMissingSubKey: false);
            using var key = Registry.LocalMachine.OpenSubKey(RegistryProvisioningKey);
            return key is null
                ? CredentialPurgeStep.Removed
                : CredentialPurgeStep.Failed("key still present after delete");
        }
        catch (Exception ex)
        {
            return CredentialPurgeStep.Failed(ex.GetType().Name);
        }
    }

    /// <summary>
    /// PAT-1764: deletes one generic credential from this account's Credential
    /// Manager (SYSTEM's when run from the uninstall custom action). A target that
    /// does not exist counts as removed. Never reads or logs the credential value.
    /// </summary>
    internal static CredentialPurgeStep DeleteCredentialReporting(string target)
    {
        if (CredDelete(target, 1 /* CRED_TYPE_GENERIC */, 0))
            return CredentialPurgeStep.Removed;
        var error = Marshal.GetLastWin32Error();
        return error == ErrorNotFound
            ? CredentialPurgeStep.Removed
            : CredentialPurgeStep.Failed($"CredDelete error {error}");
    }

    private const int ErrorNotFound = 1168;

    /// <summary>
    /// PAT-1764: whether the installer left an enrolment token in the registry
    /// provisioning key. Reads presence only; the value is never returned.
    /// </summary>
    internal static bool RegistryEnrollmentTokenPresent() =>
        !string.IsNullOrEmpty(ReadRegistryProvisioning(RegistryEnrollmentTokenValue));

    /// <summary>
    /// PAT-1764: deletes only the EnrollmentToken value from the registry
    /// provisioning key, leaving any other value in place.
    /// </summary>
    internal static void DeleteRegistryEnrollmentTokenValue()
    {
        using var key = Registry.LocalMachine.OpenSubKey(RegistryProvisioningKey, writable: true);
        key?.DeleteValue(RegistryEnrollmentTokenValue, throwOnMissingValue: false);
    }

    /// <summary>
    /// PAT-1755: whether an unconsumed enrolment token is sitting in either location an
    /// installer provisions one: the credential file store, which this MSI writes, or the
    /// registry provisioning key, which an MSI predating PAT-1755 wrote and which a device
    /// upgraded from one can still carry. Presence only; no value is returned.
    /// </summary>
    internal static bool IgnoredEnrollmentTokenPresent() =>
        CredsFileEnrollmentTokenPresent() || RegistryEnrollmentTokenPresent();

    /// <summary>
    /// PAT-1755: deletes the unconsumed enrolment token from both provisioning locations.
    /// Both are attempted even when the first throws, so one unreachable location never
    /// leaves a live single-use secret behind in the other; the first failure is then
    /// reported to the caller.
    /// </summary>
    internal static void DeleteIgnoredEnrollmentToken()
    {
        Exception? failure = null;
        try { DeleteCredsFileEnrollmentToken(); }     catch (Exception ex) { failure = ex; }
        try { DeleteRegistryEnrollmentTokenValue(); } catch (Exception ex) { failure ??= ex; }
        if (failure is not null)
            throw failure;
    }

    // -------------------------------------------------------------------------
    // PAT-1760: what "holds credentials" means, defined once
    // -------------------------------------------------------------------------

    /// <summary>
    /// PAT-1760: the single definition of a usable bearer token. Empty or whitespace
    /// means the device has none. Patched.Service's DeviceCredentials delegates here.
    /// </summary>
    internal static bool IsUsableBearerToken(string? bearerToken) => !string.IsNullOrWhiteSpace(bearerToken);

    /// <summary>
    /// PAT-1760: the single definition of a usable HMAC secret. Empty or whitespace
    /// means the device has none: Convert.FromBase64String("   ") yields an empty key,
    /// which signs every request invalidly.
    /// </summary>
    internal static bool IsUsableHmacSecret(string? hmacSecret) => !string.IsNullOrWhiteSpace(hmacSecret);

    /// <summary>PAT-1760: a device is enrolled only when it holds both, each usable.</summary>
    internal static bool IsUsablePair(string? bearerToken, string? hmacSecret) =>
        IsUsableBearerToken(bearerToken) && IsUsableHmacSecret(hmacSecret);

    /// <summary>
    /// PAT-1765: the single definition of a usable enrolment token. Empty or
    /// whitespace means the device has none: sending it can only draw a 401 that
    /// suspends the device for a token that was never real.
    /// </summary>
    internal static bool IsUsableEnrollmentToken(string? enrollmentToken) => !string.IsNullOrWhiteSpace(enrollmentToken);

    /// <summary>
    /// PAT-1765: the first usable enrolment token from <paramref name="sources"/>, read
    /// in order and only as far as needed. A blank value in a higher-priority source
    /// (for example an empty Credential Manager entry) no longer hides a real token in
    /// a lower one, and is never returned.
    /// </summary>
    internal static string? FirstUsableEnrollmentToken(params Func<string?>[] sources)
    {
        foreach (var source in sources)
        {
            var value = source();
            if (IsUsableEnrollmentToken(value))
                return value;
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Factories
    // -------------------------------------------------------------------------

    /// <summary>
    /// Original factory — throws if any post-enrolment credential is absent.
    /// Preserved for callers that cannot tolerate an enrolment-pending state.
    /// </summary>
    public static CredentialStore Load()
    {
        var tenantId    = ReadCredential(TargetTenantId)
                       ?? Environment.GetEnvironmentVariable(EnvTenantId)
                       ?? ReadCredsFile("tenant-id")
                       ?? throw Missing(TargetTenantId, EnvTenantId);
        var bearerToken = ReadCredential(TargetBearerToken)
                       ?? Environment.GetEnvironmentVariable(EnvBearerToken)
                       ?? ReadCredsFile("bearer-token")
                       ?? throw Missing(TargetBearerToken, EnvBearerToken);
        var hmacSecret  = ReadCredential(TargetHmacSecret)
                       ?? Environment.GetEnvironmentVariable(EnvHmacSecret)
                       ?? ReadCredsFile("hmac-secret")
                       ?? throw Missing(TargetHmacSecret, EnvHmacSecret);
        return new CredentialStore(tenantId, bearerToken, hmacSecret, null)
        { _canonicalDeviceIdentity = ReadCredential(TargetDeviceId) ?? ReadCredsFile("canonical-device-identity") };
    }

    /// <summary>
    /// Service startup factory — handles the enrolment-pending state without throwing.
    /// If full post-enrolment credentials are present, returns a fully enrolled store.
    /// If only an enrolment token is present, returns an enrolment-pending store
    /// (TenantId / BearerToken / HmacSecret are empty strings; the worker calls
    /// AgentEnroller before the first run cycle).
    /// PAT-1766: when neither a usable credential set nor an enrolment token can be
    /// found, returns a store that is <see cref="AwaitingProvisioning"/> instead of
    /// throwing. The service keeps running, reports the state and polls
    /// <see cref="RefreshProvisioning"/>; exiting here failed StartServices, so an
    /// MSI install or upgrade onto an unprovisioned device rolled back (1920/1603).
    ///
    /// Credential source priority:
    ///   1. Windows Credential Manager
    ///   2. Environment variables
    ///   3. File store (%ProgramData%\Patched\creds\*)
    ///   4. Registry provisioning store (HKLM\SOFTWARE\Patched\Enrollment) — written
    ///      by the WiX installer as an ARM64-safe alternative to the DLL custom action
    ///      (PAT-599). Raw credentials found here are migrated to Credential Manager
    ///      and the registry key is deleted before returning.
    /// </summary>
    public static CredentialStore LoadForStartup(ILogger? log = null) =>
        LoadForStartup(log, StartupSources.Real);

    /// <summary>
    /// PAT-1760: every source LoadForStartup reads or changes, so the decision can be
    /// tested without Credential Manager, the file store or HKLM. Production always
    /// uses <see cref="Real"/>.
    /// </summary>
    internal sealed record StartupSources(
        Func<string, string?> ReadCredential,
        Func<string, string?> ReadEnvironment,
        Func<string, string?> ReadCredsFile,
        Func<string, string?> ReadRegistry,
        Action<string, string> WriteCredential,
        Action DeleteRegistryKey,
        Func<bool> IgnoredEnrollmentTokenPresent,
        Action DeleteIgnoredEnrollmentToken,
        string SuspendedFile,
        Func<string?> ReadEnrollmentTokenSource,
        IAgentCredentialWriter CredentialWriter)
    {
        internal static readonly StartupSources Real = new(
            CredentialStore.ReadCredential,
            Environment.GetEnvironmentVariable,
            CredentialStore.ReadCredsFile,
            ReadRegistryProvisioning,
            Write,
            CredentialStore.DeleteRegistryProvisioningKey,
            CredentialStore.IgnoredEnrollmentTokenPresent,
            CredentialStore.DeleteIgnoredEnrollmentToken,
            DefaultSuspendedFile,
            ReadEnrollmentTokenFromRealSources,
            HostCredentialWriter.Instance);
    }

    internal static CredentialStore LoadForStartup(ILogger? log, StartupSources src)
    {
        // PAT-1766: every store built here can re-run this same load while it waits
        // to be provisioned (RefreshProvisioning).
        Func<CredentialStore?> reload = () => LoadForStartup(log, src);

        var tenantId    = src.ReadCredential(TargetTenantId)    ?? src.ReadEnvironment(EnvTenantId)    ?? src.ReadCredsFile("tenant-id");
        var bearerToken = src.ReadCredential(TargetBearerToken) ?? src.ReadEnvironment(EnvBearerToken) ?? src.ReadCredsFile("bearer-token");
        var hmacSecret  = src.ReadCredential(TargetHmacSecret)  ?? src.ReadEnvironment(EnvHmacSecret)  ?? src.ReadCredsFile("hmac-secret");
        bool storedPairPresent = bearerToken != null && hmacSecret != null;

        // PAT-1760: "holds credentials" means the same thing here as everywhere else in
        // the agent: a bearer token and HMAC secret that are both non-whitespace
        // (IsUsablePair). A stored pair that is present but unusable (for example a
        // whitespace secret in Credential Manager) used to count as enrolled, so the
        // installer's enrolment token was deleted below and the device could never
        // recover. It is now treated as not enrolled: an enrolment token, if any, is
        // loaded and used instead.
        bool storedComplete = tenantId != null && bearerToken != null && hmacSecret != null;
        if (storedComplete && IsUsablePair(bearerToken, hmacSecret))
        {
            // PAT-1764: a token the installer wrote over existing credentials is never
            // used (re-enrolling over working credentials is PAT-1760's territory), so
            // it must not sit in a provisioning store as a live, unused secret. PAT-1755
            // moved the installer's write from the registry to the credential file store,
            // so both locations are cleared.
            IgnoredEnrollmentToken.Discard(
                src.IgnoredEnrollmentTokenPresent, src.DeleteIgnoredEnrollmentToken,
                log ?? NullLogger.Instance);
            return new CredentialStore(tenantId!, bearerToken!, hmacSecret!, null, src.SuspendedFile, src.ReadEnrollmentTokenSource, src.CredentialWriter, reload, storedPairPresent)
            { _canonicalDeviceIdentity = src.ReadCredential(TargetDeviceId) ?? src.ReadCredsFile("canonical-device-identity") };
        }

        // Registry provisioning store (PAT-599): check for raw credentials written by
        // the WiX installer via RegistryValue elements (no DLL, ARM64-safe). Migrate
        // them to Credential Manager immediately and delete the registry key.
        // PAT-1760: only when no complete stored set exists, as before; an unusable
        // stored set is not overwritten from here.
        if (!storedComplete)
        {
            var regTenantId    = src.ReadRegistry("TenantId");
            var regBearerToken = src.ReadRegistry("BearerToken");
            var regHmacSecret  = src.ReadRegistry("HmacSecret");
            if (regTenantId != null && regBearerToken != null && regHmacSecret != null)
            {
                try { src.WriteCredential(TargetTenantId,    regTenantId); }    catch { /* CM unavailable; in-memory values still work for this run */ }
                try { src.WriteCredential(TargetBearerToken, regBearerToken); } catch { /* CM unavailable; in-memory values still work for this run */ }
                try { src.WriteCredential(TargetHmacSecret,  regHmacSecret); }  catch { /* CM unavailable; in-memory values still work for this run */ }
                src.DeleteRegistryKey();
                return new CredentialStore(regTenantId, regBearerToken, regHmacSecret, null, src.SuspendedFile, src.ReadEnrollmentTokenSource, src.CredentialWriter, reload, storedCredentialPairPresent: true);
            }
        }

        // Enrollment-token path: check Credential Manager, file store, then registry.
        // PAT-1765: only a usable (non-whitespace) token counts; a blank one is the same
        // as no token, as it is for TryEnrolAsync and the worker.
        var enrollToken = FirstUsableEnrollmentToken(
            () => src.ReadCredential(TargetEnrollmentToken),
            () => src.ReadCredsFile(EnrollmentTokenProvisioner.FileName),
            () => src.ReadRegistry("EnrollmentToken"));
        if (enrollToken != null)
        {
            if (storedComplete)
            {
                (log ?? NullLogger.Instance).LogWarning(
                    "Stored agent credentials are present but unusable (an empty or whitespace bearer token or HMAC secret); " +
                    "they are not used and the enrollment token found on this device will be used to enrol");
            }
            return new CredentialStore("", "", "", enrollToken, src.SuspendedFile, src.ReadEnrollmentTokenSource, src.CredentialWriter, reload, storedPairPresent);
        }

        // PAT-1760: an unusable stored set with no enrolment token keeps the previous
        // behaviour (the service starts rather than failing identity resolution). Every
        // authenticated caller checks for a usable pair first, so it sends nothing and
        // collects nothing until a fresh enrolment token is provisioned.
        // PAT-1766: the store is AwaitingProvisioning, so the worker reports this state
        // (AgentProvisioning.NotProvisionedMessage) and polls for a token or usable
        // credentials. It is not logged here because the poll re-runs this load.
        if (storedComplete)
            return new CredentialStore(tenantId!, bearerToken!, hmacSecret!, null, src.SuspendedFile, src.ReadEnrollmentTokenSource, src.CredentialWriter, reload, storedPairPresent);

        // PAT-1766: no identity at all (installed without credentials, an upgrade that
        // lost an unconsumed token, or an uninstall that purged credentials and then
        // rolled back). PAT-1764 threw here and the service exited 2, which failed
        // StartServices and rolled the install back. The service now starts in the
        // not-provisioned state instead.
        return new CredentialStore("", "", "", null, src.SuspendedFile, src.ReadEnrollmentTokenSource, src.CredentialWriter, reload, storedCredentialPairPresent: false);
    }

    /// <summary>
    /// Test-only: builds an in-memory <see cref="CredentialStore"/> from literal
    /// values without touching Windows Credential Manager, the file-store fallback,
    /// or the registry provisioning store — unlike <see cref="Load"/>/
    /// <see cref="LoadForStartup"/>, which unconditionally call a raw
    /// <c>DllImport("advapi32.dll")</c> P/Invoke this repo's non-Windows CI host
    /// cannot run. Internal + <c>InternalsVisibleTo</c> (Service.Tests) rather than
    /// public: never intended for production code, only for tests (e.g.
    /// DecommissionStatusReporterTests) that need a working credentials object to
    /// exercise a real HTTP+signing round trip against a fake handler.
    ///
    /// PAT-1763: the store is fully off the host. Its suspended marker is a
    /// per-instance path under the temp directory (never
    /// %ProgramData%\Patched\creds\suspended), it reads no enrolment-token source,
    /// and <see cref="UpdateFromEnrolment"/> writes to an
    /// <see cref="InMemoryAgentCredentialWriter"/>.
    /// </summary>
    internal static CredentialStore ForTesting(string tenantId, string bearerToken, string hmacSecret) =>
        new(tenantId, bearerToken, hmacSecret, null,
            Path.Combine(Path.GetTempPath(), "patched-credential-store-tests", Guid.NewGuid().ToString("N"), "suspended"),
            () => null,
            new InMemoryAgentCredentialWriter(),
            () => null,
            storedCredentialPairPresent: true);

    // -------------------------------------------------------------------------
    // Enrolment helpers (called by AgentEnroller after a successful /v1/enrol)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Persists the three post-enrolment credentials to Credential Manager and
    /// updates the in-memory properties so all DI consumers see them immediately.
    /// Also removes the now-consumed enrolment token from Credential Manager.
    /// Throws if the Credential Manager write fails — caller should handle.
    /// </summary>
    public void UpdateFromEnrolment(string tenantId, string bearerToken, string hmacSecret, string? canonicalDeviceId = null)
    {
        _credentialWriter.WriteCredential(TargetTenantId,    tenantId);
        _credentialWriter.WriteCredential(TargetBearerToken, bearerToken);
        _credentialWriter.WriteCredential(TargetHmacSecret,  hmacSecret);
        // Bind identity to this credential pair so partial writes or reprovisioning
        // cannot borrow the prior device's canonical UUID. Empty clears old identity.
        string identity = Guid.TryParseExact(canonicalDeviceId, "D", out var uuid) && uuid != Guid.Empty
            ? System.Text.Json.JsonSerializer.Serialize(new { tenant_id = tenantId, device_id = uuid.ToString("D"), credential_hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(bearerToken))) }) : "";
        _credentialWriter.WriteCredential(TargetDeviceId, identity);

        // Best-effort removal of the consumed token: Credential Manager, the file
        // fallback and the registry provisioning key (PAT-599). See HostCredentialWriter.
        _credentialWriter.DiscardConsumedEnrollmentToken();

        TenantId        = tenantId;
        BearerToken     = bearerToken;
        HmacSecret      = hmacSecret;
        _canonicalDeviceIdentity = identity;
        EnrollmentToken = null;
        StoredCredentialPairPresent = true;
    }

    /// <summary>
    /// Writes the suspended sentinel file.  Subsequent service cycles see
    /// <see cref="IsSuspended"/> == true and skip all collection / upload.
    /// </summary>
    public void MarkSuspended()
    {
        // Directory.CreateDirectory of _suspendedFile's own parent, not the
        // static CredsDir constant above — so this still lands next to
        // _suspendedFile itself when a test instance (CreateForTests) has
        // redirected it to a scratch temp path instead of the real
        // %ProgramData%\Patched\creds.
        if (WritesHostCredentialStorage)
        {
            CredentialFiles.MarkSuspended();
            return;
        }
        Directory.CreateDirectory(Path.GetDirectoryName(_suspendedFile)!);
        File.WriteAllText(_suspendedFile, "");
    }

    /// <summary>
    /// Removes the suspended sentinel file, idempotently (no-op, no throw, if
    /// already absent — <see cref="File.Delete"/> does not throw on a missing
    /// path). PAT-1042: called from the Service project's agent-config fetch
    /// success path (AgentConfigFetcher.VerifyAndCache, after a
    /// signature-verified 200 is durably committed) — the mirror image of
    /// <see cref="MarkSuspended"/> above. A verified 200 is proof the device
    /// has working credentials again, so enforcement resumes to NORMAL
    /// immediately, symmetric with the immediate suspend on 401 (no
    /// consecutive-success threshold). This also self-heals a transient or
    /// mistaken 401 for free.
    /// </summary>
    public void ClearSuspended()
    {
        if (WritesHostCredentialStorage) CredentialFiles.DeleteIfTrusted("suspended");
        else File.Delete(_suspendedFile);
    }

    /// <summary>
    /// PAT-1766: true when this device can neither authenticate nor enrol: it holds no
    /// usable credential pair (<see cref="IsUsablePair"/>) and no enrolment token. The
    /// service runs in this state without collecting or sending anything, and polls
    /// <see cref="RefreshProvisioning"/>. A device suspended by a rejected token still
    /// holds that token, so it is not in this state; <c>WaitForRecoveryAsync</c> owns it.
    /// </summary>
    public bool AwaitingProvisioning => !IsUsablePair(BearerToken, HmacSecret) && !IsUsableEnrollmentToken(EnrollmentToken);

    /// <summary>
    /// PAT-1766: while <see cref="AwaitingProvisioning"/>, re-runs the startup load
    /// against the same sources (Credential Manager, environment, file store and the
    /// registry provisioning key, including the raw-credential migration and the
    /// ignored-token cleanup LoadForStartup already does). When that finds a usable
    /// credential pair or an enrolment token, this store takes on those values in
    /// place, so every service already holding the singleton sees them, and returns
    /// true. Returns false, changing nothing, when the device is not waiting or
    /// nothing new was found. Exceptions from the sources propagate to the caller.
    ///
    /// Values are assigned in <see cref="UpdateFromEnrolment"/>'s order (bearer token
    /// before HMAC secret, see DeviceCredentials.TryRead). A store waiting with an
    /// empty pair cannot be read as holding a mixed pair. One that started from an
    /// unusable stored pair (a non-empty bearer token) has the same brief window
    /// UpdateFromEnrolment has for that device: a request signed with the old token and
    /// the new secret is rejected, and the existing suspend and verified-200 path
    /// recovers it.
    /// </summary>
    public bool RefreshProvisioning()
    {
        if (!AwaitingProvisioning)
            return false;

        var fresh = _reloadForStartup();
        if (fresh is null)
            return false;

        // Preserve presence separately from usability. A re-read may discover a
        // stored blank pair and still remain AwaitingProvisioning; the worker needs
        // that evidence to report credentials_empty instead of conflating it with a
        // genuinely bare install.
        StoredCredentialPairPresent = fresh.StoredCredentialPairPresent;
        if (fresh.AwaitingProvisioning)
            return false;

        TenantId        = fresh.TenantId;
        _canonicalDeviceIdentity = fresh._canonicalDeviceIdentity;
        BearerToken     = fresh.BearerToken;
        HmacSecret      = fresh.HmacSecret;
        EnrollmentToken = fresh.EnrollmentToken;
        return true;
    }

    /// <summary>
    /// PAT-1203: re-reads the enrollment-token sources (Credential Manager,
    /// file store, registry provisioning key — <see
    /// cref="ReadEnrollmentTokenFromRealSources"/>, the same three
    /// LoadForStartup checks once at process start) and updates the in-memory
    /// <see cref="EnrollmentToken"/> if a different, non-empty value is now
    /// present. Exists because EnrollmentToken above is otherwise only ever
    /// set once, at construction — nothing re-reads disk for the lifetime of
    /// a running instance, so a fresh token an admin drops in later would
    /// otherwise be invisible without a full service restart.
    ///
    /// Returns false (no-op) once <see cref="BearerToken"/> and
    /// <see cref="HmacSecret"/> form a usable pair (PAT-1760; previously once
    /// BearerToken was non-empty) — an already-enrolled device (including one suspended by a later
    /// *revocation*, which has nothing to do with the enrollment token) has
    /// no enrollment token to refresh, so this avoids a pointless Credential
    /// Manager / disk / registry probe on every recheck for that far more
    /// common suspended case.
    ///
    /// Returns false when the freshly read value is empty or identical to
    /// the current one — deliberately does NOT trigger a caller retry against
    /// the same still-rejected token, which would just repeat the identical
    /// 410/401 forever (the same failure mode flagged in macOS's
    /// patched-enroll.sh 410/401 branch, PAT-1203).
    /// </summary>
    public bool RefreshEnrollmentToken()
    {
        // PAT-1760: the short-circuit applies only to a device holding a usable pair.
        // A bearer token with an empty or whitespace secret is not enrolled, and a
        // fresh enrolment token is the only way it can recover.
        if (IsUsablePair(BearerToken, HmacSecret))
            return false;

        // PAT-1765: a whitespace-only value is no token and never signals a retry.
        var fresh = _readEnrollmentTokenSource();
        if (!IsUsableEnrollmentToken(fresh) || fresh == EnrollmentToken)
            return false;

        EnrollmentToken = fresh;
        return true;
    }

    // -------------------------------------------------------------------------
    // Write a generic credential to Credential Manager (used by installer CA too)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Write a credential to Credential Manager. Called by AgentEnroller after a
    /// successful enrolment exchange, and by LoadForStartup when migrating credentials
    /// from the registry provisioning store.
    /// </summary>
    public static void Write(string target, string value)
    {
        var blob = Encoding.UTF8.GetBytes(value);
        var cred = new NativeCredential
        {
            Type               = 1,   // CRED_TYPE_GENERIC
            TargetName         = target,
            CredentialBlob     = Marshal.AllocHGlobal(blob.Length),
            CredentialBlobSize = (uint)blob.Length,
            Persist            = 2,   // CRED_PERSIST_LOCAL_MACHINE — survives reboot
            UserName           = "PatchedAgent",
        };
        try
        {
            Marshal.Copy(blob, 0, cred.CredentialBlob, blob.Length);
            if (!CredWrite(ref cred, 0))
                throw new InvalidOperationException(
                    $"CredWrite failed for {target}: {Marshal.GetLastWin32Error()}");
        }
        finally
        {
            Marshal.FreeHGlobal(cred.CredentialBlob);
        }
    }

    // -------------------------------------------------------------------------
    // P/Invoke — Windows Credential Manager (advapi32.dll)
    // -------------------------------------------------------------------------

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NativeCredential
    {
        public uint    Flags;
        public uint    Type;
        public string  TargetName;
        public string? Comment;
        public long    LastWritten;
        public uint    CredentialBlobSize;
        public IntPtr  CredentialBlob;
        public uint    Persist;
        public uint    AttributeCount;
        public IntPtr  Attributes;
        public string? TargetAlias;
        public string? UserName;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, uint type, uint flags,
        out IntPtr credentialPtr);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr credentialPtr);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWrite(ref NativeCredential credential, uint flags);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredDelete(string target, uint type, uint flags);

    private static string? ReadCredential(string target)
    {
        if (!CredRead(target, 1 /* CRED_TYPE_GENERIC */, 0, out var ptr))
            return null;
        try
        {
            var cred = Marshal.PtrToStructure<NativeCredential>(ptr);
            if (cred.CredentialBlobSize == 0 || cred.CredentialBlob == IntPtr.Zero)
                return null;
            var blob = new byte[cred.CredentialBlobSize];
            Marshal.Copy(cred.CredentialBlob, blob, 0, blob.Length);
            return Encoding.UTF8.GetString(blob);
        }
        finally
        {
            CredFree(ptr);
        }
    }

    /// <summary>
    /// Read a generic credential's username + password from Windows Credential
    /// Manager by target name. Used for proxy credentials (PAT-309): the
    /// installer stores the proxy username in the credential's UserName field
    /// and the password in the (DPAPI-protected) blob. Returns null when the
    /// target is absent. Never logs the values.
    /// </summary>
    public static (string user, string pass)? ReadGenericCredential(string target)
    {
        if (!CredRead(target, 1 /* CRED_TYPE_GENERIC */, 0, out var ptr))
            return null;
        try
        {
            var cred = Marshal.PtrToStructure<NativeCredential>(ptr);
            string user = cred.UserName ?? "";
            string pass = "";
            if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
            {
                var blob = new byte[cred.CredentialBlobSize];
                Marshal.Copy(cred.CredentialBlob, blob, 0, blob.Length);
                pass = Encoding.UTF8.GetString(blob);
            }
            return (user, pass);
        }
        finally
        {
            CredFree(ptr);
        }
    }

    private static InvalidOperationException Missing(string credTarget, string envVar) =>
        new($"Required credential '{credTarget}' not found in Windows Credential Manager " +
            $"and environment variable '{envVar}' is not set. " +
            "Run the Patched installer to provision credentials.");
}
