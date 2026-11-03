using System.Security.Cryptography;
using System.Diagnostics;
using System.Text;
using System.Security.AccessControl;
using Patched.Shared.InstallationEvidence;
using Xunit;

namespace Patched.Service.Tests;

public sealed class WindowsInstallationEvidenceTests
{
    [Theory]
    [InlineData(0x10000000u, true)] // GENERIC_ALL
    [InlineData(0x40000000u, true)] // GENERIC_WRITE
    [InlineData(0x80000000u, false)] // GENERIC_READ
    [InlineData(0x20000000u, false)] // GENERIC_EXECUTE
    [InlineData(0x00040000u, true)] // WRITE_DAC
    [InlineData(0x00080000u, true)] // WRITE_OWNER
    [InlineData(0x00010000u, true)] // DELETE
    [InlineData(0x00000002u, true)] // FILE_WRITE_DATA
    [InlineData(0x00000001u, false)] // FILE_READ_DATA
    public void MutationMaskDistinguishesGenericAndObjectSpecificRights(uint mask, bool expected) =>
        Assert.Equal(expected, WindowsInstallationEvidence.GrantsMutation((FileSystemRights)unchecked((int)mask)));

    [Theory]
    [InlineData(@"\\server\share\app.exe")]
    [InlineData(@"\\?\C:\app.exe")]
    [InlineData(@"C:\app.exe:stream")]
    [InlineData(@"C:\folder\..\app.exe")]
    [InlineData(@"C:\folder.\app.exe")]
    [InlineData(@"C:app.exe")]
    [InlineData(@"C:\folder\CON.exe")]
    [InlineData(@"C:\folder\LPT1.exe")]
    [InlineData("C:\\folder\n\\app.exe")]
    public void RejectsPathsThatCouldEscapeTheReviewedLocalFile(string path) =>
        Assert.False(WindowsInstallationEvidence.IsSafePath(path));

    [Fact]
    public void AcceptsCanonicalFixedPath() =>
        Assert.True(WindowsInstallationEvidence.IsSafePath(@"C:\Program Files\Fixture\Fixture.exe"));

    // PAT-2116: C:\Program Files\Patched exactly as WIN-STAGING's Get-Acl showed it under
    // 0.14.2. The helper directory check rejected this DACL, so every coverage helper spawn
    // on a real install failed and all apps reported helper_failed.
    private const string Users = "S-1-5-32-545";
    private const string CreatorOwner = "S-1-3-0";
    private const string AllAppPackages = "S-1-15-2-1";
    private const string AllRestrictedAppPackages = "S-1-15-2-2";
    private const FileSystemRights GenericAll = (FileSystemRights)0x10000000;
    private const FileSystemRights GenericReadExecute = unchecked((FileSystemRights)0xA0000000);
    private const FileSystemRights ReadAndExecute = FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize;

    private static WindowsInstallationEvidence.AclEntry Ace(string sid, FileSystemRights rights, bool inheritOnly = false) =>
        new(sid, rights, Allow: true, inheritOnly);

    internal static readonly WindowsInstallationEvidence.AclEntry[] ProgramFilesPatchedDacl =
    [
        Ace(WindowsInstallationEvidence.TrustedInstallerSid, FileSystemRights.FullControl),
        Ace(WindowsInstallationEvidence.TrustedInstallerSid, GenericAll, inheritOnly: true),
        Ace(WindowsInstallationEvidence.LocalSystemSid, FileSystemRights.FullControl),
        Ace(WindowsInstallationEvidence.LocalSystemSid, GenericAll, inheritOnly: true),
        Ace(WindowsInstallationEvidence.AdministratorsSid, FileSystemRights.FullControl),
        Ace(WindowsInstallationEvidence.AdministratorsSid, GenericAll, inheritOnly: true),
        Ace(Users, ReadAndExecute),
        Ace(Users, GenericReadExecute, inheritOnly: true),
        Ace(CreatorOwner, GenericAll, inheritOnly: true),
        Ace(AllAppPackages, ReadAndExecute),
        Ace(AllAppPackages, GenericReadExecute, inheritOnly: true),
        Ace(AllRestrictedAppPackages, ReadAndExecute),
        Ace(AllRestrictedAppPackages, GenericReadExecute, inheritOnly: true),
    ];

    [Fact]
    public void HelperInstallDirectoryAcceptsTheDaclARealInstallInherits() =>
        Assert.Null(WindowsInstallationEvidence.InstallDirectoryRefusal(
            WindowsInstallationEvidence.LocalSystemSid, ProgramFilesPatchedDacl));

    [Theory]
    [InlineData(Users, 0x00000002u, false)]              // FILE_ADD_FILE
    [InlineData(Users, 0x00000004u, false)]              // FILE_ADD_SUBDIRECTORY
    [InlineData(Users, 0x00000040u, false)]              // FILE_DELETE_CHILD
    [InlineData("S-1-5-11", 0x000301BFu, false)]         // Authenticated Users: Modify
    [InlineData("S-1-1-0", 0x40000000u, false)]          // Everyone: GENERIC_WRITE
    [InlineData(CreatorOwner, 0x10000000u, false)]       // applies to the directory itself
    [InlineData(Users, 0x40000000u, true)]               // PAT-2399: inherit-only still reaches every child
    public void HelperInstallDirectoryRejectsAnyOtherWriter(string sid, uint mask, bool inheritOnly)
    {
        var entry = Ace(sid, (FileSystemRights)unchecked((int)mask), inheritOnly);
        var refusal = WindowsInstallationEvidence.InstallDirectoryRefusal(
            WindowsInstallationEvidence.LocalSystemSid, [.. ProgramFilesPatchedDacl, entry]);
        // The refusal names the one offending principal and its rights, for the WARN line.
        Assert.Equal(new WindowsInstallationEvidence.AclRefusal("install_dir_acl", sid, entry.Rights), refusal);
        Assert.Equal($"principal={sid} rights=0x{mask:X8}", refusal!.Value.Detail);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(Users)]
    [InlineData("S-1-5-21-1-2-3-1001")]
    public void HelperInstallDirectoryRejectsAnUntrustedOwner(string? owner) =>
        Assert.Equal("install_dir_owner",
            WindowsInstallationEvidence.InstallDirectoryRefusal(owner, ProgramFilesPatchedDacl)?.Reason);

    [Fact]
    public void HelperInstallDirectoryIgnoresDenyEntries() =>
        Assert.Null(WindowsInstallationEvidence.InstallDirectoryRefusal(WindowsInstallationEvidence.LocalSystemSid,
            [.. ProgramFilesPatchedDacl, new(Users, FileSystemRights.FullControl, Allow: false, InheritOnly: false)]));

    // The real SDDL of C:\Program Files\Patched on WIN-STAGING (Get-Acl .Sddl, 0.14.2), parsed
    // by Windows and read back through ReadAcl, so the inherit-only flag and the raw GENERIC_*
    // bits survive the .NET ACL conversion exactly as the helper spawn sees them.
    internal const string ProgramFilesPatchedSddl =
        "O:SYG:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)" +
        "(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)" +
        "(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)" +
        "(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)" +
        "(A;OICIIOID;GXGR;;;S-1-15-2-2)";

    [WindowsTheory]
    [InlineData("", null)]
    [InlineData("(A;;0x2;;;BU)", "install_dir_acl")]          // Users: add file
    [InlineData("(A;OICI;GA;;;WD)", "install_dir_acl")]       // Everyone: GENERIC_ALL, not inherit-only
    [InlineData("(A;OICIIO;GA;;;WD)", "install_dir_acl")]     // PAT-2399: inherit-only, but every child gets it
    [InlineData("(A;OICIIO;GXGR;;;WD)", null)]                // inherit-only read and execute hands over nothing
    public void HelperInstallDirectoryPolicyHoldsOnTheRealProgramFilesDacl(string extraAce, string? expected)
    {
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm(ProgramFilesPatchedSddl + extraAce);
        var (owner, entries) = WindowsInstallationEvidence.ReadAcl(security);
        Assert.Equal(WindowsInstallationEvidence.LocalSystemSid, owner);
        Assert.Contains(entries, e => e.Sid == CreatorOwner && e.InheritOnly && (e.Rights & GenericAll) != 0);
        Assert.Equal(expected, WindowsInstallationEvidence.InstallDirectoryRefusal(owner, entries)?.Reason);
    }

    [Fact]
    public void HelperRejectsArbitraryArgumentsBeforeDoingAnyWork()
    {
        Assert.Equal(2, InstallationEvidenceProbe.RunCommand([InstallationEvidenceProbe.Command, "0"]));
        Assert.Equal(2, InstallationEvidenceProbe.RunCommand([InstallationEvidenceProbe.Command, @"C:\secret"]));
        Assert.Equal(2, InstallationEvidenceProbe.RunCommand([InstallationEvidenceProbe.Command, "-1"]));
        Assert.Equal(2, InstallationEvidenceProbe.RunCommand([InstallationEvidenceProbe.Command, "0", "extra"]));
    }

    // A six-byte stub is not a PE wintrust can parse (TRUST_E_SUBJECT_FORM_UNKNOWN), and the
    // PAT-2116 unsigned rule never applies to an unparseable subject, so it stays unknown.
    [WindowsFact]
    public void UnsignedFilePreservesHashButSignatureRemainsUnknown()
    {
        var dir = Directory.CreateTempSubdirectory("patched-evidence-").FullName;
        var path = Path.Combine(dir, "fixture.exe");
        try
        {
            var bytes = new byte[] { 77, 90, 1, 2, 3, 4 };
            File.WriteAllBytes(path, bytes);
            var result = WindowsInstallationEvidence.Read(new("fixture", "fixture", "x86_64", dir, path));
            Assert.Equal("partial", result.CollectionStatus);
            Assert.Equal("unknown", result.SignatureState);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), result.ExecutableSha256);
            Assert.Null(result.Signer);
            Assert.Equal(["signature_unavailable"], result.Errors);
        }
        finally { File.Delete(path); Directory.Delete(dir); }
    }

    [WindowsFact]
    public void MissingFileIsUnavailableNeverAbsentOrInvalid()
    {
        var dir = Directory.CreateTempSubdirectory("patched-evidence-").FullName;
        try
        {
            var result = WindowsInstallationEvidence.Read(new("fixture", "fixture", "x86_64", dir, Path.Combine(dir, "missing.exe")));
            Assert.Equal("unavailable", result.CollectionStatus);
            Assert.Equal("unknown", result.SignatureState);
            Assert.Null(result.ExecutablePath);
        }
        finally { Directory.Delete(dir); }
    }

    [WindowsFact]
    public void ReparseFileCannotBeFollowed()
    {
        var dir = Directory.CreateTempSubdirectory("patched-evidence-").FullName;
        var actual = Path.Combine(dir, "actual.exe");
        var link = Path.Combine(dir, "link.exe");
        try
        {
            File.WriteAllBytes(actual, [77, 90, 1]);
            File.CreateSymbolicLink(link, actual);
            var result = WindowsInstallationEvidence.Read(new("fixture", "fixture", "x86_64", dir, link));
            Assert.Equal("unavailable", result.CollectionStatus);
            Assert.Null(result.ExecutableSha256);
        }
        finally { File.Delete(link); File.Delete(actual); Directory.Delete(dir); }
    }

    // PAT-1983: the hung child is SpinForeverHelper, built from this repository on every
    // build, not the runner image's powershell.exe. What this proves is unchanged - the
    // helper terminates a process that outlives its budget and reports unknown - but it no
    // longer rests on a binary, a start-up profile or a signing state the repository does
    // not control. Same class of fragility PAT-1971 removed from the Authenticode test,
    // reached through process-spawn timing rather than signature state.
    //
    // PAT-1991: a 100ms budget fired before the runtime had even booted, so a child that
    // exited on its own immediately passed exactly as a hung one did. The test now rests on
    // positive signals rather than on the budget beating start-up latency:
    //   - the start hook blocks until the helper has created its readiness file, so the
    //     child is known to have reached its blocking call however slow start-up was;
    //   - the budget is long enough that a child which exits by itself after becoming ready
    //     does so well before the deadline, and the probe then returns helper_failed;
    //   - the exit code must be -1, the code Process.Kill passes to TerminateProcess, which
    //     a child that ended normally (code 0) cannot produce.
    [WindowsFact]
    public async Task HelperTimeoutTerminatesTheProcessAndReturnsUnknown()
    {
        var helper = SpinForeverHelperPath();
        Assert.True(File.Exists(helper), $"SpinForeverHelper was not staged beside the tests at {helper}.");
        var dir = Directory.CreateTempSubdirectory("patched-helper-timeout-").FullName;
        var ready = Path.Combine(dir, "ready");
        var start = new ProcessStartInfo(helper)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(helper)!,
        };
        start.ArgumentList.Add(ready);
        var budget = TimeSpan.FromSeconds(2);
        var clock = Stopwatch.StartNew();
        Process? observed = null;
        var becameReady = false;
        try
        {
            var result = await InstallationEvidenceProbe.RunHelperAsync(start, budget, process =>
            {
                observed = Process.GetProcessById(process.Id);
                _ = observed.SafeHandle; // Retain a handle so PID reuse cannot change the exit observation.
                var readyBy = Stopwatch.StartNew();
                while (!File.Exists(ready) && !observed.HasExited && readyBy.Elapsed < TimeSpan.FromSeconds(30))
                    Thread.Sleep(10);
                becameReady = File.Exists(ready);
            });
            Assert.True(becameReady, "SpinForeverHelper never signalled that it was running, so a kill here would prove nothing.");
            Assert.Equal(["collection_timeout"], result.Errors);
            Assert.Equal("unknown", result.SignatureState);
            Assert.Equal("unavailable", result.CollectionStatus);
            Assert.NotNull(observed);
            Assert.True(observed.HasExited);
            Assert.Equal(-1, observed.ExitCode);
            Assert.True(clock.Elapsed < budget + TimeSpan.FromSeconds(35));
        }
        finally
        {
            observed?.Dispose();
            Directory.Delete(dir, recursive: true);
        }
    }

    // Service.Tests.csproj stages the helper project's build output into this fixed
    // subdirectory of the test output, so the path is settled by the build rather than by
    // walking back out of bin/ and guessing a configuration or target framework.
    private static string SpinForeverHelperPath() =>
        Path.Combine(AppContext.BaseDirectory, "SpinForeverHelper",
            OperatingSystem.IsWindows() ? "SpinForeverHelper.exe" : "SpinForeverHelper");

    [Fact]
    public async Task HelperOutputCannotExceedItsMemoryBound()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(new string('x', 16385)));
        using var reader = new StreamReader(stream);
        await Assert.ThrowsAsync<InvalidDataException>(() => InstallationEvidenceProbe.ReadBoundedAsync(reader, CancellationToken.None));
    }

    [Fact]
    public async Task HelperOutputWithinBoundIsPreserved()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("fixture"));
        using var reader = new StreamReader(stream);
        Assert.Equal("fixture", await InstallationEvidenceProbe.ReadBoundedAsync(reader, CancellationToken.None));
    }

    // PAT-1971: deliberately non-gating. WinVerifyTrust reports "valid" only for a chain the
    // machine already trusts, so no fixture this repository controls can reach that branch
    // without mutating a trust store, and there is no Patched Authenticode certificate to sign
    // one with (windows/installer/sign-hook.bat is still a stub). The signed binary therefore
    // has to come from outside the repository, and it is named explicitly rather than assumed:
    // windows-build.yml points this at dotnet.exe in a step that cannot fail the build. Do not
    // put it back in the gate. Asserting on the Authenticode state of a binary shipped by the
    // runner image made main red with no code regression, which is the defect this replaces.
    //
    // The fixture must be embedded signed, so that this exercises the embedded branch rather
    // than the catalog fallback PAT-1981 added below. A catalog-signed System32 binary would
    // now also come back valid, but through the other path, which would make this a weaker
    // test of the same thing rather than cover of the embedded one.
    // An externally supplied fixture only, not a production reviewed-product entry.
    [SignedFixtureFact]
    public void SignedWindowsExecutableProvidesVerifiedSignerAndHash()
    {
        var path = SignedFixtureFactAttribute.FixturePath!;
        var expectedSigner = Environment.GetEnvironmentVariable(SignedFixtureFactAttribute.SignerVariable) is { Length: > 0 } s
            ? s : "Microsoft";
        var dir = Path.GetDirectoryName(path)!;
        var result = WindowsInstallationEvidence.Read(new("fixture", "fixture", "x86_64", dir, path));
        Assert.Equal("complete", result.CollectionStatus);
        Assert.Equal("valid", result.SignatureState);
        Assert.Contains(expectedSigner, result.Signer);
        Assert.Equal(64, result.ExecutableSha256!.Length);
    }

    // The design rule the catalog fallback has to hold: a digest mismatch is an answer, not a
    // gap, so it is never re-asked as a catalog lookup. Without that rule a tampered
    // embedded-signed binary could be laundered out of "invalid" into "unknown", or, if some
    // catalog happened to carry a matching entry, into "valid" with a borrowed signer.
    // Opt-in for the same reason as the test above: it needs an embedded-signed binary this
    // repository does not have one of.
    [SignedFixtureFact]
    public void TamperedEmbeddedSignatureStaysInvalidRatherThanFallingThroughToTheCatalog()
    {
        var bytes = File.ReadAllBytes(SignedFixtureFactAttribute.FixturePath!);
        Assert.True(bytes.Length > 1024, "the signed fixture is too small to tamper meaningfully");
        var dir = Directory.CreateTempSubdirectory("patched-evidence-").FullName;
        var path = Path.Combine(dir, "tampered.exe");
        try
        {
            bytes[bytes.Length / 2] ^= 0xFF;
            File.WriteAllBytes(path, bytes);
            var result = WindowsInstallationEvidence.Read(new("fixture", "fixture", "x86_64", dir, path));
            Assert.Equal("invalid", result.SignatureState);
            Assert.Null(result.Signer);
            Assert.Equal("partial", result.CollectionStatus);
        }
        finally { File.Delete(path); Directory.Delete(dir); }
    }

    // PAT-1981. Windows signs most of what it ships into a catalog rather than embedding an
    // Authenticode signature in the PE, so a file-handle-only WinVerifyTrust reported the whole
    // of System32 as unsigned and SignatureState could not tell a genuinely Microsoft-signed OS
    // binary from an unsigned one. This is the guard for that, and unlike the embedded fixture
    // above it gates: the subject is not a binary a runner image happens to ship and can change
    // the signing arrangements of, it is the running operating system's own files, and an
    // unsigned System32 is worth a red build rather than a shrug. Take the catalog fallback out
    // of ReadSignature and this goes red.
    [WindowsTheory]
    [InlineData(@"WindowsPowerShell\v1.0\powershell.exe")]
    [InlineData("notepad.exe")]
    public void CatalogSignedOperatingSystemBinaryReportsAValidSignature(string relative)
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), relative);
        Assert.True(File.Exists(path), path);
        var result = WindowsInstallationEvidence.Read(
            new("fixture", "fixture", "x86_64", Path.GetDirectoryName(path)!, path));
        Assert.Equal("valid", result.SignatureState);
        Assert.NotNull(result.Signer);
        Assert.Contains("Microsoft", result.Signer);
        Assert.Equal("complete", result.CollectionStatus);
        Assert.Empty(result.Errors);
        Assert.Equal(64, result.ExecutableSha256!.Length);
    }

    // A catalog binds a signature to file content, not to a location, so the same bytes outside
    // System32 still verify and one flipped byte stops verifying. The negative half is the one
    // that matters: a file no catalog contains is never invalid and never a fabricated valid.
    // Since PAT-2116 it is "unsigned", and only because every condition of the unsigned rule
    // held: no embedded signature, a SHA-256 catalog lookup that ran and found nothing, no SHA-1
    // catalog either, and a catalog database that answered for System32's own binaries. This is
    // also the on-device check that CryptCATAdminEnumCatalogFromHash really reports a miss as
    // ERROR_NOT_FOUND: if it does not, this reads "unknown" and goes red.
    [WindowsFact]
    public void ModifiedCopyOfACatalogSignedBinaryIsUnsignedWhileTheIntactCopyStaysValid()
    {
        var source = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        Assert.True(File.Exists(source), source);
        var dir = Directory.CreateTempSubdirectory("patched-evidence-").FullName;
        var intact = Path.Combine(dir, "intact.exe");
        var modified = Path.Combine(dir, "modified.exe");
        try
        {
            File.Copy(source, intact);
            var bytes = File.ReadAllBytes(source);
            bytes[bytes.Length / 2] ^= 0xFF;
            File.WriteAllBytes(modified, bytes);

            var verified = WindowsInstallationEvidence.Read(new("fixture", "fixture", "x86_64", dir, intact));
            Assert.Equal("valid", verified.SignatureState);
            Assert.Contains("Microsoft", verified.Signer);
            // PAT-2116: the pinnable publisher comes from the same verified provider chain. A
            // catalog-signed OS binary chains to a Microsoft product root.
            Assert.Equal(64, verified.SignerThumbprint!.Length);
            Assert.Contains("Microsoft", verified.Issuer);
            Assert.Equal(64, verified.RootThumbprint!.Length);
            Assert.Equal("microsoft", verified.RootKind);

            var tampered = WindowsInstallationEvidence.Read(new("fixture", "fixture", "x86_64", dir, modified));
            Assert.Equal("unsigned", tampered.SignatureState);
            Assert.Null(tampered.Signer);
            Assert.Null(tampered.RootKind);
            Assert.Equal("complete", tampered.CollectionStatus);
            Assert.Empty(tampered.Errors);
        }
        finally { File.Delete(intact); File.Delete(modified); Directory.Delete(dir); }
    }

    // The gating half of the above: a well-formed PE this repository built itself, so the
    // "no signature present" branch of WinVerifyTrust is exercised against a subject wintrust
    // can actually parse, unlike the six-byte stub. Nothing here depends on the runner image.
    // Since PAT-1981 it also covers the catalog miss that now follows that branch: no catalog
    // contains this file, and the result has to stay unknown rather than become valid.
    // The assertion that matters is the negative one: an unverified binary is never valid, and
    // the hash is still recorded. Since PAT-2116 a well-formed PE with no embedded signature and
    // a successful catalog miss is "unsigned" (see the unsigned rule on SignatureVerdictLogic).
    [WindowsFact]
    public void UnsignedRealExecutableIsUnsignedRatherThanValid()
    {
        var source = typeof(WindowsInstallationEvidenceTests).Assembly.Location;
        Assert.NotEqual(string.Empty, source);
        var dir = Directory.CreateTempSubdirectory("patched-evidence-").FullName;
        var path = Path.Combine(dir, "fixture.exe");
        try
        {
            File.Copy(source, path);
            var result = WindowsInstallationEvidence.Read(new("fixture", "fixture", "x86_64", dir, path));
            Assert.Equal("complete", result.CollectionStatus);
            Assert.Equal("unsigned", result.SignatureState);
            Assert.Null(result.Signer);
            Assert.Empty(result.Errors);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(source))).ToLowerInvariant(),
                result.ExecutableSha256);
        }
        finally { File.Delete(path); Directory.Delete(dir); }
    }

    [WindowsFact]
    public void ReparseDirectoryCannotBeFollowed()
    {
        var dir = Directory.CreateTempSubdirectory("patched-evidence-").FullName;
        var actual = Path.Combine(dir, "actual");
        var link = Path.Combine(dir, "link");
        Directory.CreateDirectory(actual);
        var path = Path.Combine(actual, "fixture.exe");
        try
        {
            File.WriteAllBytes(path, [77, 90, 1]);
            Directory.CreateSymbolicLink(link, actual);
            var result = WindowsInstallationEvidence.Read(new("fixture", "fixture", "x86_64", link, Path.Combine(link, "fixture.exe")));
            Assert.Equal("unavailable", result.CollectionStatus);
            Assert.Null(result.ExecutableSha256);
        }
        finally { Directory.Delete(link); File.Delete(path); Directory.Delete(actual); Directory.Delete(dir); }
    }

    [WindowsFact]
    public void LockedFileDeniesConcurrentWrites()
    {
        var dir = Directory.CreateTempSubdirectory("patched-evidence-").FullName;
        var path = Path.Combine(dir, "fixture.exe");
        try
        {
            File.WriteAllBytes(path, [77, 90, 1]);
            using var held = WindowsInstallationEvidence.OpenLocalFile(path);
            Assert.Throws<IOException>(() => File.Open(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite));
        }
        finally { File.Delete(path); Directory.Delete(dir); }
    }

    // PAT-2060: with LongPathsEnabled off, the Windows default, CreateFile on a raw path of
    // MAX_PATH or more fails, so an install this deep had no evidence at all. The tree is made
    // through \\?\ so the fixture does not depend on the machine's long-path setting either.
    [WindowsFact]
    public void InstallPathPastMaxPathStillProducesEvidence()
    {
        var (root, dir) = CreateDeepInstallDirectory();
        var path = Path.Combine(dir, "fixture.exe");
        try
        {
            Assert.True(path.Length > 260, $"{path.Length}");
            var bytes = new byte[] { 77, 90, 1, 2, 3, 4 };
            File.WriteAllBytes(@"\\?\" + path, bytes);
            var result = WindowsInstallationEvidence.Read(new("fixture", "fixture", "x86_64", dir, path));
            Assert.Equal("partial", result.CollectionStatus);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), result.ExecutableSha256);
            Assert.Equal(path, result.ExecutablePath);
            Assert.Equal(dir, result.InstallPath);
            Assert.Equal("unknown", result.SignatureState);
        }
        finally { Directory.Delete(@"\\?\" + root, true); }
    }

    // The signature half at depth: the same catalog-signed bytes verify past MAX_PATH exactly as
    // they do at a short path, so a deep install is not reported as unsigned.
    [WindowsFact]
    public void CatalogSignedCopyPastMaxPathStaysValid()
    {
        var source = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        Assert.True(File.Exists(source), source);
        var (root, dir) = CreateDeepInstallDirectory();
        var path = Path.Combine(dir, "intact.exe");
        try
        {
            File.Copy(source, @"\\?\" + path);
            var result = WindowsInstallationEvidence.Read(new("fixture", "fixture", "x86_64", dir, path));
            Assert.Equal("valid", result.SignatureState);
            Assert.Contains("Microsoft", result.Signer);
            Assert.Equal("complete", result.CollectionStatus);
        }
        finally { Directory.Delete(@"\\?\" + root, true); }
    }

    // The prefix must not weaken the walk: a directory link past MAX_PATH is still refused on
    // its own handle, exactly as the short-path reparse tests above require.
    [WindowsFact]
    public void ReparseDirectoryPastMaxPathCannotBeFollowed()
    {
        var (root, dir) = CreateDeepInstallDirectory();
        var actual = Path.Combine(dir, "actual");
        var link = Path.Combine(dir, "link");
        try
        {
            Directory.CreateDirectory(@"\\?\" + actual);
            File.WriteAllBytes(@"\\?\" + Path.Combine(actual, "fixture.exe"), [77, 90, 1]);
            Directory.CreateSymbolicLink(@"\\?\" + link, @"\\?\" + actual);
            var result = WindowsInstallationEvidence.Read(new("fixture", "fixture", "x86_64", link, Path.Combine(link, "fixture.exe")));
            Assert.Equal("unavailable", result.CollectionStatus);
            Assert.Null(result.ExecutableSha256);
        }
        finally
        {
            if (Directory.Exists(@"\\?\" + link)) Directory.Delete(@"\\?\" + link);
            Directory.Delete(@"\\?\" + root, true);
        }
    }

    // A temp root with enough 40-character components under it to pass MAX_PATH while staying
    // inside IsSafePath's 512-character bound.
    private static (string Root, string Dir) CreateDeepInstallDirectory()
    {
        var root = Directory.CreateTempSubdirectory("patched-evidence-").FullName;
        var dir = root;
        while (dir.Length < 300) dir = Path.Combine(dir, new string('d', 40));
        Assert.True(dir.Length < 440, $"{dir.Length}");
        Directory.CreateDirectory(@"\\?\" + dir);
        return (root, dir);
    }

    private const string WindowsOnly = "Requires Windows file sharing, reparse, WinVerifyTrust and catalog APIs.";

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows()) Skip = WindowsOnly;
        }
    }

    private sealed class WindowsTheoryAttribute : TheoryAttribute
    {
        public WindowsTheoryAttribute()
        {
            if (!OperatingSystem.IsWindows()) Skip = WindowsOnly;
        }
    }

    // Opt-in. The caller names a signed .exe on a local fixed drive, so the gating suite never
    // asserts on a binary this repository does not control. xunit reads Skip at discovery, so
    // the variables have to be set before the test process starts.
    private sealed class SignedFixtureFactAttribute : FactAttribute
    {
        internal const string PathVariable = "PATCHED_SIGNED_FIXTURE";
        internal const string SignerVariable = "PATCHED_SIGNED_FIXTURE_SIGNER";

        internal static string? FixturePath =>
            Environment.GetEnvironmentVariable(PathVariable) is { Length: > 0 } path ? path : null;

        public SignedFixtureFactAttribute()
        {
            if (!OperatingSystem.IsWindows()) Skip = "Requires the Windows WinVerifyTrust API.";
            else if (FixturePath is null)
                Skip = $"Opt-in: set {PathVariable} to a signed .exe on a local fixed drive " +
                    $"(and {SignerVariable} to a substring of its expected subject) to exercise Authenticode verification.";
        }
    }
}
