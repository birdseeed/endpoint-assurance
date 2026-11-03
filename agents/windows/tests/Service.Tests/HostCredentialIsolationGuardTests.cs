using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Patched.Shared.Auth;
using Patched.Shared.Paths;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1763 (credentials), widened by PAT-1774 (every other %ProgramData%\Patched
/// writer): no Service test may write the running user's Windows Credential
/// Manager or %ProgramData%\Patched. These guards hold that line two ways.
///
///   1. Behaviour: every CredentialStore a test can build
///      (<see cref="CredentialStore.CreateForTests"/>, <see cref="CredentialStore.ForTesting"/>)
///      stores enrolment credentials in an <see cref="InMemoryAgentCredentialWriter"/>
///      and keeps its suspended marker outside %ProgramData%.
///   2. Source: no compiled Service test calls the production constructors of
///      AgentEnroller, AgentConfigFetcher, TriggerAcl, DecommissionHandoff or
///      PendingUpdateRestartScheduler (which all default to %ProgramData%\Patched
///      paths), or the CredentialStore factories and helpers that reach host
///      credential storage.
///
/// This is a source-pattern guard, not a runtime one: it catches a test that
/// constructs one of these types with the wrong argument count, but not every
/// possible way source could reach a production path (an alias, a helper that
/// wraps the constructor, a reflection call). A hash-of-the-real-tree
/// before/after hook would catch any writer regardless of how it got there, and
/// is the acceptance criterion's own preferred shape (PAT-1774 brief) — not
/// implemented here because xUnit has no built-in assembly-wide fixture without
/// adding a new package dependency or retrofitting a `[Collection]` attribute
/// onto every existing Service.Tests class, and it is unverifiable from a
/// non-Windows session (no real %ProgramData%\Patched exists to hash). Left as a
/// follow-up for a session that can verify it on Windows.
/// </summary>
public sealed class HostCredentialIsolationGuardTests
{
    private static readonly string ProgramDataPatched = Path.GetFullPath(PathConstants.StateDir);

    private static bool IsUnderProgramDataPatched(string path)
    {
        string full = Path.GetFullPath(path);
        return full.StartsWith(ProgramDataPatched.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
                   StringComparison.OrdinalIgnoreCase)
               || string.Equals(full, ProgramDataPatched, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateForTests_StoresEnrolmentCredentialsInMemory_NotInTheHostCredentialManager()
    {
        string suspended = Path.Combine(Path.GetTempPath(), $"patched-guard-{Guid.NewGuid():N}", "suspended");
        var writer = new InMemoryAgentCredentialWriter();
        var creds = CredentialStore.CreateForTests(suspended, bearerToken: "", credentialWriter: writer);

        Assert.False(creds.WritesHostCredentialStorage);
        Assert.False(CredentialStore.CreateForTests(suspended).WritesHostCredentialStorage);

        // On a non-Windows host a Credential Manager write would throw
        // DllNotFoundException; on Windows it would land in the real store. The
        // writer check above covers Windows; this covers the call path.
        creds.UpdateFromEnrolment("tenant-x", "bearer-x", "c2VjcmV0");

        Assert.Equal("tenant-x", writer.Written[CredentialStore.TargetTenantId]);
        Assert.Equal("bearer-x", writer.Written[CredentialStore.TargetBearerToken]);
        Assert.Equal("c2VjcmV0", writer.Written[CredentialStore.TargetHmacSecret]);
        Assert.Equal(1, writer.EnrollmentTokenDiscards);
        Assert.Equal("tenant-x", creds.TenantId);
    }

    [Fact]
    public void ForTesting_IsFullyOffTheHost()
    {
        var creds = CredentialStore.ForTesting("tenant-y", "bearer-y", "c2VjcmV0");

        Assert.False(creds.WritesHostCredentialStorage);
        Assert.False(IsUnderProgramDataPatched(creds.SuspendedMarkerPath),
            $"ForTesting's suspended marker must not be under {ProgramDataPatched}: {creds.SuspendedMarkerPath}");
        Assert.StartsWith(Path.GetFullPath(Path.GetTempPath()), Path.GetFullPath(creds.SuspendedMarkerPath));
        Assert.NotEqual(creds.SuspendedMarkerPath, CredentialStore.ForTesting("t", "b", "s").SuspendedMarkerPath);

        creds.UpdateFromEnrolment("tenant-z", "bearer-z", "c2VjcmV0");
        Assert.Equal("tenant-z", creds.TenantId);

        // A store with no usable pair re-reads its enrolment-token source. For
        // ForTesting that source is empty, never Credential Manager, the file
        // store or HKLM (which would throw DllNotFoundException off Windows).
        var pending = CredentialStore.ForTesting("", "", "");
        Assert.False(pending.RefreshEnrollmentToken());
        Assert.Null(pending.EnrollmentToken);
    }

    [Fact]
    public void ForTesting_SuspendedMarkerRoundTrip_StaysUnderTemp()
    {
        var creds = CredentialStore.ForTesting("tenant-y", "bearer-y", "c2VjcmV0");
        try
        {
            Assert.False(creds.IsSuspended);
            creds.MarkSuspended();
            Assert.True(creds.IsSuspended);
            Assert.True(File.Exists(creds.SuspendedMarkerPath));
            creds.ClearSuspended();
            Assert.False(creds.IsSuspended);
        }
        finally
        {
            try { Directory.Delete(Path.GetDirectoryName(creds.SuspendedMarkerPath)!, recursive: true); } catch { /* best effort */ }
        }
    }

    // ---------------------------------------------------------------------
    // Source guard
    // ---------------------------------------------------------------------

    /// <summary>
    /// Constructors whose short overloads bind %ProgramData%\Patched paths. A test
    /// must use the overload that takes scratch paths, so the argument count is
    /// pinned exactly: a miscount fails the guard rather than passing it.
    ///
    /// PAT-1774: widened beyond the original PAT-1763 credential-writer seam
    /// (AgentEnroller/AgentConfigFetcher) to every other class in Service that
    /// writes under %ProgramData%\Patched and now carries the identical
    /// production-ctor-delegates-to-internal-scratch-ctor seam: TriggerAcl (the
    /// trigger directory + its DACL), DecommissionHandoff (the decommission
    /// staging directory, the removal script, and the report-creds snapshot) and
    /// PendingUpdateRestartScheduler (the self-update restart staging directory,
    /// script and task XML). A test that constructs one of these with its short,
    /// production-path constructor is exactly as unsafe as constructing
    /// AgentEnroller/AgentConfigFetcher that way — see each class's own PAT-1774
    /// doc comment.
    /// </summary>
    private static readonly (string Type, int[] AllowedArgumentCounts)[] ScratchPathConstructors =
    {
        // 4: scratch floor path; 5: the same plus the PAT-1765 backoff clock.
        ("AgentEnroller", new[] { 4, 5 }),
        ("AgentConfigFetcher", new[] { 5, 6 }),
        // 2: log + scratch trigger directory (production ctor takes only log).
        ("TriggerAcl", new[] { 2 }),
        // 6: log, creds + 4 scratch paths (production ctor takes only log, creds).
        ("DecommissionHandoff", new[] { 6 }),
        // 5: log + 4 scratch paths (production ctor takes only log).
        ("PendingUpdateRestartScheduler", new[] { 5 }),
    };

    /// <summary>Calls that reach host credential storage directly.</summary>
    private static readonly string[] ForbiddenCalls =
    {
        "CredentialStore.Load(",
        "CredentialStore.LoadForStartup(",
        "CredentialStore.Write(",
        "CredentialStore.ReadGenericCredential(",
        "CredentialStore.DeleteCredentialReporting",
        "CredentialStore.DeleteRegistryProvisioningKeyReporting",
        "CredentialStore.DeleteRegistryEnrollmentTokenValue",
        "CredentialStore.RegistryEnrollmentTokenPresent",
        "CredentialStore.CreateFileStorePurge(",
        // PAT-1755: the production provisioner writes %ProgramData%\Patched\creds and
        // repairs that directory's DACL; a test must inject its own seams instead.
        "CredentialStore.CreateEnrollmentTokenProvisioner(",
        "CredentialStore.DeleteCredsFileEnrollmentToken",
        "CredentialStore.IgnoredEnrollmentTokenPresent",
        "CredentialStore.DeleteIgnoredEnrollmentToken",
        "EnrollmentTokenProvisionCommand.RunProduction",
        "StartupSources.Real",
    };

    private static string ThisSourceFile([CallerFilePath] string path = "") => path;

    private static IReadOnlyList<string> CompiledTestSources()
    {
        string thisFile = ThisSourceFile();
        string dir = Path.GetDirectoryName(thisFile)!;
        Assert.True(Directory.Exists(dir), $"test sources not found at {dir}; this guard must run from a source checkout");
        string csproj = Path.Combine(dir, "Service.Tests.csproj");
        Assert.True(File.Exists(csproj), $"{csproj} not found");

        var removed = Regex.Matches(File.ReadAllText(csproj), "<Compile\\s+Remove=\"([^\"]+)\"")
            .Select(m => Path.GetFullPath(Path.Combine(dir, m.Groups[1].Value)))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return Directory.EnumerateFiles(dir, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                          .Any(part => part is "bin" or "obj"))
            .Where(f => !removed.Contains(Path.GetFullPath(f)))
            .Where(f => !string.Equals(Path.GetFullPath(f), Path.GetFullPath(thisFile), StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    [Fact]
    public void GuardSeesTheTestSources()
    {
        var sources = CompiledTestSources().Select(Path.GetFileName).ToList();
        Assert.Contains("AgentEnrollerRecoveryTests.cs", sources);
        Assert.Contains("AgentConfigRollbackFloorTests.cs", sources);
        Assert.DoesNotContain("InventoryCollectorTests.cs", sources); // Compile Remove in the csproj
    }

    [Fact]
    public void NoServiceTestConstructsAnEnrollerOrFetcherWithProductionPaths()
    {
        var violations = new List<string>();
        foreach (string file in CompiledTestSources())
        {
            string text = File.ReadAllText(file);
            foreach (var (type, allowed) in ScratchPathConstructors)
            {
                var shapes = new[]
                {
                    new Regex($@"\bnew\s+{type}\s*\("),
                    new Regex($@"\b{type}\??\s+\w+\s*\([^;{{}}]*?\)\s*=>\s*new\s*\(", RegexOptions.Singleline),
                    new Regex($@"\b{type}\??\s+\w+\s*=\s*new\s*\("),
                };
                foreach (var shape in shapes)
                {
                    foreach (Match m in shape.Matches(text))
                    {
                        int open = m.Index + m.Length - 1;
                        int count = CountArguments(text, open);
                        if (!allowed.Contains(count))
                        {
                            int line = text.Take(m.Index).Count(c => c == '\n') + 1;
                            violations.Add($"{Path.GetFileName(file)}:{line}: {type} constructed with {count} arguments (allowed: {string.Join(" or ", allowed)})");
                        }
                    }
                }
            }
        }
        Assert.True(violations.Count == 0, string.Join(Environment.NewLine, violations));
    }

    [Fact]
    public void NoServiceTestCallsHostCredentialStorage()
    {
        var violations = new List<string>();
        foreach (string file in CompiledTestSources())
        {
            string text = File.ReadAllText(file);
            foreach (string call in ForbiddenCalls)
            {
                int at = text.IndexOf(call, StringComparison.Ordinal);
                if (at >= 0)
                    violations.Add($"{Path.GetFileName(file)}:{text.Take(at).Count(c => c == '\n') + 1}: {call}");
            }
        }
        Assert.True(violations.Count == 0, string.Join(Environment.NewLine, violations));
    }

    [Theory]
    [InlineData("new AgentEnroller(a, b, c)", 3)]
    [InlineData("new AgentEnroller(a, b(1, 2), \"x, y\", (t, _, _) => t.Add(\"a,b\"))", 4)]
    [InlineData("new AgentEnroller(\n  a,\n  new[] { 1, 2 },\n  @\"c:\\x, y\",\n  'x')", 4)]
    [InlineData("new AgentEnroller()", 0)]
    public void CountArguments_HandlesNestingAndLiterals(string source, int expected)
    {
        Assert.Equal(expected, CountArguments(source, source.IndexOf('(')));
    }

    /// <summary>
    /// Counts the top-level arguments of the argument list opening at
    /// <paramref name="open"/>, skipping nested brackets and string/char literals.
    /// </summary>
    private static int CountArguments(string text, int open)
    {
        int depth = 0, commas = 0;
        bool sawContent = false;
        for (int i = open; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '"' || c == '\'')
            {
                bool verbatim = c == '"' && i > 0 && (text[i - 1] == '@' || (i > 1 && text[i - 1] == '$' && text[i - 2] == '@'));
                i = SkipLiteral(text, i, verbatim);
                sawContent = true;
                continue;
            }
            switch (c)
            {
                case '(' or '[' or '{':
                    depth++;
                    if (depth > 1) sawContent = true;
                    break;
                case ')' or ']' or '}':
                    depth--;
                    if (depth == 0)
                        return sawContent ? commas + 1 : 0;
                    break;
                case ',' when depth == 1:
                    commas++;
                    break;
                default:
                    if (depth == 1 && !char.IsWhiteSpace(c)) sawContent = true;
                    break;
            }
        }
        return -1;
    }

    private static int SkipLiteral(string text, int start, bool verbatim)
    {
        char quote = text[start];
        for (int i = start + 1; i < text.Length; i++)
        {
            if (verbatim && text[i] == '"' && i + 1 < text.Length && text[i + 1] == '"') { i++; continue; }
            if (!verbatim && text[i] == '\\') { i++; continue; }
            if (text[i] == quote) return i;
        }
        return text.Length;
    }
}
