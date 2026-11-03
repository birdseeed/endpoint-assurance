using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1066: unit tests for AgentHealthStore — the persisted degraded-capability
/// store backing the agent_health.degraded wire section (go-service/docs/
/// PAYLOAD_SCHEMA.md). Every test points the store at a temp file (via the
/// test-only storePathOverride constructor parameter) so none of this touches the
/// real %ProgramData%\Patched\agent-health.json path.
///
/// The two properties every test here ultimately protects:
///   1. ever_succeeded only ever goes false -> true, and survives a fault
///      resolving and later recurring (acceptance criterion 6).
///   2. A present-but-corrupt store file is NEVER treated as empty and
///      overwritten — RecordFailure/RecordSuccess must no-op (log, don't write),
///      leaving the file byte-for-byte unchanged, and BuildPayloadSection must
///      return null (not an empty/all-clear section) in that state
///      (acceptance criterion 7).
/// </summary>
public sealed class AgentHealthStoreTests
{
    private static string NewStorePath(string tmpDir) => Path.Combine(tmpDir, "agent-health.json");

    private static AgentHealthStore MakeStore(string path) =>
        new(NullLogger<AgentHealthStore>.Instance, path);

    // -------------------------------------------------------------------------
    // First-run / clean-empty behaviour
    // -------------------------------------------------------------------------

    [Fact]
    public void BuildPayloadSection_NoFileYet_ReturnsNonNull_EmptyDegraded()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path  = NewStorePath(tmpDir);
            Assert.False(File.Exists(path));
            var store = MakeStore(path);

            var section = store.BuildPayloadSection();

            Assert.NotNull(section);
            Assert.Empty(section!.Degraded);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void RecordFailure_ThenBuild_ReadsBackCleanly_ReturnsNonNull_NotEmpty()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path  = NewStorePath(tmpDir);
            var store = MakeStore(path);

            store.RecordFailure("capability_missing", "sample_capability", "not_available");

            Assert.True(File.Exists(path));   // atomically written
            var section = store.BuildPayloadSection();
            Assert.NotNull(section);
            var entry = Assert.Single(section!.Degraded);
            Assert.Equal("capability_missing",   entry.Kind);
            Assert.Equal("sample_capability",       entry.Subject);
            Assert.Equal("not_available",        entry.Reason);
            Assert.Equal(1,                      entry.Count);
            Assert.False(entry.EverSucceeded);
            Assert.Equal(entry.FirstSeen, entry.LastSeen);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    // -------------------------------------------------------------------------
    // RecordFailure: repeat calls bump count, preserve first_seen
    // -------------------------------------------------------------------------

    [Fact]
    public void RecordFailure_RepeatedCalls_BumpsCount_PreservesFirstSeen_RefreshesReason()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var store = MakeStore(NewStorePath(tmpDir));

            store.RecordFailure("directive_skipped", "device_removal", "no_device_id");
            var firstSeenAfterFirstCall = store.BuildPayloadSection()!.Degraded[0].FirstSeen;

            store.RecordFailure("directive_skipped", "device_removal", "no_device_id");
            store.RecordFailure("directive_skipped", "device_removal", "still_no_device_id");

            var entry = Assert.Single(store.BuildPayloadSection()!.Degraded);
            Assert.Equal(3, entry.Count);
            Assert.Equal(firstSeenAfterFirstCall, entry.FirstSeen);      // preserved across repeats
            Assert.Equal("still_no_device_id",    entry.Reason);        // refreshed to latest
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    // -------------------------------------------------------------------------
    // RecordSuccess: clears active, sets ledger
    // -------------------------------------------------------------------------

    [Fact]
    public void RecordSuccess_ClearsActiveFault_SetsEverSucceededTrue()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var store = MakeStore(NewStorePath(tmpDir));

            store.RecordFailure("capability_missing", "sample_capability", "not_available");
            Assert.Single(store.BuildPayloadSection()!.Degraded);

            store.RecordSuccess("capability_missing", "sample_capability");

            Assert.Empty(store.BuildPayloadSection()!.Degraded);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void RecordSuccess_WithNoPriorFailure_IsANoOpOnActive_ButStillSetsLedger()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var store = MakeStore(NewStorePath(tmpDir));

            store.RecordSuccess("capability_missing", "sample_capability");
            Assert.Empty(store.BuildPayloadSection()!.Degraded);

            // Now fail once and confirm ever_succeeded is already true from the
            // earlier bare RecordSuccess call, even though there was never an
            // active fault for it to clear.
            store.RecordFailure("capability_missing", "sample_capability", "not_available");
            var entry = Assert.Single(store.BuildPayloadSection()!.Degraded);
            Assert.True(entry.EverSucceeded);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    // -------------------------------------------------------------------------
    // PAT-1269: last_success timestamp ledger — updated on every RecordSuccess,
    // unlike ever_succeeded which only ever moves false -> true once. Backs
    // BootstrapUpdater's periodic self-update check so "has this endpoint
    // checked in lately" is a fact readable from agent-health.json.
    // -------------------------------------------------------------------------

    [Fact]
    public void RecordSuccess_StampsLastSuccess_WithCurrentUtcTime()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var store = MakeStore(NewStorePath(tmpDir));
            var before = DateTimeOffset.UtcNow;

            store.RecordSuccess("self_update", "artifact");

            var lastSuccess = store.GetLastSuccess("self_update", "artifact");
            Assert.NotNull(lastSuccess);
            Assert.InRange(lastSuccess!.Value, before.AddSeconds(-5), DateTimeOffset.UtcNow.AddSeconds(5));
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void RecordSuccess_RepeatedCalls_AdvancesLastSuccessEachTime()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var store = MakeStore(NewStorePath(tmpDir));

            store.RecordSuccess("self_update", "artifact");
            var first = store.GetLastSuccess("self_update", "artifact");
            Thread.Sleep(10);
            store.RecordSuccess("self_update", "artifact");
            var second = store.GetLastSuccess("self_update", "artifact");

            Assert.NotNull(first);
            Assert.NotNull(second);
            Assert.True(second > first, "last_success must advance on every RecordSuccess call, unlike ever_succeeded");
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void GetLastSuccess_NeverRecorded_ReturnsNull()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var store = MakeStore(NewStorePath(tmpDir));

            Assert.Null(store.GetLastSuccess("self_update", "artifact"));
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void GetLastSuccess_DoesNotConflateDifferentKindSubjectPairs()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var store = MakeStore(NewStorePath(tmpDir));

            store.RecordSuccess("self_update", "artifact");

            Assert.NotNull(store.GetLastSuccess("self_update", "artifact"));
            Assert.Null(store.GetLastSuccess("self_update", "apply"));       // different subject
            Assert.Null(store.GetLastSuccess("capability_missing", "artifact")); // different kind
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void CorruptFile_GetLastSuccess_ReturnsNull_DoesNotThrow()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path = NewStorePath(tmpDir);
            File.WriteAllBytes(path, "{{{{not json"u8.ToArray());
            var store = MakeStore(path);

            DateTimeOffset? result = null;
            var ex = Record.Exception(() => result = store.GetLastSuccess("self_update", "artifact"));

            Assert.Null(ex);
            Assert.Null(result);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void TopLevelNullLastSuccess_BuildPayloadSection_ReturnsNull()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path = NewStorePath(tmpDir);
            File.WriteAllBytes(path, Encoding.UTF8.GetBytes("{\"Active\":{},\"EverSucceeded\":{},\"LastSuccess\":null}"));
            var store = MakeStore(path);

            Assert.Null(store.BuildPayloadSection());
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void NestedNullLastSuccess_RecordSuccess_DoesNotThrow_LeavesFileByteForByteUnchanged()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path  = NewStorePath(tmpDir);
            var bytes = Encoding.UTF8.GetBytes("{\"Active\":{},\"EverSucceeded\":{},\"LastSuccess\":{\"k\":null}}");
            File.WriteAllBytes(path, bytes);
            var store = MakeStore(path);

            var ex = Record.Exception(() => store.RecordSuccess("capability_missing", "sample_capability"));

            Assert.Null(ex);
            Assert.Equal(bytes, File.ReadAllBytes(path));
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 6 — resolve-then-recur preserves ever_succeeded=true
    // -------------------------------------------------------------------------

    [Fact]
    public void ResolveThenRecur_PreservesEverSucceededTrue()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var store = MakeStore(NewStorePath(tmpDir));

            // 1. Record failure.
            store.RecordFailure("capability_missing", "sample_capability", "not_available");
            var afterFirstFailure = Assert.Single(store.BuildPayloadSection()!.Degraded);
            Assert.False(afterFirstFailure.EverSucceeded);

            // 2. Record success — clears active, sets ledger true.
            store.RecordSuccess("capability_missing", "sample_capability");
            Assert.Empty(store.BuildPayloadSection()!.Degraded);

            // 3. Record failure again for the SAME (kind, subject).
            store.RecordFailure("capability_missing", "sample_capability", "not_available");

            var entry = Assert.Single(store.BuildPayloadSection()!.Degraded);
            Assert.True(entry.EverSucceeded, "ever_succeeded must remain true, not reset to false, after a resolve-then-recur cycle");
            Assert.Equal(1, entry.Count);   // count restarted for this NEW active occurrence
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    // -------------------------------------------------------------------------
    // Nesting by kind then subject — no collision between different pairs
    // -------------------------------------------------------------------------

    [Fact]
    public void MultipleKindSubjectPairs_AreIndependent()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var store = MakeStore(NewStorePath(tmpDir));

            store.RecordFailure("capability_missing", "sample_capability", "not_available");
            store.RecordFailure("directive_skipped",  "device_removal", "no_device_id");
            store.RecordSuccess("directive_skipped",   "device_removal");   // resolve only the second

            var degraded = store.BuildPayloadSection()!.Degraded;
            var entry = Assert.Single(degraded);
            Assert.Equal("capability_missing", entry.Kind);
            Assert.Equal("sample_capability",     entry.Subject);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 7 — corrupt file never overwritten, never poisons
    // the ledger, BuildPayloadSection returns null (not empty/all-clear)
    // -------------------------------------------------------------------------

    [Fact]
    public void CorruptFile_RecordFailure_DoesNotThrow_LeavesFileByteForByteUnchanged()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path = NewStorePath(tmpDir);
            var garbage = "{ this is not valid json at all -- 8f#$%"u8.ToArray();
            File.WriteAllBytes(path, garbage);

            var store = MakeStore(path);

            var ex = Record.Exception(() => store.RecordFailure("capability_missing", "sample_capability", "not_available"));

            Assert.Null(ex);
            Assert.Equal(garbage, File.ReadAllBytes(path));   // byte-for-byte unchanged — never "fixed"
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void CorruptFile_RecordSuccess_DoesNotThrow_LeavesFileByteForByteUnchanged()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path = NewStorePath(tmpDir);
            var garbage = "not json"u8.ToArray();
            File.WriteAllBytes(path, garbage);

            var store = MakeStore(path);

            var ex = Record.Exception(() => store.RecordSuccess("capability_missing", "sample_capability"));

            Assert.Null(ex);
            Assert.Equal(garbage, File.ReadAllBytes(path));
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void CorruptFile_BuildPayloadSection_ReturnsNull()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path = NewStorePath(tmpDir);
            File.WriteAllBytes(path, "{{{{not json"u8.ToArray());

            var store = MakeStore(path);

            Assert.Null(store.BuildPayloadSection());
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void EmptyFile_IsTreatedAsCorrupt_NotAsFresh()
    {
        // A zero-length file is "present" (File.Exists is true) but fails to
        // deserialize — per the critical invariant, that is corrupt, not fresh.
        // Only a genuinely ABSENT file is "start from empty".
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path = NewStorePath(tmpDir);
            File.WriteAllBytes(path, []);

            var store = MakeStore(path);

            Assert.Null(store.BuildPayloadSection());
            var ex = Record.Exception(() => store.RecordFailure("capability_missing", "sample_capability", "not_available"));
            Assert.Null(ex);
            Assert.Equal(0, new FileInfo(path).Length);   // still empty — not "fixed" into a fresh store
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Fact]
    public void CorruptFile_DoesNotDestroyLedger_OnceRecoverable()
    {
        // Simulates: a healthy store existed, then something corrupted the file
        // on disk (out of this store's control). Recording against the corrupt
        // file must not silently start a fresh store — once a human/ops action
        // restores the good file, the original ledger must still be there.
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path  = NewStorePath(tmpDir);
            var store = MakeStore(path);

            store.RecordFailure("capability_missing", "sample_capability", "not_available");
            store.RecordSuccess("capability_missing", "sample_capability");   // ever_succeeded = true
            var goodBytes = File.ReadAllBytes(path);

            // Corrupt the file out from under the store.
            File.WriteAllBytes(path, "corrupted-bytes"u8.ToArray());

            // Attempts to record against the corrupt file must not write anything.
            store.RecordFailure("capability_missing", "sample_capability", "not_available");
            Assert.Equal("corrupted-bytes"u8.ToArray(), File.ReadAllBytes(path));

            // Restore the good bytes (simulating recovery) and confirm the ledger survived.
            File.WriteAllBytes(path, goodBytes);
            store.RecordFailure("capability_missing", "sample_capability", "not_available");
            var entry = Assert.Single(store.BuildPayloadSection()!.Degraded);
            Assert.True(entry.EverSucceeded);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    // -------------------------------------------------------------------------
    // P1 #1 (non-author review): a top-level `{"Active":null}` (or
    // `{"EverSucceeded":null}`) must NOT be coerced into a fresh empty
    // dictionary — that silently produces a false explicit all-clear on the wire
    // and lets RecordFailure/RecordSuccess overwrite the ever_succeeded ledger.
    // It must be treated exactly like syntactically-invalid JSON: Corrupt.
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("{\"Active\":null,\"EverSucceeded\":{}}")]
    [InlineData("{\"Active\":{},\"EverSucceeded\":null}")]
    public void TopLevelNull_BuildPayloadSection_ReturnsNull(string json)
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path = NewStorePath(tmpDir);
            File.WriteAllBytes(path, Encoding.UTF8.GetBytes(json));
            var store = MakeStore(path);

            Assert.Null(store.BuildPayloadSection());
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Theory]
    [InlineData("{\"Active\":null,\"EverSucceeded\":{}}")]
    [InlineData("{\"Active\":{},\"EverSucceeded\":null}")]
    public void TopLevelNull_RecordFailure_DoesNotThrow_LeavesFileByteForByteUnchanged(string json)
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path  = NewStorePath(tmpDir);
            var bytes = Encoding.UTF8.GetBytes(json);
            File.WriteAllBytes(path, bytes);
            var store = MakeStore(path);

            var ex = Record.Exception(() =>
                store.RecordFailure("capability_missing", "sample_capability", "not_available"));

            Assert.Null(ex);
            Assert.Equal(bytes, File.ReadAllBytes(path));   // never "fixed" into a fresh store
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Theory]
    [InlineData("{\"Active\":null,\"EverSucceeded\":{}}")]
    [InlineData("{\"Active\":{},\"EverSucceeded\":null}")]
    public void TopLevelNull_RecordSuccess_DoesNotThrow_LeavesFileByteForByteUnchanged(string json)
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path  = NewStorePath(tmpDir);
            var bytes = Encoding.UTF8.GetBytes(json);
            File.WriteAllBytes(path, bytes);
            var store = MakeStore(path);

            var ex = Record.Exception(() => store.RecordSuccess("capability_missing", "sample_capability"));

            Assert.Null(ex);
            Assert.Equal(bytes, File.ReadAllBytes(path));
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    // -------------------------------------------------------------------------
    // P1 #2 (non-author review): shapes that deserialize successfully at the top
    // level (Active/EverSucceeded themselves non-null) but contain a null value
    // nested further down — an inner Dictionary<string,ActiveFault>, an
    // ActiveFault itself, or an inner Dictionary<string,bool> — must not reach
    // BuildPayloadSection/RecordFailure/RecordSuccess and throw a
    // NullReferenceException. They must be treated as Corrupt, same as
    // syntactically-invalid JSON, never as a thrown exception.
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("{\"Active\":{\"k\":null},\"EverSucceeded\":{}}")]
    [InlineData("{\"Active\":{\"k\":{\"s\":null}},\"EverSucceeded\":{}}")]
    [InlineData("{\"Active\":{},\"EverSucceeded\":{\"k\":null}}")]
    public void NestedNull_BuildPayloadSection_ReturnsNull_NeverThrows(string json)
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path = NewStorePath(tmpDir);
            File.WriteAllBytes(path, Encoding.UTF8.GetBytes(json));
            var store = MakeStore(path);

            object? section = null;
            var ex = Record.Exception(() => section = store.BuildPayloadSection());

            Assert.Null(ex);
            Assert.Null(section);
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Theory]
    [InlineData("{\"Active\":{\"k\":null},\"EverSucceeded\":{}}")]
    [InlineData("{\"Active\":{\"k\":{\"s\":null}},\"EverSucceeded\":{}}")]
    [InlineData("{\"Active\":{},\"EverSucceeded\":{\"k\":null}}")]
    public void NestedNull_RecordFailure_DoesNotThrow_LeavesFileByteForByteUnchanged(string json)
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path  = NewStorePath(tmpDir);
            var bytes = Encoding.UTF8.GetBytes(json);
            File.WriteAllBytes(path, bytes);
            var store = MakeStore(path);

            var ex = Record.Exception(() =>
                store.RecordFailure("capability_missing", "sample_capability", "not_available"));

            Assert.Null(ex);
            Assert.Equal(bytes, File.ReadAllBytes(path));
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }

    [Theory]
    [InlineData("{\"Active\":{\"k\":null},\"EverSucceeded\":{}}")]
    [InlineData("{\"Active\":{\"k\":{\"s\":null}},\"EverSucceeded\":{}}")]
    [InlineData("{\"Active\":{},\"EverSucceeded\":{\"k\":null}}")]
    public void NestedNull_RecordSuccess_DoesNotThrow_LeavesFileByteForByteUnchanged(string json)
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tmpDir);
        try
        {
            var path  = NewStorePath(tmpDir);
            var bytes = Encoding.UTF8.GetBytes(json);
            File.WriteAllBytes(path, bytes);
            var store = MakeStore(path);

            var ex = Record.Exception(() => store.RecordSuccess("capability_missing", "sample_capability"));

            Assert.Null(ex);
            Assert.Equal(bytes, File.ReadAllBytes(path));
        }
        finally { Directory.Delete(tmpDir, recursive: true); }
    }
}
