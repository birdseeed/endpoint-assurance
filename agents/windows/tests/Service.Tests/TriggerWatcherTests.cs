using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Patched.Shared.Contract;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// Tests the trigger validator boundary checks directly (the logic extracted from TriggerWatcher).
/// These are platform-neutral and run on macOS CI.
/// Full TriggerWatcher integration (file ACL / drain loop) requires Windows.
/// </summary>
public sealed class TriggerWatcherTests
{
    [Theory]
    [InlineData("abc123.trigger",    true)]
    [InlineData("uuid-style.trigger",true)]
    [InlineData("../evil.trigger",   false)]
    [InlineData("evil\\.trigger",    false)]
    [InlineData("evil\0name.trigger",false)]
    [InlineData("toolong" + "x" + ".trigger", true)]
    [InlineData("no-extension",      false)]
    public void FilenameValidation(string filename, bool expectedValid)
    {
        Assert.Equal(expectedValid, IsValidFilename(filename));
    }

    [Fact]
    public void Trigger_ValidDeploy_PassesValidation()
    {
        var json = """{"labels":["slack"],"requested_by":"bob","requested_at":"2026-12-11T10:00:00Z","source":"tray"}""";
        Assert.True(TriggerRequestValidator.TryValidate(json, json.Length, out _, out _));
    }

    [Fact]
    public void Trigger_Oversized_FailsValidation()
    {
        var json = """{"labels":["slack"]}""";
        Assert.False(TriggerRequestValidator.TryValidate(json, 5000, out _, out _));
    }

    [Fact]
    public void Trigger_EmptyLabels_FailsValidation()
    {
        var json = """{"labels":[]}""";
        Assert.False(TriggerRequestValidator.TryValidate(json, json.Length, out _, out var err));
        Assert.NotNull(err);
    }

    [Fact]
    public void Trigger_LabelWithSlash_FailsValidation()
    {
        var json = """{"labels":["../patched/evil"]}""";
        Assert.False(TriggerRequestValidator.TryValidate(json, json.Length, out _, out _));
    }

    private static bool IsValidFilename(string f)
    {
        if (f.Contains('/') || f.Contains('\\') || f.Contains('\0'))
            return false;
        if (!f.EndsWith(".trigger", StringComparison.OrdinalIgnoreCase))
            return false;
        return f.Length <= 128;
    }

    // --- Full drain-loop integration tests (PAT-906 starvation fix) ---------
    // These exercise TriggerWatcher.DrainTriggers(triggerDir) end to end, via
    // the internal test-directory overload, including the real ACL owner read
    // (the files this process creates are self-owned, so they pass the
    // owner-acceptability check). Windows-only, like the rest of this project.

    private const string LegitTriggerJson =
        """{"labels":["slack"],"requested_by":"bob","requested_at":"2026-12-11T10:00:00Z","source":"tray"}""";

    private static string MakeTempTriggerDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "patched-trigger-watcher-tests-" + Guid.NewGuid());
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void Drain_ValidTriggerSurvivesFloodOfRejectableFiles()
    {
        // A flood of well-formed-but-invalid (self-owned, openable) decoys must
        // not consume the same per-pass allowance that gates a legitimate
        // trigger: TryExamineFile deletes each decoy immediately and none of
        // them ever reach the rate limiter. Sort the decoys ahead of the
        // legitimate trigger by filename so this reproduces the pre-fix
        // ordering that used to exhaust the old fixed examine cap.
        var dir = MakeTempTriggerDir();
        try
        {
            for (var i = 0; i < 500; i++)
                File.WriteAllText(Path.Combine(dir, $"0-decoy-{i:D5}.trigger"), """{"labels":[]}""");
            File.WriteAllText(Path.Combine(dir, "z-legit.trigger"), LegitTriggerJson);

            var watcher = new TriggerWatcher(NullLogger<TriggerWatcher>.Instance);
            var result = watcher.DrainTriggers(dir);

            Assert.Single(result);
            Assert.Equal(["slack"], result[0].Labels);
            // Decoys are rejected-and-deleted inline; the legitimate trigger is
            // consumed too, so nothing should be left in the directory.
            Assert.Empty(Directory.EnumerateFiles(dir, "*.trigger"));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Drain_LockedFileDoesNotBlockValidTriggerInSamePass()
    {
        // The core of the vulnerability: a file TryExamineFile cannot even open
        // (locked by another handle) used to consume an examine-cap slot
        // without being deleted, so enough of them ahead of a legitimate
        // trigger hid it forever. Confirm a single locked decoy no longer
        // prevents the legitimate trigger from being drained in the same pass.
        var dir = MakeTempTriggerDir();
        try
        {
            var lockedPath = Path.Combine(dir, "0-locked.trigger");
            File.WriteAllText(lockedPath, """{"type":"os_defer"}""");
            File.WriteAllText(Path.Combine(dir, "z-legit.trigger"), LegitTriggerJson);

            // Simulate an attacker holding the decoy open. TryExamineFile opens
            // with FileShare.None, which conflicts with ANY concurrently open
            // handle regardless of this handle's own share flags, so this
            // alone is enough to make the decoy unopenable to the service.
            using var lockHandle = new FileStream(lockedPath, FileMode.Open, FileAccess.Read, FileShare.Read);

            var watcher = new TriggerWatcher(NullLogger<TriggerWatcher>.Instance);
            var result = watcher.DrainTriggers(dir);

            Assert.Single(result);
            Assert.Equal(["slack"], result[0].Labels);
            // A single failed open must not delete the file -- it might be a
            // legitimate client mid-write. Only repeated/aged failures quarantine it.
            Assert.True(File.Exists(lockedPath));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Drain_PersistentlyLockedFile_IsQuarantinedAfterRepeatedFailures()
    {
        // A file that stays unopenable across several separate drain passes is
        // not a legitimate in-flight write (File.WriteAllText opens, writes,
        // and closes in one call) -- it is quarantined (force-deleted) so it
        // stops occupying a slot forever. Below the threshold, nothing happens;
        // at the threshold, quarantine fires.
        var dir = MakeTempTriggerDir();
        try
        {
            var lockedPath = Path.Combine(dir, "locked.trigger");
            File.WriteAllText(lockedPath, """{"type":"os_defer"}""");

            // Grant FileShare.Delete so the eventual quarantine delete can
            // succeed while this "attacker" handle is still open, letting the
            // test assert on the resulting log line deterministically rather
            // than on OS/filesystem-version-dependent delete-while-open
            // existence semantics.
            using var lockHandle = new FileStream(
                lockedPath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);

            var logger = new CapturingLogger();
            var now = DateTimeOffset.UtcNow;
            var watcher = new TriggerWatcher(logger, new TriggerRateLimiter(), () => now);

            for (var pass = 0; pass < 4; pass++)
            {
                watcher.DrainTriggers(dir);
                now = now.AddSeconds(1);
            }
            Assert.DoesNotContain(logger.Warnings, w => w.Contains("Quarantining", StringComparison.Ordinal));

            watcher.DrainTriggers(dir); // 5th consecutive failure -- crosses the threshold
            // FileShare.Delete was granted, so the quarantine force-delete
            // succeeds on this pass -- the delete-succeeds branch.
            Assert.Contains(logger.Warnings, w =>
                w.Contains("Quarantining", StringComparison.Ordinal) &&
                w.Contains("force-deleted", StringComparison.Ordinal));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Drain_ValidTriggerBehindMoreLockedDecoysThanOpenBudget_IsStillConsumed()
    {
        // The exact hole the gate blocked: an attacker HOLDS many decoy files
        // open so they can neither be validated nor force-deleted, planted
        // ahead of a legitimate trigger. Once each decoy is quarantined it is
        // skipped WITHOUT an open attempt, so it stops consuming the per-pass
        // open budget -- and a legitimate trigger parked behind MORE decoys
        // than that budget is still consumed within a bounded number of passes.
        // A small injected open budget keeps the test to a handful of files
        // while exercising the >budget path exactly.
        const int budget = 8;
        var decoyCount = budget + 4; // strictly more held-open decoys than the budget
        var dir = MakeTempTriggerDir();
        var handles = new List<FileStream>();
        try
        {
            for (var i = 0; i < decoyCount; i++)
            {
                var p = Path.Combine(dir, $"0-decoy-{i:D3}.trigger");
                File.WriteAllText(p, """{"type":"os_defer"}""");
                // FileShare.Read conflicts with the service's exclusive
                // FileShare.None open (unopenable) and omits FileShare.Delete
                // (so the quarantine force-delete fails and the decoy enters the
                // skip-and-retry Quarantined state rather than being deleted).
                handles.Add(new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.Read));
            }
            File.WriteAllText(Path.Combine(dir, "z-legit.trigger"), LegitTriggerJson);

            var now = DateTimeOffset.UtcNow; // fixed clock -> only the failure-count threshold advances
            var watcher = new TriggerWatcher(
                NullLogger<TriggerWatcher>.Instance, new TriggerRateLimiter(), () => now, maxOpenAttempts: budget);

            IReadOnlyList<TriggerRequest> drained = [];
            for (var pass = 0; pass < 12 && drained.Count == 0; pass++)
                drained = watcher.DrainTriggers(dir);

            Assert.Single(drained);
            Assert.Equal(["slack"], drained[0].Labels);
            // The legitimate trigger was consumed and deleted; the held-open
            // decoys remain (still locked), now quarantined.
            Assert.False(File.Exists(Path.Combine(dir, "z-legit.trigger")));
        }
        finally
        {
            foreach (var h in handles) h.Dispose();
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Drain_QuarantinedFile_IsDeletedOnceHandleReleased()
    {
        // A file driven into the Quarantined state (unopenable AND undeletable
        // while held) must be force-deleted on a later pass the moment the
        // attacker's handle drops -- via the cheap once-per-pass delete retry,
        // with no open attempt.
        var dir = MakeTempTriggerDir();
        try
        {
            var lockedPath = Path.Combine(dir, "0-locked.trigger");
            File.WriteAllText(lockedPath, """{"type":"os_defer"}""");

            var logger = new CapturingLogger();
            var now = DateTimeOffset.UtcNow;
            var watcher = new TriggerWatcher(logger, new TriggerRateLimiter(), () => now);

            // FileShare.Read: unopenable to the service AND no FileShare.Delete,
            // so the quarantine force-delete fails and the file stays present in
            // the Quarantined state.
            var handle = new FileStream(lockedPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                for (var pass = 0; pass < 5; pass++)
                    watcher.DrainTriggers(dir); // 5th failure quarantines; force-delete fails
                Assert.Contains(logger.Warnings, w =>
                    w.Contains("Quarantining", StringComparison.Ordinal) &&
                    w.Contains("could not be force-deleted", StringComparison.Ordinal));
                Assert.True(File.Exists(lockedPath)); // still held open, delete could not succeed
            }
            finally { handle.Dispose(); } // attacker releases the handle

            // Next pass: no open attempt, just the cheap delete retry, which now
            // succeeds because the handle is gone.
            watcher.DrainTriggers(dir);
            Assert.False(File.Exists(lockedPath));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Drain_HundredsOfQuarantinedNames_CostNoOpenBudget_ValidTriggerStillConsumed()
    {
        // The final gate finding: no per-pass constant may be consumable by
        // quarantined names (a fixed walk bound was itself a starvation lever,
        // so it is gone; the walk is O(directory size) by design). This proves
        // bound-independence directly: with an open budget of 16, a valid
        // trigger is still consumed from a directory holding 300
        // already-quarantined held-open decoys. If quarantined skips cost ANY
        // open budget, or tripped any other occupiable bound, the 300 decoys
        // would exhaust it long before the legitimate trigger was reached.
        const int budget = 16;
        const int decoyCount = 300;
        var dir = MakeTempTriggerDir();
        var handles = new List<FileStream>();
        try
        {
            for (var i = 0; i < decoyCount; i++)
            {
                var p = Path.Combine(dir, $"0-decoy-{i:D5}.trigger");
                File.WriteAllText(p, """{"type":"os_defer"}""");
                // Unopenable to the service's exclusive open AND undeletable
                // (no FileShare.Delete), so each decoy ends up Quarantined.
                handles.Add(new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.Read));
            }

            var logger = new CapturingLogger();
            var now = DateTimeOffset.UtcNow;
            var watcher = new TriggerWatcher(
                logger, new TriggerRateLimiter(), () => now, maxOpenAttempts: budget);

            // Drive all 300 decoys into the Quarantined state via the AGE
            // threshold: advance the clock 3 minutes per pass (past the
            // 2-minute quarantine age), so every open attempt makes
            // irreversible progress -- it either starts tracking an untracked
            // decoy or quarantines one first seen on an earlier pass. Each
            // decoy needs exactly two open attempts, so 300 decoys at 16 opens
            // per pass are all quarantined within ceil(600/16) = 38 passes
            // regardless of enumeration order (the code must not, and does
            // not, depend on the order the filesystem returns).
            for (var pass = 0; pass < 40; pass++)
            {
                watcher.DrainTriggers(dir);
                now = now.AddMinutes(3);
            }
            // All decoys quarantined-but-held: reported as ONE aggregate
            // warning per pass (not one line per decoy, which would let an
            // attacker drive log volume).
            Assert.Contains(logger.Warnings, w =>
                w.Contains($"{decoyCount} quarantined trigger file(s) still held open", StringComparison.Ordinal));

            // Plant the legitimate trigger behind all 300 quarantined names and
            // drain once: quarantined skips must cost zero open budget, so this
            // single pass reaches and consumes it.
            var legit = Path.Combine(dir, "z-legit.trigger");
            File.WriteAllText(legit, LegitTriggerJson);

            var drained = watcher.DrainTriggers(dir);

            Assert.Single(drained);
            Assert.Equal(["slack"], drained[0].Labels);
            Assert.False(File.Exists(legit));
            // The held decoys are all still present (still locked), still
            // quarantined, and still only cost a delete retry each.
            Assert.Equal(decoyCount, Directory.EnumerateFiles(dir, "*.trigger").Count());
        }
        finally
        {
            foreach (var h in handles) h.Dispose();
            Directory.Delete(dir, recursive: true);
        }
    }

    // --- CountOsDeferrals (PAT-906) ------------------------------------------
    // TriggerWatcher.CountOsDeferrals used to live on OsUpdateChecker as its own
    // raw scan of the trigger directory. TriggerAcl grants any authenticated
    // user FILE_ADD_FILE on that directory by design (so the tray/Self Service
    // can drop legitimate triggers), so the unvalidated scan let a standard user
    // inflate the deferral count that feeds OsUpdateStateEngine's escalation
    // policy just by dropping arbitrary {"type":"os_defer"} files -- and the
    // first validated version was still starvable, because its per-pass ceiling
    // was consumed before validation and rejected decoys were never deleted.
    // Counting now runs the same hardened walk as the drain; these tests pin
    // both the validation behaviour and the count-specific semantics (a count
    // never consumes a valid file). The owner-reader seam makes the
    // owner-rejection paths deterministic without manipulating real file ACLs.

    private const string ValidUserSid = "S-1-5-21-1004336348-1177238915-682003330-1001"; // normal user
    private const string ForeignSid   = "S-1-1-0"; // Everyone -- rejected by TriggerOwnerPolicy

    private static TriggerFileValidator.OwnerInfo ValidOwner   => new(true, ValidUserSid, "CORP\\alice");
    private static TriggerFileValidator.OwnerInfo ForeignOwner => new(true, ForeignSid, null);

    private static TriggerWatcher MakeCountWatcher(
        Func<string, TriggerFileValidator.OwnerInfo> ownerReader,
        int? maxOpenAttempts = null)
        => new(NullLogger<TriggerWatcher>.Instance, new TriggerRateLimiter(),
               () => DateTimeOffset.UtcNow, maxOpenAttempts: maxOpenAttempts, ownerReader: ownerReader);

    private static string WriteTypedTrigger(string dir, string type = "os_defer")
    {
        var path = Path.Combine(dir, Guid.NewGuid() + ".trigger");
        File.WriteAllText(path, $$"""{"type":"{{type}}","requested_at":"2026-07-14T10:00:00Z"}""");
        return path;
    }

    [Fact]
    public void Count_ForeignOwnedOsDeferTrigger_IsNotCounted_AndDeleted()
    {
        var dir = MakeTempTriggerDir();
        try
        {
            var path = WriteTypedTrigger(dir);
            var count = MakeCountWatcher(_ => ForeignOwner).CountOsDeferrals(dir);
            Assert.Equal(0, count);
            // Invalid files are deleted by the count too -- leaving them behind
            // is how rejected decoys used to consume the ceiling forever.
            Assert.False(File.Exists(path));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Count_LegitimatelyOwnedOsDeferTrigger_IsCounted_AndNotConsumed()
    {
        var dir = MakeTempTriggerDir();
        try
        {
            var path = WriteTypedTrigger(dir);
            var count = MakeCountWatcher(_ => ValidOwner).CountOsDeferrals(dir);
            Assert.Equal(1, count);
            // Counting must never consume: the drain owns deletion of valid
            // triggers, and this file still has to reach HandleOsDeferAsync.
            Assert.True(File.Exists(path));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Count_MixOfForeignAndLegitimateOwners_OnlyCountsLegitimate()
    {
        var dir = MakeTempTriggerDir();
        try
        {
            var legit1  = WriteTypedTrigger(dir);
            var legit2  = WriteTypedTrigger(dir);
            var foreign = WriteTypedTrigger(dir);

            var owners = new Dictionary<string, TriggerFileValidator.OwnerInfo>
            {
                [legit1]  = ValidOwner,
                [legit2]  = ValidOwner,
                [foreign] = ForeignOwner,
            };
            var count = MakeCountWatcher(p => owners[p]).CountOsDeferrals(dir);
            Assert.Equal(2, count);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Count_UnreadableOwner_IsNotCounted()
    {
        var dir = MakeTempTriggerDir();
        try
        {
            WriteTypedTrigger(dir);
            var count = MakeCountWatcher(_ => new TriggerFileValidator.OwnerInfo(false, "", null))
                .CountOsDeferrals(dir);
            Assert.Equal(0, count);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Count_NonOsDeferTrigger_IsNotCounted_AndNotConsumed()
    {
        var dir = MakeTempTriggerDir();
        try
        {
            var path = WriteTypedTrigger(dir, type: "scan");
            var count = MakeCountWatcher(_ => ValidOwner).CountOsDeferrals(dir);
            Assert.Equal(0, count);
            // A valid non-os_defer trigger belongs to the drain: the count must
            // neither count it nor delete it.
            Assert.True(File.Exists(path));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Count_OversizedTrigger_IsRejectedBeforeOwnerRead_NotCounted()
    {
        var dir = MakeTempTriggerDir();
        try
        {
            // A 1 MB os_defer file, well over the size cap. The owner is a
            // legitimate user, so the ONLY thing that can reject it is the size
            // cap. The read is bounded off the open handle (PAT-906), so a
            // planted oversized file is rejected without buffering the whole
            // file or even reaching the owner check.
            var path = Path.Combine(dir, Guid.NewGuid() + ".trigger");
            File.WriteAllText(path, """{"type":"os_defer"}""" + new string(' ', 1024 * 1024));

            var ownerReadPaths = new List<string>();
            var count = MakeCountWatcher(p => { ownerReadPaths.Add(p); return ValidOwner; })
                .CountOsDeferrals(dir);

            Assert.Equal(0, count);
            // The oversized file is rejected during the capped read, BEFORE its
            // owner is read, proving the cap bounds allocation ahead of any
            // owner/schema work -- and it is deleted like any other reject.
            Assert.DoesNotContain(path, ownerReadPaths);
            Assert.False(File.Exists(path));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Count_BomPrefixedOsDeferTrigger_IsCounted()
    {
        var dir = MakeTempTriggerDir();
        try
        {
            // The tray and Self Service write triggers via
            // File.WriteAllText(..., Encoding.UTF8), which prefixes a UTF-8 BOM.
            // The capped read must strip it (as the old StreamReader-based read
            // did) or the JSON parse fails and real deferrals silently stop
            // counting.
            var path = Path.Combine(dir, Guid.NewGuid() + ".trigger");
            File.WriteAllText(path, """{"type":"os_defer"}""",
                new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

            var count = MakeCountWatcher(_ => ValidOwner).CountOsDeferrals(dir);
            Assert.Equal(1, count);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Count_RateLimit_CapsCountPerOwnerWithinSingleCall_WithoutDeleting()
    {
        var dir = MakeTempTriggerDir();
        try
        {
            // Default TriggerRateLimiter caps at 10 per owner per window; drop 15
            // well-formed, legitimately self-owned triggers and confirm only 10
            // are ever counted from a single call -- and that none are deleted
            // (rate-limit excess in a count is simply not counted; the files
            // are valid and still belong to the drain).
            for (var i = 0; i < 15; i++) WriteTypedTrigger(dir);
            var count = MakeCountWatcher(_ => ValidOwner).CountOsDeferrals(dir);
            Assert.Equal(10, count);
            Assert.Equal(15, Directory.EnumerateFiles(dir, "*.trigger").Count());
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Count_FloodOfTriggers_StopsAtPerPassOpenCeiling()
    {
        var dir = MakeTempTriggerDir();
        try
        {
            // Plant more os_defer triggers than the per-pass open ceiling. The
            // enumeration is streamed and must stop at the ceiling, so the
            // owner-reader (invoked once per file that passes the capped read)
            // is called at most ceiling times -- proving a planted flood cannot
            // drive unbounded work (PAT-906). The rate limiter separately caps
            // the returned count, so bounded work is asserted via the owner-read
            // count, not the return value. A small injected ceiling keeps the
            // test to a handful of files.
            const int ceiling = 16;
            for (var i = 0; i < ceiling + 20; i++) WriteTypedTrigger(dir);

            var ownerReads = 0;
            MakeCountWatcher(_ => { ownerReads++; return ValidOwner; }, maxOpenAttempts: ceiling)
                .CountOsDeferrals(dir);

            Assert.True(ownerReads <= ceiling,
                $"owner-reader invoked {ownerReads} times, exceeding the per-pass open ceiling {ceiling}");
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Count_InvalidFloodAheadOfValidOsDefer_ValidCounted_DecoysDoNotSurvive()
    {
        var dir = MakeTempTriggerDir();
        try
        {
            // The gate regression (PAT-906 follow-up): rejected decoys must not
            // permanently consume the per-pass ceiling, and must not survive to
            // the next pass. Plant more foreign-owned decoys than the open
            // ceiling, all sorting before the legitimate trigger's filename.
            // Because each decoy is deleted the moment it is rejected, it never
            // occupies a slot again: the flood drains away across calls, the
            // legitimate trigger is counted, and the directory is left holding
            // only the legitimate trigger.
            const int ceiling = 16;
            const int decoys  = ceiling + 20;
            for (var i = 0; i < decoys; i++)
            {
                var path = Path.Combine(dir, $"0-decoy-{i:D5}.trigger");
                File.WriteAllText(path, """{"type":"os_defer"}""");
            }
            var legit = Path.Combine(dir, "z-legit.trigger");
            File.WriteAllText(legit, """{"type":"os_defer"}""");

            var watcher = MakeCountWatcher(
                p => p == legit ? ValidOwner : ForeignOwner, maxOpenAttempts: ceiling);

            // 36 decoys, 16 deletions per call: the legitimate trigger must be
            // reached and counted within 3 calls (and every earlier call must
            // have deleted every decoy it touched).
            var count = 0;
            for (var call = 0; call < 3 && count == 0; call++)
                count = watcher.CountOsDeferrals(dir);

            Assert.Equal(1, count);
            // Decoys do not survive: only the legitimate (valid, never consumed
            // by a count) trigger remains, left in place for the drain.
            Assert.Equal([legit], Directory.EnumerateFiles(dir, "*.trigger"));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Count_ThenDrain_CountedTriggerIsStillDrained()
    {
        var dir = MakeTempTriggerDir();
        try
        {
            // Counting must not double-consume or pre-charge the drain: the
            // count uses a fresh rate limiter per call (never the drain's
            // rolling per-owner window), so a counted os_defer trigger is still
            // accepted -- not dropped as rate-limit excess -- and consumed when
            // the same watcher instance drains next. Uses the real owner read
            // (the file is self-owned) since both paths must agree on it.
            var path = Path.Combine(dir, Guid.NewGuid() + ".trigger");
            File.WriteAllText(path, """{"type":"os_defer"}""");

            var watcher = new TriggerWatcher(NullLogger<TriggerWatcher>.Instance);

            Assert.Equal(1, watcher.CountOsDeferrals(dir));
            Assert.True(File.Exists(path));

            var drained = watcher.DrainTriggers(dir);
            Assert.Single(drained);
            Assert.True(drained[0].IsOsDefer);
            Assert.False(File.Exists(path));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Count_NoTriggerDirectory_ReturnsZero()
    {
        var dir = Path.Combine(Path.GetTempPath(), "patched-trigger-tests-missing-" + Guid.NewGuid());
        var count = MakeCountWatcher(_ => ValidOwner).CountOsDeferrals(dir);
        Assert.Equal(0, count);
    }

    private sealed class CapturingLogger : ILogger<TriggerWatcher>
    {
        public List<string> Warnings { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel >= LogLevel.Warning)
                Warnings.Add(formatter(state, exception));
        }
    }
}
