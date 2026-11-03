using System.Text.RegularExpressions;
using System.Xml.Linq;
using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1293 (round 2, non-author review). Pure content assertions on the generated
/// Task Scheduler XML task definition — the format this ticket moved to specifically
/// BECAUSE the original command-line design (<c>/SC ONCE /ST /SD</c>) parsed
/// <c>/SD</c> against the SYSTEM's own regional short-date order and silently
/// failed to register on any non-US-date-order locale, en-GB included (see
/// <see cref="PendingUpdateRestartTaskXml"/>'s class doc comment for the full
/// story). Cannot exercise the XML AGAINST a real Task Scheduler from this (or any)
/// CI host — see PendingUpdateRestartSchedulerTests for that caveat and the
/// Windows-VM verification this ticket's report describes instead. This proves the
/// generator emits the right document shape, not that schtasks.exe actually accepts
/// it (the VM run is what proves that).
/// </summary>
public class PendingUpdateRestartTaskXmlTests
{
    private const string TaskName   = "PatchedAgentSelfUpdateRestart";
    private const string ScriptPath = @"C:\ProgramData\Patched\self-update-restart\restart-agent.ps1";

    private static string BuildXml(
        string taskName = TaskName, string scriptPath = ScriptPath, DateTime? now = null) =>
        PendingUpdateRestartTaskXml.Build(taskName, scriptPath, now ?? new DateTime(2026, 8, 13, 10, 0, 0));

    // -------------------------------------------------------------------------
    // Baseline: the document is well-formed XML, and declares the encoding it
    // is actually written with (Encoding.Unicode / UTF-16, at the
    // PendingUpdateRestartScheduler call site) — a mismatch is grounds for a
    // parser to reject the file outright.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_ProducesWellFormedXml()
    {
        string xml = BuildXml();
        var doc = XDocument.Parse(xml); // throws on malformed input
        Assert.Equal("Task", doc.Root!.Name.LocalName);
    }

    [Fact]
    public void Build_DeclaresUtf16Encoding()
    {
        string xml = BuildXml();
        Assert.StartsWith("<?xml version=\"1.0\" encoding=\"UTF-16\"?>", xml);
    }

    [Fact]
    public void Build_UsesTheMitTaskSchedulerNamespace()
    {
        string xml = BuildXml();
        var doc = XDocument.Parse(xml);
        Assert.Equal("http://schemas.microsoft.com/windows/2004/02/mit/task", doc.Root!.Name.NamespaceName);
    }

    // -------------------------------------------------------------------------
    // The core of the round-2 fix: <StartBoundary> is ISO-8601, computed from
    // the same "now + RestartDelay" instant the original /ST-/SD design used —
    // only the OUTPUT format changed, not the underlying time math, so these
    // mirror the midnight-rollover tests the earlier command-line design had.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_StartBoundaryIsExactlyNowPlusRestartDelay()
    {
        string xml = BuildXml(now: new DateTime(2026, 8, 13, 10, 0, 0));
        Assert.Contains("<StartBoundary>2026-08-13T10:05:00</StartBoundary>", xml);
    }

    [Fact]
    public void Build_MidnightRollover_FiveMinutesPast2357_IsTomorrowsDate()
    {
        // The exact boundary named in the PAT-1293 brief: a bare /ST close to
        // midnight, without an accompanying /SD, would have resolved against
        // TODAY's date under the original design. <StartBoundary> is a single
        // combined ISO-8601 value, so there is no equivalent "date left
        // implicit" failure mode — but the underlying instant must still land
        // on the correct calendar day.
        string xml = BuildXml(now: new DateTime(2026, 8, 13, 23, 57, 0));

        Assert.Contains("<StartBoundary>2026-08-14T00:02:00</StartBoundary>", xml);
        Assert.DoesNotContain("2026-08-13T00:02", xml);
    }

    [Fact]
    public void Build_MidnightRollover_ExactlyAtMidnightDelayWindow_StillRolls()
    {
        // now = 23:55:00 exactly, so now + 5 minutes lands EXACTLY on midnight —
        // the very first instant of the next day, not "close to" it. Also
        // crosses a month/year boundary ( is not a leap year).
        string xml = BuildXml(now: new DateTime(2026, 8, 28, 23, 55, 0));
        Assert.Contains("<StartBoundary>2026-09-01T00:00:00</StartBoundary>", xml);
    }

    [Fact]
    public void Build_NonRolloverCase_SameCalendarDay()
    {
        string xml = BuildXml(now: new DateTime(2026, 8, 13, 12, 30, 0));
        Assert.Contains("<StartBoundary>2026-08-13T12:35:00</StartBoundary>", xml);
    }

    // -------------------------------------------------------------------------
    // THE regression proof: <StartBoundary> must be ISO-8601 and must NEVER
    // contain a locale-ordered date (slash-separated day/month or month/day).
    // This is guarding a LOCALE ASSUMPTION, not just a string format — the bug
    // this whole file exists to prevent was schtasks silently misreading a
    // slash-separated date on an en-GB host, so a test that only checked "is
    // there a StartBoundary element" would not have caught it. This one would.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_StartBoundary_IsIso8601_ContainsNoLocaleOrderedDate()
    {
        string xml = BuildXml();
        var doc = XDocument.Parse(xml);
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        string startBoundary = doc.Descendants(ns + "StartBoundary").Single().Value;

        // Strict ISO-8601 "yyyy-MM-ddTHH:mm:ss" — the exact shape the Task
        // Scheduler XML schema requires, locale-independent by specification.
        Assert.Matches(new Regex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$"), startBoundary);

        // Never a slash: a slash-separated date is exactly the locale-ordered
        // shape (MM/dd/yyyy vs dd/MM/yyyy) that broke registration on en-GB in
        // the design this replaces.
        Assert.DoesNotContain("/", startBoundary);
    }

    // -------------------------------------------------------------------------
    // Principal: the SID, not the localised display name "SYSTEM" — same class
    // of locale bug as the date, fixed the same way from the start.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_PrincipalUsesLocalSystemSid_NotTheLocalisedDisplayName()
    {
        string xml = BuildXml();

        Assert.Contains($"<UserId>{PendingUpdateRestartTaskXml.LocalSystemSid}</UserId>", xml);
        Assert.Equal("S-1-5-18", PendingUpdateRestartTaskXml.LocalSystemSid);
        Assert.DoesNotContain("<UserId>SYSTEM</UserId>", xml);
    }

    [Fact]
    public void Build_PrincipalHasHighestAvailableRunLevel_AndOmitsLogonType()
    {
        // "ServiceAccount" is a legal <LogonType> value per the published Task
        // Scheduler XSD and was the first thing tried here, but a real
        // schtasks.exe rejected it outright ("The task XML contains a value
        // which is incorrectly formatted or out of range" — verified on the
        // Windows staging VM, see the PAT-1293 report). Omitting <LogonType>
        // entirely was verified to register successfully instead, and matches
        // the shape Task Scheduler's own /Query /XML export produces for
        // built-in-account tasks — so its ABSENCE here is a deliberate,
        // evidence-based choice, not an oversight, and is worth guarding
        // against a well-intentioned "helpful" re-addition.
        string xml = BuildXml();

        Assert.Contains("<RunLevel>HighestAvailable</RunLevel>", xml);
        Assert.DoesNotContain("<LogonType>", xml);
    }

    // -------------------------------------------------------------------------
    // Idempotent re-registration policy and battery settings (round-2 review):
    // the DEFAULTS for DisallowStartIfOnBatteries/StopIfGoingOnBatteries are
    // both `true`, which would silently prevent this task from ever firing on
    // an unplugged laptop — a normal state for the endpoints this ships to.
    // Set explicitly to false so the intent is visible, not implied by omission.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_MultipleInstancesPolicyIsIgnoreNew()
    {
        string xml = BuildXml();
        Assert.Contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>", xml);
    }

    [Fact]
    public void Build_NeverBlockedByBatteryState_AndRunsWhenMissed()
    {
        string xml = BuildXml();

        Assert.Contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>", xml);
        Assert.Contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>", xml);
        // A machine asleep/off at the fire time should still run the task once
        // available, rather than silently dropping the one-shot trigger.
        Assert.Contains("<StartWhenAvailable>true</StartWhenAvailable>", xml);
    }

    [Fact]
    public void Build_HasABoundedExecutionTimeLimit()
    {
        string xml = BuildXml();
        Assert.Contains("<ExecutionTimeLimit>PT10M</ExecutionTimeLimit>", xml);
    }

    // -------------------------------------------------------------------------
    // The action: powershell.exe invoked with the same flags/shape the original
    // /TR string used, now as separate <Command>/<Arguments> elements.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_ActionInvokesPowerShellWithTheScriptPath()
    {
        string xml = BuildXml();

        Assert.Contains("<Command>powershell.exe</Command>", xml);
        Assert.Contains(
            $"<Arguments>-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{ScriptPath}\"</Arguments>",
            xml);
    }

    // -------------------------------------------------------------------------
    // XML escaping: XElement handles this automatically (the whole point of
    // building via System.Xml.Linq rather than hand-rolled string
    // interpolation — see the class doc comment), but it must actually happen,
    // not merely be assumed. A task name or script path containing XML special
    // characters must still round-trip through Parse without throwing, and the
    // parsed value must equal the original unescaped string.
    // -------------------------------------------------------------------------
    [Fact]
    public void Build_EscapesXmlSpecialCharactersInTaskName()
    {
        const string taskName = "Patched & <Restart> \"Task\"";
        string xml = BuildXml(taskName: taskName);

        var doc = XDocument.Parse(xml); // throws if not well-formed
        string description = doc.Descendants().First(e => e.Name.LocalName == "Description").Value;
        Assert.Contains(taskName, description); // round-trips to the original, unescaped value
        // The raw XML text must not contain a literal unescaped '&' or '<' from
        // the task name (would make the document malformed) — proven indirectly
        // above by Parse not throwing, and directly here by confirming the
        // escaped forms are present in the raw text.
        Assert.Contains("&amp;", xml);
        Assert.Contains("&lt;Restart&gt;", xml);
    }

    [Fact]
    public void Build_EscapesXmlSpecialCharactersInScriptPath()
    {
        const string scriptPath = @"C:\Program Files\Patched & Co\restart-agent.ps1";
        string xml = BuildXml(scriptPath: scriptPath);

        var doc = XDocument.Parse(xml);
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        string arguments = doc.Descendants(ns + "Arguments").Single().Value;
        Assert.Contains(scriptPath, arguments); // round-trips to the original path
        Assert.Contains("&amp;", xml);
    }

    [Fact]
    public void Build_RestartDelayAppliesRegardlessOfWhichConstantIsRead()
    {
        // Regression guard: PendingUpdateRestartTaskXml.Build reads
        // PendingUpdateRestartScheduler.RestartDelay directly rather than a
        // second, possibly-drifting copy of "5 minutes".
        var now = new DateTime(2026, 8, 13, 10, 0, 0);
        string xml = BuildXml(now: now);
        string expectedStartBoundary = (now + PendingUpdateRestartScheduler.RestartDelay)
            .ToString("yyyy-MM-ddTHH:mm:ss");

        Assert.Contains($"<StartBoundary>{expectedStartBoundary}</StartBoundary>", xml);
    }
}
