using System.Globalization;
using System.Xml.Linq;

namespace Patched.Service;

/// <summary>
/// PAT-1293 (fixed in non-author review round 2): builds the Task Scheduler XML
/// task definition for the self-update restart task, registered via
/// <c>schtasks /Create /TN "&lt;name&gt;" /XML "&lt;path&gt;" /F</c>.
///
/// This replaces an EARLIER version of this class that passed
/// <c>/SC ONCE /ST &lt;time&gt; /SD &lt;date&gt;</c> directly on the schtasks.exe
/// command line. That was a real bug, not a style preference: schtasks.exe parses
/// <c>/SD</c> using the SYSTEM's own regional short-date order, not a fixed one.
/// <see cref="CultureInfo.InvariantCulture"/> on OUR side only pins what THIS CODE
/// emits — it says nothing about what schtasks on the TARGET machine expects to
/// receive. On an en-GB endpoint (Patched is a UK company; en-GB is the common
/// case among our own endpoints, not an edge case) a date like "08/13/2026" is
/// read as day=08, month=13 — not a valid month — and <c>/Create</c> fails
/// outright. Because registration is deliberately fail-safe (see
/// <see cref="PendingUpdateRestartScheduler"/>), that failure was silent from the
/// product's point of view except for the AgentHealthStore degraded signal: the
/// task would never register, and the self-update rail would stop at exactly the
/// wall this ticket exists to remove — one layer further out, specifically on the
/// locale this company ships to most. That is the PAT-1261/PAT-1269/PAT-1293
/// "correct code, never invoked" pattern recurring a fourth time, so the fix
/// removes the dependency instead of documenting around it.
///
/// The Task Scheduler XML schema's &lt;StartBoundary&gt; is ISO-8601
/// ("yyyy-MM-ddTHH:mm:ss") BY SPECIFICATION — unlike <c>/SD</c> on the command
/// line, this is not a convention this codebase is choosing to assume; it is the
/// documented wire format Task Scheduler itself parses, independent of the
/// machine's regional settings. schtasks.exe still does the actual registration,
/// so the <see cref="DecommissionHandoff"/> precedent — schtasks.exe as the
/// mechanism, with its English STDOUT/STDERR parsed for classification — still
/// holds; only the INPUT format changed, from locale-dependent command-line
/// arguments to a locale-independent XML document. Parsing schtasks' own English
/// output is a heuristic that degrades to a logged "unknown" on a non-English
/// host; passing it a locale-ordered date was an input format that hard-FAILED
/// registration outright on a whole locale. Those are different bets, and the
/// existing English-output precedent is not cover for the latter.
///
/// Pure string generation, exactly like <see cref="PendingUpdateRestartScript"/>
/// — no OS gate, no real file or process I/O — so the exact XML shape (including
/// the &lt;StartBoundary&gt; time math and its midnight-rollover case) is directly
/// unit testable on any host. Built with <see cref="System.Xml.Linq.XElement"/>
/// rather than hand-rolled string interpolation specifically so element/attribute
/// escaping (task name, script path) is handled by the framework, not by a
/// second manual `.Replace` call this class would otherwise need to get right —
/// the whole point of this file is removing a hand-rolled formatting assumption
/// that turned out to be wrong, not adding another one.
/// </summary>
public static class PendingUpdateRestartTaskXml
{
    /// <summary>
    /// Well-known SID for the LocalSystem account (S-1-5-18), used in
    /// &lt;UserId&gt; instead of the literal string "SYSTEM". The display name
    /// "SYSTEM" is itself localised on non-English Windows (it is a
    /// translated account name, not a fixed identifier) — using the SID is the
    /// XML-schema equivalent of the exact class of bug this file exists to fix
    /// for &lt;StartBoundary&gt;, just for the account identity instead of the
    /// date, so it is pinned the same way from the start rather than waiting to
    /// be found the same way the date bug was.
    /// </summary>
    internal const string LocalSystemSid = "S-1-5-18";

    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    /// <summary>
    /// Builds the task definition XML. <paramref name="now"/> plus
    /// <see cref="PendingUpdateRestartScheduler.RestartDelay"/> gives the fire
    /// time embedded as &lt;StartBoundary&gt;; the midnight-rollover behaviour
    /// (5 minutes past 23:57 lands on tomorrow's date) falls out of ordinary
    /// <see cref="DateTime"/> arithmetic the same way it did for the original
    /// /ST-/SD design — only the OUTPUT format changed, not the underlying time
    /// math, which is why the midnight-rollover tests carry over essentially
    /// unchanged (see PendingUpdateRestartTaskXmlTests).
    /// </summary>
    public static string Build(string taskName, string scriptPath, DateTime now)
    {
        DateTime fireAt = now + PendingUpdateRestartScheduler.RestartDelay;

        // ISO-8601, no timezone designator: Task Scheduler interprets a
        // designator-less <StartBoundary> as LOCAL time on the machine that
        // runs the task, which is exactly what we want — "now" and RestartDelay
        // are both already in the machine's own local time (DateTime.Now, not
        // UtcNow), matching schtasks.exe's own /ST-/SD local-time semantics
        // from the design this replaces.
        string startBoundary = fireAt.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture);

        string arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{scriptPath}\"";

        var task = new XElement(Ns + "Task",
            new XAttribute("version", "1.4"),
            new XElement(Ns + "RegistrationInfo",
                new XElement(Ns + "Description",
                    $"{taskName} (PAT-1293): one-shot bounce of the Patched Agent service so a " +
                    "staged self-update can apply.")),
            new XElement(Ns + "Triggers",
                new XElement(Ns + "TimeTrigger",
                    new XElement(Ns + "StartBoundary", startBoundary),
                    new XElement(Ns + "Enabled", "true"))),
            // Principal in the XML, not on the command line (round-2 review):
            // LocalSystemSid rather than the localised display name "SYSTEM",
            // HighestAvailable run level (equivalent to the original design's
            // /RL HIGHEST). Deliberately NO <LogonType> element. "ServiceAccount"
            // is a legal value per the published Task Scheduler XSD, and was the
            // first thing tried here — but verified live against a real
            // schtasks.exe (Windows staging VM, PAT-1293 report): it is rejected
            // outright with "The task XML contains a value which is incorrectly
            // formatted or out of range." Omitting the element entirely was
            // verified to register successfully instead (as was explicit S4U,
            // but omission is what Task Scheduler's own /Query /XML export
            // produces for built-in-account tasks, so it is the choice that
            // needs no further special-casing to justify). A SID alone is
            // sufficient for schtasks to resolve the logon behaviour for a
            // well-known built-in account — there is no password to store and
            // no interactive session involved either way.
            new XElement(Ns + "Principals",
                new XElement(Ns + "Principal", new XAttribute("id", "Author"),
                    new XElement(Ns + "UserId", LocalSystemSid),
                    new XElement(Ns + "RunLevel", "HighestAvailable"))),
            new XElement(Ns + "Settings",
                // Equivalent of the original /F (idempotent re-registration):
                // if a prior run of this exact task is somehow still executing
                // when a new one is (re-)staged, do not queue or parallel-run a
                // second instance of a task whose whole job is a one-shot
                // service bounce.
                new XElement(Ns + "MultipleInstancesPolicy", "IgnoreNew"),
                // Round-2 review: the DEFAULT for both of these is `true` (do
                // not start / do stop on battery), which is the SAME shape of
                // silent no-op this file exists to close for the locale bug —
                // a laptop running unplugged is a normal state for the
                // endpoints this ships to, not an edge case, and the task
                // would otherwise simply never fire with no error anywhere to
                // notice. Both are set explicitly rather than left as defaults
                // so the intent is visible in the XML, not implied by omission.
                new XElement(Ns + "DisallowStartIfOnBatteries", "false"),
                new XElement(Ns + "StopIfGoingOnBatteries", "false"),
                // If the fire time is missed entirely (machine asleep/off at
                // the 5-minute mark), run it as soon as the machine is next
                // available rather than silently dropping a ONCE trigger that
                // never got its chance — same "do not let a background bounce
                // silently fail to happen" reasoning as the battery settings
                // above.
                new XElement(Ns + "StartWhenAvailable", "true"),
                new XElement(Ns + "AllowHardTerminate", "true"),
                new XElement(Ns + "Enabled", "true"),
                new XElement(Ns + "Hidden", "false"),
                // Bounded, like every other detached/background action in this
                // service (PendingUpdateApplier's MaxAttempts, the decommission
                // script's cross-boot report budget, ...): a hung
                // Stop-Service/Start-Service must not leave a zombie task
                // running indefinitely.
                new XElement(Ns + "ExecutionTimeLimit", "PT10M")),
            new XElement(Ns + "Actions", new XAttribute("Context", "Author"),
                new XElement(Ns + "Exec",
                    new XElement(Ns + "Command", "powershell.exe"),
                    new XElement(Ns + "Arguments", arguments))));

        // Task Scheduler's own /XML export is UTF-16 with an explicit
        // declaration; matched here (declaration + File.WriteAllText(...,
        // Encoding.Unicode) at the call site in PendingUpdateRestartScheduler)
        // so the declared and actual encodings never disagree — an XML parser
        // is entitled to reject a document whose declared encoding does not
        // match its actual bytes. XDocument.ToString() deliberately omits the
        // <?xml ...?> declaration (a documented .NET behaviour, not an
        // oversight), so it is prepended explicitly rather than relying on it.
        var doc = new XDocument(new XDeclaration("1.0", "UTF-16", null), task);
        return doc.Declaration + "\r\n" + doc.ToString();
    }
}
