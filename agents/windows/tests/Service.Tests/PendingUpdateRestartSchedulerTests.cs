using Patched.Service;
using Xunit;

namespace Patched.Service.Tests;

/// <summary>
/// PAT-1293. <see cref="PendingUpdateRestartScheduler"/> itself is NOT
/// independently unit testable end-to-end — registering a real Windows scheduled
/// task requires a live Task Scheduler service (Windows-only, admin-only); see its
/// own class doc comment, mirroring <see cref="DecommissionHandoff"/>'s identical
/// caveat. This covers the piece of it that IS pure logic:
/// <see cref="PendingUpdateRestartScheduler.BuildCreateArgs"/> — now just the
/// <c>/TN</c> + <c>/XML</c> + <c>/F</c> shape, after round 2 non-author review
/// moved the trigger time, principal, and run level out of command-line flags and
/// into the task-definition XML (see <see cref="PendingUpdateRestartTaskXml"/> and
/// PendingUpdateRestartTaskXmlTests, which cover the interesting — and, before
/// round 2, actually broken — start-time and locale logic that used to live here).
/// </summary>
public class PendingUpdateRestartSchedulerTests
{
    private const string TaskName = "PatchedAgentSelfUpdateRestart";
    private const string XmlPath  = @"C:\ProgramData\Patched\self-update-restart\restart-task.xml";

    [Fact]
    public void BuildCreateArgs_UsesXmlRegistration_NotInlineFlags()
    {
        string args = PendingUpdateRestartScheduler.BuildCreateArgs(TaskName, XmlPath);

        Assert.Contains($"/TN \"{TaskName}\"", args);
        Assert.Contains($"/XML \"{XmlPath}\"", args);
        Assert.Contains("/F", args);

        // PAT-1293 round 2: the regression this test guards against. /SC ONCE
        // /ST /SD /RU /RL on the command line is exactly what broke registration
        // on non-US-date-order locales (en-GB included) — none of that belongs
        // here anymore; it all lives in the XML document instead.
        Assert.DoesNotContain("/SC", args);
        Assert.DoesNotContain("/ST", args);
        Assert.DoesNotContain("/SD", args);
        Assert.DoesNotContain("/RU", args);
        Assert.DoesNotContain("/RL", args);
        Assert.DoesNotContain("/TR", args);
    }

    [Fact]
    public void BuildCreateArgs_QuotesTaskNameAndXmlPath()
    {
        // Spaces are common in both — the XML file lives under %ProgramData%
        // (no spaces today, but the task name or a future path shape might).
        string args = PendingUpdateRestartScheduler.BuildCreateArgs(
            "Patched Agent Self Update Restart", @"C:\Program Files\Patched\restart-task.xml");

        Assert.Contains("/TN \"Patched Agent Self Update Restart\"", args);
        Assert.Contains(@"/XML ""C:\Program Files\Patched\restart-task.xml""", args);
    }

    [Fact]
    public void BuildCreateArgs_RestartDelayIsFiveMinutes()
    {
        // Pins the brief's stated delay rationale (lets an in-flight cycle finish
        // rather than cutting it off instantly) as a concrete, regression-proof
        // value rather than only a comment. Consumed by
        // PendingUpdateRestartTaskXml.Build, not by this class directly anymore,
        // but the constant itself still lives on PendingUpdateRestartScheduler.
        Assert.Equal(TimeSpan.FromMinutes(5), PendingUpdateRestartScheduler.RestartDelay);
    }
}
