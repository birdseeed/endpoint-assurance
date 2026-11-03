namespace Patched.Shared.Removal;

/// <summary>
/// PAT-1623. Content-equivalent with the macOS
/// <c>RemovalPromptPolicy.swift</c>. Andy's 2026-09-12 ruling: the OS-update
/// deadline prompt and this one share the window shell, the brand, the layout
/// and the interruption gate — but never the policy, because that object
/// would have to lie about one of them (the OS update counts down to a real
/// deadline and disables Defer at zero remaining; removal has no deadline and
/// no terminal state, ever). <see cref="Patched.Shared.Interruption.InterruptionPolicy"/>
/// stays genuinely shared (it only bounds how long a presentation *attempt*
/// stays quiet, which is identical for both prompts); this type exists so the
/// defer/terminal semantics never are.
/// </summary>
public sealed record RemovalPromptPolicy
{
    /// <summary>
    /// Ceiling for the daemon's own "how long has this been waiting on the
    /// user" audit/telemetry accounting. Set by policy, never by the person
    /// at the keyboard. Reaching it changes nothing about what the prompt can
    /// do — see <see cref="CanAlwaysDefer"/>.
    /// </summary>
    public int DeferralBudget { get; init; } = 5;

    public static readonly RemovalPromptPolicy Defaults = new();

    /// <summary>
    /// Always true, for any budget and any observed deferral count. The
    /// ruling is explicit: "The removal prompt must never render a 'no
    /// deferrals remaining' state, or any control that forces the user's
    /// hand." Kept as a named, tested seam rather than a bare `true` at each
    /// call site.
    /// </summary>
    public bool CanAlwaysDefer(long deferralCount) => true;
}
