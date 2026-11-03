//
//  RemovalPromptPolicy.swift
//  PatchedUpdater
//
//  PAT-1623. Andy's 2026-09-12 ruling on removal vs. the OS-update deadline
//  prompt: "Shared: the window shell, brand, layout, deferral row, and the
//  interruption gate. Separate: the policy... Model each prompt as a request
//  carrying its own copy, its own defer semantics, and its own terminal
//  behaviour, driven from one shared policy *object* — not one policy value
//  both prompts share, since that object would have to lie about one of
//  them."
//
//  InterruptionPolicy (PAT-1624) stays shared as-is: it only bounds how long
//  the never-interrupt gate keeps a *presentation attempt* quiet, and that
//  timing restraint is genuinely identical for both prompts. What must never
//  be shared is *this* — the defer/terminal semantics — because the two
//  prompts disagree about it completely: the OS update counts down to a real
//  deadline and disables Defer at zero remaining; removal has no deadline and
//  no terminal state at all. Giving both prompts one InterruptionPolicy-style
//  struct with a shared `deferralsRemaining` field would force one of them to
//  either fabricate a deadline or fabricate infinite deferrals. This type
//  exists so removal gets its own instance instead.
//

import Foundation

struct RemovalPromptPolicy: Equatable {
    /// Ceiling the daemon uses for its own "how long has this been waiting on
    /// the user" audit/telemetry accounting (see requestRemovalDefer). Set by
    /// policy, never by the person at the keyboard — there is no UI control
    /// for it anywhere in this ticket.
    ///
    /// Reaching this number changes nothing about what the prompt can do.
    /// The ruling is explicit: "The removal prompt must never render a
    /// 'no deferrals remaining' state, or any control that forces the user's
    /// hand... There is no dead end." `canAlwaysDefer` below is the single
    /// place that guarantee lives in code.
    var deferralBudget: Int

    static let defaults = RemovalPromptPolicy(deferralBudget: 5)

    /// Always true, for any budget and any observed deferral count — including
    /// a count at or past the budget. Kept as a named function (rather than a
    /// bare `true` inlined at each call site) so the "no terminal state ever"
    /// guarantee is one testable seam instead of a convention every future
    /// call site has to remember to uphold.
    func canAlwaysDefer(deferralCount: Int) -> Bool { true }
}
