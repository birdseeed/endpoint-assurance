//
//  PromptPresentationGovernor.swift
//  PatchedUpdater
//
//  PAT-1624: what happens when the never-interrupt gate keeps saying no.
//
//  The gate (InterruptionGate) answers one question about right now. This
//  governor is the thing that remembers, applies the agreed bounds, and decides
//  whether an attempt turns into a window, a notification, or nothing at all.
//
//  THE THREE PROPERTIES THAT MATTER MORE THAN THE NUMBERS:
//
//  1. Suppression DELAYS, it never cancels. Every suppressed attempt is retried
//     on the next tick of StatusStore's existing blocking-prompt timer and on
//     the existing unlock observer.
//
//  2. Suppression NEVER touches the deferral budget. Nothing in this file
//     reads, writes, decrements or resets `deferrals_remaining`; it never calls
//     `StatusStore.requestOsDefer()` and never writes an `os_defer` marker.
//     Only a human pressing Defer spends a deferral. Otherwise somebody who is
//     genuinely on camera all day would sit past an OS-update deadline by
//     accident and the deadline would stop meaning anything.
//
//  3. Counters accrue only while a user session is active and unlocked, and
//     reset on any successful presentation. Locked or logged out is ABSENCE,
//     not suppression: a laptop shut in a bag for a day must not arrive at
//     "cannot be prompted" having never been near a camera.
//

import Foundation

@MainActor
final class PromptPresentationGovernor {

    /// What the caller should do with this attempt.
    enum Outcome: Equatable {
        /// Show the window.
        case present
        /// No user session, or the screen is locked. Not suppression: no
        /// counter moves, nothing is recorded.
        case absent
        /// Gated, still inside the suppression window. Try again next tick.
        case suppressed(InterruptionReason)
        /// Past the suppression window: hand off to a notification, which the
        /// OS already delivers correctly during a call and under Focus.
        case notificationFallback(InterruptionReason)
        /// Past the suppression window and already notified inside the
        /// once-per-day gap. Stay quiet.
        case silent(InterruptionReason)

        var reason: InterruptionReason? {
            switch self {
            case .present, .absent: return nil
            case .suppressed(let r), .notificationFallback(let r), .silent(let r): return r
            }
        }
    }

    // MARK: Collaborators

    private let gate: InterruptionGate
    private let events: AgentEventSink
    private let operatorSignal: OperatorSignalSink
    private let retryInterval: TimeInterval
    private var calendar: Calendar

    /// Which prompt this governor guards. One instance per user-facing surface,
    /// so a quiet OS-update prompt does not silence a removal prompt.
    let surface: String

    private(set) var policy: InterruptionPolicy

    // MARK: Counters (all reset by recordSuccessfulPresentation)

    private(set) var consecutiveSuppressedAttempts = 0
    /// Distinct local calendar days on which a suppressed attempt happened
    /// while the session was active. Wall-clock days are the wrong unit here:
    /// a machine that was asleep contributed no days.
    private(set) var suppressedDayCount = 0
    private var lastSuppressedDay: Date?
    private(set) var suppressionRunStartedAt: Date?
    private var lastFallbackNotificationAt: Date?
    private(set) var operatorSignalled = false

    init(
        surface: String,
        gate: InterruptionGate = InterruptionGate(),
        policy: InterruptionPolicy = .defaults,
        retryInterval: TimeInterval,
        events: AgentEventSink,
        operatorSignal: OperatorSignalSink,
        calendar: Calendar = .current
    ) {
        self.surface = surface
        self.gate = gate
        self.policy = policy
        self.retryInterval = retryInterval
        self.events = events
        self.operatorSignal = operatorSignal
        self.calendar = calendar
    }

    /// Live policy updates from the signed config. Counters are left alone: a
    /// config refresh mid-suppression must not hand the user a fresh 8 hours.
    func updatePolicy(_ policy: InterruptionPolicy) {
        self.policy = policy
    }

    /// The attempt cap the current policy and retry interval work out to.
    var attemptCap: Int { policy.effectiveAttemptCap(retryInterval: retryInterval) }

    // MARK: - The decision

    func evaluate(now: Date = Date(), sessionActive: Bool) -> Outcome {
        // Absence, not suppression. No counter moves and nothing is recorded:
        // a locked screen is not evidence that the agent could not find a
        // moment, it is evidence that nobody was there to find one for.
        guard sessionActive else { return .absent }

        let decision = gate.canInterruptNow()
        guard let reason = decision.reason else {
            recordSuccessfulPresentation(now: now)
            return .present
        }

        consecutiveSuppressedAttempts += 1
        if suppressionRunStartedAt == nil { suppressionRunStartedAt = now }
        countDay(now)

        let cap = attemptCap
        events.info("prompt suppressed", [
            "surface": surface,
            "reason": reason.rawValue,
            "attempt": consecutiveSuppressedAttempts,
            "attempt_cap": cap,
            "suppressed_days": suppressedDayCount,
        ])

        maybeSignalOperator(now: now, reason: reason)

        guard consecutiveSuppressedAttempts >= cap else {
            return .suppressed(reason)
        }
        return fallbackOutcome(now: now, reason: reason)
    }

    /// Called when the window actually went up, and on the allow path. Resets
    /// every counter and withdraws any standing operator signal: the agent got
    /// through, so there is nothing left for an admin to act on.
    func recordSuccessfulPresentation(now: Date = Date()) {
        let wasSuppressing = consecutiveSuppressedAttempts > 0
        consecutiveSuppressedAttempts = 0
        suppressedDayCount = 0
        lastSuppressedDay = nil
        suppressionRunStartedAt = nil
        lastFallbackNotificationAt = nil
        if operatorSignalled {
            operatorSignal.clearPromptUnreachable(surface: surface)
            operatorSignalled = false
        }
        if wasSuppressing {
            events.info("prompt presented after suppression", ["surface": surface])
        }
    }

    // MARK: - Bounds

    private func countDay(_ now: Date) {
        let day = calendar.startOfDay(for: now)
        guard day != lastSuppressedDay else { return }
        lastSuppressedDay = day
        suppressedDayCount += 1
    }

    private func fallbackOutcome(now: Date, reason: InterruptionReason) -> Outcome {
        if let last = lastFallbackNotificationAt,
           now.timeIntervalSince(last) < policy.notificationFallbackInterval {
            return .silent(reason)
        }
        lastFallbackNotificationAt = now
        events.info("prompt fell back to notification", [
            "surface": surface,
            "reason": reason.rawValue,
            "suppressed_days": suppressedDayCount,
        ])
        return .notificationFallback(reason)
    }

    private func maybeSignalOperator(now: Date, reason: InterruptionReason) {
        guard !operatorSignalled,
              suppressedDayCount >= policy.operatorSignalAfterDays,
              let since = suppressionRunStartedAt else { return }
        operatorSignalled = true
        operatorSignal.signalPromptUnreachable(
            surface: surface,
            reason: reason,
            since: since,
            suppressedDays: suppressedDayCount
        )
        events.error("prompt unreachable", [
            "surface": surface,
            "reason": reason.rawValue,
            "suppressed_days": suppressedDayCount,
        ])
    }
}
