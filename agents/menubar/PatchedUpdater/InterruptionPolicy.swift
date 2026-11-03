//
//  InterruptionPolicy.swift
//  PatchedUpdater
//
//  PAT-1624: the numeric bounds on how long the never-interrupt gate is
//  allowed to keep the agent quiet before it changes tactics.
//
//  TIER PLACEMENT. The gate itself is unconditional and applies at every tier,
//  assurance included: it is a restraint, not a capability, and the OS-update
//  prompt it protects against has no tier gate anywhere. Only these four
//  numbers are tunable, and only at managed tier. Every other tenant runs the
//  defaults below, which are the values agreed on the ticket and anchored to
//  what already exists (`blockingReminderInterval` is 2 hours,
//  `os_update_policy.blocking_window_days` is 3, `deferral_budget` is 5).
//
//  These bounds gate *presentation*, not the deadline. The deadline keeps
//  running underneath. A device that cannot be prompted for three days inside a
//  three-day blocking window reaches the deadline with the user never having
//  seen the prompt: the operator is told and decides. Patched does not force a
//  window over somebody's call to make a deadline.
//

import Foundation

// MARK: - Policy

struct InterruptionPolicy: Equatable {

    /// How many *active* hours of unbroken suppression the agent will keep
    /// trying to present for before it falls back to a notification.
    ///
    /// This, not the attempt count, is the policy. One working day of never
    /// finding a safe moment is enough.
    var suppressionWindowHours: Int

    /// Optional hard ceiling on consecutive suppressed attempts.
    ///
    /// Normally `nil`, in which case the cap is *derived* from
    /// `suppressionWindowHours` and the live retry interval, so changing the
    /// retry interval later cannot silently change the policy. An explicit
    /// value only ever tightens the derived cap (whichever is smaller wins),
    /// because tightening means more silence and silence is the safe direction.
    var maxSuppressedAttempts: Int?

    /// Minimum gap between the fallback notifications that replace the window
    /// once the window above has elapsed. More than once a day is nagging, and
    /// nagging trains dismissal.
    var notificationFallbackIntervalHours: Int

    /// Distinct active days of unbroken suppression before the operator is
    /// signalled. Matches `os_update_policy.blocking_window_days` so an admin
    /// hears about it while there is still time to act.
    var operatorSignalAfterDays: Int

    static let defaults = InterruptionPolicy(
        suppressionWindowHours: 8,
        maxSuppressedAttempts: nil,
        notificationFallbackIntervalHours: 24,
        operatorSignalAfterDays: 3
    )

    var suppressionWindow: TimeInterval { TimeInterval(suppressionWindowHours) * 3600 }
    var notificationFallbackInterval: TimeInterval { TimeInterval(notificationFallbackIntervalHours) * 3600 }

    /// The attempt count the window works out to at this retry interval.
    ///
    /// At the shipped 2-hour retry and the default 8-hour window this is
    /// exactly 4, which is the number on the ticket. Halve the retry interval
    /// and it becomes 8 attempts, still 8 hours: the hours are what is
    /// promised, the attempt count is bookkeeping.
    func effectiveAttemptCap(retryInterval: TimeInterval) -> Int {
        guard retryInterval > 0 else { return max(1, maxSuppressedAttempts ?? 1) }
        let derived = max(1, Int(ceil(suppressionWindow / retryInterval)))
        guard let explicit = maxSuppressedAttempts else { return derived }
        return max(1, min(explicit, derived))
    }
}

// MARK: - Signed-config overrides

/// The `interruption_policy` block of agent-config.json. Every field is
/// optional: an absent field, a null, or a value outside its sane range leaves
/// the shipped default in place rather than failing the whole config.
struct InterruptionPolicyOverrides: Decodable, Equatable {
    var suppressionWindowHours: Int?
    var maxSuppressedAttempts: Int?
    var notificationFallbackIntervalHours: Int?
    var operatorSignalAfterDays: Int?
}

extension InterruptionPolicy {

    /// Resolve the live policy from the signed config.
    ///
    /// Managed tier only. Overrides delivered to any other tier are ignored
    /// outright rather than partially applied, so an assurance tenant runs
    /// exactly the shipped defaults whatever the config says. Out-of-range
    /// values are dropped field by field, never clamped to something the
    /// operator did not ask for.
    static func resolve(overrides: InterruptionPolicyOverrides?, tier: Posture.Tier?) -> InterruptionPolicy {
        guard tier == .managed, let overrides else { return .defaults }

        var policy = InterruptionPolicy.defaults
        if let hours = overrides.suppressionWindowHours, (1...168).contains(hours) {
            policy.suppressionWindowHours = hours
        }
        if let attempts = overrides.maxSuppressedAttempts, (1...1000).contains(attempts) {
            policy.maxSuppressedAttempts = attempts
        }
        if let hours = overrides.notificationFallbackIntervalHours, (1...168).contains(hours) {
            policy.notificationFallbackIntervalHours = hours
        }
        if let days = overrides.operatorSignalAfterDays, (1...365).contains(days) {
            policy.operatorSignalAfterDays = days
        }
        return policy
    }
}
