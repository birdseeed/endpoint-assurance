//
//  PromptPresentationGovernorTests.swift
//  PatchedUpdaterTests
//
//  PAT-1624: the bounds, proven with a synthetic permanently-busy state rather
//  than a click-through.
//
//  Anchored to the shipped values: a 2-hour retry, an 8-hour suppression window
//  (so 4 consecutive suppressed attempts), a fallback notification at most once
//  a day, and an operator signal after 3 days.
//

import XCTest
@testable import PatchedUpdater

@MainActor
final class PromptPresentationGovernorTests: XCTestCase {

    private let retry: TimeInterval = 2 * 3600
    private let surface = "os_update_blocking_prompt"

    private var signals: StubInterruptionSignals!
    private var events: RecordingEventSink!
    private var operatorSignal: RecordingOperatorSignal!

    override func setUp() {
        super.setUp()
        signals = StubInterruptionSignals()
        events = RecordingEventSink()
        operatorSignal = RecordingOperatorSignal()
    }

    private func makeGovernor(policy: InterruptionPolicy = .defaults) -> PromptPresentationGovernor {
        PromptPresentationGovernor(
            surface: surface,
            gate: InterruptionGate(source: signals),
            policy: policy,
            retryInterval: retry,
            events: events,
            operatorSignal: operatorSignal
        )
    }

    /// A fixed start so day boundaries in the tests are unambiguous.
    private func day(_ index: Int, hour: Int = 9) -> Date {
        var components = DateComponents()
        components.year = 2026
        components.month = 9
        components.day = 14 + index
        components.hour = hour
        return Calendar.current.date(from: components)!
    }

    // MARK: - Happy path

    func testClearSignalsPresent() {
        let governor = makeGovernor()
        XCTAssertEqual(governor.evaluate(now: day(0), sessionActive: true), .present)
        XCTAssertEqual(governor.consecutiveSuppressedAttempts, 0)
    }

    // MARK: - Bound 1: stop presenting after the suppression window

    func testDefaultAttemptCapIsFourAtTheTwoHourRetry() {
        // 8 active hours at the shipped 2-hour retry, expressed in hours and
        // derived into attempts so the two cannot disagree.
        XCTAssertEqual(makeGovernor().attemptCap, 4)
    }

    func testFirstThreeSuppressedAttemptsJustDelay() {
        signals.camera = .busy
        let governor = makeGovernor()
        for attempt in 1...3 {
            let outcome = governor.evaluate(now: day(0, hour: 9 + attempt * 2), sessionActive: true)
            XCTAssertEqual(outcome, .suppressed(.cameraInUse), "attempt \(attempt) should still be retrying")
        }
    }

    func testFourthConsecutiveSuppressedAttemptFallsBackToANotification() {
        signals.camera = .busy
        let governor = makeGovernor()
        var outcome: PromptPresentationGovernor.Outcome = .absent
        for attempt in 1...4 {
            outcome = governor.evaluate(now: day(0, hour: 9 + attempt * 2), sessionActive: true)
        }
        XCTAssertEqual(outcome, .notificationFallback(.cameraInUse))
    }

    func testHalvingTheRetryIntervalKeepsTheEightHourPolicy() {
        // The ticket's rule: express the policy in hours so changing the retry
        // interval later cannot silently change it.
        let hourly = PromptPresentationGovernor(
            surface: surface,
            gate: InterruptionGate(source: signals),
            policy: .defaults,
            retryInterval: 3600,
            events: events,
            operatorSignal: operatorSignal
        )
        XCTAssertEqual(hourly.attemptCap, 8)   // 8 attempts x 1 hour = the same 8 hours
    }

    func testDoublingTheRetryIntervalKeepsTheEightHourPolicy() {
        let fourHourly = PromptPresentationGovernor(
            surface: surface,
            gate: InterruptionGate(source: signals),
            policy: .defaults,
            retryInterval: 4 * 3600,
            events: events,
            operatorSignal: operatorSignal
        )
        XCTAssertEqual(fourHourly.attemptCap, 2)  // 2 attempts x 4 hours = 8 hours
    }

    // MARK: - Bound 2: notification at most once per day

    func testSecondFallbackInsideTheSameDayIsSilent() {
        signals.microphone = .busy
        let governor = makeGovernor()
        for attempt in 1...4 { _ = governor.evaluate(now: day(0, hour: 8 + attempt), sessionActive: true) }
        // Fifth attempt, still the same day, is past the cap but inside the gap.
        let outcome = governor.evaluate(now: day(0, hour: 14), sessionActive: true)
        XCTAssertEqual(outcome, .silent(.microphoneInUse))
    }

    func testAFurtherFallbackFiresOnceTheDailyGapHasElapsed() {
        signals.microphone = .busy
        let governor = makeGovernor()
        for attempt in 1...4 { _ = governor.evaluate(now: day(0, hour: 8 + attempt), sessionActive: true) }
        let outcome = governor.evaluate(now: day(1, hour: 14), sessionActive: true)
        XCTAssertEqual(outcome, .notificationFallback(.microphoneInUse))
    }

    // MARK: - Bound 3: operator signal after three days

    func testOperatorIsNotSignalledAfterOneBusyDay() {
        signals.presenting = .busy
        let governor = makeGovernor()
        for attempt in 1...6 { _ = governor.evaluate(now: day(0, hour: 8 + attempt), sessionActive: true) }
        XCTAssertTrue(operatorSignal.raised.isEmpty, "one busy day is a normal calendar and needs no human")
    }

    func testOperatorIsSignalledOnTheThirdConsecutiveBusyDay() {
        signals.presenting = .busy
        let governor = makeGovernor()
        for index in 0...2 {
            for attempt in 1...4 {
                _ = governor.evaluate(now: day(index, hour: 8 + attempt), sessionActive: true)
            }
        }
        XCTAssertEqual(operatorSignal.raised.count, 1)
        XCTAssertEqual(operatorSignal.raised.first?.surface, surface)
        XCTAssertEqual(operatorSignal.raised.first?.reason, .presenting)
        XCTAssertEqual(operatorSignal.raised.first?.suppressedDays, 3)
    }

    func testOperatorIsSignalledOnlyOncePerSuppressionRun() {
        signals.presenting = .busy
        let governor = makeGovernor()
        for index in 0...5 {
            for attempt in 1...4 {
                _ = governor.evaluate(now: day(index, hour: 8 + attempt), sessionActive: true)
            }
        }
        XCTAssertEqual(operatorSignal.raised.count, 1)
    }

    // MARK: - Bound 4: absence is not suppression

    func testALockedSessionMovesNoCounters() {
        signals.camera = .busy
        let governor = makeGovernor()
        for index in 0...9 {
            let outcome = governor.evaluate(now: day(index), sessionActive: false)
            XCTAssertEqual(outcome, .absent)
        }
        XCTAssertEqual(governor.consecutiveSuppressedAttempts, 0)
        XCTAssertEqual(governor.suppressedDayCount, 0)
        XCTAssertTrue(operatorSignal.raised.isEmpty,
                      "a laptop shut in a bag must not arrive at cannot-be-prompted")
        XCTAssertTrue(events.entries.isEmpty, "absence is not a suppression event")
    }

    func testALaptopInABagForThreeDaysThenAvailableStillPresents() {
        signals.camera = .busy
        let governor = makeGovernor()
        for index in 0...2 { _ = governor.evaluate(now: day(index), sessionActive: false) }
        signals.clear()
        XCTAssertEqual(governor.evaluate(now: day(3), sessionActive: true), .present)
    }

    // MARK: - Counters reset on a successful presentation

    func testASuccessfulPresentationResetsEveryCounter() {
        signals.camera = .busy
        let governor = makeGovernor()
        for attempt in 1...3 { _ = governor.evaluate(now: day(0, hour: 8 + attempt), sessionActive: true) }
        XCTAssertEqual(governor.consecutiveSuppressedAttempts, 3)

        signals.clear()
        XCTAssertEqual(governor.evaluate(now: day(0, hour: 13), sessionActive: true), .present)
        XCTAssertEqual(governor.consecutiveSuppressedAttempts, 0)
        XCTAssertEqual(governor.suppressedDayCount, 0)
        XCTAssertNil(governor.suppressionRunStartedAt)

        // And the run starts again from zero rather than tipping straight over.
        signals.camera = .busy
        XCTAssertEqual(governor.evaluate(now: day(0, hour: 15), sessionActive: true), .suppressed(.cameraInUse))
    }

    func testASuccessfulPresentationWithdrawsAStandingOperatorSignal() {
        signals.camera = .busy
        let governor = makeGovernor()
        for index in 0...2 {
            for attempt in 1...4 { _ = governor.evaluate(now: day(index, hour: 8 + attempt), sessionActive: true) }
        }
        XCTAssertEqual(operatorSignal.raised.count, 1)

        signals.clear()
        _ = governor.evaluate(now: day(3), sessionActive: true)
        XCTAssertEqual(operatorSignal.cleared, [surface])
        XCTAssertFalse(governor.operatorSignalled)
    }

    // MARK: - Suppression delays, it never cancels

    func testEveryOutcomeLeavesTheNextAttemptPossible() {
        signals.focus = .busy
        let governor = makeGovernor()
        for attempt in 1...20 {
            let outcome = governor.evaluate(now: day(attempt / 4, hour: 8 + attempt % 4), sessionActive: true)
            XCTAssertNotEqual(outcome, .present)
        }
        // The moment the machine is free, the prompt goes up.
        signals.clear()
        XCTAssertEqual(governor.evaluate(now: day(9), sessionActive: true), .present)
    }

    // MARK: - Privacy

    func testSuppressionEventsCarryOnlyTheReasonCode() {
        signals.camera = .busy
        let governor = makeGovernor()
        _ = governor.evaluate(now: day(0), sessionActive: true)

        let suppression = events.messages("prompt suppressed")
        XCTAssertEqual(suppression.count, 1)
        let fields = suppression[0].fields
        XCTAssertEqual(
            Set(fields.keys),
            ["surface", "reason", "attempt", "attempt_cap", "suppressed_days"],
            "a suppression event must carry the reason code and nothing about the session"
        )
        XCTAssertEqual(fields["reason"] as? String, "camera_in_use")
    }

    func testNoEventEverRecordsADurationOrAnApplication() {
        signals.camera = .busy
        let governor = makeGovernor()
        for index in 0...3 {
            for attempt in 1...4 { _ = governor.evaluate(now: day(index, hour: 8 + attempt), sessionActive: true) }
        }
        let forbidden = ["app", "application", "bundle", "process", "duration", "started_at", "ended_at", "held_by"]
        for entry in events.entries {
            for key in entry.fields.keys {
                XCTAssertFalse(forbidden.contains(key), "event field '\(key)' leaks session detail")
            }
        }
    }

    // MARK: - Policy changes mid-run

    func testAConfigRefreshDoesNotHandTheUserAFreshWindow() {
        signals.camera = .busy
        let governor = makeGovernor()
        for attempt in 1...3 { _ = governor.evaluate(now: day(0, hour: 8 + attempt), sessionActive: true) }
        governor.updatePolicy(.defaults)
        XCTAssertEqual(governor.consecutiveSuppressedAttempts, 3)
        let outcome = governor.evaluate(now: day(0, hour: 13), sessionActive: true)
        XCTAssertEqual(outcome, .notificationFallback(.cameraInUse))
    }

    func testAManagedTenantCanWidenTheSuppressionWindow() {
        signals.camera = .busy
        var policy = InterruptionPolicy.defaults
        policy.suppressionWindowHours = 24
        let governor = makeGovernor(policy: policy)
        XCTAssertEqual(governor.attemptCap, 12)
        for attempt in 1...11 {
            XCTAssertEqual(
                governor.evaluate(now: day(0, hour: 8).addingTimeInterval(Double(attempt) * 3600), sessionActive: true),
                .suppressed(.cameraInUse)
            )
        }
    }
}
