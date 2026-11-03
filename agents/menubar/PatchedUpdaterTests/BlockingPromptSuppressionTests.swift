//
//  BlockingPromptSuppressionTests.swift
//  PatchedUpdaterTests
//
//  PAT-1624: the gate wired into the real StatusStore presentation path.
//
//  The load-bearing assertion in this file is the deferral budget one. A person
//  who is genuinely on camera all day must not lose deferrals to suppression,
//  or they sit past an OS-update deadline by accident and the deadline stops
//  meaning anything. That is proven here by bytes on disk, not by clicking.
//

import XCTest
@testable import PatchedUpdater

@MainActor
final class BlockingPromptSuppressionTests: XCTestCase {

    private var baseDir: URL!
    private var signals: StubInterruptionSignals!
    private var session: StubSessionState!
    private var events: RecordingEventSink!
    private var operatorSignal: RecordingOperatorSignal!

    private var statusURL: URL { baseDir.appendingPathComponent("update-status.json") }
    private var triggerDir: URL { baseDir.appendingPathComponent("triggers", isDirectory: true) }

    override func setUp() {
        super.setUp()
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("blocking-prompt-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        signals = StubInterruptionSignals()
        session = StubSessionState()
        events = RecordingEventSink()
        operatorSignal = RecordingOperatorSignal()
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: baseDir)
        super.tearDown()
    }

    /// An os_update section that requires the blocking prompt: update_required
    /// plus an urgent severity is exactly what `requiresBlockingPrompt` asks for.
    private func writeStatus(deferralsRemaining: Int = 5) throws {
        let json = """
        {
          "schema_version": 2,
          "generated_at": "2026-09-14T08:00:00Z",
          "overall_state": "updates_available",
          "apps": [],
          "os_update": {
            "installed_os": "26.5.0",
            "latest_os": "26.6.2",
            "target_os": "26.6.2",
            "state": "update_required",
            "severity": "high",
            "security_relevant": true,
            "actively_exploited": false,
            "deadline": "2026-09-20T00:00:00Z",
            "deferrals_remaining": \(deferralsRemaining),
            "release_age_days": 21,
            "checked_at": "2026-09-14T07:00:00Z"
          }
        }
        """
        try json.write(to: statusURL, atomically: true, encoding: .utf8)
    }

    private func makeStore() -> StatusStore {
        StatusStore(
            baseDir: baseDir,
            gate: InterruptionGate(source: signals),
            policy: .defaults,
            sessionState: session,
            events: events,
            operatorSignal: operatorSignal,
            observing: false
        )
    }

    private func triggerFiles() -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: triggerDir.path))?.sorted() ?? []
    }

    // MARK: - Unknown target (PAT-2133)

    /// With no policy target and no known latest release the daemon reports
    /// state `unknown` and omits target_os. The whole status must still
    /// decode, and an unknown state never prompts or shows the card.
    func testStatusWithNoTargetOsDecodesAsUnknown() throws {
        let json = """
        {
          "schema_version": 2,
          "generated_at": "2026-09-14T08:00:00Z",
          "overall_state": "up_to_date",
          "apps": [],
          "os_update": {
            "installed_os": "26.5.0",
            "latest_os": null,
            "state": "unknown",
            "severity": "none",
            "security_relevant": false,
            "actively_exploited": false,
            "deadline": null,
            "deferrals_remaining": 5,
            "release_age_days": null,
            "checked_at": "2026-09-14T07:00:00Z"
          }
        }
        """
        try json.write(to: statusURL, atomically: true, encoding: .utf8)
        let store = makeStore()
        let osUpdate = try XCTUnwrap(store.status?.osUpdate)
        XCTAssertNil(osUpdate.targetOs)
        XCTAssertEqual(osUpdate.state, .unknown)
        XCTAssertFalse(osUpdate.shouldShowCard)
        XCTAssertFalse(store.shouldShowBlockingPrompt)
    }

    // MARK: - Presentation

    func testPromptIsPresentedWhenNothingIsInTheWay() throws {
        try writeStatus()
        let store = makeStore()
        XCTAssertTrue(store.shouldShowBlockingPrompt)

        var presented = 0
        let outcome = store.attemptBlockingPromptPresentation { _ in presented += 1 }
        XCTAssertEqual(outcome, .present)
        XCTAssertEqual(presented, 1)
    }

    func testPromptIsNotPresentedWhileTheCameraIsInUse() throws {
        try writeStatus()
        signals.camera = .busy
        let store = makeStore()

        var presented = 0
        let outcome = store.attemptBlockingPromptPresentation { _ in presented += 1 }
        XCTAssertEqual(outcome, .suppressed(.cameraInUse))
        XCTAssertEqual(presented, 0)
        // Delayed, not cancelled: the daemon still says a prompt is due.
        XCTAssertTrue(store.shouldShowBlockingPrompt)
    }

    func testPromptAppearsOnTheNextAttemptOnceTheCallEnds() throws {
        try writeStatus()
        signals.camera = .busy
        let store = makeStore()

        var presented = 0
        _ = store.attemptBlockingPromptPresentation { _ in presented += 1 }
        XCTAssertEqual(presented, 0)

        signals.clear()
        let outcome = store.attemptBlockingPromptPresentation { _ in presented += 1 }
        XCTAssertEqual(outcome, .present)
        XCTAssertEqual(presented, 1)
    }

    func testALockedScreenPresentsNothingAndCostsNoAttempts() throws {
        try writeStatus()
        session.isActiveAndUnlocked = false
        let store = makeStore()

        var presented = 0
        let outcome = store.attemptBlockingPromptPresentation { _ in presented += 1 }
        XCTAssertEqual(outcome, .absent)
        XCTAssertEqual(presented, 0)
        XCTAssertEqual(store.promptGovernor.consecutiveSuppressedAttempts, 0)
    }

    // MARK: - The deferral budget is untouched

    func testAFullSuppressedCycleLeavesTheStatusFileByteForByteIdentical() throws {
        try writeStatus(deferralsRemaining: 5)
        let before = try Data(contentsOf: statusURL)
        signals.camera = .busy
        let store = makeStore()
        XCTAssertEqual(store.status?.osUpdate?.deferralsRemaining, 5)

        // Four days of an unbroken permanently-busy state: past the attempt cap,
        // past the notification fallback, past the operator signal.
        for index in 0..<4 {
            for attempt in 0..<4 {
                let now = Date(timeIntervalSince1970: 1_789_000_000)
                    .addingTimeInterval(Double(index) * 86_400 + Double(attempt) * 7_200)
                store.attemptBlockingPromptPresentation(now: now) { _ in
                    XCTFail("the window must never appear while the camera is in use")
                }
            }
        }

        let after = try Data(contentsOf: statusURL)
        XCTAssertEqual(before, after, "suppression must never rewrite update-status.json")
        XCTAssertEqual(store.status?.osUpdate?.deferralsRemaining, 5,
                       "suppression must never consume, extend or reset the deferral budget")
    }

    func testSuppressionNeverWritesAnOsDeferMarker() throws {
        try writeStatus()
        signals.microphone = .busy
        let store = makeStore()

        for index in 0..<4 {
            for attempt in 0..<4 {
                let now = Date(timeIntervalSince1970: 1_789_000_000)
                    .addingTimeInterval(Double(index) * 86_400 + Double(attempt) * 7_200)
                store.attemptBlockingPromptPresentation(now: now) { _ in }
            }
        }

        let deferMarkers = triggerFiles().filter { $0.hasPrefix("os_defer") }
        XCTAssertTrue(deferMarkers.isEmpty, "only a human pressing Defer may spend a deferral")
    }

    func testPressingDeferIsStillTheOnlyThingThatSpendsADeferral() throws {
        try writeStatus()
        let store = makeStore()
        store.requestOsDefer()
        let deferMarkers = triggerFiles().filter { $0.hasPrefix("os_defer") }
        XCTAssertEqual(deferMarkers.count, 1, "the existing Defer path must be unchanged")
    }

    // MARK: - PAT-1661: os_defer marker write failure is observable

    func testOsDeferWriteSuccessFiresNoFailureEventAndDismissesAsBefore() throws {
        try writeStatus()
        let store = makeStore()
        XCTAssertTrue(store.shouldShowBlockingPrompt)

        store.requestOsDefer()

        XCTAssertFalse(store.shouldShowBlockingPrompt, "prompt still dismisses optimistically on success")
        XCTAssertTrue(events.messages("os_defer marker write failed").isEmpty,
                      "a successful write must not log a failure event")
    }

    func testOsDeferWriteFailureLogsOnceAndStillDismisses() throws {
        try writeStatus()
        let store = makeStore()
        XCTAssertTrue(store.shouldShowBlockingPrompt)

        // Force the trigger write to fail: the directory exists but is
        // read-only, so the atomic write's temp-file create fails.
        try FileManager.default.createDirectory(at: triggerDir, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: triggerDir.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: triggerDir.path) }

        store.requestOsDefer()

        XCTAssertFalse(store.shouldShowBlockingPrompt,
                       "the prompt must still dismiss optimistically even when the write fails")
        XCTAssertEqual(events.messages("os_defer marker write failed").count, 1,
                       "a failed write must log exactly one failure event")
        let deferMarkers = triggerFiles().filter { $0.hasPrefix("os_defer") }
        XCTAssertTrue(deferMarkers.isEmpty, "the write genuinely failed, no marker landed on disk")
    }

    // MARK: - Bounded fallback under a synthetic permanently-busy state

    func testTheBoundedFallbackFiresWhenTheMachineIsNeverFree() throws {
        try writeStatus()
        signals.presenting = .busy
        let store = makeStore()

        var outcomes: [PromptPresentationGovernor.Outcome] = []
        for index in 0..<3 {
            for attempt in 0..<4 {
                let now = Date(timeIntervalSince1970: 1_789_000_000)
                    .addingTimeInterval(Double(index) * 86_400 + Double(attempt) * 7_200)
                outcomes.append(store.attemptBlockingPromptPresentation(now: now) { _ in })
            }
        }

        XCTAssertTrue(outcomes.contains(.suppressed(.presenting)), "early attempts should just delay")
        XCTAssertTrue(outcomes.contains(.notificationFallback(.presenting)), "the notification fallback must fire")
        XCTAssertEqual(operatorSignal.raised.count, 1, "the operator must be told after three days")
        XCTAssertEqual(operatorSignal.raised.first?.suppressedDays, 3)
    }

    // MARK: - The operator marker cannot be eaten by the update daemon

    func testTheOperatorMarkerIsNotATriggerFile() throws {
        try writeStatus()
        signals.camera = .busy
        // The real trigger-directory sink, so the on-disk filename is asserted.
        let store = StatusStore(
            baseDir: baseDir,
            gate: InterruptionGate(source: signals),
            policy: .defaults,
            sessionState: session,
            events: events,
            operatorSignal: TriggerDirectoryOperatorSignal(triggerDirectory: triggerDir, events: events),
            observing: false
        )

        for index in 0..<3 {
            for attempt in 0..<4 {
                let now = Date(timeIntervalSince1970: 1_789_000_000)
                    .addingTimeInterval(Double(index) * 86_400 + Double(attempt) * 7_200)
                store.attemptBlockingPromptPresentation(now: now) { _ in }
            }
        }

        let files = triggerFiles()
        XCTAssertEqual(files.count, 1)
        // The daemon consumes at most one *.trigger per run and deletes it. A
        // .trigger here would be silently eaten and would displace a real
        // deploy or scan request.
        XCTAssertFalse(files[0].hasSuffix(".trigger"))
        XCTAssertTrue(files[0].hasSuffix(".marker"))

        let marker = try JSONSerialization.jsonObject(
            with: Data(contentsOf: triggerDir.appendingPathComponent(files[0]))
        ) as? [String: Any]
        XCTAssertEqual(marker?["type"] as? String, "prompt_unreachable")
        XCTAssertEqual(marker?["reason"] as? String, "camera_in_use")
        XCTAssertEqual(marker?["surface"] as? String, StatusStore.blockingPromptSurface)
    }

    func testReSignallingOverwritesRatherThanAccumulates() throws {
        let sink = TriggerDirectoryOperatorSignal(triggerDirectory: triggerDir, events: events)
        for _ in 0..<5 {
            sink.signalPromptUnreachable(
                surface: StatusStore.blockingPromptSurface,
                reason: .presenting,
                since: Date(),
                suppressedDays: 3
            )
        }
        XCTAssertEqual(triggerFiles().count, 1)
        sink.clearPromptUnreachable(surface: StatusStore.blockingPromptSurface)
        XCTAssertTrue(triggerFiles().isEmpty)
    }

    // MARK: - Attempt plumbing

    func testTheAttemptCounterChangesEveryTimeSoTheRetryCanFire() throws {
        try writeStatus()
        signals.camera = .busy
        let store = makeStore()
        let first = store.blockingPromptAttempt
        store.requestBlockingPromptAttempt()
        store.requestBlockingPromptAttempt()
        XCTAssertEqual(store.blockingPromptAttempt, first + 2,
                       "a continuously-true flag would never re-fire onChange")
    }

    func testNoAttemptIsRequestedWhenNoPromptIsDue() throws {
        // No status file at all: nothing is due, so nothing is retried.
        let store = makeStore()
        XCTAssertFalse(store.shouldShowBlockingPrompt)
        store.requestBlockingPromptAttempt()
        XCTAssertEqual(store.blockingPromptAttempt, 0)
    }
}
