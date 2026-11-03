//
//  InterruptionGateTests.swift
//  PatchedUpdaterTests
//
//  PAT-1624: the gate's own decision logic, one signal at a time.
//
//  The live readers are exercised separately at the bottom of this file: not
//  for their answer (which depends on whatever the machine happens to be doing)
//  but for the one property that would silently destroy the feature: a signal
//  that is permanently unreadable makes the agent fail closed forever and no
//  prompt ever appears again.
//

import XCTest
@testable import PatchedUpdater

final class InterruptionGateTests: XCTestCase {

    private func gate(_ signals: StubInterruptionSignals) -> InterruptionGate {
        InterruptionGate(source: signals)
    }

    // MARK: - Allow

    func testAllClearAllowsTheInterruption() {
        XCTAssertEqual(gate(StubInterruptionSignals()).canInterruptNow(), .allow)
    }

    // MARK: - Each signal suppresses on its own

    func testCameraInUseSuppresses() {
        let decision = gate(StubInterruptionSignals(camera: .busy)).canInterruptNow()
        XCTAssertEqual(decision, .suppress(.cameraInUse))
    }

    func testMicrophoneInUseSuppresses() {
        // A dial-in with video off is still a call.
        let decision = gate(StubInterruptionSignals(microphone: .busy)).canInterruptNow()
        XCTAssertEqual(decision, .suppress(.microphoneInUse))
    }

    func testPresentingSuppresses() {
        let decision = gate(StubInterruptionSignals(presenting: .busy)).canInterruptNow()
        XCTAssertEqual(decision, .suppress(.presenting))
    }

    func testFocusSuppresses() {
        let decision = gate(StubInterruptionSignals(focus: .busy)).canInterruptNow()
        XCTAssertEqual(decision, .suppress(.focusOrDoNotDisturb))
    }

    // MARK: - Fail closed toward silence

    func testUnreadableCameraSuppresses() {
        let decision = gate(StubInterruptionSignals(camera: .unreadable)).canInterruptNow()
        XCTAssertEqual(decision, .suppress(.signalUnreadable))
    }

    func testUnreadableMicrophoneSuppresses() {
        let decision = gate(StubInterruptionSignals(microphone: .unreadable)).canInterruptNow()
        XCTAssertEqual(decision, .suppress(.signalUnreadable))
    }

    func testUnreadablePresentingSuppresses() {
        let decision = gate(StubInterruptionSignals(presenting: .unreadable)).canInterruptNow()
        XCTAssertEqual(decision, .suppress(.signalUnreadable))
    }

    func testUnreadableFocusSuppresses() {
        let decision = gate(StubInterruptionSignals(focus: .unreadable)).canInterruptNow()
        XCTAssertEqual(decision, .suppress(.signalUnreadable))
    }

    func testEverySingleSignalUnreadableSuppresses() {
        // Belt and braces: no combination of unreadable signals can produce an
        // allow. A delayed prompt costs a day; a window over a demo costs the account.
        for unreadable in 0..<4 {
            let signals = StubInterruptionSignals()
            switch unreadable {
            case 0: signals.camera = .unreadable
            case 1: signals.microphone = .unreadable
            case 2: signals.presenting = .unreadable
            default: signals.focus = .unreadable
            }
            XCTAssertFalse(gate(signals).canInterruptNow().isAllowed)
        }
    }

    // MARK: - Reason precedence

    func testDefinitelyBusyBeatsUnreadableInTheReasonCode() {
        // Both suppress. The reason an admin sees should be the informative one.
        let signals = StubInterruptionSignals(camera: .unreadable, microphone: .busy)
        XCTAssertEqual(gate(signals).canInterruptNow(), .suppress(.microphoneInUse))
    }

    func testFirstBusySignalInFixedOrderWins() {
        let signals = StubInterruptionSignals(camera: .busy, microphone: .busy, presenting: .busy, focus: .busy)
        XCTAssertEqual(gate(signals).canInterruptNow(), .suppress(.cameraInUse))
    }

    // MARK: - Reason codes carry nothing about the session

    func testReasonCodesAreFixedVocabulary() {
        // Privacy: the reason code is the entire payload of a suppression
        // event. Pin the vocabulary so nothing app-specific can be added to it
        // without this test failing.
        XCTAssertEqual(
            Set(InterruptionReason.allCases.map(\.rawValue)),
            ["camera_in_use", "microphone_in_use", "presenting", "focus_or_do_not_disturb", "signal_unreadable"]
        )
    }

    // MARK: - Focus reader (file-shape driven, so testable without a real Focus)

    private func writeDoNotDisturb(_ json: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("dnd-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("Assertions.json")
        try json.write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    func testFocusReaderTreatsMissingDatabaseAsIdle() {
        // A Mac that has never used Focus has no database. Treating that as
        // unreadable would silence the agent permanently on every such machine.
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("no-such-dnd-\(UUID().uuidString)/Assertions.json")
        let source = SystemInterruptionSignals(doNotDisturbDatabaseURL: missing)
        XCTAssertEqual(source.focusReading(), .idle)
    }

    func testFocusReaderTreatsNoAssertionRecordsAsIdle() throws {
        let url = try writeDoNotDisturb(#"{"data":[{"storeInvalidationRecords":[]}]}"#)
        XCTAssertEqual(SystemInterruptionSignals(doNotDisturbDatabaseURL: url).focusReading(), .idle)
    }

    func testFocusReaderTreatsEmptyAssertionRecordsAsIdle() throws {
        let url = try writeDoNotDisturb(#"{"data":[{"storeAssertionRecords":[]}]}"#)
        XCTAssertEqual(SystemInterruptionSignals(doNotDisturbDatabaseURL: url).focusReading(), .idle)
    }

    func testFocusReaderTreatsAnActiveAssertionAsBusy() throws {
        let url = try writeDoNotDisturb(
            #"{"data":[{"storeAssertionRecords":[{"assertionDetails":{"assertionDetailsModeIdentifier":"com.apple.donotdisturb.mode.default"}}]}]}"#
        )
        XCTAssertEqual(SystemInterruptionSignals(doNotDisturbDatabaseURL: url).focusReading(), .busy)
    }

    func testFocusReaderTreatsAnUnparseableDatabaseAsUnreadable() throws {
        // If Apple changes this undocumented file the agent gets quieter, never louder.
        let url = try writeDoNotDisturb("not json at all")
        XCTAssertEqual(SystemInterruptionSignals(doNotDisturbDatabaseURL: url).focusReading(), .unreadable)
    }

    func testFocusReaderTreatsAnUnexpectedShapeAsUnreadable() throws {
        let url = try writeDoNotDisturb(#"{"data":"not an array"}"#)
        XCTAssertEqual(SystemInterruptionSignals(doNotDisturbDatabaseURL: url).focusReading(), .unreadable)
    }

    // MARK: - Live readers

    func testLiveCameraAndMicrophoneSignalsAreReadable() {
        // Not asserting idle or busy: whether this machine is on a call is not
        // the test's business. Asserting *readable* is, because a permanently
        // unreadable signal fails closed forever and the agent would never
        // raise another prompt on any device. That is the regression that would
        // look identical to "working" from Linear.
        let source = SystemInterruptionSignals()
        XCTAssertNotEqual(source.cameraReading(), .unreadable,
                          "CoreMediaIO camera signal unreadable, so the gate would fail closed forever")
        XCTAssertNotEqual(source.microphoneReading(), .unreadable,
                          "CoreAudio microphone signal unreadable, so the gate would fail closed forever")
    }
}
