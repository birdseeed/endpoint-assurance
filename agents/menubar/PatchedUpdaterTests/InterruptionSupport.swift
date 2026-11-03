//
//  InterruptionSupport.swift
//  PatchedUpdaterTests
//
//  PAT-1624 shared test doubles. The whole point of the signal seam is that the
//  bounds can be proven without a real camera, a real call or a two-hour wait,
//  so every collaborator the gate and the governor take has a stub here.
//

import Foundation
@testable import PatchedUpdater

// MARK: - Signals

final class StubInterruptionSignals: InterruptionSignalSource {
    var camera: SignalReading = .idle
    var microphone: SignalReading = .idle
    var presenting: SignalReading = .idle
    var focus: SignalReading = .idle

    init(camera: SignalReading = .idle,
         microphone: SignalReading = .idle,
         presenting: SignalReading = .idle,
         focus: SignalReading = .idle) {
        self.camera = camera
        self.microphone = microphone
        self.presenting = presenting
        self.focus = focus
    }

    func cameraReading() -> SignalReading { camera }
    func microphoneReading() -> SignalReading { microphone }
    func presentingReading() -> SignalReading { presenting }
    func focusReading() -> SignalReading { focus }

    /// Everything clear.
    func clear() {
        camera = .idle; microphone = .idle; presenting = .idle; focus = .idle
    }
}

// MARK: - Session

final class StubSessionState: UserSessionStateProviding {
    var isActiveAndUnlocked: Bool
    init(isActiveAndUnlocked: Bool = true) { self.isActiveAndUnlocked = isActiveAndUnlocked }
}

// MARK: - Event sink

final class RecordingEventSink: AgentEventSink, @unchecked Sendable {
    struct Entry {
        let level: String
        let msg: String
        let fields: [String: Any]
    }
    private(set) var entries: [Entry] = []

    func record(level: String, msg: String, fields: [String: Any]) {
        entries.append(Entry(level: level, msg: msg, fields: fields))
    }

    func messages(_ msg: String) -> [Entry] { entries.filter { $0.msg == msg } }

    /// Every string value recorded, flattened. Used to prove no application or
    /// session detail ever reaches an event.
    var allStringValues: [String] {
        entries.flatMap { entry in
            [entry.level, entry.msg] + entry.fields.values.compactMap { $0 as? String }
        }
    }
}

// MARK: - Operator signal

final class RecordingOperatorSignal: OperatorSignalSink, @unchecked Sendable {
    struct Raised {
        let surface: String
        let reason: InterruptionReason
        let since: Date
        let suppressedDays: Int
    }
    private(set) var raised: [Raised] = []
    private(set) var cleared: [String] = []

    func signalPromptUnreachable(surface: String, reason: InterruptionReason, since: Date, suppressedDays: Int) {
        raised.append(Raised(surface: surface, reason: reason, since: since, suppressedDays: suppressedDays))
    }

    func clearPromptUnreachable(surface: String) {
        cleared.append(surface)
    }
}
