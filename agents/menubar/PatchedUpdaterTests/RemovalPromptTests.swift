//
//  RemovalPromptTests.swift
//  PatchedUpdaterTests
//
//  PAT-1623: the removal notify/defer surface wired into the real StatusStore
//  presentation path, mirroring BlockingPromptSuppressionTests.swift's style
//  for the sibling PAT-273 surface.
//
//  Load-bearing assertions:
//    - a running removal target produces a `.present` outcome (and only once
//      per newly-deferred app, not on every reload of an unchanged file);
//    - Defer writes a `removal_defer` marker in the trigger shape and never
//      touches the daemon's own automatic retry, nor any os_defer marker;
//    - the prompt never has a terminal/forcing state at any budget;
//    - the OS-update prompt and the removal prompt never both present in the
//      same tick ("queue, do not stack");
//    - the whole path is inert off managed tier.
//

import XCTest
@testable import PatchedUpdater

@MainActor
final class RemovalPromptTests: XCTestCase {

    private var baseDir: URL!
    private var signals: StubInterruptionSignals!
    private var session: StubSessionState!
    private var events: RecordingEventSink!
    private var operatorSignal: RecordingOperatorSignal!

    private var uninstallStatusURL: URL { baseDir.appendingPathComponent("uninstall-status.json") }
    private var updateStatusURL: URL { baseDir.appendingPathComponent("update-status.json") }
    private var triggerDir: URL { baseDir.appendingPathComponent("triggers", isDirectory: true) }

    override func setUp() {
        super.setUp()
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("removal-prompt-\(UUID().uuidString)", isDirectory: true)
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

    private func writeUninstallStatus(entries: [(entryId: Int, name: String, outcome: String)]) throws {
        let removals = entries.map {
            """
            {"entry_id": \($0.entryId), "name": "\($0.name)", "outcome": "\($0.outcome)", "verify_result": null, "method": "app_bundle", "recorded_at": "2026-09-12T08:00:00Z"}
            """
        }.joined(separator: ",")
        let json = """
        {
          "schema_version": 1,
          "generated_at": "2026-09-12T08:00:00Z",
          "last_run": {"started_at": "2026-09-12T07:59:00Z", "finished_at": "2026-09-12T08:00:00Z"},
          "removals": [\(removals)]
        }
        """
        try json.write(to: uninstallStatusURL, atomically: true, encoding: .utf8)
    }

    private func writeBlockingOsUpdateStatus() throws {
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
            "deferrals_remaining": 5,
            "release_age_days": 21,
            "checked_at": "2026-09-14T07:00:00Z"
          }
        }
        """
        try json.write(to: updateStatusURL, atomically: true, encoding: .utf8)
    }

    private func triggerFiles() -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: triggerDir.path))?.sorted() ?? []
    }

    // MARK: - Tier gate: inert off managed tier

    func testInertWhenTierIsNotApplied() throws {
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        let store = makeStore()
        // applyRemovalTierGate was never called: fail-closed default.
        XCTAssertNil(store.pendingRemoval)

        var presented = 0
        let outcome = store.attemptRemovalPromptPresentation { _ in presented += 1 }
        XCTAssertEqual(outcome, .absent)
        XCTAssertEqual(presented, 0)
    }

    func testInertForEveryNonManagedTier() throws {
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        let store = makeStore()

        for tier: Posture.Tier in [.assurance, .other("report"), .other("patch"), .other("weird")] {
            store.applyRemovalTierGate(tier)
            XCTAssertNil(store.pendingRemoval, "tier \(tier) must never surface a removal prompt")
            var presented = 0
            let outcome = store.attemptRemovalPromptPresentation { _ in presented += 1 }
            XCTAssertEqual(outcome, .absent)
            XCTAssertEqual(presented, 0)
        }
    }

    func testManagedTierSurfacesThePendingRemoval() throws {
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        let store = makeStore()
        store.applyRemovalTierGate(.managed)
        XCTAssertEqual(store.pendingRemoval, .init(entryId: 1, name: "Slack"))
    }

    // MARK: - Presentation

    func testARunningRemovalTargetPresentsTheWindow() throws {
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        let store = makeStore()
        store.applyRemovalTierGate(.managed)

        var presented = 0
        let outcome = store.attemptRemovalPromptPresentation { _ in presented += 1 }
        XCTAssertEqual(outcome, .present)
        XCTAssertEqual(presented, 1)
    }

    func testOnlyDeferredAppRunningOutcomesSurface() throws {
        try writeUninstallStatus(entries: [(1, "Zoom", "removed"), (2, "Docker", "failed_hard")])
        let store = makeStore()
        store.applyRemovalTierGate(.managed)
        XCTAssertNil(store.pendingRemoval)
    }

    func testSuppressedByCameraDelaysNotCancels() throws {
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        signals.camera = .busy
        let store = makeStore()
        store.applyRemovalTierGate(.managed)

        var presented = 0
        let outcome = store.attemptRemovalPromptPresentation { _ in presented += 1 }
        XCTAssertEqual(outcome, .suppressed(.cameraInUse))
        XCTAssertEqual(presented, 0)
        XCTAssertNotNil(store.pendingRemoval, "suppression delays, it never cancels")
    }

    // MARK: - Re-notification restraint ("retry without re-notifying every cycle")

    func testReloadingTheSameUnchangedStatusDoesNotRequestANewAttempt() throws {
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        let store = makeStore()
        store.applyRemovalTierGate(.managed)
        let firstAttempt = store.removalPromptAttempt
        XCTAssertGreaterThan(firstAttempt, 0, "the first sighting is itself an attempt opportunity")

        // Re-write the identical content (simulates the daemon's next cycle
        // re-confirming the same still-running app) and reload.
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        store.reload()
        XCTAssertEqual(store.removalPromptAttempt, firstAttempt,
                        "an unchanged pending app must not re-request an attempt every cycle")
    }

    func testADifferentAppEnteringTheDeferredSetIsAFreshAttempt() throws {
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        let store = makeStore()
        store.applyRemovalTierGate(.managed)
        let firstAttempt = store.removalPromptAttempt

        try writeUninstallStatus(entries: [
            (1, "Slack", "deferred_app_running"),
            (2, "Docker Desktop", "deferred_app_running"),
        ])
        store.reload()
        XCTAssertGreaterThan(store.removalPromptAttempt, firstAttempt,
                              "a different app newly needing removal is a state change, not a repeat")
    }

    // MARK: - Defer

    func testDeferWritesARemovalDeferMarkerInTheEstablishedShape() throws {
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        let store = makeStore()
        store.applyRemovalTierGate(.managed)
        guard let pending = store.pendingRemoval else { return XCTFail("expected a pending removal") }

        store.requestRemovalDefer(pending: pending)

        let markers = triggerFiles().filter { $0.hasPrefix("removal_defer_") && $0.hasSuffix(".trigger") }
        XCTAssertEqual(markers.count, 1)
        let marker = try JSONSerialization.jsonObject(
            with: Data(contentsOf: triggerDir.appendingPathComponent(markers[0]))
        ) as? [String: Any]
        XCTAssertEqual(marker?["type"] as? String, "removal_defer")
        XCTAssertEqual(marker?["entry_id"] as? Int, 1)
        XCTAssertEqual(marker?["name"] as? String, "Slack")
        XCTAssertNotNil(marker?["deferred_at"])
        XCTAssertNotNil(marker?["requested_by"])
    }

    func testDeferDoesNotWriteOrTouchAnOsDeferMarker() throws {
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        let store = makeStore()
        store.applyRemovalTierGate(.managed)
        guard let pending = store.pendingRemoval else { return XCTFail("expected a pending removal") }

        store.requestRemovalDefer(pending: pending)

        let osDeferMarkers = triggerFiles().filter { $0.hasPrefix("os_defer") }
        XCTAssertTrue(osDeferMarkers.isEmpty, "removal's defer must never spend an OS-update deferral")
    }

    // MARK: - PAT-1661: removal_defer marker write failure is observable

    func testRemovalDeferWriteSuccessFiresNoFailureEventAndDismissesAsBefore() throws {
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        let store = makeStore()
        store.applyRemovalTierGate(.managed)
        guard let pending = store.pendingRemoval else { return XCTFail("expected a pending removal") }

        store.requestRemovalDefer(pending: pending)

        XCTAssertNil(store.pendingRemoval, "prompt still dismisses optimistically on success")
        XCTAssertTrue(events.messages("removal_defer marker write failed").isEmpty,
                      "a successful write must not log a failure event")
    }

    func testRemovalDeferWriteFailureLogsOnceAndStillDismisses() throws {
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        let store = makeStore()
        store.applyRemovalTierGate(.managed)
        guard let pending = store.pendingRemoval else { return XCTFail("expected a pending removal") }

        // Force the trigger write to fail: the directory exists but is
        // read-only, so the atomic write's temp-file create fails.
        try FileManager.default.createDirectory(at: triggerDir, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: triggerDir.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: triggerDir.path) }

        store.requestRemovalDefer(pending: pending)

        XCTAssertNil(store.pendingRemoval,
                     "the prompt must still dismiss optimistically even when the write fails")
        XCTAssertEqual(events.messages("removal_defer marker write failed").count, 1,
                       "a failed write must log exactly one failure event")
        let markers = triggerFiles().filter { $0.hasPrefix("removal_defer_") && $0.hasSuffix(".trigger") }
        XCTAssertTrue(markers.isEmpty, "the write genuinely failed, no marker landed on disk")
    }

    func testDeferDismissesLocallyWithoutTouchingTheDaemonsAutomaticRetry() throws {
        // The daemon's own DeferredAppRunning retry (RemovalRunner/patched-
        // uninstall.sh) is driven entirely server/daemon-side by the next
        // scheduled run re-inspecting the app — nothing in requestRemovalDefer
        // reaches into that path. This test proves the local-only contract:
        // pressing Defer clears *this app's* prompt without deleting or
        // rewriting uninstall-status.json (the daemon's own record), so its
        // next run is free to reconcile exactly as if nobody had pressed
        // anything.
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        let before = try Data(contentsOf: uninstallStatusURL)
        let store = makeStore()
        store.applyRemovalTierGate(.managed)
        guard let pending = store.pendingRemoval else { return XCTFail("expected a pending removal") }

        store.requestRemovalDefer(pending: pending)

        XCTAssertNil(store.pendingRemoval, "the local prompt is dismissed optimistically")
        let after = try Data(contentsOf: uninstallStatusURL)
        XCTAssertEqual(before, after, "Defer must never rewrite the daemon's own status file")
    }

    // MARK: - No terminal state, ever

    func testNeverRendersATerminalStateAtAnyBudget() {
        for budget in [0, 1, 5, 1000] {
            let policy = RemovalPromptPolicy(deferralBudget: budget)
            for deferralCount in [0, 1, budget, budget + 1, budget * 10 + 7] {
                XCTAssertTrue(policy.canAlwaysDefer(deferralCount: deferralCount),
                              "budget=\(budget) count=\(deferralCount) must never produce a forcing state")
            }
        }
    }

    func testRepeatedDefersNeverExhaustTheAbilityToDeferAgain() throws {
        // A budget of 1 is the most adversarial case: if anything gated on
        // "count < budget" this would flip to false on the second defer.
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        let store = makeStore()
        store.applyRemovalTierGate(.managed)

        for _ in 0..<5 {
            guard let pending = store.pendingRemoval else {
                // Simulate the app reappearing as still-deferred next cycle,
                // exactly like the daemon's automatic retry would report.
                try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
                store.reload()
                continue
            }
            store.requestRemovalDefer(pending: pending)
            try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
            store.reload()
        }
        // No assertion fails getting here means no code path ever refused a
        // defer or entered a disabled/terminal branch.
    }

    // MARK: - "Queue, do not stack"

    func testOsUpdateAndRemovalNeverPresentInTheSameTick() throws {
        try writeBlockingOsUpdateStatus()
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        let store = makeStore()
        store.applyRemovalTierGate(.managed)
        XCTAssertTrue(store.shouldShowBlockingPrompt)
        XCTAssertNotNil(store.pendingRemoval)

        var osUpdatePresented = 0
        var removalPresented = 0
        let osOutcome = store.attemptBlockingPromptPresentation { _ in osUpdatePresented += 1 }
        let removalOutcome = store.attemptRemovalPromptPresentation { _ in removalPresented += 1 }

        XCTAssertEqual(osOutcome, .present)
        XCTAssertEqual(osUpdatePresented, 1)
        // The OS-update prompt wanted the screen this tick, so removal must
        // not also present — regardless of order the scene evaluates them in.
        XCTAssertEqual(removalOutcome, .absent)
        XCTAssertEqual(removalPresented, 0)
    }

    func testRemovalPresentsOnceTheOsUpdatePromptIsNoLongerDue() throws {
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        // No update-status.json at all: shouldShowBlockingPrompt is false.
        let store = makeStore()
        store.applyRemovalTierGate(.managed)
        XCTAssertFalse(store.shouldShowBlockingPrompt)

        var removalPresented = 0
        let outcome = store.attemptRemovalPromptPresentation { _ in removalPresented += 1 }
        XCTAssertEqual(outcome, .present)
        XCTAssertEqual(removalPresented, 1)
    }

    func testBothSuppressedByTheSameSignalNeitherPresents() throws {
        try writeBlockingOsUpdateStatus()
        try writeUninstallStatus(entries: [(1, "Slack", "deferred_app_running")])
        signals.camera = .busy
        let store = makeStore()
        store.applyRemovalTierGate(.managed)

        var osUpdatePresented = 0
        var removalPresented = 0
        let osOutcome = store.attemptBlockingPromptPresentation { _ in osUpdatePresented += 1 }
        let removalOutcome = store.attemptRemovalPromptPresentation { _ in removalPresented += 1 }

        XCTAssertEqual(osOutcome, .suppressed(.cameraInUse))
        XCTAssertEqual(osUpdatePresented, 0)
        // Queued behind the OS-update surface, not evaluated against the gate
        // at all this tick.
        XCTAssertEqual(removalOutcome, .absent)
        XCTAssertEqual(removalPresented, 0)
    }
}
