//
//  StatusStore.swift
//  PatchedUpdater
//
//  Reads update-status.json (written by the privileged daemon) and requests
//  update runs by dropping a trigger file. The menu bar app holds NO privilege:
//  it only reads a world-readable status file and writes a request into a
//  sticky (mode 1733) trigger directory the daemon watches.
//
//  Paths default to /Library/Application Support/Patched. Set the environment
//  variable PATCHED_UPDATER_DIR to point at a writable directory for local
//  development without the daemon installed.
//

import Foundation
import Combine

@MainActor
final class StatusStore: ObservableObject {

    @Published private(set) var status: UpdateStatus?
    @Published private(set) var loadError: String?
    @Published private(set) var lastTriggerAt: Date?
    @Published private(set) var lastTriggerError: String?
    /// True when the daemon-written os_update section says a blocking
    /// acknowledgement window should be presented (PAT-273).
    @Published private(set) var shouldShowBlockingPrompt = false
    /// PAT-1624: bumped every time the agent should *attempt* to present the
    /// blocking prompt: the timer tick, an unlock, or the daemon newly asking
    /// for one. `shouldShowBlockingPrompt` alone is not enough to drive the
    /// presentation: SwiftUI's `.onChange` compares values, so a flag that has
    /// been continuously true since the first attempt never fires again and a
    /// suppressed prompt would be cancelled rather than delayed.
    @Published private(set) var blockingPromptAttempt = 0

    let baseDir: URL

    private var statusURL: URL { baseDir.appendingPathComponent("update-status.json") }
    private var triggerDir: URL { baseDir.appendingPathComponent("triggers", isDirectory: true) }
    private var uninstallStatusURL: URL { baseDir.appendingPathComponent("uninstall-status.json") }

    private var watchSource: DispatchSourceFileSystemObject?
    private var pollTimer: Timer?
    private var blockingTimer: Timer?
    private var unlockObserver: NSObjectProtocol?

    private let minTriggerInterval: TimeInterval = 30
    /// Static so the governor can be built from it inside `init` before the
    /// instance is fully formed. Still the PAT-273 cadence, unchanged.
    static let blockingReminderInterval: TimeInterval = 2 * 3600  // every 2 hours

    // MARK: PAT-1624 never-interrupt gate

    /// The surface name carried on every suppression event and operator signal.
    static let blockingPromptSurface = "os_update_blocking_prompt"

    private let sessionState: UserSessionStateProviding
    /// PAT-1661: kept so requestOsDefer/requestRemovalDefer can log a marker
    /// write failure through the same sink the prompt governors already use,
    /// rather than inventing a second logging path.
    private let events: AgentEventSink
    let promptGovernor: PromptPresentationGovernor

    // MARK: PAT-1623 removal notify/defer surface

    /// One app currently blocking its own removal by staying open. At most
    /// one is surfaced at a time (see evaluateRemovalPrompt); the daemon may
    /// be waiting on more, but stacking multiple removal windows is exactly
    /// the "two near-identical prompts" the PAT-1623 ruling rejects.
    struct PendingRemovalPrompt: Equatable {
        let entryId: Int
        let name: String
    }

    /// The surface name carried on every suppression event for this prompt —
    /// distinct from `blockingPromptSurface` so a quiet OS-update prompt does
    /// not silence removal, or vice versa (PromptPresentationGovernor's own
    /// contract).
    static let removalPromptSurface = "removal"

    let removalPromptGovernor: PromptPresentationGovernor
    let removalPolicy: RemovalPromptPolicy = .defaults

    @Published private(set) var pendingRemoval: PendingRemovalPrompt?
    /// Bumped only when a NEW app enters the deferred-running set (or on the
    /// first sighting) — never on every reload of an unchanged status file.
    /// Mirrors NotificationManager's posture-diffing restraint: "only fire
    /// when there were previously no [ids]" — here, only fire on ids not
    /// seen before. That is the "retry without re-notifying every cycle"
    /// requirement.
    @Published private(set) var removalPromptAttempt = 0

    private var uninstallStatus: UninstallStatus?
    private var knownDeferredRemovalIds: Set<Int> = []
    private var removalDeferCount = 0

    /// PAT-1623: "Managed tier only, fail closed." Starts false (fail closed)
    /// and is only ever raised by `applyRemovalTierGate`, driven from
    /// AgentConfigStore's tier the same way `applyInterruptionPolicy` is
    /// driven — see AgentMenuBarScene's `.onChange(of: configStore.tier)`.
    /// Anything other than exactly `.managed` — assurance, other, or no
    /// tier read yet — keeps this path entirely inert: no evaluation, no
    /// attempt, no window, ever.
    private(set) var isManagedTierForRemoval = false

    static var resolvedBaseDir: URL {
        if let override = ProcessInfo.processInfo.environment["PATCHED_UPDATER_DIR"], !override.isEmpty {
            return URL(fileURLWithPath: override, isDirectory: true)
        }
        return URL(fileURLWithPath: "/Library/Application Support/Patched", isDirectory: true)
    }

    /// Production callers use `StatusStore()`. Every parameter exists so the
    /// never-interrupt bounds can be exercised without a real camera, a real
    /// call or a two-hour wait.
    init(
        baseDir: URL? = nil,
        gate: InterruptionGate = InterruptionGate(),
        policy: InterruptionPolicy = .defaults,
        sessionState: UserSessionStateProviding = SystemUserSessionState(),
        events: AgentEventSink? = nil,
        operatorSignal: OperatorSignalSink? = nil,
        observing: Bool = true
    ) {
        let resolvedBase = baseDir ?? Self.resolvedBaseDir
        self.baseDir = resolvedBase
        self.sessionState = sessionState

        let sink = events ?? AgentEventLog()
        self.events = sink
        self.promptGovernor = PromptPresentationGovernor(
            surface: Self.blockingPromptSurface,
            gate: gate,
            policy: policy,
            retryInterval: Self.blockingReminderInterval,
            events: sink,
            operatorSignal: operatorSignal ?? TriggerDirectoryOperatorSignal(
                triggerDirectory: resolvedBase.appendingPathComponent("triggers", isDirectory: true),
                events: sink
            )
        )
        // PAT-1623: a second, independent governor instance for the removal
        // surface. Same InterruptionGate/retry cadence (that timing bound is
        // genuinely shared, see RemovalPromptPolicy's header comment) but its
        // own counters, so a quiet OS-update prompt can never silence removal
        // or vice versa.
        self.removalPromptGovernor = PromptPresentationGovernor(
            surface: Self.removalPromptSurface,
            gate: gate,
            policy: policy,
            retryInterval: Self.blockingReminderInterval,
            events: sink,
            operatorSignal: operatorSignal ?? TriggerDirectoryOperatorSignal(
                triggerDirectory: resolvedBase.appendingPathComponent("triggers", isDirectory: true),
                events: sink
            )
        )

        reload()
        guard observing else { return }
        startWatching()
        startUnlockObservation()
        scheduleBlockingPromptTimer()
    }

    // MARK: - Reading status

    func reload() {
        let url = statusURL
        guard FileManager.default.fileExists(atPath: url.path) else {
            status = nil
            loadError = nil   // no file = first-run, not an error
            shouldShowBlockingPrompt = false
            reloadUninstallStatus()
            return
        }
        do {
            let data = try Data(contentsOf: url)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            status = try decoder.decode(UpdateStatus.self, from: data)
            loadError = nil
        } catch {
            loadError = "Could not read status: \(error.localizedDescription)"
        }
        evaluateBlockingPrompt()
        // Independent of update-status.json above: uninstall-status.json is a
        // separate file written by a separate daemon (patched-uninstall.sh,
        // PAT-376), and one existing without the other is a normal state on a
        // fresh install or a report-tier device.
        reloadUninstallStatus()
    }

    // MARK: - Removal notify/defer surface (PAT-1623)

    private func reloadUninstallStatus() {
        let url = uninstallStatusURL
        guard FileManager.default.fileExists(atPath: url.path) else {
            uninstallStatus = nil
            evaluateRemovalPrompt()
            return
        }
        do {
            let data = try Data(contentsOf: url)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            uninstallStatus = try decoder.decode(UninstallStatus.self, from: data)
        } catch {
            // Keep last-known-good rather than clearing an already-notified
            // prompt on a transient read failure (matches update-status.json's
            // own reload() behaviour above).
        }
        evaluateRemovalPrompt()
    }

    /// PAT-1623: managed tier only, fail closed. Driven from AgentConfigStore
    /// the same way `applyInterruptionPolicy` is — see AgentMenuBarScene.
    func applyRemovalTierGate(_ tier: Posture.Tier?) {
        isManagedTierForRemoval = (tier == .managed)
        evaluateRemovalPrompt()
    }

    private func evaluateRemovalPrompt() {
        guard isManagedTierForRemoval else {
            // Fail closed: never attempts, never shows, regardless of what
            // the daemon wrote. Reset the dedup set too, so a later upgrade
            // to managed tier treats every currently-deferred app as newly
            // seen rather than silently swallowing its one notification.
            pendingRemoval = nil
            knownDeferredRemovalIds = []
            return
        }

        let deferred = (uninstallStatus?.removals ?? []).filter { $0.outcome == .deferredAppRunning }
        let currentIds = Set(deferred.map(\.entryId))
        let newIds = currentIds.subtracting(knownDeferredRemovalIds)
        knownDeferredRemovalIds = currentIds

        guard let first = deferred.first else {
            pendingRemoval = nil
            return
        }
        pendingRemoval = PendingRemovalPrompt(entryId: first.entryId, name: first.name)

        // A newly-deferred app is a fresh attempt opportunity; an app that
        // was already known-deferred on the previous read is not — that is
        // the "retry without re-notifying every cycle" requirement. The
        // governor's own suppression retry (camera/mic/etc.) is unaffected:
        // this only gates whether evaluateRemovalPrompt itself asks for a
        // new attempt, not whether an in-flight suppressed attempt keeps
        // being retried.
        if !newIds.isEmpty { requestRemovalPromptAttempt() }
    }

    /// PAT-1623: ask the scene to try again for the removal surface. Never
    /// presents anything itself — attemptRemovalPromptPresentation below is
    /// the one call site that decides.
    func requestRemovalPromptAttempt() {
        guard pendingRemoval != nil else { return }
        removalPromptAttempt &+= 1
    }

    /// The one call site every removal notify/defer prompt goes through.
    ///
    /// "Queue, do not stack" (PAT-1623 ruling): the OS-update prompt has a
    /// real deadline and always wins a same-tick collision, so removal only
    /// gets a turn when the OS-update surface does not currently want the
    /// screen at all. That check is unconditional on `shouldShowBlockingPrompt`
    /// rather than on the OS-update governor's own outcome, deliberately: an
    /// OS-update attempt that is itself being suppressed by the interruption
    /// gate this tick is still "the OS-update surface's turn", not an opening
    /// for removal to slip through underneath it.
    @discardableResult
    func attemptRemovalPromptPresentation(
        now: Date = Date(),
        present: (StatusStore) -> Void
    ) -> PromptPresentationGovernor.Outcome {
        guard isManagedTierForRemoval, pendingRemoval != nil else { return .absent }
        guard !shouldShowBlockingPrompt else { return .absent }

        let outcome = removalPromptGovernor.evaluate(now: now, sessionActive: sessionState.isActiveAndUnlocked)
        switch outcome {
        case .present:
            present(self)
        case .notificationFallback:
            NotificationManager.shared.fireRemovalPromptFallback(appName: pendingRemoval?.name, now: now)
        case .absent, .suppressed, .silent:
            break
        }
        return outcome
    }

    /// Drop a `removal_defer` marker — the "os_defer shape" the ticket asks
    /// for, mirroring `requestOsDefer()` below field-for-field except for the
    /// app identity (removal is per-app; the OS update is one global clock).
    /// PAT-1620 accepted-type list extended for this ticket: see
    /// TriggerRequestValidator (Windows) and patched-update.sh's trigger
    /// parser/consumer (macOS) for the matching addition and the "why not
    /// reuse os_defer" reasoning — the two deferral budgets are unrelated and
    /// must never be tallied against each other.
    ///
    /// This never touches the daemon's existing automatic DeferredAppRunning
    /// retry (PAT-376): that already runs next cycle regardless of whether
    /// anyone ever presses this button. It only (a) gives the daemon a marker
    /// it can tally for its own audit evidence of "waiting on the user", and
    /// (b) clears the local prompt so it is not re-shown until the next state
    /// change (see evaluateRemovalPrompt's id-diffing) — never gated on the
    /// tally itself, per RemovalPromptPolicy.canAlwaysDefer.
    func requestRemovalDefer(pending: PendingRemovalPrompt) {
        let fm = FileManager.default
        if !fm.fileExists(atPath: triggerDir.path) {
            try? fm.createDirectory(at: triggerDir, withIntermediateDirectories: true)
        }
        removalDeferCount &+= 1
        _ = removalPolicy.canAlwaysDefer(deferralCount: removalDeferCount) // always true; see RemovalPromptPolicy
        let marker: [String: Any] = [
            "type": "removal_defer",
            "entry_id": pending.entryId,
            "name": pending.name,
            "deferred_at": ISO8601DateFormatter().string(from: Date()),
            "requested_by": NSUserName()
        ]
        let fileURL = triggerDir.appendingPathComponent("removal_defer_\(UUID().uuidString).trigger")
        guard let data = try? JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys]) else { return }
        // PAT-1661: mirrors requestOsDefer's own fix, bundled together per the
        // ticket so removal_defer is not left inconsistent with os_defer. A
        // failed write loses the only audit evidence the user was asked to
        // defer, so it is logged. The dismiss below is unchanged either way.
        do {
            try data.write(to: fileURL, options: [.atomic])
        } catch {
            events.error("removal_defer marker write failed", [
                "error": error.localizedDescription,
                "entry_id": pending.entryId,
                "name": pending.name
            ])
        }
        // Dismiss the local prompt optimistically, exactly like requestOsDefer
        // does for the OS-update prompt; the next daemon run is authoritative.
        pendingRemoval = nil
    }

    /// The daemon writes status atomically (rename), so watching the directory
    /// survives inode changes. A 20-second poll backstops missed events.
    private func startWatching() {
        let fd = open(baseDir.path, O_EVTONLY)
        if fd >= 0 {
            let source = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: fd,
                eventMask: [.write, .rename, .delete],
                queue: .main
            )
            source.setEventHandler { [weak self] in
                Task { @MainActor in self?.reload() }
            }
            source.setCancelHandler { close(fd) }
            source.resume()
            watchSource = source
        }

        pollTimer = Timer.scheduledTimer(withTimeInterval: 20, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.reload() }
        }
    }

    // MARK: - Requesting a run

    func requestScan() {
        if let last = lastTriggerAt, Date().timeIntervalSince(last) < minTriggerInterval {
            lastTriggerError = "Please wait a moment before requesting another run."
            return
        }

        let fm = FileManager.default
        if !fm.fileExists(atPath: triggerDir.path) {
            do {
                try fm.createDirectory(at: triggerDir, withIntermediateDirectories: true)
            } catch {
                lastTriggerError = "Updater is not installed correctly (no trigger directory)."
                return
            }
        }

        let request: [String: Any] = [
            "type": "scan",
            "labels": ["*"],
            "requested_by": NSUserName(),
            "requested_at": ISO8601DateFormatter().string(from: Date()),
            "source": "self-service"
        ]

        let fileURL = triggerDir.appendingPathComponent(UUID().uuidString + ".trigger")
        do {
            let data = try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys])
            try data.write(to: fileURL, options: [.atomic])
            lastTriggerAt = Date()
            lastTriggerError = nil
        } catch {
            lastTriggerError = "Could not request scan: \(error.localizedDescription)"
        }
    }

    // MARK: - OS update blocking prompt (PAT-273)

    private func evaluateBlockingPrompt() {
        let wasShowing = shouldShowBlockingPrompt
        shouldShowBlockingPrompt = status?.osUpdate?.requiresBlockingPrompt ?? false
        // A newly-required prompt is an attempt opportunity in its own right;
        // the 2-hour timer and the unlock observer supply the rest.
        if shouldShowBlockingPrompt && !wasShowing { requestBlockingPromptAttempt() }
    }

    /// PAT-1624: ask the scene to try again. Never presents anything itself:
    /// the gate decision happens in `attemptBlockingPromptPresentation`.
    func requestBlockingPromptAttempt() {
        guard shouldShowBlockingPrompt else { return }
        blockingPromptAttempt &+= 1
    }

    /// The one call site every OS-update blocking prompt goes through.
    ///
    /// The window only ever appears on `.present`. Every other outcome leaves
    /// `shouldShowBlockingPrompt` exactly as it was, so the next timer tick or
    /// unlock tries again: suppression delays, it never cancels.
    ///
    /// Nothing on this path touches `deferrals_remaining`. `requestOsDefer()`
    /// is the only thing in this file that spends a deferral and only a human
    /// pressing Defer reaches it.
    @discardableResult
    func attemptBlockingPromptPresentation(
        now: Date = Date(),
        present: (StatusStore) -> Void
    ) -> PromptPresentationGovernor.Outcome {
        guard shouldShowBlockingPrompt else { return .absent }

        let outcome = promptGovernor.evaluate(now: now, sessionActive: sessionState.isActiveAndUnlocked)
        switch outcome {
        case .present:
            present(self)
        case .notificationFallback:
            NotificationManager.shared.fireBlockingPromptFallback(osUpdate: status?.osUpdate, now: now)
        case .absent, .suppressed, .silent:
            break
        }
        return outcome
    }

    /// Apply the `interruption_policy` block from the signed agent config.
    /// Managed tier only; every other tier keeps the shipped defaults.
    func applyInterruptionPolicy(overrides: InterruptionPolicyOverrides?, tier: Posture.Tier?) {
        promptGovernor.updatePolicy(.resolve(overrides: overrides, tier: tier))
    }

    /// Drop an os_defer marker into the triggers directory. The daemon tallies
    /// these on its next run to decrement deferrals_remaining in os_update.
    func requestOsDefer() {
        let fm = FileManager.default
        if !fm.fileExists(atPath: triggerDir.path) {
            try? fm.createDirectory(at: triggerDir, withIntermediateDirectories: true)
        }
        let marker: [String: Any] = [
            "type": "os_defer",
            "deferred_at": ISO8601DateFormatter().string(from: Date()),
            "requested_by": NSUserName()
        ]
        let fileURL = triggerDir.appendingPathComponent("os_defer_\(UUID().uuidString).trigger")
        guard let data = try? JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys]) else { return }
        // PAT-1661: a failed write here loses the daemon's only audit evidence
        // that the user was asked to defer, so it is logged rather than
        // silently discarded. This does not change the dismiss below: the
        // prompt still clears optimistically on both success and failure,
        // exactly as before.
        do {
            try data.write(to: fileURL, options: [.atomic])
        } catch {
            events.error("os_defer marker write failed", ["error": error.localizedDescription])
        }
        // Dismiss the prompt optimistically; the next daemon run reconciles.
        shouldShowBlockingPrompt = false
    }

    private func startUnlockObservation() {
        unlockObserver = DistributedNotificationCenter.default().addObserver(
            forName: NSNotification.Name("com.apple.screenIsUnlocked"),
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.reload()
                // PAT-1624: unlock is an attempt opportunity. Re-assigning the
                // same `true` to shouldShowBlockingPrompt used to be the way
                // this re-fired, but SwiftUI's `.onChange` compares values and
                // ignores an equal one, so a prompt suppressed on the previous
                // tick was never retried. The attempt counter always changes.
                self?.requestBlockingPromptAttempt()
                // PAT-1623: same reasoning for removal. Also covers the case
                // where removal was queued behind a same-tick OS-update
                // prompt (attemptRemovalPromptPresentation's "queue, do not
                // stack" check) — once that OS-update need clears, removal
                // needs its own attempt opportunity to ever get shown, since
                // evaluateRemovalPrompt only requests one on a *new* app
                // arriving, not on the OS-update prompt getting out of the
                // way.
                self?.requestRemovalPromptAttempt()
            }
        }
    }

    private func scheduleBlockingPromptTimer() {
        blockingTimer = Timer.scheduledTimer(
            withTimeInterval: Self.blockingReminderInterval,
            repeats: true
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.reload()
                self?.requestBlockingPromptAttempt()
                self?.requestRemovalPromptAttempt()
            }
        }
    }
}
