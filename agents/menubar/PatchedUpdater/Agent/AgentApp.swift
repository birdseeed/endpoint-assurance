//
//  AgentApp.swift
//  PatchedUpdater — Agent (PAT-476)
//
//  The posture-driven menu-bar agent scene: a `MenuBarExtra` that shows the
//  ring-mark tray icon (state badge from posture) and the glanceable posture
//  popover. This is the app's only scene: the legacy deploy-focused window
//  and its Self Service hand-offs were removed in PAT-1619.
//
//  Data flow (read-only, no credentials):
//    PostureStore  →  AgentPostureModel  →  TrayIcon + PopoverView
//
//  `AgentPostureModel` owns the posture business logic (tray state derivation
//  and staleness flag). `PostureStore` is the file-watch reader that
//  PosturePreviewProvider replaces for local dev / previews.
//
//  `StatusStore` is threaded into the scene (not the model) solely so the
//  OS-update blocking prompt keeps firing after PAT-1619, see the `onChange`
//  in `AgentMenuBarScene.body` below.
//
//  No MDM. No remote control: the agent is strictly read-only. It never
//  writes a trigger and never launches another app on the user's behalf.
//

import SwiftUI

// MARK: - Observable posture model

/// Drives both `TrayIcon` and `PopoverView` from a single source of truth.
/// Owns tray-state derivation and staleness.
@MainActor
final class AgentPostureModel: ObservableObject {

    // MARK: Published state

    @Published private(set) var posture: Posture?
    @Published private(set) var loadError: String?
    @Published private(set) var trayState: TrayState = .clean

    // MARK: Staleness

    /// True when the cached posture is older than PostureStore.staleThreshold.
    var isStale: Bool {
        if _simulateStale { return true }
        guard let generatedAt = posture?.generatedAt else { return false }
        return Date().timeIntervalSince(generatedAt) > PostureStore.staleThreshold
    }

    /// Internal flag used only by previews; production always uses PostureStore.
    var _simulateStale: Bool = false

    // MARK: - Init (live — wired to PostureStore)

    private var postureStore: PostureStore?

    /// Production init: observes the PostureStore file-watch reader.
    convenience init(store: PostureStore) {
        self.init(posture: store.posture)
        self.postureStore = store
        // Observe published changes from PostureStore.
        // We hold a strong ref to the store; the store's own lifecycle is
        // managed by PatchedUpdaterApp (via @StateObject).
        updateFromStore(store)
    }

    func updateFromStore(_ store: PostureStore) {
        posture   = store.posture
        loadError = store.loadError
        // scanning: collector hasn't delivered a result yet (no error either)
        if store.posture == nil && store.loadError == nil {
            trayState = .scanning
            return
        }
        // offline: cached posture exists but is stale
        if store.posture != nil && isStale {
            trayState = .offline
            return
        }
        trayState = deriveTrayState(from: store.posture)
    }

    // MARK: - Init (stub — for previews / PosturePreviewProvider)

    init(posture: Posture?) {
        self.posture   = posture
        self.trayState = deriveTrayState(from: posture)
    }

    // MARK: - Tray state derivation

    private func deriveTrayState(from posture: Posture?) -> TrayState {
        guard let posture else { return .clean }

        // Critical: any HIGH or CRITICAL severity CVE finding
        let hasHighCritical = posture.findings?.contains {
            $0.severity.uppercased() == "HIGH" || $0.severity.uppercased() == "CRITICAL"
        } ?? false
        if hasHighCritical { return .critical }

        // Issues: pending updates, compliance failures, or app policy drift
        let hasUpdates    = !(posture.updates ?? []).isEmpty
        let hasDrift      = !(posture.appPolicy?.drift ?? []).isEmpty
        let hasMediumCVEs = !(posture.findings ?? []).isEmpty
        let hasFailures   = (posture.compliance.primary?.failed ?? 0) > 0
        if hasUpdates || hasDrift || hasMediumCVEs || hasFailures { return .issues }

        return .clean
    }

    // MARK: - Manual refresh

    /// Re-reads the local posture cache immediately rather than waiting for
    /// the next file-watch event or 60-second poll. Read-only: this just
    /// re-parses the same on-disk cache PostureStore already watches, no
    /// network call and no privilege. Backs the Offline panel's Retry row.
    func retryLoad() {
        postureStore?.reload()
    }
}

// MARK: - MenuBarExtra scene builder

/// The posture agent's `MenuBarExtra` scene, and (since PAT-1619) the app's
/// only scene. Called from `PatchedUpdaterApp.body`.
///
/// `statusStore` is threaded through only to keep the OS-update blocking
/// prompt firing: it used to be summoned from an `onChange` on the now-removed
/// Deploy window; that observation is rehosted here so PAT-273's deadline
/// prompt is unaffected by the window's removal.
///
/// Usage:
/// ```swift
/// var body: some Scene {
///     AgentMenuBarScene(store: postureStore, statusStore: statusStore, configStore: configStore)
/// }
/// ```
struct AgentMenuBarScene: Scene {
    @ObservedObject var store: PostureStore
    @ObservedObject var statusStore: StatusStore
    @ObservedObject var configStore: AgentConfigStore
    @StateObject private var model: AgentPostureModel

    init(store: PostureStore, statusStore: StatusStore, configStore: AgentConfigStore) {
        self.store = store
        self.statusStore = statusStore
        self.configStore = configStore
        // @StateObject requires a wrappedValue init with an autoclosure.
        // We initialise with the store's current snapshot; live updates flow
        // via .onChange below.
        _model = StateObject(wrappedValue: AgentPostureModel(store: store))
    }

    var body: some Scene {
        MenuBarExtra {
            PopoverView(model: model)
        } label: {
            TrayIcon(state: model.trayState)
        }
        .menuBarExtraStyle(.window)
        .onChange(of: store.posture?.generatedAt) { _ in
            model.updateFromStore(store)
        }
        .onChange(of: store.loadError) { _ in
            model.updateFromStore(store)
        }
        // PAT-1624: managed-tier bounds for the never-interrupt gate. Resolved
        // in AgentConfigStore (which enforces the managed-tier-only rule), so
        // this only has to hand the result to the governor.
        .onChange(of: configStore.interruptionPolicy) { policy in
            statusStore.promptGovernor.updatePolicy(policy)
            statusStore.removalPromptGovernor.updatePolicy(policy)
        }
        // PAT-1623: removal's own tier gate — "Managed tier only, fail
        // closed" — is independent of the interruption-policy overrides
        // above (those apply at managed tier too, but a report/patch tenant
        // must never even attempt a removal prompt, overrides or not).
        .onChange(of: configStore.tier) { tier in
            statusStore.applyRemovalTierGate(tier)
        }
        // PAT-273 / PAT-1619: the blocking OS-update deadline prompt used to be
        // summoned from an onChange on the legacy Deploy window. Rehosted here
        // so it keeps firing now that window is gone.
        //
        // PAT-1624: it is driven off `blockingPromptAttempt` rather than
        // `shouldShowBlockingPrompt` because the gate can turn any given
        // attempt into silence, and the retry has to be able to fire again
        // while the flag stays continuously true. The window itself only ever
        // appears on a `.present` outcome, and the store owns that decision, so
        // every future prompt surface (PAT-1623 removal next) gets the same
        // gate by going through the same call.
        .onChange(of: statusStore.blockingPromptAttempt) { _ in
            statusStore.attemptBlockingPromptPresentation { store in
                BlockingUpdateWindowController.shared.present(store: store)
            }
        }
        // PAT-1623: the removal notify/defer surface promised above, now
        // wired through the same never-interrupt gate and the same
        // attempt-counter pattern as the OS-update prompt it shares a window
        // shell with. `attemptRemovalPromptPresentation` itself enforces
        // "queue, do not stack" against `shouldShowBlockingPrompt`.
        .onChange(of: statusStore.removalPromptAttempt) { _ in
            statusStore.attemptRemovalPromptPresentation { store in
                RemovalPromptWindowController.shared.present(store: store)
            }
        }
    }
}
