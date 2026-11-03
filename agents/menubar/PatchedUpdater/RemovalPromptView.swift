//
//  RemovalPromptView.swift
//  PatchedUpdater
//
//  PAT-1623: the notify/defer surface PAT-1598 promises for app removal.
//  "Never take a running application with unsaved work" is an end-user
//  interaction, and the application that used to own end-user interaction
//  (Self Service) was deleted under PAT-1617. This is the replacement surface
//  in the menu bar agent.
//
//  Deliberately NOT modelled on BlockingOSUpdateView beyond the shared window
//  shell (PromptWindowShell) and layout language:
//    - no countdown, no deadline row, no "required by" copy
//    - no deferrals-remaining count shown anywhere
//    - the Defer button is never disabled, under any policy or budget value
//      (RemovalPromptPolicy.canAlwaysDefer is always true) — the ruling is
//      explicit that removal has no terminal/forcing state, ever.
//  A removal that waits is fine; this window says so and gets out of the way.
//

import SwiftUI
import AppKit

// MARK: - Window controller

final class RemovalPromptWindowController: NSWindowController {
    static let shared = RemovalPromptWindowController()

    private init() {
        let window = PromptWindowShell.makeWindow(title: "App Removal Pending — Patched", height: 220)
        super.init(window: window)
    }

    required init?(coder: NSCoder) { fatalError() }

    func present(store: StatusStore) {
        guard let pending = store.pendingRemoval else { return }
        let view = RemovalPromptView(pending: pending, store: store)
        window?.contentView = NSHostingView(rootView: view)
        window?.center()
        NSApp.setActivationPolicy(.regular)
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func dismiss() {
        window?.orderOut(nil)
        NSApp.setActivationPolicy(.accessory)
    }
}

// MARK: - SwiftUI view

struct RemovalPromptView: View {
    let pending: StatusStore.PendingRemovalPrompt
    @ObservedObject var store: StatusStore

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider().overlay(Brand.rule)
            actionBar
        }
        .background(Brand.snow)
        .frame(width: 480)
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "app.dashed")
                .font(.system(size: 28, weight: .light))
                .foregroundStyle(Brand.signal)
            VStack(alignment: .leading, spacing: 6) {
                Text("\(pending.name) is still open")
                    .font(Brand.display(17))
                    .foregroundStyle(Brand.slate)
                // Plain language, no countdown, no threat: it names the app
                // and says what happens when it closes. Nothing else.
                Text("Your organisation has asked Patched to remove \(pending.name). It will be removed the next time you close it.")
                    .font(Brand.sans(12))
                    .foregroundStyle(Brand.mute)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(20)
    }

    // MARK: - Action bar

    private var actionBar: some View {
        HStack {
            deferButton
            Spacer()
            okButton
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    /// Never disabled. There is no "no deferrals remaining" state for
    /// removal at any budget (RemovalPromptPolicy.canAlwaysDefer, PAT-1623
    /// ruling) — unlike BlockingOSUpdateView's deferButton, which disables at
    /// deferralsRemaining == 0, this button has no such condition to check.
    private var deferButton: some View {
        Button {
            store.requestRemovalDefer(pending: pending)
            RemovalPromptWindowController.shared.dismiss()
        } label: {
            Text("Defer")
                .font(Brand.sans(13))
                .foregroundStyle(Brand.mute)
        }
        .buttonStyle(.plain)
    }

    private var okButton: some View {
        Button {
            RemovalPromptWindowController.shared.dismiss()
        } label: {
            Text("OK")
                .font(Brand.sans(13, weight: .medium))
                .foregroundStyle(.white)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(Brand.signal)
                .cornerRadius(6)
        }
        .buttonStyle(.plain)
    }
}
