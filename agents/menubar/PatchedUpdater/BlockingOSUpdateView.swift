//
//  BlockingOSUpdateView.swift
//  PatchedUpdater
//
//  Foreground Nudge-style acknowledgement window (PAT-273).
//  Summoned by StatusStore on screen unlock and every 2 hours when
//  os_update.requiresBlockingPrompt is true.
//
//  NEVER forces or silently installs the OS — "Update now" only ever
//  deep-links to Software Update. At deferrals == 0 the Defer button is
//  disabled but the window remains dismissible; it simply reappears on the
//  cadence. We do not lock the machine.
//

import SwiftUI
import AppKit

// MARK: - Window controller

final class BlockingUpdateWindowController: NSWindowController {
    static let shared = BlockingUpdateWindowController()

    private init() {
        let window = PromptWindowShell.makeWindow(title: "macOS Update Required — Patched")
        super.init(window: window)
    }

    required init?(coder: NSCoder) { fatalError() }

    func present(store: StatusStore) {
        guard let osUpdate = store.status?.osUpdate else { return }
        let view = BlockingOSUpdateView(osUpdate: osUpdate, store: store)
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

struct BlockingOSUpdateView: View {
    let osUpdate: UpdateStatus.OsUpdate
    @ObservedObject var store: StatusStore

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider().overlay(Brand.rule)
            detail
            Divider().overlay(Brand.rule)
            actionBar
        }
        .background(Brand.snow)
        .frame(width: 480)
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: headerIcon)
                .font(.system(size: 28, weight: .light))
                .foregroundStyle(headerColor)
            VStack(alignment: .leading, spacing: 4) {
                Text(headerTitle)
                    .font(Brand.display(17))
                    .foregroundStyle(Brand.slate)
                Text(headerSubtitle)
                    .font(Brand.sans(12))
                    .foregroundStyle(Brand.mute)
            }
            Spacer()
        }
        .padding(20)
    }

    private var headerIcon: String {
        osUpdate.state == .deadlinePassed ? "exclamationmark.triangle" : "exclamationmark.circle"
    }

    private var headerColor: Color {
        osUpdate.severity == .critical
            ? Color(red: 0.8, green: 0.1, blue: 0.1)
            : Brand.signal
    }

    private var headerTitle: String {
        switch osUpdate.state {
        case .deadlinePassed: return "macOS update overdue"
        default:              return osUpdate.targetOs.map { "macOS \($0) required" } ?? "macOS update required"
        }
    }

    private var headerSubtitle: String {
        if osUpdate.activelyExploited {
            return "This update fixes an actively exploited security vulnerability."
        } else if osUpdate.securityRelevant {
            return "This update contains important security fixes."
        }
        return "Your organisation requires this macOS version."
    }

    // MARK: - Detail

    private var detail: some View {
        VStack(alignment: .leading, spacing: 10) {
            versionRow
            if let deadline = osUpdate.deadline {
                detailRow(
                    icon: "calendar",
                    label: osUpdate.state == .deadlinePassed ? "Deadline" : "Required by",
                    value: deadline.formatted(date: .long, time: .omitted)
                )
            }
            detailRow(
                icon: "arrow.down.circle",
                label: "Installed",
                value: osUpdate.installedOs
            )
            if osUpdate.state != .deadlinePassed {
                deferralRow
            }
        }
        .padding(20)
    }

    private var versionRow: some View {
        detailRow(
            icon: "apple.logo",
            label: "Available",
            value: osUpdate.targetOs ?? "Unknown"
        )
    }

    private var deferralRow: some View {
        HStack(spacing: 8) {
            Image(systemName: "clock")
                .font(.system(size: 13))
                .foregroundStyle(Brand.mute)
                .frame(width: 18)
            Text("Deferrals remaining")
                .font(Brand.sans(12))
                .foregroundStyle(Brand.mute)
            Spacer()
            Text("\(osUpdate.deferralsRemaining)")
                .font(Brand.mono(12, weight: .medium))
                .foregroundStyle(osUpdate.deferralsRemaining == 0 ? Brand.signal : Brand.slate)
        }
    }

    private func detailRow(icon: String, label: String, value: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 13))
                .foregroundStyle(Brand.mute)
                .frame(width: 18)
            Text(label)
                .font(Brand.sans(12))
                .foregroundStyle(Brand.mute)
            Spacer()
            Text(value)
                .font(Brand.mono(12, weight: .medium))
                .foregroundStyle(Brand.slate)
        }
    }

    // MARK: - Action bar

    private var actionBar: some View {
        HStack {
            if osUpdate.state != .deadlinePassed {
                deferButton
            }
            Spacer()
            updateNowButton
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    @ViewBuilder
    private var deferButton: some View {
        let canDefer = osUpdate.deferralsRemaining > 0
        Button {
            store.requestOsDefer()
            BlockingUpdateWindowController.shared.dismiss()
        } label: {
            Text("Defer")
                .font(Brand.sans(13))
                .foregroundStyle(canDefer ? Brand.mute : Brand.mute.opacity(0.4))
        }
        .buttonStyle(.plain)
        .disabled(!canDefer)
    }

    private var updateNowButton: some View {
        Button {
            NSWorkspace.shared.open(
                URL(string: "x-apple.systempreferences:com.apple.preferences.softwareupdate")!
            )
            BlockingUpdateWindowController.shared.dismiss()
        } label: {
            Text("Update now")
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
