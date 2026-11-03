//  PatchedMenuBarAgent.swift
//  Patched — macOS Menu Bar Agent
//
//  A "branded but native" MenuBarExtra: a first-party-feeling status utility
//  that surfaces Scan · Patch · Prove state and hands off to the Self Service
//  app for anything substantial. Nothing here depends on MDM; OS-update prompts
//  are Nudge-style (user-actioned), never forced.
//
//  Design tokens (Pivot/Quiet, native-tuned):
//    accent  signal orange  #f5530a  (one accent only)
//    secure  green · critical red · idle grey
//  Typography is the SYSTEM font; SF Mono is used for technical evidence
//  (versions, CVE IDs, benchmark refs). SF Symbols throughout.
//
//  Requires macOS 13+ (MenuBarExtra). Drop-in single file; wire your real
//  scanner/service into AgentModel.
//
//  swift-tools: SwiftUI

import SwiftUI

// MARK: - Brand palette

enum Brand {
    static let signal      = Color(red: 0xF5/255, green: 0x53/255, blue: 0x0A/255) // #f5530a
    static let signalDeep  = Color(red: 0xC9/255, green: 0x3F/255, blue: 0x04/255) // #c93f04
    static let signalWash  = Color(red: 0xF5/255, green: 0x53/255, blue: 0x0A/255).opacity(0.08)

    static let slate       = Color(red: 0x0F/255, green: 0x11/255, blue: 0x15/255)
    static let graphite    = Color(red: 0x2A/255, green: 0x2D/255, blue: 0x33/255)
    static let mute        = Color(red: 0x7D/255, green: 0x80/255, blue: 0x89/255)

    static let secure      = Color(red: 0x1E/255, green: 0x9E/255, blue: 0x57/255)
    static let critical    = Color(red: 0xE2/255, green: 0x3B/255, blue: 0x2E/255)
    static let idle        = Color(red: 0x8A/255, green: 0x8D/255, blue: 0x94/255)
}

// MARK: - Domain model

/// Platform-neutral status (a Windows tray build will reuse this).
enum AgentStatus: Equatable {
    case secure(lastScan: String, compliance: String)
    case updates([PendingUpdate])
    case actionNeeded([Finding])
    case scanning(scanned: Int, total: Int)
    case offline(lastScan: String, lastCompliance: String)

    /// Drives the menu-bar template badge.
    var badge: MenuBarBadge {
        switch self {
        case .secure:        return .none
        case .updates:       return .attention   // orange
        case .actionNeeded:  return .critical     // red
        case .scanning:      return .scanning     // indeterminate
        case .offline:       return .idle         // hollow grey
        }
    }
}

struct PendingUpdate: Identifiable, Equatable {
    let id = UUID()
    let app: String
    let fromVersion: String
    let toVersion: String
    let cve: String
    let verifiedSource: String   // provenance — the patch came from a known-good signed source
    let tint: Color
    let badgeLetters: String
}

struct Finding: Identifiable, Equatable {
    let id = UUID()
    let severity: Severity
    let title: String            // plain language, platform-neutral
    let detail: String
    let benchmark: String        // SF Mono evidence, e.g. "CIS 2.5.1 · Full-disk encryption"
    enum Severity { case critical, attention
        var color: Color { self == .critical ? Brand.critical : Brand.signal }
        var label: String { self == .critical ? "Critical" : "Attention" }
    }
}

enum MenuBarBadge { case none, attention, critical, scanning, idle }

// MARK: - Observable agent

@MainActor
final class AgentModel: ObservableObject {
    @Published var status: AgentStatus = .secure(
        lastScan: "2 minutes ago",
        compliance: "CIS 142 / 142 · No known CVEs"
    )

    // Replace with your real scan pipeline (CVE/NVD + CIS benchmark engine).
    func scanNow() { status = .scanning(scanned: 0, total: 247) }
    func cancelScan() { /* … */ }
    func retry() { /* re-reach the Patched service */ }

    // Hand-offs — the menu bar never becomes a settings panel.
    func openSelfService(deepLink: String = "patched://self-service") {
        if let url = URL(string: deepLink) { NSWorkspace.shared.open(url) }
    }
    func openPatched() { openSelfService(deepLink: "patched://home") }
    func remindLater() { /* snooze the nudge */ }
}

// MARK: - Menu bar entry point

@main
struct PatchedAgentApp: App {
    @StateObject private var model = AgentModel()

    var body: some Scene {
        MenuBarExtra {
            PopoverRoot()
                .environmentObject(model)
                .frame(width: 320)
        } label: {
            MenuBarIcon(badge: model.status.badge)
        }
        .menuBarExtraStyle(.window)   // a real popover, not an NSMenu
    }
}

// MARK: - Menu bar icon (monochrome template + state badge)

/// The Patched mark drawn as a template image so AppKit tints it for the
/// light/dark menu bar automatically. State is a small badge overlay — we
/// never colour-fill the glyph itself.
struct MenuBarIcon: View {
    let badge: MenuBarBadge
    @State private var pulse = false

    var body: some View {
        ZStack(alignment: .topTrailing) {
            PixelPMark(cell: 2, on: .primary)        // template; AppKit handles tint
                .opacity(badge == .scanning && pulse ? 0.4 : 1)
                .animation(badge == .scanning
                           ? .easeInOut(duration: 0.65).repeatForever(autoreverses: true)
                           : .default, value: pulse)

            switch badge {
            case .attention: Dot(color: Brand.signal)
            case .critical:  Dot(color: Brand.critical)
            case .idle:      Dot(color: .clear, stroke: Brand.idle)
            case .none, .scanning: EmptyView()
            }
        }
        .frame(width: 18, height: 16)
        .onAppear { if badge == .scanning { pulse = true } }
    }

    struct Dot: View {
        var color: Color
        var stroke: Color? = nil
        var body: some View {
            Circle()
                .fill(color)
                .overlay(stroke.map { Circle().strokeBorder($0, lineWidth: 1.5) })
                .frame(width: 6, height: 6)
                .offset(x: 2, y: -1)
        }
    }
}

/// The pixel-P mark, rendered from the brand's 5×7 endpoint-cell glyph.
/// Pass `accent` to light one cell signal-orange (header lockup); leave nil for the
/// monochrome menu-bar template icon.
struct PixelPMark: View {
    var cell: CGFloat
    var on: Color = Brand.slate
    var accent: (row: Int, col: Int)? = nil
    private let glyph: [[Int]] = [
        [1,1,1,1,0],[1,0,0,0,1],[1,0,0,0,1],
        [1,1,1,1,0],[1,0,0,0,0],[1,0,0,0,0],[1,0,0,0,0],
    ]
    var body: some View {
        VStack(spacing: cell * 0.18) {
            ForEach(glyph.indices, id: \.self) { r in
                HStack(spacing: cell * 0.18) {
                    ForEach(glyph[r].indices, id: \.self) { c in
                        Rectangle()
                            .fill(color(r, c))
                            .frame(width: cell, height: cell)
                    }
                }
            }
        }
    }
    private func color(_ r: Int, _ c: Int) -> Color {
        if glyph[r][c] == 0 { return .clear }
        if let a = accent, a.row == r, a.col == c { return Brand.signal }
        return on
    }
}

/// The in-app brand: the word “Patched” in the system font. No mark in the header
/// (the pixel-P lives only in the menu-bar icon).
struct PatchedLockup: View {
    var size: CGFloat = 15
    var ink: Color = Brand.slate
    var body: some View {
        Text("Patched")
            .font(.system(size: size, weight: .semibold))
            .tracking(-0.2)
            .foregroundStyle(ink)
            .accessibilityLabel("Patched")
    }
}

// MARK: - Popover router

struct PopoverRoot: View {
    @EnvironmentObject var model: AgentModel

    var body: some View {
        VStack(spacing: 0) {
            PopoverHeader()
            Divider().opacity(0)   // header has its own spacing
            switch model.status {
            case let .secure(last, compliance):
                SecureView(lastScan: last, compliance: compliance)
            case let .updates(updates):
                UpdatesView(updates: updates)
            case let .actionNeeded(findings):
                ActionNeededView(findings: findings)
            case let .scanning(scanned, total):
                ScanningView(scanned: scanned, total: total)
            case let .offline(last, compliance):
                OfflineView(lastScan: last, lastCompliance: compliance)
            }
        }
        .padding(13)
        .background(.regularMaterial)         // NSVisualEffectView vibrancy
    }
}

struct PopoverHeader: View {
    @EnvironmentObject var model: AgentModel
    var body: some View {
        HStack {
            PatchedLockup(size: 15)            // pixel-P mark + “Patched” (system font)
            Spacer()
            Button { model.openPatched() } label: {
                Image(systemName: "gearshape").font(.system(size: 13))
            }
            .buttonStyle(.plain).foregroundStyle(Brand.mute)
        }
        .padding(.bottom, 11)
    }
}

// MARK: - Reusable status line

struct StatusLine<Accessory: View>: View {
    let title: String
    let subtitle: String
    @ViewBuilder var indicator: () -> Accessory

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            indicator().padding(.top, 3)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(Brand.slate)
                Text(subtitle).font(.system(size: 12))
                    .foregroundStyle(Brand.mute)
            }
            Spacer(minLength: 0)
        }
    }
}

struct StatusDot: View {
    var color: Color
    var body: some View {
        Circle().fill(color).frame(width: 9, height: 9)
            .background(Circle().fill(color.opacity(0.16)).frame(width: 15, height: 15))
    }
}

// MARK: - 1 · Secure

struct SecureView: View {
    let lastScan: String
    let compliance: String
    @EnvironmentObject var model: AgentModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            StatusLine(title: "Protected",
                       subtitle: "Last scanned \(lastScan) · continuous") {
                StatusDot(color: Brand.secure)
            }
            Label {
                Text(compliance)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Brand.graphite)
            } icon: {
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: 11)).foregroundStyle(Brand.secure)
            }
            .padding(.top, 13)

            Divider().padding(.vertical, 12)

            MenuRow(icon: "arrow.clockwise", title: "Scan now", shortcut: "⌘R") { model.scanNow() }
            MenuRow(icon: "arrow.up.forward.app", title: "Open Patched") { model.openPatched() }
            MenuRow(icon: "power", title: "Quit", shortcut: "⌘Q") { NSApp.terminate(nil) }
        }
    }
}

// MARK: - 2 · Updates available (Nudge-style, user-actioned)

struct UpdatesView: View {
    let updates: [PendingUpdate]
    @EnvironmentObject var model: AgentModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            StatusLine(title: "\(updates.count) updates ready",
                       subtitle: "Recommended — you choose when to install") {
                StatusDot(color: Brand.signal)
            }
            Divider().padding(.vertical, 11)

            VStack(spacing: 0) {
                ForEach(updates) { u in
                    UpdateRow(update: u)
                    if u.id != updates.last?.id { Divider() }
                }
            }

            Label {
                Text("Nothing installs without your approval.")
                    .font(.system(size: 11.5)).foregroundStyle(Brand.mute)
            } icon: {
                Image(systemName: "lock.fill").font(.system(size: 11))
                    .foregroundStyle(Brand.mute)
            }
            .padding(.top, 12)

            HStack(spacing: 8) {
                PrimaryButton("Review in Patched", systemImage: "arrow.right") {
                    model.openSelfService()
                }
                SecondaryButton("Later") { model.remindLater() }
                    .frame(maxWidth: 78)
            }
            .padding(.top, 14)
        }
    }
}

struct UpdateRow: View {
    let update: PendingUpdate
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            RoundedRectangle(cornerRadius: 7)
                .fill(update.tint)
                .frame(width: 28, height: 28)
                .overlay(Text(update.badgeLetters)
                    .font(.system(size: 13, weight: .semibold)).foregroundStyle(.white))
            VStack(alignment: .leading, spacing: 2) {
                Text(update.app).font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Brand.slate)
                HStack(spacing: 4) {
                    Text(update.fromVersion); Text("→").foregroundStyle(Brand.graphite)
                    Text(update.toVersion).foregroundStyle(Brand.secure)
                }
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Brand.mute)
                HStack(spacing: 6) {
                    Chip(text: update.cve, tint: Brand.graphite,
                         bg: Brand.slate.opacity(0.055))
                    Chip(text: "Verified · \(update.verifiedSource)", tint: Brand.secure,
                         bg: Brand.secure.opacity(0.10), systemImage: "checkmark.seal.fill")
                }
                .padding(.top, 5)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 9)
    }
}

// MARK: - 3 · Action needed

struct ActionNeededView: View {
    let findings: [Finding]
    @EnvironmentObject var model: AgentModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            StatusLine(title: "Action needed",
                       subtitle: "\(findings.count) critical finding on this device") {
                StatusDot(color: Brand.critical)
            }
            ForEach(findings) { f in
                FindingCard(finding: f).padding(.top, 13)
            }
            PrimaryButton("Resolve in Patched", systemImage: "arrow.right") {
                model.openSelfService()
            }
            .padding(.top, 14)

            Label {
                Text("You stay in control — Patched guides the fix, nothing is forced.")
                    .font(.system(size: 11.5)).foregroundStyle(Brand.mute)
            } icon: {
                Image(systemName: "checkmark.shield").font(.system(size: 11))
                    .foregroundStyle(Brand.mute)
            }
            .padding(.top, 12)
        }
    }
}

struct FindingCard: View {
    let finding: Finding
    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 8) {
                Text(finding.severity.label.uppercased())
                    .font(.system(size: 9.5, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.white)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(finding.severity.color, in: RoundedRectangle(cornerRadius: 4))
                Text(finding.title).font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Brand.slate)
            }
            Text(finding.detail).font(.system(size: 12))
                .foregroundStyle(Brand.graphite).fixedSize(horizontal: false, vertical: true)
            Text(finding.benchmark).font(.system(size: 10.5, design: .monospaced))
                .foregroundStyle(Brand.mute)
        }
        .padding(12)
        .background(finding.severity.color.opacity(0.05),
                    in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8)
            .strokeBorder(finding.severity.color.opacity(0.28), lineWidth: 1))
    }
}

// MARK: - 4 · Scanning (indeterminate, cancellable)

struct ScanningView: View {
    let scanned: Int
    let total: Int
    @EnvironmentObject var model: AgentModel
    private var pct: Int { total == 0 ? 0 : Int((Double(scanned) / Double(total)) * 100) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            StatusLine(title: "Scanning…",
                       subtitle: "Checking against live CVE data & CIS benchmarks") {
                ProgressView().controlSize(.small)
            }
            Text("Comparing app \(scanned) of \(total) against the National Vulnerability Database.")
                .font(.system(size: 12.5)).foregroundStyle(Brand.graphite)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 14)

            ProgressView(value: Double(scanned), total: Double(total))   // determinate
                .progressViewStyle(.linear)
                .tint(Brand.signal).padding(.top, 12)

            HStack {
                Text("\(scanned) / \(total) apps · 142 checks")
                Spacer()
                Text("\(pct)%")
            }
            .font(.system(size: 10.5, design: .monospaced))
            .foregroundStyle(Brand.mute).padding(.top, 9)

            Divider().padding(.vertical, 12)
            MenuRow(icon: "xmark.circle", title: "Cancel scan") { model.cancelScan() }
        }
    }
}

// MARK: - 5 · Offline / stale

struct OfflineView: View {
    let lastScan: String
    let lastCompliance: String
    @EnvironmentObject var model: AgentModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            StatusLine(title: "Can’t reach Patched",
                       subtitle: "Last scan \(lastScan)") {
                StatusDot(color: Brand.idle)
            }
            Label {
                Text("Your protection status may be out of date. Check your connection and try again.")
                    .font(.system(size: 12.5)).foregroundStyle(Brand.graphite)
                    .fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "wifi.slash").font(.system(size: 13))
                    .foregroundStyle(Brand.mute)
            }
            .padding(.top, 13)

            Label {
                Text("Showing last known result · \(lastCompliance)")
                    .font(.system(size: 11, design: .monospaced)).foregroundStyle(Brand.mute)
            } icon: {
                Image(systemName: "clock").font(.system(size: 11)).foregroundStyle(Brand.mute)
            }
            .padding(.top, 12)

            HStack(spacing: 8) {
                Button { model.retry() } label: {
                    Label("Retry now", systemImage: "arrow.clockwise")
                        .font(.system(size: 13, weight: .semibold))
                        .frame(maxWidth: .infinity, minHeight: 30)
                }
                .buttonStyle(.plain)
                .foregroundStyle(.white)
                .background(Brand.slate, in: RoundedRectangle(cornerRadius: 7))

                SecondaryButton("Open Patched") { model.openPatched() }
            }
            .padding(.top, 14)
        }
    }
}

// MARK: - Shared controls

struct MenuRow: View {
    let icon: String
    let title: String
    var shortcut: String? = nil
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                Image(systemName: icon).font(.system(size: 13))
                    .foregroundStyle(Brand.graphite).frame(width: 16)
                Text(title).font(.system(size: 13)).foregroundStyle(Brand.slate)
                Spacer()
                if let shortcut {
                    Text(shortcut).font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Brand.mute)
                }
            }
            .padding(.horizontal, 9).frame(height: 30)
            .background(hover ? Brand.slate.opacity(0.06) : .clear,
                        in: RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
    }
}

struct PrimaryButton: View {
    let title: String; var systemImage: String? = nil; let action: () -> Void
    init(_ title: String, systemImage: String? = nil, action: @escaping () -> Void) {
        self.title = title; self.systemImage = systemImage; self.action = action
    }
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Text(title)
                if let systemImage { Image(systemName: systemImage) }
            }
            .font(.system(size: 13, weight: .semibold))
            .frame(maxWidth: .infinity, minHeight: 30)
            .foregroundStyle(.white)
            .background(hover ? Brand.signalDeep : Brand.signal,
                        in: RoundedRectangle(cornerRadius: 7))
        }
        .buttonStyle(.plain).onHover { hover = $0 }
    }
}

struct SecondaryButton: View {
    let title: String; let action: () -> Void
    init(_ title: String, action: @escaping () -> Void) { self.title = title; self.action = action }
    var body: some View {
        Button(action: action) {
            Text(title).font(.system(size: 13, weight: .semibold))
                .frame(maxWidth: .infinity, minHeight: 30)
                .foregroundStyle(Brand.slate)
                .background(Brand.slate.opacity(0.06), in: RoundedRectangle(cornerRadius: 7))
        }
        .buttonStyle(.plain)
    }
}

struct Chip: View {
    let text: String; let tint: Color; let bg: Color; var systemImage: String? = nil
    var body: some View {
        HStack(spacing: 4) {
            if let systemImage { Image(systemName: systemImage).font(.system(size: 9)) }
            Text(text)
        }
        .font(.system(size: 10, design: .monospaced))
        .foregroundStyle(tint)
        .padding(.horizontal, 6).padding(.vertical, 2)
        .background(bg, in: RoundedRectangle(cornerRadius: 5))
    }
}

// MARK: - Preview seeds

#Preview("Secure") {
    PopoverRoot().environmentObject(AgentModel()).frame(width: 320)
}

#Preview("Updates") {
    let m = AgentModel()
    m.status = .updates([
        .init(app: "Safari", fromVersion: "17.4", toVersion: "17.5",
              cve: "CVE-2026-1842", verifiedSource: "Apple",
              tint: Color(red: 0.10, green: 0.45, blue: 0.91), badgeLetters: "Sa"),
        .init(app: "Google Chrome", fromVersion: "125.0", toVersion: "126.0",
              cve: "CVE-2026-2011", verifiedSource: "Google",
              tint: Color(red: 0.07, green: 0.64, blue: 0.42), badgeLetters: "Ch"),
        .init(app: "Zoom", fromVersion: "6.0.10", toVersion: "6.1.2",
              cve: "CVE-2026-1990", verifiedSource: "Zoom",
              tint: Color(red: 0.17, green: 0.42, blue: 1.0), badgeLetters: "Zo"),
    ])
    return PopoverRoot().environmentObject(m).frame(width: 320)
}

#Preview("Action needed") {
    let m = AgentModel()
    m.status = .actionNeeded([
        .init(severity: .critical, title: "Disk encryption is off",
              detail: "This device’s drive isn’t encrypted. If it’s lost or stolen, your files could be read. Turn on encryption to close this gap.",
              benchmark: "Benchmark · CIS 2.5.1 · Full-disk encryption"),
    ])
    return PopoverRoot().environmentObject(m).frame(width: 320)
}

#Preview("Scanning") {
    let m = AgentModel(); m.status = .scanning(scanned: 118, total: 247)
    return PopoverRoot().environmentObject(m).frame(width: 320)
}

#Preview("Offline") {
    let m = AgentModel()
    m.status = .offline(lastScan: "6 days ago", lastCompliance: "CIS 141 / 142")
    return PopoverRoot().environmentObject(m).frame(width: 320)
}
