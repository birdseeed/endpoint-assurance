//
//  TrayIcon.swift
//  PatchedUpdater — Agent (PAT-476 / PAT-645)
//
//  The menu-bar template icon for the posture agent. Reflects five posture
//  states as a badge overlay on the ring mark:
//
//    clean    — no badge (all apps current, no findings, compliance ≥ threshold)
//    issues   — signal-orange dot (pending updates or compliance failures)
//    critical — critical-red dot  (CVSS-HIGH/CRITICAL findings unpatched)
//    scanning — grey pulsing dot  (collector active; no cached result yet)
//    offline  — grey outlined dot (cached posture older than staleThreshold)
//
//  The glyph is always drawn as a template image (black on clear) so AppKit
//  tints it automatically for the light / dark menu bar. The coloured badge is
//  rendered as a separate small filled circle overlay — we never colour-fill the
//  glyph itself.
//
//  Reference: menubar/design/agent/Patched Menu Bar Agent.html → MenuBarIcon
//

import SwiftUI

// MARK: - Posture tray state

/// The five tray-icon states driven by posture. Computed from `Posture` in
/// `AgentPostureModel` and passed here as a value type so the view stays dumb.
enum TrayState: Equatable {
    /// No unpatched findings, no pending updates, compliance ≥ threshold.
    case clean
    /// Pending updates available or minor compliance failures (no critical CVEs).
    case issues
    /// Unpatched HIGH or CRITICAL severity CVE findings present.
    case critical
    /// Posture collector is active; no cached result exists yet.
    case scanning
    /// Cached posture is older than PostureStore.staleThreshold.
    case offline
}

// MARK: - Menu-bar icon view

/// Renders the ring mark with a state badge. Use as the `label:` of a
/// `MenuBarExtra`.
struct TrayIcon: View {
    let state: TrayState
    @State private var pulse = false

    var body: some View {
        ZStack(alignment: .topTrailing) {
            // Template mark — AppKit auto-tints for light/dark menu bar.
            // showArc: false so the single-colour template is all-black.
            RingMarkView(size: 18, ink: .primary, showArc: false)
                .frame(width: 18, height: 18)

            badge
        }
        .frame(width: 18, height: 18)
    }

    @ViewBuilder
    private var badge: some View {
        switch state {
        case .clean:
            EmptyView()
        case .issues:
            BadgeDot(fill: Brand.signal)
        case .critical:
            BadgeDot(fill: Brand.critical)
        case .scanning:
            BadgeDot(fill: Brand.mute)
                .opacity(pulse ? 1.0 : 0.3)
                .onAppear {
                    withAnimation(.easeInOut(duration: 0.9).repeatForever(autoreverses: true)) {
                        pulse = true
                    }
                }
                .onDisappear { pulse = false }
        case .offline:
            BadgeRing()
        }
    }
}

// MARK: - Badge dot

private struct BadgeDot: View {
    let fill: Color

    var body: some View {
        Circle()
            .fill(fill)
            .frame(width: 6, height: 6)
            .offset(x: 3, y: -1)
    }
}

// MARK: - Badge ring (offline — outlined, no fill)

private struct BadgeRing: View {
    var body: some View {
        Circle()
            .strokeBorder(Brand.mute, lineWidth: 1.5)
            .frame(width: 6, height: 6)
            .offset(x: 3, y: -1)
    }
}

// MARK: - Previews

#Preview("Clean") {
    TrayIcon(state: .clean)
        .frame(width: 40, height: 30)
        .padding()
}

#Preview("Issues") {
    TrayIcon(state: .issues)
        .frame(width: 40, height: 30)
        .padding()
}

#Preview("Critical") {
    TrayIcon(state: .critical)
        .frame(width: 40, height: 30)
        .padding()
}

#Preview("Scanning") {
    TrayIcon(state: .scanning)
        .frame(width: 40, height: 30)
        .padding()
}

#Preview("Offline") {
    TrayIcon(state: .offline)
        .frame(width: 40, height: 30)
        .padding()
}
