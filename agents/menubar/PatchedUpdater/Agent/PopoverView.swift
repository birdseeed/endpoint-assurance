//
//  PopoverView.swift
//  PatchedUpdater — Agent (PAT-554 / PAT-645)
//
//  Glanceable posture popover for the macOS menu-bar agent.
//  Dispatches to one of five distinct state panels driven by AgentPostureModel.trayState:
//
//    clean    → CleanStatePanel    (Protected headline, CIS pass line)
//    issues   → UpdateActionPanel  (gauge, dismiss row, read-only per-app rows)
//    critical → CriticalStatePanel (CVE card, reassurance note)
//    scanning → ScanningStatePanel (spinner, progress track)
//    offline  → OfflineStatePanel  (last-known CIS score, Retry re-reads cache)
//
//  PAT-1619: removed every hand-off into the (now-quarantined) Self Service
//  app. The popover is disclosure-only: it shows posture, it does not launch
//  or deep-link into another app. Rows that lost their only action either
//  disappeared (the header gear, the Clean-state buttons, the per-app Update
//  button, the footer link) or were given a real, purely-local action instead
//  (Offline's Retry now re-reads the on-disk posture cache; see
//  AgentPostureModel.retryLoad()). The Critical panel's "Resolve" CTA was
//  removed rather than pointed at FindingDetailView, which renders an
//  unrelated CIS/disk-encryption finding, not the CVE finding this panel
//  shows. See FindingDetailView.swift's header comment.
//
//  Non-negotiables (CLAUDE.md):
//    - SF Pro system font only — Archivo for "Patched" lockup only
//    - One accent: #F5530A (Brand.signal), ≤ ~2% of surface
//    - Ring mark in header (code-drawn RingMarkView)
//    - Honest tier gating: gated affordances visible but clearly marked
//    - No MDM / no remote control; agent is read-only
//    - Provenance on every version / install shown
//

import SwiftUI
import AppKit

// MARK: - Root popover

struct PopoverView: View {
    @ObservedObject var model: AgentPostureModel

    var body: some View {
        VStack(spacing: 0) {
            PopoverHeader()
            Divider()
                .overlay(Brand.rule)

            postureContent

            Divider()
                .overlay(Brand.rule)

            PopoverFooter(posture: model.posture)

            Divider()
                .overlay(Brand.rule)

            PopoverPrivacyNote()
        }
        .frame(width: 320)
        .background(.regularMaterial)
    }

    @ViewBuilder
    private var postureContent: some View {
        switch model.trayState {
        case .scanning:
            ScanningStatePanel()
                .padding(.horizontal, 14)
                .padding(.vertical, 14)
        case .offline:
            OfflineStatePanel(posture: model.posture, model: model)
        case .clean:
            if let posture = model.posture {
                CleanStatePanel(posture: posture)
            } else {
                NoDataView(error: model.loadError)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 12)
            }
        case .critical:
            if let posture = model.posture {
                CriticalStatePanel(posture: posture)
            } else {
                NoDataView(error: model.loadError)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 12)
            }
        case .issues:
            if let posture = model.posture {
                UpdateActionPanel(posture: posture)
            } else {
                NoDataView(error: model.loadError)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 12)
            }
        }
    }
}

// MARK: - Header

/// Ring mark + "Patched" wordmark lockup.
/// Per CLAUDE.md: ring mark at 20pt; "Patched" in Archivo 600 15pt.
/// The "Managed" badge from an earlier spec revision is dropped (PAT-645).
/// PAT-1619: the trailing settings-gear button (its only action was the
/// Self Service hand-off) was removed rather than left as a dead affordance.
private struct PopoverHeader: View {
    var body: some View {
        HStack(spacing: 8) {
            RingMarkView(size: 20, ink: Brand.slate, showArc: false)
                .accessibilityHidden(true)

            Text("Patched")
                .font(.custom("Archivo", size: 15).weight(.semibold))
                .tracking(-0.3)
                .foregroundStyle(Brand.slate)

            Spacer()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
    }
}

// MARK: - Clean state panel (Protected)

/// PAT-1619: "Scan now" and "Open Patched" both routed to the Self Service
/// hand-off with no local action of their own; both removed rather than left
/// as dead buttons. This panel is now read-only status disclosure.
private struct CleanStatePanel: View {
    let posture: Posture

    private var benchmark: Posture.Compliance.Benchmark? { posture.compliance.primary }

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 28))
                .foregroundStyle(Brand.secure)

            VStack(alignment: .leading, spacing: 4) {
                Text("Protected")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(Brand.slate)
                if let bm = benchmark {
                    Text("CIS \(bm.passed) / \(bm.benchmarkTotal) controls · \(bm.failed == 0 ? "no findings" : "\(bm.failed) findings")")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Brand.secure)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 14)
    }
}

// MARK: - Update action panel (Issues)

private struct UpdateActionPanel: View {
    let posture: Posture

    private var updates: [Posture.AppUpdate] { posture.updates ?? [] }

    var body: some View {
        VStack(spacing: 0) {
            PostureSummaryRow(posture: posture, updates: updates)
                .padding(.horizontal, 14)
                .padding(.vertical, 14)

            if updates.isEmpty {
                AllUpToDateRow()
            } else {
                DismissRow()
                    .padding(.horizontal, 14)
                    .padding(.bottom, 12)

                Divider()
                    .overlay(Brand.rule)

                AppUpdateList(updates: updates)
            }
        }
    }
}

// MARK: - Critical state panel (Action needed)

/// PAT-1619: the "Resolve in Patched" CTA that used to deep-link into Self
/// Service compliance detail was removed rather than rewired to the orphaned
/// FindingDetailView: that view renders one specific advisory CIS finding
/// (disk encryption off), an unrelated data model to the CVE findings this
/// panel shows, so wiring it in would show the wrong content for the finding
/// that triggered this panel. See FindingDetailView.swift's header comment.
private struct CriticalStatePanel: View {
    let posture: Posture

    private var criticalFindings: [Posture.Finding] {
        (posture.findings ?? []).filter {
            $0.severity.uppercased() == "HIGH" || $0.severity.uppercased() == "CRITICAL"
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Finding card
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 22))
                    .foregroundStyle(Brand.signal)

                VStack(alignment: .leading, spacing: 4) {
                    Text("\(criticalFindings.count) critical finding\(criticalFindings.count == 1 ? "" : "s")")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(Brand.slate)
                    if let first = criticalFindings.first {
                        Text(first.cveId)
                            .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                            .foregroundStyle(Brand.signal)
                        Text(first.appName)
                            .font(.system(size: 12))
                            .foregroundStyle(Brand.mute)
                        if criticalFindings.count > 1 {
                            Text("+\(criticalFindings.count - 1) more")
                                .font(.system(size: 11))
                                .foregroundStyle(Brand.mute)
                        }
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 14)

            Divider().overlay(Brand.rule)

            // Reassurance note
            Text("Patched never acts without you. Findings like this are evidence, not automatic fixes.")
                .font(.system(size: 11))
                .foregroundStyle(Brand.mute)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
        }
    }
}

// MARK: - Scanning state panel

private struct ScanningStatePanel: View {
    @State private var rotation: Double = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: "arrow.trianglehead.2.counterclockwise.rotate.90")
                    .font(.system(size: 18))
                    .foregroundStyle(Brand.mute)
                    .rotationEffect(.degrees(rotation))
                    .onAppear {
                        withAnimation(.linear(duration: 1.5).repeatForever(autoreverses: false)) {
                            rotation = 360
                        }
                    }

                VStack(alignment: .leading, spacing: 3) {
                    Text("Scanning…")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(Brand.slate)
                    Text("Checking against live CVE data and CIS benchmarks.")
                        .font(.system(size: 12))
                        .foregroundStyle(Brand.mute)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            ProgressView()
                .progressViewStyle(.linear)
                .frame(maxWidth: .infinity)
                .tint(Brand.mute)
        }
    }
}

// MARK: - Offline state panel

/// PAT-1619: Retry used to hand off to Self Service; it now calls
/// AgentPostureModel.retryLoad(), which re-reads the same on-disk posture
/// cache PostureStore already watches. No network call, no privilege.
private struct OfflineStatePanel: View {
    let posture: Posture?
    let model: AgentPostureModel

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "wifi.slash")
                    .font(.system(size: 20))
                    .foregroundStyle(Brand.mute)

                VStack(alignment: .leading, spacing: 4) {
                    Text("Posture data is stale")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(Brand.slate)
                    if let bm = posture?.compliance.primary {
                        Text("Last known: CIS \(bm.passed) / \(bm.benchmarkTotal)")
                            .font(.system(size: 11.5, design: .monospaced))
                            .foregroundStyle(Brand.mute)
                    } else {
                        Text("Collector hasn't reported recently.")
                            .font(.system(size: 12))
                            .foregroundStyle(Brand.mute)
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 14)

            Divider().overlay(Brand.rule)

            Button {
                model.retryLoad()
            } label: {
                Label("Retry", systemImage: "arrow.clockwise")
                    .font(.system(size: 13, weight: .medium))
                    .frame(maxWidth: .infinity, minHeight: 34)
                    .foregroundStyle(Brand.slate)
                    .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 7))
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
        }
    }
}

// MARK: - Posture summary row

private struct PostureSummaryRow: View {
    let posture: Posture
    let updates: [Posture.AppUpdate]

    private var unpatchedCount: Int { updates.count }
    private var patchedCount: Int   { max(0, posture.appCount - unpatchedCount) }
    private let patchingCount: Int  = 0

    private var patchedFrac: Double {
        posture.appCount > 0 ? Double(patchedCount) / Double(posture.appCount) : 1
    }

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            PopoverGaugeView(patchedFrac: patchedFrac, patchingFrac: 0)
                .frame(width: 62, height: 62)

            VStack(alignment: .leading, spacing: 0) {
                Text(unpatchedCount == 0 ? "All apps up to date" : "\(unpatchedCount) update\(unpatchedCount == 1 ? "" : "s") ready")
                    .font(.system(size: 15, weight: .semibold))
                    .tracking(-0.15)
                    .foregroundStyle(Brand.slate)

                Text("This Mac")
                    .font(.system(size: 12))
                    .foregroundStyle(Brand.mute)
                    .padding(.top, 3)

                HStack(spacing: 11) {
                    LegendItem(color: Brand.slate, label: "\(patchedCount) patched")
                    LegendItem(color: Color.primary.opacity(0.18), label: "\(unpatchedCount) unpatched")
                }
                .padding(.top, 8)
            }

            Spacer(minLength: 0)
        }
    }
}

// MARK: - Gauge view

/// Squircle arc meter matching the JS gauge() in Self-Service Agent.html.
struct PopoverGaugeView: View {
    var patchedFrac: Double
    var patchingFrac: Double

    private let size: CGFloat = 62

    private var strokeWidth: CGFloat  { max(5, size * 0.085) }
    private var cornerRadius: CGFloat { size * 0.26 }
    private var inset: CGFloat        { strokeWidth / 2 + 3 }

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: cornerRadius)
                .inset(by: inset)
                .stroke(Color.primary.opacity(0.12), lineWidth: strokeWidth)

            if patchedFrac > 0 {
                RoundedRectangle(cornerRadius: cornerRadius)
                    .inset(by: inset)
                    .trim(from: 0, to: CGFloat(patchedFrac))
                    .stroke(Brand.slate, style: StrokeStyle(lineWidth: strokeWidth, lineCap: .round))
            }

            if patchingFrac > 0 {
                RoundedRectangle(cornerRadius: cornerRadius)
                    .inset(by: inset)
                    .trim(from: CGFloat(patchedFrac), to: CGFloat(min(1, patchedFrac + patchingFrac)))
                    .stroke(Brand.signal, style: StrokeStyle(lineWidth: strokeWidth, lineCap: .round))
            }
        }
        .frame(width: size, height: size)
    }
}

// MARK: - Legend item

private struct LegendItem: View {
    let color: Color
    let label: String

    var body: some View {
        HStack(spacing: 5) {
            RoundedRectangle(cornerRadius: 2)
                .fill(color)
                .frame(width: 7, height: 7)
            Text(label)
                .font(.system(size: 10.5))
                .foregroundStyle(Brand.mute)
                .monospacedDigit()
        }
    }
}

// MARK: - Dismiss row

/// PAT-1619: "Patch all" was a stub that always routed to Self Service (its
/// TODO promised a real triggerPatchAll() daemon dispatch that was never
/// built and is dead under PAT-1481's supersession). Removed along with the
/// TODO rather than kept as a hand-off with no in-agent function. "Later"
/// survives unchanged: it only dismisses the popover, no hand-off involved.
private struct DismissRow: View {
    var body: some View {
        HStack(spacing: 8) {
            Button {
                NSApp.keyWindow?.resignFirstResponder()
                NSApp.keyWindow?.close()
            } label: {
                Text("Later")
                    .font(.system(size: 13, weight: .semibold))
                    .padding(.horizontal, 14)
                    .frame(minHeight: 34)
                    .foregroundStyle(Brand.slate)
                    .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 7))
            }
            .buttonStyle(.plain)
        }
    }
}

// MARK: - App update list

private struct AppUpdateList: View {
    let updates: [Posture.AppUpdate]

    private var visibleUpdates: [Posture.AppUpdate] { Array(updates.prefix(5)) }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Needs patching")
                    .font(.system(size: 10, weight: .semibold))
                    .tracking(0.8)
                    .textCase(.uppercase)
                    .foregroundStyle(Color.primary.opacity(0.38))
                Spacer()
            }
            .padding(.horizontal, 14)
            .padding(.top, 10)
            .padding(.bottom, 6)

            ForEach(visibleUpdates) { update in
                AppUpdateRow(update: update)
            }

            if updates.count > 5 {
                HStack {
                    Text("+\(updates.count - 5) more")
                        .font(.system(size: 11))
                        .foregroundStyle(Brand.mute)
                    Spacer()
                }
                .padding(.horizontal, 22)
                .padding(.bottom, 8)
            }
        }
    }
}

// MARK: - App update row

/// PAT-1619: the trailing "Update" button hung off the Self Service hand-off
/// with no in-agent action of its own. Removed and replaced with a plain
/// "Available" badge. The row is read-only, not a button that does nothing.
private struct AppUpdateRow: View {
    let update: Posture.AppUpdate

    var body: some View {
        HStack(spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 7)
                    .fill(Color.primary.opacity(0.07))
                    .frame(width: 30, height: 30)
                Text(String(update.appName.prefix(1)).uppercased())
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Brand.mute)
            }

            VStack(alignment: .leading, spacing: 1) {
                Text(update.appName)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Brand.slate)
                    .lineLimit(1)
                Text("\(update.currentVersion) → \(update.targetVersion)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Brand.mute)
                    .lineLimit(1)
            }

            Spacer(minLength: 0)

            Text("Available")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Brand.mute)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
    }
}

// MARK: - All up to date row

private struct AllUpToDateRow: View {
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 13))
                .foregroundStyle(Brand.secure)
            Text("All apps up to date")
                .font(.system(size: 13))
                .foregroundStyle(Brand.mute)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}

// MARK: - No data view

private struct NoDataView: View {
    let error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "clock.badge.questionmark")
                    .font(.system(size: 18))
                    .foregroundStyle(Brand.mute)
                Text("Awaiting first scan")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Brand.slate)
            }
            Text(error ?? "The posture collector hasn't run yet. Status will appear here once the first scan completes.")
                .font(.system(size: 12))
                .foregroundStyle(Brand.mute)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 8)
    }
}

// MARK: - Footer

/// PAT-1619: the trailing "Open Self Service" link was the most explicit of
/// the eight hand-offs; removed rather than left pointing at a surface the
/// agent no longer launches. The footer is now the last-checked timestamp only.
private struct PopoverFooter: View {
    let posture: Posture?

    var body: some View {
        HStack {
            Text(lastCheckedText)
                .font(.system(size: 11))
                .foregroundStyle(Color.primary.opacity(0.38))

            Spacer()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    private var lastCheckedText: String {
        guard let lastScan = posture?.evidence.lastScan else {
            return "Not yet scanned"
        }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return "Last checked \(f.localizedString(for: lastScan, relativeTo: Date()))"
    }
}

// MARK: - Collection disclosure (PAT-1624)

/// The agent is now the only end-user surface (PAT-1617), so the never-interrupt
/// gate's own collection statement lives here, on the surface every user of the
/// agent can already see, rather than only in documentation.
///
/// The sentence is exact and load bearing. The gate evaluates a boolean at
/// decision time and keeps nothing: not which application held the camera, not
/// when, not for how long. "Camera in use 14:02 to 15:30" is attendance
/// monitoring, and a customer's employee representative will ask.
private struct PopoverPrivacyNote: View {
    var body: some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: "hand.raised")
                .font(.system(size: 10))
                .foregroundStyle(Color.primary.opacity(0.32))
                .padding(.top, 1)

            Text("Patched checks whether your camera or microphone is in use so that it does not interrupt you, and records nothing about it.")
                .font(.system(size: 10))
                .foregroundStyle(Color.primary.opacity(0.42))
                .fixedSize(horizontal: false, vertical: true)

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
    }
}

// MARK: - Previews

#Preview("Updates ready — stub posture") {
    let model = AgentPostureModel(posture: PosturePreviewProvider.preview())
    PopoverView(model: model)
}

#Preview("Protected — no updates") {
    let model = AgentPostureModel(posture: PosturePreviewProvider.preview())
    PopoverView(model: model)
}

#Preview("Scanning") {
    let model = AgentPostureModel(posture: nil)
    PopoverView(model: model)
}

#Preview("Offline — stale") {
    // _simulateStale is @MainActor-isolated; assume isolation inside #Preview.
    let model = AgentPostureModel(posture: PosturePreviewProvider.preview())
    MainActor.assumeIsolated { model._simulateStale = true }
    return PopoverView(model: model)
}
