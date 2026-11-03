//
//  FindingDetailView.swift
//  PatchedUpdater
//
//  PAT-300 — Advisory configuration finding-detail.
//
//  The destination for the menu-bar agent's "How to fix this →" CTA and the
//  Compliance sidebar tab in the Deploy window. This is an ADVISORY view:
//
//   • A configuration / CIS finding (disk encryption off) is advisory only.
//     Patched detects it, explains the risk, and shows the user how to enable
//     FileVault THEMSELVES. There is NO "Resolve in Patched" / "Fix for me" /
//     auto-remediation control anywhere in this file. By design.
//   • Enforcement (turning FileVault on, holding it in place) needs managed
//     config = Full Endpoint Management (Tier 3). Surfaced here as an OPTIONAL
//     upsell, not a paywall — the self-serve steps are complete on Report plan.
//
//  Uses Brand tokens from BrandTokens.swift (signal, critical, secure, mute,
//  slate, paper/card, snow/surface, signalWash, mono, sans).
//
//  PAT-1619: ComplianceDetailView's only caller (the legacy Deploy window's
//  Compliance tab) was removed, so this file is now unreferenced by any
//  shipped code. Left in place rather than deleted: it was considered as a
//  destination for the agent popover's Critical panel "Resolve" CTA, but its
//  content (ConfigFinding.fileVaultOff, a specific CIS disk-encryption
//  finding sourced from UpdateStatus.complianceFindings) is a different data
//  model to the CVE findings that panel shows (Posture.Finding, cveId +
//  appName), so wiring them together would present the wrong finding for
//  whatever actually triggered the panel. A generic finding-detail view that
//  covers both CVE and CIS findings would be new scope, not this ticket's.
//

import SwiftUI
import AppKit

// MARK: - Finding model

struct ConfigFinding: Identifiable {
    let id = UUID()
    let title: String           // "Disk encryption is off"
    let severity: CFSeverity    // .high → rendered as the CRITICAL pill
    let risk: String            // plain-language "why it matters"
    let cisControlRef: String   // e.g. "2.5.1.1"
    let cisControlName: String  // "Full-disk encryption (FileVault)"
    let steps: [FixStep]

    enum CFSeverity { case low, medium, high, critical }
}

struct FixStep: Identifiable {
    let id = UUID()
    let n: Int
    let title: String
    let detail: String
}

extension ConfigFinding {
    static let fileVaultOff = ConfigFinding(
        title: "Disk encryption is off",
        severity: .high,
        risk: """
        FileVault isn't turned on, so the data on this Mac is stored unencrypted. \
        If the laptop is lost or stolen, someone can pull the drive — or boot from \
        another disk — and read your files, email and saved passwords without your \
        account password. Turning FileVault on encrypts the whole disk so the data \
        stays unreadable without your credentials.
        """,
        cisControlRef: "2.5.1.1",
        cisControlName: "Full-disk encryption (FileVault)",
        steps: [
            FixStep(n: 1,
                    title: "Open System Settings → Privacy & Security",
                    detail: "Click the Apple menu → System Settings, then choose Privacy & Security in the sidebar."),
            FixStep(n: 2,
                    title: "Find FileVault and click Turn On…",
                    detail: "Scroll to the FileVault row. You'll be asked to authenticate with your account password."),
            FixStep(n: 3,
                    title: "Save your recovery key somewhere safe",
                    detail: "Choose to create a recovery key (or store it in iCloud), then keep it in your password manager — it's the only way back in if you forget your password."),
            FixStep(n: 4,
                    title: "Let encryption finish in the background",
                    detail: "Your Mac stays usable while it encrypts. Patched's next scan confirms the control as passing and updates your compliance record automatically."),
        ]
    )
}

// MARK: - Compliance tab root

struct ComplianceDetailView: View {
    @ObservedObject var statusStore: StatusStore

    private var hasDiskEncryptionFinding: Bool {
        statusStore.status?.complianceFindings?.first(where: { $0.findingId == "disk_encryption_off" }) != nil
    }

    var body: some View {
        if hasDiskEncryptionFinding {
            FindingDetailScreen(finding: .fileVaultOff) {
                NSWorkspace.shared.open(URL(string: "https://patched.im/pricing")!)
            }
        } else {
            allClearEmptyState
        }
    }

    private var allClearEmptyState: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 48))
                .foregroundStyle(Brand.secure)
            Text("All compliance checks passed")
                .font(Brand.sans(18, weight: .semibold))
                .foregroundStyle(Brand.slate)
            Text("No configuration findings to review on this device.")
                .font(Brand.sans(13))
                .foregroundStyle(Brand.mute)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Brand.surface)
    }
}

// MARK: - Advisory finding-detail screen

struct FindingDetailScreen: View {
    let finding: ConfigFinding
    /// Wire into pricing page or compare-tiers sheet.
    var onCompareTiers: () -> Void = {}

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {

                Breadcrumb(trail: ["Compliance", finding.title])

                // 1–3 · Finding-card header (risk + mono CIS evidence)
                FindingCard(finding: finding)
                    .padding(.bottom, 20)

                // 4 · Self-serve fix steps
                SectionLabel(text: "Here's how to turn it on")
                CardContainer {
                    ForEach(Array(finding.steps.enumerated()), id: \.element.id) { i, step in
                        if i > 0 { Divider().overlay(Brand.hair) }
                        FixStepRow(step: step)
                    }
                }
                RecoveryKeyCallout()
                    .padding(.bottom, 20)

                // 5 · Tier 3 upsell — optional, not a paywall
                SectionLabel(text: "Want this handled for you?")
                Tier3UpsellCard(onCompareTiers: onCompareTiers)
                    .padding(.bottom, 18)

                // 6 · Reassurance line — kept verbatim from the rest of the app
                Label(
                    "You stay in control — Patched guides the fix, nothing is forced.",
                    systemImage: "lock.fill"
                )
                .font(Brand.sans(12))
                .foregroundStyle(Brand.mute)
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Brand.surface)
    }
}

// MARK: - Finding-card header (reuses the agent's red-bordered finding-card treatment)

struct FindingCard: View {
    let finding: ConfigFinding
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Pill + category
            HStack(spacing: 11) {
                Label("CRITICAL", systemImage: "circle.fill")
                    .labelStyle(.titleAndIcon)
                    .imageScale(.small)
                    .font(Brand.mono(10, weight: .semibold))
                    .tracking(0.8)
                    .foregroundStyle(.white)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(Brand.critical, in: RoundedRectangle(cornerRadius: 5))
                Text("CONFIGURATION FINDING · ADVISORY")
                    .font(Brand.mono(10))
                    .tracking(0.4)
                    .foregroundStyle(Brand.mute)
            }

            // Title
            Text(finding.title)
                .font(Brand.sans(20, weight: .bold))
                .tracking(-0.4)
                .padding(.top, 12)

            // 2 · Plain-language risk
            Text(finding.risk)
                .font(Brand.sans(13))
                .foregroundStyle(.primary.opacity(0.85))
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 8)

            Divider().padding(.top, 14)

            // 3 · Evidence line — mono CIS ref
            Label(
                "\(finding.cisControlRef) · \(finding.cisControlName)",
                systemImage: "lock.fill"
            )
            .font(Brand.mono(11))
            .foregroundStyle(Brand.mute)
            .padding(.top, 13)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Brand.card, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Brand.critical, lineWidth: 1))
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Brand.critical.opacity(0.07))
                .padding(-3)  // soft critical-wash halo
        )
    }
}

// MARK: - Fix-step row

struct FixStepRow: View {
    let step: FixStep
    var body: some View {
        HStack(alignment: .top, spacing: 13) {
            Text("\(step.n)")
                .font(Brand.mono(11, weight: .bold))
                .foregroundStyle(Brand.surface)
                .frame(width: 22, height: 22)
                .background(Circle().fill(.primary))
            VStack(alignment: .leading, spacing: 3) {
                Text(step.title)
                    .font(Brand.sans(13, weight: .medium))
                    .fixedSize(horizontal: false, vertical: true)
                Text(step.detail)
                    .font(Brand.sans(12))
                    .foregroundStyle(Brand.mute)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 13)
        .padding(.horizontal, 16)
    }
}

// MARK: - Recovery-key callout (secure-tinted)

struct RecoveryKeyCallout: View {
    var body: some View {
        HStack(alignment: .top, spacing: 11) {
            Image(systemName: "key.fill")
                .font(.system(size: 15))
                .foregroundStyle(Brand.secure)
            VStack(alignment: .leading, spacing: 3) {
                Text("Don't lose your recovery key")
                    .font(Brand.sans(13, weight: .semibold))
                Text("Without it — and without your password — encrypted data can't be recovered by anyone, including Patched and Apple. Store it before you start.")
                    .font(Brand.sans(12))
                    .foregroundStyle(.primary.opacity(0.8))
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 12)
        .padding(.horizontal, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Brand.secure.opacity(0.10), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Brand.secure.opacity(0.22)))
        .padding(.top, 12)
    }
}

// MARK: - Tier 3 upsell (reuses the plans-sheet voice / featured styling)

struct Tier3UpsellCard: View {
    var onCompareTiers: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("FULL ENDPOINT MANAGEMENT · TIER 3")
                .font(Brand.mono(9, weight: .semibold))
                .foregroundStyle(.white)
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(Brand.signal, in: RoundedRectangle(cornerRadius: 5))
                .offset(y: -10)

            HStack(alignment: .top, spacing: 13) {
                Image(systemName: "checkmark.shield.fill")
                    .font(.system(size: 18))
                    .foregroundStyle(Brand.signal)
                    .frame(width: 36, height: 36)
                    .background(Brand.signalWash, in: RoundedRectangle(cornerRadius: 9))
                VStack(alignment: .leading, spacing: 4) {
                    Text("On Full Endpoint Management, Patched enforces this for you")
                        .font(Brand.sans(14, weight: .bold))
                        .tracking(-0.2)
                        .fixedSize(horizontal: false, vertical: true)
                    Text("Tier 3 manages configuration across the estate — FileVault is switched on and held in place, recovery keys are escrowed centrally, and drift is corrected without anyone touching a setting. On your current Report plan, Patched detects and guides; you make the change.")
                        .font(Brand.sans(12))
                        .foregroundStyle(.primary.opacity(0.8))
                        .fixedSize(horizontal: false, vertical: true)
                    Label("COMING SOON · OPTIONAL, NOT REQUIRED", systemImage: "clock")
                        .font(Brand.mono(9, weight: .semibold))
                        .foregroundStyle(Brand.mute)
                        .padding(.top, 5)
                }
            }

            HStack(spacing: 9) {
                Button("Compare tiers") { onCompareTiers() }
                    .buttonStyle(.borderedProminent)
                    .tint(Brand.signal)
                    .controlSize(.regular)
                Button("About Full Endpoint Management") { onCompareTiers() }
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
            }
            .padding(.top, 14)

            Label(
                "Optional. The steps above are all you need on your current plan — nothing here is gated behind an upgrade.",
                systemImage: "info.circle"
            )
            .font(Brand.sans(11))
            .foregroundStyle(Brand.mute)
            .padding(.top, 10)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Brand.card, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Brand.signal.opacity(0.4), lineWidth: 1.5))
    }
}

// MARK: - Breadcrumb

struct Breadcrumb: View {
    let trail: [String]
    var body: some View {
        HStack(spacing: 6) {
            ForEach(Array(trail.enumerated()), id: \.offset) { i, t in
                if i > 0 {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundStyle(Brand.mute)
                }
                Text(t)
                    .font(Brand.sans(12))
                    .foregroundStyle(i == trail.count - 1 ? Brand.mute : .primary.opacity(0.75))
                    .fontWeight(i == trail.count - 1 ? .regular : .medium)
            }
        }
        .padding(.bottom, 14)
    }
}

// MARK: - Layout helpers

/// Grouped inset card container (white background, rounded, thin border).
struct CardContainer<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        VStack(spacing: 0) {
            content
        }
        .background(Brand.card, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Brand.hair))
    }
}

struct SectionLabel: View {
    let text: String
    var body: some View {
        Text(text)
            .font(Brand.sans(12, weight: .semibold))
            .foregroundStyle(Brand.mute)
            .padding(.leading, 4)
            .padding(.top, 22)
            .padding(.bottom, 9)
    }
}

// MARK: - Preview

#Preview("Advisory finding-detail") {
    FindingDetailScreen(finding: .fileVaultOff)
        .frame(width: 600, height: 720)
}

#Preview("All-clear empty state") {
    struct PreviewStore: View {
        @StateObject private var store = StatusStore()
        var body: some View {
            ComplianceDetailView(statusStore: store)
                .frame(width: 600, height: 500)
        }
    }
    return PreviewStore()
}
