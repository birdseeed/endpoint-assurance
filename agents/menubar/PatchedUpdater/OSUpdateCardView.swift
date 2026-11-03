//
//  OSUpdateCardView.swift
//  PatchedUpdater
//
//  Nudge-style OS update card (PAT-273).
//  Rendered only when os_update.shouldShowCard is true.
//  The caller guards on that before showing it.
//
//  Card states:
//   update_recommended — passive amber card; "Remind me later" dismisses for session
//   update_required    — deadline-bearing; Defer decrements deferral budget
//   deadline_passed    — red persistent card; no Defer
//   unsupported_hw     — quiet notice; no actions beyond "Learn more"
//

import SwiftUI
import AppKit

struct OSUpdateCardView: View {
    let osUpdate: UpdateStatus.OsUpdate
    /// Optional actions. Default nil so glanceable embeddings
    /// can show the card without wiring defer/dismiss; a caller that owns the
    /// defer/dismiss flow passes both.
    var onDefer: (() -> Void)? = nil
    var onDismiss: (() -> Void)? = nil

    private var isRequired: Bool {
        osUpdate.state == .updateRequired || osUpdate.state == .deadlinePassed
    }

    private var accentColor: Color {
        switch osUpdate.severity {
        case .critical: return Color(red: 0.8, green: 0.1, blue: 0.1)
        case .high:     return Brand.signal
        default:        return Color(red: 0.85, green: 0.55, blue: 0.0)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            switch osUpdate.state {
            case .updateRecommended:
                recommendedCard
            case .updateRequired:
                requiredCard
            case .deadlinePassed:
                overdueCard
            case .unsupportedHardware:
                unsupportedCard
            default:
                EmptyView()
            }
        }
    }

    // MARK: - Recommended (passive)

    private var recommendedCard: some View {
        HStack(spacing: 12) {
            Image(systemName: "arrow.down.circle")
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(accentColor)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(osUpdate.targetOs.map { "macOS \($0) available" } ?? "macOS update available")
                    .font(Brand.sans(13, weight: .medium))
                    .foregroundStyle(Brand.slate)
                subtitleLine
            }
            Spacer()
            updateNowButton
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    // MARK: - Required (deadline-bearing)

    private var requiredCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 12) {
                Image(systemName: "exclamationmark.circle")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(accentColor)
                    .frame(width: 20)
                VStack(alignment: .leading, spacing: 2) {
                    Text(osUpdate.targetOs.map { "macOS \($0) required" } ?? "macOS update required")
                        .font(Brand.sans(13, weight: .medium))
                        .foregroundStyle(Brand.slate)
                    subtitleLine
                }
                Spacer()
                updateNowButton
            }
            if onDefer != nil || osUpdate.deferralsRemaining > 0 {
                HStack {
                    Spacer()
                    deferButton
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    // MARK: - Overdue (deadline passed)

    private var overdueCard: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(accentColor)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text("macOS update overdue")
                    .font(Brand.sans(13, weight: .medium))
                    .foregroundStyle(Brand.slate)
                Text("Required update past deadline")
                    .font(Brand.mono(10))
                    .foregroundStyle(Brand.mute)
            }
            Spacer()
            updateNowButton
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    // MARK: - Unsupported hardware

    private var unsupportedCard: some View {
        HStack(spacing: 12) {
            Image(systemName: "info.circle")
                .font(.system(size: 13))
                .foregroundStyle(Brand.mute)
                .frame(width: 20)
            Text(osUpdate.targetOs.map { "This Mac cannot reach macOS \($0)" } ?? "This Mac cannot reach the required macOS version")
                .font(Brand.sans(12))
                .foregroundStyle(Brand.mute)
            Spacer()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    // MARK: - Shared components

    @ViewBuilder
    private var subtitleLine: some View {
        HStack(spacing: 6) {
            if osUpdate.activelyExploited {
                Text("Actively exploited CVE")
                    .font(Brand.mono(10))
                    .foregroundStyle(accentColor)
            } else if osUpdate.securityRelevant {
                Text("Security update")
                    .font(Brand.mono(10))
                    .foregroundStyle(Brand.mute)
            }
            if let deadline = osUpdate.deadline {
                Text("Due \(deadline, formatter: shortDateFormatter)")
                    .font(Brand.mono(10))
                    .foregroundStyle(isRequired ? accentColor : Brand.mute)
            }
            if osUpdate.deferralsRemaining > 0 && isRequired {
                Text("\(osUpdate.deferralsRemaining) deferral\(osUpdate.deferralsRemaining == 1 ? "" : "s") left")
                    .font(Brand.mono(10))
                    .foregroundStyle(Brand.mute)
            }
        }
    }

    private var updateNowButton: some View {
        Button {
            NSWorkspace.shared.open(
                URL(string: "x-apple.systempreferences:com.apple.preferences.softwareupdate")!
            )
        } label: {
            Text("Update now")
                .font(Brand.sans(11, weight: .medium))
                .foregroundStyle(accentColor)
        }
        .buttonStyle(.plain)
    }

    @ViewBuilder
    private var deferButton: some View {
        if osUpdate.deferralsRemaining > 0 {
            Button {
                onDefer?()
                onDismiss?()
            } label: {
                Text("Remind me later")
                    .font(Brand.sans(11))
                    .foregroundStyle(Brand.mute)
            }
            .buttonStyle(.plain)
        } else {
            Text("No deferrals remaining")
                .font(Brand.mono(10))
                .foregroundStyle(Brand.mute)
        }
    }

    private let shortDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .none
        return f
    }()
}
