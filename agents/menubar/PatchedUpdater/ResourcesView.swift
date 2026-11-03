//
//  ResourcesView.swift
//  PatchedUpdater
//
//  Static docs shelf: links out to Patched documentation. Copy is placeholder
//  until docs.patched.im is populated; layout is final.
//

import SwiftUI
import AppKit

private struct DocLink {
    let title: String
    let description: String
    let urlString: String
    let symbol: String
}

private let docLinks: [DocLink] = [
    DocLink(
        title: "What Patched verifies",
        description: "How Developer ID and provenance are checked before every deploy",
        urlString: "https://docs.patched.im/verification",
        symbol: "checkmark.seal"
    ),
    DocLink(
        title: "Update policy",
        description: "How updates are staged, verified, and promoted to your catalog",
        urlString: "https://docs.patched.im/policy",
        symbol: "arrow.triangle.2.circlepath"
    ),
    DocLink(
        title: "Request an app",
        description: "Ask for an app to be added to your tenant's allowlist",
        urlString: "https://docs.patched.im/request",
        symbol: "plus.square"
    ),
    DocLink(
        title: "Open dashboard",
        description: "View compliance reports, CVE findings, and estate posture",
        urlString: "https://dashboard.patched.im",
        symbol: "chart.bar.doc.horizontal"
    ),
]

struct ResourcesView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                sectionHeader("Documentation")

                ForEach(docLinks, id: \.title) { link in
                    DocRow(link: link)
                    Divider().overlay(Brand.hair).padding(.leading, 52)
                }

                sectionHeader("Support")

                DocRow(link: DocLink(
                    title: "Get help",
                    description: "Contact the Patched team for deployment or configuration questions",
                    urlString: "https://dashboard.patched.im/support",
                    symbol: "questionmark.circle"
                ))
            }
        }
        .background(Brand.snow)
    }

    private func sectionHeader(_ text: String) -> some View {
        Text(text.uppercased())
            .font(Brand.mono(10).uppercaseSmallCaps())
            .foregroundStyle(Brand.mute)
            .padding(.horizontal, 16)
            .padding(.top, 14)
            .padding(.bottom, 6)
    }
}

private struct DocRow: View {
    let link: DocLink

    var body: some View {
        Button {
            if let url = URL(string: link.urlString) {
                NSWorkspace.shared.open(url)
            }
        } label: {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: link.symbol)
                    .font(.system(size: 14))
                    .foregroundStyle(Brand.mute)
                    .frame(width: 20, alignment: .center)
                    .padding(.top, 1)

                VStack(alignment: .leading, spacing: 2) {
                    Text(link.title)
                        .font(Brand.sans(13, weight: .medium))
                        .foregroundStyle(Brand.slate)
                    Text(link.description)
                        .font(Brand.sans(11))
                        .foregroundStyle(Brand.mute)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer()

                Text("→")
                    .font(Brand.sans(13))
                    .foregroundStyle(Brand.mute)
                    .padding(.top, 1)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
