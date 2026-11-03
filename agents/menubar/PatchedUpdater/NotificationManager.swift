//
//  NotificationManager.swift
//  PatchedUpdater
//
//  Diffs consecutive posture loads and fires UNUserNotificationCenter alerts on
//  state transitions.
//
//  PAT-528 — U5d notifications
//

import Foundation
import UserNotifications

@MainActor final class NotificationManager: ObservableObject {
    static let shared = NotificationManager()

    private var lastUpdateIds: Set<String> = []
    private var lastFindingIds: Set<String> = []
    private var osDeadlineNotified: Bool = false

    @MainActor
    func requestPermissionIfNeeded() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    func removeAll() {
        UNUserNotificationCenter.current().removeAllPendingNotificationRequests()
        UNUserNotificationCenter.current().removeAllDeliveredNotifications()
    }

    // MARK: - Posture diff

    func evaluate(previous: Posture?, current: Posture) {
        evaluateUpdates(previous: previous, current: current)
        evaluateFindings(previous: previous, current: current)
    }

    // MARK: - OS deadline (fed from StatusStore — OsUpdate lives in UpdateStatus, not Posture)

    func evaluateOsDeadline(osUpdate: UpdateStatus.OsUpdate?) {
        guard let osUpdate, !osDeadlineNotified else { return }
        guard osUpdate.state == .updateRequired, let deadline = osUpdate.deadline else { return }
        let daysUntil = Calendar.current.dateComponents([.day], from: Date(), to: deadline).day ?? Int.max
        guard daysUntil <= 3 else { return }

        let formatter = DateFormatter()
        formatter.dateFormat = "EEE d MMM"
        let deadlineString = formatter.string(from: deadline)

        fire(
            id: "os-deadline",
            title: "macOS update required",
            body: "Required by \(deadlineString). Open Self Service to schedule."
        )
        osDeadlineNotified = true
    }

    // MARK: - Never-interrupt fallback (PAT-1624)

    /// The agent has spent its whole suppression window without finding a safe
    /// moment for the blocking window, so it hands off to a notification. The
    /// OS already handles these correctly during a call and under Focus: it
    /// delivers them quietly rather than over the screen share.
    ///
    /// The copy says nothing about why. The reason code is a local diagnostic,
    /// not something to read back to the person about their own call.
    func fireBlockingPromptFallback(osUpdate: UpdateStatus.OsUpdate?, now: Date = Date()) {
        var body = "Patched has not found a quiet moment to show this. Open Software Update when you are free."
        if let deadline = osUpdate?.deadline {
            let formatter = DateFormatter()
            formatter.dateFormat = "EEE d MMM"
            body = "Required by \(formatter.string(from: deadline)). Patched has not found a quiet moment to show this. Open Software Update when you are free."
        }

        // Date-stamped so the once-a-day fallbacks do not replace each other in
        // Notification Centre.
        let stamp = ISO8601DateFormatter.promptFallbackDayStamp.string(from: now)
        fire(
            id: "os-update-prompt-fallback-\(stamp)",
            title: "macOS update still required",
            body: body
        )
    }

    /// PAT-1623: the removal notify/defer surface's own never-interrupt
    /// fallback, mirroring fireBlockingPromptFallback exactly but with
    /// removal's plain-language copy — no deadline, no threat, names the app.
    func fireRemovalPromptFallback(appName: String?, now: Date = Date()) {
        let name = appName ?? "An application"
        let body = "\(name) is still open. Patched has not found a quiet moment to show this — it will be removed once you close it."

        // Date-stamped, same reasoning as the OS-update fallback: consecutive
        // once-a-day fallbacks must not replace each other in Notification
        // Centre, and the app name keeps two different apps' fallbacks apart
        // on the same day.
        let stamp = ISO8601DateFormatter.promptFallbackDayStamp.string(from: now)
        fire(
            id: "removal-prompt-fallback-\(name)-\(stamp)",
            title: "App removal pending",
            body: body
        )
    }

    // MARK: - Private evaluation helpers

    private func evaluateUpdates(previous: Posture?, current: Posture) {
        let currentIds = Set((current.updates ?? []).map(\.identifier))
        let previousIds = lastUpdateIds

        let newIds = currentIds.subtracting(previousIds)
        lastUpdateIds = currentIds

        guard !newIds.isEmpty else { return }
        // Only fire when there were previously no pending updates (or this is first load).
        // Avoids re-alerting on every refresh when the user already has pending updates.
        guard previousIds.isEmpty else { return }

        let allUpdates = current.updates ?? []
        let newUpdates = allUpdates.filter { newIds.contains($0.identifier) }
        let count = newUpdates.count
        guard count > 0 else { return }

        let nameList = newUpdates.prefix(3).map(\.appName)
        var body = nameList.joined(separator: ", ")
        if count > 3 { body += " + \(count - 3) more" }

        fire(id: "updates-found", title: "Updates available", body: "\(count) app\(count == 1 ? "" : "s") need updating: \(body)")
    }

    private func evaluateFindings(previous: Posture?, current: Posture) {
        let currentFindings = current.findings ?? []
        let currentIds = Set(currentFindings.map(\.id))
        let previousIds = lastFindingIds
        lastFindingIds = currentIds

        let newIds = currentIds.subtracting(previousIds)
        guard !newIds.isEmpty else { return }

        let newCritical = currentFindings.filter { newIds.contains($0.id) && $0.severity.lowercased() == "critical" }
        for finding in newCritical {
            fire(
                id: "cve-\(finding.cveId)-\(finding.appName)",
                title: "Security alert",
                body: "Critical vulnerability in \(finding.appName) \(finding.appVersion)"
            )
        }
    }

    // MARK: - Delivery

    private func fire(id: String, title: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(identifier: id, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request, withCompletionHandler: nil)
    }
}

private extension ISO8601DateFormatter {
    /// yyyy-MM-dd, used only to keep consecutive fallback notification ids apart.
    static let promptFallbackDayStamp: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withFullDate]
        return f
    }()
}
