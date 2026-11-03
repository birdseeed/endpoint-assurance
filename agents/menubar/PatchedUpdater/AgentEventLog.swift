//
//  AgentEventLog.swift
//  PatchedUpdater
//
//  PAT-1624: the Swift side of the agent's structured event record.
//
//  The shell half of the agent already writes JSON lines
//  (`macos/patched-collect.sh:log_jsonl` -> /Library/Logs/Patched/collect.jsonl,
//  records shaped `{ts, level, component, msg, fields}`). There was no Swift
//  equivalent, so this is the minimal one, deliberately emitting the identical
//  record shape so one parser reads both and `log_request`'s component list can
//  pick this file up unchanged.
//
//  PATH. The menu-bar app is unprivileged: /Library/Logs/Patched is root-owned
//  and it cannot write there. It writes to the calling user's own
//  ~/Library/Logs/Patched/agent.jsonl instead, with component "agent" so the
//  two families never collide.
//
//  PRIVACY. Callers pass a reason code and counters. Nothing in this file
//  collects, derives or infers anything about what the user was doing.
//

import Foundation

// MARK: - Sink seam

protocol AgentEventSink {
    func record(level: String, msg: String, fields: [String: Any])
}

extension AgentEventSink {
    func info(_ msg: String, _ fields: [String: Any] = [:]) {
        record(level: "info", msg: msg, fields: fields)
    }
    func warn(_ msg: String, _ fields: [String: Any] = [:]) {
        record(level: "warn", msg: msg, fields: fields)
    }
    func error(_ msg: String, _ fields: [String: Any] = [:]) {
        record(level: "error", msg: msg, fields: fields)
    }
}

// MARK: - JSON lines implementation

struct AgentEventLog: AgentEventSink {

    static let component = "agent"
    /// Matches the shell helper's own truncate threshold.
    static let maxBytes: UInt64 = 10 * 1024 * 1024

    let fileURL: URL

    static var resolvedLogDirectory: URL {
        if let override = ProcessInfo.processInfo.environment["PATCHED_AGENT_LOG_DIR"], !override.isEmpty {
            return URL(fileURLWithPath: override, isDirectory: true)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/Patched", isDirectory: true)
    }

    init(directory: URL? = nil, filename: String = "agent.jsonl") {
        fileURL = (directory ?? Self.resolvedLogDirectory).appendingPathComponent(filename)
    }

    private static let timestampFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        f.timeZone = TimeZone(secondsFromGMT: 0)
        return f
    }()

    func record(level: String, msg: String, fields: [String: Any]) {
        let record: [String: Any] = [
            "ts": Self.timestampFormatter.string(from: Date()),
            "level": level,
            "component": Self.component,
            "msg": msg,
            "fields": fields,
        ]
        guard JSONSerialization.isValidJSONObject(record),
              var line = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]) else {
            return
        }
        line.append(0x0A)
        append(line)
    }

    private func append(_ line: Data) {
        let fm = FileManager.default
        let directory = fileURL.deletingLastPathComponent()
        if !fm.fileExists(atPath: directory.path) {
            try? fm.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        if !fm.fileExists(atPath: fileURL.path) {
            fm.createFile(atPath: fileURL.path, contents: nil)
        }
        guard let handle = try? FileHandle(forWritingTo: fileURL) else { return }
        defer { try? handle.close() }

        // Truncate rather than rotate. A logging helper is not worth a lock and
        // this file only ever gains a line every couple of hours.
        if let size = try? handle.seekToEnd(), size > Self.maxBytes {
            try? handle.truncate(atOffset: 0)
            try? handle.seek(toOffset: 0)
        }
        try? handle.write(contentsOf: line)
    }
}

// MARK: - Operator signal

/// How the agent tells the platform that it has a user it cannot reach.
protocol OperatorSignalSink {
    /// Raise the signal. Callers guarantee this fires at most once per
    /// suppression run.
    func signalPromptUnreachable(surface: String, reason: InterruptionReason, since: Date, suppressedDays: Int)
    /// Withdraw it: the agent got through, so the operator has nothing to act on.
    func clearPromptUnreachable(surface: String)
}

/// Writes a marker into the daemon's trigger directory, the only outbound
/// channel an unprivileged menu-bar app has (mode 1733, same directory
/// `requestOsDefer` already writes into).
///
/// The extension is `.marker`, NOT `.trigger`, and that is deliberate: the
/// daemon's consume step filters on `fn.endswith(".trigger")` and takes at most
/// one per run, so a `.trigger` here would be silently eaten and would displace
/// a real deploy or scan request. A `.marker` is invisible to that step.
///
/// The filename is fixed rather than UUID-suffixed so the marker is idempotent:
/// re-signalling overwrites, and the directory never accumulates.
///
/// KNOWN GAP, reported rather than papered over: nothing on the daemon side
/// folds this marker into the `agent_health` payload yet, so today the signal
/// is durable and local but not yet uploaded. See the follow-up on the ticket.
struct TriggerDirectoryOperatorSignal: OperatorSignalSink {

    let triggerDirectory: URL
    let events: AgentEventSink

    private func markerURL(for surface: String) -> URL {
        let safe = surface.replacingOccurrences(of: "/", with: "_")
        return triggerDirectory.appendingPathComponent("prompt-unreachable-\(safe).marker")
    }

    func signalPromptUnreachable(surface: String, reason: InterruptionReason, since: Date, suppressedDays: Int) {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        let marker: [String: Any] = [
            "type": "prompt_unreachable",
            "surface": surface,
            "reason": reason.rawValue,
            "unreachable_since": formatter.string(from: since),
            "signalled_at": formatter.string(from: Date()),
            "suppressed_days": suppressedDays,
        ]

        let fm = FileManager.default
        if !fm.fileExists(atPath: triggerDirectory.path) {
            try? fm.createDirectory(at: triggerDirectory, withIntermediateDirectories: true)
        }
        guard let data = try? JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys]) else { return }
        try? data.write(to: markerURL(for: surface), options: [.atomic])
    }

    func clearPromptUnreachable(surface: String) {
        try? FileManager.default.removeItem(at: markerURL(for: surface))
    }
}
