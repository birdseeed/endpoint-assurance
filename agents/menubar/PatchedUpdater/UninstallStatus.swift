//
//  UninstallStatus.swift
//  PatchedUpdater
//
//  Codable model for /Library/Application Support/Patched/uninstall-status.json,
//  written atomically by the privileged uninstall-check daemon
//  (endpoint/patched-uninstall.sh, PAT-376). Schema:
//  contracts/uninstall-status.schema.json (schema_version 1). Field-for-field
//  identical outcome vocabulary to the Windows engine
//  (windows/src/Shared/Removal/RemovalContracts.cs's RemovalOutcome) so both
//  platforms describe removal state through one shared shape.
//
//  PAT-1623: before this ticket the menu bar app never read this file at all —
//  the backend already detected a running removal target and wrote
//  outcome == "deferred_app_running" here, but nothing told the person at the
//  keyboard. This model only decodes what the notify/defer surface needs
//  (entry_id, name, outcome, recorded_at); verify_result and method are left
//  undecoded rather than modelled, same as UpdateStatus.swift's convention of
//  guarding on absence rather than requiring every field up front.
//

import Foundation

struct UninstallStatus: Codable {
    let schemaVersion: Int
    let generatedAt: Date
    let lastRun: LastRun?
    let removals: [RemovalEntry]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case generatedAt = "generated_at"
        case lastRun = "last_run"
        case removals
    }

    struct LastRun: Codable {
        let startedAt: Date?
        let finishedAt: Date?

        enum CodingKeys: String, CodingKey {
            case startedAt = "started_at"
            case finishedAt = "finished_at"
        }
    }

    struct RemovalEntry: Codable, Identifiable {
        var id: Int { entryId }
        let entryId: Int
        let name: String
        let outcome: Outcome
        let recordedAt: Date

        enum CodingKeys: String, CodingKey {
            case entryId = "entry_id"
            case name
            case outcome
            case recordedAt = "recorded_at"
        }
    }

    /// Mirrors RemovalOutcome (Windows) / the shell engine's outcome strings.
    /// Decodes leniently to `.unknown` so a server/engine vocabulary addition
    /// never crashes the reader (house style, matches UpdateStatus.OverallState).
    enum Outcome: String, Codable {
        case removed
        case removedResidual = "removed_residual"
        case alreadyRemoved = "already_removed"
        case manualRemovalRequired = "manual_removal_required"
        /// The one outcome this ticket surfaces to the person at the keyboard:
        /// the target app was running and did not close, so the backend is
        /// already retrying next cycle (PAT-376/PAT-1598). Everything else
        /// here is read for completeness but drives no UI in this ticket.
        case deferredAppRunning = "deferred_app_running"
        case failedTransient = "failed_transient"
        case failedHard = "failed_hard"
        case authorityRefused = "authority_refused"
        case skippedBaselineProtected = "skipped_baseline_protected"
        case unknown

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = Outcome(rawValue: raw) ?? .unknown
        }
    }
}
