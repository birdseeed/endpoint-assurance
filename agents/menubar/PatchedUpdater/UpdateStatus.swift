//
//  UpdateStatus.swift
//  PatchedUpdater
//
//  Codable model for /Library/Application Support/Patched/update-status.json.
//  This is the read-only contract the privileged update daemon writes and the
//  menu bar app consumes. Schema version tracks PAT-45.
//

import Foundation

struct UpdateStatus: Codable {
    let schemaVersion: Int
    let generatedAt: Date
    let device: Device?
    let lastRun: LastRun?
    let nextScheduledRun: Date?
    let overallState: OverallState
    let counts: Counts?
    let apps: [AppEntry]
    /// PAT-273: OS update awareness. Absent until that ticket lands; guard on nil.
    let osUpdate: OsUpdate?
    /// PAT-300: configuration/CIS advisory findings. Absent until daemon has run with compliance detection. Guard on nil.
    let complianceFindings: [ComplianceFinding]?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case generatedAt = "generated_at"
        case device
        case lastRun = "last_run"
        case nextScheduledRun = "next_scheduled_run"
        case overallState = "overall_state"
        case counts
        case apps
        case osUpdate = "os_update"
        case complianceFindings = "compliance_findings"
    }

    struct Device: Codable {
        let hwUuid: String?
        let computerName: String?

        enum CodingKeys: String, CodingKey {
            case hwUuid = "hw_uuid"
            case computerName = "computer_name"
        }
    }

    struct LastRun: Codable {
        let startedAt: Date?
        let finishedAt: Date?
        let trigger: String?
        let installomatorTag: String?

        enum CodingKeys: String, CodingKey {
            case startedAt = "started_at"
            case finishedAt = "finished_at"
            case trigger
            case installomatorTag = "installomator_tag"
        }
    }

    struct Counts: Codable {
        let total: Int
        let upToDate: Int
        let updatesAvailable: Int
        let errors: Int

        enum CodingKeys: String, CodingKey {
            case total
            case upToDate = "up_to_date"
            case updatesAvailable = "updates_available"
            case errors
        }
    }

    enum OverallState: String, Codable {
        case upToDate = "up_to_date"
        case updatesAvailable = "updates_available"
        case updating
        case error
        case unknown

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = OverallState(rawValue: raw) ?? .unknown
        }
    }

    struct AppEntry: Codable, Identifiable {
        var id: String { label }
        let label: String
        let name: String
        let installedVersion: String?
        let availableVersion: String?
        let state: AppState
        let lastAction: LastAction?
        let lastActionAt: Date?
        /// PAT-45: renamed from verified_team_id.
        let verifiedSigner: String?
        /// PAT-45: non-null when state == .verificationFailed.
        let failureReason: FailureReason?
        let message: String?

        enum CodingKeys: String, CodingKey {
            case label
            case name
            case installedVersion = "installed_version"
            case availableVersion = "available_version"
            case state
            case lastAction = "last_action"
            case lastActionAt = "last_action_at"
            case verifiedSigner = "verified_signer"
            case failureReason = "failure_reason"
            case message
        }

        enum FailureReason: String, Codable {
            case missingExpectedSigner = "missing_expected_signer"
            case signatureUntrusted    = "signature_untrusted"
            case signerMismatch        = "signer_mismatch"
            case blockedVersion = "blocked_version"
            case blockedVersionResolutionFailed = "blocked_version_resolution_failed"
            case sha256Mismatch = "sha256_mismatch"
            case executionAuthorityRefused = "execution_authority_refused"

            init(from decoder: Decoder) throws {
                let raw = try decoder.singleValueContainer().decode(String.self)
                self = FailureReason(rawValue: raw) ?? .signerMismatch
            }
        }

        enum LastAction: String, Codable {
            case installed
            case alreadyCurrent = "already_current"
            case updateAvailable = "update_available"
            case notInstalled = "not_installed"
            case verificationFailed = "verification_failed"
            case error
            case versionBlocked = "version_blocked"
            case authorityRefused = "authority_refused"
            case unknown

            init(from decoder: Decoder) throws {
                let raw = try decoder.singleValueContainer().decode(String.self)
                self = LastAction(rawValue: raw) ?? .unknown
            }
        }
    }

    // MARK: - OS update (PAT-273)

    struct OsUpdate: Codable {
        let installedOs: String
        let latestOs: String?
        /// Nil when neither a policy target nor the latest release is known
        /// (PAT-2133); the daemon then reports state `unknown` and omits the key.
        let targetOs: String?
        let state: OsUpdateState
        let severity: Severity
        let securityRelevant: Bool
        let activelyExploited: Bool
        let deadline: Date?
        let deferralsRemaining: Int
        let releaseAgeDays: Int?
        let checkedAt: Date

        enum CodingKeys: String, CodingKey {
            case installedOs       = "installed_os"
            case latestOs          = "latest_os"
            case targetOs          = "target_os"
            case state
            case severity
            case securityRelevant  = "security_relevant"
            case activelyExploited = "actively_exploited"
            case deadline
            case deferralsRemaining = "deferrals_remaining"
            case releaseAgeDays    = "release_age_days"
            case checkedAt         = "checked_at"
        }

        enum Severity: String, Codable {
            case none, low, medium, high, critical

            var label: String { rawValue.capitalized }
            var isUrgent: Bool { self == .high || self == .critical }

            init(from decoder: Decoder) throws {
                let raw = try decoder.singleValueContainer().decode(String.self)
                self = Severity(rawValue: raw) ?? .medium
            }
        }

        enum OsUpdateState: String, Codable {
            case upToDate          = "up_to_date"
            case updateRecommended = "update_recommended"
            case updateRequired    = "update_required"
            case deadlinePassed    = "deadline_passed"
            case unsupportedHardware = "unsupported_hardware"
            case unknown

            init(from decoder: Decoder) throws {
                let raw = try decoder.singleValueContainer().decode(String.self)
                self = OsUpdateState(rawValue: raw) ?? .unknown
            }
        }

        /// True when the app should escalate to a blocking acknowledgement window.
        /// Derived from severity (computed by the daemon) rather than recalculating
        /// the blocking_window_days threshold in the app — the daemon already
        /// promotes to .high when the deadline is within the blocking window.
        var requiresBlockingPrompt: Bool {
            guard state == .updateRequired || state == .deadlinePassed else { return false }
            return severity.isUrgent
        }

        /// True when the card should be shown at all.
        var shouldShowCard: Bool { state != .upToDate && state != .unknown }
    }

    enum AppState: String, Codable {
        case upToDate = "up_to_date"
        case updateAvailable = "update_available"
        case updating
        case installed
        case verificationFailed = "verification_failed"
        case error
        case notInstalled = "not_installed"
        case unknown

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = AppState(rawValue: raw) ?? .unknown
        }
    }
}

// MARK: - Presentation helpers

extension UpdateStatus.AppEntry.FailureReason {
    var displayText: String {
        switch self {
        case .missingExpectedSigner: return "missing expected signer"
        case .signatureUntrusted:    return "signature untrusted"
        case .signerMismatch:        return "signer mismatch"
        case .blockedVersion:        return "version blocked"
        case .blockedVersionResolutionFailed: return "blocked version could not be resolved"
        case .sha256Mismatch:        return "download hash mismatch"
        case .executionAuthorityRefused: return "execution authority refused"
        }
    }
}

extension UpdateStatus.AppState {
    var statusLabel: String {
        switch self {
        case .upToDate, .installed:   return "Up to date"
        case .updateAvailable:        return "Update available"
        case .updating:               return "Deploying…"
        case .verificationFailed:     return "Verification failed"
        case .error:                  return "Error"
        case .notInstalled:           return "Not installed"
        case .unknown:                return "Version pending"   // PAT-45: calm, not an error
        }
    }

    var isInProgress: Bool { self == .updating }
    var needsAttention: Bool { self == .verificationFailed || self == .error }
}

// MARK: - Compliance finding (PAT-300)

struct ComplianceFinding: Codable, Identifiable {
    var id: String { findingId }
    let findingId: String
    let severity: FindingSeverity

    enum CodingKeys: String, CodingKey {
        case findingId = "id"
        case severity
    }

    enum FindingSeverity: String, Codable {
        case low, medium, high, critical

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = FindingSeverity(rawValue: raw) ?? .medium
        }
    }
}
