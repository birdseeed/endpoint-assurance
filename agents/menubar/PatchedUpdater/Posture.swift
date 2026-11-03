//
//  Posture.swift
//  PatchedUpdater
//
//  Platform-neutral Codable model for GET /v1/posture, the device posture the
//  desktop surfaces (menu-bar agent + Self Service) render from. The contract is
//  vendored at contracts/posture.schema.json (server-owned, patched.im). This
//  model is the macOS half of the U0 shared read-client; the Windows half is
//  windows/src/Shared/Posture/PostureModels.cs and must stay content-equivalent.
//
//  The app NEVER fetches this directly — it has no credentials. The privileged
//  endpoint poller verifies /v1/posture and writes a world-readable posture.json cache;
//  PostureStore reads that cache (last-known-good). See PostureStore.swift.
//
//  House style (matches UpdateStatus.swift): snake_case CodingKeys, and every
//  enum decodes leniently to an `.unknown`/conservative case so a server-side
//  vocabulary addition never crashes the reader.
//

import Foundation

struct Posture: Codable {
    let schemaVersion: Int
    let generatedAt: Date
    let device: Device
    let tier: Tier
    let appCount: Int
    let compliance: Compliance
    let evidence: Evidence
    /// Optional sections — absent on older server builds; guard on nil.
    let findings: [Finding]?
    let updates: [AppUpdate]?
    let appPolicy: AppPolicy?
    let scanStatus: ScanStatus?
    let proveStatus: ProveStatus?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case generatedAt = "generated_at"
        case device
        case tier
        case appCount = "app_count"
        case compliance
        case evidence
        case findings
        case updates
        case appPolicy = "app_policy"
        case scanStatus = "scan_status"
        case proveStatus = "prove_status"
    }

    // MARK: - Tier + honest gating
    //
    // The single seam for honest tier gating. The whole UI asks `posture.tier`
    // (or the per-app helper below) — no surface hardcodes a tier string.
    //
    // The agent has NO installer: Patch & Deploy and Uninstall are gated
    // affordances that hand off to Self Service / upgrade, never inline acts.
    // PAT-1807 collapses this to the same two-value device-tier vocabulary
    // PAT-1599 already gave the Windows agent: "managed" is the sole actuating
    // tier (matches the daemon's real deploy gate — PatchedWorker.ActuatingTierAllows
    // now accepts only "managed"). "assurance" (the observe-only default,
    // formerly "report_deploy") and anything unrecognized present these
    // actions but gated.
    //
    // This is the DEVICE tier only. Per-app enforcement is a separate,
    // unchanged vocabulary — see EnforcementTier below, which still accepts
    // "patch"/"app_management"/"managed" (PAT-1121) and is untouched by this
    // collapse.

    enum Tier: Codable, Equatable {
        case assurance
        case managed
        case other(String)

        /// Maps a raw tier string to a case. Unknown values (including the
        /// retired "report_deploy"/"patch"/"report" device-tier names) become
        /// `.other(raw)`, never a silent downgrade — the raw value stays
        /// inspectable (Plans sheet / tier-name copy already pattern-match on
        /// it) and every gate in this file still fails closed on `.other`
        /// regardless, since only `.managed` actuates. The single seam both
        /// the JSON decoder below and AgentConfigStore.mapTier (agent-config.json's
        /// tier field, same vocabulary) go through, so the two callers can't
        /// drift apart again — PAT-1416 found them disagreeing on exactly this
        /// unknown-value case.
        ///
        /// Case-insensitive on the way in (matched on `raw.lowercased()`) to stay
        /// content-equivalent with the Windows seam (PostureGating.GrantsPatchDeploy/
        /// GrantsAppManagement use StringComparison.OrdinalIgnoreCase) — PAT-1416
        /// review caught that a tier of "MANAGED" would actuate on Windows but
        /// fail closed here. `.other` keeps the original, non-lowercased `raw` so
        /// downstream compat matching (e.g. PlansSheet's `["managed", "full"]`
        /// check) still sees the real value. `rawValue` below is unaffected: it's
        /// driven by `self`, not by `raw`, so a known case always re-encodes to
        /// its one canonical lowercase string.
        init(rawString raw: String) {
            switch raw.lowercased() {
            case "assurance": self = .assurance
            case "managed":   self = .managed
            default:          self = .other(raw)
            }
        }

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self.init(rawString: raw)
        }

        func encode(to encoder: Encoder) throws {
            var c = encoder.singleValueContainer()
            try c.encode(rawValue)
        }

        var rawValue: String {
            switch self {
            case .assurance:    return "assurance"
            case .managed:      return "managed"
            case .other(let s): return s
            }
        }

        /// Whether this tier actuates Patch & Deploy / app management at all.
        /// Shared by both gates below so they cannot drift apart. Only
        /// "managed" actuates (PAT-1807); every other tier — including
        /// "assurance" and any unrecognized value — is report-only, present
        /// but gated. Conservative (fails closed) on unknown tiers.
        private var actuates: Bool { self == .managed }

        /// Patch & Deploy (Install / Get / one-click deploy) is enabled.
        var grantsPatchDeploy: Bool { actuates }

        /// App-management (user Uninstall) is enabled at the device level.
        /// Gated identically to Patch & Deploy; the per-app gate adds
        /// enforcement_tier + user_removable on top (see Posture.canUninstall).
        var grantsAppManagement: Bool { actuates }
    }

    /// Convenience for surfaces that just need the one boolean.
    var canPatchDeploy: Bool { tier.grantsPatchDeploy }

    /// Whether the user may be offered an Uninstall for this app. Three gates,
    /// all required: the device tier grants app management, the app's policy
    /// allows enforcement at app-management tier or above, and the app is
    /// user_removable (false for mandatory apps). Never a dead/fake button:
    /// when this is false the UI shows the honest gated/"Required" state.
    func canUninstall(_ app: AppPolicy.AppEntry) -> Bool {
        tier.grantsAppManagement
            && app.userRemovable
            && app.enforcementTier.actuates
    }

    // MARK: - Device

    struct Device: Codable {
        let id: String
        let serial: String?
        let hwUuid: String?
        let hostname: String?
        let computerName: String?
        let hwModel: String?
        let arch: String?
        let os: String
        let osVersion: String?
        let osBuild: String?
        let agentVersion: String?
        let firstSeen: Date?
        let lastSeen: Date?

        enum CodingKeys: String, CodingKey {
            case id, serial
            case hwUuid = "hw_uuid"
            case hostname
            case computerName = "computer_name"
            case hwModel = "hw_model"
            case arch, os
            case osVersion = "os_version"
            case osBuild = "os_build"
            case agentVersion = "agent_version"
            case firstSeen = "first_seen"
            case lastSeen = "last_seen"
        }
    }

    // MARK: - Compliance

    struct Compliance: Codable {
        let platform: String
        let benchmarks: [Benchmark]

        /// The benchmark the headline surfaces summarise (first declared).
        var primary: Benchmark? { benchmarks.first }

        struct Benchmark: Codable, Identifiable {
            var id: String { "\(benchmark) \(benchmarkVersion)" }
            let benchmark: String
            let benchmarkVersion: String
            let implemented: Int
            let benchmarkTotal: Int
            let passed: Int
            let failed: Int
            let notApplicable: Int
            let errors: Int
            let compliancePct: Double
            let sections: [Section]

            enum CodingKeys: String, CodingKey {
                case benchmark
                case benchmarkVersion = "benchmark_version"
                case implemented
                case benchmarkTotal = "benchmark_total"
                case passed, failed
                case notApplicable = "not_applicable"
                case errors
                case compliancePct = "compliance_pct"
                case sections
            }

            /// "98 of 142" — coverage, never a hardcoded total (see U1/U3 rule).
            var coverageText: String { "\(implemented) of \(benchmarkTotal)" }
        }

        struct Section: Codable, Identifiable {
            var id: String { section }
            let section: String
            let passed: Int
            let total: Int
            let controls: [Control]
        }

        struct Control: Codable, Identifiable {
            var id: String { ruleKey }
            let ruleKey: String
            let title: String
            let severity: Severity
            let status: Status
            let observedValue: String?
            let evaluatedAt: Date

            enum CodingKeys: String, CodingKey {
                case ruleKey = "rule_key"
                case title, severity, status
                case observedValue = "observed_value"
                case evaluatedAt = "evaluated_at"
            }
        }
    }

    enum ScanStatus: String, Codable {
        case active, paused, error, unknown

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = ScanStatus(rawValue: raw) ?? .unknown
        }
    }

    enum ProveStatus: String, Codable {
        case current, pending, error, unknown

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = ProveStatus(rawValue: raw) ?? .unknown
        }
    }

    enum Severity: String, Codable {
        case low, medium, high, critical, unknown

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = Severity(rawValue: raw.lowercased()) ?? .unknown
        }
    }

    enum Status: String, Codable {
        case pass, fail
        case notApplicable = "not_applicable"
        case error
        case unknown

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = Status(rawValue: raw) ?? .unknown
        }
    }

    // MARK: - Evidence

    struct Evidence: Codable {
        let coverageWindowDays: Int
        let scansLogged: Int
        let lastSignedReportDigest: String?
        let recentScanTimes: [Date]

        enum CodingKeys: String, CodingKey {
            case coverageWindowDays = "coverage_window_days"
            case scansLogged = "scans_logged"
            case lastSignedReportDigest = "last_signed_report_digest"
            case recentScanTimes = "recent_scan_times"
        }

        var lastScan: Date? { recentScanTimes.first }
    }

    // MARK: - CVE findings

    struct Finding: Codable, Identifiable {
        var id: String { "\(cveId)|\(appName)|\(appVersion)" }
        let cveId: String
        let description: String
        let cvssV3Score: Double?
        let severity: String
        let publishedAt: Date?
        let appName: String
        let appVersion: String
        let matchConfidence: MatchConfidence
        let lastSeenAt: Date

        enum CodingKeys: String, CodingKey {
            case cveId = "cve_id"
            case description
            case cvssV3Score = "cvss_v3_score"
            case severity
            case publishedAt = "published_at"
            case appName = "app_name"
            case appVersion = "app_version"
            case matchConfidence = "match_confidence"
            case lastSeenAt = "last_seen_at"
        }

        enum MatchConfidence: String, Codable {
            case versionConfirmed = "version_confirmed"
            case versionUnverified = "version_unverified"
            case unknown

            init(from decoder: Decoder) throws {
                let raw = try decoder.singleValueContainer().decode(String.self)
                self = MatchConfidence(rawValue: raw) ?? .unknown
            }
        }
    }

    // MARK: - Available updates

    struct AppUpdate: Codable, Identifiable {
        var id: String { identifier }
        let appName: String
        let identifier: String
        /// Installomator catalog label (e.g. "zoom") — this, not `identifier`
        /// (a bundle ID), is what the daemon's install trigger matches
        /// against. Optional only to tolerate a cached posture.json fetched
        /// before the server started emitting this field; falls back to
        /// `identifier` in that case (matches the prior, broken behavior —
        /// better than crashing on decode).
        let label: String?
        let currentVersion: String
        let targetVersion: String
        let source: String
        let linkedCveIds: [String]

        /// The value to request an install/update for — always prefer the
        /// catalog label over the bundle-ID `identifier`. See PAT-771-adjacent
        /// fix: the daemon's trigger matching is label-only, no ID fallback.
        var installRequestID: String { label ?? identifier }

        enum CodingKeys: String, CodingKey {
            case appName = "app_name"
            case identifier
            case label
            case currentVersion = "current_version"
            case targetVersion = "target_version"
            case source
            case linkedCveIds = "linked_cve_ids"
        }
    }

    // MARK: - App policy + drift

    struct AppPolicy: Codable {
        let apps: [AppEntry]
        let drift: [DriftEntry]

        struct AppEntry: Codable, Identifiable {
            var id: String { identifier }
            let appName: String
            let identifier: String
            /// Installomator catalog label — install/uninstall triggers and
            /// status lookups match on this, NOT on identifier (a bundle ID).
            /// Empty when no catalog entry matches (e.g. an app approved via
            /// the allowlist but not tracked by Installomator).
            let label: String
            let policy: Policy
            let userRemovable: Bool
            let enforcementTier: EnforcementTier

            enum CodingKeys: String, CodingKey {
                case appName = "app_name"
                case identifier, label, policy
                case userRemovable = "user_removable"
                case enforcementTier = "enforcement_tier"
            }
        }

        struct DriftEntry: Codable, Identifiable {
            var id: String { "\(driftType.rawValue)|\(identifier)" }
            let driftType: DriftType
            let appName: String
            let identifier: String
            let policy: Policy
            let enforcementTier: EnforcementTier

            enum CodingKeys: String, CodingKey {
                case driftType = "drift_type"
                case appName = "app_name"
                case identifier, policy
                case enforcementTier = "enforcement_tier"
            }
        }
    }

    enum Policy: String, Codable {
        case mandatory, approved, unapproved, unmanaged, unknown

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = Policy(rawValue: raw) ?? .unknown
        }

        /// "Required by your IT" badge — no Uninstall affordance.
        var isRequired: Bool { self == .mandatory }
    }

    /// Tier at which enforcement acts may be taken for an app. `report` is
    /// advisory only; `app_management`/`managed` actuate (subject to device tier).
    enum EnforcementTier: String, Codable {
        case report
        case appManagement = "app_management"
        case managed
        case unknown

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = EnforcementTier(rawValue: raw) ?? .unknown
        }

        var actuates: Bool { self == .appManagement || self == .managed }
    }

    enum DriftType: String, Codable {
        case mandatoryMissing = "mandatory_missing"
        case unapprovedPresent = "unapproved_present"
        case unknown

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = DriftType(rawValue: raw) ?? .unknown
        }
    }
}
