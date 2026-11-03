// Posture.swift — platform-neutral Codable model for GET /v1/posture.
//
// Source of truth: contracts/posture.schema.json (schema_version 1).
// Do NOT import UIKit, AppKit, or any platform-specific framework here.
// Used by both the macOS menu-bar agent and the Windows-bridged Swift layer.
//
// PAT-471 · U0 · Posture read-client + vendored contract.

import Foundation

// MARK: - Top-level response

/// Decoded response from GET /v1/posture (schema_version 1).
public struct Posture: Codable, Sendable {
    public let schemaVersion: Int
    public let generatedAt: Date
    public let device: Device
    public let tier: String
    public let appCount: Int
    public let compliance: Compliance
    public let evidence: Evidence
    public let findings: [Finding]?
    public let updates: [Update]?
    public let appPolicy: AppPolicy?

    enum CodingKeys: String, CodingKey {
        case schemaVersion  = "schema_version"
        case generatedAt    = "generated_at"
        case device
        case tier
        case appCount       = "app_count"
        case compliance
        case evidence
        case findings
        case updates
        case appPolicy      = "app_policy"
    }
}

// MARK: - Device

public struct Device: Codable, Sendable {
    public let id: String
    public let serial: String?
    public let hwUuid: String?
    public let hostname: String?
    public let computerName: String?
    public let hwModel: String?
    public let arch: String?
    public let os: String
    public let osVersion: String?
    public let osBuild: String?
    public let agentVersion: String?
    public let firstSeen: Date?
    public let lastSeen: Date?

    enum CodingKeys: String, CodingKey {
        case id
        case serial
        case hwUuid        = "hw_uuid"
        case hostname
        case computerName  = "computer_name"
        case hwModel       = "hw_model"
        case arch
        case os
        case osVersion     = "os_version"
        case osBuild       = "os_build"
        case agentVersion  = "agent_version"
        case firstSeen     = "first_seen"
        case lastSeen      = "last_seen"
    }
}

// MARK: - Compliance

public struct Compliance: Codable, Sendable {
    public let platform: String
    public let benchmarks: [Benchmark]
}

public struct Benchmark: Codable, Sendable {
    public let benchmark: String
    public let benchmarkVersion: String
    public let implemented: Int
    public let benchmarkTotal: Int
    public let passed: Int
    public let failed: Int
    public let notApplicable: Int
    public let errors: Int
    public let compliancePct: Double
    public let sections: [Section]

    enum CodingKeys: String, CodingKey {
        case benchmark
        case benchmarkVersion  = "benchmark_version"
        case implemented
        case benchmarkTotal    = "benchmark_total"
        case passed
        case failed
        case notApplicable     = "not_applicable"
        case errors
        case compliancePct     = "compliance_pct"
        case sections
    }
}

public struct Section: Codable, Sendable {
    public let section: String
    public let passed: Int
    public let total: Int
    public let controls: [Control]
}

public struct Control: Codable, Sendable {
    public let ruleKey: String
    public let title: String
    public let severity: Severity
    public let status: ControlStatus
    public let observedValue: String?
    public let evaluatedAt: Date

    enum CodingKeys: String, CodingKey {
        case ruleKey       = "rule_key"
        case title
        case severity
        case status
        case observedValue = "observed_value"
        case evaluatedAt   = "evaluated_at"
    }
}

public enum Severity: String, Codable, Sendable {
    case low, medium, high, critical
}

public enum ControlStatus: String, Codable, Sendable {
    case pass, fail, notApplicable = "not_applicable", error
}

// MARK: - Evidence

public struct Evidence: Codable, Sendable {
    public let coverageWindowDays: Int
    public let scansLogged: Int
    public let lastSignedReportDigest: String?
    public let recentScanTimes: [Date]

    enum CodingKeys: String, CodingKey {
        case coverageWindowDays    = "coverage_window_days"
        case scansLogged           = "scans_logged"
        case lastSignedReportDigest = "last_signed_report_digest"
        case recentScanTimes       = "recent_scan_times"
    }
}

// MARK: - Findings (CVE)

public struct Finding: Codable, Sendable {
    public let cveId: String
    public let description: String
    public let cvssV3Score: Double?
    public let severity: String
    public let publishedAt: Date?
    public let appName: String
    public let appVersion: String
    public let matchConfidence: MatchConfidence
    public let lastSeenAt: Date

    enum CodingKeys: String, CodingKey {
        case cveId           = "cve_id"
        case description
        case cvssV3Score     = "cvss_v3_score"
        case severity
        case publishedAt     = "published_at"
        case appName         = "app_name"
        case appVersion      = "app_version"
        case matchConfidence = "match_confidence"
        case lastSeenAt      = "last_seen_at"
    }
}

public enum MatchConfidence: String, Codable, Sendable {
    case versionConfirmed  = "version_confirmed"
    case versionUnverified = "version_unverified"
}

// MARK: - Updates

public struct Update: Codable, Sendable {
    public let appName: String
    public let identifier: String
    public let currentVersion: String
    public let targetVersion: String
    public let source: UpdateSource
    public let linkedCveIds: [String]

    enum CodingKeys: String, CodingKey {
        case appName        = "app_name"
        case identifier
        case currentVersion = "current_version"
        case targetVersion  = "target_version"
        case source
        case linkedCveIds   = "linked_cve_ids"
    }
}

public enum UpdateSource: String, Codable, Sendable {
    case catalog, manual
}

// MARK: - App Policy

public struct AppPolicy: Codable, Sendable {
    public let apps: [AppPolicyEntry]
    public let drift: [DriftEntry]
}

public struct AppPolicyEntry: Codable, Sendable {
    public let appName: String
    public let identifier: String
    public let policy: PolicyType
    public let userRemovable: Bool
    public let enforcementTier: EnforcementTier

    enum CodingKeys: String, CodingKey {
        case appName         = "app_name"
        case identifier
        case policy
        case userRemovable   = "user_removable"
        case enforcementTier = "enforcement_tier"
    }
}

public struct DriftEntry: Codable, Sendable {
    public let driftType: DriftType
    public let appName: String
    public let identifier: String
    public let policy: PolicyType
    public let enforcementTier: EnforcementTier

    enum CodingKeys: String, CodingKey {
        case driftType       = "drift_type"
        case appName         = "app_name"
        case identifier
        case policy
        case enforcementTier = "enforcement_tier"
    }
}

public enum PolicyType: String, Codable, Sendable {
    case mandatory, approved, unapproved, unmanaged
}

public enum DriftType: String, Codable, Sendable {
    case mandatoryMissing  = "mandatory_missing"
    case unapprovedPresent = "unapproved_present"
}

public enum EnforcementTier: String, Codable, Sendable {
    case report
    case appManagement = "app_management"
    case managed
}
