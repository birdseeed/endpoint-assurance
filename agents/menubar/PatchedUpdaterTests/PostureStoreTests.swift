//
//  PostureStoreTests.swift
//  PatchedUpdaterTests
//
//  Desktop chain U0: posture model decoding, the honest tier-gating seam, the
//  "X of N" coverage rule, crash-safety on unknown vocabulary, and the
//  PostureStore last-known-good cache (missing file, parse, staleness).
//

import XCTest
@testable import PatchedUpdater

@MainActor
final class PostureStoreTests: XCTestCase {

    // Assurance-tier posture (gated surfaces) — PAT-1807's observe-only
    // default, formerly "report_deploy".
    private let assuranceTierJSON = """
    {
      "schema_version": 1,
      "generated_at": "2026-12-17T08:12:44Z",
      "device": { "id": "8f3a1c2e-4b5d-4e6f-9a0b-1c2d3e4f5a6b", "os": "macOS", "os_version": "15.5" },
      "tier": "assurance",
      "app_count": 73,
      "compliance": {
        "platform": "macOS",
        "benchmarks": [
          {
            "benchmark": "CIS Apple macOS", "benchmark_version": "v3.0.0",
            "implemented": 98, "benchmark_total": 142,
            "passed": 84, "failed": 11, "not_applicable": 3, "errors": 0,
            "compliance_pct": 88.4,
            "sections": [
              { "section": "2", "passed": 22, "total": 27, "controls": [
                { "rule_key": "2.5.1", "title": "FileVault", "severity": "critical", "status": "pass", "observed_value": "On", "evaluated_at": "2026-12-17T08:12:31Z" }
              ] }
            ]
          }
        ]
      },
      "evidence": { "coverage_window_days": 30, "scans_logged": 29, "last_signed_report_digest": null, "recent_scan_times": ["2026-12-17T08:12:40Z"] },
      "app_policy": {
        "apps": [
          { "app_name": "CrowdStrike Falcon", "identifier": "com.crowdstrike.falcon.Agent", "label": "crowdstrikefalcon", "policy": "mandatory", "user_removable": false, "enforcement_tier": "app_management" },
          { "app_name": "Google Chrome", "identifier": "com.google.Chrome", "label": "googlechrome", "policy": "approved", "user_removable": true, "enforcement_tier": "app_management" }
        ],
        "drift": [
          { "drift_type": "unapproved_present", "app_name": "uTorrent", "identifier": "com.bittorrent.uTorrent", "policy": "unapproved", "enforcement_tier": "app_management" }
        ]
      }
    }
    """

    private func decode(_ json: String) throws -> Posture {
        try PostureStore.decoder.decode(Posture.self, from: Data(json.utf8))
    }

    // MARK: - Model + coverage

    func testDecodesAndCoverageText() throws {
        let p = try decode(assuranceTierJSON)
        XCTAssertEqual(p.schemaVersion, 1)
        XCTAssertEqual(p.device.os, "macOS")
        XCTAssertEqual(p.appCount, 73)
        // "X of N" — never a hardcoded total.
        XCTAssertEqual(p.compliance.primary?.coverageText, "98 of 142")
    }

    // MARK: - Honest gating

    func testReportTierGatesActions() throws {
        let p = try decode(assuranceTierJSON)
        XCTAssertFalse(p.canPatchDeploy)
        let falcon = p.appPolicy!.apps[0]
        let chrome = p.appPolicy!.apps[1]
        XCTAssertTrue(falcon.policy.isRequired)
        XCTAssertFalse(p.canUninstall(falcon))   // gated + mandatory
        XCTAssertFalse(p.canUninstall(chrome))   // tier gates it
    }

    func testRetiredPatchTierNoLongerActuates() throws {
        // PAT-1807: "patch" is a retired device-tier name (folded into
        // "managed"); it now falls to .other(raw) and stays gated, same as
        // Windows' GrantsPatchDeploy/GrantsAppManagement (managed-only,
        // post-PAT-1599).
        let p = try decode(assuranceTierJSON.replacingOccurrences(of: "\"assurance\"", with: "\"patch\""))
        XCTAssertFalse(p.canPatchDeploy)
        XCTAssertFalse(p.canUninstall(p.appPolicy!.apps[0]))
        XCTAssertFalse(p.canUninstall(p.appPolicy!.apps[1]))
    }

    func testManagedTierEnablesActionsExceptMandatory() throws {
        // PAT-1807: "managed" is the sole actuating device tier (PAT-1599
        // retired the former "patch" rung entirely); it is the agent tier
        // the "full_endpoint" subscription tier maps to (PAT-1048/PAT-1121).
        let p = try decode(assuranceTierJSON.replacingOccurrences(of: "\"assurance\"", with: "\"managed\""))
        XCTAssertTrue(p.canPatchDeploy)
        XCTAssertFalse(p.canUninstall(p.appPolicy!.apps[0]))  // mandatory: user_removable=false
        XCTAssertTrue(p.canUninstall(p.appPolicy!.apps[1]))   // approved + app_management + removable
    }

    func testManagedTierDecodeIsCaseInsensitiveAndReencodesCanonical() throws {
        // PAT-1416 review: Windows' PostureGating matches "managed" with
        // OrdinalIgnoreCase; this pins the macOS seam at the same behaviour so
        // "MANAGED" cannot actuate on Windows while failing closed here.
        let p = try decode(assuranceTierJSON.replacingOccurrences(of: "\"assurance\"", with: "\"MANAGED\""))
        XCTAssertEqual(p.tier, .managed)
        XCTAssertTrue(p.canPatchDeploy)
        XCTAssertEqual(p.tier.rawValue, "managed")  // re-encodes canonical lowercase, not "MANAGED"

        let reencoded = try JSONEncoder().encode(p.tier)
        XCTAssertEqual(String(data: reencoded, encoding: .utf8), "\"managed\"")
    }

    func testUnknownVocabularyDoesNotThrow() throws {
        let json = assuranceTierJSON
            .replacingOccurrences(of: "\"critical\"", with: "\"catastrophic\"")
            .replacingOccurrences(of: "\"assurance\"", with: "\"some_future_tier\"")
        let p = try decode(json)
        XCTAssertFalse(p.canPatchDeploy)                                 // unknown tier → gated
        XCTAssertEqual(p.compliance.primary?.sections[0].controls[0].severity, .unknown)
    }

    // MARK: - PostureStore cache (last-known-good)

    private func tempDir() -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("posture-test-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func testMissingCacheIsFirstRunNotError() {
        let store = PostureStore(baseDir: tempDir())
        XCTAssertNil(store.posture)
        XCTAssertNil(store.loadError)     // no file = honest first-run
        XCTAssertFalse(store.isStale)
    }

    func testReadsCachedPosture() throws {
        let dir = tempDir()
        try Data(assuranceTierJSON.utf8).write(to: dir.appendingPathComponent("posture.json"))
        let store = PostureStore(baseDir: dir)
        XCTAssertNotNil(store.posture)
        XCTAssertEqual(store.posture?.appCount, 73)
        XCTAssertNil(store.loadError)
        XCTAssertEqual(store.lastConnectedAt, store.posture?.generatedAt)
    }

    func testRejectsRawSignedEnvelope() throws {
        let dir = tempDir()
        let rawEnvelope = """
        { "signed_payload": "eyJub3QiOiJhIHBvc3R1cmUifQ==", "key_id": "test", "signature": "test" }
        """
        try Data(rawEnvelope.utf8).write(to: dir.appendingPathComponent("posture.json"))

        let store = PostureStore(baseDir: dir)

        XCTAssertNil(store.posture)
        XCTAssertNil(store.lastConnectedAt)
        XCTAssertNotNil(store.loadError)
    }

    func testCorruptCacheSurfacesError() throws {
        let dir = tempDir()
        try Data("{ not json".utf8).write(to: dir.appendingPathComponent("posture.json"))
        let store = PostureStore(baseDir: dir)
        XCTAssertNotNil(store.loadError)
    }

    func testStalenessFlag() throws {
        let dir = tempDir()
        // generated_at well beyond the 36h threshold.
        let oldJSON = assuranceTierJSON.replacingOccurrences(
            of: "\"2026-12-17T08:12:44Z\"", with: "\"2000-01-01T00:00:00Z\"")
        try Data(oldJSON.utf8).write(to: dir.appendingPathComponent("posture.json"))
        let store = PostureStore(baseDir: dir)
        XCTAssertNotNil(store.posture)
        XCTAssertTrue(store.isStale)
    }
}
