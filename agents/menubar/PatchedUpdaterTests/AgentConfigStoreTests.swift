//
//  AgentConfigStoreTests.swift
//  PatchedUpdaterTests
//
//  PAT-1416: pins AgentConfigStore's tier mapping now that it's routed through
//  the shared Posture.Tier(rawString:) seam instead of its own parallel switch.
//  Covers every case that seam recognises, plus the deliberate unknown-value
//  behaviour (falls to .other(raw) — see AgentConfigStore.mapTier's own doc
//  comment for why that's still fail-closed for gating).
//
//  PAT-1807 collapsed the device-tier vocabulary to assurance/managed; the
//  retired "patch"/"report_deploy"/"report" names now fall to .other(raw)
//  like any other unrecognized value, same as Windows' string-based gate.
//

import XCTest
@testable import PatchedUpdater

@MainActor
final class AgentConfigStoreTests: XCTestCase {

    private func tempDir() -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("agent-config-test-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func writeConfig(tier: String, to dir: URL) throws {
        let json = """
        { "tier": "\(tier)" }
        """
        try Data(json.utf8).write(to: dir.appendingPathComponent("agent-config.json"))
    }

    func testMapsRetiredPatchTierToOtherAndGates() throws {
        // PAT-1807: "patch" is a retired device-tier name (folded into
        // "managed"). It is no longer a distinct case — it now falls to
        // .other(raw), the same as any other unrecognized value, and stays
        // gated.
        let dir = tempDir()
        try writeConfig(tier: "patch", to: dir)
        let store = AgentConfigStore(baseDir: dir)
        XCTAssertEqual(store.tier, .other("patch"))
        XCTAssertFalse(store.tier?.grantsPatchDeploy ?? true)
    }

    func testMapsRetiredReportDeployTierToAssuranceRoleButNotCase() throws {
        // PAT-1807: "report_deploy" is retired in favor of "assurance"; the
        // raw string no longer maps to a dedicated case, but it still gates
        // identically to the new "assurance" value (both fail closed).
        let dir = tempDir()
        try writeConfig(tier: "report_deploy", to: dir)
        let store = AgentConfigStore(baseDir: dir)
        XCTAssertEqual(store.tier, .other("report_deploy"))
        XCTAssertFalse(store.tier?.grantsPatchDeploy ?? true)
    }

    func testMapsAssuranceTier() throws {
        // PAT-1807: "assurance" is the new canonical observe-only default
        // (formerly "report_deploy").
        let dir = tempDir()
        try writeConfig(tier: "assurance", to: dir)
        let store = AgentConfigStore(baseDir: dir)
        XCTAssertEqual(store.tier, .assurance)
        XCTAssertFalse(store.tier?.grantsPatchDeploy ?? true)
    }

    func testMapsManagedTier() throws {
        // PAT-1416: the actual regression. "managed" used to fall through mapTier's
        // default arm to .report, silently overriding a correctly-gated posture.tier
        // via effectiveTier's precedence (agentConfigStore.tier ?? posture?.tier).
        let dir = tempDir()
        try writeConfig(tier: "managed", to: dir)
        let store = AgentConfigStore(baseDir: dir)
        XCTAssertEqual(store.tier, .managed)
    }

    func testMapsManagedTierCaseInsensitive() throws {
        // PAT-1416 review: same case-insensitivity pin as PostureStoreTests, on the
        // agent-config.json path — mapTier now shares Posture.Tier(rawString:), so
        // this must hold here too, not just on the posture.json decode path.
        let dir = tempDir()
        try writeConfig(tier: "MANAGED", to: dir)
        let store = AgentConfigStore(baseDir: dir)
        XCTAssertEqual(store.tier, .managed)
        XCTAssertEqual(store.tier?.rawValue, "managed")
    }

    func testMapsReportTierToOther() throws {
        // PAT-1807: "report" was never a canonical device-tier value here
        // (it was already advisory-only); it now falls to .other(raw) like
        // every other unrecognized value.
        let dir = tempDir()
        try writeConfig(tier: "report", to: dir)
        let store = AgentConfigStore(baseDir: dir)
        XCTAssertEqual(store.tier, .other("report"))
    }

    func testUnknownTierFallsToOther() throws {
        // Deliberate choice, pinned: unknown values land on .other(raw), matching
        // Posture.Tier's JSON decoder. Gating is unaffected either way (only
        // .managed actuates).
        let dir = tempDir()
        try writeConfig(tier: "some_future_tier", to: dir)
        let store = AgentConfigStore(baseDir: dir)
        XCTAssertEqual(store.tier, .other("some_future_tier"))
        XCTAssertFalse(store.tier?.grantsPatchDeploy ?? true)
    }

}
