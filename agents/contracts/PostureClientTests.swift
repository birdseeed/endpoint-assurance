// PostureClientTests.swift — XCTest suite for PostureClient + Posture model.
//
// Tests:
//   1. Decode contracts/posture.sample.macos.json completely.
//   2. Decode contracts/posture.sample.windows.json completely.
//   3. Offline fallback: missing cache + network failure → throws offlineNoCacheAvailable.
//   4. Offline fallback: cache present + network failure → returns cached Posture.
//
// These tests are self-contained; they do NOT need a live server.
//
// PAT-471 · U0 · Posture read-client + vendored contract.

import XCTest
@testable import Patched   // adjust the module name to wherever Posture.swift / PostureClient.swift live

// MARK: - Fixture Loader

private enum Fixture {
    static func load(_ name: String) -> Data {
        // Resolve relative to this source file so the tests work without a bundle.
        let thisFile = URL(fileURLWithPath: #file)
        // Tests live in contracts/; the fixtures are siblings (also in contracts/).
        let url = thisFile.deletingLastPathComponent().appendingPathComponent(name)
        guard let data = try? Data(contentsOf: url), !data.isEmpty else {
            XCTFail("Cannot load fixture \(name) from \(url.path)")
            return Data()
        }
        return data
    }

    static var macos: Data { load("posture.sample.macos.json") }
    static var windows: Data { load("posture.sample.windows.json") }
}

// MARK: - Decoder helper

private let iso8601Decoder: JSONDecoder = {
    let d = JSONDecoder()
    d.dateDecodingStrategy = .iso8601
    return d
}()

// MARK: - PostureDecodeTests

final class PostureDecodeTests: XCTestCase {

    // -------------------------------------------------------------------------
    // 1. Decode macOS sample fixture completely

    func testDecodeMacosSampleFixture() throws {
        let posture = try iso8601Decoder.decode(Posture.self, from: Fixture.macos)

        // Top-level
        XCTAssertEqual(posture.schemaVersion, 1)
        XCTAssertEqual(posture.tier, "assurance")
        XCTAssertEqual(posture.appCount, 73)

        // Device
        XCTAssertEqual(posture.device.id, "8f3a1c2e-4b5d-4e6f-9a0b-1c2d3e4f5a6b")
        XCTAssertEqual(posture.device.serial, "C02ABCD1EFGH")
        XCTAssertEqual(posture.device.os, "macOS")
        XCTAssertEqual(posture.device.arch, "arm64")
        XCTAssertEqual(posture.device.osVersion, "15.5")
        XCTAssertEqual(posture.device.agentVersion, "1.4.2")
        XCTAssertNotNil(posture.device.firstSeen)
        XCTAssertNotNil(posture.device.lastSeen)

        // Compliance
        XCTAssertEqual(posture.compliance.platform, "macOS")
        XCTAssertEqual(posture.compliance.benchmarks.count, 1)
        let bm = posture.compliance.benchmarks[0]
        XCTAssertEqual(bm.benchmark, "CIS Apple macOS")
        XCTAssertEqual(bm.benchmarkVersion, "v3.0.0")
        XCTAssertEqual(bm.implemented, 98)
        XCTAssertEqual(bm.benchmarkTotal, 142)
        XCTAssertEqual(bm.passed, 84)
        XCTAssertEqual(bm.failed, 11)
        XCTAssertEqual(bm.notApplicable, 3)
        XCTAssertEqual(bm.errors, 0)
        XCTAssertEqual(bm.compliancePct, 88.4, accuracy: 0.001)
        XCTAssertEqual(bm.sections.count, 2)

        let section2 = bm.sections[0]
        XCTAssertEqual(section2.section, "2")
        XCTAssertEqual(section2.passed, 22)
        XCTAssertEqual(section2.total, 27)
        XCTAssertEqual(section2.controls.count, 3)

        let gatekeeperControl = section2.controls[0]
        XCTAssertEqual(gatekeeperControl.ruleKey, "2.3.3.12")
        XCTAssertEqual(gatekeeperControl.severity, .high)
        XCTAssertEqual(gatekeeperControl.status, .pass)
        XCTAssertEqual(gatekeeperControl.observedValue, "assessments enabled")
        XCTAssertNotNil(gatekeeperControl.evaluatedAt)

        // Evidence
        XCTAssertEqual(posture.evidence.coverageWindowDays, 30)
        XCTAssertEqual(posture.evidence.scansLogged, 29)
        XCTAssertNotNil(posture.evidence.lastSignedReportDigest)
        XCTAssertEqual(posture.evidence.recentScanTimes.count, 5)

        // Findings
        let findings = try XCTUnwrap(posture.findings)
        XCTAssertEqual(findings.count, 2)
        let f0 = findings[0]
        XCTAssertEqual(f0.cveId, "CVE-2025-24201")
        XCTAssertEqual(f0.cvssV3Score, 8.8, accuracy: 0.001)
        XCTAssertEqual(f0.matchConfidence, .versionConfirmed)
        XCTAssertNotNil(f0.publishedAt)
        XCTAssertNotNil(f0.lastSeenAt)

        // Updates
        let updates = try XCTUnwrap(posture.updates)
        XCTAssertEqual(updates.count, 2)
        XCTAssertEqual(updates[0].identifier, "com.google.Chrome")
        XCTAssertEqual(updates[0].source, .catalog)
        XCTAssertEqual(updates[0].linkedCveIds, ["CVE-2025-24201"])

        // App policy
        let policy = try XCTUnwrap(posture.appPolicy)
        XCTAssertEqual(policy.apps.count, 3)
        XCTAssertEqual(policy.apps[0].policy, .mandatory)
        XCTAssertFalse(policy.apps[0].userRemovable)
        XCTAssertEqual(policy.apps[0].enforcementTier, .appManagement)
        XCTAssertEqual(policy.drift.count, 2)
        XCTAssertEqual(policy.drift[0].driftType, .unapprovedPresent)
        XCTAssertEqual(policy.drift[1].driftType, .mandatoryMissing)
    }

    // -------------------------------------------------------------------------
    // 2. Decode Windows sample fixture completely

    func testDecodeWindowsSampleFixture() throws {
        let posture = try iso8601Decoder.decode(Posture.self, from: Fixture.windows)

        // Top-level
        XCTAssertEqual(posture.schemaVersion, 1)
        XCTAssertEqual(posture.tier, "assurance")
        XCTAssertEqual(posture.appCount, 61)

        // Device
        XCTAssertEqual(posture.device.os, "Windows")
        XCTAssertEqual(posture.device.arch, "x86_64")
        XCTAssertEqual(posture.device.osBuild, "26100")

        // Compliance
        XCTAssertEqual(posture.compliance.platform, "Windows")
        let bm = posture.compliance.benchmarks[0]
        XCTAssertEqual(bm.benchmark, "CIS Microsoft Windows 11 Enterprise")
        XCTAssertEqual(bm.sections.count, 2)
        let section18 = bm.sections[1]
        XCTAssertEqual(section18.section, "18")

        // Findings
        let findings = try XCTUnwrap(posture.findings)
        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings[0].cveId, "CVE-2025-21333")
        XCTAssertEqual(findings[0].cvssV3Score, 7.8, accuracy: 0.001)
        XCTAssertEqual(findings[0].matchConfidence, .versionConfirmed)

        // Updates
        let updates = try XCTUnwrap(posture.updates)
        XCTAssertEqual(updates.count, 2)
        XCTAssertEqual(updates[1].appName, "7-Zip")
        XCTAssertTrue(updates[1].linkedCveIds.isEmpty)

        // App policy
        let policy = try XCTUnwrap(posture.appPolicy)
        XCTAssertEqual(policy.drift.count, 1)
        XCTAssertEqual(policy.drift[0].driftType, .unapprovedPresent)
        XCTAssertEqual(policy.drift[0].appName, "qBittorrent")
    }
}

// MARK: - PostureClientOfflineTests

// ---- Stub URL protocol ----

/// A URLProtocol that always fails with a network error.
private final class FailingURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let error = URLError(.notConnectedToInternet)
        client?.urlProtocol(self, didFailWithError: error)
    }
    override func stopLoading() {}
}

private func makeFailingSession() -> URLSession {
    let config = URLSessionConfiguration.ephemeral
    config.protocolClasses = [FailingURLProtocol.self]
    return URLSession(configuration: config)
}

// ---- Tests ----

final class PostureClientOfflineTests: XCTestCase {

    // Temporary directories used by each test (cleaned up in tearDown).
    private var tmpCredsDir: URL!
    private var tmpCacheFile: URL!

    override func setUp() {
        super.setUp()
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("PostureClientTests-\(UUID().uuidString)")
        tmpCredsDir = base.appendingPathComponent("creds")
        tmpCacheFile = base.appendingPathComponent("posture.cache.json")
        try? FileManager.default.createDirectory(at: tmpCredsDir, withIntermediateDirectories: true)
        // Write fake credentials so the client doesn't throw credentialMissing.
        writeCredential("bearer-token", value: "test-bearer-token")
        // Fake HMAC secret: 32 zero bytes, base64-encoded.
        writeCredential("hmac-secret", value: Data(count: 32).base64EncodedString())
    }

    override func tearDown() {
        let base = tmpCredsDir.deletingLastPathComponent()
        try? FileManager.default.removeItem(at: base)
        super.tearDown()
    }

    private func writeCredential(_ name: String, value: String) {
        let url = tmpCredsDir.appendingPathComponent(name)
        try? value.data(using: .utf8)?.write(to: url)
    }

    // -------------------------------------------------------------------------
    // 3. Missing cache + network failure → throws offlineNoCacheAvailable

    func testMissingCacheAndOfflineThrows() async throws {
        let client = PostureClient(
            credsDir: tmpCredsDir,
            apiBaseURL: URL(string: "https://127.0.0.1:0")!,  // unreachable
            cacheFileURL: tmpCacheFile,
            urlSession: makeFailingSession()
        )

        do {
            _ = try await client.fetch()
            XCTFail("Expected offlineNoCacheAvailable to be thrown")
        } catch PostureClientError.offlineNoCacheAvailable {
            // Expected.
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    // -------------------------------------------------------------------------
    // 4. Cache present + network failure → returns cached Posture

    func testCachedPostureReturnedWhenOffline() async throws {
        // Write the macOS sample fixture as the cache.
        let cacheDir = tmpCacheFile.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
        try Fixture.macos.write(to: tmpCacheFile)

        let client = PostureClient(
            credsDir: tmpCredsDir,
            apiBaseURL: URL(string: "https://127.0.0.1:0")!,
            cacheFileURL: tmpCacheFile,
            urlSession: makeFailingSession()
        )

        let posture = try await client.fetch()
        XCTAssertEqual(posture.schemaVersion, 1)
        XCTAssertEqual(posture.device.os, "macOS")
        XCTAssertEqual(posture.tier, "assurance")
    }
}
