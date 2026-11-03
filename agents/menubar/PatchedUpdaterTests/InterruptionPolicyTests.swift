//
//  InterruptionPolicyTests.swift
//  PatchedUpdaterTests
//
//  PAT-1624: tier placement and the four tunable bounds.
//
//  The gate is unconditional at every tier; only these numbers are tunable and
//  only at managed tier. Shipping the suppression to managed tenants alone
//  would leave assurance customers, which is the launch offer, receiving
//  windows over their calls while the people who paid more are left alone, so
//  so the *policy* is managed-only and the *gate* is not.
//

import XCTest
@testable import PatchedUpdater

@MainActor
final class InterruptionPolicyTests: XCTestCase {

    private let overrides = InterruptionPolicyOverrides(
        suppressionWindowHours: 2,
        maxSuppressedAttempts: 1,
        notificationFallbackIntervalHours: 4,
        operatorSignalAfterDays: 1
    )

    // MARK: - Defaults

    func testShippedDefaultsMatchTheAgreedBounds() {
        let policy = InterruptionPolicy.defaults
        XCTAssertEqual(policy.suppressionWindowHours, 8)
        XCTAssertNil(policy.maxSuppressedAttempts)
        XCTAssertEqual(policy.notificationFallbackIntervalHours, 24)
        XCTAssertEqual(policy.operatorSignalAfterDays, 3)
        XCTAssertEqual(policy.effectiveAttemptCap(retryInterval: 2 * 3600), 4)
    }

    // MARK: - Tier placement

    func testManagedTierAppliesOverrides() {
        let policy = InterruptionPolicy.resolve(overrides: overrides, tier: .managed)
        XCTAssertEqual(policy.suppressionWindowHours, 2)
        XCTAssertEqual(policy.maxSuppressedAttempts, 1)
        XCTAssertEqual(policy.notificationFallbackIntervalHours, 4)
        XCTAssertEqual(policy.operatorSignalAfterDays, 1)
    }

    func testEveryOtherTierIgnoresOverridesEntirely() {
        for tier in [Posture.Tier.assurance, .other("report"), .other("patch"), .other("report_deploy"), .other("anything")] {
            XCTAssertEqual(
                InterruptionPolicy.resolve(overrides: overrides, tier: tier),
                .defaults,
                "tier \(tier) must run the shipped bounds"
            )
        }
    }

    func testAnUnknownTierIsNotManaged() {
        XCTAssertEqual(InterruptionPolicy.resolve(overrides: overrides, tier: nil), .defaults)
    }

    // MARK: - Out-of-range values are dropped, not clamped

    func testZeroAndNegativeValuesLeaveTheDefaultsInPlace() {
        let bad = InterruptionPolicyOverrides(
            suppressionWindowHours: 0,
            maxSuppressedAttempts: -1,
            notificationFallbackIntervalHours: 0,
            operatorSignalAfterDays: 0
        )
        XCTAssertEqual(InterruptionPolicy.resolve(overrides: bad, tier: .managed), .defaults)
    }

    func testAbsurdlyLargeValuesLeaveTheDefaultsInPlace() {
        let bad = InterruptionPolicyOverrides(
            suppressionWindowHours: 100_000,
            maxSuppressedAttempts: 100_000,
            notificationFallbackIntervalHours: 100_000,
            operatorSignalAfterDays: 100_000
        )
        XCTAssertEqual(InterruptionPolicy.resolve(overrides: bad, tier: .managed), .defaults)
    }

    func testAPartialOverrideOnlyChangesTheFieldItNames() {
        let partial = InterruptionPolicyOverrides(operatorSignalAfterDays: 7)
        let policy = InterruptionPolicy.resolve(overrides: partial, tier: .managed)
        XCTAssertEqual(policy.operatorSignalAfterDays, 7)
        XCTAssertEqual(policy.suppressionWindowHours, 8)
        XCTAssertEqual(policy.notificationFallbackIntervalHours, 24)
    }

    // MARK: - Derived attempt cap

    func testTheAttemptCapIsDerivedFromTheWindowAndTheRetryInterval() {
        let policy = InterruptionPolicy.defaults
        XCTAssertEqual(policy.effectiveAttemptCap(retryInterval: 1 * 3600), 8)
        XCTAssertEqual(policy.effectiveAttemptCap(retryInterval: 2 * 3600), 4)
        XCTAssertEqual(policy.effectiveAttemptCap(retryInterval: 3 * 3600), 3)  // rounded up
        XCTAssertEqual(policy.effectiveAttemptCap(retryInterval: 8 * 3600), 1)
    }

    func testAnExplicitCapOnlyEverTightensTheDerivedOne() {
        var policy = InterruptionPolicy.defaults
        policy.maxSuppressedAttempts = 2
        XCTAssertEqual(policy.effectiveAttemptCap(retryInterval: 2 * 3600), 2)
        // An explicit cap looser than the window cannot buy more attempts:
        // more attempts means more chances to interrupt, and silence is the
        // safe direction.
        policy.maxSuppressedAttempts = 99
        XCTAssertEqual(policy.effectiveAttemptCap(retryInterval: 2 * 3600), 4)
    }

    func testTheCapIsNeverZero() {
        XCTAssertGreaterThanOrEqual(InterruptionPolicy.defaults.effectiveAttemptCap(retryInterval: 0), 1)
        XCTAssertGreaterThanOrEqual(InterruptionPolicy.defaults.effectiveAttemptCap(retryInterval: 999 * 3600), 1)
    }

    // MARK: - Reading it out of a real agent-config.json

    private func writeConfig(_ json: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("interruption-config-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try json.write(to: dir.appendingPathComponent("agent-config.json"), atomically: true, encoding: .utf8)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    func testManagedConfigOverridesReachTheStore() throws {
        let dir = try writeConfig("""
        {
          "tenant_id": "00000000-0000-0000-0000-000000000000",
          "config_version": 3,
          "tier": "managed",
          "interruption_policy": {
            "suppression_window_hours": 12,
            "notification_fallback_interval_hours": 6,
            "operator_signal_after_days": 2
          }
        }
        """)
        let store = AgentConfigStore(baseDir: dir)
        XCTAssertEqual(store.tier, .managed)
        XCTAssertEqual(store.interruptionPolicy.suppressionWindowHours, 12)
        XCTAssertEqual(store.interruptionPolicy.notificationFallbackIntervalHours, 6)
        XCTAssertEqual(store.interruptionPolicy.operatorSignalAfterDays, 2)
    }

    func testAssuranceTierConfigOverridesAreIgnoredByTheStore() throws {
        let dir = try writeConfig("""
        {
          "tenant_id": "00000000-0000-0000-0000-000000000000",
          "config_version": 3,
          "tier": "assurance",
          "interruption_policy": {
            "suppression_window_hours": 1,
            "operator_signal_after_days": 1
          }
        }
        """)
        let store = AgentConfigStore(baseDir: dir)
        XCTAssertEqual(store.interruptionPolicy, .defaults)
    }

    func testAConfigWithNoInterruptionBlockUsesTheDefaults() throws {
        let dir = try writeConfig("""
        {
          "tenant_id": "00000000-0000-0000-0000-000000000000",
          "config_version": 1,
          "tier": "managed"
        }
        """)
        let store = AgentConfigStore(baseDir: dir)
        XCTAssertEqual(store.interruptionPolicy, .defaults)
    }
}
