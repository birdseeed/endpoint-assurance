//
//  AgentEventLogTests.swift
//  PatchedUpdaterTests
//
//  PAT-1624: the Swift event record has to be the same shape the shell half
//  already writes (`macos/patched-collect.sh:log_jsonl`), or the log-collection
//  directive picks up two incompatible formats.
//

import XCTest
@testable import PatchedUpdater

final class AgentEventLogTests: XCTestCase {

    private var dir: URL!

    override func setUp() {
        super.setUp()
        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("agent-log-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
        super.tearDown()
    }

    private func lines(_ log: AgentEventLog) throws -> [[String: Any]] {
        let raw = try String(contentsOf: log.fileURL, encoding: .utf8)
        return raw.split(separator: "\n").compactMap {
            try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any]
        }
    }

    func testARecordCarriesTheSharedJsonLinesShape() throws {
        let log = AgentEventLog(directory: dir)
        log.info("prompt suppressed", ["reason": "camera_in_use", "attempt": 1])

        let records = try lines(log)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(Set(records[0].keys), ["ts", "level", "component", "msg", "fields"])
        XCTAssertEqual(records[0]["component"] as? String, "agent")
        XCTAssertEqual(records[0]["level"] as? String, "info")
        XCTAssertEqual(records[0]["msg"] as? String, "prompt suppressed")
        XCTAssertEqual((records[0]["fields"] as? [String: Any])?["reason"] as? String, "camera_in_use")
    }

    func testRecordsAppendOnePerLine() throws {
        let log = AgentEventLog(directory: dir)
        log.info("one")
        log.warn("two")
        log.error("three")
        XCTAssertEqual(try lines(log).count, 3)
        XCTAssertEqual(try lines(log).map { $0["level"] as? String }, ["info", "warn", "error"])
    }

    func testTheDirectoryIsCreatedOnFirstWrite() throws {
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path))
        let log = AgentEventLog(directory: dir)
        log.info("first")
        XCTAssertTrue(FileManager.default.fileExists(atPath: log.fileURL.path))
    }

    func testTheLogPathIsUserWritableNotTheRootOwnedOne() {
        // The menu-bar app holds no privilege: /Library/Logs/Patched is
        // root-owned and every write there would silently fail.
        XCTAssertFalse(AgentEventLog().fileURL.path.hasPrefix("/Library/"))
        XCTAssertTrue(AgentEventLog().fileURL.path.hasSuffix("Library/Logs/Patched/agent.jsonl"))
    }
}
