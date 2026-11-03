//
//  PostureStore.swift
//  PatchedUpdater
//
//  Reads posture.json (the world-readable cache the privileged endpoint poller
//  writes after verifying GET /v1/posture) and publishes it to the
//  desktop surfaces. The app holds NO credentials and never hits the network: it
//  only reads this last-known-good cache, so it renders the last posture even
//  when offline. Mirrors StatusStore.swift (same base dir, file-watch + poll).
//
//  Windows parity: windows/src/Shared/Posture/PostureReader.cs.
//
//  Paths default to /Library/Application Support/Patched. Set PATCHED_UPDATER_DIR
//  to a writable directory for local development without the collector installed.
//

import Foundation
import Combine

@MainActor
final class PostureStore: ObservableObject {

    /// Last-known-good posture, or nil when no cache exists yet (first run,
    /// pre-collector) or the cache could not be parsed.
    @Published private(set) var posture: Posture?
    /// Set only when a cache file exists but could not be read/parsed. nil when
    /// there is simply no cache yet — that is honest first-run, not an error.
    @Published private(set) var loadError: String?

    /// Posture older than this is flagged stale (the collector refreshes well
    /// inside this window). Kept in sync with PostureReader.StaleThreshold.
    static let staleThreshold: TimeInterval = 36 * 3600

    let baseDir: URL
    private var postureURL: URL { baseDir.appendingPathComponent("posture.json") }

    private var watchSource: DispatchSourceFileSystemObject?
    private var pollTimer: Timer?

    /// Resolved base dir, shared with StatusStore so both read the same location.
    static var resolvedBaseDir: URL {
        if let override = ProcessInfo.processInfo.environment["PATCHED_UPDATER_DIR"], !override.isEmpty {
            return URL(fileURLWithPath: override, isDirectory: true)
        }
        return URL(fileURLWithPath: "/Library/Application Support/Patched", isDirectory: true)
    }

    init(baseDir: URL? = nil) {
        self.baseDir = baseDir ?? Self.resolvedBaseDir
        reload()
        startWatching()
    }

    deinit {
        watchSource?.cancel()
        pollTimer?.invalidate()
    }

    // MARK: - Reading the cache

    func reload() {
        let url = postureURL
        guard FileManager.default.fileExists(atPath: url.path) else {
            posture = nil
            loadError = nil   // no file = first-run, not an error
            return
        }
        do {
            let data = try Data(contentsOf: url)
            let previousPosture = posture
            let newPosture = try Self.decoder.decode(Posture.self, from: data)
            posture = newPosture
            loadError = nil
            NotificationManager.shared.evaluate(previous: previousPosture, current: newPosture)
        } catch {
            // Keep the previously decoded posture (last-known-good) on a parse
            // failure; only surface the error so the UI can note staleness.
            loadError = "Could not read posture: \(error.localizedDescription)"
        }
    }

    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    // MARK: - Staleness

    /// Age of the cached posture, or nil when there is none.
    var age: TimeInterval? {
        guard let generatedAt = posture?.generatedAt else { return nil }
        return max(0, Date().timeIntervalSince(generatedAt))
    }

    /// Timestamp signed into the decoded posture body by the platform. This is
    /// safe to present as the last successful connection only because this
    /// store accepts the cache written by the verified privileged poller.
    var lastConnectedAt: Date? {
        posture?.generatedAt
    }

    /// True when the cache exists but is older than the stale threshold — the UI
    /// should keep rendering it but note it may be out of date.
    var isStale: Bool {
        guard let age else { return false }
        return age > Self.staleThreshold
    }

    // MARK: - File watching

    /// The verified endpoint poller writes posture.json atomically (rename), so watching the
    /// directory survives inode changes. A 60-second poll backstops missed events.
    private func startWatching() {
        let fd = open(baseDir.path, O_EVTONLY)
        if fd >= 0 {
            let source = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: fd,
                eventMask: [.write, .rename, .delete],
                queue: .main
            )
            source.setEventHandler { [weak self] in
                Task { @MainActor in self?.reload() }
            }
            source.setCancelHandler { close(fd) }
            source.resume()
            watchSource = source
        }

        pollTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.reload() }
        }
        RunLoop.main.add(pollTimer!, forMode: .common)
    }
}

// MARK: - Preview helpers

#if DEBUG
extension PostureStore {
    /// Returns a PostureStore loaded from the bundled sample fixture.
    /// Copies the fixture to a temp directory so PostureStore can read it
    /// via its normal file path (posture.json).
    static func withFixture() -> PostureStore {
        var dir = URL(fileURLWithPath: #filePath)
        for _ in 0..<8 {
            dir = dir.deletingLastPathComponent()
            let sample = dir.appendingPathComponent("contracts/posture.sample.macos.json")
            guard FileManager.default.fileExists(atPath: sample.path) else { continue }
            let tmp = FileManager.default.temporaryDirectory
                .appendingPathComponent("patched-preview", isDirectory: true)
            try? FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
            let dest = tmp.appendingPathComponent("posture.json")
            try? FileManager.default.removeItem(at: dest)
            try? FileManager.default.copyItem(at: sample, to: dest)
            return PostureStore(baseDir: tmp)
        }
        assertionFailure("PostureStore.withFixture(): could not locate contracts/posture.sample.macos.json within 8 levels of \(#filePath)")
        return PostureStore()
    }
}
#endif
