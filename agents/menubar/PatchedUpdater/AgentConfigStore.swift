//
//  AgentConfigStore.swift
//  PatchedUpdater
//
//  Reads agent-config.json (the inner config the privileged collector writes
//  after verifying GET /v1/agent-config — see macos/patched-upload.sh) and
//  publishes the live tier to the desktop surfaces. The app holds NO credentials
//  and never hits the network: it only reads this last-known-good cache.
//  Mirrors PostureStore.swift (same base dir, file-watch + poll).
//
//  Paths default to /Library/Application Support/Patched. Set PATCHED_UPDATER_DIR
//  to a writable directory for local development without the collector installed.
//

import Foundation
import Combine

@MainActor
final class AgentConfigStore: ObservableObject {

    /// Live tier from the last successfully decoded agent-config.json, or nil
    /// when no cache exists yet. Views fall back to posture?.tier when nil.
    @Published private(set) var tier: Posture.Tier?

    /// PAT-1624: the resolved never-interrupt bounds. The gate itself is
    /// unconditional at every tier; only these four numbers are tunable, and
    /// only at managed tier. `InterruptionPolicy.resolve` enforces that, so a
    /// non-managed tenant reading this always sees the shipped defaults.
    @Published private(set) var interruptionPolicy: InterruptionPolicy = .defaults

    static let staleThreshold: TimeInterval = 48 * 3600

    let baseDir: URL
    private var configURL: URL { baseDir.appendingPathComponent("agent-config.json") }

    private var watchSource: DispatchSourceFileSystemObject?
    private var pollTimer: Timer?

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
        let url = configURL
        guard FileManager.default.fileExists(atPath: url.path) else {
            tier = nil
            interruptionPolicy = .defaults
            return
        }
        do {
            let data = try Data(contentsOf: url)
            let config = try Self.decoder.decode(AgentConfig.self, from: data)
            if let updatedAt = config.updatedAt {
                let age = max(0, Date().timeIntervalSince(updatedAt))
                if age > Self.staleThreshold {
                    NSLog("[AgentConfigStore] agent-config.json is %.0f hours old — may be stale", age / 3600)
                }
            }
            let resolvedTier = mapTier(config.tier)
            tier = resolvedTier
            interruptionPolicy = .resolve(overrides: config.interruptionPolicy, tier: resolvedTier)
        } catch {
            // Keep last-known-good tier on decode failure.
            NSLog("[AgentConfigStore] Could not read agent-config.json: %@", error.localizedDescription)
        }
    }

    /// PAT-1416: used to hand-roll this mapping ("patch" / "report_deploy", every
    /// other string including "managed" falling to .report) separately from
    /// Posture.Tier's own JSON decoder, and the two had drifted: this one had no
    /// "managed" case at all, and sent unknown values to .report while the
    /// decoder sent them to .other(raw). Now routed through the one shared
    /// mapping (Posture.Tier.init(rawString:)) so they cannot drift apart again.
    /// That also means unknown values here now land on .other(raw) instead of
    /// .report — a deliberate choice, not a side effect: gating is unaffected
    /// (only .patch/.managed actuate; .other and .report both fail closed
    /// identically), and .other(raw) keeps the actual string around for the
    /// Plans sheet / tier-name copy that already pattern-matches on it, instead
    /// of quietly discarding it.
    private func mapTier(_ raw: String) -> Posture.Tier {
        Posture.Tier(rawString: raw)
    }

    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    // MARK: - Minimal decode model

    private struct AgentConfig: Decodable {
        let tier: String
        let updatedAt: Date?
        /// PAT-1624. Optional: absent on every config the platform emits today,
        /// and absent means the shipped defaults.
        let interruptionPolicy: InterruptionPolicyOverrides?
    }

    // MARK: - File watching

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
