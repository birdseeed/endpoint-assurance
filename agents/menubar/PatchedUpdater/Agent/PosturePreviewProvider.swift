//
//  PosturePreviewProvider.swift
//  PatchedUpdater — Agent (PAT-476)
//
//  Loads contracts/posture.sample.macos.json from the app bundle as stub data
//  for local development and Xcode previews. No live network calls; the real
//  read-client (PostureStore) replaces this when the privileged collector is
//  installed and has written posture.json.
//
//  Bundle lookup: the file is included as a resource in the target (added via
//  project.yml). Falls back to an in-process synthesised Posture value when the
//  resource is missing so previews always compile.
//

import Foundation

enum PosturePreviewProvider {

    /// Returns a Posture decoded from the bundled sample fixture, or nil when the
    /// resource is absent (e.g. unit-test hosts that don't embed resources).
    static func load() -> Posture? {
        guard let url = Bundle.main.url(forResource: "posture.sample.macos", withExtension: "json")
               ?? sampleURL else {
            return nil
        }
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? PostureStore.decoder.decode(Posture.self, from: data)
    }

    // MARK: - Dev-time path fallback

    /// Resolve the sample file from the source tree when running inside Xcode
    /// without a full bundle (Swift Package tests, etc.).
    private static var sampleURL: URL? {
        // Walk up from the source file's compile-time path to find contracts/.
        let sourceFile = URL(fileURLWithPath: #filePath)
        var dir = sourceFile
        for _ in 0..<8 {
            dir = dir.deletingLastPathComponent()
            let candidate = dir.appendingPathComponent("contracts/posture.sample.macos.json")
            if FileManager.default.fileExists(atPath: candidate.path) {
                return candidate
            }
        }
        return nil
    }

    /// Synthesised stub used in previews when the JSON file cannot be found at all.
    static func preview() -> Posture {
        load() ?? _synthesised
    }

    // MARK: - Synthesised fallback

    private static let _synthesised: Posture = {
        // Minimal valid Posture so Xcode Preview never crashes.
        let json = """
        {
          "schema_version": 1,
          "generated_at": "2026-12-17T08:12:44Z",
          "device": {
            "id": "preview-device",
            "os": "macOS",
            "os_version": "15.5"
          },
          "tier": "assurance",
          "app_count": 73,
          "compliance": {
            "platform": "macOS",
            "benchmarks": [{
              "benchmark": "CIS Apple macOS",
              "benchmark_version": "v3.0.0",
              "implemented": 98,
              "benchmark_total": 142,
              "passed": 84,
              "failed": 11,
              "not_applicable": 3,
              "errors": 0,
              "compliance_pct": 88.4,
              "sections": []
            }]
          },
          "evidence": {
            "coverage_window_days": 30,
            "scans_logged": 29,
            "recent_scan_times": ["2026-12-17T08:12:40Z"]
          }
        }
        """
        let data = Data(json.utf8)
        // swiftlint:disable force_try
        return try! PostureStore.decoder.decode(Posture.self, from: data)
        // swiftlint:enable force_try
    }()
}
