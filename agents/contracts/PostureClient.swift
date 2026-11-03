// PostureClient.swift — async Swift actor for fetching device posture.
//
// Reads bearer + HMAC credentials from /etc/patched/ — the SAME credential
// store used by patched-fetch-config.sh and patched-fetch-posture.sh.
// No second credential path is introduced.
//
// HMAC signing matches the shell scripts:
//   secret = base64-decode(hmac-secret file)
//   sig    = HMAC-SHA256(secret, body: empty) → lowercase hex
//   headers: Authorization: Bearer <token>
//             X-Patched-Signature: <hex>
//             X-Patched-Timestamp: <unix-epoch>
//             X-Patched-Nonce: <uuid-hex>
//
// Offline / last-known-good:
//   On network failure, returns the cached posture if one exists.
//   Never throws when offline and a cache is present.
//   Cache location: ~/Library/Application Support/Patched/posture.cache.json
//
// Platform-neutral: no UIKit / AppKit imports.
//
// PAT-471 · U0 · Posture read-client + vendored contract.

import CryptoKit
import Foundation

// MARK: - Errors

public enum PostureClientError: Error, Sendable {
    case credentialMissing(String)
    case httpError(Int)
    case noData
    case decodingFailed(Error)
    case offlineNoCacheAvailable
}

// MARK: - PostureClient

/// Fetches device posture from GET /v1/posture, with offline last-known-good caching.
public actor PostureClient {

    // -------------------------------------------------------------------------
    // MARK: Configuration

    /// Location of the per-device credential files (same as the shell endpoint scripts).
    private let credsDir: URL

    /// Base URL for the Patched API, e.g. https://api.patched.im
    private let apiBaseURL: URL

    /// Where the last-known-good posture is written after a successful fetch.
    private let cacheFileURL: URL

    private let urlSession: URLSession
    private let jsonDecoder: JSONDecoder

    // -------------------------------------------------------------------------
    // MARK: Init

    /// - Parameters:
    ///   - credsDir: Directory containing `bearer-token` and `hmac-secret` files.
    ///               Defaults to `/etc/patched` — the same path as the shell scripts.
    ///   - apiBaseURL: Override for testing; defaults to `https://api.patched.im`.
    ///   - cacheFileURL: Override for testing; defaults to
    ///                   `~/Library/Application Support/Patched/posture.cache.json`.
    ///   - urlSession: Override for testing.
    public init(
        credsDir: URL = URL(fileURLWithPath: "/etc/patched"),
        apiBaseURL: URL = URL(string: "https://api.patched.im")!,
        cacheFileURL: URL? = nil,
        urlSession: URLSession = .shared
    ) {
        self.credsDir = credsDir
        self.apiBaseURL = apiBaseURL
        self.urlSession = urlSession

        if let override = cacheFileURL {
            self.cacheFileURL = override
        } else {
            let appSupport = FileManager.default.urls(
                for: .applicationSupportDirectory, in: .userDomainMask
            ).first ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
            self.cacheFileURL = appSupport
                .appendingPathComponent("Patched")
                .appendingPathComponent("posture.cache.json")
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        self.jsonDecoder = decoder
    }

    // -------------------------------------------------------------------------
    // MARK: Public API

    /// Fetch the device posture.
    ///
    /// On success: writes the response to the cache and returns the decoded `Posture`.
    /// On network failure: if a cache exists, returns the cached `Posture`; otherwise throws
    ///   `PostureClientError.offlineNoCacheAvailable`.
    /// On non-200 HTTP: throws `PostureClientError.httpError(_)`.
    public func fetch() async throws -> Posture {
        do {
            let posture = try await fetchFromNetwork()
            persistCache(posture)
            return posture
        } catch PostureClientError.credentialMissing, PostureClientError.httpError, PostureClientError.decodingFailed, PostureClientError.noData {
            // Propagate credential / decode / server errors — caller must handle.
            throw
        } catch {
            // Network-layer failure (URLError etc.) — try last-known-good.
            if let cached = loadCache() {
                return cached
            }
            throw PostureClientError.offlineNoCacheAvailable
        }
    }

    // -------------------------------------------------------------------------
    // MARK: Network fetch (internal)

    private func fetchFromNetwork() async throws -> Posture {
        let bearerToken = try readCredential(filename: "bearer-token")
        let hmacSecretB64 = try readCredential(filename: "hmac-secret")

        guard let secretData = Data(base64Encoded: hmacSecretB64.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw PostureClientError.credentialMissing("hmac-secret is not valid base64")
        }

        let ts = Int(Date().timeIntervalSince1970)
        let nonce = UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")
        let sig = hmacHex(secret: secretData, method: "GET", endpointID: "posture", timestamp: "\(ts)", nonce: nonce, body: Data())

        let endpoint = apiBaseURL.appendingPathComponent("v1/posture")
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
        request.setValue(sig,          forHTTPHeaderField: "X-Patched-Signature")
        request.setValue("\(ts)",       forHTTPHeaderField: "X-Patched-Timestamp")
        request.setValue(nonce,         forHTTPHeaderField: "X-Patched-Nonce")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 30

        let (data, response) = try await urlSession.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw PostureClientError.noData
        }
        guard httpResponse.statusCode == 200 else {
            throw PostureClientError.httpError(httpResponse.statusCode)
        }
        guard !data.isEmpty else {
            throw PostureClientError.noData
        }

        do {
            return try jsonDecoder.decode(Posture.self, from: data)
        } catch {
            throw PostureClientError.decodingFailed(error)
        }
    }

    // -------------------------------------------------------------------------
    // MARK: Cache (internal)

    private func loadCache() -> Posture? {
        guard FileManager.default.fileExists(atPath: cacheFileURL.path),
              let data = try? Data(contentsOf: cacheFileURL) else { return nil }
        return try? jsonDecoder.decode(Posture.self, from: data)
    }

    private func persistCache(_ posture: Posture) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(posture) else { return }
        let dir = cacheFileURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try? data.write(to: cacheFileURL, options: .atomic)
    }

    // -------------------------------------------------------------------------
    // MARK: Credentials (internal)

    /// Read a single-line credential file from credsDir, stripping whitespace.
    private func readCredential(filename: String) throws -> String {
        let url = credsDir.appendingPathComponent(filename)
        guard let data = try? Data(contentsOf: url),
              let raw = String(data: data, encoding: .utf8) else {
            throw PostureClientError.credentialMissing(filename)
        }
        let value = raw.components(separatedBy: .newlines).first?
            .trimmingCharacters(in: .whitespaces) ?? ""
        guard !value.isEmpty else {
            throw PostureClientError.credentialMissing(filename)
        }
        return value
    }

    // -------------------------------------------------------------------------
    // MARK: HMAC-SHA256 (internal)
    //
    // Mirrors the shell script logic:
    //   secret = base64-decode(hmac-secret)
    //   sig    = HMAC-SHA256(secret, body) as lowercase hex
    //
    // GET /v1/posture has an empty body — callers pass Data().

    private func hmacHex(secret: Data, method: String, endpointID: String, timestamp: String, nonce: String, body: Data) -> String {
        let key = SymmetricKey(data: secret)
        var input = Data("patched-hmac-v3\n\(method)\n\(endpointID)\n\(timestamp)\n\(nonce)\n".utf8)
        input.append(body)
        let mac = HMAC<SHA256>.authenticationCode(for: input, using: key)
        return mac.map { String(format: "%02x", $0) }.joined()
    }
}
