// VaultwardenTokenCache — Keychain-backed OAuth token cache + JSON backoff store.
//
// W2 of spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91
// Panel #1 verdict (D8F2F0FCD05E484FBF56115911DE04C2): split storage design:
//   - token + expires_at → Keychain via SecureStore (AES-256, TM-excluded)
//   - consecutive_429_count + next_attempt_at + last_fetch → plain JSON file
//     (non-sensitive operational counters)
//
// Security invariants:
//   - The access token string NEVER touches the filesystem.
//   - BackoffEntry MUST NOT ever gain a `token`-like field (T-W2-K05 guards).
//   - JSON file is written with explicit fchmod(0o600) after atomic rename.
//
// Cross-platform injection: `SecureStore` protocol received at init — lets tests
// inject MockSecureStore instead of hitting the real Keychain (panel #2).
//
// See: super-challenge-w2-token-cache-disk-safety-2026-06-24.md §7
//      super-challenge-w2-cross-platform-secure-cache-2026-06-24.md §6

import Foundation
import ShiSecretsKit
#if canImport(os)
import os
#endif

// MARK: - VaultwardenTokenCache

/// Actor-isolated two-part cache:
/// - **Token half**: `read/writeToken()` → `SecureStore` (Keychain on Mac)
/// - **Backoff half**: `read/writeBackoff()` → plain JSON file, mode 0o600
actor VaultwardenTokenCache {

    // MARK: - Keychain coordinates

    /// Canonical service: `io.shikki.vault` — shared with vault-credentials so all
    /// shi-secrets-brokerd items live under one service and require the fewest ACL entries.
    /// Prompt count: 0 when signed (keychain-access-groups entitlement covers the ACL),
    ///               2 prompts unsigned on first run (one per service: io.shikki.vault,
    ///               eu.fj-studios.shikki.vault-key), NOT 3 — token and credentials share
    ///               the same service.
    ///
    /// Carry-over from legacy service `io.shikki.vault.token` /
    /// account `client-credentials-access-token` is handled in readToken():
    /// if the canonical item is absent, the legacy item is read, migrated, and deleted.
    let keychainService = "io.shikki.vault"
    let keychainAccount = "access-token"

    /// Legacy coordinates — kept only for one-time migration in readToken().
    private let legacyKeychainService = "io.shikki.vault.token"
    private let legacyKeychainAccount = "client-credentials-access-token"

    // MARK: - Token entry (Keychain half)

    struct TokenEntry {
        let token: String
        let expiresAt: Date
        /// W6.5: session_fingerprint binding. `nil` for entries written before
        /// W6.5 (read path treats `nil` as "no binding" for backward compat;
        /// next write upgrades the entry).
        let sessionFingerprint: String?
        // NOTE: NOT Codable on purpose — prevents accidental JSON serialization
        // to disk (T-W2-K05). JSON encoding happens ONLY inside writeToken().
    }

    // MARK: - Backoff entry (file half)

    struct BackoffEntry: Codable {
        let consecutive429Count: Int
        let nextAttemptAt: Date
        let lastFetch: Date
        // INVARIANT: NEVER add a `token`, `accessToken`, `access_token`,
        // or similar field here. T-W2-K05 source-scan enforces this.
    }

    // MARK: - Dependencies

    private let store: any SecureStore
    private let backoffFilePath: String
    private let logger: ShikkiSecretsLogger

    // MARK: - Init

    /// - Parameter store: `SecureStore` for the token half. Inject
    ///   `MockSecureStore` in tests; use `KeychainSecureStore()` in production.
    /// - Parameter backoffFilePath: Full path for the JSON backoff file.
    ///   Defaults to `~/.shikki/credentials/.brokerd-backoff.json`.
    ///   Pass a temp path in tests to avoid touching the real credentials dir.
    init(
        store: any SecureStore,
        backoffFilePath: String? = nil,
        logger: ShikkiSecretsLogger = ShikkiSecretsLogger()
    ) {
        self.store = store
        self.backoffFilePath = backoffFilePath ?? VaultwardenTokenCache.defaultBackoffFilePath()
        self.logger = logger
    }

    static func defaultBackoffFilePath() -> String {
        let credDir = ProcessInfo.processInfo.environment["CREDENTIALS_DIRECTORY"]
            ?? "\(NSHomeDirectory())/.shikki/credentials"
        return "\(credDir)/.brokerd-backoff.json"
    }

    // MARK: - Token I/O (Keychain)

    /// Read the cached token. Returns `nil` if absent or if stored bytes are corrupt
    /// (corruption logs a warning and falls through to `nil` — triggers re-fetch).
    ///
    /// W6.5: also returns `session_fingerprint` if present in the JSON; legacy
    /// entries written before W6.5 have `nil` and are accepted (caller decides
    /// whether to enforce fingerprint binding).
    func readToken() async throws -> TokenEntry? {
        var data: Data?
        data = try await store.read(service: keychainService, account: keychainAccount)
        if data == nil {
            // Carry-over migration: try legacy service/account (io.shikki.vault.token /
            // client-credentials-access-token), copy to canonical location, delete legacy.
            if let legacyData = try await store.read(
                service: legacyKeychainService, account: legacyKeychainAccount
            ) {
                logger.info("[token-cache] migrating token from legacy Keychain item to io.shikki.vault/access-token")
                try? await store.write(legacyData, service: keychainService, account: keychainAccount)
                try? await store.delete(service: legacyKeychainService, account: legacyKeychainAccount)
                data = legacyData
            }
        }
        guard let data else {
            logger.debug("[token-cache] cache miss — no Keychain entry")
            return nil
        }
        // Decode {"token":"...","expires_at":"ISO8601","session_fingerprint":"...?"}
        // (session_fingerprint is OPTIONAL — added in W6.5; legacy entries lack it.)
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: String],
              let tokenStr = json["token"],
              let expiresAtStr = json["expires_at"],
              let expiresAt = ISO8601DateFormatter().date(from: expiresAtStr)
        else {
            logger.warning("[token-cache] Keychain entry malformed — deleting and re-fetching")
            try? await store.delete(service: keychainService, account: keychainAccount)
            return nil
        }
        let fingerprint = json["session_fingerprint"]  // nil for legacy entries
        return TokenEntry(token: tokenStr, expiresAt: expiresAt, sessionFingerprint: fingerprint)
    }

    /// Write token + expiresAt to Keychain. The token string is NEVER written
    /// to any file on disk; only the Keychain blob is touched.
    ///
    /// W6.5: `sessionFingerprint` defaults to the current session's fingerprint
    /// (via `SessionFingerprint.current()`); pass `nil` explicitly to skip
    /// fingerprint binding (test code only).
    func writeToken(
        _ token: String,
        expiresAt: Date,
        sessionFingerprint: String? = nil
    ) async throws {
        // Use the explicitly passed fingerprint, or compute current.
        let effectiveFingerprint = sessionFingerprint ?? SessionFingerprint.current()
        var payload: [String: String] = [
            "token":      token,
            "expires_at": ISO8601DateFormatter().string(from: expiresAt),
        ]
        if let fp = effectiveFingerprint {
            payload["session_fingerprint"] = fp
        }
        let data = try JSONSerialization.data(withJSONObject: payload)
        try await store.write(data, service: keychainService, account: keychainAccount)
        logger.debug("[token-cache] token written to Keychain, expires \(ISO8601DateFormatter().string(from: expiresAt))")
    }

    /// W6.5 — convenience check used by Bootstrap to decide whether to honor
    /// a cached token or treat it as `lockedBySessionChange`.
    ///
    /// `nonisolated` because the check reads only the (passed-in) `TokenEntry`
    /// + the platform fingerprint (which is its own thread-safe static).
    /// No actor-isolated state is touched, so callers may invoke it
    /// synchronously from any context.
    ///
    /// Returns:
    ///   • `true` if the entry has no fingerprint (legacy / opt-out)
    ///     OR the fingerprint matches the current session
    ///   • `false` if fingerprints differ → caller should treat as locked
    nonisolated func sessionFingerprintMatches(entry: TokenEntry) -> Bool {
        guard let stored = entry.sessionFingerprint else {
            // Legacy entry (no fingerprint): backward-compatible, accept.
            return true
        }
        guard let current = SessionFingerprint.current() else {
            // Platform lookup failed: defensive default — accept (don't
            // lock the operator out on a transient sysctl/loginctl failure).
            return true
        }
        return stored == current
    }

    /// Delete the cached token from Keychain.
    func deleteToken() async throws {
        try await store.delete(service: keychainService, account: keychainAccount)
        logger.debug("[token-cache] Keychain token entry deleted")
    }

    // MARK: - Backoff I/O (file)

    /// Read the backoff counters from the JSON file. Returns `nil` if absent or
    /// corrupt (corruption deletes the file, returns `nil` → counters restart at 0).
    func readBackoff() async throws -> BackoffEntry? {
        guard FileManager.default.fileExists(atPath: backoffFilePath) else {
            return nil
        }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: backoffFilePath)) else {
            return nil
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        if let entry = try? decoder.decode(BackoffEntry.self, from: data) {
            return entry
        }
        // Corrupt file → delete and reset.
        logger.warning("[token-cache] backoff file corrupt — deleting, counters reset to 0")
        try? FileManager.default.removeItem(atPath: backoffFilePath)
        return nil
    }

    /// Write backoff counters atomically with mode 0o600.
    ///
    /// Uses write-to-temp + fchmod(0o600) + rename pattern so:
    /// 1. Mode 600 is set BEFORE the rename (Dgr-T1 from panel #1).
    /// 2. The rename is atomic — no partial file visible on crash.
    /// 3. Orphaned temp files have mode 600, not umask-default 644.
    func writeBackoff(_ entry: BackoffEntry) async throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(entry)

        // Ensure parent directory exists.
        let dir = (backoffFilePath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true, attributes: nil
        )

        // Write to a sibling temp file first.
        let tmpPath = backoffFilePath + ".tmp.\(Int.random(in: 100_000..<999_999))"
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }

        // Use POSIX open with O_CREAT | O_WRONLY | O_EXCL and explicit mode 0o600.
        // This guarantees the temp file starts with mode 600 — not umask-inherited.
        guard let cPath = tmpPath.cString(using: .utf8) else {
            throw CocoaError(.fileWriteInapplicableStringEncoding)
        }
        let fd = open(cPath, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR)
        guard fd >= 0 else {
            throw CocoaError(.fileWriteNoPermission)
        }
        // Write bytes.
        let written = data.withUnsafeBytes { ptr in
            Foundation.write(fd, ptr.baseAddress!, data.count)
        }
        close(fd)
        guard written == data.count else {
            throw CocoaError(.fileWriteUnknown)
        }

        // Atomic rename: temp → final.
        guard rename(cPath, (backoffFilePath as NSString).fileSystemRepresentation) == 0 else {
            throw CocoaError(.fileWriteUnknown)
        }

        // Belt-and-suspenders: explicitly chmod the final file.
        // Darwin's rename() preserves the mode we set on the temp file,
        // but an explicit fchmod on the path removes ambiguity.
        let finalFd = open((backoffFilePath as NSString).fileSystemRepresentation,
                           O_RDONLY)
        if finalFd >= 0 {
            fchmod(finalFd, S_IRUSR | S_IWUSR)
            close(finalFd)
        }
    }

    // MARK: - High-level orchestration

    /// Record a successful token exchange:
    /// 1. Write new token to Keychain.
    /// 2. Reset backoff counters to zero.
    func recordSuccess(token: String, ttl: TimeInterval) async throws {
        let expiresAt = Date().addingTimeInterval(ttl)
        try await writeToken(token, expiresAt: expiresAt)
        let reset = BackoffEntry(consecutive429Count: 0,
                                 nextAttemptAt: Date(),
                                 lastFetch: Date())
        try await writeBackoff(reset)
        logger.info("[token-cache] token cached successfully, TTL=\(Int(ttl))s")
    }

    /// Record a 429 response.
    /// - Returns: Seconds to wait before the next attempt (capped at 30min).
    func record429() async throws -> TimeInterval {
        let current = try await readBackoff() ?? BackoffEntry(
            consecutive429Count: 0,
            nextAttemptAt: Date(),
            lastFetch: Date()
        )
        let newCount = current.consecutive429Count + 1
        // Exponential backoff: 60s * 2^(count-1), capped at 1800s (30min).
        let delay = min(60.0 * pow(2.0, Double(newCount - 1)), 1800.0)
        let nextAttempt = Date().addingTimeInterval(delay)
        let updated = BackoffEntry(
            consecutive429Count: newCount,
            nextAttemptAt: nextAttempt,
            lastFetch: current.lastFetch
        )
        try await writeBackoff(updated)
        logger.warning("[token-cache] 429 received (count=\(newCount)), next attempt in \(Int(delay))s")
        return delay
    }

    /// Reset the backoff counter (called after a successful 200 OK).
    func resetBackoff() async throws {
        let reset = BackoffEntry(consecutive429Count: 0,
                                 nextAttemptAt: Date(),
                                 lastFetch: Date())
        try await writeBackoff(reset)
    }
}
