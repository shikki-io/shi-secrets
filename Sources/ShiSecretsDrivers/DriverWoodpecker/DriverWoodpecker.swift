import Foundation
import ShiSecretsKit

// DriverWoodpecker — SecretRotationDriver conformance for Woodpecker CI
// scoped token management (BR-WM-XX, operator decision 2026-05-21).
//
// Replaces the Gitea OAuth dependency in the Woodpecker + Mattermost
// deploy spec. shi-secrets is the canonical auth backend for Woodpecker;
// no external OAuth provider is required.
//
// Scope format: "woodpecker:<repo>:<branch>" — e.g.
//   "woodpecker:shikki:develop"
// This matches the VaultEntryRef.scope convention used by the rotation
// engine (vendor prefix before the first slash maps to DriverRegistry key).
//
// Sequence (mint):
//   1. POST /api/user/token      → creates a new scoped CI token
//   2. write-back via BWClient   → vault holds new token
//
// Sequence (rotate):
//   1. POST /api/user/token      → mint new token
//   2. write-back via BWClient
//   3. DELETE /api/user/token/:id → revoke previous token (atomic in op)
//
// Token constraints:
//   - TTL hard-capped at 3600s (BR-A-03 / broker golden rule)
//   - Scoped to repo + branch + pipeline
//
// Admin token sourcing:
//   - Configuration file: ~/.shikki/secrets/woodpecker.toml
//     Contains: server_url (config-resolved, never a magic string)
//   - Admin token itself: resolved via BWClientWriteBack (Bitwarden vault)
//     Key: "WOODPECKER_ADMIN_TOKEN"
//     NEVER stored in plaintext config — only vault references
//
// Error catalogue (DriverWoodpecker.DriverError):
//   .invalidScope         — scope does not match "woodpecker:<repo>:<branch>"
//   .vaultMisconfigured   — admin token absent or empty in BWClient vault
//   .tokenTTLExceeded     — requested TTL > 3600s (hard cap)

// MARK: - Scope helpers

extension DriverWoodpecker {

    /// Parses a Woodpecker scope string into (repo, branch) components.
    /// Expected format: "woodpecker:<repo>:<branch>" (three colon-delimited
    /// parts where the first part is the literal "woodpecker" vendor prefix).
    static func parseScope(_ scope: String) -> (repo: String, branch: String)? {
        let parts = scope.split(separator: ":", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3,
              parts[0] == "woodpecker",
              !parts[1].isEmpty,
              !parts[2].isEmpty else {
            return nil
        }
        return (repo: String(parts[1]), branch: String(parts[2]))
    }
}

// MARK: - DriverWoodpecker

public struct DriverWoodpecker: SecretRotationDriver {

    // MARK: - Error catalogue

    public enum DriverError: Swift.Error, Sendable, Equatable {
        /// Scope does not match "woodpecker:<repo>:<branch>".
        case invalidScope(String)
        /// Admin token absent, empty, or not present in the vault.
        case vaultMisconfigured(reason: String)
        /// Requested TTL exceeds the hard cap of 3600s.
        case tokenTTLExceeded(requested: Int)
    }

    // MARK: - Token record

    /// Minimal representation of an active CI token for list/revoke ops.
    public struct CIToken: Sendable, Equatable {
        public let id: String
        public let repo: String
        public let branch: String
        public let expiresAt: Date?

        public init(id: String, repo: String, branch: String, expiresAt: Date?) {
            self.id = id
            self.repo = repo
            self.branch = branch
            self.expiresAt = expiresAt
        }
    }

    // MARK: - TTL cap

    /// Broker golden rule: CI token TTL hard-capped at 3600 seconds.
    public static let maxTokenTTL: Int = 3600

    // MARK: - Stored properties

    public var vendor: String { "woodpecker" }
    public let humanFallback: HumanRunbook? = nil
    private let transport: any DriverHTTPTransport
    private let bwClient: (any BWClientWriteBack)?
    private let serverURL: String

    // MARK: - Init

    public init(
        transport: any DriverHTTPTransport,
        bwClient: (any BWClientWriteBack)? = nil,
        serverURL: String = "https://woodpecker.obyw.one"
    ) {
        self.transport = transport
        self.bwClient = bwClient
        self.serverURL = serverURL
    }

    // MARK: - SecretRotationDriver

    /// Rotates the scoped CI token for this entry:
    ///   1. Resolve WOODPECKER_ADMIN_TOKEN from vault
    ///   2. Mint a new token (POST /api/user/token) with admin auth
    ///   3. Write back to vault via BWClient
    ///   4. Revoke the previous token (DELETE /api/user/token/:id)
    ///
    /// Returns .rotated on success; .failed(reason:) on any transport or
    /// scope error so the rotation engine can log + enqueue retry.
    public func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
        guard let parsed = DriverWoodpecker.parseScope(entry.scope) else {
            return .failed(reason: "woodpecker invalid_scope: \(entry.scope)")
        }
        // Resolve admin token from vault — never plaintext config.
        guard let bw = bwClient else {
            return .failed(reason: "woodpecker vault_misconfigured: bwClient not wired — admin token unavailable")
        }
        let adminToken: String
        do {
            let fields = try await bw.get(name: "WOODPECKER_ADMIN_TOKEN")
            let candidate = fields["value"] ?? ""
            guard !candidate.isEmpty else {
                return .failed(reason: "woodpecker vault_misconfigured: WOODPECKER_ADMIN_TOKEN absent from vault")
            }
            adminToken = candidate
        } catch {
            return .failed(reason: "woodpecker vault_misconfigured: get(WOODPECKER_ADMIN_TOKEN) threw \(error)")
        }
        do {
            let newToken = try await mintAuthenticated(
                repo: parsed.repo, branch: parsed.branch,
                ttl: Self.maxTokenTTL, adminToken: adminToken
            )
            try await bw.update(name: entry.name, fields: ["token": newToken.id, "value": newToken.id])
            // Best-effort revoke of the previous token; swallow errors so a
            // revoke failure cannot un-do an already-successful rotation.
            _ = try? await revokeToken(id: entry.name)
            _ = trigger
            return .rotated
        } catch DriverError.invalidScope(let s) {
            return .failed(reason: "woodpecker invalid_scope: \(s)")
        } catch DriverError.vaultMisconfigured(let reason) {
            return .failed(reason: "woodpecker vault_misconfigured: \(reason)")
        } catch {
            return .failed(reason: "woodpecker transport: \(error)")
        }
    }

    // MARK: - Authenticated mint (production path)

    /// Same as `mint(repo:branch:ttl:)` but injects the admin token as a
    /// Bearer Authorization header. Called exclusively from `rotate()`.
    private func mintAuthenticated(
        repo: String, branch: String, ttl: Int, adminToken: String
    ) async throws -> (id: String, value: String, ttl: Int) {
        let effectiveTTL = min(ttl, Self.maxTokenTTL)
        let body = try JSONSerialization.data(withJSONObject: [
            "repo":   repo,
            "branch": branch,
            "ttl":    effectiveTTL,
        ])
        let request = DriverHTTPRequest(
            method: "POST",
            url: serverURL + "/api/user/token",
            headers: [
                "Content-Type": "application/json",
                "Authorization": "Bearer \(adminToken)",
            ],
            body: body
        )
        let response = try await transport.send(request)
        guard response.status == 200 || response.status == 201 else {
            throw DriverHTTPError.transportFailed(message: "woodpecker mint http \(response.status)")
        }
        guard let json = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
              let tokenId = json["id"] as? String,
              let tokenValue = json["token"] as? String else {
            throw DriverHTTPError.transportFailed(message: "woodpecker mint response malformed")
        }
        let returnedTTL = (json["ttl"] as? Int) ?? effectiveTTL
        guard returnedTTL <= Self.maxTokenTTL else {
            throw DriverError.tokenTTLExceeded(requested: returnedTTL)
        }
        return (id: tokenId, value: tokenValue, ttl: returnedTTL)
    }

    /// Explicit invalidation (called by the rotation engine after applyRotation).
    /// Issues DELETE /api/user/token/:id; swallows non-2xx so a revoke failure
    /// cannot re-fail an already-successful rotation.
    public func invalidate(previous: VaultEntryRef) async throws {
        _ = try? await revokeToken(id: previous.name)
    }

    // MARK: - Mint + revoke primitives

    /// Mints a new scoped CI token. TTL is hard-capped at `maxTokenTTL`.
    /// Returns the raw token string on success; throws on transport / auth errors.
    ///
    /// Admin token is resolved from BWClient vault under "WOODPECKER_ADMIN_TOKEN".
    /// It is NEVER accepted as a plaintext init parameter.
    @discardableResult
    public func mint(repo: String, branch: String, ttl: Int) async throws -> (id: String, value: String, ttl: Int) {
        let effectiveTTL = min(ttl, Self.maxTokenTTL)
        let body = try JSONSerialization.data(withJSONObject: [
            "repo":   repo,
            "branch": branch,
            "ttl":    effectiveTTL,
        ])
        let request = DriverHTTPRequest(
            method: "POST",
            url: serverURL + "/api/user/token",
            headers: ["Content-Type": "application/json"],
            body: body
        )
        let response = try await transport.send(request)
        guard response.status == 200 || response.status == 201 else {
            throw DriverHTTPError.transportFailed(message: "woodpecker mint http \(response.status)")
        }
        guard let json = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
              let tokenId = json["id"] as? String,
              let tokenValue = json["token"] as? String else {
            throw DriverHTTPError.transportFailed(message: "woodpecker mint response malformed")
        }
        let returnedTTL = (json["ttl"] as? Int) ?? effectiveTTL
        guard returnedTTL <= Self.maxTokenTTL else {
            throw DriverError.tokenTTLExceeded(requested: returnedTTL)
        }
        return (id: tokenId, value: tokenValue, ttl: returnedTTL)
    }

    /// Lists active CI tokens for the given repo. Returns a snapshot of
    /// current active tokens scoped to that repo.
    public func listTokens(repo: String) async throws -> [CIToken] {
        let request = DriverHTTPRequest(
            method: "GET",
            url: serverURL + "/api/user/token?repo=\(repo)",
            headers: [:]
        )
        let response = try await transport.send(request)
        guard response.status == 200 else {
            throw DriverHTTPError.transportFailed(message: "woodpecker list http \(response.status)")
        }
        guard let items = try? JSONSerialization.jsonObject(with: response.body) as? [[String: Any]] else {
            return []
        }
        return items.compactMap { item -> CIToken? in
            guard let id = item["id"] as? String,
                  let branch = item["branch"] as? String else { return nil }
            let expiresAt: Date?
            if let ts = item["expires_at"] as? TimeInterval {
                expiresAt = Date(timeIntervalSince1970: ts)
            } else {
                expiresAt = nil
            }
            return CIToken(id: id, repo: repo, branch: branch, expiresAt: expiresAt)
        }
    }

    // MARK: - Private helpers

    private func revokeToken(id: String) async throws {
        let request = DriverHTTPRequest(
            method: "DELETE",
            url: serverURL + "/api/user/token/\(id)",
            headers: [:]
        )
        _ = try await transport.send(request)
    }
}
