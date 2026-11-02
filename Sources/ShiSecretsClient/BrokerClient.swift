import Foundation
import ShiSecretsKit

// BrokerClient — protocol layer between callers (CLI, future Vapor app
// servers, future iOS clients) and the broker daemon.
//
// Phase 0.2 of features/shikkisecrets-broker-completion.md (BR-G-03).
// Promoted out of ShiSecretsCLI into its own library target so any
// consumer can `import ShiSecretsClient` without taking a dep on the
// CLI surface.
//
// Tests inject `RecordingBrokerClient` (in test support); production
// callers inject `ProductionBrokerClient` from this target.

/// Any caller that needs to talk to the broker over the local socket.
/// All methods are async — production impl performs blocking socket IO
/// on a private actor; test impls return canned data immediately.
public protocol BrokerClient: Sendable {
    func get(name: String) async throws -> String
    func list(filter: String?) async throws -> [VaultEntryRef]
    func set(name: String, value: String) async throws
    /// Remove a vault entry by name. Idempotent (no error if name does not exist).
    /// Wire method: `secret.delete` (dispatched by `BrokerWireDispatcher` since W3).
    func delete(name: String) async throws
    /// Rotate the value of a vault entry in-place.
    /// Wire method: `secret.rotate` — Phase 0.5, not yet dispatched by the broker.
    /// `ProductionBrokerClient.rotate` throws `.methodNotImplemented` until Phase 0.5 ships.
    func rotate(name: String) async throws -> RotationResult
    func revoke(jti: String) async throws
    func revokeAllBots(dryRun: Bool, force: Bool) async throws -> RevokeAllBotsResult
    /// Item #9 — passkey-signed `revokeAllBots` variant.
    func revokeAllBotsSigned(_ signed: SignedAdminAction) async throws -> RevokeAllBotsResult
    func blastRadius(jti: String) async throws -> BlastRadiusReport
    func recentAudit(hours: Int) async throws -> [AuditRow]
    func seamsRows() async throws -> [SeamsWriter.Row]

    // MARK: - vault.* (feat/vault-unlock-2026-11-01)
    /// Derive the vault session key from the master password. Never stored.
    func vaultUnlock(masterPassword: String, email: String) async throws
    /// Query the daemon's locked/unlocked state (no secret material returned).
    func vaultStatus() async throws -> VaultStatus
}

/// Result from vault.status. True means locked; data operations will fail.
public struct VaultStatus: Sendable, Equatable {
    public let locked: Bool
    public init(locked: Bool) { self.locked = locked }
}

// MARK: - Result types

public struct RotationResult: Sendable, Equatable, Codable {
    public let secretName: String
    public let oldJtiSuffix: String   // last 4 chars of prior jti (display only)
    public let invalidAt: Date
    public init(secretName: String, oldJtiSuffix: String, invalidAt: Date) {
        self.secretName = secretName
        self.oldJtiSuffix = oldJtiSuffix
        self.invalidAt = invalidAt
    }
}

public struct RevokeAllBotsResult: Sendable, Equatable, Codable {
    public let revokedCount: Int
    public let passkeyPreservedCount: Int
    public init(revokedCount: Int, passkeyPreservedCount: Int) {
        self.revokedCount = revokedCount
        self.passkeyPreservedCount = passkeyPreservedCount
    }
}

public struct BlastRadiusReport: Sendable, Equatable, Codable {
    public let rootJti: String
    public let sub: String
    public let scope: String
    public let dependents: [Dependent]
    public struct Dependent: Sendable, Equatable, Codable {
        public let jti: String
        public let scope: String
        public init(jti: String, scope: String) {
            self.jti = jti
            self.scope = scope
        }
    }
    public init(rootJti: String, sub: String, scope: String, dependents: [Dependent]) {
        self.rootJti = rootJti
        self.sub = sub
        self.scope = scope
        self.dependents = dependents
    }
}

// MARK: - Errors

public enum BrokerClientError: Swift.Error, Sendable, Equatable {
    /// Could not connect to the broker socket.
    case socketUnavailable(path: String, errno: Int32)
    /// Broker returned a JSON-RPC error.
    case brokerError(code: Int, message: String)
    /// Local encode/decode of wire payload failed.
    case wireDecodeFailed(String)
    /// Method not yet implemented in the client. Phase 0.2 ships the
    /// framework; some method paths still throw this until their
    /// daemon-side handlers wire up (Phase 0.3 / 0.4).
    case methodNotImplemented(String)
    /// Caller denied (server-side policy reject mapped from
    /// `BrokerResponse.deny(.reason)`).
    case denied(reason: String)
    /// Connection closed before a full response arrived.
    case connectionClosed
}
