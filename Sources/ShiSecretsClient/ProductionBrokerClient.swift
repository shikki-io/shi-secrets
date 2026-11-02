import Foundation
import ShiSecretsKit

// ProductionBrokerClient — wire-protocol-bridged `BrokerClient` impl.
//
// Phase 0.2 (BR-G-03) of features/shikkisecrets-broker-completion.md.
// Each protocol method builds a `WireRequest`, round-trips via
// `SocketConnection`, parses the `WireResponse`, and returns the typed
// result or throws `BrokerClientError`.
//
// JSON-RPC method namespace mapping (operator-stable; daemon side must
// register these in its handler dispatch table):
//
//   secret.get                    → BrokerClient.get(name:)           ✓ dispatched W3
//   secret.list                   → BrokerClient.list(filter:)        ✓ dispatched W3
//   secret.set                    → BrokerClient.set(name:value:)     ✓ dispatched W3
//   secret.delete                 → BrokerClient.delete(name:)        ✓ dispatched W3 (added 2026-11-02)
//   secret.rotate                 → BrokerClient.rotate(name:)        ✗ Phase 0.5 — not dispatched; throws .methodNotImplemented
//   token.revoke                  → BrokerClient.revoke(jti:)         ✗ Phase 0.5 — not dispatched
//   token.revokeAllBots           → BrokerClient.revokeAllBots(dryRun:force:)        ✗ Phase 0.5
//   token.revokeAllBotsSigned     → BrokerClient.revokeAllBotsSigned(_:)             ✗ Phase 0.5
//   audit.blastRadius             → BrokerClient.blastRadius(jti:)    ✗ Phase 0.6
//   audit.recent                  → BrokerClient.recentAudit(hours:)  ✗ Phase 0.6
//   audit.seams                   → BrokerClient.seamsRows()          ✗ Phase 0.6
//
// Each request id is a freshly-minted UUID string (caller can mismatch
// match-anti-pattern is irrelevant at single-frame transport).

public actor ProductionBrokerClient: BrokerClient {

    public let socket: SocketConnection

    public init(socket: SocketConnection = SocketConnection()) {
        self.socket = socket
    }

    // MARK: - secret.*

    public func get(name: String) async throws -> String {
        let params: JSONValue = .object(["name": .string(name)])
        let result = try await call(method: "secret.get", params: params)
        guard case let .string(value) = result else {
            throw BrokerClientError.wireDecodeFailed("secret.get expected string, got \(result)")
        }
        return value
    }

    public func list(filter: String?) async throws -> [VaultEntryRef] {
        var paramsDict: [String: JSONValue] = [:]
        if let f = filter { paramsDict["filter"] = .string(f) }
        let result = try await call(method: "secret.list", params: .object(paramsDict))
        guard case let .array(items) = result else {
            throw BrokerClientError.wireDecodeFailed("secret.list expected array")
        }
        let entries: [VaultEntryRef] = try items.map { item in
            let data = try jsonValueToData(item)
            return try decodeResult(item, as: VaultEntryRef.self)
        }
        return entries
    }

    public func set(name: String, value: String) async throws {
        let params: JSONValue = .object(["name": .string(name), "value": .string(value)])
        _ = try await call(method: "secret.set", params: params)
    }

    public func delete(name: String) async throws {
        let params: JSONValue = .object(["name": .string(name)])
        _ = try await call(method: "secret.delete", params: params)
    }

    /// Phase 0.5 placeholder. `secret.rotate` is not yet handled by the
    /// broker dispatcher — calling this method throws `.methodNotImplemented`
    /// rather than forwarding the unhandled wire frame (which would return
    /// -32601 Method not found from the dispatcher's default arm).
    public func rotate(name: String) async throws -> RotationResult {
        throw BrokerClientError.methodNotImplemented(
            "secret.rotate is not yet dispatched by the broker (Phase 0.5)"
        )
    }

    // MARK: - token.*

    public func revoke(jti: String) async throws {
        let params: JSONValue = .object(["jti": .string(jti)])
        _ = try await call(method: "token.revoke", params: params)
    }

    public func revokeAllBots(dryRun: Bool, force: Bool) async throws -> RevokeAllBotsResult {
        let params: JSONValue = .object(["dryRun": .bool(dryRun), "force": .bool(force)])
        let result = try await call(method: "token.revokeAllBots", params: params)
        return try decodeResult(result, as: RevokeAllBotsResult.self)
    }

    public func revokeAllBotsSigned(_ signed: SignedAdminAction) async throws -> RevokeAllBotsResult {
        let signedJSON = try jsonValueFromEncodable(signed)
        let params: JSONValue = .object(["signed": signedJSON])
        let result = try await call(method: "token.revokeAllBotsSigned", params: params)
        return try decodeResult(result, as: RevokeAllBotsResult.self)
    }

    // MARK: - audit.*

    public func blastRadius(jti: String) async throws -> BlastRadiusReport {
        let params: JSONValue = .object(["jti": .string(jti)])
        let result = try await call(method: "audit.blastRadius", params: params)
        return try decodeResult(result, as: BlastRadiusReport.self)
    }

    public func recentAudit(hours: Int) async throws -> [AuditRow] {
        let params: JSONValue = .object(["hours": .int(Int64(hours))])
        let result = try await call(method: "audit.recent", params: params)
        guard case let .array(items) = result else {
            throw BrokerClientError.wireDecodeFailed("audit.recent expected array")
        }
        return try items.map { try decodeResult($0, as: AuditRow.self) }
    }

    public func seamsRows() async throws -> [SeamsWriter.Row] {
        let result = try await call(method: "audit.seams", params: .object([:]))
        guard case let .array(items) = result else {
            throw BrokerClientError.wireDecodeFailed("audit.seams expected array")
        }
        return try items.map { try decodeResult($0, as: SeamsWriter.Row.self) }
    }

    // MARK: - vault.* (feat/vault-unlock-2026-11-01)

    /// Send vault.unlock to the broker. The master password travels over the
    /// 0600 Unix socket — local process-to-process only, never over the network.
    public func vaultUnlock(masterPassword: String, email: String) async throws {
        let params: JSONValue = .object([
            "masterPassword": .string(masterPassword),
            "email": .string(email),
        ])
        _ = try await call(method: "vault.unlock", params: params)
    }

    /// Query locked/unlocked state from the broker (vault.status).
    public func vaultStatus() async throws -> VaultStatus {
        let result = try await call(method: "vault.status", params: .object([:]))
        guard case let .object(obj) = result, case let .bool(locked) = obj["locked"] else {
            throw BrokerClientError.wireDecodeFailed("vault.status expected {locked: Bool}")
        }
        return VaultStatus(locked: locked)
    }

    /// Drop the vault key from memory and custody store (vault.lock).
    public func vaultLock() async throws {
        _ = try await call(method: "vault.lock", params: .object([:]))
    }

    // MARK: - Internals

    private func call(method: String, params: JSONValue) async throws -> JSONValue {
        let id = UUID().uuidString
        let req = WireRequest(method: method, params: params, id: id)
        let resp = try await socket.roundTrip(req)
        if let err = resp.error {
            // Map deny code to denied-error variant for caller UX
            if err.code == WireErrorCode.denied {
                throw BrokerClientError.denied(reason: err.message)
            }
            throw BrokerClientError.brokerError(code: err.code, message: err.message)
        }
        guard let result = resp.result else {
            throw BrokerClientError.wireDecodeFailed("response missing result")
        }
        return result
    }

    private func decodeResult<T: Decodable>(_ value: JSONValue, as type: T.Type) throws -> T {
        let data = try jsonValueToData(value)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(type, from: data)
    }

    private func jsonValueToData(_ value: JSONValue) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(value)
    }

    private func jsonValueFromEncodable<T: Encodable>(_ value: T) throws -> JSONValue {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(value)
        return try JSONDecoder().decode(JSONValue.self, from: data)
    }
}
