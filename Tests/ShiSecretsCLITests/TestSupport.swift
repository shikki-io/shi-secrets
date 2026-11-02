import Foundation
@testable import ShiSecretsCLI
import ShiSecretsClient
import ShiSecretsKit

// RecordingBrokerClient — in-process BrokerClient the CLI tests use to
// exercise command plumbing end-to-end without a live broker / socket.
actor RecordingBrokerClient: BrokerClient {

    struct GetCall: Sendable, Equatable {
        let name: String
    }
    struct RotateCall: Sendable, Equatable {
        let name: String
    }
    struct RevokeCall: Sendable, Equatable {
        let jti: String
    }
    struct RevokeAllBotsCall: Sendable, Equatable {
        let dryRun: Bool
        let force: Bool
    }

    // State.
    var plaintexts: [String: String] = [:]
    var listings: [VaultEntryRef] = []
    var tokenRows: [TokenRegistry.Row] = []
    var seamRows: [SeamsWriter.Row] = []
    var nextRotationResult: RotationResult?
    var revokeAllBotsResponse = RevokeAllBotsResult(revokedCount: 0, passkeyPreservedCount: 0)

    // Call log.
    var getCalls: [GetCall] = []
    var rotateCalls: [RotateCall] = []
    var revokeCalls: [RevokeCall] = []
    var revokeAllBotsCalls: [RevokeAllBotsCall] = []
    var setCalls: [(name: String, value: String)] = []

    func seedPlaintext(_ name: String, _ value: String) { plaintexts[name] = value }
    func seedListings(_ entries: [VaultEntryRef]) { listings = entries }
    func seedTokenRows(_ rows: [TokenRegistry.Row]) { tokenRows = rows }
    func seedSeamRows(_ rows: [SeamsWriter.Row]) { seamRows = rows }
    func setNextRotationResult(_ r: RotationResult) { nextRotationResult = r }
    func setRevokeAllBotsResponse(_ r: RevokeAllBotsResult) { revokeAllBotsResponse = r }

    nonisolated func get(name: String) async throws -> String {
        await logGet(name)
        return await readPlaintext(name)
    }
    private func logGet(_ name: String) { getCalls.append(GetCall(name: name)) }
    private func readPlaintext(_ name: String) -> String { plaintexts[name] ?? "" }

    nonisolated func list(filter: String?) async throws -> [VaultEntryRef] {
        _ = filter
        return await snapshotListings()
    }
    private func snapshotListings() -> [VaultEntryRef] { listings }

    nonisolated func set(name: String, value: String) async throws {
        await logSet(name: name, value: value)
    }
    private func logSet(name: String, value: String) {
        setCalls.append((name, value))
        plaintexts[name] = value
    }

    var deleteCalls: [String] = []
    nonisolated func delete(name: String) async throws {
        await logDelete(name)
    }
    private func logDelete(_ name: String) {
        deleteCalls.append(name)
        plaintexts.removeValue(forKey: name)
    }

    nonisolated func rotate(name: String) async throws -> RotationResult {
        return await internalRotate(name: name)
    }
    private func internalRotate(name: String) -> RotationResult {
        rotateCalls.append(RotateCall(name: name))
        if let pinned = nextRotationResult {
            return pinned
        }
        return RotationResult(
            secretName: name,
            oldJtiSuffix: "a3f2",
            invalidAt: Date(timeIntervalSince1970: 0)
        )
    }

    nonisolated func revoke(jti: String) async throws {
        await internalRevoke(jti)
    }
    private func internalRevoke(_ jti: String) {
        revokeCalls.append(RevokeCall(jti: jti))
    }

    nonisolated func revokeAllBots(dryRun: Bool, force: Bool) async throws -> RevokeAllBotsResult {
        return await internalRevokeAllBots(dryRun: dryRun, force: force)
    }
    private func internalRevokeAllBots(dryRun: Bool, force: Bool) -> RevokeAllBotsResult {
        revokeAllBotsCalls.append(RevokeAllBotsCall(dryRun: dryRun, force: force))
        return revokeAllBotsResponse
    }

    // Item #9 — signed-envelope variant. Recording-only; tests that
    // need a full verify path drive `AdminActionVerifier` directly.
    var revokeAllBotsSignedCalls: [SignedAdminAction] = []
    nonisolated func revokeAllBotsSigned(_ signed: SignedAdminAction) async throws -> RevokeAllBotsResult {
        return await internalRevokeAllBotsSigned(signed)
    }
    private func internalRevokeAllBotsSigned(_ signed: SignedAdminAction) -> RevokeAllBotsResult {
        revokeAllBotsSignedCalls.append(signed)
        return revokeAllBotsResponse
    }

    nonisolated func blastRadius(jti: String) async throws -> BlastRadiusReport {
        return await internalBlastRadius(jti: jti)
    }
    private func internalBlastRadius(jti: String) -> BlastRadiusReport {
        BlastRadiusGraph.compute(rows: tokenRows, rootJti: jti)
            ?? BlastRadiusReport(rootJti: jti, sub: "?", scope: "?", dependents: [])
    }

    nonisolated func recentAudit(hours: Int) async throws -> [AuditRow] {
        _ = hours
        return []
    }

    nonisolated func seamsRows() async throws -> [SeamsWriter.Row] {
        return await snapshotSeams()
    }
    private func snapshotSeams() -> [SeamsWriter.Row] { seamRows }

    // vault.* stubs — RecordingBrokerClient exercises CLI rendering;
    // vault unlock is not exercised in the existing CLI test suite.
    nonisolated func vaultUnlock(masterPassword: String, email: String) async throws {}
    nonisolated func vaultStatus() async throws -> VaultStatus { VaultStatus(locked: false) }
}

// Fixed-clock helper for footer snapshots.
enum FixedDate {
    static let invalidAt = Date(timeIntervalSince1970: 1_714_670_123) // deterministic
}
