import Foundation
@testable import ShiSecretsKit
import Testing

// VaultAuthRequiredTests - a logged-out or locked vault is an expected state:
// its own wire code, a machine-readable reason, the exact remedy command and a
// distinct exit code. -32603 stays reserved for real internal errors.

@Suite("VaultAuthRequired")
struct VaultAuthRequiredTests {

    private struct Boom: Swift.Error {}

    /// Round-trips a response through the real NDJSON codec.
    private func overTheWire(_ response: WireResponse) throws -> WireResponse {
        let frame = try encodeWireFrame(response)
        let (body, _) = try #require(extractNextFrame(from: frame))
        return try JSONDecoder().decode(WireResponse.self, from: body)
    }

    @Test("codes are in the application range and do not collide")
    func codesAreDistinct() {
        let codes = [
            WireErrorCode.denied, WireErrorCode.scopeViolation, WireErrorCode.rateLimit,
            WireErrorCode.bootstrapFailed, WireErrorCode.notLoggedIn, WireErrorCode.vaultLocked,
        ]
        #expect(Set(codes).count == codes.count)
        #expect(WireErrorCode.notLoggedIn != WireErrorCode.internalError)
        #expect(WireErrorCode.vaultLocked != WireErrorCode.internalError)
    }

    @Test("locked vault: named code, reason, remedy, message, exit code")
    func lockedVault() throws {
        let auth = try #require(VaultAuthRequired.classify(VaultUnlockError.locked))
        #expect(auth.kind == .vaultLocked)
        #expect(auth.message == "Vault is locked. Run: shi secrets unlock")
        #expect(auth.exitCode == 3)
        let wire = try overTheWire(WireResponse(id: "1", error: auth.wireError()))
        let err = try #require(wire.error)
        #expect(err.code == WireErrorCode.vaultLocked)
        #expect(err.data == .object(["reason": .string("vault_locked"), "remedy": .string("shi secrets unlock")]))
        #expect(VaultAuthRequired(wireError: err) == auth)
    }

    @Test("logged-out vault (session missing or expired): unlock re-authenticates")
    func notLoggedIn() throws {
        let auth = try #require(VaultAuthRequired.classify(VaultwardenClientError.notAuthenticated))
        #expect(auth.kind == .notLoggedIn)
        #expect(auth.remedy == "shi secrets unlock")
        #expect(auth.message.contains("Not logged in"))
        #expect(auth.message.hasSuffix("Run: shi secrets unlock"))
        #expect(auth.exitCode == 4)
        let wire = try overTheWire(WireResponse(id: "2", error: auth.wireError()))
        #expect(wire.error?.code == WireErrorCode.notLoggedIn)
    }

    @Test("missing credentials: remedy is the credentials setup verb")
    func credentialsMissing() throws {
        let auth = try #require(VaultAuthRequired.classify(VaultwardenClientError.credentialsNotLoaded))
        #expect(auth.kind == .notLoggedIn)
        #expect(auth.remedy == "shi secrets setup vault-credentials")
        #expect(auth.message.contains(auth.remedy))
    }

    @Test("exit codes are distinct from each other and from generic failure 1")
    func exitCodesDistinct() {
        #expect(VaultAuthRequired.locked.exitCode != VaultAuthRequired.sessionExpired.exitCode)
        #expect(![0, 1].contains(VaultAuthRequired.locked.exitCode))
        #expect(![0, 1].contains(VaultAuthRequired.sessionExpired.exitCode))
    }

    @Test("--json carries reason and remedy, and nothing secret")
    func jsonBody() throws {
        let data = Data(VaultAuthRequired.locked.jsonString.utf8)
        let obj = try #require(try JSONSerialization.jsonObject(with: data) as? [String: String])
        #expect(obj["reason"] == "vault_locked")
        #expect(obj["remedy"] == "shi secrets unlock")
        #expect(obj["message"] == "Vault is locked. Run: shi secrets unlock")
    }

    @Test("a real failure is not classified: it stays an internal error")
    func internalErrorNotClassified() {
        #expect(VaultAuthRequired.classify(Boom()) == nil)
        #expect(VaultAuthRequired.classify(VaultwardenClientError.fetchSecretFailed(httpStatus: 500)) == nil)
        #expect(VaultAuthRequired.classify(VaultUnlockError.accountKeyMissing) == nil)
        let internalErr = WireError(code: WireErrorCode.internalError, message: "secret.list failed: boom")
        #expect(VaultAuthRequired(wireError: internalErr) == nil)
        #expect(WireErrorCode.internalError == -32603)
    }

    @Test("deny reasons map both ways and reach the wire as the named codes")
    func denyReasonBridge() throws {
        #expect(VaultAuthRequired(denyReason: .vaultLocked) == .locked)
        #expect(VaultAuthRequired(denyReason: .vaultNotLoggedIn)?.kind == .notLoggedIn)
        #expect(VaultAuthRequired(denyReason: .internalError) == nil)
        let wire = try BrokerResponse.deny(.vaultLocked).toWireResponse(id: "d")
        #expect(wire.error?.code == WireErrorCode.vaultLocked)
        let wire2 = try BrokerResponse.deny(.vaultNotLoggedIn).toWireResponse(id: "d")
        #expect(wire2.error?.code == WireErrorCode.notLoggedIn)
    }
}
