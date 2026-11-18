import Crypto
import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// VaultAuthWireDispatchTests - every broker method that touches the vault maps
// a logged-out or locked vault to a named wire error with the remedy, and keeps
// -32603 for real internal errors. Uses a fake BWClient: no Keychain, no network.

/// BWClient whose every vault call throws the configured error.
actor FailingBWClient: BWClient {
    struct Boom: Swift.Error {}
    private let failure: any Swift.Error
    private var epoch: UInt64 = 0
    init(failure: any Swift.Error) { self.failure = failure }
    func get(name: String) async throws -> [String: String] { throw failure }
    func set(name: String, value: String) async throws { throw failure }
    func delete(name: String) async throws { throw failure }
    func list() async throws -> [String] { throw failure }
    func update(name: String, fields: [String: String]) async throws { throw failure }
    func invalidateSession() async { epoch &+= 1 }
    var isSessionValid: Bool { true }
    var sessionEpoch: UInt64 { epoch }
    func unlock(masterPassword: String, email: String) async throws { throw failure }
    var isVaultUnlocked: Bool { false }
}

@Suite("VaultAuthWireDispatch")
struct VaultAuthWireDispatchTests {

    private func makeDispatcher(failure: any Swift.Error) async throws -> (BrokerWireDispatcher, UnixSocketServer) {
        let kernel = ShikkiKernel()
        let audit = AuditWriter()
        let seams = SeamsWriter()
        let registry = TokenRegistry()
        let drivers = DriverRegistry()
        let engine = RotationEngine(drivers: drivers, audit: audit, seams: seams, registry: registry)
        let verifier = ManifestVerifier(pinnedPublicKey: Curve25519.Signing.PrivateKey().publicKey)
        let manifestStore = ManifestStore(verifier: verifier, seams: seams)
        let scopeValidator = try ScopeValidator(allowlist: ["test-key"])
        let bridge = MCPBridge(bearerAllowlist: ["bearer-auth"])
        let socket = UnixSocketServer(config: UnixSocketConfig(
            socketPath: "/tmp/sh-vauth-\(UUID().uuidString.prefix(8)).s",
            expectedMode: 0o600,
            expectedUid: UInt32(geteuid())
        ))
        let bw = FailingBWClient(failure: failure)
        let minter = TokenMinter(registry: registry, signingKey: Curve25519.Signing.PrivateKey(), toolManifest: [])
        let gateway = RequestGateway(scopeValidator: scopeValidator, bwClient: bw, audit: audit)
        let daemon = BrokerDaemon(
            kernel: kernel, audit: audit, seams: seams, registry: registry,
            drivers: drivers, engine: engine, manifestStore: manifestStore, gateway: gateway,
            bridge: bridge, socket: socket, bwClient: bw, minter: minter,
            bootstrap: StubBootstrapProvider()
        )
        try await daemon.start()
        return (BrokerWireDispatcher(daemon: daemon, bridge: bridge), socket)
    }

    private func request(_ method: String) -> WireRequest {
        switch method {
        case "secret.set":
            return WireRequest(method: method, params: .object(["name": .string("test-key"), "value": .string("v")]), id: "r")
        case "secret.get", "secret.delete":
            return WireRequest(method: method, params: .object(["name": .string("test-key")]), id: "r")
        default:
            return WireRequest(method: method, params: nil, id: "r")
        }
    }

    /// Dispatch, then pass the response through the real NDJSON codec.
    private func roundTrip(_ method: String, failure: any Swift.Error) async throws -> WireError {
        let (dispatcher, socket) = try await makeDispatcher(failure: failure)
        defer { Task { await socket.shutdown() } }
        let response = await dispatcher.dispatch(request(method), peerUid: UInt32(geteuid()))
        let frame = try encodeWireFrame(response)
        let (body, _) = try #require(extractNextFrame(from: frame))
        let decoded = try JSONDecoder().decode(WireResponse.self, from: body)
        return try #require(decoded.error, "\(method) must fail")
    }

    @Test("locked vault: list/get/set/delete all answer vault_locked with the unlock remedy",
          arguments: ["secret.list", "secret.get", "secret.set", "secret.delete"])
    func locked(method: String) async throws {
        let err = try await roundTrip(method, failure: VaultUnlockError.locked)
        #expect(err.code == WireErrorCode.vaultLocked)
        #expect(err.message == "Vault is locked. Run: shi secrets unlock")
        #expect(err.data == .object(["reason": .string("vault_locked"), "remedy": .string("shi secrets unlock")]))
    }

    @Test("logged-out vault: list/get/set/delete all answer not_logged_in with the unlock remedy",
          arguments: ["secret.list", "secret.get", "secret.set", "secret.delete"])
    func loggedOut(method: String) async throws {
        let err = try await roundTrip(method, failure: VaultwardenClientError.notAuthenticated)
        #expect(err.code == WireErrorCode.notLoggedIn)
        #expect(err.message.contains("Run: shi secrets unlock"))
        #expect(err.data == .object(["reason": .string("not_logged_in"), "remedy": .string("shi secrets unlock")]))
    }

    @Test("the operator's case: secret.list notAuthenticated is no longer -32603")
    func operatorCase() async throws {
        let err = try await roundTrip("secret.list", failure: VaultwardenClientError.notAuthenticated)
        #expect(err.code != WireErrorCode.internalError)
        #expect(!err.message.contains("secret.list failed"))
    }

    @Test("broker without a session: not_logged_in, remedy starts the broker",
          arguments: ["secret.list", "secret.set", "secret.delete"])
    func brokerNoSession(method: String) async throws {
        let err = try await roundTrip(method, failure: BWClientError.sessionInvalidated)
        #expect(err.code == WireErrorCode.notLoggedIn)
        #expect(err.data == .object(["reason": .string("not_logged_in"), "remedy": .string("shi secrets brokerd start")]))
    }

    @Test("a real internal error still maps to -32603",
          arguments: ["secret.list", "secret.set", "secret.delete"])
    func internalStays(method: String) async throws {
        let err = try await roundTrip(method, failure: FailingBWClient.Boom())
        #expect(err.code == WireErrorCode.internalError)
        #expect(err.message.hasPrefix("\(method) failed"))
    }
}
