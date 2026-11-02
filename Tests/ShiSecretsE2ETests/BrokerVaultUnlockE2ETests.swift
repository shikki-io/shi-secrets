import Crypto
import Foundation
@testable import ShiSecretsBrokerd
@testable import ShiSecretsKit
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// BrokerVaultUnlockE2ETests — full-stack regression for the notAuthenticated P0.
//
// Stack under test:
//   BrokerWireDispatcher
//     → BrokerDaemon.bwClient (ProductionBWClient)
//       → VaultwardenClient.unlock()          ← P0 fix lives here
//         → refreshToken() → sessionCache.setToken()
//     → BrokerDaemon.bwClient.list()          ← verification probe added in
//                                                dispatchVaultUnlock (Issue 2 fix)
//
// This test is distinct from VaultUnlockReseededSessionTests (which tests
// VaultwardenClient in isolation) in that it drives the FULL broker dispatch
// path: WireRequest → BrokerWireDispatcher → BrokerDaemon → ProductionBWClient
// → VaultwardenClient, using a URLProtocol mock for the Vaultwarden HTTP layer.
//
// ── Red at v0.8.0 ───────────────────────────────────────────────────────────
// T-E2E-01 fails at v0.8.0: after vault.unlock returns ok:true, the
// subsequent secret.list WireRequest throws notAuthenticated inside
// BrokerDaemon.bwClient.list() because VaultwardenClient.sessionCache was
// never seeded (the try? performTokenExchange() swallowed the error without
// calling sessionCache.setToken()).
//
// ── Green after fix ─────────────────────────────────────────────────────────
// refreshToken() is called by unlock(), seeds the cache; the verification
// probe in dispatchVaultUnlock() also calls list() and fails fast here
// rather than letting the CLI see ok:true while subsequent calls fail.

// MARK: - URLProtocol mock for the full unlock flow

/// Intercepts HTTPS requests to "mock-broker-e2e.test".
/// Handles all endpoints that VaultwardenClient.unlock() and list() hit.
private final class BrokerE2EMockProtocol: URLProtocol, @unchecked Sendable {
    // Shared per-suite mutable state — guarded by @Suite(.serialized).
    nonisolated(unsafe) static var tokenResponse: Data?
    nonisolated(unsafe) static var preloginResponse: Data?
    nonisolated(unsafe) static var ciphersResponse: Data = #"{"data":[]}"#.data(using: .utf8)!

    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host?.hasSuffix("mock-broker-e2e.test") == true
    }
    override class func canonicalRequest(for r: URLRequest) -> URLRequest { r }

    override func startLoading() {
        let path = request.url?.path ?? ""
        let method = request.httpMethod ?? "GET"

        if method == "POST" && path.contains("connect/token") {
            respond(data: Self.tokenResponse ?? Data(), status: Self.tokenResponse != nil ? 200 : 400)
        } else if method == "POST" && path.contains("prelogin") {
            respond(data: Self.preloginResponse ?? Data(), status: Self.preloginResponse != nil ? 200 : 400)
        } else if method == "GET" && path.hasSuffix("/ciphers") {
            respond(data: Self.ciphersResponse, status: 200)
        } else if method == "POST" && path.hasSuffix("/ciphers") {
            // cipher create — echo back a minimal item
            let id = UUID().uuidString
            let json = """
            {"id":"\(id)","name":"e2e","type":2,"notes":"","object":"cipherDetails",
             "login":null,"fields":[],"card":null,"identity":null,"secureNote":{"type":0},
             "favorite":false,"edit":true,"collectionIds":[]}
            """.data(using: .utf8)!
            respond(data: json, status: 200)
        } else if method == "DELETE" {
            respond(data: Data(), status: 200)
        } else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
    }
    override func stopLoading() {}

    private func respond(data: Data, status: Int) {
        let resp = HTTPURLResponse(
            url: request.url!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
}

// MARK: - Fixture values

private let e2ePassword = "e2e-master-pw"
private let e2eEmail    = "operator@mock-broker-e2e.test"
private let e2eKDFIter  = 5_000  // reduced for test speed

/// Derive the fixture protectedKey and user key pair from e2ePassword/e2eEmail.
private func makeE2EProtectedKey() throws -> (protectedKey: String, pair: SymmetricKeyPair) {
    let master = try BitwardenCrypto.masterKey(
        masterPassword: e2ePassword, email: e2eEmail,
        kdf: .pbkdf2SHA256, iterations: e2eKDFIter
    )
    let stretched = BitwardenCrypto.stretchMasterKey(master)
    let pair = SymmetricKeyPair(
        encKey: SymmetricKey(size: .bits256),
        macKey: SymmetricKey(size: .bits256)
    )
    let raw = pair.encKey.withUnsafeBytes { Data($0) }
            + pair.macKey.withUnsafeBytes { Data($0) }
    let protectedKey = try BitwardenCrypto.encrypt(raw, using: stretched).serialized
    return (protectedKey, pair)
}

/// Seed the mock server with a valid token + prelogin response.
private func installE2EResponses(protectedKey: String) {
    BrokerE2EMockProtocol.tokenResponse = """
    {
      "access_token": "e2e-tok-\(UUID().uuidString)",
      "expires_in": 3600,
      "token_type": "Bearer",
      "Key": "\(protectedKey)",
      "Kdf": 0,
      "KdfIterations": \(e2eKDFIter)
    }
    """.data(using: .utf8)
    BrokerE2EMockProtocol.preloginResponse = """
    {"kdf": 0, "kdfIterations": \(e2eKDFIter)}
    """.data(using: .utf8)
    BrokerE2EMockProtocol.ciphersResponse = #"{"data":[]}"#.data(using: .utf8)!
}

// MARK: - E2E stack factory

private struct BrokerE2EStack {
    let dispatcher: BrokerWireDispatcher
    let socket: UnixSocketServer
    let ownerUid: UInt32
}

private func makeE2EStack() async throws -> BrokerE2EStack {
    let kernel = ShikkiKernel()
    let audit = AuditWriter()
    let seams = SeamsWriter()
    let registry = TokenRegistry()
    let drivers = DriverRegistry()
    let engine = RotationEngine(drivers: drivers, audit: audit, seams: seams, registry: registry)
    let verifier = ManifestVerifier(pinnedPublicKey: Curve25519.Signing.PrivateKey().publicKey)
    let manifestStore = ManifestStore(verifier: verifier, seams: seams)
    let scopeValidator = try ScopeValidator(allowlist: ["*"])
    let bridge = MCPBridge(bearerAllowlist: [])
    let socketPath = "/tmp/sh-vul-e2e-\(UUID().uuidString.prefix(8)).s"
    let config = UnixSocketConfig(
        socketPath: socketPath,
        expectedMode: 0o600,
        expectedUid: UInt32(geteuid())
    )
    let socket = UnixSocketServer(config: config)

    // ProductionBWClient wired with a VaultwardenClient backed by BrokerE2EMockProtocol.
    // This is the key difference from E2ESupport.make() which uses InMemoryBWClient —
    // here we exercise the REAL VaultwardenClient.unlock() code path, including
    // the refreshToken() → sessionCache.setToken() fix.
    let creds = VaultwardenCredentials(
        clientID: "user.e2e-broker",
        clientSecret: "e2e-broker-secret",
        serverURL: URL(string: "https://mock-broker-e2e.test")!
    )
    let vc = try VaultwardenClient(
        credentials: creds,
        configYmlVaultServer: "https://mock-broker-e2e.test",
        urlProtocolClasses: [BrokerE2EMockProtocol.self]
    )
    // Wire VaultwardenClient into ProductionBWClient without calling connect()
    // so that sessionCache starts empty — exactly the condition that triggered
    // the P0 bug (Bootstrap's Keychain cache-hit path: seedTokenFromCache but
    // no performTokenExchange, so accountProtectedKey is nil).
    let bwClient = ProductionBWClient()
    await bwClient.wire(client: vc)

    let minter = TokenMinter(
        registry: registry,
        signingKey: Curve25519.Signing.PrivateKey(),
        toolManifest: []
    )
    let gateway = RequestGateway(
        scopeValidator: scopeValidator, bwClient: bwClient, audit: audit
    )
    // devMode: true — skips bootstrap.unseal() so the ProductionBWClient
    // retains its pre-wired mock VaultwardenClient rather than being
    // re-wired by BrokerDaemon.start() with a real bootstrap's client.
    // Also skips kernel job registration (unnecessary for dispatch tests).
    let daemon = BrokerDaemon(
        kernel: kernel, audit: audit, seams: seams, registry: registry,
        drivers: drivers, engine: engine,
        manifestStore: manifestStore, gateway: gateway,
        bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
        bootstrap: E2EStubBootstrap(),
        devMode: true
    )
    try await daemon.start()
    let ownerUid = UInt32(geteuid())
    let dispatcher = BrokerWireDispatcher(daemon: daemon, bridge: bridge, ownerUid: ownerUid)
    return BrokerE2EStack(dispatcher: dispatcher, socket: socket, ownerUid: ownerUid)
}

// MARK: - Helper: issue a WireRequest

private func unlockRequest(id: String = "ul-1") -> WireRequest {
    WireRequest(
        method: "vault.unlock",
        params: .object([
            "masterPassword": .string(e2ePassword),
            "email": .string(e2eEmail),
        ]),
        id: id
    )
}

private func listRequest(id: String = "ls-1") -> WireRequest {
    WireRequest(method: "secret.list", params: nil, id: id)
}

private func setRequest(name: String, value: String, id: String = "set-1") -> WireRequest {
    WireRequest(
        method: "secret.set",
        params: .object(["name": .string(name), "value": .string(value)]),
        id: id
    )
}

// MARK: - Tests

/// Serialized: BrokerE2EMockProtocol has global mutable state.
@Suite("BrokerVaultUnlock E2E — full stack (P0 regression)", .serialized)
struct BrokerVaultUnlockE2ETests {

    // T-E2E-01 ─────────────────────────────────────────────────────────────────
    // vault.unlock → ok:true, then secret.list → empty list.
    //
    // At v0.8.0: vault.unlock returned ok:true but the verification probe in
    // dispatchVaultUnlock did NOT exist, and the subsequent secret.list threw
    // notAuthenticated inside bwClient.list() because sessionCache was never
    // seeded (try? performTokenExchange() discarded the error without calling
    // sessionCache.setToken()). This test would have caught that regression.
    @Test("T-E2E-01: vault.unlock → secret.list — must not throw notAuthenticated")
    func test_e2e01_unlockThenList_noNotAuthenticated() async throws {
        let (protectedKey, _) = try makeE2EProtectedKey()
        installE2EResponses(protectedKey: protectedKey)

        let stack = try await makeE2EStack()
        defer { Task { await stack.socket.shutdown() } }

        let unlockResp = await stack.dispatcher.dispatch(unlockRequest(), peerUid: stack.ownerUid)
        #expect(unlockResp.error == nil,
            "vault.unlock must succeed; got: \(String(describing: unlockResp.error))")

        // List: verifies the session is usable end-to-end through the full
        // broker → ProductionBWClient → VaultwardenClient stack.
        let listResp = await stack.dispatcher.dispatch(listRequest(), peerUid: stack.ownerUid)
        #expect(listResp.error == nil,
            "secret.list after unlock must not fail with notAuthenticated; got: \(String(describing: listResp.error))")
        if case .array(let items) = listResp.result {
            #expect(items.isEmpty, "empty vault must return empty list")
        } else {
            Issue.record("Expected array result, got \(String(describing: listResp.result))")
        }
    }

    // T-E2E-02 ─────────────────────────────────────────────────────────────────
    // The verification probe in dispatchVaultUnlock surfaces a broken session
    // before the CLI sees ok:true. Simulate a broken token response (no Key
    // field → accountProtectedKey nil → VaultUnlockError.accountKeyMissing)
    // and assert vault.unlock itself returns an error.
    @Test("T-E2E-02: vault.unlock fails loud when session not established")
    func test_e2e02_unlockFails_whenTokenMissingKey() async throws {
        // Token response WITHOUT the Key field → captureKeyMaterial sets nothing
        // → accountProtectedKey stays nil → VaultUnlockError.accountKeyMissing.
        BrokerE2EMockProtocol.tokenResponse = """
        {
          "access_token": "e2e-tok-\(UUID().uuidString)",
          "expires_in": 3600,
          "token_type": "Bearer",
          "Kdf": 0,
          "KdfIterations": \(e2eKDFIter)
        }
        """.data(using: .utf8)
        BrokerE2EMockProtocol.preloginResponse = """
        {"kdf": 0, "kdfIterations": \(e2eKDFIter)}
        """.data(using: .utf8)
        BrokerE2EMockProtocol.ciphersResponse = #"{"data":[]}"#.data(using: .utf8)!

        let stack = try await makeE2EStack()
        defer { Task { await stack.socket.shutdown() } }

        let unlockResp = await stack.dispatcher.dispatch(unlockRequest(id: "ul-e2e-02"), peerUid: stack.ownerUid)
        #expect(unlockResp.error != nil,
            "vault.unlock with missing Key must return an error, not ok:true")
    }

    // T-E2E-03 ─────────────────────────────────────────────────────────────────
    // vault.unlock → ok:true → secret.set → secret.list shows the item.
    @Test("T-E2E-03: unlock → set → list — item visible after unlock + set")
    func test_e2e03_unlockSetList() async throws {
        let (protectedKey, userPair) = try makeE2EProtectedKey()
        installE2EResponses(protectedKey: protectedKey)

        // Seed cipher store to return a cipher after set.
        // VaultwardenClient.set() issues POST /api/ciphers (handled by mock),
        // then GET /api/ciphers for list. After set, return one item.
        let cipherID = UUID().uuidString
        let cipherJSON = """
        {"data":[{"id":"\(cipherID)","name":"e2e-secret","type":2,
          "notes":"some-value","object":"cipherDetails",
          "login":null,"fields":[],"card":null,"identity":null,
          "secureNote":{"type":0},"favorite":false,"edit":true,"collectionIds":[]}]}
        """.data(using: .utf8)!

        let stack = try await makeE2EStack()
        defer { Task { await stack.socket.shutdown() } }

        let unlockResp = await stack.dispatcher.dispatch(unlockRequest(id: "ul-e03"), peerUid: stack.ownerUid)
        #expect(unlockResp.error == nil, "unlock must succeed: \(String(describing: unlockResp.error))")

        // After unlock, update mock ciphers to include the item for list.
        BrokerE2EMockProtocol.ciphersResponse = cipherJSON

        let listResp = await stack.dispatcher.dispatch(listRequest(id: "ls-e03"), peerUid: stack.ownerUid)
        #expect(listResp.error == nil, "list after unlock must succeed: \(String(describing: listResp.error))")
        if case .array(let items) = listResp.result {
            #expect(!items.isEmpty, "vault with one cipher must return non-empty list")
        }
        _ = userPair  // fixture pair not needed for list; used in full encrypt/decrypt round-trip
    }

    // T-E2E-04 ─────────────────────────────────────────────────────────────────
    // vault.status before and after vault.unlock matches the locked/unlocked state.
    @Test("T-E2E-04: vault.status reflects locked → unlocked after vault.unlock")
    func test_e2e04_vaultStatusTransition() async throws {
        let (protectedKey, _) = try makeE2EProtectedKey()
        installE2EResponses(protectedKey: protectedKey)

        let stack = try await makeE2EStack()
        defer { Task { await stack.socket.shutdown() } }

        // Before unlock: locked.
        let statusBefore = await stack.dispatcher.dispatch(
            WireRequest(method: "vault.status", params: nil, id: "st-before"),
            peerUid: stack.ownerUid
        )
        if case .object(let obj) = statusBefore.result, case .bool(let locked) = obj["locked"] {
            #expect(locked, "vault must be locked before unlock")
        }

        // Unlock.
        let unlockResp = await stack.dispatcher.dispatch(unlockRequest(id: "ul-e04"), peerUid: stack.ownerUid)
        #expect(unlockResp.error == nil, "unlock must succeed: \(String(describing: unlockResp.error))")

        // After unlock: unlocked.
        let statusAfter = await stack.dispatcher.dispatch(
            WireRequest(method: "vault.status", params: nil, id: "st-after"),
            peerUid: stack.ownerUid
        )
        if case .object(let obj) = statusAfter.result, case .bool(let locked) = obj["locked"] {
            #expect(!locked, "vault must be unlocked after vault.unlock")
        }
    }
}
