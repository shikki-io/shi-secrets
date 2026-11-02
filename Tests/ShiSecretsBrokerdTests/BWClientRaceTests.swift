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

// 3rd-pass validator T2 — BWClient `invalidateSession` races
// `handleRequest` on a real daemon.
//
// The U5 post-mint race-closure guard in BrokerDaemon.handleRequest
// captures the bw-session epoch BEFORE mint and re-checks it AFTER
// persist. If an `invalidateSession` call lands between prepare and
// persist, the daemon must:
//   * run the compensating revoke (seam emitted by I2 hook)
//   * return `.deny(.brokerSessionInvalid)` (review finding #3 —
//     dedicated reason, not overloaded onto `.incidentBypass`)
//
// `RacingBWClient` is the test double: first `isSessionValid` read
// returns true (so the pre-mint gate passes), second read returns
// false AND `sessionEpoch` bumps (so the post-mint U5 re-check
// trips). Models the real race without needing a threading harness.

@Suite("BWClientMintRace")
struct BWClientRaceTests {

    private func socketPath() -> String {
        "/tmp/sh-br-\(UUID().uuidString.prefix(8)).s"
    }

    /// Test double — `isSessionValid` toggles true→false across two
    /// reads; `sessionEpoch` bumps alongside the toggle. Implements
    /// the full `BWClient` surface but refuses actual get/update (we
    /// never drive them in handleRequest's mint path).
    fileprivate actor RacingBWClient: BWClient {
        private var sessionValidReads: Int = 0
        private var epochReads: Int = 0
        private var _sessionEpoch: UInt64 = 0

        init() {}

        var isSessionValid: Bool {
            get async {
                sessionValidReads += 1
                // First read → true (pre-mint gate passes).
                // Subsequent reads → false (U5 re-check trips).
                return sessionValidReads == 1
            }
        }

        var sessionEpoch: UInt64 {
            get async {
                epochReads += 1
                // First read (pre-mint) → 0. Second read (post-mint)
                // → 1, modeling an `invalidateSession` that ran
                // between prepare and persist.
                if epochReads >= 2 {
                    _sessionEpoch = 1
                }
                return _sessionEpoch
            }
        }

        func get(name: String) async throws -> [String: String] {
            throw BWClientError.sessionInvalidated
        }

        func set(name: String, value: String) async throws {
            throw BWClientError.sessionInvalidated
        }

        func delete(name: String) async throws {
            throw BWClientError.sessionInvalidated
        }

        func list() async throws -> [String] {
            throw BWClientError.sessionInvalidated
        }

        func update(name: String, fields: [String: String]) async throws {
            throw BWClientError.sessionInvalidated
        }

        func invalidateSession() async {
            _sessionEpoch &+= 1
        }

        // Vault unlock / lock stubs — RacingBWClient exercises the
        // mint-vs-invalidate race only; vault operations are not exercised here.
        func unlock(masterPassword: String, email: String) async throws {}
        var isVaultUnlocked: Bool { false }
        func lock() async throws {}
        func lockMemoryOnly() async throws {}
        var lockReason: String? { nil }
        var custodyBackend: String? { nil }
        func reEncryptLegacyPlaintext(dryRun: Bool) async throws -> VaultReencryptResult {
            VaultReencryptResult(count: 0, failures: [:])
        }
    }

    @Test("bw invalidate between prepare and persist → .deny(.brokerSessionInvalid) + compensateRevoke seam (T2)")
    func test_handleRequest_bwInvalidateBetweenPrepareAndPersist_returnsBrokerSessionInvalid() async throws {
        let kernel = ShikkiKernel()
        let audit = AuditWriter()
        let seams = SeamsWriter()
        let registry = TokenRegistry()
        let drivers = DriverRegistry()
        let engine = RotationEngine(
            drivers: drivers, audit: audit, seams: seams, registry: registry
        )
        let verifier = ManifestVerifier(pinnedPublicKey: Curve25519.Signing.PrivateKey().publicKey)
        let manifestStore = ManifestStore(verifier: verifier, seams: seams)
        let scopeValidator = try ScopeValidator(allowlist: ["ovh/OVH_APP_KEY"])
        let bridge = MCPBridge()
        let socket = UnixSocketServer(
            config: UnixSocketConfig(
                socketPath: socketPath(),
                expectedMode: 0o600,
                expectedUid: UInt32(geteuid())
            )
        )
        let bwClient = RacingBWClient()
        let minter = TokenMinter(
            registry: registry,
            signingKey: Curve25519.Signing.PrivateKey(),
            toolManifest: []
        )
        let gateway = RequestGateway(
            scopeValidator: scopeValidator, bwClient: bwClient, audit: audit
        )
        let daemon = BrokerDaemon(
            kernel: kernel, audit: audit, seams: seams, registry: registry,
            drivers: drivers, engine: engine,
            manifestStore: manifestStore, gateway: gateway,
            bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
            bootstrap: StubBootstrapProvider()
        )
        try await daemon.start()
        defer { Task { await socket.shutdown() } }

        let request = BrokerRequest(
            sub: "claude@tusken",
            scope: "ovh/OVH_APP_KEY",
            op: .read,
            ttl: 600,
            toolName: nil
        )
        let wrapped = WrappedRequest(
            peerUid: UInt32(geteuid()),
            transport: .unix,
            llmTouched: false,
            payload: Data()
        )
        let response = await daemon.handleRequest(request, wrapped: wrapped)

        // U5 post-mint re-check trips → .deny(.brokerSessionInvalid).
        if case .deny(let reason) = response {
            #expect(reason == .brokerSessionInvalid)
        } else {
            Issue.record("expected .deny(.brokerSessionInvalid), got \(response)")
        }

        // compensateRevoke ran. Since persist succeeded (the mint WAS
        // registered before the race was detected), the revoke hits a
        // live row — no persistCompensationNoOp seam, but the row is
        // now marked revoked. Assert via registry snapshot.
        let registryRows = await registry.all()
        #expect(registryRows.count == 1)
        let row = try #require(registryRows.first)
        #expect(row.revoked == true, "freshly-issued jti should be revoked after race detection")

        // Audit: allow row was written (pre-persist) + deny row
        // written post-race-detection.
        let auditRows = await audit.all()
        #expect(auditRows.count == 2)
        #expect(auditRows.first?.allow == .allow)
        #expect(auditRows.last?.allow == .deny)
        #expect(auditRows.last?.reason == .brokerSessionInvalid)
    }
}
